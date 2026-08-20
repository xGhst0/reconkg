"""Parse real scan output into evidence. Offline, no network.

`db_import` in spirit: point it at an nmap XML file you produced and it turns
into the same evidence dicts the fixtures use. This is the seam that gets you
off hand-written test data and onto real boxes without the coordinator ever
opening a socket.

XML safety: nmap XML is a file you produced, but "a file the operator points
us at" is still untrusted input -- CTF write-ups get shared, scan artefacts
get passed around. `defusedxml` is used when available and is the recommended
install.

Without it we fall back to the stdlib parser plus a hand-written guard. That
guard used to reject any document containing `<!DOCTYPE`, which sounded
prudent and was catastrophic: **every real nmap file opens with
`<!DOCTYPE nmaprun>`**, so on any machine without defusedxml the importer
refused 100% of legitimate input while the test suite -- built entirely on
hand-written XML that omitted the doctype -- passed. Golden fixtures from a
real scan found it immediately.

The guard now rejects what is actually dangerous: entity declarations, an
internal subset, and external SYSTEM/PUBLIC identifiers. A bare doctype with
no subset carries no payload and is allowed through.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from xml.etree.ElementTree import ParseError

from .auth import validate_address

log = logging.getLogger(__name__)

try:  # pragma: no cover - depends on environment
    from defusedxml.ElementTree import parse as _safe_parse
    DEFUSED = True
except ImportError:  # pragma: no cover
    from xml.etree.ElementTree import parse as _stdlib_parse
    DEFUSED = False

    def _safe_parse(source):
        text = Path(source).read_text(encoding="utf-8", errors="replace") \
            if not hasattr(source, "read") else source.read()
        reason = unsafe_doctype_reason(text)
        if reason:
            raise ValueError(
                f"refusing to parse: {reason}. Install defusedxml for "
                "hardened parsing.")
        import io
        return _stdlib_parse(io.StringIO(text))


_ENTITY_DECL = re.compile(r"<!ENTITY", re.I)
_DOCTYPE = re.compile(r"<!DOCTYPE\s+([^\[>]*)(\[)?", re.I)


def unsafe_doctype_reason(text: str) -> Optional[str]:
    """Return why this document is dangerous, or None if it is benign.

    Split out and named so it can be tested directly against real nmap
    output. The three things worth refusing:

      <!ENTITY ...>              entity declaration -- billion laughs, XXE
      <!DOCTYPE x [ ... ]>       internal subset -- where entities hide
      <!DOCTYPE x SYSTEM "...">  external identifier -- fetches a URL

    `<!DOCTYPE nmaprun>` is none of those. It declares a name and stops.
    """
    if _ENTITY_DECL.search(text):
        return "document declares an XML entity"
    match = _DOCTYPE.search(text)
    if match is None:
        return None
    if match.group(2):
        return "doctype carries an internal subset"
    identifier = (match.group(1) or "").strip()
    if re.search(r"\b(SYSTEM|PUBLIC)\b", identifier, re.I):
        return "doctype references an external DTD"
    return None


MAX_HOSTS_PER_IMPORT = 4096
MAX_PORTS_PER_HOST = 8192
"""RC-08: a scan file is untrusted input with no natural size limit. A 5000
host XML imported without complaint; nothing stops a 5,000,000 one."""

SCANTYPE_TOOL = {"syn": "nmap-sS", "connect": "nmap-sT", "ack": "nmap-sT",
                 "window": "nmap-sT", "null": "nmap-sT", "fin": "nmap-sT",
                 "xmas": "nmap-sT", "udp": "nmap-sT"}


@dataclass
class ImportResult:
    source: str
    hosts: dict[str, dict] = field(default_factory=dict)
    """address -> evidence payload, shaped for EvidenceSource.put()."""
    port_tool: str = "nmap-sT"
    """Which tool asserted reachability -- taken from <scaninfo type=...>.

    Ports and services must be staged under different tool keys because they
    were produced by different techniques with different reliability
    ceilings. Filing a version guess under the sweep's key would let it
    inherit the sweep's credibility, which is the RC-01 failure in miniature.
    """
    service_tool: str = "nmap-sV"
    warnings: list[str] = field(default_factory=list)
    discovered_only: list[str] = field(default_factory=list)
    """Hosts confirmed up but carrying no port data, e.g. from `nmap -sn`."""

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    def summary(self) -> str:
        lines = [f"[*] Importing '{self.source}'"]
        for address, payload in self.hosts.items():
            lines.append(
                f"[+] {address}: {len(payload.get('ports', []))} ports, "
                f"{len(payload.get('services', []))} services")
        for w in self.warnings:
            lines.append(f"[!] {w}")
        for address in self.discovered_only:
            lines.append(f"[+] {address}: up, no port data (host discovery)")
        lines.append(f"[*] Imported {self.host_count} host(s)")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# nmap XML
# --------------------------------------------------------------------------- #

_STATE_CONFIDENCE = {"open": 0.95, "filtered": 0.6, "closed": 0.9,
                     "open|filtered": 0.5, "unfiltered": 0.7}


def parse_nmap_xml(path: str | Path) -> ImportResult:
    """Turn an nmap XML run into per-host evidence payloads.

    Confidence comes from nmap's own `conf` attribute on the service element
    (1-10) rather than a flat constant. nmap already tells us how sure it is;
    discarding that and substituting a guess would be throwing away the best
    signal in the file.
    """
    file = Path(path).expanduser()
    if not file.is_file():
        raise FileNotFoundError(f"no such scan file: {file}")

    try:
        tree = _safe_parse(str(file))
    except ParseError as exc:
        # `ParseError` subclasses `SyntaxError`, not `ValueError`, so it sails
        # straight past every `except ValueError` written to mean "this file
        # is not usable" -- the API's upload handler and the scan runner's
        # both. Converted here, at the one function that parses, rather than
        # at each call site: a caller that forgets is the shape this codebase
        # keeps finding, and `run()` writing an empty file with `mkstemp`
        # makes an nmap that exits 0 having written nothing hit exactly this.
        raise ValueError(f"{file} is not well-formed XML: {exc}") from None
    root = tree.getroot()
    if root.tag != "nmaprun":
        raise ValueError(f"{file} is not nmap XML (root element <{root.tag}>)")

    scaninfo = root.find("scaninfo")
    scantype = scaninfo.get("type", "") if scaninfo is not None else ""
    result = ImportResult(source="Nmap XML",
                          port_tool=SCANTYPE_TOOL.get(scantype, "nmap-sT"))
    if not DEFUSED:
        result.warnings.append(
            "defusedxml not installed; parsed with the stdlib fallback")

    for host in root.findall("host"):
        if len(result.hosts) >= MAX_HOSTS_PER_IMPORT:
            result.warnings.append(
                f"stopped at {MAX_HOSTS_PER_IMPORT} hosts; file truncated")
            break

        raw_address = _host_address(host)
        if raw_address is None:
            result.warnings.append("host element with no usable address")
            continue
        try:
            address = validate_address(raw_address)
        except ValueError as exc:
            result.warnings.append(f"rejected address {raw_address!r}: {exc}")
            continue

        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue

        ports_out: list[dict] = []
        services_out: list[dict] = []

        for port in host.findall("./ports/port"):
            if len(ports_out) >= MAX_PORTS_PER_HOST:
                result.warnings.append(
                    f"{address}: stopped at {MAX_PORTS_PER_HOST} ports")
                break
            try:
                number = int(port.get("portid", ""))
            except ValueError:
                result.warnings.append(f"{address}: unparseable portid")
                continue
            state_el = port.find("state")
            state = state_el.get("state", "unknown") if state_el is not None \
                else "unknown"
            ports_out.append({
                "number": number,
                "protocol": port.get("protocol", "tcp"),
                "state": _normalise_state(state),
                "confidence": _STATE_CONFIDENCE.get(state, 0.5),
            })

            service = port.find("service")
            if service is None:
                continue
            entry = _service_entry(number, service)
            if entry is not None:
                services_out.append(entry)

        if not ports_out and not services_out:
            # A host-discovery run (-sn) reports the host up with no <ports>
            # element at all. "This address is live" is real evidence and was
            # being thrown away, so an operator who ran a ping sweep first
            # imported nothing and could not tell why.
            result.hosts.setdefault(address, {})
            result.discovered_only.append(address)
            continue
        payload: dict = {}
        if ports_out:
            payload["ports"] = ports_out
        if services_out:
            payload["services"] = services_out
        result.hosts[address] = payload

    return result


def _host_address(host) -> Optional[str]:
    """Prefer IPv4/IPv6; fall back to the first hostname."""
    for addr in host.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            value = addr.get("addr")
            if value:
                return value
    name = host.find("./hostnames/hostname")
    return name.get("name") if name is not None else None


def _normalise_state(raw: str) -> str:
    if raw in ("open", "closed", "filtered"):
        return raw
    if raw == "open|filtered":
        return "filtered"
    return "unknown"


UNINFORMATIVE_SERVICES = {"tcpwrapped", "unknown"}
"""nmap saying "something answered and I could not identify it". Recording
that as a service identification at the probe's own confidence would let a
non-answer masquerade as a finding."""


def _service_entry(port: int, service) -> Optional[dict]:
    name = service.get("name")
    if not name:
        return None

    # nmap's conf is 1-10. Below ~7 it is guessing from the port number alone.
    try:
        conf = int(service.get("conf", "3"))
    except ValueError:
        conf = 3
    confidence = max(0.05, min(conf / 10.0, 1.0))

    product = service.get("product")
    version = service.get("version")
    method = service.get("method", "")

    # method="table" means nmap never spoke to the service -- it looked the
    # port number up in nmap-services. That is a convention, not evidence.
    table_only = method == "table"
    ambiguous = table_only or not version

    if table_only:
        confidence = min(confidence, 0.3)

    if name.lower() in UNINFORMATIVE_SERVICES:
        ambiguous = True
        confidence = min(confidence, 0.2)

    entry = {
        "port": port,
        "service": name,
        "product": product,
        "version": version,
        "ambiguous": ambiguous,
        "confidence": round(confidence, 3),
    }
    if service.get("tunnel"):
        entry["tunnel"] = service.get("tunnel")
    cpes = [c.text for c in service.findall("cpe") if c.text]
    if cpes:
        entry["cpe"] = cpes[0]
    extra = " ".join(filter(None, [product, version,
                                   service.get("extrainfo")]))
    if extra:
        entry["banner"] = extra
    return entry


# --------------------------------------------------------------------------- #
# Ingest helper
# --------------------------------------------------------------------------- #

async def ingest(result: ImportResult, store, evidence, *,
                 principal: str, port_tool: Optional[str] = None,
                 service_tool: Optional[str] = None) -> list[str]:
    """Register imported hosts and stage their evidence.

    `principal` is the authenticated submitter, exactly as with the HTTP
    ingress -- an import is evidence submission and gets the same identity
    accounting. Importing the same file three times under one principal does
    not manufacture corroboration.
    """
    from .models import Provenance

    ports_key = port_tool or result.port_tool
    services_key = service_tool or result.service_tool
    added: list[str] = []
    for address, payload in result.hosts.items():
        await store.ensure_host(address, Provenance(
            source_tool="operator", principal=principal, confidence=1.0,
            note=f"imported from {result.source}"))
        if payload.get("ports"):
            evidence.put(ports_key, address, {"ports": payload["ports"]},
                         principal=principal)
        if payload.get("services"):
            evidence.put(services_key, address,
                         {"services": payload["services"]},
                         principal=principal)
        added.append(address)
    return added
