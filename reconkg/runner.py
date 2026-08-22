"""The only module in reconkg permitted to execute anything.

Non-negotiable 9 exists because thirteen of forty-seven findings are one
control built on one path and forgotten on a second. An execution path is
the worst conceivable place to learn that a fourteenth time, so there is
exactly one path and this is it. Nothing else in the tree imports
`subprocess` or `asyncio.create_subprocess_*`, and a test asserts that.

Three properties, in the order they matter.

**Named profiles, not caller-supplied flags.** The caller asks for
`service`, never for `-sT -sV --version-intensity 9`. A flag allowlist
would be a filter applied to caller-influenced strings, and this project
has three separate findings about precisely that shape: RC-31 (a membership
test that looked type-safe because `Category` subclassed `str`), RC-32
(msfconsole re-splitting its own argument on `;`), and RC-37 (`--script
exploit` selecting a *category* rather than a file). Filtering hostile
strings is a game you win by not playing. Nothing the caller sends becomes
a flag.

**Argv is a list, never a string.** `create_subprocess_exec`, never
`_shell`. There is no interpolation anywhere in this module. Exactly one
caller-derived value reaches the process -- the target address -- and it
arrives as its own argv element where no metacharacter means anything.

**Re-validation at the chokepoint.** `app.py` already checks
`validate_address` and `require_scope` before calling here. This checks the
address again anyway. RC-07's finding was that per-ingress validation loses,
and the ingress that forgets is always the one nobody has written yet; the
console, a scheduled job and a future CLI are all callers that do not exist
today. The check belongs where the packets leave.

**What is deliberately absent.** No `-sS`, `-sU` or `-O`: they need root,
and a coordinator that asks to run privileged is a coordinator that will be
run privileged. Every profile is an unprivileged connect scan. No `-sC` and
no `--script` in any form: NSE brings the whole `commands.py` category tier
into play, and running scripts is a materially larger decision than running
a port scan. When that is wanted it gets its own review, not a quiet
addition to a tuple here.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .auth import validate_address
from .importers import ImportResult, parse_nmap_xml

log = logging.getLogger(__name__)

BINARY = "nmap"

#: Profile -> argv fragment. The whole vocabulary a caller has.
#:
#: `--open` on the port profiles because a closed port is not evidence
#: anyone acts on and it triples the size of the XML. `-sn` carries no port
#: flags at all: a host-discovery run legitimately produces hosts with no
#: port data, which RC-22's round-7 finding taught the importer to record
#: rather than silently drop.
PROFILES: dict[str, tuple[str, ...]] = {
    "discovery": ("-sn",),
    "quick": ("-sT", "-F", "--open"),
    "service": ("-sT", "-sV", "--version-intensity", "9", "--open"),
    "thorough": ("-sT", "-sV", "-p-", "--open"),
}

DEFAULT_PROFILE = "service"

#: Wall-clock ceilings, per profile. A scan that hangs holds a slot, and two
#: slots is the whole budget -- so the timeout is what stops one unreachable
#: host from making the feature look broken for everyone.
TIMEOUTS: dict[str, float] = {
    "discovery": 300.0,
    "quick": 600.0,
    "service": 1800.0,
    "thorough": 5400.0,
}

#: Concurrent scans across the whole process. Low on purpose: nmap is
#: bandwidth-hungry and the failure mode of an unbounded pool is a lab
#: network that stops working while somebody debugs the wrong thing.
MAX_CONCURRENT = 2

MAX_STDERR = 4000

_slots: Optional[asyncio.Semaphore] = None


class ScannerError(RuntimeError):
    """The scan could not be run, or ran and failed."""


class ScannerMissing(ScannerError):
    """nmap is not installed.

    Its own type so a caller can say "nmap is not installed" rather than
    "scan failed", which is the difference between a five-second fix and an
    afternoon.
    """


class ScannerTimeout(ScannerError):
    """The scan ran past its ceiling and was killed.

    A subclass rather than a flag because the HTTP layer maps it to 504
    while a non-zero exit maps to 502, and those are genuinely different
    facts: one says "this host is slow or filtered, try a smaller profile",
    the other says "nmap refused the arguments". Discriminating on a
    substring of the message would work until someone rewords the message.
    """


@dataclass
class ScanRun:
    """What happened, in enough detail to explain a disappointing result."""

    target: str
    profile: str
    argv: tuple[str, ...] = ()
    returncode: int = -1
    duration_s: float = 0.0
    stderr: str = ""
    timed_out: bool = False
    result: Optional[ImportResult] = None

    @property
    def hosts_up(self) -> int:
        return len(self.result.hosts) if self.result else 0

    def as_dict(self) -> dict:
        payload = {
            "target": self.target,
            "profile": self.profile,
            # The exact argv, because an operator reading "0 services found"
            # should be able to see whether -sV was in the command at all.
            "command": list(self.argv),
            "returncode": self.returncode,
            "duration_s": round(self.duration_s, 1),
            "timed_out": self.timed_out,
            "hosts": self.hosts_up,
            "services": sum(len(h.get("services", []))
                            for h in (self.result.hosts.values()
                                      if self.result else [])),
            "warnings": list(self.result.warnings) if self.result else [],
        }
        if self.stderr:
            payload["stderr"] = self.stderr
        return payload


def available() -> Optional[str]:
    """Absolute path to nmap, or None. Resolved rather than assumed.

    Returned rather than raised because "is scanning possible here" is a
    question the UI asks on load to decide whether to offer the button at
    all, and a disabled control with a reason beats one that fails on click.
    """
    return shutil.which(BINARY)


def profile_names() -> list[str]:
    return sorted(PROFILES)


def build_argv(target: str, profile: str, xml_path: str) -> tuple[str, ...]:
    """The command, assembled from a fixed vocabulary plus one address.

    Split out and returned so it can be asserted directly. A test that reads
    the argv this produces is checking the thing that runs; a test that mocks
    the subprocess and checks what it was called with is checking the mock.
    """
    binary = available()
    if binary is None:
        raise ScannerMissing(
            f"{BINARY} is not installed or not on PATH. On Kali: "
            "`sudo apt install nmap`.")
    try:
        flags = PROFILES[profile]
    except KeyError:
        raise ScannerError(
            f"unknown scan profile {profile!r}; "
            f"choose one of {', '.join(profile_names())}") from None

    # Re-validated here even though every current caller validates first.
    # See the module docstring: the ingress that forgets is the one nobody
    # has written yet, and this is where the packets leave.
    address = validate_address(target)

    # `--` before the address so a target that somehow began with a dash
    # cannot be read as a flag. validate_address already refuses those, which
    # makes this the belt to its braces -- and belts are cheap when the
    # failure is "scanned something the operator did not name".
    return (binary, *flags, "-oX", xml_path, "--", address)


async def run(target: str, profile: str = DEFAULT_PROFILE, *,
              timeout: Optional[float] = None) -> ScanRun:
    """Run one scan and parse its XML into evidence payloads.

    Writes XML to a private temp file rather than reading `-oX -` from
    stdout: the file is parsed by the same hardened `parse_nmap_xml` an
    uploaded file goes through, doctype guard and host caps included, so
    there is one parser and one set of bounds rather than two. `mkstemp` is
    0600, which is the RC-25 lesson applied before it becomes a finding.
    """
    global _slots
    if _slots is None:
        _slots = asyncio.Semaphore(MAX_CONCURRENT)

    handle, xml_path = tempfile.mkstemp(prefix="reconkg-scan-", suffix=".xml")
    os.close(handle)

    # `build_argv` is inside the try, not above it. It raises on a bad
    # address, an unknown profile and a missing nmap -- all three reachable
    # from an authenticated caller -- and every one of those refusals used to
    # leave a 0-byte file behind, once per attempt, growing without bound.
    # That is RC-03/RC-18 in a directory instead of a dict.
    try:
        argv = build_argv(target, profile, xml_path)
        run_record = ScanRun(target=target, profile=profile, argv=argv)
        limit = (timeout if timeout is not None
                 else TIMEOUTS.get(profile, 1800.0))
        started = time.monotonic()

        async with _slots:
            log.info("scanning %s with profile %s", target, profile)
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            try:
                _out, err = await asyncio.wait_for(process.communicate(),
                                                   timeout=limit)
            except asyncio.TimeoutError:
                run_record.timed_out = True
                process.kill()
                # Reap it. An unawaited killed child becomes a zombie held
                # by the event loop for the life of the process.
                await process.wait()
                err = b""
            run_record.returncode = process.returncode if not \
                run_record.timed_out else -1
            run_record.stderr = err.decode("utf-8", "replace")[:MAX_STDERR]
        run_record.duration_s = time.monotonic() - started

        if run_record.timed_out:
            raise ScannerTimeout(
                f"scan of {target} exceeded {limit:.0f}s and was stopped. "
                f"Profile {profile!r} is the slow one -- try 'quick'.")
        if run_record.returncode != 0:
            raise ScannerError(
                f"nmap exited {run_record.returncode}: "
                f"{run_record.stderr.strip()[:300] or 'no error output'}")

        try:
            run_record.result = parse_nmap_xml(xml_path)
        except (FileNotFoundError, ValueError) as exc:
            # nmap exited 0 and produced nothing parseable. Rare, and worth
            # naming rather than surfacing as "0 hosts": a silent empty
            # result reads exactly like a clean host.
            raise ScannerError(
                f"nmap exited 0 but its XML was unusable: {exc}") from None
        return run_record
    finally:
        try:
            os.unlink(xml_path)
        except OSError:                     # pragma: no cover - defensive
            pass


# --------------------------------------------------------------------------- #
# whatweb -- the producer `HttpAppStage` was written for and never given
#
# `stages.HttpAppStage` declares `tool = "whatweb"`, reads `{"apps": [...]}`
# from the evidence source, and fires only for ports whose service is
# http/https/http-alt. `sources.py` registers whatweb at 0.85 -- above
# nmap-sV's 0.75 and well clear of the 0.45 correlation floor. The slot, the
# module, the planner gap that names it and the reliability ceiling all
# shipped. Nothing ever produced the evidence, so every scan logged
# "web-layer/http-app-probe -> no_data (no web fingerprints)".
#
# It matters because `nmap -sV` reads the opening banner and stops. It sees
# `Server: Microsoft-IIS/10.0` and cannot see that the application behind it
# is Jenkins 2.222 or WordPress 5.8 -- which is where a large share of
# actually exploitable CVEs live, and which this corpus holds.
# --------------------------------------------------------------------------- #

WEB_BINARY = "whatweb"

WEB_TOOL = "whatweb"
"""The evidence tool key, and it must equal `stages.HttpAppStage.tool`.

Filed under any other name, the producer writes evidence the consumer never
reads and the stage goes on reporting no_data -- which is the failure this
whole addition exists to end, reintroduced by a typo.
"""

#: Passive: one GET per URL, no path guessing. whatweb's `-a 3` and `-a 4`
#: brute-force directories and plugin paths, which is a materially different
#: level of contact with the target. That gets its own review rather than a
#: quiet edit to this constant -- the same rule the nmap profiles are held to.
WEB_AGGRESSION = "1"

WEB_TIMEOUT = 300.0
MAX_APPS_PER_PORT = 32
HTTP_SERVICES = ("http", "https", "http-alt")


def web_available() -> Optional[str]:
    """Absolute path to whatweb, or None. Same contract as `available()`."""
    return shutil.which(WEB_BINARY)


def _web_url(address: str, port: int, service: str,
             tunnel: Optional[str] = None) -> str:
    """One URL, built from validated parts and nothing else.

    The scheme comes from nmap's `tunnel` attribute FIRST and the service
    name second, and getting that order wrong is not a cosmetic error.

    nmap reports a TLS web service as `service="http" tunnel="ssl"` -- the
    name alone says http. Reading only the name fetched port 443 as
    `http://host:443/`, Apache answered `400 Bad Request`, and the page
    title recorded as the application's identity was therefore
    "400 Bad Request". On the host that exposed this, the real title was
    "rConfig - Configuration Management", which was the one thing the whole
    web pass existed to find.

    The port number is deliberately not consulted: 8443 is not always TLS
    and 443 is not always HTTPS. The tunnel is what nmap actually observed.
    """
    number = int(port)
    if not 1 <= number <= 65535:
        raise ScannerError(f"port out of range: {port}")
    secure = (tunnel or "").strip().lower() == "ssl" or service == "https"
    return f"{'https' if secure else 'http'}://{address}:{number}/"


def build_web_argv(target: str, ports, json_path: str) -> tuple[str, ...]:
    """The whatweb command, from a fixed vocabulary plus validated URLs.

    `ports` is a sequence of `(port, service)` as the graph knows them. The
    address is re-validated here for the reason the module docstring gives:
    this is where packets leave, and the ingress that forgets to check is
    always the one nobody has written yet.
    """
    binary = web_available()
    if binary is None:
        raise ScannerMissing(
            f"{WEB_BINARY} is not installed or not on PATH. On Kali: "
            "`sudo apt install whatweb`.")

    address = validate_address(target)
    urls = []
    for entry in ports:
        # Two- or three-tuples: (port, service) or (port, service, tunnel).
        # Tolerant because the tunnel is the fix for a bug the two-tuple
        # form caused, and a caller that has not been updated should degrade
        # to the old behaviour rather than raise.
        port, service = entry[0], entry[1]
        tunnel = entry[2] if len(entry) > 2 else None
        if service not in HTTP_SERVICES:
            # The caller here is our own route, so this is not a filter on
            # hostile input. It is a guard against a bug that would
            # otherwise surface as a silent empty result: the stage consumes
            # http ports only, so anything else fingerprinted here is work
            # nothing will ever read.
            raise ScannerError(
                f"{service!r} on port {port} is not an HTTP service; "
                f"whatweb runs only against {', '.join(HTTP_SERVICES)}")
        urls.append(_web_url(address, port, service, tunnel))
    if not urls:
        raise ScannerError("no HTTP services to fingerprint")

    return (binary, "-a", WEB_AGGRESSION, "--no-errors",
            f"--log-json={json_path}", "--", *urls)


def _port_from_url(url: str) -> Optional[int]:
    """The port whatweb reported back, or None.

    Read from whatweb's own `target` rather than assumed from the order the
    URLs went in: whatweb follows redirects and reorders results, so position
    is not identity. Attaching a Jenkins fingerprint to the wrong port is
    worse than missing it.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.port:
            return int(parsed.port)
        if parsed.scheme == "https":
            return 443
        if parsed.scheme == "http":
            return 80
    except (ValueError, TypeError):
        return None
    return None


def parse_whatweb(raw: str) -> list[dict]:
    """whatweb's JSON into the `apps` shape `HttpAppStage` consumes.

    Only plugins reporting a **version** become fingerprints. A plugin
    without one is a detection, not a product claim, and promoting it would
    manufacture precisely the `product_only` matches that gave an IIS 10.0
    host two 2008 ActiveX CVEs. The version is also load-bearing rather than
    decorative: `build_leads` skips an unversioned fingerprint outright, so
    an entry without one is work that produces nothing.

    Both shapes whatweb emits are accepted -- a JSON array, and one object
    per line -- because which you get depends on the version installed, and
    a parser written against the one on the author's machine is how RC-22
    happened.
    """
    text = (raw or "").strip()
    if not text:
        return []
    try:
        blob = json.loads(text)
        records = blob if isinstance(blob, list) else [blob]
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    apps: list[dict] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        port = _port_from_url(str(record.get("target") or ""))
        if port is None:
            continue
        plugins = record.get("plugins")
        if not isinstance(plugins, dict):
            continue
        found = 0
        for name, detail in plugins.items():
            if found >= MAX_APPS_PER_PORT:
                break
            if not isinstance(detail, dict):
                continue
            versions = [str(v).strip() for v in (detail.get("version") or [])
                        if str(v).strip()]
            if not versions:
                continue
            strings = [str(s).strip() for s in (detail.get("string") or [])
                       if str(s).strip()]
            apps.append({
                "port": port,
                "product": str(name).strip()[:120],
                "version": versions[0][:64],
                "banner": strings[0][:300] if strings else None,
                # Under whatweb's registered 0.85 ceiling, which clamps it
                # regardless. Stated here rather than left to the stage's
                # default so the number is visible where the claim is made.
                "confidence": 0.8,
            })
            found += 1

        # The application's own name, which is not a versioned product claim
        # and is the most valuable thing on the page.
        #
        # Only versioned plugins become CVE-matchable fingerprints above --
        # correctly, since `build_leads` skips an unversioned one and a
        # product-only match manufactures noise. But that rule discarded the
        # `Title` plugin, and on a real host `Title` read
        # "rConfig - Configuration Management" while every versioned plugin
        # reported Apache, OpenSSL, PHP and jQuery. The stack was captured
        # and the application was thrown away -- the exact gap
        # `NO_WEB_APPLICATION` was added to complain about, with the answer
        # already in hand.
        #
        # Recorded ambiguous and below the correlation floor on purpose. A
        # page title is a claim about identity, not about version, and it
        # must name the application without ever producing a lead on its own.
        title = plugins.get("Title")
        if isinstance(title, dict) and found < MAX_APPS_PER_PORT:
            names = [str(s).strip() for s in (title.get("string") or [])
                     if str(s).strip()]
            if names:
                apps.append({
                    "port": port,
                    "product": names[0][:120],
                    "version": None,
                    "banner": names[0][:300],
                    "ambiguous": True,
                    "confidence": 0.4,
                })
    return apps


async def run_web(target: str, ports, *,
                  timeout: Optional[float] = None):
    """Fingerprint the web layer on ports already known to speak HTTP.

    Returns `(ScanRun, apps)` rather than just the apps, so a caller can
    report what was run even when it found nothing. An empty result and a
    failed run look identical otherwise, and telling those two apart is the
    distinction this project exists to preserve.
    """
    global _slots
    if _slots is None:
        _slots = asyncio.Semaphore(MAX_CONCURRENT)

    handle, json_path = tempfile.mkstemp(prefix="reconkg-web-",
                                         suffix=".json")
    os.close(handle)
    started = time.monotonic()
    try:
        argv = build_web_argv(target, ports, json_path)
        record = ScanRun(target=target, profile=WEB_TOOL, argv=argv)
        limit = timeout if timeout is not None else WEB_TIMEOUT

        async with _slots:
            log.info("web-fingerprinting %s on %d port(s)", target, len(ports))
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            try:
                _out, err = await asyncio.wait_for(process.communicate(),
                                                   timeout=limit)
            except asyncio.TimeoutError:
                record.timed_out = True
                process.kill()
                await process.wait()
                err = b""
            record.returncode = -1 if record.timed_out else process.returncode
            record.stderr = err.decode("utf-8", "replace")[:MAX_STDERR]
        record.duration_s = time.monotonic() - started

        if record.timed_out:
            raise ScannerTimeout(
                f"whatweb against {target} exceeded {limit:.0f}s and was "
                "stopped")

        try:
            raw = Path(json_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw = ""
        apps = parse_whatweb(raw)

        # whatweb exits non-zero for a target that merely refused the
        # connection, which is a fact about the host and not a failure of the
        # run. The log file decides: readable output with a non-zero exit is
        # reported, silence with a non-zero exit is raised.
        if not apps and record.returncode not in (0, None):
            raise ScannerError(
                f"whatweb exited {record.returncode} and produced no "
                "fingerprints: "
                f"{record.stderr.strip()[:300] or 'no error output'}")
        return record, apps
    finally:
        try:
            os.unlink(json_path)
        except OSError:                     # pragma: no cover - defensive
            pass


# --------------------------------------------------------------------------- #
# `check` -- confirming a lead against the host, without exploiting it
#
# `commands.FIRING_VERBS` is {run, exploit, rerun, rexploit, rcheck} and its
# comment says why `check` is absent: "it probes for applicability without
# exploiting, which is the behaviour this tool is for". That capability was
# designed in and never used.
#
# It is the difference between a ledger of suspicion and a ledger of fact. A
# host produced 97 leads from version inference; the exploit index
# cross-references 3,030 CVEs to Metasploit modules, and for any lead in that
# set `check` answers whether this host actually has it. Ninety-seven maybes
# become three confirmations and ninety-four inferences, which is the whole
# job.
#
# Nothing here composes a firing verb. The setup list is handed to
# `commands._refuse_firing_verbs`, which splits it the way msfconsole splits
# its own `-x` argument (RC-32) rather than the way Python would -- a check
# that tokenises differently from the thing it protects is a check that
# agrees only with itself.
# --------------------------------------------------------------------------- #

MSF_BINARY = "msfconsole"
MSF_TIMEOUT = 300.0
"""msfconsole takes tens of seconds just to start. The ceiling is generous
because the alternative -- killing it during load -- looks identical to a
target that did not answer."""

#: Ordered, and the order is load-bearing. "does not support check" contains
#: the word "check" and "cannot reliably check exploitability" contains
#: "exploitability"; testing for a verdict before ruling out a non-answer
#: reads MSF declining to answer as an answer.
_CHECK_VERDICTS = (
    ("unsupported", ("does not support check", "no check implemented")),
    ("unknown", ("cannot reliably check", "check failed", "check raised")),
    ("vulnerable", ("appears to be vulnerable", "is vulnerable",
                    "target is vulnerable")),
    ("safe", ("is not exploitable", "is not vulnerable",
              "target is not vulnerable", "the target is safe")),
)


@dataclass
class CheckResult:
    """One module's verdict on one service. Never an exploitation attempt."""

    target: str
    port: int
    cve_id: str
    module: str
    verdict: str = "unknown"
    detail: str = ""
    duration_s: float = 0.0
    argv: tuple = ()

    @property
    def confirmed(self) -> bool:
        return self.verdict == "vulnerable"

    def as_dict(self) -> dict:
        return {"target": self.target, "port": self.port,
                "cve_id": self.cve_id, "module": self.module,
                "verdict": self.verdict, "detail": self.detail[:600],
                "duration_s": round(self.duration_s, 1),
                "command": list(self.argv), "confirmed": self.confirmed}


def msf_available() -> Optional[str]:
    """Absolute path to msfconsole, or None."""
    return shutil.which(MSF_BINARY)


def parse_check_output(text: str) -> tuple[str, str]:
    """msfconsole's check output as (verdict, the line that decided it).

    Returning the deciding line rather than only the verdict, because an
    operator who disagrees with a verdict needs to see what it was read
    from. A bare "safe" that cannot be traced back to a sentence is a claim
    with no provenance, which is the thing this project refuses everywhere
    else.
    """
    lowered = (text or "").lower()
    for verdict, needles in _CHECK_VERDICTS:
        for needle in needles:
            index = lowered.find(needle)
            if index == -1:
                continue
            start = lowered.rfind("\n", 0, index) + 1
            end = lowered.find("\n", index)
            line = (text[start:end] if end != -1 else text[start:]).strip()
            return verdict, line[:400]
    return "unknown", ""


def build_check_argv(module: str, target: str, port: int) -> tuple[str, ...]:
    """The msfconsole line that asks, and cannot tell it to fire.

    `module` must have come from the operator's own Metasploit index --
    `catalog.py` is emphatic that a fabricated path which half-matches a CVE
    costs an afternoon and teaches an operator to distrust the tool. This
    validates the shape; the caller is responsible for the provenance, and
    the route only passes paths it read out of the index.
    """
    from .commands import _refuse_firing_verbs, validate_module_path

    binary = msf_available()
    if binary is None:
        raise ScannerMissing(
            f"{MSF_BINARY} is not installed or not on PATH. On Kali: "
            "`sudo apt install metasploit-framework`.")

    path = validate_module_path(module)
    address = validate_address(target)
    number = int(port)
    if not 1 <= number <= 65535:
        raise ScannerError(f"port out of range: {port}")

    setup = [f"use {path}", f"set RHOSTS {address}", f"set RPORT {number}",
             "check", "exit"]
    # Splits the way msfconsole splits, not the way Python does. `check` is
    # deliberately not a firing verb; anything that became one -- through a
    # module path carrying a `;`, or a future edit to this list -- is refused
    # here rather than discovered on a live host.
    _refuse_firing_verbs(setup, path)
    return (binary, "-q", "-x", "; ".join(setup))


async def run_check(module: str, target: str, port: int, cve_id: str = "", *,
                    timeout: Optional[float] = None) -> CheckResult:
    """Ask one Metasploit module whether this host is actually vulnerable.

    A non-zero exit is not a verdict. msfconsole exits non-zero for a module
    that failed to load as readily as for one that answered, so the verdict
    comes from the output and the exit status only colours the detail --
    reading an exit code as "safe" would turn a broken run into a clean bill
    of health, which is the single worst outcome this function has.
    """
    global _slots
    if _slots is None:
        _slots = asyncio.Semaphore(MAX_CONCURRENT)

    argv = build_check_argv(module, target, port)
    result = CheckResult(target=target, port=int(port), cve_id=cve_id,
                         module=module, argv=argv)
    limit = timeout if timeout is not None else MSF_TIMEOUT
    started = time.monotonic()

    async with _slots:
        log.info("checking %s against %s:%s", module, target, port)
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(process.communicate(),
                                              timeout=limit)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            result.duration_s = time.monotonic() - started
            raise ScannerTimeout(
                f"check of {module} against {target}:{port} exceeded "
                f"{limit:.0f}s. msfconsole is slow to start; raise the "
                "timeout before concluding anything about the host.")
    result.duration_s = time.monotonic() - started

    text = (out or b"").decode("utf-8", "replace") + \
           (err or b"").decode("utf-8", "replace")
    result.verdict, result.detail = parse_check_output(text)
    if result.verdict == "unknown" and not result.detail:
        result.detail = (text.strip()[-400:] or
                         f"msfconsole exited {process.returncode} with no "
                         "readable output")
    return result
