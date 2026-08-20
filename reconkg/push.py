"""Push a parsed nmap scan into a running coordinator over its own API.

Both halves of this already existed and nothing joined them.
`importers.parse_nmap_xml` turns an nmap run into per-host evidence payloads,
and `/api/evidence` accepts exactly that shape. But the importer's only
caller is `console.cmd_import`, and RC-8D established that each console
`Workspace` owns a private `TargetStore` and never touches
`app.state.store` -- so a console import never reaches the graph the web UI
serves. The page has no file input either. An operator holding an nmap XML
and looking at the UI had no supported way to get one into the other, and
the honest answer was "hand-write the JSON", which is not a workflow.

    python -m reconkg.push ~/scans/host.xml --scan

This is that joint and deliberately nothing more. It adds no parser, no
route and no trust surface: it reuses the project's own importer and posts
through the same authenticated, scope-checked, rate-limited ingress a
scanner unit would use. Evidence is filed under the importer's own tool keys
so ports and service guesses keep the separate reliability ceilings RC-01
gave them -- a version guess must not inherit a port sweep's credibility.

**It opens no connections to the hosts in the file.** The only address it
contacts is the coordinator's, loopback by default. Pushing a scan of
10.10.10.42 sends nothing whatever to 10.10.10.42; nmap already did the
touching, and this moves bytes that are already on disk.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from .importers import parse_nmap_xml

log = logging.getLogger("reconkg.push")

DEFAULT_URL = "http://127.0.0.1:8765"
TOKEN_ENV = "RECONKG_TOKEN"
URL_ENV = "RECONKG_URL"
USER_AGENT = "reconkg-push/1.0"

# A 429 here is not an error. The limiter refills steadily and the server
# says how long to wait, so waiting is the correct response -- an import of
# forty hosts will legitimately hit the bucket. Bounded so a misconfigured
# limit cannot turn one command into an unattended overnight loop.
MAX_RETRIES = 5
MAX_WAIT = 60.0


class PushError(RuntimeError):
    pass


def _detail(body) -> str:
    if isinstance(body, dict):
        return str(body.get("detail") or body.get("message") or body)[:300]
    return str(body)[:300]


def _retry_after(body) -> float:
    """Honour the server's own figure, bounded. Falls back to a short wait.

    Bounded because `Retry-After` is caller-visible server state and a wrong
    or hostile value should cost a pause, not the rest of the evening.
    """
    raw = body.get("retry_after") if isinstance(body, dict) else None
    try:
        return max(0.5, min(float(raw), MAX_WAIT))
    except (TypeError, ValueError):
        return 2.0


def _request(url: str, token: str, payload: Optional[dict] = None,
             timeout: int = 30) -> tuple[int, dict]:
    """One API call. Returns (status, body); raises only on transport failure.

    A non-2xx comes back rather than raising because each caller decides per
    status: 404 on evidence means the target was never created, and 429 is a
    wait rather than a failure. Collapsing those into one exception would
    lose the distinction that decides what to do next.
    """
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json",
                 "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8") or "{}"
            return response.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace") or "{}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"detail": raw[:300]}
        if not isinstance(body, dict):
            body = {"detail": str(body)[:300]}
        body.setdefault("retry_after", exc.headers.get("Retry-After"))
        return exc.code, body
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise PushError(
            f"cannot reach the coordinator at {url}: {exc}. Is "
            "`python -m reconkg.app` running, and is --url right?") from None


def _send(url: str, token: str, payload: dict, what: str) -> dict:
    for attempt in range(1, MAX_RETRIES + 1):
        status, body = _request(url, token, payload)
        if 200 <= status < 300:
            return body
        if status == 429 and attempt < MAX_RETRIES:
            wait = _retry_after(body)
            log.info("rate limited on %s, waiting %.0fs", what, wait)
            time.sleep(wait)
            continue
        if status == 401:
            raise PushError(
                f"{what}: HTTP 401 -- the token was rejected. Set "
                f"{TOKEN_ENV} or pass --token; the app prints one at startup.")
        if status == 403:
            raise PushError(
                f"{what}: HTTP 403 -- the credential is valid but its role or "
                f"scope forbids this. Pushing needs `operator` (it defines "
                f"targets as well as submitting evidence). {_detail(body)}")
        raise PushError(f"{what}: HTTP {status} {_detail(body)}")
    raise PushError(f"{what}: still rate limited after {MAX_RETRIES} tries")


def push(path: str | Path, url: str, token: str, *,
         run_scan: bool = False) -> dict:
    """Parse one nmap XML and stage every host in it through the API.

    The target is created before its evidence because `/api/evidence`
    answers 404 for an unknown address -- the store is the single writer and
    will not accept evidence for a host nobody declared.
    """
    result = parse_nmap_xml(path)
    base = url.rstrip("/")
    report = {"source": str(path), "hosts": [], "ports": 0, "services": 0,
              "scanned": [], "warnings": list(result.warnings)}

    addresses = list(result.hosts) + [
        a for a in result.discovered_only if a not in result.hosts]

    for address in addresses:
        payload = result.hosts.get(address, {})
        _send(f"{base}/api/targets", token, {"address": address},
              f"create target {address}")
        report["hosts"].append(address)

        if payload.get("ports"):
            _send(f"{base}/api/evidence", token,
                  {"tool": result.port_tool, "address": address,
                   "data": {"ports": payload["ports"]}},
                  f"ports for {address}")
            report["ports"] += len(payload["ports"])

        if payload.get("services"):
            _send(f"{base}/api/evidence", token,
                  {"tool": result.service_tool, "address": address,
                   "data": {"services": payload["services"]}},
                  f"services for {address}")
            report["services"] += len(payload["services"])

        if run_scan:
            # Staging evidence does not correlate it; the pipeline is what
            # turns a fingerprint into a lead. Optional rather than automatic
            # because a scan draws five times an evidence POST from the same
            # bucket, and importing forty hosts should not silently cost
            # forty pipeline runs.
            body = _send(f"{base}/api/targets/{address}/scan", token, {},
                         f"scan {address}")
            report["scanned"].append(
                {"address": address, "leads": len(body.get("ledger", []))})

    return report


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m reconkg.push",
        description="Load an nmap XML file into a running reconkg over its "
                    "API. Contacts the coordinator only, never the hosts in "
                    "the file.")
    parser.add_argument("scan", help="path to an nmap -oX XML file")
    parser.add_argument("--url", default=os.environ.get(URL_ENV, DEFAULT_URL),
                        help=f"coordinator base URL (or set {URL_ENV})")
    parser.add_argument("--token", default=os.environ.get(TOKEN_ENV, ""),
                        help=f"bearer token (or set {TOKEN_ENV}); the app "
                             "prints one at startup")
    parser.add_argument("--scan", dest="run_scan", action="store_true",
                        help="run the correlation pipeline after loading")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(message)s")

    token = args.token.strip()
    if not token:
        print(f"no token: pass --token or set {TOKEN_ENV}. `python -m "
              "reconkg.app` prints one at startup.", file=sys.stderr)
        return 2

    try:
        report = push(args.scan, args.url, token, run_scan=args.run_scan)
    except FileNotFoundError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        # The importer refuses a file that is not nmap XML, and says why.
        print(f"refused {args.scan}: {exc}", file=sys.stderr)
        return 2
    except PushError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1

    print("\n--- push summary " + "-" * 43)
    print(f"  hosts      {len(report['hosts']):>7,}")
    print(f"  ports      {report['ports']:>7,}")
    print(f"  services   {report['services']:>7,}")
    for warning in report["warnings"]:
        print(f"  [!] {warning}")
    for entry in report["scanned"]:
        print(f"  scanned {entry['address']}: {entry['leads']} lead(s)")
    if not report["hosts"]:
        print("\n  The file parsed but held no usable hosts. A scan of a "
              "down\n  host produces exactly this, and so does an XML from a "
              "run that\n  found nothing.")
        return 1
    if not report["services"]:
        print("\n  No service data: CVE matching needs product and version "
              "strings,\n  so re-scan with `nmap -sV` or no lead can be "
              "produced from this.")
    print(f"\n  loaded into {args.url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
