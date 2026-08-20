"""Runnable example: fallback routing, confidence decay, ledger output.

    python -m reconkg.demo

Scenario baked into the fixtures:
  * the SYN sweep times out            -> falls back to the connect sweep
  * the banner probe can't version 80  -> ambiguous, fingerprint downgraded,
                                          falls back to the deep probe
  * the deep probe resolves 2.4.49     -> whatweb corroborates it independently
  * correlation ranks Apache RCE above the OpenSSH enumeration lead
"""

from __future__ import annotations

import asyncio
import logging

from .engine import DiscoveryEngine, default_pipeline
from .stages import EvidenceSource
from .store import ChangeEvent, TargetStore

TARGET = "10.10.10.42"

FIXTURES = {
    # SYN sweep: the path is filtered, adapter reports a timeout.
    ("nmap-sS", TARGET): TimeoutError("no response to SYN probes"),

    # Connect sweep: slower, but it gets through.
    ("nmap-sT", TARGET): {"ports": [
        {"number": 22, "state": "open", "confidence": 0.9},
        {"number": 80, "state": "open", "confidence": 0.9},
        {"number": 445, "state": "filtered", "confidence": 0.6},
    ]},

    # Banner probe: SSH is clean, HTTP gives a product with no version.
    ("nmap-sV", TARGET): {"services": [
        {"port": 22, "service": "ssh", "product": "OpenSSH",
         "version": "7.4", "confidence": 0.85,
         "banner": "SSH-2.0-OpenSSH_7.4"},
        {"port": 80, "service": "http", "product": "Apache httpd",
         "version": None, "ambiguous": True, "confidence": 0.7,
         "banner": "Server: Apache"},
    ]},

    # Deep probe: protocol-specific probing pins the version down.
    ("nmap-sV-intensity9", TARGET): {"services": [
        {"port": 22, "service": "ssh", "product": "OpenSSH",
         "version": "7.4", "confidence": 0.9},
        {"port": 80, "service": "http", "product": "Apache httpd",
         "version": "2.4.49", "confidence": 0.88,
         "banner": "Server: Apache/2.4.49 (Unix)"},
    ]},

    # Web layer: an independent tool agreeing raises confidence further.
    ("whatweb", TARGET): {"apps": [
        {"port": 80, "product": "Apache httpd", "version": "2.4.49",
         "cpe": "cpe:/a:apache:http_server:2.4.49", "confidence": 0.75},
    ]},
}


PRINCIPALS = {
    # Two genuinely separate scanner hosts. Independence is measured here,
    # not on the tool name -- see reconkg.sources.
    "nmap-sS": "scanner-a", "nmap-sT": "scanner-a",
    "nmap-sV": "scanner-a", "nmap-sV-intensity9": "scanner-a",
    "whatweb": "scanner-b",
}


def build_evidence() -> EvidenceSource:
    evidence = EvidenceSource()
    for (tool, address), data in FIXTURES.items():
        evidence.put(tool, address, data,
                     principal=PRINCIPALS.get(tool, "unknown"))
    return evidence


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)-18s %(message)s",
        datefmt="%H:%M:%S")

    store = TargetStore()
    engine = DiscoveryEngine(store, build_evidence(), default_pipeline())

    async def watcher(event: ChangeEvent) -> None:
        interesting = {"fingerprint.confidence_changed", "lead.added",
                       "stage.finished"}
        if event.kind.value in interesting:
            print(f"  [event] {event.kind.value:32} {event.path or event.target}"
                  f"  {event.payload}")

    store.subscribe(watcher)

    print(f"\n=== discovery pipeline: {TARGET} ===\n")
    report = await engine.run(TARGET)

    print("\n=== attempt history ===")
    for a in report.attempts:
        print(f"  {a.slot:16} {a.stage:16} {a.tool:22} "
              f"{a.outcome:10} {a.duration_ms:7.2f}ms  {a.detail}")
    if report.exhausted_slots:
        print(f"  EXHAUSTED: {report.exhausted_slots}")

    print("\n=== prioritised attack-surface ledger ===")
    if not report.ledger:
        print("  (no leads above confidence threshold)")
    for r in report.ledger:
        print(f"  {r.priority:5.3f}  {r.cve_id:16} cvss {r.cvss:4.1f}  "
              f"{r.protocol}:{r.port} {r.product} {r.version}")
        print(f"         conf {r.fingerprint_confidence:.2f} "
              f"via {', '.join(r.corroborated_by)} | {r.rationale}")

    print("\n=== provenance trail for the Apache fingerprint ===")
    host = store.get(TARGET)
    port80 = host.find_port(80)
    for fp in port80.service.fingerprints:
        print(f"  {fp.key}  ambiguous={fp.ambiguous}  conf={fp.confidence}")
        for p in fp.provenance_log:
            print(f"      {p.observed_at:%H:%M:%S} {p.source_tool:22} "
                  f"{p.principal:10} {p.confidence:5.3f}  {p.note or ''}")

    print(f"\n{len(store.event_log)} change events emitted.\n")


if __name__ == "__main__":
    asyncio.run(main())
