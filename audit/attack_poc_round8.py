"""Round 8 Red Cell PoCs: observability, snapshots, console, host.updated.

Same contract as `attack_poc.py`: each check returns
`(finding_id, confirmed: bool, evidence: str)` and the runner prints a table.

One deliberate difference in transport. `attack_poc.py` drives a separately
launched uvicorn over the network. Every finding here needs to read process
state the wire does not expose -- the `Metrics` label registry, the ticket
table, snapshot file modes on disk, the store after a lifespan restore -- so
these run the *same* ASGI app in-process through `TestClient`. Nothing is
stubbed: the real middleware, the real lifespan (restore + autosave), the real
auth dependencies and the real WebSocket handshake all execute. A finding that
needed a network to be true would be marked theoretical; none of them do.

Run from the repo root:  python3 audit/attack_poc_round8.py
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ADMIN_T = "a" * 24
VIEWER_T = "v" * 24
SCANNER_T = "s" * 24
OPERATOR_T = "o" * 24

ADMIN = {"Authorization": f"Bearer {ADMIN_T}"}
VIEWER = {"Authorization": f"Bearer {VIEWER_T}"}
SCANNER = {"Authorization": f"Bearer {SCANNER_T}"}
OPERATOR = {"Authorization": f"Bearer {OPERATOR_T}"}

# A viewer scoped to one subnet, and -- the interesting one -- an *admin*
# scoped to the same subnet. The role grammar allows it; the question is
# whether anything honours it.
TOKENS = (f"adm:admin:{ADMIN_T},"
          f"view:viewer:{VIEWER_T}:10.10.10.0/24,"
          f"scan:scanner:{SCANNER_T},"
          f"lead:operator:{OPERATOR_T}")
SCOPED_ADMIN_TOKENS = (f"adm:admin:{ADMIN_T}:10.10.10.0/24,"
                       f"lead:operator:{OPERATOR_T}")


def banner(msg):
    print(f"\n{'=' * 72}\n{msg}\n{'=' * 72}")


def _app(tokens: str = TOKENS, *, snapshot_dir: str | None = None):
    """A fresh coordinator with a fresh module-global AppState.

    `reconkg.app.state` is built at import time and the correlation middleware
    captures *that* object's `Metrics`, so a test that rebinds `app.state`
    after import instruments an orphan. These PoCs therefore rebuild the app
    module from scratch under the environment they need.
    """
    for name in [n for n in list(sys.modules) if n.startswith("reconkg")]:
        del sys.modules[name]
    os.environ["RECONKG_TOKENS"] = tokens
    if snapshot_dir is None:
        os.environ.pop("RECONKG_SNAPSHOT_DIR", None)
    else:
        os.environ["RECONKG_SNAPSHOT_DIR"] = snapshot_dir
    from fastapi.testclient import TestClient
    from reconkg import app as app_module
    return app_module, TestClient(app_module.app)


# --------------------------------------------------------------------------- #
# RC-23  Metric cardinality squatting -- unauthenticated
# --------------------------------------------------------------------------- #

def rc23_cardinality_squat():
    """An anonymous client can blind /metrics permanently.

    `CorrelationMiddleware` counts every request before authentication runs --
    it has to, or 401s would be invisible -- and `_route_label` falls back to
    the *raw path* for any request the router did not match. A 404 therefore
    mints a new series whose label the attacker chose.

    The cardinality cap (RC-03/RC-18's lesson, correctly applied) bounds the
    memory: past 128 distinct label tuples everything folds into `_other`. But
    the cap is first-come, and an anonymous actor gets there first. After 200
    junk 404s the budget is spent, and every *real* route from then on is
    folded into `_other` -- the metric survives, the signal does not, and
    there is no eviction and no reset short of a restart.
    """
    app_module, client = _app()
    with client as c:
        family = app_module.state.metrics._families[
            "reconkg_http_requests_total"]
        before = family.distinct_series
        for i in range(200):
            c.get(f"/zz{i}")            # anonymous, unmatched route
        squatted = family.distinct_series
        c.get("/api/health", headers=ADMIN)
        health_series = [k for k in family.series if "health" in str(k)]
        body = c.get("/metrics", headers=ADMIN).text
        junk_lines = sum(1 for line in body.splitlines() if "/zz" in line)
    confirmed = bool(squatted > before and not health_series)
    return ("RC-23", confirmed,
            f"anon 404s took {squatted} series (was {before}); "
            f"/api/health got its own series: {bool(health_series)}; "
            f"{junk_lines} attacker-chosen lines in /metrics")


# --------------------------------------------------------------------------- #
# RC-24  Snapshot restore bypasses the store's validation chokepoint
# --------------------------------------------------------------------------- #

def rc24_restore_bypasses_validation():
    """RC-07's fix is skipped by a door that did not exist when it was made.

    RC-07 moved address validation onto `TargetStore.ensure_host` with the
    reasoning that the store is the only writer, so per-ingress validation is
    a losing game. `persistence.load` assigns `store._hosts[host.address]`
    directly. It is a writer, and it is not the store's write path: no
    `validate_address`, and no `MAX_TARGETS`.

    Anyone who can write the snapshot file -- same-uid local access, a
    restored backup, a snapshot directory on shared storage -- puts arbitrary
    strings into graph keys, and from there into `ChangeEvent.path` broadcast
    to every analyst window. That is RC-04 for the third time.
    """
    tmp = Path(tempfile.mkdtemp(prefix="rc24-"))
    hostile = "10.0.0.1\r\nX-Injected: yes"
    try:
        app_module, client = _app(snapshot_dir=str(tmp))
        with client as c:
            c.post("/api/targets", json={"address": "10.10.10.42"},
                   headers=OPERATOR)
        # Leaving the context runs the lifespan shutdown, which flushes a
        # final snapshot because the store is dirty.
        snap = app_module.state.snapshots.snapshot_files(newest_first=True)[0]

        conn = sqlite3.connect(str(snap))
        document = json.loads(
            conn.execute("SELECT document FROM hosts").fetchone()[0])
        document["address"] = hostile
        conn.execute("INSERT INTO hosts(address, document, updated_at) "
                     "VALUES(?,?,?)",
                     (hostile, json.dumps(document), "2026-01-01"))
        conn.commit()
        conn.close()

        # Second boot: the lifespan restore reads the tampered file.
        app_module, client = _app(snapshot_dir=str(tmp))
        with client as c:
            listed = [row["address"]
                      for row in c.get("/api/targets", headers=OPERATOR).json()]
            at_api = c.post("/api/targets", json={"address": hostile},
                            headers=OPERATOR).status_code
        landed = hostile in listed
        return ("RC-24", landed,
                f"API refuses the same address (HTTP {at_api}); restore "
                f"accepted it: "
                f"{[a for a in listed if a != '10.10.10.42']!r}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# RC-25  Snapshot file permissions
# --------------------------------------------------------------------------- #

def rc25_snapshot_world_readable():
    """The whole engagement, mode 0644, in a 0755 directory.

    `persistence.connect` lets sqlite3 create the file with the default mode
    and `_write_atomically` calls `directory.mkdir()` with the default mode.
    On any multi-user host every local account can read every host, port,
    service, fingerprint and lead in the graph -- the confidentiality half of
    the scope model, defeated by `cat`. Snapshots are the first component in
    this system that writes the graph anywhere durable, so this is a new
    exposure rather than an inherited one.
    """
    tmp = Path(tempfile.mkdtemp(prefix="rc25-"))
    try:
        snap_dir = tmp / "snaps"
        app_module, client = _app(snapshot_dir=str(snap_dir))
        with client as c:
            c.post("/api/targets", json={"address": "10.10.10.42"},
                   headers=OPERATOR)
        path = app_module.state.snapshots.snapshot_files(newest_first=True)[0]
        file_mode = stat.S_IMODE(path.stat().st_mode)
        dir_mode = stat.S_IMODE(snap_dir.stat().st_mode)
        readable = bool(file_mode & (stat.S_IROTH | stat.S_IRGRP))
        content = path.read_bytes()
        return ("RC-25", readable,
                f"file {oct(file_mode)} in dir {oct(dir_mode)}; "
                f"{len(content)} bytes containing "
                f"{b'10.10.10.42' in content and 'the graph' or 'no graph'}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# RC-26  WebSocket ticket eviction as a cross-principal DoS
# --------------------------------------------------------------------------- #

def rc26_ticket_eviction_dos():
    """RC-18's cap turned an unbounded dict into a shared, evictable one.

    `issue_ticket` drops the *oldest outstanding ticket* when the 512 cap is
    reached, explicitly so an issuance flood cannot lock a legitimate operator
    out. It has the opposite effect: the table is global, `/api/ws-ticket`
    needs only VIEWER, and nothing rate-limits it. 512 requests from the
    lowest-privilege credential in the system evict every other principal's
    unredeemed ticket, and their handshake closes 1008.
    """
    app_module, client = _app()
    from reconkg.auth import MAX_OUTSTANDING_TICKETS, current_authenticator

    def redeem(c, ticket):
        try:
            with c.websocket_connect(f"/ws?ticket={ticket}"):
                return "connected"
        except Exception as exc:
            return type(exc).__name__

    with client as c:
        control = c.post("/api/ws-ticket", headers=OPERATOR).json()["ticket"]
        baseline = redeem(c, control)
        victim = c.post("/api/ws-ticket", headers=OPERATOR).json()["ticket"]
        codes = {c.post("/api/ws-ticket", headers=VIEWER).status_code
                 for _ in range(MAX_OUTSTANDING_TICKETS + 5)}
        outstanding = len(current_authenticator()._tickets)
        after = redeem(c, victim)
    confirmed = baseline == "connected" and after != "connected"
    return ("RC-26", confirmed,
            f"viewer issued {MAX_OUTSTANDING_TICKETS + 5} tickets "
            f"(codes {sorted(codes)}, {outstanding} outstanding); operator "
            f"handshake {baseline!r} -> {after!r}")


# --------------------------------------------------------------------------- #
# RC-27  host.updated fan-out with no rate limit
# --------------------------------------------------------------------------- #

def rc27_host_updated_amplification():
    """A new event on a hot path, on the one write route nothing throttles.

    Cycle 8 made re-observing a known host emit `host.updated` -- correct, and
    the reason autosave and metrics see re-observations at all. But
    `POST /api/targets` is the only graph-write route that never calls
    `state.limiter.check`: RC-17 added the limiter to `/api/evidence` and then
    to `/scan`, and `/api/targets` was cheap and idempotent so nobody went
    back. It is neither of those things now. One byte-identical POST fans out
    to every connected analyst window, and to the autosave, and to the metrics
    subscriber, at whatever rate the caller likes.
    """
    app_module, client = _app()
    with client as c:
        c.post("/api/targets", json={"address": "10.10.10.42"},
               headers=OPERATOR)
        ticket = c.post("/api/ws-ticket", headers=OPERATOR).json()["ticket"]
        with c.websocket_connect(f"/ws?ticket={ticket}") as ws:
            ws.receive_json()                       # hello
            ws.receive_json()                       # replayed host.added
            before = app_module.state.store.events_emitted
            # Only the accepted POSTs fan out, so only those are waited for --
            # once the route grew a rate limit (RC-27's fix) a fixed count of
            # 100 receives blocked forever on messages that were never sent.
            statuses = [c.post("/api/targets", json={"address": "10.10.10.42"},
                               headers=OPERATOR).status_code
                        for _ in range(100)]
            codes = set(statuses)
            accepted = sum(1 for s in statuses if s == 201)
            received = [ws.receive_json() for _ in range(accepted)]
        emitted = app_module.state.store.events_emitted - before
    kinds = {m.get("kind") for m in received}
    confirmed = codes == {201} and emitted == 100
    return ("RC-27", confirmed,
            f"100 repeat POSTs -> codes {sorted(codes)} (no 429), "
            f"{emitted} events emitted, {len(received)} messages delivered "
            f"per client, kinds={sorted(kinds)}")


# --------------------------------------------------------------------------- #
# RC-28  Scope is not enforced on the telemetry describing the graph
# --------------------------------------------------------------------------- #

def rc28_scoped_admin_reads_all_targets():
    """The /metrics docstring's own argument, applied one step further.

    It reasons that a scope-restricted *viewer* must not see label values
    carrying target addresses, "scope enforced on the graph but not on the
    telemetry describing it", and gates on ADMIN. But `Principal.scope` is
    orthogonal to role -- `adm:admin:<tok>:10.10.10.0/24` parses -- and the
    metrics handlers never call `require_scope`. The same principal is refused
    a direct read of an out-of-scope host with 403 and is then handed every
    address in the engagement as a metric label.
    """
    app_module, client = _app(SCOPED_ADMIN_TOKENS)
    with client as c:
        for address in ("10.10.10.42", "192.0.2.7", "secret.corp.example"):
            c.post("/api/targets", json={"address": address},
                   headers=OPERATOR)
            c.post(f"/api/targets/{address}/scan", headers=OPERATOR)
        direct = c.get("/api/targets/192.0.2.7", headers=ADMIN).status_code
        listed = [r["address"]
                  for r in c.get("/api/targets", headers=ADMIN).json()]
        body = c.get("/metrics", headers=ADMIN).text
        leaked = sorted({line.split('target="')[1].split('"')[0]
                         for line in body.splitlines() if 'target="' in line})
    confirmed = direct == 403 and len(leaked) > len(listed)
    return ("RC-28", confirmed,
            f"scoped admin: direct read of out-of-scope host HTTP {direct}, "
            f"/api/targets={listed}, but /metrics labels expose {leaked}")


# --------------------------------------------------------------------------- #
# RC-29  A declared metric nothing increments
# --------------------------------------------------------------------------- #

def rc29_auth_failures_never_counted():
    """`reconkg_auth_failures_total` is registered, documented and dead.

    The stated purpose of this cycle's observability work was to answer
    questions seven audit rounds could not, one of which was "which principal
    is hammering the ingress". Rate-limit rejections are counted at both call
    sites. Authentication and authorisation refusals are raised as
    HTTPExceptions inside `auth.py`, which does not import `Metrics`, so
    credential-stuffing against the ingress reads as zero forever -- and a
    dashboard permanently reading zero is worse than no dashboard, because
    somebody trusts it.
    """
    app_module, client = _app()
    with client as c:
        for i in range(10):
            c.get("/api/health", headers={"Authorization": f"Bearer bad{i}"})
        for i in range(5):
            c.get("/metrics", headers=VIEWER)       # 403: role too low
        c.get("/api/targets")                       # 401: no credential
        total = app_module.state.metrics.total("reconkg_auth_failures_total")
        http = app_module.state.metrics
        four01 = http.counter_value("reconkg_http_requests_total",
                                    method="GET", route="/api/health",
                                    status="401")
    return ("RC-29", total == 0.0,
            f"16 refused requests (10x401 + 5x403 + 1x401); "
            f"reconkg_auth_failures_total={total}; the generic HTTP counter "
            f"saw {four01} of them but carries no principal or reason")


# --------------------------------------------------------------------------- #
# RC-30  /api/health is unscoped telemetry at VIEWER
# --------------------------------------------------------------------------- #

def rc30_health_counts_are_global():
    """The oldest surviving telemetry route was never scoped either.

    RC-16 filtered `/api/targets` to the caller's scope. `/api/health` reports
    `hosts`, `events_retained` and `events_emitted` across the whole graph to
    any VIEWER. A principal confined to one subnet learns how many hosts the
    engagement holds in total, and -- by polling `events_emitted` -- when
    someone is scanning a host it is not allowed to see. Small, but it is the
    same class as RC-28 and it predates this cycle, which is why nobody
    reviewing the new metrics endpoints looked at it.
    """
    app_module, client = _app()
    with client as c:
        for address in ("10.10.10.42", "192.0.2.7", "secret.corp.example"):
            c.post("/api/targets", json={"address": address},
                   headers=OPERATOR)
        health = c.get("/api/health", headers=VIEWER).json()
        listed = c.get("/api/targets", headers=VIEWER).json()
        before = health["events_emitted"]
        c.post("/api/targets/192.0.2.7/scan", headers=SCANNER)
        after = c.get("/api/health", headers=VIEWER).json()["events_emitted"]
    confirmed = health["hosts"] > len(listed) and after > before
    return ("RC-30", confirmed,
            f"scoped viewer sees {len(listed)} of {health['hosts']} hosts, "
            f"and watches events_emitted move {before} -> {after} for a scan "
            f"of a host outside its scope")


# --------------------------------------------------------------------------- #
# Negative results -- attacks that did not work
# --------------------------------------------------------------------------- #

def rc8a_correlation_id_injection():
    """Client-supplied request ids: the sanitisation claim holds.

    Two independent controls. `CorrelationMiddleware.trust_incoming_id`
    defaults False and `app.py` does not override it, so the header is not
    read at all; and `_clean_id` rejects by character class (RC-04's rule)
    with a 128-char bound, so even with the flag on, CRLF, quotes, braces and
    a 10 MB value cannot forge a log record. Verified against the formatter
    directly rather than by reading the flag.
    """
    app_module, client = _app()
    from reconkg.observability import (JsonFormatter, _clean_id,
                                       correlation_scope)
    hostile = ['abc\r\n{"level":"INFO","message":"forged"}',
               'x" , "admin": true, "y":"', "a" * 10_000,
               "‮gnitset", "\x00\x1b[31m", "../../etc/passwd"]
    lines = []
    for raw in hostile:
        with correlation_scope(request_id=raw):
            record = logging.LogRecord("t", logging.INFO, "p", 1, "hello",
                                       (), None)
            lines.append(JsonFormatter().format(record))
    one_object_each = all(len(line.splitlines()) == 1 for line in lines)
    parses = all(json.loads(line)["message"] == "hello" for line in lines)
    bounded = all(len(json.loads(line)["request_id"]) <= 128 for line in lines)
    with client as c:
        echoed = c.get("/api/health",
                       headers={**OPERATOR, "x-request-id": "abc\r\nevil"}
                       ).headers.get("x-request-id", "")
    confirmed = not (one_object_each and parses and bounded
                     and "evil" not in echoed)
    return ("RC-8A", confirmed,
            f"6 hostile ids: single-line={one_object_each} parses={parses} "
            f"bounded={bounded}; header ignored, echoed id={echoed!r}")


def rc8b_prometheus_exposition_injection():
    """Forging a metric series through a label value: refused.

    `_clean_label_value` strips control characters (so CRLF cannot start a new
    sample line) and `_escape_label` escapes backslash and double quote, so a
    path like `/a%0d%0anmap_evil{x="1"} 99` lands as one escaped label value
    rather than a second series.
    """
    app_module, client = _app()
    with client as c:
        for path in ['/x%22y', '/a%0d%0areconkg_forged%7Bx%3D%221%22%7D%2099',
                     '/%5Cq', '/caf%C3%A9']:
            c.get(path)
        body = c.get("/metrics", headers=ADMIN).text
    forged = [l for l in body.splitlines() if l.startswith("reconkg_forged")]
    multiline = [l for l in body.splitlines()
                 if l and not l.startswith("#") and "\r" in l]
    sample = [l for l in body.splitlines()
              if l.startswith("reconkg_http_requests_total") and "x" in l
              and "y" in l][:1]
    return ("RC-8B", bool(forged or multiline),
            f"forged series={forged}, raw-CR lines={len(multiline)}; "
            f"quotes escaped, control chars stripped -- sample {sample}")


def rc8c_metrics_role_gate():
    """Both metrics routes really are ADMIN-only. Nothing to see."""
    app_module, client = _app()
    with client as c:
        codes = {name: (c.get("/metrics", headers=h).status_code,
                        c.get("/api/metrics", headers=h).status_code)
                 for name, h in (("viewer", VIEWER), ("scanner", SCANNER),
                                 ("operator", OPERATOR), ("anon", {}))}
        admin_codes = (c.get("/metrics", headers=ADMIN).status_code,
                       c.get("/api/metrics", headers=ADMIN).status_code)
    leaked = [n for n, pair in codes.items() if 200 in pair]
    return ("RC-8C", bool(leaked),
            f"{codes}; admin={admin_codes}")


def rc8d_console_authorisation():
    """The console honours no roles and no scope -- and that is defensible.

    It is not an authorisation bypass because there is nothing to bypass: a
    `Console` owns private `Workspace` objects, each with its own
    `TargetStore` and `EvidenceSource`. It never touches `app.state.store`,
    never constructs a `SnapshotManager`, and so cannot read the persisted
    graph either. `principal="operator"` is a provenance *label* on evidence
    the operator themself imported, not a credential.

    What it does have is the local operator's own file access -- `import` and
    `catalog load` read any path they are given. That is the same authority
    the shell already grants. Asserted here so the claim is checked rather
    than assumed: if someone later wires the console onto the shared store or
    the snapshot directory, this flips to confirmed.
    """
    app_module, client = _app()
    with client as c:
        c.post("/api/targets", json={"address": "10.10.10.42"},
               headers=OPERATOR)
    from reconkg.console import Console
    console = Console(principal="attacker", autoload_catalog=False)
    try:
        shared_store = console.ws.store is app_module.state.store
        visible = console.execute("targets")
        has_snapshots = hasattr(console, "snapshots")
        no_creds = console.execute("search recon")
    finally:
        console.close()
    confirmed = shared_store or has_snapshots or "10.10.10.42" in visible
    return ("RC-8D", confirmed,
            f"console store is app store: {shared_store}; snapshot manager: "
            f"{has_snapshots}; sees API graph: "
            f"{'10.10.10.42' in visible}; runs uncredentialed: "
            f"{'Matching Modules' in no_creds}")


CHECKS = [rc23_cardinality_squat, rc24_restore_bypasses_validation,
          rc25_snapshot_world_readable, rc26_ticket_eviction_dos,
          rc27_host_updated_amplification, rc28_scoped_admin_reads_all_targets,
          rc29_auth_failures_never_counted, rc30_health_counts_are_global,
          rc8a_correlation_id_injection,
          rc8b_prometheus_exposition_injection, rc8c_metrics_role_gate,
          rc8d_console_authorisation]


def main():
    logging.disable(logging.CRITICAL)   # the app logs JSON to stderr by design
    banner("RED CELL PoC RUN -- ROUND 8")
    rows = []
    for check in CHECKS:
        try:
            rows.append(check())
        except Exception as exc:
            rows.append((check.__name__, "ERROR", f"{type(exc).__name__}: {exc}"))
    for fid, confirmed, evidence in rows:
        mark = ("CONFIRMED" if confirmed is True
                else "no finding" if confirmed is False else str(confirmed))
        print(f"{fid:8} {mark:11} {evidence}")


if __name__ == "__main__":
    main()
