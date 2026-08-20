"""RC-14 per-target scoping, RC-15 rate limiting, and contradiction detection."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from reconkg.auth import Principal, Role, load_principals
from reconkg.models import Fingerprint, Provenance, Service
from reconkg.planner import Gap, GapPlanner
from reconkg.ratelimit import Bucket, RateLimiter

SCOPED_T, WIDE_T, OP_T = "s" * 24, "w" * 24, "o" * 24
TOKENS = (f"lab1:scanner:{SCOPED_T}:10.10.10.0/24;*.htb,"
          f"wide:scanner:{WIDE_T},"
          f"lead:operator:{OP_T}")
SCOPED = {"Authorization": f"Bearer {SCOPED_T}"}
WIDE = {"Authorization": f"Bearer {WIDE_T}"}
OP = {"Authorization": f"Bearer {OP_T}"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("RECONKG_TOKENS", TOKENS)
    from reconkg import app as app_module
    app_module.state = app_module.AppState()
    with TestClient(app_module.app) as c:
        for address in ("10.10.10.42", "192.0.2.7", "box.htb"):
            c.post("/api/targets", json={"address": address}, headers=OP)
        yield c


def _prov(principal="scanner-a", confidence=0.9, tool="nmap-sV"):
    return Provenance(source_tool=tool, principal=principal,
                      confidence=confidence)


# --------------------------------------------------------------------------- #
# RC-14  Scope matching
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("patterns,address,expected", [
    (("10.10.10.0/24",), "10.10.10.42", True),
    (("10.10.10.0/24",), "10.10.11.42", False),
    (("*.htb",), "box.htb", True),
    (("*.htb",), "boxhtb", False),
    (("*.htb",), "sub.box.htb", True),
    (("10.0.0.5",), "10.0.0.5", True),
    (("10.0.0.5",), "10.0.0.6", False),
    (("10.10.10.0/24",), "box.htb", False),      # hostname vs CIDR
    (("*",), "anything.example.com", True),
    ((), "anything", True),                       # unrestricted
    (("not a pattern/x",), "10.0.0.1", False),    # unparseable, denied
])
def test_scope_matching(patterns, address, expected):
    principal = Principal("p", Role.SCANNER, patterns)
    assert principal.may_touch(address) is expected


def test_scope_parses_from_the_token_entry():
    principals = load_principals(TOKENS)
    by_name = {p.name: p for p in principals.values()}
    assert by_name["lab1"].scope == ("10.10.10.0/24", "*.htb")
    assert by_name["wide"].scope == ()


# --------------------------------------------------------------------------- #
# RC-14  Enforcement
# --------------------------------------------------------------------------- #

def _evidence(address):
    return {"tool": "nmap-sT", "address": address,
            "data": {"ports": [{"number": 80, "state": "open"}]}}


def test_scoped_principal_may_act_inside_its_scope(client):
    assert client.post("/api/evidence", headers=SCOPED,
                       json=_evidence("10.10.10.42")).status_code == 201
    assert client.post("/api/evidence", headers=SCOPED,
                       json=_evidence("box.htb")).status_code == 201


def test_scoped_principal_is_refused_outside_its_scope(client):
    r = client.post("/api/evidence", headers=SCOPED, json=_evidence("192.0.2.7"))
    assert r.status_code == 403
    assert "scoped to" in r.json()["detail"]


def test_scope_applies_to_scanning_too(client):
    assert client.post("/api/targets/192.0.2.7/scan",
                       headers=SCOPED).status_code == 403
    assert client.post("/api/targets/10.10.10.42/scan",
                       headers=SCOPED).status_code == 200


def test_unscoped_principal_is_unaffected(client):
    assert client.post("/api/evidence", headers=WIDE,
                       json=_evidence("192.0.2.7")).status_code == 201


def test_scope_is_checked_before_existence(client):
    """Out-of-scope must not be distinguishable from non-existent by probing:
    both an unknown in-scope host and a known out-of-scope host should not
    leak which targets exist."""
    r = client.post("/api/evidence", headers=SCOPED,
                    json=_evidence("198.51.100.9"))
    assert r.status_code == 403          # not 404


def test_operator_scope_applies_to_target_creation(client, monkeypatch):
    from reconkg import app as app_module
    monkeypatch.setenv("RECONKG_TOKENS",
                       f"lead:operator:{OP_T}:10.10.10.0/24")
    app_module.state = app_module.AppState()
    with TestClient(app_module.app) as c:
        assert c.post("/api/targets", json={"address": "10.10.10.9"},
                      headers=OP).status_code == 201
        assert c.post("/api/targets", json={"address": "1.2.3.4"},
                      headers=OP).status_code == 403


# --------------------------------------------------------------------------- #
# RC-15  Rate limiting
# --------------------------------------------------------------------------- #

def test_bucket_refills_over_time():
    bucket = Bucket(capacity=2, refill_per_second=10)
    assert bucket.take() and bucket.take()
    assert not bucket.take()
    time.sleep(0.25)
    assert bucket.take()


def test_bucket_reports_a_usable_retry_after():
    bucket = Bucket(capacity=1, refill_per_second=2)
    bucket.take()
    assert 0 < bucket.retry_after() <= 0.5


def test_limiter_is_per_principal():
    limiter = RateLimiter(capacity=1, refill_per_second=0.0001)
    assert limiter.check("a")[0] is True
    assert limiter.check("a")[0] is False
    assert limiter.check("b")[0] is True      # b unaffected by a


def test_limiter_table_is_bounded():
    """A limiter that leaks memory keyed on an attacker-influenced value is
    not a defence -- that was RC-03's lesson."""
    limiter = RateLimiter(capacity=5, max_principals=50)
    for i in range(500):
        limiter.check(f"principal-{i}")
    assert len(limiter._buckets) <= 50


def test_evidence_ingress_is_rate_limited(client):
    from reconkg import app as app_module
    app_module.state.limiter = RateLimiter(capacity=3, refill_per_second=0.001)
    codes = [client.post("/api/evidence", headers=WIDE,
                         json=_evidence("192.0.2.7")).status_code
             for _ in range(6)]
    assert codes[:3] == [201, 201, 201]
    assert codes[3:] == [429, 429, 429]


def test_rate_limited_response_carries_retry_after(client):
    from reconkg import app as app_module
    app_module.state.limiter = RateLimiter(capacity=1, refill_per_second=0.5)
    client.post("/api/evidence", headers=WIDE, json=_evidence("192.0.2.7"))
    r = client.post("/api/evidence", headers=WIDE, json=_evidence("192.0.2.7"))
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


def test_one_noisy_principal_does_not_block_another(client):
    from reconkg import app as app_module
    app_module.state.limiter = RateLimiter(capacity=2, refill_per_second=0.001)
    for _ in range(4):
        client.post("/api/evidence", headers=WIDE, json=_evidence("192.0.2.7"))
    assert client.post("/api/evidence", headers=SCOPED,
                       json=_evidence("10.10.10.42")).status_code == 201


# --------------------------------------------------------------------------- #
# Contradiction detection
# --------------------------------------------------------------------------- #

def _service_with(*fingerprints):
    svc = Service(name="http", provenance=_prov())
    svc.fingerprints.extend(fingerprints)
    return svc


def test_two_credible_versions_of_one_product_conflict():
    svc = _service_with(
        Fingerprint(product="Apache httpd", version="2.4.49",
                    provenance=_prov("scanner-a", 0.9)),
        Fingerprint(product="Apache httpd", version="2.4.58",
                    provenance=_prov("scanner-b", 0.85)))
    conflicts = svc.contradictions()
    assert len(conflicts) == 1
    assert {f.version for f in conflicts[0]} == {"2.4.49", "2.4.58"}


def test_different_products_are_not_a_contradiction():
    svc = _service_with(
        Fingerprint(product="Apache httpd", version="2.4.49",
                    provenance=_prov("scanner-a", 0.9)),
        Fingerprint(product="nginx", version="1.24.0",
                    provenance=_prov("scanner-b", 0.9)))
    assert svc.contradictions() == []


def test_an_unversioned_claim_is_unresolved_not_contradictory():
    svc = _service_with(
        Fingerprint(product="Apache httpd", version="2.4.49",
                    provenance=_prov("scanner-a", 0.9)),
        Fingerprint(product="Apache httpd", version=None, ambiguous=True,
                    provenance=_prov("scanner-b", 0.9)))
    assert svc.contradictions() == []


def test_a_weak_claim_does_not_contradict_a_strong_one():
    """Below the correlation floor it generates no leads, so it is noise,
    not a conflict worth an analyst's attention."""
    svc = _service_with(
        Fingerprint(product="Apache httpd", version="2.4.49",
                    provenance=_prov("scanner-a", 0.9)),
        Fingerprint(product="Apache httpd", version="2.4.58",
                    provenance=_prov("mallory", 0.2)))
    assert svc.contradictions() == []


@pytest.mark.asyncio
async def test_planner_surfaces_a_contradiction_with_both_sides():
    from reconkg.models import Host, Port, PortState

    host = Host(address="10.0.0.9", provenance=_prov("operator", 1.0))
    port = Port(number=80, state=PortState.OPEN, provenance=_prov())
    port.service = _service_with(
        Fingerprint(product="Apache httpd", version="2.4.49",
                    provenance=_prov("scanner-a", 0.9)),
        Fingerprint(product="Apache httpd", version="2.4.58",
                    provenance=_prov("scanner-b", 0.85)))
    host.ports.append(port)

    plan = GapPlanner().plan(host)
    conflict = next(r for r in plan if r.gap is Gap.CONTRADICTION)
    assert "Both cannot be true" in conflict.reason
    assert "scanner-a" in conflict.reason and "scanner-b" in conflict.reason
    assert conflict.action == "resolve_conflict"
    assert conflict.priority > 0.8


# --------------------------------------------------------------------------- #
# Round-5 Red Cell findings: RC-16 read scope, RC-17 scan cost, RC-18 tickets
# --------------------------------------------------------------------------- #

def test_rc16_scoped_principal_cannot_read_out_of_scope_hosts(client):
    """Scope covered writes only. Read access is how you learn what to
    attack; restricting writes alone is half a control."""
    assert client.get("/api/targets/192.0.2.7", headers=SCOPED).status_code == 403
    assert client.get("/api/targets/10.10.10.42",
                      headers=SCOPED).status_code == 200


def test_rc16_target_listing_is_filtered_to_scope(client):
    listed = {h["address"] for h in
              client.get("/api/targets", headers=SCOPED).json()}
    assert listed == {"10.10.10.42", "box.htb"}
    assert "192.0.2.7" not in listed
    # An unscoped principal still sees everything.
    wide = {h["address"] for h in
            client.get("/api/targets", headers=WIDE).json()}
    assert "192.0.2.7" in wide


def test_rc16_plan_ledger_and_attempts_respect_scope(client):
    client.post("/api/evidence", headers=WIDE, json=_evidence("192.0.2.7"))
    client.post("/api/targets/192.0.2.7/scan", headers=WIDE)
    for path in ["/api/targets/192.0.2.7/plan",
                 "/api/targets/192.0.2.7/ledger",
                 "/api/targets/192.0.2.7/attempts",
                 "/api/targets/192.0.2.7/handoff/CVE-2021-41773"]:
        assert client.get(path, headers=SCOPED).status_code == 403, path


def test_rc16_websocket_refuses_an_out_of_scope_subscription(client):
    from starlette.websockets import WebSocketDisconnect
    ticket = client.post("/api/ws-ticket", headers=SCOPED).json()["ticket"]
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
                f"/ws?ticket={ticket}&target=192.0.2.7") as ws:
            ws.receive_json()


def test_rc16_unfiltered_websocket_still_only_sees_in_scope_events(client):
    """The subtler half: connecting with no target filter must not become a
    firehose of everything."""
    ticket = client.post("/api/ws-ticket", headers=SCOPED).json()["ticket"]
    with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
        assert ws.receive_json()["type"] == "hello"
        client.post("/api/evidence", headers=WIDE, json=_evidence("192.0.2.7"))
        client.post("/api/targets/192.0.2.7/scan", headers=WIDE)
        client.post("/api/evidence", headers=SCOPED,
                    json=_evidence("10.10.10.42"))
        client.post("/api/targets/10.10.10.42/scan", headers=SCOPED)
        seen = set()
        for _ in range(12):
            msg = ws.receive_json()
            if msg.get("type") == "change":
                seen.add(msg["target"])
            if "10.10.10.42" in seen:
                break
    assert "192.0.2.7" not in seen


def test_rc17_scan_endpoint_draws_from_the_rate_limit(client):
    """The scan runs the whole pipeline; it was exempt from the limiter."""
    from reconkg import app as app_module
    from reconkg.ratelimit import RateLimiter
    app_module.state.limiter = RateLimiter(capacity=6, refill_per_second=0.001)
    codes = [client.post("/api/targets/10.10.10.42/scan",
                         headers=SCOPED).status_code for _ in range(4)]
    assert 429 in codes


def test_rc18_outstanding_tickets_are_capped(client):
    from reconkg.auth import MAX_OUTSTANDING_TICKETS, current_authenticator
    for _ in range(MAX_OUTSTANDING_TICKETS + 200):
        client.post("/api/ws-ticket", headers=WIDE)
    assert len(current_authenticator()._tickets) <= MAX_OUTSTANDING_TICKETS


def test_rc18_a_fresh_ticket_still_works_after_a_flood(client):
    """Eviction drops the oldest, so an issuance flood must not lock out the
    operator who asks next."""
    from reconkg.auth import MAX_OUTSTANDING_TICKETS
    for _ in range(MAX_OUTSTANDING_TICKETS + 50):
        client.post("/api/ws-ticket", headers=WIDE)
    ticket = client.post("/api/ws-ticket", headers=SCOPED).json()["ticket"]
    with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
        assert ws.receive_json()["type"] == "hello"


@pytest.mark.parametrize("form", [
    "10.10.10.042", "010.010.010.042", "0xA0A0A2A", "10.10.10.42.",
])
def test_rc5a_alternate_address_encodings_do_not_bypass_scope(client, form):
    """Scope is checked on the normalised address, so decimal/octal/hex
    spellings cannot smuggle a host past it."""
    r = client.post("/api/evidence", headers=SCOPED,
                    json={"tool": "nmap-sT", "address": form, "data": {}})
    assert r.status_code in (403, 422), f"{form} -> {r.status_code}"


def test_rc5a_whitespace_normalises_rather_than_bypassing(client):
    r = client.post("/api/evidence", headers=SCOPED,
                    json=_evidence("  10.10.10.42  "))
    assert r.status_code == 201        # in scope after normalisation
