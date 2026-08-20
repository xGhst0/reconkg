"""Regression tests for Red Cell findings RC-01 .. RC-06.

Each test fails against the pre-audit code and passes after remediation.
"""

from __future__ import annotations

import asyncio
import random
import string

import pytest
from fastapi.testclient import TestClient

from reconkg import auth
from reconkg.auth import (AuthError, Authenticator, load_principals,
                          validate_address)
from reconkg.engine import DiscoveryEngine, StageSlot
from reconkg.models import (MAX_PROVENANCE_HEAD, MAX_PROVENANCE_TAIL,
                            Fingerprint, Provenance)
from reconkg.sources import (UNREGISTERED_RELIABILITY, SourceRegistry,
                             default_registry)
from reconkg.stages import (DiscoveryStage, EvidenceSource, Outcome, PortObs,
                            StageResult)
from reconkg.store import MAX_EVENT_LOG, ChangeEvent, EventKind, TargetStore
from reconkg.vulnref import (CorrelationConfig, VulnEntry, build_leads,
                             compare_versions, parse_version,
                             version_satisfies)

TOKENS = "analyst:" + "a" * 24 + ",scanner:" + "b" * 24
ANALYST = {"Authorization": "Bearer " + "a" * 24}
SCANNER = {"Authorization": "Bearer " + "b" * 24}


# --------------------------------------------------------------------------- #
# RC-01  Declared confidence is advisory, not authoritative
# --------------------------------------------------------------------------- #

def test_rc01_registry_clamps_declared_confidence():
    reg = default_registry()
    # nmap-sV is a banner grab: ceiling 0.75, so a claimed 1.0 lands at 0.75.
    assert reg.effective_confidence("nmap-sV", 1.0) == 0.75
    # A submitter may still lower its own confidence.
    assert reg.effective_confidence("nmap-sV", 0.4) == 0.30


def test_rc01_unregistered_tool_cannot_reach_the_correlation_floor():
    reg = SourceRegistry()
    effective = reg.effective_confidence("totally-legit-scanner", 1.0)
    assert effective == UNREGISTERED_RELIABILITY
    assert effective < CorrelationConfig().min_confidence

    fp = Fingerprint(product="Apache httpd", version="2.4.49",
                     provenance=Provenance(source_tool="totally-legit-scanner",
                                           principal="mallory",
                                           confidence=effective))
    entry = VulnEntry("CVE-2021-41773", "Apache RCE", "apache",
                      ((">=", "2.4.49"), ("<=", "2.4.49")), 9.8)
    assert build_leads(fp, [entry], CorrelationConfig()) == []


# --------------------------------------------------------------------------- #
# RC-01b  Corroboration forgery
# --------------------------------------------------------------------------- #

def test_rc01b_tool_name_rotation_yields_no_corroboration_bonus():
    """The original primitive: one actor, many tool labels, compounded trust."""
    forged = Fingerprint(product="Apache httpd", version="2.4.49",
                         provenance=Provenance(source_tool="nmap-sV",
                                               principal="mallory",
                                               confidence=0.4))
    for tool in ["nmap-sT", "whatweb", "nessus", "qualys", "openvas"]:
        forged.observe(Provenance(source_tool=tool, principal="mallory",
                                  confidence=0.4))

    honest = Fingerprint(product="Apache httpd", version="2.4.49",
                         provenance=Provenance(source_tool="nmap-sV",
                                               principal="scanner-a",
                                               confidence=0.4))
    honest.observe(Provenance(source_tool="whatweb", principal="scanner-b",
                              confidence=0.4))

    assert forged.confidence == 0.4          # six labels, one opinion
    assert honest.confidence > forged.confidence
    assert len(forged.corroborating_tools) == 6  # labels are still recorded
    assert len(forged.corroborating_principals) == 1


# --------------------------------------------------------------------------- #
# RC-02  Malformed evidence must not kill the pipeline
# --------------------------------------------------------------------------- #

class HostileStage(DiscoveryStage):
    """Emits observations that fail model validation."""
    name, technique, tool = "hostile", "stub", "nmap-sS"
    timeout_s = 1.0

    async def run(self, address, evidence, context):
        return StageResult(Outcome.SUCCESS, "hostile batch", [
            PortObs(number=99999),        # out of range -> ValidationError
            PortObs(number=0),            # out of range
            PortObs(number=80, state="wide-open"),  # bad enum -> ValueError
            PortObs(number=443),          # the one good observation
        ], [443])


@pytest.mark.asyncio
async def test_rc02_bad_observations_are_rejected_individually():
    store = TargetStore()
    engine = DiscoveryEngine(store, EvidenceSource(),
                             [StageSlot(HostileStage(), label="slot")])
    report = await engine.run("192.0.2.1")          # must not raise
    ports = [p.number for p in store.get("192.0.2.1").ports]
    assert ports == [443]                            # good one survived
    assert report.finished_at is not None
    assert report.attempts[0].outcome == "success"


# --------------------------------------------------------------------------- #
# RC-03  Bounded growth
# --------------------------------------------------------------------------- #

def test_rc03_provenance_log_is_capped_and_counts_elisions():
    fp = Fingerprint(product="Apache httpd",
                     provenance=Provenance(source_tool="nmap-sV",
                                           principal="scanner-a",
                                           confidence=0.5))
    for i in range(500):
        fp.observe(Provenance(source_tool="nmap-sV", principal="scanner-a",
                              confidence=0.5, note=f"obs {i}"))
    assert len(fp.provenance_log) <= MAX_PROVENANCE_HEAD + MAX_PROVENANCE_TAIL
    assert fp.elided_observations > 0
    # The origin of the node is preserved, not overwritten.
    assert fp.provenance_log[0].note is None


@pytest.mark.asyncio
async def test_rc03_event_log_is_a_ring_buffer():
    store = TargetStore()
    for i in range(MAX_EVENT_LOG + 250):
        await store.emit(ChangeEvent(kind=EventKind.STAGE_STARTED,
                                     target="192.0.2.2", payload={"i": i}))
    assert len(store.event_log) == MAX_EVENT_LOG
    assert store.events_emitted == MAX_EVENT_LOG + 250
    assert store.event_log[-1].payload["i"] == MAX_EVENT_LOG + 249


# --------------------------------------------------------------------------- #
# RC-04  Address validation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", [
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "10.0.0.1\r\nX-Injected: yes",
    "10.0.0.1\nSet-Cookie: x=1",
    "host name with spaces",
    "a" * 254,
    "",
    "   ",
    "-leading-hyphen.example.com",
    "10.0.0.1;drop",
    "\x00null",
])
def test_rc04_hostile_addresses_are_rejected(bad):
    with pytest.raises(ValueError):
        validate_address(bad)


@pytest.mark.parametrize("good,expected", [
    ("10.10.10.42", "10.10.10.42"),
    ("192.0.2.1", "192.0.2.1"),
    ("2001:db8::1", "2001:db8::1"),
    ("Example.COM", "example.com"),
    ("host-1.sub.example.com", "host-1.sub.example.com"),
])
def test_rc04_legitimate_addresses_survive(good, expected):
    assert validate_address(good) == expected


# --------------------------------------------------------------------------- #
# RC-05  Concurrent scans of one target
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_rc05_concurrent_scans_of_one_target_are_serialised():
    from reconkg.demo import TARGET, build_evidence
    from reconkg.engine import default_pipeline

    store = TargetStore()
    engine = DiscoveryEngine(store, build_evidence(), default_pipeline())
    reports = await asyncio.gather(*[engine.run(TARGET) for _ in range(10)])

    assert all(r.finished_at is not None for r in reports)
    host = store.get(TARGET)
    numbers = [p.number for p in host.ports]
    assert len(numbers) == len(set(numbers))           # no duplicate ports
    leads = [(l.cve_id, l.matched_fingerprint_id) for l in host.all_leads()]
    assert len(leads) == len(set(leads))               # no duplicate leads


# --------------------------------------------------------------------------- #
# RC-06  Authentication
# --------------------------------------------------------------------------- #

def test_rc06_missing_token_config_is_fatal_not_permissive():
    with pytest.raises(AuthError):
        load_principals("")
    with pytest.raises(AuthError):
        load_principals("analyst:short")          # below MIN_TOKEN_LEN
    with pytest.raises(AuthError):
        load_principals("nocolon")
    with pytest.raises(AuthError):                # shared credential
        load_principals("a:" + "x" * 20 + ",b:" + "x" * 20)


def test_rc06_authenticator_resolves_principal_from_token():
    a = Authenticator(load_principals(TOKENS))
    assert a.from_header("Bearer " + "a" * 24).name == "analyst"
    for bad in [None, "", "Bearer wrong", "Basic " + "a" * 24, "a" * 24]:
        with pytest.raises(AuthError):
            a.from_header(bad)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("RECONKG_TOKENS", TOKENS)
    from reconkg import app as app_module
    app_module.state = app_module.AppState()
    with TestClient(app_module.app) as c:
        yield c


def test_rc06_every_route_requires_a_credential(client):
    routes = [
        ("get", "/api/health", None),
        ("get", "/api/targets", None),
        ("get", "/api/targets/10.10.10.42", None),
        ("post", "/api/targets", {"address": "10.10.10.42"}),
        ("post", "/api/evidence",
         {"tool": "nmap-sT", "address": "10.10.10.42", "data": {}}),
        ("post", "/api/targets/10.10.10.42/scan", None),
        ("get", "/api/targets/10.10.10.42/ledger", None),
    ]
    for method, path, body in routes:
        r = getattr(client, method)(path, json=body) if body \
            else getattr(client, method)(path)
        assert r.status_code == 401, f"{method.upper()} {path} was {r.status_code}"


def test_rc06_websocket_rejects_anonymous_connection(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()


def test_rc06_websocket_accepts_a_single_use_ticket(client):
    ticket = client.post("/api/ws-ticket", headers=ANALYST).json()["ticket"]
    with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
        assert ws.receive_json()["type"] == "hello"


def test_rc12_raw_token_in_query_string_is_refused(client):
    """A standing credential in a URL leaks into logs and history."""
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws?token={'a' * 24}") as ws:
            ws.receive_json()


def test_rc12_ticket_is_single_use(client):
    from starlette.websockets import WebSocketDisconnect
    ticket = client.post("/api/ws-ticket", headers=ANALYST).json()["ticket"]
    with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
        ws.receive_json()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
            ws.receive_json()


def test_rc12_ticket_endpoint_itself_requires_auth(client):
    assert client.post("/api/ws-ticket").status_code == 401


def test_rc12_expired_ticket_is_refused(client, monkeypatch):
    from reconkg import auth as auth_module
    from starlette.websockets import WebSocketDisconnect
    ticket = client.post("/api/ws-ticket", headers=ANALYST).json()["ticket"]
    real = auth_module.time.monotonic
    monkeypatch.setattr(auth_module.time, "monotonic",
                        lambda: real() + auth_module.TICKET_TTL_SECONDS + 5)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
            ws.receive_json()


def test_rc04_api_rejects_hostile_address(client):
    r = client.post("/api/targets", json={"address": "<script>x</script>"},
                    headers=ANALYST)
    assert r.status_code == 422
    r = client.get("/api/targets/..%2f..%2fetc%2fpasswd", headers=ANALYST)
    assert r.status_code in (400, 404)


def test_rc01_end_to_end_forgery_is_defeated(client):
    """The full RC-01/RC-01b chain, through the real API."""
    target = "203.0.113.10"
    client.post("/api/targets", json={"address": target}, headers=SCANNER)
    client.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sT", "address": target,
        "data": {"ports": [{"number": 80, "state": "open", "confidence": 1.0}]}})
    # One principal, three tool labels, all claiming maximum confidence.
    for tool in ["nmap-sV", "nmap-sV-intensity9", "whatweb"]:
        body = {"services": [{"port": 80, "service": "http",
                              "product": "Apache httpd", "version": "2.4.49",
                              "confidence": 1.0}]} if "sV" in tool else \
               {"apps": [{"port": 80, "product": "Apache httpd",
                          "version": "2.4.49", "confidence": 1.0}]}
        client.post("/api/evidence", headers=SCANNER,
                    json={"tool": tool, "address": target, "data": body})

    report = client.post(f"/api/targets/{target}/scan", headers=SCANNER).json()
    top = report["ledger"][0]
    # A lead still appears -- one authenticated scanner saying "Apache 2.4.49"
    # is legitimate evidence -- but it cannot claim independent corroboration
    # and cannot reach the priority a genuinely corroborated finding would.
    assert top["independent_principals"] == ["scanner"]
    assert top["priority"] < 1.0
    graph = client.get(f"/api/targets/{target}", headers=ANALYST).json()
    fp = graph["ports"][0]["service"]["fingerprints"][0]
    assert fp["provenance"]["confidence"] <= 0.9
    assert fp["provenance"]["declared_confidence"] == 1.0


def test_rc02_end_to_end_malformed_evidence_returns_200_not_500(client):
    target = "203.0.113.11"
    client.post("/api/targets", json={"address": target}, headers=SCANNER)
    client.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sS", "address": target,
        "data": {"ports": [{"number": 99999, "state": "open"}]}})
    r = client.post(f"/api/targets/{target}/scan", headers=SCANNER)
    assert r.status_code == 200


def test_evidence_for_unknown_target_is_refused(client):
    r = client.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sS", "address": "198.51.100.7", "data": {}})
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Comparator fuzzing
# --------------------------------------------------------------------------- #

REAL_BANNERS = [
    "2.4.49", "2.4.50", "1.0.1f", "7.4p1", "9.3p2", "2.4.6-rhel", "8.2p1",
    "1.1.1k", "2.15.0", "5.3.18", "0.9.8zh", "2.4.41-4ubuntu3.14",
    "3.0.0-beta1", "10.0", "1", "2021.11.1", "4.6.4",
]


def test_comparator_is_a_total_order_on_real_banners():
    for a in REAL_BANNERS:
        assert compare_versions(a, a) == 0
        for b in REAL_BANNERS:
            assert compare_versions(a, b) == -compare_versions(b, a)


def test_comparator_is_transitive_on_real_banners():
    ordered = sorted(REAL_BANNERS,
                     key=lambda v: [t for t in parse_version(v)])
    for i in range(len(ordered) - 1):
        assert compare_versions(ordered[i], ordered[i + 1]) <= 0


def test_fuzz_comparator_never_raises_unexpectedly():
    rng = random.Random(1337)
    alphabet = string.printable
    for _ in range(4000):
        raw = "".join(rng.choice(alphabet)
                      for _ in range(rng.randint(0, 24)))
        parse_version(raw)                    # must never raise
        try:
            version_satisfies(raw, "<", "2.4.49")
        except ValueError:
            pass                              # documented rejection


def test_fuzz_no_versionless_string_matches_a_constrained_cve():
    """A banner with no digits must never satisfy a version constraint --
    that would silently mark every unparseable service as vulnerable."""
    rng = random.Random(99)
    entry = VulnEntry("CVE-2021-41773", "Apache RCE", "apache",
                      ((">=", "2.4.49"), ("<=", "2.4.49")), 9.8)
    for _ in range(1000):
        raw = "".join(rng.choice(string.ascii_letters + "-_. ")
                      for _ in range(rng.randint(1, 16)))
        fp = Fingerprint(product="Apache httpd", version=raw,
                         provenance=Provenance(source_tool="nmap-sV",
                                               principal="scanner-a",
                                               confidence=0.9))
        assert build_leads(fp, [entry], CorrelationConfig()) == []
