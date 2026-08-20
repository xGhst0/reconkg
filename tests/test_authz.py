"""RC-13: authorisation tiers. Authentication existed; roles did not."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from reconkg.auth import AuthError, Role, load_principals

VIEWER_T, SCANNER_T, OPERATOR_T = "v" * 24, "s" * 24, "o" * 24
TOKENS = (f"analyst:viewer:{VIEWER_T},"
          f"box1:scanner:{SCANNER_T},"
          f"lead:operator:{OPERATOR_T}")
VIEWER = {"Authorization": f"Bearer {VIEWER_T}"}
SCANNER = {"Authorization": f"Bearer {SCANNER_T}"}
OPERATOR = {"Authorization": f"Bearer {OPERATOR_T}"}

TARGET = "10.10.10.42"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("RECONKG_TOKENS", TOKENS)
    from reconkg import app as app_module
    app_module.state = app_module.AppState()
    with TestClient(app_module.app) as c:
        c.post("/api/targets", json={"address": TARGET}, headers=OPERATOR)
        yield c


# --------------------------------------------------------------------------- #
# Role parsing
# --------------------------------------------------------------------------- #

def test_roles_are_ordered():
    assert Role.ADMIN.satisfies(Role.VIEWER)
    assert Role.OPERATOR.satisfies(Role.SCANNER)
    assert not Role.VIEWER.satisfies(Role.SCANNER)
    assert not Role.SCANNER.satisfies(Role.OPERATOR)
    assert Role.VIEWER.satisfies(Role.VIEWER)


def test_role_is_parsed_from_the_token_string():
    principals = load_principals(TOKENS)
    by_name = {p.name: p.role for p in principals.values()}
    assert by_name == {"analyst": Role.VIEWER, "box1": Role.SCANNER,
                       "lead": Role.OPERATOR}


def test_two_field_form_still_works_and_grants_operator():
    """Silently downgrading an existing deployment to read-only would look
    like a broken scanner rather than a policy change."""
    principals = load_principals("legacy:" + "x" * 20)
    assert next(iter(principals.values())).role is Role.OPERATOR


def test_unknown_role_is_rejected_by_name():
    with pytest.raises(AuthError, match="unknown role 'wizard'"):
        load_principals("someone:wizard:" + "x" * 20)


def test_too_many_fields_is_rejected():
    with pytest.raises(AuthError, match="malformed"):
        load_principals("a:viewer:" + "x" * 20 + ":10.0.0.0/8:extra")


# --------------------------------------------------------------------------- #
# Enforcement
# --------------------------------------------------------------------------- #

def test_viewer_can_read_everything(client):
    for path in ["/api/health", "/api/targets", f"/api/targets/{TARGET}",
                 "/api/modules", "/api/catalog", f"/api/targets/{TARGET}/plan"]:
        assert client.get(path, headers=VIEWER).status_code == 200, path


def test_viewer_cannot_submit_evidence_or_scan(client):
    r = client.post("/api/evidence", headers=VIEWER, json={
        "tool": "nmap-sT", "address": TARGET, "data": {}})
    assert r.status_code == 403
    assert "viewer" in r.json()["detail"]
    assert client.post(f"/api/targets/{TARGET}/scan",
                       headers=VIEWER).status_code == 403


def test_scanner_can_submit_evidence_and_scan(client):
    assert client.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sT", "address": TARGET,
        "data": {"ports": [{"number": 80, "state": "open"}]}}
    ).status_code == 201
    assert client.post(f"/api/targets/{TARGET}/scan",
                       headers=SCANNER).status_code == 200


def test_scanner_cannot_define_new_targets(client):
    """The unattended lab box is the credential most likely to leak; it
    should not be able to invent scope."""
    r = client.post("/api/targets", json={"address": "10.0.0.99"},
                    headers=SCANNER)
    assert r.status_code == 403
    assert client.get("/api/targets/10.0.0.99", headers=VIEWER).status_code == 404


def test_operator_can_do_everything_below_it(client):
    assert client.post("/api/targets", json={"address": "10.0.0.55"},
                       headers=OPERATOR).status_code == 201
    assert client.post("/api/evidence", headers=OPERATOR, json={
        "tool": "nmap-sT", "address": "10.0.0.55",
        "data": {"ports": [{"number": 22, "state": "open"}]}}
    ).status_code == 201


def test_403_is_distinguished_from_401(client):
    """A real credential with the wrong role is a config fix, not a hunt
    for a bad token -- the status code should say which."""
    assert client.post("/api/targets", json={"address": "10.0.0.77"}
                       ).status_code == 401
    assert client.post("/api/targets", json={"address": "10.0.0.77"},
                       headers=SCANNER).status_code == 403


def test_evidence_response_reports_the_acting_role(client):
    body = client.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sT", "address": TARGET,
        "data": {"ports": [{"number": 80, "state": "open"}]}}).json()
    assert body["principal"] == "box1"
    assert body["role"] == "scanner"


def test_provenance_records_the_principal_name_not_the_object(client):
    client.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sT", "address": TARGET,
        "data": {"ports": [{"number": 80, "state": "open"}]}})
    client.post(f"/api/targets/{TARGET}/scan", headers=SCANNER)
    graph = client.get(f"/api/targets/{TARGET}", headers=VIEWER).json()
    principals = {p["provenance"]["principal"] for p in graph["ports"]}
    assert principals == {"box1"}


def test_viewer_may_still_open_a_websocket(client):
    ticket = client.post("/api/ws-ticket", headers=VIEWER).json()["ticket"]
    with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
        assert ws.receive_json()["type"] == "hello"
