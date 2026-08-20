"""Regressions for round-8 findings RC-24, RC-25, RC-29."""

from __future__ import annotations

import json
import os
import stat

import pytest
from fastapi.testclient import TestClient

from reconkg import persistence
from reconkg.models import Host, Provenance

ADMIN_T = "a" * 24
ADMIN = {"Authorization": f"Bearer {ADMIN_T}"}


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("RECONKG_TOKENS", f"admin:admin:{ADMIN_T}")
    monkeypatch.setenv("RECONKG_SNAPSHOT_DIR", str(tmp_path / "snaps"))
    from reconkg import app as app_module
    app_module.state = app_module.AppState()
    with TestClient(app_module.app) as c:
        yield c


def _doc(address: str) -> str:
    return json.dumps({"address": address,
                       "provenance": {"source_tool": "t", "confidence": 1.0}})


# --------------------------------------------------------------------------- #
# RC-24  Validation on the model, not on one writer
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", [
    "10.0.0.1\r\nX-Injected: yes",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "a" * 300,
    "",
])
def test_rc24_host_cannot_be_constructed_with_a_hostile_address(bad):
    """RC-07 put the check on `ensure_host`; `persistence.load` then wrote
    straight into `store._hosts` and became a second, unvalidated writer.
    The rule now lives where no assignment path can skip it."""
    with pytest.raises(Exception):
        Host(address=bad, provenance=Provenance(source_tool="t",
                                                confidence=1.0))


def test_rc24_a_poisoned_snapshot_cannot_reintroduce_a_bad_address(tmp_path):
    """The actual attack: hand-craft a snapshot row the API would refuse
    with 422 and restore it."""
    db = tmp_path / "poison.sqlite"
    conn = persistence.connect(db)
    with conn:
        conn.execute("INSERT INTO hosts VALUES(?,?,?)",
                     ("10.0.0.1\r\nX-Injected: yes",
                      _doc("10.0.0.1\r\nX-Injected: yes"), "now"))
        conn.execute("INSERT INTO hosts VALUES(?,?,?)",
                     ("10.0.0.9", _doc("10.0.0.9"), "now"))
    conn.close()

    restored = persistence.load(db)
    assert [h.address for h in restored.list_hosts()] == ["10.0.0.9"]


def test_rc24_a_good_snapshot_still_restores(tmp_path):
    """The fix must not cost the happy path."""
    db = tmp_path / "clean.sqlite"
    conn = persistence.connect(db)
    with conn:
        for address in ("10.0.0.1", "box.htb", "2001:db8::1"):
            conn.execute("INSERT INTO hosts VALUES(?,?,?)",
                         (address, _doc(address), "now"))
    conn.close()
    assert len(persistence.load(db).list_hosts()) == 3


# --------------------------------------------------------------------------- #
# RC-25  Snapshots are the whole engagement
# --------------------------------------------------------------------------- #

def test_rc25_snapshot_file_and_directory_are_owner_only(tmp_path):
    db = tmp_path / "nested" / "recon.sqlite"
    persistence.connect(db).close()
    assert stat.S_IMODE(os.stat(db).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(db.parent).st_mode) == 0o700


def test_rc25_permissions_are_reasserted_on_an_existing_file(tmp_path):
    """A snapshot written by an older build is still sitting there at 0644."""
    db = tmp_path / "recon.sqlite"
    persistence.connect(db).close()
    os.chmod(db, 0o644)
    persistence.connect(db).close()
    assert stat.S_IMODE(os.stat(db).st_mode) == 0o600


# --------------------------------------------------------------------------- #
# RC-29  A counter that never moves reads as "no attacks"
# --------------------------------------------------------------------------- #

def test_rc29_auth_failures_are_counted_by_reason(client):
    for headers in ({}, {"Authorization": "Bearer wrong"},
                    {"Authorization": "Basic x"}, {},
                    {"Authorization": "Bearer wrong"}):
        assert client.get("/api/targets", headers=headers).status_code == 401

    counters = client.get("/api/metrics", headers=ADMIN).json()["metrics"]["counters"]
    family = counters["reconkg_auth_failures_total"]
    by_reason = {s["labels"]["reason"]: s["value"] for s in family["series"]}
    # Two absent headers, two bad bearer tokens, one non-bearer scheme.
    # Absent and malformed are counted apart: "nobody is authenticating" and
    # "something is authenticating wrongly" are different signals.
    assert by_reason == {"missing": 2.0, "invalid": 2.0, "malformed": 1.0}
    assert family["total"] == 5.0


def test_rc29_reason_labels_come_from_a_fixed_vocabulary(client):
    """The label must never carry attacker-supplied text -- that is how a
    bounded counter becomes a cardinality bomb."""
    from reconkg.auth import Role, _failure_reason, AuthError

    assert _failure_reason(AuthError("missing credential")) == "missing"
    assert _failure_reason(AuthError("invalid credential")) == "invalid"
    assert _failure_reason(AuthError("expected 'Bearer <token>'")) == "malformed"
    assert _failure_reason(AuthError("missing credential")) == "missing"
    assert _failure_reason(AuthError("credential for 'x' expired on ...")) \
        == "expired"
    assert _failure_reason(AuthError("\n".join(["weird"] * 50))) == "invalid"


def test_rc29_a_broken_hook_cannot_break_the_refusal(client, monkeypatch):
    """Telemetry failing must not turn a 401 into a 500."""
    from reconkg import auth

    auth.on_auth_failure(lambda reason: (_ for _ in ()).throw(RuntimeError("x")))
    try:
        assert client.get("/api/targets").status_code == 401
    finally:
        auth.on_auth_failure(None)


def test_rc29_the_hook_sits_on_the_path_every_route_uses(client):
    """RC-29's root cause was a counting dependency bolted on beside
    `require_principal` while `require_role` resolved through the original,
    so it was never called. Prove the hook fires for a role-gated route."""
    from reconkg import auth

    seen: list[str] = []
    auth.on_auth_failure(seen.append)
    try:
        client.get("/api/metrics")          # ADMIN-gated
        client.post("/api/evidence", json={"tool": "x", "address": "10.0.0.1",
                                           "data": {}})   # SCANNER-gated
        client.get("/api/health")           # VIEWER-gated
    finally:
        auth.on_auth_failure(None)
    assert seen == ["missing", "missing", "missing"]
