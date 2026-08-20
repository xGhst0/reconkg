"""Round-9 red cell: findings RC-31..RC-35, plus the round-8 carry-overs.

Every test in this file failed before the corresponding fix. They are kept
grouped by finding so a regression names the control it broke rather than the
assertion it tripped.
"""

from __future__ import annotations

import shlex

import pytest
from fastapi.testclient import TestClient

from reconkg.catalog import ExploitCatalog, ExploitRecord
from reconkg.commands import (BoundaryViolation, Category, Command,
                              DEFAULT_CATEGORIES, NEVER_COMPOSED,
                              assert_no_composed_exploits, filter_commands,
                              metasploit_commands)
from reconkg.handoff import build_commands, build_handoff
from reconkg.vulnref import DEFAULT_REFERENCE, LedgerRow

ADMIN_T = "a" * 24
VIEWER_T = "v" * 24
SCANNER_T = "s" * 24
OPERATOR_T = "o" * 24

ADMIN = {"Authorization": f"Bearer {ADMIN_T}"}
VIEWER = {"Authorization": f"Bearer {VIEWER_T}"}
SCANNER = {"Authorization": f"Bearer {SCANNER_T}"}
OPERATOR = {"Authorization": f"Bearer {OPERATOR_T}"}

TOKENS = (f"adm:admin:{ADMIN_T},"
          f"view:viewer:{VIEWER_T}:10.10.10.0/24,"
          f"scan:scanner:{SCANNER_T},"
          f"lead:operator:{OPERATOR_T}")
SCOPED_ADMIN_TOKENS = (f"adm:admin:{ADMIN_T}:10.10.10.0/24,"
                       f"lead:operator:{OPERATOR_T},"
                       f"scan:scanner:{SCANNER_T}")


def _client(monkeypatch, tokens: str = TOKENS):
    monkeypatch.setenv("RECONKG_TOKENS", tokens)
    monkeypatch.delenv("RECONKG_SNAPSHOT_DIR", raising=False)
    from reconkg import app as app_module
    app_module.state = app_module.AppState()
    return app_module, TestClient(app_module.app)


def _seed(c, address: str) -> None:
    """Enough evidence for the Apache 2.4.49 lead to exist in the ledger."""
    c.post("/api/targets", json={"address": address}, headers=OPERATOR)
    c.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sT", "address": address,
        "data": {"ports": [{"number": 80, "state": "open",
                            "confidence": 0.9}]}})
    c.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sV-intensity9", "address": address,
        "data": {"services": [
            {"port": 80, "service": "http", "product": "Apache httpd",
             "version": "2.4.49", "confidence": 0.9,
             "banner": "Server: Apache/2.4.49 (Unix)"}]}})
    c.post(f"/api/targets/{address}/scan", headers=SCANNER)


def _row(**kw) -> LedgerRow:
    base = dict(target="10.10.10.42", port=8080, protocol="tcp",
                service="http", product="Apache httpd", version="2.4.49",
                cve_id="CVE-2021-41773", title="path traversal", cvss=9.8,
                maturity="weaponised", fingerprint_confidence=0.9,
                priority=0.9, rationale="version match")
    base.update(kw)
    return LedgerRow(**base)


class _FakeCatalog:
    """One record, whose identifier is whatever the feed said it was."""

    def __init__(self, identifier: str) -> None:
        self._record = ExploitRecord("metasploit", identifier, "t",
                                     cves=("CVE-2021-41773",))

    def records_for(self, cve):
        return [self._record]


# --------------------------------------------------------------------------- #
# RC-31  A category that is a bare string walks through the boundary
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw", ["EXPLOIT", " exploit", "exploit\n",
                                 "Exploit", "DOS", "Brute"])
def test_rc31_a_string_category_cannot_carry_a_composed_argv(raw):
    """`Category` subclasses `str`, so `"exploit"` compares and hashes equal
    to `Category.EXPLOIT` -- but `"EXPLOIT"` does not. A category arriving as
    text from a feed, a JSON body or a `script.db` row therefore missed the
    `NEVER_COMPOSED` membership test entirely, and the exploit tier shipped
    with an argv."""
    with pytest.raises((BoundaryViolation, ValueError)):
        Command(tool="msfconsole", category=raw,
                argv=("msfconsole", "-q", "-x", "use x"),
                reference="r")


def test_rc31_a_string_category_is_normalised_to_the_enum():
    """The safe half of the same defect: a string category left the dataclass
    holding a `str`, so `as_dict()` raised AttributeError on `.value` and
    `requires_opt_in` silently answered False for every tier."""
    command = Command(tool="nuclei", category="UNCLASSIFIED",
                      argv=("nuclei", "-id", "CVE-1"), reference="r")
    assert command.category is Category.UNCLASSIFIED
    assert command.requires_opt_in is True
    assert command.as_dict()["category"] == "unclassified"


def test_rc31_an_unknown_category_string_is_refused():
    with pytest.raises(ValueError):
        Command(tool="nmap", category="totally-safe-trust-me",
                argv=("nmap", "-sV"), reference="r")


def test_rc31_assert_no_composed_exploits_sees_a_smuggled_string():
    """The runtime backstop must not depend on the constructor's coercion --
    `object.__setattr__` and unpickling both reach it."""
    command = Command(tool="x", category=Category.EXPLOIT, reference="m")
    object.__setattr__(command, "category", "EXPLOIT")
    object.__setattr__(command, "argv", ("boom",))
    with pytest.raises(BoundaryViolation):
        assert_no_composed_exploits([command])


def test_rc31_a_string_category_cannot_be_spoofed_down_to_safe():
    """The inverse direction: an intrusive command labelled with a string the
    default filter happens to admit."""
    command = Command(tool="nuclei", category="SAFE",
                      argv=("nuclei", "-id", "CVE-1"), reference="r")
    assert command.category is Category.SAFE      # normalised, not aliased
    assert filter_commands([command], [Category.SAFE]) == [command]
    assert filter_commands([command], [Category.VULN]) == []


# --------------------------------------------------------------------------- #
# RC-32  A firing verb smuggled through a module path
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("module", [
    "exploit/multi/http/x; run",
    "exploit/multi/http/x;run",
    "exploit/multi/http/x\nexploit",
    "exploit/multi/http/x\rrun -j",
    "exploit/multi/http/x; RUN",
])
def test_rc32_a_module_path_cannot_smuggle_a_firing_verb(module):
    """`_refuse_firing_verbs` took the first word of each *setup step*, but
    msfconsole's `-x` splits the whole string on `;` and newlines. A module
    identifier from a feed carrying `; run` became a firing statement inside
    an argv element that `shlex.quote` then wrapped intact."""
    with pytest.raises(BoundaryViolation):
        metasploit_commands(module, "10.10.10.42", 8080)


def test_rc32_a_hostile_target_cannot_smuggle_a_firing_verb():
    with pytest.raises(BoundaryViolation):
        metasploit_commands("exploit/multi/http/x", "10.0.0.5; exploit", 8080)


def test_rc32_the_feed_path_reaches_the_same_check():
    """The reachable version: the identifier comes from the Metasploit index,
    which is a file reconkg downloads and parses."""
    commands = build_commands(_row(), _FakeCatalog("exploit/multi/http/x; run"),
                              allowed=list(Category))
    joined = " ".join(c.rendered for c in commands)
    assert "run" not in joined.split()
    assert "; run" not in joined
    # A clean identifier still composes, so the fix is a filter, not a mute.
    ok = build_commands(_row(), _FakeCatalog("exploit/multi/http/x"),
                        allowed=list(Category))
    assert any(c.tool == "msfconsole" and c.composed for c in ok)


def test_rc32_argv_parts_may_not_carry_control_characters():
    with pytest.raises(ValueError):
        Command(tool="nmap", category=Category.SAFE,
                argv=("nmap", "-sV\nrm -rf /"), reference="r")


# --------------------------------------------------------------------------- #
# RC-33  The second composition path: ExploitRecord
# --------------------------------------------------------------------------- #

def test_rc33_record_oneliner_refuses_a_smuggled_firing_verb():
    """`commands.metasploit_commands` grew the boundary check;
    `ExploitRecord.msf_oneliner` composes the same msfconsole line and never
    had one. Same control, second path -- the standing pattern."""
    record = ExploitRecord("metasploit", "exploit/multi/http/x; run", "t")
    assert record.msf_oneliner("10.0.0.1", 80) is None


def test_rc33_record_oneliner_refuses_a_firing_verb_in_extras():
    record = ExploitRecord("metasploit", "exploit/multi/http/x", "t")
    assert record.msf_oneliner("10.0.0.1", 80,
                               extra={"LHOST": "1.2.3.4; run"}) is None


def test_rc33_lookup_command_quotes_a_hostile_identifier():
    """`lookup_command` interpolated the identifier into a single-quoted
    shell string. An identifier containing a quote closed it."""
    record = ExploitRecord("metasploit", "exploit/x'; id; '", "t")
    tokens = shlex.split(record.lookup_command())
    assert tokens[:3] == ["msfconsole", "-q", "-x"]
    assert len(tokens) == 4

    edb = ExploitRecord("exploit-db", "EDB-1; rm -rf /", "t")
    assert len(shlex.split(edb.lookup_command())) == 3


def test_rc33_a_clean_record_still_composes():
    record = ExploitRecord("metasploit", "exploit/multi/http/x", "t")
    line = record.msf_oneliner("10.0.0.1", 80)
    assert line is not None and len(shlex.split(line)) == 4


# --------------------------------------------------------------------------- #
# RC-34  The category gate, bypassed by the `lookups` list
# --------------------------------------------------------------------------- #

def test_rc34_the_vuln_script_lookup_honours_the_category_gate():
    """`build_commands` gates `nmap --script vuln` behind the `vuln` tier and
    attaches the authorisation warning. `build_handoff` then emitted the same
    invocation as a plain string in `lookups`, unfiltered and unwarned -- the
    control on one path, bypassed on the second."""
    default = build_handoff(_row(), DEFAULT_REFERENCE)
    assert not any("--script vuln" in line for line in default.lookups)
    assert "--script vuln" not in default.render()

    opted_in = build_handoff(_row(), DEFAULT_REFERENCE,
                             allowed=[Category.VULN, Category.SAFE])
    assert any("--script vuln" in line for line in opted_in.lookups)


def test_rc34_the_safe_lookups_are_still_emitted():
    default = build_handoff(_row(), DEFAULT_REFERENCE)
    assert any(line.startswith("searchsploit --cve")
               for line in default.lookups)


# --------------------------------------------------------------------------- #
# RC-35  A script.db row that declares one category, as a string
# --------------------------------------------------------------------------- #

def test_rc35_a_single_category_string_is_not_downgraded():
    """`_worst_category` iterates its argument. Handed the list
    `["exploit"]` it sees one category; handed the string `"exploit"` -- the
    shape a `script.db` parser produces for a single-category script -- it
    sees ten one-character names, discards all of them as unrecognised, and
    returns `unclassified`. Unclassified is composable on opt-in, so an
    exploit script arrives with the target filled in."""
    from reconkg.commands import _worst_category
    assert _worst_category("exploit") is Category.EXPLOIT
    assert _worst_category("safe") is Category.SAFE


def test_rc35_an_exploit_script_is_never_composed_whatever_the_row_shape():
    from reconkg.commands import nmap_commands
    for declared in ("exploit", ["exploit"], ("exploit", "safe"),
                     ["EXPLOIT"], [" Exploit "]):
        commands = nmap_commands("10.10.10.42", 80, scripts=("http-vuln-x",),
                                 categories={"http-vuln-x": declared})
        script = [c for c in commands if "http-vuln-x" in
                  (c.reference or "") or "http-vuln-x" in (c.argv or ())]
        assert script, declared
        assert script[0].category is Category.EXPLOIT, declared
        assert script[0].argv is None, declared


def test_rc35_an_unrecognised_tag_does_not_launder_a_permissive_one():
    """A tag the enum does not know was dropped, so `["safe", "malware"]`
    resolved to `safe` and was emitted by default. An unknown tag is exactly
    the case the module says it will not guess about."""
    from reconkg.commands import _worst_category

    # `malware` was the original example, chosen because the enum did not
    # know it. It does now -- all fourteen NSE categories are present -- so
    # the finding is re-tested with a tag that is genuinely unrecognised.
    # The rule under test is unchanged: an unknown tag must not be dropped
    # and leave a permissive one deciding alone.
    assert _worst_category(["safe", "nonesuch-tag"]) is Category.UNCLASSIFIED
    assert _worst_category(["safe"]) is Category.SAFE
    # And a tag that is now recognised as a pure topic does not override the
    # safety label sitting beside it.
    assert _worst_category(["safe", "malware"]) is Category.SAFE


# --------------------------------------------------------------------------- #
# The /handoff route's `categories` parameter -- attacked, no finding
# --------------------------------------------------------------------------- #

def test_rc35_unknown_category_fails_closed(monkeypatch):
    app_module, client = _client(monkeypatch)
    with client as c:
        _seed(c, "10.10.10.42")
        bad = c.get("/api/targets/10.10.10.42/handoff/CVE-2021-41773"
                    "?categories=safe,everything", headers=VIEWER)
        assert bad.status_code == 400
        empty = c.get("/api/targets/10.10.10.42/handoff/CVE-2021-41773"
                      "?categories=,", headers=VIEWER)
        assert empty.status_code == 400


def test_rc35_categories_do_not_widen_authz(monkeypatch):
    """The parameter selects a view, not a permission: it must not let a
    principal read a lead on a host outside its scope."""
    app_module, client = _client(monkeypatch)
    with client as c:
        _seed(c, "192.0.2.7")
        out = c.get("/api/targets/192.0.2.7/handoff/CVE-2021-41773"
                    "?categories=exploit,intrusive", headers=VIEWER)
        assert out.status_code == 403


def test_rc35_no_composed_exploit_reaches_the_api(monkeypatch):
    app_module, client = _client(monkeypatch)
    every = ",".join(item.value for item in Category)
    with client as c:
        _seed(c, "10.10.10.42")
        response = c.get("/api/targets/10.10.10.42/handoff/CVE-2021-41773"
                         f"?categories={every}", headers=VIEWER)
        assert response.status_code == 200
        for command in response.json()["commands"]:
            if command["category"] in {item.value for item in NEVER_COMPOSED}:
                assert command["argv"] is None
                assert command["composed"] is False


# --------------------------------------------------------------------------- #
# RC-36  The resolver's loud-failure promise, on the path that matters
# --------------------------------------------------------------------------- #

def test_rc36_a_requested_corpus_is_not_silently_replaced(monkeypatch,
                                                          tmp_path):
    """`from_env` refuses to fall back to the built-in nine, and says so at
    length. `DiscoveryEngine` never called it: its `reference=` default is
    `DEFAULT_REFERENCE`, not `None`, so `coerce` wrapped the built-ins and
    `RECONKG_VULN_DB` was never read. Every scan through the API ran against
    nine hand-written entries while the operator believed a 250,000-CVE
    corpus was loaded -- and a missing corpus file reported 'no leads' with
    total confidence."""
    from reconkg.engine import DiscoveryEngine
    from reconkg.stages import EvidenceSource
    from reconkg.store import TargetStore

    monkeypatch.setenv("RECONKG_VULN_DB", str(tmp_path / "absent.sqlite"))
    with pytest.raises(FileNotFoundError):
        DiscoveryEngine(TargetStore(), EvidenceSource(), [])


def test_rc36_the_builtins_are_still_the_default_when_nothing_was_asked_for(
        monkeypatch):
    from reconkg.engine import DiscoveryEngine
    from reconkg.resolver import StaticResolver
    from reconkg.stages import EvidenceSource
    from reconkg.store import TargetStore

    monkeypatch.delenv("RECONKG_VULN_DB", raising=False)
    engine = DiscoveryEngine(TargetStore(), EvidenceSource(), [])
    assert isinstance(engine.resolver, StaticResolver)
    assert "demonstration fixture" in engine.resolver.describe()


def test_rc36_an_explicit_reference_still_wins(monkeypatch, tmp_path):
    """A caller that passes entries meant it -- the tests and the demo do.
    The defect was the *default* silently answering the environment's
    question."""
    from reconkg.engine import DiscoveryEngine
    from reconkg.stages import EvidenceSource
    from reconkg.store import TargetStore

    monkeypatch.setenv("RECONKG_VULN_DB", str(tmp_path / "absent.sqlite"))
    engine = DiscoveryEngine(TargetStore(), EvidenceSource(), [],
                             reference=DEFAULT_REFERENCE)
    assert len(engine.resolver) == len(DEFAULT_REFERENCE)


# --------------------------------------------------------------------------- #
# RC-23  Metric cardinality squatting by an anonymous client
# --------------------------------------------------------------------------- #

def _middleware_metrics(app):
    """The metrics object the middleware actually holds.

    `add_middleware` captured it when the module was imported, so a test that
    replaces `app_module.state` gets a different one -- and would then assert
    against a counter nothing increments.
    """
    from reconkg.observability import CorrelationMiddleware
    node = app.middleware_stack
    while node is not None:
        if isinstance(node, CorrelationMiddleware):
            return node.metrics
        node = getattr(node, "app", None)
    raise AssertionError("correlation middleware not in the stack")


def test_rc23_unmatched_routes_share_one_series(monkeypatch):
    app_module, client = _client(monkeypatch)
    with client as c:
        metrics = _middleware_metrics(app_module.app)
        family = metrics._families["reconkg_http_requests_total"]
        before = family.distinct_series
        for i in range(200):
            assert c.get(f"/zz{i}").status_code == 404
        assert family.distinct_series - before <= 1
        c.get("/api/health", headers=ADMIN)
        assert any("health" in str(k) for k in family.series)
        assert "/zz" not in metrics.render_prometheus()


# --------------------------------------------------------------------------- #
# RC-26  Ticket eviction across principals
# --------------------------------------------------------------------------- #

def test_rc26_a_viewer_flood_cannot_evict_another_principals_ticket(
        monkeypatch):
    app_module, client = _client(monkeypatch)
    from reconkg.auth import MAX_OUTSTANDING_TICKETS

    with client as c:
        victim = c.post("/api/ws-ticket", headers=OPERATOR).json()["ticket"]
        for _ in range(MAX_OUTSTANDING_TICKETS + 5):
            c.post("/api/ws-ticket", headers=VIEWER)
        with c.websocket_connect(f"/ws?ticket={victim}") as ws:
            assert ws.receive_json()["type"] == "hello"


def test_rc26_one_principal_cannot_hold_the_whole_table(monkeypatch):
    app_module, client = _client(monkeypatch)
    from reconkg.auth import (MAX_OUTSTANDING_TICKETS,
                              MAX_TICKETS_PER_PRINCIPAL, current_authenticator)
    with client as c:
        for _ in range(MAX_OUTSTANDING_TICKETS + 20):
            c.post("/api/ws-ticket", headers=VIEWER)
        held = current_authenticator()._tickets
        assert len(held) <= MAX_TICKETS_PER_PRINCIPAL
        assert len(held) <= MAX_OUTSTANDING_TICKETS


# --------------------------------------------------------------------------- #
# RC-27  POST /api/targets was the one unthrottled graph write
# --------------------------------------------------------------------------- #

def test_rc27_repeat_target_posts_are_rate_limited(monkeypatch):
    app_module, client = _client(monkeypatch)
    with client as c:
        codes = {c.post("/api/targets", json={"address": "10.10.10.42"},
                        headers=OPERATOR).status_code for _ in range(200)}
        assert 429 in codes


# --------------------------------------------------------------------------- #
# RC-28  Scope is not enforced on telemetry
# --------------------------------------------------------------------------- #

def test_rc28_a_scoped_admin_is_refused_the_metrics(monkeypatch):
    app_module, client = _client(monkeypatch, SCOPED_ADMIN_TOKENS)
    with client as c:
        for address in ("10.10.10.42", "192.0.2.7"):
            c.post("/api/targets", json={"address": address}, headers=OPERATOR)
        assert c.get("/metrics", headers=ADMIN).status_code == 403
        assert c.get("/api/metrics", headers=ADMIN).status_code == 403


def test_rc28_an_unscoped_admin_still_reads_the_metrics(monkeypatch):
    app_module, client = _client(monkeypatch)
    with client as c:
        assert c.get("/metrics", headers=ADMIN).status_code == 200
        assert c.get("/api/metrics", headers=ADMIN).status_code == 200


# --------------------------------------------------------------------------- #
# RC-30  /api/health is unscoped telemetry
# --------------------------------------------------------------------------- #

def test_rc30_health_counts_are_scoped(monkeypatch):
    app_module, client = _client(monkeypatch)
    with client as c:
        for address in ("10.10.10.42", "192.0.2.7", "203.0.113.9"):
            c.post("/api/targets", json={"address": address}, headers=OPERATOR)
        health = c.get("/api/health", headers=VIEWER).json()
        listed = c.get("/api/targets", headers=VIEWER).json()
        assert health["hosts"] == len(listed) == 1

        before = health["events_emitted"]
        c.post("/api/targets/192.0.2.7/scan", headers=SCANNER)
        after = c.get("/api/health", headers=VIEWER).json()["events_emitted"]
        assert after == before, "a scan outside scope must not be observable"

        unscoped = c.get("/api/health", headers=ADMIN).json()
        assert unscoped["hosts"] == 3
