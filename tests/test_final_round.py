"""Final round: msf one-liner, contradiction discounting, token expiry,
persistence."""

from __future__ import annotations

import json
import shlex
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from reconkg import persistence
from reconkg.auth import AuthError, Authenticator, Role, load_principals
from reconkg.catalog import ExploitCatalog, ExploitRecord
from reconkg.handoff import build_handoff
from reconkg.models import ExploitMaturity, Fingerprint, Provenance
from reconkg.persistence import SchemaMismatch
from reconkg.store import TargetStore
from reconkg.vulnref import (DEFAULT_REFERENCE, CorrelationConfig, LedgerRow,
                             VulnEntry, build_leads)

APACHE = VulnEntry("CVE-2021-41773", "Apache RCE", "apache",
                   ((">=", "2.4.49"), ("<=", "2.4.49")), 9.8,
                   ExploitMaturity.WEAPONISED)


@pytest.fixture
def catalog(tmp_path):
    (tmp_path / "msf.json").write_text(json.dumps({"m": {
        "name": "Apache Normalize Path RCE",
        "fullname": "exploit/multi/http/apache_normalize_path_rce",
        "type": "exploit", "references": [["CVE", "2021-41773"]]}}))
    (tmp_path / "e.csv").write_text(
        "id,file,description,codes,verified\n"
        "50383,a.sh,Apache 2.4.49 RCE,CVE-2021-41773,1\n")
    cat = ExploitCatalog()
    cat.load_metasploit(tmp_path / "msf.json")
    cat.load_exploitdb(tmp_path / "e.csv")
    return cat


def _row(**kw):
    base = dict(target="10.10.10.42", port=80, protocol="tcp", service="http",
                product="Apache httpd", version="2.4.49",
                cve_id="CVE-2021-41773", title="Apache RCE", cvss=9.8,
                maturity="weaponised", fingerprint_confidence=0.92,
                corroborated_by=["nmap-sV"], independent_principals=["a", "b"],
                priority=1.0, rationale="in range")
    base.update(kw)
    return LedgerRow(**base)


# --------------------------------------------------------------------------- #
# Metasploit command
#
# Migrated from `msf_oneliners` to the typed `Command` in commands.py. Kept
# rather than replaced: these assertions encode the boundary, and a boundary
# test that disappears during a refactor is how a boundary quietly moves.
# --------------------------------------------------------------------------- #

from reconkg.commands import Category, BoundaryViolation


def _msf(catalog, **kw):
    built = build_handoff(_row(**kw), DEFAULT_REFERENCE, catalog,
                          allowed=list(Category))
    return [c for c in built.commands if c.tool == "msfconsole"]


def test_command_is_prefilled_for_the_target(catalog):
    line = _msf(catalog)[0].rendered
    assert "use exploit/multi/http/apache_normalize_path_rce" in line
    assert "set RHOSTS 10.10.10.42" in line
    assert "set RPORT 80" in line


def test_command_stops_short_of_firing(catalog):
    """The boundary: configured, not launched.

    Unchanged in substance from the pre-refactor version. `show options` is
    where an operator reads RHOSTS back before committing, and composing past
    it for every lead in a ledger is what would make this an exploitation
    chain whose last step is a paste.
    """
    line = _msf(catalog)[0].rendered
    body = shlex.split(line)[-1]
    steps = [c.strip() for c in body.split(";")]
    assert steps[-1] == "show options"
    for verb in ("run", "exploit", "rerun", "rexploit"):
        assert verb not in steps
        assert not any(s.startswith(verb + " ") for s in steps)


def test_the_builder_refuses_a_firing_verb_outright(catalog):
    """Defence against a future edit, not against today's code."""
    from reconkg.commands import _refuse_firing_verbs

    with pytest.raises(BoundaryViolation):
        _refuse_firing_verbs(["use exploit/foo", "set RHOSTS x", "run"],
                             "exploit/foo")


def test_an_exploit_category_command_cannot_be_composed():
    """The type refuses it, so no builder can produce one by accident."""
    from reconkg.commands import Command

    with pytest.raises(BoundaryViolation):
        Command(tool="nmap", category=Category.EXPLOIT,
                argv=("nmap", "--script", "http-shellshock", "10.0.0.1"))


def test_no_command_without_a_catalogue():
    """No catalogue means no verified module name, so nothing is emitted --
    a guessed path is worse than silence."""
    built = build_handoff(_row(), DEFAULT_REFERENCE, allowed=list(Category))
    assert [c for c in built.commands if c.tool == "msfconsole"] == []


def test_no_command_for_a_cve_the_index_does_not_know(catalog):
    assert _msf(catalog, cve_id="CVE-1999-0001") == []


def test_msf_commands_are_opt_in_not_default(catalog):
    """Default categories are safe/discovery/version. A Metasploit line is
    intrusive and must not appear until the operator asks for it."""
    default = build_handoff(_row(), DEFAULT_REFERENCE, catalog)
    assert [c for c in default.commands if c.tool == "msfconsole"] == []


def test_exploitdb_records_produce_no_oneliner(catalog):
    """Only Metasploit records have a module to `use`."""
    edb = [r for r in catalog.records_for("CVE-2021-41773")
           if r.source == "exploit-db"][0]
    assert edb.msf_oneliner("10.0.0.1", 80) is None


def test_oneliner_quotes_a_hostile_target():
    record = ExploitRecord("metasploit", "exploit/x/y", "t")
    line = record.msf_oneliner("10.0.0.1; rm -rf /", 80)
    tokens = shlex.split(line)
    assert tokens[:3] == ["msfconsole", "-q", "-x"]
    assert len(tokens) == 4          # the payload stays one argument


def test_command_appears_in_rendered_handoff(catalog):
    text = build_handoff(_row(), DEFAULT_REFERENCE, catalog,
                         allowed=list(Category)).render()
    assert "use exploit/multi/http/apache_normalize_path_rce" in text
    assert "(intrusive)" in text, "the category must be visible in the output"
    assert "show options" in text


def test_the_rendered_handoff_warns_when_it_shows_opt_in_commands(catalog):
    """The authorisation warning travels with the commands that need it,
    rather than sitting in a footer nobody reads."""
    from reconkg.commands import INTRUSIVE_WARNING

    text = build_handoff(_row(), DEFAULT_REFERENCE, catalog,
                         allowed=list(Category)).render()
    assert INTRUSIVE_WARNING in text

    default = build_handoff(_row(), DEFAULT_REFERENCE, catalog).render()
    assert INTRUSIVE_WARNING not in default, (
        "no opt-in commands were shown, so the warning is noise")


# --------------------------------------------------------------------------- #
# Contradiction discounting
# --------------------------------------------------------------------------- #

def _fp(version, principal="scanner-a", confidence=0.9):
    return Fingerprint(product="Apache httpd", version=version,
                       provenance=Provenance(source_tool="nmap-sV",
                                             principal=principal,
                                             confidence=confidence))


def test_disputed_lead_is_discounted():
    fp = _fp("2.4.49")
    clean = build_leads(fp, [APACHE], CorrelationConfig())[0]
    disputed = build_leads(fp, [APACHE], CorrelationConfig(),
                           contradicted=True)[0]
    assert disputed.priority == pytest.approx(round(clean.priority * 0.5, 4))
    assert "DISPUTED" in disputed.rationale


@pytest.mark.asyncio
async def test_engine_marks_and_discounts_both_sides_of_a_conflict():
    from reconkg.builtin_modules import module_pipeline
    from reconkg.engine import DiscoveryEngine
    from reconkg.stages import EvidenceSource

    store, evidence = TargetStore(), EvidenceSource()
    evidence.put("nmap-sT", "10.0.0.5",
                 {"ports": [{"number": 80, "state": "open"}]},
                 principal="scanner-a")
    evidence.put("nmap-sV", "10.0.0.5", {"services": [
        {"port": 80, "service": "http", "product": "Apache httpd",
         "version": "2.4.49", "confidence": 1.0}]}, principal="scanner-a")
    # The second claim must come from a stage that also runs: a SUCCESS
    # short-circuits its own fallbacks, so deep_probe would never fire here.
    evidence.put("whatweb", "10.0.0.5", {"apps": [
        {"port": 80, "product": "Apache httpd", "version": "2.4.50",
         "confidence": 1.0}]}, principal="scanner-b")

    engine = DiscoveryEngine(store, evidence, module_pipeline())
    report = await engine.run("10.0.0.5")

    assert report.ledger, "expected leads for both claimed versions"
    assert all(r.disputed for r in report.ledger)
    assert all("DISPUTED" in r.rationale for r in report.ledger)
    assert all(r.priority < 0.6 for r in report.ledger)


def test_disputed_row_gets_a_handoff_caveat():
    caveats = build_handoff(_row(disputed=True), DEFAULT_REFERENCE).caveats
    assert any("DISPUTED" in c for c in caveats)


# --------------------------------------------------------------------------- #
# Token expiry
# --------------------------------------------------------------------------- #

def _tok(n):
    return n * 22


def test_expired_credential_is_refused():
    entry = f"lab:scanner:{_tok('s')}:10.0.0.0/8@2020-01-01"
    auth = Authenticator(load_principals(entry))
    with pytest.raises(AuthError, match="expired on 2020-01-01"):
        auth.resolve(_tok("s"))


def test_unexpired_credential_still_resolves():
    future = (datetime.now(timezone.utc) + timedelta(days=30)).date()
    entry = f"lab:scanner:{_tok('s')}:10.0.0.0/8@{future}"
    principal = Authenticator(load_principals(entry)).resolve(_tok("s"))
    assert principal.name == "lab"
    assert 29 <= principal.expires_in_days <= 30


def test_expiry_is_optional_and_absent_means_unlimited():
    principal = Authenticator(
        load_principals(f"lab:scanner:{_tok('s')}:10.0.0.0/8")).resolve(_tok("s"))
    assert principal.expires_at is None
    assert principal.expires_in_days is None
    assert principal.expired is False


def test_bad_expiry_format_is_rejected_by_name():
    with pytest.raises(AuthError, match="expected @YYYY-MM-DD"):
        load_principals(f"lab:scanner:{_tok('s')}:10.0.0.0/8@soon")


def test_scope_survives_alongside_an_expiry():
    future = (datetime.now(timezone.utc) + timedelta(days=5)).date()
    p = Authenticator(load_principals(
        f"lab:scanner:{_tok('s')}:10.10.10.0/24;*.htb@{future}")
    ).resolve(_tok("s"))
    assert p.scope == ("10.10.10.0/24", "*.htb")
    assert p.may_touch("10.10.10.9") and not p.may_touch("192.0.2.1")


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

@pytest.fixture
async def populated_store():
    from reconkg.builtin_modules import module_pipeline
    from reconkg.demo import TARGET, build_evidence
    from reconkg.engine import DiscoveryEngine

    store = TargetStore()
    await DiscoveryEngine(store, build_evidence(), module_pipeline()).run(TARGET)
    return store


@pytest.mark.asyncio
async def test_snapshot_round_trip_preserves_the_graph(populated_store, tmp_path):
    from reconkg.demo import TARGET

    db = tmp_path / "recon.sqlite"
    assert persistence.save(populated_store, db) == 1

    restored = persistence.load(db)
    original = populated_store.get(TARGET)
    back = restored.get(TARGET)

    assert back is not None
    assert {p.number for p in back.ports} == {p.number for p in original.ports}
    fp_original = original.find_port(80).service.best_fingerprint()
    fp_back = back.find_port(80).service.best_fingerprint()
    assert fp_back.version == fp_original.version
    assert fp_back.confidence == fp_original.confidence


@pytest.mark.asyncio
async def test_provenance_survives_the_round_trip(populated_store, tmp_path):
    """The audit trail is the point of the graph; losing it on restart would
    make the snapshot worse than useless."""
    from reconkg.demo import TARGET

    db = tmp_path / "recon.sqlite"
    persistence.save(populated_store, db)
    fp = persistence.load(db).get(TARGET).find_port(80).service \
        .best_fingerprint()
    assert fp.corroborating_principals == {"scanner-a", "scanner-b"}
    assert len(fp.provenance_log) >= 2
    assert fp.provenance.declared_confidence is not None


@pytest.mark.asyncio
async def test_resaving_updates_rather_than_duplicates(populated_store, tmp_path):
    db = tmp_path / "recon.sqlite"
    persistence.save(populated_store, db)
    persistence.save(populated_store, db)
    assert persistence.host_count(db) == 1


@pytest.mark.asyncio
async def test_forget_removes_one_host(populated_store, tmp_path):
    from reconkg.demo import TARGET
    db = tmp_path / "recon.sqlite"
    persistence.save(populated_store, db)
    assert persistence.forget(db, TARGET) is True
    assert persistence.forget(db, TARGET) is False
    assert persistence.host_count(db) == 0


def test_corrupt_row_is_skipped_not_fatal(tmp_path):
    db = tmp_path / "recon.sqlite"
    conn = persistence.connect(db)
    with conn:
        conn.execute("INSERT INTO hosts VALUES('10.0.0.1', ?, ?)",
                     ("{not json", "now"))
        conn.execute("INSERT INTO hosts VALUES('10.0.0.2', ?, ?)",
                     ('{"address": "10.0.0.2", "provenance": '
                      '{"source_tool": "operator", "confidence": 1.0}}', "now"))
    conn.close()
    store = persistence.load(db)
    assert [h.address for h in store.list_hosts()] == ["10.0.0.2"]


def test_schema_version_mismatch_fails_loudly(tmp_path):
    db = tmp_path / "recon.sqlite"
    conn = persistence.connect(db)
    with conn:
        conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    conn.close()
    with pytest.raises(SchemaMismatch, match="schema v99"):
        persistence.connect(db)


def test_load_of_an_empty_database_is_an_empty_store(tmp_path):
    assert persistence.load(tmp_path / "fresh.sqlite").list_hosts() == []
