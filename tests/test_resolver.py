"""The seam between the engine and the corpus.

Until this existed, `vulndb.py` was orphaned: built, indexed, benchmarked at
100,000 records, and imported by nothing except its own builder. The tests
that matter here are the ones that would fail if it went back to being
orphaned -- a lead that could only have come from the corpus, and a failure
that is loud rather than a silent fall back to nine entries.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from reconkg.cpe import CPERange, parse as parse_cpe
from reconkg.models import (ExploitMaturity, Fingerprint, Port, Provenance,
                            Service)
from reconkg.resolver import (ENV_VAR, DbResolver, StaticResolver, coerce,
                              from_env)
from reconkg.vulndb import VulnDB
from reconkg.vulnref import DEFAULT_REFERENCE, VulnEntry

# A product deliberately absent from the built-in nine. If a lead for this
# appears, it came from the corpus and nowhere else.
CORPUS_ONLY = VulnEntry(
    cve_id="CVE-2023-99999",
    title="Synthetic flaw in Fictional Widget Server",
    product_match="widgetserv",
    cvss=9.1,
    maturity=ExploitMaturity.NOT_DEFINED,
    cpe_ranges=(CPERange(
        cpe=parse_cpe("cpe:2.3:a:fictional:widgetserv:*:*:*:*:*:*:*:*"),
        version_start_including="2.0",
        version_end_excluding="3.0"),),
)


@pytest.fixture
def corpus(tmp_path):
    path = tmp_path / "vuln.db"
    with VulnDB(path) as db:
        db.ingest([CORPUS_ONLY])
        db.set_meta("built_at", "9999999999")
    return path


def prov(tool="nmap", confidence=0.9, principal=None) -> Provenance:
    return Provenance(source_tool=tool, confidence=confidence,
                      principal=principal or tool)


def _fp(**kw) -> Fingerprint:
    base = dict(product="widgetserv", version="2.5",
                cpe="cpe:2.3:a:fictional:widgetserv:2.5:*:*:*:*:*:*:*",
                provenance=prov())
    base.update(kw)
    return Fingerprint(**base)


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #

def test_no_env_var_gives_the_built_in_reference():
    resolver = from_env({})
    assert isinstance(resolver, StaticResolver)
    assert len(resolver) == len(DEFAULT_REFERENCE)


def test_env_var_gives_the_corpus(corpus):
    resolver = from_env({ENV_VAR: str(corpus)})
    assert isinstance(resolver, DbResolver)


def test_a_blank_env_var_is_treated_as_unset():
    assert isinstance(from_env({ENV_VAR: "   "}), StaticResolver)


def test_a_missing_database_fails_loudly_rather_than_falling_back(tmp_path):
    """The worst outcome available: the operator asks for a 300,000-CVE
    corpus, gets nine hand-written entries, and the scan reports almost
    nothing while looking like it worked."""
    with pytest.raises(FileNotFoundError) as exc:
        from_env({ENV_VAR: str(tmp_path / "absent.db")})
    assert "does not exist" in str(exc.value)
    assert "builddb" in str(exc.value), "the error should say how to fix it"


# --------------------------------------------------------------------------- #
# Narrowing
# --------------------------------------------------------------------------- #

def test_corpus_resolver_finds_an_entry_the_built_ins_do_not_have(corpus):
    resolver = from_env({ENV_VAR: str(corpus)})
    found = resolver.candidates(_fp())

    assert [e.cve_id for e in found] == ["CVE-2023-99999"]
    assert not any(e.cve_id == "CVE-2023-99999" for e in DEFAULT_REFERENCE), (
        "the fixture is supposed to be absent from the built-ins")


def test_the_lead_survives_matching_not_just_lookup(corpus):
    """Narrowing is not matching. An entry returned by SQL still has to pass
    `entry.matches`, and a test that stops at the lookup would not notice if
    the two disagreed about versions."""
    from reconkg.vulnref import CorrelationConfig, build_leads

    resolver = from_env({ENV_VAR: str(corpus)})
    fp = _fp()
    leads = build_leads(fp, resolver.candidates(fp), CorrelationConfig())

    assert [lead.cve_id for lead in leads] == ["CVE-2023-99999"]


def test_a_version_outside_the_range_produces_no_lead(corpus):
    """The CPE lookup excluding a row is an answer, not missing data.

    First cut of `VulnDB.candidates` fell back to substring matching whenever
    the CPE query returned nothing. So a host running 4.0 -- correctly
    excluded from a 2.0-to-3.0 range -- came back through the alias path,
    which carries no version bounds, and got the lead anyway.
    """
    from reconkg.vulnref import CorrelationConfig, build_leads

    resolver = from_env({ENV_VAR: str(corpus)})
    fp = _fp(version="4.0",
             cpe="cpe:2.3:a:fictional:widgetserv:4.0:*:*:*:*:*:*:*")
    assert resolver.candidates(fp) == [], (
        "the version is outside the range; the fallback must not re-admit it")
    assert build_leads(fp, resolver.candidates(fp), CorrelationConfig()) == []


def test_an_unparseable_cpe_falls_back_to_the_product_name(corpus, caplog):
    resolver = from_env({ENV_VAR: str(corpus)})
    fp = _fp(cpe="this is not a cpe")

    with caplog.at_level("WARNING"):
        found = resolver.candidates(fp)

    assert any("unparseable CPE" in r.message for r in caplog.records), (
        "a malformed CPE silently demotes to substring matching; that should "
        "not be invisible")
    assert [e.cve_id for e in found] == ["CVE-2023-99999"]


def test_a_fingerprint_with_no_cpe_still_resolves(corpus):
    resolver = from_env({ENV_VAR: str(corpus)})
    assert resolver.candidates(_fp(cpe=None))


def test_an_unknown_product_resolves_to_nothing(corpus):
    resolver = from_env({ENV_VAR: str(corpus)})
    fp = _fp(product="nothing-like-this", version="1.0",
             cpe="cpe:2.3:a:acme:absent:1.0:*:*:*:*:*:*:*")
    assert resolver.candidates(fp) == []


# --------------------------------------------------------------------------- #
# Engine wiring -- the part that was missing entirely
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_the_engine_produces_a_corpus_lead_end_to_end(corpus):
    """The regression this file exists for. `vulndb` was built, indexed and
    benchmarked while no code path queried it."""
    from reconkg.engine import DiscoveryEngine
    from reconkg.store import TargetStore

    store = TargetStore()
    engine = DiscoveryEngine(store, evidence=None,
                             reference=from_env({ENV_VAR: str(corpus)}))

    await store.ensure_host("10.0.0.1", prov())
    await store.record_port("10.0.0.1", Port(number=8080, provenance=prov()))
    await store.set_service("10.0.0.1", 8080,
                            Service(name="http", provenance=prov()))
    await store.record_fingerprint("10.0.0.1", 8080, _fp())

    rows = await engine._correlate("10.0.0.1")
    assert [row.cve_id for row in rows] == ["CVE-2023-99999"]


@pytest.mark.asyncio
async def test_the_engine_still_defaults_to_the_built_ins(monkeypatch):
    """Offline, zero setup, no corpus. The demo path must keep working."""
    from reconkg.engine import DiscoveryEngine
    from reconkg.store import TargetStore

    monkeypatch.delenv(ENV_VAR, raising=False)
    engine = DiscoveryEngine(TargetStore(), evidence=None)
    assert isinstance(engine.resolver, StaticResolver)


# --------------------------------------------------------------------------- #
# describe() -- "no leads" must be disambiguable
# --------------------------------------------------------------------------- #

def test_the_built_in_reference_admits_what_it_is():
    text = StaticResolver().describe()
    assert "demonstration fixture" in text
    assert ENV_VAR in text, "should say how to get a real corpus"


def test_a_stale_corpus_says_so(tmp_path):
    path = tmp_path / "old.db"
    with VulnDB(path) as db:
        db.ingest([CORPUS_ONLY])
        db.set_meta("built_at", "1")        # 1970
    resolver = DbResolver(VulnDB(path))

    text = resolver.describe()
    assert "STALE" in text
    assert "fetch" in text, "should say how to refresh"
    resolver.close()


def test_a_fresh_corpus_does_not_cry_wolf(corpus):
    import time
    with VulnDB(corpus) as db:
        db.set_meta("built_at", str(int(time.time())))
    resolver = DbResolver(VulnDB(corpus))
    assert "STALE" not in resolver.describe()
    resolver.close()


def test_an_unreadable_build_date_is_reported_not_crashed(corpus):
    with VulnDB(corpus) as db:
        db.set_meta("built_at", "not-a-timestamp")
    resolver = DbResolver(VulnDB(corpus))
    assert "unreadable" in resolver.describe()
    resolver.close()


# --------------------------------------------------------------------------- #
# An empty CPE result has two causes, and only one of them is an answer
#
# Found by `selfcheck` against a full 381,322-CVE corpus: nginx, MySQL, IIS
# and vsftpd each returned zero leads, and not one was a corpus gap. nmap
# emits `mysql:mysql` where NVD files MySQL under vendor `oracle`,
# `nginx:nginx` where NVD has `f5`, `microsoft:iis` where NVD writes
# `internet_information_services`. Every one of those CVEs was present and
# unreachable, and the silence was indistinguishable from "not affected".
# --------------------------------------------------------------------------- #

def test_a_known_identity_with_no_version_match_stays_silent(corpus):
    """The half that must NOT fall back.

    `fictional:widgetserv` is in this corpus, bounded 2.0 <= v < 3.0. A host
    on 9.9 is genuinely unaffected, and re-admitting the entry through the
    substring path -- which carries no version bounds at all -- would hand
    that host a lead for something fixed six majors earlier.
    """
    db = VulnDB(corpus)
    observed = parse_cpe("cpe:2.3:a:fictional:widgetserv:9.9:*:*:*:*:*:*:*")

    assert db.knows_identity(observed) is True
    assert db.candidates(observed, "widgetserv") == []
    db.close()


def test_a_vendor_disagreement_is_recovered_with_version_bounds_intact(corpus):
    """Tier two, and where nearly all the recovery lives.

    Same product, under a vendor this corpus has never filed anything for --
    the nmap-versus-NVD disagreement that hides every MySQL CVE behind
    `oracle` and every nginx one behind `f5`. The lookup returned nothing
    because the key was wrong, not because the host was clean.

    Relaxing the vendor is safe in a way that the substring path is not: the
    version predicate is untouched, so this cannot admit a CVE the ranges
    exclude. 2.5 is inside [2.0, 3.0) and the entry comes back.
    """
    db = VulnDB(corpus)
    observed = parse_cpe("cpe:2.3:a:notavendor:widgetserv:2.5:*:*:*:*:*:*:*")

    assert db.knows_identity(observed) is False
    assert db.candidates_for_cpe(observed) == [], "tier one should not match"

    found = db.candidates(observed, "widgetserv")
    assert [e.cve_id for e in found] == [CORPUS_ONLY.cve_id], (
        "an unrecognised vendor suppressed the product lookup, so a CVE that "
        "is in the corpus was reported as absent")
    db.close()


def test_a_vendor_disagreement_still_respects_the_version_range(corpus):
    """Tier two must not become tier three by another name.

    Same unknown vendor, but a version outside the entry's range. If
    relaxing the vendor also relaxed the bounds, this would return a lead
    for a host running six majors past the fix -- which is the exact failure
    the original single-tier design was written to prevent, reintroduced
    through the door added to fix a different problem.
    """
    db = VulnDB(corpus)
    observed = parse_cpe("cpe:2.3:a:notavendor:widgetserv:9.9:*:*:*:*:*:*:*")

    assert db.candidates(observed, "widgetserv") == []
    db.close()


def test_a_one_character_alias_does_not_match_every_product(corpus):
    """The false positive that made 16/18 worse than 13/18.

    On a full corpus the alias table holds single characters -- `i` on 167
    CVEs, plus `ie`, `go`, `qt`, `mq`. A raw `instr(needle, alias)` made
    `instr('nginx', 'i')` true, so one CVE surfaced as the top lead for
    nginx, Microsoft IIS and Jenkins at once: three unrelated products, one
    wrong answer, indistinguishable from a hit.

    Matching whole words keeps the short aliases usable rather than banning
    them -- `go` is a real product, and it should match the word "go" and
    not the middle of "mongodb".
    """
    db = VulnDB(corpus)
    with VulnDB(corpus) as writer:
        writer._conn.execute(
            "INSERT INTO product_alias(cve_id, alias) VALUES(?, 'i')",
            (CORPUS_ONLY.cve_id,))
        writer._conn.commit()

    assert db.candidates_for_product("nginx") == []
    assert db.candidates_for_product("jenkins") == []
    assert db.candidates_for_product("microsoft iis httpd") == []
    db.close()


def test_a_wildcard_row_does_not_make_every_identity_known(corpus):
    """`knows_identity` matches exactly, and this is why.

    Applicability rows carry `*` for unspecified attributes. If the probe
    honoured wildcards, a single `vendor='*'` row among 2.8 million
    statements would answer "known" for every identifier ever invented --
    turning the check into a constant and restoring the exact bug it exists
    to close.
    """
    db = VulnDB(corpus)
    unknown = parse_cpe("cpe:2.3:a:nobody:nothing:1.0:*:*:*:*:*:*:*")

    assert db.knows_identity(unknown) is False
    db.close()


# --------------------------------------------------------------------------- #
# coerce
# --------------------------------------------------------------------------- #

def test_coerce_accepts_a_plain_sequence():
    """664 existing tests pass `reference=[...]`. They must keep working."""
    resolver = coerce(list(DEFAULT_REFERENCE))
    assert isinstance(resolver, StaticResolver)
    assert len(resolver) == len(DEFAULT_REFERENCE)


def test_coerce_passes_a_resolver_through(corpus):
    original = from_env({ENV_VAR: str(corpus)})
    assert coerce(original) is original


def test_coerce_of_an_empty_sequence_is_empty_not_the_default():
    """An empty registry once became falsy and got silently replaced by the
    global default. Asking for nothing must yield nothing."""
    assert len(coerce([])) == 0
