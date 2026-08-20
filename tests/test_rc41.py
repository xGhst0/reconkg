"""RC-41: the entry lookup consulted a different source from the lead.

`build_handoff` finds the `VulnEntry` behind a lead to source two things an
analyst reads: the caveats (from `entry.notes`) and any operator-supplied
follow-up commands (`entry.handoff`). Every caller handed it
`DEFAULT_REFERENCE` -- the nine built-in CVEs -- while the lead itself came
from whatever resolver was configured.

So the lookup succeeded for nine CVEs and missed for every one of the
~250,000 a real corpus holds. The corpus's own note about a vulnerability was
dropped, silently, on exactly the leads the corpus exists to produce. Nothing
failed, nothing logged, and the demo path looked perfect.

Eleventh instance of one shape: a control or a lookup implemented on one path
and forgotten on the second. It was found by an integration test rather than
a unit test, which is the point -- every unit test passed `DEFAULT_REFERENCE`
and every unit test was right about what it asserted.
"""

from __future__ import annotations

import pytest

from reconkg.cpe import CPERange, parse as parse_cpe
from reconkg.handoff import _entry_for, build_handoff
from reconkg.models import ExploitMaturity
from reconkg.resolver import (ENV_VAR, StaticResolver, from_env)
from reconkg.vulndb import VulnDB
from reconkg.vulnref import DEFAULT_REFERENCE, LedgerRow, VulnEntry

CORPUS_CVE = "CVE-2023-99991"
NOTE = ("Only exploitable when mod_proxy is enabled with a ProxyPassMatch "
        "rule; check the vhost before spending time on this.")
OPERATOR_STEP = "curl -sk https://example.invalid/healthz"

ENTRY = VulnEntry(
    cve_id=CORPUS_CVE, title="Synthetic corpus flaw",
    product_match="widgetserv", cvss=9.1,
    maturity=ExploitMaturity.NOT_DEFINED, notes=NOTE,
    handoff=(OPERATOR_STEP,),
    cpe_ranges=(CPERange(
        cpe=parse_cpe("cpe:2.3:a:fictional:widgetserv:*:*:*:*:*:*:*:*"),
        version_start_including="2.0", version_end_excluding="3.0"),),
)


@pytest.fixture
def corpus(tmp_path):
    path = tmp_path / "vuln.db"
    with VulnDB(path) as db:
        db.ingest([ENTRY])
    return path


def _row(cve_id: str = CORPUS_CVE) -> LedgerRow:
    return LedgerRow(
        target="10.10.10.42", port=8080, protocol="tcp", service="http",
        product="widgetserv", version="2.5", cve_id=cve_id,
        title="Synthetic corpus flaw", cvss=9.1, maturity="not_defined",
        priority=0.8, fingerprint_confidence=0.9, rationale="cpe_exact")


# --------------------------------------------------------------------------- #
# The finding
# --------------------------------------------------------------------------- #

def test_a_corpus_cve_carries_its_own_note_into_the_caveats(corpus):
    """The failing assertion, minimised. Before the fix this returned the
    generic caveats and dropped the corpus note entirely."""
    resolver = from_env({ENV_VAR: str(corpus)})
    built = build_handoff(_row(), resolver)

    assert any(NOTE in caveat for caveat in built.caveats), (
        "the corpus entry's note never reached the analyst")
    resolver.close()


def test_a_corpus_cve_carries_its_operator_supplied_commands(corpus):
    """`VulnEntry.handoff` is the one field where an operator puts a command
    they verified themselves. Losing it is losing the only suggestion in the
    system that was not generated."""
    resolver = from_env({ENV_VAR: str(corpus)})
    built = build_handoff(_row(), resolver)

    assert OPERATOR_STEP in built.operator_supplied
    resolver.close()


def test_the_note_reaches_the_rendered_text(corpus):
    resolver = from_env({ENV_VAR: str(corpus)})
    assert NOTE in build_handoff(_row(), resolver).render()
    resolver.close()


def test_the_built_in_path_still_works():
    """The nine were never broken, and the fix must not break them. This is
    the half that kept passing and hid the other half."""
    entry = DEFAULT_REFERENCE[0]
    built = build_handoff(_row(entry.cve_id), StaticResolver())
    if entry.notes:
        assert any(entry.notes in c for c in built.caveats)


# --------------------------------------------------------------------------- #
# `_entry_for` accepts either shape
# --------------------------------------------------------------------------- #

def test_a_plain_iterable_still_resolves():
    """Every existing test passes a list. They must keep working, or the fix
    trades one silent regression for another."""
    assert _entry_for(DEFAULT_REFERENCE, DEFAULT_REFERENCE[0].cve_id) is not None


def test_a_resolver_resolves(corpus):
    resolver = from_env({ENV_VAR: str(corpus)})
    found = _entry_for(resolver, CORPUS_CVE)
    assert found is not None and found.notes == NOTE
    resolver.close()


def test_an_unknown_cve_returns_none_from_both_shapes(corpus):
    resolver = from_env({ENV_VAR: str(corpus)})
    assert _entry_for(resolver, "CVE-1999-0001") is None
    assert _entry_for(DEFAULT_REFERENCE, "CVE-1999-0001") is None
    resolver.close()


@pytest.mark.parametrize("spelling", [
    CORPUS_CVE, CORPUS_CVE.lower(), f"  {CORPUS_CVE}  "])
def test_the_lookup_is_not_case_or_whitespace_sensitive(corpus, spelling):
    """A ledger row's id and a corpus key differing only in case would
    reproduce the whole finding one layer down."""
    resolver = from_env({ENV_VAR: str(corpus)})
    assert _entry_for(resolver, spelling) is not None
    resolver.close()


def test_a_broken_resolver_degrades_rather_than_500s(caplog):
    """A hand-off that raises takes out the whole route. Losing the notes is
    bad; losing the lead is worse."""
    class Exploding:
        def entry_for(self, cve_id):
            raise RuntimeError("index unavailable")

    with caplog.at_level("WARNING"):
        assert _entry_for(Exploding(), CORPUS_CVE) is None
    assert any("entry lookup failed" in r.message for r in caplog.records)


def test_a_non_iterable_reference_does_not_raise():
    assert _entry_for(None, CORPUS_CVE) is None
    assert _entry_for(42, CORPUS_CVE) is None


# --------------------------------------------------------------------------- #
# Both paths, because fixing one is how this happened
# --------------------------------------------------------------------------- #

def test_the_api_and_the_console_agree_on_the_caveats(corpus, monkeypatch):
    """The API was fixed first. Had the console not been fixed with it, the
    REPL and the HTTP route would report different caveats for the same lead
    on the same host -- which is RC-41 reproduced rather than resolved."""
    from reconkg.console import Console

    monkeypatch.setenv(ENV_VAR, str(corpus))
    console = Console()
    try:
        api_resolver = from_env({ENV_VAR: str(corpus)})
        try:
            api = build_handoff(_row(), api_resolver)
        finally:
            api_resolver.close()
        cli = build_handoff(_row(), console.resolver)
        assert api.caveats == cli.caveats
        assert api.operator_supplied == cli.operator_supplied
    finally:
        console.close()


def test_the_console_no_longer_holds_a_list_that_shadows_its_resolver(corpus,
                                                                     monkeypatch):
    """`Console.reference` was a list of the built-in nine whenever a corpus
    was configured. The attribute survives for compatibility; it must not be
    a different source from `resolver`."""
    from reconkg.console import Console

    monkeypatch.setenv(ENV_VAR, str(corpus))
    console = Console()
    try:
        assert console.reference is console.resolver
    finally:
        console.close()


# --------------------------------------------------------------------------- #
# RC-42: a truncated candidate set kept the wrong rows
#
# Found by `reconkg.selfcheck` on a 30,000-CVE corpus, not by any test here.
# `apache:http_server` narrowed to 3,806 rows, of which 1,918 could contain
# version 2.4.49. `LIMIT 500` kept 501 -- and not one of them was a major-2
# row, because SQLite returns rows in rowid order and the corpus was written
# major-1-first. The applicable CVE was silently absent and the scan reported
# no lead for the single most common service on the internet.
#
# The truncation warning fired, correctly, and told the operator nothing they
# could act on. A warning is not a fix; ordering before limiting is.
# --------------------------------------------------------------------------- #

def test_rc42_truncation_keeps_the_rows_that_can_match(tmp_path):
    from reconkg.cpe import parse as parse_cpe

    # 900 rows for one product: 600 that cannot contain 2.4.49, written
    # first, then 300 that can. Insertion order is the trap.
    entries = []
    for n in range(600):
        entries.append(VulnEntry(
            cve_id=f"CVE-2000-{n:05d}", title="wrong major",
            product_match="http server", cvss=5.0,
            cpe_ranges=(CPERange(
                cpe=parse_cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
                version_start_including="1.0",
                version_end_excluding="2.0"),)))
    for n in range(300):
        entries.append(VulnEntry(
            cve_id=f"CVE-2021-{n:05d}", title="right major",
            product_match="http server", cvss=9.8,
            cpe_ranges=(CPERange(
                cpe=parse_cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
                version_start_including="2.4.0",
                version_end_excluding="2.5.0"),)))

    path = tmp_path / "big.db"
    with VulnDB(path) as db:
        db.ingest(entries)
        observed = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        found = db.candidates_for_cpe(observed, limit=100)

    assert len(found) <= 101
    applicable = [e for e in found
                  if any(r.version_start_including == "2.4.0"
                         for r in e.cpe_ranges)]
    assert applicable, (
        "the truncation discarded every row that could match; a lookup that "
        "returns only inapplicable candidates reports 'no lead' with total "
        "confidence")


def test_rc42_a_truncated_lookup_still_produces_the_lead(tmp_path):
    """The consequence, end to end. Ordering is only worth anything if a
    lead comes out the other side."""
    from reconkg.cpe import parse as parse_cpe
    from reconkg.models import Fingerprint, Provenance
    from reconkg.resolver import DbResolver
    from reconkg.vulnref import CorrelationConfig, build_leads

    entries = [VulnEntry(
        cve_id=f"CVE-2000-{n:05d}", title="wrong major",
        product_match="http server", cvss=5.0,
        cpe_ranges=(CPERange(
            cpe=parse_cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
            version_start_including="1.0",
            version_end_excluding="2.0"),)) for n in range(400)]
    entries.append(VulnEntry(
        cve_id="CVE-2021-41773", title="Path traversal",
        product_match="http server", cvss=9.8,
        cpe_ranges=(CPERange(
            cpe=parse_cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
            version_start_including="2.4.49",
            version_end_including="2.4.49"),)))

    path = tmp_path / "big.db"
    with VulnDB(path) as db:
        db.ingest(entries)
        resolver = DbResolver(db, limit=50)
        fp = Fingerprint(
            product="Apache httpd", version="2.4.49",
            cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            provenance=Provenance(source_tool="nmap", principal="t",
                                  confidence=0.9))
        leads = build_leads(fp, resolver.candidates(fp), CorrelationConfig())

    assert [lead.cve_id for lead in leads] == ["CVE-2021-41773"]
