"""The whole pipeline, end to end, with all three corpora live.

Every other file in this suite tests one seam. `test_wiring.py` proves the
three corpora are *reachable*; `test_golden_nmap.py` proves the importer
survives genuine nmap output; `test_resolver.py` proves a lead can come from
a corpus rather than the built-in nine. Nothing walked the whole chain in one
place, and the chain is where the interesting failures have always been --
every finding in `audit/AUDIT.md` with the shape "a control enforced on one
path and bypassed on a second" was invisible to a test that stopped at the
seam.

The journey under test, once, in order:

    tests/fixtures/nmap_sV_localhost.xml   real nmap 7.80 output
      -> parse_nmap_xml                    ports, services, CPEs, confidences
      -> POST /api/evidence                the authenticated ingress
      -> TargetStore                       host/port/service/fingerprint
      -> DiscoveryEngine + DbResolver      correlation against a real corpus
      -> LedgerRow                         prioritised, with provenance
      -> GET /handoff                      all three corpora consulted
      -> Command[]                         from all three sources, categorised

What is asserted is deliberately not "it returned 200". These are the
statements a refactor would break silently:

* the lead can be traced back to the tool *and* the principal that asserted
  the fingerprint it rests on, all the way from the rendered hand-off;
* the CVE came from the operator's corpus, not from `DEFAULT_REFERENCE` --
  the two entries used here are absent from the built-in nine, and asserted
  to be absent, so a regression to the built-ins reads as "no lead";
* the ledger is ordered by priority, and a KEV or EPSS signal genuinely
  moves an entry's position rather than merely appearing in its rationale;
* the default tier contains no opt-in command, opting in changes the set and
  surfaces the authorisation warning;
* an exploit-category item is named and never composed, at every tier;
* the whole thing still works with zero corpora configured, and says so.

Plus the invariant that has no single owner anywhere else: **no lead is
silently lost.** Every fingerprint in the graph either produced a ledger row
or has a reason it did not, drawn from the documented rules. A fingerprint
that falls through all of them is the failure this suite could not otherwise
see, because "no leads", "no corpus" and "confidence too low" all look
identical from outside.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from reconkg import app as app_module
from reconkg.builtin_modules import module_pipeline
from reconkg.catalog import ExploitRecord
from reconkg.commands import (DEFAULT_CATEGORIES, INTRUSIVE_WARNING,
                              NEVER_COMPOSED, Category)
from reconkg.cpe import CPERange, parse as parse_cpe
from reconkg.engine import DiscoveryEngine
from reconkg.exploitdb import ExploitDB
from reconkg.feeds import EpssScores, ExploitationSignals, KevCatalog
from reconkg.importers import ingest, parse_nmap_xml
from reconkg.models import ExploitMaturity
from reconkg.resolver import DbResolver
from reconkg.scriptdb import ScriptDB, ScriptEntry
from reconkg.stages import EvidenceSource
from reconkg.store import TargetStore
from reconkg.vulndb import VulnDB
from reconkg.vulnref import DEFAULT_REFERENCE, CorrelationConfig, VulnEntry

FIXTURES = Path(__file__).parent / "fixtures"
SCAN = FIXTURES / "nmap_sV_localhost.xml"
TARGET = "127.0.0.1"
HTTP_PORT = 8080
SSH_PORT = 2222

ADMIN_T = "a" * 24
VIEWER_T = "v" * 24
SCANNER_T = "s" * 24
OPERATOR_T = "o" * 24

ADMIN = {"Authorization": f"Bearer {ADMIN_T}"}
VIEWER = {"Authorization": f"Bearer {VIEWER_T}"}
SCANNER = {"Authorization": f"Bearer {SCANNER_T}"}
OPERATOR = {"Authorization": f"Bearer {OPERATOR_T}"}

TOKENS = (f"adm:admin:{ADMIN_T},"
          f"view:viewer:{VIEWER_T},"
          f"scan:scanner:{SCANNER_T},"
          f"lead:operator:{OPERATOR_T}")

#: The principal name the scanner credential authenticates as. Provenance
#: must carry this and not the tool label, and never the request body
#: (RC-01b).
SCANNER_PRINCIPAL = "scan"

# --------------------------------------------------------------------------- #
# Corpus one: two entries that are not in the built-in nine
#
# Both are real Apache httpd CVEs and neither appears in DEFAULT_REFERENCE,
# which `test_the_corpus_cves_are_absent_from_the_built_in_reference` asserts
# rather than assumes. If correlation regressed to the built-ins, every test
# below that names one of these would fail with "no such lead" instead of
# passing on a lead that came from the wrong place.
#
# The severities are chosen so that CVSS alone ranks HIGH above LOW by a
# factor of 1.33 -- less than KEV_FACTOR (1.6) and less than a maximum EPSS
# factor (1.5) -- so an exploitation signal on LOW has to be able to reorder
# the ledger. Both priorities stay well below the 1.0 clamp, where a
# reordering test would silently stop testing anything.
# --------------------------------------------------------------------------- #

APACHE_CPE = parse_cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")

CORPUS_HIGH = VulnEntry(
    cve_id="CVE-2023-25690",
    title="Apache mod_proxy HTTP request smuggling",
    product_match="http_server",
    cvss=6.0,
    maturity=ExploitMaturity.FUNCTIONAL,
    notes="Requires a RewriteRule or ProxyPassMatch with an unsafe pattern.",
    cpe_ranges=(CPERange(cpe=APACHE_CPE,
                         version_start_including="2.4.0",
                         version_end_including="2.4.55"),),
)

CORPUS_LOW = VulnEntry(
    cve_id="CVE-2022-31813",
    title="Apache mod_proxy X-Forwarded-* header removal",
    product_match="http_server",
    cvss=4.5,
    maturity=ExploitMaturity.FUNCTIONAL,
    cpe_ranges=(CPERange(cpe=APACHE_CPE,
                         version_start_including="2.4.0",
                         version_end_including="2.4.53"),),
)

HIGH = CORPUS_HIGH.cve_id
LOW = CORPUS_LOW.cve_id

#: Corpus two's whole output for this lead. `searchsploit -x <id>` is built
#: only by `handoff._exploit_commands`; nothing else in the codebase emits
#: `-x`, and this id exists in no shipped index.
EDB_ID = "51193"

#: Corpus three. Neither name is an NSE category, neither is the `vuln`
#: seed, and nothing in the codebase names either of them.
SCRIPT_MARKER = "http-integration-marker"
SCRIPT_EXPLOIT = "http-vuln-cve2023-25690"


def build_vuln_db(tmp_path) -> str:
    path = tmp_path / "vuln.sqlite"
    with VulnDB(path) as db:
        db.ingest([CORPUS_HIGH, CORPUS_LOW])
        db.set_meta("built_at", "9999999999")
    return str(path)


def build_exploit_db(tmp_path) -> str:
    path = tmp_path / "exploits.sqlite"
    with ExploitDB(path) as db:
        db.ingest([ExploitRecord("exploit-db", f"EDB-{EDB_ID}",
                                 "Apache 2.4.x mod_proxy request smuggling",
                                 cves=(HIGH,), platform="linux",
                                 verified=True)])
    return str(path)


def build_script_db(tmp_path) -> str:
    path = tmp_path / "scripts.sqlite"
    with ScriptDB(path) as db:
        db.ingest([
            ScriptEntry(filename=f"{SCRIPT_MARKER}.nse", name=SCRIPT_MARKER,
                        categories=("safe", "discovery")),
            ScriptEntry(filename=f"{SCRIPT_EXPLOIT}.nse",
                        name=SCRIPT_EXPLOIT, categories=("exploit",)),
        ])
    return str(path)


# --------------------------------------------------------------------------- #
# Fixtures: the app, with and without corpora
# --------------------------------------------------------------------------- #

def _fresh_state(monkeypatch):
    monkeypatch.setenv("RECONKG_TOKENS", TOKENS)
    monkeypatch.delenv("RECONKG_SNAPSHOT_DIR", raising=False)
    app_module.state = app_module.AppState()
    return app_module


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """All three corpora built on disk and pointed at by the environment."""
    monkeypatch.setenv("RECONKG_VULN_DB", build_vuln_db(tmp_path))
    monkeypatch.setenv("RECONKG_EXPLOIT_DB", build_exploit_db(tmp_path))
    monkeypatch.setenv("RECONKG_SCRIPT_DB", build_script_db(tmp_path))
    module = _fresh_state(monkeypatch)
    with TestClient(module.app) as client:
        yield module, client


@pytest.fixture
def offline(monkeypatch):
    """No corpus of any kind. The demonstration path, and the default."""
    for var in ("RECONKG_VULN_DB", "RECONKG_EXPLOIT_DB", "RECONKG_SCRIPT_DB"):
        monkeypatch.delenv(var, raising=False)
    module = _fresh_state(monkeypatch)
    with TestClient(module.app) as client:
        yield module, client


# --------------------------------------------------------------------------- #
# The import -> ingress -> store -> scan leg
# --------------------------------------------------------------------------- #

def import_and_submit(client, scan: Path = SCAN) -> dict:
    """Real nmap XML through the authenticated ingress, then a scan.

    The importer's per-host payload *is* the evidence body -- that is what
    `ImportResult.hosts` is for -- so this posts exactly what
    `importers.ingest` would have staged, under exactly the tool keys the
    scan file's own `<scaninfo type=...>` selected. Nothing is hand-written,
    which is what makes the fingerprint downstream a real one.
    """
    result = parse_nmap_xml(scan)
    assert result.host_count == 1, "fixture should describe exactly one host"
    address, payload = next(iter(result.hosts.items()))

    created = client.post("/api/targets", json={"address": address},
                          headers=OPERATOR)
    assert created.status_code == 201, created.text

    for key, tool in (("ports", result.port_tool),
                      ("services", result.service_tool)):
        if not payload.get(key):
            continue
        posted = client.post("/api/evidence", headers=SCANNER, json={
            "tool": tool, "address": address, "data": {key: payload[key]}})
        assert posted.status_code == 201, posted.text

    scanned = client.post(f"/api/targets/{address}/scan", headers=SCANNER)
    assert scanned.status_code == 200, scanned.text
    return scanned.json()


def test_the_corpus_cves_are_absent_from_the_built_in_reference():
    """The control that makes every corpus assertion below mean something."""
    built_in = {entry.cve_id for entry in DEFAULT_REFERENCE}
    assert HIGH not in built_in
    assert LOW not in built_in


def test_a_real_scan_file_reaches_the_graph_as_host_port_service_fingerprint(
        wired):
    """Leg one, asserted at the graph rather than at the parser.

    `test_golden_nmap.py` checks the parser's output. This checks that the
    output survived the HTTP ingress, the reliability clamp and the stage
    routing, and is in the store as four distinct kinds of node.
    """
    module, client = wired
    import_and_submit(client)

    host = module.state.store.get(TARGET)
    assert host is not None
    port = host.find_port(HTTP_PORT)
    assert port is not None and port.state.value == "open"

    service = next(svc for prt, svc in host.iter_services()
                   if prt.number == HTTP_PORT)
    assert service.name == "http"
    fingerprint = service.best_fingerprint()
    assert fingerprint is not None
    assert (fingerprint.product, fingerprint.version) == ("Apache httpd",
                                                          "2.4.49")
    assert fingerprint.cpe == "cpe:/a:apache:http_server:2.4.49"
    assert fingerprint.ambiguous is False

    # And the ssh listener came through the same run, so this is a graph and
    # not one lucky path.
    ssh = next(svc for prt, svc in host.iter_services()
               if prt.number == SSH_PORT)
    assert ssh.best_fingerprint().product == "OpenSSH"


def test_provenance_survives_the_whole_chain(wired):
    """Who said this, with what, and how sure were we allowed to be.

    Traced in the direction an analyst actually needs it: from a line in the
    rendered hand-off back to the fingerprint, and from the fingerprint back
    to the authenticated submitter. Every link here has been a finding at
    some point -- RC-01 (declared confidence taken at face value), RC-01b
    (independence keyed on a caller-supplied tool label), and the
    `maturity_source`/`match_method` columns that say what kind of claim the
    row is.
    """
    module, client = wired
    import_and_submit(client)

    host = module.state.store.get(TARGET)
    fingerprint = next(svc for prt, svc in host.iter_services()
                       if prt.number == HTTP_PORT).best_fingerprint()

    # The fingerprint names its tool and its principal, and the principal is
    # the credential's, not the body's.
    assert fingerprint.provenance.source_tool == "nmap-sV"
    assert fingerprint.provenance.principal == SCANNER_PRINCIPAL
    # nmap said conf="10"; the registry ceiling for a banner grab is 0.75.
    assert fingerprint.provenance.declared_confidence == 1.0
    assert fingerprint.provenance.confidence == 0.75
    assert fingerprint.corroborating_tools == {"nmap-sV"}
    assert fingerprint.corroborating_principals == {SCANNER_PRINCIPAL}

    # The lead in the graph points back at that exact fingerprint node.
    lead = next(l for l in host.all_leads() if l.cve_id == HIGH)
    assert lead.matched_fingerprint_id == fingerprint.id

    # The ledger row carries the same two facts, and says what kind of match
    # attached the CVE.
    row = next(r for r in module.state.reports[TARGET].ledger
               if r.cve_id == HIGH)
    assert row.corroborated_by == ["nmap-sV"]
    assert row.independent_principals == [SCANNER_PRINCIPAL]
    assert row.fingerprint_confidence == 0.75
    assert row.match_method == "cpe_range"
    assert row.maturity_source == "declared"

    # And it is legible in the text an operator reads, which is the only
    # place most of them will ever look.
    body = client.get(f"/api/targets/{TARGET}/handoff/{HIGH}",
                      headers=VIEWER).json()
    assert SCANNER_PRINCIPAL in body["rendered"]
    assert "1 independent submitter(s)" in body["rendered"]
    assert "Only one independent submitter" in " ".join(body["caveats"])


def test_the_lead_came_from_the_corpus_and_not_from_the_built_in_nine(wired):
    """The RC-36 property, asserted at the end of the chain instead of at
    the resolver: a CVE in the ledger that exists in no shipped table."""
    _module, client = wired
    import_and_submit(client)

    ledger = client.get(f"/api/targets/{TARGET}/ledger",
                        headers=VIEWER).json()
    found = {row["cve_id"] for row in ledger}
    assert HIGH in found and LOW in found
    # The built-in Apache entry for this exact version is *not* here, which
    # is the other half of the claim: the corpus replaced the reference, it
    # did not merge with it.
    assert "CVE-2021-41773" not in found

    corpus = client.get("/api/corpus", headers=VIEWER).json()
    by_name = {entry["corpus"]: entry for entry in corpus["corpora"]}
    assert by_name["vulnerabilities"]["resolver"] == "DbResolver"
    assert by_name["vulnerabilities"]["demonstration_fixture"] is False
    assert "2 CVEs" in by_name["vulnerabilities"]["describe"]


def test_the_ledger_is_ordered_by_priority(wired):
    _module, client = wired
    import_and_submit(client)
    ledger = client.get(f"/api/targets/{TARGET}/ledger",
                        headers=VIEWER).json()

    priorities = [row["priority"] for row in ledger]
    assert priorities == sorted(priorities, reverse=True)
    assert len(priorities) >= 2, "need two rows for ordering to mean anything"
    # Severity alone puts HIGH first, which is what the signal tests below
    # have to be able to overturn.
    assert ledger[0]["cve_id"] == HIGH
    # `min_priority` is a filter on the same ordering, not a second one.
    cut = ledger[0]["priority"]
    top = client.get(f"/api/targets/{TARGET}/ledger?min_priority={cut}",
                     headers=VIEWER).json()
    assert [row["cve_id"] for row in top] == [
        row["cve_id"] for row in ledger if row["priority"] >= cut]


# --------------------------------------------------------------------------- #
# The hand-off leg: three corpora, one lead
# --------------------------------------------------------------------------- #

def _handoff(client, cve: str = HIGH, categories: str = "") -> dict:
    query = f"?categories={categories}" if categories else ""
    response = client.get(f"/api/targets/{TARGET}/handoff/{cve}{query}",
                          headers=VIEWER)
    assert response.status_code == 200, response.text
    return response.json()


def test_the_handoff_carries_commands_from_all_three_corpora(wired):
    """The end of the chain, and the assertion `test_wiring.py` makes one
    corpus at a time. Each of these lines can only have come from one
    source, and all three have to be present in the same response for the
    hand-off to be what it claims to be."""
    _module, client = wired
    import_and_submit(client)
    body = _handoff(client, categories="safe,discovery,version,vuln")

    rendered = body["rendered"]
    sources = {command["source"] for command in body["commands"]}

    # Corpus one: the lead itself, and the reference links keyed on its id.
    assert body["lead"]["cve_id"] == HIGH
    assert f"https://nvd.nist.gov/vuln/detail/{HIGH}" in body["references"]
    # Corpus one's operator note reaches the caveats.
    assert any("ProxyPassMatch" in caveat for caveat in body["caveats"])

    # Corpus two: `searchsploit -x <id>`, built nowhere else.
    assert "exploitdb-corpus" in sources
    assert any(command["rendered"] == f"searchsploit -x {EDB_ID}"
               for command in body["commands"])
    assert f"searchsploit -x {EDB_ID}" in rendered

    # Corpus three: a script name that exists only in the index built above.
    composed = {command["rendered"] for command in body["commands"]
                if command["composed"]}
    assert f"nmap -p {HTTP_PORT} --script {SCRIPT_MARKER} {TARGET}" in composed
    assert SCRIPT_MARKER in rendered


def test_the_default_tier_holds_no_opt_in_command_and_opting_in_changes_it(
        wired):
    """Two claims that only mean something together.

    A default tier with no opt-in command is trivially satisfiable by
    emitting nothing, and an opt-in that changes nothing is a tickbox that
    lies. So: the default set is non-empty and entirely non-opt-in, the
    opted-in set is a strict superset, and the warning appears with it and
    only with it.
    """
    _module, client = wired
    import_and_submit(client)

    default = _handoff(client)
    every = _handoff(client, categories=",".join(c.value for c in Category))

    assert default["commands"], "the default tier must not be empty"
    permitted = {c.value for c in DEFAULT_CATEGORIES}
    for command in default["commands"]:
        if command["composed"]:
            assert command["category"] in permitted, command
            assert command["requires_opt_in"] is False, command

    default_lines = {c["rendered"] for c in default["commands"]}
    every_lines = {c["rendered"] for c in every["commands"]}
    assert default_lines < every_lines, "opting in must widen the set"
    assert any(c["requires_opt_in"] for c in every["commands"])

    # The authorisation warning rides with the opt-in commands, not with the
    # default ones -- RC-34's finding was exactly a line that escaped it.
    assert INTRUSIVE_WARNING not in default["rendered"]
    assert INTRUSIVE_WARNING in every["rendered"]
    assert "--script vuln" not in " ".join(default["lookups"])
    assert any("--script vuln" in line for line in every["lookups"])


@pytest.mark.parametrize("categories", [
    "",
    "safe",
    "safe,discovery,version",
    "safe,discovery,version,vuln,intrusive",
    "exploit",
    "exploit,dos,brute,fuzzer",
])
def test_an_exploit_category_item_is_named_and_never_composed_at_every_tier(
        wired, categories):
    """The boundary, swept across the tickboxes rather than asserted once.

    The `exploit`-category script comes from the corpus, so this is also the
    statement that wiring a third-party index in cannot widen what reconkg
    will aim at a host: whatever the operator ticks, the exploit tier is
    named and never carries an argv.
    """
    _module, client = wired
    import_and_submit(client)
    body = _handoff(client, categories=categories)

    never = {c.value for c in NEVER_COMPOSED}
    for command in body["commands"]:
        if command["category"] in never:
            assert command["composed"] is False, command
            assert command["argv"] is None, command
        # And no composed command may carry a category *selector* as its
        # script argument, whatever the row claimed (RC-37).
        for token in (command["argv"] or ()):
            assert token not in ("all", "exploit", "brute", "dos", "fuzzer")

    if "exploit" in categories:
        named = [c for c in body["commands"]
                 if SCRIPT_EXPLOIT in (c["reference"] or "")]
        assert named, body["commands"]
        assert all(c["composed"] is False for c in named)


# --------------------------------------------------------------------------- #
# The offline path: no corpus at all
# --------------------------------------------------------------------------- #

def test_the_whole_chain_works_with_zero_corpora_and_says_so(offline):
    """The demonstration path an operator gets on a clean checkout.

    Everything answers, and every one of the three corpora states in its own
    words that it was not consulted -- which is the distinction the panel
    exists for. "No known exploit" from an index nobody configured is not a
    finding, and a system that renders it identically to a real negative is
    lying by omission.
    """
    module, client = offline
    import_and_submit(client)

    ledger = client.get(f"/api/targets/{TARGET}/ledger",
                        headers=VIEWER).json()
    # The built-in nine, correlating the same real fingerprints.
    found = {row["cve_id"] for row in ledger}
    assert "CVE-2021-41773" in found          # Apache 2.4.49 on 8080
    assert "CVE-2018-15473" in found          # OpenSSH 7.4 on 2222
    assert HIGH not in found and LOW not in found

    body = _handoff(client, "CVE-2021-41773")
    assert body["commands"] and body["rendered"]
    assert not [c for c in body["commands"]
                if c["source"] == "exploitdb-corpus"]
    assert SCRIPT_MARKER not in body["rendered"]

    corpus = client.get("/api/corpus", headers=VIEWER).json()
    by_name = {entry["corpus"]: entry for entry in corpus["corpora"]}
    assert by_name["vulnerabilities"]["demonstration_fixture"] is True
    assert "not a vulnerability database" in \
        by_name["vulnerabilities"]["describe"]
    assert by_name["exploits"]["configured"] is False
    assert "means 'not checked'" in by_name["exploits"]["describe"]
    assert by_name["scripts"]["configured"] is False
    assert "never assumed safe" in by_name["scripts"]["describe"]

    # The resolvers say it directly too, which is where the route gets it.
    assert "demonstration fixture" in module.state.engine.resolver.describe()
    assert "not checked" in module.state.exploits.describe()
    assert "unknown" in module.state.scripts.describe()


# --------------------------------------------------------------------------- #
# Exploitation signals actually reorder
# --------------------------------------------------------------------------- #

async def _ingested() -> tuple[TargetStore, EvidenceSource]:
    """A store holding the real scan file, staged as the importer stages it.

    A fresh pair per engine on purpose: re-running a pipeline over one store
    re-observes every fingerprint, which changes the confidences the leads
    are scored from -- and a reordering test whose two runs disagree about
    the inputs is testing nothing it claims to test.
    """
    store, evidence = TargetStore(), EvidenceSource()
    result = parse_nmap_xml(SCAN)
    added = await ingest(result, store, evidence, principal="scanner-a")
    assert added == [TARGET]
    return store, evidence


async def _ledger_with(signals, corpus_path: str):
    store, evidence = await _ingested()
    engine = DiscoveryEngine(store, evidence, module_pipeline(),
                             reference=DbResolver(VulnDB(corpus_path)),
                             signals=signals)
    try:
        return await engine.run(TARGET)
    finally:
        engine.resolver.close()


def _kev(tmp_path, cve: str) -> KevCatalog:
    path = tmp_path / "kev.json"
    path.write_text(json.dumps({
        "catalogVersion": "2026.08.19",
        "vulnerabilities": [{
            "cveID": cve, "vendorProject": "Apache", "product": "httpd",
            "vulnerabilityName": "Apache HTTP Server flaw",
            "dateAdded": "2026-01-05",
            "knownRansomwareCampaignUse": "Known"}]}))
    catalog = KevCatalog()
    catalog.load(path)
    assert cve in catalog
    return catalog


def _epss(tmp_path, cve: str) -> EpssScores:
    path = tmp_path / "epss.csv"
    path.write_text("#model_version:v2025.03.14,score_date:2026-08-19\n"
                    "cve,epss,percentile\n"
                    f"{cve},0.97400,0.99900\n")
    scores = EpssScores()
    scores.load(path)
    assert scores.probability(cve) == pytest.approx(0.974)
    return scores


async def test_the_ledger_ranks_on_severity_when_nothing_is_known(tmp_path):
    """The baseline the two tests below overturn."""
    report = await _ledger_with(None, build_vuln_db(tmp_path))
    order = [row.cve_id for row in report.ledger]
    assert order.index(HIGH) < order.index(LOW)
    assert [r.priority for r in report.ledger] == \
        sorted((r.priority for r in report.ledger), reverse=True)


@pytest.mark.parametrize("signal", ["kev", "epss"])
async def test_an_exploitation_signal_moves_an_entry_up_the_ledger(tmp_path,
                                                                   signal):
    """Not "the rationale mentions KEV" -- the row *moves*.

    A mid-severity CVE under active exploitation must be able to pass a
    higher-severity one nobody is touching; that is the operational rule the
    feeds exist for, and it is only true if the multiplier is applied before
    the clamp and before the sort. Asserting the explanatory text would pass
    on an implementation that computed the factor and then discarded it.
    """
    corpus = build_vuln_db(tmp_path)
    baseline = await _ledger_with(None, corpus)
    before = {row.cve_id: row.priority for row in baseline.ledger}

    if signal == "kev":
        signals = ExploitationSignals(kev=_kev(tmp_path, LOW))
        expected = "KEV: actively exploited"
    else:
        signals = ExploitationSignals(epss=_epss(tmp_path, LOW))
        expected = "EPSS"

    report = await _ledger_with(signals, corpus)
    order = [row.cve_id for row in report.ledger]
    assert order.index(LOW) < order.index(HIGH), (
        f"{signal} did not reorder: "
        f"{[(r.cve_id, r.priority) for r in report.ledger]}")

    lifted = next(r for r in report.ledger if r.cve_id == LOW)
    untouched = next(r for r in report.ledger if r.cve_id == HIGH)
    assert lifted.priority > before[LOW]
    assert untouched.priority == before[HIGH], \
        "a signal on one CVE must not move another"
    assert expected in lifted.rationale
    assert expected not in untouched.rationale
    # The ordering invariant still holds after the signal is applied.
    assert [r.priority for r in report.ledger] == \
        sorted((r.priority for r in report.ledger), reverse=True)


# --------------------------------------------------------------------------- #
# No lead is silently lost
# --------------------------------------------------------------------------- #

def _reason_for_no_lead(fingerprint, resolver, cfg: CorrelationConfig) -> str:
    """The documented reasons a fingerprint produces no lead, in the order
    `build_leads` applies them.

    Anything not covered here is a fingerprint the system dropped for a
    reason nobody wrote down, which is the failure the test below exists to
    catch: from outside, "the host is clean", "the corpus holds nothing for
    it" and "we did not believe the banner" all render as an empty ledger.
    """
    if fingerprint.confidence < cfg.min_confidence:
        return (f"confidence {fingerprint.confidence:.2f} below the "
                f"correlation floor {cfg.min_confidence:.2f}")
    if not fingerprint.version and not cfg.include_unversioned:
        return "no version, and unversioned leads are off"
    candidates = list(resolver.candidates(fingerprint))
    if not candidates:
        return "the corpus returned no candidate entry for this product"
    rejections = []
    for entry in candidates:
        matched, why, _method = entry.matches(fingerprint)
        if matched:
            return ""       # a match with no lead is the bug, not a reason
        rejections.append(f"{entry.cve_id}: {why}")
    return "; ".join(rejections)


async def test_no_lead_is_silently_lost(tmp_path):
    """Every fingerprint in the graph is accounted for.

    The real scan file carries five services and the shapes are deliberately
    unlike each other: a probed version with a CPE the corpus knows, a
    probed version with a CPE it has never heard of, a product with no
    version at all, a `tcpwrapped` non-answer, and a table guess on a closed
    port. Each one must either appear in the ledger or have a reason it does
    not, and the reason must be one of the rules the correlator documents.

    This is the invariant no single test owned. `_correlate` iterates
    services, fingerprints and candidates in nested loops with several
    `continue`s between them, and a fingerprint that falls out of the middle
    of that is invisible: the ledger is simply shorter, and shorter looks
    exactly like safer.
    """
    store, evidence = await _ingested()
    resolver = DbResolver(VulnDB(build_vuln_db(tmp_path)))
    engine = DiscoveryEngine(store, evidence, module_pipeline(),
                             reference=resolver)
    try:
        report = await engine.run(TARGET)

        host = store.get(TARGET)
        fingerprints = [(port, fp) for port, svc in host.iter_services()
                        for fp in svc.fingerprints]
        assert len(fingerprints) >= 4, \
            "the fixture should produce several distinct fingerprints"

        with_leads = {lead.matched_fingerprint_id
                      for lead in host.all_leads()}
        explained, unexplained = {}, []
        for port, fingerprint in fingerprints:
            if fingerprint.id in with_leads:
                continue
            reason = _reason_for_no_lead(fingerprint, resolver,
                                         engine.correlation)
            if reason:
                explained[(port.number, fingerprint.key)] = reason
            else:
                unexplained.append((port.number, fingerprint.key))

        assert not unexplained, (
            "fingerprint(s) produced no lead and no recorded reason: "
            f"{unexplained}")
        # Not vacuous in either direction: some fingerprints led somewhere,
        # some did not, and every one of the latter has a stated reason.
        assert with_leads, "no fingerprint produced a lead at all"
        assert explained, "no fingerprint was rejected -- test is vacuous"
        assert all(reason for reason in explained.values())

        # Every ledger row is traceable back to a fingerprint that is still
        # in the graph. The converse direction of the same invariant: a row
        # about a node nobody can find is as bad as a node with no row.
        ids = {fp.id for _port, fp in fingerprints}
        for lead in host.all_leads():
            assert lead.matched_fingerprint_id in ids

        # And the report's ledger agrees with the graph, row for row.
        assert sorted(r.cve_id for r in report.ledger) == \
            sorted(lead.cve_id for lead in host.all_leads())
    finally:
        resolver.close()


async def test_the_reasons_are_the_ones_the_correlator_actually_documents(
        tmp_path):
    """The companion to the test above: the reasons are specific.

    A "reason" that is the same string for every rejected fingerprint would
    satisfy the invariant and tell an analyst nothing. These are the
    distinct rules the fixture is built to exercise, each named by the
    fingerprint it applies to.
    """
    store, evidence = await _ingested()
    resolver = DbResolver(VulnDB(build_vuln_db(tmp_path)))
    engine = DiscoveryEngine(store, evidence, module_pipeline(),
                             reference=resolver)
    try:
        await engine.run(TARGET)
        host = store.get(TARGET)
        by_port = {port.number: fp for port, svc in host.iter_services()
                   for fp in svc.fingerprints}

        # OpenSSH 7.4: believed, versioned, and simply not in this corpus.
        ssh = _reason_for_no_lead(by_port[SSH_PORT], resolver,
                                  engine.correlation)
        assert "no candidate entry" in ssh

        # Postfix answered with a product and no version, so the banner
        # stage halved its confidence and it never reached the floor.
        smtp = _reason_for_no_lead(by_port[2525], resolver,
                                   engine.correlation)
        assert "below the correlation floor" in smtp

        # tcpwrapped is nmap declining to identify. It must not be a lead
        # and it must not be silent either.
        wrapped = _reason_for_no_lead(by_port[6379], resolver,
                                      engine.correlation)
        assert "below the correlation floor" in wrapped

        assert len({ssh, smtp}) == 2, "reasons must distinguish the cases"
    finally:
        resolver.close()


# --------------------------------------------------------------------------- #
# Failure records survive the chain too
# --------------------------------------------------------------------------- #

def test_the_attempt_record_names_the_techniques_that_did_not_work(wired):
    """"Port 445 timed out under sT twice" is information.

    The engine's module docstring makes this promise and the API exposes it;
    a real scan file exercises it because the SYN sweep has no evidence
    staged under its key and falls back to the connect sweep, exactly as an
    operator who ran `nmap -sT` would see.
    """
    _module, client = wired
    import_and_submit(client)
    body = client.get(f"/api/targets/{TARGET}/attempts",
                      headers=VIEWER).json()

    attempts = body["attempts"]
    assert attempts
    outcomes = {(a["tool"], a["outcome"]) for a in attempts}
    assert ("nmap-sS", "no_data") in outcomes, \
        "the primary sweep had no fixture and must be recorded as such"
    assert ("nmap-sT", "success") in outcomes, "the fallback carried the slot"
    assert ("nmap-sV", "ambiguous") in outcomes, \
        "the unversioned smtp banner must route to the fallback"
    for attempt in attempts:
        assert attempt["slot"] and attempt["stage"] and attempt["detail"]
        assert attempt["duration_ms"] >= 0.0
