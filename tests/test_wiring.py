"""Wiring the three corpora into the running system.

The defect this file exists for, in one sentence: `RECONKG_EXPLOIT_DB` and
`RECONKG_SCRIPT_DB` were read by nothing that shipped. `resolver.py` grew
`exploits_from_env` and `scripts_from_env`, `handoff.build_handoff` grew
`exploits=` and `scripts=` parameters, both corpora were built and tested --
and `app.handoff` called `build_handoff(row, DEFAULT_REFERENCE,
state.catalog, selected)`, `console.cmd_handoff` called it with three
arguments, and `AppState` held neither resolver. Two indexes an operator can
build, point an environment variable at, and never once be told were not
consulted.

That is RC-36 a second and third time. There, `DiscoveryEngine` defaulted
`reference=DEFAULT_REFERENCE`, so `coerce` never reached `from_env` and the
CVE corpus was silently ignored. The tests below are the RC-36 tests
repeated for the two corpora that had the same hole, plus the end-to-end
checks that say the wiring is real rather than merely present:

* set-but-unopenable raises at construction, on every surface;
* unset gives the Null variant, which is a claim about the question having
  been asked -- not about the answer being empty;
* a hand-off over HTTP carries a command that could only have come from the
  exploit corpus and one that could only have come from the script corpus;
* the API and the console answer identically for the same lead and the same
  category selection, because two surfaces disagreeing about which corpora
  are live is the bug class this codebase keeps re-finding;
* `/api/corpus` names all three, and the page renders all three.
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

from reconkg import app as app_module
from reconkg.catalog import ExploitRecord
from reconkg.commands import DEFAULT_CATEGORIES, NEVER_COMPOSED, Category
from reconkg.exploitdb import ExploitDB
from reconkg.resolver import (NullExploitResolver, NullScriptResolver,
                              StaticResolver)
from reconkg.scriptdb import ScriptDB, ScriptEntry

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

TARGET = "10.10.10.42"
CVE = "CVE-2021-41773"

#: Only the exploit corpus can produce this. `searchsploit -x <id>` is built
#: exclusively by `handoff._exploit_commands`, and the id is one this test
#: wrote into its own index -- the built-in catalogue has no such record and
#: no other builder emits `-x` at all.
EDB_ID = "50383"

#: Only the script corpus can produce this. It is not an NSE category, it is
#: not the `vuln` seed, and nothing in the codebase names it.
SCRIPT_MARKER = "http-corpus-marker"

#: Category `exploit` in the same index. It must arrive named and uncomposed
#: however the tickboxes are set.
SCRIPT_EXPLOIT = "http-vuln-cve2021-41773"


# --------------------------------------------------------------------------- #
# Corpora, built on disk exactly as an operator's `builddb` run leaves them
# --------------------------------------------------------------------------- #

def build_exploit_db(tmp_path) -> str:
    path = tmp_path / "exploits.sqlite"
    with ExploitDB(path) as db:
        db.ingest([ExploitRecord("exploit-db", f"EDB-{EDB_ID}",
                                 "Apache 2.4.49 path traversal",
                                 cves=(CVE,), platform="linux",
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


def _fresh_state(monkeypatch):
    monkeypatch.setenv("RECONKG_TOKENS", TOKENS)
    app_module.state = app_module.AppState()
    return app_module


def _seed(c, address: str = TARGET) -> None:
    """Enough evidence for the Apache 2.4.49 lead to reach the ledger."""
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


@pytest.fixture
def offline(monkeypatch):
    """No corpus of any kind configured. The default an operator gets."""
    for var in ("RECONKG_VULN_DB", "RECONKG_EXPLOIT_DB", "RECONKG_SCRIPT_DB"):
        monkeypatch.delenv(var, raising=False)
    module = _fresh_state(monkeypatch)
    with TestClient(module.app) as c:
        yield module, c


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """All three variables set, corpora two and three built in tmp_path."""
    monkeypatch.delenv("RECONKG_VULN_DB", raising=False)
    monkeypatch.setenv("RECONKG_EXPLOIT_DB", build_exploit_db(tmp_path))
    monkeypatch.setenv("RECONKG_SCRIPT_DB", build_script_db(tmp_path))
    module = _fresh_state(monkeypatch)
    with TestClient(module.app) as c:
        yield module, c


# --------------------------------------------------------------------------- #
# RC-36, repeated for corpus two and corpus three
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("var", ["RECONKG_EXPLOIT_DB", "RECONKG_SCRIPT_DB"])
def test_a_requested_corpus_is_not_silently_replaced(monkeypatch, tmp_path,
                                                     var):
    """The RC-36 test, twice more.

    An operator who set the variable made a claim: this index exists and I
    want it used. Answering "no published exploit for any CVE" or "categories
    unknown for every script" instead is a silent, confident, wrong answer on
    every lead of the run -- and it looks exactly like a clean result.
    """
    monkeypatch.setenv("RECONKG_TOKENS", TOKENS)
    monkeypatch.setenv(var, str(tmp_path / "absent.sqlite"))
    with pytest.raises(FileNotFoundError, match=var):
        app_module.AppState()


@pytest.mark.parametrize("var", ["RECONKG_EXPLOIT_DB", "RECONKG_SCRIPT_DB"])
def test_the_console_refuses_the_same_missing_corpus(monkeypatch, tmp_path,
                                                     var):
    """Same contract on the second surface. A console that starts happily
    against a corpus the API refuses to start against is the disagreement
    this work exists to remove."""
    from reconkg.console import Console

    monkeypatch.setenv(var, str(tmp_path / "absent.sqlite"))
    with pytest.raises(FileNotFoundError, match=var):
        Console(autoload_catalog=False)


def test_unset_gives_the_null_resolvers_and_says_which(offline):
    module, _c = offline
    assert isinstance(module.state.exploits, NullExploitResolver)
    assert isinstance(module.state.scripts, NullScriptResolver)
    assert isinstance(module.state.engine.resolver, StaticResolver)
    # The distinction the whole panel exists for.
    assert "not checked" in module.state.exploits.describe()
    assert "unknown" in module.state.scripts.describe()
    assert "never assumed safe" in module.state.scripts.describe()


def test_the_app_still_works_fully_offline(offline):
    """No corpus, no network, no degradation: scan, ledger and hand-off all
    answer, and the hand-off carries the commands it always did."""
    _module, c = offline
    _seed(c)
    assert c.get("/api/health", headers=VIEWER).status_code == 200
    ledger = c.get(f"/api/targets/{TARGET}/ledger", headers=VIEWER).json()
    assert any(row["cve_id"] == CVE for row in ledger)
    body = c.get(f"/api/targets/{TARGET}/handoff/{CVE}", headers=VIEWER).json()
    assert body["commands"]
    assert body["rendered"]


def test_offline_output_is_byte_identical_to_the_unwired_call(offline):
    """The default tier does not move.

    A lead with no opt-in must show exactly what it showed before this
    wiring: with the Null resolvers in place, passing them is the same
    hand-off as passing nothing.
    """
    from reconkg.handoff import build_handoff

    module, c = offline
    _seed(c)
    row = module.state.reports[TARGET].ledger[0]
    with_nulls = build_handoff(row, (), module.state.catalog, None,
                               exploits=module.state.exploits,
                               scripts=module.state.scripts)
    without = build_handoff(row, (), module.state.catalog, None)
    assert [x.as_dict() for x in with_nulls.commands] == \
           [x.as_dict() for x in without.commands]


# --------------------------------------------------------------------------- #
# End to end, through the HTTP layer
# --------------------------------------------------------------------------- #

def _commands(c, categories: str = ""):
    query = f"?categories={categories}" if categories else ""
    body = c.get(f"/api/targets/{TARGET}/handoff/{CVE}{query}",
                 headers=VIEWER)
    assert body.status_code == 200, body.text
    return body.json()


def test_the_handoff_carries_a_command_only_the_exploit_corpus_could_produce(
        wired):
    _module, c = wired
    _seed(c)
    body = _commands(c)
    exploit_lines = [x for x in body["commands"]
                     if x["source"] == "exploitdb-corpus"]
    assert exploit_lines, body["commands"]
    assert any(x["rendered"] == f"searchsploit -x {EDB_ID}"
               for x in exploit_lines)
    # And in the rendered text an operator actually reads.
    assert f"searchsploit -x {EDB_ID}" in body["rendered"]


def test_the_handoff_carries_a_command_only_the_script_corpus_could_produce(
        wired):
    _module, c = wired
    _seed(c)
    body = _commands(c)
    composed = {x["rendered"] for x in body["commands"] if x["composed"]}
    assert f"nmap -p 80 --script {SCRIPT_MARKER} 10.10.10.42" in composed
    assert SCRIPT_MARKER in body["rendered"]


def test_neither_corpus_line_appears_when_the_variables_are_unset(offline):
    """The converse. If these commands showed up without a corpus, the tests
    above would be asserting nothing."""
    _module, c = offline
    _seed(c)
    body = _commands(c)
    assert not [x for x in body["commands"]
                if x["source"] == "exploitdb-corpus"]
    assert SCRIPT_MARKER not in body["rendered"]


def test_an_exploit_category_script_from_the_corpus_stays_named_only(wired):
    """Wiring a corpus in must not widen what may be composed. `exploit` is
    never-composed whatever the tickboxes say."""
    _module, c = wired
    _seed(c)
    every = ",".join(x.value for x in Category)
    body = _commands(c, every)
    named = [x for x in body["commands"] if SCRIPT_EXPLOIT in
             (x["reference"] or "")]
    assert named, body["commands"]
    for command in named:
        assert command["composed"] is False
        assert command["argv"] is None
    for command in body["commands"]:
        if command["category"] in {x.value for x in NEVER_COMPOSED}:
            assert command["composed"] is False


def test_the_corpus_commands_respect_the_default_tier(wired):
    """The exploit-corpus line is `safe` -- it reads a local file and
    contacts nothing -- so it is in the default tier. The `exploit`-category
    script is not composed in it, or anywhere."""
    _module, c = wired
    _seed(c)
    default = ",".join(sorted(x.value for x in DEFAULT_CATEGORIES))
    body = _commands(c, default)
    assert any(x["source"] == "exploitdb-corpus" for x in body["commands"])
    opt_in = {"vuln", "intrusive", "unclassified", "auth", "default",
              "malware", "broadcast", "external"}
    for command in body["commands"]:
        if command["composed"]:
            assert command["category"] not in opt_in, command


# --------------------------------------------------------------------------- #
# The API and the console, on the same lead
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("categories", ["", "safe,discovery,version",
                                        "safe,discovery,version,vuln"])
def test_the_api_and_the_console_agree(wired, categories):
    """Same lead, same selection, same commands -- from both surfaces.

    The console is given the API's own ledger row so that the only thing
    under test is which corpora each side consults. Its catalogue is the
    API's for the same reason: an autoloaded index differing between the two
    would fail this test for a reason that is not the one it is asking about.
    """
    from reconkg.console import Console

    module, c = wired
    _seed(c)
    body = _commands(c, categories)

    console = Console(catalog=module.state.catalog, autoload_catalog=False)
    try:
        assert not isinstance(console.exploits, NullExploitResolver)
        assert not isinstance(console.scripts, NullScriptResolver)
        console.ws.ledger.extend(module.state.reports[TARGET].ledger)
        line = f"handoff {CVE}"
        if categories:
            line += f" --categories {categories}"
        assert console.execute(line).strip() == body["rendered"].strip()
    finally:
        console.close()


def test_the_console_refuses_an_unknown_category_rather_than_ignoring_it(
        offline):
    from reconkg.console import Console

    console = Console(autoload_catalog=False)
    try:
        out = console.execute(f"handoff {CVE} --categories safe,wizard")
        assert "unknown command category 'wizard'" in out
    finally:
        console.close()


def test_the_console_resolver_answers_the_environment_too(monkeypatch,
                                                          tmp_path):
    """RC-36 on the console's own fork: `reference` defaulted to the built-in
    nine, so the REPL never read `RECONKG_VULN_DB` while the API did."""
    from reconkg.console import Console

    monkeypatch.setenv("RECONKG_VULN_DB", str(tmp_path / "absent.sqlite"))
    with pytest.raises(FileNotFoundError, match="RECONKG_VULN_DB"):
        Console(autoload_catalog=False)


# --------------------------------------------------------------------------- #
# /api/corpus and the panel
# --------------------------------------------------------------------------- #

def test_the_corpus_route_names_all_three(offline):
    _module, c = offline
    body = c.get("/api/corpus", headers=VIEWER).json()
    assert [entry["corpus"] for entry in body["corpora"]] == \
           ["vulnerabilities", "exploits", "scripts"]
    for entry in body["corpora"]:
        assert entry["describe"]
        assert entry["resolver"]


def test_each_corpus_reports_its_own_resolvers_words_verbatim(wired):
    module, c = wired
    body = c.get("/api/corpus", headers=VIEWER).json()
    by_name = {entry["corpus"]: entry for entry in body["corpora"]}
    assert by_name["vulnerabilities"]["describe"] == \
        module.state.engine.resolver.describe()
    assert by_name["exploits"]["describe"] == module.state.exploits.describe()
    assert by_name["scripts"]["describe"] == module.state.scripts.describe()
    assert by_name["exploits"]["configured"] is True
    assert by_name["scripts"]["configured"] is True


def test_an_unconfigured_corpus_says_not_checked_rather_than_none_found(
        offline):
    """The distinction the panel exists for. "No known exploit" from a corpus
    that was never configured is not a finding."""
    _module, c = offline
    body = c.get("/api/corpus", headers=VIEWER).json()
    by_name = {entry["corpus"]: entry for entry in body["corpora"]}
    assert by_name["exploits"]["configured"] is False
    assert by_name["exploits"]["not_checked"] is True
    assert "not checked" in by_name["exploits"]["describe"]
    assert by_name["scripts"]["configured"] is False
    assert by_name["scripts"]["not_checked"] is True


def test_the_legacy_corpus_keys_still_describe_corpus_one(offline):
    """Existing clients read `describe`/`resolver` at the top level."""
    module, c = offline
    body = c.get("/api/corpus", headers=VIEWER).json()
    assert body["describe"] == module.state.engine.resolver.describe()
    assert body["resolver"] == "StaticResolver"
    assert body["demonstration_fixture"] is True


def test_the_corpus_route_keeps_its_peers_auth_treatment(offline):
    _module, c = offline
    assert c.get("/api/corpus").status_code == 401
    assert c.get("/api/corpus", headers=VIEWER).status_code == 200
    assert c.get("/api/corpus", headers=ADMIN).status_code == 200


def test_the_panel_renders_every_corpus_the_route_returns(offline):
    """A route that reports three and a page that shows one is the same
    silence in a different place."""
    _module, c = offline
    page = c.get("/ui", headers=VIEWER).text
    assert "corpus-list" in page
    assert "corpus.corpora" in page
    # The three states an operator must be able to tell apart.
    assert "not configured" in page
    assert "not checked" in page
    assert "demonstration fixture -- not a vulnerability database" in page
    # describe() reaches the screen unaltered, through textContent.
    assert 'el("pre", "mono-pre", entry.describe)' in page


def test_the_panel_introduced_no_markup_sink(offline):
    _module, c = offline
    page = c.get("/ui", headers=VIEWER).text
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                 "document.write", "eval(", "new Function"):
        assert sink not in page, sink


# --------------------------------------------------------------------------- #
# Resource lifecycle
# --------------------------------------------------------------------------- #

def test_shutdown_closes_the_corpus_connections(monkeypatch, tmp_path):
    """The Db variants hold an open SQLite connection each. The suite builds
    an AppState per test; without a close on shutdown that is one leaked file
    handle per corpus per test."""
    monkeypatch.setenv("RECONKG_EXPLOIT_DB", build_exploit_db(tmp_path))
    monkeypatch.setenv("RECONKG_SCRIPT_DB", build_script_db(tmp_path))
    module = _fresh_state(monkeypatch)
    exploits, scripts = module.state.exploits, module.state.scripts
    with TestClient(module.app) as c:
        assert c.get("/api/corpus", headers=VIEWER).status_code == 200
    with pytest.raises(sqlite3.ProgrammingError):
        exploits.exploits_for(CVE)
    with pytest.raises(sqlite3.ProgrammingError):
        scripts.categories_for(SCRIPT_MARKER)


def test_closing_twice_is_not_an_error(monkeypatch, tmp_path):
    """Teardown that cannot be run twice is not teardown -- the console's
    `close` has said so since it was written, and the app's says it now."""
    monkeypatch.setenv("RECONKG_EXPLOIT_DB", build_exploit_db(tmp_path))
    monkeypatch.setenv("RECONKG_SCRIPT_DB", build_script_db(tmp_path))
    module = _fresh_state(monkeypatch)
    module.state.close()
    module.state.close()


def test_the_console_closes_its_corpora_too(monkeypatch, tmp_path):
    from reconkg.console import Console

    monkeypatch.setenv("RECONKG_EXPLOIT_DB", build_exploit_db(tmp_path))
    monkeypatch.setenv("RECONKG_SCRIPT_DB", build_script_db(tmp_path))
    console = Console(autoload_catalog=False)
    exploits = console.exploits
    console.close()
    console.close()
    with pytest.raises(sqlite3.ProgrammingError):
        exploits.exploits_for(CVE)
