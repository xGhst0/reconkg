"""Round-10 red cell: findings RC-37..RC-40, against corpora two and three.

ExploitDB (`files_exploits.csv`) and nmap's `script.db` both landed since
round 9. Both are files reconkg reads from the network or from a directory
any installed NSE script can write, and both feed the command builder.

Every test in this file failed before the corresponding fix. They are
grouped by finding so a regression names the control it broke rather than
the assertion it tripped. The last section holds the things that were
attacked and held -- kept as tests because "we checked this" is only worth
anything if it stays checked.
"""

from __future__ import annotations

import tracemalloc

import pytest

from reconkg.catalog import ExploitRecord
from reconkg.commands import (BoundaryViolation, Category, Command,
                              NEVER_COMPOSED, _worst_category,
                              coerce_category, nmap_commands,
                              validate_module_path, validate_script_name)
from reconkg.handoff import build_commands, build_handoff
from reconkg.resolver import DbScriptResolver, StaticScriptResolver
from reconkg.scriptdb import ScriptDB, ScriptEntry, parse_entry
from reconkg.vulnref import DEFAULT_REFERENCE, LedgerRow


def _row(**kw) -> LedgerRow:
    base = dict(target="10.10.10.42", port=80, protocol="tcp", service="http",
                product="Apache httpd", version="2.4.49",
                cve_id="CVE-2021-41773", title="path traversal", cvss=9.8,
                maturity="weaponised", fingerprint_confidence=0.9,
                priority=0.9, rationale="version match")
    base.update(kw)
    return LedgerRow(**base)


def _db(*lines: str) -> ScriptDB:
    """A `script.db` as the file spells one, ingested."""
    db = ScriptDB(":memory:")
    for line in lines:
        entry = parse_entry(line)
        assert entry is not None, line
        db.ingest([entry])
    return db


class _FakeCatalog:
    def __init__(self, identifier: str) -> None:
        self._record = ExploitRecord("metasploit", identifier, "t",
                                     cves=("CVE-2021-41773",))

    def records_for(self, cve):
        return [self._record]


# --------------------------------------------------------------------------- #
# RC-37  A script.db filename that is itself an nmap script *selector*
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,line", [
    ("exploit", 'Entry { filename = "exploit.nse", '
                'categories = { "safe", } }'),
    ("all", 'Entry { filename = "all.nse", categories = { "safe", } }'),
    ("brute", 'Entry { filename = "brute.nse", categories = { "safe", } }'),
    ("dos", 'Entry { filename = "dos.nse", categories = { "safe", } }'),
    ("fuzzer", 'Entry { filename = "fuzzer.nse", categories = { "safe", } }'),
])
def test_rc37_a_category_named_script_is_not_composed(name, line):
    """`--script` is an expression language, not a filename.

    `validate_script_name` says so in its own docstring -- and then passes
    `exploit`, which is a perfectly well-formed script name *and* the name of
    the NSE category that runs every exploit on the system. `_nse_selection`
    knows this rule ("any name that is itself an NSE category classifies as
    itself") and applied it to exactly one hard-coded string, `vuln`. For a
    name arriving from `script.db` the category came from the row, so a row
    claiming `exploit.nse` is `safe` produced

        nmap -p 80 --script exploit 10.10.10.42

    classified `safe`, in the DEFAULT tier, with no opt-in and no
    authorisation warning. `all` is worse: it is not an NSE category at all,
    so no amount of category bookkeeping catches it, and it selects every
    script installed.
    """
    resolver = DbScriptResolver(_db(line))
    row = _row(service=name)
    assert [e.name for e in resolver.scripts_for(name, "")] == [name]

    # Default tier: nothing aimed at the target may carry this selector.
    default = build_commands(row, scripts=resolver)
    for command in default:
        assert name not in (command.argv or ()), command.rendered

    # And with every category opted in, it is still named, never composed.
    every = build_commands(row, scripts=resolver, allowed=list(Category))
    selector = [c for c in every
                if name in (c.argv or ()) or name in (c.reference or "")]
    assert selector, "the script must still be reported, just not composed"
    for command in selector:
        assert command.category in NEVER_COMPOSED, command.rendered
        assert command.argv is None, command.rendered


def test_rc37_a_row_cannot_downgrade_its_own_selector():
    """The row's claim is taken as the *floor*, never as the ceiling."""
    from reconkg.commands import script_selection_category

    assert script_selection_category("exploit", ["safe"]) is Category.EXPLOIT
    assert script_selection_category("all", ["safe"]) in NEVER_COMPOSED
    assert script_selection_category("vuln", ["vuln"]) is Category.VULN
    # A plain script is unaffected: it is whatever script.db says it is.
    assert script_selection_category("http-title",
                                     ["safe", "discovery"]) is Category.SAFE
    assert (script_selection_category("http-shellshock", ["exploit"])
            is Category.EXPLOIT)


def test_rc37_the_vuln_seed_still_behaves():
    """`--script vuln` is the pre-existing behaviour and must not change."""
    commands = nmap_commands("10.10.10.42", 80, scripts=("vuln",),
                             categories={"vuln": ["vuln"]})
    vuln = [c for c in commands if "vuln" in (c.argv or ())]
    assert vuln and vuln[0].category is Category.VULN
    assert vuln[0].composed


# --------------------------------------------------------------------------- #
# RC-38  RC-35's guard, undone one frame above it
# --------------------------------------------------------------------------- #

def test_rc38_a_bare_string_category_list_is_not_split_into_characters():
    """`_worst_category` learned in RC-35 that a bare string is one category
    and not seven. `handoff._nse_selection` then wrote

        declared = [str(c) for c in (entry.categories or ())]

    which performs the exact decomposition the guard exists to prevent,
    before the guard is ever reached. An `exploit` script arrived at
    `_worst_category` as `['e','x','p','l','o','i','t']`, resolved to
    `unclassified` -- which is composable on opt-in -- and shipped with the
    target filled in.
    """
    from reconkg.handoff import _nse_selection

    entry = ScriptEntry(filename="http-shellshock.nse",
                        name="http-shellshock", categories="exploit")
    # The entry itself already knew, which is what makes the divergence a
    # bug rather than a policy choice.
    assert entry.category is Category.EXPLOIT

    _, categories, _ = _nse_selection(_row(), StaticScriptResolver([entry]))
    assert categories["http-shellshock"] == ["exploit"]
    assert _worst_category(categories["http-shellshock"]) is Category.EXPLOIT


def test_rc38_the_exploit_script_is_never_composed():
    entry = ScriptEntry(filename="http-shellshock.nse",
                        name="http-shellshock", categories="exploit")
    commands = build_commands(_row(), scripts=StaticScriptResolver([entry]),
                              allowed=list(Category))
    found = [c for c in commands
             if "http-shellshock" in (c.argv or ())
             or "http-shellshock" in (c.reference or "")]
    assert found
    for command in found:
        assert command.category is Category.EXPLOIT
        assert command.argv is None


def test_rc38_script_entry_normalises_its_own_categories():
    """Fixed at the type, not only at the one caller that tripped over it."""
    assert ScriptEntry("x.nse", "x", "exploit").categories == ("exploit",)
    assert ScriptEntry("x.nse", "x", ["exploit"]).categories == ("exploit",)
    assert ScriptEntry("x.nse", "x", ()).categories == ()


def test_rc38_the_categories_fallback_path_is_guarded_too():
    """The second branch: a row that declares nothing falls back to
    `scripts.categories_for(name)`, which is a resolver method a third-party
    implementation supplies -- the same string is equally possible there."""
    from reconkg.handoff import _nse_selection

    class _StringResolver:
        def scripts_for(self, service="", cve_id=""):
            return [ScriptEntry("http-shellshock.nse", "http-shellshock", ())]

        def categories_for(self, script):
            return "exploit"          # a string, not a sequence

        def describe(self):
            return "hostile"

    _, categories, _ = _nse_selection(_row(), _StringResolver())
    assert _worst_category(categories["http-shellshock"]) is Category.EXPLOIT


# --------------------------------------------------------------------------- #
# RC-39  `$` matches before a trailing newline, and one validator forgot
#        to strip
# --------------------------------------------------------------------------- #

def test_rc39_a_module_path_may_not_carry_a_trailing_newline():
    r"""Every other validator in the codebase calls `.strip()` before it
    matches; `validate_module_path` did not, and Python's `$` matches
    immediately before a trailing newline. `exploit/multi/http/x\n` was
    therefore a valid module path, and the validator handed it back with the
    newline still in it.

    Fixed the way the two sibling validators already work -- strip, then
    match on `\A`/`\Z` anchors so the check does not depend on remembering
    to strip -- so the caller's `module` is the cleaned value and nothing
    downstream can meet the newline.
    """
    assert validate_module_path("exploit/multi/http/x\n") == \
        "exploit/multi/http/x"
    assert validate_module_path("  exploit/multi/http/x  ") == \
        "exploit/multi/http/x"
    for junk in ("\n", "  ", "exploit/x\nrun", "exploit/x; run", ""):
        with pytest.raises(BoundaryViolation):
            validate_module_path(junk)


def test_rc39_the_named_only_branch_does_not_leak_the_newline():
    """The uncomposed branch has no `_clean_argv` behind it, so the newline
    reached `reference` and `rendered` -- text the hand-off prints and an
    operator pastes, where a line break detaches the `[source]` annotation
    from the module it annotates."""
    from reconkg.commands import metasploit_commands

    named = metasploit_commands("exploit/multi/http/x\n", "10.0.0.1", 80,
                                category=Category.EXPLOIT)[0]
    assert named.argv is None
    assert "\n" not in named.reference
    assert "\n" not in named.rendered


def test_rc39_one_poisoned_index_record_does_not_blank_the_handoff():
    """RC-32's promise, stated in `build_commands`: "one poisoned index
    record must not blank the whole hand-off". It caught `BoundaryViolation`
    only, and `_clean_argv` raises `ValueError` -- so a record that got past
    `validate_module_path` and was refused one frame later took the entire
    lead with it, and the API answered 500."""
    commands = build_commands(_row(), _FakeCatalog("exploit/multi/http/x\n"),
                              allowed=list(Category))
    assert commands
    assert any(c.tool == "searchsploit" for c in commands)
    joined = " ".join(c.rendered for c in commands)
    assert "\n" not in joined

    ok = build_commands(_row(), _FakeCatalog("exploit/multi/http/x"),
                        allowed=list(Category))
    assert any(c.tool == "msfconsole" and c.composed for c in ok)


def test_rc39_the_record_composer_is_clean_on_the_same_input():
    """RC-33's second path, re-checked against the same input. It shares
    `validate_module_path`, so it shares the fix -- which is the point of
    RC-33 having been fixed by delegation rather than by duplication."""
    record = ExploitRecord("metasploit", "exploit/multi/http/x\n", "t")
    line = record.msf_oneliner("10.0.0.1", 80)
    assert line is not None and "\n" not in line
    assert ExploitRecord("metasploit", "exploit/x; run",
                         "t").msf_oneliner("10.0.0.1") is None


# --------------------------------------------------------------------------- #
# RC-40  A bound checked after the thing it bounds has been allocated
# --------------------------------------------------------------------------- #

def _hostile_script_db(tmp_path, megabytes: int = 16):
    path = tmp_path / "script.db"
    with path.open("w") as handle:
        handle.write('Entry { filename = "http-title.nse", '
                     'categories = { "safe", "discovery", } }\n')
        handle.write("A" * (megabytes * 1024 * 1024))    # no newline, ever
    return path


def test_rc40_an_unbounded_line_is_not_read_into_memory(tmp_path):
    """`MAX_LINE_BYTES` says it "stops a crafted file from turning a
    line-by-line read into a memory problem". It was applied to `raw` --
    after `for raw in handle` had materialised the whole line. A `script.db`
    that is one 500MB line is a file `nmap --script-updatedb` will happily
    produce from a scripts directory, and reading it cost 500MB before the
    bound was consulted."""
    from reconkg.scriptdb import ParseStats, read_script_db

    path = _hostile_script_db(tmp_path, 16)
    stats = ParseStats()
    tracemalloc.start()
    try:
        entries = list(read_script_db(path, stats))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert [e.name for e in entries] == ["http-title"]
    assert stats.skipped == 1
    assert any("bytes" in e for e in stats.errors)
    # Generous: the bound is 8KiB and the read buffer is 64KiB. 16MiB of
    # line must not be resident, and before the fix the peak was over 30MB.
    assert peak < 4 * 1024 * 1024, f"peak was {peak} bytes"


def test_rc40_provenance_hashing_does_not_slurp_the_file(tmp_path):
    """The second unbounded read, on the same file, two functions along:
    `_record_script_provenance` calls `path.read_bytes()` to digest it."""
    from reconkg.resolver import _record_script_provenance

    path = _hostile_script_db(tmp_path, 16)
    db = ScriptDB(":memory:")
    tracemalloc.start()
    try:
        _record_script_provenance(db, path, 1)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    feed = db.feed("script.db")
    assert feed is not None and len(feed.sha256) == 64
    assert feed.bytes == path.stat().st_size
    assert peak < 4 * 1024 * 1024, f"peak was {peak} bytes"


def test_rc40_the_csv_reader_is_bounded_the_same_way(tmp_path):
    """`files_exploits.csv` is downloaded, and `csv.field_size_limit` bounds
    a *field*, not the line the reader had to materialise to find it."""
    from reconkg.exploitdb import read_exploit_csv

    path = tmp_path / "files_exploits.csv"
    with path.open("w") as handle:
        handle.write("id,file,description,date_published,author,type,"
                     "platform,port,verified,codes\n")
        handle.write("1,a,b,2020-01-01,x,remote,linux,80,1,CVE-2020-1\n")
        handle.write("2," + "A" * (16 * 1024 * 1024) + "\n")

    tracemalloc.start()
    try:
        with pytest.raises(ValueError):
            list(read_exploit_csv(path))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 * 1024, f"peak was {peak} bytes"


def test_rc40_a_real_script_db_still_parses(tmp_path):
    from reconkg.scriptdb import ParseStats, read_script_db

    path = tmp_path / "script.db"
    path.write_text("\n".join([
        'Entry { filename = "http-title.nse", categories = { "default", '
        '"discovery", "safe", } }',
        '-- a comment nmap does not write, but a file might acquire',
        'Entry { filename = "http-shellshock.nse", categories = { "exploit", '
        '"intrusive", "vuln", } }',
        'Entry { filename = "smb-brute.nse", categories = { "brute", '
        '"intrusive", } }',
    ]) + "\n")
    stats = ParseStats()
    entries = list(read_script_db(path, stats))
    assert [e.name for e in entries] == ["http-title", "http-shellshock",
                                         "smb-brute"]
    assert entries[1].category is Category.EXPLOIT
    assert stats.parsed == 3 and stats.skipped == 1


# --------------------------------------------------------------------------- #
# Attacked, held. Negative results, kept so they stay negative.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", [
    "http-title,exploit/*", "http-*", "not intrusive", "http-title or exploit",
    "exploit/*", "../../etc/passwd", "-oN/tmp/x", "http title",
    "http-title\x00exploit", "http-title\nexploit", "http-title;exploit",
    "http-title‮", "a" * 200, "", ".nse",
])
def test_script_name_expressions_are_refused(name):
    """nmap's `--script` expression syntax, one operator at a time. None of
    these may become a script name; `shlex.quote` would make every one of
    them a single well-formed shell word."""
    with pytest.raises(BoundaryViolation):
        validate_script_name(name)


@pytest.mark.parametrize("raw", [
    "50383; rm -rf /", "-x", "--output=/etc/cron.d/x", "5 0", "0x1f", "5e3",
    "٥٣", "EDB-EDB-1", "1" * 12, "", " 1 2",
])
def test_edb_ids_that_are_not_ids_are_refused(raw):
    from reconkg.commands import validate_edb_id

    with pytest.raises(BoundaryViolation):
        validate_edb_id(raw)


def test_like_wildcards_cannot_widen_the_script_query():
    """`scripts_for` builds LIKE patterns. Verified rather than assumed: the
    escape character, both wildcards, and a bracket, each supplied in the
    input itself."""
    db = _db('Entry { filename = "http-title.nse", categories = { "safe", } }',
             'Entry { filename = "ftp-anon.nse", categories = { "safe", } }',
             'Entry { filename = "smb-brute.nse", categories = { "brute", } }')
    for hostile in ("%", "_", "\\", "[a-z]", "%%", "\\%", "a%b", "%_%"):
        assert db.scripts_for(hostile, "") == [], hostile
    # And a value that does match is unaffected by the escaping.
    assert [e.name for e in db.scripts_for("http", "")] == ["http-title"]
    assert db.scripts_for("", "CVE-%-%") == []
    assert db.scripts_for("", "%") == []


def test_a_downgraded_script_is_still_only_a_script():
    """A `script.db` that lies about a real script -- calling
    `http-shellshock` safe -- is *not* refused, and that is the design.
    script.db is the authority on categories by construction, and anyone who
    can rewrite it can equally drop a new `.nse` beside it. What the fix
    guarantees is narrower and checkable: the lie buys exactly one script,
    never a category selector and never `all`.
    """
    resolver = DbScriptResolver(_db(
        'Entry { filename = "http-shellshock.nse", '
        'categories = { "safe", } }'))
    commands = build_commands(_row(), scripts=resolver)
    composed = [c for c in commands if "http-shellshock" in (c.argv or ())]
    assert composed and composed[0].category is Category.SAFE
    # ...and it is one named script, not an expression.
    assert composed[0].argv[-2] == "http-shellshock"


def test_no_composed_never_composed_command_escapes_build_commands():
    """The blanket property, re-run over every corpus shape this round
    produced."""
    entries = [ScriptEntry("exploit.nse", "exploit", ("safe",)),
               ScriptEntry("all.nse", "all", ("safe",)),
               ScriptEntry("http-x.nse", "http-x", "exploit"),
               ScriptEntry("http-y.nse", "http-y", ("dos", "safe")),
               ScriptEntry("http-z.nse", "http-z", ())]
    for service in ("http", "exploit", "all"):
        commands = build_commands(_row(service=service),
                                  scripts=StaticScriptResolver(entries),
                                  allowed=list(Category))
        for command in commands:
            if command.category in NEVER_COMPOSED:
                assert command.argv is None, command
            assert "all" not in (command.argv or ())
            assert "exploit" not in (command.argv or ())


def test_the_handoff_lookups_never_carry_a_selector():
    """RC-34's list, re-checked: it is built from `row`, not from the script
    corpus, so no `script.db` row reaches it."""
    handoff = build_handoff(_row(service="exploit"), DEFAULT_REFERENCE,
                            scripts=StaticScriptResolver(
                                [ScriptEntry("exploit.nse", "exploit",
                                             ("safe",))]))
    for line in handoff.lookups:
        assert "--script exploit" not in line
        assert "--script all" not in line


def test_the_ui_has_no_markup_sink_for_the_new_command_shapes():
    """RC-13's control, re-verified against the shapes corpora two and three
    produce: the page still builds every node with createElement, and a
    `composed: false` command still yields no copy button and no shell
    text."""
    from reconkg.ui import PAGE

    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                      "document.write", "eval("):
        assert forbidden not in PAGE, forbidden
    # The copy button and the code node are inside the `composed` branch.
    body = PAGE.split("function renderCommand(")[1].split(
        "\nfunction ")[0]
    composed_half = body.split("if (command.composed) {")[1].split(
        "} else {")[0]
    named_half = body.split("} else {")[1]
    assert "copyButton" in composed_half
    assert "copyButton" not in named_half
    assert "command.rendered" not in named_half


# --------------------------------------------------------------------------- #
# The structural fix the audit's conclusion asked for
#
# `Category` subclassed `str` and that cost two findings, in opposite
# directions. RC-31: a string looked like a Category to a set-membership test,
# so the exploit tier shipped composed. PROP-04: a Category looked like a
# string to a normaliser, so an exploit script resolved to `unclassified`,
# which is composed on opt-in. Both silent, both fail-open.
#
# It is a plain Enum now. These tests exist because the change is invisible in
# behaviour -- all 1210 tests passed before and after -- and the next person
# who wants `category == "exploit"` to work will reach for `(str, Enum)`
# without knowing what it costs.
# --------------------------------------------------------------------------- #

def test_category_is_not_a_string_subclass():
    """The whole point. Revert this and RC-31 and PROP-04 come back."""
    assert not issubclass(Category, str), (
        "Category subclasses str again -- see RC-31 and PROP-04 in "
        "audit/AUDIT.md before changing this back")


def test_a_string_is_not_a_category_and_never_equals_one():
    """RC-31's primitive, now a type error rather than a False comparison."""
    assert Category.EXPLOIT != "exploit"
    assert "exploit" not in NEVER_COMPOSED
    assert "EXPLOIT" not in NEVER_COMPOSED
    assert not isinstance("exploit", Category)


def test_a_category_is_not_a_string(monkeypatch):
    """PROP-04's primitive. An enum member reaching an `isinstance(x, str)`
    branch was how an exploit script became `unclassified`."""
    assert not isinstance(Category.EXPLOIT, str)
    assert str(Category.EXPLOIT) != "exploit", (
        "if str() ever returns the bare value, PROP-04's confusion returns "
        "with it")


def test_the_value_is_still_reachable_and_still_the_nse_word():
    """Removing str-ness must not have renamed the vocabulary. The wire
    format and the NSE word are the same thing and both are `.value`."""
    assert Category.EXPLOIT.value == "exploit"
    assert Category("exploit") is Category.EXPLOIT


def test_every_category_serialises_to_its_nse_word():
    for category in Category:
        assert Category(category.value) is category


def test_as_dict_still_emits_a_plain_string_for_the_ui():
    """The UI and the API read `category` as text. A bare enum would render
    as `Category.SAFE` in the browser."""
    payload = Command(tool="nmap", category=Category.SAFE,
                      argv=("nmap", "-p", "80")).as_dict()
    assert payload["category"] == "safe"
    assert isinstance(payload["category"], str)


def test_coerce_still_accepts_the_spellings_that_arrive_from_feeds():
    """Feeds send strings; that must keep working. What changed is that the
    string is converted at the boundary instead of passing for a Category."""
    for spelling in ("exploit", "EXPLOIT", " Exploit ", Category.EXPLOIT):
        assert coerce_category(spelling) is Category.EXPLOIT
