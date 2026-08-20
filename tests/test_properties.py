"""Property-based fuzzing. The complement to the example-based suite.

An example test checks a behaviour somebody thought of. These check
behaviours nobody has to think of: statements that must hold for *every*
input, exercised against inputs a generator invents. Where an example test
says "this exploit script is not composed", a property here says "no
generated string, category, script name, module path or EDB id produces a
composed command in a never-composed category" -- which is the claim
`commands.py`'s docstring actually makes.

Structure, and why the properties are grouped this way:

    safety      the security boundary. If one of these fails, reconkg has
                aimed a weapon. These get the largest example budgets.
    versions    where the subtle bugs live: an ordering that is not
                transitive silently mis-ranks a ledger and never crashes.
    parsing     never raise, never half-parse, never silently corrupt.
    stores      what goes in comes back, and a re-ingest replaces.

Findings that came out of this file have named regression tests beside the
round-9/round-10 red-cell findings:

    PROP-01  `CPE.__str__` did not re-escape `\\:`, so a CPE with an escaped
             colon did not survive a `str()`/`parse()` round trip -- and
             `vulndb` stores exactly that string and re-parses it, so every
             attribute after the colon shifted one position in the corpus.
             (tests/test_cpe_matching.py)
    PROP-02  `VulnDB.ingest` raised `sqlite3.IntegrityError` on a batch
             containing one CVE twice, losing every good row in the batch.
             Both sibling corpora guard this case explicitly; corpus one did
             not. (tests/test_integrity.py)
    PROP-03  The `.nse` suffix strip was not a fixed point, so `a.nse.nse`
             normalised to `a.nse` in the parser and to `a` in the store --
             the corpus and the parser disagreed about a row's identity and
             the script became invisible to every lookup.
             (tests/test_scriptdb.py)

Runtime is capped deliberately (`MAX` below, plus per-test overrides): the
whole suite has to stay inside a couple of minutes, and a property that only
runs nightly is a property nobody runs.
"""

from __future__ import annotations

import shlex
import string

import pytest

pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, assume, given, settings, strategies as st

from reconkg.catalog import ExploitRecord
from reconkg.commands import (BoundaryViolation, Category, Command,
                              DEFAULT_CATEGORIES, NEVER_COMPOSED,
                              assert_no_composed_exploits, coerce_category,
                              filter_commands, http_probe_commands,
                              metasploit_commands, nmap_commands,
                              normalise_categories, nuclei_commands,
                              script_selection_category, searchsploit_commands,
                              searchsploit_examine_commands, validate_edb_id,
                              validate_module_path, validate_script_name,
                              _worst_category)
from reconkg.cpe import ANY, CPE, CPERange, MatchMethod, parse as parse_cpe
from reconkg.exploitdb import ExploitDB, clean_text, safe_edb_id
from reconkg.handoff import build_commands
from reconkg.scriptdb import (NotAScriptDb, ScriptDB, ScriptEntry,
                              clean_category, parse_entry, safe_script_name)
from reconkg.vulndb import VulnDB
from reconkg.vulnref import (LedgerRow, VulnEntry, compare_versions,
                             parse_version, version_satisfies)

MAX = 200
"""Default example budget. Enough to find the shapes that matter; small
enough that the whole file runs in seconds."""

PROFILE = settings(max_examples=MAX, deadline=None,
                   suppress_health_check=[HealthCheck.too_slow,
                                          HealthCheck.data_too_large,
                                          HealthCheck.function_scoped_fixture])


# --------------------------------------------------------------------------- #
# Strategies. Hostile by construction, because every one of these values
# arrives from a downloaded feed, a rebuilt script.db or an HTTP body.
# --------------------------------------------------------------------------- #

#: Characters that mean something to a shell, to msfconsole's `-x` parser, to
#: nmap's `--script` expression grammar, or to a terminal.
NASTY = "\x00\n\r\t;|&$`'\"\\ *?[]{}()<>#!~%,=+:/^\x1b\x7f‮"

hostile_text = st.text(
    alphabet=st.sampled_from(list(string.ascii_letters + string.digits)
                             + list(NASTY)),
    min_size=0, max_size=24)

any_text = st.one_of(
    hostile_text,
    st.text(max_size=32),                       # full unicode, any plane
    st.sampled_from([
        "", " ", "\n", "\x00", "exploit", "all", "EXPLOIT", " exploit ",
        "vuln,exploit", "http-title.nse", "a" * 300, "-oN/tmp/x",
        "exploit/multi/http/x; run", "50383; rm -rf /", "EDB-50383",
        "‮http-title", "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
    ]))

category_input = st.one_of(
    st.sampled_from(list(Category)),
    st.sampled_from([c.value for c in Category]),
    st.sampled_from([c.value.upper() for c in Category]),
    st.sampled_from([f" {c.value} " for c in Category]),
    any_text)

#: A version as a banner spells one. Numeric, alphabetic and mixed, plus the
#: distribution-packaged shapes that carry a backport marker.
version_text = st.one_of(
    st.from_regex(r"\A[0-9]{1,3}(\.[0-9]{1,3}){0,3}\Z", fullmatch=True),
    st.from_regex(r"\A[0-9]{1,3}(\.[0-9]{1,3}){0,2}(rc|p|a|b)[0-9]{0,2}\Z",
                  fullmatch=True),
    st.sampled_from(["", "*", "-", "0", "2.4", "2.4.0", "2.4.49", "2.4.50",
                     "2.4.9", "1.0.1f", "1.0.1g", "7.4p1", "2.4.49rc1",
                     "4ubuntu3.14", "2.4.6-el7", "unknown", "9" * 40]),
    hostile_text)

#: A plausible target. Control characters are excluded because
#: `app.validate_address` refuses them at the API boundary, so they cannot
#: reach a builder -- `test_a_control_character_target_is_refused_loudly`
#: pins that assumption rather than leaving it implicit.
target_text = st.one_of(
    st.from_regex(r"\A[a-z0-9.-]{1,32}\Z", fullmatch=True),
    st.sampled_from(["10.0.0.1", "example.com", "$(id)", "a;rm -rf /",
                     "'; drop --", "a b", "--script=exploit", "[::1]",
                     "‮evil"]))

port_number = st.integers(min_value=0, max_value=65535)

script_name = st.one_of(
    st.from_regex(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,20}\Z", fullmatch=True),
    st.sampled_from([c.value for c in Category]),
    st.sampled_from(["all", "ALL", "exploit.nse", "http-title,exploit/*",
                     "vuln", "-oN", "", ".", "a.nse.nse", "a" * 80]),
    any_text)

edb_id_input = st.one_of(
    st.from_regex(r"\A[0-9]{1,9}\Z", fullmatch=True),
    st.sampled_from(["EDB-50383", "edb-50383", "0", "9999999999", "",
                     "50383; rm -rf /", "-x", "5 0"]),
    any_text)

module_path = st.one_of(
    st.from_regex(r"\A[A-Za-z0-9][A-Za-z0-9_./-]{0,40}\Z", fullmatch=True),
    st.sampled_from(["exploit/multi/http/apache_normalize_path_rce",
                     "auxiliary/scanner/http/title",
                     "exploit/x\n", "exploit/x; run", "exploit/x; exploit -j",
                     "", " ", "/", "-"]),
    any_text)

cve_id = st.one_of(
    st.from_regex(r"\ACVE-[0-9]{4}-[0-9]{4,7}\Z", fullmatch=True),
    st.sampled_from(["CVE-2021-41773", "cve-2021-41773", "", "CVE-x",
                     "CVE-2021-41773; run"]),
    any_text)

category_list = st.one_of(
    st.lists(category_input, max_size=4),
    category_input,                             # RC-35's bare-string shape
    st.none(),
    st.tuples(category_input),
)


def _ledger_row(target, port, service, product, version, cve):
    return LedgerRow(target=target, port=port, protocol="tcp", service=service,
                     product=product, version=version, cve_id=cve,
                     title="t", cvss=7.5, maturity="functional",
                     fingerprint_confidence=0.8)


ledger_row = st.builds(
    _ledger_row,
    target_text, port_number,
    st.one_of(st.sampled_from(["http", "https", "ssh", "smb", "", "ssl/http",
                               "unknown", "%"]), any_text),
    st.one_of(st.sampled_from(["Apache httpd", "OpenSSH", "", None]),
              any_text),
    st.one_of(version_text, st.none()),
    cve_id)


class _Scripts:
    """A `ScriptResolver` that returns whatever the generator invented.

    Deliberately not a `ScriptDB`: the resolver is a protocol a third party
    implements, so the hand-off has to survive one that returns hostile rows
    -- which is the RC-38 shape one layer further out.
    """

    def __init__(self, entries):
        self._entries = entries

    def scripts_for(self, service="", cve_id="", limit=25):
        return list(self._entries)

    def categories_for(self, script):
        for entry in self._entries:
            if getattr(entry, "name", None) == script:
                return list(entry.categories)
        return []


class _Exploits:
    def __init__(self, records):
        self._records = records

    def exploits_for(self, cve):
        return list(self._records)


script_entry = st.builds(
    lambda name, cats: ScriptEntry(filename=f"{name}.nse", name=name,
                                   categories=cats),
    script_name, category_list)

exploit_record = st.builds(
    lambda ident, title, platform: ExploitRecord(
        source="exploit-db", identifier=ident, title=title,
        cves=("CVE-2021-41773",), platform=platform, kind="webapps"),
    edb_id_input, any_text, any_text)


# --------------------------------------------------------------------------- #
# 1-2. The boundary, and the quoting that makes it real
# --------------------------------------------------------------------------- #

def _check(commands):
    """Every safety invariant a list of Commands must satisfy, at once.

    One helper rather than one assertion per builder: the invariants are
    properties of a `Command`, not of the function that produced it, and a
    per-builder copy is one more place for the next builder to be forgotten.
    """
    for command in commands:
        category = coerce_category(command.category)
        # P1. The boundary. A composed argv in a never-composed category is
        # reconkg aiming an exploit, which is the one thing this project
        # exists not to do.
        assert not (category in NEVER_COMPOSED and command.composed), (
            f"{command.tool}: composed {category.value} command "
            f"{command.argv!r}")
        if not command.composed:
            # A named command with nothing to look up tells the analyst
            # nothing, which reads exactly like no exploit existing.
            assert command.reference
            continue
        # P2. Quoting round-trips exactly. This is what makes the injection
        # defence a property rather than an accident: if `rendered` re-splits
        # into anything other than `argv`, the line an operator pastes is not
        # the command reconkg composed.
        assert shlex.split(command.rendered) == list(command.argv), (
            f"{command.tool}: {command.rendered!r} does not re-split into "
            f"{command.argv!r}")
        for part in command.argv:
            assert isinstance(part, str)
            assert not any(ch in part for ch in ("\x00", "\n", "\r"))
    # The runtime backstop agrees with the loop above.
    assert_no_composed_exploits(commands)
    return commands


@PROFILE
@given(category_input, st.lists(any_text, max_size=4), any_text)
def test_a_never_composed_category_can_never_carry_an_argv(raw, argv, ref):
    """P1, at the type.

    Construction is the only route to a `Command`, so a property here covers
    every builder that exists and every builder that will exist.
    """
    try:
        category = coerce_category(raw)
    except ValueError:
        # An uninterpretable category is refused before anything can classify
        # it as safe -- the RC-31 fix. Nothing composed comes of it.
        with pytest.raises(ValueError):
            Command(tool="t", category=raw, argv=tuple(argv) or None,
                    reference=ref or "x")
        return
    try:
        command = Command(tool="t", category=raw, argv=tuple(argv) or None,
                          reference=ref or "x")
    except BoundaryViolation:
        assert category in NEVER_COMPOSED and argv
        return
    except ValueError:
        # `_clean_argv` refused a control character, or a named command
        # carried no reference. Both are refusals, not compositions.
        return
    _check([command])


@PROFILE
@given(cve_id, any_text, version_text)
def test_searchsploit_commands_hold_the_boundary(cve, product, version):
    _check(searchsploit_commands(cve, product, version))


@PROFILE
@given(edb_id_input, any_text, any_text)
def test_searchsploit_examine_holds_the_boundary(edb, title, platform):
    try:
        commands = searchsploit_examine_commands(edb, title, platform)
    except BoundaryViolation:
        assert safe_edb_id(edb) is None
        return
    _check(commands)
    # The id reaching argv is the *validated* one, never the raw feed value.
    assert commands[0].argv[-1] == validate_edb_id(edb)


@PROFILE
@given(target_text, port_number,
       st.lists(script_name, max_size=4),
       st.dictionaries(script_name, category_list, max_size=4))
def test_nmap_commands_hold_the_boundary(target, port, scripts, categories):
    try:
        commands = nmap_commands(target, port, scripts, categories)
    except (BoundaryViolation, ValueError):
        # A name that is not a script name, or a target carrying a control
        # character. Refusal is the correct outcome; nothing was composed.
        return
    _check(commands)


@PROFILE
@given(module_path, target_text, st.one_of(st.none(), port_number),
       category_input)
def test_metasploit_commands_hold_the_boundary(module, target, port, raw):
    try:
        commands = metasploit_commands(module, target, port, category=raw)
    except (BoundaryViolation, ValueError):
        return
    _check(commands)
    for command in commands:
        if command.composed:
            # Composed up to `show options` and no further, as msfconsole
            # itself would re-split the `-x` string.
            assert "show options" in command.argv[-1]


@PROFILE
@given(cve_id, target_text, port_number, st.booleans())
def test_the_remaining_builders_hold_the_boundary(cve, target, port, tls):
    try:
        commands = (http_probe_commands(target, port, tls)
                    + nuclei_commands(cve, target))
    except (BoundaryViolation, ValueError):
        return
    _check(commands)


@settings(max_examples=120, deadline=None,
          suppress_health_check=[HealthCheck.too_slow,
                                 HealthCheck.data_too_large])
@given(ledger_row, st.lists(script_entry, max_size=4),
       st.lists(exploit_record, max_size=4),
       st.one_of(st.none(), st.lists(category_input, max_size=5)))
def test_build_commands_holds_the_boundary_end_to_end(row, scripts, records,
                                                      allowed):
    """P1 and P4 through the whole assembly, which is the path the API uses.

    `build_commands` is where the builders, the script resolver, the exploit
    corpus and the category filter meet, and a boundary that holds in each
    piece separately is not the same claim as one that holds in the
    composition -- RC-34 and RC-39 were both failures of the composition.
    """
    try:
        permitted = ({coerce_category(a) for a in allowed}
                     if allowed is not None else set(DEFAULT_CATEGORIES))
    except ValueError:
        with pytest.raises(ValueError):
            build_commands(row, None, allowed, _Exploits(records),
                           _Scripts(scripts))
        return

    try:
        commands = build_commands(row, None, allowed, _Exploits(records),
                                  _Scripts(scripts))
    except (BoundaryViolation, ValueError):
        # A target `validate_address` would have refused at the API boundary.
        # Loud refusal, nothing composed.
        return

    _check(commands)
    for command in commands:
        # P4. The filter's contract: a composed command outside the allowed
        # set is the operator's selection being ignored.
        if command.composed:
            assert coerce_category(command.category) in permitted


@PROFILE
@given(st.lists(st.tuples(category_input, st.booleans()), max_size=6),
       st.one_of(st.none(), st.lists(category_input, max_size=5)))
def test_filter_commands_never_widens_the_selection(spec, allowed):
    """P4 directly, against a hand-built list rather than a builder."""
    commands = []
    for raw, composed in spec:
        try:
            commands.append(Command(
                tool="t", category=raw,
                argv=("echo", "x") if composed else None, reference="ref"))
        except (BoundaryViolation, ValueError):
            continue
    try:
        permitted = ({coerce_category(a) for a in allowed}
                     if allowed is not None else set(DEFAULT_CATEGORIES))
        out = filter_commands(commands, allowed)
    except ValueError:
        return
    for command in out:
        if command.composed:
            assert coerce_category(command.category) in permitted
    # Never-composed commands always survive: hiding them would mean an
    # analyst is not told a working exploit exists.
    assert all(c in out for c in commands if not c.composed)


@PROFILE
@given(target_text, port_number, st.sampled_from(["\x00", "\n", "\r"]))
def test_a_control_character_target_is_refused_loudly(target, port, ch):
    """The assumption `target_text` rests on, pinned.

    A control character in an argv element survives `shlex.quote` -- quoting
    makes it one shell word, which is correct for the shell and irrelevant to
    the tool that then parses the word itself. `_clean_argv` refuses it at
    construction, and this asserts the refusal rather than trusting that
    `app.validate_address` is the only way in.
    """
    with pytest.raises(ValueError):
        nmap_commands(target + ch, port)


# --------------------------------------------------------------------------- #
# 3. coerce_category
# --------------------------------------------------------------------------- #

@PROFILE
@given(st.one_of(category_input, st.integers(), st.none(), st.booleans(),
                 st.floats(allow_nan=True), st.binary(max_size=8)))
def test_coerce_category_returns_a_member_or_raises(raw):
    """P3. Never an unvalidated string -- RC-31's finding, as a property.

    `Category` subclasses `str`, so a bare string compares and hashes equal
    to a member, and a membership test against `NEVER_COMPOSED` looks
    type-safe while being case-sensitive. Anything that is not exactly a
    member has to be refused here or it is never refused at all.
    """
    try:
        value = coerce_category(raw)
    except ValueError:
        return
    assert isinstance(value, Category)
    assert value in set(Category)
    assert coerce_category(value) is value          # idempotent


@PROFILE
@given(category_list)
def test_worst_category_is_total_and_conservative(declared):
    """`_worst_category` answers for every collection shape, and a firing tag
    decides outright whatever sits beside it."""
    verdict = _worst_category(declared)
    assert isinstance(verdict, Category)
    tokens = {t.strip().lower() for t in normalise_categories(declared)}
    if tokens & {c.value for c in NEVER_COMPOSED}:
        assert verdict in NEVER_COMPOSED


# --------------------------------------------------------------------------- #
# 5. script.db content can never select a category
# --------------------------------------------------------------------------- #

_FIRING = {c.value for c in NEVER_COMPOSED}
_SELECTS_EVERYTHING = {"all"}


@PROFILE
@given(script_name, category_list, target_text, port_number)
def test_a_script_name_that_selects_a_category_is_never_composed(
        name, declared, target, port):
    """P5. RC-37 generalised from five hand-picked names to every name.

    `--script <name>` is an expression over names, globs and *category
    names*, so a `script.db` row of `filename = "exploit.nse"` is a
    well-formed name that runs the whole exploit category. The row's claim is
    a floor, never a ceiling: no declared category may make a selector look
    safer than what it selects.
    """
    try:
        category = script_selection_category(name, declared)
    except (BoundaryViolation, ValueError):
        return
    validated = validate_script_name(name).lower()
    if validated in _FIRING | _SELECTS_EVERYTHING:
        assert category in NEVER_COMPOSED, (name, declared, category)

    try:
        commands = nmap_commands(target, port, [name], {validated: declared})
    except (BoundaryViolation, ValueError):
        return
    _check(commands)
    for command in commands:
        if command.composed and "--script" in command.argv:
            selected = command.argv[command.argv.index("--script") + 1].lower()
            assert selected not in _FIRING | _SELECTS_EVERYTHING


@PROFILE
@given(st.text(alphabet=st.sampled_from(
    list(string.printable) + ["\x00", "‮", "é"]), max_size=120))
def test_a_generated_script_db_line_never_yields_a_composed_selector(line):
    """P5 from the file format inwards: the generator writes the line, the
    parser reads it, and the hand-off composes from what came out."""
    entry = parse_entry(line)
    if entry is None:
        return
    assert entry.name == safe_script_name(entry.name)
    assert entry.categories                     # never an empty claim
    row = _ledger_row("10.0.0.1", 80, "http", "Apache", "2.4.49",
                      "CVE-2021-41773")
    commands = build_commands(row, None, list(Category), None,
                              _Scripts([entry]))
    _check(commands)
    for command in commands:
        if command.composed and "--script" in command.argv:
            selected = command.argv[command.argv.index("--script") + 1].lower()
            assert selected not in _FIRING | _SELECTS_EVERYTHING


# --------------------------------------------------------------------------- #
# 6-8. Version comparison
# --------------------------------------------------------------------------- #

@PROFILE
@given(version_text)
def test_compare_versions_is_reflexive(v):
    assert compare_versions(v, v) == 0


@PROFILE
@given(version_text, version_text)
def test_compare_versions_is_antisymmetric(a, b):
    """P6. `cmp(a, b) == -cmp(b, a)` for every pair of strings."""
    assert compare_versions(a, b) == -compare_versions(b, a)
    assert compare_versions(a, b) in (-1, 0, 1)


@PROFILE
@given(version_text, version_text, version_text)
def test_compare_versions_is_transitive(a, b, c):
    """P6. The property a mis-ranked ledger fails silently on.

    An intransitive comparator does not crash. It sorts a list into an order
    that depends on the input permutation, so the top of the ledger looks
    stable and is wrong, and no example test will ever notice.
    """
    ab, bc, ac = (compare_versions(a, b), compare_versions(b, c),
                  compare_versions(a, c))
    if ab <= 0 and bc <= 0:
        assert ac <= 0, (a, b, c)
    if ab >= 0 and bc >= 0:
        assert ac >= 0, (a, b, c)


@PROFILE
@given(version_text, version_text)
def test_version_equality_is_a_congruence(a, b):
    """Equal versions compare identically against everything else.

    `2.4` and `2.4.0` are the same version, and a ranking that agreed with
    that only sometimes would be worse than one that never did -- it would be
    order-dependent, which is the shape of bug that survives review.
    """
    if compare_versions(a, b) == 0:
        for probe in ("0", "2.4.49", "9999", "1.0.1g", ""):
            assert compare_versions(a, probe) == compare_versions(b, probe)


@PROFILE
@given(version_text, st.sampled_from(["<", "<=", ">", ">=", "==", "!=", "~",
                                      "", "in"]), version_text)
def test_version_satisfies_raises_only_valueerror(version, op, bound):
    """P7, restated -- and this is a case where the property as briefed is
    wrong and the code is right.

    The brief asked for "never raises for any pair of strings".
    `version_satisfies` raises `ValueError` *deliberately* on a version with
    no numeric component, because a banner reading `Apache/unknown-build`
    must not compare as very old and silently satisfy `< 2.4.49`. Making it
    total would turn an unparseable banner into a confident lead, which is
    the failure mode `vulnref` exists to avoid, and `test_reconkg.py` and
    `test_audit_regressions.py` both pin the raise.

    The invariant that *is* true, and is the one callers depend on, is that
    the function is total in its failure mode: for any pair of strings and
    any operator it returns a bool or raises `ValueError`, never anything
    else. `VulnEntry._product_match` catches and logs; a `TypeError` or an
    `re` error escaping from here surfaces as a 500 instead of a dropped
    lead.
    """
    try:
        result = version_satisfies(version, op, bound)
    except ValueError:
        unparseable = not any(kind == 1 for kind, _ in parse_version(version))
        assert unparseable or op not in {"<", "<=", ">", ">=", "==", "!="}
        return
    assert isinstance(result, bool)


#: A version whose ordering can be computed independently of the code under
#: test, so the oracle is not the implementation.
_numeric_version = st.tuples(st.integers(0, 40), st.integers(0, 40),
                             st.integers(0, 40))


def _spell(triple):
    return ".".join(str(n) for n in triple)


@settings(max_examples=250, deadline=None)
@given(_numeric_version, _numeric_version, _numeric_version,
       st.booleans(), st.booleans())
def test_a_version_inside_a_cpe_range_satisfies_it(observed, lo, hi,
                                                   lo_inclusive, hi_inclusive):
    """P8, with an independent oracle.

    Membership is decided here by comparing Python tuples of integers, which
    owes nothing to `compare_versions`. `CPERange.matches` must agree in both
    directions: a version inside the window matches, one outside does not.
    Generated rather than hand-picked, because the interesting cases are the
    eight boundary combinations and nobody hand-picks all eight.
    """
    assume(lo <= hi)
    statement = CPERange(
        cpe=CPE(part="a", vendor="v", product="p"),
        version_start_including=_spell(lo) if lo_inclusive else None,
        version_start_excluding=None if lo_inclusive else _spell(lo),
        version_end_including=_spell(hi) if hi_inclusive else None,
        version_end_excluding=None if hi_inclusive else _spell(hi))
    fingerprint = CPE(part="a", vendor="v", product="p",
                      version=_spell(observed))

    inside = ((observed >= lo if lo_inclusive else observed > lo)
              and (observed <= hi if hi_inclusive else observed < hi))
    matched, method, why = statement.matches(fingerprint)
    assert matched is inside, (observed, lo, hi, lo_inclusive, hi_inclusive,
                               why)
    if matched:
        assert method is MatchMethod.CPE_RANGE
    # A match with no stated reason is a row nobody can check.
    assert why


# --------------------------------------------------------------------------- #
# 9-10. CPE parsing
# --------------------------------------------------------------------------- #

_cpe_field = st.one_of(st.sampled_from(["a", "o", "h", "*", "-"]),
                       hostile_text)

cpe_text = st.one_of(
    st.builds(lambda parts: "cpe:2.3:" + ":".join(parts),
              st.lists(_cpe_field, min_size=1, max_size=13)),
    st.builds(lambda parts: "cpe:/" + ":".join(parts),
              st.lists(_cpe_field, min_size=1, max_size=13)),
    any_text)

_ATTRIBUTES = ("part", "vendor", "product", "version", "update", "edition",
               "language", "sw_edition", "target_sw", "target_hw", "other")


@PROFILE
@given(cpe_text)
def test_cpe_parse_never_raises_and_never_half_builds(raw):
    """P9. A malformed CPE in a banner is a fact about the target, not a
    caller error, so it must not stop the rest of the fingerprint being
    used -- and a partially-built CPE is worse than none, because the
    attributes that did parse are then trusted."""
    result = parse_cpe(raw)
    assert result is None or isinstance(result, CPE)
    if result is None:
        return
    for attribute in _ATTRIBUTES:
        value = getattr(result, attribute)
        assert isinstance(value, str) and value != ""
    assert result.part in ("a", "o", "h", ANY, "-")


@PROFILE
@given(cpe_text)
def test_cpe_parse_round_trips_through_str(raw):
    """P10. `parse(str(parse(s))) == parse(s)`.

    Not a cosmetic property. `vulndb` stores `str(cpe)` in the `criteria`
    column and re-parses it on every candidate lookup, so a `str()` that
    loses information corrupts the corpus rather than the display. PROP-01:
    an escaped colon made every later attribute shift one position on the way
    back in, turning `product` into a version fragment without raising
    anything.
    """
    once = parse_cpe(raw)
    if once is None:
        return
    twice = parse_cpe(str(once))
    assert twice == once, (raw, str(once), twice)
    assert str(twice) == str(once)


#: A CPE attribute as `parse` produces one: non-empty and lower-case.
#: Restricting to lower case is not a weakened property -- `parse` documents
#: that attributes are lower-cased, so an upper-case attribute is a value
#: `parse` never returns and a round trip through it is not defined.
#: Whitespace-only values are excluded for the same reason: `parse` strips
#: the string it is handed, and an empty field is read as ANY, so a CPE whose
#: first or last attribute is a single space is not a value `parse` can
#: return. No constructor in the tree produces one either -- `infer_cpe`
#: writes ANY where it has nothing -- so this is the strategy declining to
#: generate a value outside the function's domain, not the property being
#: relaxed to fit the code.
_built_attribute = st.one_of(
    st.sampled_from(["*", "-", "a", "o", "h"]),
    hostile_text.map(lambda t: t.lower().strip()).filter(bool))


@PROFILE
@given(st.sampled_from(["a", "o", "h", "*", "-"]),
       st.lists(_built_attribute, min_size=10, max_size=10))
def test_a_cpe_built_from_arbitrary_attributes_survives_str(part, rest):
    """The same round trip from the other end: a `CPE` built directly rather
    than parsed. `infer_cpe` and the NVD importer both construct one, and
    both results reach `str()` on the way into SQLite -- PROP-01 corrupted
    the corpus on exactly this path, not on the display path."""
    parts = [part] + list(rest)
    cpe = CPE(*parts)
    reparsed = parse_cpe(str(cpe))
    assert reparsed == cpe, (parts, str(cpe), reparsed)


# --------------------------------------------------------------------------- #
# 11. Sanitisers and validators
# --------------------------------------------------------------------------- #

@PROFILE
@given(st.one_of(any_text, st.binary(max_size=16), st.integers(), st.none()))
def test_safe_edb_id_returns_an_id_or_nothing(raw):
    """P11. Never a partially-cleaned string: a row whose id is
    `50383; rm -rf /` is not an id with a problem, it is not an id."""
    value = safe_edb_id(raw)
    if value is None:
        return
    assert value.isdigit() and 1 <= len(value) <= 9
    assert safe_edb_id(value) == value                  # idempotent
    # The commands-side twin agrees. Two implementations of one control is
    # one implementation and one bypass (RC-04/RC-07's standing lesson).
    assert validate_edb_id(value) == value


@PROFILE
@given(st.one_of(any_text, st.binary(max_size=16), st.integers(), st.none()))
def test_clean_text_never_raises_and_bounds_its_output(raw):
    text = clean_text(raw)
    assert isinstance(text, str)
    assert not any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text)
    assert clean_text(text) == text                     # idempotent


@PROFILE
@given(st.one_of(script_name, st.binary(max_size=16), st.integers(),
                 st.none()))
def test_script_name_normalisation_is_a_fixed_point(raw):
    """P11. Both twins agree, and both are idempotent.

    Idempotence is the property PROP-03 failed: the `.nse` strip removed one
    suffix, so `a.nse.nse` normalised to `a.nse` in `parse_entry` and to `a`
    in `ScriptDB._write_batch`, and the corpus and the parser disagreed about
    which row was which. A normalisation applied on two code paths has to be
    a fixed point or it is two normalisations.
    """
    safe = safe_script_name(raw)
    try:
        validated = validate_script_name(raw)
    except (BoundaryViolation, ValueError):
        assert safe is None
        return
    assert safe == validated, (raw, safe, validated)
    assert safe_script_name(safe) == safe
    assert validate_script_name(validated) == validated
    assert not safe.lower().endswith(".nse")


@PROFILE
@given(st.one_of(module_path, st.binary(max_size=16), st.integers(),
                 st.none()))
def test_validate_module_path_is_a_fixed_point(raw):
    try:
        value = validate_module_path(raw)
    except BoundaryViolation:
        return
    assert validate_module_path(value) == value
    assert value and value == value.strip()
    assert not any(ch in value for ch in "\n\r\x00; ")


@PROFILE
@given(st.one_of(any_text, st.binary(max_size=16), st.none()))
def test_clean_category_returns_a_token_or_nothing(raw):
    value = clean_category(raw)
    if value is None:
        return
    assert value == value.lower().strip()
    assert clean_category(value) == value
    # Whatever survives is a token `_worst_category` can resolve, and an
    # unrecognised word resolves conservatively rather than being dropped.
    assert isinstance(_worst_category([value]), Category)


# --------------------------------------------------------------------------- #
# 12. Ingest: parse anything, crash on nothing, store nothing malformed
# --------------------------------------------------------------------------- #

@PROFILE
@given(st.text(alphabet=st.sampled_from(
    list(string.printable) + ["\x00", "‮"]), max_size=200))
def test_parse_entry_never_raises_and_never_half_parses(line):
    """P12, per line. A comment, a blank line or a record from a future nmap
    is not a reason to abandon the file; a half-parsed record is worse than
    no record, because the half that parsed is then trusted."""
    entry = parse_entry(line)
    if entry is None:
        return
    assert isinstance(entry, ScriptEntry)
    assert entry.filename == f"{entry.name}.nse"
    assert safe_script_name(entry.name) == entry.name
    assert entry.categories and isinstance(entry.categories, tuple)
    for token in entry.categories:
        assert clean_category(token) == token
    assert isinstance(entry.category, Category)


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.too_slow,
                                 HealthCheck.function_scoped_fixture])
@given(st.lists(st.text(alphabet=st.sampled_from(
    list(string.printable) + ["\x00", "‮"]), max_size=120), max_size=12))
def test_a_generated_script_db_file_is_ingested_or_refused(tmp_path, lines):
    """P12, per file. Either the entries land in the corpus or the file is
    refused with `NotAScriptDb` -- never a silent empty index, which reads to
    an operator as "every script is unclassified"."""
    path = tmp_path / "script.db"
    path.write_text("\n".join(lines), encoding="utf-8")
    db = ScriptDB()
    try:
        try:
            written, stats = db.ingest_file(path)
        except NotAScriptDb:
            assert db.stats().scripts == 0
            return
        assert written > 0
        assert db.stats().scripts == written
        assert stats.parsed >= written
        for category in db.category_counts():
            assert clean_category(category) == category
    finally:
        db.close()


_CSV_FIELD = st.text(alphabet=st.sampled_from(
    list(string.ascii_letters + string.digits) + list(",;'\\ \t‮")),
    max_size=20)


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.too_slow,
                                 HealthCheck.function_scoped_fixture])
@given(st.lists(st.lists(_CSV_FIELD, min_size=1, max_size=6), max_size=6),
       st.booleans())
def test_a_generated_exploit_csv_is_ingested_or_rejected(tmp_path, rows,
                                                         with_header):
    """P12 for corpus two.

    A row that cannot be parsed is counted and dropped; a file with no `id`
    column is a different file and is refused by name. Neither outcome is a
    crash, and no stored record fails `safe_edb_id`.
    """
    header = ("id,file,description,date_published,author,type,platform,port,"
              "codes,verified" if with_header else "a,b,c")
    body = "\n".join(",".join(f'"{field}"' for field in row) for row in rows)
    path = tmp_path / "files_exploits.csv"
    path.write_text(header + "\n" + body, encoding="utf-8")

    db = ExploitDB()
    try:
        try:
            written, stats = db.ingest_csv(path)
        except ValueError:
            # Loud refusal, naming the file. Nothing was stored.
            assert db.stats().exploits == 0
            return
        assert db.stats().exploits == written
        for record in db.exploits_for_platform("", limit=1000):
            assert safe_edb_id(record.identifier) is not None
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# 13-14. Store round-trips and re-ingest stability
# --------------------------------------------------------------------------- #

@PROFILE
@given(st.lists(exploit_record, max_size=6))
def test_exploitdb_round_trips_every_record_it_accepts(records):
    """P13. What the store returns re-ingests to itself, unchanged.

    Stated as a fixed point rather than as raw equality because ingest
    normalises deliberately -- `EDB-50383` and `50383` are the same entry,
    titles lose control characters, and a title is bounded. The property that
    matters is that the normalisation converges: read-back is stable, so a
    daily refresh cannot drift a record one clean-up at a time.
    """
    # Last one wins inside a batch, which is what the write path documents
    # and what the delete-then-insert gives across batches. Comparing an
    # earlier duplicate against the stored row would be asserting the
    # opposite of the stated contract.
    latest = {}
    for record in records:
        key = safe_edb_id(record.identifier)
        if key is not None:
            latest[key] = record

    db = ExploitDB()
    try:
        db.ingest(records)
        for key, record in latest.items():
            stored = db.get(key)
            assert stored is not None
            assert stored.identifier == f"EDB-{key}"
            assert stored.title == clean_text(record.title)
            assert stored.platform == clean_text(record.platform, 64)
            db.ingest([stored])
            assert db.get(key) == stored
    finally:
        db.close()


@PROFILE
@given(st.lists(script_entry, max_size=6))
def test_scriptdb_round_trips_every_entry_it_accepts(entries):
    """P13 for corpus three, including the identity the parser assigns.

    PROP-03: this failed on `a.nse.nse`, where the parser and the store
    disagreed about a row's name, so a script present in the corpus was
    invisible to every lookup. Fail-safe -- an invisible script resolves to
    `unclassified` -- and still a row nobody can find.
    """
    latest = {}
    for entry in entries:
        name = safe_script_name(entry.name)
        if name is not None:
            latest[name] = entry

    db = ScriptDB()
    try:
        db.ingest(entries)
        for name, entry in latest.items():
            stored = db.get(name)
            assert stored is not None, (entry, name)
            assert stored.name == name
            assert stored.filename == f"{name}.nse"
            # The category verdict survives storage. This is the one that
            # must not drift: it decides whether a command is composed.
            assert isinstance(stored.category, Category)
            assert stored.category == db.category_of(name)
            db.ingest([stored])
            assert db.get(name) == stored
    finally:
        db.close()


_vuln_entry = st.builds(
    lambda cve, title, product, cvss: VulnEntry(
        cve_id=cve, title=title, product_match=product, cvss=cvss),
    st.from_regex(r"\ACVE-20[0-9]{2}-[0-9]{4}\Z", fullmatch=True),
    st.text(max_size=12), st.sampled_from(["apache", "openssh", "", "nginx"]),
    st.floats(0.0, 10.0))


@PROFILE
@given(st.lists(_vuln_entry, max_size=6))
def test_vulndb_ingest_accepts_any_generated_corpus(entries):
    """P12 and P13 for corpus one.

    PROP-02: a batch containing one CVE twice raised `sqlite3.IntegrityError`
    out of `executemany`, which aborts the transaction and loses every good
    row in the batch with it -- up to two thousand. Both sibling corpora
    dedupe inside a batch and say in a comment why; this one did not.
    """
    db = VulnDB()
    try:
        written = db.ingest(entries)
        distinct = {e.cve_id for e in entries}
        assert written == len(distinct)
        assert db.stats().cves == len(distinct)
        for cve in distinct:
            assert db.get(cve) is not None
    finally:
        db.close()


@settings(max_examples=40, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(exploit_record, max_size=5),
       st.lists(script_entry, max_size=5),
       st.lists(_vuln_entry, max_size=5),
       st.integers(min_value=2, max_value=4))
def test_re_ingesting_a_corpus_n_times_changes_no_row_count(
        records, entries, vulns, times):
    """P14. Bug 5 from docs/CORPUS-PATTERN.md, as a property.

    "A daily refresh that doubles the corpus is worse than no refresh."
    Written as example tests this is three cases over three hand-made
    fixtures; written as a property it is the claim itself, over every corpus
    the generator can invent -- including the duplicate-key and empty-batch
    shapes nobody writes a fixture for.
    """
    exploits, scripts, vulndb = ExploitDB(), ScriptDB(), VulnDB()
    try:
        def counts():
            return (exploits.stats().as_dict(), scripts.stats().as_dict(),
                    vulndb.stats().as_dict())

        exploits.ingest(records)
        scripts.ingest(entries)
        vulndb.ingest(vulns)
        first = counts()
        for _ in range(times - 1):
            exploits.ingest(records)
            scripts.ingest(entries)
            vulndb.ingest(vulns)
            assert counts() == first
    finally:
        exploits.close()
        scripts.close()
        vulndb.close()
