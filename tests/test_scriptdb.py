"""Corpus three: nmap's `script.db`, the categories, and the seam.

Same structure as `test_exploitdb.py` and for the same reason -- the five
bugs in CORPUS-PATTERN.md were written down so the third corpus would not pay
to find them again -- with one addition the other two corpora did not need.

`script.db` is the only feed reconkg reads whose contents decide a *safety*
question. A poisoned ExploitDB row costs one wrong `searchsploit -x`; a
poisoned `script.db` row that resolves to the wrong category is a command
reconkg composes and aims at a host. RC-35 is that finding in its smallest
form -- a row declaring one category as a bare string -- and the fixture
below carries it, an unknown tag, a malformed line and an exploit-category
script, because those are the four shapes that decide whether the boundary
holds.

The fixture is synthetic. The script *names* are real nmap ones (a fact, not
a copy) and the file is written here rather than lifted from an install, for
the reason exploitdb ships no fixture either.
"""

from __future__ import annotations

import pytest

from reconkg.commands import (BoundaryViolation, Category, validate_script_name)
from reconkg.handoff import build_commands, build_handoff
from reconkg.resolver import (SCRIPT_ENV_VAR, DbScriptResolver,
                              NullScriptResolver, StaticScriptResolver,
                              scripts_from_env)
from reconkg.scriptdb import (NotAScriptDb, ScriptDB, ScriptEntry,
                              clean_category, cve_fragments, parse_entry,
                              read_script_db, safe_script_name,
                              script_matches, service_prefixes)
from reconkg.vulnref import LedgerRow

# --------------------------------------------------------------------------- #
# The golden fixture
# --------------------------------------------------------------------------- #

GOLDEN = """\
Entry { filename = "http-title.nse", categories = { "default", "discovery", "safe", } }
Entry { filename = "http-shellshock.nse", categories = { "exploit", "intrusive", "vuln", } }
Entry { filename = "http-vuln-cve2017-5638.nse", categories = { "exploit", "intrusive", "vuln", } }
Entry { filename = "http-enum.nse", categories = { "discovery", "intrusive", } }
Entry { filename = "http-slowloris.nse", categories = { "dos", "intrusive", } }
Entry { filename = "http-brute.nse", categories = { "brute", "intrusive", } }
Entry { filename = "ssl-cert.nse", categories = { "default", "safe", "discovery", } }
Entry { filename = "ssl-heartbleed.nse", categories = { "vuln", "safe", } }
Entry { filename = "smb-vuln-ms17-010.nse", categories = { "vuln", "intrusive", } }
Entry { filename = "smb-os-discovery.nse", categories = { "default", "discovery", "safe", } }
Entry { filename = "banner.nse", categories = { "discovery", "safe", } }
Entry { filename = "sslv2.nse", categories = { "default", "safe", } }
Entry { filename = "httpd-fingerprint.nse", categories = { "safe", } }
Entry { filename = "http-fetch.nse", categories = { "safe" } }
Entry { filename = "smtp-open-relay.nse", categories = "intrusive" }
Entry { filename = "http-quantum-probe.nse", categories = { "quantum", "safe", } }
Entry { filename = "http-nothing.nse", categories = { } }
this line is not an Entry at all
Entry { filename = "http-truncated.nse", categories = { "safe",
Entry { filename = "http-title.nse,exploit/*", categories = { "safe", } }
"""
"""One realistic `script.db` excerpt, carrying every shape that matters.

    http-title              three categories, the ordinary case
    http-shellshock         **exploit** -- must be named, never composed
    http-vuln-cve2017-5638  the CVE-in-the-name mapping rule
    http-slowloris          dos, and http-brute, brute -- the other two
                            never-composed tiers
    httpd-fingerprint       a name that *starts with* `http` but is not an
                            `http-` script; the prefix rule must not claim it
    http-fetch              a table with no trailing comma (nmap writes both)
    smtp-open-relay         **RC-35**: categories as a bare string
    http-quantum-probe      an unknown tag beside `safe`
    http-nothing            an empty categories table
    http-truncated          a malformed line -- unterminated table
    the last line           a filename that is an `--script` expression
"""


@pytest.fixture
def script_db_file(tmp_path):
    path = tmp_path / "script.db"
    path.write_text(GOLDEN, encoding="utf-8")
    return path


@pytest.fixture
def db(tmp_path, script_db_file):
    store = ScriptDB(tmp_path / "scripts.sqlite")
    store.ingest_file(script_db_file)
    yield store
    store.close()


# --------------------------------------------------------------------------- #
# The parser. Lua, read as text.
# --------------------------------------------------------------------------- #

def test_an_ordinary_entry_parses_to_name_and_categories():
    entry = parse_entry(
        'Entry { filename = "http-title.nse", categories = '
        '{ "default", "discovery", "safe", } }')
    assert entry.name == "http-title"
    assert entry.filename == "http-title.nse"
    assert entry.categories == ("default", "discovery", "safe")


def test_a_table_without_a_trailing_comma_parses():
    entry = parse_entry(
        'Entry { filename = "http-fetch.nse", categories = { "safe" } }')
    assert entry.categories == ("safe",)


def test_rc35_a_bare_string_becomes_a_one_element_tuple():
    """The finding, at its source. `_worst_category` iterates its argument,
    so a parser returning the *string* `"exploit"` decomposes it into seven
    unrecognised characters and lands on `unclassified` -- which is
    composable on opt-in. The shape is accepted here and normalised, so no
    consumer downstream ever receives a string to iterate."""
    entry = parse_entry(
        'Entry { filename = "smtp-open-relay.nse", categories = "intrusive" }')
    assert entry.categories == ("intrusive",)
    assert entry.category is Category.INTRUSIVE


def test_rc35_a_bare_exploit_string_still_resolves_to_exploit():
    entry = parse_entry(
        'Entry { filename = "http-evil.nse", categories = "exploit" }')
    assert entry.categories == ("exploit",)
    assert entry.category is Category.EXPLOIT


def test_an_unknown_tag_is_kept_and_voids_the_verdict():
    """RC-35's second half. Dropping the tag would leave `safe` deciding
    alone, and the script would be emitted by default. nmap adds categories;
    this parser does not get to assume the ones it knows are all of them."""
    entry = parse_entry(
        'Entry { filename = "http-quantum-probe.nse", categories = '
        '{ "quantum", "safe", } }')
    assert "quantum" in entry.categories
    assert entry.category is Category.UNCLASSIFIED


def test_an_empty_categories_table_is_unclassified_not_empty():
    entry = parse_entry(
        'Entry { filename = "http-nothing.nse", categories = { } }')
    assert entry.categories == ("unclassified",)
    assert entry.category is Category.UNCLASSIFIED


@pytest.mark.parametrize("line", [
    "",
    "   ",
    "-- a comment",
    "this line is not an Entry at all",
    'Entry { filename = "http-truncated.nse", categories = { "safe",',
    'Entry { categories = { "safe", } }',
    'Entry { filename = "x.nse" }',
    "os.execute('rm -rf /')",
    'Entry { filename = "a.nse", categories = { "safe", } } } print(1)',
])
def test_a_line_that_is_not_an_entry_is_none_not_an_exception(line):
    assert parse_entry(line) is None


def test_the_parser_does_not_evaluate_lua():
    """A crafted script.db is a supply-chain vector -- `nmap
    --script-updatedb` rebuilds it from whatever .nse files are on disk. The
    only defence that holds is not having an interpreter in the path at
    all."""
    import reconkg.scriptdb as scriptdb

    source = (scriptdb.__file__)
    text = open(source, encoding="utf-8").read()
    for forbidden in ("eval(", "exec(", "lupa", "subprocess"):
        assert forbidden not in text, f"{forbidden} in scriptdb.py"


# --------------------------------------------------------------------------- #
# Sanitising. Every value here came out of third-party Lua source.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("http-title.nse", "http-title"),
    ("http-title", "http-title"),
    (" http-title.nse ", "http-title"),
    ("HTTP-Title.NSE", "HTTP-Title"),
    ("ms-sql-info.nse", "ms-sql-info"),
    ("smb2-time.nse", "smb2-time"),
])
def test_a_well_formed_script_name_survives(raw, expected):
    assert safe_script_name(raw) == expected


@pytest.mark.parametrize("raw", [
    "http-title.nse,exploit/*",         # an --script expression
    "exploit/*",
    "all",                              # a name is fine; see below
    "-sV",
    "--script-args=x",
    "http title",
    "http-title; nmap -sS x",
    "../../etc/passwd",
    "$(id)",
    "http-title\nall",
    "", None, "   ",
    "a" * 200,
])
def test_a_hostile_script_name_is_refused_or_kept_whole(raw):
    """`all` is a legal script name shape and a legitimate nmap keyword; it
    is not refused here because refusing it would be refusing a name pattern
    rather than a structure. Everything else in this list is a *selection
    expression*, and those are refused outright rather than trimmed -- a
    trimmed name would point the corpus at a different script from the one
    the file declared."""
    result = safe_script_name(raw)
    assert result is None or result == raw.strip()


def test_the_command_builder_refuses_the_same_names():
    for raw in ("http-title.nse,exploit/*", "exploit/*", "-sV", "http title",
                "", "http-title; id", "a" * 200):
        with pytest.raises(BoundaryViolation):
            validate_script_name(raw)


def test_the_command_builder_accepts_the_ordinary_ones():
    assert validate_script_name("http-shellshock.nse") == "http-shellshock"
    assert validate_script_name("vuln") == "vuln"


@pytest.mark.parametrize("raw,expected", [
    ("safe", "safe"), ("SAFE", "safe"), ("  vuln  ", "vuln"),
    ("quantum", "quantum"), ("version", "version"),
])
def test_a_category_token_is_lowercased_and_kept(raw, expected):
    assert clean_category(raw) == expected


@pytest.mark.parametrize("raw", [
    "safe\nexploit", "safe exploit", "", None, "a" * 100, "-safe", "1safe",
    "safe;", "safe\x00",
])
def test_a_category_that_is_not_a_word_is_refused(raw):
    assert clean_category(raw) is None


def test_a_refused_category_becomes_unclassified_not_nothing():
    """The row said *something*. Dropping it would leave the tags reconkg
    could read deciding alone, which is the laundering RC-35 describes."""
    entry = parse_entry(
        'Entry { filename = "x.nse", categories = { "safe", "not a word" } }')
    assert entry.category is Category.UNCLASSIFIED


def test_a_row_whose_filename_is_an_expression_is_dropped(db):
    assert db.get("http-title") is not None
    assert db.categories_for("http-title") == ["default", "discovery", "safe"]
    # The last fixture line declared `http-title.nse,exploit/*`. If it had
    # been trimmed rather than dropped it would have overwritten the real
    # http-title row with `["safe"]`.
    assert "exploit" not in db.categories_for("http-title")


# --------------------------------------------------------------------------- #
# The store
# --------------------------------------------------------------------------- #

def test_the_lookup_the_corpus_exists_for(db):
    assert db.categories_for("http-shellshock") == ["exploit", "intrusive",
                                                    "vuln"]
    assert db.categories_for("http-shellshock.nse") == db.categories_for(
        "http-shellshock")


def test_a_script_the_corpus_does_not_hold_returns_nothing(db):
    assert db.categories_for("http-invented") == []
    assert db.category_of("http-invented") is Category.UNCLASSIFIED


def test_the_reverse_lookup_by_category(db):
    assert db.scripts_in_category("exploit") == ["http-shellshock",
                                                 "http-vuln-cve2017-5638"]
    assert "ssl-cert" in db.scripts_in_category("default")


def test_the_reverse_lookup_refuses_a_non_token(db):
    assert db.scripts_in_category("safe; drop table script") == []


def test_category_of_takes_the_most_restrictive(db):
    """`ssl-heartbleed` declares both `vuln` and `safe` in the fixture, which
    is exactly the disagreement `_worst_category` exists to resolve."""
    assert db.category_of("ssl-heartbleed") is Category.VULN
    assert db.category_of("http-slowloris") is Category.DOS
    assert db.category_of("http-brute") is Category.BRUTE


def test_get_returns_the_whole_entry(db):
    entry = db.get("smb-vuln-ms17-010")
    assert entry.filename == "smb-vuln-ms17-010.nse"
    assert entry.category is Category.VULN
    assert entry.as_dict()["category"] == "vuln"


def test_stats_count_scripts_and_links_separately(db):
    stats = db.stats()
    assert stats.scripts == 17, "one row per parseable entry, deduplicated"
    assert stats.category_links > stats.scripts
    assert stats.distinct_categories >= 8


def test_both_columns_of_the_join_table_are_indexed(db):
    """Bug 2. The read path is `category` and the *delete* path in
    `_write_batch` is `filename`; an index on the first alone is what took
    corpus one's ingest from 65,570/s to 697/s."""
    indexed = {row[1] for row in db._conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='index' "
        "AND tbl_name='script_category'") if row[1]}
    text = " ".join(indexed)
    assert "(category)" in text
    assert "(filename)" in text


def test_the_name_column_is_indexed_too(db):
    """Every lookup in the module is by name, not by the primary key."""
    rows = [r[0] for r in db._conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' "
        "AND tbl_name='script'") if r[0]]
    assert any("(name)" in sql for sql in rows)


def test_a_query_plan_uses_the_category_index(db):
    plan = " ".join(str(r[3]) for r in db._conn.execute(
        "EXPLAIN QUERY PLAN SELECT s.name FROM script_category c "
        "JOIN script s ON s.filename = c.filename WHERE c.category = ?",
        ("exploit",)))
    assert "script_category_category" in plan or "USING INDEX" in plan


# --------------------------------------------------------------------------- #
# Bug 5: re-ingest updates, it does not append
# --------------------------------------------------------------------------- #

def test_reingesting_updates_rather_than_duplicating(db, script_db_file):
    before = db.stats().as_dict()
    db.ingest_file(script_db_file)
    db.ingest_file(script_db_file)
    assert db.stats().as_dict() == before


def test_reingest_does_not_duplicate_the_join_rows_either(db, script_db_file):
    """The parent table's primary key hides this: `script` deduplicates and
    looks correct while `script_category` triples underneath."""
    db.ingest_file(script_db_file)
    assert db.categories_for("http-shellshock") == ["exploit", "intrusive",
                                                    "vuln"]


def test_a_rewritten_row_replaces_its_old_categories(db, tmp_path):
    """An nmap upgrade that reclassifies a script must not leave the old
    verdict behind, or the corpus accumulates every claim ever made."""
    path = tmp_path / "script2.db"
    path.write_text(
        'Entry { filename = "http-shellshock.nse", categories = { "safe", } }\n',
        encoding="utf-8")
    db.ingest_file(path)
    assert db.categories_for("http-shellshock") == ["safe"]


def test_a_duplicate_inside_one_batch_does_not_abort_it():
    with ScriptDB() as store:
        written = store.ingest([
            ScriptEntry("a.nse", "a", ("safe",)),
            ScriptEntry("a.nse", "a", ("vuln",)),
            ScriptEntry("b.nse", "b", ("safe",)),
        ])
        assert written == 2
        assert store.categories_for("a") == ["vuln"], "last one wins"
        assert store.categories_for("b") == ["safe"]


def test_a_bare_string_handed_to_the_store_is_not_stored_per_character():
    with ScriptDB() as store:
        store.ingest([ScriptEntry("x.nse", "x", "exploit")])
        assert store.categories_for("x") == ["exploit"]
        assert store.category_of("x") is Category.EXPLOIT


# --------------------------------------------------------------------------- #
# Malformed input. The file is Lua and not a stable API.
# --------------------------------------------------------------------------- #

def test_a_malformed_line_costs_that_line_only(db, script_db_file):
    """The fixture carries an unterminated table and a line of prose. Both
    are dropped; every entry around them survives."""
    assert db.get("http-truncated") is None
    assert db.get("http-title") is not None
    assert db.get("http-quantum-probe") is not None


def test_the_skipped_lines_are_counted_not_silent(tmp_path, script_db_file):
    with ScriptDB() as store:
        written, stats = store.ingest_file(script_db_file)
    assert written == 17
    assert stats.skipped >= 3
    assert stats.errors, "a skipped line with no record of it is a silent drop"


def test_a_file_that_is_not_script_db_is_refused_not_silently_empty(tmp_path):
    """The worst outcome for this corpus: an index that loads without
    complaint and reports every script as unclassified, which is a defensible
    state nobody would investigate."""
    path = tmp_path / "wrong.db"
    path.write_text("id,file,description\n1,a,b\n", encoding="utf-8")
    with ScriptDB() as store:
        with pytest.raises(NotAScriptDb):
            store.ingest_file(path)


def test_a_long_file_of_the_wrong_kind_is_refused_early(tmp_path):
    path = tmp_path / "wrong.db"
    path.write_text("not an entry\n" * 5000, encoding="utf-8")
    with ScriptDB() as store:
        with pytest.raises(NotAScriptDb):
            store.ingest_file(path)


def test_an_empty_file_is_refused(tmp_path):
    path = tmp_path / "empty.db"
    path.write_text("", encoding="utf-8")
    with ScriptDB() as store:
        with pytest.raises(NotAScriptDb):
            store.ingest_file(path)


def test_a_missing_file_raises(tmp_path):
    with ScriptDB() as store:
        with pytest.raises(FileNotFoundError):
            store.ingest_file(tmp_path / "absent.db")


def test_reading_streams_one_entry_at_a_time(script_db_file):
    """A generator, not a list. The file is small, and so was corpus one's
    until it was not; `ingest` wants a batch at a time either way."""
    from reconkg.scriptdb import ParseStats

    stats = ParseStats()
    stream = read_script_db(script_db_file, stats)
    first = next(stream)
    assert first.name == "http-title"
    assert stats.parsed == 1, "the whole file was read to yield one entry"
    assert len(list(stream)) == 16


def test_provenance_survives_a_refresh(db):
    """Bug 5 applies to the provenance row exactly as it applies to the
    corpus: `name` is the primary key, so a rebuild replaces rather than
    appends a second answer to 'how old is this index'."""
    db.record_feed("script.db", url="/usr/share/nmap/scripts/script.db",
                   record_count=17, fetched_at="2026-01-01T00:00:00+00:00")
    db.record_feed("script.db", record_count=18,
                   fetched_at="2026-02-01T00:00:00+00:00")
    assert len(db.feeds()) == 1
    assert db.feed("script.db").record_count == 18


def test_an_absurdly_long_line_is_skipped_not_read_into_memory(tmp_path):
    path = tmp_path / "script.db"
    path.write_text(
        'Entry { filename = "http-title.nse", categories = { "safe", } }\n'
        + 'Entry { filename = "x.nse", categories = { "'
        + "a" * 50_000 + '", } }\n',
        encoding="utf-8")
    with ScriptDB() as store:
        written, stats = store.ingest_file(path)
    assert written == 1
    assert stats.skipped == 1


# --------------------------------------------------------------------------- #
# The mapping. Two rules, and no third.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("service,expected", [
    ("http", ("http",)),
    ("https", ("http", "ssl")),
    ("HTTP", ("http",)),
    ("ssl/http", ("http",)),
    ("http?", ("http",)),
    ("microsoft-ds", ("smb", "smb2")),
    ("ms-wbt-server", ("rdp",)),
    ("irc", ("irc",)),
    ("", ()),
    ("Apache httpd 2.4.49", ()),
    ("unknown-service-with-a-very-long-name", ()),
])
def test_service_prefixes(service, expected):
    assert service_prefixes(service) == expected


@pytest.mark.parametrize("cve,expected", [
    ("CVE-2017-5638", ("cve2017-5638", "cve-2017-5638")),
    ("cve-2017-5638", ("cve2017-5638", "cve-2017-5638")),
    ("CVE-2021-44228", ("cve2021-44228", "cve-2021-44228")),
    ("", ()),
    ("CVE-2017", ()),
    ("not a cve", ()),
    ("CVE-2017-5638; drop table script", ()),
])
def test_cve_fragments(cve, expected):
    assert cve_fragments(cve) == expected


@pytest.mark.parametrize("name,prefixes,fragments,expected", [
    ("http-title", ("http",), (), True),
    ("http", ("http",), (), True),
    ("httpd-fingerprint", ("http",), (), False),
    ("https-title", ("http",), (), False),
    ("ssl-cert", ("http", "ssl"), (), True),
    ("smb-os-discovery", ("http",), (), False),
    ("http-vuln-cve2017-5638", (), ("cve2017-5638",), True),
    ("http-vuln-cve2017-5638", (), ("cve2018-5638",), False),
    ("", ("http",), (), False),
    ("http-title", (), (), False),
    ("http-title", ("",), (), False),
])
def test_script_matches(name, prefixes, fragments, expected):
    assert script_matches(name, prefixes, fragments) is expected


def test_the_prefix_rule_stops_at_a_name_boundary():
    """`httpd-fingerprint` starts with the letters `http` and is not an HTTP
    script. A substring test would claim it, and a suggestion nobody can
    justify is worse than a gap, because the gap is visible."""
    assert script_matches("httpd-fingerprint", ("http",)) is False


def test_scripts_for_a_service_finds_the_family(db):
    found = {e.name for e in db.scripts_for("http")}
    assert "http-title" in found
    assert "http-enum" in found
    assert "httpd-fingerprint" not in found
    assert "smb-os-discovery" not in found


def test_scripts_for_a_cve_finds_the_named_script(db):
    found = [e.name for e in db.scripts_for("", "CVE-2017-5638")]
    assert found == ["http-vuln-cve2017-5638"]


def test_a_cve_named_script_leads_the_service_family(db):
    found = [e.name for e in db.scripts_for("http", "CVE-2017-5638")]
    assert found[0] == "http-vuln-cve2017-5638", (
        "the script naming the exact flaw is the stronger signal, so a "
        "truncation must lose the protocol family first")


def test_no_service_and_no_cve_is_no_suggestion(db):
    assert db.scripts_for("", "") == []
    assert db.scripts_for("Apache httpd", "not-a-cve") == []


def test_a_wildcard_service_cannot_select_the_whole_catalogue(db):
    """`%` is a LIKE wildcard. Unescaped it matches every script in the
    corpus and presents the entire NSE catalogue as relevant to one lead."""
    assert db.scripts_for("%") == []
    assert db.scripts_for("%%%") == []


def test_scripts_for_is_ordered_before_it_is_limited(db):
    found = db.scripts_for("http", "CVE-2017-5638", limit=1)
    assert [e.name for e in found] == ["http-vuln-cve2017-5638"]


def test_every_returned_entry_carries_its_categories(db):
    for entry in db.scripts_for("http"):
        assert entry.categories, f"{entry.name} came back unclassified"


# --------------------------------------------------------------------------- #
# The resolver seam
# --------------------------------------------------------------------------- #

def test_no_env_var_gives_the_null_resolver():
    assert isinstance(scripts_from_env({}), NullScriptResolver)


def test_the_null_resolver_says_unknown_never_safe():
    text = NullScriptResolver().describe()
    assert "unknown" in text
    assert "unclassified" in text
    assert "safe" not in text.replace("assumed safe", "")
    assert SCRIPT_ENV_VAR in text


def test_the_null_resolver_answers_nothing_for_every_question():
    resolver = NullScriptResolver()
    assert resolver.categories_for("http-shellshock") == ()
    assert resolver.scripts_for("http", "CVE-2017-5638") == ()


def test_a_missing_script_db_fails_loudly(tmp_path):
    with pytest.raises(FileNotFoundError) as exc:
        scripts_from_env({SCRIPT_ENV_VAR: str(tmp_path / "absent.db")})
    assert "script-updatedb" in str(exc.value)


def test_the_env_var_accepts_nmaps_own_file(script_db_file):
    resolver = scripts_from_env({SCRIPT_ENV_VAR: str(script_db_file)})
    assert isinstance(resolver, DbScriptResolver)
    assert list(resolver.categories_for("http-shellshock")) == [
        "exploit", "intrusive", "vuln"]
    resolver.close()


def test_the_env_var_also_accepts_a_prebuilt_index(tmp_path, script_db_file):
    path = tmp_path / "prebuilt.sqlite"
    with ScriptDB(path) as store:
        store.ingest_file(script_db_file)
    resolver = scripts_from_env({SCRIPT_ENV_VAR: str(path)})
    assert list(resolver.categories_for("ssl-heartbleed")) == ["safe", "vuln"]
    resolver.close()


def test_a_file_of_the_wrong_kind_named_by_the_env_var_is_refused(tmp_path):
    path = tmp_path / "script.db"
    path.write_text("nothing here\n", encoding="utf-8")
    with pytest.raises(NotAScriptDb):
        scripts_from_env({SCRIPT_ENV_VAR: str(path)})


def test_the_db_resolver_describes_the_never_composed_count(script_db_file):
    resolver = scripts_from_env({SCRIPT_ENV_VAR: str(script_db_file)})
    text = resolver.describe()
    assert "scripts" in text
    assert "never-composed" in text
    # The operator's own path, not `:memory:`. A parsed script.db lives in
    # memory, and naming that tells them nothing about which file the
    # categories came from.
    assert str(script_db_file) in text
    resolver.close()


def test_parsing_nmaps_file_records_where_it_came_from(script_db_file):
    """No fetch step writes a manifest for this corpus -- the file arrives
    with nmap -- so the digest and the file's own mtime are recorded here.
    Provenance must not be a property of one code path."""
    resolver = scripts_from_env({SCRIPT_ENV_VAR: str(script_db_file)})
    feed = resolver._db.feed("script.db")
    assert feed is not None
    assert feed.url == str(script_db_file)
    assert len(feed.sha256) == 64
    assert feed.record_count == 17
    resolver.close()


def test_the_static_resolver_answers_both_questions():
    resolver = StaticScriptResolver([
        ScriptEntry("http-shellshock.nse", "http-shellshock",
                    ("exploit", "intrusive", "vuln")),
        ScriptEntry("smb-os-discovery.nse", "smb-os-discovery",
                    ("safe", "discovery")),
    ])
    assert resolver.categories_for("http-shellshock") == (
        "exploit", "intrusive", "vuln")
    assert resolver.categories_for("absent") == ()
    assert [e.name for e in resolver.scripts_for("http")] == [
        "http-shellshock"]
    assert resolver.scripts_for("", "") == ()


# --------------------------------------------------------------------------- #
# End to end: the boundary, with real categories behind it
# --------------------------------------------------------------------------- #

def _row(**kw) -> LedgerRow:
    base = dict(target="10.10.10.42", port=80, protocol="tcp", service="http",
                product="Apache httpd", version="2.4.49",
                cve_id="CVE-2017-5638", title="Struts RCE", cvss=9.8,
                maturity="weaponised", priority=0.9,
                fingerprint_confidence=0.9, rationale="version match")
    base.update(kw)
    return LedgerRow(**base)


def _resolver(script_db_file):
    return scripts_from_env({SCRIPT_ENV_VAR: str(script_db_file)})


def test_an_exploit_category_script_is_named_never_composed(script_db_file):
    """The line the whole corpus exists to draw. `http-vuln-cve2017-5638` is
    `exploit` in script.db, it matches the lead's CVE by name, and it must
    arrive as a reference with no argv."""
    resolver = _resolver(script_db_file)
    commands = build_commands(_row(), scripts=resolver,
                              allowed=list(Category))

    named = [c for c in commands
             if "http-vuln-cve2017-5638" in (c.reference or "")]
    assert named, "the exploit-category script was not reported at all"
    assert named[0].category is Category.EXPLOIT
    assert named[0].argv is None
    assert not any("http-vuln-cve2017-5638" in (c.argv or ())
                   for c in commands)
    resolver.close()


def test_the_target_never_appears_beside_an_exploit_script(script_db_file):
    resolver = _resolver(script_db_file)
    for command in build_commands(_row(), scripts=resolver,
                                  allowed=list(Category)):
        if command.category in (Category.EXPLOIT, Category.DOS,
                                Category.BRUTE, Category.FUZZER):
            assert not command.composed
            assert "10.10.10.42" not in command.rendered
    resolver.close()


def test_a_safe_script_is_composed_and_emitted_by_default(script_db_file):
    resolver = _resolver(script_db_file)
    commands = build_commands(_row(service="ssl"), scripts=resolver)
    composed = [c for c in commands if c.composed and "--script" in
                (c.argv or ())]
    names = {c.argv[c.argv.index("--script") + 1] for c in composed}
    assert "ssl-cert" in names
    for command in composed:
        assert command.category in (Category.SAFE, Category.DISCOVERY,
                                    Category.VERSION)
    resolver.close()


def test_a_vuln_script_is_withheld_until_the_operator_opts_in(script_db_file):
    resolver = _resolver(script_db_file)
    default = build_commands(_row(service="ssl"), scripts=resolver)
    assert not any("ssl-heartbleed" in (c.argv or ()) for c in default)

    opted = build_commands(_row(service="ssl"), scripts=resolver,
                           allowed=[Category.SAFE, Category.VULN])
    assert any("ssl-heartbleed" in (c.argv or ()) for c in opted)
    resolver.close()


def test_an_unknown_tag_keeps_a_script_out_of_the_default_tier(tmp_path):
    """`http-quantum-probe` is tagged `quantum` and `safe`. The unknown tag
    voids the verdict, so it must not be emitted by default.

    Its own one-line script.db rather than the golden fixture: the fixture
    holds nine `http-*` scripts and only the highest-ranked five are
    composed, so a failure there could mean the policy broke or could mean
    the cut moved. Isolating the variable is CORPUS-PATTERN.md's rule and
    the reason corpus one nearly "fixed" a working index."""
    path = tmp_path / "script.db"
    path.write_text(
        'Entry { filename = "http-quantum-probe.nse", categories = '
        '{ "quantum", "safe", } }\n', encoding="utf-8")
    resolver = scripts_from_env({SCRIPT_ENV_VAR: str(path)})
    default = build_commands(_row(), scripts=resolver)
    assert not any("http-quantum-probe" in (c.argv or ()) for c in default)

    opted = build_commands(_row(), scripts=resolver,
                           allowed=[Category.UNCLASSIFIED])
    composed = [c for c in opted if "http-quantum-probe" in (c.argv or ())]
    assert composed and composed[0].category is Category.UNCLASSIFIED
    resolver.close()


def test_a_poisoned_row_costs_that_row_and_not_the_handoff(tmp_path):
    """RC-32's rule, third feed. The store drops an unusable name at ingest;
    this asserts the hand-off survives one arriving by any other route."""
    class _Hostile:
        def categories_for(self, script):
            return ()

        def scripts_for(self, service="", cve_id=""):
            return [ScriptEntry("x", "http-title.nse,exploit/*", ("safe",)),
                    ScriptEntry("http-title.nse", "http-title", ("safe",))]

        def describe(self):
            return "hostile"

    commands = build_commands(_row(), scripts=_Hostile())
    assert any("http-title" in (c.argv or ()) for c in commands)
    assert not any("exploit/*" in " ".join(c.argv or ()) for c in commands)


def test_the_remainder_is_named_rather_than_dropped(tmp_path):
    """Bug 4 in different clothes. `http` matches over a hundred scripts in a
    stock install; a silent cut is a correctness bug wearing a performance
    bug's clothes."""
    path = tmp_path / "script.db"
    path.write_text("".join(
        f'Entry {{ filename = "http-{n:03d}.nse", categories = '
        f'{{ "safe", }} }}\n' for n in range(30)), encoding="utf-8")
    resolver = scripts_from_env({SCRIPT_ENV_VAR: str(path)})
    commands = build_commands(_row(), scripts=resolver)
    summary = [c for c in commands if "further NSE scripts" in (c.reference or "")]
    assert summary, "the scripts that did not fit were dropped silently"
    assert not summary[0].composed
    resolver.close()


# --------------------------------------------------------------------------- #
# No script.db: behaviour identical to before this corpus existed
# --------------------------------------------------------------------------- #

def test_no_script_db_leaves_the_commands_exactly_as_they_were():
    """The regression that would matter most. An operator who has not set
    `RECONKG_SCRIPT_DB` must get byte-for-byte what they got yesterday."""
    before = build_commands(_row())
    after = build_commands(_row(), scripts=NullScriptResolver())
    assert [c.as_dict() for c in before] == [c.as_dict() for c in after]

    nmap = [c for c in before if c.tool == "nmap"]
    assert [c.category.value for c in nmap] == ["version"], (
        "the vuln-category invocation is opt-in and nothing else is emitted")


def test_the_vuln_category_selector_is_still_classified_vuln():
    """`--script vuln` names a category, not a script, so what it runs is
    that category by definition -- the one mapping that is a rule rather than
    a table entry."""
    commands = build_commands(_row(), allowed=[Category.VERSION,
                                               Category.VULN])
    scripted = [c for c in commands
                if c.composed and "vuln" in (c.argv or ())]
    assert scripted and scripted[0].category is Category.VULN


def test_the_hand_off_renders_without_a_script_index():
    text = build_handoff(_row(), ()).render()
    assert "Lead: CVE-2017-5638" in text


def test_the_hand_off_renders_with_one(script_db_file):
    resolver = _resolver(script_db_file)
    text = build_handoff(_row(), (), None, list(Category),
                         scripts=resolver).render()
    assert "http-vuln-cve2017-5638" in text
    assert "(exploit)" in text
    resolver.close()


# --------------------------------------------------------------------------- #
# PROP-03  The `.nse` strip was not a fixed point
#
# Found by tests/test_properties.py::test_script_name_normalisation_is_a_fixed
# _point, minimised to `a.nse.nse`. The suffix was removed once, and the
# normalisation runs on two paths -- `parse_entry` names the row, and
# `ScriptDB._write_batch` names it again from that name -- so the parser said
# `a.nse` and the store said `a`. The row was written under a name the parser
# never produces, and `get`, `categories_for` and `category_of` all missed it.
#
# Fail-safe (an unfindable script resolves to `unclassified`, which is opt-in)
# and still wrong: it reads to an operator as "nmap ships no script for this".
# --------------------------------------------------------------------------- #

def test_prop03_the_nse_strip_is_idempotent():
    from reconkg.scriptdb import safe_script_name

    assert safe_script_name("a.nse.nse") == "a"
    assert safe_script_name(safe_script_name("a.nse.nse")) == "a"
    assert safe_script_name("http-title.nse") == "http-title"
    assert safe_script_name("http-title") == "http-title"


def test_prop03_the_two_implementations_agree():
    """`commands.validate_script_name` is the same normalisation on the other
    side of the module boundary. A control with two implementations has one
    implementation and one bypass (RC-04/RC-07), and that applies to a
    normalisation as much as to a check."""
    from reconkg.scriptdb import safe_script_name

    for raw in ("a.nse.nse", "http-title.nse", "http-title", "x.NSE.nse"):
        assert safe_script_name(raw) == validate_script_name(raw)


def test_prop03_a_doubly_suffixed_row_is_findable_after_ingest():
    from reconkg.scriptdb import ScriptDB, ScriptEntry, parse_entry

    entry = parse_entry('Entry { filename = "a.nse.nse", '
                        'categories = { "exploit", } }')
    assert entry is not None
    assert entry.name == "a" and entry.filename == "a.nse"
    with ScriptDB() as db:
        db.ingest([entry])
        stored = db.get(entry.name)
        assert stored is not None
        assert stored == entry
        assert db.category_of(entry.name) is Category.EXPLOIT


# --------------------------------------------------------------------------- #
# PROP-04  A category declared as the project's own enum resolved to
#          `unclassified`, which is composable on opt-in
#
# Found by tests/test_properties.py::test_worst_category_is_total_and
# _conservative. `Category` subclasses `str`, so a member passed the
# `isinstance(x, str)` test in `normalise_categories` and was handed on
# unchanged; every consumer then did `Category(str(name).strip().lower())`,
# and `str(Category.EXPLOIT)` is `'Category.EXPLOIT'`. An entry declaring
# `categories=(Category.EXPLOIT,)` -- which is what a `ScriptResolver` written
# against reconkg's own API would naturally produce -- therefore resolved to
# `unclassified`, and unclassified is emitted once the operator opts in.
#
# RC-35 taught the collection layer that a bare string is one category. It did
# not teach it that an enum member is one category spelled in the type the
# module hands out.
# --------------------------------------------------------------------------- #

def test_prop04_an_enum_category_is_not_downgraded():
    from reconkg.commands import _worst_category, normalise_categories

    assert normalise_categories([Category.EXPLOIT]) == ("exploit",)
    assert normalise_categories(Category.EXPLOIT) == ("exploit",)
    assert _worst_category([Category.EXPLOIT]) is Category.EXPLOIT
    assert _worst_category((Category.SAFE, Category.BRUTE)) is Category.BRUTE


def test_prop04_an_enum_declared_exploit_script_is_never_composed():
    from reconkg.commands import NEVER_COMPOSED, nmap_commands
    from reconkg.scriptdb import ScriptEntry

    entry = ScriptEntry("x.nse", "x", (Category.EXPLOIT,))
    assert entry.category is Category.EXPLOIT

    commands = nmap_commands("10.0.0.1", 80, ["x"],
                             {"x": list(entry.categories)})
    firing = [c for c in commands if c.category in NEVER_COMPOSED]
    assert firing and all(c.argv is None for c in firing)


def test_prop04_the_enum_shape_survives_storage():
    from reconkg.scriptdb import ScriptDB, ScriptEntry

    with ScriptDB() as db:
        db.ingest([ScriptEntry("x.nse", "x", (Category.EXPLOIT,))])
        assert db.categories_for("x") == ["exploit"]
        assert db.category_of("x") is Category.EXPLOIT
