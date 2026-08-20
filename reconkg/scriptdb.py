"""Corpus three: nmap's `script.db`, the one source that classifies itself.

`vulndb` answers "which CVEs could apply to this service". `exploitdb`
answers "has anybody published something for them". This answers the
question those two cannot: **what does running this check do to the target**.

docs/COMMAND-MAPPING.md establishes why that question needs its own corpus.
Safety is a property of the individual check, not of the tool -- a nuclei
template tagged `rce` may fingerprint or may achieve RCE, and nothing in its
metadata distinguishes them. NSE is the exception: every script declares its
categories, nmap ships the index as `scripts/script.db`, and the vocabulary
is the one `commands.Category` already speaks. Until now reconkg stood a
two-entry dictionary (`{"vuln": ["vuln"]}`) in for roughly six hundred real
scripts, which meant every script outside it resolved to `unclassified` --
correct, conservative, and useless.

Parsed, not evaluated
---------------------
`script.db` is Lua source. nmap loads it with a Lua interpreter; reconkg
does not, and must not. An operator installs NSE scripts from the internet
(`nmap --script-updatedb` rebuilds this file from whatever `.nse` files are
in the scripts directory), so the file is a plausible supply-chain vector:
it arrives as executable source from a third party. This module reads it as
text with a regex per line, and every value that comes out is treated as
feed data -- bounded, control characters refused, and dropped outright if it
does not have the shape of a script name.

The same discipline as `commands.validate_edb_id`, one feed along. A script
name reaches `argv` in `nmap --script <name> <target>`, and a name is
`[A-Za-z0-9][A-Za-z0-9_.-]*` -- every other character is a character that
means something to nmap's `--script` expression parser (which understands
`,`, `and`, `or`, `not`, globs and directory paths) rather than to the
script loader.

Storage narrows, Python decides
-------------------------------
CORPUS-PATTERN.md's line, held. SQLite finds the scripts whose name shares a
prefix with the service or contains a CVE id. Whether that script is
*relevant* -- and what category it resolves to when the tags disagree -- is
`script_matches` and `commands._worst_category`, in Python, where both are
tested and mutation-tested.

The mapping is deliberately narrow. Two rules, each one a convention nmap
itself follows and neither one an inference reconkg invented:

  1. **Name prefix.** NSE names its scripts for the protocol they speak:
     `http-*`, `smb-*`, `ssl-*`. A service of `http` makes `http-title` a
     candidate.
  2. **CVE in the name.** nmap carries `http-vuln-cve2017-5638`,
     `smb-vuln-ms17-010` and dozens like them. A lead for CVE-2017-5638
     makes the first one a candidate.

There is no third rule. Matching on description text, or guessing that a
`mysql-*` script applies to MariaDB, produces suggestions nobody can check,
and an unjustifiable mapping in a security tool is worse than a gap: the gap
is visible.

Licence
-------
Nothing is bundled. `script.db` is part of an nmap installation and stays
there; reconkg reads the operator's own copy at the path they name in
`RECONKG_SCRIPT_DB`. No fixture in this repository is derived from a real
file, for the same reason no ExploitDB row is.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence

from .commands import Category, _worst_category, normalise_categories
from .vulndb import FeedSource, SchemaMismatch, bounded_lines

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

#: One `script.db` record, as the file spells one:
#:
#:     Entry { filename = "http-shellshock.nse", categories = { "exploit",
#:     "intrusive", "vuln", } }
#:
#: Anchored, and the inner brace group excludes braces so one line cannot
#: swallow the next. The length bounds live in the pattern rather than in a
#: slice because a bound expressed as a quantifier is checked by the same
#: pass that checks the shape -- there is no second place to forget it.
_ENTRY_RE = re.compile(
    r'^\s*Entry\s*\{\s*filename\s*=\s*"([^"\\\x00-\x1f]{1,255})"\s*,\s*'
    r'categories\s*=\s*\{([^{}]{0,4096})\}\s*,?\s*\}\s*,?\s*$')

#: The same record with `categories` given as a bare string rather than a
#: table. Real nmap never writes this; RC-35 is the finding that a parser
#: which *returns* one is enough to turn an exploit script into a composed
#: command, because `_worst_category` iterating a string sees single
#: characters. Accepting the shape here and normalising it to a one-element
#: tuple means the rest of the system never meets it.
_ENTRY_STR_RE = re.compile(
    r'^\s*Entry\s*\{\s*filename\s*=\s*"([^"\\\x00-\x1f]{1,255})"\s*,\s*'
    r'categories\s*=\s*"([^"\\\x00-\x1f]{0,64})"\s*,?\s*\}\s*,?\s*$')

_QUOTED_RE = re.compile(r'"([^"\\\x00-\x1f]{0,64})"')

#: A script name as nmap spells one, minus the `.nse` suffix. Bounded, and
#: the first character must be alphanumeric so a name cannot begin with `-`
#: and arrive at nmap as an option rather than as a script.
SCRIPT_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")

#: An NSE category token. Lower-case words in the real vocabulary; digits and
#: dashes are allowed so a category nmap adds later is *recorded* rather than
#: discarded -- `_worst_category` then resolves it to `unclassified`, which
#: is the conservative answer and the point of RC-35's second half.
CATEGORY_RE = re.compile(r"\A[a-z][a-z0-9_-]{0,31}\Z")

#: Lines longer than this are not `script.db` records. nmap's own longest is
#: well under 200 bytes; the bound stops a crafted file from turning a
#: line-by-line read into a memory problem.
MAX_LINE_BYTES = 8192

#: How many lines are read before a file that has produced no entry at all is
#: refused. A real `script.db` matches on line one.
SNIFF_LINES = 200

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One row per NSE script. `filename` is the primary key because it is what
-- the file is keyed by, and a primary key is what makes a re-ingest replace
-- rather than append (bug 5). `name` is the same value without `.nse`, which
-- is how nmap's `--script` argument and every human being spells it.
CREATE TABLE IF NOT EXISTS script (
    filename TEXT PRIMARY KEY,
    name     TEXT NOT NULL DEFAULT ''
);
-- Every lookup in this module is by name, not by filename. Without this the
-- service-prefix query is a full scan per lead -- survivable at six hundred
-- rows and precisely the assumption that stopped being true for corpus one
-- at a hundred thousand.
CREATE INDEX IF NOT EXISTS script_name ON script(name);

-- The join table. One script carries several categories and one category
-- covers hundreds of scripts; neither direction fits in a column, and a
-- comma-joined string would mean answering "what is in the exploit
-- category" with a LIKE over every row.
CREATE TABLE IF NOT EXISTS script_category (
    filename TEXT NOT NULL REFERENCES script(filename) ON DELETE CASCADE,
    category TEXT NOT NULL,
    PRIMARY KEY (filename, category)
);
-- Bug 2, both directions. `category` is the read path -- "which scripts are
-- exploit-category" -- and `filename` is the *delete* path in
-- `_write_batch`. An index on the read path alone is what took corpus one's
-- ingest from 65,570/s to 697/s, and the delete is the query nobody profiles
-- because it does not appear in any feature.
CREATE INDEX IF NOT EXISTS script_category_category
    ON script_category(category);
CREATE INDEX IF NOT EXISTS script_category_filename
    ON script_category(filename);

CREATE TABLE IF NOT EXISTS feed_source (
    name         TEXT PRIMARY KEY,
    url          TEXT NOT NULL DEFAULT '',
    sha256       TEXT NOT NULL DEFAULT '',
    bytes        INTEGER NOT NULL DEFAULT 0,
    record_count INTEGER NOT NULL DEFAULT 0,
    fetched_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS feed_source_fetched ON feed_source(fetched_at);
"""


class NotAScriptDb(ValueError):
    """The file named is not an nmap `script.db`.

    Its own exception because the alternative -- ingesting nothing and
    reporting success -- is the failure this corpus is least able to survive.
    An empty script index does not read as "empty"; it reads as "every script
    is unclassified", which is a defensible state the operator would have no
    reason to investigate.
    """


@dataclass(frozen=True)
class ScriptEntry:
    """One NSE script and the categories it declares."""

    filename: str
    name: str
    categories: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # RC-38. `parse_entry` always builds a tuple, but this type is
        # public: `StaticScriptResolver` takes hand-built entries and a
        # third-party `ScriptResolver` returns whatever it likes. A bare
        # string here is RC-35's shape, and every consumer that unpacks
        # `categories` itself -- rather than going through `.category` --
        # would decompose it into single characters and resolve an exploit
        # script to `unclassified`. Normalised once, at the type, so no
        # consumer can meet the shape at all.
        object.__setattr__(self, "categories",
                           normalise_categories(self.categories))

    @property
    def category(self) -> Category:
        """The single category policy should judge this script by.

        `commands._worst_category`, unchanged and unduplicated. The
        resolution rules -- a firing category decides outright, an unknown
        tag voids the verdict -- are a security control, and a second
        implementation here would be a second thing to get wrong.
        """
        return _worst_category(self.categories)

    def as_dict(self) -> dict:
        return {"filename": self.filename, "name": self.name,
                "categories": list(self.categories),
                "category": self.category.value}


@dataclass
class ScriptDbStats:
    scripts: int = 0
    category_links: int = 0
    distinct_categories: int = 0

    def as_dict(self) -> dict:
        return {"scripts": self.scripts,
                "category_links": self.category_links,
                "distinct_categories": self.distinct_categories}


@dataclass
class ParseStats:
    lines: int = 0
    parsed: int = 0
    skipped: int = 0
    errors: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Sanitising. Lua source from a third party, treated as such.
# --------------------------------------------------------------------------- #

def _strip_nse(text: str) -> str:
    """Remove the `.nse` suffix, and keep removing it.

    PROP-03. One strip is not a fixed point, and this normalisation runs on
    two code paths: `parse_entry` names the row and `ScriptDB._write_batch`
    names it again. `a.nse.nse` therefore became `a.nse` in the parser and
    `a` in the store, so the corpus held a script under a name the parser
    never produced and every lookup for it -- `get`, `categories_for`,
    `category_of` -- missed. The miss is fail-safe (an unfindable script
    resolves to `unclassified`) and it is still a row nobody can find, which
    is the shape of bug that reads as "nmap has no script for this".

    A normalisation applied on two paths has to be idempotent or it is two
    normalisations, which is the RC-04/RC-07 lesson applied to a cleanup
    rather than to a check.
    """
    text = text.strip()
    while text.lower().endswith(".nse"):
        text = text[:-len(".nse")].strip()
    return text


def safe_script_name(raw) -> Optional[str]:
    """`"http-shellshock.nse"` -> `'http-shellshock'`, or None.

    None, never a partially-cleaned string. A filename of
    `http-title.nse,exploit/*` is not a name with a problem: it is an
    `--script` *expression*, and stripping the dangerous half would leave a
    row in the corpus pointing at a different script from the one the file
    named.
    """
    text = _strip_nse(str(raw or ""))
    return text if SCRIPT_NAME_RE.match(text) else None


def clean_category(raw) -> Optional[str]:
    """A category token, lower-cased, or None if it is not a token at all.

    Unknown *words* survive on purpose -- nmap has added categories before
    and will again, and `_worst_category` turns an unrecognised word into
    `unclassified` rather than ignoring it (RC-35). What does not survive is
    a value that is not a word: control characters, embedded quotes,
    whitespace and length are each evidence the token did not come out of the
    file intact, and the caller records `unclassified` in its place rather
    than dropping the row's claim entirely.
    """
    text = str(raw or "").strip().lower()
    return text if CATEGORY_RE.match(text) else None


def parse_entry(line) -> Optional[ScriptEntry]:
    """One `script.db` line -> a `ScriptEntry`, or None if it is not one.

    Tolerant per line, because a comment, a blank line or a record from a
    future nmap is not a reason to abandon the file. Conservative per record:

    * a row whose categories table is empty made no safety claim, so it is
      recorded as `unclassified` rather than as nothing;
    * a token that survives the quotes but not `clean_category` is recorded
      as `unclassified` too, for the same reason -- the row said *something*
      and reconkg could not read it;
    * `categories = "exploit"` (RC-35's shape) becomes `("exploit",)`, so no
      consumer ever receives a bare string to iterate.
    """
    text = str(line or "")
    match = _ENTRY_RE.match(text)
    if match is not None:
        raw_categories = _QUOTED_RE.findall(match.group(2))
    else:
        match = _ENTRY_STR_RE.match(text)
        if match is None:
            return None
        raw_categories = [match.group(2)]

    name = safe_script_name(match.group(1))
    if name is None:
        return None

    categories: list[str] = []
    for token in raw_categories:
        cleaned = clean_category(token)
        value = cleaned if cleaned is not None else Category.UNCLASSIFIED.value
        if value not in categories:
            categories.append(value)
    if not categories:
        categories = [Category.UNCLASSIFIED.value]

    return ScriptEntry(filename=f"{name}.nse", name=name,
                       categories=tuple(categories))


# --------------------------------------------------------------------------- #
# The mapping. Two rules, both of them conventions nmap follows.
# --------------------------------------------------------------------------- #

#: Service name -> the NSE name prefixes that speak that protocol.
#:
#: Only entries where nmap's own naming makes the link unambiguous. An
#: encrypted service gets `ssl-*` as well, because that is where the
#: certificate and cipher checks live regardless of what rides on top.
SERVICE_PREFIXES: dict[str, tuple[str, ...]] = {
    "http": ("http",),
    "https": ("http", "ssl"),
    "http-proxy": ("http",),
    "http-alt": ("http",),
    "ssl": ("ssl", "tls"),
    "tls": ("ssl", "tls"),
    "smb": ("smb", "smb2"),
    "microsoft-ds": ("smb", "smb2"),
    "netbios-ssn": ("smb", "smb2"),
    "ftp": ("ftp",),
    "ftps": ("ftp", "ssl"),
    "ssh": ("ssh",),
    "smtp": ("smtp",),
    "smtps": ("smtp", "ssl"),
    "imap": ("imap",),
    "imaps": ("imap", "ssl"),
    "pop3": ("pop3",),
    "pop3s": ("pop3", "ssl"),
    "domain": ("dns",),
    "dns": ("dns",),
    "mysql": ("mysql",),
    "ms-sql": ("ms-sql",),
    "ms-sql-s": ("ms-sql",),
    "mssql": ("ms-sql",),
    "postgresql": ("pgsql",),
    "pgsql": ("pgsql",),
    "oracle": ("oracle",),
    "mongodb": ("mongodb",),
    "redis": ("redis",),
    "memcached": ("memcached",),
    "rdp": ("rdp",),
    "ms-wbt-server": ("rdp",),
    "vnc": ("vnc",),
    "snmp": ("snmp",),
    "telnet": ("telnet",),
    "ldap": ("ldap",),
    "ldaps": ("ldap", "ssl"),
    "nfs": ("nfs",),
    "rpcbind": ("rpcinfo",),
    "ntp": ("ntp",),
    "sip": ("sip",),
    "ajp13": ("ajp",),
}

#: A service token reconkg is willing to use as a prefix on its own. NSE
#: names scripts after the protocol they speak, so `service == "irc"` finding
#: the `irc-*` family is nmap's convention rather than reconkg's guess -- but
#: only when the token has the shape of a protocol name, because a
#: version-detection string like `Apache httpd` is not one.
_SERVICE_TOKEN_RE = re.compile(r"\A[a-z][a-z0-9]{1,15}\Z")


def service_prefixes(service) -> tuple[str, ...]:
    """The NSE name prefixes worth searching for a service. Possibly empty.

    Empty is a real answer and the honest one for `unknown`, `tcpwrapped` or
    a blank: no prefix means no name-based suggestion, which is preferable to
    a suggestion built on a service string that identified nothing.
    """
    token = str(service or "").strip().lower()
    if not token:
        return ()
    # nmap writes `http?` for an uncertain match and `ssl/http` for a
    # tunnelled one. The protocol is the last component either way.
    token = token.split("/")[-1].rstrip("?")
    known = SERVICE_PREFIXES.get(token)
    if known is not None:
        return known
    if _SERVICE_TOKEN_RE.match(token):
        return (token,)
    return ()


#: `CVE-2017-5638` as it appears inside a script name. nmap writes
#: `http-vuln-cve2017-5638`; the hyphenated spelling is included because
#: third-party scripts use it and both are cheap to search for.
_CVE_RE = re.compile(r"\ACVE-(\d{4})-(\d{4,7})\Z", re.IGNORECASE)


def cve_fragments(cve_id) -> tuple[str, ...]:
    """The substrings of a script name that would name this CVE.

    Empty for anything that is not a CVE id. A partial match -- searching for
    `2017` because the id was malformed -- would return every script
    published that year, which is not a mapping, it is noise wearing one.
    """
    match = _CVE_RE.match(str(cve_id or "").strip())
    if match is None:
        return ()
    year, number = match.group(1), match.group(2)
    return (f"cve{year}-{number}", f"cve-{year}-{number}")


def script_matches(name, prefixes: Sequence[str] = (),
                   fragments: Sequence[str] = ()) -> bool:
    """Is this script relevant to the service or CVE those came from?

    The decision, in Python, on this side of the seam. SQL narrows to rows
    that could match; this says whether one does, and it is the function to
    read when a suggestion looks wrong.

    A prefix matches only at a name boundary: `http` matches `http-title` and
    `http` itself, and does not match `httpd-fingerprint`, because "the name
    begins with these letters" is a substring test and "the name is for this
    protocol" is what was meant.
    """
    text = str(name or "").strip().lower()
    if not text:
        return False
    for fragment in fragments:
        token = str(fragment or "").lower()
        if token and token in text:
            return True
    for prefix in prefixes:
        token = str(prefix or "").lower()
        if not token:
            continue
        if text == token or text.startswith(f"{token}-"):
            return True
    return False


# --------------------------------------------------------------------------- #
# The store
# --------------------------------------------------------------------------- #

class ScriptDB:
    """script name -> declared categories, and the reverse. Narrows only."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path) if path == ":memory:" else str(
            Path(path).expanduser())
        self._conn = self._connect()

    # -- lifecycle ----------------------------------------------------------- #

    def _connect(self) -> sqlite3.Connection:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # `check_same_thread=False` because the corpus is opened once, by
        # whichever thread constructs `AppState`, and read from whichever
        # thread the ASGI server runs the route on -- under `TestClient`
        # those are two different threads, and under a server that dispatches
        # a sync route to the threadpool they are too. Without this the first
        # hand-off after wiring raised `SQLite objects created in a thread can
        # only be used in that same thread`, which is a corpus configured,
        # loaded, and then unusable: the exact silence this wiring removed,
        # relocated one layer down.
        #
        # Safe because of what is done with the handle, not by assertion.
        # Every resolver method is a read; SQLite is compiled serialized, so
        # each `execute` is atomic and takes its own cursor. The write paths
        # (`ingest`, `builddb`, `fetch`) are single-threaded batch jobs and
        # own the connection for their run.
        conn = sqlite3.connect(
            self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        # Bug 1: off by default, per-connection, and not stored in the file.
        # The write path deletes children explicitly regardless.
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA)

        row = conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            conn.execute("INSERT INTO meta(key, value) VALUES(?, ?)",
                         ("schema_version", str(SCHEMA_VERSION)))
            conn.commit()
        elif int(row["value"]) != SCHEMA_VERSION:
            found = int(row["value"])
            conn.close()
            raise SchemaMismatch(
                f"{self.path} was written with script schema v{found}; this "
                f"build speaks v{SCHEMA_VERSION}. Rebuild it rather than "
                "guessing at the difference.")
        return conn

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ScriptDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- ingestion ----------------------------------------------------------- #

    def ingest(self, entries: Iterable[ScriptEntry], batch: int = 2000) -> int:
        written = 0
        pending: list[ScriptEntry] = []
        for entry in entries:
            pending.append(entry)
            if len(pending) >= batch:
                written += self._write_batch(pending)
                pending.clear()
        if pending:
            written += self._write_batch(pending)
        log.info("ingested %d NSE script entries", written)
        return written

    def _write_batch(self, entries: Sequence[ScriptEntry]) -> int:
        script_rows: list[tuple] = []
        link_rows: list[tuple] = []
        keys: list[tuple] = []
        seen: set[str] = set()

        for entry in entries:
            name = safe_script_name(getattr(entry, "name", "")
                                    or getattr(entry, "filename", ""))
            if name is None:
                log.warning("dropping script entry with unusable name %r",
                            getattr(entry, "filename", ""))
                continue
            filename = f"{name}.nse"
            if filename in seen:
                # Last one wins, matching the delete-then-insert semantics
                # across batches. One duplicate must not abort an
                # `executemany` and cost two thousand good rows with it.
                script_rows = [r for r in script_rows if r[0] != filename]
                link_rows = [r for r in link_rows if r[0] != filename]
            seen.add(filename)
            keys.append((filename,))
            script_rows.append((filename, name))

            # RC-35/RC-38 at the storage boundary too. A caller handing a
            # bare string in would otherwise store one row per character.
            declared = normalise_categories(
                getattr(entry, "categories", ()) or ())
            written_categories: set[str] = set()
            for raw in declared:
                cleaned = clean_category(raw)
                value = (cleaned if cleaned is not None
                         else Category.UNCLASSIFIED.value)
                if value not in written_categories:
                    written_categories.add(value)
                    link_rows.append((filename, value))
            if not written_categories:
                link_rows.append((filename, Category.UNCLASSIFIED.value))

        if not script_rows:
            return 0

        with self._conn:
            # Bug 5: replace, never append. Children first and explicitly.
            self._conn.executemany(
                "DELETE FROM script_category WHERE filename = ?", keys)
            self._conn.executemany(
                "DELETE FROM script WHERE filename = ?", keys)
            self._conn.executemany(
                "INSERT INTO script(filename, name) VALUES(?, ?)", script_rows)
            self._conn.executemany(
                "INSERT INTO script_category(filename, category) "
                "VALUES(?, ?)", link_rows)
        return len(script_rows)

    def ingest_file(self, path: str | Path, batch: int = 2000
                    ) -> tuple[int, ParseStats]:
        """Ingest an nmap `script.db` straight from disk, streaming."""
        stats = ParseStats()
        written = self.ingest(read_script_db(path, stats), batch=batch)
        return written, stats

    # -- retrieval ----------------------------------------------------------- #

    def categories_for(self, script: str) -> list[str]:
        """The categories `script.db` declares for one script. Sorted.

        Takes `http-shellshock` or `http-shellshock.nse`; an operator and a
        `--script` argument spell it the first way and the file spells it the
        second. Returns `[]` for a script the corpus does not hold, which the
        caller must read as "not classified" rather than "no categories" --
        `NullScriptResolver.describe()` exists because those two are
        indistinguishable at this return type.
        """
        name = safe_script_name(script)
        if name is None:
            return []
        return [row["category"] for row in self._conn.execute(
            "SELECT c.category FROM script s JOIN script_category c "
            "ON c.filename = s.filename WHERE s.name = ? "
            "ORDER BY c.category", (name,))]

    def category_of(self, script: str) -> Category:
        """The single category policy judges this script by."""
        declared = self.categories_for(script)
        return _worst_category(declared) if declared else Category.UNCLASSIFIED

    def get(self, script: str) -> Optional[ScriptEntry]:
        name = safe_script_name(script)
        if name is None:
            return None
        row = self._conn.execute(
            "SELECT filename, name FROM script WHERE name = ?",
            (name,)).fetchone()
        if row is None:
            return None
        return ScriptEntry(filename=row["filename"], name=row["name"],
                           categories=tuple(self.categories_for(name)))

    def scripts_in_category(self, category: str,
                            limit: int = 500) -> list[str]:
        """The reverse lookup: every script filed under one category.

        Uses `script_category_category`. This is the question an operator
        asks when deciding what a `--script exploit` run would actually do,
        and this corpus makes it answerable without a Lua interpreter.
        """
        key = clean_category(category)
        if key is None:
            return []
        rows = self._conn.execute(
            "SELECT s.name FROM script_category c JOIN script s "
            "ON s.filename = c.filename WHERE c.category = ? "
            "ORDER BY s.name LIMIT ?", (key, limit + 1)).fetchall()
        if len(rows) > limit:
            log.warning("category %s holds more than %d scripts; the list is "
                        "truncated", key, limit)
            rows = rows[:limit]
        return [row["name"] for row in rows]

    def scripts_for(self, service: str = "", cve_id: str = "",
                    limit: int = 25) -> list[ScriptEntry]:
        """Scripts plausibly relevant to a service or a CVE.

        Two rules and no third: name prefix, and CVE id in the name. SQL
        narrows with a prefix range and a substring search; `script_matches`
        decides, so the rule an operator can read is the rule that ran.

        Ordered before it is limited (bug 4). A CVE-named script is the
        stronger signal -- it names the exact flaw rather than the protocol
        -- so truncation loses the protocol-family scripts first rather than
        an arbitrary subset, and says so in the log.
        """
        prefixes = service_prefixes(service)
        fragments = cve_fragments(cve_id)
        if not prefixes and not fragments:
            return []

        clauses: list[str] = []
        args: list = []
        for prefix in prefixes:
            clauses.append("name = ? OR name LIKE ? ESCAPE '\\'")
            args += [prefix, f"{_like_escape(prefix)}-%"]
        for fragment in fragments:
            clauses.append("name LIKE ? ESCAPE '\\'")
            args.append(f"%{_like_escape(fragment)}%")

        rows = self._conn.execute(
            "SELECT filename, name FROM script WHERE "
            + " OR ".join(f"({c})" for c in clauses)
            + " ORDER BY name", args).fetchall()

        matched = [row for row in rows
                   if script_matches(row["name"], prefixes, fragments)]
        # Bug 3's shape: a per-row cost on a query that returns many rows.
        # One `categories_for` call per match is a second round trip per
        # script, and `http` alone matches over a hundred of them. One
        # grouped read instead.
        tags = self._categories_for_many([row["filename"] for row in matched])
        found = [ScriptEntry(filename=row["filename"], name=row["name"],
                             categories=tuple(tags.get(row["filename"], ())))
                 for row in matched]

        # Named for the flaw first, then for the protocol; alphabetical
        # within each group, so the order is total and a test can assert it.
        found.sort(key=lambda e: (0 if script_matches(e.name, (), fragments)
                                  else 1, e.name))
        if len(found) > limit:
            log.warning(
                "%d NSE scripts match service %r / %s; showing %d. Raise "
                "`limit` or query the index directly.",
                len(found), service, cve_id or "no CVE", limit)
            found = found[:limit]
        return found

    def _categories_for_many(self, filenames: Sequence[str]) -> dict:
        """Categories for a set of scripts in one read, chunked.

        Chunked because SQLite's parameter limit is 999 by default and a
        query that works on a stock nmap install and fails on a directory
        with a thousand third-party scripts is the worst kind of limit: it
        appears only where the corpus is largest.
        """
        out: dict = {}
        names = list(filenames)
        chunk = 400
        for start in range(0, len(names), chunk):
            window = names[start:start + chunk]
            placeholders = ", ".join("?" for _ in window)
            for row in self._conn.execute(
                    "SELECT filename, category FROM script_category "
                    f"WHERE filename IN ({placeholders}) "
                    "ORDER BY filename, category", window):
                out.setdefault(row["filename"], []).append(row["category"])
        return out

    # -- introspection -------------------------------------------------------- #

    def stats(self) -> ScriptDbStats:
        one = self._conn.execute("SELECT COUNT(*) n FROM script").fetchone()
        links = self._conn.execute(
            "SELECT COUNT(*) n, COUNT(DISTINCT category) d "
            "FROM script_category").fetchone()
        return ScriptDbStats(scripts=one["n"], category_links=links["n"],
                             distinct_categories=links["d"])

    def category_counts(self) -> dict:
        return {row["category"]: row["n"] for row in self._conn.execute(
            "SELECT category, COUNT(*) n FROM script_category "
            "GROUP BY category ORDER BY category")}

    # -- provenance ----------------------------------------------------------- #

    def record_feed(self, name: str, url: str = "", sha256: str = "",
                    bytes_: int = 0, record_count: int = 0,
                    fetched_at: Optional[str] = None) -> FeedSource:
        key = (name or "").strip().lower()
        if not key:
            raise ValueError("a feed source needs a name")
        stamp = (fetched_at or datetime.now(timezone.utc).isoformat())
        with self._conn:
            self._conn.execute(
                "INSERT INTO feed_source(name, url, sha256, bytes, "
                "record_count, fetched_at) VALUES(?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET url=excluded.url, "
                "sha256=excluded.sha256, bytes=excluded.bytes, "
                "record_count=excluded.record_count, "
                "fetched_at=excluded.fetched_at",
                (key, url or "", sha256 or "", int(bytes_ or 0),
                 int(record_count or 0), stamp))
        return FeedSource(name=key, url=url or "", sha256=sha256 or "",
                          bytes=int(bytes_ or 0),
                          record_count=int(record_count or 0),
                          fetched_at=stamp)

    def feeds(self) -> list[FeedSource]:
        return [FeedSource(name=row["name"], url=row["url"],
                           sha256=row["sha256"], bytes=row["bytes"],
                           record_count=row["record_count"],
                           fetched_at=row["fetched_at"])
                for row in self._conn.execute(
                    "SELECT name, url, sha256, bytes, record_count, "
                    "fetched_at FROM feed_source ORDER BY fetched_at ASC, "
                    "name ASC")]

    def feed(self, name: str) -> Optional[FeedSource]:
        key = (name or "").strip().lower()
        for source in self.feeds():
            if source.name == key:
                return source
        return None

    def set_meta(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)))

    def get_meta(self, key: str) -> Optional[str]:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?",
                                 (key,)).fetchone()
        return row["value"] if row else None


def _like_escape(text: str) -> str:
    """Neutralise `%` and `_` in a LIKE pattern built from input.

    Not injection -- the value is still bound -- but a service string of `%`
    would otherwise match every script in the corpus and present the whole
    NSE catalogue as relevant to one lead.
    """
    return (str(text).replace("\\", "\\\\").replace("%", "\\%")
            .replace("_", "\\_"))


# --------------------------------------------------------------------------- #
# File -> entries, streaming
# --------------------------------------------------------------------------- #

def read_script_db(path: str | Path,
                   stats: Optional[ParseStats] = None
                   ) -> Iterator[ScriptEntry]:
    """Stream an nmap `script.db` as entries, one line resident at a time.

    Tolerant per line, strict per file, exactly as `read_exploit_csv` is. A
    malformed line is counted and dropped -- files acquire comments and nmap
    adds records this parser has not met -- but a file that yields no entry
    at all is not a slightly different `script.db`. It is a different file,
    and ingesting it silently would leave the operator with an index that
    reports every script as unclassified while `describe()` says a corpus is
    loaded.
    """
    stats = stats if stats is not None else ParseStats()
    file = Path(path).expanduser()
    if not file.is_file():
        raise FileNotFoundError(f"nmap script.db not found: {file}")

    with file.open("r", encoding="utf-8", errors="replace") as handle:
        matched = False
        # RC-40. `for raw in handle` materialises the whole line and only
        # then compares it with the bound, which is the bound describing the
        # allocation rather than preventing it. `bounded_lines` never holds
        # more than the bound plus one read buffer, so a `script.db` that is
        # a single 500MB line costs 72KiB and one skipped line.
        for raw, truncated in bounded_lines(handle, MAX_LINE_BYTES):
            stats.lines += 1
            entry = None if truncated else parse_entry(raw)
            if entry is None:
                if truncated:
                    stats.skipped += 1
                    if len(stats.errors) < 20:
                        stats.errors.append(
                            f"line {stats.lines}: over {MAX_LINE_BYTES} "
                            "bytes")
                elif raw.strip():
                    stats.skipped += 1
                    if len(stats.errors) < 20:
                        stats.errors.append(
                            f"line {stats.lines}: not an Entry record")
                # The sniff bound covers an over-long line as well: a file of
                # nothing but 500MB lines is exactly the shape that should be
                # abandoned early, and reaching the bound through a `continue`
                # placed above this check would have read all of it.
                if not matched and stats.lines >= SNIFF_LINES:
                    # Refused early rather than after reading a gigabyte of
                    # something else. A real script.db matches on line one.
                    raise NotAScriptDb(
                        f"{file} does not look like an nmap script.db: no "
                        f"`Entry {{ filename = ... }}` record in its first "
                        f"{SNIFF_LINES} lines. Point RECONKG_SCRIPT_DB at "
                        "the script.db in your nmap scripts directory.")
                continue
            matched = True
            stats.parsed += 1
            yield entry

    if not stats.parsed:
        raise NotAScriptDb(
            f"{file} contains no NSE script entries ({stats.lines} lines "
            f"read, {stats.skipped} unparseable). An empty script index "
            "reads as 'every script is unclassified', so this is refused "
            "rather than loaded.")
