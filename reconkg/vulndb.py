"""SQLite-backed vulnerability database, indexed by CPE identity.

The problem this exists to solve. `DEFAULT_REFERENCE` is a tuple of nine
entries and `build_leads` scans all of them for every fingerprint. That is
fine for nine. NVD carries well over 250,000 CVEs, and the naive extension of
the current design -- load them all into a list and scan it per fingerprint --
fails twice over:

    memory   every applicability statement for every CVE, resident, forever
    time     250k linear comparisons per fingerprint, per scan

Both are fixed by the same thing: an index on `(part, vendor, product)`, which
is exactly the CPE identity triple. A fingerprint resolves to one triple, so a
lookup touches the handful of CVEs for that product instead of the whole
corpus. SQLite gives that for free, on disk, with no server.

The store keeps the *matching* semantics in `cpe.py` where they already live
and are already mutation-tested. This module is storage and retrieval only:
it narrows 250,000 candidates down to the dozens that share a product
identity, and hands those to the matcher that decides. Putting version
comparison into SQL would have meant reimplementing `compare_versions` in a
dialect that cannot express it.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from functools import lru_cache
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence

from .cpe import CPE, CPERange, parse as parse_cpe
from .models import ExploitMaturity
from .vulnref import VulnEntry

log = logging.getLogger(__name__)

SCHEMA_VERSION = 4

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve (
    cve_id   TEXT PRIMARY KEY,
    title    TEXT NOT NULL DEFAULT '',
    cvss     REAL NOT NULL DEFAULT 0.0,
    notes    TEXT NOT NULL DEFAULT '',
    product_match TEXT NOT NULL DEFAULT '',
    -- Operator-supplied follow-up commands, JSON. Empty for anything ingested
    -- from NVD, which has no such concept -- but without the column the field
    -- vanished on a round trip through the corpus, so a hand-curated entry
    -- lost the one suggestion in the whole system that a human had verified.
    -- A store that silently drops a field it was handed is the same class of
    -- bug as a lookup that consults the wrong source (RC-41); persisting an
    -- often-empty column is the cheaper side of that trade.
    handoff  TEXT NOT NULL DEFAULT '[]',
    source   TEXT NOT NULL DEFAULT 'nvd',
    updated  TEXT NOT NULL
);

-- One row per applicability statement. The index below is the whole point:
-- it turns "which CVEs could apply to apache:http_server" from a scan of the
-- corpus into a b-tree seek.
-- Bounds live in columns, not a JSON blob. The blob cost a `json.loads` per
-- candidate row, and a hot product returns hundreds of rows per lookup --
-- measurable, and the reason median lookup latency tracked corpus size on
-- the first benchmark despite the index being used correctly.
CREATE TABLE IF NOT EXISTS applicability (
    cve_id   TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    part     TEXT NOT NULL,
    vendor   TEXT NOT NULL,
    product  TEXT NOT NULL,
    criteria TEXT NOT NULL,      -- the full CPE 2.3 string
    vsi TEXT, vse TEXT, vei TEXT, vee TEXT,
    vulnerable INTEGER NOT NULL DEFAULT 1,
    -- Leading numeric component of each bound, NULL where unbounded. Version
    -- comparison is not lexicographic, so SQL cannot decide a match -- but
    -- the major number is monotone, so SQL can *narrow* soundly: a range
    -- spanning majors 2..3 cannot contain a 7.x version. This exists because
    -- `apache:http_server` returns 56,411 candidate rows on a full corpus,
    -- and an unordered `LIMIT 500` over that silently discards the row that
    -- actually applies. Narrowing first makes the limit reachable instead of
    -- routinely hit.
    major_lo INTEGER, major_hi INTEGER
);
CREATE INDEX IF NOT EXISTS applicability_identity
    ON applicability(part, vendor, product, major_lo, major_hi);
CREATE INDEX IF NOT EXISTS applicability_cve ON applicability(cve_id);
-- Tier two of `candidates()` and the gate on tier three both look up by
-- product with the vendor relaxed, and `applicability_identity` cannot serve
-- that: vendor sits between part and product in its key, so a product-only
-- predicate degrades to a scan of 2.8 million rows. It would run on the miss
-- path -- exactly where nobody notices a slow query until a scan takes a
-- minute and the cause is three layers down.
CREATE INDEX IF NOT EXISTS applicability_product
    ON applicability(product, part, major_lo, major_hi);

-- Product-name fallback for fingerprints with no usable CPE. Separate table
-- because it is a different access pattern -- substring, not equality -- and
-- mixing them would mean scanning the applicability index for a LIKE.
CREATE TABLE IF NOT EXISTS product_alias (
    cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    alias  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS product_alias_name ON product_alias(alias);
-- Without this, the delete-before-insert in `_write_batch` scans the whole
-- alias table once per CVE, which is quadratic in corpus size: the ingest
-- rate fell from 65,000/s to 700/s between a 2,000- and a 100,000-CVE build.
CREATE INDEX IF NOT EXISTS product_alias_cve ON product_alias(cve_id);

-- Where each part of the corpus came from, and when. The corpus is not one
-- artefact: NVD is continuous, EPSS regenerates daily, KEV changes weekly,
-- and a single `built_at` averages those into a number that can be true and
-- useless at the same time -- "built yesterday" while the EPSS half of the
-- scoring input is three months old.
--
-- `name` is the primary key rather than an autoincrement id precisely
-- because a refresh must *replace* the row for a feed, not append a second
-- one. An append-only provenance table answers "when was EPSS fetched" with
-- a list, and every caller then has to re-derive "the latest" correctly.
CREATE TABLE IF NOT EXISTS feed_source (
    name         TEXT PRIMARY KEY,
    url          TEXT NOT NULL DEFAULT '',
    sha256       TEXT NOT NULL DEFAULT '',
    bytes        INTEGER NOT NULL DEFAULT 0,
    record_count INTEGER NOT NULL DEFAULT 0,
    fetched_at   TEXT NOT NULL
);
-- Staleness reporting orders and filters on the fetch time, and the delete
-- path below filters on `name`, which the primary key already covers.
CREATE INDEX IF NOT EXISTS feed_source_fetched ON feed_source(fetched_at);
"""


#: How much of a line an ingest will hold in memory before deciding it is
#: not a record. The corpus files reconkg reads are downloaded or rebuilt
#: from a directory a third party can write, and neither format has any
#: reason to carry a line this long.
READ_CHUNK_BYTES = 64 * 1024


def bounded_lines(handle, limit: int, chunk: int = READ_CHUNK_BYTES):
    """Yield `(line, truncated)` without ever holding more than the bound.

    RC-40. Both corpus parsers stated a per-line bound and then checked it
    against a line `for raw in handle` had already materialised, which is the
    bound reporting on the allocation rather than preventing it -- a
    `script.db` that is one 500MB line costs 500MB before the check runs, and
    `nmap --script-updatedb` will build exactly that from a scripts directory
    if something in it says so.

    `truncated` is True for a line that exceeded `limit`; its text is
    discarded rather than returned in part, because a partial record is not a
    record and the caller's only correct response is to count it and move on.
    Resident memory is bounded by `limit + chunk` regardless of file shape.
    """
    buffer = ""
    over = False
    while True:
        data = handle.read(chunk)
        if not data:
            break
        buffer += data
        while True:
            cut = buffer.find("\n")
            if cut == -1:
                break
            line, buffer = buffer[:cut + 1], buffer[cut + 1:]
            if over:
                yield "", True
                over = False
            else:
                yield line, False
        if len(buffer) > limit:
            buffer = ""
            over = True
    if over:
        yield "", True
    elif buffer:
        yield buffer, False



class SchemaMismatch(RuntimeError):
    """The database was written by a different schema version."""


@dataclass
class DbStats:
    cves: int = 0
    statements: int = 0
    aliases: int = 0
    sources: dict = None

    def as_dict(self) -> dict:
        return {"cves": self.cves, "statements": self.statements,
                "aliases": self.aliases, "sources": self.sources or {}}


@dataclass(frozen=True)
class FeedSource:
    """Provenance for one feed: where it came from, and how old it is."""

    name: str
    url: str = ""
    sha256: str = ""
    bytes: int = 0
    record_count: int = 0
    fetched_at: str = ""

    @property
    def age_days(self) -> Optional[float]:
        """Days since this feed was fetched, or None if unreadable.

        None rather than 0.0 on a bad timestamp: a caller deciding whether to
        warn must be able to tell "fresh" from "cannot tell", because the
        second one is the case where a silent 0 would suppress the warning.
        """
        when = _parse_time(self.fetched_at)
        if when is None:
            return None
        return (datetime.now(timezone.utc) - when).total_seconds() / 86400.0

    def as_dict(self) -> dict:
        return {"name": self.name, "url": self.url, "sha256": self.sha256,
                "bytes": self.bytes, "record_count": self.record_count,
                "fetched_at": self.fetched_at, "age_days": self.age_days}


class VulnDB:
    """Indexed corpus. Narrows candidates; `cpe.py` still decides matches."""

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
        # Off by default in SQLite, and per-connection rather than stored in
        # the file. Without it the ON DELETE CASCADE declarations below are
        # documentation, not behaviour -- which is exactly how re-ingesting a
        # feed came to triple the applicability table while the CVE table,
        # protected by its primary key, looked correct.
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
                f"{self.path} was written with schema v{found}; this build "
                f"speaks v{SCHEMA_VERSION}. Rebuild it rather than guessing "
                "at the difference.")
        return conn

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "VulnDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- ingestion ----------------------------------------------------------- #

    def ingest(self, entries: Iterable[VulnEntry], source: str = "nvd",
               batch: int = 2000) -> int:
        """Bulk-load entries. Returns the number written.

        Batched inside one transaction per chunk: a single transaction over
        250k CVEs holds a write lock for minutes and loses everything on an
        interrupt, while a transaction per row is roughly a hundred times
        slower than either.
        """
        now = datetime.now(timezone.utc).isoformat()
        written = 0
        pending: list[VulnEntry] = []

        for entry in entries:
            pending.append(entry)
            if len(pending) >= batch:
                written += self._write_batch(pending, source, now)
                pending.clear()
        if pending:
            written += self._write_batch(pending, source, now)

        log.info("ingested %d entries from %s", written, source)
        return written

    def _write_batch(self, entries: Sequence[VulnEntry], source: str,
                     now: str) -> int:
        cve_rows = []
        statement_rows = []
        alias_rows = []
        seen: set[str] = set()

        for entry in entries:
            # PROP-02. Two rows for one CVE inside a single batch abort the
            # whole `executemany` on the primary key, which loses up to two
            # thousand good rows for one duplicate -- and an NVD delta that
            # carries a CVE twice, or two feeds merged before ingest, is not
            # an exotic input. Last one wins, which is the same semantics the
            # delete-then-insert gives across batches, and the same guard
            # `exploitdb` and `scriptdb` already state in their write paths.
            # A control implemented in two of the three corpora is a control
            # with a hole in it.
            if entry.cve_id in seen:
                cve_rows = [r for r in cve_rows if r[0] != entry.cve_id]
                statement_rows = [r for r in statement_rows
                                  if r[0] != entry.cve_id]
                alias_rows = [r for r in alias_rows if r[0] != entry.cve_id]
            seen.add(entry.cve_id)
            cve_rows.append((entry.cve_id, entry.title, entry.cvss,
                             entry.notes, entry.product_match,
                             json.dumps(list(entry.handoff or ())),
                             source, now))
            for statement in entry.cpe_ranges:
                cpe = statement.cpe
                statement_rows.append((
                    entry.cve_id, cpe.part, cpe.vendor, cpe.product,
                    str(cpe),
                    statement.version_start_including,
                    statement.version_start_excluding,
                    statement.version_end_including,
                    statement.version_end_excluding,
                    int(bool(statement.vulnerable)),
                    _major(statement.version_start_including
                           or statement.version_start_excluding),
                    _major(statement.version_end_including
                           or statement.version_end_excluding),
                ))
            if entry.product_match:
                alias_rows.append((entry.cve_id,
                                   entry.product_match.strip().lower()))

        keys = [(cve_id,) for cve_id in seen]
        with self._conn:
            # Replace rather than ignore: re-ingesting a refreshed feed must
            # update a CVE whose CVSS or applicability has changed, and its
            # old statements must go with it.
            #
            # The child deletes are explicit rather than left to the cascade.
            # The pragma that makes the cascade real is per-connection, so a
            # future caller opening this file by any other route would
            # silently reintroduce the duplication bug. Correctness here
            # should not depend on a connection setting made elsewhere.
            self._conn.executemany(
                "DELETE FROM applicability WHERE cve_id = ?", keys)
            self._conn.executemany(
                "DELETE FROM product_alias WHERE cve_id = ?", keys)
            self._conn.executemany("DELETE FROM cve WHERE cve_id = ?", keys)
            self._conn.executemany(
                "INSERT INTO cve(cve_id, title, cvss, notes, product_match, "
                "handoff, source, updated) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?)", cve_rows)
            self._conn.executemany(
                "INSERT INTO applicability(cve_id, part, vendor, product, "
                "criteria, vsi, vse, vei, vee, vulnerable, major_lo, "
                "major_hi) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                statement_rows)
            self._conn.executemany(
                "INSERT INTO product_alias(cve_id, alias) VALUES(?, ?)",
                alias_rows)
        return len(cve_rows)

    # -- retrieval ----------------------------------------------------------- #

    def candidates_for_cpe(self, observed: CPE, limit: int = 500, *,
                           match_vendor: bool = True) -> list[VulnEntry]:
        """CVEs whose applicability shares this CPE identity.

        Includes statements whose vendor or product is ANY, because those are
        real in NVD and a strict equality lookup would silently drop them.
        Matching is still `cpe.py`'s decision -- this only narrows.

        `match_vendor=False` drops the vendor predicate and narrows on
        product and version alone. That is tier two of `candidates()`: nmap
        and NVD disagree about vendors often enough to matter -- `oracle`
        versus `mysql`, `f5` versus `nginx` -- and relaxing the vendor is
        cheap because **the version bounds are untouched**. It cannot produce
        the failure the substring path can, where a host on 4.0 collects a
        lead for something fixed in 3.0.

        Parameterised rather than duplicated into a second method: two
        near-identical queries is how the ordering fix from RC-42 ends up
        applied to one of them and not the other.
        """
        vendor = observed.vendor if match_vendor else None
        major = _major(observed.version)
        rows = self._conn.execute(
            """
            SELECT c.cve_id, c.title, c.cvss, c.notes, c.product_match,
                   c.handoff,
                   a.criteria, a.vsi, a.vse, a.vei, a.vee, a.vulnerable
              FROM applicability a JOIN cve c ON c.cve_id = a.cve_id
             WHERE a.part = ?
               AND (? IS NULL OR a.vendor = ? OR a.vendor = '*')
               AND (a.product = ? OR a.product = '*')
               AND (? IS NULL OR a.major_lo IS NULL OR a.major_lo <= ?)
               AND (? IS NULL OR a.major_hi IS NULL OR a.major_hi >= ?)
             -- Ordered before it is limited, and this is not cosmetic.
             -- Without it SQLite returns rows in rowid order, so a truncated
             -- result is an arbitrary prefix of the insertion order. Measured
             -- on a 30,000-CVE corpus: apache:http_server narrowed to 3,806
             -- rows of which 1,918 could match version 2.4.49, the LIMIT kept
             -- the first 501, and NOT ONE of them was a major-2 row. The
             -- applicable CVE was silently absent and the scan reported no
             -- lead. The truncation warning fired correctly and told the
             -- operator nothing they could act on.
             --
             -- Rows whose lower bound sits on the observed major are the ones
             -- that can contain it, so they go first; an unbounded row could
             -- match anything and goes next; everything else is a wider
             -- window that survives narrowing but rarely applies.
             ORDER BY CASE
                        WHEN ? IS NULL THEN 0
                        WHEN a.major_lo = ? THEN 0
                        WHEN a.major_lo IS NULL THEN 1
                        ELSE 2
                      END,
                      a.cve_id DESC
             LIMIT ?
            """,
            (observed.part, vendor, vendor, observed.product,
             major, major, major, major, major, major, limit + 1),
        ).fetchall()

        if len({r["cve_id"] for r in rows}) > limit:
            # Loud, because the alternative is quietly handing the matcher an
            # arbitrary subset and reporting "no leads" with total confidence.
            log.warning(
                "%s:%s: more than %d candidates after narrowing; results are "
                "truncated and may omit an applicable CVE. Raise `limit` or "
                "supply a version.", observed.vendor, observed.product, limit)
        return _rows_to_entries(rows)

    def candidates_for_product(self, product: Optional[str],
                               limit: int = 200) -> list[VulnEntry]:
        """Fallback for fingerprints with no CPE at all.

        Matches on the alias table with the *fingerprint* as the haystack,
        which is the same direction `_product_match` uses: an entry aliased
        "http server" must be found for a banner reading "Apache httpd".

        Whole words, not fragments. A raw `instr(needle, alias)` matched any
        alias appearing anywhere inside the product string, and on a full
        corpus the alias table holds single characters: `i` on 167 CVEs, plus
        `ie`, `go`, `qt`, `mq`, `rt`, `jq`, `3d`, `zz`. `instr('nginx', 'i')`
        is true, so one of those CVEs surfaced as the top lead for nginx, for
        Microsoft IIS and for Jenkins simultaneously -- three unrelated
        products, one wrong answer, and it looked exactly like a hit.

        Padding both sides with spaces makes the alias match as a token. It
        also keeps the short ones honest rather than banning them: `go` is a
        real product with real CVEs, and it should match the word "go" and
        not the middle of "mongodb".
        """
        if not product or not product.strip():
            return []
        needle = product.strip().lower()
        rows = self._conn.execute(
            """
            SELECT c.cve_id, c.title, c.cvss, c.notes, c.product_match,
                   c.handoff,
                   NULL AS criteria, NULL AS vsi, NULL AS vse, NULL AS vei,
                   NULL AS vee, 1 AS vulnerable
              FROM product_alias p JOIN cve c ON c.cve_id = p.cve_id
             WHERE p.alias != ''
               AND instr(' ' || ? || ' ', ' ' || p.alias || ' ') > 0
             LIMIT ?
            """,
            (needle, limit),
        ).fetchall()
        return _rows_to_entries(rows)

    def knows_identity(self, observed: CPE) -> bool:
        """Has this corpus ever filed anything under this vendor:product?

        The question that makes an empty candidate set interpretable.

        Exact match, no wildcards on purpose: a single `vendor='*'` row
        anywhere in 2.8 million applicability statements would otherwise
        answer "yes" for every identifier ever invented, which is the reverse
        of what this is for.

        `part` leads the `applicability_identity` index, so including it
        makes this a prefix seek rather than a scan.
        """
        row = self._conn.execute(
            "SELECT 1 FROM applicability "
            " WHERE part = ? AND vendor = ? AND product = ? LIMIT 1",
            (observed.part, observed.vendor, observed.product)).fetchone()
        return row is not None

    def knows_product(self, product: str) -> bool:
        """Has this corpus filed anything under this product, any vendor?

        The gate on tier three. `knows_identity` asks about a vendor:product
        pair and is the wrong question here: `mysql:mysql` exists in NVD, so
        it answers "known" and suppresses the fallback -- while every MySQL
        CVE anyone cares about is filed under `oracle`. Asking about the
        product alone is what separates "we know this software and your
        version is fine" from "we have never heard of this software".
        """
        row = self._conn.execute(
            "SELECT 1 FROM applicability WHERE product = ? LIMIT 1",
            (product,)).fetchone()
        return row is not None

    def candidates(self, observed: Optional[CPE], product: Optional[str],
                   limit: int = 500) -> list[VulnEntry]:
        """The lookup the engine actually calls.

        An empty CPE result used to end the search, on the reasoning that it
        is an *answer*: the version fell outside every applicability range,
        and re-admitting the entry through the substring path -- which has no
        version bounds at all -- would hand a host running 4.0 a lead for a
        vulnerability fixed in 3.0. That reasoning is correct and is kept.

        What it missed is that emptiness has two causes and only one of them
        is an answer:

            known identity, nothing matched -> not affected. Stay silent.
            unknown identity                -> we looked up the wrong key.

        nmap's CPE dictionary and NVD's disagree about names often enough to
        matter: nmap emits `mysql:mysql` where NVD files MySQL under vendor
        `oracle`, `nginx:nginx` where NVD has `f5`, and `microsoft:iis` where
        NVD spells it `internet_information_services`. Measured against
        `selfcheck`'s eighteen realistic fingerprints on a full 381k corpus,
        four of the five misses were this and none were corpus gaps -- every
        one of those CVEs was present and unreachable.

        Silence for "not affected" and silence for "wrong identifier" read
        identically to an analyst. That is the ambiguity `describe()` exists
        to shout about, happening a layer down at row level.

        So there are three tiers, weakening in one direction only:

          1. vendor + product + version   the CPE as observed
          2. product + version            vendor relaxed, bounds INTACT
          3. product name, no version     last resort, and it can be wrong

        Tier two widens the candidate set and nothing more, and it is worth
        being exact about what that does NOT buy. This method only narrows;
        `cpe.py` still decides the match, and it compares part, vendor and
        product. So relaxing the vendor here hands the matcher rows it then
        rejects on vendor anyway -- it cannot, by itself, recover a
        vendor-naming disagreement. That correction belongs upstream, where
        `DbResolver.candidates` substitutes the curated identity from
        `_KNOWN_PRODUCTS` before the lookup runs. Tier two is retained
        because a narrowing layer returning a superset is harmless by
        construction, and it costs one indexed query on the miss path.

        Tier three is the one that can be wrong, so it runs only when the
        corpus has never heard of the product under any vendor at all -- at
        that point silence would be a claim we have no basis for. Leads from
        it carry the substring path's weaker `match_method`, so the ledger
        stays honest about how they were reached.

        The first cut of this went straight from tier one to tier three and
        scored 16/18 on `selfcheck` -- with CVE-2026-16860 topping nginx,
        IIS and Jenkins simultaneously off a one-character alias. A higher
        number made of wrong answers is worse than a lower one, because the
        cost of a bad lead is an operator's afternoon and their trust in
        every other row.
        """
        if observed is not None:
            found = self.candidates_for_cpe(observed, limit)
            if found:
                return found

            found = self.candidates_for_cpe(observed, limit,
                                            match_vendor=False)
            if found:
                log.info(
                    "%s:%s matched on product alone; this corpus files that "
                    "product under a different vendor. Version bounds still "
                    "applied.", observed.vendor, observed.product)
                return found

            if self.knows_product(observed.product):
                # Known product, no version match at either tier. That is an
                # answer, and the answer is "not affected".
                return []

            log.info(
                "%s is not a product this corpus knows under any vendor; "
                "falling back to the product-name path, which carries no "
                "version bounds.", observed.product)
        return self.candidates_for_product(product, limit)

    def get(self, cve_id: str) -> Optional[VulnEntry]:
        rows = self._conn.execute(
            """
            SELECT c.cve_id, c.title, c.cvss, c.notes, c.product_match,
                   c.handoff,
                   a.criteria, a.vsi, a.vse, a.vei, a.vee, a.vulnerable
              FROM cve c LEFT JOIN applicability a ON a.cve_id = c.cve_id
             WHERE c.cve_id = ?
            """, (str(cve_id or "").strip().upper(),)).fetchall()
        entries = _rows_to_entries(rows)
        return entries[0] if entries else None

    # -- introspection -------------------------------------------------------- #

    def stats(self) -> DbStats:
        cves = self._conn.execute("SELECT COUNT(*) n FROM cve").fetchone()["n"]
        statements = self._conn.execute(
            "SELECT COUNT(*) n FROM applicability").fetchone()["n"]
        aliases = self._conn.execute(
            "SELECT COUNT(*) n FROM product_alias").fetchone()["n"]
        sources = {row["source"]: row["n"] for row in self._conn.execute(
            "SELECT source, COUNT(*) n FROM cve GROUP BY source")}
        return DbStats(cves=cves, statements=statements, aliases=aliases,
                       sources=sources)

    def products(self, limit: int = 50) -> list[tuple[str, str, int]]:
        """Most-covered products. Useful for answering "is my feed loaded?"."""
        return [(row["vendor"], row["product"], row["n"])
                for row in self._conn.execute(
                    "SELECT vendor, product, COUNT(DISTINCT cve_id) n "
                    "FROM applicability GROUP BY vendor, product "
                    "ORDER BY n DESC LIMIT ?", (limit,))]

    # -- provenance ----------------------------------------------------------- #

    def record_feed(self, name: str, url: str = "", sha256: str = "",
                    bytes_: int = 0, record_count: int = 0,
                    fetched_at: Optional[str] = None) -> FeedSource:
        """Record where one feed came from. Upsert, never append.

        Bug 5 from CORPUS-PATTERN.md applies to provenance as much as to the
        corpus itself: a daily refresh that appends a row per feed per day
        turns "how old is EPSS" into a query with an ORDER BY that somebody
        will eventually write without one. One row per feed, replaced.
        """
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
        """Every recorded feed, oldest fetch first -- the stale one leads."""
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

    def forget_feed(self, name: str) -> int:
        """Drop one feed's provenance. `name` is the primary key, so this is
        an index seek rather than the table scan bug 2 warns about."""
        key = (name or "").strip().lower()
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM feed_source WHERE name = ?", (key,))
        return cursor.rowcount

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


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #

def _parse_time(value: Optional[str]) -> Optional[datetime]:
    """ISO-8601 (or a bare epoch) to an aware datetime, or None.

    Tolerant of the trailing `Z` that NVD and EPSS both emit, which
    `fromisoformat` rejects before 3.11, and of a naive timestamp, which is
    assumed UTC because everything reconkg writes is UTC.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.fromtimestamp(float(text), timezone.utc)
        except (TypeError, ValueError, OSError, OverflowError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _major(version: Optional[str]) -> Optional[int]:
    """Leading numeric component, or None if there isn't one.

    Returns None generously -- for ANY, NA, empty, and anything that does not
    start with digits. None means "do not narrow on this", which keeps the
    filter sound: it can only ever be too permissive, never too strict.
    """
    if not version or not isinstance(version, str):
        return None
    head = ""
    for char in version.lstrip():
        if char.isdigit():
            head += char
        else:
            break
    if not head:
        return None
    try:
        return int(head[:9])          # guard against a pathological banner
    except ValueError:
        return None


@lru_cache(maxsize=8192)
def _cached_cpe(criteria: str) -> Optional[CPE]:
    """Parse once per distinct CPE string, not once per candidate row.

    NVD reuses a small number of identity strings across an enormous number
    of CVEs -- `cpe:2.3:a:apache:http_server:*:...` appears on hundreds. The
    cache turns a per-row parse into a dict hit for all but the first.
    """
    return parse_cpe(criteria)


def _load_statement(row: sqlite3.Row) -> Optional[CPERange]:
    cpe = _cached_cpe(row["criteria"])
    if cpe is None:
        return None
    return CPERange(cpe=cpe,
                    version_start_including=row["vsi"],
                    version_start_excluding=row["vse"],
                    version_end_including=row["vei"],
                    version_end_excluding=row["vee"],
                    vulnerable=bool(row["vulnerable"]))


def _load_handoff(row) -> tuple[str, ...]:
    """Operator commands off a row, tolerating a column that is not there.

    The alias-fallback query selects no `handoff`, and a database written by
    schema v3 has no such column at all. Neither is worth an exception: the
    honest answer in both cases is "no operator commands recorded", which is
    also the truth.
    """
    try:
        blob = row["handoff"]
    except (IndexError, KeyError):
        return ()
    try:
        loaded = json.loads(blob) if blob else []
    except (json.JSONDecodeError, TypeError):
        return ()
    return tuple(str(x) for x in loaded if isinstance(x, str))


def _rows_to_entries(rows: Iterable[sqlite3.Row]) -> list[VulnEntry]:
    """Regroup the join back into one entry per CVE.

    A CVE with forty applicability statements arrives as forty rows. Rebuilding
    one entry per CVE keeps the matcher's contract unchanged -- it still sees
    a `VulnEntry` with a tuple of statements, exactly as it does from the
    in-memory reference.
    """
    grouped: dict[str, dict] = {}
    for row in rows:
        cve_id = row["cve_id"]
        entry = grouped.get(cve_id)
        if entry is None:
            entry = grouped[cve_id] = {
                "title": row["title"], "cvss": row["cvss"],
                "notes": row["notes"], "product_match": row["product_match"],
                "handoff": _load_handoff(row),
                "statements": [],
            }
        if row["criteria"]:
            statement = _load_statement(row)
            if statement is not None:
                entry["statements"].append(statement)

    return [
        VulnEntry(cve_id=cve_id, title=data["title"],
                  product_match=data["product_match"],
                  constraints=(), cvss=data["cvss"],
                  maturity=ExploitMaturity.NOT_DEFINED,
                  # An entry reached through the alias table has no version
                  # bounds at all, so without this it would attach to every
                  # fingerprint naming that product regardless of version.
                  # Entries with CPE statements carry their own bounds and
                  # must not be double-gated -- a statement that legitimately
                  # applies to all versions would otherwise be suppressed.
                  requires_version=not data["statements"],
                  cpe_ranges=tuple(data["statements"]),
                  handoff=data["handoff"],
                  notes=data["notes"])
        for cve_id, data in grouped.items()
    ]
