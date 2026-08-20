"""Where candidate CVEs come from.

The engine used to hold `self.reference`, a list of `VulnEntry`, and hand the
whole list to `build_leads` for every fingerprint. That signature cannot
express "ask the index for the entries matching *this* fingerprint", so the
SQLite corpus built in `vulndb.py` had nothing to plug into: it existed, and
no code path queried it.

A resolver is the seam. It answers one question -- given a fingerprint, which
entries are worth examining -- and `build_leads` is unchanged, still a pure
function over an iterable. Two implementations:

    StaticResolver   the nine built-in entries. Offline, zero setup, and the
                     reason the demo and 664 existing tests still run.
    DbResolver       the indexed corpus. Returns the dozens of entries that
                     share a CPE identity instead of all 250,000.

`from_env()` picks between them on `RECONKG_VULN_DB`. Set means the corpus is
the source of truth; unset means the built-ins. Not a union -- a lead should
have one provenance, and merging a curated table with a feed means a merge
rule to get subtly wrong.

Deciding stays in `cpe.py`. A resolver narrows and nothing more; every entry
it returns is still put through `entry.matches(fp)`. This matters for
`DbResolver` in particular: SQL selects on product identity, which is a
coarser question than applicability.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Protocol, Sequence, runtime_checkable

from .models import Fingerprint
from .vulnref import DEFAULT_REFERENCE, VulnEntry

log = logging.getLogger(__name__)

ENV_VAR = "RECONKG_VULN_DB"
EXPLOIT_ENV_VAR = "RECONKG_EXPLOIT_DB"
SCRIPT_ENV_VAR = "RECONKG_SCRIPT_DB"


@runtime_checkable
class Resolver(Protocol):
    """Narrows the corpus to candidates for one fingerprint."""

    def candidates(self, fp: Fingerprint) -> Sequence[VulnEntry]:
        ...

    def entry_for(self, cve_id: str) -> Optional[VulnEntry]:
        """The single entry behind a lead, by CVE id.

        RC-41. `build_handoff` looks the entry up to source two things an
        analyst reads: the caveats (from `entry.notes`) and any
        operator-supplied follow-up commands (`entry.handoff`). It was handed
        `DEFAULT_REFERENCE` by every caller, so the lookup succeeded for the
        nine built-in CVEs and missed for every one of the 250,000 that come
        from a real corpus -- silently dropping the corpus's own note about
        the vulnerability on exactly the leads that matter.

        A second lookup path that consults a different source from the one
        that produced the lead is this codebase's most-repeated bug. Putting
        it on the resolver means there is one source, and it is the one the
        lead came from.
        """
        ...

    def describe(self) -> str:
        """One line for the ledger header and the UI corpus panel.

        Present because "no leads" is ambiguous -- it can mean the host is
        clean or it can mean the corpus is nine hand-written entries. The
        analyst needs to be able to tell those apart without reading code.
        """
        ...


class StaticResolver:
    """Every entry, every time. The original behaviour, made explicit."""

    def __init__(self, entries: Iterable[VulnEntry] = DEFAULT_REFERENCE) -> None:
        self._entries = list(entries)

    def candidates(self, fp: Fingerprint) -> Sequence[VulnEntry]:
        return self._entries

    def entry_for(self, cve_id: str) -> Optional[VulnEntry]:
        key = str(cve_id or "").strip().upper()
        return next((e for e in self._entries
                     if e.cve_id.upper() == key), None)

    def describe(self) -> str:
        count = len(self._entries)
        if self._entries and list(self._entries) == list(DEFAULT_REFERENCE):
            return (f"built-in reference ({count} entries) -- a demonstration "
                    f"fixture, not a vulnerability database. Set {ENV_VAR} to "
                    "use a real corpus.")
        return f"in-memory reference ({count} entries)"

    def __len__(self) -> int:
        return len(self._entries)


class DbResolver:
    """The indexed corpus. Looks up by CPE, falls back to product name."""

    def __init__(self, db, limit: int = 500) -> None:
        self._db = db
        self._limit = limit

    def candidates(self, fp: Fingerprint) -> Sequence[VulnEntry]:
        from .cpe import parse as parse_cpe

        observed = parse_cpe(fp.cpe) if fp.cpe else None
        if observed is None and fp.cpe:
            # Worth saying out loud. A malformed CPE silently demotes the
            # lookup to substring matching, which is the weakest path we
            # have, and the analyst would otherwise see only that the result
            # was poor.
            log.warning("unparseable CPE %r on %s; falling back to product "
                        "name", fp.cpe, fp.key)
        return self._db.candidates(observed, fp.product, limit=self._limit)

    def entry_for(self, cve_id: str) -> Optional[VulnEntry]:
        """Indexed by primary key, so this is a seek rather than a scan."""
        try:
            return self._db.get(cve_id)
        except Exception as exc:                # pragma: no cover - defensive
            log.warning("entry lookup failed for %s: %s", cve_id, exc)
            return None

    def describe(self) -> str:
        stats = self._db.stats()
        built = self._db.get_meta("built_at")
        when = _age(built)
        feeds = _feed_ages(self._db)
        # RC-43. An empty corpus reported `stale: false, demonstration_
        # fixture: false` -- i.e. healthy -- on a real Kali install where the
        # NVD pull had silently not landed while KEV, EPSS and ExploitDB all
        # had. Every scan would then have said "no leads" with total
        # confidence, which is the single failure this whole describe()
        # mechanism exists to prevent, missed at the most obvious value.
        #
        # Zero is not a small number here, it is a broken build. Say so
        # first, in the words the UI and selfcheck already scan for.
        if stats.cves == 0:
            return (f"EMPTY corpus at {self._db.path}: 0 CVEs. The build "
                    "produced nothing, so every lookup will report 'no "
                    "leads' regardless of the host. Re-run `python -m "
                    "reconkg.fetch --nvd` (an NVD pull without an API key "
                    "is throttled and often interrupted), then `python -m "
                    f"reconkg.builddb`.{feeds}")
        return (f"corpus at {self._db.path}: {stats.cves:,} CVEs, "
                f"{stats.statements:,} applicability statements{when}{feeds}")

    def close(self) -> None:
        self._db.close()


# Per-feed staleness thresholds, in days. The corpus is not one artefact and
# a single build date averages it into a number that can be reassuring and
# wrong at the same time: EPSS is regenerated every day, so an EPSS file from
# March is three months of scoring input missing while the database is
# truthfully "built yesterday".
FEED_STALE_AFTER = {
    "epss": 7,          # regenerated daily; a week old is already suspect
    "kev": 14,          # changes weekly
    "nvd": 30,          # continuous, but a month's publication gap is real
    "exploitdb": 30,
    # script.db changes when nmap does, which is a release or two a year.
    # Holding it to the 30-day default would mark a correct, current index
    # stale on every run and teach the operator to ignore the word.
    "script.db": 365,
}
DEFAULT_FEED_STALE_AFTER = 30

# Why each feed matters, so the warning says what is actually lost rather
# than only that a number is large.
FEED_ROLE = {
    "epss": "exploit-probability scores",
    "kev": "known-exploited flags",
    "nvd": "CVE records",
    "exploitdb": "exploit index",
    "script.db": "NSE script categories",
}


def _feed_ages(db) -> str:
    """Per-feed provenance, with the stale and the absent ones named.

    Named, not counted. "1 feed is stale" makes the analyst open a database
    to find out which, and the answer changes what they should distrust: a
    stale KEV under-reports active exploitation, a stale EPSS mis-ranks
    everything.

    Age is the second question. The first is whether the feed landed at all,
    because a feed that contributed nothing is not merely old -- it is
    absent, and its date is the least trustworthy thing about it.
    """
    try:
        feeds = list(db.feeds())
    except Exception:                      # pragma: no cover - defensive
        return ""
    if not feeds:
        return (" (no per-feed provenance recorded -- rebuild with a current "
                "builddb to record it)")

    fresh: list[str] = []
    stale: list[str] = []
    absent: list[str] = []
    unknown: list[str] = []
    for feed in feeds:
        # Emptiness is checked before age and independently of it. A feed
        # holding no records did not land, and dating it then reports the
        # opposite of the truth: `builddb.record_provenance` dates an NVD
        # directory containing no page files from the directory itself, so a
        # pull that failed on its first request is stamped with the moment
        # `fetch_nvd` created the directory it never wrote into -- and sorts
        # as the *freshest* feed present. RC-43 said this for the corpus
        # total and left the per-feed line beside it still claiming health.
        if feed.record_count == 0:
            role = FEED_ROLE.get(feed.name, "data")
            absent.append(f"{feed.name} contributed 0 records ({role} are "
                          f"missing entirely, not merely out of date)")
            continue
        age = feed.age_days
        if age is None:
            unknown.append(feed.name)
            continue
        limit = FEED_STALE_AFTER.get(feed.name, DEFAULT_FEED_STALE_AFTER)
        days = int(age)
        if age > limit:
            role = FEED_ROLE.get(feed.name, "data")
            stale.append(f"{feed.name} {days}d old, over its {limit}d "
                         f"refresh window ({role} are out of date)")
        else:
            fresh.append(f"{feed.name} {days}d")

    parts = []
    if fresh:
        parts.append("feeds: " + ", ".join(fresh))
    if unknown:
        parts.append("fetch date unreadable for " + ", ".join(unknown))
    text = "; ".join(parts)
    if absent:
        # Carries the STALE token deliberately rather than inventing a second
        # one. A feed holding nothing is strictly worse than a feed holding
        # old data, and STALE is the word the UI badge and the ledger header
        # key off; a new token would leave the badge green for the worse of
        # the two conditions -- which is how this was missed the first time.
        text = (f"{text}; " if text else "") + "STALE -- EMPTY feeds: " + \
               "; ".join(absent) + \
               ". These did not land. Re-run `python -m reconkg.fetch " \
               "--all`, check that it exits 0, then rebuild."
    if stale:
        # STALE is the token the UI and the ledger header key off, and it has
        # to appear whenever *any* part of the corpus is stale -- otherwise
        # "corpus is fresh" stays true while a feed rots.
        text = (f"{text}; " if text else "") + "STALE feeds -- " + \
               "; ".join(stale) + \
               ". Refresh with `python -m reconkg.fetch --all`."
    return f". {text}" if text else ""


def _age(built_at: Optional[str]) -> str:
    """Staleness, stated rather than implied.

    A corpus that has not been refreshed in months under-reports silently:
    every CVE published since the last build is simply absent, and the tool
    reports that absence with exactly the same confidence it reports a real
    negative.
    """
    if not built_at:
        return " (build date unknown)"
    try:
        import time
        days = int((time.time() - float(built_at)) / 86400)
    except (TypeError, ValueError):
        return " (build date unreadable)"
    if days < 0:
        return " (build date is in the future -- check the clock)"
    if days <= 1:
        return ", built today"
    if days <= 30:
        return f", built {days} days ago"
    return (f", built {days} days ago -- STALE. Every CVE published since is "
            f"missing and will read as 'no leads'. Refresh with "
            f"`python -m reconkg.fetch --all`.")


def from_env(env: Optional[dict] = None) -> Resolver:
    """Pick a resolver from the environment.

    Failure here is loud and does not fall back. If the operator set
    `RECONKG_VULN_DB` and it cannot be opened, quietly serving nine
    hand-written entries instead would be the worst possible outcome: the
    scan runs, reports almost nothing, and looks like it worked.
    """
    env = env if env is not None else os.environ
    path = (env.get(ENV_VAR) or "").strip()
    if not path:
        return StaticResolver()

    from .vulndb import VulnDB

    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise FileNotFoundError(
            f"{ENV_VAR} points at {resolved}, which does not exist. Build it "
            "with `python -m reconkg.fetch --all` then "
            "`python -m reconkg.builddb`, or unset the variable to use the "
            "built-in reference.")

    db = VulnDB(resolved)
    resolver = DbResolver(db)
    log.info("%s", resolver.describe())
    return resolver


# --------------------------------------------------------------------------- #
# The second corpus: CVE -> published exploit index
# --------------------------------------------------------------------------- #

@runtime_checkable
class ExploitResolver(Protocol):
    """Answers "what has been published for this CVE", and nothing else.

    A separate protocol from `Resolver` rather than a method bolted onto it.
    The two corpora answer different questions, refresh on different clocks
    and are configured by different environment variables, and a combined
    interface would force every caller with one of them to stub the other.
    """

    def exploits_for(self, cve_id: str) -> Sequence:
        ...

    def describe(self) -> str:
        ...


class NullExploitResolver:
    """No exploit corpus configured. Says so, rather than implying none exist.

    Returning an empty list is the correct answer to "what does the corpus
    hold"; it is the wrong answer to "does public tooling exist for this
    CVE", and `describe()` is what keeps those two apart in the ledger
    header. Silence here reads as "nothing published", which is the most
    expensive wrong answer this corpus can give.
    """

    def exploits_for(self, cve_id: str) -> Sequence:
        return ()

    def describe(self) -> str:
        return (f"no exploit index configured -- 'no known exploit' below "
                f"means 'not checked'. Build one with `python -m "
                f"reconkg.fetch --exploitdb` then `python -m reconkg.builddb`"
                f" and set {EXPLOIT_ENV_VAR}.")


class StaticExploitResolver:
    """A fixed list of records, for tests and for an in-memory catalogue."""

    def __init__(self, records: Iterable = ()) -> None:
        self._records = list(records)

    def exploits_for(self, cve_id: str) -> Sequence:
        from .catalog import normalise_cve

        key = normalise_cve(cve_id) or str(cve_id or "").strip().upper()
        return [r for r in self._records
                if key in {str(c).upper() for c in getattr(r, "cves", ())}]

    def describe(self) -> str:
        return f"in-memory exploit index ({len(self._records)} entries)"


class DbExploitResolver:
    """The indexed ExploitDB corpus, looked up by CVE."""

    def __init__(self, db, limit: int = 200,
                 platform: Optional[str] = None) -> None:
        self._db = db
        self._limit = limit
        self._platform = platform

    def exploits_for(self, cve_id: str) -> Sequence:
        from .exploitdb import rank

        found = self._db.exploits_for_cve(cve_id, limit=self._limit)
        # Ranking is deliberately on this side of the seam. SQL ordered the
        # rows so that a truncation loses the weakest ones; deciding which
        # entries an analyst should look at *first*, given the platform of
        # the host in front of them, is judgement, and CORPUS-PATTERN.md is
        # explicit that judgement does not go into the store.
        return rank(found, self._platform)

    def describe(self) -> str:
        stats = self._db.stats()
        feeds = _feed_ages(self._db)
        return (f"exploit index at {self._db.path}: {stats.exploits:,} "
                f"entries, {stats.distinct_cves:,} CVEs cross-referenced"
                f"{feeds}")

    def close(self) -> None:
        self._db.close()


def exploits_from_env(env: Optional[dict] = None) -> ExploitResolver:
    """Pick an exploit resolver from the environment.

    Same contract as `from_env`, and it matters for the same reason: if the
    operator set `RECONKG_EXPLOIT_DB` and it cannot be opened, falling back
    to "nothing published for any CVE" would be a silent, confident, wrong
    answer on every lead in the run. Unset is a different thing entirely --
    the operator never claimed to have an index -- and gets the null resolver
    that says so out loud.
    """
    env = env if env is not None else os.environ
    path = (env.get(EXPLOIT_ENV_VAR) or "").strip()
    if not path:
        return NullExploitResolver()

    from .exploitdb import ExploitDB

    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise FileNotFoundError(
            f"{EXPLOIT_ENV_VAR} points at {resolved}, which does not exist. "
            "Build it with `python -m reconkg.fetch --exploitdb` then "
            "`python -m reconkg.builddb`, or unset the variable to run "
            "without an exploit index.")

    resolver = DbExploitResolver(ExploitDB(resolved))
    log.info("%s", resolver.describe())
    return resolver


# --------------------------------------------------------------------------- #
# The third corpus: NSE script -> declared categories
# --------------------------------------------------------------------------- #

@runtime_checkable
class ScriptResolver(Protocol):
    """Answers "what does this NSE script do to the target", and nothing else.

    A third protocol for the same reason there is a second: the question is
    different (safety, not existence), the source refreshes on a different
    clock (an nmap upgrade, not a daily feed), and it is configured by its own
    environment variable.
    """

    def categories_for(self, script: str) -> Sequence[str]:
        ...

    def scripts_for(self, service: str = "", cve_id: str = "") -> Sequence:
        ...

    def describe(self) -> str:
        ...


class NullScriptResolver:
    """No `script.db` configured. Says categories are *unknown*.

    The wording matters more here than anywhere else in this module. An empty
    category list is the correct answer to "what does the corpus hold" and
    the worst possible answer to "is this script safe", because downstream
    the absence of a category resolves to `unclassified` -- which is
    conservative and correct, and reads to an operator as though something
    classified it. `describe()` is where the difference is stated out loud,
    and it says *unclassified*, never *safe*.
    """

    def categories_for(self, script: str) -> Sequence[str]:
        return ()

    def scripts_for(self, service: str = "", cve_id: str = "") -> Sequence:
        return ()

    def describe(self) -> str:
        return (f"no nmap script.db configured -- NSE script categories are "
                f"unknown, so every script is treated as unclassified "
                f"(opt-in, never assumed safe). Point {SCRIPT_ENV_VAR} at the "
                f"script.db in your nmap scripts directory, typically "
                f"/usr/share/nmap/scripts/script.db.")


class StaticScriptResolver:
    """A fixed set of `ScriptEntry`, for tests and for a hand-built map."""

    def __init__(self, entries: Iterable = ()) -> None:
        self._entries = list(entries)

    def categories_for(self, script: str) -> Sequence[str]:
        from .commands import normalise_categories
        from .scriptdb import safe_script_name

        key = safe_script_name(script)
        if key is None:
            return ()
        for entry in self._entries:
            if safe_script_name(getattr(entry, "name", "")) == key:
                # RC-38. The entries are whatever the caller handed in, so a
                # bare string is possible here even though `ScriptEntry` now
                # normalises its own; `tuple("exploit")` is seven characters.
                return normalise_categories(
                    getattr(entry, "categories", ()) or ())
        return ()

    def scripts_for(self, service: str = "", cve_id: str = "") -> Sequence:
        from .scriptdb import cve_fragments, script_matches, service_prefixes

        prefixes = service_prefixes(service)
        fragments = cve_fragments(cve_id)
        if not prefixes and not fragments:
            return ()
        return [e for e in self._entries
                if script_matches(getattr(e, "name", ""), prefixes, fragments)]

    def describe(self) -> str:
        return f"in-memory NSE script index ({len(self._entries)} scripts)"


class DbScriptResolver:
    """The indexed `script.db`, looked up by script name or by service/CVE."""

    def __init__(self, db, limit: int = 25) -> None:
        self._db = db
        self._limit = limit

    def categories_for(self, script: str) -> Sequence[str]:
        return tuple(self._db.categories_for(script))

    def scripts_for(self, service: str = "", cve_id: str = "") -> Sequence:
        return self._db.scripts_for(service, cve_id, limit=self._limit)

    def describe(self) -> str:
        stats = self._db.stats()
        counts = self._db.category_counts()
        # The exploit-category count is the number an operator most needs:
        # it is how many scripts on this machine are ones reconkg will name
        # and refuse to compose.
        never = sum(counts.get(name, 0)
                    for name in ("exploit", "dos", "fuzzer", "brute"))
        feeds = _feed_ages(self._db)
        # The path an operator recognises. A parsed script.db lives in
        # `:memory:`, and reporting that tells them nothing about which file
        # on their disk the categories came from.
        where = self._db.get_meta("source_path") or self._db.path
        return (f"nmap script index at {where}: {stats.scripts:,} "
                f"scripts across {stats.distinct_categories} categories, "
                f"{never:,} in never-composed categories{feeds}")

    def close(self) -> None:
        self._db.close()


#: The SQLite file magic. `RECONKG_SCRIPT_DB` accepts either nmap's own
#: `script.db` -- which is what an operator has on disk and the path they will
#: reach for -- or a prebuilt index. Sniffing the header is how the two are
#: told apart, because both are conventionally named `script.db` and
#: extensions lie.
_SQLITE_MAGIC = b"SQLite format 3\x00"


def scripts_from_env(env: Optional[dict] = None) -> ScriptResolver:
    """Pick a script resolver from the environment.

    Same contract as the other two, and loud for the same reason: if the
    operator set the variable and the file cannot be read, falling back to
    "categories unknown" would mean every NSE suggestion silently becomes
    opt-in and the operator's own index is never consulted. Unset is a
    different claim entirely and gets the null resolver, which says so.
    """
    env = env if env is not None else os.environ
    path = (env.get(SCRIPT_ENV_VAR) or "").strip()
    if not path:
        return NullScriptResolver()

    from .scriptdb import ScriptDB

    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise FileNotFoundError(
            f"{SCRIPT_ENV_VAR} points at {resolved}, which does not exist. "
            "It should be the script.db in your nmap scripts directory "
            "(usually /usr/share/nmap/scripts/script.db; `nmap "
            "--script-updatedb` regenerates it), or unset the variable to "
            "run without NSE categories.")

    if _looks_like_sqlite(resolved):
        db = ScriptDB(resolved)
    else:
        # nmap's own file. Parsed into an in-memory index rather than written
        # beside it: the scripts directory is usually root-owned, and a tool
        # that quietly drops a database into /usr/share is a tool nobody
        # should run as root.
        db = ScriptDB(":memory:")
        written, stats = db.ingest_file(resolved)
        db.set_meta("source_path", str(resolved))
        _record_script_provenance(db, resolved, written)
        log.info("parsed %s: %d scripts from %d lines (%d lines skipped)",
                 resolved, written, stats.lines, stats.skipped)

    resolver = DbScriptResolver(db)
    log.info("%s", resolver.describe())
    return resolver


def _record_script_provenance(db, path: Path, written: int) -> None:
    """Where these categories came from, and how old the file is.

    There is no fetch step for this corpus -- the file arrives with nmap --
    so the manifest `fetch.py` writes for the other two has nothing to say
    about it. The digest and the file's own mtime are recorded here instead,
    which is the same fallback `builddb.py` uses when a feeds directory has
    no manifest: provenance must not be a property of one code path.

    Best effort. An unreadable stat or an OSError mid-hash costs the
    provenance row, never the index.
    """
    import hashlib

    try:
        # RC-40. `path.read_bytes()` is the second unbounded read of the same
        # hostile file, two functions along from the one `read_script_db`
        # bounds: the parser streams, and then the provenance step slurps the
        # whole thing to digest it. Chunked, so the memory cost of recording
        # where the categories came from does not depend on the size of the
        # file they came from.
        digest = hashlib.sha256()
        size = 0
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
                size += len(block)
        stamp = datetime.fromtimestamp(path.stat().st_mtime,
                                       tz=timezone.utc).isoformat()
        db.record_feed("script.db", url=str(path),
                       sha256=digest.hexdigest(),
                       bytes_=size, record_count=written,
                       fetched_at=stamp)
    except OSError as exc:                  # pragma: no cover - defensive
        log.warning("no provenance recorded for %s: %s", path, exc)


def _looks_like_sqlite(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(len(_SQLITE_MAGIC)) == _SQLITE_MAGIC
    except OSError:
        return False


def coerce(source) -> Resolver:
    """Accept a resolver, a sequence of entries, or None.

    The engine's `reference=` parameter took a sequence in every existing
    test and caller. Rather than rewrite those call sites, they keep working
    and get wrapped here.
    """
    if source is None:
        return from_env()
    if hasattr(source, "candidates") and hasattr(source, "describe"):
        return source
    return StaticResolver(source)
