"""Turn downloaded feeds into an indexed database. Offline; no network.

    python -m reconkg.builddb --feeds ~/.reconkg/feeds --out ~/.reconkg/vuln.db

Reads whatever `fetch.py` left on disk, parses it with the existing loaders in
`feeds.py`, and writes the result into the SQLite store in `vulndb.py`. It is
a separate command from the fetch on purpose: rebuilding the index after
changing the parser should not mean re-downloading 300,000 CVEs.

It also records where each feed came from into `feed_source`, reading the
sha256 and fetch timestamp out of the manifest `fetch.py` leaves beside the
feeds -- and, where there is no manifest, deriving what it can from the files
themselves. A corpus is not one artefact and its parts age at different
rates; without a per-feed record there is no way to answer "is this complete,
and how old is each part of it".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from .exploitdb import ExploitDB
from .feeds import EpssScores, KevCatalog, load_nvd
from .vulndb import VulnDB
from .vulnref import VulnEntry

log = logging.getLogger("reconkg.builddb")


def _sha256(path: Path, limit: int = 512 * 1024 * 1024) -> str:
    """Digest a feed file. Empty string rather than an exception on failure.

    Bounded because this is the fallback path for a feeds directory with no
    manifest, and hashing a directory of NVD pages that totals a gigabyte to
    fill in a provenance column nobody asked for is not a trade worth making
    silently.
    """
    digest = hashlib.sha256()
    read = 0
    try:
        with open(path, "rb") as handle:
            while read < limit:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
                read += len(chunk)
    except OSError:
        return ""
    return digest.hexdigest() if read < limit else ""


def _mtime_iso(path: Path) -> str:
    try:
        return datetime.fromtimestamp(
            path.stat().st_mtime, timezone.utc).isoformat()
    except OSError:
        return datetime.now(timezone.utc).isoformat()


def _count_csv_rows(path: Path) -> int:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return max(sum(1 for _ in handle) - 1, 0)
    except OSError:
        return 0


def record_provenance(db, feeds: Path, name: str,
                      path: Optional[Path], records: int,
                      manifest: Optional[dict] = None) -> None:
    """Write one `feed_source` row, preferring what `fetch.py` recorded.

    The manifest is the good source: it holds the sha256 of the bytes that
    came off the wire and the moment they did. Falling back to the file on
    disk covers a corpus assembled by hand or copied between machines --
    without it, provenance would be present on the fetch path and absent on
    every other one, which is the bug shape this codebase keeps finding.
    """
    manifest = manifest if manifest is not None else {}
    entry = manifest.get(name) or {}
    if entry:
        db.record_feed(
            name=name,
            url=str(entry.get("url", "")),
            sha256=str(entry.get("sha256", "")),
            bytes_=int(entry.get("bytes", 0) or 0),
            # The manifest counts what was downloaded; for an incremental
            # NVD pull that is the delta, not the corpus. The count the
            # database should report is what it actually holds.
            record_count=(records if records is not None
                          else int(entry.get("records", 0) or 0)),
            fetched_at=str(entry.get("fetched_at", "")) or _mtime_iso(feeds),
        )
        return

    if path is None or not path.exists():
        return
    if path.is_dir():
        newest = max((p.stat().st_mtime for p in path.glob("nvd-*.json")),
                     default=None)
        stamp = (datetime.fromtimestamp(newest, timezone.utc).isoformat()
                 if newest else _mtime_iso(path))
        size = sum(p.stat().st_size for p in path.glob("nvd-*.json"))
        db.record_feed(name=name, url="", sha256="", bytes_=size,
                       record_count=records or 0, fetched_at=stamp)
        return
    db.record_feed(name=name, url="", sha256=_sha256(path),
                   bytes_=path.stat().st_size, record_count=records or 0,
                   fetched_at=_mtime_iso(path))


def iter_nvd_entries(feeds: Path) -> Iterator[VulnEntry]:
    """Stream entries from every NVD page file, one page resident at a time.

    Streaming rather than accumulating is the difference between a build that
    runs on a laptop and one that needs several gigabytes: the page files
    total well over a gigabyte of JSON, and `ingest` only ever needs a batch
    at a time.
    """
    directory = feeds / "nvd"
    if not directory.is_dir():
        log.warning("no nvd/ directory under %s -- skipping NVD", feeds)
        return

    pages = sorted(p for p in directory.glob("nvd-*.json"))
    if not pages:
        log.warning("no NVD page files in %s", directory)
        return

    for index, page in enumerate(pages, 1):
        try:
            entries = load_nvd(page)
        except (ValueError, OSError, FileNotFoundError) as exc:
            # One corrupt page should cost that page, not the build. A failed
            # download leaves a .part file, so a bad .json here is rare and
            # worth reporting loudly.
            log.error("page %s unreadable (%s) -- skipped", page.name, exc)
            continue
        log.debug("page %d/%d: %d entries", index, len(pages), len(entries))
        yield from entries


def build_exploits(feeds: Path, out: Path, manifest: Optional[dict] = None,
                   batch: int = 2000) -> dict:
    """Corpus two: `files_exploits.csv` into its own indexed store.

    A separate database file from the CVE corpus, not another table in it.
    The two are keyed differently, sized differently and refreshed on
    different clocks -- ExploitDB changes daily and is 46,000 rows, NVD is
    continuous and 250,000 -- and merging them would mean rebuilding both to
    refresh either. It also keeps the licence boundary crisp: the exploit
    index is GPL-2.0-or-later data the operator fetched, and it lives in a
    file they can delete on its own.
    """
    source = feeds / "files_exploits.csv"
    report: dict = {"path": str(out)}
    if not source.exists():
        log.info("no files_exploits.csv under %s -- skipping the exploit "
                 "index", feeds)
        return {}

    with ExploitDB(out) as db:
        written, stats = db.ingest_csv(source, batch=batch)
        db.set_meta("built_at", str(int(time.time())))
        db.set_meta("exploitdb_path", str(source))
        # Provenance goes into *this* database as well as the CVE one. A
        # corpus that cannot say how old it is has to be trusted on the say-so
        # of a file next to it, and these two are separable by design.
        record_provenance(db, feeds, "exploitdb", source, written,
                          manifest or {})
        report.update({
            "exploits": written,
            "rows": stats.rows,
            "skipped": stats.skipped,
            "with_cve": stats.with_cve,
            "stats": db.stats().as_dict(),
        })
    if stats.skipped:
        log.warning("%d of %d exploit index rows were unparseable and are "
                    "absent from the corpus", stats.skipped, stats.rows)
    return report


def build(feeds: Path, out: Path, batch: int = 2000,
          exploits_out: Optional[Path] = None) -> dict:
    started = time.monotonic()
    report: dict = {}

    # Imported here rather than at module scope: `fetch.py` is the only
    # module that touches the network, and the build path deliberately does
    # not depend on it being importable at all -- a feeds directory copied
    # from another machine still builds.
    from .fetch import read_manifest

    manifest = read_manifest(feeds)
    if not manifest:
        log.info("no fetch manifest in %s -- provenance will be derived from "
                 "the files on disk", feeds)

    with VulnDB(out) as db:
        counted = 0

        def counting() -> Iterator[VulnEntry]:
            nonlocal counted
            for entry in iter_nvd_entries(feeds):
                counted += 1
                if counted % 25_000 == 0:
                    log.info("  %d CVEs ingested...", counted)
                yield entry

        report["nvd"] = db.ingest(counting(), source="nvd", batch=batch)
        nvd_dir = feeds / "nvd"
        if nvd_dir.is_dir() or "nvd" in manifest:
            # The count recorded is what the database holds, not what the
            # last pull downloaded: after an incremental refresh those differ
            # by three orders of magnitude, and the useful answer to "is this
            # corpus complete" is the first one.
            record_provenance(db, feeds, "nvd", nvd_dir,
                              db.stats().cves, manifest)

        # KEV and EPSS stay as files rather than tables. They are small,
        # regenerated daily, and consumed whole by `ExploitationSignals`;
        # copying them into SQLite would mean rebuilding the database every
        # morning to pick up a scoring input that reloads in a second.
        kev_file = feeds / "known_exploited_vulnerabilities.json"
        if kev_file.exists():
            kev = KevCatalog()
            kev.load(kev_file)
            db.set_meta("kev_path", str(kev_file))
            report["kev"] = len(kev)
            record_provenance(db, feeds, "kev", kev_file, len(kev), manifest)

        epss_file = feeds / "epss_scores-current.csv"
        if epss_file.exists():
            epss = EpssScores()
            epss.load(epss_file)
            db.set_meta("epss_path", str(epss_file))
            report["epss"] = len(epss)
            record_provenance(db, feeds, "epss", epss_file, len(epss),
                              manifest)

        edb_file = feeds / "files_exploits.csv"
        if edb_file.exists():
            db.set_meta("exploitdb_path", str(edb_file))
            report["exploitdb"] = str(edb_file)
            record_provenance(db, feeds, "exploitdb", edb_file,
                              _count_csv_rows(edb_file), manifest)

        db.set_meta("built_at", str(int(time.time())))
        stats = db.stats()
        report["feeds"] = [f.as_dict() for f in db.feeds()]

    exploit_path = (exploits_out if exploits_out is not None
                    else Path(out).with_name("exploits.db"))
    exploit_report = build_exploits(feeds, exploit_path, manifest, batch)
    if exploit_report:
        report["exploit_index"] = exploit_report

    report["elapsed_s"] = round(time.monotonic() - started, 1)
    report["stats"] = stats.as_dict()
    return report


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m reconkg.builddb")
    parser.add_argument("--feeds", default="~/.reconkg/feeds")
    parser.add_argument("--out", default="~/.reconkg/vuln.db")
    parser.add_argument("--exploits-out", default="",
                        help="where to write the exploit index "
                             "(default: exploits.db beside --out)")
    parser.add_argument("--batch", type=int, default=2000)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(message)s")

    feeds = Path(args.feeds).expanduser()
    if not feeds.is_dir():
        print(f"no such feeds directory: {feeds}\n"
              "run `python -m reconkg.fetch --dest {feeds} --all` first",
              file=sys.stderr)
        return 2

    exploits_out = (Path(args.exploits_out).expanduser()
                    if args.exploits_out else None)
    report = build(feeds, Path(args.out).expanduser(), args.batch,
                   exploits_out)
    stats = report["stats"]

    print("\n--- build summary " + "-" * 42)
    print(f"  CVEs            {stats['cves']:>10,}")
    print(f"  applicability   {stats['statements']:>10,}")
    print(f"  product aliases {stats['aliases']:>10,}")
    if "kev" in report:
        print(f"  KEV entries     {report['kev']:>10,}")
    if "epss" in report:
        print(f"  EPSS scores     {report['epss']:>10,}")
    if "exploit_index" in report:
        index = report["exploit_index"]
        print(f"  exploit entries {index['exploits']:>10,}  "
              f"({index['stats']['distinct_cves']:,} CVEs cross-referenced, "
              f"{index['skipped']:,} rows skipped)")
    print(f"  elapsed         {report['elapsed_s']:>10.1f}s")

    if report.get("feeds"):
        print("\n  provenance (feed_source)")
        for feed in report["feeds"]:
            age = feed["age_days"]
            age_text = f"{age:.1f}d ago" if age is not None else "date unknown"
            print(f"    {feed['name']:<10} {feed['record_count']:>10,} "
                  f"records  {feed['sha256'][:12] or '-':<12} {age_text}")
    print(f"\n  written to {Path(args.out).expanduser()}")
    print(f"  point reconkg at it with RECONKG_VULN_DB="
          f"{Path(args.out).expanduser()}")
    if "exploit_index" in report:
        print(f"  and RECONKG_EXPLOIT_DB={report['exploit_index']['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
