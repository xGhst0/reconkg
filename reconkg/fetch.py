"""Corpus downloader. Operator-run, deliberately outside the engine.

reconkg's engine opens no outbound connections. That rule is worth keeping,
so the network code lives here instead of being threaded through the scanner:
a separate entry point, run deliberately, that writes files to disk. The
engine then parses those files offline exactly as it does today. Nothing in
`app.py`, `engine.py` or `store.py` imports this module, and a test asserts
that.

    python -m reconkg.fetch --dest ~/.reconkg/feeds --all
    python -m reconkg.fetch --dest ~/.reconkg/feeds --kev --epss
    python -m reconkg.fetch --dest ~/.reconkg/feeds --nvd --since
    python -m reconkg.build-db --feeds ~/.reconkg/feeds --out ~/.reconkg/vuln.db

Sources, all free and all published for this purpose:

    NVD 2.0 API     ~300k CVEs, paged at 2000. Rate limited to 5 requests per
                    30s without a key, 50 with one. Request a key at
                    https://nvd.nist.gov/developers/request-an-api-key -- the
                    full pull is roughly 25 minutes keyed, four hours not.
    CISA KEV        one JSON file, ~1400 entries, the active-exploitation set
    EPSS            one gzipped CSV, every CVE, regenerated daily
    ExploitDB       files_exploits.csv -- the index only. reconkg records
                    EDB-IDs and titles so an analyst can `searchsploit -x`
                    them. It does not download exploit code, and nothing in
                    the pipeline executes any.

On resumption: the NVD puller checkpoints its page cursor, so an interrupted
four-hour pull continues rather than restarting. This matters more than it
sounds -- an unresumable download at NVD's unkeyed rate limit is a download
that never finishes on a laptop that sleeps.

On refreshing: `--since` pulls only what NVD says changed, using
`lastModStartDate`/`lastModEndDate` and the last successful pull recorded in
the same checkpoint. The window is capped at 120 days, which is NVD's limit;
past that this falls back to a full pull rather than issuing a request the
API rejects. Delta pages are written under their own filenames so a refresh
adds to the corpus on disk instead of overwriting the middle of it.

On provenance: every download's sha256, byte count and record count is left
in `_fetch_manifest.json` beside the feeds, because `builddb.py` is a
separate process and those numbers otherwise die at exit -- which is how the
corpus came to be an opaque blob with no record of where it came from.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from datetime import timedelta
from typing import Callable, Iterable, Iterator, Optional

log = logging.getLogger("reconkg.fetch")

USER_AGENT = "reconkg/1.0 (vulnerability corpus builder)"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EDB_URL = ("https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
           "files_exploits.csv")

NVD_PAGE = 2000
NVD_DELAY_KEYED = 0.7      # 50 req / 30s, with headroom
NVD_DELAY_ANON = 6.5       # 5 req / 30s, with headroom

# NVD 2.0 documents a maximum of 120 days between `lastModStartDate` and
# `lastModEndDate`. Asking for more is a 404 with a message, not a truncated
# answer -- but a client that only discovers that from the server has already
# thrown away the alternative, so the check lives here and the fallback is a
# full pull.
NVD_MAX_WINDOW_DAYS = 120

# Where fetch results are left for `builddb.py`. The sha256, byte count and
# record count are computed during the download and, before this existed,
# died with the process -- so the database could say how many CVEs it held
# and nothing at all about where they came from.
MANIFEST_NAME = "_fetch_manifest.json"


class FetchError(RuntimeError):
    pass


@dataclass
class FetchResult:
    name: str
    path: Optional[Path] = None
    bytes_written: int = 0
    sha256: str = ""
    records: int = 0
    skipped: bool = False
    error: str = ""
    url: str = ""
    fetched_at: str = ""
    incremental: bool = False

    def describe(self) -> str:
        if self.error:
            return f"{self.name:<10} FAILED  {self.error}"
        if self.skipped:
            return f"{self.name:<10} skipped (already current)"
        mode = " (delta)" if self.incremental else ""
        return (f"{self.name:<10} {self.records:>7,} records  "
                f"{self.bytes_written / 1e6:>7.1f} MB  "
                f"{self.sha256[:12]}{mode}")

    def as_manifest_entry(self) -> dict:
        return {"name": self.name, "url": self.url, "sha256": self.sha256,
                "bytes": self.bytes_written, "records": self.records,
                "fetched_at": self.fetched_at or _now_iso(),
                "incremental": self.incremental,
                "path": str(self.path) if self.path else ""}


# --------------------------------------------------------------------------- #
# Provenance sidecar
# --------------------------------------------------------------------------- #

def manifest_path(dest: Path) -> Path:
    return Path(dest) / MANIFEST_NAME


def read_manifest(dest: Path) -> dict:
    """What previous fetch runs recorded. Missing or corrupt reads as empty.

    Corrupt is not fatal on purpose: provenance is a report about the corpus,
    and losing the report must not stop the corpus being rebuilt.
    """
    path = manifest_path(dest)
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        log.warning("fetch manifest at %s is unreadable; provenance for feeds "
                    "fetched before now is lost", path)
        return {}
    feeds = loaded.get("feeds") if isinstance(loaded, dict) else None
    return feeds if isinstance(feeds, dict) else {}


def write_manifest(dest: Path, results: Iterable[FetchResult]) -> Path:
    """Merge these results into the sidecar and return its path.

    Merge, not overwrite: `--kev` alone must not erase what the last `--all`
    recorded about NVD. A failed or skipped feed keeps its previous entry --
    replacing a good record with a failure would make the corpus look newer
    than it is, which is the one direction a staleness report must never err
    in.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    feeds = read_manifest(dest)
    for result in results:
        if result.error or result.skipped:
            continue
        feeds[result.name] = result.as_manifest_entry()
    payload = {"version": 1, "updated": _now_iso(), "feeds": feeds}
    path = manifest_path(dest)
    partial = path.with_suffix(path.suffix + ".part")
    partial.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    partial.replace(path)
    return path


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

def _open(url: str, headers: Optional[dict] = None, timeout: int = 120):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                   **(headers or {})})
    return urllib.request.urlopen(request, timeout=timeout)


def _get_json(url: str, headers: Optional[dict] = None, retries: int = 4,
              timeout: int = 120) -> dict:
    """GET with backoff. NVD returns 503 under load routinely, not rarely."""
    delay = 2.0
    last = ""
    for attempt in range(1, retries + 1):
        try:
            with _open(url, headers, timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            # 403/404 are terminal -- a bad API key or a moved endpoint does
            # not improve by asking again, and retrying a 403 sixteen times
            # looks like something reconkg should not look like.
            if exc.code in (400, 403, 404):
                raise FetchError(f"{url} -> HTTP {exc.code} {exc.reason}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = str(exc)
        if attempt < retries:
            log.warning("%s failed (%s), retrying in %.0fs", url, last, delay)
            time.sleep(delay)
            delay *= 2
    raise FetchError(f"{url} failed after {retries} attempts: {last}")


def _download(url: str, dest: Path, decompress: bool = False,
              timeout: int = 300) -> tuple[int, str]:
    """Stream to a temp file, then rename. Returns (bytes, sha256).

    Written to `.part` and renamed on completion so an interrupted download
    cannot leave a half-file that parses as a valid but truncated feed. A
    corpus that is silently missing its last 40,000 CVEs is worse than one
    that is obviously absent.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".part")
    digest = hashlib.sha256()
    total = 0

    with _open(url, timeout=timeout) as response, open(partial, "wb") as handle:
        stream = gzip.GzipFile(fileobj=response) if decompress else response
        while True:
            chunk = stream.read(1 << 16)
            if not chunk:
                break
            handle.write(chunk)
            digest.update(chunk)
            total += len(chunk)

    partial.replace(dest)
    return total, digest.hexdigest()


# --------------------------------------------------------------------------- #
# NVD
# --------------------------------------------------------------------------- #

def _read_checkpoint(checkpoint: Path) -> dict:
    if not checkpoint.exists():
        return {}
    try:
        saved = json.loads(checkpoint.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        log.warning("checkpoint unreadable, restarting the pull")
        return {}
    return saved if isinstance(saved, dict) else {}


def _parse_iso(value) -> Optional[datetime]:
    """ISO-8601 (tolerating a trailing Z) to an aware UTC datetime, or None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _nvd_stamp(when: datetime) -> str:
    """The extended ISO-8601 NVD 2.0 wants: milliseconds and an offset."""
    return when.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _digest_pages(pages: Path) -> tuple[int, str]:
    """(bytes, sha256) over every page file now on disk, in name order.

    Across all pages rather than the ones this run happened to write: after
    an incremental pull the corpus on disk is the full set plus a delta, and
    a digest of only the delta identifies nothing an operator can check.
    """
    digest = hashlib.sha256()
    total = 0
    for page in sorted(pages.glob("nvd-*.json")):
        try:
            blob = page.read_bytes()
        except OSError:
            continue
        digest.update(page.name.encode())
        digest.update(blob)
        total += len(blob)
    return total, digest.hexdigest()


def fetch_nvd(dest: Path, api_key: Optional[str] = None,
              resume: bool = True,
              progress: Optional[Callable[[int, int], None]] = None,
              since=None, now: Optional[datetime] = None) -> FetchResult:
    """Page the NVD 2.0 API into one JSON file per page, plus a checkpoint.

    `since` selects the incremental path:

        None        full pull, the original behaviour
        "auto"      the window starts at the last successful pull recorded in
                    the checkpoint; a full pull when there is no such record
        a timestamp an explicit `lastModStartDate`

    The window is capped at `NVD_MAX_WINDOW_DAYS`, which is NVD's documented
    limit. Over it, this falls back to a full pull rather than issuing a
    request the API rejects, or -- worse -- silently splitting the range and
    reporting a delta that is missing whatever fell between the halves.
    """
    result = FetchResult(name="nvd", url=NVD_API)
    pages = dest / "nvd"
    pages.mkdir(parents=True, exist_ok=True)
    checkpoint = pages / "_checkpoint.json"
    now = (now or datetime.now(timezone.utc))
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    headers = {"apiKey": api_key} if api_key else {}
    delay = NVD_DELAY_KEYED if api_key else NVD_DELAY_ANON
    if not api_key:
        log.warning("no NVD API key: throttled to 5 requests per 30s. The "
                    "full pull will take hours. Set NVD_API_KEY to cut it to "
                    "roughly 25 minutes.")

    saved = _read_checkpoint(checkpoint)
    # Survives every kind of restart: it is provenance about the corpus, not
    # a cursor into one pull, so `--no-resume` must not discard it.
    last_pull = saved.get("last_pull")

    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    if since is not None:
        anchor = (_parse_iso(last_pull) if since == "auto"
                  else _parse_iso(since))
        if anchor is None:
            log.info("no usable last-pull timestamp; pulling the full corpus "
                     "and recording one for next time")
        elif anchor > now:
            log.warning("last pull is in the future (%s) -- check the clock; "
                        "falling back to a full pull", anchor.isoformat())
        elif (now - anchor) > timedelta(days=NVD_MAX_WINDOW_DAYS):
            gap = (now - anchor).days
            log.warning(
                "last pull was %d days ago, over NVD's %d-day "
                "lastModStartDate window; falling back to a full pull",
                gap, NVD_MAX_WINDOW_DAYS)
        else:
            window_start, window_end = anchor, now

    mode = "delta" if window_start else "full"

    start = 0
    total = None
    if resume and saved:
        # The cursor is only meaningful within the pull that produced it. A
        # delta pull's index 2000 is not a full pull's index 2000, so
        # resuming across a mode change would skip the first 2000 records of
        # the new pull and report success. Same shape as the control-on-one-
        # path bug: the resume check existed, the mode was never part of it.
        saved_mode = saved.get("mode", "full")
        if saved_mode != mode:
            log.info("checkpoint is from a %s pull, this is a %s pull -- "
                     "starting from the top", saved_mode, mode)
        else:
            try:
                start = int(saved.get("next_index", 0))
                total = saved.get("total")
            except (ValueError, TypeError):
                log.warning("checkpoint unreadable, restarting the pull")
                start = 0
            if start and mode == "delta":
                # Reuse the interrupted run's window. Recomputing it would
                # shift the result set under a cursor that indexes into the
                # old one.
                resumed_start = _parse_iso(saved.get("window_start"))
                resumed_end = _parse_iso(saved.get("window_end"))
                if resumed_start and resumed_end:
                    window_start, window_end = resumed_start, resumed_end
                else:
                    start = 0
            if start:
                log.info("resuming NVD pull at index %d of %s", start, total)

    stamp = (_nvd_stamp(window_end).replace(":", "").replace("-", "")[:15]
             if window_end else "")

    def _checkpoint(payload: dict) -> None:
        base = {"mode": mode,
                "updated": datetime.now(timezone.utc).isoformat()}
        if last_pull:
            base["last_pull"] = last_pull
        if window_start and window_end:
            base["window_start"] = window_start.isoformat()
            base["window_end"] = window_end.isoformat()
        base.update(payload)
        checkpoint.write_text(json.dumps(base))

    fetched = 0
    try:
        while True:
            params = {"resultsPerPage": NVD_PAGE, "startIndex": start}
            if window_start and window_end:
                params["lastModStartDate"] = _nvd_stamp(window_start)
                params["lastModEndDate"] = _nvd_stamp(window_end)
            query = urllib.parse.urlencode(params)
            payload = _get_json(f"{NVD_API}?{query}", headers)

            total = payload.get("totalResults", total)
            batch = payload.get("vulnerabilities", [])
            if not batch:
                break

            # A delta page must not land on a full page's filename. Writing
            # `nvd-000000.json` with 300 changed records would delete 2,000
            # unchanged ones from the corpus on the next build -- a refresh
            # that shrinks the database.
            name = (f"nvd-delta-{stamp}-{start:06d}.json" if window_start
                    else f"nvd-{start:06d}.json")
            page_file = pages / name
            page_file.write_text(json.dumps(payload), encoding="utf-8")
            fetched += len(batch)
            start += len(batch)

            _checkpoint({"next_index": start, "total": total})
            if progress:
                progress(start, total or 0)

            if total is not None and start >= total:
                break
            time.sleep(delay)
    except FetchError as exc:
        # Partial corpus is still a corpus. Report what landed rather than
        # discarding an hour of paging because page 97 timed out.
        result.error = f"{exc} (kept {fetched:,} records; rerun to resume)"
        result.records = fetched
        result.incremental = bool(window_start)
        return result

    result.records = fetched
    result.path = pages
    result.incremental = bool(window_start)
    result.fetched_at = now.isoformat()
    result.bytes_written, result.sha256 = _digest_pages(pages)
    if total is None or start >= total:
        # `last_pull` is the *start* of this run, not its end: a record
        # modified while the pull was in flight must be caught by the next
        # window rather than falling into the gap between them.
        last_pull = (window_end or now).isoformat()
        checkpoint.write_text(json.dumps(
            {"next_index": 0, "total": total, "complete": True,
             "mode": mode, "last_pull": last_pull,
             "updated": datetime.now(timezone.utc).isoformat()}))
    return result


# --------------------------------------------------------------------------- #
# Single-file feeds
# --------------------------------------------------------------------------- #

def fetch_kev(dest: Path) -> FetchResult:
    result = FetchResult(name="kev", url=KEV_URL)
    target = dest / "known_exploited_vulnerabilities.json"
    try:
        result.bytes_written, result.sha256 = _download(KEV_URL, target)
        result.path = target
        result.fetched_at = _now_iso()
        payload = json.loads(target.read_text(encoding="utf-8"))
        result.records = len(payload.get("vulnerabilities", []))
    except (FetchError, urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        result.error = str(exc)
    return result


def fetch_epss(dest: Path) -> FetchResult:
    result = FetchResult(name="epss", url=EPSS_URL)
    target = dest / "epss_scores-current.csv"
    try:
        result.bytes_written, result.sha256 = _download(
            EPSS_URL, target, decompress=True)
        result.path = target
        result.fetched_at = _now_iso()
        with open(target, encoding="utf-8") as handle:
            result.records = sum(
                1 for line in handle
                if line.strip() and not line.startswith("#")) - 1
    except (FetchError, urllib.error.URLError, OSError) as exc:
        result.error = str(exc)
    return result


def fetch_exploitdb(dest: Path) -> FetchResult:
    """The ExploitDB *index* -- IDs, titles, paths. No exploit code."""
    result = FetchResult(name="exploitdb", url=EDB_URL)
    target = dest / "files_exploits.csv"
    try:
        result.bytes_written, result.sha256 = _download(EDB_URL, target)
        result.path = target
        result.fetched_at = _now_iso()
        with open(target, encoding="utf-8", errors="replace") as handle:
            result.records = max(sum(1 for _ in handle) - 1, 0)
    except (FetchError, urllib.error.URLError, OSError) as exc:
        result.error = str(exc)
    return result


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m reconkg.fetch",
        description="Download vulnerability feeds for offline parsing.")
    parser.add_argument("--dest", default="~/.reconkg/feeds",
                        help="directory to write feeds into")
    parser.add_argument("--all", action="store_true", help="every feed")
    parser.add_argument("--nvd", action="store_true")
    parser.add_argument("--kev", action="store_true")
    parser.add_argument("--epss", action="store_true")
    parser.add_argument("--exploitdb", action="store_true")
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                        help="NVD API key (or set NVD_API_KEY)")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument(
        "--since", nargs="?", const="auto", default=None, metavar="ISO8601",
        help="pull only CVEs modified since this timestamp; with no value, "
             "since the last successful pull. Falls back to a full pull when "
             f"the gap exceeds NVD's {NVD_MAX_WINDOW_DAYS}-day window.")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(message)s")

    dest = Path(args.dest).expanduser()
    dest.mkdir(parents=True, exist_ok=True)

    wanted = {"nvd": args.nvd, "kev": args.kev, "epss": args.epss,
              "exploitdb": args.exploitdb}
    if args.all or not any(wanted.values()):
        wanted = dict.fromkeys(wanted, True)

    def show(done: int, total: int) -> None:
        if total:
            sys.stderr.write(f"\r  nvd {done:>7,} / {total:,} "
                             f"({100 * done / total:5.1f}%)")
            sys.stderr.flush()

    results: list[FetchResult] = []
    if wanted["kev"]:
        results.append(fetch_kev(dest))
    if wanted["epss"]:
        results.append(fetch_epss(dest))
    if wanted["exploitdb"]:
        results.append(fetch_exploitdb(dest))
    if wanted["nvd"]:
        results.append(fetch_nvd(dest, args.api_key,
                                 resume=not args.no_resume, progress=show,
                                 since=args.since))
        sys.stderr.write("\n")

    # Before the summary: the provenance sidecar is what `builddb.py` reads
    # to populate `feed_source`, and losing it because the operator killed
    # the process while reading the summary would be a silly way to lose it.
    write_manifest(dest, results)

    print("\n--- fetch summary " + "-" * 42)
    for result in results:
        print("  " + result.describe())
    print(f"\n  written to {dest}")

    failed = [r for r in results if r.error]
    if failed:
        print(f"\n  {len(failed)} feed(s) failed. Rerun to resume; the NVD "
              "puller continues from its checkpoint.")
        return 1
    print("\n  next: python -m reconkg.builddb --feeds "
          f"{dest} --out {dest.parent / 'vuln.db'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
