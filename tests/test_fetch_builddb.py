"""Fetch and build, end to end, against a real HTTP server.

The public feeds are unreachable from CI, and mocking `urlopen` would test the
mock rather than the client -- it would not exercise chunked reads, gzip
framing, HTTP status handling, or the paging cursor. So these tests stand up
an actual server on localhost serving payloads shaped like the real ones, and
point the fetcher at it.

What that does and does not prove: it proves the client pages correctly,
resumes from a checkpoint, decompresses gzip, survives a 503, and refuses to
retry a 403. It does not prove the real endpoints still have these shapes --
only a live pull does that, which is why `--dest` output is reported with
counts the operator can sanity-check.
"""

from __future__ import annotations

import gzip
import json
import threading
import urllib.error
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from reconkg import fetch as fetchmod
from reconkg.builddb import build, iter_nvd_entries
from reconkg.cpe import parse as parse_cpe
from reconkg.resolver import DbResolver
from reconkg.vulndb import SchemaMismatch, VulnDB


# --------------------------------------------------------------------------- #
# A server that behaves like the real ones, including badly
# --------------------------------------------------------------------------- #

TOTAL_CVES = 4500          # spans three pages at the real 2000 page size
FLAKY_INDEX = 2000         # this page 503s once before succeeding

# The server's idea of now, so `lastModified` is deterministic. CVE n was
# last modified n days before this instant -- which makes "everything
# modified in the last five days" exactly six records, countable by hand.
SERVER_NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)
MAX_WINDOW_DAYS = 120      # NVD's documented cap, enforced by the server too


def _last_modified(number: int) -> datetime:
    return SERVER_NOW - timedelta(days=number)


def _parse_stamp(text: str):
    text = text.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _synthetic_cve(number: int) -> dict:
    """One NVD 2.0 record, in the shape the API actually returns."""
    vendor, product = [("apache", "http_server"), ("openbsd", "openssh"),
                       ("nginx", "nginx"), ("oracle", "mysql"),
                       ("apache", "tomcat")][number % 5]
    return {
        "cve": {
            "id": f"CVE-2024-{number:05d}",
            "lastModified": _last_modified(number).isoformat(
                timespec="milliseconds").replace("+00:00", ""),
            "descriptions": [
                {"lang": "en", "value": f"Synthetic issue {number} in {product}."}
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 5.0 + (number % 50) / 10.0},
                }]
            },
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": (f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:"
                                     "*:*:*:*"),
                        "versionStartIncluding": "1.0",
                        "versionEndExcluding": "9.9",
                    }],
                }]
            }],
        }
    }


class _Handler(BaseHTTPRequestHandler):
    flaked: set = set()
    queries: list = []           # every /nvd query string, in order

    def log_message(self, *args):        # keep pytest output readable
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):                                    # noqa: N802
        route = urlparse(self.path)
        query = parse_qs(route.query)

        if route.path == "/nvd":
            self.queries.append(route.query)
            start = int(query.get("startIndex", ["0"])[0])
            per_page = int(query.get("resultsPerPage", ["2000"])[0])
            begin = query.get("lastModStartDate", [None])[0]
            end = query.get("lastModEndDate", [None])[0]

            # The real API's rules, enforced rather than assumed. Both dates
            # or neither, and no more than 120 days between them -- a client
            # that gets either wrong should fail here, in a test, and not in
            # production against NIST.
            if bool(begin) != bool(end):
                return self._send(
                    404, b"lastModStartDate and lastModEndDate are a pair",
                    "text/plain")
            if begin and end:
                try:
                    begin_at, end_at = _parse_stamp(begin), _parse_stamp(end)
                except ValueError:
                    return self._send(404, b"unparseable date", "text/plain")
                if (end_at - begin_at) > timedelta(days=MAX_WINDOW_DAYS):
                    return self._send(
                        404, b"maxlastModStartDate range is 120 days",
                        "text/plain")
                universe = [n for n in range(TOTAL_CVES)
                            if begin_at <= _last_modified(n) <= end_at]
            else:
                universe = list(range(TOTAL_CVES))

            # Transient 503 once, to prove the backoff path is real. Only on
            # the full-corpus path, where index 2000 exists.
            if (not begin and start == FLAKY_INDEX
                    and start not in self.flaked):
                self.flaked.add(start)
                return self._send(503, b"busy", "text/plain")

            window = universe[start:start + per_page]
            batch = [_synthetic_cve(n) for n in window]
            payload = {"resultsPerPage": len(batch), "startIndex": start,
                       "totalResults": len(universe),
                       "vulnerabilities": batch}
            return self._send(200, json.dumps(payload).encode(),
                              "application/json")

        if route.path == "/kev":
            payload = {
                "catalogVersion": "2026.08.18",
                "vulnerabilities": [
                    {"cveID": "CVE-2024-00001", "vendorProject": "Apache",
                     "product": "HTTP Server", "vulnerabilityName": "Path traversal",
                     "dateAdded": "2024-03-01",
                     "knownRansomwareCampaignUse": "Known"},
                    {"cveID": "CVE-2024-00002", "vendorProject": "OpenBSD",
                     "product": "OpenSSH", "vulnerabilityName": "RCE",
                     "dateAdded": "2024-07-11",
                     "knownRansomwareCampaignUse": "Unknown"},
                ],
            }
            return self._send(200, json.dumps(payload).encode(),
                              "application/json")

        if route.path == "/epss":
            rows = ["#model_version:v2025.03.14,score_date:2026-08-18T00:00:00Z",
                    "cve,epss,percentile"]
            rows += [f"CVE-2024-{n:05d},{(n % 100) / 1000:.5f},"
                     f"{(n % 100) / 100:.5f}" for n in range(TOTAL_CVES)]
            body = gzip.compress("\n".join(rows).encode())
            return self._send(200, body, "application/gzip")

        if route.path == "/edb":
            rows = ["id,file,description,date_published,author,type,platform,port"]
            rows += [f"{50000 + n},exploits/linux/remote/{50000 + n}.py,"
                     f"Synthetic {n} - Remote Code Execution,2024-01-01,"
                     f"researcher,remote,linux," for n in range(500)]
            return self._send(200, "\n".join(rows).encode(), "text/csv")

        if route.path == "/forbidden":
            return self._send(403, b"nope", "text/plain")

        self._send(404, b"", "text/plain")


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture
def wired(server, monkeypatch):
    """Point the fetcher at the local server, with a small page size."""
    monkeypatch.setattr(fetchmod, "NVD_API", f"{server}/nvd")
    monkeypatch.setattr(fetchmod, "KEV_URL", f"{server}/kev")
    monkeypatch.setattr(fetchmod, "EPSS_URL", f"{server}/epss")
    monkeypatch.setattr(fetchmod, "EDB_URL", f"{server}/edb")
    monkeypatch.setattr(fetchmod, "NVD_DELAY_ANON", 0.0)
    monkeypatch.setattr(fetchmod, "NVD_DELAY_KEYED", 0.0)
    return server


# --------------------------------------------------------------------------- #
# Fetch
# --------------------------------------------------------------------------- #

def test_nvd_pages_through_the_whole_corpus(wired, tmp_path):
    result = fetchmod.fetch_nvd(tmp_path, api_key="test-key")

    assert result.error == ""
    assert result.records == TOTAL_CVES, (
        "the puller must follow the cursor to the end, not stop after page one")
    pages = sorted((tmp_path / "nvd").glob("nvd-*.json"))
    assert len(pages) == 3


def test_a_transient_503_is_retried_not_fatal(wired, tmp_path):
    _Handler.flaked.clear()
    result = fetchmod.fetch_nvd(tmp_path, api_key="test-key")
    assert result.records == TOTAL_CVES
    assert FLAKY_INDEX in _Handler.flaked, "the 503 branch never fired"


def test_a_403_is_terminal(wired, tmp_path, server, monkeypatch):
    """A 403 is a bad key or a blocked client. Hammering it is both futile
    and the behaviour of a tool nobody should be running."""
    monkeypatch.setattr(fetchmod, "NVD_API", f"{server}/forbidden")
    attempts = []
    real_open = fetchmod._open

    def counting(url, headers=None, timeout=120):
        attempts.append(url)
        return real_open(url, headers, timeout)

    monkeypatch.setattr(fetchmod, "_open", counting)
    result = fetchmod.fetch_nvd(tmp_path, api_key="bad")

    assert "403" in result.error
    assert len(attempts) == 1, f"retried a 403 {len(attempts)} times"


def test_an_interrupted_pull_resumes_from_its_checkpoint(wired, tmp_path,
                                                         monkeypatch):
    """The failure this guards: an unresumable four-hour download on a laptop
    that sleeps is a download that never completes."""
    calls = {"n": 0}
    real_get = fetchmod._get_json

    def failing(url, headers=None, retries=4, timeout=120):
        calls["n"] += 1
        if calls["n"] == 2:
            raise fetchmod.FetchError("simulated network drop")
        return real_get(url, headers, retries, timeout)

    monkeypatch.setattr(fetchmod, "_get_json", failing)
    first = fetchmod.fetch_nvd(tmp_path, api_key="k")

    assert first.error and first.records == 2000, "expected a partial pull"
    checkpoint = json.loads((tmp_path / "nvd" / "_checkpoint.json").read_text())
    assert checkpoint["next_index"] == 2000

    monkeypatch.setattr(fetchmod, "_get_json", real_get)
    second = fetchmod.fetch_nvd(tmp_path, api_key="k")

    assert second.error == ""
    assert second.records == TOTAL_CVES - 2000, (
        "resume re-downloaded pages it already had")
    assert len(sorted((tmp_path / "nvd").glob("nvd-*.json"))) == 3


def test_no_resume_starts_over(wired, tmp_path):
    fetchmod.fetch_nvd(tmp_path, api_key="k")
    again = fetchmod.fetch_nvd(tmp_path, api_key="k", resume=False)
    assert again.records == TOTAL_CVES


def test_a_corrupt_checkpoint_restarts_rather_than_crashing(wired, tmp_path):
    (tmp_path / "nvd").mkdir(parents=True)
    (tmp_path / "nvd" / "_checkpoint.json").write_text("{ not json")
    result = fetchmod.fetch_nvd(tmp_path, api_key="k")
    assert result.records == TOTAL_CVES


def test_kev_epss_and_exploitdb_land_on_disk(wired, tmp_path):
    kev = fetchmod.fetch_kev(tmp_path)
    epss = fetchmod.fetch_epss(tmp_path)
    edb = fetchmod.fetch_exploitdb(tmp_path)

    assert kev.error == "" and kev.records == 2
    assert epss.error == "" and epss.records == TOTAL_CVES
    assert edb.error == "" and edb.records == 500
    for result in (kev, epss, edb):
        assert len(result.sha256) == 64, "no integrity digest recorded"


def test_epss_is_decompressed_on_the_way_in(wired, tmp_path):
    fetchmod.fetch_epss(tmp_path)
    text = (tmp_path / "epss_scores-current.csv").read_text()
    assert text.startswith("#model_version"), "gzip was never unwrapped"


def test_a_partial_download_never_becomes_a_valid_looking_feed(wired, tmp_path,
                                                               monkeypatch):
    """A truncated corpus that parses is worse than one that is obviously
    missing -- it silently under-reports for as long as nobody notices."""
    def exploding(*args, **kwargs):
        raise OSError("connection reset mid-stream")

    monkeypatch.setattr(fetchmod, "_open", exploding)
    result = fetchmod.fetch_kev(tmp_path)

    assert result.error
    assert not (tmp_path / "known_exploited_vulnerabilities.json").exists()


# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #

@pytest.fixture
def built(wired, tmp_path):
    feeds = tmp_path / "feeds"
    fetchmod.fetch_nvd(feeds, api_key="k")
    fetchmod.fetch_kev(feeds)
    fetchmod.fetch_epss(feeds)
    fetchmod.fetch_exploitdb(feeds)
    report = build(feeds, tmp_path / "vuln.db")
    return feeds, tmp_path / "vuln.db", report


def test_build_ingests_every_fetched_cve(built):
    _, db_path, report = built
    assert report["stats"]["cves"] == TOTAL_CVES
    assert report["stats"]["statements"] == TOTAL_CVES
    assert report["kev"] == 2
    assert report["epss"] == TOTAL_CVES
    assert db_path.exists()


def test_lookup_by_cpe_returns_only_that_product(built):
    _, db_path, _ = built
    with VulnDB(db_path) as db:
        observed = parse_cpe("cpe:2.3:a:apache:tomcat:9.0.1:*:*:*:*:*:*:*")
        found = db.candidates_for_cpe(observed)

    assert found, "an indexed lookup found nothing for a product in the corpus"
    assert all(any(r.cpe.product == "tomcat" for r in e.cpe_ranges)
               for e in found), "the index leaked another vendor's product"


def test_tomcat_is_not_filed_as_httpd(built):
    """Apache ships both. Substring matching cannot tell them apart; this is
    the whole reason the CPE path exists."""
    _, db_path, _ = built
    with VulnDB(db_path) as db:
        httpd = db.candidates_for_cpe(
            parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"))
        tomcat = db.candidates_for_cpe(
            parse_cpe("cpe:2.3:a:apache:tomcat:9.0.1:*:*:*:*:*:*:*"))

    assert {e.cve_id for e in httpd}.isdisjoint({e.cve_id for e in tomcat})


def test_an_unknown_product_returns_nothing(built):
    _, db_path, _ = built
    with VulnDB(db_path) as db:
        found = db.candidates_for_cpe(
            parse_cpe("cpe:2.3:a:acme:nonexistent:1.0:*:*:*:*:*:*:*"))
    assert found == []


def test_alias_fallback_matches_the_banner_direction(built):
    """`instr(banner, alias)` -- the alias is the needle, the fingerprint the
    haystack, matching `_product_match`. Reversing it silently breaks every
    fallback lookup."""
    _, db_path, _ = built
    with VulnDB(db_path) as db:
        found = db.candidates_for_product("nginx 1.18.0 (Ubuntu)")
    assert found, "alias lookup found nothing for a product that is in the corpus"


def test_alias_lookup_ignores_blank_input(built):
    _, db_path, _ = built
    with VulnDB(db_path) as db:
        assert db.candidates_for_product("") == []
        assert db.candidates_for_product("   ") == []
        assert db.candidates_for_product(None) == []


def test_reingest_updates_rather_than_duplicates(built):
    """A daily refresh must not double the corpus every morning."""
    feeds, db_path, _ = built
    before = build(feeds, db_path)["stats"]
    after = build(feeds, db_path)["stats"]
    assert before["cves"] == after["cves"] == TOTAL_CVES
    assert before["statements"] == after["statements"]


def test_alias_entries_still_require_a_version(built):
    """Without this, one alias-matched CVE attaches to every host running that
    product at any version -- 250,000 CVEs' worth of noise."""
    _, db_path, _ = built
    with VulnDB(db_path) as db:
        found = db.candidates_for_product("nginx 1.18.0")
    assert all(e.requires_version for e in found if not e.cpe_ranges)


def test_a_stale_schema_is_refused_not_guessed_at(tmp_path):
    path = tmp_path / "old.db"
    with VulnDB(path) as db:
        db.set_meta("schema_version", "0")
    with pytest.raises(SchemaMismatch):
        VulnDB(path)


def test_missing_nvd_directory_is_survivable(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    assert list(iter_nvd_entries(empty)) == []


def test_a_corrupt_page_costs_that_page_only(built):
    feeds, db_path, _ = built
    pages = sorted((feeds / "nvd").glob("nvd-*.json"))
    pages[1].write_text("{ truncated")

    report = build(feeds, db_path.with_name("partial.db"))
    assert 0 < report["stats"]["cves"] < TOTAL_CVES, (
        "one bad page either killed the build or was silently ignored")


# --------------------------------------------------------------------------- #
# Incremental pull -- `--since`
#
# The daily refresh re-downloads ~300,000 records to collect the few hundred
# that changed. These exercise the window against a server that enforces the
# same rules NVD does: both dates or neither, and 120 days maximum.
# --------------------------------------------------------------------------- #

FIRST_PULL_AT = SERVER_NOW - timedelta(days=5)
EXPECTED_DELTA = 6          # CVEs 0..5, modified within those five days


def _queries_since(mark: int) -> list[str]:
    return _Handler.queries[mark:]


def test_a_full_pull_records_when_it_happened(wired, tmp_path):
    """Without this the incremental path has no anchor and every run is a
    full run wearing a flag."""
    result = fetchmod.fetch_nvd(tmp_path, api_key="k", now=FIRST_PULL_AT)

    assert result.records == TOTAL_CVES
    assert result.incremental is False
    checkpoint = json.loads((tmp_path / "nvd" / "_checkpoint.json").read_text())
    assert checkpoint["complete"] is True
    assert checkpoint["last_pull"] == FIRST_PULL_AT.isoformat()


def test_a_second_pull_asks_only_for_what_changed(wired, tmp_path):
    fetchmod.fetch_nvd(tmp_path, api_key="k", now=FIRST_PULL_AT)

    mark = len(_Handler.queries)
    delta = fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto",
                               now=SERVER_NOW)

    assert delta.error == ""
    assert delta.incremental is True
    assert delta.records == EXPECTED_DELTA, (
        "the second pull re-downloaded the corpus instead of the delta")
    sent = _queries_since(mark)
    assert sent and all("lastModStartDate" in q for q in sent), (
        "no window was sent; this is a full pull with a flag on it")
    assert all("lastModEndDate" in q for q in sent), (
        "NVD rejects a start date without an end date")


def test_a_delta_page_never_overwrites_a_full_page(wired, tmp_path):
    """A delta written to `nvd-000000.json` would delete 2,000 unchanged CVEs
    from the corpus on the next build -- a refresh that shrinks the database."""
    fetchmod.fetch_nvd(tmp_path, api_key="k", now=FIRST_PULL_AT)
    full_pages = {p.name: p.read_bytes()
                  for p in (tmp_path / "nvd").glob("nvd-*.json")}

    fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto", now=SERVER_NOW)

    after = {p.name: p.read_bytes()
             for p in (tmp_path / "nvd").glob("nvd-*.json")}
    for name, blob in full_pages.items():
        assert after[name] == blob, f"the delta overwrote {name}"
    assert any(name.startswith("nvd-delta-") for name in after), (
        "the delta was not written where the builder will find it")


def test_a_second_build_keeps_the_whole_corpus_and_ingests_the_delta(wired,
                                                                     tmp_path):
    """Acceptance from CYCLE-9: rebuild twice, second run pulls only deltas --
    and the database must be no smaller for it."""
    feeds = tmp_path / "feeds"
    fetchmod.fetch_nvd(feeds, api_key="k", now=FIRST_PULL_AT)
    first = build(feeds, tmp_path / "vuln.db")
    assert first["stats"]["cves"] == TOTAL_CVES

    delta = fetchmod.fetch_nvd(feeds, api_key="k", since="auto",
                               now=SERVER_NOW)
    second = build(feeds, tmp_path / "vuln.db")

    assert delta.records == EXPECTED_DELTA
    assert second["stats"]["cves"] == TOTAL_CVES, (
        "the delta build changed the corpus size -- it must update in place")
    assert second["stats"]["statements"] == first["stats"]["statements"]


def test_a_gap_wider_than_the_window_falls_back_to_a_full_pull(wired, tmp_path):
    """NVD caps lastModStartDate..lastModEndDate at 120 days. A client that
    sends 200 gets a 404, and a client that silently splits the range gets a
    corpus with a hole in it."""
    fetchmod.fetch_nvd(tmp_path, api_key="k",
                       now=SERVER_NOW - timedelta(days=200))

    mark = len(_Handler.queries)
    result = fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto",
                                now=SERVER_NOW)

    assert result.error == ""
    assert result.incremental is False
    assert result.records == TOTAL_CVES, "fell back to a partial pull, not a full one"
    assert not any("lastModStartDate" in q for q in _queries_since(mark)), (
        "sent a window the API documents as invalid")


def test_a_gap_just_inside_the_window_still_goes_incremental(wired, tmp_path):
    """The boundary in the other direction: 119 days is legal, and treating
    it as a full pull would make `--since` useless for anyone refreshing
    monthly."""
    fetchmod.fetch_nvd(tmp_path, api_key="k",
                       now=SERVER_NOW - timedelta(days=119))
    result = fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto",
                                now=SERVER_NOW)

    assert result.incremental is True
    assert result.records == 120         # CVEs 0..119


def test_an_explicit_since_overrides_the_checkpoint(wired, tmp_path):
    fetchmod.fetch_nvd(tmp_path, api_key="k", now=FIRST_PULL_AT)
    result = fetchmod.fetch_nvd(
        tmp_path, api_key="k",
        since=(SERVER_NOW - timedelta(days=2)).isoformat(), now=SERVER_NOW)

    assert result.incremental is True
    assert result.records == 3           # CVEs 0, 1, 2


def test_since_with_no_prior_pull_is_a_full_pull(wired, tmp_path):
    """First run of a `--since` cron job. There is nothing to be incremental
    from, and quietly fetching nothing would be the worst outcome."""
    mark = len(_Handler.queries)
    result = fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto",
                                now=SERVER_NOW)

    assert result.records == TOTAL_CVES
    assert result.incremental is False
    assert not any("lastModStartDate" in q for q in _queries_since(mark))


def test_a_future_last_pull_falls_back_rather_than_asking_backwards(wired,
                                                                    tmp_path):
    fetchmod.fetch_nvd(tmp_path, api_key="k",
                       now=SERVER_NOW + timedelta(days=3))
    result = fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto",
                                now=SERVER_NOW)
    assert result.records == TOTAL_CVES and result.incremental is False


def test_the_delta_pull_records_a_new_last_pull(wired, tmp_path):
    fetchmod.fetch_nvd(tmp_path, api_key="k", now=FIRST_PULL_AT)
    fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto", now=SERVER_NOW)

    checkpoint = json.loads((tmp_path / "nvd" / "_checkpoint.json").read_text())
    assert checkpoint["last_pull"] == SERVER_NOW.isoformat(), (
        "the window never advances, so every delta re-pulls the same days")
    assert checkpoint["mode"] == "delta"


def test_an_empty_delta_still_advances_the_clock(wired, tmp_path):
    """Nothing changed is an answer. If it does not move `last_pull`, the
    window grows every day until it crosses 120 and triggers a full pull."""
    anchor = SERVER_NOW + timedelta(hours=1)     # after every lastModified
    fetchmod.fetch_nvd(tmp_path, api_key="k", now=anchor)
    later = anchor + timedelta(hours=1)
    result = fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto", now=later)

    assert result.error == "" and result.records == 0
    checkpoint = json.loads((tmp_path / "nvd" / "_checkpoint.json").read_text())
    assert checkpoint["last_pull"] == later.isoformat()


def test_an_interrupted_delta_resumes_inside_its_own_window(wired, tmp_path,
                                                            monkeypatch):
    """The existing resume-by-cursor behaviour, on the incremental path. The
    window must be the interrupted run's window: recomputing it would shift
    the result set under a cursor that indexes into the old one."""
    monkeypatch.setattr(fetchmod, "NVD_PAGE", 2)
    fetchmod.fetch_nvd(tmp_path, api_key="k", now=FIRST_PULL_AT)

    calls = {"n": 0}
    real_get = fetchmod._get_json

    def failing(url, headers=None, retries=4, timeout=120):
        calls["n"] += 1
        if calls["n"] == 2:
            raise fetchmod.FetchError("simulated network drop")
        return real_get(url, headers, retries, timeout)

    monkeypatch.setattr(fetchmod, "_get_json", failing)
    first = fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto",
                               now=SERVER_NOW)
    assert first.error and first.records == 2

    checkpoint = json.loads((tmp_path / "nvd" / "_checkpoint.json").read_text())
    assert checkpoint["next_index"] == 2
    assert checkpoint["mode"] == "delta"
    assert checkpoint["window_start"] == FIRST_PULL_AT.isoformat()

    monkeypatch.setattr(fetchmod, "_get_json", real_get)
    # A later `now` on the resume: the stored window must win, or the four
    # records still outstanding are counted against a different range.
    second = fetchmod.fetch_nvd(tmp_path, api_key="k", since="auto",
                                now=SERVER_NOW + timedelta(hours=6))

    assert second.error == ""
    assert second.records == EXPECTED_DELTA - 2, (
        "resume re-fetched pages it already had, or changed window mid-pull")


def test_a_full_pull_does_not_resume_from_a_delta_cursor(wired, tmp_path):
    """A delta's index 2000 is not a full pull's index 2000. Reusing the
    cursor across modes skips the first 2,000 records and reports success --
    the same shape as every other control that held on one path and not the
    second."""
    pages = tmp_path / "nvd"
    pages.mkdir(parents=True)
    (pages / "_checkpoint.json").write_text(json.dumps({
        "next_index": 2000, "total": 2400, "mode": "delta",
        "window_start": (SERVER_NOW - timedelta(days=5)).isoformat(),
        "window_end": SERVER_NOW.isoformat(),
    }))

    result = fetchmod.fetch_nvd(tmp_path, api_key="k", now=SERVER_NOW)

    assert result.records == TOTAL_CVES, (
        "a full pull inherited a delta cursor and skipped the start of the "
        "corpus")


def test_no_resume_still_keeps_the_last_pull_timestamp(wired, tmp_path):
    """`--no-resume` discards a cursor, not the provenance of the last run."""
    fetchmod.fetch_nvd(tmp_path, api_key="k", now=FIRST_PULL_AT)
    result = fetchmod.fetch_nvd(tmp_path, api_key="k", resume=False,
                                since="auto", now=SERVER_NOW)
    assert result.incremental is True and result.records == EXPECTED_DELTA


# --------------------------------------------------------------------------- #
# Provenance -- the `feed_source` table
# --------------------------------------------------------------------------- #

def test_the_fetch_manifest_survives_the_process(wired, tmp_path):
    """The sha256 was computed on every download and thrown away at exit."""
    results = [fetchmod.fetch_kev(tmp_path), fetchmod.fetch_epss(tmp_path),
               fetchmod.fetch_exploitdb(tmp_path),
               fetchmod.fetch_nvd(tmp_path, api_key="k")]
    fetchmod.write_manifest(tmp_path, results)

    recorded = fetchmod.read_manifest(tmp_path)
    assert set(recorded) == {"kev", "epss", "exploitdb", "nvd"}
    for name, entry in recorded.items():
        assert len(entry["sha256"]) == 64, f"{name} has no digest"
        assert entry["bytes"] > 0 and entry["url"]
        assert entry["fetched_at"]


def test_a_partial_fetch_does_not_erase_another_feeds_provenance(wired,
                                                                 tmp_path):
    """`--kev` alone must not blank out what the last `--all` recorded."""
    fetchmod.write_manifest(tmp_path, [fetchmod.fetch_kev(tmp_path),
                                       fetchmod.fetch_epss(tmp_path)])
    before = fetchmod.read_manifest(tmp_path)["epss"]

    fetchmod.write_manifest(tmp_path, [fetchmod.fetch_kev(tmp_path)])
    after = fetchmod.read_manifest(tmp_path)

    assert after["epss"] == before, "an unrelated feed lost its provenance"


def test_a_failed_fetch_never_makes_the_corpus_look_newer(wired, tmp_path,
                                                          monkeypatch):
    fetchmod.write_manifest(tmp_path, [fetchmod.fetch_kev(tmp_path)])
    good = fetchmod.read_manifest(tmp_path)["kev"]

    monkeypatch.setattr(fetchmod, "_open",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    failed = fetchmod.fetch_kev(tmp_path)
    fetchmod.write_manifest(tmp_path, [failed])

    assert failed.error
    assert fetchmod.read_manifest(tmp_path)["kev"] == good, (
        "a failed fetch overwrote a good record, hiding the staleness")


def test_a_corrupt_manifest_does_not_stop_a_build(wired, tmp_path):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    fetchmod.fetch_kev(feeds)
    (feeds / fetchmod.MANIFEST_NAME).write_text("{ truncated")

    report = build(feeds, tmp_path / "vuln.db")
    assert report["kev"] == 2


@pytest.fixture
def provenanced(wired, tmp_path):
    feeds = tmp_path / "feeds"
    results = [fetchmod.fetch_nvd(feeds, api_key="k"),
               fetchmod.fetch_kev(feeds), fetchmod.fetch_epss(feeds),
               fetchmod.fetch_exploitdb(feeds)]
    fetchmod.write_manifest(feeds, results)
    report = build(feeds, tmp_path / "vuln.db")
    return feeds, tmp_path / "vuln.db", report


def test_the_build_records_where_every_feed_came_from(provenanced):
    _, db_path, _ = provenanced
    with VulnDB(db_path) as db:
        feeds = {f.name: f for f in db.feeds()}

    assert set(feeds) == {"nvd", "kev", "epss", "exploitdb"}
    assert feeds["nvd"].record_count == TOTAL_CVES
    assert feeds["kev"].record_count == 2
    assert feeds["epss"].record_count == TOTAL_CVES
    for name, feed in feeds.items():
        assert len(feed.sha256) == 64, f"{name} landed without a digest"
        assert feed.bytes > 0
        assert feed.url.startswith("http"), f"{name} has no source URL"
        assert feed.age_days is not None and feed.age_days < 1


def test_rebuilding_updates_the_provenance_row_rather_than_appending(
        provenanced):
    """Bug 5 from CORPUS-PATTERN.md, applied to provenance: a daily refresh
    that appends a row per feed per day answers "how old is EPSS" with a
    list."""
    feeds, db_path, _ = provenanced
    build(feeds, db_path)
    build(feeds, db_path)

    with VulnDB(db_path) as db:
        rows = db.feeds()
        raw = db._conn.execute("SELECT COUNT(*) n FROM feed_source").fetchone()

    assert len(rows) == 4
    assert raw["n"] == 4, "feed_source grew on re-ingest"


def test_record_feed_replaces_in_place(tmp_path):
    with VulnDB(tmp_path / "v.db") as db:
        db.record_feed("epss", url="http://a", sha256="a" * 64, bytes_=10,
                       record_count=1, fetched_at="2026-01-01T00:00:00+00:00")
        db.record_feed("epss", url="http://b", sha256="b" * 64, bytes_=20,
                       record_count=2, fetched_at="2026-02-01T00:00:00+00:00")
        feeds = db.feeds()

        assert len(feeds) == 1
        assert feeds[0].url == "http://b" and feeds[0].record_count == 2
        assert db.feed("EPSS") is not None, "lookup is case-sensitive"
        assert db.forget_feed("epss") == 1
        assert db.feeds() == []


def test_a_feed_name_is_required(tmp_path):
    with VulnDB(tmp_path / "v.db") as db:
        with pytest.raises(ValueError):
            db.record_feed("  ")


def test_an_unreadable_fetch_date_is_not_reported_as_fresh(tmp_path):
    with VulnDB(tmp_path / "v.db") as db:
        db.record_feed("epss", fetched_at="whenever")
        assert db.feed("epss").age_days is None


def test_provenance_survives_a_feeds_directory_with_no_manifest(wired,
                                                               tmp_path):
    """A corpus copied between machines, or built before the manifest
    existed. Provenance on the fetch path only is the bug shape this codebase
    keeps finding."""
    feeds = tmp_path / "feeds"
    fetchmod.fetch_nvd(feeds, api_key="k")
    fetchmod.fetch_kev(feeds)
    fetchmod.fetch_epss(feeds)
    assert not fetchmod.manifest_path(feeds).exists()

    build(feeds, tmp_path / "vuln.db")
    with VulnDB(tmp_path / "vuln.db") as db:
        feeds_by_name = {f.name: f for f in db.feeds()}

    assert {"nvd", "kev", "epss"} <= set(feeds_by_name)
    assert feeds_by_name["kev"].record_count == 2
    assert len(feeds_by_name["kev"].sha256) == 64
    assert feeds_by_name["nvd"].bytes > 0


def test_an_incremental_refresh_reports_the_corpus_not_the_delta(wired,
                                                                 tmp_path):
    """`record_count` answers "is this corpus complete". After a delta pull
    the honest answer is 4,500, not 6."""
    feeds = tmp_path / "feeds"
    fetchmod.write_manifest(feeds, [
        fetchmod.fetch_nvd(feeds, api_key="k", now=FIRST_PULL_AT)])
    build(feeds, tmp_path / "vuln.db")

    fetchmod.write_manifest(feeds, [
        fetchmod.fetch_nvd(feeds, api_key="k", since="auto", now=SERVER_NOW)])
    build(feeds, tmp_path / "vuln.db")

    with VulnDB(tmp_path / "vuln.db") as db:
        assert db.feed("nvd").record_count == TOTAL_CVES


# --------------------------------------------------------------------------- #
# Per-feed staleness in describe()
# --------------------------------------------------------------------------- #

def _stale(db_path, name, days):
    when = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with VulnDB(db_path) as db:
        db.record_feed(name, url="http://x", sha256="c" * 64, bytes_=1,
                       record_count=1, fetched_at=when)


def test_a_stale_epss_feed_is_named_specifically(provenanced):
    """"corpus is fresh" must not be able to be true while EPSS is three
    months old -- and "1 feed is stale" makes the analyst open the database
    to find out which."""
    _, db_path, _ = provenanced
    _stale(db_path, "epss", 92)

    resolver = DbResolver(VulnDB(db_path))
    text = resolver.describe()
    resolver.close()

    assert "STALE" in text
    assert "fetch" in text, "did not say how to fix it"
    # Everything is asserted against the text *after* STALE: the corpus path
    # in the prefix is a pytest temp directory named after this test, so
    # "epss" appears there whether or not describe() ever said it.
    stale_part = text.split("STALE", 1)[1]
    assert "epss" in stale_part, "the stale feed was counted, not named"
    assert "92" in stale_part, "did not say how old"
    assert "kev" not in stale_part and "nvd" not in stale_part, (
        "named feeds that are current as stale")


def test_a_stale_kev_feed_is_named_and_epss_is_not(provenanced):
    _, db_path, _ = provenanced
    _stale(db_path, "kev", 40)

    resolver = DbResolver(VulnDB(db_path))
    text = resolver.describe()
    resolver.close()

    stale_part = text.split("STALE", 1)[1]
    assert "kev" in stale_part
    assert "epss" not in stale_part


def test_a_freshly_fetched_corpus_does_not_cry_wolf_per_feed(provenanced):
    _, db_path, _ = provenanced
    resolver = DbResolver(VulnDB(db_path))
    text = resolver.describe()
    resolver.close()

    assert "STALE" not in text
    feed_part = text.split("feeds:", 1)[1]
    for name in ("epss", "nvd", "kev", "exploitdb"):
        assert name in feed_part, (
            "per-feed dates are the point; a single build date hides the rot")


def test_each_feed_ages_at_its_own_rate(provenanced):
    """EPSS regenerates daily, NVD is continuous, KEV changes weekly. Twenty
    days is fine for NVD and three refresh cycles missed for EPSS."""
    _, db_path, _ = provenanced
    _stale(db_path, "epss", 20)
    _stale(db_path, "nvd", 20)

    resolver = DbResolver(VulnDB(db_path))
    text = resolver.describe()
    resolver.close()

    stale_part = text.split("STALE", 1)[1]
    assert "epss" in stale_part
    assert "nvd" not in stale_part


def test_a_corpus_with_no_provenance_says_so_rather_than_claiming_freshness(
        tmp_path):
    """A database built before `feed_source` existed. Silence here reads as
    "all feeds current"."""
    path = tmp_path / "bare.db"
    with VulnDB(path) as db:
        db.set_meta("built_at", "1")
    resolver = DbResolver(VulnDB(path))
    text = resolver.describe()
    resolver.close()

    assert "no per-feed provenance" in text


# --------------------------------------------------------------------------- #
# The CLI, which is what an operator actually runs
# --------------------------------------------------------------------------- #

def test_the_cli_writes_the_manifest_the_builder_reads(wired, tmp_path,
                                                       capsys):
    code = fetchmod.main(["--dest", str(tmp_path), "--kev", "--epss"])
    capsys.readouterr()

    assert code == 0
    recorded = fetchmod.read_manifest(tmp_path)
    assert set(recorded) == {"kev", "epss"}, (
        "the fetch summary printed provenance the build cannot read")


def test_the_cli_since_flag_takes_the_incremental_path(wired, tmp_path,
                                                       capsys, monkeypatch):
    seen = {}
    real = fetchmod.fetch_nvd

    def spy(dest, api_key=None, resume=True, progress=None, since=None,
            now=None):
        seen["since"] = since
        return real(dest, api_key, resume, progress, since, now)

    monkeypatch.setattr(fetchmod, "fetch_nvd", spy)
    fetchmod.main(["--dest", str(tmp_path), "--nvd", "--since"])
    capsys.readouterr()
    assert seen["since"] == "auto", "--since with no value must mean 'last pull'"

    fetchmod.main(["--dest", str(tmp_path), "--nvd", "--since",
                   "2026-08-01T00:00:00+00:00"])
    capsys.readouterr()
    assert seen["since"] == "2026-08-01T00:00:00+00:00"
