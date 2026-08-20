# Building a corpus, the second time

`vulndb.py` is the first indexed corpus in reconkg. It will not be the last —
the next one is CVE → ExploitDB entry → tool/script → command, and it has the
same shape. This is the record of how the first one was built, what broke,
and which bugs will recur if the pattern is re-derived from scratch rather
than reused.

Read this before starting corpus number two.

---

## The shape

Four pieces, deliberately separate. Keeping them separate is most of the
value:

```
fetch.py     network. Downloads to disk. Nothing else imports it.
builddb.py   offline. Parses files -> ingests. Rebuild without re-downloading.
vulndb.py    storage + retrieval. Narrows candidates. Decides nothing.
cpe.py       matching semantics. Decides. Already mutation-tested.
```

The split that matters most is the last one. **Storage narrows; a separate
module decides.** `vulndb` takes 250,000 CVEs down to the dozens sharing a
product identity, then hands them to the matcher unchanged. Version
comparison never went into SQL, because SQL cannot express it correctly and
reimplementing `compare_versions` in a second dialect would mean two
implementations disagreeing at 2am.

For the exploit corpus the same line applies: SQLite finds the candidate
ExploitDB rows for a CVE; the code that decides which one is *applicable*
(platform, port, verified flag, whether the target matches) stays in Python
where it can be tested.

The fetch/build split earns itself the first time a parser bug means
rebuilding the index. Re-downloading 300,000 records because you fixed a
regex is a mistake you make once.

## The index is the entire design

One decision does all the work: **index on the identity you look up by.**

For CVEs that is the CPE triple `(part, vendor, product)`, because that is
what a fingerprint resolves to. For the exploit corpus it will be the CVE ID
itself, plus a secondary index on `(platform, type)` for the "what else
exists for this OS" query.

Everything else follows. Get this wrong and no amount of caching rescues it;
get it right and a 50x larger corpus costs nothing.

## Bugs that will happen again

These are not hypothetical. Each cost real time on corpus one.

**1. `ON DELETE CASCADE` does nothing by default.**
SQLite ships with foreign keys *off*, and the pragma is per-connection, not
stored in the file. The cascade declarations read like behaviour and are
documentation. Symptom: the parent table looked correct because its primary
key deduplicated, while the child table tripled on every re-ingest —
4,500 → 9,000 → 13,500.
*Do:* delete from child tables explicitly in the write path. Do not rely on
the pragma, because the next caller to open the file by another route will
not set it.

**2. An index on the read path is not enough.**
`product_alias` was indexed on `alias` for lookups and had nothing on
`cve_id`, which the delete-before-insert used. Every re-ingest scanned the
whole table once per record. Ingest fell from 65,570/s to 697/s between a
2,000 and a 100,000 record build — a full corpus would have taken an hour.
*Do:* index every column you filter on, including in `DELETE`.

**3. JSON blobs cost per row, and hot keys return many rows.**
Storing each applicability statement as JSON meant a `json.loads` plus a CPE
parse for every candidate. `apache:http_server` returns hundreds.
*Do:* columns, not blobs, for anything read per-row. Cache parses of strings
that repeat across records (`lru_cache` on the CPE parse; NVD reuses a small
set of identity strings across an enormous number of CVEs).

**4. `LIMIT` without `ORDER BY` silently discards the right answer.**
`apache:http_server` matched 56,411 rows and the query returned an arbitrary
500. The applicable CVE might never reach the matcher, and the tool reports
"no leads" with total confidence.
*Do:* narrow before limiting, and log loudly when the limit is still hit.
Silent truncation is a correctness bug wearing a performance bug's clothes.

**5. Re-ingest must update, not append.**
A daily refresh that doubles the corpus is worse than no refresh. Delete the
record and its children, then insert.

## Verification that actually verifies

**Test the client against a real server, not a mocked `urlopen`.** Mocking
tests the mock. A `ThreadingHTTPServer` on localhost serving realistically
shaped payloads exercises paging, gzip framing, chunked reads, a transient
503, a terminal 403, and a mid-pull drop with resume. That is 20 tests and it
found the resume path was correct.

**Benchmark at real corpus size before believing the design.** Reading the
code would not have found any of bugs 1–4. Each surfaced as a number.

**Isolate the variable you are actually testing.** The first benchmark
verdict said "the index is broken" because lookup latency grew 30x. It was
not — a bigger corpus genuinely holds more Apache CVEs, so a slower lookup
there is correct. The honest probe queries an identity *absent from both
corpora*: the result set is empty either way, so only corpus size varies.
That showed 50x the data at 0.78x the cost.

A benchmark that conflates two effects will send you optimising the wrong
one. I nearly "fixed" a working index.

## Numbers from corpus one

Reference points for judging whether corpus two is behaving:

```
ingest rate      82,561 records/s      (after the index fix)
100k records     1.2s to build
on disk          ~40 MB per 100k records with one statement each
indexed lookup   ~0.006 ms, flat against corpus size
```

## Provenance and refresh (cycle 9, stream A)

Three additions, and the schema is now v3.

**`feed_source(name PK, url, sha256, bytes, record_count, fetched_at)`.**
`name` is the primary key so a refresh replaces the row. Bug 5 applies to
provenance exactly as it applies to the corpus: an append-only table answers
"how old is EPSS" with a list, and the caller who forgets the `ORDER BY`
gets the wrong answer silently.

**The fetch/build split needed a sidecar.** `fetch.py` computes a sha256 per
download and `builddb.py` runs in a different process, so the digest died at
exit. `_fetch_manifest.json` beside the feeds carries it across, merged per
feed rather than overwritten — `--kev` alone must not erase what `--all`
recorded about NVD — and a failed fetch never replaces a good record, because
that would make the corpus look *newer* than it is. `builddb.py` falls back
to hashing the files on disk when there is no manifest, so provenance is not
a property of the fetch path only. (That last one is the recurring bug: a
control on one path, absent on the second.)

**Incremental NVD.** `--since` sends `lastModStartDate`/`lastModEndDate`,
capped at NVD's documented 120 days, falling back to a full pull past that.
Two things that are not obvious:

- *Delta pages need their own filenames.* Writing 300 changed records to
  `nvd-000000.json` deletes 2,000 unchanged ones from the next build. A
  refresh that shrinks the database is the worst kind of refresh.
- *The resume cursor is scoped to a pull mode.* A delta's index 2000 is not
  a full pull's index 2000. The checkpoint records `mode` and the active
  window, and a cursor from the other mode is discarded rather than reused.

**Staleness is per feed.** `resolver.describe()` reports each feed against
its own refresh rate — EPSS 7 days, KEV 14, NVD 30 — and names the stale one.
A single build date can be true and useless simultaneously: "built
yesterday" while EPSS is three months old.

## Applying this to CVE → ExploitDB → command

The sketch, so it does not get re-derived:

- **Source.** `files_exploits.csv` from the ExploitDB repo. `fetch.py`
  already downloads it and records a sha256; nothing parses it yet beyond
  the index loader in `catalog.py`.
- **Schema.** `exploit(edb_id PK, title, path, type, platform, port,
  verified, date)` and `exploit_cve(edb_id, cve_id)` with an index on
  `cve_id`. The join table matters: one exploit can carry several CVEs and
  one CVE can have many exploits.
- **Licence.** Unresolved, and flagged in COMMAND-MAPPING.md. Check before
  redistributing any bundled index.
- **The boundary is unchanged.** This corpus stores *identifiers, titles and
  paths* so an analyst can `searchsploit -x` them. It does not store exploit
  code, and the command builder composes up to the parameter check, not
  past it.
