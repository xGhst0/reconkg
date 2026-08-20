---
name: verify-on-kali
description: Run the reconkg test suite correctly and read the result honestly. Use before merging any branch, after pulling on the Kali box, or whenever a pytest run produces mass failures that look like broken code. Also covers building the CVE corpus and running selfcheck.
---

# Verifying reconkg

The authoring copy is on Windows and has no Python. The suite runs on Kali.
Every branch is therefore written blind and verified somewhere else, which
makes "did it actually run, and did I read the output correctly" the whole
job of this skill.

## Run the suite

Never run bare `python3 -m pytest` against the system interpreter. Kali is
PEP 668 externally-managed and its packaged pytest is 8.x with no
`pytest-asyncio`, which is not the environment this project declares.

```bash
cd ~/Desktop/reconkg
python3 -m venv .venv && source .venv/bin/activate
make install          # pip install -e ".[dev]"
make test             # python3 -m pytest -q
```

Confirm you are not on the system pytest before trusting any result:

```bash
python -c "import _pytest, sys; print(sys.executable); print(_pytest.__file__)"
```

If that prints `/usr/lib/python3/dist-packages/_pytest/__init__.py`, the venv
is not active and the run means nothing.

## Reading a failing run

Sort failures into these three buckets before concluding anything about the
code. Two of them are not code defects, and treating them as defects has
already cost one full debugging cycle.

**1. Environment, not code.** Dozens of failures reading `async def functions
are not natively supported`, plus collection errors mentioning
`PytestRemovedIn9Warning ... requested an async fixture`, plus warnings
`Unknown config option: asyncio_mode` and `Unknown pytest.mark.asyncio`.

That is one missing package, `pytest-asyncio`, reported once per async test.
`required_plugins` in `pyproject.toml` should now abort the run with a single
line instead — if you are seeing the seventy-failure version, you are running
a pytest old enough to ignore `required_plugins`, or an ini file is shadowing
`pyproject.toml`. Fix the environment; change no code.

**2. Host-dependent.** Kali ships real data that tests may accidentally pick
up: `/usr/share/exploitdb/files_exploits.csv`, nmap's `script.db`, and
`/usr/share/metasploit-framework/db/modules_metadata_base.json`. A test that
expects an empty index and finds a populated one is asserting against the
host rather than against a fixture. Check the setup log for `catalog` lines
reporting thousands of rows loaded. These are real bugs, but they are test
isolation bugs, not defects in the behaviour under test.

**3. Genuine.** Everything else. These are the only ones that mean the change
is wrong.

Report the three counts separately. "77 failed" is not a useful sentence when
74 of them are one `pip install`.

## Never report a number you did not produce

The one rule that matters here. Corpus sizes, hit rates, test counts and
mutation scores are all quantities this project has previously stated wrongly
from memory or from a stale README. If you did not run the command in this
session, say so instead of quoting a figure. The README's test count has been
wrong twice.

## Building the corpus and running selfcheck

The suite passing says nothing about whether the corpus landed. Those are
separate questions and the second one is the one that decides whether scans
find anything.

```bash
python3 -m reconkg.fetch --dest ~/.reconkg/feeds --nvd -v
ls ~/.reconkg/feeds/nvd/            # must contain nvd-*.json, not just a checkpoint
python3 -m reconkg.builddb --feeds ~/.reconkg/feeds --out ~/.reconkg/vuln.db
```

`-v` matters: without it a rate-limited or interrupted pull compresses to
"1 feed(s) failed" and the reason is lost. An unkeyed pull is throttled to 5
requests per 30s; `NVD_API_KEY` lifts that. The pull checkpoints and resumes.

Two traps, both of which have already happened here:

- `fetch_nvd` creates `~/.reconkg/feeds/nvd/` **before** its first request, so
  a pull that fails immediately leaves an empty directory that the build will
  happily record as a feed. Always check the directory holds page files.
- Resume trusts `_checkpoint.json` without checking the pages it claims to
  have written still exist. If the checkpoint shows a non-zero `next_index`
  and the directory has no `nvd-*.json`, delete the checkpoint or pass
  `--no-resume`, or the pull silently fetches only the tail.

Then:

```bash
export RECONKG_VULN_DB=~/.reconkg/vuln.db
export RECONKG_EXPLOIT_DB=~/.reconkg/exploits.db
export RECONKG_SCRIPT_DB=/usr/share/nmap/scripts/script.db
python3 -m reconkg.selfcheck
```

A corpus reporting `EMPTY corpus ... 0 CVEs` means the build produced nothing
regardless of what the per-feed ages say. Read the feed line for `EMPTY
feeds:` to see which one did not land.

## Before merging

`make check` runs the suite plus the mutation harness, and is what CI runs.
A branch goes to `main` only after a clean run on this machine, because CI
uses a clean interpreter with the dev extras always installed and therefore
cannot reproduce the two environment classes above.
