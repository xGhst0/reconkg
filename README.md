# reconkg

A vulnerability triage tool. It takes what a scan already found, works out
which CVEs plausibly apply, tells you how confident it is and why, and gives
you the commands to check for yourself.

It does not scan anything, and it does not exploit anything.

## Install on Kali

```bash
git clone https://github.com/xGhst0/reconkg && cd reconkg && pip install -e . --break-system-packages && python -m reconkg.selfcheck
```

That last step reports what it can and cannot see: whether nmap's `script.db`
was found, which corpora are configured, and how many realistic fingerprints
actually produce a lead. Run it first. Out of the box the answer is "nine
hand-written CVEs", and `selfcheck` says so rather than letting you assume
otherwise.

## Getting a real corpus

The nine built-in entries are a demonstration fixture. For anything real:

```bash
export NVD_API_KEY=...          # free: https://nvd.nist.gov/developers/request-an-api-key
python -m reconkg.fetch  --dest ~/.reconkg/feeds --all
python -m reconkg.builddb --feeds ~/.reconkg/feeds --out ~/.reconkg/vuln.db

export RECONKG_VULN_DB=~/.reconkg/vuln.db
export RECONKG_EXPLOIT_DB=~/.reconkg/exploits.db
export RECONKG_SCRIPT_DB=/usr/share/nmap/scripts/script.db
```

The API key is optional and buys speed, nothing else. NVD is ~381,000 CVEs
paged at 2000, so about 190 requests: roughly half an hour throttled to the
unkeyed 5-per-30s, and under ten minutes keyed. It checkpoints, so an
interrupted pull resumes. `--since` pulls only what changed.

If a key is rejected, NVD answers **404 with a `message: Invalid apiKey`
header** rather than 401 — a bare 404 against an endpoint that is up means
the key, not a moved URL.

If a corpus variable is set and the file cannot be opened, reconkg refuses to
start. Quietly serving nine entries when you asked for 300,000 would mean a
scan that finds nothing and looks like it worked.

## Use it

```bash
python -m reconkg.app        # serves http://127.0.0.1:8765/ui
python -m reconkg.console    # REPL
```

`app` binds loopback only, with no flag to change it. This process holds your
scan results and issues commands aimed at hosts you are testing; an SSH
tunnel is a small price next to having that reachable from the rest of the
network. `--port` moves it, `RECONKG_PORT` sets a default.

**Authentication.** Every route needs `Authorization: Bearer <token>`, from
`RECONKG_TOKENS` in the form `name:role:token` (roles: `viewer`, `scanner`,
`operator`, `admin`; tokens at least 16 characters). If it is unset, `app`
mints one for that process only and prints it at startup — not written to
disk, different every restart.

A browser cannot attach a header to a plain navigation, so opening `/ui`
directly will 401. Use a header-injecting extension, or drive the API:

```bash
export RECONKG_TOKENS="me:admin:$(openssl rand -hex 16)"
curl -H "Authorization: Bearer ${RECONKG_TOKENS##*:}" \
     http://127.0.0.1:8765/api/corpus
```

The UI shows the knowledge graph with provenance on click, so you can see
*why* a CVE was attached to a host rather than trusting a score, and a ledger
ordered by triage priority with KEV and EPSS weighed in.

## What it will and will not hand you

Every suggested command carries an [NSE
category](https://nmap.org/book/nse-usage.html) describing what running it
does to the target. That vocabulary is nmap's, not invented here.

| Category | What reconkg does |
|---|---|
| `safe`, `discovery`, `version` | composed, shown by default |
| `intrusive`, `vuln`, `unclassified` | composed, shown when you tick the box, with the authorisation warning |
| `exploit`, `dos`, `fuzzer`, `brute` | **named, never composed** |

The last row is the boundary. If a working exploit exists for a lead,
reconkg tells you the module or template and where to find it. It does not
assemble that into an invocation with your target already in it. Metasploit
suggestions stop at `show options` — the step where you read RHOSTS back and
confirm it is the host you are authorised against.

That is one keystroke of difference on a box you own, and a much larger
difference in what the tool is.

Safety is classified per *check*, never per tool. That is not fussiness:
current nuclei CVE templates achieve detection **by exploiting** — one posts
a `subprocess.run('cat /etc/passwd')` payload through a Langflow RCE and
matches on `root:.*:0:0:`. Anything that assumes "nuclei detects, Metasploit
exploits" is wrong at the first template it meets, so nuclei is treated as
unclassified and sits behind the opt-in.

## Honest limits

- **Version inference is blind to backporting.** RHEL and Debian patch in
  place without changing the version string, so a version match is not a
  patch-level match. Leads say so.
- **Most boxes do not fall to a version→CVE path.** Web logic flaws,
  credential reuse, SUID/sudo misconfiguration and AD abuse have no CVE to
  match, and no corpus size changes that. `selfcheck` prints the real hit
  rate rather than a flattering one.
- **A stale corpus under-reports silently.** Every CVE published since the
  last build is simply absent, reported with the same confidence as a true
  negative. `describe()` marks a corpus stale past 30 days and names which
  feed is old.

## Development

Kali is PEP 668 externally-managed, so install into a virtualenv rather than
over the system interpreter. Kali's own Python tooling is built against the
packaged pytest and pydantic, and upgrading those underneath it is not a
trade worth making for a test run.

```bash
python3 -m venv .venv && source .venv/bin/activate
make install     # editable install with dev extras
make test        # full pytest suite
make check       # test + the mutation harness
```

`make install` is `pip install -e ".[dev]"`. The dev extra is not optional
decoration — `pytest-asyncio` drives most of this suite, and a run without it
reports every async test as broken code rather than as a missing plugin.
`required_plugins` in `pyproject.toml` now stops the run with one line
instead of failing seventy-odd tests that are fine.

To install over the system interpreter anyway, the Makefile has the hook:

```bash
make install PIP_FLAGS=--break-system-packages
```

The benchmarks are scripts, not modules — there is no `audit/__init__.py`:

```bash
python audit/mutation.py            # mutation testing
python audit/scale_bench.py         # corpus scale benchmark
```

`docs/` carries the design notes and the reasoning behind the decisions
above. `audit/AUDIT.md` is the finding record: 47 findings across ten
adversarial rounds, including an analysis of the one bug shape that accounts
for 13 of them and an honest assessment of what has and has not prevented it.

## Licence

MIT — see `LICENSE`.

reconkg ships no vulnerability data. The corpora are built on your machine
from feeds you fetch yourself, which keeps their licences yours to honour;
ExploitDB's index in particular is GPL-2.0-or-later and is deliberately never
redistributed here.

## Use it on things you are allowed to touch

Everything reconkg emits is a suggestion for a human to run. Running
`intrusive` or `vuln` checks against a system you do not own or have written
authorisation to test is illegal in most jurisdictions.
