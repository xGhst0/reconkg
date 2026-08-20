# reconkg — contributor brief

Read this before writing a line. It is the shared context for everyone
working this cycle.

## What the system is

An asset knowledge-graph and vulnerability-lead coordinator for lab and CTF
work. It builds a provenance-tracked graph from scan evidence and produces a
ranked attack-surface ledger for a human to act on. Evidence arrives three
ways: parsed nmap XML, POSTed JSON, and — new this cycle — a scan reconkg
ran itself.

**It runs reconnaissance. It does not run exploits.**

That boundary moved, and the new position has to be stated far more
carefully than the old one. "No outbound connections at all" was a single
predicate a test could check in one line. "Reconnaissance but not
exploitation" is a judgement, and judgements rot. So it is written out here
in full, and the things that enforce it are named.

**What reconkg may now do**

* Run **nmap** against an address the operator has declared, from the web UI
  or the API: fixed argv, no shell, an allowlisted flag set, and the target
  passed through `validate_address` and `require_scope` first.
* Fetch corpus data from NVD, CISA, FIRST and GitLab, as `fetch.py` always
  has.

**What reconkg must still never do**

* Execute an exploit, deliver a payload, or compose any command in the
  `exploit`, `dos`, `fuzzer` or `brute` tier. `NEVER_COMPOSED` used to decide
  what appeared on a screen. It now decides what *runs*, which raises its
  stakes rather than lowering them — read every change to `commands.py` in
  that light.
* Run anything the Metasploit hand-off names. That line still stops at
  `show options`; firing it is still the operator's own keystroke, and
  `test_oneliner_stops_short_of_firing` still asserts it.
* Send a packet outside the caller's scope. `validate_address` and
  `require_scope` were integrity controls protecting the graph. They are now
  the things that decide where traffic goes, so a bypass that used to mean
  "bad data" now means "scanned a host you were not authorised to touch".
  Findings against them are a severity higher than they were.

**The invariant narrowed, it did not disappear.** The correlation path is
still network-free: `engine.py`, `store.py`, `models.py`, `vulnref.py` and
everything they call open no sockets, and a test still enforces exactly that.
Only the runner may execute anything. If a *correlation* stage ever opens a
socket, that is still a bug — narrowing the assertion is not the same as
deleting it, and the narrowed one is the version worth keeping.

If a task seems to need exploitation, payload delivery, or a scan of
something outside scope: stop and say so.

## Layout

```
reconkg/
  models.py       graph nodes; provenance; confidence arithmetic
  store.py        the ONLY writer to the graph; emits ChangeEvents
  engine.py       stage pipeline, fallback routing, correlation
  stages.py       DiscoveryStage interface + the evidence boundary
  modules.py      module system: metadata, typed options, registry
  builtin_modules.py  the shipped stages as declared modules
  planner.py      gap analysis -> "which module closes this gap"
  vulnref.py      version comparison, CVE matching, lead scoring
  cpe.py          CPE parse/compare; the identifier match path
  commands.py     command classification and the composition tiers
  catalog.py      Exploit-DB / Metasploit *index* loading (metadata only)
  handoff.py      renders a lead into operator lookups + msf one-liner
  importers.py    nmap XML -> evidence
  push.py         an nmap XML -> a *running* coordinator, over its API
  runner.py       the ONLY module that may execute a scanner  (TO BUILD)
  auth.py         credentials, roles, per-target scope, address validation
  sources.py      per-tool reliability ceilings
  ratelimit.py    per-principal token buckets
  persistence.py  SQLite snapshot save/load
  snapshots.py    autosave / restore / retention on top of it
  observability.py  metrics, correlation IDs, JSON logs
  events.py       WebSocket fan-out
  console.py      msfconsole-style REPL (its own private store -- RC-8D)
  ui.py           the single-page UI, as a module-level string
  app.py          FastAPI surface
  --- corpora, all operator-run and offline once fetched ---
  fetch.py        downloads NVD / KEV / EPSS / ExploitDB
  builddb.py      those feeds -> indexed SQLite
  feeds.py        the per-feed parsers
  vulndb.py       corpus one: CVEs and applicability
  exploitdb.py    corpus two: the Exploit-DB index
  scriptdb.py     corpus three: nmap's script.db
  resolver.py     picks a corpus from the environment; describes its health
  selfcheck.py    measures the above against real data on this machine
audit/
  AUDIT.md        eleven rounds of findings, RC-01..RC-47 + PROP-01..05
  mutation.py     targeted mutation harness
  attack_poc*.py  red-cell proof-of-concepts
tests/            1227 tests; fixtures/ holds REAL nmap 7.80 output
```

Setup and test, from the repo root. Kali is PEP 668 externally-managed, so
use a venv — the system pytest is 8.x with no `pytest-asyncio` and reports
seventy-odd async tests as broken code rather than as a missing plugin:

```
python3 -m venv .venv && source .venv/bin/activate
make install     # pip install -e ".[dev]"
make test        # must stay green
make check       # test + mutation
```

Mutation on its own: `python3 audit/mutation.py <module>`.

## Non-negotiables

1. **Verify, don't assert.** Run what you write. "Should work" is not done.
2. **No invented APIs.** If a library interface is uncertain, check it. A
   fabricated method name is the least excusable failure here.
3. **Tests assert values, not directions.** A mutation pass found 47
   survivors because tests said "confidence goes up" and never "confidence
   is 0.88". Pin the numbers.
4. **Docstrings say *why*, not *what*.** The signature says what. Explain the
   trade-off, the failure it prevents, or the alternative rejected.
5. **Handle the unhappy path.** Errors, empty states, and hostile input are
   the deliverable, not polish.
6. **Bounded state.** Any dict keyed on something a caller influences needs a
   cap. This has been a finding twice (RC-03, RC-18).
7. **Secrets never in source**, including examples and tests.
8. **Do not edit files you do not own.** Your prompt names them. `app.py` is
   owned by the tech lead this cycle — if you need wiring there, describe the
   integration in your final message instead of doing it.
9. **One execution chokepoint.** If reconkg runs a command, it runs through
   `runner.py` and nowhere else. No `subprocess`, `os.system`, `os.exec*` or
   `shell=True` anywhere else in the tree, and a test asserts it. Thirteen of
   forty-seven findings are one control built on one path and forgotten on a
   second; an execution path is the worst conceivable place to learn that a
   fourteenth time. So there is exactly one path, and it has a name.
10. **Argv is a list, never a string.** No shell, no interpolation, and
   `shlex.quote` is not a defence — RC-32 established that quoting *correctly*
   is precisely what delivers a payload intact as a single argument. The fix
   is not to quote better; it is never to build a command line at all.

## The standing question

Thirteen of forty-seven findings are the same shape — a control, lookup or
normalisation built on one path and absent from a second:

```
RC-04 -> RC-07   address validation: enforced in the API, not the importer
RC-03 -> RC-18   unbounded state: fixed twice, missed again on WS tickets
RC-14 -> RC-16   scope: enforced on writes, not on reads
RC-07 -> RC-24   chokepoint intact; the traffic went around it
RC-43 -> RC-44   emptiness reported for the corpus, not for its feeds
```

Before you finish: **name the second path** for whatever you built. If a
control only runs on one route, say so explicitly in your final message even
if you fixed it.

This mattered when the worst case was a wrong ledger. Now that a control can
decide whether packets leave the machine, answer it before you write the
code rather than after.

## Style

Match the existing code. Four-space indent, ~79 columns, `from __future__
import annotations`, dataclasses or pydantic as the neighbouring module does,
module-level docstring explaining the design decision the module embodies.
Logging via `logging.getLogger(__name__)`, never print (except in the
console/demo, which are user-facing by design).
