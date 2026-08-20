# reconkg — contributor brief

Read this before writing a line. It is the shared context for everyone
working this cycle.

## What the system is

An asset knowledge-graph and vulnerability-lead coordinator for lab and CTF
work. It ingests **evidence other tools produced** (parsed nmap XML, POSTed
JSON), builds a provenance-tracked graph, and produces a ranked
attack-surface ledger for a human to act on.

**It opens no connections to targets and contains no exploitation code.**
That is a structural property, not a policy toggle: `tests/test_reconkg.py`
traps `socket.socket.connect` during a full pipeline run, and the gap planner
routes vulnerability leads to `handoff` with `module=None` rather than to any
executable slot. Do not add outbound scanning, exploit execution, or payload
delivery. If a task seems to need it, stop and say so.

## Layout

```
reconkg/
  models.py       graph nodes; provenance; confidence arithmetic
  store.py        the ONLY writer to the graph; emits ChangeEvents
  engine.py       stage pipeline, fallback routing, correlation
  stages.py       DiscoveryStage interface + the offline evidence boundary
  modules.py      module system: metadata, typed options, registry
  builtin_modules.py  the shipped stages as declared modules
  planner.py      gap analysis -> "which module closes this gap"
  vulnref.py      version comparison, CVE matching, lead scoring
  catalog.py      Exploit-DB / Metasploit *index* loading (metadata only)
  handoff.py      renders a lead into operator lookups + msf one-liner
  importers.py    nmap XML -> evidence (offline)
  auth.py         credentials, roles, per-target scope, address validation
  sources.py      per-tool reliability ceilings
  ratelimit.py    per-principal token buckets
  persistence.py  SQLite snapshot save/load  (NOT yet wired to anything)
  events.py       WebSocket fan-out
  app.py          FastAPI surface
audit/
  AUDIT.md        seven rounds of findings, RC-01..RC-22
  mutation.py     targeted mutation harness
  attack_poc.py   red-cell proof-of-concepts
tests/            363 tests; fixtures/ holds REAL nmap 7.80 output
```

Run from the repo root: `python3 -m pytest -q` (must stay green).
Mutation: `python3 audit/mutation.py <module>`.

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

## The standing question

Three times this project shipped a control on one path and missed the second:

```
RC-04 -> RC-07   address validation: enforced in the API, not the importer
RC-03 -> RC-18   unbounded state: fixed twice, missed again on WS tickets
RC-14 -> RC-16   scope: enforced on writes, not on reads
```

Before you finish: **name the second path** for whatever you built. If a
control only runs on one route, say so explicitly in your final message even
if you fixed it.

## Style

Match the existing code. Four-space indent, ~79 columns, `from __future__
import annotations`, dataclasses or pydantic as the neighbouring module does,
module-level docstring explaining the design decision the module embodies.
Logging via `logging.getLogger(__name__)`, never print (except in the
console/demo, which are user-facing by design).
