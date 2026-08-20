# Cycle 8 — whiteboard

```
                        ┌─────────────────────────────┐
                        │  WHAT reconkg IS TODAY      │
                        │  363 tests · mutation 100%  │
                        │  7 audit rounds · RC-01..22 │
                        └──────────────┬──────────────┘
                                       │
   evidence in            ┌────────────┴────────────┐          operator out
   (nmap XML, POST)  ───► │  store → engine → graph │ ────►  ledger + plan
                          │  provenance · confidence│         + handoff
                          └────────────┬────────────┘         (msf one-liner)
                                       │
                        ┌──────────────┴──────────────┐
                        │  GAPS THIS CYCLE CLOSES     │
                        └─────────────────────────────┘

  ①  no pyproject / no declared deps   → defusedxml undeclared caused RC-22
  ②  persistence exists, unwired       → snapshot code nothing calls
  ③  no operator console               → REST-only; the msfconsole feel is missing
  ④  no observability                  → 22 findings, zero metrics, no correlation IDs
  ⑤  no token rotation                 → expiry landed; revocation did not
```

## The cycle

```
 PHASE 1  BUILD  (4 agents, parallel, disjoint NEW files)
 ─────────────────────────────────────────────────────────────────────
   devops        pyproject.toml, requirements*.txt, Makefile, CI
   snapshots     reconkg/snapshots.py     autosave / restore / retention
   console       reconkg/console.py       msfconsole-style REPL
   observability reconkg/observability.py structured logs, metrics, IDs

 PHASE 2  INTEGRATE  (tech lead, sequential — app.py is shared)
 ─────────────────────────────────────────────────────────────────────
   wire the four modules into app.py; add token rotation/revocation
   full suite + mutation must stay green

 PHASE 3  ATTACK  (2 agents, parallel, read-mostly)
 ─────────────────────────────────────────────────────────────────────
   QA            adversarial tests against the new surface
   Red Cell      RC-23+ : attack the console, metrics, snapshots, rotation

 PHASE 4  SIGN-OFF  (tech lead)
 ─────────────────────────────────────────────────────────────────────
   fix confirmed findings, re-run everything, update AUDIT.md
```

## Why these five, in this order

**① packaging first** because it is the *root cause* of RC-22, not just a
convenience. `defusedxml` was never declared, so the hardened parser path was
never the one that ran, and the fallback rejected every real nmap file. A
dependency you rely on and do not declare is a bug waiting for a fresh
machine.

**② snapshots** because `persistence.py` currently is code nothing calls. It
has tests and no callers, which is the most flattering possible state for a
module and the least useful.

**③ console** because the whole module system — rank, references, typed
options, `info` rendering — was built for an operator surface that does not
exist yet. It is currently metadata with no reader.

**④ observability** because seven audit rounds produced twenty-two findings
and the system still cannot tell you how many scans ran, how many leads were
disputed, or which principal is hammering the ingress. Every finding so far
was found by reading code, never by watching the system.

**⑤ rotation** because expiry without revocation means a leaked token is
valid until its date, and the only remedy is a restart.

## The standing question

Three times this project has shipped a control on one path and forgotten the
second (RC-04→07 validation, RC-03→18 unbounded state, RC-14→16 scope). Every
agent this cycle carries the same instruction: **name the second path.**
