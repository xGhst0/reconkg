# Red Cell audit — reconkg coordinator

Scope: our own code, run on localhost. Seven PoCs in `audit/attack_poc.py`,
each executed against a live uvicorn instance before and after remediation.

## Threat model

The coordinator holds a knowledge graph an analyst makes decisions from. Its
value to an attacker is not the data — it's **the ability to write to it**.
Anyone who can influence the graph controls which findings an analyst chases
and which they ignore. That makes evidence integrity, not confidentiality,
the primary security property. Everything below follows from that.

## Findings

| ID | Severity | Location | Flaw | Status |
|----|----------|----------|------|--------|
| RC-01 | **Critical** | `app.py` `put_evidence`, `engine._apply_one` | Submitter declared its own `confidence`, written verbatim onto provenance. A fabricated host produced a 0.66-priority weaponised lead with no scan ever having run. | Fixed |
| RC-01b | **Critical** | `models.GraphNode.observe` | Independence was keyed on `source_tool`, a caller-supplied string. One actor posting under three invented tool names compounded two 0.30 claims past the 0.45 correlation floor. | Fixed |
| RC-02 | **High** | `engine._apply` | Only `KeyError` was caught. A port number of 99999 raised `ValidationError`, escaping stage isolation, the slot loop and `run()` → HTTP 500, no ledger. One hostile integer disabled a target. | Fixed |
| RC-03 | **High** | `models`, `store`, `app` | `provenance_log`, `event_log` and `reports` were unbounded. 40 rescans grew the event log from 21 to 660 entries; nothing evicted. | Fixed |
| RC-04 | **Medium** | `app.TargetIn` | `address` accepted any 1–253 characters — CRLF, `<script>`, `../../etc/passwd` — then interpolated into event paths broadcast to every analyst window. | Fixed |
| RC-06 | **High** | all routes, `/ws` | No authentication anywhere. Anonymous read of the whole graph and anonymous write to the evidence ingress. | Fixed |
| RC-05 | Low | `engine._downgrade`, `_correlate` | Read-iterate-await over live graph lists during concurrent scans. **Not reproduced** at 8 concurrent scans; hardened regardless. | Hardened |

## Root cause

RC-01 and RC-01b are one bug wearing two hats: **the system accepted an
identity claim and a credibility claim from the same untrusted party**. The
confidence model was sound in isolation — noisy-OR over independent sources
is the right arithmetic — but it was fed inputs the submitter controlled, so
it computed a correct answer from forged premises.

The fix separates three things that had been conflated into one string:

- `principal` — **who**, from the authenticated credential, never the body.
  Independence is measured here.
- `source_tool` — **what**, a label. Selects a reliability ceiling.
- `confidence` — **how sure that tool claims to be**, advisory. Multiplied by
  the operator-registered ceiling for that tool, so a caller can lower its own
  confidence but never raise it.

Unregistered tools are capped at 0.25, deliberately below the 0.45
correlation floor. Unknown tooling can populate the graph; it cannot
manufacture a lead by itself.

## Remediation

- `sources.py` — operator-controlled reliability registry; declared confidence
  clamped, never trusted.
- `auth.py` — bearer credentials from `RECONKG_TOKENS` only. No default token,
  no dev-mode fallback: with the variable unset the app refuses to start. Two
  principals may not share a credential, or independence accounting is a lie.
  Address validation rejects by character class at ingress, so hostile strings
  never enter the graph and no downstream consumer has to remember to escape.
- `models.py` — independence on `principal`; provenance log bounded head+tail
  with an `elided_observations` counter rather than silent truncation.
- `engine.py` — per-observation rejection of malformed input; per-target scan
  lock; defensive copies while iterating the graph.
- `store.py` — event log is a ring buffer; `add_hostnames` restores the
  single-writer invariant the API handler was bypassing.

## Verification

67 tests pass. `tests/test_audit_regressions.py` carries one regression per
finding, each failing against the pre-audit code. Comparator fuzzing: 4000
random strings through `parse_version` without an unexpected raise, and 1000
digit-free banners confirmed never to satisfy a version constraint — a
versionless string matching would silently mark every unparseable service as
vulnerable.

Post-fix PoC run, all seven closed:

```
RC-01    declared 1.0 -> effective priority 0.441, principals ['scanner']
RC-01b   three tool labels from one principal -> lead=None
RC-02    scan returned HTTP 200
RC-02b   scan returned HTTP 200
RC-03    retained 65 -> 704 (cap 5000); provenance_log = 40 (cap 50)
RC-04    0/4 hostile addresses accepted
RC-06    anonymous GET /api/targets -> HTTP 401
```

## What this audit did not cover

- **Persistence.** Still in-memory; a restart loses the graph. Unreviewed
  because it doesn't exist yet.
- **Authorisation.** Authentication is in; there are no roles. Any valid
  credential can write evidence for any target. A read-only analyst token
  is the obvious next control.
- **Token lifecycle.** No rotation, expiry, or revocation. Static
  environment tokens are appropriate for a lab and not for anything else.
- **Contradiction detection.** The graph holds mutually exclusive claims at
  separate confidences and never flags the conflict. An attacker who cannot
  forge corroboration can still add plausible noise.

---

# Round 2 — surface added after the first audit

Scope: scan importers, availability catalogue, third-party module loading.
Four findings, all confirmed against a live instance and all fixed.

| ID | Severity | Location | Flaw | Status |
|----|----------|----------|------|--------|
| RC-07 | **Critical** | `importers._host_address` | The importer never validated addresses. `<address addr="10.0.0.1&#10;X-Injected: yes">`, `<script>alert(1)</script>` and `../../../etc/passwd` all became graph keys and event paths broadcast to every analyst window. | Fixed |
| RC-08 | **Medium** | `importers.parse_nmap_xml` | No cap on hosts or ports. A 5000-host file imported without complaint; nothing stopped a 5,000,000-host one. | Fixed |
| RC-09 | Low | `catalog.load_exploitdb` | An oversized CSV field surfaced as a raw `_csv.Error` escaping the loader, and titles were unbounded. | Fixed |
| RC-10 | **Medium** | `modules.load_path` | Executed every `.py` in a directory, with the danger noted only in a docstring. A `loadpath` typo pointing at `~/Downloads` was a one-word mistake. | Fixed |

## RC-07 is the interesting one

It is RC-04 again, six commits later, through a door that did not exist when
RC-04 was fixed. That is the lesson worth keeping: **validating per-ingress
loses**. Every new entry point is a new chance to forget, and the importer
was written by someone (me) who had read the RC-04 fix and still did not
carry it across.

The fix moves validation onto `TargetStore.ensure_host`. The store is the
only writer to the graph, so a future importer that forgets cannot poison it.
`test_rc07_store_refuses_a_hostile_address_from_any_caller` asserts the
chokepoint directly rather than testing the importer's manners.

## Open, and worth doing next

- **Index integrity.** `infer_maturity` trusts `~/.msf4/store/modules_metadata_base.json`
  and `files_exploits.csv` as they sit on disk. Anyone who can write those
  files controls lead ranking. No integrity check, no staleness warning.
- **Token in the WebSocket query string.** Browsers cannot set headers on a
  WS handshake, so `?token=` is supported — and query strings land in proxy
  logs, server access logs, and browser history. A short-lived ticket
  exchanged over REST would fix it.
- **No rate limiting on `/api/evidence`.** Bounded payloads and bounded
  retention exist; request rate does not.
- **No authorisation tiers.** Still true from round 1: any valid credential
  can write evidence for any target.

---

# Round 3 — the trust dependencies I introduced

Two of round 2's open items are now closed, plus the correlation wiring they
were blocking.

## RC-11 — index integrity (was: open)

`infer_maturity` reads `files_exploits.csv` and `modules_metadata_base.json`
straight off disk and lets them decide how leads rank. That trust cannot be
removed — they are the operator's own files — but it can be made **visible**,
which is the difference between a compromise and an undetected one.

- Every load records `IndexProvenance`: sha256, size, mtime, entry count.
- `write_lockfile()` pins the digests; `verify_lockfile()` raises
  `IndexChanged` on a mismatch. Strict by default: a swapped index means every
  maturity judgement downstream is attacker-chosen, which should stop a run
  rather than colour a log line nobody reads.
- Indexes older than 90 days are flagged. A stale index reports "nothing
  known" for anything newer, and the caller cannot tell that apart from a
  genuinely unexploited CVE — silence that looks like safety.
- `GET /api/catalog` exposes all of it, because an operator reading a ledger
  should be able to see what the ranking was based on.

Verified by tampering: rewriting the msf index to point a different CVE at a
fabricated module is caught on the next `verify_lockfile`.

## RC-12 — WebSocket credential in the query string (was: open)

Browsers cannot set an `Authorization` header on a WS upgrade, so `?token=`
existed for a real reason — and query strings land in proxy logs, access logs
and browser history. Raw tokens are no longer accepted there. `POST
/api/ws-ticket` mints a 60-second, single-use ticket instead. Leaking one
costs a one-minute replay window against a socket you already opened, not
your standing credential. Replay is refused; expiry is refused.

## Correlation now consumes availability

`build_leads` takes an optional catalogue. An entry's hand-declared maturity
is upgraded by what is actually indexed on this machine, never downgraded,
and the ledger records which it was:

```
CVE-2021-41773  maturity weaponised  from index  priority 0.735
availability: EDB-50383, exploit/multi/http/apache_normalize_path_rce
```

`maturity_source` distinguishing `declared` from `index` matters: a number
someone typed into a reference table and a number derived from observed
tooling deserve different weight, and collapsing them would hide which one
you are looking at.

## Still open

- **Authorisation tiers.** Unchanged since round 1, and now the oldest debt
  in the file: any valid credential can write evidence for any target.
- **Rate limiting** on `/api/evidence`.
- **Persistence.** Still in-memory.
- **Contradiction detection.** The graph holds mutually exclusive claims at
  separate confidences and never flags the conflict.
- **Golden-file parser tests.** Every nmap fixture is one I wrote, so the
  parser is only tested against XML shaped the way I imagined it. Real files
  from several nmap versions would be worth more than another twenty
  synthetic cases.

---

# Round 4 — RC-13: authorisation tiers

The oldest item in this file, open since round 1. Authentication proved *who*
was calling; nothing constrained *what they could do*. Any valid credential
could write evidence for any target and invent new targets at will.

## Tiers

`RECONKG_TOKENS` entries are now `name:role:token`:

| Role | Can |
|------|-----|
| `viewer` | read the graph, ledger, plan, modules, catalogue; open a WebSocket |
| `scanner` | + submit evidence, run a scan |
| `operator` | + define targets |
| `admin` | reserved for trust configuration |

The split follows **who may change what the graph believes**. Evidence
submission and scope definition are deliberately separate: an unattended
scanner box in a lab is the credential most likely to leak, and a leaked
scanner token should not be able to invent new targets to point the system at.

## Compatibility

The two-field `name:token` form still parses and grants `operator`, with a
warning every start. Silently downgrading a working deployment to read-only
would present as a broken scanner rather than as a policy change, and the
person debugging it would be looking in the wrong place.

## 403 vs 401

Kept distinct on purpose. 401 means the credential is wrong — go find a good
token. 403 means the credential is real and the role is wrong — that is a
config fix, and conflating the two sends the operator hunting for the wrong
problem.

Verified live:

```
operator creates target : 201
scanner creates target  : 403  role 'scanner' cannot perform this action;
                               'operator' or higher required
viewer submits evidence : 403
scanner submits evidence: 201
viewer scans            : 403
scanner scans           : 200
viewer reads ledger     : 200
no credential           : 401
```

190 tests pass.

## Still open

- **Per-target scoping.** Roles are global: a scanner may submit evidence for
  *any* target, not a defined subset. That is the next tightening, and it is
  the one that would actually contain a leaked lab credential.
- **Rate limiting** on `/api/evidence`.
- **Persistence.** Still in-memory.
- **Contradiction detection.**
- **Golden-file parser tests** against real nmap output.

---

# Round 5 — final Red Cell pass

Target: everything added in rounds 3 and 4 (scoping, roles, rate limiting,
tickets). Six probes, four confirmed, all fixed and re-verified.

| ID | Severity | Flaw | Status |
|----|----------|------|--------|
| RC-16 | **High** | Scope covered writes only. A principal restricted to `10.10.10.0/24` could read any host in the graph, list every target, and subscribe to the live event stream for all of them. | Fixed |
| RC-17 | **Medium** | `/scan` was exempt from the rate limiter — and it is the expensive endpoint, running the whole pipeline and re-correlating. The cheap operation was throttled; the costly one was not. | Fixed |
| RC-18 | **Medium** | Unredeemed WS tickets accumulated without bound: 5000 issuances retained 5000 entries. Expiry is not a cap when issue rate exceeds TTL. | Fixed |
| RC-19 | Low | `TargetStore.subscribe`'s unsubscribe raised `ValueError` on a second call, so a double `ConnectionManager.shutdown()` blew up during teardown. | Fixed |
| RC-5A | — | Attempted scope bypass via octal/hex/decimal/trailing-dot address spellings. **Not exploitable**: scope is checked on the normalised address. Regression tests added. | No finding |
| RC-5C | — | Attempted rate-limit bypass by rotating the target address. **Not exploitable**: the bucket is keyed on principal, not target. | No finding |

## RC-16 is the one worth remembering

Scope was implemented for writes because that is where the obvious damage is
— poisoned evidence, invented targets. But **read access is how you learn
what to attack.** A leaked lab credential that can enumerate every host in
the engagement, watch scans land in real time, and read the ranked ledger has
lost most of what the scope was for, even if it can never write a byte
outside its subnet.

The subtle half was the WebSocket. Blocking `?target=` for out-of-scope
addresses is obvious; the leak was connecting with *no* filter and receiving
the firehose. Scope is now a predicate on the session itself, so an
unfiltered subscription is silently narrowed rather than broadened.

## Post-fix verification

```
RC5-A scope bypass via encoding      no bypass (normalised before check)
RC5-B read out-of-scope host         403
RC5-B host listing                   ['10.10.10.42']   (was: all hosts)
RC5-C rate limit across repeats      [201, 201, 429, 429]
RC5-D scan endpoint limited          {429}             (was: {200})
RC5-E out-of-scope subscription      refused
RC5-F outstanding tickets            512               (was: 5000, uncapped)
```

233 tests pass.

## Handed back to the operator — still open

Nothing here is a blocker for lab use. All of it is real.

- **Persistence.** Still in-memory; a restart loses the graph. The largest
  remaining gap and the one with no security dimension at all.
- **Token lifecycle.** No rotation, expiry, or revocation for the standing
  bearer credentials. Static environment tokens suit a lab and nothing else.
- **Contradiction detection is passive.** The planner now surfaces conflicting
  credible claims, but correlation still builds leads off both sides. It
  should probably discount them until resolved.
- **Golden-file parser tests.** Every nmap fixture is one I wrote. The parser
  is tested against XML shaped the way I imagined it, which is the weakest
  evidence in the suite.
- **Mutation testing.** 233 tests constrain the code as far as anyone has
  checked, and nobody has checked. A mutation run would say whether they
  actually pin behaviour or merely execute it.

---

# Round 6 — closing the open list

Everything the Red Cell left open is now either fixed or explicitly declined
with a reason. Plus the operator-requested Metasploit one-liner.

## Metasploit one-liner

`handoff` now emits a pre-filled msfconsole line when — and only when — a
module for that CVE exists in the local index:

```
msfconsole -q -x 'use exploit/multi/http/apache_normalize_path_rce;
                  set RHOSTS 10.10.10.42; set RPORT 80; show options'
```

Two constraints, both load-bearing:

- **Nothing guessed.** The module name comes from `modules_metadata_base.json`
  on this machine. No catalogue, no one-liner — a fabricated path that
  half-matches a CVE costs an operator an afternoon and teaches them to
  distrust the tool.
- **Stops at `show options`, not `run`.** You land in the module fully
  configured; firing is your keystroke. Composing `; run` per-lead would make
  this an auto-exploitation chain with a paste as the last step, and the
  per-lead judgement is precisely the part worth keeping human — it is where
  you notice the version rests on one unverified banner, or that the host is
  out of scope. `test_oneliner_stops_short_of_firing` asserts it.

## RC-21 — contradiction detection was passive

The planner surfaced conflicting credible claims while correlation went on
ranking both sides at full priority, so the ledger still read confident. At
most one of two contradictory versions is right, so at least half of what is
ranked on them is wrong. Disputed leads now take a 0.5 multiplier, carry
`disputed: true`, and say `DISPUTED` in the rationale and hand-off caveats.

## RC-20 — token lifecycle

Standing credentials had no lifetime. A lab token pasted into a scanner unit
file outlives the engagement it was cut for. Entries take an optional
`@YYYY-MM-DD`, checked at resolve time. Absent expiry is still unlimited —
now a visible choice rather than the only option.

## Persistence

SQLite, snapshot rather than ORM. `TargetStore` stays the single in-memory
writer and the engine is untouched, so the hot path is as fast and as tested
as it was. Schema is versioned and refuses to open a newer database rather
than misreading columns; a corrupt row is skipped, not fatal.

The trade is stated plainly: a snapshot is point-in-time, so a crash between
snapshots loses what happened since. The alternative — threading a session
through every mutation in `store.py` — is where the concurrency bugs would
live, and this is a lab coordinator.

## Not done, and why

- **Golden-file parser tests.** nmap is not installable in this sandbox, so
  every fixture is still one I wrote and the parser remains tested only
  against XML shaped the way I imagined it. This is the weakest evidence in
  the suite and it did not improve this round. Run one real scan, drop the
  XML in `tests/fixtures/`, and it is fixed.
- **Mutation testing.** `mutmut` installs but a meaningful run takes far
  longer than this session allows. 255 tests constrain the code as far as
  anyone has checked, and nobody has checked.

## Pattern worth carrying forward

Across six rounds the same shape recurred: a control built on one path and
forgotten on the second.

```
RC-04 -> RC-07    address validation: API but not the importer
RC-03 -> RC-18    unbounded state: fixed twice, missed on tickets
RC-14 -> RC-16    scope: writes but not reads
```

Each was found by attacking the fix rather than the original. Assume a fourth
instance exists that nobody has looked for yet — the productive question on
any new control is "where is the second path?"

255 tests pass.

---

# Round 7 — the two items I had left undone

Both were listed as "not done, and why". Both are now done, and both found
real bugs, which is the argument for not accepting "sandbox limitation" as an
answer too quickly.

## Golden fixtures — and the critical bug they found

nmap was not installable via `apt-get install` (no root), but `apt-get
download` plus `dpkg -x` into a local prefix works. Six fixtures in
`tests/fixtures/` are genuine nmap 7.80 output against live listeners:
version detection, port scan without `-sV`, IPv6, host-discovery-only, an
NSE script run, and a down host. `regenerate.py` documents the commands.

They found this on the first run:

> **Every real nmap file opens with `<!DOCTYPE nmaprun>`, and the XXE
> hardening rejected any document containing `<!DOCTYPE`.** On any machine
> without `defusedxml` installed -- the default, since nothing declared it --
> the importer refused 100% of genuine nmap output while the entire test
> suite passed, because every fixture I had written omitted the doctype line.

The guard now refuses what is actually dangerous -- entity declarations, an
internal subset, an external SYSTEM/PUBLIC identifier -- and lets a bare
doctype through. `unsafe_doctype_reason()` is split out and tested directly
against all six real files.

Two more, smaller:

- **`nmap -sn` hosts were dropped.** A host-discovery run has no `<ports>`
  element; the importer skipped any host with no ports and no services, so a
  ping sweep imported nothing and gave no reason. Live hosts are now recorded
  with `discovered_only` noting why they carry no port data.
- **`tcpwrapped` was treated as an identification.** It is nmap declining to
  identify. Recording it at probe confidence let a non-answer look like a
  finding; it is now capped at 0.2 and marked ambiguous.

## Mutation testing — including a broken harness

`audit/mutation.py` mutates the decision functions by AST rewrite and checks
the tests notice. It reported **100% on the first run, and that number was a
lie**: the subprocess environment was built by hand and dropped the
site-packages containing pytest, so every mutant "died" on a startup failure.

Caught by pointing the harness at tests that could not possibly cover the
mutated function and demanding survivors. It now inherits the environment,
runs an unmutated baseline first, and refuses to report at all if the
baseline does not pass.

Honest numbers followed, and they were not flattering:

```
                     before        after
vulnref               65.9%        100%
models                74.2%        100%
auth                  65.4%        100%
catalog               81.8%        100%
sources               60.0%        100%
ratelimit             70.0%        100%
importers             76.2%        100%
                  ---------------------
                  111/158        154/158 + 4 equivalent
```

47 survivors, all the same shape: **the tests asserted directions, never
arithmetic.** "Corroboration raises confidence" passes whether the bonus is
1.125 or 2.125. The entire `_corroboration_bonus` formula, the CVSS divisor,
the version penalty, the provenance cap arithmetic, and every rounding call
were unpinned -- constants that decide how a ledger ranks, checked by nothing.
`tests/test_exact_behaviour.py` (77 tests) pins the numbers.

Four mutants are recorded as **equivalent** in `EQUIVALENT`, each with a
justification that can be falsified: an unreachable clamp, a boundary where
both branches compute the same state, a comparison over a weight table with
no collisions, and a rounding call no reachable input can exercise. Listing
them beats both chasing an impossible 100% and quietly counting them as
failures.

363 tests pass. Mutation score 100% on the decision logic, with the harness
itself verified against a deliberately inadequate test set.

---

# Round 8 — the four modules cycle 8 added

Scope: `observability.py` (metrics, correlation IDs, JSON logs),
`snapshots.py` (autosave, restore, retention), `console.py` (operator REPL)
and the `app.py` integration, plus the new `host.updated` event in
`store.py`. Twelve probes, eight confirmed, four negative. All are in
`audit/attack_poc_round8.py` and every line of evidence below is that file's
own output, not a reading of the source.

| ID | Severity | Location | Flaw | Status |
|----|----------|----------|------|--------|
| RC-23 | **High** | `observability.CorrelationMiddleware`, `_route_label` | Metrics are counted before authentication and unmatched routes are labelled with the **raw path**, so 200 anonymous 404s consume the entire 128-series budget of `reconkg_http_requests_total`. Every genuine route afterwards is folded into `_other`. Bounded memory, destroyed signal, no eviction short of a restart. | Open |
| RC-24 | **High** | `persistence.load` via `snapshots.restore_into` | Restore assigns `store._hosts[address]` directly, skipping `TargetStore.ensure_host` — so no `validate_address` and no `MAX_TARGETS`. `10.0.0.1\r\nX-Injected: yes` is rejected by the API with 422 and accepted by the restore path, landing in graph keys and in `ChangeEvent.path`. RC-04/RC-07 for the third time. | Open |
| RC-25 | **Medium** | `persistence.connect`, `snapshots._write_atomically` | Snapshot databases are created mode `0644` inside a `0755` directory. The entire engagement — hosts, services, fingerprints, leads — is readable by every local account. Snapshots are the first thing in this system that writes the graph durably, so this exposure is new. | Open |
| RC-26 | **Medium** | `auth.Authenticator.issue_ticket`, `app.ws_ticket` | The RC-18 cap evicts the **oldest outstanding ticket** from a table shared by all principals, `/api/ws-ticket` requires only VIEWER, and nothing rate-limits it. 517 requests from the lowest-privilege credential evicted an operator's unredeemed ticket; its handshake then closed 1008. | Open |
| RC-27 | **Medium** | `app.create_target`, `store.ensure_host` | `POST /api/targets` is the one graph-write route that never calls `state.limiter.check`. It was cheap and idempotent until cycle 8 made re-observation emit `host.updated`; 100 byte-identical POSTs now return 201, emit 100 events and deliver 100 messages *per connected client*, plus autosave and metrics work. | Open |
| RC-28 | **Medium** | `app.prometheus_metrics`, `app.metrics_json` | Scope is not applied to telemetry. `adm:admin:<tok>:10.10.10.0/24` parses, and that principal is refused a direct read of `192.0.2.7` with 403 while `/metrics` hands it every address in the engagement as a label value. The endpoint's own docstring makes this exact argument and then only checks the role. | Open |
| RC-29 | Low | `auth.py`, `observability.default_specs` | `reconkg_auth_failures_total` is registered, documented, and incremented by nothing. 16 refused requests (401s and 403s) left it at `0.0`. "Which principal is hammering the ingress" is the question this cycle existed to answer, and it is answerable only for rate-limit rejections. | Open |
| RC-30 | Low | `app.health` | `/api/health` reports `hosts`, `events_retained` and `events_emitted` for the whole graph to any VIEWER. A viewer scoped to one subnet saw 1 of 3 hosts on `/api/targets` and the true total of 3 on `/api/health`, and watched `events_emitted` move 3 → 17 as a host outside its scope was scanned. RC-16, on a route that predates it. | Open |
| RC-8A | — | `CorrelationMiddleware`, `_clean_id` | Attempted log forgery through a client-supplied `x-request-id`: CRLF, a JSON-closing quote, 10 000 characters, an RTL override, NUL and an ANSI escape. **Not exploitable.** `trust_incoming_id` defaults False so the header is not read at all, and `_clean_id` rejects by character class with a 128-char bound; all six ids produced one parseable JSON object each. | No finding |
| RC-8B | — | `_clean_label_value`, `_escape_label` | Attempted forging of a metric series through a path label (`/a%0d%0areconkg_forged{x="1"} 99`). **Not exploitable.** Control characters are stripped before storage and quotes and backslashes escaped at render; no forged sample, no raw CR in the body. | No finding |
| RC-8C | — | `/metrics`, `/api/metrics` | Both routes really are ADMIN-only: viewer/scanner/operator all get 403 on both, anonymous gets 401, admin 200. The gate itself is sound — RC-28 is about scope, not role. | No finding |
| RC-8D | — | `console.py` | The console honours no role and no scope, **and that is defensible**: each `Workspace` owns a private `TargetStore` and `EvidenceSource`, it never touches `app.state.store`, and it constructs no `SnapshotManager`, so it cannot read the persisted graph either. `principal="operator"` is a provenance label on evidence the operator imported, not a credential. Its file access (`import`, `catalog load`) is the authority the shell already granted. Asserted rather than assumed, so that wiring it onto the shared store later flips this to confirmed. | No finding, by design |

## Root cause

Round 8's instance of the standing pattern is **RC-24**, and it is the
cleanest one yet because the fix it evades is written down three feet away.
RC-07 concluded, in this file: *"validating per-ingress loses. Every new entry
point is a new chance to forget... the store is the only writer, so the check
belongs on the write."* `snapshots.py` honours that rule scrupulously in the
direction it was thinking about — its docstring says "Observer, never writer"
and it means it. Then it calls `persistence.load`, which is a writer, reaches
past the store's public surface into `store._hosts`, and puts whatever is in
the file into the graph. The chokepoint is intact; the traffic went around it.

Three of the others are the same shape at one remove:

- **RC-27** — the rate limiter was added to `/api/evidence` (RC-15) and
  extended to `/scan` (RC-17). `/api/targets` was skipped both times for a
  good reason that cycle 8 quietly invalidated: it used to be idempotent and
  silent, and `host.updated` made it neither.
- **RC-28 / RC-30** — RC-16 established that scope must cover reads, and
  covered the reads that existed. Two telemetry surfaces describing the same
  graph were added or overlooked, and neither calls `require_scope`.
- **RC-26** — RC-18 bounded the ticket table. Bounding a shared table without
  partitioning it by principal converts a memory leak into a DoS one
  principal can inflict on another; the eviction comment argues for exactly
  the behaviour that causes it.

RC-23 is the one genuinely new shape, and it is worth stating on its own: a
cap can be correct about memory and wrong about meaning. `_Family.resolve`
does precisely what RC-03 and RC-18 asked for — it bounds a dict keyed on
caller-influenced input — and because the policy is first-come-first-served,
the caller who arrives first owns the budget. For a metric whose label an
unauthenticated actor supplies, that caller is the attacker. The cap needs to
prefer known-good keys (templated routes) over unknown ones, or unmatched
requests need a single constant label.

## Where the second path is, for each control added this cycle

| Control added in cycle 8 | The route that skips it |
|---|---|
| `validate_address` at the store (RC-07) | `persistence.load` → `store._hosts[...] = host` (RC-24) |
| `MAX_TARGETS` on target creation | the same restore path — an attacker-sized snapshot has no cap (RC-24) |
| ADMIN gate on metric label values | a *scoped* admin; role checked, scope never (RC-28) |
| Scope on graph reads (RC-16) | `/api/health` aggregate counters (RC-30) |
| Per-principal rate limits (RC-15/RC-17) | `POST /api/targets`, now a fan-out route (RC-27) |
| Bounded metric cardinality (RC-03/RC-18) | anonymous 404s, which reach the counter before auth (RC-23) |
| Bounded WS ticket table (RC-18) | shared eviction: any viewer can evict any principal (RC-26) |
| Correlation-ID sanitisation | none found — `trust_incoming_id=False` and `_clean_id` both hold (RC-8A) |

## Still open

Confirmed and unfixed, in the order I would fix them:

1. **RC-24** — restore must go through `ensure_host`, or `Host.address` must
   carry a validator. Cheapest fix in the list and it closes the pattern.
2. **RC-23** — label unmatched routes with a constant, or reserve the series
   budget for templated routes.
3. **RC-25** — `0o600` on the snapshot file and `0o700` on the directory.
4. **RC-26**, **RC-27**, **RC-28**, **RC-29**, **RC-30** as described above.

Inherited and still true:

- **Token rotation and revocation.** Cycle 8's plan (item ⑤) listed it for
  the integration phase; `auth.py` contains no `revoke` and no rotation.
  Expiry from RC-20 is the whole lifecycle story, so a leaked token is still
  valid until its date and the only remedy is a restart with a different
  environment.
- **`AppState` is a module global captured by the middleware.** Rebuilding
  `app.state` after import — as most test fixtures in this repo do — leaves
  `CorrelationMiddleware` writing into an orphaned `Metrics`, so HTTP metrics
  read as empty through `/api/metrics`. Harmless in production, where the app
  is imported once; it means the HTTP metric path is effectively untested
  through the API, and it is why the PoC harness rebuilds the module instead.
- **Index integrity, contradiction discounting, golden fixtures, mutation
  coverage** — unchanged from round 7.

Not attempted, and why:

- **Cross-filesystem `os.replace` in `_write_atomically`.** Would raise
  `OSError` and be counted as a failure rather than corrupting anything, so
  the interesting case is availability, not integrity, and it needs a mount
  this sandbox cannot make.
- **`RECONKG_SNAPSHOT_DIR` pointed somewhere harmful.** The variable is set
  by whoever starts the process; an operator who can set it can already write
  files as that user. Nothing in a *request* influences the path or the
  filename — the name is `basename-<UTC timestamp>-<seq>.sqlite` with no
  caller-supplied component — so there is no traversal here. Stated as a
  negative result rather than left unmentioned.

Twelve probes run; eight confirmed. 506 tests pass, unchanged: this round
wrote no code outside `audit/`.

## Round 8 — remediation (tech lead)

Three of the eight fixed and pinned; five remain open and are listed below
honestly rather than quietly closed.

| ID | Status | Fix |
|----|--------|-----|
| RC-24 | **Fixed** | Address validation moved from `TargetStore.ensure_host` onto a `field_validator` on `Host.address`. |
| RC-25 | **Fixed** | Snapshots are `0600` in a `0700` directory, reasserted on every open so a file written by an older build is corrected. |
| RC-29 | **Fixed** | `auth.on_auth_failure()` hook on `require_principal` — the one path every route resolves through. |

### RC-24 is the third instance, so the rule moved a layer down

RC-07's own text says "the store is the only writer, so the check belongs on
the write." That was true when it was written. `persistence.load` then reached
past the store's public surface into `_hosts` and became a second writer: an
address the API refuses with 422 was accepted by a snapshot restore.

Chokepoint intact, traffic routed around it — for the third time. So the check
moved to the only place with no second path: constructing or deserialising a
`Host` at all. Pydantic enforces it on every code path that can produce one,
including any future writer nobody has thought of.

Verified against a hand-crafted poisoned snapshot: the CRLF row is skipped
with a logged reason, the clean row beside it restores.

### RC-29's fix found a second bug in the metric itself

The counter was dead because a counting dependency sat *beside*
`require_principal` while `require_role` resolved *through* it. Wiring the
hook onto the shared path fixed the count — and then showed the label
vocabulary was wrong: an absent `Authorization` header and a malformed one
both reported `malformed`. "Nobody is authenticating" and "something is
authenticating wrongly" are different operational signals, and a metric that
conflates them is half a metric. Now `missing` / `malformed` / `invalid` /
`expired`, from a fixed vocabulary so the label can never carry attacker text.

### Still open — not fixed this round

- **RC-23 (High)** — 200 anonymous 404s exhaust the 128-series budget of
  `reconkg_http_requests_total`; unmatched routes are labelled with the raw
  path and counted before auth. Memory is bounded, signal is destroyed. Fix
  is to label unmatched routes as `__unmatched__` and count after routing.
- **RC-26 (Med)** — the outstanding-ticket cap is shared across principals, so
  a viewer flood evicts an operator's ticket. Needs a per-principal cap; the
  same shape as RC-18's fix, one level out.
- **RC-27 (Med)** — `POST /api/targets` is the only graph-write route with no
  rate limit, and `host.updated` turned it into a WebSocket fan-out.
- **RC-28 / RC-30 (Med/Low)** — scope is not applied to `/metrics` labels or
  `/api/health` counters. Scope now covers reads of the graph but not the
  telemetry describing it.

RC-23 and RC-27 are the two worth doing next: both are cheap, and both are
the same "control on two of three routes" shape the audit keeps finding.

519 tests pass. Mutation score 100% on `auth` and `sources` after the change.

---

# Rounds 9 and 10, plus the property pass — RC-31..RC-41, PROP-01..PROP-05

Three corpora landed between round 8 and here: the NVD/KEV/EPSS vulnerability
index, the ExploitDB index, and nmap's `script.db`. All three ingest data
downloaded over the network, and all three feed the command builder. The
findings below are almost entirely about that new surface.

## Round 9 — the command classifier

| ID | Sev | What it was | Fix | Pinned by |
|---|---|---|---|---|
| RC-31 | High | `Category` subclasses `str`, so `Category.EXPLOIT == "exploit"` **and hashes equal** — which made the `NEVER_COMPOSED` membership test look type-safe. `"EXPLOIT"`, `" exploit"`, `"Exploit"` are not in the set, so `Command(category="EXPLOIT", argv=...)` was accepted, the backstop passed it, and `requires_opt_in` answered `False`. Exploit tier, composed, labelled default. | `coerce_category()` normalises in `__post_init__` before any policy reads the field; `assert_no_composed_exploits` and `filter_commands` re-coerce rather than trust the attribute | `test_round9_redcell.py::test_rc31_*` |
| RC-32 | High | msfconsole re-splits its `-x` argument on `;`. A catalog identifier of `exploit/multi/http/x; run` only had to `startswith("exploit/")` to pass. `shlex.quote` is no defence — quoting correctly is what delivers the payload intact as one argument | `_refuse_firing_verbs` splits the way msfconsole does; `validate_module_path` rejects command sequences; argv elements carrying NUL/CR/LF refused | `test_rc32_*` |
| RC-33 | High | `ExploitRecord.msf_oneliner` composes the same line by a second path and never had either check. `lookup_command` interpolated the identifier into a hand-written single-quoted string — `exploit/x'; id; '` closed the quote | both methods call the same validators from `commands.py`; all quoting through `shlex.quote` | `test_rc33_*` |
| RC-34 | Med | `build_commands` classified `nmap --script vuln` as `vuln` and withheld it until opt-in, with the warning. `build_handoff` then emitted the identical invocation as plain text under "Verification lookups" — no category, no opt-in, no warning | the lookup is emitted only when `Category.VULN` is permitted | `test_rc34_*` |
| RC-35 | Med | `_worst_category` iterates its argument, and a string is iterable: `"exploit"` became seven unrecognised one-character names, all dropped, resolving to `unclassified` — which *is* composable on opt-in. Second half: an unknown tag was dropped rather than counted, so `["safe", "malware"]` resolved to `safe` | a bare string reads as one category; an unrecognised tag contributes `UNCLASSIFIED` | `test_rc35_*` |
| RC-36 | High | `from_env()` refuses to fall back to the built-in nine and says so at length. `DiscoveryEngine.__init__` defaulted `reference=DEFAULT_REFERENCE`, so `coerce()` never reached it and **`RECONKG_VULN_DB` was read by nobody on the API path** | default is `None`, meaning "ask the environment" | `test_rc36_*` |

## Round 10 — the two new corpora

| ID | Sev | What it was | Fix | Pinned by |
|---|---|---|---|---|
| RC-37 | **Critical** | `--script` is an expression language over names, globs *and category names*. `exploit` is a well-formed script name, so a `script.db` row `Entry { filename = "exploit.nse", categories = { "safe", } }` produced `nmap --script exploit <target>` classified **`safe`, in the default tier** — every exploit-category script on the machine, aimed, no opt-in, no warning. `all` is worse: not a category at all, so no bookkeeping could catch it | `script_selection_category()` resolves the row's claim *and* what the name selects, taking the more restrictive. The row is a floor, never a ceiling | `test_round10_redcell.py::test_rc37_*` |
| RC-38 | High | RC-35's guard undone one stack frame above it. `_nse_selection` did `[str(c) for c in entry.categories]` — the exact decomposition the guard prevents — *before* the guard ran | one `normalise_categories()` called by every consumer | `test_rc38_*` |
| RC-39 | Med | `validate_module_path` was the only validator that did not `.strip()`, and `$` matches before a trailing newline. Worse: `_clean_argv` then raised `ValueError` while `build_commands` caught only `BoundaryViolation`, so one poisoned index record blanked the whole hand-off and 500'd the route | strip before matching; `\A`/`\Z` anchors on six patterns; the drop-sites catch both exception types | `test_rc39_*` |
| RC-40 | Med (DoS) | Three bounds checked *after* the thing they bound was allocated. `read_script_db` stated a per-line limit and then let `for raw in handle` materialise the line first — 33 MB peak on a 16 MB line, and `nmap --script-updatedb` will build exactly that | `vulndb.bounded_lines()` caps resident memory at `limit + 64 KiB`; provenance hashing chunked | three `tracemalloc` tests |

## The property pass — invariants, not examples

34 properties over the safety controls, version ordering, parsing and the
three stores. Five failures, all real:

| ID | Sev | What it was | Fix |
|---|---|---|---|
| PROP-01 | High | `CPE.__str__` did not re-escape `\:` and `\\` that `parse` had consumed. Not cosmetic: `vulndb` stores `str(cpe)` as `criteria` and re-parses it, so **a colon anywhere in a CPE shifted every later attribute one position in the stored corpus**, silently | `_escape` in `cpe.py` |
| PROP-02 | Med | `VulnDB.ingest` raised `IntegrityError` on the same CVE twice in one batch, aborting the transaction and losing up to 2000 good rows. Both sibling corpora guarded this; corpus one did not | intra-batch dedupe, last-wins |
| PROP-03 | Med | `.nse` stripping was not a fixed point and ran on two paths — `a.nse.nse` became `a.nse` in one and `a` in the other, so the row was stored under a name the parser never produces and every lookup missed | loop the strip in both |
| PROP-04 | High | `Category` subclasses `str`, so an enum member passed `normalise_categories`' `isinstance(x, str)` unchanged, and consumers then did `Category(str(name))` — `str(Category.EXPLOIT)` is `'Category.EXPLOIT'`. A resolver declaring `categories=(Category.EXPLOIT,)` — the natural thing against reconkg's own API — resolved to `unclassified`, which is composed on opt-in | `_token()` unwraps enum members in the single normaliser |
| PROP-05 | Med | `searchsploit_commands` interpolated banner product/version into argv; a `\r` in a POSTable banner made `_clean_argv` raise outside any handler, blanking the whole hand-off | `_feed_argument()` strips control characters and bounds length |

## RC-41 — found by the integration test, on the last pass

| ID | Sev | What it was | Fix | Pinned by |
|---|---|---|---|---|
| RC-41 | High | `build_handoff` looks up the `VulnEntry` behind a lead to source the caveats (`entry.notes`) and the operator-supplied follow-ups (`entry.handoff`). Every caller handed it `DEFAULT_REFERENCE` while the lead came from the configured resolver. The lookup succeeded for nine CVEs and missed for every one of the ~250,000 a real corpus holds — dropping the corpus's own note on exactly the leads the corpus exists to produce. Nothing failed, nothing logged | `entry_for(cve_id)` on the resolver protocol; `app.py` and `console.py` both pass their resolver. `VulnEntry.handoff` also gained a column, because it was silently lost on every corpus round trip | `test_rc41.py` (14 tests) |

Worth stating plainly: **every unit test passed, and every unit test was
right about what it asserted.** They all handed `build_handoff` a list,
because that was the signature. Only walking the whole chain with a real
corpus configured asked the question that mattered.

---

## The pattern, counted

Of 45 findings across ten rounds, **13 are the same shape**: a control,
lookup or normalisation implemented on one path and absent from a second.

RC-04→RC-07 (validation: API but not importer) · RC-03→RC-18 (unbounded
state, fixed twice, missed on tickets) · RC-14→RC-16 (scope: writes but not
reads) · RC-07→RC-24 (chokepoint intact, traffic routed around it) ·
`VulnDB.candidates`' alias fallback routing around the version check ·
RC-33 (`ExploitRecord` composing by a second path) · RC-34 (`lookups`
bypassing the category gate inside one function) · RC-36 (engine default
bypassing `from_env`) · RC-38 (normalisation above the guard) · RC-41
(entry lookup against the wrong source, twice — API and console) ·
PROP-03 (two strip implementations) · PROP-04 (enum vs string in one
normaliser) · the mutation harness' own line-keyed exemptions drifting.

### What has been tried, and whether it worked

| Approach | Verdict |
|---|---|
| Fix the bug, add a regression test | **No.** Every one of the 13 had a passing regression test for its predecessor. The test pinned the path it knew about. |
| Move the control to a chokepoint | **Partly.** RC-24 moved validation onto the pydantic model — the one layer with no second path — and address validation has not recurred since. It works when a chokepoint genuinely exists. |
| Write the pattern down | **No.** `CORPUS-PATTERN.md` documents five recurring bugs; corpus two avoided all five *and* introduced RC-37 and RC-38, which are the same family in a new place. |
| Attack the fix rather than the original | **Yes, mostly.** This is how RC-07, RC-24, RC-38 and RC-41's second half were found. It is a habit, not a structural guarantee. |
| Property-based testing | **Best result so far.** PROP-04 is precisely the shape, and no example-based test had found it in two rounds of looking, because nobody thought to pass an enum member where a string was expected. A property quantifies over inputs nobody would think to write down. |
| Integration testing | **Found RC-41 immediately**, after eleven rounds of unit and adversarial testing missed it. Unit tests cannot see a wiring error by construction: they supply the dependency themselves. |

### The honest conclusion

Nothing tried so far *prevents* the next one. Two things reliably *find* it —
properties that quantify over inputs, and integration tests that supply no
dependencies — and both were added late.

The one structural change that would help is narrower than "be careful": make
the second path impossible to write rather than remembering to check it.
RC-41's fix is the model — the entry lookup moved onto the resolver, so there
is no longer a way to express "look this up somewhere other than where the
lead came from". `Category` being a `str` subclass is the counter-example and
has now caused two findings (RC-31, PROP-04); it should probably stop
subclassing `str`, which would turn both into type errors at construction.

Next round should start there rather than with a new feature.
