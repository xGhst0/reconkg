# Cycle 9 — whiteboard and work breakdown

Three workstreams, one hard dependency between them, one boundary that is
not negotiable by any of them.

```
        A. corpus provenance          C. commands.py
           (independent)                 (blocks D)
                |                            |
                |                            v
                |                      D. local web UI
                v                            |
        ------------------  E. red cell + QA  <-
```

**A** and **C** can run in parallel. **D** cannot start before **C**, because
the UI's main panel renders commands and building it against a placeholder
shape means building it twice. **E** attacks whatever landed.

---

## The rule every stream inherits

reconkg composes commands up to the parameter check and not past it.

- `safe`, `discovery`, `version` — composed, emitted freely
- `intrusive`, `vuln` — composed, emitted when the operator ticks the box,
  with the authorisation warning attached
- `exploit`, `dos`, `fuzzer`, `brute` — **named, not composed.** The lead says
  which module or template exists and where to find it. It does not assemble
  an invocation with the target filled in.

Categories are the NSE vocabulary (Nmap Project, n.d.), not a local
invention. A source that does not classify its own checks is `unclassified`,
which is treated as `intrusive` — the conservative default, because
COMMAND-MAPPING.md established that assuming otherwise is how you ship an
exploit labelled as a probe.

Anyone reviewing this cycle: a test asserting the exploit tier stays
uncomposed is part of the deliverable, not optional.

---

## A. Corpus provenance and refresh

*Owner: DevOps + senior. Independent of everything else.*

The corpus lands as a single opaque blob with no record of where it came
from. Three gaps:

1. **Per-feed provenance in the database.** `fetch.py` computes a sha256 for
   every download and throws it away at process exit. Record source URL,
   sha256, byte count, record count and fetch timestamp into a `feed_source`
   table. Without it there is no way to answer "is this corpus complete, and
   how old is each part of it" — and the parts age at different rates. EPSS
   regenerates daily; NVD is continuous; KEV changes weekly.

2. **`--since` incremental pull.** NVD supports `lastModStartDate` /
   `lastModEndDate` with a 120-day window cap. A daily refresh currently
   re-pulls ~300,000 records to collect the few hundred that changed. Store
   the last successful pull timestamp in `meta`, pass it on the next run,
   fall back to a full pull when the gap exceeds the window.

3. **Staleness already half-done.** `resolver.describe()` reports `STALE`
   past 30 days. Extend it to per-feed once (1) exists, so "corpus is fresh"
   cannot be true while EPSS is three months old.

Acceptance: rebuild twice, second run pulls only deltas; `feed_source` shows
per-feed dates; a corpus with a stale EPSS feed says so specifically.

## B. — folded into A

## C. `commands.py` — the tool-agnostic replacement for `msf_oneliners`

*Owner: architect + mid. Blocks D. This is the cycle's centre of gravity.*

`msf_oneliners: list[str]` is a hardcoded field name threaded from
`handoff.py` into the `app.py` API response. It has to die, and replacing it
is an API contract change.

```python
@dataclass(frozen=True)
class Command:
    tool: str            # nmap, nuclei, searchsploit, curl, openssl, msfconsole
    category: Category   # NSE vocabulary
    argv: tuple[str, ...] | None    # None for the named-not-composed tier
    reference: str       # what to look up when argv is None
    source: str          # which index asserted this mapping
    rationale: str       # why this command, for this CVE, on this host
```

`argv` as a tuple, not a string. Every existing one-liner is shlex-quoted at
the point of rendering; keeping argv structured means quoting happens once,
in one place, and the UI can render a copy button without re-parsing a
shell string.

Builders, one per tool, each declaring its own category:

| Tool | Category | Notes |
|---|---|---|
| `searchsploit --cve` | safe | pure lookup, no target contact |
| `nmap --script <vuln script>` | vuln | from `script.db`, which ships the categories |
| `nmap -sV -p` | version | already how fingerprints arrive |
| `curl -I` / `openssl s_client` | safe | banner and certificate confirmation |
| `nuclei -id` | **unclassified → intrusive** | see COMMAND-MAPPING.md; many CVE templates exploit |
| `msfconsole ... show options` | intrusive | stops at the parameter check |
| exploit-category modules | exploit | named only, `argv=None` |

The nuclei row is the one to get right. Its templates carry excellent
identification metadata and no safety classification, so reconkg must not
infer one.

Acceptance: `msf_oneliners` gone from the codebase; every emitted command
carries a category; a test walks the AST asserting no builder can produce
`argv` for an exploit-category entry.

## D. Local web UI

*Owner: UX + junior + senior. Starts when C lands.*

Single page, served by the existing FastAPI app, no build step, no CDN.

- Target input, live scan progress over the existing WebSocket event bus
- Graph: host → port → service → fingerprint → lead, provenance visible on
  click. This is the panel that justifies the whole architecture — an analyst
  can see *why* a CVE was assigned rather than trusting a number.
- Ledger table, sortable on CVSS / KEV / EPSS / match method, backport
  warning shown as a column not a footnote
- Category tickboxes: `safe`, `discovery`, `version` ticked by default;
  `intrusive` and `vuln` unticked, warning on tick
- Corpus panel fed directly by `resolver.describe()` — including the
  "demonstration fixture" and `STALE` strings, which exist precisely so the
  UI can distinguish "clean host" from "empty corpus"

Acceptance: a scan against a corpus-backed target renders leads, provenance
and commands with no console errors; ticking `intrusive` changes what is
shown and shows the warning.

## E. Red cell and QA

*Owner: red cell, then QA. Runs against whatever A/C/D produced.*

Standing items from round 8 still open: RC-23, RC-26, RC-27, RC-28, RC-30.

New surface worth attacking, in the order I would attack it:

1. **The UI is a new ingress.** Every input reaching the API through a form
   is an input the API layer previously only saw from authenticated clients.
   Check authz on every new route, not just the obvious ones.
2. **Command construction is injection-shaped.** `argv` comes partly from
   feed data — CVE titles, template IDs, module paths — which is attacker-
   influenceable if someone can get a record into a feed. Fuzz it.
3. **The category gate is the control.** Attack it directly: can a crafted
   feed record or a malformed `script.db` produce an `exploit` command with
   `argv` populated? Can a category be spoofed to `safe`?
4. **The resolver's loud-failure promise.** Confirm no path silently falls
   back to the built-in nine when a corpus was requested.
5. **The pattern from every prior round:** a control enforced on one path and
   bypassed on the second. This cycle's version already appeared once —
   `VulnDB.candidates` enforced version bounds in the CPE query and the alias
   fallback routed around them. Assume there is another.

QA: golden fixtures for `script.db` parsing, mutation testing on
`commands.py` at the same bar as the existing nine modules, and the
15-fingerprint HTB benchmark re-run once a real corpus exists.

---

## Sequencing

1. C — `commands.py`, because D is blocked on it and A is not blocked on
   anything
2. A in parallel
3. D once C's shape is fixed
4. E against all of it
5. Re-run `audit/mutation.py` and `audit/scale_bench.py`; neither should
   regress

## Definition of done

- 683 tests still pass, plus new coverage for A, C, D
- Mutation score holds at 100% on targeted modules, `commands.py` included
- `msf_oneliners` appears nowhere
- A test asserts the exploit tier is named and not composed
- `docs/CORPUS-PATTERN.md` updated if A changes the schema shape
