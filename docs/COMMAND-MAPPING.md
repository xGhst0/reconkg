# Mapping CVEs to tool commands — design note

Prepared for the reconkg dev team, August 2026. Every source below was
fetched live. The verification table at the end marks what was confirmed,
what was partially confirmed, and what could not be established at all.

---

## The finding that changes the design

reconkg was about to emit `nuclei -id CVE-XXXX-NNNNN` as a *verification*
command, on the assumption that nuclei detects and Metasploit exploits. That
assumption is false, and it is not a marginal case.

Take `CVE-2026-0770.yaml`, a current template in the ProjectDiscovery
repository. It authenticates to Langflow with default credentials, posts a
payload to `/api/v1/validate/code` that calls
`__import__('subprocess').run('cat /etc/passwd', ...)`, and matches the
response against `root:.*:0:0:`. That is remote code execution carried out
against the target. It is filed under `http/cves/`, tagged `vuln`, and
carries `metadata: verified: true` — where "verified" means the template was
confirmed to work, not that it is safe to run.

Detection by exploitation is a normal technique, not an aberration. A
template that proves RCE by achieving RCE is the most reliable detection
available. The mistake would be reconkg presenting it under a label that
implies otherwise.

**So safety cannot be a property of the tool.** It is a property of the
individual check. Any design that says "nuclei commands are verification,
Metasploit commands are exploitation" is wrong at the first template it
meets.

## 1. The taxonomy already exists — adopt it

The Nmap Scripting Engine has carried a category vocabulary for this since
2007: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`,
`external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`
(Nmap Project, n.d.).

Three of those definitions do the work reconkg needs, quoted rather than
paraphrased because the precision matters:

- **safe** — "Scripts which weren't designed to crash services, use large
  amounts of network bandwidth or other resources, or exploit security holes."
- **intrusive** — "scripts that cannot be classified in the `safe` category
  because the risks are too high that they will crash the target system, use
  up significant resources on the target host ... or otherwise be perceived
  as malicious."
- **exploit** — "These scripts aim to actively exploit some vulnerability."

And the partition is explicit: "Unless a script is in the special `version`
category, it should be categorized as either `safe` or `intrusive`."

Two things follow. First, reconkg should not invent a vocabulary; it should
use this one, which practitioners already read fluently and which has two
decades of shared understanding behind it. Second, `safe` is defined by what
a check *does to the target*, not by which binary runs it — exactly the axis
the nuclei finding says we need.

Nmap also ships `scripts/script.db`, a machine-readable index of script name
to category list, and `--script-help` prints categories per script. So for
NSE the classification is available as data rather than as a judgement
reconkg has to make.

**But the name is part of the classification too** (red cell round 10,
RC-37). `--script` is not a filename argument; it is an expression over
script names, wildcards, directory paths and *category names*, so
`--script exploit` runs every exploit-category script on the machine and
`--script all` runs every script installed. A bare category word is also a
perfectly well-formed script name, and `script.db` is rebuilt from whatever
`.nse` files are in the operator's scripts directory — which makes "the row
says this script is `safe`" and "running this argument is safe" two
different claims. reconkg therefore resolves a script's category from the
row *and* from what the name selects, and takes the more restrictive of the
two: a row can make a script look more dangerous than it is, and cannot make
a selector look safer than it is. `script.db` is authoritative about
categories; it is not authoritative about what an nmap argument does.

**Recommendation.** Every command reconkg emits carries an NSE-derived
category. Default policy emits only `safe`, `discovery` and `version`.
`intrusive` and `vuln` are available behind an explicit operator flag with
the authorisation warning attached. `exploit`, `dos`, `fuzzer` and `brute`
are never emitted. Where a source does not classify its own checks, the
command is marked `unclassified` and treated as `intrusive` — the
conservative default, since the nuclei case shows the alternative assumption
fails.

## 2. Mapping sources, and what is actually known about them

| Source | Machine-readable | CVE mapping | Self-classifies safety |
|---|---|---|---|
| Nmap NSE | `script.db`, `--script-help` | in script description/refs | **Yes** — the categories above |
| nuclei templates | YAML, `classification.cve-id` | explicit field | Partly — `tags`, but see below |
| Metasploit modules | module metadata `References` | explicit `CVE` refs | Partly — `Rank`, which is reliability not safety |
| ExploitDB | `files_exploits.csv` | CVE column | No |
| Vulners | API | yes | Not established (see table) |

The nuclei metadata block is genuinely rich and well-structured —
`cve-id`, `cvss-metrics`, `cvss-score`, `epss-score`, `epss-percentile`,
`cwe-id`, plus Shodan and FOFA queries. As an *identification* source it is
excellent. Its `tags` field is not a safety classification: the RCE template
above is tagged `cve,cve2026,langflow,rce,authenticated,vuln,vkev`, and
nothing there distinguishes "detects" from "achieves".

**On mapping accuracy.** ProjectDiscovery's April 2026 release notes record
fixes to "CVE-ID mismatches in template metadata" and "invalid CPE formats"
across multiple templates. That is evidence the mapping carries errors and is
actively corrected. It is *not* a measured error rate, and no published study
establishing one was found. Anyone quoting a false-mapping percentage for
these sources is guessing.

## 3. Version inference remains wrong, and VEX is not yet the way out

The earlier note (CVE-IDENTIFICATION.md) established that backporting breaks
version inference and that OVAL was the answer. That still holds, with an
update: Red Hat has published CSAF files for every Red Hat Security Advisory
and VEX files for every CVE record in its portfolio since July 2024 (Red Hat
Product Security, n.d.). For RHEL targets specifically, that is authoritative
affectedness data rather than a version guess.

Ecosystem-wide, though, VEX is not ready to be leaned on. The OpenSSF's
January 2026 industry report — drawing on Amazon, Cisco, Debian, Ericsson,
Google, Microsoft, Red Hat and others — states plainly that "VEX feels more
like a promise than a practice" (Open Source Security Foundation [OpenSSF],
2026). Four obstacles are named that bear directly on reconkg:

- **No common discovery protocol.** Every organisation distributes VEX
  differently. There is no lookup a scanner can rely on.
- **Trust by hosting, not signature.** The report notes that for many
  consumers "trust is currently based on *where* the file is hosted rather
  than cryptographic proof."
- **Four competing formats** — CSAF, OpenVEX, CycloneDX, SPDX 3.0.
- **Identifier confusion** across PURLs, CPEs and hashes, which the report
  calls a foundation problem for automation.

The report also gives a figure worth keeping: roughly **40,000 new CVEs
annually**. That is the number the corpus pipeline has to absorb, and it is
the reason a nine-entry reference table was never going to be extended by
hand.

**Recommendation.** Do not build general VEX ingestion this cycle. Build the
per-source affectedness *field* now — a status of `affected`,
`not_affected`, `fixed` or `under_investigation` with a recorded source — so
that a lead can carry an authoritative verdict when one exists and fall back
to version inference when it does not. Red Hat CSAF is the one feed worth
ingesting first, because it is complete for its portfolio and because RHEL
backporting is the specific case where reconkg is currently blind in both
directions.

---

## References

Nmap Project. (n.d.). *Usage and examples*. Nmap network scanning.
https://nmap.org/book/nse-usage.html

Open Source Security Foundation. (2026, January 8). *Signal in the noise: An
industry-wide perspective on the state of VEX*.
https://openssf.org/blog/2026/01/08/signal-in-the-noise-an-industry-wide-perspective-on-the-state-of-vex/

ProjectDiscovery. (2026, April). *Nuclei templates — April 2026*.
https://projectdiscovery.io/blog/nuclei-templates-april-2026

ProjectDiscovery. (n.d.). *CVE-2026-0770.yaml*. Nuclei templates.
https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-0770.yaml

Red Hat Product Security. (n.d.). *CSAF/VEX overview*. Red Hat security data
guidelines. https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/

---

## Verification table

| Source | Status | Usage | Action |
|---|---|---|---|
| Nmap Project, NSE usage and examples | **VERIFIED** — primary documentation fetched; all category definitions quoted directly from it | Cited for the category vocabulary and the safe/intrusive partition, which the page states verbatim | Kept; this is the note's load-bearing source |
| ProjectDiscovery, CVE-2026-0770.yaml | **VERIFIED** — template fetched and read in full | Cited as a concrete instance of a CVE template that exploits rather than probes. The claim rests on the template body, not on interpretation | Kept |
| ProjectDiscovery, April 2026 release notes | **PARTIAL** — reached via search summary rather than the blog post itself. The specific items (CVE-ID mismatches, invalid CPE formats) are reported consistently but were not read on the source page | Cited only for the existence of metadata errors, not for any rate | Kept, and hedged in the text accordingly |
| OpenSSF, State of VEX (Jan 2026) | **VERIFIED** — full report fetched; quotations checked against it | Cited for adoption state, the four named obstacles, and the ~40,000 CVE/year figure | Kept |
| Red Hat Product Security, CSAF/VEX | **PARTIAL** — the guidelines site is real and was returned by search; the July 2024 completeness claim came from the search summary and was not confirmed on Red Hat's own page in this pass | Cited for Red Hat publishing CSAF/VEX across its portfolio | Kept but flagged; **verify before the dev team commits to a Red Hat ingestion path** |
| Nuclei template total count and CVE coverage | **NOT FOUND** | Would have quantified coverage | Omitted. No count is stated anywhere in this note rather than an estimate being offered |
| False-mapping rates for any source | **NOT FOUND** | Would have let us weight sources numerically | Omitted, and the absence is stated explicitly in section 2 |
| Licences for nuclei / ExploitDB / Vulners data | **NOT CHECKED** | Matters for redistribution if reconkg ever ships a bundled index | Flagged as an open item, not asserted |
| Vulners | **NOT ASSESSED** | Was in the brief | No usable primary source examined; the table marks it "not established" rather than guessing |

**Lead Researcher, critic pass.** The brief asked four questions and this
note firmly answers two. Question 1 is answered structurally but not
quantitatively — there are no coverage or accuracy numbers here because none
were found, and inventing them would have been worse than the gap. Question 4
is answered for direction but the Red Hat completeness claim needs a second
look before code depends on it. The nuclei finding was not something the
brief anticipated, and it is the most consequential result: it invalidates
the design the dev team was about to build.
