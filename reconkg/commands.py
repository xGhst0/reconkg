"""Commands attached to a lead, classified by what they do to the target.

This replaces `Handoff.msf_oneliners`, a `list[str]` whose field name assumed
one tool would ever matter. Two things forced the change.

The first is obvious in hindsight: nmap, nuclei, curl, openssl and
searchsploit all belong here, and a field called `msf_oneliners` cannot hold
them.

The second came out of the research in docs/COMMAND-MAPPING.md and is the
reason this module is shaped the way it is. **Safety is not a property of the
tool.** The obvious design -- nuclei detects, Metasploit exploits -- is
false. Current nuclei CVE templates achieve detection *by exploiting*:
CVE-2026-0770.yaml posts a `subprocess.run('cat /etc/passwd')` payload
through a Langflow RCE and matches on `root:.*:0:0:`. Under a tool-based
scheme that would have shipped as a "verification" command.

So every command carries a category describing what running it does, and the
vocabulary is Nmap's, not one invented here (Nmap Project, n.d.). It has
twenty years of shared understanding behind it and `script.db` publishes the
classification as data.

The tiers, and what reconkg does with each:

    safe, discovery, version     composed, emitted freely
    intrusive, vuln              composed, emitted on explicit opt-in
    exploit, dos, fuzzer, brute  NAMED, NOT COMPOSED

The last tier is the boundary. reconkg will tell you that
`exploit/multi/http/apache_normalize_path_rce` exists and applies to this
CVE. It will not assemble that into an invocation with your target in it.
The line is not "text is dangerous" -- `show options` is composed and that is
a Metasploit command. The line is that composing the final, aimed invocation
for every lead in a ledger removes the parameter check, which is the last
place a wrong RHOST gets caught before it reaches a host nobody authorised.

`assert_no_composed_exploits()` enforces this at runtime and a test walks the
AST to enforce it at build time.
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional, Sequence

log = logging.getLogger(__name__)


class Category(Enum):
    """Nmap NSE script categories. Not a local invention.

    A plain `Enum`, deliberately not `(str, Enum)`. It subclassed `str` for
    the convenience of `category == "exploit"` and JSON serialisation, and
    that convenience cost two findings:

      RC-31   `Category.EXPLOIT == "exploit"` and the two hash alike, so
              `"EXPLOIT" in NEVER_COMPOSED` was False and the tier check was
              skipped entirely -- while every reader of the code saw a set
              membership test and read it as type-safe.
      PROP-04 the mirror image. An enum member satisfied `isinstance(x, str)`
              in the normaliser and passed through unconverted, so a consumer
              doing `Category(str(name))` got `'Category.EXPLOIT'` and
              resolved it to `unclassified` -- which is composable on opt-in.

    Both were silent, both were fail-open, and both are type errors now:
    `Category("exploit")` still works, `"exploit"` is no longer a Category,
    and nothing can be half of one. `.value` is required at every
    serialisation point, which is a small tax paid once and visible in review
    rather than a comparison that quietly answers False.

    This is the structural fix the audit's own conclusion asked for: make the
    second path impossible to express rather than remembering to check it.

    Definitions quoted from the Nmap book, because paraphrase loses the
    precision that makes them useful:

    safe        "Scripts which weren't designed to crash services, use large
                amounts of network bandwidth or other resources, or exploit
                security holes."
    intrusive   "cannot be classified in the safe category because the risks
                are too high that they will crash the target system, use up
                significant resources on the target host ... or otherwise be
                perceived as malicious."
    exploit     "These scripts aim to actively exploit some vulnerability."
    """

    # The full NSE vocabulary. All fourteen, because a partial copy means
    # real script.db rows fall through to `unclassified` -- `default` alone
    # appears on hundreds of scripts.
    AUTH = "auth"
    BROADCAST = "broadcast"
    BRUTE = "brute"
    DEFAULT = "default"
    DISCOVERY = "discovery"
    DOS = "dos"
    EXPLOIT = "exploit"
    EXTERNAL = "external"
    FUZZER = "fuzzer"
    INTRUSIVE = "intrusive"
    MALWARE = "malware"
    SAFE = "safe"
    VERSION = "version"
    VULN = "vuln"
    UNCLASSIFIED = "unclassified"
    """The source did not classify this check. Treated as `intrusive`.

    Conservative on purpose. COMMAND-MAPPING.md establishes that the
    permissive assumption is how an exploit ends up labelled a probe, and
    nuclei -- whose metadata is otherwise excellent -- publishes no safety
    classification at all.
    """


#: The safety axis, and only these three.
#:
#: This is the distinction I flattened on the first pass and the Nmap book is
#: explicit about: "Unless a script is in the special `version` category, it
#: should be categorized as either `safe` or `intrusive`." Safety is stated by
#: `safe` / `intrusive` / `version`. Everything else -- `auth`, `broadcast`,
#: `default`, `discovery`, `external`, `malware` -- is a *topic*, describing
#: what a script is about rather than what running it costs the target.
#:
#: Treating a topic label as a safety verdict is wrong in both directions. A
#: script tagged only `discovery` has made no safety claim, so assuming it
#: benign is the nuclei mistake again. And `default` is a selection set, not a
#: promise: the book notes default scripts are "almost always" safe, while
#: allowing mildly intrusive ones in.
SAFETY_BEARING = frozenset({
    Category.SAFE, Category.INTRUSIVE, Category.VERSION})

#: Emitted without asking.
DEFAULT_CATEGORIES = frozenset({
    Category.SAFE, Category.DISCOVERY, Category.VERSION})

#: Emitted when the operator opts in, with the authorisation warning.
OPT_IN_CATEGORIES = frozenset({
    Category.VULN, Category.INTRUSIVE, Category.UNCLASSIFIED,
    Category.AUTH, Category.DEFAULT, Category.MALWARE,
    # `broadcast` adds hosts nobody named, and `external` hands your target
    # to a third party. Neither damages the target, and both are scope
    # problems -- which on an authorised engagement is the same severity.
    Category.BROADCAST, Category.EXTERNAL})

#: Never composed into a runnable invocation. Named only.
NEVER_COMPOSED = frozenset({
    Category.EXPLOIT, Category.DOS, Category.FUZZER, Category.BRUTE})

INTRUSIVE_WARNING = (
    "These contact the target in ways a port scan does not, and some can "
    "crash a service. Run them only against systems you own or have written "
    "authorisation to test.")


class BoundaryViolation(RuntimeError):
    """A never-composed category arrived with a runnable argv."""


@dataclass(frozen=True)
class Command:
    """One suggested command, or one named reference to an uncomposed one."""

    tool: str
    category: Category
    argv: Optional[tuple[str, ...]] = None
    """Structured, not a shell string.

    Quoting happens once, in `rendered`, rather than at each construction
    site where one builder forgetting `shlex.quote` becomes an injection
    through a CVE title. `None` means this command was deliberately not
    composed -- see `reference`.
    """
    reference: str = ""
    """What to look up when `argv` is None. A module path, a template id."""
    source: str = ""
    """Which index asserted this mapping. An analyst weighing a suggestion
    needs to know whether it came from `script.db` or from a substring."""
    rationale: str = ""

    def __post_init__(self) -> None:
        # RC-31. `Category` subclasses `str`, so `Category.EXPLOIT == "exploit"`
        # and the two hash alike -- which made the membership test below look
        # type-safe when it was not. `"EXPLOIT"`, `" exploit"` and `"Exploit"`
        # are all equally plausible ways for a category to arrive from a feed,
        # a `script.db` row or a JSON body, and none of them are in
        # NEVER_COMPOSED. The tier check was therefore skipped entirely and
        # the command shipped composed, with `requires_opt_in` answering False
        # into the bargain. Normalise once, here, before any policy reads it.
        object.__setattr__(self, "category", coerce_category(self.category))
        if self.argv is not None:
            object.__setattr__(self, "argv", _clean_argv(self.tool, self.argv))
        if self.category in NEVER_COMPOSED and self.argv is not None:
            raise BoundaryViolation(
                f"{self.tool}: category {self.category.value} must not carry "
                f"a composed argv. Name it via `reference` instead.")
        if self.argv is None and not self.reference:
            raise ValueError(
                f"{self.tool}: a command with no argv must say what to look "
                "up, or it tells the analyst nothing.")

    @property
    def composed(self) -> bool:
        return self.argv is not None

    @property
    def requires_opt_in(self) -> bool:
        return self.category in OPT_IN_CATEGORIES

    @property
    def rendered(self) -> str:
        """Shell-ready text. The single place quoting happens."""
        if self.argv is None:
            return f"{self.reference}   (not composed; {self.category.value})"
        return " ".join(shlex.quote(part) for part in self.argv)

    def as_dict(self) -> dict:
        return {"tool": self.tool, "category": self.category.value,
                "composed": self.composed, "rendered": self.rendered,
                "argv": list(self.argv) if self.argv else None,
                "reference": self.reference, "source": self.source,
                "rationale": self.rationale,
                "requires_opt_in": self.requires_opt_in}


# --------------------------------------------------------------------------- #
# Builders. One per tool; each declares its own category.
# --------------------------------------------------------------------------- #

def searchsploit_commands(cve_id: str, product: str = "",
                          version: str = "") -> list[Command]:
    """Pure index lookup. Never contacts the target, so unambiguously safe."""
    out = [Command(
        tool="searchsploit", category=Category.SAFE,
        argv=("searchsploit", "--cve", _feed_argument(cve_id, 64)),
        source="exploitdb-index",
        rationale="Lists ExploitDB entries cross-referenced to this CVE. "
                  "Local index lookup; the target is not contacted.")]

    term = _feed_argument(
        " ".join(p for p in (product, version) if p), 200)
    if term:
        out.append(Command(
            tool="searchsploit", category=Category.SAFE,
            argv=("searchsploit", term), source="exploitdb-index",
            rationale=f"Catches entries filed against {term!r} that carry no "
                      "CVE cross-reference. ExploitDB's CVE column is sparse "
                      "for older submissions."))
    return out


def searchsploit_examine_commands(edb_id: str, title: str = "",
                                  platform: str = "",
                                  source: str = "exploitdb-index"
                                  ) -> list[Command]:
    """`searchsploit -x <id>`: read one local exploit file. Never composed
    against a target, because there is no target in it.

    Unambiguously `safe` in the NSE sense, and for the strongest available
    reason: the command opens a file in the operator's own exploitdb
    checkout and pages it. No packet leaves the machine, so none of the
    "does this crash the service" reasoning that governs the other builders
    applies at all.

    RC-32 discipline, second feed. `edb_id` arrives from a downloaded CSV,
    so it is validated before it is interpolated -- exactly as
    `validate_module_path` guards the Metasploit identifier. `title` and
    `platform` are equally attacker-influenceable and therefore go into the
    *rationale* only, never into `argv`: a rationale is prose an analyst
    reads, and an argv is a thing a shell runs, and the difference is worth
    holding even when both are quoted.
    """
    identifier = validate_edb_id(edb_id)
    context = ", ".join(p for p in (
        f"platform {_summarise(platform, 40)}" if platform else "",
        f"titled {_summarise(title, 120)!r}" if title else "") if p)
    return [Command(
        tool="searchsploit", category=Category.SAFE,
        argv=("searchsploit", "-x", identifier), source=source,
        rationale=(f"Displays ExploitDB entry {identifier}"
                   + (f" ({context})" if context else "")
                   + ". Reads a file from your local exploitdb checkout; "
                     "the target is not contacted and nothing is executed."))]


def nmap_commands(target: str, port: int, scripts: Sequence[str] = (),
                  categories: Optional[dict] = None) -> list[Command]:
    """NSE. The one source that publishes its own safety classification.

    `categories` maps script name to its `script.db` category list. Absent,
    a script is `unclassified` -- reconkg does not guess, because guessing
    permissively is the failure mode this module exists to prevent.
    """
    out = [Command(
        tool="nmap", category=Category.VERSION,
        argv=("nmap", "-sV", "-p", str(port), target), source="nmap",
        rationale="Re-runs service and version detection to confirm the "
                  "fingerprint this lead was built on.")]

    lookup = categories or {}
    for script in scripts:
        # RC-32 discipline, third feed. The name arrives from `script.db`,
        # which is Lua source an operator installed from the internet, and it
        # reaches argv in `--script <name>`. Checked before it is
        # interpolated anywhere -- including into the named-only branch,
        # where it is still text an operator will paste.
        script = validate_script_name(script)
        # RC-37. Not `_worst_category(script.db's claim)` -- that trusts the
        # row about a name that may not be a script at all. The name is part
        # of the verdict: `--script exploit` runs the exploit category
        # whatever a row says about it, and `--script all` runs everything.
        category = script_selection_category(script, lookup.get(script))
        if category in NEVER_COMPOSED:
            out.append(Command(
                tool="nmap", category=category,
                reference=f"nmap NSE script {script}", source="nmap script.db",
                rationale=f"{script} is category {category.value} in "
                          "script.db. Named rather than composed."))
            continue
        out.append(Command(
            tool="nmap", category=category,
            argv=("nmap", "-p", str(port), "--script", script, target),
            source="nmap script.db",
            rationale=f"{script} is category {category.value} in script.db."))
    return out


def http_probe_commands(target: str, port: int,
                        tls: bool = False) -> list[Command]:
    """Banner and certificate confirmation. A request any client makes."""
    scheme = "https" if tls else "http"
    out = [Command(
        tool="curl", category=Category.SAFE,
        argv=("curl", "-sSI", "--max-time", "10",
              f"{scheme}://{target}:{port}/"),
        source="builtin",
        rationale="Fetches response headers to confirm the server banner. "
                  "A HEAD request, which is what any browser sends.")]
    if tls:
        out.append(Command(
            tool="openssl", category=Category.SAFE,
            argv=("openssl", "s_client", "-connect", f"{target}:{port}",
                  "-servername", target),
            source="builtin",
            rationale="Reads the certificate and negotiated protocol; often "
                      "identifies the stack more precisely than the banner."))
    return out


def nuclei_commands(cve_id: str, target: str) -> list[Command]:
    """Nuclei publishes no safety classification, so this is unclassified.

    Its identification metadata is excellent -- `cve-id`, CVSS, EPSS, CWE,
    CPE -- but `tags` describes subject matter, not what running the template
    does. CVE-2026-0770 is tagged `rce` and is a working exploit; so are
    templates that merely fingerprint. Since the source cannot tell us,
    reconkg refuses to infer and files the whole tool under opt-in.
    """
    return [Command(
        tool="nuclei", category=Category.UNCLASSIFIED,
        argv=("nuclei", "-id", _feed_argument(cve_id, 64), "-u", target),
        source="nuclei-templates",
        rationale="Nuclei does not classify template safety. Many CVE "
                  "templates confirm a finding by exploiting it -- treat "
                  "this as intrusive unless you have read the template.")]


def metasploit_commands(module: str, target: str, port: Optional[int] = None,
                        category: Category = Category.INTRUSIVE,
                        source: str = "msf-index") -> list[Command]:
    """Configured up to `show options`, or named if the module exploits.

    `show options` is where an operator reads RHOSTS back and confirms it is
    the host they are authorised against. Metasploit put that step there
    deliberately. Composing past it, for every lead in a ledger, is the one
    thing that turns a triage tool into an exploitation chain.
    """
    category = coerce_category(category)
    # RC-32. The identifier comes from a downloaded index, so it is feed data
    # and is checked before it is interpolated anywhere -- including into the
    # named-only branch, where it is still text an operator will paste.
    module = validate_module_path(module)

    if category in NEVER_COMPOSED:
        return [Command(
            tool="msfconsole", category=category,
            reference=f"metasploit module {module}", source=source,
            rationale=f"{module} is an exploit module. reconkg names it so "
                      "you can find it; it does not aim it for you.")]

    setup = [f"use {module}", f"set RHOSTS {target}"]
    if port:
        setup.append(f"set RPORT {port}")
    setup.append("show options")

    # Belt and braces. Nothing above can currently append a firing verb, but
    # this function is the one place a future edit could, and the failure is
    # silent: the line would look exactly like the safe one.
    _refuse_firing_verbs(setup, module)

    return [Command(
        tool="msfconsole", category=category,
        argv=("msfconsole", "-q", "-x", "; ".join(setup)), source=source,
        rationale="Opens the module configured for this target and stops at "
                  "the options table. Check RHOSTS before you go further.")]


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #

#: Metasploit verbs that launch. `check` is deliberately absent -- it probes
#: for applicability without exploiting, which is the behaviour this tool is
#: for. `run` and `exploit` are synonyms in msfconsole; `rerun` and `rexploit`
#: reload and fire, and `-j`/`-z` variants background the session.
FIRING_VERBS = frozenset({"run", "exploit", "rerun", "rexploit", "rcheck"})

#: How msfconsole itself splits a `-x` string into statements. RC-32: the
#: check used to run per *setup step*, taking the first word of each. But the
#: steps are joined with "; " into a single argv element, and msfconsole then
#: re-splits that element on `;` and on newlines. A module identifier of
#: `exploit/multi/http/x; run` is one setup step whose first word is `use`,
#: and three statements once msfconsole is done with it -- the second being
#: `run`. `shlex.quote` does not help: the whole string is *meant* to be one
#: argument, and quoting it correctly is what delivers the payload intact.
_STATEMENT_SEPARATORS = re.compile(r"[;\r\n]")

#: A Metasploit module path as the index actually spells one. Deliberately
#: strict: identifiers come out of a downloaded JSON index, and every
#: character outside this set is a character that means something to
#: msfconsole's parser rather than to the module loader.
MODULE_PATH_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_./-]{0,255}\Z")

#: An ExploitDB identifier, as ExploitDB spells one. Stricter than the module
#: path because it can afford to be: the id is digits and nothing else, so
#: every other character is evidence the value did not come from the `id`
#: column intact.
EDB_ID_RE = re.compile(r"\A[0-9]{1,9}\Z")


def validate_edb_id(edb_id) -> str:
    """`50383` or `EDB-50383` -> `'50383'`. Anything else is a refusal.

    The same argument as `validate_module_path`, one feed along.
    `files_exploits.csv` is downloaded, so its `id` column is attacker
    -influenceable, and this value becomes an argument to a command an
    operator will paste. `shlex.quote` in `Command.rendered` makes it one
    shell word; it does not stop `-x --output=/etc/cron.d/x` from being an
    *option* to searchsploit rather than an id. Structure, not quoting, is
    what refuses that, and the structure of an ExploitDB id is: digits.
    """
    text = str(edb_id or "").strip()
    if text[:4].upper() == "EDB-":
        text = text[4:].strip()
    if not EDB_ID_RE.match(text):
        raise BoundaryViolation(
            f"exploit identifier {str(edb_id)!r} is not an ExploitDB id. An "
            "id is digits; a feed record carrying anything else is an "
            "argument smuggled into a command line, not an entry to display.")
    return text


#: An NSE script name as `script.db` spells one, minus the `.nse` suffix.
#: The first character must be alphanumeric: a name beginning with `-` is an
#: option to nmap, not a script.
SCRIPT_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def validate_script_name(script) -> str:
    """`http-shellshock.nse` or `http-shellshock` -> `'http-shellshock'`.

    The third feed, the same argument. `script.db` is Lua source rebuilt from
    whatever `.nse` files are in the operator's scripts directory, so a name
    in it is attacker-influenceable in exactly the way an ExploitDB id is,
    and it lands in `argv` as `nmap --script <name> <target>`.

    `shlex.quote` is not the control here. nmap's `--script` argument is an
    *expression* language -- `http-title,exploit/*` selects a script and then
    a whole category by glob, and `all` selects every script on the system --
    so a value that survives quoting intact as one shell word can still ask
    nmap to run something nobody chose. Structure refuses that; quoting
    cannot.
    """
    text = str(script or "").strip()
    # PROP-03. Repeated, not once: `scriptdb.safe_script_name` is the same
    # normalisation on the other side of the module boundary, and if the two
    # disagree about what `a.nse.nse` is called then the name the corpus is
    # keyed by is not the name this validator blesses.
    while text.lower().endswith(".nse"):
        text = text[:-len(".nse")].strip()
    if not SCRIPT_NAME_RE.match(text):
        raise BoundaryViolation(
            f"NSE script name {str(script)!r} is not a script name. nmap "
            "reads `--script` as an expression over names, globs and "
            "categories; a script.db row carrying separators, globs or "
            "whitespace is a selection smuggled into a command line, not a "
            "script to run.")
    return text


def _feed_argument(text, limit: int) -> str:
    """Feed-derived *prose* made safe to place in an argv element.

    PROP-05. `searchsploit_commands` interpolated the product and version
    straight from the fingerprint, and a fingerprint is banner text: it
    arrives in a POSTed evidence body (`stages` reads `entry["version"]`
    unfiltered) or out of an nmap file. A `\r` in it reached `_clean_argv`,
    which correctly refused it -- with a `ValueError` raised from the first
    line of `build_commands`, outside any handler, so one poisoned banner
    blanked the entire hand-off and the route answered 500.

    That is RC-39's finding at a different feed: a control raising in a place
    the caller does not expect is a denial of the whole feature rather than
    of the one bad value. The refusal in `_clean_argv` stays -- it is the
    backstop -- but text that is a *search term* rather than an identifier
    has no business carrying control characters in the first place, and the
    honest repair is to strip them here, where the value stops being prose
    and becomes an argument.

    Bounded as well: a 64KB banner is not a search term, and a command line
    an operator is expected to read has a length past which it is not one.
    """
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(text or ""))
    return " ".join(cleaned.split())[:limit].strip()


def _summarise(text, limit: int) -> str:
    """Feed text made safe to read in a terminal. Rationale use only.

    Control characters out, length bounded. A title is index data an operator
    reads off a terminal, and an embedded escape sequence can repaint the
    line it appears on -- which would let a poisoned row describe itself as
    something other than what the argv beside it actually does.
    """
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(text or "")).strip()
    return cleaned[:limit] + "..." if len(cleaned) > limit else cleaned


def coerce_category(value) -> Category:
    """A `Category`, or a `ValueError`. Never a bare string. (RC-31.)"""
    if isinstance(value, Category):
        return value
    try:
        return Category(str(value).strip().lower())
    except (ValueError, AttributeError):
        raise ValueError(
            f"{value!r} is not a command category. The vocabulary is NSE's: "
            f"{', '.join(c.value for c in Category)}.") from None


def _clean_argv(tool: str, argv) -> tuple[str, ...]:
    """Every argv element is a string with no statement separator in it.

    A newline or a NUL inside an argument survives `shlex.quote` -- quoting
    makes it one shell word, which is correct for the shell and irrelevant to
    the tool that then parses the word itself. Refusing them at construction
    is the only place the check is not tool-specific.
    """
    parts = tuple(argv)
    for part in parts:
        if not isinstance(part, str):
            raise ValueError(
                f"{tool}: argv elements must be strings, got {type(part).__name__}")
        if any(ch in part for ch in ("\x00", "\n", "\r")):
            raise ValueError(
                f"{tool}: argv element {part!r} carries a control character. "
                "Whatever produced it is not a command fragment.")
    return parts


def validate_module_path(module: str) -> str:
    r"""Refuse a module identifier that is really a command sequence.

    RC-39. This was the one validator in the module that did not `.strip()`
    before it matched, and `MODULE_PATH_RE` was anchored with `$` -- which in
    Python matches immediately *before* a trailing newline. That made
    `exploit/multi/http/x\n` a valid module path. It could not reach a
    composed argv (`_clean_argv` refuses control characters one frame later)
    but it reached `reference` on the never-composed branch, and the
    `ValueError` it provoked on the composed branch escaped `build_commands`
    entirely, taking the whole hand-off with it. Both anchors are now `\A`
    and `\Z`, here and in the two sibling patterns, so the shape of the
    check does not depend on remembering to strip.
    """
    text = str(module or "").strip()
    if not MODULE_PATH_RE.match(text):
        raise BoundaryViolation(
            f"module identifier {text!r} is not a module path. A feed record "
            "carrying separators or whitespace is a statement smuggled into "
            "an msfconsole `-x` string, not a module to `use`.")
    return text


def _refuse_firing_verbs(setup: Sequence[str], module: str) -> None:
    """Refuse anything that fires, as *msfconsole* would parse it.

    Splitting the way the consumer splits is the whole point: a check that
    tokenises differently from the thing it is protecting is a check that
    agrees with itself and with nothing else.
    """
    for step in setup:
        for statement in _STATEMENT_SEPARATORS.split(step):
            verb = statement.strip().split()[0].lower() if statement.strip() \
                else ""
            if verb in FIRING_VERBS:
                raise BoundaryViolation(
                    f"metasploit setup for {module} contains {verb!r}. "
                    "reconkg composes up to `show options` and stops; firing "
                    "is the operator's step.")


def normalise_categories(declared) -> tuple[str, ...]:
    """A declared-category collection, as a tuple of tokens. (RC-38.)

    RC-35 taught `_worst_category` that a bare string is one category and not
    seven, by special-casing `str` at the top of that function. That guard
    only helps a caller that hands the collection straight to it.
    `handoff._nse_selection` did not: it wrote

        declared = [str(c) for c in (entry.categories or ())]

    which performs the exact decomposition the guard exists to prevent, one
    frame before the guard runs. The standing lesson of RC-04/RC-07 and
    RC-14/RC-16 -- a control with two implementations has one implementation
    and one bypass -- applies to a *normalisation* just as much as to a
    check, so the normalisation is a function now and everything that unpacks
    a category collection calls it: `_worst_category`, `ScriptEntry`,
    `ScriptDB._write_batch`, `StaticScriptResolver` and `_nse_selection`.

    A non-iterable is one token rather than an error: this runs on the path
    that decides whether a command is composed, and the conservative reading
    of an unexpected shape is "one tag reconkg cannot recognise", which
    `_worst_category` resolves to `unclassified`.
    """
    if declared is None:
        return ()
    if isinstance(declared, (str, bytes, bytearray)):
        declared = [declared]
    try:
        items = list(declared)
    except TypeError:
        items = [declared]
    return tuple(_token(item) for item in items)


def _token(item) -> str:
    """One declared category as a plain lower-case token.

    PROP-04. `Category` subclasses `str`, so a member passes `isinstance(x,
    str)` and used to be handed on unchanged -- and every consumer then did
    `Category(str(name).strip().lower())`, where `str(Category.EXPLOIT)` is
    `'Category.EXPLOIT'`, not `'exploit'`. An entry declaring its categories
    with the project's own enum therefore resolved to `unclassified`, which
    is opt-in *composable*: `ScriptEntry("x.nse", "x", (Category.EXPLOIT,))`
    produced `nmap --script x <target>` behind one opt-in rather than a named
    reference.

    This is RC-35's finding reached through a different value shape. The
    guard there taught the collection layer that a bare string is one
    category; it did not teach it that an enum member is one category
    spelled in the type the API hands out. Unwrapped here, once, because
    this function is the single normalisation every consumer goes through.
    """
    if isinstance(item, Category):
        return item.value
    if isinstance(item, str):
        return item
    return str(item)


#: `--script all` is not an NSE category, so no category bookkeeping catches
#: it -- and it selects every script installed, including the four tiers this
#: project will not compose. Anything in here is treated as selecting the
#: worst of them.
_SELECTS_EVERYTHING = frozenset({"all"})


def script_selection_category(script, declared=()) -> Category:
    """What `nmap --script <name>` actually *runs*, not what the row claims.

    RC-37. `--script` takes an expression over script names, globs and
    category names, and a bare category name is a perfectly well-formed
    script name: `exploit` passes `validate_script_name` because there is
    nothing wrong with it as a name. `handoff._nse_selection` knew the rule
    -- "any name that is itself an NSE category classifies as itself" -- and
    applied it to exactly one hard-coded string, `vuln`. Every other name
    came out of `script.db`, which is a file rebuilt from whatever `.nse`
    files sit in the operator's scripts directory, so a row of

        Entry { filename = "exploit.nse", categories = { "safe", } }

    produced `nmap -p 80 --script exploit <target>` classified `safe`: the
    DEFAULT tier, no opt-in, no authorisation warning, and every
    exploit-category script on the machine aimed at the host.

    The row's claim is therefore a *floor*, never a ceiling. Whatever
    `script.db` says is resolved together with what the name itself selects,
    and `_worst_category` picks the more restrictive of the two -- so a row
    can make a script look more dangerous than it is, and cannot make a
    selector look safer than it is.
    """
    name = validate_script_name(script)
    tokens = list(normalise_categories(declared))
    lowered = name.lower()
    if lowered in _SELECTS_EVERYTHING:
        # `all` includes exploit, dos, fuzzer and brute by definition.
        tokens.append(Category.EXPLOIT.value)
    else:
        try:
            tokens.append(Category(lowered).value)
        except ValueError:
            pass                    # an ordinary script name; nothing added
    return _worst_category(tokens)


def _worst_category(declared: Iterable[str]) -> Category:
    """Most restrictive category wins.

    A script tagged both `safe` and `vuln` is treated as `vuln`. Taking the
    most permissive label would let a single benign tag launder everything
    beside it, which is precisely how the nuclei mistake would have happened.
    """
    # RC-35: a bare string is iterable, so `"exploit"` used to decompose into
    # seven unrecognised single characters and resolve to `unclassified` --
    # which is composable on opt-in. One row in a `script.db` parser written
    # to return a string rather than a list would have been enough. RC-38
    # moved the rule into `normalise_categories` because this was not the
    # only place that unpacked the collection.
    declared = normalise_categories(declared)

    seen: set[Category] = set()
    for name in declared:
        try:
            seen.add(Category(str(name).strip().lower()))
        except ValueError:
            # RC-35, second half: an unknown tag is *counted*, not dropped.
            # Dropping it left the recognised tags deciding alone, so
            # `["safe", "something-new"]` resolved to `safe` and was emitted
            # by default. nmap adds categories; this code should not assume
            # the ones it knows are all of them.
            seen.add(Category.UNCLASSIFIED)

    if not seen:
        return Category.UNCLASSIFIED

    # Resolution, in the order the Nmap book's own model implies.
    #
    # 1. A firing category decides outright.
    # 2. `vuln` next: it actively tests for a known flaw and, per the book,
    #    "touches the target in ways a plain port scan does not".
    # 3. Then the escalating topics -- `broadcast` adds hosts nobody named
    #    and `external` hands your target to a third party. Neither harms the
    #    target, and both override a `safe` tag because on an authorised
    #    engagement a scope breach is the failure that matters.
    # 4. Then the safety axis proper, most restrictive first.
    # 5. Topics with no safety label made no safety claim, so no verdict is
    #    inferred from them.
    for category in (Category.EXPLOIT, Category.DOS, Category.FUZZER,
                     Category.BRUTE, Category.VULN, Category.BROADCAST,
                     Category.EXTERNAL):
        if category in seen:
            return category

    # An unrecognised tag is present: no safety verdict can be trusted, so
    # none is returned, even if `safe` sits beside it.
    if Category.UNCLASSIFIED in seen:
        return Category.UNCLASSIFIED

    for category in (Category.INTRUSIVE, Category.VERSION, Category.SAFE):
        if category in seen:
            return category

    return Category.UNCLASSIFIED


def filter_commands(commands: Iterable[Command],
                    allowed: Optional[Iterable[Category]] = None
                    ) -> list[Command]:
    """Apply the operator's category selection.

    Never-composed commands always survive the filter. They carry no argv, so
    showing them costs nothing, and hiding them would mean an analyst is not
    told a working exploit exists -- which is information they need in order
    to judge how urgent the lead is.
    """
    permitted = ({coerce_category(a) for a in allowed} if allowed is not None
                 else set(DEFAULT_CATEGORIES))
    selected = list(commands)
    # The filter is the last thing every emission path runs, and a caller can
    # reach it without having gone through `build_commands`. Re-asserting the
    # boundary here costs one pass over a short list and removes the "which
    # entry point did this come in by" question entirely.
    assert_no_composed_exploits(selected)
    return [c for c in selected
            if coerce_category(c.category) in permitted or not c.composed]


def assert_no_composed_exploits(commands: Iterable[Command]) -> None:
    """Runtime backstop for the boundary.

    `Command.__post_init__` already refuses this, so reaching here means
    something constructed a Command by a route that bypassed it -- a
    `dataclasses.replace`, an unpickle, a future subclass. The check is cheap
    and the failure it guards is not recoverable by inspection.
    """
    for command in commands:
        # Re-coerced rather than trusted: the routes that reach here are
        # precisely the ones that skipped `__post_init__`, so the attribute
        # may hold whatever they put there -- including a string spelled in a
        # case that does not match the enum (RC-31).
        try:
            category = coerce_category(command.category)
        except ValueError:
            raise BoundaryViolation(
                f"{command.tool} carries an uninterpretable category "
                f"{command.category!r}; refusing to classify it as safe.")
        if category in NEVER_COMPOSED and command.composed:
            raise BoundaryViolation(
                f"{command.tool} carries a composed argv for category "
                f"{category.value}: {command.argv!r}")
