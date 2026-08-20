"""Hand-off: where reconkg stops and your own tooling starts.

This renders a lead into the lookup commands you would otherwise retype by
hand, with the target details filled in. It prints text. It does not execute
anything, and reconkg has no code path that does.

Deliberate constraint: the emitted commands are **lookups and references**
-- searchsploit queries, NVD links, the vendor advisory. Exploit-module paths
are not guessed. A fabricated module name that half-matches the CVE is worse
than no suggestion at all: it sends you down a wrong path with false
confidence, and it is the single most common way generated tooling wastes an
operator's afternoon. If you want a specific follow-up command attached to an
entry, put it in `VulnEntry.handoff` yourself -- an operator-supplied string
is verifiable in a way a generated guess is not.
"""

from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .commands import (BoundaryViolation, Category, Command,
                       DEFAULT_CATEGORIES, assert_no_composed_exploits,
                       coerce_category, filter_commands, http_probe_commands,
                       metasploit_commands, nmap_commands, normalise_categories,
                       nuclei_commands, searchsploit_commands,
                       searchsploit_examine_commands, validate_script_name,
                       INTRUSIVE_WARNING)
from .vulnref import LedgerRow, VulnEntry

log = logging.getLogger(__name__)

SCOPE_WARNING = (
    "reconkg does not run these. Confirm the target is in scope and that you "
    "are authorised before you do.")


@dataclass
class Handoff:
    row: LedgerRow
    lookups: list[str]
    references: list[str]
    caveats: list[str]
    operator_supplied: list[str]
    commands: list[Command] = field(default_factory=list)
    """Every suggested command, each carrying an NSE safety category.

    Replaces the old `msf_oneliners: list[str]`, whose name assumed one tool
    would ever matter and which carried no indication of what running the
    line would do to the target. See docs/COMMAND-MAPPING.md: safety is a
    property of the individual check, not of the tool.
    """

    def render(self) -> str:
        r = self.row
        out = [
            "",
            f"[*] Lead: {r.cve_id} on {r.target}:{r.port}/{r.protocol} "
            f"({r.service})",
            f"[*] Product: {r.product or 'unknown'} {r.version or ''}".rstrip(),
            f"[*] Priority {r.priority:.3f} | CVSS {r.cvss} | "
            f"maturity {r.maturity}",
            f"[*] Fingerprint confidence {r.fingerprint_confidence:.2f} "
            f"from {len(self.row.independent_principals)} independent "
            f"submitter(s): {', '.join(r.independent_principals) or 'none'}",
            "",
            "[*] Basis for this lead:",
            f"    {r.rationale}",
            "",
        ]
        if self.caveats:
            out.append("[!] Before you spend time on this:")
            out += [f"    - {c}" for c in self.caveats]
            out.append("")

        composed = [c for c in self.commands if c.composed]
        named = [c for c in self.commands if not c.composed]

        if composed:
            out.append("[*] Commands, by what they do to the target:")
            for command in composed:
                flag = " [OPT-IN]" if command.requires_opt_in else ""
                out.append(f"    ({command.category.value}){flag} "
                           f"{command.rendered}")
                out.append(f"        {command.rationale}")
            if any(c.requires_opt_in for c in composed):
                out.append(f"    [!] {INTRUSIVE_WARNING}")
            out.append("")

        if named:
            # Named but not composed. An analyst needs to know a working
            # exploit exists -- that is most of what tells them how urgent
            # this lead is -- without reconkg aiming it for them.
            out.append("[*] Known exploit tooling for this CVE "
                       "(named, not composed):")
            for command in named:
                out.append(f"    ({command.category.value}) "
                           f"{command.reference}   [{command.source}]")
            out.append("")

        if self.lookups:
            out.append("[*] Verification lookups:")
            out += [f"    {c}" for c in self.lookups]
            out.append("")

        if self.operator_supplied:
            out.append("[*] Operator-supplied follow-up for this entry:")
            out += [f"    {c}" for c in self.operator_supplied]
            out.append("")

        out.append("[*] References:")
        out += [f"    {u}" for u in self.references]
        out += ["", f"[!] {SCOPE_WARNING}", ""]
        return "\n".join(out)


def _caveats(row: LedgerRow, entry: Optional[VulnEntry]) -> list[str]:
    """The reasons this lead might be a waste of your time.

    Stating these up front is the whole value of the ledger. A tool that only
    ever says "here is a critical finding" trains you to ignore it.
    """
    out: list[str] = []
    if getattr(row, "disputed", False):
        out.append(
            "DISPUTED: another credible source claims a different version for "
            "this service. At most one of them is right, so this lead may be "
            "built on the wrong one. Resolve the conflict first.")
    if len(row.independent_principals) < 2:
        out.append(
            "Only one independent submitter backs this fingerprint. Nothing "
            "has corroborated it -- treat the version as a claim, not a fact.")
    if row.fingerprint_confidence < 0.6:
        out.append(
            f"Fingerprint confidence is {row.fingerprint_confidence:.2f}. "
            "Re-fingerprint before committing time to this.")
    if row.product and "apache" in row.product.lower():
        out.append(
            "Distribution backports: RHEL/Debian patch in place while leaving "
            "the version string alone. A version match is not a patch-level "
            "match.")
    if row.maturity in ("theoretical", "not_defined"):
        out.append("No known working technique is recorded for this entry.")
    if entry is not None and entry.notes:
        out.append(entry.notes)
    return out


MAX_EXPLOIT_COMMANDS = 5
"""How many `searchsploit -x` lines one lead may carry.

Some CVEs have forty indexed entries. Printing all forty is not thoroughness,
it is a wall the analyst scrolls past, and the resolver has already ranked
them -- verified first, platform match next. The remainder is *named* in a
line of its own rather than dropped, because a silent cut here is the same
bug as bug 4 in CORPUS-PATTERN.md wearing different clothes.
"""


def build_handoff(row: LedgerRow, reference: Iterable[VulnEntry] = (),
                  catalog=None,
                  allowed: Optional[Iterable[Category]] = None,
                  exploits=None, scripts=None) -> Handoff:
    # RC-41. `reference` may be a plain iterable (the built-in nine, and what
    # every test passes) or a Resolver. It must be allowed to be a resolver,
    # because the entry found here supplies the caveats and the
    # operator-supplied commands, and looking those up in a list that did not
    # produce the lead means they are silently absent for every CVE that came
    # from a real corpus -- which, once a corpus is configured, is all of
    # them. The nine built-ins kept working, which is exactly why nothing
    # noticed until an integration test asked.
    entry = _entry_for(reference, row.cve_id)
    cve = shlex.quote(row.cve_id)
    product = shlex.quote(f"{row.product or ''} {row.version or ''}".strip())

    # RC-34. `--script vuln` runs the whole NSE vuln category, several of
    # whose scripts are intrusive; `build_commands` classifies exactly this
    # invocation as `vuln` and withholds it until the operator opts in. This
    # list then emitted the same line as plain text under the heading
    # "Verification lookups", with no category, no opt-in and no
    # authorisation warning -- the control enforced on one path and bypassed
    # on the second, inside a single function.
    permitted = ({coerce_category(a) for a in allowed} if allowed is not None
                 else set(DEFAULT_CATEGORIES))
    lookups = [
        f"searchsploit --cve {cve}",
        f"searchsploit {product}" if product else "",
        (f"nmap -sV -p {row.port} --script vuln {shlex.quote(row.target)}"
         if Category.VULN in permitted else ""),
    ]
    lookups = [c for c in lookups if c]

    references = [f"https://nvd.nist.gov/vuln/detail/{row.cve_id}",
                  f"https://www.cve.org/CVERecord?id={row.cve_id}"]

    operator = list(getattr(entry, "handoff", ()) or ()) if entry else []

    commands = build_commands(row, catalog, allowed, exploits, scripts)
    return Handoff(row=row, lookups=lookups, references=references,
                   caveats=_caveats(row, entry), operator_supplied=operator,
                   commands=commands)


MAX_SCRIPT_COMMANDS = 5
"""How many `script.db`-matched NSE scripts one lead may carry.

`http` alone matches over a hundred scripts in a stock nmap install. The
store has already ordered them -- CVE-named first, then the protocol family
-- so the cut loses the weakest candidates, and the remainder is named in a
line of its own rather than dropped (bug 4).
"""


def _nse_selection(row: LedgerRow, scripts) -> tuple[tuple[str, ...],
                                                     dict, int]:
    """Which NSE scripts this lead gets, and what `script.db` says they are.

    This is what replaced `categories={"vuln": ["vuln"]}` -- a two-entry
    dictionary standing in for the ~600 scripts a real nmap install carries,
    which meant every script outside it resolved to `unclassified`.

    `vuln` stays in the list and is still classified `vuln`, and that is not
    a leftover hard-coding: `--script vuln` names a *category*, not a script,
    so what the invocation runs is that category by definition. The rule is
    stated rather than tabulated -- any name that is itself an NSE category
    classifies as itself -- so the same line covers a future `--script auth`
    without a second entry to forget.

    With no resolver configured nothing else is added and the emitted set is
    byte-for-byte what it was before this corpus existed. That is the point:
    an operator who has not pointed `RECONKG_SCRIPT_DB` anywhere gets today's
    behaviour, and unclassified stays opt-in.
    """
    selected: list[str] = ["vuln"]
    categories: dict[str, list[str]] = {"vuln": _self_category("vuln")}
    if scripts is None:
        return tuple(selected), categories, 0

    try:
        found = list(scripts.scripts_for(row.service or "", row.cve_id))
    except Exception as exc:                # pragma: no cover - defensive
        log.warning("script index lookup failed for %s: %s", row.cve_id, exc)
        return tuple(selected), categories, 0

    for entry in found[:MAX_SCRIPT_COMMANDS]:
        raw = str(getattr(entry, "name", "") or "")
        try:
            # RC-32 discipline. One poisoned row costs that row and a
            # warning, not the hand-off -- and it is dropped here rather than
            # in `nmap_commands`, where the whole list shares one call.
            name = validate_script_name(raw)
        except (BoundaryViolation, ValueError) as exc:
            log.warning("dropping script.db row %r for %s: %s", raw,
                        row.cve_id, exc)
            continue
        if name in categories:
            continue
        # RC-38. `[str(c) for c in ...]` is the decomposition RC-35's guard
        # in `_worst_category` exists to prevent, performed one frame before
        # the guard can run: a `categories` of `"exploit"` became seven
        # unrecognised single characters, resolved to `unclassified`, and an
        # exploit script shipped composed with the target in it. Both
        # branches take arbitrary objects -- `scripts` is a `ScriptResolver`,
        # which is a protocol a third party implements -- so both normalise.
        declared = list(normalise_categories(
            getattr(entry, "categories", ()) or ()))
        if not declared:
            declared = list(normalise_categories(
                scripts.categories_for(name)))
        # A row that declared nothing made no safety claim. Unclassified is
        # the conservative reading and the one COMMAND-MAPPING.md argues for.
        categories[name] = declared or [Category.UNCLASSIFIED.value]
        selected.append(name)

    return tuple(selected), categories, max(0, len(found) - MAX_SCRIPT_COMMANDS)


def _script_help_expression(row: LedgerRow) -> str:
    """The `--script-help` expression that lists the rest, or `default`.

    Built from `service_prefixes`, whose output is a bounded token from a
    fixed table or a `[a-z][a-z0-9]{1,15}` match -- never the raw service
    string. This lands in a rationale an operator reads and may paste, which
    is prose rather than argv, and the distinction is worth holding even
    where both are safe.
    """
    from .scriptdb import service_prefixes

    prefixes = service_prefixes(getattr(row, "service", "") or "")
    return ",".join(f"{p}-*" for p in prefixes) or "default"


def _self_category(name: str) -> list[str]:
    """`--script <name>` where `name` is an NSE category runs that category."""
    try:
        return [coerce_category(name).value]
    except ValueError:                      # pragma: no cover - defensive
        return [Category.UNCLASSIFIED.value]


def build_commands(row: LedgerRow, catalog=None,
                   allowed: Optional[Iterable[Category]] = None,
                   exploits=None, scripts=None) -> list[Command]:
    """Assemble every command for a lead, then apply the category filter.

    Built first and filtered second, deliberately. Filtering during
    construction would mean each builder re-implementing the policy, and the
    policy is the security control -- it belongs in exactly one place.
    """
    out: list[Command] = []
    out += searchsploit_commands(row.cve_id, row.product or "",
                                 row.version or "")
    selected, categories, extra_scripts = _nse_selection(row, scripts)
    out += nmap_commands(row.target, row.port, scripts=selected,
                         categories=categories)
    if extra_scripts > 0:
        out.append(Command(
            tool="nmap", category=Category.UNCLASSIFIED,
            reference=(f"{extra_scripts} further NSE scripts match this "
                       f"service or CVE"),
            source="nmap script.db",
            rationale="Only the highest-ranked matches are composed above "
                      "(CVE-named first, then the protocol family). List the "
                      "rest with `nmap --script-help "
                      f"'{_script_help_expression(row)}'`."))

    service = (row.service or "").lower()
    if "http" in service:
        out += http_probe_commands(row.target, row.port,
                                   tls="https" in service or "ssl" in service)
        out += nuclei_commands(row.cve_id, row.target)

    if catalog is not None:
        for record in catalog.records_for(row.cve_id):
            # Metasploit records only. An ExploitDB record is a file to read,
            # not a module to `use`, and composing `use EDB-50383` would be a
            # command that cannot work -- worse than none, because it looks
            # authoritative.
            if getattr(record, "source", "") != "metasploit":
                continue
            module = str(getattr(record, "identifier", "") or "")
            if not module.startswith(("exploit/", "auxiliary/", "post/")):
                continue
            # Intrusive, not exploit. The module exploits; the command
            # reconkg composes configures it and prints the options table,
            # which opens no connection at all. Classifying by the module's
            # path rather than by what the command does would have made every
            # msf suggestion uncomposable -- a stricter line than the one
            # this project actually holds, moved silently.
            try:
                out += metasploit_commands(str(module), row.target, row.port,
                                           category=Category.INTRUSIVE)
            except (BoundaryViolation, ValueError) as exc:
                # RC-32: one poisoned index record must not blank the whole
                # hand-off, and it must not be silent either -- a record that
                # tried to smuggle a statement is a fact about the feed.
                #
                # RC-39: `ValueError` as well. The promise above was written
                # against `BoundaryViolation`, but the boundary is enforced
                # in two exception types -- `validate_module_path` raises the
                # first and `Command._clean_argv` raises the second -- so a
                # record refused by the second one took the entire hand-off
                # with it and the API answered 500. Catching one of the two
                # types a control raises is the same defect as implementing
                # it in one of the two places it runs.
                log.warning("dropping metasploit record %r for %s: %s",
                            module, row.cve_id, exc)

    out += _exploit_commands(row, exploits)

    assert_no_composed_exploits(out)
    return filter_commands(out, allowed)


def _entry_for(reference, cve_id: str) -> Optional[VulnEntry]:
    """Find one entry, whether `reference` is a resolver or an iterable."""
    lookup = getattr(reference, "entry_for", None)
    if callable(lookup):
        try:
            return lookup(cve_id)
        except Exception as exc:                # pragma: no cover - defensive
            log.warning("entry lookup failed for %s: %s", cve_id, exc)
            return None

    key = str(cve_id or "").strip().upper()
    try:
        return next((e for e in reference
                     if str(getattr(e, "cve_id", "")).upper() == key), None)
    except TypeError:
        return None


def _exploit_commands(row: LedgerRow, exploits) -> list[Command]:
    """`searchsploit -x` for each indexed ExploitDB entry on this CVE.

    Corpus two's whole output. The chain is CVE -> ExploitDB entry -> tool ->
    command, and this is where it terminates: a local file read, category
    `safe`, that never touches the target.

    Everything reaching `argv` here has been through
    `commands.validate_edb_id`, because it came out of a CSV downloaded over
    the network. The title and platform reach the rationale only. One
    poisoned row costs that row and a warning, not the hand-off -- the same
    rule the metasploit branch above learned in RC-32.
    """
    if exploits is None:
        return []
    try:
        records = list(exploits.exploits_for(row.cve_id))
    except Exception as exc:                # pragma: no cover - defensive
        log.warning("exploit index lookup failed for %s: %s", row.cve_id, exc)
        return []

    out: list[Command] = []
    for record in records[:MAX_EXPLOIT_COMMANDS]:
        identifier = str(getattr(record, "identifier", "") or "")
        try:
            out += searchsploit_examine_commands(
                identifier,
                title=str(getattr(record, "title", "") or ""),
                platform=str(getattr(record, "platform", "") or ""),
                source="exploitdb-corpus")
        except (BoundaryViolation, ValueError) as exc:
            log.warning("dropping exploit index record %r for %s: %s",
                        identifier, row.cve_id, exc)

    extra = len(records) - MAX_EXPLOIT_COMMANDS
    if extra > 0:
        # Named, not composed, and not silently dropped. The analyst needs to
        # know the count -- "twelve more published exploits" is itself a
        # statement about how exposed this service is.
        out.append(Command(
            tool="searchsploit", category=Category.SAFE,
            reference=(f"{extra} further ExploitDB entries indexed for "
                       f"{row.cve_id}"),
            source="exploitdb-corpus",
            rationale="Only the highest-ranked entries are composed above "
                      "(verified first, then platform match, then newest). "
                      "List the rest with "
                      f"`searchsploit --cve {row.cve_id}`."))
    return out


def render_handoff(row: LedgerRow, reference: Iterable[VulnEntry] = (),
                   catalog=None,
                   allowed: Optional[Iterable[Category]] = None,
                   exploits=None, scripts=None) -> str:
    return build_handoff(row, reference, catalog, allowed, exploits,
                         scripts).render()
