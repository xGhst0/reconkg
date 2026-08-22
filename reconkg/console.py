"""Operator console: an msfconsole-shaped REPL over the existing objects.

The module system already declares rank, references, typed options and
`info` rendering, and the registry already supports `rank:` / `cve:` /
`category:` search. None of it had a reader. This is the reader.

Three decisions worth defending:

**The console owns no logic.** Every command is a thin adapter over an object
that already exists -- `ModuleRegistry.search`, `OptionDataStore.set`,
`render_info`, `GapPlanner.plan`, `render_plan`, `parse_nmap_xml`, `ingest`,
`DiscoveryEngine.run`, `build_handoff`. A REPL that re-derives validation or
formatting drifts from the API surface within a cycle, and then two
"authoritative" answers disagree. Where behaviour looks missing here, it is
missing there.

**`execute(line) -> str` instead of print().** The dispatch layer returns
text and never touches stdin/stdout, so every command is testable as a pure
function of console state. `main()` is the only thing that reads a terminal.
This is also why there is no readline dependency in the core: a completion
library is a nice-to-have, and a test suite that needs a pty is not.

**`run` runs recon modules and nothing else.** It refuses any module outside
the `recon/` category, and vulnerability leads have no `run` path at all --
`vulns` lists them and `handoff` prints lookups plus the pre-filled
msfconsole line for you to paste yourself. That mirrors `planner.py`, where a
lead produces `action="handoff"` with `module=None`. There is no command in
the table that opens a socket, spawns a process, or delivers a payload, and
`tests/test_console.py` asserts it.

Errors are the product. An unknown command suggests the nearest match, `set`
on an unknown option lists the valid ones, `run` with a missing option names
it, and anything that raises is caught, reported, and the session continues.
An operator who mistypes at 3am should be corrected, not dropped into a
traceback with their state gone.
"""

from __future__ import annotations

import asyncio
import difflib
import logging
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from . import builtin_modules as _builtin_modules  # noqa: F401  (registers)
from .catalog import ExploitCatalog
from .engine import DiscoveryEngine, StageSlot
from .handoff import build_handoff
from .importers import ingest, parse_nmap_xml
from .modules import (ModuleRegistry, Rank, ReconModule,
                      registry as default_module_registry, render_info)
# `_table` is private to modules.py, and reimplementing column alignment here
# to avoid touching a leading underscore would be the worse trade: two
# renderers that drift. Noted for whoever next owns modules.py -- this wants
# to be public.
from .modules import _table as _render_table
from .planner import GapPlanner, render_plan
from .resolver import coerce, exploits_from_env, scripts_from_env
from .stages import EvidenceSource
from .store import TargetStore
from .vulnref import DEFAULT_REFERENCE, LedgerRow, VulnEntry

log = logging.getLogger(__name__)

BANNER = r"""
       =[ reconkg operator console ]
+ -- --=[ evidence in, ranked leads out. no sockets, no payloads. ]
+ -- --=[ `help` for commands, `search` for modules ]
"""

MAX_WORKSPACES = 32
"""RC-03/RC-18 class: `workspace <name>` is operator-supplied and creates on
first use, so it is a dict keyed on unbounded input. Capped."""

MAX_LEDGER_ROWS = 2000
"""A ledger is a worklist for a human. Past a couple of thousand rows nobody
reads it, and the memory is real -- re-import into a fresh workspace."""

MAX_HISTORY = 500

_MISSING_EVIDENCE_HINT = (
    "no evidence is staged under tool key {tool!r} for {target}. "
    "`import <nmap.xml>` first, or POST evidence to the API.")


# --------------------------------------------------------------------------- #
# Workspace
# --------------------------------------------------------------------------- #

@dataclass
class Workspace:
    """One graph plus its staged evidence and accumulated ledger.

    Workspaces exist so an operator can keep two engagements apart without
    restarting. They share nothing: separate `TargetStore`, separate
    `EvidenceSource`. A cross-workspace read would be exactly the scope leak
    RC-14/RC-16 were about.
    """

    name: str
    store: TargetStore = field(default_factory=TargetStore)
    evidence: EvidenceSource = field(default_factory=EvidenceSource)
    ledger: list[LedgerRow] = field(default_factory=list)

    def merge_ledger(self, rows: Iterable[LedgerRow]) -> int:
        """Add rows we have not already recorded. Returns how many were new.

        Correlation re-runs over the whole host on every `run`, so the same
        lead comes back each time. Dedupe on the identity of the lead, not on
        object equality -- priority can legitimately change between runs.
        """
        seen = {(r.target, r.protocol, r.port, r.cve_id) for r in self.ledger}
        added = 0
        for row in rows:
            key = (row.target, row.protocol, row.port, row.cve_id)
            if key in seen:
                continue
            if len(self.ledger) >= MAX_LEDGER_ROWS:
                log.warning("workspace %s ledger capped at %d rows",
                            self.name, MAX_LEDGER_ROWS)
                break
            self.ledger.append(row)
            seen.add(key)
            added += 1
        self.ledger.sort(key=lambda r: (r.priority, r.cvss), reverse=True)
        return added


# --------------------------------------------------------------------------- #
# Command table
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Command:
    name: str
    usage: str
    summary: str
    handler: str
    aliases: tuple[str, ...] = ()


COMMANDS: tuple[Command, ...] = (
    Command("help", "help [command]", "Show commands, or detail on one",
            "cmd_help", ("?",)),
    Command("search", "search <query> [rank:X] [cve:Y] [category:Z]",
            "Search declared module metadata", "cmd_search"),
    Command("use", "use <module|search-index>",
            "Select a module for configuration", "cmd_use"),
    Command("back", "back", "Deselect the current module", "cmd_back"),
    Command("info", "info [module]",
            "Full metadata, options and references", "cmd_info"),
    Command("show", "show options|advanced|missing|modules|all",
            "Show the selected module's datastore", "cmd_show"),
    Command("set", "set <OPTION> <value>",
            "Set a validated option on the selected module", "cmd_set"),
    Command("unset", "unset <OPTION>", "Reset an option to its default",
            "cmd_unset"),
    Command("run", "run", "Run the selected recon module against RHOST",
            "cmd_run"),
    Command("targets", "targets", "Hosts in this workspace", "cmd_targets",
            ("hosts",)),
    Command("services", "services [target]",
            "Ports, services and fingerprints", "cmd_services"),
    Command("vulns", "vulns [--min-priority X]",
            "The prioritised lead ledger", "cmd_vulns"),
    Command("plan", "plan [target]", "Gap analysis: what to do next",
            "cmd_plan"),
    Command("handoff", "handoff <CVE> [target] [--categories a,b]",
            "Verification lookups for a lead (runs nothing)", "cmd_handoff"),
    Command("import", "import <path-to-nmap.xml>",
            "Parse an nmap XML file into staged evidence", "cmd_import"),
    Command("catalog", "catalog [load exploitdb|metasploit <path>]",
            "Exploit index status (metadata only)", "cmd_catalog"),
    Command("workspace", "workspace [name]",
            "List or switch workspaces", "cmd_workspace"),
    Command("history", "history", "Commands issued this session",
            "cmd_history"),
    Command("exit", "exit", "Leave the console", "cmd_exit", ("quit",)),
)


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #

class Console:
    """Stateful REPL. `execute(line)` is the whole interface.

    Async plumbing note: the store and engine are async, and the store's lock
    binds itself to the first event loop that touches it. One `asyncio.run`
    per command would therefore bind a new loop each time and raise "bound to
    a different event loop" on the second command. So the console owns one
    long-lived loop for its whole session and drives every coroutine on it.
    """

    def __init__(self, *, registry: Optional[ModuleRegistry] = None,
                 catalog: Optional[ExploitCatalog] = None,
                 reference: Optional[Iterable[VulnEntry]] = None,
                 exploits=None, scripts=None,
                 principal: str = "operator",
                 workspace: str = "default",
                 autoload_catalog: bool = True) -> None:
        # `or` would be wrong: ModuleRegistry defines __len__, so an empty
        # registry is falsy and a caller passing one would silently get the
        # global. Same trap the planner documents.
        self.registry = (default_module_registry if registry is None
                         else registry)
        if catalog is None and autoload_catalog:
            # Autoload rather than wait for `catalog load`. Without a
            # catalogue `handoff` silently omits the pre-filled msfconsole
            # line -- the operator sees a lead with no follow-up and has no
            # way to know a module for it is sitting in their own install.
            # A missing index is not an error; autoload() reports "not
            # installed" and the console starts anyway.
            catalog = ExploitCatalog()
            try:
                self.catalog_report = catalog.autoload()
            except Exception as exc:          # never block startup on this
                log.warning("catalogue autoload failed: %s", exc)
                self.catalog_report = {"error": str(exc)}
        else:
            self.catalog_report = {}
        self.catalog = catalog
        # RC-36, on the console's side of the same fork. `reference` defaulted
        # to `DEFAULT_REFERENCE`, so `coerce` never reached `from_env` and the
        # REPL ran against the built-in nine while the API -- same host, same
        # environment -- resolved against the operator's corpus. Two code
        # paths disagreeing about which corpus is live is the bug this
        # codebase keeps finding; `None` means "ask the environment" here for
        # exactly the reason it does in `DiscoveryEngine`.
        self.resolver = coerce(reference)
        # The same wiring app.py needed, on the console's side of it.
        # RC-41 was exactly this shape: the API and the REPL are two callers
        # of one thing, and fixing one leaves the other answering
        # differently about the same host. `getattr` because the built-in
        # fixture is a StaticResolver with no feed paths to read.
        _load_signals = getattr(self.resolver, "signals", None)
        self.signals = _load_signals() if callable(_load_signals) else None
        self.reference = self.resolver
        """Where `build_handoff` reads notes and operator-supplied follow-ups.

        RC-41: this was a *list* -- `DEFAULT_REFERENCE` whenever a resolver
        was configured -- on the reasoning that an indexed corpus cannot be
        iterated. True, and beside the point: `build_handoff` never needed to
        iterate it, only to find one entry by CVE id. Handing it the nine
        built-ins meant the caveats and operator notes were correct for those
        nine and silently empty for every CVE the corpus actually produced.

        The resolver answers `entry_for(cve_id)` by primary key, so the
        lookup consults the same source that produced the lead. `app.py`
        passes its own resolver for the same reason; two paths reading
        different sources is the bug this file's own comment, eight lines
        up, was written about.
        """
        self.exploits = exploits if exploits is not None else exploits_from_env()
        self.scripts = scripts if scripts is not None else scripts_from_env()
        """Corpora two and three, on the same contract as the API's.

        Acquired at construction so a set-but-unopenable `RECONKG_EXPLOIT_DB`
        stops the console before it prints its first hand-off, rather than
        answering "no published exploits" for every lead of the session.
        Unset gets the Null variants, which say "not checked" out loud.
        """
        self.principal = principal
        self.module: Optional[ReconModule] = None
        self.running = True
        self.history: list[str] = []
        self.last_search: list[type[ReconModule]] = []
        self.workspaces: dict[str, Workspace] = {
            workspace: Workspace(name=workspace)}
        self.workspace = workspace
        self._loop = asyncio.new_event_loop()
        self._dispatch: dict[str, Command] = {}
        for command in COMMANDS:
            self._dispatch[command.name] = command
            for alias in command.aliases:
                self._dispatch[alias] = command

    # -- lifecycle ---------------------------------------------------------- #

    def close(self) -> None:
        """Idempotent: teardown that cannot be run twice is not teardown."""
        if not self._loop.is_closed():
            self._loop.close()
        # The Db variants hold an open SQLite connection each. A REPL is
        # long-lived and a test suite builds hundreds of consoles; neither
        # should depend on the garbage collector to give the handles back.
        for resolver in (self.resolver, self.exploits, self.scripts):
            closer = getattr(resolver, "close", None)
            if closer is None:
                continue
            try:
                closer()
            except Exception as exc:        # pragma: no cover - defensive
                log.warning("error closing %s: %s",
                            type(resolver).__name__, exc)

    def _await(self, coro):
        return self._loop.run_until_complete(coro)

    @property
    def ws(self) -> Workspace:
        return self.workspaces[self.workspace]

    @property
    def prompt(self) -> str:
        base = f"reconkg ({self.workspace})"
        if self.module is None:
            return f"{base} > "
        return f"{base} {self.module.meta.fullname} > "

    def banner(self) -> str:
        return BANNER

    # -- dispatch ----------------------------------------------------------- #

    def execute(self, line: str) -> str:
        """Run one input line (possibly several `;`-separated commands).

        `plan` emits copy-pasteable `use X; set RHOST y; run` lines, so the
        console has to accept them back verbatim or that output is a lie.
        """
        outputs = [self._execute_one(part) for part in _split_commands(line)]
        return "\n".join(o for o in outputs if o)

    def _execute_one(self, line: str) -> str:
        line = line.strip()
        if not line or line.startswith("#"):
            return ""
        if len(self.history) >= MAX_HISTORY:
            del self.history[0]
        self.history.append(line)

        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            return f"[-] Could not parse that line: {exc} (unbalanced quote?)"
        if not tokens:
            return ""

        name, args = tokens[0].lower(), tokens[1:]
        command = self._dispatch.get(name)
        if command is None:
            return self._unknown(name)

        try:
            return getattr(self, command.handler)(args)
        except KeyboardInterrupt:  # pragma: no cover - interactive only
            raise
        except Exception as exc:
            # Constraint: never crash the REPL. A command that raises loses
            # its own output, not the operator's session state.
            log.exception("console command %r raised", name)
            return (f"[-] {command.name} failed: {type(exc).__name__}: {exc}\n"
                    f"[*] Session is intact. `help {command.name}` for usage.")

    def _unknown(self, name: str) -> str:
        known = sorted(self._dispatch)
        near = difflib.get_close_matches(name, known, n=3, cutoff=0.5)
        near = near or [k for k in known if k.startswith(name[:2])][:3]
        hint = f" Did you mean: {', '.join(near)}?" if near else ""
        return (f"[-] Unknown command: {name!r}.{hint}\n"
                "[*] `help` lists every command.")

    # -- help --------------------------------------------------------------- #

    def cmd_help(self, args: list[str]) -> str:
        if args:
            command = self._dispatch.get(args[0].lower())
            if command is None:
                return self._unknown(args[0].lower())
            alias = (f"\n  Aliases: {', '.join(command.aliases)}"
                     if command.aliases else "")
            return (f"\n  {command.name}\n  {'-' * len(command.name)}\n"
                    f"  {command.summary}\n  Usage: {command.usage}{alias}\n")
        rows = [[c.name, c.summary] for c in COMMANDS]
        return ("\nCommands\n========\n"
                + _render_table(["Command", "Description"], rows) + "\n\n"
                "[*] reconkg reads evidence other tools produced. No command "
                "here contacts a target.\n")

    # -- module selection --------------------------------------------------- #

    def cmd_search(self, args: list[str]) -> str:
        query = " ".join(args)
        try:
            results = self.registry.search(query)
        except ValueError as exc:
            # `rank:nonsense` -- name the legal values rather than echoing
            # an enum repr at someone mid-engagement.
            ranks = ", ".join(r.value for r in Rank)
            return f"[-] Bad filter: {exc}\n[*] Valid ranks: {ranks}"
        self.last_search = results
        if not results:
            return (f"[*] No modules match {query!r}.\n"
                    "[*] Filters: rank:<manual..excellent> cve:<id> "
                    "category:<recon>")
        rows = []
        for index, cls in enumerate(results):
            meta = cls.meta
            rows.append([str(index), meta.fullname, meta.rank.value,
                         meta.disclosure_date.isoformat()
                         if meta.disclosure_date else "-",
                         meta.name])
        return ("\nMatching Modules\n================\n"
                + _render_table(["#", "Name", "Rank", "Disclosure",
                                 "Description"], rows)
                + f"\n\n[*] {len(results)} module(s). `use <name>` or "
                  "`use <#>`.\n")

    def _resolve(self, token: str) -> str:
        """Accept a search index as well as a fullname, as msfconsole does.

        The index is a second path into module selection, so it is bounds
        checked and then resolved through the same `registry.get` -- it
        cannot name a module the registry would refuse.
        """
        if token.isdigit():
            index = int(token)
            if not self.last_search:
                raise KeyError("no search results to index into; "
                               "run `search <query>` first")
            if index >= len(self.last_search):
                raise KeyError(
                    f"search index {index} out of range "
                    f"(0-{len(self.last_search) - 1})")
            return self.last_search[index].meta.fullname
        return token

    def cmd_use(self, args: list[str]) -> str:
        if not args:
            return "[-] use what? Usage: use <module|search-index>"
        try:
            fullname = self._resolve(args[0])
            # registry.get already builds a 'Did you mean' hint; surfacing
            # it beats writing a second, worse fuzzy matcher here.
            self.module = self.registry.create(fullname)
        except KeyError as exc:
            return f"[-] {_unwrap(exc)}"
        meta = self.module.meta
        missing = self.module.options.missing_required()
        tail = (f"\n[!] Required and unset: {', '.join(missing)}"
                if missing else "")
        return (f"[*] Using {meta.fullname} ({meta.rank.value})\n"
                f"[*] {meta.name}{tail}\n"
                "[*] `info` for detail, `show options` to configure.")

    def cmd_back(self, args: list[str]) -> str:
        if self.module is None:
            return "[*] No module selected."
        name = self.module.meta.fullname
        self.module = None
        return f"[*] Left {name}."

    def cmd_info(self, args: list[str]) -> str:
        if args:
            try:
                module = self.registry.create(self._resolve(args[0]))
            except KeyError as exc:
                return f"[-] {_unwrap(exc)}"
        elif self.module is not None:
            module = self.module
        else:
            return ("[-] No module selected and none named. "
                    "Usage: info [module]")
        return render_info(module)

    # -- datastore ---------------------------------------------------------- #

    def cmd_show(self, args: list[str]) -> str:
        what = (args[0].lower() if args else "options")
        if what == "modules":
            return self.cmd_search([])
        if self.module is None:
            return ("[-] No module selected. `use <module>` first, or "
                    "`show modules`.")
        store = self.module.options
        if what in ("options", "all"):
            out = ["\nModule options (" + self.module.meta.fullname + "):",
                   _render_table(["Name", "Current Setting", "Required",
                                  "Description"],
                                 [list(r) for r in store.rows(False)]), ""]
            if what == "all":
                out += ["Advanced options:",
                        _render_table(["Name", "Current Setting", "Required",
                                       "Description"],
                                      [list(r) for r in store.rows(True)]), ""]
            missing = store.missing_required()
            if missing:
                out.append(f"[!] Required and unset: {', '.join(missing)}")
            return "\n".join(out)
        if what == "advanced":
            return ("\nAdvanced options (" + self.module.meta.fullname
                    + "):\n"
                    + _render_table(["Name", "Current Setting", "Required",
                                     "Description"],
                                    [list(r) for r in store.rows(True)])
                    + "\n")
        if what == "missing":
            missing = store.missing_required()
            if not missing:
                return "[*] All required options are set."
            return ("[!] Required and unset: " + ", ".join(missing)
                    + "\n[*] set " + missing[0] + " <value>")
        return (f"[-] Cannot show {what!r}. "
                "Valid: options, advanced, missing, modules, all")

    def cmd_set(self, args: list[str]) -> str:
        if self.module is None:
            return ("[-] No module selected. `use <module>` before setting "
                    "options.")
        if len(args) < 2:
            return "[-] Usage: set <OPTION> <value>"
        name, raw = args[0], " ".join(args[1:])
        store = self.module.options
        if name not in store:
            valid = [o.name for o in store]
            near = difflib.get_close_matches(name.upper(), valid, n=1,
                                             cutoff=0.4)
            hint = f" Did you mean {near[0]}?" if near else ""
            return (f"[-] Unknown option {name.upper()!r} for "
                    f"{self.module.meta.fullname}.{hint}\n"
                    f"[*] Valid options: {', '.join(valid)}")
        try:
            # Validation belongs to OptionDataStore; the console's job is to
            # report the message it raises, not to second-guess it.
            value = store.set(name, raw)
        except ValueError as exc:
            option = store.option(name)
            return (f"[-] Rejected: {exc}\n"
                    f"[*] {option.name} is {option.type.value}"
                    + (f", one of: {', '.join(option.choices)}"
                       if option.choices else "")
                    + (f" -- {option.description}" if option.description
                       else ""))
        return f"[+] {name.upper()} => {store.option(name).display(value)}"

    def cmd_unset(self, args: list[str]) -> str:
        if self.module is None:
            return "[-] No module selected."
        if not args:
            return "[-] Usage: unset <OPTION>"
        store = self.module.options
        if args[0] not in store:
            return (f"[-] Unknown option {args[0].upper()!r}.\n"
                    f"[*] Valid options: "
                    f"{', '.join(o.name for o in store)}")
        store.unset(args[0])
        return (f"[+] {args[0].upper()} reset to default "
                f"({store.option(args[0]).display(store.get(args[0])) or '-'})")

    # -- execution ---------------------------------------------------------- #

    def cmd_run(self, args: list[str]) -> str:
        """Run the selected recon module. There is no exploit path here.

        Two guards, both structural rather than a policy flag: the module has
        to come from the registry (so it is a `ReconModule`, which consumes
        an `EvidenceSource` and cannot open a socket), and its declared
        category has to be `recon`. A future category is refused by default
        instead of being run by default.
        """
        if self.module is None:
            return ("[-] No module selected. `use <module>` first, then "
                    "`run`.\n[*] `search recon` to find one.")
        module = self.module
        if module.meta.category != "recon":
            return (f"[-] Refusing to run {module.meta.fullname}: only "
                    f"'recon/' modules are runnable from this console. "
                    "Vulnerability leads go to `handoff`.")
        missing = module.options.missing_required()
        if missing:
            first = missing[0]
            return (f"[-] Cannot run {module.meta.fullname}: required option "
                    f"{', '.join(missing)} not set.\n"
                    f"[*] set {first} <value>   (`show options` for the rest)")

        target = module.opt("RHOST")
        if target is None:
            return ("[-] This module declares no RHOST, so there is nothing "
                    "to scope the run to.")

        staged = (module.tool, target) in self.ws.evidence.fixtures
        engine = DiscoveryEngine(
            self.ws.store, self.ws.evidence,
            [StageSlot(module, [], label=module.meta.fullname)],
            reference=self.resolver, catalog=self.catalog,
            signals=self.signals)
        report = self._await(engine.run(target))

        rows = [[a.stage, a.outcome, f"{a.duration_ms:.2f}ms", a.detail]
                for a in report.attempts]
        out = [f"\n[*] Running {module.meta.fullname} against {target}",
               _render_table(["Stage", "Outcome", "Elapsed", "Detail"], rows),
               ""]
        if report.exhausted_slots:
            out.append(f"[!] Slot exhausted: "
                       f"{', '.join(report.exhausted_slots)}")
            if not staged:
                out.append("[!] " + _MISSING_EVIDENCE_HINT.format(
                    tool=module.tool, target=target))
        else:
            out.append(f"[+] {module.meta.fullname} completed "
                       f"({len(report.attempts)} attempt(s)).")
        added = self.ws.merge_ledger(report.ledger)
        if added:
            out.append(f"[+] {added} new lead(s) in the ledger -- `vulns` to "
                       "review, `handoff <CVE>` to act.")
        elif report.ledger:
            out.append(f"[*] {len(report.ledger)} lead(s), none new.")
        out.append("[*] `plan` for what is still unknown about this host.")
        return "\n".join(out)

    # -- graph readers ------------------------------------------------------- #

    def cmd_targets(self, args: list[str]) -> str:
        hosts = self.ws.store.list_hosts()
        if not hosts:
            return ("[*] No hosts in workspace "
                    f"{shlex.quote(self.workspace)}. "
                    "`import <nmap.xml>` to populate one.")
        rows = []
        for host in hosts:
            services = sum(1 for _ in host.iter_services())
            leads = sum(len(svc.leads) for _, svc in host.iter_services())
            rows.append([host.address, ",".join(host.hostnames) or "-",
                         str(len(host.ports)), str(services), str(leads),
                         f"{host.confidence:.2f}"])
        return ("\nHosts\n=====\n"
                + _render_table(["Address", "Hostnames", "Ports", "Services",
                                 "Leads", "Confidence"], rows) + "\n")

    def cmd_services(self, args: list[str]) -> str:
        hosts = self.ws.store.list_hosts()
        if args:
            hosts = [h for h in hosts if h.address == args[0]]
            if not hosts:
                return (f"[-] No such host: {shlex.quote(args[0])}. "
                        "`targets` lists what is known.")
        rows = []
        for host in hosts:
            for port in host.ports:
                svc = port.service
                fingerprints = svc.fingerprints if svc else []
                best = max(fingerprints, key=lambda f: f.confidence,
                           default=None)
                rows.append([
                    host.address, f"{port.protocol}:{port.number}",
                    port.state.value, svc.name if svc else "-",
                    (f"{best.product or '?'} {best.version or ''}".strip()
                     if best else "-"),
                    f"{best.confidence:.2f}" if best else "-"])
        if not rows:
            return "[*] No ports recorded yet. `import <nmap.xml>` first."
        return ("\nServices\n========\n"
                + _render_table(["Host", "Port", "State", "Service",
                                 "Fingerprint", "Conf"], rows) + "\n")

    def cmd_vulns(self, args: list[str]) -> str:
        floor = 0.0
        if args:
            if args[0] != "--min-priority":
                return (f"[-] Unknown argument {args[0]!r}. "
                        "Usage: vulns [--min-priority X]")
            if len(args) < 2:
                return "[-] --min-priority needs a number, e.g. 0.6"
            try:
                floor = float(args[1])
            except ValueError:
                return (f"[-] --min-priority must be a number, got "
                        f"{args[1]!r}")
        rows = [r for r in self.ws.ledger if r.priority >= floor]
        if not rows:
            if self.ws.ledger:
                return (f"[*] No leads at or above priority {floor:.2f} "
                        f"({len(self.ws.ledger)} below it).")
            return ("[*] No leads. Import evidence and `run` a fingerprint "
                    "module to correlate.")
        table = [[f"{r.priority:.3f}", r.cve_id, f"{r.cvss:.1f}",
                  f"{r.target}:{r.port}",
                  f"{r.product or '?'} {r.version or ''}".strip(),
                  r.maturity, f"{r.fingerprint_confidence:.2f}",
                  "DISPUTED" if r.disputed else ""] for r in rows]
        return ("\nAttack-surface ledger\n=====================\n"
                + _render_table(["Priority", "CVE", "CVSS", "Target",
                                 "Product", "Maturity", "Conf", "Flag"], table)
                + "\n\n[*] reconkg does not run these. "
                  "`handoff <CVE>` for verification lookups.\n")

    def cmd_plan(self, args: list[str]) -> str:
        planner = GapPlanner(self.registry)
        hosts = self.ws.store.list_hosts()
        if args:
            hosts = [h for h in hosts if h.address == args[0]]
            if not hosts:
                return (f"[-] No such host: {shlex.quote(args[0])}. "
                        "`targets` lists what is known.")
        if not hosts:
            return "[*] Nothing to plan against. `import <nmap.xml>` first."
        out = []
        for host in hosts:
            out.append(f"[*] Plan for {host.address}")
            out.append(render_plan(planner.plan(host)))
        return "\n".join(out)

    def cmd_handoff(self, args: list[str]) -> str:
        """Print lookups for a lead. Executes nothing, by construction.

        `build_handoff` shell-quotes every command it emits because operators
        paste these. Nothing here re-joins or unquotes that output.

        `--categories` is the console's spelling of the API's `?categories=`
        query parameter, and it is here so the two surfaces can be held to
        the same answer for the same selection. Omitted, both take
        `DEFAULT_CATEGORIES`: the opt-in tier stays out until it is asked
        for, on both paths.
        """
        try:
            args, selected = _split_categories(args)
        except ValueError as exc:
            return f"[-] {exc}"
        if not args:
            return "[-] Usage: handoff <CVE> [target]"
        wanted = args[0].upper()
        if not wanted.startswith("CVE-"):
            wanted = f"CVE-{wanted}"
        rows = [r for r in self.ws.ledger if r.cve_id.upper() == wanted]
        if len(args) > 1:
            rows = [r for r in rows if r.target == args[1]]
        if not rows:
            known = sorted({r.cve_id for r in self.ws.ledger})
            hint = (f"\n[*] In the ledger: {', '.join(known)}" if known
                    else "\n[*] The ledger is empty; `run` a fingerprint "
                         "module first.")
            return f"[-] No ledger entry for {wanted}.{hint}"
        return "\n".join(
            build_handoff(row, self.resolver, self.catalog, selected,
                          exploits=self.exploits,
                          scripts=self.scripts).render()
            for row in rows)

    # -- evidence ------------------------------------------------------------ #

    def cmd_import(self, args: list[str]) -> str:
        if not args:
            return "[-] Usage: import <path-to-nmap.xml>"
        path = Path(" ".join(args)).expanduser()
        try:
            result = parse_nmap_xml(path)
        except FileNotFoundError:
            return f"[-] No such scan file: {shlex.quote(str(path))}"
        except ValueError as exc:
            return f"[-] Refused {shlex.quote(str(path))}: {exc}"
        added = self._await(ingest(result, self.ws.store, self.ws.evidence,
                                   principal=self.principal))
        out = [result.summary(),
               f"[+] Staged as principal {self.principal!r} under tool keys "
               f"{result.port_tool} / {result.service_tool}"]
        if added:
            out.append(f"[*] next: use recon/discovery/connect_sweep; "
                       f"set RHOST {added[0]}; run")
        return "\n".join(out)

    def cmd_catalog(self, args: list[str]) -> str:
        if args and args[0] == "load":
            return self._catalog_load(args[1:])
        if self.catalog is None or len(self.catalog) == 0:
            return ("[*] Exploit index: empty. Maturity comes from the "
                    "declared reference only.\n"
                    "[*] `catalog load exploitdb <files_exploits.csv>` or "
                    "`catalog load metasploit <modules_metadata.json>`\n"
                    "[*] The index is metadata. Loading it runs nothing.")
        rows = [["records", str(len(self.catalog))],
                ["CVEs", str(self.catalog.cve_count)]]
        for source, stats in self.catalog.stats.items():
            rows.append([source, f"{stats.loaded} loaded, "
                                 f"{stats.skipped} skipped, "
                                 f"{stats.with_cve} with CVE"])
        return ("\nExploit index (metadata only)\n"
                "=============================\n"
                + _render_table(["Item", "Value"], rows) + "\n")

    def _catalog_load(self, args: list[str]) -> str:
        if len(args) < 2:
            return "[-] Usage: catalog load exploitdb|metasploit <path>"
        kind, path = args[0].lower(), " ".join(args[1:])
        if self.catalog is None:
            self.catalog = ExploitCatalog()
        loaders = {"exploitdb": self.catalog.load_exploitdb,
                   "edb": self.catalog.load_exploitdb,
                   "metasploit": self.catalog.load_metasploit,
                   "msf": self.catalog.load_metasploit}
        if kind not in loaders:
            return (f"[-] Unknown index type {kind!r}. "
                    "Valid: exploitdb, metasploit")
        try:
            stats = loaders[kind](path)
        except FileNotFoundError as exc:
            return f"[-] {exc}"
        return (f"[+] {kind}: {stats.loaded} record(s) loaded, "
                f"{stats.skipped} skipped, {stats.with_cve} carry a CVE")

    # -- session ------------------------------------------------------------- #

    def cmd_workspace(self, args: list[str]) -> str:
        if not args:
            rows = [["*" if name == self.workspace else "", name,
                     str(len(ws.store.list_hosts())), str(len(ws.ledger))]
                    for name, ws in self.workspaces.items()]
            return ("\nWorkspaces\n==========\n"
                    + _render_table(["Cur", "Name", "Hosts", "Leads"], rows)
                    + "\n")
        name = args[0]
        if name not in self.workspaces:
            if len(self.workspaces) >= MAX_WORKSPACES:
                return (f"[-] Workspace limit reached ({MAX_WORKSPACES}). "
                        "Reuse an existing one.")
            if not name.replace("-", "").replace("_", "").isalnum():
                return ("[-] Workspace names are alphanumeric plus - and _ "
                        f"(got {shlex.quote(name)}).")
            self.workspaces[name] = Workspace(name=name)
            self.workspace = name
            return f"[+] Created and switched to workspace {name}."
        self.workspace = name
        return f"[*] Workspace: {name}"

    def cmd_history(self, args: list[str]) -> str:
        if not self.history:
            return "[*] No history."
        return "\n".join(f"  {i:>3}  {line}"
                         for i, line in enumerate(self.history))

    def cmd_exit(self, args: list[str]) -> str:
        self.running = False
        return "[*] Leaving. The graph is in memory only; snapshot to keep it."


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _split_commands(line: str) -> list[str]:
    """Split on `;` outside quotes.

    Needed because `Recommendation.command()` renders exactly that shape.
    A naive `line.split(';')` would cut a semicolon inside a quoted banner.
    """
    parts, current, quote = [], [], ""
    for char in line:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
            current.append(char)
        elif char == ";":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [p for p in parts if p.strip()] or [""]


def _split_categories(args: list[str]):
    """Pull `--categories a,b,c` (or `--categories=a,b,c`) out of an argv.

    Returns the remaining positional arguments and either a list of
    `Category` or `None`. `None` is not the empty list: it means the operator
    said nothing and `build_handoff` applies `DEFAULT_CATEGORIES`, which is
    the same reading `app.handoff` gives an absent query parameter. An
    unknown name is refused by name rather than dropped -- silently ignoring
    it would answer a narrower question than the one that was asked, and look
    like the answer to the wider one.
    """
    from .commands import Category

    rest: list[str] = []
    raw: Optional[str] = None
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--categories":
            if index + 1 >= len(args):
                raise ValueError("--categories needs a comma-separated list, "
                                 "e.g. --categories safe,version")
            raw = args[index + 1]
            index += 2
            continue
        if token.startswith("--categories="):
            raw = token.split("=", 1)[1]
            index += 1
            continue
        rest.append(token)
        index += 1

    if raw is None or not raw.strip():
        # An empty value reads as "not sent", exactly as `app.handoff` reads
        # an empty query parameter. Two surfaces, one rule.
        return rest, None
    selected = []
    for name in raw.split(","):
        name = name.strip().lower()
        if not name:
            continue
        try:
            selected.append(Category(name))
        except ValueError:
            valid = ", ".join(c.value for c in Category)
            raise ValueError(f"unknown command category {name!r}. "
                             f"Valid: {valid}") from None
    return rest, selected


def _unwrap(exc: Exception) -> str:
    """KeyError stringifies with its own quotes; strip them for display."""
    text = str(exc)
    if text.startswith("'") and text.endswith("'"):
        return text[1:-1]
    return text


def main(argv: Optional[list[str]] = None) -> int:  # pragma: no cover
    """Terminal loop. Deliberately thin -- all behaviour is in execute()."""
    logging.basicConfig(level=logging.WARNING,
                        format="%(levelname)-7s %(name)-20s %(message)s")
    console = Console()
    print(console.banner())
    try:
        while console.running:
            try:
                line = input(console.prompt)
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print("^C  (`exit` to quit)")
                continue
            output = console.execute(line)
            if output:
                print(output)
    finally:
        console.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
