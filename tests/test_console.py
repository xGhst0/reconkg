"""Console tests: exact output, not 'it did not raise'.

Every test drives `Console.execute()` and asserts on the string it returns.
Nothing here needs a pty, a subprocess or readline -- if a test ever does,
the console has grown logic that belongs in the objects underneath it.

The assertions pin operator-visible text, because for a REPL the text *is*
the behaviour. A `set` that rejects a bad port silently is a different
product from one that says "RPORT must be 1-65535", and only the second one
gets an operator un-stuck at 3am.
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import pytest

from reconkg.builtin_modules import BUILTIN_MODULES
from reconkg.catalog import ExploitCatalog
from reconkg.console import (COMMANDS, MAX_WORKSPACES, Console, Workspace,
                             _split_commands)
from reconkg.modules import (ModuleInfo, ModuleRegistry, Option, OptType,
                             Rank, ReconModule, Reference, RefType)
from reconkg.stages import Outcome, StageResult

FIXTURES = Path(__file__).parent / "fixtures"
NMAP_XML = FIXTURES / "nmap_sV_localhost.xml"

SWEEP_RUN = "use recon/discovery/connect_sweep; set RHOST 127.0.0.1; run"
BANNER_RUN = "use recon/fingerprint/banner_probe; set RHOST 127.0.0.1; run"


# --------------------------------------------------------------------------- #
# Test modules -- registered into a local registry, never the global one, so
# these cannot leak into another test file's search results.
# --------------------------------------------------------------------------- #

class PortProbeModule(ReconModule):
    """Carries the typed options the built-ins happen not to declare."""

    name = "test-port-probe"
    technique = "test"
    tool = "nmap-sV"
    meta = ModuleInfo(
        fullname="recon/test/port_probe",
        name="Typed-option test probe",
        description="Exercises PORT and ENUM validation from the console.",
        authors=("test suite",),
        rank=Rank.GOOD,
        references=(Reference(RefType.CVE, "2021-41773"),),
    )
    option_spec = (
        Option("RHOST", OptType.ADDRESS, None, True, "Target address"),
        Option("RPORT", OptType.PORT, 8080, False, "Port to scope to"),
        Option("MODE", OptType.ENUM, "fast", False, "Probe depth",
               choices=("fast", "deep")),
    )

    async def run(self, address, evidence, context):
        return StageResult(Outcome.NO_DATA, "test module collected nothing")


class LootModule(ReconModule):
    """A module outside `recon/`. The console must refuse to run it."""

    name = "test-loot"
    technique = "test"
    tool = "nmap-sV"
    meta = ModuleInfo(fullname="post/test/loot_grab", name="Post-ex stand-in",
                      description="Not a recon module.", rank=Rank.NORMAL)
    option_spec = (Option("RHOST", OptType.ADDRESS, "127.0.0.1", True,
                          "Target address"),)

    async def run(self, address, evidence, context):  # pragma: no cover
        raise AssertionError("the console must never run a non-recon module")


_REAL_AUTOLOAD = ExploitCatalog.autoload
"""Captured before the isolation fixture rebinds the attribute, so the
fixture can still run the real loader -- against paths that do not exist."""


@pytest.fixture(autouse=True)
def no_host_exploit_indexes(tmp_path):
    """Point catalogue autoload at a directory that does not exist.

    `Console()` autoloads by default, and `DEFAULT_EDB_PATHS` /
    `DEFAULT_MSF_PATHS` name the exact files Kali ships. On the box this
    console is written for, every console here therefore started with
    46,968 Exploit-DB rows and 6,160 Metasploit entries already loaded, and
    `catalog` reported an index where this file asserts an empty one. Green
    in CI, red on a real host, is the least useful failure a suite has: the
    test was reading the machine instead of controlling it.

    Patched on `ExploitCatalog` rather than passing `autoload_catalog=False`
    to each console: `autoload`'s path tuples are default arguments bound at
    def time, so rebinding the module constants isolates nothing, and an
    autouse fixture also covers the consoles built inside a test body rather
    than through the `console` fixture -- the second path, which is where
    this project keeps losing controls.

    The real loader still runs; only the paths change. The branch exercised
    is "not installed", which is what a machine without searchsploit reports
    and what every assertion in this file has always assumed.

    Its own `MonkeyPatch`, not the `monkeypatch` fixture: a test below calls
    `monkeypatch.undo()` mid-test, and undo() is all-or-nothing on the
    instance it is called on. Sharing one would let a test silently hand the
    host's indexes back to any console it built afterwards.
    """
    absent = tmp_path / "no-such-index-dir"

    def autoload_from_nowhere(self, *args, **kwargs):
        # Caller-supplied paths are ignored rather than forwarded: nothing
        # here passes any, and honouring them would reopen the hole.
        return _REAL_AUTOLOAD(
            self,
            edb_paths=(str(absent / "files_exploits.csv"),),
            msf_paths=(str(absent / "modules_metadata_base.json"),))

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ExploitCatalog, "autoload", autoload_from_nowhere)
        yield


@pytest.fixture()
def registry() -> ModuleRegistry:
    reg = ModuleRegistry()
    for cls in BUILTIN_MODULES:
        reg.register(cls)
    reg.register(PortProbeModule)
    reg.register(LootModule)
    return reg


@pytest.fixture()
def console(registry, no_host_exploit_indexes):
    # The isolation fixture is autouse, so this argument changes nothing at
    # runtime; it is here so the ordering is a declared dependency rather
    # than an assumption about how pytest sequences autouse fixtures.
    con = Console(registry=registry)
    yield con
    con.close()


# --------------------------------------------------------------------------- #
# help / dispatch
# --------------------------------------------------------------------------- #

def test_help_lists_every_command(console):
    out = console.execute("help")
    for command in COMMANDS:
        assert command.name in out
    assert "No command here contacts a target." in out


def test_help_on_one_command_shows_usage(console):
    out = console.execute("help vulns")
    assert "Usage: vulns [--min-priority X]" in out
    assert "The prioritised lead ledger" in out


def test_unknown_command_suggests_the_nearest_match(console):
    out = console.execute("serch apache")
    assert "[-] Unknown command: 'serch'." in out
    assert "Did you mean: search" in out
    assert "`help` lists every command." in out


def test_unknown_help_topic_is_not_a_traceback(console):
    assert "Unknown command: 'wat'" in console.execute("help wat")


def test_empty_and_comment_lines_produce_nothing(console):
    assert console.execute("") == ""
    assert console.execute("   ") == ""
    assert console.execute("# a note to self") == ""


def test_unbalanced_quote_is_reported_not_raised(console):
    out = console.execute('set RHOST "127.0.0.1')
    assert "[-] Could not parse that line" in out
    assert "unbalanced quote?" in out


# --------------------------------------------------------------------------- #
# search / use / info
# --------------------------------------------------------------------------- #

def test_search_renders_rank_and_index(console):
    out = console.execute("search category:recon")
    assert "Matching Modules" in out
    assert "recon/discovery/syn_sweep" in out
    assert "great" in out
    assert "`use <name>` or `use <#>`" in out


def test_search_supports_cve_filter(console):
    out = console.execute("search cve:2021-41773")
    assert "recon/test/port_probe" in out
    assert "recon/discovery/syn_sweep" not in out


def test_search_bad_rank_names_the_valid_ones(console):
    out = console.execute("search rank:bogus")
    assert out.startswith("[-] Bad filter:")
    assert "Valid ranks: manual, low, normal, good, great, excellent" in out


def test_search_with_no_hits_explains_the_filters(console):
    out = console.execute("search zzzznothing")
    assert "[*] No modules match 'zzzznothing'." in out
    assert "rank:<manual..excellent>" in out


def test_use_bad_module_surfaces_the_registry_suggestion(console):
    out = console.execute("use recon/fingerprint/banner_prob")
    assert "[-] no such module: recon/fingerprint/banner_prob." in out
    assert "Did you mean: recon/fingerprint/banner_probe?" in out
    assert console.module is None


def test_use_by_search_index_is_bounds_checked(console):
    console.execute("search category:recon")
    assert "[-] search index 99 out of range" in console.execute("use 99")
    fresh = Console(registry=console.registry)
    try:
        assert "[-] no search results to index into" in fresh.execute("use 0")
    finally:
        fresh.close()


def test_use_selects_and_warns_about_required_options(console):
    out = console.execute("use recon/fingerprint/banner_probe")
    assert "[*] Using recon/fingerprint/banner_probe (normal)" in out
    assert "[!] Required and unset: RHOST" in out
    assert console.prompt == (
        "reconkg (default) recon/fingerprint/banner_probe > ")


def test_back_clears_the_module(console):
    console.execute("use recon/fingerprint/banner_probe")
    assert console.execute("back") == "[*] Left recon/fingerprint/banner_probe."
    assert console.module is None
    assert console.execute("back") == "[*] No module selected."


def test_info_renders_metadata_and_references(console):
    out = console.execute("info recon/fingerprint/banner_probe")
    assert "Module: recon/fingerprint/banner_probe" in out
    assert "Rank: Normal" in out
    assert "https://nmap.org/book/vscan.html" in out
    assert "Basic options:" in out
    assert "Notes:" in out


def test_info_without_a_module_is_an_error(console):
    assert "[-] No module selected and none named." in console.execute("info")


# --------------------------------------------------------------------------- #
# show / set / unset -- validation is OptionDataStore's, the message is ours
# --------------------------------------------------------------------------- #

def test_show_options_hides_advanced_and_flags_missing(console):
    console.execute("use recon/test/port_probe")
    out = console.execute("show options")
    assert "RHOST" in out and "RPORT" in out
    assert "TIMEOUT" not in out
    assert "[!] Required and unset: RHOST" in out


def test_show_advanced_and_missing(console):
    console.execute("use recon/fingerprint/banner_probe")
    assert "TIMEOUT" in console.execute("show advanced")
    assert console.execute("show missing") == (
        "[!] Required and unset: RHOST\n[*] set RHOST <value>")
    console.execute("set RHOST 127.0.0.1")
    assert console.execute("show missing") == "[*] All required options are set."


def test_show_without_a_module_points_at_use(console):
    assert "[-] No module selected." in console.execute("show options")


def test_show_of_something_unknown_lists_the_valid_words(console):
    console.execute("use recon/test/port_probe")
    out = console.execute("show sessions")
    assert "[-] Cannot show 'sessions'." in out
    assert "Valid: options, advanced, missing, modules, all" in out


def test_set_bad_port_is_rejected_with_an_actionable_message(console):
    console.execute("use recon/test/port_probe")
    out = console.execute("set RPORT 99999")
    assert out == ("[-] Rejected: RPORT must be 1-65535\n"
                   "[*] RPORT is port -- Port to scope to")
    assert console.module.opt("RPORT") == 8080  # unchanged


def test_set_non_numeric_port_is_rejected(console):
    console.execute("use recon/test/port_probe")
    assert "[-] Rejected: RPORT must be an integer" in console.execute(
        "set RPORT eighty")


def test_set_enum_lists_the_choices(console):
    console.execute("use recon/test/port_probe")
    out = console.execute("set MODE sideways")
    assert "[-] Rejected: MODE must be one of: fast, deep" in out
    assert "one of: fast, deep" in out
    assert console.execute("set MODE deep") == "[+] MODE => deep"


def test_set_bad_address_goes_through_validate_address(console):
    console.execute("use recon/fingerprint/banner_probe")
    out = console.execute("set RHOST 10.0.0.1\r\nX-Injected: yes")
    assert out.startswith("[-] Rejected:")
    assert console.module.opt("RHOST") is None


def test_set_unknown_option_lists_valid_ones(console):
    console.execute("use recon/fingerprint/banner_probe")
    out = console.execute("set RHOSTS 127.0.0.1")
    assert ("[-] Unknown option 'RHOSTS' for recon/fingerprint/banner_probe."
            " Did you mean RHOST?") in out
    assert "[*] Valid options: RHOST, TIMEOUT, DECAY, CONFIDENCE" in out


def test_set_without_a_module_is_an_error(console):
    assert console.execute("set RHOST 127.0.0.1") == (
        "[-] No module selected. `use <module>` before setting options.")


def test_set_with_no_value_shows_usage(console):
    console.execute("use recon/test/port_probe")
    assert console.execute("set RPORT") == "[-] Usage: set <OPTION> <value>"


def test_unset_restores_the_default(console):
    console.execute("use recon/test/port_probe")
    console.execute("set RPORT 443")
    assert console.execute("unset RPORT") == "[+] RPORT reset to default (8080)"
    assert console.module.opt("RPORT") == 8080
    assert "[-] Unknown option 'NOPE'." in console.execute("unset NOPE")


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #

def test_run_before_use_is_an_error_not_a_traceback(console):
    out = console.execute("run")
    assert out == ("[-] No module selected. `use <module>` first, then `run`.\n"
                   "[*] `search recon` to find one.")


def test_run_with_missing_rhost_names_rhost(console):
    console.execute("use recon/fingerprint/banner_probe")
    out = console.execute("run")
    assert ("[-] Cannot run recon/fingerprint/banner_probe: required option "
            "RHOST not set.") in out
    assert "[*] set RHOST <value>" in out


def test_run_without_evidence_says_where_evidence_comes_from(console):
    console.execute("use recon/discovery/connect_sweep")
    console.execute("set RHOST 10.10.10.42")
    out = console.execute("run")
    assert "[!] Slot exhausted: recon/discovery/connect_sweep" in out
    assert ("no evidence is staged under tool key 'nmap-sT' for 10.10.10.42"
            in out)


def test_run_refuses_a_module_outside_recon(console):
    console.execute("use post/test/loot_grab")
    out = console.execute("run")
    assert out == ("[-] Refusing to run post/test/loot_grab: only 'recon/' "
                   "modules are runnable from this console. Vulnerability "
                   "leads go to `handoff`.")


def test_second_run_reports_no_new_leads(console):
    console.execute(f"import {NMAP_XML}")
    console.execute(SWEEP_RUN)
    first = console.execute(BANNER_RUN)
    assert "[+] 3 new lead(s) in the ledger" in first
    second = console.execute("run")
    assert "[*] 3 lead(s), none new." in second
    assert len(console.ws.ledger) == 3


# --------------------------------------------------------------------------- #
# import / graph readers
# --------------------------------------------------------------------------- #

def test_import_missing_file_is_reported(console):
    out = console.execute("import /nonexistent/scan.xml")
    assert out.startswith("[-] No such scan file:")


def test_import_stages_evidence_and_names_the_next_step(console):
    out = console.execute(f"import {NMAP_XML}")
    assert "[+] 127.0.0.1: 5 ports, 5 services" in out
    assert ("[+] Staged as principal 'operator' under tool keys "
            "nmap-sT / nmap-sV") in out
    assert ("[*] next: use recon/discovery/connect_sweep; "
            "set RHOST 127.0.0.1; run") in out


def test_import_rejects_a_non_nmap_document(console, tmp_path):
    bad = tmp_path / "notes.xml"
    bad.write_text("<notes><n>hi</n></notes>", encoding="utf-8")
    out = console.execute(f"import {bad}")
    assert "[-] Refused" in out and "is not nmap XML" in out


def test_targets_and_services_before_and_after_import(console):
    assert "[*] No hosts in workspace default." in console.execute("targets")
    assert console.execute("services") == (
        "[*] No ports recorded yet. `import <nmap.xml>` first.")
    console.execute(f"import {NMAP_XML}")
    console.execute(SWEEP_RUN)
    console.execute(BANNER_RUN)
    hosts = console.execute("targets")
    assert "127.0.0.1" in hosts
    services = console.execute("services 127.0.0.1")
    assert "tcp:8080" in services
    assert "Apache httpd 2.4.49" in services
    assert "0.75" in services
    assert "[-] No such host: 10.0.0.9." in console.execute("services 10.0.0.9")


def test_plan_routes_leads_to_handoff_and_gaps_to_modules(console):
    console.execute(f"import {NMAP_XML}")
    console.execute(SWEEP_RUN)
    console.execute(BANNER_RUN)
    out = console.execute("plan 127.0.0.1")
    assert "[*] Plan for 127.0.0.1" in out
    assert "gap(s) identified" in out
    assert "-> handoff CVE-2021-41773   [operator action, no module]" in out
    assert "-> use recon/fingerprint/deep_probe" in out


def test_plan_with_no_hosts_and_an_unknown_host(console):
    assert console.execute("plan") == (
        "[*] Nothing to plan against. `import <nmap.xml>` first.")
    assert "[-] No such host:" in console.execute("plan 10.0.0.9")


# --------------------------------------------------------------------------- #
# vulns / handoff
# --------------------------------------------------------------------------- #

@pytest.fixture()
def correlated(console):
    """A console with the localhost fixture imported and correlated."""
    console.execute(f"import {NMAP_XML}")
    console.execute(SWEEP_RUN)
    console.execute(BANNER_RUN)
    return console


def test_vulns_is_empty_before_correlation(console):
    assert console.execute("vulns") == (
        "[*] No leads. Import evidence and `run` a fingerprint module to "
        "correlate.")


def test_vulns_lists_the_ledger_in_priority_order(correlated):
    out = correlated.execute("vulns")
    assert "CVE-2021-41773" in out
    # 0.735 before match-method weighting; a product-substring match now
    # carries 0.75 (see docs/CVE-IDENTIFICATION.md).
    assert "0.551" in out
    assert "weaponised" in out
    assert out.index("CVE-2021-41773") < out.index("CVE-2018-15473")
    assert "[*] reconkg does not run these." in out


def test_vulns_min_priority_filters(correlated):
    assert correlated.execute("vulns --min-priority 0.8") == (
        "[*] No leads at or above priority 0.80 (3 below it).")
    kept = correlated.execute("vulns --min-priority 0.5")
    assert "CVE-2021-41773" in kept
    assert "CVE-2018-15473" not in kept


def test_vulns_bad_arguments(correlated):
    assert correlated.execute("vulns --min-priority high") == (
        "[-] --min-priority must be a number, got 'high'")
    assert correlated.execute("vulns --min-priority") == (
        "[-] --min-priority needs a number, e.g. 0.6")
    assert "[-] Unknown argument '-x'." in correlated.execute("vulns -x")


def test_handoff_prints_lookups_caveats_and_shell_quoted_commands(correlated):
    out = correlated.execute("handoff CVE-2021-41773")
    assert "[*] Lead: CVE-2021-41773 on 127.0.0.1:8080/tcp (http)" in out
    assert "searchsploit --cve CVE-2021-41773" in out
    assert "searchsploit 'Apache httpd 2.4.49'" in out  # shell-quoted
    assert "[!] Before you spend time on this:" in out
    assert "Distribution backports" in out
    assert ("reconkg does not run these. Confirm the target is in scope"
            in out)


def test_handoff_accepts_a_bare_cve_number(correlated):
    assert "CVE-2021-41773" in correlated.execute("handoff 2021-41773")


def test_handoff_for_an_unknown_cve_lists_what_is_known(correlated):
    out = correlated.execute("handoff CVE-1999-0001")
    assert "[-] No ledger entry for CVE-1999-0001." in out
    assert "[*] In the ledger: CVE-2018-15473, CVE-2021-41773" in out


def test_handoff_without_arguments(console):
    assert console.execute("handoff") == "[-] Usage: handoff <CVE> [target]"


# --------------------------------------------------------------------------- #
# catalog / workspace / history
# --------------------------------------------------------------------------- #

def test_catalog_empty_explains_what_it_would_do(console):
    # The precondition is pinned, not implied. When a host index leaked in,
    # the only symptom was a string mismatch two lines further down, which
    # names the assertion and not the cause.
    assert console.catalog_report == {"exploit-db": "not installed",
                                      "metasploit": "not installed"}
    assert len(console.catalog) == 0
    out = console.execute("catalog")
    assert "[*] Exploit index: empty." in out
    assert "The index is metadata. Loading it runs nothing." in out


def test_catalog_load_bad_type_and_missing_file(console):
    assert "[-] Unknown index type 'nessus'." in console.execute(
        "catalog load nessus /tmp/x")
    assert "[-] Usage: catalog load" in console.execute("catalog load")
    assert "not found" in console.execute(
        "catalog load metasploit /nonexistent/modules.json")


def test_workspaces_are_isolated_and_capped(console):
    console.execute(f"import {NMAP_XML}")
    assert console.execute("workspace lab2") == (
        "[+] Created and switched to workspace lab2.")
    assert "[*] No hosts in workspace lab2." in console.execute("targets")
    assert console.execute("workspace default") == "[*] Workspace: default"
    assert "127.0.0.1" in console.execute("targets")

    listing = console.execute("workspace")
    assert "default" in listing and "lab2" in listing

    assert "[-] Workspace names are alphanumeric" in console.execute(
        "workspace 'lab; rm -rf /'")
    for i in range(MAX_WORKSPACES):
        out = console.execute(f"workspace w{i}")
    assert f"[-] Workspace limit reached ({MAX_WORKSPACES})." in out
    assert len(console.workspaces) == MAX_WORKSPACES


def test_history_and_exit(console):
    console.execute("help")
    assert "  0  help" in console.execute("history")
    assert console.execute("exit").startswith("[*] Leaving.")
    assert console.running is False


def test_semicolon_chaining_replays_a_planner_line(console):
    out = console.execute(
        "use recon/fingerprint/deep_probe; set RHOST 127.0.0.1")
    assert "[*] Using recon/fingerprint/deep_probe" in out
    assert "[+] RHOST => 127.0.0.1" in out


def test_split_commands_ignores_semicolons_inside_quotes():
    assert _split_commands("a; b") == ["a", " b"]
    assert _split_commands("set BANNER 'a; b'") == ["set BANNER 'a; b'"]


# --------------------------------------------------------------------------- #
# Constraint 4: a raising command must not take the session with it
# --------------------------------------------------------------------------- #

def test_exception_inside_a_command_is_caught_and_the_session_survives(
        console, monkeypatch):
    def boom():
        raise RuntimeError("graph read failed")

    monkeypatch.setattr(console.ws.store, "list_hosts", boom)
    out = console.execute("targets")
    assert out == ("[-] targets failed: RuntimeError: graph read failed\n"
                   "[*] Session is intact. `help targets` for usage.")
    monkeypatch.undo()
    # The session keeps its state: still running, still dispatching.
    assert console.running is True
    assert "Commands" in console.execute("help")
    assert "[*] No hosts in workspace default." in console.execute("targets")


def test_a_raising_module_is_contained_by_the_engine(console, monkeypatch):
    async def explode(self, address, evidence, context):
        raise RuntimeError("stage blew up")

    monkeypatch.setattr(PortProbeModule, "run", explode)
    console.execute("use recon/test/port_probe; set RHOST 127.0.0.1")
    out = console.execute("run")
    assert "error" in out
    assert "RuntimeError: stage blew up" in out
    assert console.running is True


# --------------------------------------------------------------------------- #
# Constraint 5: no console path executes anything against a target
# --------------------------------------------------------------------------- #

FULL_SESSION = [
    "help",
    "search category:recon",
    "use 0",
    "info",
    "show options",
    "show advanced",
    "set RHOST 127.0.0.1",
    "run",
    "back",
    "targets",
    "services",
    "vulns",
    "plan",
    "handoff CVE-2021-41773",
    "catalog",
    "workspace scratch",
    "workspace default",
    "history",
]


def test_no_command_dispatches_to_anything_executable(console, monkeypatch):
    """The structural claim, asserted rather than asserted-in-a-docstring.

    Every outbound or process-spawning primitive is trapped, then the whole
    command table is driven -- including `run` and `handoff` on a live lead.
    If any command ever grows a shell-out or a socket, this fails loudly.
    """
    def trap(name):
        def fail(*args, **kwargs):
            raise AssertionError(f"console reached {name}")
        return fail

    monkeypatch.setattr(socket.socket, "connect", trap("socket.connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", trap("socket.connect_ex"))
    monkeypatch.setattr(socket, "create_connection",
                        trap("socket.create_connection"))
    monkeypatch.setattr(subprocess, "Popen", trap("subprocess.Popen"))
    monkeypatch.setattr(subprocess, "run", trap("subprocess.run"))
    monkeypatch.setattr(subprocess, "call", trap("subprocess.call"))

    console.execute(f"import {NMAP_XML}")
    console.execute(SWEEP_RUN)
    console.execute(BANNER_RUN)
    for line in FULL_SESSION:
        out = console.execute(line)
        assert "Traceback" not in out

    # A lead is not a runnable thing: there is no module to select for it.
    assert "[-] no such module: CVE-2021-41773." in console.execute(
        "use CVE-2021-41773")
    # ...and no command is named after execution.
    names = {c.name for c in COMMANDS} | {
        a for c in COMMANDS for a in c.aliases}
    assert names.isdisjoint({"exploit", "execute", "shell", "sessions",
                             "payload", "check", "rexploit", "sniff"})


def test_handoff_never_returns_a_command_the_console_would_run(correlated):
    """`handoff` output is for the operator's shell, not for `execute()`.

    Every line it emits is a lookup or a reference. Feeding them back in must
    be a no-op error, never a dispatch -- that is the property that keeps the
    hand-off a hand-off.
    """
    out = correlated.execute("handoff CVE-2021-41773")
    pasteable = [line.strip() for line in out.splitlines()
                 if line.startswith("    ") and line.strip()]
    assert pasteable
    dispatchable = {c.name for c in COMMANDS} | {
        a for c in COMMANDS for a in c.aliases}
    for line in pasteable:
        first = line.split()[0].lower()
        assert first not in dispatchable, f"{line!r} is dispatchable"


# --------------------------------------------------------------------------- #
# Full transcript
# --------------------------------------------------------------------------- #

def test_full_session_transcript(console):
    """search -> use -> set -> show options -> import -> run -> vulns ->
    handoff, asserting the operator-visible text at each step."""
    search = console.execute("search rank:great category:recon")
    assert "recon/discovery/connect_sweep" in search
    assert "recon/discovery/syn_sweep" in search
    assert "recon/fingerprint/banner_probe" not in search  # rank floor

    assert "[*] Using recon/discovery/connect_sweep (great)" in console.execute(
        "use recon/discovery/connect_sweep")

    imported = console.execute(f"import {NMAP_XML}")
    assert "[*] Imported 1 host(s)" in imported

    assert console.execute("set RHOST 127.0.0.1") == "[+] RHOST => 127.0.0.1"
    options = console.execute("show options")
    assert "RHOST 127.0.0.1 yes" in " ".join(options.split())
    assert "[!] Required and unset" not in options

    sweep = console.execute("run")
    assert "connect-sweep" in sweep and "success" in sweep
    assert "[+] recon/discovery/connect_sweep completed (1 attempt(s))." in sweep

    banner = console.execute(BANNER_RUN)
    assert "[+] 3 new lead(s) in the ledger" in banner

    ledger = console.execute("vulns")
    assert "CVE-2021-41773" in ledger and "127.0.0.1:8080" in ledger

    hand = console.execute("handoff CVE-2021-41773 127.0.0.1")
    # RC-34: `--script vuln` is the `vuln` tier and is withheld until the
    # operator opts in. The version re-check is `version` and is not.
    assert "nmap -sV -p 8080 127.0.0.1" in hand
    assert "--script vuln" not in hand
    assert "[!] reconkg does not run these." in hand

    assert console.execute("exit").startswith("[*] Leaving.")


def test_workspace_dataclass_ledger_is_bounded(monkeypatch):
    """RC-03/RC-18 class: the per-workspace ledger has a hard cap."""
    from reconkg import console as console_module
    from reconkg.vulnref import LedgerRow

    monkeypatch.setattr(console_module, "MAX_LEDGER_ROWS", 3)
    ws = Workspace(name="capped")
    rows = [LedgerRow(target="10.0.0.1", port=p, protocol="tcp",
                      service="http", product="x", version="1",
                      cve_id=f"CVE-2020-{p}", title="t", cvss=5.0,
                      maturity="functional", fingerprint_confidence=0.9)
            for p in range(10)]
    assert ws.merge_ledger(rows) == 3
    assert len(ws.ledger) == 3
