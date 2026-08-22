"""The execution chokepoint, exercised with and without a scanner.

`build_argv` is the whole security surface and it is entirely testable
offline, so most of this file never starts a process: the argv is asserted
directly, because a test that mocks the subprocess and then inspects what the
mock was called with is a test of the mock.

What genuinely needs a process gets a fake one shaped like what
`create_subprocess_exec` returns, and that fake replays a real nmap 7.80
fixture into the `-oX` path the runner chose. The XML the runner parses is
therefore genuine output rather than something hand-written to match the
parser -- the distinction `tests/test_golden_nmap.py` was written to make.

Nothing here runs nmap unless nmap is installed, and the few tests that do
are `skipif`-guarded and scan 127.0.0.1 and nothing else. A test suite that
scans anything but loopback is a test suite that eventually scans a network
nobody authorised.

The `sandbox` fixture installs a `create_subprocess_exec` that *raises*, so a
test which forgets to install its own fake fails loudly instead of quietly
launching the real binary against the real network.
"""

from __future__ import annotations

import asyncio
import os
import stat
import tempfile
from pathlib import Path

import pytest

from reconkg import runner
from reconkg.importers import ImportResult, parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"
ALL_SCANS = sorted(FIXTURES.glob("*.xml"))

#: A path that is never executed -- every test that reaches the exec call
#: replaces `create_subprocess_exec` first. Standing in for the resolved
#: binary is what lets the argv tests run on CI, which has no nmap.
FAKE_NMAP = "/usr/bin/nmap"

requires_nmap = pytest.mark.skipif(
    runner.available() is None,
    reason="nmap is not installed; the offline argv tests cover the rest")


# --------------------------------------------------------------------------- #
# A process that behaves like the real one, including badly
# --------------------------------------------------------------------------- #

class _Occupancy:
    """How many scans were inside the semaphore at once, and at most."""

    def __init__(self) -> None:
        self.current = 0
        self.peak = 0

    def enter(self) -> None:
        self.current += 1
        self.peak = max(self.peak, self.current)

    def leave(self) -> None:
        self.current -= 1


class _FakeProcess:
    """The four members `run()` actually touches, and nothing else.

    Deliberately not a `unittest.mock.Mock`: a Mock answers every attribute,
    so a runner that started calling `process.terminate()` instead of
    `kill()` would still pass. Missing methods should be `AttributeError`s.
    """

    def __init__(self, *, returncode: int = 0, stderr_bytes: bytes = b"",
                 delay: float = 0.0,
                 tracker: _Occupancy | None = None) -> None:
        self.returncode = returncode
        self._stderr = stderr_bytes
        self._delay = delay
        self._tracker = tracker
        self.killed = False
        self.waited = False

    async def communicate(self) -> tuple[bytes, bytes]:
        if self._tracker is not None:
            self._tracker.enter()
        try:
            if self._delay:
                await asyncio.sleep(self._delay)
        finally:
            if self._tracker is not None:
                self._tracker.leave()
        return b"", self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        self.waited = True
        return self.returncode


class _Sandbox:
    """Records what the runner tried to execute, without executing it."""

    def __init__(self, monkeypatch, tmpdir: Path) -> None:
        self._monkeypatch = monkeypatch
        self.tmpdir = tmpdir
        self.calls: list[tuple[str, ...]] = []
        self.processes: list[_FakeProcess] = []
        self.modes: list[int] = []

    def install(self, *, returncode: int = 0, stderr_bytes: bytes = b"",
                delay: float = 0.0, fixture: str | None = None,
                raw: bytes | None = None,
                tracker: _Occupancy | None = None) -> "_Sandbox":
        payload = raw
        if fixture is not None:
            payload = (FIXTURES / fixture).read_bytes()

        async def create(*argv, **_kwargs):
            self.calls.append(tuple(argv))
            out = argv[argv.index("-oX") + 1]
            self.modes.append(stat.S_IMODE(os.stat(out).st_mode))
            if payload is not None:
                Path(out).write_bytes(payload)
            process = _FakeProcess(returncode=returncode,
                                   stderr_bytes=stderr_bytes, delay=delay,
                                   tracker=tracker)
            self.processes.append(process)
            return process

        self._monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
        return self

    @property
    def xml_path(self) -> str:
        argv = self.calls[0]
        return argv[argv.index("-oX") + 1]


@pytest.fixture
def sandbox(monkeypatch, tmp_path):
    """A runner that thinks nmap exists, writes to tmp_path, and cannot exec.

    `_slots` is reset because it is a module-level semaphore created lazily on
    first use and then bound to whichever event loop first contended on it.
    pytest-asyncio gives every test its own loop, so a semaphore carried over
    from an earlier test raises "bound to a different event loop" the moment
    two scans queue behind it.
    """
    monkeypatch.setattr(runner, "available", lambda: FAKE_NMAP)
    monkeypatch.setattr(runner, "_slots", None)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    async def refuse(*argv, **_kwargs):
        raise AssertionError(f"the runner executed something: {argv}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", refuse)
    return _Sandbox(monkeypatch, tmp_path)


# --------------------------------------------------------------------------- #
# build_argv -- the security surface
# --------------------------------------------------------------------------- #

def test_the_profile_vocabulary_is_exactly_these_four():
    """The caller's entire vocabulary, pinned.

    A profile added to the table is a new set of flags reaching the network
    from an authenticated HTTP request. This test failing is the review
    trigger; the module docstring is explicit that NSE and privileged scan
    types get their own review rather than a quiet addition to a tuple.
    """
    assert sorted(runner.PROFILES) == ["discovery", "quick", "service",
                                       "thorough"]
    assert runner.profile_names() == ["discovery", "quick", "service",
                                      "thorough"]
    assert runner.DEFAULT_PROFILE == "service"
    assert runner.BINARY == "nmap"
    assert runner.MAX_CONCURRENT == 2
    assert runner.MAX_STDERR == 4000


def test_every_profile_has_its_own_ceiling_declared():
    """`TIMEOUTS.get(profile, 1800.0)` silently gives a new profile half an
    hour. `thorough` is budgeted 5400s, so the fallback is not a safe default
    for the one profile most likely to need more than it -- the table has to
    cover the vocabulary rather than most of it."""
    assert set(runner.TIMEOUTS) == set(runner.PROFILES)
    assert runner.TIMEOUTS == {"discovery": 300.0, "quick": 600.0,
                               "service": 1800.0, "thorough": 5400.0}


@pytest.mark.parametrize("profile,expected", [
    ("discovery", ("-sn",)),
    ("quick", ("-sT", "-F", "--open")),
    ("service", ("-sT", "-sV", "--version-intensity", "9", "--open")),
    ("thorough", ("-sT", "-sV", "-p-", "--open")),
])
def test_each_profile_produces_exactly_this_argv(sandbox, profile, expected):
    """The command, character for character.

    "contains -sT" would pass for a command that also contained `-sS`. The
    only assertion that cannot be satisfied by an argv with something extra
    in it is equality with the whole tuple.
    """
    argv = runner.build_argv("127.0.0.1", profile, "/tmp/scan.xml")

    assert argv == (FAKE_NMAP, *expected, "-oX", "/tmp/scan.xml", "--",
                    "127.0.0.1")
    assert isinstance(argv, tuple)
    assert all(isinstance(element, str) for element in argv)


@pytest.mark.parametrize("profile", sorted(runner.PROFILES))
def test_the_address_is_its_own_argv_element_after_a_double_dash(sandbox,
                                                                 profile):
    """This is the entire defence.

    No shell and no interpolation means the address is one element in an
    execv vector, where `;`, `$(` and a newline are just bytes in a string
    nothing will ever re-parse. `--` in front of it is the belt to that
    braces: a target that somehow began with a dash still cannot be read as
    a flag.
    """
    argv = runner.build_argv("127.0.0.1", profile, "/tmp/scan.xml")

    assert argv[-1] == "127.0.0.1"
    assert argv[-2] == "--"
    assert argv.count("--") == 1
    assert argv.count("127.0.0.1") == 1
    assert argv.index("-oX") == len(argv) - 4
    assert argv[argv.index("-oX") + 1] == "/tmp/scan.xml"


FORBIDDEN_FLAGS = ("-sS", "-sU", "-O", "-sC")


@pytest.mark.parametrize("profile", sorted(runner.PROFILES))
def test_no_profile_asks_for_root_or_for_nse(sandbox, profile):
    """Parametrised over the live table so a fifth profile is covered the
    moment it is added, rather than the day someone remembers to extend a
    hard-coded list here.

    `-sS`, `-sU` and `-O` need root, and a coordinator that asks to be run
    privileged is a coordinator that will be run privileged. `-sC` and
    `--script` pull the whole `commands.py` category tier into an execution
    path -- RC-37 is precisely `--script exploit` selecting a category rather
    than a file.
    """
    flags = runner.PROFILES[profile]
    argv = runner.build_argv("127.0.0.1", profile, "/tmp/scan.xml")

    for flag in FORBIDDEN_FLAGS:
        assert flag not in flags, f"{profile} declares {flag}"
        assert flag not in argv, f"{profile} runs with {flag}"
    assert not any(f.startswith("--script") for f in flags), profile
    assert not any(a.startswith("--script") for a in argv), profile
    assert not any(a.startswith("-oN") or a.startswith("-oG") for a in argv)


def test_the_argv_carries_the_validated_address_not_the_raw_one(sandbox):
    """`build_argv` must use what `validate_address` returned, not what the
    caller sent. Passing `target` through instead would look identical in
    every test that scans "127.0.0.1", and would send the unnormalised string
    -- whitespace, mixed case, a non-canonical IPv6 literal -- to the wire
    while the graph recorded the canonical one. RC-04 in miniature.
    """
    assert runner.build_argv(" 127.0.0.1 ", "quick",
                             "/tmp/scan.xml")[-1] == "127.0.0.1"
    assert runner.build_argv("LOCALHOST", "quick",
                             "/tmp/scan.xml")[-1] == "localhost"
    assert runner.build_argv("0:0:0:0:0:0:0:1", "quick",
                             "/tmp/scan.xml")[-1] == "::1"


#: Six shapes of hostile target, one per delivery mechanism this project has
#: already been bitten by somewhere: shell chaining, header/log injection, a
#: smuggled output flag, command substitution, path traversal, and an NSE
#: category smuggled in as a second word.
HOSTILE_TARGETS = [
    "10.0.0.1; id",
    "10.0.0.1\nX: y",
    "-oN/tmp/pwned",
    "$(id)",
    "../../etc/passwd",
    "10.0.0.1 --script exploit",
]
HOSTILE_IDS = ["shell-chain", "newline-injection", "smuggled-output-flag",
               "command-substitution", "path-traversal", "nse-category"]


@pytest.mark.parametrize("target", HOSTILE_TARGETS, ids=HOSTILE_IDS)
def test_a_hostile_target_never_becomes_an_argv_element(sandbox, target):
    """Re-validation at the chokepoint, which is the point of re-validating.

    `app.py` checks these already. The console, a scheduled job and a future
    CLI are callers that do not exist yet, and RC-07's finding was that the
    ingress which forgets is always the one nobody has written. The type is
    `ValueError` because `validate_address` raises it -- pinned rather than
    caught as a union, so wrapping it in `ScannerError` later is a visible
    decision instead of a silent one.
    """
    produced = []
    for profile in runner.PROFILES:
        with pytest.raises(ValueError):
            produced.append(runner.build_argv(target, profile, "/tmp/s.xml"))

    assert produced == [], f"{target!r} reached an argv"


def test_a_missing_nmap_is_its_own_error_type(sandbox, monkeypatch):
    """"nmap is not installed" and "the scan failed" are a five-second fix
    and an afternoon respectively, so they are different types."""
    monkeypatch.setattr(runner, "available", lambda: None)

    with pytest.raises(runner.ScannerMissing) as excinfo:
        runner.build_argv("127.0.0.1", "quick", "/tmp/scan.xml")

    message = str(excinfo.value)
    assert "nmap is not installed or not on PATH" in message
    assert "apt install nmap" in message, "did not say how to fix it"
    assert issubclass(runner.ScannerMissing, runner.ScannerError)


def test_an_unknown_profile_names_the_ones_that_exist(sandbox):
    """A rejection that lists the alternatives is the difference between a
    typo fixed in one attempt and a hunt through the source."""
    with pytest.raises(runner.ScannerError) as excinfo:
        runner.build_argv("127.0.0.1", "aggressive", "/tmp/scan.xml")

    assert type(excinfo.value) is runner.ScannerError, (
        "a missing binary was reported as a bad profile, or the reverse")
    message = str(excinfo.value)
    assert "'aggressive'" in message
    for name in runner.profile_names():
        assert name in message, f"{name} was not offered"


def test_available_resolves_the_binary_by_name(monkeypatch):
    """Resolved rather than assumed, and returned rather than raised: the UI
    asks this on load to decide whether to offer the button at all."""
    asked: list[str] = []

    def found(name):
        asked.append(name)
        return "/usr/bin/nmap"

    monkeypatch.setattr(runner.shutil, "which", found)
    assert runner.available() == "/usr/bin/nmap"
    assert asked == ["nmap"]

    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    assert runner.available() is None


# --------------------------------------------------------------------------- #
# ScanRun.as_dict -- what the operator is shown
# --------------------------------------------------------------------------- #

AS_DICT_KEYS = {"target", "profile", "command", "returncode", "duration_s",
                "timed_out", "hosts", "services", "warnings"}


def test_as_dict_pins_the_keys_a_report_is_rendered_from(sandbox):
    """The command is in the payload so "0 services found" is diagnosable.

    An operator looking at an empty result needs to know whether `-sV` was in
    the command at all; without that the answer to "why did the version scan
    find nothing" is a guess. `command` is a list of strings for the same
    reason argv is a list everywhere else -- a joined string in a JSON field
    is a command line somebody will eventually paste into a shell.
    """
    result = parse_nmap_xml(FIXTURES / "nmap_sV_localhost.xml")
    argv = runner.build_argv("127.0.0.1", "service", "/tmp/scan.xml")
    record = runner.ScanRun(target="127.0.0.1", profile="service", argv=argv,
                            returncode=0, duration_s=8.2149, result=result)

    payload = record.as_dict()

    assert set(payload) == AS_DICT_KEYS
    assert "stderr" not in payload, "an empty stderr became a visible field"
    assert payload["command"] == list(argv)
    assert isinstance(payload["command"], list)
    assert all(isinstance(element, str) for element in payload["command"])
    assert "-sV" in payload["command"]
    assert payload["target"] == "127.0.0.1"
    assert payload["profile"] == "service"
    assert payload["returncode"] == 0
    assert payload["duration_s"] == 8.2
    assert payload["timed_out"] is False
    assert payload["hosts"] == 1
    assert payload["services"] == 5
    assert payload["warnings"] == result.warnings
    assert record.hosts_up == 1


def test_a_zero_service_result_still_shows_whether_sV_ran(sandbox):
    """The case the `command` field exists for, made concrete: a ping sweep
    reports one host and no services, and that is correct rather than
    broken -- provable from the argv, which has no `-sV` in it."""
    result = parse_nmap_xml(FIXTURES / "nmap_ping_only.xml")
    argv = runner.build_argv("127.0.0.1", "discovery", "/tmp/scan.xml")
    record = runner.ScanRun(target="127.0.0.1", profile="discovery",
                            argv=argv, returncode=0, duration_s=0.01,
                            stderr="Warning: no targets were specified",
                            result=result)

    payload = record.as_dict()

    assert payload["hosts"] == 1
    assert payload["services"] == 0
    assert payload["command"] == [FAKE_NMAP, "-sn", "-oX", "/tmp/scan.xml",
                                  "--", "127.0.0.1"]
    assert "-sV" not in payload["command"]
    assert payload["duration_s"] == 0.0
    assert payload["stderr"] == "Warning: no targets were specified"
    assert set(payload) == AS_DICT_KEYS | {"stderr"}


def test_a_run_that_produced_nothing_reports_zeroes_rather_than_none():
    """A `ScanRun` that never got as far as parsing must still serialise.

    `hosts: null` and `services: null` in a JSON payload is a client-side
    crash in whatever renders the count; the default `returncode` of -1 is
    there so "never ran" is distinguishable from "exited 0".
    """
    payload = runner.ScanRun(target="10.0.0.1", profile="quick").as_dict()

    assert payload["hosts"] == 0
    assert payload["services"] == 0
    assert payload["warnings"] == []
    assert payload["command"] == []
    assert payload["returncode"] == -1
    assert payload["duration_s"] == 0.0
    assert payload["timed_out"] is False
    assert set(payload) == AS_DICT_KEYS


# --------------------------------------------------------------------------- #
# run() -- against a fake process replaying real nmap output
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_a_successful_run_parses_its_own_xml(sandbox):
    """The XML goes through `parse_nmap_xml`, the same hardened parser an
    uploaded file goes through -- one parser, one doctype guard, one set of
    host caps. A second parser here would be a second path for exactly the
    control this codebase keeps finding built only on the first."""
    sandbox.install(returncode=0, fixture="nmap_sV_localhost.xml")

    record = await runner.run("127.0.0.1", "service")

    assert record.returncode == 0
    assert record.timed_out is False
    assert record.stderr == ""
    assert isinstance(record.result, ImportResult)
    assert list(record.result.hosts) == ["127.0.0.1"]
    assert record.result.port_tool == "nmap-sT"
    assert record.hosts_up == 1
    assert record.as_dict()["services"] == 5
    assert sandbox.calls[0] == (
        FAKE_NMAP, "-sT", "-sV", "--version-intensity", "9", "--open",
        "-oX", sandbox.xml_path, "--", "127.0.0.1")
    assert not Path(sandbox.xml_path).exists()


@pytest.mark.asyncio
async def test_a_nonzero_exit_repeats_nmaps_own_complaint(sandbox):
    """nmap explains itself on stderr. Replacing that with "scan failed"
    throws away the only sentence that says what to change."""
    sandbox.install(returncode=1,
                    stderr_bytes=b"Failed to resolve \"nosuchhost\".\n")

    with pytest.raises(runner.ScannerError) as excinfo:
        await runner.run("127.0.0.1", "quick")

    message = str(excinfo.value)
    assert "nmap exited 1" in message
    assert 'Failed to resolve "nosuchhost".' in message
    assert not Path(sandbox.xml_path).exists()


@pytest.mark.asyncio
async def test_a_silent_failure_says_that_it_was_silent(sandbox):
    """An exit code with an empty stderr formatted as "nmap exited 2: " reads
    like truncated output. Naming the emptiness is the unhappy path of the
    unhappy path."""
    sandbox.install(returncode=2, stderr_bytes=b"")

    with pytest.raises(runner.ScannerError) as excinfo:
        await runner.run("127.0.0.1", "quick")

    assert "nmap exited 2: no error output" in str(excinfo.value)


@pytest.mark.asyncio
async def test_xml_that_is_not_nmap_output_is_named_not_counted_as_empty(
        sandbox):
    """nmap exits 0 and leaves something unparseable. Surfacing that as
    "0 hosts" reads exactly like a clean host, which is the one wrong answer
    an operator will act on."""
    sandbox.install(returncode=0,
                    raw=b"<?xml version='1.0'?><notnmap/>")

    with pytest.raises(runner.ScannerError) as excinfo:
        await runner.run("127.0.0.1", "quick")

    message = str(excinfo.value)
    assert "nmap exited 0 but its XML was unusable" in message
    assert "not nmap XML" in message
    assert "<notnmap>" in message
    assert not Path(sandbox.xml_path).exists()


@pytest.mark.asyncio
async def test_a_scan_of_a_host_that_is_down_is_a_result_not_an_error(
        sandbox):
    """Real output from a scan of an unreachable host: exit 0, no `<host>`
    element at all. That is an answer -- "nothing there" -- and turning it
    into an exception would make an ordinary lab outcome look like a broken
    scanner."""
    sandbox.install(returncode=0, fixture="nmap_host_down.xml")

    record = await runner.run("192.0.2.99", "quick")

    assert record.returncode == 0
    assert record.hosts_up == 0
    assert record.result.hosts == {}
    assert record.result.discovered_only == []
    assert record.as_dict()["hosts"] == 0


#: Every golden fixture, and what the runner should report for it. Written
#: out rather than recomputed from the parse, because an expectation derived
#: from the code under test asserts nothing at all.
EXPECTED_COUNTS = {
    "nmap_host_down.xml": (0, 0),
    "nmap_ipv6.xml": (1, 2),
    "nmap_ping_only.xml": (1, 0),
    "nmap_portscan_only.xml": (1, 3),
    "nmap_sV_localhost.xml": (1, 5),
    "nmap_with_scripts.xml": (1, 2),
}


def test_the_counts_below_cover_every_fixture():
    """A seventh fixture arriving with no expectation beside it would be
    silently untested by the parametrised run below."""
    assert sorted(EXPECTED_COUNTS) == [scan.name for scan in ALL_SCANS]
    assert len(ALL_SCANS) == 6


@pytest.mark.asyncio
@pytest.mark.parametrize("name,counts", sorted(EXPECTED_COUNTS.items()))
async def test_every_real_scan_shape_survives_the_runners_own_path(
        sandbox, name, counts):
    """Six shapes real nmap actually produces -- ipv6, host down, ping-only,
    ports without `-sV`, full version detection, and NSE output the parser
    has no business reading -- driven through `run()` rather than through
    `parse_nmap_xml` alone, so the ScanRun assembly and the temp-file
    handling are covered for each of them and not just for the happy one."""
    hosts, services = counts
    sandbox.install(returncode=0, fixture=name)

    record = await runner.run("127.0.0.1", "service")
    payload = record.as_dict()

    assert payload["hosts"] == hosts
    assert payload["services"] == services
    assert payload["returncode"] == 0
    assert payload["timed_out"] is False
    assert not Path(sandbox.xml_path).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("target", HOSTILE_TARGETS, ids=HOSTILE_IDS)
async def test_a_hostile_target_never_reaches_the_process(sandbox, target):
    """The second path for the same control.

    `build_argv` refusing these proves the assembler is safe. This proves
    `run()` cannot reach `create_subprocess_exec` around it -- which is the
    question that actually matters, because RC-24 was a chokepoint that was
    intact while the traffic went around it.
    """
    sandbox.install(returncode=0, fixture="nmap_ping_only.xml")

    with pytest.raises(ValueError):
        await runner.run(target, "quick")

    assert sandbox.calls == [], f"{target!r} was executed"


@pytest.mark.asyncio
async def test_run_starts_nothing_when_nmap_is_absent(sandbox, monkeypatch):
    sandbox.install(returncode=0, fixture="nmap_ping_only.xml")
    monkeypatch.setattr(runner, "available", lambda: None)

    with pytest.raises(runner.ScannerMissing):
        await runner.run("127.0.0.1", "quick")

    assert sandbox.calls == []


@pytest.mark.asyncio
async def test_run_starts_nothing_for_an_unknown_profile(sandbox):
    sandbox.install(returncode=0, fixture="nmap_ping_only.xml")

    with pytest.raises(runner.ScannerError):
        await runner.run("127.0.0.1", "aggressive")

    assert sandbox.calls == []


# --------------------------------------------------------------------------- #
# Timeouts
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
@pytest.mark.parametrize("profile,expected", [
    ("discovery", 300.0), ("quick", 600.0),
    ("service", 1800.0), ("thorough", 5400.0),
])
async def test_each_profile_waits_its_own_ceiling(sandbox, monkeypatch,
                                                  profile, expected):
    """Asserted by watching what `wait_for` is handed, because the honest
    alternative is a test that takes ninety minutes. Two slots is the entire
    budget, so one unreachable host holding a slot forever is the failure
    that makes the feature look broken for everybody else."""
    sandbox.install(returncode=0, fixture="nmap_ping_only.xml")
    seen: list[float | None] = []
    real_wait_for = asyncio.wait_for

    async def recording(awaitable, timeout=None):
        seen.append(timeout)
        return await real_wait_for(awaitable, timeout)

    monkeypatch.setattr(asyncio, "wait_for", recording)
    await runner.run("127.0.0.1", profile)

    assert seen == [expected]


@pytest.mark.asyncio
async def test_an_explicit_timeout_overrides_the_profile_ceiling(sandbox,
                                                                 monkeypatch):
    sandbox.install(returncode=0, fixture="nmap_ping_only.xml")
    seen: list[float | None] = []
    real_wait_for = asyncio.wait_for

    async def recording(awaitable, timeout=None):
        seen.append(timeout)
        return await real_wait_for(awaitable, timeout)

    monkeypatch.setattr(asyncio, "wait_for", recording)
    await runner.run("127.0.0.1", "thorough", timeout=12.5)

    assert seen == [12.5]


@pytest.mark.asyncio
async def test_a_timeout_kills_the_child_and_then_reaps_it(sandbox,
                                                           monkeypatch):
    """`kill()` alone leaves a zombie the event loop holds for the life of
    the process -- two of those and the semaphore never opens again. The
    `await process.wait()` after the kill is what stops a timeout from
    permanently consuming a slot, so both halves are asserted.

    `timed_out` is read off the record the runner built rather than off a
    returned value, because `run()` raises on timeout and discards the
    `ScanRun` -- see the note in the handover about that.
    """
    sandbox.install(delay=5.0)
    built: list[runner.ScanRun] = []

    class _Recording(runner.ScanRun):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            built.append(self)

    monkeypatch.setattr(runner, "ScanRun", _Recording)

    with pytest.raises(runner.ScannerError) as excinfo:
        await runner.run("127.0.0.1", "thorough", timeout=0.05)

    message = str(excinfo.value)
    assert "127.0.0.1" in message
    assert "'thorough'" in message, "the operator is not told which profile"
    assert "'quick'" in message, "no cheaper profile suggested"

    process = sandbox.processes[0]
    assert process.killed is True
    assert process.waited is True, "a killed child was never reaped"

    assert len(built) == 1
    assert built[0].timed_out is True
    assert built[0].returncode == -1
    assert built[0].stderr == ""
    assert built[0].result is None
    assert built[0].as_dict()["timed_out"] is True
    assert not Path(sandbox.xml_path).exists()


# --------------------------------------------------------------------------- #
# Temp-file hygiene
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_the_scan_xml_never_outlives_the_run(sandbox):
    """RC-25 was snapshot files left at 0644. Scan XML is worse than a
    snapshot: it is the whole engagement -- every address, port, banner and
    version the operator holds -- and the failure mode is not a crash but a
    directory that quietly accumulates them.

    All three exits are walked in one test on purpose: cleanup that holds on
    the success path and not on the timeout path is the shape thirteen of
    forty-seven findings had.
    """
    sandbox.install(returncode=0, fixture="nmap_sV_localhost.xml")
    await runner.run("127.0.0.1", "service")
    assert list(sandbox.tmpdir.iterdir()) == [], "leaked after a clean scan"

    sandbox.install(returncode=2, stderr_bytes=b"nmap: bad argument")
    with pytest.raises(runner.ScannerError):
        await runner.run("127.0.0.1", "quick")
    assert list(sandbox.tmpdir.iterdir()) == [], "leaked after a failed scan"

    sandbox.install(delay=5.0)
    with pytest.raises(runner.ScannerError):
        await runner.run("127.0.0.1", "quick", timeout=0.05)
    assert list(sandbox.tmpdir.iterdir()) == [], "leaked after a timeout"

    paths = [argv[argv.index("-oX") + 1] for argv in sandbox.calls]
    assert len(paths) == 3
    assert len(set(paths)) == 3, "two scans shared one output file"
    assert [Path(p).exists() for p in paths] == [False, False, False]
    assert all(Path(p).name.startswith("reconkg-scan-") for p in paths)
    assert all(p.endswith(".xml") for p in paths)


@pytest.mark.skipif(os.name != "posix",
                    reason="POSIX file modes; this suite's home is Kali")
@pytest.mark.asyncio
async def test_the_scan_xml_is_private_for_as_long_as_it_exists(sandbox):
    """0600 from `mkstemp`, checked at the moment nmap would be writing into
    it. A world-readable file that is deleted a minute later was still
    world-readable for a minute, on a box other people have accounts on."""
    sandbox.install(returncode=0, fixture="nmap_sV_localhost.xml")

    await runner.run("127.0.0.1", "service")

    assert sandbox.modes == [0o600]


# --------------------------------------------------------------------------- #
# Concurrency
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_the_semaphore_actually_bounds_concurrent_scans(sandbox):
    """`MAX_CONCURRENT = 2` is a constant until something enforces it.

    nmap is bandwidth-hungry and the failure mode of an unbounded pool is a
    lab network that stops working while somebody debugs the wrong thing --
    so the assertion is on observed peak occupancy inside the semaphore, not
    on the constant. Six scans are launched at once; two is the peak.
    """
    occupancy = _Occupancy()
    sandbox.install(returncode=0, fixture="nmap_ping_only.xml", delay=0.05,
                    tracker=occupancy)

    records = await asyncio.gather(*[
        runner.run(f"10.0.0.{n}", "discovery") for n in range(1, 7)])

    assert runner.MAX_CONCURRENT == 2
    assert occupancy.peak == 2, (
        f"{occupancy.peak} scans ran at once against a budget of 2")
    assert occupancy.current == 0, "a slot was never released"
    assert len(records) == 6
    assert [r.returncode for r in records] == [0] * 6
    assert len(sandbox.calls) == 6
    assert list(sandbox.tmpdir.iterdir()) == []


@pytest.mark.asyncio
async def test_a_failing_scan_releases_its_slot(sandbox):
    """A failed scan must hand its slot back before it raises.

    The `async with` closes before the non-zero exit is turned into an
    exception, which is the ordering that makes this safe -- but it is
    ordering, not a guarantee, and two slots is the whole budget. A refactor
    that moved the raise inside the block would wedge the scanner after two
    failures, with no error left pointing at the cause.
    """
    occupancy = _Occupancy()
    sandbox.install(returncode=1, stderr_bytes=b"boom", tracker=occupancy)

    for _ in range(4):
        with pytest.raises(runner.ScannerError):
            await runner.run("127.0.0.1", "quick")

    assert occupancy.current == 0
    assert occupancy.peak == 1

    sandbox.install(returncode=0, fixture="nmap_ping_only.xml")
    record = await runner.run("127.0.0.1", "discovery")
    assert record.returncode == 0, "the pool never recovered from a failure"


# --------------------------------------------------------------------------- #
# With a real nmap on the box -- loopback only, ever
# --------------------------------------------------------------------------- #

@requires_nmap
def test_available_returns_an_executable_absolute_path():
    path = runner.available()

    assert path is not None
    assert os.path.isabs(path)
    assert os.access(path, os.X_OK)
    assert runner.build_argv("127.0.0.1", "quick", "/tmp/scan.xml")[0] == path


@requires_nmap
@pytest.mark.asyncio
async def test_a_real_scan_of_loopback_returns_parsed_evidence(monkeypatch):
    """The only test in this file that puts packets on an interface.

    127.0.0.1 and nothing else, forever. A suite that scans anything routable
    is a suite that eventually scans a network nobody authorised, and the
    BRIEF is explicit that a bypass here means "scanned a host you were not
    authorised to touch" rather than "bad data".

    What this pins is the plumbing: nmap was found, executed, exited cleanly,
    wrote XML this project's own parser accepted, and its temp file was
    removed afterwards. Nothing else in the file proves the binary actually
    runs -- every other case replays a fixture through a fake process.

    It deliberately does NOT assert that the host comes back with open ports.
    `-F` covers the top 100, and a box with nothing listening there yields an
    empty result *correctly* -- nmap reports the host down and the importer
    skips it. That is a fact about the machine, not about reconkg, and an
    earlier version of this test asserted it and failed on a box whose only
    listener was on 8765. Asserting it is a test that reads the machine
    instead of controlling it, which is the defect this suite already found
    once in test_console.py.
    """
    monkeypatch.setattr(runner, "_slots", None)

    record = await runner.run("127.0.0.1", "quick", timeout=120.0)

    assert record.returncode == 0
    assert record.timed_out is False
    assert isinstance(record.result, ImportResult)

    # Whatever it found, it may only ever have found loopback.
    assert set(record.result.hosts) <= {"127.0.0.1"}
    assert set(record.result.discovered_only) <= {"127.0.0.1"}

    payload = record.as_dict()
    assert payload["command"][0] == runner.available()
    assert payload["command"][-2:] == ["--", "127.0.0.1"]
    assert "-sT" in payload["command"]
    assert "-sV" not in payload["command"], "the quick profile grew a -sV"
    assert payload["hosts"] == len(record.result.hosts)

    xml_path = record.argv[record.argv.index("-oX") + 1]
    assert not Path(xml_path).exists(), "a real run left its XML behind"


@requires_nmap
@pytest.mark.asyncio
async def test_a_real_discovery_scan_records_the_host_with_no_port_data(
        monkeypatch):
    """`-sn` legitimately produces a host with no ports. RC-22's round-7
    finding was the importer dropping exactly that, so an operator who ran a
    ping sweep first imported nothing and could not tell why."""
    monkeypatch.setattr(runner, "_slots", None)

    record = await runner.run("127.0.0.1", "discovery", timeout=60.0)

    assert record.returncode == 0
    assert record.result.discovered_only == ["127.0.0.1"]
    assert record.result.hosts == {"127.0.0.1": {}}
    assert record.as_dict()["services"] == 0
    assert "-sn" in record.as_dict()["command"]


# --------------------------------------------------------------------------- #
# Three defects found while writing this file, all since fixed
#
# Each was real in the first cut of runner.py. They are kept as plain
# regressions rather than deleted, because the value of having found them is
# only banked if the edit that reintroduces one fails by name.
# --------------------------------------------------------------------------- #

def test_the_timeout_path_has_the_type_app_py_catches():
    """A cross-module contract, asserted from the runner's side.

    `app.py`'s nmap route catches `runner.ScannerTimeout` between its
    `ScannerMissing` and `ScannerError` handlers. Python evaluates each
    except-expression in turn, so if that class did not exist, every
    `ScannerError` that is not a `ScannerMissing` -- a non-zero exit, a
    timeout, unusable XML -- would raise `AttributeError` while the handler
    chain was being walked, and the caller would get 500 instead of the 502
    or 504 the route was written to return.

    Neither file is wrong in isolation, which is exactly why such a mismatch
    survives review of both: it exists only in the pair. That is the RC-22
    shape -- something relied on, declared nowhere, checked by nothing.
    """
    assert issubclass(runner.ScannerTimeout, runner.ScannerError)
    assert not issubclass(runner.ScannerTimeout, runner.ScannerMissing)


@pytest.mark.asyncio
async def test_a_refused_target_does_not_leave_its_temp_file_behind(sandbox):
    """`build_argv` must sit inside the try whose finally unlinks.

    It raises on a bad address, an unknown profile and a missing nmap -- all
    three reachable from an authenticated caller. With it above the try, each
    refusal left a 0-byte `reconkg-scan-*.xml` behind, once per attempt,
    growing without bound: RC-03/RC-18 in a directory instead of a dict.
    """
    with pytest.raises(ValueError):
        await runner.run("10.0.0.1; id", "quick")

    assert list(sandbox.tmpdir.iterdir()) == []


@pytest.mark.asyncio
async def test_an_empty_xml_after_a_clean_exit_is_named_not_raw(sandbox):
    """`ParseError` subclasses `SyntaxError`, not `ValueError`.

    So it sails past every `except ValueError` written to mean "this file is
    not usable" -- the runner's here, and the API upload handler's too. And
    `mkstemp` leaves an empty file, so an nmap that exits 0 having written
    nothing lands on exactly this path. Converted in `parse_nmap_xml` rather
    than at each call site, so a third caller cannot forget.
    """
    sandbox.install(returncode=0)          # exits 0, writes nothing at all

    with pytest.raises(runner.ScannerError) as excinfo:
        await runner.run("127.0.0.1", "quick")

    assert "nmap exited 0 but its XML was unusable" in str(excinfo.value)
