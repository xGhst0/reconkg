"""Test-wide isolation from the machine the tests happen to run on.

Three times this suite has been caught reading the host instead of
controlling it, and the third time cost seventeen failures in one run:

    RC-46   `Console()` autoloads `/usr/share/exploitdb`, and Kali ships
            one, so every console in `test_console.py` started with 46,968
            rows already loaded and `catalog` reported a populated index
            where the file asserts an empty one.

    runner  the live loopback test required 127.0.0.1 to show open ports in
            nmap's top 100 -- a fact about the box, not about reconkg.

    here    exporting `RECONKG_VULN_DB` in a shell profile, which is the
            documented way to point reconkg at a corpus, made the entire
            suite resolve against 381,322 real CVEs instead of the nine-entry
            demonstration fixture. Seventeen tests that pin exact CVE ids and
            exact lead counts failed, and not one of them because the code
            was wrong: `test_ledger_ranks_corroborated_weaponised_match_first`
            wanted CVE-2021-41773 and got CVE-2021-42013, which on a real
            corpus is the better answer.

The shape is identical every time: green in CI, red on the machine the tool
is actually for. CI has no corpus, no exploit index and nothing listening, so
it cannot reproduce any of the three -- which is exactly why they survive.

Clearing the environment once, for every test, makes a local run reproduce
CI rather than the operator's laptop. Nothing is lost by it: CI passes with
none of these set, so no test can be relying on inheriting one.
"""

from __future__ import annotations

import pytest

#: Everything reconkg reads from the environment to find state on this
#: machine. Cleared wholesale rather than named per-test, because the failure
#: mode is a *new* variable that nobody remembers to add to a per-test list --
#: the standing question in BRIEF.md wearing different clothes.
HOST_ENVIRONMENT = (
    "RECONKG_VULN_DB",
    "RECONKG_EXPLOIT_DB",
    "RECONKG_SCRIPT_DB",
    "RECONKG_TOKENS",
    "RECONKG_SNAPSHOT_DIR",
    "RECONKG_PORT",
    "RECONKG_TOKEN",
    "RECONKG_URL",
    "NVD_API_KEY",
)


@pytest.fixture(autouse=True)
def isolate_from_the_host(monkeypatch):
    """Unset every reconkg environment variable for the duration of a test.

    Autouse and unconditional. A test that wants one sets it itself, and its
    own `monkeypatch.setenv` runs after this fixture, so opting in still
    works exactly as it did -- `wired` and `_fresh_state` are unaffected.

    `raising=False` because absent is the normal case: on CI none of these
    exist, and this fixture is only load-bearing on a developer's machine.
    """
    for name in HOST_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
