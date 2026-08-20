"""The only module in reconkg permitted to execute anything.

Non-negotiable 9 exists because thirteen of forty-seven findings are one
control built on one path and forgotten on a second. An execution path is
the worst conceivable place to learn that a fourteenth time, so there is
exactly one path and this is it. Nothing else in the tree imports
`subprocess` or `asyncio.create_subprocess_*`, and a test asserts that.

Three properties, in the order they matter.

**Named profiles, not caller-supplied flags.** The caller asks for
`service`, never for `-sT -sV --version-intensity 5`. A flag allowlist
would be a filter applied to caller-influenced strings, and this project
has three separate findings about precisely that shape: RC-31 (a membership
test that looked type-safe because `Category` subclassed `str`), RC-32
(msfconsole re-splitting its own argument on `;`), and RC-37 (`--script
exploit` selecting a *category* rather than a file). Filtering hostile
strings is a game you win by not playing. Nothing the caller sends becomes
a flag.

**Argv is a list, never a string.** `create_subprocess_exec`, never
`_shell`. There is no interpolation anywhere in this module. Exactly one
caller-derived value reaches the process -- the target address -- and it
arrives as its own argv element where no metacharacter means anything.

**Re-validation at the chokepoint.** `app.py` already checks
`validate_address` and `require_scope` before calling here. This checks the
address again anyway. RC-07's finding was that per-ingress validation loses,
and the ingress that forgets is always the one nobody has written yet; the
console, a scheduled job and a future CLI are all callers that do not exist
today. The check belongs where the packets leave.

**What is deliberately absent.** No `-sS`, `-sU` or `-O`: they need root,
and a coordinator that asks to run privileged is a coordinator that will be
run privileged. Every profile is an unprivileged connect scan. No `-sC` and
no `--script` in any form: NSE brings the whole `commands.py` category tier
into play, and running scripts is a materially larger decision than running
a port scan. When that is wanted it gets its own review, not a quiet
addition to a tuple here.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .auth import validate_address
from .importers import ImportResult, parse_nmap_xml

log = logging.getLogger(__name__)

BINARY = "nmap"

#: Profile -> argv fragment. The whole vocabulary a caller has.
#:
#: `--open` on the port profiles because a closed port is not evidence
#: anyone acts on and it triples the size of the XML. `-sn` carries no port
#: flags at all: a host-discovery run legitimately produces hosts with no
#: port data, which RC-22's round-7 finding taught the importer to record
#: rather than silently drop.
PROFILES: dict[str, tuple[str, ...]] = {
    "discovery": ("-sn",),
    "quick": ("-sT", "-F", "--open"),
    "service": ("-sT", "-sV", "--version-intensity", "5", "--open"),
    "thorough": ("-sT", "-sV", "-p-", "--open"),
}

DEFAULT_PROFILE = "service"

#: Wall-clock ceilings, per profile. A scan that hangs holds a slot, and two
#: slots is the whole budget -- so the timeout is what stops one unreachable
#: host from making the feature look broken for everyone.
TIMEOUTS: dict[str, float] = {
    "discovery": 300.0,
    "quick": 600.0,
    "service": 1800.0,
    "thorough": 5400.0,
}

#: Concurrent scans across the whole process. Low on purpose: nmap is
#: bandwidth-hungry and the failure mode of an unbounded pool is a lab
#: network that stops working while somebody debugs the wrong thing.
MAX_CONCURRENT = 2

MAX_STDERR = 4000

_slots: Optional[asyncio.Semaphore] = None


class ScannerError(RuntimeError):
    """The scan could not be run, or ran and failed."""


class ScannerMissing(ScannerError):
    """nmap is not installed.

    Its own type so a caller can say "nmap is not installed" rather than
    "scan failed", which is the difference between a five-second fix and an
    afternoon.
    """


class ScannerTimeout(ScannerError):
    """The scan ran past its ceiling and was killed.

    A subclass rather than a flag because the HTTP layer maps it to 504
    while a non-zero exit maps to 502, and those are genuinely different
    facts: one says "this host is slow or filtered, try a smaller profile",
    the other says "nmap refused the arguments". Discriminating on a
    substring of the message would work until someone rewords the message.
    """


@dataclass
class ScanRun:
    """What happened, in enough detail to explain a disappointing result."""

    target: str
    profile: str
    argv: tuple[str, ...] = ()
    returncode: int = -1
    duration_s: float = 0.0
    stderr: str = ""
    timed_out: bool = False
    result: Optional[ImportResult] = None

    @property
    def hosts_up(self) -> int:
        return len(self.result.hosts) if self.result else 0

    def as_dict(self) -> dict:
        payload = {
            "target": self.target,
            "profile": self.profile,
            # The exact argv, because an operator reading "0 services found"
            # should be able to see whether -sV was in the command at all.
            "command": list(self.argv),
            "returncode": self.returncode,
            "duration_s": round(self.duration_s, 1),
            "timed_out": self.timed_out,
            "hosts": self.hosts_up,
            "services": sum(len(h.get("services", []))
                            for h in (self.result.hosts.values()
                                      if self.result else [])),
            "warnings": list(self.result.warnings) if self.result else [],
        }
        if self.stderr:
            payload["stderr"] = self.stderr
        return payload


def available() -> Optional[str]:
    """Absolute path to nmap, or None. Resolved rather than assumed.

    Returned rather than raised because "is scanning possible here" is a
    question the UI asks on load to decide whether to offer the button at
    all, and a disabled control with a reason beats one that fails on click.
    """
    return shutil.which(BINARY)


def profile_names() -> list[str]:
    return sorted(PROFILES)


def build_argv(target: str, profile: str, xml_path: str) -> tuple[str, ...]:
    """The command, assembled from a fixed vocabulary plus one address.

    Split out and returned so it can be asserted directly. A test that reads
    the argv this produces is checking the thing that runs; a test that mocks
    the subprocess and checks what it was called with is checking the mock.
    """
    binary = available()
    if binary is None:
        raise ScannerMissing(
            f"{BINARY} is not installed or not on PATH. On Kali: "
            "`sudo apt install nmap`.")
    try:
        flags = PROFILES[profile]
    except KeyError:
        raise ScannerError(
            f"unknown scan profile {profile!r}; "
            f"choose one of {', '.join(profile_names())}") from None

    # Re-validated here even though every current caller validates first.
    # See the module docstring: the ingress that forgets is the one nobody
    # has written yet, and this is where the packets leave.
    address = validate_address(target)

    # `--` before the address so a target that somehow began with a dash
    # cannot be read as a flag. validate_address already refuses those, which
    # makes this the belt to its braces -- and belts are cheap when the
    # failure is "scanned something the operator did not name".
    return (binary, *flags, "-oX", xml_path, "--", address)


async def run(target: str, profile: str = DEFAULT_PROFILE, *,
              timeout: Optional[float] = None) -> ScanRun:
    """Run one scan and parse its XML into evidence payloads.

    Writes XML to a private temp file rather than reading `-oX -` from
    stdout: the file is parsed by the same hardened `parse_nmap_xml` an
    uploaded file goes through, doctype guard and host caps included, so
    there is one parser and one set of bounds rather than two. `mkstemp` is
    0600, which is the RC-25 lesson applied before it becomes a finding.
    """
    global _slots
    if _slots is None:
        _slots = asyncio.Semaphore(MAX_CONCURRENT)

    handle, xml_path = tempfile.mkstemp(prefix="reconkg-scan-", suffix=".xml")
    os.close(handle)
    argv = build_argv(target, profile, xml_path)
    run_record = ScanRun(target=target, profile=profile, argv=argv)
    limit = timeout if timeout is not None else TIMEOUTS.get(profile, 1800.0)
    started = time.monotonic()

    try:
        async with _slots:
            log.info("scanning %s with profile %s", target, profile)
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            try:
                _out, err = await asyncio.wait_for(process.communicate(),
                                                   timeout=limit)
            except asyncio.TimeoutError:
                run_record.timed_out = True
                process.kill()
                # Reap it. An unawaited killed child becomes a zombie held
                # by the event loop for the life of the process.
                await process.wait()
                err = b""
            run_record.returncode = process.returncode if not \
                run_record.timed_out else -1
            run_record.stderr = err.decode("utf-8", "replace")[:MAX_STDERR]
        run_record.duration_s = time.monotonic() - started

        if run_record.timed_out:
            raise ScannerTimeout(
                f"scan of {target} exceeded {limit:.0f}s and was stopped. "
                f"Profile {profile!r} is the slow one -- try 'quick'.")
        if run_record.returncode != 0:
            raise ScannerError(
                f"nmap exited {run_record.returncode}: "
                f"{run_record.stderr.strip()[:300] or 'no error output'}")

        try:
            run_record.result = parse_nmap_xml(xml_path)
        except (FileNotFoundError, ValueError) as exc:
            # nmap exited 0 and produced nothing parseable. Rare, and worth
            # naming rather than surfacing as "0 hosts": a silent empty
            # result reads exactly like a clean host.
            raise ScannerError(
                f"nmap exited 0 but its XML was unusable: {exc}") from None
        return run_record
    finally:
        try:
            os.unlink(xml_path)
        except OSError:                     # pragma: no cover - defensive
            pass
