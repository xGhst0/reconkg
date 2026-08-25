"""Discovery stages and the evidence boundary.

ARCHITECTURAL RULE (Architect, non-negotiable): stages never open sockets.
A stage consumes an `EvidenceSource` -- parsed output that some external tool
produced -- and returns structured observations. That keeps the engine a pure
state machine: fully testable, deterministic, and incapable of touching a
network by accident. `tests/test_offline.py` enforces it by trapping
`socket.socket.connect` during a full pipeline run.

To wire a real scanner in later, implement `EvidenceSource.collect()` to shell
out to your tool and parse its output. The engine contract does not change.
"""

from __future__ import annotations

import abc
import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Observations -- what a stage is allowed to assert
# --------------------------------------------------------------------------- #

@dataclass
class PortObs:
    number: int
    state: str = "open"
    protocol: str = "tcp"
    confidence: float = 0.8


@dataclass
class ServiceObs:
    port: int
    name: str
    protocol: str = "tcp"
    tunnel: Optional[str] = None
    confidence: float = 0.7


@dataclass
class FingerprintObs:
    port: int
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    banner: Optional[str] = None
    ambiguous: bool = False
    application: bool = False
    """Set by the identity arbiter; travels to `Fingerprint.application`."""
    protocol: str = "tcp"
    confidence: float = 0.6


Observation = PortObs | ServiceObs | FingerprintObs


class Outcome(str, Enum):
    SUCCESS = "success"
    AMBIGUOUS = "ambiguous"
    """Ran, but could not commit to a version -- triggers fallback."""
    TIMEOUT = "timeout"
    ERROR = "error"
    NO_DATA = "no_data"
    SKIPPED = "skipped"

    @property
    def needs_fallback(self) -> bool:
        return self in {Outcome.AMBIGUOUS, Outcome.TIMEOUT, Outcome.ERROR,
                        Outcome.NO_DATA}


@dataclass
class StageResult:
    outcome: Outcome
    detail: str = ""
    observations: list[Observation] = field(default_factory=list)
    scope_ports: list[int] = field(default_factory=list)
    """Ports whose existing fingerprints should be downgraded on a bad outcome."""


# --------------------------------------------------------------------------- #
# Evidence boundary
# --------------------------------------------------------------------------- #

class EvidenceSource:
    """Offline fixture store. The seam where real tool adapters plug in.

    `collect(tool, address)` returns whatever that tool "saw". Raising
    `TimeoutError` or any exception here is a supported way to exercise the
    engine's failure routing.
    """

    def __init__(self, fixtures: Optional[dict] = None) -> None:
        self.fixtures: dict[tuple[str, str], object] = dict(fixtures or {})
        self.principals: dict[tuple[str, str], str] = {}
        self.calls: list[tuple[str, str]] = []

    def put(self, tool: str, address: str, data: object,
            principal: str = "system") -> None:
        """Store evidence along with WHO submitted it.

        `principal` must come from an authenticated credential, never from
        the request body -- it is the field the confidence model measures
        independence on (RC-01b).
        """
        self.fixtures[(tool, address)] = data
        self.principals[(tool, address)] = principal

    def principal_for(self, tool: str, address: str) -> str:
        return self.principals.get((tool, address), "system")

    async def collect(self, tool: str, address: str) -> object:
        self.calls.append((tool, address))
        data = self.fixtures.get((tool, address))
        if isinstance(data, Exception):
            raise data
        if callable(data):
            result = data(address)
            return await result if asyncio.iscoroutine(result) else result
        return data


# --------------------------------------------------------------------------- #
# Stage interface
# --------------------------------------------------------------------------- #

class DiscoveryStage(abc.ABC):
    """One technique. Runs under a timeout, isolated from its siblings."""

    name: str = "unnamed"
    technique: str = "generic"
    tool: str = "unknown"
    timeout_s: float = 10.0
    decay_factor: float = 0.6
    """How hard to downgrade in-scope fingerprints when this stage fails."""

    @abc.abstractmethod
    async def run(self, address: str, evidence: EvidenceSource,
                  context: dict) -> StageResult:
        """Return observations. Must not raise for expected failures --
        return an Outcome instead. Unexpected exceptions are caught by the
        engine and converted to Outcome.ERROR."""

    def __repr__(self) -> str:  # pragma: no cover - debugging nicety
        return f"<{type(self).__name__} {self.name}>"


# --------------------------------------------------------------------------- #
# Concrete stages (offline)
# --------------------------------------------------------------------------- #

class PortSweepStage(DiscoveryStage):
    """Primary port discovery. Fixture: {"ports": [{"number":80,...}, ...]}."""

    name = "port-sweep"
    technique = "syn-sweep"
    tool = "nmap-sS"
    timeout_s = 8.0

    async def run(self, address, evidence, context) -> StageResult:
        data = await evidence.collect(self.tool, address)
        if not data or not data.get("ports"):
            return StageResult(Outcome.NO_DATA, "no ports returned")
        obs: list[Observation] = [
            PortObs(number=p["number"], state=p.get("state", "open"),
                    protocol=p.get("protocol", "tcp"),
                    confidence=p.get("confidence", 0.85))
            for p in data["ports"]
        ]
        return StageResult(Outcome.SUCCESS, f"{len(obs)} ports", obs,
                           [p.number for p in obs if isinstance(p, PortObs)])


class ConnectSweepStage(PortSweepStage):
    """Fallback sweep -- slower, noisier, but survives filtered paths."""

    name = "connect-sweep"
    technique = "full-connect"
    tool = "nmap-sT"
    timeout_s = 20.0


class BannerStage(DiscoveryStage):
    """Primary service/version identification.

    Fixture entries may set ``"ambiguous": true`` to model a banner that
    identifies a product but not a usable version -- the case that must
    trigger the fallback path rather than being written in as fact.
    """

    name = "banner-probe"
    technique = "banner-grab"
    tool = "nmap-sV"
    timeout_s = 12.0
    decay_factor = 0.5

    async def run(self, address, evidence, context) -> StageResult:
        data = await evidence.collect(self.tool, address)
        if not data:
            return StageResult(Outcome.NO_DATA, "probe returned nothing")

        obs: list[Observation] = []
        ambiguous_ports: list[int] = []
        for entry in data.get("services", []):
            port = entry["port"]
            obs.append(ServiceObs(port=port, name=entry["service"],
                                  tunnel=entry.get("tunnel"),
                                  confidence=entry.get("confidence", 0.8)))
            ambiguous = entry.get("ambiguous", False) or not entry.get("version")
            obs.append(FingerprintObs(
                port=port, product=entry.get("product"),
                version=entry.get("version"), cpe=entry.get("cpe"),
                banner=entry.get("banner"), ambiguous=ambiguous,
                confidence=entry.get("confidence", 0.6) * (0.5 if ambiguous else 1.0),
            ))
            if ambiguous:
                ambiguous_ports.append(port)

        if not obs:
            return StageResult(Outcome.NO_DATA, "no services parsed")
        if ambiguous_ports:
            return StageResult(
                Outcome.AMBIGUOUS,
                f"unresolved version on {sorted(set(ambiguous_ports))}",
                obs, sorted(set(ambiguous_ports)),
            )
        return StageResult(Outcome.SUCCESS, f"{len(data['services'])} services",
                           obs, [e["port"] for e in data["services"]])


class OperatorStage(DiscoveryStage):
    """What a human read, which no fingerprinter could have told us.

    `/api/evidence` has accepted `tool: "operator"` since evidence submission
    existed, the source registry gives it the only 1.0 reliability in the
    table, and no stage ever collected it. Submissions returned 201, reported
    that ceiling back to the caller, and were staged into a bin nothing read.
    An accepted write that changes nothing is the worst shape this project
    has, because at the point of use it is indistinguishable from one that
    worked.

    Runs last, and that is the point. Every other stage is a tool inferring
    from bytes on the wire; this is the operator saying what the page says
    about itself. It is how the version in a footer -- the thing the Coverage
    panel asks for by name on every gap it files under "operator judgement"
    -- gets into the graph at all, and being a second principal it is also
    the only submission that can answer "uncorroborated".

    Never returns AMBIGUOUS. `_downgrade` reads that outcome as evidence
    against unresolved fingerprints, and a human submitting one version they
    are sure of is no reason to trust nmap less about a different port.
    """

    name = "operator-evidence"
    technique = "read by a human"
    tool = "operator"
    timeout_s = 5.0

    async def run(self, address, evidence, context) -> StageResult:
        data = await evidence.collect(self.tool, address)
        if not data:
            return StageResult(Outcome.NO_DATA, "nothing submitted")

        obs: list[Observation] = []
        ports: list[int] = []
        for entry in (data.get("services") or []):
            try:
                port = int(entry["port"])
            except (KeyError, TypeError, ValueError):
                log.warning("operator evidence entry with no usable port: %r",
                            entry)
                continue
            product = entry.get("product")
            version = entry.get("version")
            if not entry.get("service") and not product and not version:
                continue
            ports.append(port)
            confidence = float(entry.get("confidence", 1.0))

            # The port, first and unconditionally. `record_port`/`set_service`
            # both require the port to already exist in the store, and this
            # stage cannot read the store to check -- `run()` only sees
            # `evidence` and this run's own `context`, which starts empty
            # every scan. A cold target an operator adds and never scans
            # first is not exotic: it is exactly the case this control exists
            # for, since the whole point is answering a gap without needing
            # a tool installed. Reading content from a port is itself
            # evidence it was open; asserting that is not a guess.
            obs.append(PortObs(number=port, confidence=confidence))

            # Optional, deliberately. An operator reading a version off a
            # login page has an opinion about the application and none about
            # which protocol answers the socket; requiring a service name
            # would make them invent one, and an invented protocol overwrites
            # a probed fact with a typed guess. Where nothing is known yet
            # this still has to name *something* for the fingerprint below to
            # attach to -- `unknown` is nmap's own word for exactly this, and
            # `set_service` never lets a placeholder overwrite a real name:
            # against an existing service it only merges provenance in.
            service_name = str(entry["service"]) if entry.get("service") \
                else "unknown"
            obs.append(ServiceObs(port=port, name=service_name,
                                  tunnel=entry.get("tunnel"),
                                  confidence=confidence))
            # setdefault, not assignment: this stage runs last, and a
            # placeholder must not overwrite what an earlier stage already
            # put in this run's own context, even though nothing downstream
            # reads it this run -- the store-level merge is already
            # non-destructive and the scratch dict should not disagree with it.
            context.setdefault("services", {}).setdefault(port, service_name)

            if not product and not version:
                continue
            obs.append(FingerprintObs(
                port=port, product=product, version=version,
                cpe=entry.get("cpe"), banner=entry.get("banner") or product,
                ambiguous=bool(entry.get("ambiguous", not version)),
                confidence=confidence))

        if not obs:
            return StageResult(Outcome.NO_DATA, "no usable entries")
        return StageResult(Outcome.SUCCESS,
                           f"{len(obs)} observation(s) from the operator",
                           obs, sorted(set(ports)))


class DeepProbeStage(BannerStage):
    """Fallback identification: heavier protocol-specific probing.

    Same output contract as BannerStage; different tool, higher confidence,
    longer timeout. Runs only when the primary stage came back ambiguous or
    failed.
    """

    name = "deep-probe"
    technique = "protocol-specific"
    tool = "nmap-sV-intensity9"
    timeout_s = 30.0


class HttpAppStage(DiscoveryStage):
    """Web-layer fingerprinting for ports already known to speak HTTP."""

    name = "http-app-probe"
    technique = "http-fingerprint"
    tool = "whatweb"
    timeout_s = 15.0

    async def run(self, address, evidence, context) -> StageResult:
        http_ports = [
            port for port, svc in context.get("services", {}).items()
            if svc in {"http", "https", "http-alt"}
        ]
        if not http_ports:
            return StageResult(Outcome.SKIPPED, "no http services known")
        data = await evidence.collect(self.tool, address)
        if not data:
            return StageResult(Outcome.NO_DATA, "no web fingerprints")
        obs: list[Observation] = [
            FingerprintObs(port=e["port"], product=e.get("product"),
                           version=e.get("version"), cpe=e.get("cpe"),
                           banner=e.get("banner"),
                           ambiguous=e.get("ambiguous", False),
                           confidence=e.get("confidence", 0.7))
            for e in data.get("apps", []) if e["port"] in http_ports
        ]
        if not obs:
            return StageResult(Outcome.NO_DATA, "nothing matched http ports")
        return StageResult(Outcome.SUCCESS, f"{len(obs)} app fingerprints",
                           obs, http_ports)
