"""Stateful discovery engine.

Pipeline of slots; each slot is one primary technique plus ordered fallbacks.
Routing rules:

  SUCCESS  -> observations applied, slot done, fallbacks not run
  SKIPPED  -> slot done (a precondition wasn't met; not a failure)
  AMBIGUOUS-> observations applied, ambiguous fingerprints downgraded,
              next fallback runs
  TIMEOUT  -> in-scope fingerprints downgraded, next fallback runs
  ERROR    -> exception isolated and logged, next fallback runs
  NO_DATA  -> next fallback runs, no confidence change

Every attempt lands in `ScanReport.attempts` whether it worked or not. The
failure record is the useful part -- "port 445 timed out under sT twice" is
information, and a system that discards it makes the analyst rediscover it.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Sequence

from pydantic import ValidationError

from .models import Fingerprint, Port, PortState, Provenance, Service
from .sources import SourceRegistry, default_registry
from .store import ChangeEvent, EventKind, TargetStore
from .stages import (DiscoveryStage, EvidenceSource, FingerprintObs, Outcome,
                     PortObs, ServiceObs, StageResult)
from .vulnref import (DEFAULT_REFERENCE, CorrelationConfig, LedgerRow,
                      VulnEntry, build_leads)

log = logging.getLogger(__name__)


@dataclass
class StageSlot:
    primary: DiscoveryStage
    fallbacks: list[DiscoveryStage] = field(default_factory=list)
    label: str = ""

    def chain(self) -> list[DiscoveryStage]:
        return [self.primary, *self.fallbacks]


@dataclass
class Attempt:
    slot: str
    stage: str
    technique: str
    tool: str
    outcome: str
    detail: str
    duration_ms: float
    attempt_index: int
    started_at: datetime

    def as_dict(self) -> dict:
        return {**self.__dict__, "started_at": self.started_at.isoformat()}


@dataclass
class ScanReport:
    target: str
    attempts: list[Attempt] = field(default_factory=list)
    ledger: list[LedgerRow] = field(default_factory=list)
    exhausted_slots: list[str] = field(default_factory=list)
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None

    @property
    def ok(self) -> bool:
        return not self.exhausted_slots

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat()
            if self.finished_at else None,
            "attempts": [a.as_dict() for a in self.attempts],
            "exhausted_slots": self.exhausted_slots,
            "ledger": [r.as_dict() for r in self.ledger],
        }


class DiscoveryEngine:
    """Runs pipelines against a target and writes everything it learns."""

    def __init__(self, store: TargetStore, evidence: EvidenceSource,
                 pipeline: Optional[Sequence[StageSlot]] = None,
                 reference=None,
                 correlation: Optional[CorrelationConfig] = None,
                 registry: Optional[SourceRegistry] = None,
                 catalog=None, signals=None) -> None:
        self.store = store
        self.evidence = evidence
        self.pipeline = list(pipeline or [])
        from .resolver import coerce
        self.resolver = coerce(reference)
        """Where candidate CVEs come from. Accepts a Resolver, or a
        sequence of entries which gets wrapped in a StaticResolver.

        RC-36: the default is `None`, which means "ask the environment", not
        `DEFAULT_REFERENCE`. It was the latter, and `coerce` therefore never
        reached `from_env` on any path a caller did not spell out --
        including `app.AppState`. `RECONKG_VULN_DB` was read by nobody: an
        operator who built a 250,000-CVE corpus, pointed the variable at it
        and ran a scan through the API got the nine built-in demonstration
        entries and no indication of it. `from_env`'s whole design is that
        this must fail loudly; the default parameter routed around it.

        Held instead of a flat list because the list could not express
        an indexed lookup -- `build_leads` was handed the entire corpus
        for every fingerprint, which is fine for nine entries and
        impossible for 250,000."""
        self.correlation = correlation or CorrelationConfig()
        self.registry = registry or default_registry()
        self.signals = signals
        """Optional feeds.ExploitationSignals -- KEV and EPSS. Absent, leads
        rank on severity alone, which the research is clear is not risk."""
        self.catalog = catalog
        """Optional ExploitCatalog. Supplies observed public availability to
        correlation; absent, maturity stays as declared in the reference."""
        self._target_locks: dict[str, asyncio.Lock] = {}

    def _lock_for(self, address: str) -> asyncio.Lock:
        """RC-05 hardening: serialise scans of a single target.

        The store lock protects individual writes, but the engine does
        read-iterate-await sequences over live graph lists (_downgrade,
        _correlate). Concurrent scans of the same host could interleave
        inside those. Different targets still run fully in parallel.
        """
        lock = self._target_locks.get(address)
        if lock is None:
            lock = self._target_locks[address] = asyncio.Lock()
        return lock

    # -- public -------------------------------------------------------------- #

    async def run(self, address: str) -> ScanReport:
        async with self._lock_for(address):
            return await self._run_locked(address)

    async def _run_locked(self, address: str) -> ScanReport:
        report = ScanReport(target=address)
        context: dict = {"services": {}, "address": address}

        await self.store.ensure_host(
            address, Provenance(source_tool="operator", principal="system",
                                confidence=1.0,
                                note="target submitted for discovery"))
        await self.store.emit(ChangeEvent(
            kind=EventKind.PIPELINE_STARTED, target=address, path=address,
            payload={"slots": [s.label or s.primary.name
                               for s in self.pipeline]}))

        for slot in self.pipeline:
            resolved = await self._run_slot(slot, address, context, report)
            if not resolved:
                label = slot.label or slot.primary.name
                report.exhausted_slots.append(label)
                log.warning("[%s] slot '%s' exhausted all %d techniques",
                            address, label, len(slot.chain()))

        report.ledger = await self._correlate(address)
        report.finished_at = datetime.now(timezone.utc)

        await self.store.emit(ChangeEvent(
            kind=EventKind.LEDGER_READY, target=address, path=address,
            payload={"rows": len(report.ledger),
                     "top": [r.as_dict() for r in report.ledger[:5]]}))
        await self.store.emit(ChangeEvent(
            kind=EventKind.PIPELINE_FINISHED, target=address, path=address,
            payload={"attempts": len(report.attempts),
                     "exhausted": report.exhausted_slots,
                     "leads": len(report.ledger)}))
        log.info("[%s] pipeline complete: %d attempts, %d leads, %d exhausted",
                 address, len(report.attempts), len(report.ledger),
                 len(report.exhausted_slots))
        return report

    # -- slot execution ------------------------------------------------------ #

    async def _run_slot(self, slot: StageSlot, address: str, context: dict,
                        report: ScanReport) -> bool:
        label = slot.label or slot.primary.name
        for index, stage in enumerate(slot.chain()):
            started = datetime.now(timezone.utc)
            t0 = time.perf_counter()

            await self.store.emit(ChangeEvent(
                kind=EventKind.STAGE_STARTED, target=address, path=address,
                payload={"slot": label, "stage": stage.name,
                         "technique": stage.technique,
                         "attempt": index + 1}))

            result = await self._execute_isolated(stage, address, context)
            elapsed = (time.perf_counter() - t0) * 1000

            report.attempts.append(Attempt(
                slot=label, stage=stage.name, technique=stage.technique,
                tool=stage.tool, outcome=result.outcome.value,
                detail=result.detail, duration_ms=round(elapsed, 2),
                attempt_index=index + 1, started_at=started))

            await self.store.emit(ChangeEvent(
                kind=EventKind.STAGE_FINISHED, target=address, path=address,
                payload={"slot": label, "stage": stage.name,
                         "outcome": result.outcome.value,
                         "detail": result.detail,
                         "duration_ms": round(elapsed, 2)}))

            # Apply whatever the stage did learn, even on a bad outcome --
            # an ambiguous banner still tells us the service is there.
            if result.observations:
                await self._apply(address, result.observations, stage, context)

            if not result.outcome.needs_fallback:
                log.info("[%s] %s/%s -> %s (%s)", address, label, stage.name,
                         result.outcome.value, result.detail)
                return True

            await self._downgrade(address, stage, result)
            log.warning("[%s] %s/%s -> %s (%s); %s", address, label,
                        stage.name, result.outcome.value, result.detail,
                        "falling back" if index + 1 < len(slot.chain())
                        else "no techniques left")
        return False

    async def _execute_isolated(self, stage: DiscoveryStage, address: str,
                                context: dict) -> StageResult:
        """Timeout + exception containment. One bad stage never kills a run."""
        try:
            return await asyncio.wait_for(
                stage.run(address, self.evidence, context),
                timeout=stage.timeout_s)
        except asyncio.TimeoutError:
            return StageResult(Outcome.TIMEOUT,
                               f"exceeded {stage.timeout_s}s",
                               scope_ports=list(context.get("services", {})))
        except TimeoutError:  # raised by an adapter itself
            return StageResult(Outcome.TIMEOUT, "adapter reported timeout",
                               scope_ports=list(context.get("services", {})))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("[%s] stage %s raised", address, stage.name)
            return StageResult(Outcome.ERROR,
                               f"{type(exc).__name__}: {exc}",
                               scope_ports=list(context.get("services", {})))

    # -- observation handling ------------------------------------------------ #

    async def _apply(self, address: str, observations, stage: DiscoveryStage,
                     context: dict) -> None:
        """RC-02: a single malformed observation must not kill the pipeline.

        Originally this caught only KeyError, so evidence carrying a port
        number of 99999 raised pydantic's ValidationError, which escaped the
        stage isolation, the slot loop and `run()` -- one hostile field, HTTP
        500, no ledger. Rejection is now per-observation and total: bad input
        is dropped and counted, the rest of the batch still lands.
        """
        rejected = 0
        for obs in observations:
            try:
                await self._apply_one(address, obs, stage, context)
            except asyncio.CancelledError:
                raise
            except (KeyError, ValueError, TypeError, ValidationError) as exc:
                rejected += 1
                log.warning("[%s] rejected observation from %s: %s: %s",
                            address, stage.name, type(exc).__name__, exc)
            except Exception:
                rejected += 1
                log.exception("[%s] unexpected error applying observation "
                              "from %s; dropped", address, stage.name)
        if rejected:
            await self.store.emit(ChangeEvent(
                kind=EventKind.STAGE_FINISHED, target=address, path=address,
                payload={"stage": stage.name, "rejected_observations": rejected,
                         "note": "malformed evidence discarded"}))

    def _provenance_for(self, address: str, stage: DiscoveryStage,
                        declared: float) -> Provenance:
        """Build provenance the submitter cannot forge.

        `principal` comes from whoever authenticated to submit the evidence,
        and the declared confidence is clamped by the registry's ceiling for
        that tool (RC-01).
        """
        principal = self.evidence.principal_for(stage.tool, address)
        effective = self.registry.effective_confidence(stage.tool, declared)
        return Provenance(source_tool=stage.tool, principal=principal,
                          confidence=effective, declared_confidence=declared,
                          note=stage.technique)

    async def _apply_one(self, address: str, obs, stage: DiscoveryStage,
                         context: dict) -> None:
        prov = self._provenance_for(address, stage, obs.confidence)
        if isinstance(obs, PortObs):
            await self.store.record_port(address, Port(
                number=obs.number, protocol=obs.protocol,
                state=PortState(obs.state), provenance=prov))
        elif isinstance(obs, ServiceObs):
            await self.store.set_service(address, obs.port, Service(
                name=obs.name, tunnel=obs.tunnel, provenance=prov),
                protocol=obs.protocol)
            context["services"][obs.port] = obs.name
        elif isinstance(obs, FingerprintObs):
            await self.store.record_fingerprint(address, obs.port, Fingerprint(
                product=obs.product, version=obs.version, cpe=obs.cpe,
                raw_banner=obs.banner, ambiguous=obs.ambiguous,
                provenance=prov), protocol=obs.protocol)
        else:  # pragma: no cover - guarded by the Observation union
            raise TypeError(f"unknown observation {type(obs).__name__}")

    async def _downgrade(self, address: str, stage: DiscoveryStage,
                         result: StageResult) -> None:
        """Lower confidence in what a failing stage was supposed to confirm.

        NO_DATA is explicitly not a downgrade. A stage that returned nothing
        examined nothing, so it is not evidence against a fingerprint some
        other technique established -- the routing table at the top of this
        module always said so, but the code did not, and a fallback probe
        with no fixture was quietly demoting good SSH fingerprints below the
        correlation floor.
        """
        if result.outcome in (Outcome.NO_DATA, Outcome.SKIPPED):
            return
        host = self.store.get(address)
        if host is None:
            return
        scope = set(result.scope_ports)
        for port, svc in list(host.iter_services()):
            if scope and port.number not in scope:
                continue
            for fp in list(svc.fingerprints):
                if result.outcome is Outcome.AMBIGUOUS and not fp.ambiguous:
                    continue  # only the unresolved claim is suspect
                await self.store.adjust_fingerprint_confidence(
                    address, port.number, fp.id, stage.decay_factor,
                    reason=f"{stage.name}:{result.outcome.value}",
                    source_tool=stage.tool, protocol=port.protocol)

    # -- correlation --------------------------------------------------------- #

    async def _correlate(self, address: str) -> list[LedgerRow]:
        """Final stage: high-confidence fingerprints -> prioritised ledger.

        Read-only with respect to the outside world. No connections, no
        payloads, no validation attempts -- this produces a list for a human
        to review and act on.
        """
        host = self.store.get(address)
        if host is None:
            return []

        rows: list[LedgerRow] = []
        for port, svc in list(host.iter_services()):
            disputed = {f.id for pair in svc.contradictions(
                self.correlation.min_confidence) for f in pair}
            for fp in list(svc.fingerprints):
                contradicted = fp.id in disputed
                candidates = self.resolver.candidates(fp)
                for lead in build_leads(fp, candidates, self.correlation,
                                        self.catalog, contradicted,
                                        self.signals):
                    await self.store.record_lead(address, port.number, lead,
                                                 protocol=port.protocol)
                    rows.append(LedgerRow(
                        target=address, port=port.number,
                        protocol=port.protocol, service=svc.name,
                        product=fp.product, version=fp.version,
                        cve_id=lead.cve_id, title=lead.title, cvss=lead.cvss,
                        maturity=lead.exploit_maturity.value,
                        maturity_source=(
                            "index" if self.catalog is not None
                            and self.catalog.records_for(lead.cve_id)
                            else "declared"),
                        availability=(
                            [r.identifier for r in
                             self.catalog.records_for(lead.cve_id)]
                            if self.catalog is not None else []),
                        fingerprint_confidence=fp.confidence,
                        corroborated_by=sorted(fp.corroborating_tools),
                        independent_principals=sorted(
                            p for p in fp.corroborating_principals
                            if p != "system"),
                        priority=lead.priority, rationale=lead.rationale,
                        disputed=contradicted,
                        match_method=_method_of(lead.rationale),
                        backport_marker=_backport_of(fp)))
        rows.sort(key=lambda r: (r.priority, r.cvss), reverse=True)
        return rows


def _method_of(rationale: str) -> str:
    """Recover the match method the lead recorded in its rationale.

    `VulnLead` is a graph node with a fixed schema and adding a field to it
    would change what every snapshot deserialises; the rationale already
    carries the method verbatim, so the ledger reads it back rather than
    duplicating state that could drift out of agreement with the text an
    analyst is looking at.
    """
    marker = " | matched by "
    return rationale.rsplit(marker, 1)[-1] if marker in rationale else "unknown"


def _backport_of(fp) -> Optional[str]:
    from .cpe import looks_backported
    return looks_backported(fp.version, fp.raw_banner)


# --------------------------------------------------------------------------- #
# Default pipeline
# --------------------------------------------------------------------------- #

def default_pipeline() -> list[StageSlot]:
    from .stages import (BannerStage, ConnectSweepStage, DeepProbeStage,
                         HttpAppStage, PortSweepStage)
    return [
        StageSlot(PortSweepStage(), [ConnectSweepStage()], label="port-discovery"),
        StageSlot(BannerStage(), [DeepProbeStage()], label="service-id"),
        StageSlot(HttpAppStage(), [], label="web-layer"),
    ]
