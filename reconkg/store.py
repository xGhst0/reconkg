"""Asset store and change-event plumbing.

The store is the single writer to the knowledge graph. Every mutation produces
a ChangeEvent, which is what the WebSocket layer broadcasts. Nothing else in
the system is allowed to mutate a Host in place -- that rule is what makes the
event stream a complete description of state.

Backing storage is in-memory here. `TargetStore` is deliberately narrow so it
can be swapped for a SQLAlchemy-backed implementation without touching the
engine: five methods, all async, no ORM types leaking out.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from typing import Awaitable, Callable, Optional

from pydantic import BaseModel, Field

from .auth import validate_address
from .models import Host, Port, Provenance, Service, VulnLead

log = logging.getLogger(__name__)


class EventKind(str, Enum):
    HOST_ADDED = "host.added"
    HOST_UPDATED = "host.updated"
    PORT_ADDED = "port.added"
    PORT_UPDATED = "port.updated"
    SERVICE_SET = "service.set"
    FINGERPRINT_ADDED = "fingerprint.added"
    FINGERPRINT_CONFIDENCE = "fingerprint.confidence_changed"
    LEAD_ADDED = "lead.added"
    STAGE_STARTED = "stage.started"
    STAGE_FINISHED = "stage.finished"
    PIPELINE_STARTED = "pipeline.started"
    PIPELINE_FINISHED = "pipeline.finished"
    LEDGER_READY = "ledger.ready"


class ChangeEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    kind: EventKind
    target: str
    path: str = ""
    """Dotted location in the graph, e.g. "10.10.10.5/tcp:80/http"."""
    payload: dict = Field(default_factory=dict)


Subscriber = Callable[[ChangeEvent], Awaitable[None]]

MAX_EVENT_LOG = 5000
"""RC-03: the event log is a ring buffer, not an append-only list. It exists
to replay recent history to a reconnecting client, not to be an archive --
anything durable belongs in the database, not in process memory."""


class TargetStore:
    """In-memory knowledge graph with change notification."""

    def __init__(self) -> None:
        self._hosts: dict[str, Host] = {}
        self._lock = asyncio.Lock()
        self._subscribers: list[Subscriber] = []
        self.event_log: deque[ChangeEvent] = deque(maxlen=MAX_EVENT_LOG)
        self.events_emitted = 0

    # -- subscription -------------------------------------------------------- #

    def subscribe(self, fn: Subscriber) -> Callable[[], None]:
        """Returns an idempotent unsubscribe callable.

        Calling it twice used to raise ValueError out of `list.remove`, so a
        double `ConnectionManager.shutdown()` -- which happens whenever two
        app instances share a store, e.g. across a test fixture teardown --
        blew up during cleanup. Teardown paths must be safe to run twice;
        that is the whole point of them.
        """
        self._subscribers.append(fn)

        def unsubscribe() -> None:
            try:
                self._subscribers.remove(fn)
            except ValueError:
                pass

        return unsubscribe

    async def emit(self, event: ChangeEvent) -> None:
        self.event_log.append(event)
        self.events_emitted += 1
        for fn in list(self._subscribers):
            try:
                await fn(event)
            except Exception:  # a broken subscriber must not stall the pipeline
                log.exception("subscriber raised on %s; dropping event for it",
                              event.kind.value)

    # -- reads --------------------------------------------------------------- #

    def get(self, address: str) -> Optional[Host]:
        return self._hosts.get(address)

    def list_hosts(self) -> list[Host]:
        return list(self._hosts.values())

    # -- writes -------------------------------------------------------------- #

    async def ensure_host(self, address: str, prov: Provenance) -> Host:
        """RC-07: address validation lives here, not at each ingress.

        The API validated addresses; the nmap importer did not, so a crafted
        `<address addr="10.0.0.1\r\nX-Injected: yes">` walked straight into
        the graph and into event paths broadcast to every analyst window --
        RC-04 reintroduced through a second door six commits later. Validating
        per-ingress is a losing game: the store is the only writer, so the
        check belongs on the write.
        """
        address = validate_address(address)
        async with self._lock:
            host = self._hosts.get(address)
            existing = host is not None
            if existing:
                host.observe(prov)
            else:
                host = Host(address=address, provenance=prov)
                self._hosts[address] = host

        # Re-observing a known host used to return here without emitting.
        # That is a real graph mutation -- observe() appends provenance and
        # recomputes confidence -- so a silent return meant analysts watching
        # the event stream never saw it and any change-driven consumer
        # (autosave, metrics) never learned the graph had moved. Found by
        # the snapshot work: an autosave subscribed to change events cannot
        # be correct if a mutation emits nothing.
        await self.emit(ChangeEvent(
            kind=EventKind.HOST_UPDATED if existing else EventKind.HOST_ADDED,
            target=address, path=address,
            payload={"address": address, "confidence": host.confidence,
                     "source": prov.source_tool, "principal": prov.principal},
        ))
        return host

    async def add_hostnames(self, address: str, hostnames: list[str],
                            prov: Provenance) -> Host:
        """Create-or-update through the store, under the lock.

        The API handler used to reach into `host.hostnames` and append
        directly, which broke the "store is the single writer" invariant the
        whole event stream depends on.
        """
        host = await self.ensure_host(address, prov)
        async with self._lock:
            added = [h for h in hostnames if h not in host.hostnames]
            host.hostnames.extend(added)
        if added:
            await self.emit(ChangeEvent(
                kind=EventKind.HOST_ADDED, target=address, path=address,
                payload={"hostnames_added": added}))
        return host

    async def record_port(self, address: str, port: Port) -> Port:
        async with self._lock:
            host = self._require(address)
            known = host.find_port(port.number, port.protocol) is not None
            stored = host.upsert_port(port)
        await self.emit(ChangeEvent(
            kind=EventKind.PORT_UPDATED if known else EventKind.PORT_ADDED,
            target=address,
            path=f"{address}/{stored.protocol}:{stored.number}",
            payload={"port": stored.number, "protocol": stored.protocol,
                     "state": stored.state.value,
                     "confidence": stored.confidence,
                     "source": stored.provenance.source_tool},
        ))
        return stored

    async def set_service(self, address: str, port_number: int,
                          service: Service, protocol: str = "tcp") -> Service:
        async with self._lock:
            host = self._require(address)
            port = host.find_port(port_number, protocol)
            if port is None:
                raise KeyError(f"{address} has no {protocol}:{port_number}")
            if port.service is None:
                port.service = service
            else:
                port.service.observe(service.provenance)
            stored = port.service
        await self.emit(ChangeEvent(
            kind=EventKind.SERVICE_SET, target=address,
            path=f"{address}/{protocol}:{port_number}/{stored.name}",
            payload={"service": stored.name, "confidence": stored.confidence,
                     "source": stored.provenance.source_tool},
        ))
        return stored

    async def record_fingerprint(self, address: str, port_number: int,
                                 fingerprint, protocol: str = "tcp"):
        async with self._lock:
            svc = self._require_service(address, port_number, protocol)
            before = {f.key for f in svc.fingerprints}
            stored = svc.upsert_fingerprint(fingerprint)
            is_new = stored.key not in before
        await self.emit(ChangeEvent(
            kind=EventKind.FINGERPRINT_ADDED if is_new
            else EventKind.FINGERPRINT_CONFIDENCE,
            target=address,
            path=f"{address}/{protocol}:{port_number}/{svc.name}/{stored.key}",
            payload={"product": stored.product, "version": stored.version,
                     "ambiguous": stored.ambiguous,
                     "confidence": stored.confidence,
                     "corroborated_by": sorted(stored.corroborating_tools),
                     "source": stored.provenance.source_tool},
        ))
        return stored

    async def adjust_fingerprint_confidence(
        self, address: str, port_number: int, fingerprint_id: str,
        factor: float, *, reason: str, source_tool: str, protocol: str = "tcp",
    ) -> Optional[float]:
        """Downgrade a specific fingerprint. Returns the new confidence."""
        async with self._lock:
            svc = self._require_service(address, port_number, protocol)
            fp = next((f for f in svc.fingerprints if f.id == fingerprint_id),
                      None)
            if fp is None:
                return None
            new = fp.decay(factor, reason=reason, source_tool=source_tool)
            key = fp.key
        await self.emit(ChangeEvent(
            kind=EventKind.FINGERPRINT_CONFIDENCE, target=address,
            path=f"{address}/{protocol}:{port_number}/{svc.name}/{key}",
            payload={"confidence": new, "reason": reason,
                     "source": source_tool, "direction": "down"},
        ))
        return new

    async def record_lead(self, address: str, port_number: int,
                          lead: VulnLead, protocol: str = "tcp") -> VulnLead:
        async with self._lock:
            svc = self._require_service(address, port_number, protocol)
            if any(l.cve_id == lead.cve_id
                   and l.matched_fingerprint_id == lead.matched_fingerprint_id
                   for l in svc.leads):
                return lead
            svc.leads.append(lead)
        await self.emit(ChangeEvent(
            kind=EventKind.LEAD_ADDED, target=address,
            path=f"{address}/{protocol}:{port_number}/{svc.name}/{lead.cve_id}",
            payload={"cve_id": lead.cve_id, "cvss": lead.cvss,
                     "priority": lead.priority,
                     "maturity": lead.exploit_maturity.value,
                     "rationale": lead.rationale},
        ))
        return lead

    # -- internals ----------------------------------------------------------- #

    def _require(self, address: str) -> Host:
        host = self._hosts.get(address)
        if host is None:
            raise KeyError(f"unknown host {address}")
        return host

    def _require_service(self, address: str, port_number: int,
                         protocol: str) -> Service:
        port = self._require(address).find_port(port_number, protocol)
        if port is None or port.service is None:
            raise KeyError(f"no service on {address} {protocol}:{port_number}")
        return port.service
