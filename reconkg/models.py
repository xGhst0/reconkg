"""Target Knowledge Graph schema.

Host -> Port -> Service -> Fingerprint -> VulnLead

Every node carries provenance: which tool asserted it, when, and how much we
trust it. Provenance is append-only -- `provenance_log` keeps every observation
so an analyst can always answer "why does the system believe this?".
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Iterator, Literal, Optional

from pydantic import BaseModel, Field, field_validator


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #

MAX_PROVENANCE_HEAD = 5
MAX_PROVENANCE_TAIL = 45
"""RC-03: the log is bounded. We keep the first few entries (how this node
came to exist) and the most recent (what it looks like now), and count what
was elided rather than silently rewriting history."""


class Provenance(BaseModel):
    """A single assertion about a node, attributed to a discovery source."""

    source_tool: str
    """What produced the claim. A label -- selects a reliability ceiling."""
    principal: str = "system"
    """WHO submitted it, from the authenticated credential. Independence is
    measured on this field, never on `source_tool` (RC-01b)."""
    observed_at: datetime = Field(default_factory=_now)
    confidence: float = Field(ge=0.0, le=1.0)
    """Effective confidence: already clamped by the source registry."""
    declared_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    """What the submitter asked for, retained for audit."""
    note: Optional[str] = None

    model_config = {"frozen": True}


class GraphNode(BaseModel):
    """Base for every node in the knowledge graph."""

    id: str = Field(default_factory=_new_id)
    provenance: Provenance
    provenance_log: list[Provenance] = Field(default_factory=list)
    elided_observations: int = 0
    """Count of log entries dropped by the cap. Never silently zero."""

    def model_post_init(self, __context) -> None:  # noqa: D105
        if not self.provenance_log:
            self.provenance_log.append(self.provenance)

    # -- confidence arithmetic ---------------------------------------------- #

    @property
    def confidence(self) -> float:
        return self.provenance.confidence

    @property
    def corroborating_tools(self) -> set[str]:
        return {p.source_tool for p in self.provenance_log}

    @property
    def corroborating_principals(self) -> set[str]:
        """The set that actually matters for independence."""
        return {p.principal for p in self.provenance_log}

    def _append_bounded(self, obs: Provenance) -> None:
        self.provenance_log.append(obs)
        cap = MAX_PROVENANCE_HEAD + MAX_PROVENANCE_TAIL
        if len(self.provenance_log) > cap:
            head = self.provenance_log[:MAX_PROVENANCE_HEAD]
            tail = self.provenance_log[-MAX_PROVENANCE_TAIL:]
            self.elided_observations += len(self.provenance_log) - len(head) - len(tail)
            self.provenance_log = head + tail

    def observe(self, obs: Provenance) -> float:
        """Fold a new observation into this node and return the new confidence.

        Genuinely independent corroboration combines with a noisy-OR:
            c = 1 - (1 - c_old)(1 - c_new)

        Independence is judged on `principal` -- the authenticated submitter.
        A principal we have already heard from cannot compound its own claim
        no matter how many `source_tool` labels it rotates through; we take
        the max instead. Keying this on the tool name was RC-01b: one actor
        posting under three invented tool names farmed the bonus and pushed
        sub-threshold claims over the correlation floor.
        """
        prior_principals = {p.principal for p in self.provenance_log}
        self._append_bounded(obs)
        old = self.provenance.confidence
        if obs.principal in prior_principals:
            new = max(old, obs.confidence)
        else:
            new = 1.0 - (1.0 - old) * (1.0 - obs.confidence)
        new = min(round(new, 4), 1.0)
        self.provenance = Provenance(
            source_tool=obs.source_tool,
            principal=obs.principal,
            observed_at=obs.observed_at,
            confidence=new,
            declared_confidence=obs.declared_confidence,
            note=obs.note,
        )
        return new

    def decay(self, factor: float, *, reason: str, source_tool: str) -> float:
        """Reduce confidence after a contradiction, timeout, or ambiguity.

        Recorded in the log like any other observation -- a downgrade is
        evidence too, and it must survive into the audit trail.
        """
        if not 0.0 < factor <= 1.0:
            raise ValueError("decay factor must be in (0, 1]")
        new = round(self.provenance.confidence * factor, 4)
        self.provenance = Provenance(
            source_tool=source_tool, principal="system", confidence=new,
            note=f"decayed: {reason}"
        )
        self._append_bounded(self.provenance)
        return new


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #

class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class ExploitMaturity(str, Enum):
    """How readily a lead can be validated. Drives triage order only."""

    NOT_DEFINED = "not_defined"
    THEORETICAL = "theoretical"
    PROOF_OF_CONCEPT = "proof_of_concept"
    FUNCTIONAL = "functional"
    WEAPONISED = "weaponised"

    @property
    def weight(self) -> float:
        return {
            "not_defined": 0.5,
            "theoretical": 0.4,
            "proof_of_concept": 0.7,
            "functional": 0.9,
            "weaponised": 1.0,
        }[self.value]


# --------------------------------------------------------------------------- #
# Nodes
# --------------------------------------------------------------------------- #

class Fingerprint(GraphNode):
    """A claim about what software is answering on a service."""

    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    raw_banner: Optional[str] = None
    ambiguous: bool = False
    """Set when a source could not commit to a single product/version."""
    application: bool = False
    """The corpus knows this product by name and it is not a platform piece.

    Set by `webid.resolve_identity` when a raw product claim -- typically a
    page title -- was arbitrated against the corpus and recognised. It is the
    only permission `build_leads` accepts for emitting product-only leads on
    a fingerprint that has no version.

    What it encodes is the difference between "Apache, version unknown",
    which is twenty years of unrelated CVEs and the reason product-only
    matching is off by default, and "rConfig, version unknown", which is a
    short list an operator can read in full. Defaulting to False keeps every
    existing snapshot, and every source that does not set it, on exactly
    today's behaviour.
    """

    @property
    def key(self) -> str:
        return f"{(self.product or '?').lower()}/{self.version or '?'}"


class VulnLead(GraphNode):
    """A candidate vulnerability match. A lead, not a finding.

    Nothing in this system validates a lead. It exists to tell an analyst
    where to look and in what order.
    """

    cve_id: str
    title: str
    cvss: float = Field(ge=0.0, le=10.0)
    exploit_maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED
    matched_fingerprint_id: str
    rationale: str
    priority: float = 0.0


class Service(GraphNode):
    name: str
    tunnel: Optional[str] = None  # e.g. "ssl"
    fingerprints: list[Fingerprint] = Field(default_factory=list)
    leads: list[VulnLead] = Field(default_factory=list)

    def best_fingerprint(self) -> Optional[Fingerprint]:
        candidates = [f for f in self.fingerprints if not f.ambiguous]
        pool = candidates or self.fingerprints
        return max(pool, key=lambda f: f.confidence, default=None)

    def contradictions(self, floor: float = 0.45) -> list[tuple[Fingerprint,
                                                                Fingerprint]]:
        """Pairs of fingerprints that cannot both be true.

        Two credible claims of the *same product* at *different versions* is
        a conflict, not two facts. The graph deliberately keeps both -- we do
        not know which is wrong -- but silently averaging them into a ranked
        ledger hides the disagreement, and an attacker who cannot forge
        corroboration can still add plausible noise. Surfacing the conflict
        is what turns that noise back into a question.

        A fingerprint with no version is not in conflict with a versioned one:
        that is an unresolved observation, not a contradiction.
        """
        credible = [f for f in self.fingerprints
                    if f.confidence >= floor and f.version and not f.ambiguous]
        out: list[tuple[Fingerprint, Fingerprint]] = []
        for i, a in enumerate(credible):
            for b in credible[i + 1:]:
                same_product = (a.product or "").lower() == (b.product or "").lower()
                if same_product and a.version != b.version:
                    out.append((a, b))
        return out

    def upsert_fingerprint(self, fp: Fingerprint) -> Fingerprint:
        for existing in self.fingerprints:
            if existing.key == fp.key:
                existing.observe(fp.provenance)
                existing.ambiguous = existing.ambiguous and fp.ambiguous
                # OR, where `ambiguous` is AND, and for the same reason: both
                # move toward the more committed claim. One source having
                # placed this product in the corpus is not unlearned because
                # a second source did not try.
                existing.application = existing.application or fp.application
                existing.raw_banner = existing.raw_banner or fp.raw_banner
                existing.cpe = existing.cpe or fp.cpe
                return existing
        self.fingerprints.append(fp)
        return fp


class Port(GraphNode):
    number: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    state: PortState = PortState.UNKNOWN
    service: Optional[Service] = None


class Host(GraphNode):
    address: str

    @field_validator("address")
    @classmethod
    def _validated_address(cls, value: str) -> str:
        """RC-24: the check lives on the model, not on one writer.

        RC-07 moved address validation onto `TargetStore.ensure_host`,
        reasoning that the store is the only writer so the check belongs on
        the write. `persistence.load` then reached past the store's public
        surface into `_hosts` and became a second, unvalidated writer -- a
        CRLF address refused with HTTP 422 at the API was accepted by a
        snapshot restore and landed in event paths.

        The chokepoint was intact; the traffic went around it. So the rule
        moves one layer down, to the place no assignment path can skip:
        constructing or deserialising a Host at all. Third instance of this
        pattern in the audit, and the last place left to put it.
        """
        from .auth import validate_address
        return validate_address(value)
    hostnames: list[str] = Field(default_factory=list)
    os_guess: Optional[str] = None
    ports: list[Port] = Field(default_factory=list)

    def find_port(self, number: int, protocol: str = "tcp") -> Optional[Port]:
        for p in self.ports:
            if p.number == number and p.protocol == protocol:
                return p
        return None

    def upsert_port(self, port: Port) -> Port:
        existing = self.find_port(port.number, port.protocol)
        if existing is None:
            self.ports.append(port)
            return port
        existing.observe(port.provenance)
        if port.state is not PortState.UNKNOWN:
            existing.state = port.state
        if port.service and existing.service is None:
            existing.service = port.service
        return existing

    def iter_services(self) -> Iterator[tuple[Port, Service]]:
        for p in self.ports:
            if p.service is not None:
                yield p, p.service

    def all_leads(self) -> list[VulnLead]:
        return [lead for _, svc in self.iter_services() for lead in svc.leads]
