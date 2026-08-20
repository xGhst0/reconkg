"""Source trust model.

RC-01 / RC-01b root cause: the coordinator treated two caller-supplied
strings -- `source_tool` and `confidence` -- as facts. An evidence submitter
could declare its own credibility, and could invent as many "independent"
tool names as it liked to farm the corroboration bonus.

The fix separates three things that were conflated:

  principal   WHO submitted it. Comes from the authenticated credential,
              never from the request body. Independence is measured here.
  source_tool WHAT produced it. A label. Selects a reliability ceiling.
  confidence  HOW sure that tool claims to be. Advisory only -- it is
              multiplied by the registered reliability of the tool, so a
              caller can lower its own confidence but never raise it past
              what the operator has decided that tool is worth.

Unregistered tools are capped at UNREGISTERED_RELIABILITY, which sits below
the default correlation floor. Unknown tooling can populate the graph; it
cannot manufacture a lead on its own.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

UNREGISTERED_RELIABILITY = 0.25
"""Deliberately below CorrelationConfig.min_confidence (0.45)."""


@dataclass(frozen=True)
class SourceProfile:
    tool: str
    reliability: float
    """Operator's ceiling on how much this tool's word is worth."""
    note: str = ""

    def __post_init__(self) -> None:
        if not 0.0 < self.reliability <= 1.0:
            raise ValueError("reliability must be in (0, 1]")


class SourceRegistry:
    """Operator-controlled table of known tools and their credibility."""

    def __init__(self, profiles: dict[str, SourceProfile] | None = None) -> None:
        self._profiles: dict[str, SourceProfile] = dict(profiles or {})

    def register(self, tool: str, reliability: float, note: str = "") -> None:
        self._profiles[tool] = SourceProfile(tool, reliability, note)

    def is_registered(self, tool: str) -> bool:
        return tool in self._profiles

    def reliability(self, tool: str) -> float:
        profile = self._profiles.get(tool)
        if profile is None:
            log.warning("evidence from unregistered tool %r capped at %.2f",
                        tool, UNREGISTERED_RELIABILITY)
            return UNREGISTERED_RELIABILITY
        return profile.reliability

    def effective_confidence(self, tool: str, declared: float) -> float:
        """Clamp a declared score to what the operator trusts this tool with."""
        declared = min(max(declared, 0.0), 1.0)
        return round(declared * self.reliability(tool), 4)


def default_registry() -> SourceRegistry:
    """Reliability ordering reflects how much each tool actually commits to.

    A SYN sweep is near-certain about reachability; a banner grab is a guess
    dressed as a fact, which is why it sits lowest.
    """
    reg = SourceRegistry()
    reg.register("nmap-sS", 0.95, "SYN sweep: reachability only")
    reg.register("nmap-sT", 0.95, "full connect: reachability only")
    reg.register("nmap-sV", 0.75, "banner grab: frequently ambiguous")
    reg.register("nmap-sV-intensity9", 0.90, "protocol-specific probing")
    reg.register("whatweb", 0.85, "http fingerprinting")
    reg.register("operator", 1.0, "asserted by a human operator")
    reg.register("correlator", 1.0, "internal")
    return reg
