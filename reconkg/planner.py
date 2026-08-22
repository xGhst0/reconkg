"""Gap analysis: read the graph, name what's wrong with it, assign a module.

This is the adaptive layer. Rather than running a fixed pipeline and stopping,
the planner inspects what the knowledge graph currently believes, identifies
where that belief is *weak or missing*, and assigns the specific module that
would close each gap.

What gets assigned, and what doesn't:

  knowledge gaps -> a module. "Port 445 is open with no service identified"
                    resolves to recon/fingerprint/banner_probe. "This
                    fingerprint has one submitter" resolves to a request for
                    an independent second opinion. These are recon actions and
                    the planner assigns them directly.

  vulnerability   -> handoff, never a module. A confirmed lead routes to
  leads              `handoff.render_handoff`, which prints lookups and
                     caveats for you to act on in your own tooling. There is
                     no execution-module slot for the planner to fill, so
                     there is nothing here that becomes an auto-exploit chain
                     when the module directory gets populated.

The distinction is structural, not a policy check that could be flipped off:
`Recommendation.module` is only ever populated from the recon registry, and
leads produce `action="handoff"` with no module attached.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .models import Fingerprint, Host, Port, PortState, Service
from .modules import ModuleRegistry, registry as default_module_registry
from .vulnref import CorrelationConfig

log = logging.getLogger(__name__)


class Gap(str, Enum):
    """What is wrong with our current understanding."""

    NO_SERVICE = "port_open_without_service"
    NO_FINGERPRINT = "service_without_fingerprint"
    AMBIGUOUS_VERSION = "fingerprint_without_version"
    BELOW_FLOOR = "confidence_below_correlation_floor"
    UNCORROBORATED = "single_submitter"
    NO_WEB_FINGERPRINT = "http_service_without_app_fingerprint"
    NO_WEB_APPLICATION = "web_platform_identified_application_not"
    FILTERED_PORT = "port_filtered_not_resolved"
    CONTRADICTION = "credible_claims_conflict"
    LEAD_READY = "lead_ready_for_operator"


@dataclass
class Recommendation:
    gap: Gap
    target: str
    reason: str
    """Written for a human: what we don't know and why it matters."""
    action: str = "run_module"
    module: Optional[str] = None
    """Recon module fullname. None for anything that isn't a recon action."""
    options: dict = field(default_factory=dict)
    port: Optional[int] = None
    protocol: str = "tcp"
    priority: float = 0.5
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"gap": self.gap.value, "target": self.target,
                "reason": self.reason, "action": self.action,
                "module": self.module, "options": self.options,
                "port": self.port, "protocol": self.protocol,
                "priority": round(self.priority, 4), "detail": self.detail}

    def command(self) -> str:
        """The console line that would carry this out."""
        if self.action != "run_module" or not self.module:
            return f"handoff {self.detail.get('cve_id', '')}".strip()
        sets = " ".join(f"set {k} {v}" for k, v in self.options.items())
        return f"use {self.module}; {sets}; run".replace(" ;", ";")


#: Products that describe what a web application RUNS ON rather than what it
#: is. whatweb reports both in one list and they are not the same kind of
#: claim: Apache, OpenSSL, PHP and jQuery are the stack, and on a
#: distribution build their CVEs are backported anyway -- which reconkg
#: already says on every such lead. The application is what an operator is
#: actually hunting.
#:
#: Observed: a host returned 97 leads across Apache 2.4.6, OpenSSL 1.0.2k,
#: PHP 7.2.34 and jQuery 2.2.4, every Apache row carrying "CentOS --
#: distribution build". The way in was rConfig 3.9.6, an application none of
#: those names mention and nothing in the run ever identified. The ledger was
#: not wrong; it was answering a different question, at length.
WEB_PLATFORM_PRODUCTS = frozenset({
    "apache", "apache httpd", "httpd", "nginx", "iis", "lighttpd",
    "microsoft iis httpd", "microsoft-iis", "openssl", "php", "mod_ssl",
    "jquery", "jquery-ui", "bootstrap", "javascript", "html5", "modernizr",
    "httpserver", "x-powered-by", "cookies", "uncommonheaders", "title",
    "country", "ip", "script", "email", "meta-author", "openssh",
})

class GapPlanner:
    """Turns graph state into an ordered list of next actions."""

    MODULE_FOR_GAP = {
        Gap.NO_SERVICE: "recon/fingerprint/banner_probe",
        Gap.NO_FINGERPRINT: "recon/fingerprint/banner_probe",
        Gap.AMBIGUOUS_VERSION: "recon/fingerprint/deep_probe",
        Gap.BELOW_FLOOR: "recon/fingerprint/deep_probe",
        Gap.NO_WEB_FINGERPRINT: "recon/http/app_fingerprint",
        Gap.FILTERED_PORT: "recon/discovery/connect_sweep",
    }

    def __init__(self, modules: Optional[ModuleRegistry] = None,
                 correlation: Optional[CorrelationConfig] = None) -> None:
        # `or` would be wrong here: ModuleRegistry defines __len__, so an
        # empty registry is falsy and would silently fall back to the global
        # one -- exactly the case a caller passing an empty registry means to
        # avoid.
        self.modules = (default_module_registry if modules is None
                        else modules)
        self.correlation = correlation or CorrelationConfig()

    def _assign(self, gap: Gap) -> Optional[str]:
        """Resolve a gap to a module, but only if it is actually registered.

        Returning a fullname the registry cannot instantiate would produce a
        recommendation the operator cannot execute.
        """
        fullname = self.MODULE_FOR_GAP.get(gap)
        if fullname is None:
            return None
        try:
            self.modules.get(fullname)
        except KeyError:
            log.warning("gap %s maps to unregistered module %s",
                        gap.value, fullname)
            return None
        return fullname

    def plan(self, host: Host) -> list[Recommendation]:
        recs: list[Recommendation] = []
        recs += self._port_gaps(host)
        recs += self._fingerprint_gaps(host)
        recs += self._lead_actions(host)
        recs.sort(key=lambda r: r.priority, reverse=True)
        return recs

    # -- gaps ---------------------------------------------------------------- #

    def _port_gaps(self, host: Host) -> list[Recommendation]:
        out = []
        for port in host.ports:
            if port.state is PortState.FILTERED:
                gap = Gap.FILTERED_PORT
                out.append(Recommendation(
                    gap=gap, target=host.address, port=port.number,
                    protocol=port.protocol,
                    reason=(f"{port.protocol}:{port.number} is filtered, so we "
                            "know something is there but not what. A full "
                            "connect attempt distinguishes a dropped probe "
                            "from a genuinely closed port."),
                    module=self._assign(gap),
                    options={"RHOST": host.address},
                    priority=0.4))
                continue
            if port.state is not PortState.OPEN:
                continue
            if port.service is None:
                gap = Gap.NO_SERVICE
                out.append(Recommendation(
                    gap=gap, target=host.address, port=port.number,
                    protocol=port.protocol,
                    reason=(f"{port.protocol}:{port.number} is open but no "
                            "service has been identified. An open port with "
                            "no service is the largest single gap in the "
                            "graph -- everything downstream depends on it."),
                    module=self._assign(gap),
                    options={"RHOST": host.address},
                    priority=0.9))
            elif not port.service.fingerprints:
                gap = Gap.NO_FINGERPRINT
                out.append(Recommendation(
                    gap=gap, target=host.address, port=port.number,
                    protocol=port.protocol,
                    reason=(f"{port.service.name} on {port.number} has no "
                            "version fingerprint, so no lead can be "
                            "correlated against it."),
                    module=self._assign(gap),
                    options={"RHOST": host.address},
                    priority=0.8))
        return out

    def _fingerprint_gaps(self, host: Host) -> list[Recommendation]:
        out = []
        floor = self.correlation.min_confidence
        for port, svc in host.iter_services():
            web = svc.name in {"http", "https", "http-alt"}
            tools = {t for fp in svc.fingerprints
                     for t in fp.corroborating_tools}
            if web and "whatweb" not in tools and svc.fingerprints:
                gap = Gap.NO_WEB_FINGERPRINT
                out.append(Recommendation(
                    gap=gap, target=host.address, port=port.number,
                    protocol=port.protocol,
                    reason=("HTTP service with no web-layer fingerprint. An "
                            "independent web fingerprint is the cheapest way "
                            "to corroborate the server version."),
                    module=self._assign(gap),
                    options={"RHOST": host.address},
                    priority=0.55))

            # The stack was identified and the application was not, which is
            # a different answer from "the web layer is understood" and used
            # to be indistinguishable from it: NO_WEB_FINGERPRINT closes as
            # soon as *any* whatweb fingerprint arrives, and Apache, OpenSSL,
            # PHP and jQuery all arrive together.
            #
            # Ranked above every other gap because it is the one an operator
            # can act on immediately and cheaply -- by opening the page. The
            # version string that matters is frequently in a footer or a
            # login banner, where no fingerprinter looks and a human reads it
            # in two seconds.
            if web and svc.fingerprints:
                named = {(fp.product or "").strip().lower()
                         for fp in svc.fingerprints}
                named.discard("")
                if named and named <= WEB_PLATFORM_PRODUCTS:
                    out.append(Recommendation(
                        gap=Gap.NO_WEB_APPLICATION, target=host.address,
                        port=port.number, protocol=port.protocol,
                        action="handoff", module=None,
                        reason=(
                            "Only the platform was identified here: "
                            f"{', '.join(sorted(named))}. Those describe what "
                            "the application runs on, not what it is, and on "
                            "a distribution build their CVEs are usually "
                            "backported -- every lead below them says so. The "
                            "application itself is unnamed, so nothing in the "
                            "ledger is about it. Open the page and read what "
                            "it calls itself; a version in a footer beats "
                            "sixty stack CVEs."),
                        priority=0.85))

            for a, b in svc.contradictions(floor):
                out.append(Recommendation(
                    gap=Gap.CONTRADICTION, target=host.address,
                    port=port.number, protocol=port.protocol,
                    action="resolve_conflict", module=self._assign(
                        Gap.AMBIGUOUS_VERSION),
                    options={"RHOST": host.address},
                    reason=(f"Two credible claims disagree on {port.number}: "
                            f"{a.key} ({a.confidence:.2f}, via "
                            f"{', '.join(sorted(a.corroborating_principals))}) "
                            f"vs {b.key} ({b.confidence:.2f}, via "
                            f"{', '.join(sorted(b.corroborating_principals))}). "
                            "Both cannot be true. Until this is resolved, any "
                            "lead built on either is suspect."),
                    priority=0.88,
                    detail={"a": a.key, "b": b.key,
                            "a_confidence": a.confidence,
                            "b_confidence": b.confidence}))

            for fp in svc.fingerprints:
                if fp.ambiguous or not fp.version:
                    gap = Gap.AMBIGUOUS_VERSION
                    out.append(Recommendation(
                        gap=gap, target=host.address, port=port.number,
                        protocol=port.protocol,
                        reason=(f"{fp.product or 'unknown product'} on "
                                f"{port.number} has no resolved version. "
                                "Version-constrained CVEs cannot match, so "
                                "this service is invisible to correlation."),
                        module=self._assign(gap),
                        options={"RHOST": host.address},
                        priority=0.85,
                        detail={"fingerprint": fp.key,
                                "confidence": fp.confidence}))
                    continue

                if fp.confidence < floor:
                    gap = Gap.BELOW_FLOOR
                    out.append(Recommendation(
                        gap=gap, target=host.address, port=port.number,
                        protocol=port.protocol,
                        reason=(f"{fp.key} sits at {fp.confidence:.2f}, below "
                                f"the {floor:.2f} correlation floor. It is in "
                                "the graph but generates no leads until it is "
                                "re-confirmed."),
                        module=self._assign(gap),
                        options={"RHOST": host.address},
                        priority=0.7,
                        detail={"fingerprint": fp.key,
                                "confidence": fp.confidence}))
                    continue

                principals = {p for p in fp.corroborating_principals
                              if p != "system"}
                if len(principals) < 2:
                    out.append(Recommendation(
                        gap=Gap.UNCORROBORATED, target=host.address,
                        port=port.number, protocol=port.protocol,
                        action="submit_independent_evidence",
                        module=None,
                        reason=(f"{fp.key} rests on a single submitter "
                                f"({', '.join(principals) or 'unknown'}). One "
                                "opinion is not corroboration -- run a "
                                "different tool from a different principal "
                                "before trusting this version."),
                        priority=0.45,
                        detail={"fingerprint": fp.key,
                                "principals": sorted(principals)}))
        return out

    def _lead_actions(self, host: Host) -> list[Recommendation]:
        """Leads route to the operator. No module is ever assigned here."""
        out = []
        for port, svc in host.iter_services():
            for lead in svc.leads:
                out.append(Recommendation(
                    gap=Gap.LEAD_READY, target=host.address,
                    port=port.number, protocol=port.protocol,
                    action="handoff", module=None,
                    reason=(f"{lead.cve_id} ({lead.title}) is ranked at "
                            f"{lead.priority:.3f}. reconkg stops here: run "
                            "`handoff` for verification lookups and caveats, "
                            "then act in your own tooling."),
                    priority=min(0.95, 0.5 + lead.priority / 2),
                    detail={"cve_id": lead.cve_id, "cvss": lead.cvss,
                            "priority": lead.priority,
                            "maturity": lead.exploit_maturity.value}))
        return out


def render_plan(recs: list[Recommendation]) -> str:
    """msf-style plan output."""
    if not recs:
        return "\n[*] No gaps identified. The graph is as complete as the " \
               "current evidence allows.\n"
    lines = ["", f"[*] {len(recs)} gap(s) identified", ""]
    for i, r in enumerate(recs):
        where = f"{r.protocol}:{r.port}" if r.port else "host"
        lines.append(f"  [{i}] {r.priority:.2f}  {r.gap.value}  ({where})")
        for chunk in _wrap(r.reason, 68):
            lines.append(f"       {chunk}")
        if r.module:
            lines.append(f"       -> use {r.module}")
        elif r.action == "handoff":
            lines.append(f"       -> handoff {r.detail.get('cve_id', '')}"
                         "   [operator action, no module]")
        else:
            lines.append(f"       -> {r.action}   [no module]")
        lines.append("")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines or [""]
