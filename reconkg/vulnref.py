"""Mock vulnerability reference and the correlation stage.

Why this is more than version-string grep (Architect): naive matchers produce
ledgers that are 80% noise, and a noisy ledger gets ignored, which is worse
than no ledger. Three rules do most of the work here:

1. A fingerprint below `min_confidence` produces no lead at all.
2. Version constraints are compared as parsed tuples, not strings, so
   "2.4.9" does not sort above "2.4.50".
3. Priority multiplies severity by *how much we believe the fingerprint* and
   by corroboration count. A 9.8 CVSS matched off one shaky banner ranks
   below a 7.5 confirmed by three tools.

Replace `DEFAULT_REFERENCE` with an NVD/OSV feed loader; `correlate()` does
not care where the entries came from.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .models import ExploitMaturity, Fingerprint, Provenance, VulnLead

log = logging.getLogger(__name__)

_VERSION_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


def parse_version(raw: str) -> tuple:
    """Tokenise a version. Digits become (1, int); alphabetic tokens become
    (0, str) so that any letter sorts below any number at the same position.

    This is a tokeniser only -- comparison semantics live in
    `compare_versions`, because deciding what a *missing* token means
    (2.4.49 vs 2.4.49rc1) requires seeing both operands.
    """
    parts: list[tuple[int, object]] = []
    for token in _VERSION_TOKEN.findall(raw or ""):
        if token.isdigit():
            parts.append((1, int(token)))
        else:
            parts.append((0, token.lower()))
    return tuple(parts)


_ABSENT = (1, 0)
"""Padding for a missing token. Sorts above any alphabetic suffix, so a
release outranks its own release candidates (2.4.49 > 2.4.49rc1), and equals
an explicit zero, so 2.4 == 2.4.0."""


def compare_versions(left: str, right: str) -> int:
    """-1 / 0 / 1, with alphabetic pre-release suffixes ranked below release."""
    a, b = parse_version(left), parse_version(right)
    width = max(len(a), len(b))
    a += (_ABSENT,) * (width - len(a))
    b += (_ABSENT,) * (width - len(b))
    return (a > b) - (a < b)


_OPS = {
    "<": lambda c: c < 0, "<=": lambda c: c <= 0,
    ">": lambda c: c > 0, ">=": lambda c: c >= 0,
    "==": lambda c: c == 0, "!=": lambda c: c != 0,
}


def version_satisfies(version: str, op: str, bound: str) -> bool:
    """Raises ValueError on a version with no numeric component -- a banner
    like "Apache/unknown-build" must not silently compare as very old."""
    if not any(kind == 1 for kind, _ in parse_version(version)):
        raise ValueError(f"unparseable version: {version!r}")
    if op not in _OPS:
        raise ValueError(f"unsupported operator: {op!r}")
    return _OPS[op](compare_versions(version, bound))


@dataclass(frozen=True)
class VulnEntry:
    cve_id: str
    title: str
    product_match: str
    """Case-insensitive substring matched against the fingerprint product."""
    constraints: tuple[tuple[str, str], ...] = ()
    """ALL must hold, e.g. ((">=", "2.4.49"), ("<=", "2.4.50"))."""
    cvss: float = 0.0
    maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED
    requires_version: bool = True
    notes: str = ""
    cpe_ranges: tuple = ()
    """CPE applicability statements (`cpe.CPERange`). Preferred over
    `product_match` when present: an identifier lookup beats a substring
    heuristic, and NVD indexes applicability this way. Typed loosely to
    avoid a circular import -- `cpe` imports `compare_versions` from here."""
    handoff: tuple[str, ...] = ()
    """Operator-supplied follow-up commands for this entry.

    Empty by default and never auto-populated. A generated exploit-module
    path that half-matches the CVE is worse than no suggestion: it carries
    false confidence. If you know the right command, put it here yourself.
    """

    def matches(self, fp: Fingerprint):
        """-> (matched, rationale, MatchMethod|None).

        CPE first, product substring second. The method is returned rather
        than discarded because the two are not equally trustworthy and the
        ledger has to say which one fired.
        """
        from .cpe import MatchMethod, infer_cpe, parse

        observed = parse(fp.cpe) or infer_cpe(fp.product, fp.version)
        if observed is not None and self.cpe_ranges:
            for statement in self.cpe_ranges:
                ok, method, why = statement.matches(observed)
                if ok:
                    return True, why, method
            return False, "no CPE applicability statement matched", None

        matched, why = self._product_match(fp)
        if not matched:
            return False, why, None
        method = (MatchMethod.PRODUCT_VERSION if fp.version
                  else MatchMethod.PRODUCT_ONLY)
        return True, why, method

    def _product_match(self, fp: Fingerprint) -> tuple[bool, str]:
        """Substring fallback for entries with no usable CPE.

        An empty `product_match` matches nothing, because `"" in anything`
        is True and an entry with no product name would otherwise attach
        itself to every fingerprint in the graph. Feed ingestion produces
        exactly that shape for a CVE still awaiting analysis -- no
        applicability data, so no product name to fall back on. Found by a
        mutation-driven test, not by reading the code.
        """
        criterion = self.product_match.strip().lower()
        if not criterion:
            return False, "entry carries no product name to match on"
        product = (fp.product or "").lower()
        if not product:
            return False, "fingerprint has no product name"
        if criterion not in product:
            return False, "product mismatch"
        if not fp.version:
            if self.requires_version:
                return False, "no version to test constraints against"
            return True, f"product match on {fp.product}; version unknown"
        try:
            ok = all(version_satisfies(fp.version, op, bound)
                     for op, bound in self.constraints)
        except Exception:
            log.warning("unparseable version %r for %s", fp.version, self.cve_id)
            return False, "version unparseable"
        if not ok:
            return False, f"{fp.version} outside affected range"
        span = ", ".join(f"{op}{b}" for op, b in self.constraints) or "any"
        return True, f"{fp.product} {fp.version} satisfies {span}"


DEFAULT_REFERENCE: tuple[VulnEntry, ...] = (
    VulnEntry("CVE-2021-41773", "Apache path traversal / RCE",
              "apache", ((">=", "2.4.49"), ("<=", "2.4.49")), 9.8,
              ExploitMaturity.WEAPONISED,
              notes="Only 2.4.49 with specific config; 2.4.50 is CVE-2021-42013."),
    VulnEntry("CVE-2021-42013", "Apache path traversal (incomplete fix)",
              "apache", ((">=", "2.4.50"), ("<=", "2.4.50")), 9.8,
              ExploitMaturity.WEAPONISED),
    VulnEntry("CVE-2019-0211", "Apache privilege escalation",
              "apache", ((">=", "2.4.17"), ("<=", "2.4.38")), 7.8,
              ExploitMaturity.PROOF_OF_CONCEPT),
    VulnEntry("CVE-2018-15473", "OpenSSH username enumeration",
              "openssh", (("<", "7.7"),), 5.3, ExploitMaturity.FUNCTIONAL),
    VulnEntry("CVE-2023-38408", "OpenSSH ssh-agent forwarding RCE",
              "openssh", (("<", "9.3"),), 9.8,
              ExploitMaturity.PROOF_OF_CONCEPT,
              notes="Requires agent forwarding to an attacker-controlled host."),
    VulnEntry("CVE-2017-0144", "SMBv1 remote code execution (MS17-010)",
              "samba", (("<", "4.6.4"),), 8.1, ExploitMaturity.WEAPONISED),
    VulnEntry("CVE-2014-0160", "OpenSSL Heartbleed",
              "openssl", ((">=", "1.0.1"), ("<", "1.0.1g")), 7.5,
              ExploitMaturity.WEAPONISED),
    VulnEntry("CVE-2021-44228", "Log4Shell",
              "log4j", ((">=", "2.0"), ("<", "2.15.0")), 10.0,
              ExploitMaturity.WEAPONISED),
    VulnEntry("CVE-2022-22965", "Spring4Shell",
              "spring", (("<", "5.3.18"),), 9.8, ExploitMaturity.FUNCTIONAL),
)


@dataclass
class CorrelationConfig:
    min_confidence: float = 0.45
    """Below this, the fingerprint is treated as too weak to generate leads."""
    include_unversioned: bool = False
    """Emit low-priority leads for product-only matches. Off by default --
    this is the single biggest source of ledger noise."""
    max_leads_per_service: int = 12
    backport_penalty: float = 0.25
    """Multiplier for a lead built on a distribution-packaged version string.

    Backporting applies a fix without changing the version number, so for
    RHEL/Debian/Ubuntu builds a version range cannot answer whether the host
    is patched. The caveat text already said so; prose an analyst skims is
    not a control, and the ranking has to carry the doubt.

    Discounted rather than suppressed: the lead may still be real, and
    hiding it would trade false positives for false negatives silently.
    """
    contradiction_penalty: float = 0.5
    """Multiplier applied to leads built on a fingerprint that a credible
    peer contradicts.

    Detection alone was passive: the planner surfaced the conflict while
    correlation went on ranking both sides at full priority, so the top of
    the ledger still looked confident. At most one of two contradictory
    versions is right, so at least half of what is ranked on them is wrong.
    """


@dataclass
class LedgerRow:
    target: str
    port: int
    protocol: str
    service: str
    product: Optional[str]
    version: Optional[str]
    cve_id: str
    title: str
    cvss: float
    maturity: str
    fingerprint_confidence: float
    corroborated_by: list[str] = field(default_factory=list)
    availability: list[str] = field(default_factory=list)
    """Public tooling identifiers indexed for this CVE, if a catalogue was
    supplied. Names from the operator's own install, never guessed."""
    maturity_source: str = "declared"
    """'declared' (hand-written in the reference) or 'index' (inferred from
    observed public availability). Which one it was changes how much weight
    the number deserves."""
    independent_principals: list[str] = field(default_factory=list)
    """Distinct authenticated submitters. One principal = one opinion,
    however many tool labels it used."""
    priority: float = 0.0
    rationale: str = ""
    disputed: bool = False
    """A credible peer contradicts the fingerprint this lead rests on."""
    match_method: str = "product_version"
    """How the CVE was attached: cpe_exact | cpe_range | product_version |
    product_only. An identifier lookup and a substring guess are different
    kinds of claim and the row has to say which it is."""
    backport_marker: Optional[str] = None
    """Distribution marker found in the version string, if any."""

    def as_dict(self) -> dict:
        return {
            "target": self.target, "port": self.port,
            "protocol": self.protocol, "service": self.service,
            "product": self.product, "version": self.version,
            "cve_id": self.cve_id, "title": self.title, "cvss": self.cvss,
            "maturity": self.maturity,
            "fingerprint_confidence": self.fingerprint_confidence,
            "corroborated_by": self.corroborated_by,
            "availability": self.availability,
            "maturity_source": self.maturity_source,
            "independent_principals": self.independent_principals,
            "priority": self.priority, "rationale": self.rationale,
            "disputed": self.disputed,
            "match_method": self.match_method,
            "backport_marker": self.backport_marker,
        }


def _corroboration_bonus(fp: Fingerprint) -> float:
    """1.0 for a single source, rising to 1.25 with independent agreement.

    Counts distinct *principals*, not tool labels. One submitter rotating
    tool names is one opinion (RC-01b).
    """
    n = len({p for p in fp.corroborating_principals if p != "system"})
    return min(1.0 + 0.125 * (n - 1), 1.25) if n else 1.0


def score(entry: VulnEntry, fp: Fingerprint,
          maturity: Optional[ExploitMaturity] = None,
          method_weight: float = 1.0) -> float:
    """Priority in [0, 1]. Clamped -- the corroboration bonus can push a
    weaponised max-CVSS match past 1.0 otherwise, and callers (including the
    ledger filter) treat this as a normalised score.

    `maturity` overrides the entry's declared value when an availability
    catalogue has inferred a stronger one.
    """
    base = (entry.cvss / 10.0) * (maturity or entry.maturity).weight
    penalty = 0.35 if not fp.version else 1.0
    raw = (base * fp.confidence * _corroboration_bonus(fp) * penalty
           * method_weight)
    return round(min(raw, 1.0), 4)


def build_leads(fp: Fingerprint, reference: Iterable[VulnEntry],
                cfg: CorrelationConfig, catalog=None,
                contradicted: bool = False, signals=None) -> list[VulnLead]:
    """Turn one fingerprint into ranked leads. Returns [] if too weak.

    `catalog` is an optional `ExploitCatalog`. When present, each entry's
    hand-declared maturity is upgraded by what public tooling is actually
    indexed on this machine -- never downgraded, because a missing index
    entry is not evidence of absence.
    """
    if fp.confidence < cfg.min_confidence:
        log.info("skipping %s: confidence %.2f below threshold %.2f",
                 fp.key, fp.confidence, cfg.min_confidence)
        return []

    from .cpe import MatchMethod, looks_backported

    backport_marker = looks_backported(fp.version, fp.raw_banner)
    leads: list[VulnLead] = []
    for entry in reference:
        if not fp.version and not cfg.include_unversioned:
            continue
        ok, rationale, method = entry.matches(fp)
        if not ok:
            continue
        method = method or MatchMethod.PRODUCT_VERSION
        maturity = entry.maturity
        if catalog is not None:
            maturity = catalog.infer_maturity(entry.cve_id, entry.maturity)
        priority = score(entry, fp, maturity, method.weight)
        exploitation = ""
        if signals is not None:
            # Applied before the clamp so exploitation can actually reorder:
            # a mid-severity CVE under attack has to be able to pass a
            # maximum-severity one nobody is touching.
            priority = round(min(priority * signals.factor(entry.cve_id),
                                 1.0), 4)
            exploitation = signals.explain(entry.cve_id)
        if backport_marker:
            priority = round(priority * cfg.backport_penalty, 4)
        if contradicted:
            priority = round(priority * cfg.contradiction_penalty, 4)
        leads.append(VulnLead(
            cve_id=entry.cve_id, title=entry.title, cvss=entry.cvss,
            exploit_maturity=maturity, matched_fingerprint_id=fp.id,
            rationale=(rationale
                       + (f" | {entry.notes}" if entry.notes else "")
                       + (" | DISPUTED: a credible peer claims a different "
                          "version for this service" if contradicted else "")
                       + (f" | BACKPORT RISK: '{backport_marker}' indicates a "
                          "distribution build; the fix may be applied without "
                          "a version bump" if backport_marker else "")
                       + (f" | {exploitation}" if exploitation else "")
                       + f" | matched by {method.value}"),
            priority=priority,
            provenance=Provenance(source_tool="correlator",
                                  confidence=fp.confidence),
        ))
    leads.sort(key=lambda l: l.priority, reverse=True)
    return leads[: cfg.max_leads_per_service]
