"""CPE parsing and applicability matching.

Built from the design note in `docs/CVE-IDENTIFICATION.md`. Three findings
from that research shape this module:

1. **CPE name matching is a specified procedure, not string equality.**
   NIST IR 7696 defines comparison as set-relational -- names can be EQUAL,
   a SUBSET or SUPERSET of one another, or DISJOINT -- and gives `*` (ANY)
   and `-` (NA) distinct meanings. Collapsing ANY and NA into "wildcard" is
   a false-positive source: a vulnerability in a product with no edition
   should not match every edition ever shipped.

2. **NVD expresses applicability with four boundary fields.**
   `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`,
   `versionEndExcluding`. `CPERange` mirrors those names deliberately so a
   feed can be read without a translation layer that has to be undone.

3. **Version-range matching is lossy for distribution packages.**
   Backporting applies a fix without changing the version number, so a
   version string alone cannot answer whether a host is patched. That is
   not fixable here; it is signalled instead, via `MatchMethod` and the
   backport flag, so a lead built on a version range says so.

The immediate motivation: nmap emits `cpe:/a:openbsd:openssh:7.4` on most
fingerprints, the importer stored it, the engine carried it through the
graph, and nothing ever read it. The precise identifier was sitting unused
next to the string heuristic that replaced it.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .vulnref import compare_versions

log = logging.getLogger(__name__)

ANY = "*"
NA = "-"

_ATTRS = ("part", "vendor", "product", "version", "update", "edition",
          "language", "sw_edition", "target_sw", "target_hw", "other")


class MatchMethod(str, Enum):
    """How a CVE came to be attached to a fingerprint.

    Recorded on every lead because the methods are not equally trustworthy,
    and an analyst is entitled to know which one produced the row in front
    of them. A CPE match is an identifier lookup. A product-substring match
    is a string heuristic that happened to fire.
    """

    CPE_EXACT = "cpe_exact"
    """Part, vendor, product and an exact version all agreed."""
    CPE_RANGE = "cpe_range"
    """Part, vendor and product agreed; version fell inside a declared window."""
    PRODUCT_VERSION = "product_version"
    """No usable CPE. Product name matched as a substring, version in range."""
    PRODUCT_ONLY = "product_only"
    """Product matched with nothing constraining the version. Weakest signal."""

    @property
    def weight(self) -> float:
        """Multiplier on lead priority.

        A substring match is not worth what an identifier match is worth.
        Collapsing them into one number is how a ledger fills with plausible
        noise that an analyst learns to scroll past, which costs more than
        the missing leads would have.
        """
        return {"cpe_exact": 1.0, "cpe_range": 0.95,
                "product_version": 0.75, "product_only": 0.3}[self.value]

    @property
    def is_cpe(self) -> bool:
        return self in (MatchMethod.CPE_EXACT, MatchMethod.CPE_RANGE)


class Relation(str, Enum):
    """Set relation between two CPE attributes, per NIST IR 7696."""

    EQUAL = "equal"
    SUBSET = "subset"
    SUPERSET = "superset"
    DISJOINT = "disjoint"


@dataclass(frozen=True)
class CPE:
    """A parsed CPE. Attributes are lower-cased; ANY and NA are preserved."""

    part: str = ANY
    vendor: str = ANY
    product: str = ANY
    version: str = ANY
    update: str = ANY
    edition: str = ANY
    language: str = ANY
    sw_edition: str = ANY
    target_sw: str = ANY
    target_hw: str = ANY
    other: str = ANY

    @property
    def is_application(self) -> bool:
        return self.part == "a"

    @property
    def has_version(self) -> bool:
        return self.version not in (ANY, NA, "")

    def identity(self) -> tuple[str, str, str]:
        """The triple an applicability statement is indexed by."""
        return (self.part, self.vendor, self.product)

    def __str__(self) -> str:
        # PROP-01. `_unescape` removes the backslashes on the way in, so a
        # `__str__` that does not put them back is not a serialisation, it is
        # a lossy render -- and `vulndb` stores exactly this string in the
        # `criteria` column and re-parses it on every candidate lookup. A
        # version of `1\\:2` therefore came back as a CPE whose *vendor* was a
        # version fragment, with every later attribute shifted one position,
        # and nothing raised. Escaped here rather than by asking callers to
        # escape, because the parser unescapes unconditionally and the two
        # have to be inverses of each other or neither is.
        return "cpe:2.3:" + ":".join(_escape(getattr(self, a))
                                     for a in _ATTRS)


def _escape(value: str) -> str:
    """The inverse of `_unescape`, for the two characters that matter.

    A backslash first, or escaping the colon would then be re-escaped by the
    pass that handles backslashes and `a\\:b` would round-trip to `a\\\\:b`.
    """
    return value.replace("\\", "\\\\").replace(":", "\\:")


def _unescape(value: str) -> str:
    """CPE escapes literal punctuation: `2\\.4\\.49` means `2.4.49`."""
    return re.sub(r"\\(.)", r"\1", value)


def _split_escaped(text: str) -> list[str]:
    """Split on ':' but not on an escaped '\\:'.

    A version can legitimately contain an escaped colon, and a naive
    `text.split(":")` shears it in half and shifts every later attribute by
    one position -- which does not raise, it silently produces a CPE whose
    vendor is a version fragment.
    """
    out: list[str] = []
    current: list[str] = []
    escaped = False
    for char in text:
        if escaped:
            current.append("\\")
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            out.append("".join(current))
            current = []
        else:
            current.append(char)
    out.append("".join(current))
    return out


def parse(raw: Optional[str]) -> Optional[CPE]:
    """Parse a CPE 2.2 URI or a 2.3 formatted string. None if unparseable.

    Returning None rather than raising: a malformed CPE in a banner is a
    fact about the target, not a caller error, and it must not stop the rest
    of the fingerprint being used.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().lower()

    if text.startswith("cpe:2.3:"):
        parts = _split_escaped(text[len("cpe:2.3:"):])
    elif text.startswith("cpe:/"):
        parts = _split_escaped(text[len("cpe:/"):])
    else:
        return None

    if not parts or parts[0] not in ("a", "o", "h", ANY, NA):
        return None

    fields = {}
    for index, name in enumerate(_ATTRS):
        value = parts[index] if index < len(parts) else ANY
        fields[name] = _unescape(value) if value else ANY
    return CPE(**fields)


def compare_attribute(source: str, target: str) -> Relation:
    """Compare one attribute, honouring ANY and NA (NIST IR 7696).

    ANY is a superset of everything. NA means "does not apply" and relates
    only to itself -- treating NA as a wildcard is how a vulnerability
    scoped to a product with no edition matches every edition there is.
    """
    if source == target:
        return Relation.EQUAL
    if source == ANY:
        return Relation.SUPERSET
    if target == ANY:
        return Relation.SUBSET
    # Everything else is DISJOINT, NA included. An explicit NA branch here
    # was unreachable-by-outcome -- it returned exactly what the fallback
    # returns -- so mutating it changed nothing and no test could tell.
    # Deleted rather than exempted: dead logic that reads as a rule invites
    # the next person to trust it.
    return Relation.DISJOINT


def attribute_matches(criterion: str, candidate: str) -> bool:
    """Does an observed value fall within what a criterion allows?

    True for EQUAL and for a criterion that is a SUPERSET of the candidate.
    A candidate of ANY against a specific criterion is refused: an unknown
    edition is not evidence of a matching edition, and assuming otherwise
    is a guess in the direction that generates work.
    """
    relation = compare_attribute(criterion, candidate)
    # SUPERSET is only ever reached when the criterion is ANY, which matches
    # anything including NA -- so the extra condition that used to sit here
    # was always true. Kept as two named cases for readability.
    return relation in (Relation.EQUAL, Relation.SUPERSET)


@dataclass(frozen=True)
class CPERange:
    """An applicability statement: a CPE plus an optional version window.

    Field names mirror NVD's `cpeMatch` so a feed reader is a direct
    translation rather than an interpretation.
    """

    cpe: CPE
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    vulnerable: bool = True

    @property
    def has_window(self) -> bool:
        return any((self.version_start_including, self.version_start_excluding,
                    self.version_end_including, self.version_end_excluding))

    def matches(self, observed: CPE) -> tuple[bool, Optional[MatchMethod], str]:
        """Evaluate this statement against an observed CPE.

        Returns (matched, method, rationale). The rationale is not
        decoration: it is what an analyst reads to decide whether to believe
        the row, and a match with no stated reason is a match nobody can
        check.
        """
        if not self.vulnerable:
            return False, None, "statement marks this configuration not vulnerable"

        for attribute in ("part", "vendor", "product"):
            if not attribute_matches(getattr(self.cpe, attribute),
                                     getattr(observed, attribute)):
                return (False, None,
                        f"{attribute} differs: statement "
                        f"{getattr(self.cpe, attribute)!r} vs observed "
                        f"{getattr(observed, attribute)!r}")

        label = f"{observed.vendor}:{observed.product}"

        if self.cpe.has_version and not self.has_window:
            if not observed.has_version:
                return False, None, "no observed version to compare"
            if compare_versions(observed.version, self.cpe.version) == 0:
                return (True, MatchMethod.CPE_EXACT,
                        f"CPE {label} version {observed.version} matches exactly")
            return False, None, f"{observed.version} != {self.cpe.version}"

        if not self.has_window:
            # Vendor and product match, nothing constrains the version. Real
            # in NVD and dangerous: it applies to every version ever shipped.
            return (True, MatchMethod.PRODUCT_ONLY,
                    f"CPE {label} matches; statement constrains no version")

        if not observed.has_version:
            return False, None, "version window declared but no observed version"

        ok, why = self._within_window(observed.version)
        if not ok:
            return False, None, why
        return True, MatchMethod.CPE_RANGE, f"CPE {label} version {why}"

    def _within_window(self, version: str) -> tuple[bool, str]:
        bounds: list[str] = []
        if self.version_start_including is not None:
            if compare_versions(version, self.version_start_including) < 0:
                return False, f"{version} below {self.version_start_including}"
            bounds.append(f">= {self.version_start_including}")
        if self.version_start_excluding is not None:
            if compare_versions(version, self.version_start_excluding) <= 0:
                return False, f"{version} not above {self.version_start_excluding}"
            bounds.append(f"> {self.version_start_excluding}")
        if self.version_end_including is not None:
            if compare_versions(version, self.version_end_including) > 0:
                return False, f"{version} above {self.version_end_including}"
            bounds.append(f"<= {self.version_end_including}")
        if self.version_end_excluding is not None:
            if compare_versions(version, self.version_end_excluding) >= 0:
                return False, f"{version} not below {self.version_end_excluding}"
            bounds.append(f"< {self.version_end_excluding}")
        return True, f"{version} satisfies {' and '.join(bounds)}"


# --------------------------------------------------------------------------- #
# Backport detection
# --------------------------------------------------------------------------- #

_BACKPORT_MARKERS = re.compile(
    # The preceding character must not be a letter, so "channel7" does not
    # read as "el7" -- but a digit or a bracket is fine, because real builds
    # spell it "4ubuntu3.14" and "Apache/2.4.6 (CentOS) el7".
    r"(?:^|[^a-z])(?:"
    r"el\d|rhel|centos|fc\d{1,2}|"          # Red Hat family
    r"ubuntu|deb\d{1,2}|dfsg|"              # Debian / Ubuntu
    r"suse|sles|"                           # SUSE
    r"amzn|al\d{4})",                       # Amazon Linux
    re.I)


def looks_backported(version: Optional[str],
                     banner: Optional[str] = None) -> Optional[str]:
    """Does this version string come from a distribution-packaged build?

    Returns the marker found, or None.

    Why it matters, from the research: backporting applies a security fix to
    an older version *without changing the version number*, and it is the
    default patch model for Red Hat, Debian and Ubuntu. A package reporting
    3.0.7 may contain every fix through 3.3.x. Version-range matching cannot
    see that, so any lead against such a build is inference, not evidence.

    Detection is deliberately narrow. A false "backported" verdict suppresses
    a real finding, which is worse than the noise it saves, so this only
    fires on explicit distribution markers rather than guessing from shape.
    """
    for text in (version, banner):
        if not text:
            continue
        found = _BACKPORT_MARKERS.search(text)
        if found:
            return re.sub(r"^[^a-z]+", "", found.group(0), flags=re.I)
    return None


# --------------------------------------------------------------------------- #
# Inference for evidence with no CPE
# --------------------------------------------------------------------------- #

_KNOWN_PRODUCTS: tuple[tuple[str, str, str], ...] = (
    # Ordered longest-key-first: "apache tomcat" must be tested before any
    # shorter apache key, or Tomcat is filed as httpd.
    ("apache tomcat", "apache", "tomcat"),
    ("apache httpd", "apache", "http_server"),
    ("microsoft iis", "microsoft", "internet_information_services"),
    ("isc bind", "isc", "bind"),
    ("postgresql", "postgresql", "postgresql"),
    ("openssh", "openbsd", "openssh"),
    ("openssl", "openssl", "openssl"),
    ("proftpd", "proftpd", "proftpd"),
    ("postfix", "postfix", "postfix"),
    ("vsftpd", "beasts", "vsftpd"),
    ("samba", "samba", "samba"),
    ("nginx", "f5", "nginx"),
    ("mysql", "oracle", "mysql"),
)


def infer_cpe(product: Optional[str], version: Optional[str]) -> Optional[CPE]:
    """Best-effort CPE from a product string. None when unsure.

    Conservative on purpose. A guessed CPE that is wrong is worse than no
    CPE, because it promotes a weak substring match into something that
    looks like an identifier match and inherits its ranking weight. Only
    names actually seen coming out of nmap are in the table.
    """
    if not product:
        return None
    name = product.strip().lower()
    for pattern, vendor, prod in _KNOWN_PRODUCTS:
        if pattern in name:
            return CPE(part="a", vendor=vendor, product=prod,
                       version=(version or ANY).lower())
    return None
