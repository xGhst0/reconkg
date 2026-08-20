"""Vulnerability feed ingestion: NVD, CISA KEV, FIRST EPSS.

Items 3 and 5 of `docs/CVE-IDENTIFICATION.md`. Three feeds, three jobs:

    NVD      what is vulnerable      applicability statements -> VulnEntry
    KEV      what is being used      binary, authoritative, dominates order
    EPSS     what is likely to be    daily probability, 30-day horizon

**All parsing is offline.** Each publisher offers a downloadable file; the
operator fetches it, reconkg reads it. That keeps the rule the whole system
is built on -- no outbound connections to anything -- and it means a lab with
no internet still gets a real corpus from a USB stick.

The prioritisation change this enables is the one the research was blunt
about: CVSS measures severity, not risk, and a base score cannot tell you
whether anything is exploiting the thing. A CVSS 7.5 in KEV is more urgent
than a CVSS 9.8 nobody has ever attacked. `exploitation_factor` encodes that
ordering, and the nine hand-written entries stop being the whole database.

Parsers are deliberately tolerant, for the same reason `catalog.py` is: these
are large published artefacts whose shapes shift between releases, and a
loader that hard-fails on one unexpected key is a loader that breaks the day
a feed is refreshed. Unreadable records are counted and skipped.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .catalog import normalise_cve
from .cpe import CPE, CPERange, parse as parse_cpe
from .models import ExploitMaturity
from .vulnref import VulnEntry

log = logging.getLogger(__name__)

MAX_CPE_RANGES_PER_CVE = 256
"""A single CVE can carry thousands of applicability statements. Beyond a
couple of hundred the extra rows change no outcome -- the first match wins --
but they do multiply memory across a whole feed."""

# CVSS metric keys in descending preference. v4.0 first where present, then
# v3.1, v3.0, and v2 last: an older scale is better than no score, but it
# should never displace a newer one.
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
              "cvssMetricV2")


@dataclass
class FeedStats:
    records: int = 0
    loaded: int = 0
    skipped: int = 0
    with_cpe: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"records": self.records, "loaded": self.loaded,
                "skipped": self.skipped, "with_cpe": self.with_cpe,
                "errors": self.errors[:20]}

    def note(self, message: str) -> None:
        self.skipped += 1
        if len(self.errors) < 20:
            self.errors.append(message)


# --------------------------------------------------------------------------- #
# NVD
# --------------------------------------------------------------------------- #

def load_nvd(path: str | Path,
             stats: Optional[FeedStats] = None) -> list[VulnEntry]:
    """Parse an NVD JSON 2.0 feed into `VulnEntry` objects.

    Handles both the API envelope (`{"vulnerabilities": [{"cve": {...}}]}`)
    and a bare list of CVE objects, because both circulate.

    Entries arrive with `cpe_ranges` populated, so matching goes through the
    identifier path rather than the substring fallback. `product_match` is
    filled from the first CPE product as a last resort for fingerprints that
    carry no CPE at all.
    """
    stats = stats if stats is not None else FeedStats()
    file = Path(path).expanduser()
    if not file.is_file():
        raise FileNotFoundError(f"NVD feed not found: {file}")

    try:
        with file.open(encoding="utf-8", errors="replace") as handle:
            blob = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{file} is not valid JSON: {exc}") from None

    entries: list[VulnEntry] = []
    for record in _iter_cve_records(blob):
        stats.records += 1
        try:
            entry = _nvd_entry(record)
        except Exception as exc:
            stats.note(f"record {stats.records}: {type(exc).__name__}: {exc}")
            continue
        if entry is None:
            stats.note(f"record {stats.records}: no usable CVE id")
            continue
        entries.append(entry)
        stats.loaded += 1
        if entry.cpe_ranges:
            stats.with_cpe += 1

    log.info("NVD: %d/%d records, %d with applicability statements",
             stats.loaded, stats.records, stats.with_cpe)
    return entries


def _iter_cve_records(blob) -> Iterator[dict]:
    if isinstance(blob, dict) and "vulnerabilities" in blob:
        for wrapper in blob["vulnerabilities"] or []:
            if isinstance(wrapper, dict):
                yield wrapper.get("cve", wrapper)
    elif isinstance(blob, dict) and "CVE_Items" in blob:      # legacy 1.1
        for wrapper in blob["CVE_Items"] or []:
            if isinstance(wrapper, dict):
                yield wrapper
    elif isinstance(blob, list):
        for item in blob:
            if isinstance(item, dict):
                yield item.get("cve", item)


def _nvd_entry(record: dict) -> Optional[VulnEntry]:
    cve_id = normalise_cve(str(record.get("id") or ""))
    if not cve_id:
        return None

    title = _english_description(record) or cve_id
    cvss = _best_cvss(record.get("metrics") or {})
    ranges = tuple(_cpe_ranges(record.get("configurations") or [])
                   )[:MAX_CPE_RANGES_PER_CVE]

    # A product name for the substring fallback, taken from the first
    # applicability statement so the two paths agree about what this is.
    product_match = ""
    for statement in ranges:
        if statement.cpe.product not in ("*", "-", ""):
            product_match = statement.cpe.product.replace("_", " ")
            break

    return VulnEntry(
        cve_id=cve_id,
        title=title[:300],
        product_match=product_match,
        constraints=(),
        cvss=cvss,
        maturity=ExploitMaturity.NOT_DEFINED,
        requires_version=False,
        cpe_ranges=ranges,
        notes=_cve_note(record),
    )


def _english_description(record: dict) -> str:
    for item in record.get("descriptions") or []:
        if isinstance(item, dict) and item.get("lang", "en") == "en":
            return str(item.get("value") or "").strip()
    return ""


def _best_cvss(metrics: dict) -> float:
    """Highest-preference CVSS base score available, or 0.0.

    Returning 0.0 rather than guessing: an absent score is a fact, and a
    fabricated one would flow straight into ranking.
    """
    for key in _CVSS_KEYS:
        for metric in metrics.get(key) or []:
            data = (metric or {}).get("cvssData") or {}
            score = data.get("baseScore", metric.get("baseScore"))
            try:
                value = float(score)
            except (TypeError, ValueError):
                continue
            if 0.0 <= value <= 10.0:
                return value
    return 0.0


def _cve_note(record: dict) -> str:
    status = str(record.get("vulnStatus") or "").strip()
    if status.lower() in ("awaiting analysis", "received", "undergoing analysis"):
        return (f"NVD status: {status} -- applicability data may be "
                "incomplete or absent")
    return ""


def _cpe_ranges(configurations) -> Iterator[CPERange]:
    """Flatten NVD's configuration tree into applicability statements.

    The tree expresses AND/OR relationships between nodes -- "vulnerable only
    when running on this OS" and similar. Flattening loses that, which means
    a host matching one arm of an AND is treated as matching. Deliberate and
    stated: reconkg knows a service version, not the surrounding platform, so
    it cannot evaluate the other arm anyway, and dropping such CVEs entirely
    would hide more than the over-match costs. `MatchMethod` already tells an
    analyst the claim rests on inference.
    """
    for configuration in configurations or []:
        nodes = (configuration or {}).get("nodes") or []
        for node in nodes:
            if (node or {}).get("negate"):
                continue          # a negated node states non-applicability
            for match in (node or {}).get("cpeMatch") or []:
                statement = _cpe_match(match)
                if statement is not None:
                    yield statement


def _cpe_match(match: dict) -> Optional[CPERange]:
    criteria = (match or {}).get("criteria") or (match or {}).get("cpe23Uri")
    parsed = parse_cpe(criteria)
    if parsed is None:
        return None
    return CPERange(
        cpe=parsed,
        version_start_including=match.get("versionStartIncluding"),
        version_start_excluding=match.get("versionStartExcluding"),
        version_end_including=match.get("versionEndIncluding"),
        version_end_excluding=match.get("versionEndExcluding"),
        vulnerable=bool(match.get("vulnerable", True)),
    )


# --------------------------------------------------------------------------- #
# CISA KEV
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor: str = ""
    product: str = ""
    name: str = ""
    date_added: Optional[date] = None
    ransomware: bool = False
    """CISA flags known use in ransomware campaigns. Worth surfacing: it
    changes who is likely on the other end, not merely whether."""


class KevCatalog:
    """Known Exploited Vulnerabilities. Membership is binary and decisive."""

    def __init__(self) -> None:
        self._entries: dict[str, KevEntry] = {}
        self.stats = FeedStats()
        self.catalog_version = ""
        self.released: Optional[datetime] = None

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, cve_id: str) -> bool:
        return (normalise_cve(cve_id) or cve_id.upper()) in self._entries

    def get(self, cve_id: str) -> Optional[KevEntry]:
        return self._entries.get(normalise_cve(cve_id) or cve_id.upper())

    def load(self, path: str | Path) -> FeedStats:
        file = Path(path).expanduser()
        if not file.is_file():
            raise FileNotFoundError(f"KEV catalog not found: {file}")
        try:
            with file.open(encoding="utf-8", errors="replace") as handle:
                blob = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{file} is not valid JSON: {exc}") from None

        self.catalog_version = str(blob.get("catalogVersion") or "")
        for record in blob.get("vulnerabilities") or []:
            self.stats.records += 1
            cve_id = normalise_cve(str((record or {}).get("cveID") or ""))
            if not cve_id:
                self.stats.note(f"record {self.stats.records}: no cveID")
                continue
            self._entries[cve_id] = KevEntry(
                cve_id=cve_id,
                vendor=str(record.get("vendorProject") or ""),
                product=str(record.get("product") or ""),
                name=str(record.get("vulnerabilityName") or "")[:300],
                date_added=_parse_date(record.get("dateAdded")),
                ransomware=str(
                    record.get("knownRansomwareCampaignUse") or ""
                ).strip().lower() == "known",
            )
            self.stats.loaded += 1
        log.info("KEV: %d entries (catalog %s)", len(self), self.catalog_version)
        return self.stats


def _parse_date(raw) -> Optional[date]:
    try:
        return datetime.strptime(str(raw).strip()[:10], "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# FIRST EPSS
# --------------------------------------------------------------------------- #

class EpssScores:
    """Daily probability that a CVE will be exploited in the next 30 days."""

    def __init__(self) -> None:
        self._scores: dict[str, tuple[float, float]] = {}
        self.stats = FeedStats()
        self.model_version = ""
        self.score_date = ""

    def __len__(self) -> int:
        return len(self._scores)

    def probability(self, cve_id: str) -> Optional[float]:
        entry = self._scores.get(normalise_cve(cve_id) or cve_id.upper())
        return entry[0] if entry else None

    def percentile(self, cve_id: str) -> Optional[float]:
        entry = self._scores.get(normalise_cve(cve_id) or cve_id.upper())
        return entry[1] if entry else None

    def load(self, path: str | Path) -> FeedStats:
        """Parse the published CSV.

        The file opens with a `#model_version:...,score_date:...` comment
        line before the header, which `csv.DictReader` would otherwise take
        as the header and then mis-key every row.
        """
        file = Path(path).expanduser()
        if not file.is_file():
            raise FileNotFoundError(f"EPSS file not found: {file}")

        with file.open(newline="", encoding="utf-8", errors="replace") as fh:
            lines = []
            for line in fh:
                if line.startswith("#"):
                    self._read_metadata(line)
                    continue
                lines.append(line)

        reader = csv.DictReader(lines)
        if not reader.fieldnames or "cve" not in reader.fieldnames:
            raise ValueError(
                f"{file} does not look like an EPSS export "
                f"(header: {reader.fieldnames})")

        for row in reader:
            self.stats.records += 1
            cve_id = normalise_cve(str(row.get("cve") or ""))
            if not cve_id:
                self.stats.note(f"row {self.stats.records}: no cve column")
                continue
            try:
                probability = float(row.get("epss") or 0.0)
                percentile = float(row.get("percentile") or 0.0)
            except ValueError:
                self.stats.note(f"row {self.stats.records}: unparseable score")
                continue
            if not 0.0 <= probability <= 1.0:
                self.stats.note(f"{cve_id}: probability out of range")
                continue
            self._scores[cve_id] = (probability, percentile)
            self.stats.loaded += 1

        log.info("EPSS: %d scores (model %s, %s)", len(self),
                 self.model_version or "unknown", self.score_date or "undated")
        return self.stats

    def _read_metadata(self, line: str) -> None:
        for chunk in line.lstrip("#").split(","):
            key, _, value = chunk.partition(":")
            key, value = key.strip(), value.strip()
            if key == "model_version":
                self.model_version = value
            elif key == "score_date":
                self.score_date = value


# --------------------------------------------------------------------------- #
# Exploitation-aware ordering
# --------------------------------------------------------------------------- #

KEV_FACTOR = 1.6
"""KEV membership dominates. Chosen so a mid-severity CVE under active
exploitation outranks a maximum-severity one that nobody is touching -- the
operational rule the research states plainly. 7.5 * 1.6 beats 9.8 * 1.0."""

EPSS_MAX_FACTOR = 0.5
"""EPSS contributes up to +50%. Below KEV deliberately: a probability, however
good the model, is a prediction, and observed exploitation is an observation.
"""


@dataclass
class ExploitationSignals:
    """KEV and EPSS together, as the ranking layer above severity."""

    kev: Optional[KevCatalog] = None
    epss: Optional[EpssScores] = None

    def factor(self, cve_id: str) -> float:
        """Multiplier applied to a lead's severity-derived priority."""
        if self.kev is not None and cve_id in self.kev:
            return KEV_FACTOR
        if self.epss is not None:
            probability = self.epss.probability(cve_id)
            if probability is not None:
                return 1.0 + EPSS_MAX_FACTOR * probability
        return 1.0

    def explain(self, cve_id: str) -> str:
        """Why this lead ranks where it does. Empty when nothing is known."""
        if self.kev is not None:
            entry = self.kev.get(cve_id)
            if entry is not None:
                added = f" since {entry.date_added}" if entry.date_added else ""
                ransom = ", used in ransomware" if entry.ransomware else ""
                return f"KEV: actively exploited{added}{ransom}"
        if self.epss is not None:
            probability = self.epss.probability(cve_id)
            if probability is not None:
                percentile = self.epss.percentile(cve_id) or 0.0
                return (f"EPSS {probability:.1%} chance of exploitation in 30 "
                        f"days ({percentile:.0%} percentile)")
        return ""

    @property
    def loaded(self) -> bool:
        return bool(self.kev and len(self.kev)) or bool(self.epss and len(self.epss))
