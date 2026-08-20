"""Exploit-availability catalogue: Exploit-DB and Metasploit *indexes*.

What this does: reads the metadata indexes that ship with searchsploit and
Metasploit, and answers one question per lead -- **does public tooling exist
for this CVE, and what is it called?** That answer is a real ranking input.
"A working module exists" and "someone wrote a theoretical advisory" are very
different leads, and until now `ExploitMaturity` was hand-declared in
`vulnref.py`, which does not scale past nine entries.

What this does not do: import exploit code, register exploit entries as
runnable modules, or drive msfrpcd. The catalogue holds *identifiers and
titles from an index file* -- `EDB-50383`, `exploit/multi/http/foo`, a date,
a rank. Nothing here is executable and nothing in reconkg executes it. An
entry ends up in `handoff` output as a name you can look up yourself.

This also fixes the fabrication problem flagged when hand-off was built.
Earlier I refused to print Metasploit module paths because guessing one that
half-matches a CVE is worse than printing nothing. Reading the real index
removes the guess: if `msf_modules_for("CVE-2021-41773")` returns a name, that
name exists on your machine, because it came out of your own install.

Both loaders are deliberately tolerant. These files are not stable public
APIs -- columns get added, the JSON shape shifts between releases. A parser
that hard-fails on an unexpected key would break on a `searchsploit -u`. Rows
that cannot be understood are counted in `skipped` and dropped.
"""

from __future__ import annotations

import csv
import hashlib
import shlex
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .models import ExploitMaturity

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE[-_ ]?(\d{4})[-_ ]?(\d{4,7})", re.I)

MAX_FIELD_BYTES = 64 * 1024
MAX_TITLE = 500
"""RC-09: csv's default field limit surfaced as a raw _csv.Error that
escaped as a crash. Bound it deliberately and fail with a message that names
the file."""

DEFAULT_EDB_PATHS = (
    "/usr/share/exploitdb/files_exploits.csv",
    "/opt/exploitdb/files_exploits.csv",
    "~/.local/share/exploitdb/files_exploits.csv",
)
DEFAULT_MSF_PATHS = (
    "~/.msf4/store/modules_metadata_base.json",
    "/usr/share/metasploit-framework/db/modules_metadata_base.json",
    "/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json",
)


def normalise_cve(raw: str) -> Optional[str]:
    """'cve 2021 41773', 'CVE-2021-41773', '2021-41773' -> 'CVE-2021-41773'."""
    if not raw:
        return None
    match = CVE_RE.search(raw)
    if match:
        return f"CVE-{match.group(1)}-{match.group(2)}"
    bare = re.fullmatch(r"\s*(\d{4})-(\d{4,7})\s*", raw)
    return f"CVE-{bare.group(1)}-{bare.group(2)}" if bare else None


def _parse_date(raw: str) -> Optional[date]:
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw.strip()[:19], fmt).date()
        except (ValueError, AttributeError):
            continue
    return None


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ExploitRecord:
    """One entry from an availability index. An identifier, not an artefact."""

    source: str                  # "exploit-db" | "metasploit"
    identifier: str              # "EDB-50383" | "exploit/multi/http/foo"
    title: str
    cves: tuple[str, ...] = ()
    published: Optional[date] = None
    platform: str = ""
    kind: str = ""               # msf module type / edb "type" column
    verified: bool = False       # EDB "verified" flag
    rank: str = ""               # msf rank string, if present
    path: str = ""               # index-relative path, for your own lookup
    port: Optional[int] = None   # EDB "port" column, where the row states one
    author: str = ""             # EDB "author" column
    """The last two exist because `exploitdb.py` stores them and returns this
    same record type. Adding fields here rather than declaring a second,
    near-identical record class: two shapes would mean a conversion at every
    boundary and two places to forget the `verified` flag."""

    def url(self) -> str:
        if self.source == "exploit-db":
            return f"https://www.exploit-db.com/exploits/{self.identifier.removeprefix('EDB-')}"
        return f"https://www.rapid7.com/db/modules/{self.identifier}"

    def lookup_command(self) -> str:
        """How *you* would pull this up. reconkg does not run it.

        RC-33: the identifier is index data, and this used to interpolate it
        into a hand-written single-quoted shell string. An identifier
        containing a quote closed it, and everything after was a command the
        operator's shell would run on paste. Quoting is `shlex`'s job here as
        it is in `Command.rendered`; nothing composes shell syntax by hand.
        """
        if self.source == "exploit-db":
            return ("searchsploit -x "
                    f"{shlex.quote(self.identifier.removeprefix('EDB-'))}")
        return f"msfconsole -q -x {shlex.quote(f'info {self.identifier}; exit')}"

    def msf_oneliner(self, rhost: str, rport: Optional[int] = None,
                     extra: Optional[dict] = None) -> Optional[str]:
        """A copy-pasteable msfconsole line, pre-filled for this target.

        Ends at `show options`, not `run`. That boundary is deliberate and it
        is the same one the rest of reconkg holds: the tool assembles the
        context, a human makes the decision. Composing `; run` for every lead
        automatically would make this an auto-exploitation chain whose only
        remaining step is a paste, and the per-lead decision is exactly the
        part worth keeping human -- it is where you notice the version came
        from one unverified banner, or that the host is out of scope.

        You land in the module fully configured. Typing `run` is your call.

        Returns None for non-Metasploit records; the module name always comes
        from the local index, never from a guess.

        RC-33: this is the *second* place an msfconsole line gets composed.
        `commands.metasploit_commands` grew the firing-verb refusal and the
        module-path check; this one did not, and it takes the same
        attacker-influenced identifier. Rather than reimplement either check,
        it calls both -- the standing lesson of RC-04/RC-07 and RC-14/RC-16 is
        that a control with two implementations has one implementation and one
        bypass. Returns None on refusal, the same answer this already gives
        for a record it cannot compose.
        """
        from .commands import (BoundaryViolation, _refuse_firing_verbs,
                               validate_module_path)

        if self.source != "metasploit" or not self.identifier:
            return None
        try:
            module = validate_module_path(self.identifier)
        except BoundaryViolation as exc:
            log.warning("refusing to compose a line for %r: %s",
                        self.identifier, exc)
            return None
        parts = [f"use {module}", f"set RHOSTS {rhost}"]
        if rport:
            parts.append(f"set RPORT {rport}")
        for key, value in (extra or {}).items():
            parts.append(f"set {key} {value}")
        parts.append("show options")
        try:
            _refuse_firing_verbs(parts, module)
        except BoundaryViolation as exc:
            log.warning("refusing to compose a line for %r: %s",
                        self.identifier, exc)
            return None
        body = "; ".join(parts)
        return f"msfconsole -q -x {shlex.quote(body)}"


STALE_AFTER_DAYS = 90
"""An index this old is a lie by omission: it will report 'nothing known'
for anything disclosed since, and the caller cannot tell that apart from a
genuinely unexploited CVE."""


@dataclass(frozen=True)
class IndexProvenance:
    """Identity of a loaded index file.

    RC-11: `infer_maturity` trusts these files exactly as they sit on disk,
    and anyone who can write them controls lead ranking. We cannot stop that
    -- they are the operator's own files -- but we can make a change *visible*
    rather than silent, which is the difference between a compromise and an
    undetected one.
    """

    label: str
    path: str
    sha256: str
    size: int
    modified: datetime
    loaded_at: datetime
    entries: int

    @property
    def age_days(self) -> int:
        return (datetime.now(timezone.utc) - self.modified).days

    @property
    def stale(self) -> bool:
        return self.age_days > STALE_AFTER_DAYS

    def as_dict(self) -> dict:
        return {"label": self.label, "path": self.path,
                "sha256": self.sha256, "size": self.size,
                "modified": self.modified.isoformat(),
                "loaded_at": self.loaded_at.isoformat(),
                "entries": self.entries, "age_days": self.age_days,
                "stale": self.stale}


def digest_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


class IndexChanged(RuntimeError):
    """A pinned index no longer matches its recorded digest."""


@dataclass
class CatalogStats:
    rows: int = 0
    loaded: int = 0
    skipped: int = 0
    with_cve: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"rows": self.rows, "loaded": self.loaded,
                "skipped": self.skipped, "with_cve": self.with_cve,
                "errors": self.errors[:20]}


# --------------------------------------------------------------------------- #
# Row parsing, shared
# --------------------------------------------------------------------------- #

def parse_edb_row(row: dict) -> Optional[ExploitRecord]:
    """One `files_exploits.csv` row -> a record, or None if it is not one.

    Module-level rather than a method because there are now two consumers:
    the in-memory catalogue below, and the SQLite corpus in `exploitdb.py`.
    Columns are read by header name, never by position -- Exploit-DB has
    added columns several times and positional parsing corrupts silently on
    the next update. A second copy of this mapping in the other module would
    be the same bug with an extra step: two parsers agreeing today and
    disagreeing after one upstream column is inserted.
    """
    edb_id = (row.get("id") or "").strip()
    if not edb_id.isdigit():
        return None
    codes = (row.get("codes") or "").replace(",", ";")
    cves = tuple(sorted({c for c in
                         (normalise_cve(part) for part in codes.split(";"))
                         if c}))
    verified = (row.get("verified") or "").strip() in {"1", "true", "True"}
    port = (row.get("port") or "").strip()
    return ExploitRecord(
        source="exploit-db", identifier=f"EDB-{edb_id}",
        title=(row.get("description") or "").strip()[:MAX_TITLE],
        cves=cves,
        published=_parse_date(row.get("date_published")
                              or row.get("date") or ""),
        platform=(row.get("platform") or "").strip(),
        kind=(row.get("type") or "").strip(),
        verified=verified,
        path=(row.get("file") or "").strip(),
        port=int(port) if port.isdigit() and int(port) <= 65535 else None,
        author=(row.get("author") or "").strip()[:MAX_TITLE],
    )


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #

class ExploitCatalog:
    """CVE -> known public tooling. Index data only."""

    def __init__(self) -> None:
        self._by_cve: dict[str, list[ExploitRecord]] = {}
        self._records: list[ExploitRecord] = []
        self.stats: dict[str, CatalogStats] = {}
        self.integrity: dict[str, IndexProvenance] = {}

    def __len__(self) -> int:
        return len(self._records)

    @property
    def cve_count(self) -> int:
        return len(self._by_cve)

    def add(self, record: ExploitRecord) -> None:
        self._records.append(record)
        for cve in record.cves:
            self._by_cve.setdefault(cve, []).append(record)

    def records_for(self, cve: str) -> list[ExploitRecord]:
        key = normalise_cve(cve) or cve.upper()
        return list(self._by_cve.get(key, ()))

    def edb_for(self, cve: str) -> list[ExploitRecord]:
        return [r for r in self.records_for(cve) if r.source == "exploit-db"]

    def msf_modules_for(self, cve: str) -> list[str]:
        """Verified module names for a CVE, from the local install's index.

        Empty is a meaningful answer: it means your Metasploit does not index
        a module for this CVE, not that none exists anywhere.
        """
        return [r.identifier for r in self.records_for(cve)
                if r.source == "metasploit"]

    def search(self, text: str, limit: int = 50) -> list[ExploitRecord]:
        needle = text.lower().strip()
        if not needle:
            return []
        hits = [r for r in self._records
                if needle in r.title.lower() or needle in r.identifier.lower()]
        return hits[:limit]

    # -- maturity inference -------------------------------------------------- #

    def infer_maturity(self, cve: str,
                       declared: ExploitMaturity = ExploitMaturity.NOT_DEFINED
                       ) -> ExploitMaturity:
        """Upgrade a maturity estimate from observed public availability.

        Rules, in order of strength:
          a Metasploit module indexed        -> WEAPONISED
          a *verified* Exploit-DB entry      -> FUNCTIONAL
          an unverified Exploit-DB entry     -> PROOF_OF_CONCEPT
          nothing indexed                    -> leave the declared value alone

        Never downgrades. An operator who hand-declared WEAPONISED knows
        something the index does not, and a missing index entry is not
        evidence of absence.
        """
        records = self.records_for(cve)
        if not records:
            return declared

        inferred = ExploitMaturity.NOT_DEFINED
        if any(r.source == "metasploit" for r in records):
            inferred = ExploitMaturity.WEAPONISED
        elif any(r.source == "exploit-db" and r.verified for r in records):
            inferred = ExploitMaturity.FUNCTIONAL
        elif any(r.source == "exploit-db" for r in records):
            inferred = ExploitMaturity.PROOF_OF_CONCEPT

        return inferred if inferred.weight > declared.weight else declared

    # -- loaders ------------------------------------------------------------- #

    def load_exploitdb(self, path: str | Path) -> CatalogStats:
        """Parse `files_exploits.csv` from a searchsploit checkout.

        Columns are read by header name. Exploit-DB has added columns several
        times; positional parsing silently corrupts on the next update.
        """
        stats = CatalogStats()
        file = Path(path).expanduser()
        if not file.is_file():
            raise FileNotFoundError(f"exploit-db index not found: {file}")

        previous_limit = csv.field_size_limit(MAX_FIELD_BYTES)
        try:
            self._read_edb(file, stats)
        finally:
            csv.field_size_limit(previous_limit)

        self.stats["exploit-db"] = stats
        self._record_integrity("exploit-db", file, stats.loaded)
        log.info("exploit-db: %d/%d rows, %d carrying a CVE",
                 stats.loaded, stats.rows, stats.with_cve)
        return stats

    def _read_edb(self, file: Path, stats: CatalogStats) -> None:
        with file.open(newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames or "id" not in reader.fieldnames:
                raise ValueError(
                    f"{file} does not look like files_exploits.csv "
                    f"(header: {reader.fieldnames})")
            while True:
                try:
                    row = next(reader)
                except StopIteration:
                    break
                except csv.Error as exc:
                    raise ValueError(
                        f"{file}: malformed CSV (field over "
                        f"{MAX_FIELD_BYTES} bytes?): {exc}") from None
                stats.rows += 1
                try:
                    record = self._edb_row(row)
                except Exception as exc:
                    stats.skipped += 1
                    if len(stats.errors) < 20:
                        stats.errors.append(f"row {stats.rows}: {exc}")
                    continue
                if record is None:
                    stats.skipped += 1
                    continue
                self.add(record)
                stats.loaded += 1
                if record.cves:
                    stats.with_cve += 1

    @staticmethod
    def _edb_row(row: dict) -> Optional[ExploitRecord]:
        return parse_edb_row(row)

    def load_metasploit(self, path: str | Path) -> CatalogStats:
        """Parse Metasploit's module metadata cache (index only).

        Tolerant of both reference shapes seen in the wild -- a list of
        ``["CVE", "2021-41773"]`` pairs and a flat list of ``"CVE-2021-41773"``
        strings -- because this file is an internal cache, not a contract.
        """
        stats = CatalogStats()
        file = Path(path).expanduser()
        if not file.is_file():
            raise FileNotFoundError(f"metasploit index not found: {file}")

        try:
            with file.open(encoding="utf-8", errors="replace") as fh:
                blob = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{file} is not valid JSON: {exc}") from None

        entries: Iterable = blob.values() if isinstance(blob, dict) else blob
        for entry in entries:
            stats.rows += 1
            if not isinstance(entry, dict):
                stats.skipped += 1
                continue
            try:
                record = self._msf_entry(entry)
            except Exception as exc:
                stats.skipped += 1
                if len(stats.errors) < 20:
                    stats.errors.append(f"entry {stats.rows}: {exc}")
                continue
            if record is None:
                stats.skipped += 1
                continue
            self.add(record)
            stats.loaded += 1
            if record.cves:
                stats.with_cve += 1

        self.stats["metasploit"] = stats
        self._record_integrity("metasploit", file, stats.loaded)
        log.info("metasploit: %d/%d entries, %d carrying a CVE",
                 stats.loaded, stats.rows, stats.with_cve)
        return stats

    @staticmethod
    def _msf_entry(entry: dict) -> Optional[ExploitRecord]:
        fullname = (entry.get("fullname") or entry.get("full_name")
                    or entry.get("ref_name") or "").strip()
        if not fullname:
            return None
        cves = tuple(sorted(_msf_cves(entry.get("references") or [])))
        rank = entry.get("rank")
        return ExploitRecord(
            source="metasploit", identifier=fullname,
            title=(entry.get("name") or fullname).strip()[:MAX_TITLE],
            cves=cves,
            published=_parse_date(entry.get("disclosure_date") or ""),
            platform=_flatten(entry.get("platform")),
            kind=(entry.get("type") or "").strip(),
            rank=str(rank) if rank is not None else "",
            path=(entry.get("path") or "").strip(),
        )

    # -- integrity ----------------------------------------------------------- #

    def _record_integrity(self, label: str, file: Path, entries: int) -> None:
        stat = file.stat()
        prov = IndexProvenance(
            label=label, path=str(file), sha256=digest_file(file),
            size=stat.st_size,
            modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
            loaded_at=datetime.now(timezone.utc), entries=entries)
        self.integrity[label] = prov
        if prov.stale:
            log.warning("%s index is %d days old (%s); anything disclosed "
                        "since will read as 'nothing known'",
                        label, prov.age_days, file)

    def stale_indexes(self) -> list[str]:
        return [label for label, p in self.integrity.items() if p.stale]

    def write_lockfile(self, path: str | Path) -> dict:
        """Pin the digests of the currently loaded indexes."""
        lock = {label: {"sha256": p.sha256, "size": p.size, "path": p.path}
                for label, p in self.integrity.items()}
        Path(path).expanduser().write_text(json.dumps(lock, indent=2))
        return lock

    def verify_lockfile(self, path: str | Path, *,
                        strict: bool = True) -> list[str]:
        """Compare loaded indexes against a pin file.

        Returns the list of complaints. With `strict`, a mismatch raises --
        a silently swapped index means every maturity judgement downstream is
        attacker-chosen, and that should stop a run rather than colour a log
        line nobody reads.
        """
        file = Path(path).expanduser()
        if not file.is_file():
            raise FileNotFoundError(f"no lockfile: {file}")
        try:
            lock = json.loads(file.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(f"{file} is not valid JSON: {exc}") from None

        complaints: list[str] = []
        for label, pinned in lock.items():
            current = self.integrity.get(label)
            if current is None:
                complaints.append(f"{label}: pinned but not loaded")
                continue
            if current.sha256 != pinned.get("sha256"):
                complaints.append(
                    f"{label}: digest changed (pinned "
                    f"{str(pinned.get('sha256'))[:12]}..., loaded "
                    f"{current.sha256[:12]}...) at {current.path}")
        for label in self.integrity:
            if label not in lock:
                complaints.append(f"{label}: loaded but not pinned")

        if complaints and strict:
            raise IndexChanged("; ".join(complaints))
        for complaint in complaints:
            log.warning("index integrity: %s", complaint)
        return complaints

    # -- convenience --------------------------------------------------------- #

    def autoload(self, edb_paths: Iterable[str] = DEFAULT_EDB_PATHS,
                 msf_paths: Iterable[str] = DEFAULT_MSF_PATHS) -> dict:
        """Load whichever indexes are present. Missing tooling is not an error.

        Returns a report rather than raising: a coordinator that refuses to
        start because searchsploit is not installed would be obnoxious.
        """
        report: dict[str, str] = {}
        for label, paths, loader in (
                ("exploit-db", edb_paths, self.load_exploitdb),
                ("metasploit", msf_paths, self.load_metasploit)):
            for candidate in paths:
                file = Path(candidate).expanduser()
                if not file.is_file():
                    continue
                try:
                    stats = loader(file)
                    report[label] = (f"loaded {stats.loaded} from {file}")
                except Exception as exc:
                    report[label] = f"failed on {file}: {exc}"
                break
            else:
                report[label] = "not installed"
        return report


def _msf_cves(references) -> set[str]:
    out: set[str] = set()
    for ref in references or []:
        if isinstance(ref, str):
            cve = normalise_cve(ref)
        elif isinstance(ref, (list, tuple)) and len(ref) >= 2:
            cve = normalise_cve(f"{ref[0]}-{ref[1]}")
        elif isinstance(ref, dict):
            cve = normalise_cve(str(ref.get("value") or ref.get("ref") or ""))
        else:
            cve = None
        if cve:
            out.add(cve)
    return out


def _flatten(value) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value or "").strip()
