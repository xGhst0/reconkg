"""Module system: declared metadata, typed options, discovery and search.

Modelled on Metasploit's module contract, with one deliberate difference.
In msf, `rank` is a claim about how reliably an exploit lands. Nothing here
lands anything, so rank means: **how much this technique's output deserves to
be believed**. It is displayed and it orders search results. It does *not*
feed the confidence model -- that stays anchored to `sources.SourceRegistry`,
which the operator controls and a module author does not. A module author
declaring `rank = EXCELLENT` must not be able to move a confidence score;
that was the RC-01 class of bug and it is not being reintroduced through a
new door.

A module declares:

  meta      identity, description, authors, references, disclosure date, rank
  options   typed, validated, with defaults and required flags
  run()     inherited from DiscoveryStage -- consumes evidence, emits
            observations, never opens a socket

Third-party modules drop into a load path and are picked up by
`ModuleRegistry.load_path()`.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import pkgutil
import re
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .auth import validate_address
from .stages import DiscoveryStage

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Rank
# --------------------------------------------------------------------------- #

class Rank(str, Enum):
    """How much this technique's output deserves to be believed."""

    MANUAL = "manual"
    LOW = "low"
    NORMAL = "normal"
    GOOD = "good"
    GREAT = "great"
    EXCELLENT = "excellent"

    @property
    def order(self) -> int:
        return ["manual", "low", "normal", "good", "great",
                "excellent"].index(self.value)


# --------------------------------------------------------------------------- #
# References
# --------------------------------------------------------------------------- #

class RefType(str, Enum):
    CVE = "CVE"
    EDB = "EDB"
    OSVDB = "OSVDB"
    URL = "URL"
    ATTACK = "ATT&CK"
    NOTE = "NOTE"


@dataclass(frozen=True)
class Reference:
    type: RefType
    value: str

    def url(self) -> str:
        if self.type is RefType.CVE:
            return f"https://nvd.nist.gov/vuln/detail/{self.value}"
        if self.type is RefType.EDB:
            return f"https://www.exploit-db.com/exploits/{self.value}"
        if self.type is RefType.ATTACK:
            return f"https://attack.mitre.org/techniques/{self.value.replace('.', '/')}/"
        return self.value

    def __str__(self) -> str:
        return f"{self.type.value}-{self.value}" if self.type in (
            RefType.CVE, RefType.EDB, RefType.OSVDB) else self.value


# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #

class OptType(str, Enum):
    STRING = "string"
    INT = "int"
    FLOAT = "float"
    BOOL = "bool"
    ENUM = "enum"
    ADDRESS = "address"
    PORT = "port"
    PATH = "path"


_TRUE = {"true", "t", "yes", "y", "on", "1"}
_FALSE = {"false", "f", "no", "n", "off", "0"}


@dataclass
class Option:
    name: str
    type: OptType = OptType.STRING
    default: Any = None
    required: bool = False
    description: str = ""
    choices: tuple[str, ...] = ()
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    validator: Optional[Callable[[Any], Any]] = None
    advanced: bool = False
    """Hidden from `show options`; visible under `show advanced`."""

    def __post_init__(self) -> None:
        self.name = self.name.upper()
        if self.type is OptType.ENUM and not self.choices:
            raise ValueError(f"{self.name}: enum option needs choices")

    def coerce(self, raw: Any) -> Any:
        """Parse and validate a value. Raises ValueError with a message the
        operator can act on -- 'must be 1-65535', not 'invalid literal'."""
        if raw is None:
            if self.required:
                raise ValueError(f"{self.name} is required")
            return None

        try:
            value = self._coerce_type(raw)
        except ValueError:
            raise
        except Exception as exc:  # narrow anything the coercer surprises us with
            raise ValueError(f"{self.name}: {exc}") from None

        if self.minimum is not None and value < self.minimum:
            raise ValueError(f"{self.name} must be >= {self.minimum}")
        if self.maximum is not None and value > self.maximum:
            raise ValueError(f"{self.name} must be <= {self.maximum}")
        if self.validator is not None:
            value = self.validator(value)
        return value

    def _coerce_type(self, raw: Any) -> Any:
        t = self.type
        if t is OptType.STRING:
            return str(raw)
        if t is OptType.INT:
            try:
                return int(str(raw).strip(), 0)
            except ValueError:
                raise ValueError(f"{self.name} must be an integer") from None
        if t is OptType.FLOAT:
            try:
                return float(raw)
            except (TypeError, ValueError):
                raise ValueError(f"{self.name} must be a number") from None
        if t is OptType.BOOL:
            if isinstance(raw, bool):
                return raw
            token = str(raw).strip().lower()
            if token in _TRUE:
                return True
            if token in _FALSE:
                return False
            raise ValueError(f"{self.name} must be true or false")
        if t is OptType.ENUM:
            token = str(raw).strip()
            if token not in self.choices:
                raise ValueError(
                    f"{self.name} must be one of: {', '.join(self.choices)}")
            return token
        if t is OptType.ADDRESS:
            return validate_address(str(raw))
        if t is OptType.PORT:
            try:
                port = int(str(raw).strip())
            except ValueError:
                raise ValueError(f"{self.name} must be an integer") from None
            if not 1 <= port <= 65535:
                raise ValueError(f"{self.name} must be 1-65535")
            return port
        if t is OptType.PATH:
            return Path(str(raw)).expanduser()
        raise ValueError(f"{self.name}: unsupported option type {t}")

    def display(self, current: Any) -> str:
        if current is None:
            return ""
        if self.type is OptType.BOOL:
            return "true" if current else "false"
        return str(current)


class OptionDataStore:
    """Per-module option state. Validates on set, not at run time.

    Failing at `set` means the operator finds out immediately, at the point
    they can fix it, instead of three commands later inside a stack trace.
    """

    def __init__(self, options: Iterable[Option]) -> None:
        self._options: dict[str, Option] = {}
        self._values: dict[str, Any] = {}
        for opt in options:
            self._options[opt.name] = opt
            self._values[opt.name] = opt.coerce(opt.default) \
                if opt.default is not None else None

    def __contains__(self, name: str) -> bool:
        return name.upper() in self._options

    def __iter__(self):
        return iter(self._options.values())

    def option(self, name: str) -> Option:
        try:
            return self._options[name.upper()]
        except KeyError:
            raise KeyError(f"unknown option: {name}") from None

    def get(self, name: str, fallback: Any = None) -> Any:
        value = self._values.get(name.upper())
        return fallback if value is None else value

    def set(self, name: str, raw: Any) -> Any:
        opt = self.option(name)
        value = opt.coerce(raw)
        self._values[opt.name] = value
        return value

    def unset(self, name: str) -> None:
        opt = self.option(name)
        self._values[opt.name] = opt.coerce(opt.default) \
            if opt.default is not None else None

    def missing_required(self) -> list[str]:
        return [o.name for o in self._options.values()
                if o.required and self._values.get(o.name) is None]

    def validate(self) -> None:
        missing = self.missing_required()
        if missing:
            raise ValueError("required options not set: " + ", ".join(missing))

    def as_dict(self) -> dict[str, Any]:
        return dict(self._values)

    def rows(self, advanced: bool = False) -> list[tuple[str, str, str, str]]:
        """(name, current, required, description) for tabular rendering."""
        return [
            (o.name, o.display(self._values.get(o.name)),
             "yes" if o.required else "no", o.description)
            for o in self._options.values() if o.advanced == advanced
        ]


# --------------------------------------------------------------------------- #
# Module metadata
# --------------------------------------------------------------------------- #

_FULLNAME = re.compile(r"^[a-z0-9_]+(/[a-z0-9_]+)+$")


@dataclass
class ModuleInfo:
    fullname: str
    """Path-style identity, e.g. 'recon/http/app_fingerprint'."""
    name: str
    description: str = ""
    authors: tuple[str, ...] = ()
    references: tuple[Reference, ...] = ()
    disclosure_date: Optional[date] = None
    rank: Rank = Rank.NORMAL
    platforms: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _FULLNAME.match(self.fullname):
            raise ValueError(
                f"module fullname must look like 'category/sub/name', "
                f"got {self.fullname!r}")

    @property
    def category(self) -> str:
        return self.fullname.split("/", 1)[0]

    def cves(self) -> list[str]:
        return [f"CVE-{r.value}" if not r.value.upper().startswith("CVE-")
                else r.value
                for r in self.references if r.type is RefType.CVE]

    def haystack(self) -> str:
        return " ".join([
            self.fullname, self.name, self.description,
            " ".join(self.authors), " ".join(self.platforms),
            " ".join(str(r) for r in self.references),
            self.rank.value,
        ]).lower()


class ReconModule(DiscoveryStage):
    """A discovery stage with declared metadata and typed options.

    Subclasses set `meta` and `option_spec`. Everything else -- timeouts,
    decay behaviour, the run() contract -- is inherited from DiscoveryStage,
    so existing pipelines accept these without modification.
    """

    meta: ModuleInfo
    option_spec: tuple[Option, ...] = ()

    def __init__(self, **overrides: Any) -> None:
        if not hasattr(self, "meta"):
            raise TypeError(f"{type(self).__name__} must declare `meta`")
        self.options = OptionDataStore(self.option_spec)
        for key, value in overrides.items():
            self.options.set(key, value)
        # DiscoveryStage identity fields default from metadata.
        if getattr(self, "name", "unnamed") == "unnamed":
            self.name = self.meta.fullname.rsplit("/", 1)[-1]

    # -- convenience -------------------------------------------------------- #

    @property
    def fullname(self) -> str:
        return self.meta.fullname

    def opt(self, name: str, fallback: Any = None) -> Any:
        return self.options.get(name, fallback)

    def info(self) -> str:
        return render_info(self)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} {self.meta.fullname}>"


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _table(headers: list[str], rows: list[list[str]], indent: str = "   ") -> str:
    if not rows:
        return indent + "(none)"
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows))
              for i, h in enumerate(headers)]
    out = [indent + "  ".join(str(h).ljust(widths[i])
                              for i, h in enumerate(headers)).rstrip(),
           indent + "  ".join("-" * widths[i] for i in range(len(headers)))]
    for row in rows:
        out.append(indent + "  ".join(str(c).ljust(widths[i])
                                      for i, c in enumerate(row)).rstrip())
    return "\n".join(out)


def render_info(module: ReconModule) -> str:
    """msfconsole-style `info` output."""
    m = module.meta
    lines = [
        "",
        f"       Name: {m.name}",
        f"     Module: {m.fullname}",
        f"       Rank: {m.rank.value.capitalize()}",
    ]
    if m.disclosure_date:
        lines.append(f"  Disclosed: {m.disclosure_date.isoformat()}")
    if m.platforms:
        lines.append(f"  Platforms: {', '.join(m.platforms)}")
    lines.append("")

    if m.authors:
        lines.append("Provided by:")
        lines += [f"  {a}" for a in m.authors]
        lines.append("")

    basic = module.options.rows(advanced=False)
    lines.append("Basic options:")
    lines.append(_table(["Name", "Current Setting", "Required", "Description"],
                        [list(r) for r in basic]))
    lines.append("")

    advanced = module.options.rows(advanced=True)
    if advanced:
        lines.append("Advanced options:")
        lines.append(_table(["Name", "Current Setting", "Required",
                             "Description"], [list(r) for r in advanced]))
        lines.append("")

    if m.description:
        lines.append("Description:")
        lines += [f"  {line}" for line in _wrap(m.description, 72)]
        lines.append("")

    if m.references:
        lines.append("References:")
        lines += [f"  {r.url()}" for r in m.references]
        lines.append("")

    if m.notes:
        lines.append("Notes:")
        for note in m.notes:
            wrapped = _wrap(note, 70)
            lines.append(f"  * {wrapped[0]}")
            lines += [f"    {w}" for w in wrapped[1:]]
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


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

class ModuleRegistry:
    """Holds module classes, searches them, and loads third-party paths."""

    def __init__(self) -> None:
        self._modules: dict[str, type[ReconModule]] = {}
        self.load_errors: list[tuple[str, str]] = []

    def __len__(self) -> int:
        return len(self._modules)

    def register(self, cls: type[ReconModule]) -> type[ReconModule]:
        """Usable as a decorator."""
        if not (inspect.isclass(cls) and issubclass(cls, ReconModule)):
            raise TypeError(f"{cls!r} is not a ReconModule")
        if inspect.isabstract(cls):
            raise TypeError(f"{cls.__name__} is abstract")
        name = cls.meta.fullname
        if name in self._modules and self._modules[name] is not cls:
            raise ValueError(f"duplicate module fullname: {name}")
        self._modules[name] = cls
        return cls

    def get(self, fullname: str) -> type[ReconModule]:
        try:
            return self._modules[fullname]
        except KeyError:
            near = self.search(fullname.rsplit("/", 1)[-1])
            hint = f" Did you mean: {near[0].meta.fullname}?" if near else ""
            raise KeyError(f"no such module: {fullname}.{hint}") from None

    def create(self, fullname: str, **options: Any) -> ReconModule:
        return self.get(fullname)(**options)

    def list(self) -> list[type[ReconModule]]:
        return sorted(self._modules.values(), key=lambda c: c.meta.fullname)

    def search(self, query: str = "", *, category: Optional[str] = None,
               rank: Optional[Rank] = None,
               cve: Optional[str] = None) -> list[type[ReconModule]]:
        """Keyword search across metadata, with msf-style filters.

        Supports inline `key:value` terms -- `search apache rank:great`,
        `search cve:2021-41773`, `search category:recon`.
        """
        terms: list[str] = []
        for token in query.split():
            key, sep, value = token.partition(":")
            if not sep:
                terms.append(token.lower())
                continue
            key = key.lower()
            if key in ("cat", "category", "type"):
                category = value
            elif key == "rank":
                rank = Rank(value.lower())
            elif key == "cve":
                cve = value
            elif key in ("name", "author", "platform"):
                terms.append(value.lower())
            else:
                terms.append(token.lower())

        results = []
        for cls in self._modules.values():
            meta = cls.meta
            if category and meta.category != category:
                continue
            if rank and meta.rank.order < rank.order:
                continue
            if cve:
                wanted = cve.upper()
                wanted = wanted if wanted.startswith("CVE-") else f"CVE-{wanted}"
                if wanted not in meta.cves():
                    continue
            hay = meta.haystack()
            if terms and not all(t in hay for t in terms):
                continue
            results.append(cls)

        results.sort(key=lambda c: (-c.meta.rank.order, c.meta.fullname))
        return results

    # -- third-party loading ------------------------------------------------- #

    def load_path(self, path: str | Path, *, trusted: bool = False) -> int:
        """Import every .py under `path` and register its ReconModules.

        RC-10: **this executes every file it finds.** That is inherent to a
        Python plugin directory, not a flaw, but it was previously a silent
        property mentioned in a docstring. `trusted=True` is now required, so
        the danger is stated at the call site where someone reviewing the code
        will actually see it -- a `loadpath` typo pointing at ~/Downloads
        should not be a one-word mistake.

        A module that fails to import is recorded in `load_errors` and
        skipped: one broken third-party file must not stop the console
        starting.
        """
        root = Path(path).expanduser()
        if not trusted:
            raise PermissionError(
                f"load_path({root}) executes every .py it finds. Pass "
                "trusted=True to confirm you control that directory.")
        if not root.is_dir():
            raise NotADirectoryError(f"not a directory: {root}")
        log.warning("executing third-party modules from %s", root)
        loaded = 0
        for file in sorted(root.rglob("*.py")):
            if file.name.startswith("_"):
                continue
            loaded += self._load_file(file)
        return loaded

    def _load_file(self, file: Path) -> int:
        spec = importlib.util.spec_from_file_location(
            f"reconkg_ext_{file.stem}", file)
        if spec is None or spec.loader is None:
            self.load_errors.append((str(file), "could not build import spec"))
            return 0
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            self.load_errors.append((str(file), f"{type(exc).__name__}: {exc}"))
            log.warning("skipping %s: %s", file, exc)
            return 0

        count = 0
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, ReconModule) and obj is not ReconModule
                    and not inspect.isabstract(obj)
                    and hasattr(obj, "meta")):
                try:
                    self.register(obj)
                    count += 1
                except (TypeError, ValueError) as exc:
                    self.load_errors.append((str(file), str(exc)))
        return count


registry = ModuleRegistry()
"""Process-wide default registry. Built-ins register into it on import."""
