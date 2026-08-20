"""Structured logging, correlation IDs and metrics for the coordinator.

Seven audit rounds produced twenty-two findings, every one of them located by
reading source or attacking it deliberately. Not one was found by watching the
system run, because the running system says nothing measurable: it cannot
report how many scans it has executed, how many leads it has disputed, which
principal is saturating the evidence ingress, or how often a stage fell back.
This module is that missing sense organ.

Three design decisions worth defending:

**No client library.** `prometheus_client` would be a dependency for maybe two
hundred lines of arithmetic, and RC-22 was caused by relying on a dependency
that was never declared. A registry we own has no import to forget and no
process-global default registry for one test to leak into the next.

**Correlation lives in a `ContextVar`, not a parameter.** The alternative --
threading a request id through `DiscoveryEngine.run` -> `_run_slot` ->
`_apply_one` -> `TargetStore.record_port` -- would touch every signature in
the write path, and the first function that forgot to pass it would silently
orphan every log line beneath it. `contextvars` is copied per `asyncio.Task`,
so concurrent scans of different targets cannot see each other's context even
though they share the event loop.

**Label values are capped.** Principal names and target addresses are
caller-influenced, and a dict keyed on caller input with no bound is the
mistake this project has now shipped twice (RC-03, RC-18). A metrics registry
that grows one series per attacker-chosen principal is a memory leak wearing a
dashboard. Overflow folds into an `_other` series rather than being dropped,
so the sum over series still equals the number of events observed -- an
undercount is worse than a coarse count, because it looks correct.
"""

from __future__ import annotations

import contextvars
import json
import logging
import math
import re
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator, Optional

log = logging.getLogger(__name__)

__all__ = [
    "Correlation", "current_correlation", "bind_correlation",
    "reset_correlation", "correlation_scope", "new_request_id",
    "JsonFormatter", "configure_json_logging",
    "MetricSpec", "Metrics", "default_specs", "COUNTER", "HISTOGRAM",
    "StoreMetricsSubscriber", "record_scan_report",
    "CorrelationMiddleware", "PROMETHEUS_CONTENT_TYPE",
    "OVERFLOW_LABEL", "DEFAULT_MAX_SERIES", "MAX_LABEL_VALUE_LEN",
    "DEFAULT_DURATION_BUCKETS", "DISPUTED_MARKER", "CARDINALITY_METRIC",
    "UNMATCHED_ROUTE",
]


# --------------------------------------------------------------------------- #
# Correlation context
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Correlation:
    """The three things worth carrying down the whole call stack.

    Frozen because a mutable object in a ContextVar defeats the isolation the
    ContextVar provides: a child task holds the *same* object the parent set,
    so mutating it in the child would be visible in the parent. Rebinding via
    `dataclasses.replace` is the only supported edit.
    """

    request_id: str
    principal: Optional[str] = None
    target: Optional[str] = None

    def as_dict(self) -> dict:
        out: dict[str, str] = {"request_id": self.request_id}
        if self.principal is not None:
            out["principal"] = self.principal
        if self.target is not None:
            out["target"] = self.target
        return out


_correlation: contextvars.ContextVar[Optional[Correlation]] = \
    contextvars.ContextVar("reconkg_correlation", default=None)

_ID_SAFE = re.compile(r"[^A-Za-z0-9._:-]")
MAX_CORRELATION_FIELD_LEN = 128
"""Correlation fields are echoed into every log line a request emits, and
`request_id` may originate in a client header. Unbounded, a 10 MB header would
be multiplied by the number of log calls made while handling the request."""


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def _clean_id(raw: Any) -> str:
    """Reject by character class rather than escaping downstream.

    Same reasoning as `auth.validate_address` (RC-04/RC-07): a correlation id
    lands in JSON log lines that a shipper parses, so a value containing a line
    feed could forge a second log record. Restricting the alphabet means no
    consumer has to remember to escape.
    """
    text = raw if isinstance(raw, str) else str(raw)
    text = _ID_SAFE.sub("_", text)[:MAX_CORRELATION_FIELD_LEN]
    return text or "unset"


def current_correlation() -> Optional[Correlation]:
    return _correlation.get()


def bind_correlation(*, request_id: Optional[str] = None,
                     principal: Optional[str] = None,
                     target: Optional[str] = None) -> contextvars.Token:
    """Merge fields over the current context; returns a reset token.

    Merging rather than replacing is what lets the HTTP middleware set
    `request_id`/`principal` once and the engine add `target` later without
    either of them knowing the other exists.
    """
    existing = _correlation.get()
    if existing is None:
        existing = Correlation(request_id=_clean_id(
            request_id if request_id is not None else new_request_id()))
    updates: dict[str, str] = {}
    if request_id is not None:
        updates["request_id"] = _clean_id(request_id)
    if principal is not None:
        updates["principal"] = _clean_id(principal)
    if target is not None:
        updates["target"] = _clean_id(target)
    return _correlation.set(replace(existing, **updates))


def reset_correlation(token: contextvars.Token) -> None:
    try:
        _correlation.reset(token)
    except ValueError:
        # The token was created in a different Context -- happens when a
        # caller binds in one task and resets in another. Clearing is the
        # honest fallback; raising would turn a logging mistake into a
        # request failure.
        _correlation.set(None)


@contextmanager
def correlation_scope(*, request_id: Optional[str] = None,
                      principal: Optional[str] = None,
                      target: Optional[str] = None) -> Iterator[Correlation]:
    token = bind_correlation(request_id=request_id, principal=principal,
                             target=target)
    try:
        bound = _correlation.get()
        yield bound  # bind_correlation always sets one
    finally:
        reset_correlation(token)


# --------------------------------------------------------------------------- #
# Structured logging
# --------------------------------------------------------------------------- #

_RESERVED = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "taskName", "thread", "threadName",
})

MAX_LOG_VALUE_LEN = 4096


def _safe_repr(value: Any) -> str:
    try:
        text = repr(value)
    except Exception as exc:  # a __repr__ that raises is not our problem
        text = f"<unreprable {type(value).__name__}: {type(exc).__name__}>"
    return text[:MAX_LOG_VALUE_LEN]


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        return sorted(_safe_repr(v) for v in value)
    if isinstance(value, BaseException):
        return f"{type(value).__name__}: {value}"
    return _safe_repr(value)


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with correlation fields folded in.

    The hard requirement is that this never raises. A formatter that throws
    takes out the log call, and `logging` swallows the traceback to stderr
    where nobody reads it -- so a hostile or merely awkward extra (a circular
    dict, an object whose `__repr__` blows up) would silently delete the record
    of whatever it was attached to. Losing a log line is bad; killing the
    request that emitted it is worse. Every failure mode below degrades to a
    line that is still valid JSON and still says what went wrong.
    """

    def __init__(self, *, static_fields: Optional[dict] = None,
                 include_source: bool = False) -> None:
        super().__init__()
        self.static_fields = dict(static_fields or {})
        self.include_source = include_source

    def _base(self, record: logging.LogRecord) -> dict:
        ts = datetime.fromtimestamp(record.created, timezone.utc)
        payload: dict[str, Any] = {
            "ts": ts.isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if self.include_source:
            payload["source"] = f"{record.module}:{record.lineno}"
        payload.update(self.static_fields)
        corr = current_correlation()
        if corr is not None:
            payload.update(corr.as_dict())
        if record.exc_info:
            payload["exc_type"] = getattr(record.exc_info[0], "__name__",
                                          str(record.exc_info[0]))
            payload["exc_text"] = self.formatException(
                record.exc_info)[:MAX_LOG_VALUE_LEN]
        if record.stack_info:
            payload["stack"] = record.stack_info[:MAX_LOG_VALUE_LEN]
        return payload

    def format(self, record: logging.LogRecord) -> str:
        try:
            payload = self._base(record)
            extras = {str(k): v for k, v in record.__dict__.items()
                      if k not in _RESERVED and not k.startswith("_")
                      and k not in payload}
        except Exception as exc:  # pragma: no cover - defence in depth
            return json.dumps({"level": getattr(record, "levelname", "ERROR"),
                               "logger": "reconkg.observability",
                               "message": "log formatting failed",
                               "log_extras_degraded": True,
                               "log_error": _safe_repr(exc)})
        payload.update(extras)

        try:
            return json.dumps(payload, default=_json_default,
                              ensure_ascii=False)
        except (TypeError, ValueError, RecursionError):
            pass

        # Second attempt. `default=` is only consulted for *unrecognised
        # types* -- json never calls it for a self-referential list, which
        # raises ValueError instead. So flatten every extra to its repr.
        degraded = {k: v for k, v in payload.items() if k not in extras}
        degraded["log_extras_degraded"] = True
        for key, value in extras.items():
            degraded[key] = _safe_repr(value)
        try:
            return json.dumps(degraded, default=_json_default,
                              ensure_ascii=False)
        except Exception as exc:  # pragma: no cover - defence in depth
            return json.dumps({
                "ts": payload.get("ts"), "level": record.levelname,
                "logger": record.name, "message": "unserialisable log record",
                "log_extras_degraded": True, "log_error": _safe_repr(exc)})


def configure_json_logging(level: int = logging.INFO, *, stream=None,
                           static_fields: Optional[dict] = None
                           ) -> logging.Handler:
    """Install the JSON formatter on the root logger. Returns the handler.

    Replaces the root handlers rather than appending: two handlers on the root
    emits every line twice, once JSON and once not, and a log people half
    trust is worse than one they ignore.
    """
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter(static_fields=static_fields))
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    return handler


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

COUNTER = "counter"
HISTOGRAM = "histogram"

OVERFLOW_LABEL = "_other"
DEFAULT_MAX_SERIES = 128
MAX_LABEL_VALUE_LEN = 96

DEFAULT_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
                            1.0, 2.5, 5.0, 10.0)

CARDINALITY_METRIC = "reconkg_metrics_cardinality_capped_total"

_METRIC_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


@dataclass(frozen=True)
class MetricSpec:
    name: str
    help: str
    kind: str = COUNTER
    labelnames: tuple[str, ...] = ()
    buckets: tuple[float, ...] = ()

    def __post_init__(self) -> None:
        if not _METRIC_NAME.match(self.name):
            raise ValueError(f"invalid metric name: {self.name!r}")
        if not self.help.strip():
            # An empty docstring renders as "# HELP name " with a trailing
            # space, which strict parsers reject and every reader finds
            # useless. Cheaper to refuse it at registration.
            raise ValueError(f"metric {self.name} needs a help string")
        if self.kind not in (COUNTER, HISTOGRAM):
            raise ValueError(f"unknown metric kind: {self.kind!r}")
        for label in self.labelnames:
            if not _LABEL_NAME.match(label):
                raise ValueError(f"invalid label name: {label!r}")
            if label == "le":
                raise ValueError("'le' is reserved for histogram buckets")
        if len(set(self.labelnames)) != len(self.labelnames):
            raise ValueError(f"duplicate label name in {self.name}")
        if self.kind == HISTOGRAM:
            bounds = tuple(float(b) for b in
                           (self.buckets or DEFAULT_DURATION_BUCKETS))
            if (list(bounds) != sorted(bounds)
                    or len(set(bounds)) != len(bounds)):
                raise ValueError("histogram buckets must strictly increase")
            if any(math.isinf(b) or math.isnan(b) for b in bounds):
                raise ValueError("+Inf bucket is implicit; do not declare it")
            object.__setattr__(self, "buckets", bounds)
        elif self.buckets:
            raise ValueError("buckets are only meaningful for histograms")


class _Histogram:
    __slots__ = ("bounds", "counts", "sum", "count")

    def __init__(self, bounds: tuple[float, ...]) -> None:
        self.bounds = bounds
        self.counts = [0] * (len(bounds) + 1)  # last slot is the +Inf bucket
        self.sum = 0.0
        self.count = 0

    def observe(self, value: float) -> None:
        value = float(value)
        if math.isnan(value):
            raise ValueError("cannot observe NaN")
        self.count += 1
        self.sum += value
        for index, bound in enumerate(self.bounds):
            if value <= bound:
                self.counts[index] += 1
                return
        self.counts[-1] += 1

    def cumulative(self) -> list[int]:
        running = 0
        out: list[int] = []
        for slot in self.counts:
            running += slot
            out.append(running)
        return out


class _Family:
    """One metric name plus its series, with a hard cap on distinct labels."""

    def __init__(self, spec: MetricSpec, max_series: int) -> None:
        self.spec = spec
        self.max_series = max_series
        self.series: dict[tuple[str, ...], Any] = {}
        self.overflow_key = tuple(OVERFLOW_LABEL for _ in spec.labelnames)
        self.capped_events = 0

    def _new_value(self) -> Any:
        if self.spec.kind == COUNTER:
            return 0.0
        return _Histogram(self.spec.buckets or DEFAULT_DURATION_BUCKETS)

    def resolve(self, key: tuple[str, ...]) -> tuple[tuple[str, ...], bool]:
        """Returns (key_to_use, was_folded_into_overflow).

        The overflow series is exempt from the cap on purpose: it is the thing
        that keeps the total conserved, so refusing to create it under pressure
        would lose exactly the counts the cap exists to preserve.
        """
        if key in self.series:
            return key, False
        distinct = len(self.series) - (1 if self.overflow_key in self.series
                                       else 0)
        if distinct < self.max_series or key == self.overflow_key:
            self.series[key] = self._new_value()
            return key, False
        self.capped_events += 1
        if self.overflow_key not in self.series:
            self.series[self.overflow_key] = self._new_value()
        return self.overflow_key, True

    @property
    def distinct_series(self) -> int:
        return len(self.series)


def _clean_label_value(value: Any) -> str:
    """Caller-influenced label values are sanitised; developer names are not.

    Control characters are stripped rather than escaped because a label value
    is simultaneously a Prometheus token, a JSON snapshot key and a dashboard
    legend, and only the first of those three understands `\\n`.
    """
    text = value if isinstance(value, str) else str(value)
    text = _CONTROL.sub("", text)
    if len(text) > MAX_LABEL_VALUE_LEN:
        text = text[:MAX_LABEL_VALUE_LEN - 1] + "…"
    return text or "unset"


def _format_value(value: float) -> str:
    number = float(value)
    if math.isnan(number):
        return "NaN"
    if math.isinf(number):
        return "+Inf" if number > 0 else "-Inf"
    if number.is_integer() and abs(number) < 1e15:
        return str(int(number))
    return repr(number)


def _escape_help(text: str) -> str:
    """Spec: in HELP, backslash and line feed escape. Quotes do not."""
    return text.replace("\\", "\\\\").replace("\n", "\\n")


def _escape_label(text: str) -> str:
    """Spec: in a label value, backslash, double quote and line feed."""
    return (text.replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n"))


def _render_labels(pairs: list[tuple[str, str]]) -> str:
    if not pairs:
        return ""
    body = ",".join(f'{n}="{_escape_label(v)}"' for n, v in pairs)
    return "{" + body + "}"


PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def default_specs() -> list[MetricSpec]:
    """The metrics the audit rounds said were missing, and nothing else.

    Each one answers a question somebody asked during an audit and could not
    answer: how many scans ran, how often did a stage fall back, who is
    hammering the ingress, how many leads did we mark disputed.
    """
    return [
        MetricSpec("reconkg_scans_started_total",
                   "Discovery pipelines started.", COUNTER, ("target",)),
        MetricSpec("reconkg_scans_finished_total",
                   "Discovery pipelines finished, by result.",
                   COUNTER, ("target", "result")),
        MetricSpec("reconkg_stage_outcomes_total",
                   "Stage attempts by slot, stage and outcome.",
                   COUNTER, ("slot", "stage", "outcome")),
        MetricSpec("reconkg_stage_fallbacks_total",
                   "Stage attempts that were not the slot's primary "
                   "technique.", COUNTER, ("slot",)),
        MetricSpec("reconkg_rejected_observations_total",
                   "Malformed observations discarded by the engine (RC-02).",
                   COUNTER, ("stage",)),
        MetricSpec("reconkg_leads_total",
                   "Vulnerability leads recorded on the graph.",
                   COUNTER, ("target",)),
        MetricSpec("reconkg_leads_disputed_total",
                   "Leads recorded while a credible peer contradicted the "
                   "matched fingerprint.", COUNTER, ("target",)),
        MetricSpec("reconkg_fingerprint_downgrades_total",
                   "Fingerprint confidence reductions, by reason.",
                   COUNTER, ("target", "reason")),
        MetricSpec("reconkg_change_events_total",
                   "ChangeEvents emitted by the store, by kind.",
                   COUNTER, ("kind",)),
        MetricSpec("reconkg_evidence_submissions_total",
                   "Evidence payloads accepted at the ingress, by principal.",
                   COUNTER, ("principal", "tool")),
        MetricSpec("reconkg_ratelimit_rejections_total",
                   "Requests refused by the per-principal token bucket.",
                   COUNTER, ("principal", "route")),
        MetricSpec("reconkg_auth_failures_total",
                   "Authentication and authorisation refusals, by reason.",
                   COUNTER, ("reason",)),
        MetricSpec("reconkg_snapshot_saves_total",
                   "Persistence snapshot attempts, by result.",
                   COUNTER, ("result",)),
        MetricSpec("reconkg_http_requests_total",
                   "HTTP requests served, by route and status.",
                   COUNTER, ("method", "route", "status")),
        MetricSpec(CARDINALITY_METRIC,
                   "Observations folded into the _other series because the "
                   "label cardinality cap was reached.",
                   COUNTER, ("metric",)),
        MetricSpec("reconkg_stage_duration_seconds",
                   "Wall time of a single stage attempt.",
                   HISTOGRAM, ("slot", "stage")),
        MetricSpec("reconkg_scan_duration_seconds",
                   "Wall time of a full discovery pipeline.",
                   HISTOGRAM, ("target",)),
        MetricSpec("reconkg_http_request_duration_seconds",
                   "Wall time of an HTTP request.",
                   HISTOGRAM, ("method", "route")),
        MetricSpec("reconkg_snapshot_duration_seconds",
                   "Wall time of a persistence snapshot write.",
                   HISTOGRAM, ()),
    ]


class Metrics:
    """In-process counter/histogram registry with bounded label cardinality.

    Not thread-safe by deployment design rather than by oversight: the
    coordinator is a single-process asyncio app, and every mutation below is a
    short run of dict operations with no `await` between read and write, so the
    event loop cannot interleave them. A lock would buy nothing here and would
    make `inc()` -- which gets called from inside exception handlers -- capable
    of blocking.
    """

    def __init__(self, specs: Optional[Iterable[MetricSpec]] = None, *,
                 max_series: int = DEFAULT_MAX_SERIES) -> None:
        if max_series < 1:
            raise ValueError("max_series must be at least 1")
        self.max_series = max_series
        self._families: dict[str, _Family] = {}
        for spec in (default_specs() if specs is None else specs):
            self.register(spec)

    # -- registration ---------------------------------------------------- #

    def register(self, spec: MetricSpec) -> None:
        if spec.name in self._families:
            raise ValueError(f"metric already registered: {spec.name}")
        self._families[spec.name] = _Family(spec, self.max_series)

    def names(self) -> list[str]:
        return sorted(self._families)

    def _family(self, name: str) -> _Family:
        family = self._families.get(name)
        if family is None:
            # A typo'd metric name is a developer error, and a silent no-op
            # leaves a dashboard permanently reading zero with nothing to
            # explain why. Loud beats quietly wrong.
            raise KeyError(f"unregistered metric: {name!r}")
        return family

    def _key(self, family: _Family, labels: dict) -> tuple[str, ...]:
        expected = family.spec.labelnames
        if set(labels) != set(expected):
            raise ValueError(
                f"{family.spec.name} expects labels {list(expected)}, "
                f"got {sorted(labels)}")
        return tuple(_clean_label_value(labels[name]) for name in expected)

    def _note_cap(self, family: _Family) -> None:
        if family.spec.name == CARDINALITY_METRIC:
            return  # self-reporting the meta-counter would recurse
        meta = self._families.get(CARDINALITY_METRIC)
        if meta is None:
            return
        key, _ = meta.resolve((_clean_label_value(family.spec.name),))
        meta.series[key] += 1.0

    # -- mutation --------------------------------------------------------- #

    def inc(self, name: str, amount: float = 1.0, **labels: Any) -> None:
        family = self._family(name)
        if family.spec.kind != COUNTER:
            raise TypeError(f"{name} is a {family.spec.kind}, not a counter")
        if amount < 0:
            raise ValueError("counters may not decrease")
        key, capped = family.resolve(self._key(family, labels))
        family.series[key] += float(amount)
        if capped:
            self._note_cap(family)

    def observe(self, name: str, value: float, **labels: Any) -> None:
        family = self._family(name)
        if family.spec.kind != HISTOGRAM:
            raise TypeError(f"{name} is a {family.spec.kind}, not a histogram")
        key, capped = family.resolve(self._key(family, labels))
        family.series[key].observe(value)
        if capped:
            self._note_cap(family)

    @contextmanager
    def time(self, name: str, **labels: Any) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe(name, time.perf_counter() - start, **labels)

    def reset(self) -> None:
        for family in self._families.values():
            family.series.clear()
            family.capped_events = 0

    # -- reads ------------------------------------------------------------ #

    def counter_value(self, name: str, **labels: Any) -> float:
        family = self._family(name)
        return float(family.series.get(self._key(family, labels), 0.0))

    def histogram(self, name: str, **labels: Any) -> Optional[_Histogram]:
        family = self._family(name)
        return family.series.get(self._key(family, labels))

    def total(self, name: str) -> float:
        """Sum over every series, overflow included -- the conserved value."""
        family = self._family(name)
        if family.spec.kind == COUNTER:
            return float(sum(family.series.values()))
        return float(sum(h.count for h in family.series.values()))

    def snapshot(self) -> dict:
        """JSON-serialisable view, for a `/metrics.json` endpoint."""
        counters: dict[str, Any] = {}
        histograms: dict[str, Any] = {}
        capped: dict[str, int] = {}
        for name in sorted(self._families):
            family = self._families[name]
            spec = family.spec
            if family.capped_events:
                capped[name] = family.capped_events
            entries = []
            for key in sorted(family.series):
                labels = dict(zip(spec.labelnames, key))
                if spec.kind == COUNTER:
                    entries.append({"labels": labels,
                                    "value": float(family.series[key])})
                else:
                    hist = family.series[key]
                    bounds = list(hist.bounds) + [float("inf")]
                    entries.append({
                        "labels": labels, "count": hist.count,
                        "sum": hist.sum,
                        "buckets": {_format_value(b): c for b, c
                                    in zip(bounds, hist.cumulative())}})
            block: dict[str, Any] = {"help": spec.help,
                                     "labels": list(spec.labelnames),
                                     "series": entries}
            if spec.kind == COUNTER:
                block["total"] = float(sum(family.series.values()))
                counters[name] = block
            else:
                block["total"] = sum(h.count for h in family.series.values())
                histograms[name] = block
        return {
            "counters": counters,
            "histograms": histograms,
            "cardinality": {
                "max_series_per_metric": self.max_series,
                "overflow_label": OVERFLOW_LABEL,
                "capped_observations": capped,
                "series_in_use": {n: self._families[n].distinct_series
                                  for n in sorted(self._families)
                                  if self._families[n].series},
            },
        }

    def render_prometheus(self) -> str:
        """Text exposition format 0.0.4.

        Serve it as `PROMETHEUS_CONTENT_TYPE`; since Prometheus 3.0 a scrape
        fails outright on a missing or unparsable Content-Type. HELP and TYPE
        precede every sample for a name, histogram buckets are cumulative and
        ascending, `+Inf` equals `_count`, and the body ends with a line feed
        -- the spec requires that final newline and hand-rolled exporters
        routinely omit it.
        """
        lines: list[str] = []
        for name in sorted(self._families):
            family = self._families[name]
            spec = family.spec
            lines.append(f"# HELP {name} {_escape_help(spec.help)}")
            lines.append(f"# TYPE {name} {spec.kind}")
            for key in sorted(family.series):
                pairs = list(zip(spec.labelnames, key))
                if spec.kind == COUNTER:
                    lines.append(f"{name}{_render_labels(pairs)} "
                                 f"{_format_value(family.series[key])}")
                    continue
                hist = family.series[key]
                bounds = list(hist.bounds) + [float("inf")]
                for bound, count in zip(bounds, hist.cumulative()):
                    bucket_pairs = pairs + [("le", _format_value(bound))]
                    lines.append(
                        f"{name}_bucket{_render_labels(bucket_pairs)} {count}")
                lines.append(f"{name}_sum{_render_labels(pairs)} "
                             f"{_format_value(hist.sum)}")
                lines.append(f"{name}_count{_render_labels(pairs)} "
                             f"{hist.count}")
        return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Store subscriber
# --------------------------------------------------------------------------- #

DISPUTED_MARKER = "DISPUTED:"
"""`vulnref.build_leads` marks a contradicted lead by splicing that string into
the rationale, and the rationale is the only trace of the dispute that reaches
the event stream -- `VulnLead` carries no boolean for it. Sniffing prose is
coupling, so `test_observability` pins the marker: if vulnref rewords, the
disputed counter fails loudly instead of quietly reading zero forever."""


class StoreMetricsSubscriber:
    """Turns ChangeEvents into metrics without touching the engine.

    Instrumentation that requires editing the code being instrumented is
    instrumentation that gets forgotten on the next code path added. The store
    is already the single writer and already emits an event for every
    mutation, so subscribing to it covers the whole graph write path for free
    -- including writes made by code nobody has written yet.

    It swallows its own exceptions rather than leaning on `TargetStore.emit`
    to do it: emit logs a full traceback per event, so a subscriber bug would
    otherwise produce one stack trace per graph mutation and bury the log it
    exists to improve.
    """

    def __init__(self, metrics: Metrics) -> None:
        self.metrics = metrics
        self.errors = 0
        self.handled = 0

    def attach(self, store) -> Callable[[], None]:
        """Subscribe and return the store's idempotent unsubscribe callable."""
        return store.subscribe(self)

    async def __call__(self, event) -> None:
        try:
            self._handle(event)
            self.handled += 1
        except Exception:
            self.errors += 1
            log.exception("metrics subscriber failed on %s",
                          getattr(event, "kind", "?"))

    def _handle(self, event) -> None:
        kind = getattr(event.kind, "value", None) or str(event.kind)
        payload = event.payload or {}
        target = event.target
        m = self.metrics
        m.inc("reconkg_change_events_total", kind=kind)

        if kind == "pipeline.started":
            m.inc("reconkg_scans_started_total", target=target)
        elif kind == "pipeline.finished":
            result = "exhausted" if payload.get("exhausted") else "ok"
            m.inc("reconkg_scans_finished_total", target=target, result=result)
        elif kind == "stage.finished":
            self._stage_finished(payload)
        elif kind == "lead.added":
            m.inc("reconkg_leads_total", target=target)
            if DISPUTED_MARKER in str(payload.get("rationale", "")):
                m.inc("reconkg_leads_disputed_total", target=target)
        elif kind == "fingerprint.confidence_changed":
            if payload.get("direction") == "down":
                m.inc("reconkg_fingerprint_downgrades_total", target=target,
                      reason=str(payload.get("reason", "unknown")))

    def _stage_finished(self, payload: dict) -> None:
        """`stage.finished` is overloaded and both shapes must be handled.

        The engine reuses this kind to report observations it rejected
        (RC-02), and that variant carries no `outcome`. Keying on the presence
        of the field rather than assuming one shape is why a
        rejected-observation event does not silently become a
        `stage_outcomes_total{outcome="None"}` series.
        """
        m = self.metrics
        stage = str(payload.get("stage", "unknown"))
        if "rejected_observations" in payload:
            m.inc("reconkg_rejected_observations_total",
                  float(payload["rejected_observations"]), stage=stage)
            return
        outcome = payload.get("outcome")
        if outcome is None:
            return
        slot = str(payload.get("slot", "unknown"))
        m.inc("reconkg_stage_outcomes_total", slot=slot, stage=stage,
              outcome=str(outcome))
        duration = payload.get("duration_ms")
        if (isinstance(duration, (int, float))
                and not isinstance(duration, bool)):
            m.observe("reconkg_stage_duration_seconds",
                      float(duration) / 1000.0, slot=slot, stage=stage)


def record_scan_report(metrics: Metrics, report) -> None:
    """The settled half of scan instrumentation; call after `engine.run`.

    `ScanReport` holds two facts the event stream does not: total wall time,
    and which attempt was a fallback rather than a primary. Neither can be
    derived from a ChangeEvent, so this is a deliberate second write path --
    see the note in the module docstring about what that costs.
    """
    if report.finished_at is not None:
        elapsed = (report.finished_at - report.started_at).total_seconds()
        metrics.observe("reconkg_scan_duration_seconds", max(0.0, elapsed),
                        target=report.target)
    for attempt in report.attempts:
        if attempt.attempt_index > 1:
            metrics.inc("reconkg_stage_fallbacks_total", slot=attempt.slot)


# --------------------------------------------------------------------------- #
# ASGI middleware
# --------------------------------------------------------------------------- #

class CorrelationMiddleware:
    """Pure-ASGI: binds a request id, echoes it back, times the request.

    Written against the raw ASGI interface rather than Starlette's
    `BaseHTTPMiddleware` because that class runs the downstream app in a
    separate anyio task, and a ContextVar set inside it does not propagate
    back out -- precisely the silent-orphaning failure this module exists to
    prevent. A plain ASGI callable stays in the caller's context.

    `trust_incoming_id` defaults to False. An id echoed from a client header
    is an attacker-chosen string that then keys log searches; `_clean_id`
    bounds and sanitises it, but generating our own is the safer default and
    the flag makes accepting one a decision somebody wrote down.
    """

    def __init__(self, app, metrics: Optional[Metrics] = None, *,
                 header: str = "x-request-id",
                 trust_incoming_id: bool = False) -> None:
        self.app = app
        self.metrics = metrics
        self.header = header.lower().encode("latin-1")
        self.trust_incoming_id = trust_incoming_id

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        incoming = None
        if self.trust_incoming_id:
            for name, value in scope.get("headers", []):
                if name.lower() == self.header:
                    incoming = value.decode("latin-1", "replace")
                    break
        request_id = _clean_id(incoming) if incoming else new_request_id()
        method = str(scope.get("method", "GET"))
        status_holder = {"status": 500}

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                status_holder["status"] = message["status"]
                headers = list(message.get("headers", []))
                headers.append((self.header,
                                request_id.encode("latin-1", "replace")))
                message = dict(message, headers=headers)
            await send(message)

        start = time.perf_counter()
        with correlation_scope(request_id=request_id):
            try:
                await self.app(scope, receive, send_wrapper)
            finally:
                if self.metrics is not None:
                    route = _route_label(scope, status_holder["status"])
                    self.metrics.inc(
                        "reconkg_http_requests_total", method=method,
                        route=route, status=str(status_holder["status"]))
                    self.metrics.observe(
                        "reconkg_http_request_duration_seconds",
                        time.perf_counter() - start, method=method,
                        route=route)


UNMATCHED_ROUTE = "_unmatched"
"""RC-23: one series for every path the router did not match.

The raw path used to be the fallback, and the fallback is reached by exactly
the requests an anonymous caller controls end to end. 200 requests to
`/zz0`..`/zz199` minted 200 series, spent the 128-series budget before any
real route had one, and folded every genuine route into `_other` from then
on. The cap bounded the memory and the attacker chose what survived.

A 404 carries no information a per-path label could give an operator that the
count alone does not, so collapsing it costs nothing and closes the door.
"""

UNMATCHED_STATUSES = frozenset({404, 405})


def _route_label(scope: dict, status: int = 200) -> str:
    """Templated path where the router supplies one, constant otherwise.

    `/api/targets/{address}` is one series; `/api/targets/10.10.10.42` is one
    series per host in the engagement. Starlette populates `scope["route"]`
    before the response starts, so by the time the `finally` runs the template
    is available -- but only for matched routes.

    Where the router matched nothing at all -- a 404, or a 405 for a method
    the route does not serve -- the label is `_unmatched` rather than the path
    the caller chose. See RC-23.
    """
    route = scope.get("route")
    template = (getattr(route, "path_format", None)
                or getattr(route, "path", None))
    if template:
        return str(template)
    if status in UNMATCHED_STATUSES:
        return UNMATCHED_ROUTE
    return str(scope.get("path", "unknown"))
