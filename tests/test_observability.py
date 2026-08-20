"""Observability: JSON logging, correlation context, metrics, exposition.

Adversarial bias, same as the rest of the suite. The interesting cases here
are the ones where the thing being observed is hostile or broken: an extra
that cannot be serialised, a principal name full of control characters, fifty
attacker-chosen label values arriving at a registry with room for five.

Every assertion pins a value. "More than zero scans" is exactly the kind of
test the mutation pass ate 47 of.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import random

import pytest

from reconkg import demo
from reconkg.engine import DiscoveryEngine, default_pipeline
from reconkg.models import Fingerprint, Provenance
from reconkg.observability import (CARDINALITY_METRIC, COUNTER,
                                   DEFAULT_DURATION_BUCKETS, DISPUTED_MARKER,
                                   HISTOGRAM, MAX_LABEL_VALUE_LEN,
                                   OVERFLOW_LABEL, PROMETHEUS_CONTENT_TYPE,
                                   Correlation, CorrelationMiddleware,
                                   JsonFormatter, MetricSpec, Metrics,
                                   StoreMetricsSubscriber, bind_correlation,
                                   correlation_scope, current_correlation,
                                   default_specs, new_request_id,
                                   record_scan_report, reset_correlation)
from reconkg.stages import EvidenceSource
from reconkg.store import ChangeEvent, EventKind, TargetStore
from reconkg.vulnref import DEFAULT_REFERENCE, CorrelationConfig, build_leads

TARGET = demo.TARGET


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def make_record(msg="hello", level=logging.INFO, name="reconkg.test",
                **extra) -> logging.LogRecord:
    record = logging.LogRecord(name=name, level=level, pathname=__file__,
                               lineno=42, msg=msg, args=(), exc_info=None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def emit(formatter: JsonFormatter, **kwargs) -> dict:
    return json.loads(formatter.format(make_record(**kwargs)))


@pytest.fixture(autouse=True)
def _clean_context():
    """A leaked correlation binding would make later tests pass for the wrong
    reason, which is worse than failing."""
    token = bind_correlation(request_id="test-setup")
    reset_correlation(token)
    yield
    from reconkg import observability
    observability._correlation.set(None)


# --------------------------------------------------------------------------- #
# JSON formatter
# --------------------------------------------------------------------------- #

def test_formatter_emits_the_expected_keys():
    line = JsonFormatter().format(make_record("pipeline complete"))
    assert "\n" not in line  # one object per line, always
    parsed = json.loads(line)
    assert set(parsed) == {"ts", "level", "logger", "message"}
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "reconkg.test"
    assert parsed["message"] == "pipeline complete"
    assert parsed["ts"].endswith("Z")


def test_formatter_interpolates_args_and_carries_extras():
    formatter = JsonFormatter()
    record = logging.LogRecord("reconkg.engine", logging.WARNING, __file__, 7,
                               "slot %s exhausted after %d", ("web-layer", 3),
                               None)
    record.slot = "web-layer"
    record.attempts = 3
    parsed = json.loads(formatter.format(record))
    assert parsed["message"] == "slot web-layer exhausted after 3"
    assert parsed["slot"] == "web-layer"
    assert parsed["attempts"] == 3
    assert parsed["level"] == "WARNING"


def test_formatter_static_fields_and_source():
    formatter = JsonFormatter(static_fields={"service": "reconkg"},
                              include_source=True)
    parsed = emit(formatter)
    assert parsed["service"] == "reconkg"
    assert parsed["source"].endswith(":42")


def test_formatter_records_exceptions():
    try:
        raise KeyError("no such host")
    except KeyError:
        import sys
        record = logging.LogRecord("reconkg.store", logging.ERROR, __file__,
                                   1, "boom", (), sys.exc_info())
    parsed = json.loads(JsonFormatter().format(record))
    assert parsed["exc_type"] == "KeyError"
    assert "KeyError: 'no such host'" in parsed["exc_text"]


class _Exploding:
    def __repr__(self):
        raise RuntimeError("repr is a trap")


def test_non_serialisable_extra_degrades_without_losing_the_line():
    """The point of the whole formatter: never take out the log call."""
    parsed = emit(JsonFormatter(), msg="submitted", payload=object(),
                  principal="scanner-a")
    assert parsed["message"] == "submitted"
    assert parsed["principal"] == "scanner-a"
    assert parsed["payload"].startswith("<object object at")


def test_extra_whose_repr_raises_still_emits():
    parsed = emit(JsonFormatter(), msg="hostile", boom=_Exploding())
    assert parsed["message"] == "hostile"
    assert parsed["boom"] == "<unreprable _Exploding: RuntimeError>"


def test_circular_extra_degrades_and_is_flagged():
    """`default=` is never consulted for a self-referential list -- json
    raises ValueError instead -- so this exercises the second attempt."""
    loop: list = [1, 2]
    loop.append(loop)
    parsed = emit(JsonFormatter(), msg="cycle", graph=loop, ok=1)
    assert parsed["log_extras_degraded"] is True
    assert parsed["message"] == "cycle"
    assert parsed["graph"] == "[1, 2, [...]]"
    assert parsed["ok"] == "1"  # everything degrades together, by repr


def test_formatter_never_raises_across_a_pile_of_awkward_extras():
    formatter = JsonFormatter()
    cycle: dict = {}
    cycle["self"] = cycle
    awkward = [object(), _Exploding(), cycle, {1: "int key"},
               {(1, 2): "tuple key"}, b"\xff\xfe", float("nan"),
               range(3), lambda: None]
    for index, value in enumerate(awkward):
        line = formatter.format(make_record(msg=f"case{index}", value=value))
        assert json.loads(line)["message"] == f"case{index}"


def test_formatter_picks_up_correlation_without_being_asked():
    formatter = JsonFormatter()
    with correlation_scope(request_id="req-1", principal="scanner-a",
                           target=TARGET):
        parsed = emit(formatter, msg="deep in the engine")
    assert parsed["request_id"] == "req-1"
    assert parsed["principal"] == "scanner-a"
    assert parsed["target"] == TARGET
    # and it is gone again once the scope closes
    assert "request_id" not in emit(formatter)


# --------------------------------------------------------------------------- #
# Correlation context
# --------------------------------------------------------------------------- #

def test_bind_merges_rather_than_replacing():
    with correlation_scope(request_id="req-9", principal="ops"):
        with correlation_scope(target=TARGET):
            corr = current_correlation()
            assert corr == Correlation("req-9", "ops", TARGET)
        assert current_correlation() == Correlation("req-9", "ops", None)
    assert current_correlation() is None


def test_correlation_fields_are_sanitised_and_bounded():
    """RC-04 lineage: a CRLF in a correlation id would forge a second JSON
    log record in whatever ships these lines."""
    with correlation_scope(request_id="a\r\nb", principal="x" * 500):
        corr = current_correlation()
    assert corr.request_id == "a__b"
    assert len(corr.principal) == 128


def test_request_ids_are_distinct():
    assert len({new_request_id() for _ in range(2000)}) == 2000


async def test_concurrent_tasks_keep_separate_correlation_ids():
    """24 interleaved tasks, each pausing at a random point mid-scope.

    If the context were a module global or a mutable object shared by
    reference, the sleeps would let a later task overwrite an earlier one's
    binding and the assertion would catch it.
    """
    formatter = JsonFormatter()
    seen: dict[int, set] = {}

    async def worker(index: int) -> None:
        rid = f"req-{index:03d}"
        with correlation_scope(request_id=rid, principal=f"p{index}",
                               target=f"10.0.0.{index}"):
            observed = set()
            for _ in range(5):
                await asyncio.sleep(random.random() / 1000)
                line = json.loads(formatter.format(make_record(msg="tick")))
                observed.add((line["request_id"], line["principal"],
                              line["target"]))
            seen[index] = observed
        assert current_correlation() is None

    await asyncio.gather(*(worker(i) for i in range(24)))

    assert len(seen) == 24
    for index, observed in seen.items():
        assert observed == {(f"req-{index:03d}", f"p{index}",
                             f"10.0.0.{index}")}


async def test_child_task_inherits_but_cannot_leak_back():
    """asyncio copies the context at task creation: the child sees the
    parent's binding, and rebinding in the child is invisible to the parent."""
    with correlation_scope(request_id="parent", target="10.0.0.1"):
        async def child():
            assert current_correlation().request_id == "parent"
            bind_correlation(request_id="child", target="10.0.0.2")
            return current_correlation()

        inner = await asyncio.create_task(child())
        assert inner == Correlation("child", None, "10.0.0.2")
        assert current_correlation() == Correlation("parent", None, "10.0.0.1")


async def test_reset_with_a_foreign_token_clears_instead_of_raising():
    holder = {}

    async def binder():
        holder["token"] = bind_correlation(request_id="other-task")

    await asyncio.create_task(binder())
    bind_correlation(request_id="mine")
    reset_correlation(holder["token"])  # token belongs to a dead context
    assert current_correlation() is None


# --------------------------------------------------------------------------- #
# Metrics: counters and histograms
# --------------------------------------------------------------------------- #

def test_counter_arithmetic_is_exact():
    m = Metrics()
    for _ in range(7):
        m.inc("reconkg_evidence_submissions_total", principal="scanner-a",
              tool="nmap-sV")
    m.inc("reconkg_evidence_submissions_total", 3.0, principal="scanner-b",
          tool="whatweb")
    assert m.counter_value("reconkg_evidence_submissions_total",
                           principal="scanner-a", tool="nmap-sV") == 7.0
    assert m.counter_value("reconkg_evidence_submissions_total",
                           principal="scanner-b", tool="whatweb") == 3.0
    assert m.counter_value("reconkg_evidence_submissions_total",
                           principal="nobody", tool="nmap-sV") == 0.0
    assert m.total("reconkg_evidence_submissions_total") == 10.0


def test_counter_rejects_wrong_labels_and_unknown_names():
    m = Metrics()
    with pytest.raises(KeyError):
        m.inc("reconkg_nonexistent_total", reason="x")
    with pytest.raises(ValueError):
        m.inc("reconkg_auth_failures_total", raeson="typo")
    with pytest.raises(ValueError):
        m.inc("reconkg_auth_failures_total", reason="x", extra="y")
    with pytest.raises(ValueError):
        m.inc("reconkg_auth_failures_total", -1.0, reason="x")
    with pytest.raises(TypeError):
        m.inc("reconkg_stage_duration_seconds", slot="a", stage="b")
    with pytest.raises(TypeError):
        m.observe("reconkg_auth_failures_total", 1.0, reason="x")


def test_label_values_are_sanitised_and_truncated():
    m = Metrics()
    m.inc("reconkg_auth_failures_total", reason="bad\r\ntoken\x00")
    m.inc("reconkg_auth_failures_total", reason="z" * 300)
    m.inc("reconkg_auth_failures_total", reason="")
    assert m.counter_value("reconkg_auth_failures_total",
                           reason="badtoken") == 1.0
    long = "z" * (MAX_LABEL_VALUE_LEN - 1) + "\u2026"
    assert m.counter_value("reconkg_auth_failures_total", reason=long) == 1.0
    assert m.counter_value("reconkg_auth_failures_total",
                           reason="unset") == 1.0


def test_histogram_buckets_are_placed_exactly():
    m = Metrics([MetricSpec("t_seconds", "Test.", HISTOGRAM, (),
                            (1.0, 2.0, 5.0))])
    for value in (0.5, 1.0, 3.0, 10.0):
        m.observe("t_seconds", value)
    hist = m.histogram("t_seconds")
    assert hist.counts == [2, 0, 1, 1]          # per-bucket, not cumulative
    assert hist.cumulative() == [2, 2, 3, 4]    # le=1, le=2, le=5, le=+Inf
    assert hist.count == 4
    assert hist.sum == 14.5
    assert m.total("t_seconds") == 4.0


def test_histogram_boundary_is_inclusive_and_nan_is_refused():
    m = Metrics([MetricSpec("t_seconds", "Test.", HISTOGRAM, (), (1.0,))])
    m.observe("t_seconds", 1.0)
    assert m.histogram("t_seconds").cumulative() == [1, 1]
    with pytest.raises(ValueError):
        m.observe("t_seconds", float("nan"))


def test_default_histogram_buckets_are_used_when_unspecified():
    m = Metrics()
    m.observe("reconkg_snapshot_duration_seconds", 0.3)
    hist = m.histogram("reconkg_snapshot_duration_seconds")
    assert hist.bounds == DEFAULT_DURATION_BUCKETS
    assert hist.cumulative() == [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]


def test_metric_spec_validation():
    with pytest.raises(ValueError):
        MetricSpec("1bad", "help")
    with pytest.raises(ValueError):
        MetricSpec("ok_total", "   ")
    with pytest.raises(ValueError):
        MetricSpec("ok_total", "help", COUNTER, ("bad-label",))
    with pytest.raises(ValueError):
        MetricSpec("ok_seconds", "help", HISTOGRAM, ("le",))
    with pytest.raises(ValueError):
        MetricSpec("ok_total", "help", COUNTER, ("a", "a"))
    with pytest.raises(ValueError):
        MetricSpec("ok_seconds", "help", HISTOGRAM, (), (2.0, 1.0))
    with pytest.raises(ValueError):
        MetricSpec("ok_seconds", "help", HISTOGRAM, (),
                   (1.0, float("inf")))
    with pytest.raises(ValueError):
        MetricSpec("ok_total", "help", COUNTER, (), (1.0,))
    with pytest.raises(ValueError):
        Metrics([MetricSpec("a_total", "h"), MetricSpec("a_total", "h")])


def test_default_registry_declares_every_mandated_metric():
    names = set(Metrics().names())
    assert {"reconkg_scans_started_total", "reconkg_scans_finished_total",
            "reconkg_stage_outcomes_total", "reconkg_leads_total",
            "reconkg_leads_disputed_total",
            "reconkg_evidence_submissions_total",
            "reconkg_ratelimit_rejections_total",
            "reconkg_auth_failures_total", "reconkg_snapshot_saves_total"
            } <= names
    assert len(names) == len(default_specs())


# --------------------------------------------------------------------------- #
# Bounded cardinality (RC-03 / RC-18 lineage)
# --------------------------------------------------------------------------- #

def test_cardinality_cap_holds_and_conserves_the_total():
    m = Metrics(max_series=5)
    for index in range(50):
        m.inc("reconkg_evidence_submissions_total",
              principal=f"attacker-{index}", tool="nmap-sV")

    family_series = m.snapshot()["counters"][
        "reconkg_evidence_submissions_total"]["series"]
    # five retained combinations plus one _other bucket, never fifty
    assert len(family_series) == 6
    assert m.total("reconkg_evidence_submissions_total") == 50.0

    kept = {s["labels"]["principal"]: s["value"] for s in family_series}
    assert kept == {"attacker-0": 1.0, "attacker-1": 1.0, "attacker-2": 1.0,
                    "attacker-3": 1.0, "attacker-4": 1.0,
                    OVERFLOW_LABEL: 45.0}
    # every label of an overflowed series collapses, not just the hot one
    overflow = [s for s in family_series
                if s["labels"]["principal"] == OVERFLOW_LABEL][0]
    assert overflow["labels"]["tool"] == OVERFLOW_LABEL


def test_overflow_series_keeps_absorbing_and_meta_counter_agrees():
    m = Metrics(max_series=2)
    for index in range(10):
        m.inc("reconkg_auth_failures_total", reason=f"reason-{index}")
    for _ in range(4):
        m.inc("reconkg_auth_failures_total", reason="reason-9")  # already hot

    assert m.total("reconkg_auth_failures_total") == 14.0
    assert m.counter_value("reconkg_auth_failures_total",
                           reason=OVERFLOW_LABEL) == 12.0
    assert m.counter_value(CARDINALITY_METRIC,
                           metric="reconkg_auth_failures_total") == 12.0
    snap = m.snapshot()["cardinality"]
    assert snap["max_series_per_metric"] == 2
    assert snap["capped_observations"]["reconkg_auth_failures_total"] == 12
    assert snap["series_in_use"]["reconkg_auth_failures_total"] == 3


def test_histogram_cardinality_cap_conserves_observations():
    m = Metrics(max_series=3)
    for index in range(20):
        m.observe("reconkg_scan_duration_seconds", 0.02,
                  target=f"10.0.0.{index}")
    assert m.total("reconkg_scan_duration_seconds") == 20.0
    overflow = m.histogram("reconkg_scan_duration_seconds",
                           target=OVERFLOW_LABEL)
    assert overflow.count == 17
    assert overflow.sum == pytest.approx(0.34)


def test_cardinality_meta_counter_does_not_recurse():
    """The meta-counter is itself label-keyed, so it must be able to overflow
    without trying to report its own overflow."""
    m = Metrics(max_series=1)
    for index in range(6):
        m.inc("reconkg_auth_failures_total", reason=f"r{index}")
        m.inc("reconkg_leads_total", target=f"t{index}")
    assert m.total("reconkg_auth_failures_total") == 6.0
    assert m.total("reconkg_leads_total") == 6.0
    assert m.total(CARDINALITY_METRIC) == 10.0
    assert len(m.snapshot()["counters"][CARDINALITY_METRIC]["series"]) == 2


def test_max_series_must_be_positive():
    with pytest.raises(ValueError):
        Metrics(max_series=0)


# --------------------------------------------------------------------------- #
# Exposition
# --------------------------------------------------------------------------- #

def test_render_prometheus_matches_expected_lines_exactly():
    m = Metrics([
        MetricSpec("test_requests_total", "Requests served.", COUNTER,
                   ("route",)),
        MetricSpec("test_latency_seconds", "Latency.", HISTOGRAM, (),
                   (0.1, 1.0)),
    ])
    m.inc("test_requests_total", route="/a")
    m.inc("test_requests_total", route="/a")
    m.inc("test_requests_total", route="/b")
    for value in (0.25, 0.5, 4.0):
        m.observe("test_latency_seconds", value)

    assert m.render_prometheus() == (
        "# HELP test_latency_seconds Latency.\n"
        "# TYPE test_latency_seconds histogram\n"
        'test_latency_seconds_bucket{le="0.1"} 0\n'
        'test_latency_seconds_bucket{le="1"} 2\n'
        'test_latency_seconds_bucket{le="+Inf"} 3\n'
        "test_latency_seconds_sum 4.75\n"
        "test_latency_seconds_count 3\n"
        "# HELP test_requests_total Requests served.\n"
        "# TYPE test_requests_total counter\n"
        'test_requests_total{route="/a"} 2\n'
        'test_requests_total{route="/b"} 1\n'
    )


def test_render_prometheus_structural_invariants():
    m = Metrics()
    m.inc("reconkg_leads_total", target=TARGET)
    m.observe("reconkg_stage_duration_seconds", 0.4, slot="web-layer",
              stage="http-app-probe")
    text = m.render_prometheus()

    assert text.endswith("\n")            # spec: last line ends with a LF
    lines = text.split("\n")[:-1]
    assert lines, "empty exposition"
    for line in lines:
        assert line == line.rstrip(), f"trailing whitespace: {line!r}"
        assert line.strip(), "blank line in body"

    # HELP/TYPE exist exactly once per registered family and precede samples
    for name in m.names():
        assert lines.count(f"# TYPE {name} counter") + \
            lines.count(f"# TYPE {name} histogram") == 1
        assert len([l for l in lines if l.startswith(f"# HELP {name} ")]) == 1
        type_at = next(i for i, l in enumerate(lines)
                       if l.startswith(f"# TYPE {name} "))
        samples = [i for i, l in enumerate(lines)
                   if l.startswith(name) and not l.startswith("#")]
        assert all(i > type_at for i in samples)

    # +Inf bucket must equal _count
    inf = next(l for l in lines
               if l.startswith("reconkg_stage_duration_seconds_bucket")
               and 'le="+Inf"' in l)
    count = next(l for l in lines
                 if l.startswith("reconkg_stage_duration_seconds_count"))
    assert inf.rsplit(" ", 1)[1] == count.rsplit(" ", 1)[1] == "1"
    assert PROMETHEUS_CONTENT_TYPE == \
        "text/plain; version=0.0.4; charset=utf-8"


def test_render_prometheus_escapes_help_and_label_values():
    m = Metrics([MetricSpec("test_paths_total",
                            'Windows paths, e.g. C:\\dir and a "quote".',
                            COUNTER, ("path",))])
    m.inc("test_paths_total", path='C:\\dir\\"x"')
    assert m.render_prometheus() == (
        "# HELP test_paths_total Windows paths, e.g. C:\\\\dir and a "
        '"quote".\n'
        "# TYPE test_paths_total counter\n"
        'test_paths_total{path="C:\\\\dir\\\\\\"x\\""} 1\n'
    )


def test_render_prometheus_samples_are_uniquely_keyed():
    """Duplicate name+labels is undefined ingestion behaviour per the spec."""
    m = Metrics()
    for index in range(400):  # well past the cap, forcing overflow reuse
        m.inc("reconkg_evidence_submissions_total", principal=f"p{index}",
              tool=f"t{index}")
    samples = [l.rsplit(" ", 1)[0] for l in m.render_prometheus().split("\n")
               if l and not l.startswith("#")]
    assert len(samples) == len(set(samples))


def test_snapshot_is_json_serialisable_and_reports_totals():
    m = Metrics()
    m.inc("reconkg_snapshot_saves_total", result="ok")
    m.inc("reconkg_snapshot_saves_total", 2.0, result="error")
    m.observe("reconkg_snapshot_duration_seconds", 0.02)
    snap = json.loads(json.dumps(m.snapshot()))
    saves = snap["counters"]["reconkg_snapshot_saves_total"]
    assert saves["total"] == 3.0
    assert saves["labels"] == ["result"]
    assert saves["series"] == [
        {"labels": {"result": "error"}, "value": 2.0},
        {"labels": {"result": "ok"}, "value": 1.0},
    ]
    duration = snap["histograms"]["reconkg_snapshot_duration_seconds"]
    assert duration["total"] == 1
    assert duration["series"][0]["count"] == 1
    assert duration["series"][0]["buckets"]["0.025"] == 1
    assert duration["series"][0]["buckets"]["+Inf"] == 1


def test_reset_clears_everything():
    m = Metrics(max_series=1)
    for index in range(4):
        m.inc("reconkg_leads_total", target=f"t{index}")
    m.reset()
    assert m.total("reconkg_leads_total") == 0.0
    assert m.snapshot()["cardinality"]["capped_observations"] == {}
    assert m.snapshot()["cardinality"]["series_in_use"] == {}


def test_metrics_time_contextmanager_records_one_observation():
    m = Metrics()
    with m.time("reconkg_snapshot_duration_seconds"):
        pass
    hist = m.histogram("reconkg_snapshot_duration_seconds")
    assert hist.count == 1
    assert hist.sum >= 0.0


# --------------------------------------------------------------------------- #
# Store subscriber against a real pipeline
# --------------------------------------------------------------------------- #

async def run_pipeline(evidence=None) -> tuple[Metrics, TargetStore,
                                               StoreMetricsSubscriber, object]:
    store = TargetStore()
    metrics = Metrics()
    subscriber = StoreMetricsSubscriber(metrics)
    subscriber.attach(store)
    engine = DiscoveryEngine(store, evidence or demo.build_evidence(),
                             default_pipeline())
    report = await engine.run(TARGET)
    return metrics, store, subscriber, report


async def test_subscriber_counts_a_real_pipeline_run_exactly():
    m, store, subscriber, report = await run_pipeline()

    assert subscriber.errors == 0
    assert subscriber.handled == store.events_emitted == 30

    assert m.counter_value("reconkg_scans_started_total", target=TARGET) == 1.0
    assert m.counter_value("reconkg_scans_finished_total", target=TARGET,
                           result="ok") == 1.0
    assert m.counter_value("reconkg_scans_finished_total", target=TARGET,
                           result="exhausted") == 0.0
    assert m.counter_value("reconkg_leads_total", target=TARGET) == 3.0
    assert len(report.ledger) == 3
    assert m.counter_value("reconkg_leads_disputed_total",
                           target=TARGET) == 0.0

    # the demo scenario: SYN sweep times out, banner probe is ambiguous,
    # both fallbacks succeed, the web layer succeeds first time.
    outcomes = {(s["labels"]["slot"], s["labels"]["stage"],
                 s["labels"]["outcome"]): s["value"]
                for s in m.snapshot()["counters"][
                    "reconkg_stage_outcomes_total"]["series"]}
    assert outcomes == {
        ("port-discovery", "port-sweep", "timeout"): 1.0,
        ("port-discovery", "connect-sweep", "success"): 1.0,
        ("service-id", "banner-probe", "ambiguous"): 1.0,
        ("service-id", "deep-probe", "success"): 1.0,
        ("web-layer", "http-app-probe", "success"): 1.0,
    }
    assert m.total("reconkg_stage_outcomes_total") == 5.0
    assert m.total("reconkg_stage_duration_seconds") == 5.0

    events = {s["labels"]["kind"]: s["value"] for s in m.snapshot()[
        "counters"]["reconkg_change_events_total"]["series"]}
    assert events == {"host.added": 1.0, "port.added": 3.0,
                      "service.set": 4.0, "fingerprint.added": 3.0,
                      "fingerprint.confidence_changed": 3.0,
                      "lead.added": 3.0, "stage.started": 5.0,
                      "stage.finished": 5.0, "pipeline.started": 1.0,
                      "pipeline.finished": 1.0, "ledger.ready": 1.0}
    assert m.total("reconkg_change_events_total") == 30.0

    # only the ambiguous banner probe downgrades anything
    assert m.counter_value("reconkg_fingerprint_downgrades_total",
                           target=TARGET,
                           reason="banner-probe:ambiguous") == 1.0
    assert m.total("reconkg_fingerprint_downgrades_total") == 1.0

    # ScanReport-derived metrics: one fallback per slot that fell back
    record_scan_report(m, report)
    assert m.counter_value("reconkg_stage_fallbacks_total",
                           slot="port-discovery") == 1.0
    assert m.counter_value("reconkg_stage_fallbacks_total",
                           slot="service-id") == 1.0
    assert m.counter_value("reconkg_stage_fallbacks_total",
                           slot="web-layer") == 0.0
    assert m.total("reconkg_scan_duration_seconds") == 1.0


async def test_subscriber_counts_disputed_leads_from_a_real_contradiction():
    """whatweb claims 2.4.50 where the deep probe said 2.4.49. Two credible
    peers, same product, different versions: both leads are disputed."""
    evidence = EvidenceSource()
    for (tool, address), data in demo.FIXTURES.items():
        payload = copy.deepcopy(data)
        if tool == "whatweb":
            payload["apps"][0]["version"] = "2.4.50"
            payload["apps"][0]["cpe"] = "cpe:/a:apache:http_server:2.4.50"
        evidence.put(tool, address, payload,
                     principal=demo.PRINCIPALS.get(tool, "unknown"))

    m, _store, subscriber, report = await run_pipeline(evidence)
    assert subscriber.errors == 0
    assert len(report.ledger) == 4
    assert sum(1 for row in report.ledger if row.disputed) == 2
    assert m.counter_value("reconkg_leads_total", target=TARGET) == 4.0
    assert m.counter_value("reconkg_leads_disputed_total",
                           target=TARGET) == 2.0


def test_disputed_marker_still_matches_what_vulnref_writes():
    """The subscriber sniffs a string out of the rationale because the event
    stream carries nothing else. Pin the coupling so a reword fails here
    rather than silently zeroing the disputed counter forever."""
    fingerprint = Fingerprint(
        product="Apache httpd", version="2.4.49",
        provenance=Provenance(source_tool="nmap-sV", principal="scanner-a",
                              confidence=0.9))
    leads = build_leads(fingerprint, DEFAULT_REFERENCE, CorrelationConfig(),
                        None, True)
    assert leads, "expected at least one Apache 2.4.49 lead"
    assert all(DISPUTED_MARKER in lead.rationale for lead in leads)
    clean = build_leads(fingerprint, DEFAULT_REFERENCE, CorrelationConfig(),
                        None, False)
    assert all(DISPUTED_MARKER not in lead.rationale for lead in clean)


async def test_subscriber_handles_the_rejected_observation_event_shape():
    """`stage.finished` is overloaded; the RC-02 variant carries no outcome
    and must not create a bogus outcome series."""
    m = Metrics()
    subscriber = StoreMetricsSubscriber(m)
    await subscriber(ChangeEvent(
        kind=EventKind.STAGE_FINISHED, target=TARGET, path=TARGET,
        payload={"stage": "banner-probe", "rejected_observations": 3,
                 "note": "malformed evidence discarded"}))
    assert m.counter_value("reconkg_rejected_observations_total",
                           stage="banner-probe") == 3.0
    assert m.total("reconkg_stage_outcomes_total") == 0.0
    assert m.total("reconkg_stage_duration_seconds") == 0.0
    assert subscriber.errors == 0


async def test_subscriber_swallows_its_own_failures():
    """A broken subscriber must not stall the pipeline, and must not emit one
    traceback per graph mutation either."""
    class Broken(StoreMetricsSubscriber):
        def _handle(self, event):
            raise RuntimeError("instrumentation bug")

    store = TargetStore()
    subscriber = Broken(Metrics())
    subscriber.attach(store)
    report = await DiscoveryEngine(store, demo.build_evidence(),
                                   default_pipeline()).run(TARGET)
    assert len(report.ledger) == 3          # pipeline unaffected
    assert subscriber.errors == store.events_emitted == 30
    assert subscriber.handled == 0


async def test_subscriber_survives_a_malformed_event():
    m = Metrics()
    subscriber = StoreMetricsSubscriber(m)

    class Junk:
        kind = "not.an.enum"
        target = None
        payload = None

    await subscriber(Junk())
    assert subscriber.errors == 0
    assert m.counter_value("reconkg_change_events_total",
                           kind="not.an.enum") == 1.0


async def test_unsubscribe_stops_the_counting():
    store = TargetStore()
    m = Metrics()
    unsubscribe = StoreMetricsSubscriber(m).attach(store)
    await store.ensure_host(TARGET, Provenance(source_tool="operator",
                                               principal="system",
                                               confidence=1.0))
    unsubscribe()
    unsubscribe()  # idempotent, per TargetStore.subscribe
    await store.ensure_host("10.10.10.43", Provenance(
        source_tool="operator", principal="system", confidence=1.0))
    assert m.counter_value("reconkg_change_events_total",
                           kind="host.added") == 1.0


async def test_two_concurrent_scans_do_not_blur_targets():
    store = TargetStore()
    m = Metrics()
    StoreMetricsSubscriber(m).attach(store)
    engine = DiscoveryEngine(store, demo.build_evidence(), default_pipeline())

    other = "10.10.10.43"
    evidence = engine.evidence
    for (tool, _address), data in demo.FIXTURES.items():
        evidence.put(tool, other, copy.deepcopy(data),
                     principal=demo.PRINCIPALS.get(tool, "unknown"))

    await asyncio.gather(engine.run(TARGET), engine.run(other))
    assert m.counter_value("reconkg_scans_started_total", target=TARGET) == 1.0
    assert m.counter_value("reconkg_scans_started_total", target=other) == 1.0
    assert m.counter_value("reconkg_leads_total", target=TARGET) == 3.0
    assert m.counter_value("reconkg_leads_total", target=other) == 3.0
    assert m.total("reconkg_leads_total") == 6.0


# --------------------------------------------------------------------------- #
# ASGI middleware
# --------------------------------------------------------------------------- #

async def call_asgi(middleware, path="/api/health", method="GET",
                    headers=None):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": path,
             "headers": headers or []}
    await middleware(scope, receive, send)
    return sent


async def test_middleware_binds_a_request_id_and_echoes_it():
    seen = {}

    async def app(scope, receive, send):
        seen["corr"] = current_correlation()
        await send({"type": "http.response.start", "status": 201,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b"{}"})

    m = Metrics()
    sent = await call_asgi(CorrelationMiddleware(app, m), path="/api/evidence",
                           method="POST")

    assert seen["corr"].request_id and len(seen["corr"].request_id) == 16
    echoed = dict(sent[0]["headers"])[b"x-request-id"].decode()
    assert echoed == seen["corr"].request_id
    assert current_correlation() is None  # scope closed

    assert m.counter_value("reconkg_http_requests_total", method="POST",
                           route="/api/evidence", status="201") == 1.0
    assert m.total("reconkg_http_request_duration_seconds") == 1.0


async def test_middleware_counts_a_raising_handler_as_500():
    async def app(scope, receive, send):
        raise RuntimeError("handler blew up")

    m = Metrics()
    with pytest.raises(RuntimeError):
        await call_asgi(CorrelationMiddleware(app, m))
    assert m.counter_value("reconkg_http_requests_total", method="GET",
                           route="/api/health", status="500") == 1.0


async def test_middleware_ignores_client_supplied_ids_by_default():
    seen = {}

    async def app(scope, receive, send):
        seen["id"] = current_correlation().request_id
        await send({"type": "http.response.start", "status": 200,
                    "headers": []})
        await send({"type": "http.response.body", "body": b""})

    hostile = [(b"x-request-id", b"forged\r\nSet-Cookie: x=1")]
    await call_asgi(CorrelationMiddleware(app), headers=hostile)
    assert seen["id"] != "forged"
    assert "\r" not in seen["id"] and "\n" not in seen["id"]

    await call_asgi(CorrelationMiddleware(app, trust_incoming_id=True),
                    headers=hostile)
    assert seen["id"] == "forged__Set-Cookie:_x_1"


async def test_middleware_passes_non_http_scopes_through_untouched():
    calls = []

    async def app(scope, receive, send):
        calls.append(scope["type"])

    m = Metrics()
    await CorrelationMiddleware(app, m)({"type": "websocket"}, None, None)
    assert calls == ["websocket"]
    assert m.total("reconkg_http_requests_total") == 0.0


async def test_middleware_prefers_the_route_template_over_the_raw_path():
    """Otherwise every host in the engagement becomes its own series."""
    class FakeRoute:
        path_format = "/api/targets/{address}"

    async def app(scope, receive, send):
        scope["route"] = FakeRoute()
        await send({"type": "http.response.start", "status": 200,
                    "headers": []})
        await send({"type": "http.response.body", "body": b""})

    m = Metrics()
    for octet in range(5):
        await call_asgi(CorrelationMiddleware(app, m),
                        path=f"/api/targets/10.0.0.{octet}")
    assert m.counter_value("reconkg_http_requests_total", method="GET",
                           route="/api/targets/{address}", status="200") == 5.0
    assert len(m.snapshot()["counters"]["reconkg_http_requests_total"]
               ["series"]) == 1
