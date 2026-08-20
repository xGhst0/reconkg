"""QA: fallback routing, isolation, confidence arithmetic, correlation, WS.

Adversarial bias -- most of these tests are about what happens when a stage
misbehaves, not when it works.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from reconkg.demo import FIXTURES, TARGET, build_evidence
from reconkg.engine import DiscoveryEngine, StageSlot, default_pipeline
from reconkg.events import QUEUE_MAX, ConnectionManager
from reconkg.models import (ExploitMaturity, Fingerprint, PortState,
                            Provenance, Service)
from reconkg.stages import (DiscoveryStage, EvidenceSource, FingerprintObs,
                            Outcome, PortObs, ServiceObs, StageResult)
from reconkg.store import EventKind, TargetStore
from reconkg.vulnref import (CorrelationConfig, VulnEntry, build_leads,
                             compare_versions, parse_version,
                             version_satisfies)


def prov(tool="test", confidence=0.8, principal=None):
    return Provenance(source_tool=tool, confidence=confidence,
                      principal=principal or tool)


# --------------------------------------------------------------------------- #
# Stubs
# --------------------------------------------------------------------------- #

class AlwaysFails(DiscoveryStage):
    name, technique, tool = "always-fails", "stub", "stub-fail"
    timeout_s = 1.0

    async def run(self, address, evidence, context):
        return StageResult(Outcome.NO_DATA, "nothing here")


class Explodes(DiscoveryStage):
    name, technique, tool = "explodes", "stub", "stub-boom"
    timeout_s = 1.0

    async def run(self, address, evidence, context):
        raise RuntimeError("adapter blew up")


class Hangs(DiscoveryStage):
    name, technique, tool = "hangs", "stub", "stub-hang"
    timeout_s = 0.05

    async def run(self, address, evidence, context):
        await asyncio.sleep(5)
        raise AssertionError("should have been cancelled")  # pragma: no cover


class Succeeds(DiscoveryStage):
    name, technique, tool = "succeeds", "stub", "stub-ok"
    timeout_s = 1.0

    def __init__(self):
        self.ran = False

    async def run(self, address, evidence, context):
        self.ran = True
        return StageResult(Outcome.SUCCESS, "ok",
                           [PortObs(number=8080, confidence=0.9)], [8080])


class BadObservation(DiscoveryStage):
    """Emits a service for a port nothing ever discovered."""
    name, technique, tool = "bad-obs", "stub", "stub-bad"
    timeout_s = 1.0

    async def run(self, address, evidence, context):
        return StageResult(Outcome.SUCCESS, "orphan",
                           [ServiceObs(port=9999, name="ghost")], [9999])


def engine_with(*stages, store=None, fallbacks=None):
    store = store or TargetStore()
    slot = StageSlot(stages[0], list(stages[1:]), label="slot")
    return store, DiscoveryEngine(store, EvidenceSource(), [slot])


# --------------------------------------------------------------------------- #
# Fallback routing
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_failure_falls_through_to_next_technique():
    ok = Succeeds()
    store, engine = engine_with(AlwaysFails(), ok)
    report = await engine.run("1.1.1.1")
    assert ok.ran
    assert [a.outcome for a in report.attempts] == ["no_data", "success"]
    assert report.exhausted_slots == []


@pytest.mark.asyncio
async def test_exception_is_isolated_not_propagated():
    ok = Succeeds()
    store, engine = engine_with(Explodes(), ok)
    report = await engine.run("1.1.1.1")
    assert report.attempts[0].outcome == "error"
    assert "adapter blew up" in report.attempts[0].detail
    assert ok.ran


@pytest.mark.asyncio
async def test_hanging_stage_is_timed_out_and_pipeline_continues():
    ok = Succeeds()
    store, engine = engine_with(Hangs(), ok)
    report = await engine.run("1.1.1.1")
    assert report.attempts[0].outcome == "timeout"
    assert report.attempts[0].duration_ms < 1000
    assert ok.ran


@pytest.mark.asyncio
async def test_all_techniques_failing_marks_slot_exhausted_and_exits_clean():
    store, engine = engine_with(AlwaysFails(), Explodes(), Hangs())
    report = await engine.run("1.1.1.1")
    assert report.exhausted_slots == ["slot"]
    assert len(report.attempts) == 3
    assert report.ok is False
    assert report.finished_at is not None  # clean exit, not a crash


@pytest.mark.asyncio
async def test_success_short_circuits_remaining_fallbacks():
    never = Succeeds()
    store, engine = engine_with(Succeeds(), never)
    report = await engine.run("1.1.1.1")
    assert len(report.attempts) == 1
    assert never.ran is False


@pytest.mark.asyncio
async def test_orphan_observation_is_dropped_without_killing_the_stage():
    store, engine = engine_with(BadObservation())
    report = await engine.run("1.1.1.1")
    assert report.attempts[0].outcome == "success"
    assert store.get("1.1.1.1").ports == []


# --------------------------------------------------------------------------- #
# Confidence arithmetic
# --------------------------------------------------------------------------- #

def test_independent_corroboration_raises_confidence():
    fp = Fingerprint(product="Apache httpd", version="2.4.49",
                     provenance=prov("nmap", 0.6, principal="scanner-a"))
    new = fp.observe(prov("whatweb", 0.6, principal="scanner-b"))
    assert new == pytest.approx(0.84)
    assert fp.corroborating_principals == {"scanner-a", "scanner-b"}


def test_same_principal_repeating_itself_does_not_compound():
    fp = Fingerprint(product="Apache httpd",
                     provenance=prov("nmap", 0.6, principal="scanner-a"))
    assert fp.observe(prov("nmap", 0.5, principal="scanner-a")) == 0.6
    assert fp.observe(prov("nmap", 0.7, principal="scanner-a")) == 0.7


def test_one_principal_rotating_tool_names_cannot_compound():
    """RC-01b regression: this was the corroboration-forgery primitive."""
    fp = Fingerprint(product="Apache httpd", version="2.4.49",
                     provenance=prov("nmap-sV", 0.3, principal="mallory"))
    for tool in ["nmap-sV-intensity9", "whatweb", "nessus", "openvas"]:
        fp.observe(prov(tool, 0.3, principal="mallory"))
    assert fp.confidence == 0.3
    assert len(fp.corroborating_principals) == 1
    assert build_leads(fp, [_APACHE], CorrelationConfig()) == []


def test_decay_is_recorded_in_the_provenance_log():
    fp = Fingerprint(product="Apache httpd", provenance=prov("nmap", 0.8))
    assert fp.decay(0.5, reason="ambiguous", source_tool="nmap") == 0.4
    assert "decayed" in fp.provenance_log[-1].note
    assert len(fp.provenance_log) == 2


def test_decay_rejects_nonsense_factors():
    fp = Fingerprint(provenance=prov())
    for bad in (0.0, -1.0, 1.5):
        with pytest.raises(ValueError):
            fp.decay(bad, reason="x", source_tool="t")


@pytest.mark.asyncio
async def test_ambiguous_result_downgrades_only_the_ambiguous_fingerprint():
    store = TargetStore()
    engine = DiscoveryEngine(store, build_evidence(),
                             default_pipeline())
    await engine.run(TARGET)
    port80 = store.get(TARGET).find_port(80)
    by_key = {f.key: f for f in port80.service.fingerprints}
    assert by_key["apache httpd/?"].confidence < 0.2      # downgraded
    assert by_key["apache httpd/2.4.49"].confidence > 0.9  # corroborated
    # Port 22 is untouched by the port-80 ambiguity. It does not reach 0.9
    # because both SSH observations come from one principal (scanner-a), so
    # they take the max rather than compounding.
    port22 = store.get(TARGET).find_port(22)
    fp22 = port22.service.fingerprints[0]
    assert fp22.confidence == pytest.approx(0.81)
    assert fp22.corroborating_principals == {"scanner-a"}


# --------------------------------------------------------------------------- #
# Version comparison and correlation
# --------------------------------------------------------------------------- #

def test_version_compare_is_numeric_not_lexical():
    assert parse_version("2.4.50") > parse_version("2.4.9")
    assert version_satisfies("2.4.50", ">", "2.4.9")
    assert version_satisfies("1.0.1f", "<", "1.0.1g")
    assert version_satisfies("2.4.49", ">=", "2.4.49")


def test_release_candidate_sorts_below_release():
    assert compare_versions("2.4.49rc1", "2.4.49") == -1
    assert version_satisfies("2.4.49rc1", "<", "2.4.49")


def test_missing_trailing_component_equals_zero():
    assert compare_versions("2.4", "2.4.0") == 0


def test_low_confidence_fingerprint_produces_no_leads():
    fp = Fingerprint(product="Apache httpd", version="2.4.49",
                     provenance=prov("nmap", 0.2))
    assert build_leads(fp, [_APACHE], CorrelationConfig()) == []


def test_unversioned_fingerprint_is_excluded_by_default():
    fp = Fingerprint(product="Apache httpd", provenance=prov("nmap", 0.9))
    assert build_leads(fp, [_APACHE], CorrelationConfig()) == []


def test_unversioned_fingerprint_can_be_opted_in_at_low_priority():
    fp = Fingerprint(product="Apache httpd", provenance=prov("nmap", 0.9))
    entry = VulnEntry("CVE-X", "t", "apache", (), 9.8,
                      ExploitMaturity.WEAPONISED, requires_version=False)
    cfg = CorrelationConfig(include_unversioned=True)
    leads = build_leads(fp, [entry], cfg)
    assert len(leads) == 1 and leads[0].priority < 0.4


def test_version_outside_range_does_not_match():
    fp = Fingerprint(product="Apache httpd", version="2.4.51",
                     provenance=prov("nmap", 0.95))
    assert build_leads(fp, [_APACHE], CorrelationConfig()) == []


def test_unparseable_version_is_rejected_not_crashed():
    fp = Fingerprint(product="Apache httpd", version="unknown-build",
                     provenance=prov("nmap", 0.95))
    assert build_leads(fp, [_APACHE], CorrelationConfig()) == []


def test_priority_is_clamped_to_one():
    fp = Fingerprint(product="Log4j", version="2.14.0",
                     provenance=prov("a", 0.99))
    fp.observe(prov("b", 0.99))
    fp.observe(prov("c", 0.99))
    entry = VulnEntry("CVE-2021-44228", "Log4Shell", "log4j",
                      ((">=", "2.0"), ("<", "2.15.0")), 10.0,
                      ExploitMaturity.WEAPONISED)
    assert build_leads(fp, [entry], CorrelationConfig())[0].priority <= 1.0


def test_leads_per_service_are_capped():
    fp = Fingerprint(product="Apache httpd", version="2.4.49",
                     provenance=prov("nmap", 0.95))
    many = [VulnEntry(f"CVE-{i}", "t", "apache", ((">=", "2.0"),), 5.0)
            for i in range(50)]
    assert len(build_leads(fp, many, CorrelationConfig(max_leads_per_service=3))) == 3


_APACHE = VulnEntry("CVE-2021-41773", "Apache RCE", "apache",
                    ((">=", "2.4.49"), ("<=", "2.4.49")), 9.8,
                    ExploitMaturity.WEAPONISED)


# --------------------------------------------------------------------------- #
# Ledger
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_ledger_ranks_corroborated_weaponised_match_first():
    store = TargetStore()
    engine = DiscoveryEngine(store, build_evidence(),
                             default_pipeline())
    report = await engine.run(TARGET)
    assert report.ledger[0].cve_id == "CVE-2021-41773"
    assert report.ledger == sorted(report.ledger,
                                   key=lambda r: (r.priority, r.cvss),
                                   reverse=True)
    assert all(0.0 <= r.priority <= 1.0 for r in report.ledger)
    assert "whatweb" in report.ledger[0].corroborated_by


@pytest.mark.asyncio
async def test_leads_are_deduplicated_across_reruns():
    store = TargetStore()
    engine = DiscoveryEngine(store, build_evidence(),
                             default_pipeline())
    await engine.run(TARGET)
    first = len(store.get(TARGET).all_leads())
    await engine.run(TARGET)
    assert len(store.get(TARGET).all_leads()) == first


# --------------------------------------------------------------------------- #
# Store and events
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_broken_subscriber_does_not_stall_the_pipeline():
    store = TargetStore()
    seen = []

    async def broken(event):
        raise RuntimeError("client handler bug")

    async def good(event):
        seen.append(event.kind)

    store.subscribe(broken)
    store.subscribe(good)
    engine = DiscoveryEngine(store, build_evidence(),
                             default_pipeline())
    report = await engine.run(TARGET)
    assert report.ledger
    assert EventKind.LEAD_ADDED in seen


@pytest.mark.asyncio
async def test_service_on_unknown_port_raises_keyerror():
    store = TargetStore()
    await store.ensure_host("2.2.2.2", prov())
    with pytest.raises(KeyError):
        await store.set_service("2.2.2.2", 80, Service(name="http",
                                                       provenance=prov()))


# --------------------------------------------------------------------------- #
# WebSocket fan-out
# --------------------------------------------------------------------------- #

class FakeWS:
    def __init__(self):
        self.sent = []
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def send_json(self, message):
        self.sent.append(message)


@pytest.mark.asyncio
async def test_broadcast_reaches_every_connected_client():
    store = TargetStore()
    manager = ConnectionManager(store)
    a, b = FakeWS(), FakeWS()
    await manager.connect(a, "a")
    await manager.connect(b, "b")

    engine = DiscoveryEngine(store, build_evidence(),
                             default_pipeline())
    await engine.run(TARGET)
    await asyncio.sleep(0.05)

    for ws in (a, b):
        kinds = [m.get("kind") for m in ws.sent if m["type"] == "change"]
        assert "lead.added" in kinds
        assert "fingerprint.confidence_changed" in kinds
    await manager.shutdown()


@pytest.mark.asyncio
async def test_target_filter_excludes_other_targets():
    store = TargetStore()
    manager = ConnectionManager(store)
    watcher = FakeWS()
    await manager.connect(watcher, "w", target_filter="9.9.9.9")

    engine = DiscoveryEngine(store, build_evidence(),
                             default_pipeline())
    await engine.run(TARGET)
    await asyncio.sleep(0.05)

    assert [m for m in watcher.sent if m["type"] == "change"] == []
    await manager.shutdown()


@pytest.mark.asyncio
async def test_new_client_receives_replay_of_recent_events():
    store = TargetStore()
    manager = ConnectionManager(store)
    engine = DiscoveryEngine(store, build_evidence(),
                             default_pipeline())
    await engine.run(TARGET)

    latecomer = FakeWS()
    await manager.connect(latecomer, "late")
    await asyncio.sleep(0.05)
    replayed = [m for m in latecomer.sent if m.get("replay")]
    assert replayed
    await manager.shutdown()


@pytest.mark.asyncio
async def test_slow_client_drops_events_instead_of_blocking():
    store = TargetStore()
    manager = ConnectionManager(store)

    class Stalled(FakeWS):
        async def send_json(self, message):
            await asyncio.sleep(3600)

    slow, fast = Stalled(), FakeWS()
    await manager.connect(slow, "slow")
    await manager.connect(fast, "fast")

    for i in range(QUEUE_MAX + 50):
        await manager.broadcast({"type": "noise", "i": i})
    await asyncio.sleep(0.05)

    # The stalled peer never blocks the broadcaster and its queue stays bounded.
    assert manager.sessions["slow"].queue.qsize() <= QUEUE_MAX
    assert slow.sent == []
    # The healthy peer keeps receiving, and is current with the newest event.
    assert fast.sent[-1]["i"] == QUEUE_MAX + 49
    # Loss is surfaced rather than hidden.
    assert any("_dropped_before" in m for m in fast.sent)
    await manager.shutdown()


# --------------------------------------------------------------------------- #
# The invariant that matters
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_full_pipeline_opens_no_outbound_connections(monkeypatch):
    """Security: trap the socket layer and run everything.

    If any future stage tries to talk to a target directly, this fails.
    """
    def forbidden(*args, **kwargs):
        raise AssertionError("outbound connection attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket.socket, "sendto", forbidden)

    store = TargetStore()
    manager = ConnectionManager(store)
    await manager.connect(FakeWS(), "observer")
    engine = DiscoveryEngine(store, build_evidence(),
                             default_pipeline())
    report = await engine.run(TARGET)
    assert report.ledger
    await manager.shutdown()


# --------------------------------------------------------------------------- #
# Downgrade semantics
# --------------------------------------------------------------------------- #

class SilentFallback(DiscoveryStage):
    """A fallback with nothing to say. Must not punish earlier findings."""
    name, technique, tool = "silent", "stub", "nmap-sV-intensity9"
    timeout_s = 1.0

    async def run(self, address, evidence, context):
        return StageResult(Outcome.NO_DATA, "no fixture")


@pytest.mark.asyncio
async def test_no_data_fallback_does_not_downgrade_earlier_fingerprints():
    """Regression: an empty scope_ports list meant "everything", so a
    NO_DATA fallback silently demoted fingerprints it never looked at."""
    from reconkg.builtin_modules import BannerProbeModule
    from reconkg.engine import DiscoveryEngine, StageSlot
    from reconkg.stages import EvidenceSource

    store = TargetStore()
    evidence = EvidenceSource()
    evidence.put("nmap-sT", "192.0.2.50",
                 {"ports": [{"number": 22, "state": "open"}]},
                 principal="scanner-a")
    evidence.put("nmap-sV", "192.0.2.50", {"services": [
        {"port": 22, "service": "ssh", "product": "OpenSSH",
         "version": "7.4", "confidence": 1.0}]}, principal="scanner-a")

    from reconkg.builtin_modules import ConnectSweepModule
    engine = DiscoveryEngine(store, evidence, [
        StageSlot(ConnectSweepModule(), label="ports"),
        StageSlot(BannerProbeModule(), [SilentFallback()], label="service-id"),
    ])
    report = await engine.run("192.0.2.50")

    fp = store.get("192.0.2.50").find_port(22).service.best_fingerprint()
    assert fp.confidence == 0.75          # ceiling for nmap-sV, not decayed
    assert any("decayed" in (p.note or "") for p in fp.provenance_log) is False
    assert any(r.cve_id == "CVE-2018-15473" for r in report.ledger)
