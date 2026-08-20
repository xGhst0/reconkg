"""Tests for the snapshot lifecycle.

Timings are deliberately tiny (tens of milliseconds) and every assertion is
on a counted value -- `saves == 1`, `skipped == 499`, `len(files) == 2` --
rather than on a direction. A debounce test that only says "fewer saves than
events" passes with an off-by-499 bug in it.
"""

from __future__ import annotations

import asyncio

import pytest

from reconkg import persistence, snapshots
from reconkg.snapshots import SnapshotManager
from reconkg.store import ChangeEvent, EventKind, TargetStore

QUIET = 0.05
STALE = 5.0


def _event(n: int = 0) -> ChangeEvent:
    return ChangeEvent(kind=EventKind.PORT_ADDED, target="10.10.10.42",
                       path=f"10.10.10.42/tcp:{1000 + n}", payload={"n": n})


@pytest.fixture
async def populated_store() -> TargetStore:
    from reconkg.builtin_modules import module_pipeline
    from reconkg.demo import TARGET, build_evidence
    from reconkg.engine import DiscoveryEngine

    store = TargetStore()
    await DiscoveryEngine(store, build_evidence(), module_pipeline()).run(TARGET)
    return store


@pytest.fixture
async def manager(tmp_path):
    """A started manager on an empty store; always closed, even on failure."""
    mgr = SnapshotManager(TargetStore(), tmp_path / "snaps",
                          retention=3, quiet_period=QUIET,
                          max_staleness=STALE).start()
    try:
        yield mgr
    finally:
        await mgr.aclose()


# --------------------------------------------------------------------------- #
# Debounce
# --------------------------------------------------------------------------- #

async def test_a_burst_of_500_events_produces_exactly_one_save(manager):
    for i in range(500):
        await manager.store.emit(_event(i))

    assert manager.pending is True
    assert manager.saves == 0            # nothing written during the burst

    await asyncio.sleep(QUIET * 6)

    assert manager.saves == 1
    assert manager.skipped == 499        # 500 events, 1 transaction
    assert manager.pending is False
    assert len(manager.snapshot_files()) == 1
    assert manager.last_saved_at is not None


async def test_two_separated_bursts_produce_two_saves(manager):
    for i in range(10):
        await manager.store.emit(_event(i))
    await asyncio.sleep(QUIET * 6)
    for i in range(10):
        await manager.store.emit(_event(i))
    await asyncio.sleep(QUIET * 6)

    assert manager.saves == 2
    assert manager.skipped == 18         # 9 coalesced per burst
    assert len(manager.snapshot_files()) == 2


async def test_an_idle_store_is_never_snapshotted(manager):
    await asyncio.sleep(QUIET * 6)
    assert manager.saves == 0
    assert manager.snapshot_files() == []


async def test_max_staleness_forces_a_save_under_continuous_load(tmp_path):
    """The failure this prevents: a scan that never goes quiet, so the
    quiet-period debounce never fires and nothing is ever written."""
    mgr = SnapshotManager(TargetStore(), tmp_path / "s", retention=10,
                          quiet_period=0.2, max_staleness=0.2).start()
    try:
        for _ in range(70):              # ~0.7s of unbroken traffic
            await mgr.store.emit(_event())
            await asyncio.sleep(0.01)
        assert mgr.saves >= 2            # ceiling fired at ~0.2s intervals
    finally:
        await mgr.aclose()


async def test_without_the_ceiling_continuous_load_never_saves(tmp_path):
    """Control for the test above: same load, ceiling out of reach, zero
    saves. Proves the saves above came from max_staleness and not from a
    gap in the traffic."""
    mgr = SnapshotManager(TargetStore(), tmp_path / "s", retention=10,
                          quiet_period=0.2, max_staleness=10.0).start()
    try:
        for _ in range(70):
            await mgr.store.emit(_event())
            await asyncio.sleep(0.01)
        assert mgr.saves == 0
        assert mgr.pending is True
    finally:
        await mgr.aclose()


# --------------------------------------------------------------------------- #
# Restore
# --------------------------------------------------------------------------- #

async def test_restore_round_trips_a_real_graph(populated_store, tmp_path):
    from reconkg.demo import TARGET

    mgr = SnapshotManager(populated_store, tmp_path / "s",
                          quiet_period=QUIET, max_staleness=STALE)
    path = await mgr.save_now()
    assert path.exists()

    fresh = TargetStore()
    reader = SnapshotManager(fresh, tmp_path / "s")
    assert await reader.restore_into(fresh) == 1
    assert reader.restores == 1

    original = populated_store.get(TARGET)
    back = fresh.get(TARGET)
    assert back is not None
    assert {p.number for p in back.ports} == {22, 80, 445}
    assert {p.number for p in back.ports} == {p.number for p in original.ports}

    fp = back.find_port(80).service.best_fingerprint()
    assert fp.version == "2.4.49"
    assert fp.confidence == original.find_port(80).service \
        .best_fingerprint().confidence
    assert fp.corroborating_principals == {"scanner-a", "scanner-b"}


async def test_restore_from_a_missing_directory_is_a_fresh_start(tmp_path):
    fresh = TargetStore()
    mgr = SnapshotManager(fresh, tmp_path / "never-created")
    assert await mgr.restore_into(fresh) == 0
    assert fresh.list_hosts() == []
    assert mgr.restores == 0


async def test_restore_skips_an_unreadable_newest_and_uses_the_older(
        populated_store, tmp_path):
    """A truncated newest snapshot must cost you the last few minutes, not
    the whole engagement."""
    from reconkg.demo import TARGET

    directory = tmp_path / "s"
    mgr = SnapshotManager(populated_store, directory, retention=5)
    good = await mgr.save_now()
    corrupt = directory / "snapshot-99999999T999999.999999-999999.sqlite"
    corrupt.write_bytes(b"this is not a database at all")

    fresh = TargetStore()
    reader = SnapshotManager(fresh, directory)
    assert await reader.restore_into(fresh) == 1
    assert reader.last_snapshot == good
    assert fresh.get(TARGET) is not None
    assert "restore" in reader.last_error


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #

async def test_retention_keeps_exactly_n_files_and_evicts_the_oldest(tmp_path):
    mgr = SnapshotManager(TargetStore(), tmp_path / "s", retention=2)
    written = [await mgr.save_now() for _ in range(4)]

    assert mgr.saves == 4
    assert mgr.snapshot_files() == written[-2:]
    assert len(mgr.snapshot_files()) == 2
    assert not written[0].exists()
    assert not written[1].exists()
    assert mgr.stats()["snapshots"] == 2


async def test_retention_of_one_keeps_only_the_newest(tmp_path):
    mgr = SnapshotManager(TargetStore(), tmp_path / "s", retention=1)
    first = await mgr.save_now()
    second = await mgr.save_now()
    assert mgr.snapshot_files() == [second]
    assert not first.exists()


def test_a_retention_of_zero_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="at least one snapshot"):
        SnapshotManager(TargetStore(), tmp_path, retention=0)


def test_a_ceiling_below_the_debounce_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="max_staleness"):
        SnapshotManager(TargetStore(), tmp_path, quiet_period=2.0,
                        max_staleness=1.0)


# --------------------------------------------------------------------------- #
# Crash safety
# --------------------------------------------------------------------------- #

async def test_an_interrupted_write_leaves_the_previous_snapshot_readable(
        populated_store, tmp_path, monkeypatch):
    from reconkg.demo import TARGET

    directory = tmp_path / "s"
    mgr = SnapshotManager(populated_store, directory, retention=3)
    good = await mgr.save_now()

    def die_mid_write(store, path):
        # What a kill -9 during a save looks like on disk: a partial file at
        # the temp path, no completed database.
        from pathlib import Path
        Path(path).write_bytes(b"SQLite format 3\x00truncated")
        raise OSError("no space left on device")

    monkeypatch.setattr(snapshots.persistence, "save", die_mid_write)
    with pytest.raises(OSError):
        await mgr.save_now()

    assert mgr.failures == 1
    assert mgr.pending is True                    # changes are still unsaved
    assert mgr.snapshot_files() == [good]         # the wreck is not a snapshot
    assert list(directory.glob(".tmp-*")) == []   # and it was cleaned up
    assert persistence.host_count(good) == 1
    assert persistence.load(good).get(TARGET) is not None


async def test_replace_is_atomic_over_an_existing_snapshot(tmp_path):
    """Verifies on *this* filesystem that a rename over a live file yields
    the new content whole, which is the property the temp-file dance buys."""
    import os

    directory = tmp_path / "s"
    directory.mkdir()
    victim = directory / "snapshot-a.sqlite"
    victim.write_bytes(b"old" * 1000)
    tmp = directory / ".tmp-new.sqlite"
    tmp.write_bytes(b"new" * 1000)
    os.replace(tmp, victim)

    assert victim.read_bytes() == b"new" * 1000
    assert not tmp.exists()


async def test_a_leftover_temp_file_is_swept_on_restore(tmp_path):
    directory = tmp_path / "s"
    directory.mkdir()
    corpse = directory / ".tmp-deadbeef.sqlite"
    corpse.write_bytes(b"half a database")

    fresh = TargetStore()
    mgr = SnapshotManager(fresh, directory)
    assert await mgr.restore_into(fresh) == 0
    assert not corpse.exists()


# --------------------------------------------------------------------------- #
# Shutdown
# --------------------------------------------------------------------------- #

async def test_aclose_flushes_a_pending_save(tmp_path):
    mgr = SnapshotManager(TargetStore(), tmp_path / "s",
                          quiet_period=30.0, max_staleness=30.0).start()
    await mgr.store.emit(_event())
    assert mgr.pending is True

    await mgr.aclose()                   # long before the debounce would fire

    assert mgr.saves == 1
    assert mgr.pending is False
    assert len(mgr.snapshot_files()) == 1


async def test_aclose_twice_does_not_raise(tmp_path):
    """RC-19: a double shutdown is a normal event, not an exception."""
    mgr = SnapshotManager(TargetStore(), tmp_path / "s",
                          quiet_period=QUIET, max_staleness=STALE).start()
    await mgr.store.emit(_event())
    await mgr.aclose()
    await mgr.aclose()
    await mgr.aclose()

    assert mgr.saves == 1                # the flush ran exactly once
    assert mgr.running is False


async def test_aclose_on_a_manager_that_never_started_is_a_no_op(tmp_path):
    mgr = SnapshotManager(TargetStore(), tmp_path / "s")
    await mgr.aclose()
    await mgr.aclose()
    assert mgr.saves == 0
    assert mgr.snapshot_files() == []


async def test_start_twice_subscribes_once(tmp_path):
    mgr = SnapshotManager(TargetStore(), tmp_path / "s",
                          quiet_period=QUIET, max_staleness=STALE)
    mgr.start()
    mgr.start()
    try:
        await mgr.store.emit(_event())
        await asyncio.sleep(QUIET * 6)
        assert mgr.saves == 1
        assert mgr.skipped == 0          # one subscription, one mark
    finally:
        await mgr.aclose()


async def test_no_saves_happen_after_close(tmp_path):
    mgr = SnapshotManager(TargetStore(), tmp_path / "s",
                          quiet_period=QUIET, max_staleness=STALE).start()
    await mgr.aclose()
    assert mgr.saves == 0

    for i in range(50):
        await mgr.store.emit(_event(i))
    await asyncio.sleep(QUIET * 6)

    assert mgr.saves == 0
    assert mgr.skipped == 0
    assert mgr.pending is False
    assert mgr.snapshot_files() == []
    assert mgr.store._subscribers == []


async def test_starting_after_close_is_refused(tmp_path):
    mgr = SnapshotManager(TargetStore(), tmp_path / "s")
    await mgr.aclose()
    with pytest.raises(RuntimeError, match="closed"):
        mgr.start()


async def test_the_manager_never_writes_to_the_store(populated_store, tmp_path):
    """The store is the single writer; the manager is an observer. A save
    must not perturb the graph or emit an event of its own."""
    before = populated_store.events_emitted
    host = populated_store.list_hosts()[0]
    document = host.model_dump_json()

    mgr = SnapshotManager(populated_store, tmp_path / "s")
    await mgr.save_now()

    assert populated_store.events_emitted == before
    assert populated_store.list_hosts()[0] is host
    assert host.model_dump_json() == document


async def test_a_repeat_observation_is_seen_by_the_autosave(tmp_path):
    """The SECOND PATH, found during the snapshot work and since closed.

    `TargetStore.ensure_host()` on a known host folds the new provenance into
    the existing node -- confidence moves, the audit log grows -- and used to
    return without emitting. An autosave driven by change events cannot be
    correct if a real mutation emits nothing, so the store now emits
    `host.updated` on that branch.

    This test is the reason the fix must stay: it asserts the graph moved AND
    that the manager noticed, with no `mark_dirty()` prompting. `mark_dirty()`
    remains for callers that mutate through some future path the event stream
    still cannot see.
    """
    from reconkg.models import Provenance
    from reconkg.store import EventKind

    store = TargetStore()
    mgr = SnapshotManager(store, tmp_path / "s",
                          quiet_period=QUIET, max_staleness=STALE).start()
    try:
        await store.ensure_host("10.10.10.42", Provenance(
            source_tool="nmap-sT", principal="scanner-a", confidence=0.5))
        await asyncio.sleep(QUIET * 6)
        assert mgr.saves == 1

        await store.ensure_host("10.10.10.42", Provenance(
            source_tool="whatweb", principal="scanner-b", confidence=0.5))

        assert store.get("10.10.10.42").confidence == 0.75   # graph moved
        assert mgr.pending is True                           # and was seen
        assert store.event_log[-1].kind is EventKind.HOST_UPDATED
        assert store.event_log[-1].payload["principal"] == "scanner-b"

        await asyncio.sleep(QUIET * 6)
        assert mgr.saves == 2
    finally:
        await mgr.aclose()


async def test_mark_dirty_does_not_inflate_the_skipped_counter(tmp_path):
    mgr = SnapshotManager(TargetStore(), tmp_path / "s",
                          quiet_period=QUIET, max_staleness=STALE).start()
    try:
        mgr.mark_dirty()
        mgr.mark_dirty()
        await asyncio.sleep(QUIET * 6)
        assert mgr.saves == 1
        assert mgr.skipped == 0
    finally:
        await mgr.aclose()


async def test_stats_reports_the_observable_counters(tmp_path):
    mgr = SnapshotManager(TargetStore(), tmp_path / "s", retention=4,
                          quiet_period=QUIET, max_staleness=STALE).start()
    try:
        await mgr.store.emit(_event())
        await mgr.store.emit(_event())
        await asyncio.sleep(QUIET * 6)

        stats = mgr.stats()
        assert stats["saves"] == 1
        assert stats["skipped"] == 1
        assert stats["failures"] == 0
        assert stats["pending"] is False
        assert stats["running"] is True
        assert stats["retention"] == 4
        assert stats["snapshots"] == 1
        assert stats["last_error"] is None
        assert stats["last_saved_at"].endswith("+00:00")
    finally:
        await mgr.aclose()
