"""Snapshot lifecycle: autosave, restore, retention.

`persistence.py` gave us `save()`/`load()` and nothing that calls them. This
module is the layer that makes the snapshot real: it watches the store's
change stream, decides *when* a snapshot is worth writing, keeps a bounded
history of them, and hands the newest one back on start-up.

Design decisions worth the ink:

**Observer, never writer.** The store is the single writer to the graph
(`store.py`). `SnapshotManager` only subscribes, reads `list_hosts()`, and
copies. It never mutates a `Host`, and the only store it ever writes into is
the one the caller passes to `restore_into()` -- via `persistence.load`,
before the event loop is serving traffic.

**Debounce with a staleness ceiling.** A pipeline run emits hundreds of
ChangeEvents in a few hundred milliseconds. Saving per event would put a
SQLite transaction on the hot path of every fingerprint update, so events
only mark the manager dirty and a background task saves once the store has
been quiet for `quiet_period`. Quiet-period alone is not enough: a store that
is *continuously* busy is never quiet, and would never be snapshotted at all
-- exactly the long scan you most want to survive a crash. `max_staleness`
is the ceiling: once the oldest un-saved change is that old, we save whether
or not the burst has ended.

**Blocking IO goes to a thread; the copy does not.** `persistence.save()` is
synchronous SQLite -- connect, executemany, commit, fsync -- and can block for
tens of milliseconds on a slow disk. On the event loop that stalls the
FastAPI surface and the WebSocket fan-out, so the save runs under
`asyncio.to_thread`. But we cannot hand the *live* store to that thread: the
engine keeps mutating `Host` objects on the loop, and `model_dump_json` on a
model being mutated from another thread yields a torn document -- a snapshot
that never corresponded to any real state. So the manager takes a deep copy
of the hosts on the event loop (pure CPU, no IO, no await points, therefore
atomic with respect to the store) and gives the thread a detached store to
serialise. The copy costs memory proportional to the graph; the alternative
costs correctness, and this is a lab-scale graph.

**Atomicity is per-file, not per-transaction.** `persistence.save()` is one
transaction, so it cannot half-update a database. It can still leave a
truncated *file* if the process dies mid-write, and that file would be the
newest snapshot -- the one restore picks. So each save writes to
`.tmp-<uuid>.sqlite` and only `os.replace()`s it into a timestamped snapshot
name once SQLite has closed cleanly. An interrupted save leaves a `.tmp-`
file, which the snapshot glob ignores and the next save sweeps away; the
previous snapshot stays the newest readable one.

**Bounded** (brief non-negotiable 6): `retention` caps the number of
snapshot files and the oldest are unlinked on every successful save. The
manager holds no per-target or per-caller state at all -- only counters and
two timestamps -- so there is no dict here for a caller to grow.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import persistence
from .store import ChangeEvent, TargetStore

log = logging.getLogger(__name__)

SNAPSHOT_SUFFIX = ".sqlite"
TMP_PREFIX = ".tmp-"

DEFAULT_QUIET_PERIOD = 2.0
DEFAULT_MAX_STALENESS = 30.0
DEFAULT_RETENTION = 5


class SnapshotManager:
    """Debounced autosave, restore-on-start and bounded snapshot retention.

    Lifecycle::

        mgr = SnapshotManager(store, "/var/lib/reconkg")
        await mgr.restore_into(store)   # before the first write
        mgr.start()                     # subscribes + starts the task
        ...
        await mgr.aclose()              # flushes if dirty; safe to repeat
    """

    def __init__(
        self,
        store: TargetStore,
        directory: str | Path,
        *,
        retention: int = DEFAULT_RETENTION,
        quiet_period: float = DEFAULT_QUIET_PERIOD,
        max_staleness: float = DEFAULT_MAX_STALENESS,
        basename: str = "snapshot",
    ) -> None:
        if retention < 1:
            raise ValueError("retention must keep at least one snapshot")
        if quiet_period <= 0 or max_staleness <= 0:
            raise ValueError("quiet_period and max_staleness must be > 0")
        if max_staleness < quiet_period:
            # Otherwise the ceiling fires before the debounce ever can, and
            # the "one save per burst" property quietly stops holding.
            raise ValueError("max_staleness must be >= quiet_period")

        self.store = store
        self.directory = Path(directory).expanduser()
        self.retention = retention
        self.quiet_period = quiet_period
        self.max_staleness = max_staleness
        self.basename = basename

        # -- observable state ------------------------------------------ #
        self.saves = 0
        """Snapshot files successfully written."""
        self.skipped = 0
        """Change events coalesced into an already-pending save. This is the
        number of SQLite transactions the debounce did not perform."""
        self.failures = 0
        self.restores = 0
        self.last_saved_at: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.last_snapshot: Optional[Path] = None

        self._pending = False
        self._closed = False
        self._task: Optional[asyncio.Task] = None
        self._unsubscribe = None
        self._activity = asyncio.Event()
        self._seq = 0
        self._first_dirty_at = 0.0
        self._last_event_at = 0.0
        self._save_lock = asyncio.Lock()

    # -- observable ------------------------------------------------------ #

    @property
    def pending(self) -> bool:
        """True when changes have arrived that no snapshot yet contains."""
        return self._pending

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def stats(self) -> dict:
        """Flat dict for the metrics/status surface to expose."""
        return {
            "saves": self.saves,
            "skipped": self.skipped,
            "failures": self.failures,
            "restores": self.restores,
            "pending": self._pending,
            "running": self.running,
            "retention": self.retention,
            "snapshots": len(self.snapshot_files()),
            "last_saved_at": (self.last_saved_at.isoformat()
                              if self.last_saved_at else None),
            "last_snapshot": (str(self.last_snapshot)
                              if self.last_snapshot else None),
            "last_error": self.last_error,
        }

    # -- lifecycle -------------------------------------------------------- #

    def start(self) -> "SnapshotManager":
        """Subscribe and start the autosave task. Idempotent."""
        if self._closed:
            raise RuntimeError("SnapshotManager is closed")
        if self.running:
            return self
        if self._unsubscribe is None:
            self._unsubscribe = self.store.subscribe(self._on_event)
        self._task = asyncio.get_running_loop().create_task(self._run())
        return self

    async def aclose(self) -> None:
        """Unsubscribe, stop the task, flush a final snapshot if dirty.

        RC-19: teardown paths get run twice (two app instances sharing a
        store, a fixture tearing down after an explicit shutdown). Calling
        this twice must be a no-op, not a crash -- hence the `_closed` latch
        and `store.subscribe`'s idempotent unsubscribe.
        """
        if self._closed:
            return
        self._closed = True

        if self._unsubscribe is not None:
            self._unsubscribe()          # stop the bleeding before flushing
            self._unsubscribe = None

        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        if self._pending:
            # A shutdown that discards the last burst is a shutdown that
            # loses the run you just did.
            with contextlib.suppress(Exception):
                await self.save_now()

    async def __aenter__(self) -> "SnapshotManager":
        return self.start()

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    # -- restore ---------------------------------------------------------- #

    async def restore_into(self, store: TargetStore) -> int:
        """Load the newest readable snapshot. Returns hosts restored.

        A missing directory or an empty one is a fresh start, not an error:
        first run is the common case and must not need a pre-seeded file.
        A snapshot that will not open (truncated by a kill -9 before this
        module existed, or written by a newer schema) is logged and the next
        older one is tried -- retention exists precisely so there is one.
        """
        if self.directory.is_dir():
            # Start-of-process housekeeping: any `.tmp-` file here is the
            # corpse of a save the last process did not finish.
            self._sweep_tmp()
        for path in self.snapshot_files(newest_first=True):
            try:
                await asyncio.to_thread(persistence.load, path, store)
            except Exception as exc:
                self.last_error = f"restore {path.name}: {exc}"[:500]
                log.warning("snapshot %s unreadable (%s); trying older",
                            path, exc)
                continue
            self.restores += 1
            self.last_snapshot = path
            count = len(store.list_hosts())
            log.info("restored %d hosts from %s", count, path)
            return count
        log.info("no readable snapshot in %s; starting empty", self.directory)
        return 0

    # -- files ------------------------------------------------------------ #

    def snapshot_files(self, *, newest_first: bool = False) -> list[Path]:
        """Snapshot files, oldest first. `.tmp-` files are not snapshots."""
        if not self.directory.is_dir():
            return []
        names = [p for p in
                 self.directory.glob(f"{self.basename}-*{SNAPSHOT_SUFFIX}")
                 if not p.name.startswith(TMP_PREFIX)]
        # The name carries a UTC timestamp plus a zero-padded sequence, so a
        # lexical sort is a chronological sort even when two saves land in
        # the same microsecond.
        names.sort(key=lambda p: p.name, reverse=newest_first)
        return names

    def _next_path(self, now: datetime) -> Path:
        self._seq = (self._seq + 1) % 1_000_000
        stamp = now.strftime("%Y%m%dT%H%M%S.%f")
        return self.directory / (
            f"{self.basename}-{stamp}-{self._seq:06d}{SNAPSHOT_SUFFIX}")

    def _prune(self) -> int:
        """Unlink oldest snapshots beyond `retention`. Returns count removed."""
        files = self.snapshot_files()
        doomed = files[:max(0, len(files) - self.retention)]
        removed = 0
        for path in doomed:
            try:
                path.unlink()
                removed += 1
            except OSError as exc:      # another process got there first
                log.warning("could not evict %s: %s", path, exc)
        return removed

    def _sweep_tmp(self) -> None:
        """Remove leftovers from a save the process did not survive."""
        for path in self.directory.glob(f"{TMP_PREFIX}*"):
            with contextlib.suppress(OSError):
                path.unlink()

    # -- saving ----------------------------------------------------------- #

    def _detach(self) -> TargetStore:
        """Point-in-time deep copy, taken on the loop with no await inside.

        Handing the live store to a worker thread would let the engine mutate
        a model mid-serialisation. This runs to completion between two
        awaits, so what the thread serialises is a state the graph really was
        in.
        """
        frozen = TargetStore()
        for host in self.store.list_hosts():
            frozen._hosts[host.address] = host.model_copy(deep=True)
        return frozen

    async def save_now(self) -> Optional[Path]:
        """Force a snapshot regardless of the debounce. Returns its path.

        Serialised by a lock: two concurrent saves would race on the temp
        sweep and on retention, and there is nothing to gain from overlapping
        writes to the same directory.
        """
        async with self._save_lock:
            # Clear *before* copying: an event arriving during the copy or
            # the write belongs to the next snapshot, not this one.
            self._pending = False
            frozen = self._detach()
            now = datetime.now(timezone.utc)
            final = self._next_path(now)
            tmp = self.directory / f"{TMP_PREFIX}{uuid.uuid4().hex}.sqlite"
            try:
                await asyncio.to_thread(self._write_atomically, frozen,
                                        tmp, final)
            except Exception as exc:
                self.failures += 1
                self.last_error = str(exc)[:500]
                self._pending = True     # unsaved changes are still unsaved
                log.exception("snapshot to %s failed", final)
                raise
            self.saves += 1
            self.last_saved_at = now
            self.last_snapshot = final
            self._prune()
            return final

    def _write_atomically(self, frozen: TargetStore, tmp: Path,
                          final: Path) -> None:
        """Runs in a worker thread. Temp file, then `os.replace`.

        `os.replace` is atomic within a filesystem, so `final` either does not
        exist or is a complete database -- never a truncated one. The temp
        file is removed on failure so a crashed save cannot accumulate
        half-written databases in the snapshot directory.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            persistence.save(frozen, tmp)
            # persistence.connect() opens WAL, and closing the last
            # connection checkpoints and removes the -wal/-shm sidecars, so
            # by here `tmp` is self-contained and safe to rename.
            os.replace(tmp, final)
        finally:
            # Only ever our own temp file: a blanket sweep here would delete
            # a concurrent writer's in-progress database.
            with contextlib.suppress(OSError):
                tmp.unlink()

    # -- the autosave task ------------------------------------------------- #

    async def _on_event(self, event: ChangeEvent) -> None:
        """Store subscriber. Marks dirty; never writes. Must not block.

        Anything slow here would slow every graph mutation in the system --
        `TargetStore.emit` awaits its subscribers in line.
        """
        if self._pending:
            self.skipped += 1
        self.mark_dirty()

    def mark_dirty(self) -> None:
        """Flag unsaved changes the event stream did not carry.

        The autosave is only as complete as `emit()`. `TargetStore.
        ensure_host()` folds a repeat observation into an existing host --
        confidence arithmetic, a new provenance entry -- and returns *without*
        emitting, so that mutation is invisible here. Until that is emitted at
        the source, a caller that knows it just re-observed a known host (the
        API ingress, the end of a pipeline run) should call this. It is the
        same signal an event gives, minus the event.
        """
        now = self._clock()
        if not self._pending:
            self._pending = True
            self._first_dirty_at = now
        self._last_event_at = now
        self._activity.set()

    @staticmethod
    def _clock() -> float:
        try:
            return asyncio.get_running_loop().time()
        except RuntimeError:            # pragma: no cover - no loop running
            return 0.0

    async def _run(self) -> None:
        while True:
            if not self._pending:
                await self._activity.wait()
                self._activity.clear()
                continue

            now = self._clock()
            quiet_left = self._last_event_at + self.quiet_period - now
            stale_left = self._first_dirty_at + self.max_staleness - now
            wait = min(quiet_left, stale_left)
            if wait > 0:
                self._activity.clear()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._activity.wait(), wait)
                continue

            try:
                await self.save_now()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Already counted and logged in save_now. Back off rather
                # than spin: a full disk would otherwise burn the loop.
                await asyncio.sleep(self.quiet_period)
