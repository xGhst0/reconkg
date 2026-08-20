"""SQLite persistence for the knowledge graph.

The last item on the audit's open list with no security dimension: everything
lived in memory, so a restart lost the engagement. Notes accumulated over a
week of a box vanished on a `systemctl restart`.

Design: **snapshot, not ORM.** `TargetStore` stays the single in-memory writer
and the engine keeps operating on live objects; this module serialises the
graph to SQLite and reads it back. That keeps the hot path exactly as fast and
as tested as it was, and confines persistence to two functions you can read in
one sitting.

The cost is honest and worth stating: a snapshot is a point-in-time copy, so a
crash between snapshots loses whatever happened since. For a lab coordinator
that is the right trade -- the alternative is threading a session through every
mutation in `store.py`, which is where the concurrency bugs would live. If
this ever needs write-ahead durability, the interface below is the seam to
replace, not the engine.

Schema is versioned. Opening a database written by a newer schema fails loudly
rather than silently misreading columns.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import Host
from .store import TargetStore

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    address    TEXT PRIMARY KEY,
    document   TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS hosts_updated ON hosts(updated_at);
"""


class SchemaMismatch(RuntimeError):
    """The database was written by a different schema version."""


SNAPSHOT_MODE = 0o600
SNAPSHOT_DIR_MODE = 0o700
"""RC-25: a snapshot is the whole engagement -- every host, service, version
and lead. It was written 0644 inside a 0755 directory, readable by any local
account on the box. Owner-only is the only defensible default for a file
whose contents are the thing the tool exists to protect."""


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (creating if needed) and verify the schema version."""
    file = Path(path).expanduser()
    file.parent.mkdir(parents=True, exist_ok=True, mode=SNAPSHOT_DIR_MODE)
    try:
        os.chmod(file.parent, SNAPSHOT_DIR_MODE)
    except OSError:                       # e.g. a mount that refuses chmod
        log.warning("could not restrict permissions on %s", file.parent)
    conn = sqlite3.connect(str(file))
    conn.row_factory = sqlite3.Row
    # WAL keeps a reader (an export, a second process) from blocking the
    # snapshot write, which is the only contention this design can produce.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    try:
        os.chmod(file, SNAPSHOT_MODE)
    except OSError:
        log.warning("could not restrict permissions on %s", file)

    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'"
                       ).fetchone()
    if row is None:
        conn.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?)",
                     (str(SCHEMA_VERSION),))
        conn.commit()
    else:
        found = int(row["value"])
        if found != SCHEMA_VERSION:
            conn.close()
            raise SchemaMismatch(
                f"{file} was written with schema v{found}; this build speaks "
                f"v{SCHEMA_VERSION}. Refusing to guess at the difference.")
    return conn


def save(store: TargetStore, path: str | Path) -> int:
    """Snapshot every host. Returns the number written.

    One transaction: a crash mid-write leaves the previous snapshot intact
    rather than a half-updated graph, which would be worse than a stale one.
    """
    now = datetime.now(timezone.utc).isoformat()
    hosts = store.list_hosts()
    with closing(connect(path)) as conn:
        with conn:                       # transactional
            conn.executemany(
                "INSERT INTO hosts(address, document, updated_at) "
                "VALUES(?, ?, ?) ON CONFLICT(address) DO UPDATE SET "
                "document=excluded.document, updated_at=excluded.updated_at",
                [(h.address, h.model_dump_json(), now) for h in hosts])
    log.info("snapshotted %d hosts to %s", len(hosts), path)
    return len(hosts)


def load(path: str | Path, store: Optional[TargetStore] = None) -> TargetStore:
    """Rebuild a store from a snapshot.

    A row that will not deserialise is skipped with a warning rather than
    aborting the load: one corrupt host should not cost you the other forty.
    """
    store = store or TargetStore()
    restored, skipped = 0, 0
    with closing(connect(path)) as conn:
        for row in conn.execute("SELECT address, document FROM hosts"):
            try:
                host = Host.model_validate_json(row["document"])
            except Exception as exc:
                skipped += 1
                log.warning("skipping unreadable host %s: %s",
                            row["address"], exc)
                continue
            store._hosts[host.address] = host
            restored += 1
    log.info("restored %d hosts from %s (%d skipped)", restored, path, skipped)
    return store


def host_count(path: str | Path) -> int:
    with closing(connect(path)) as conn:
        return conn.execute("SELECT COUNT(*) AS n FROM hosts").fetchone()["n"]


def forget(path: str | Path, address: str) -> bool:
    """Drop one host from the snapshot. Returns whether a row was removed."""
    with closing(connect(path)) as conn:
        with conn:
            cursor = conn.execute("DELETE FROM hosts WHERE address = ?",
                                  (address,))
        return cursor.rowcount > 0
