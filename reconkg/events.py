"""WebSocket fan-out for analyst clients.

Design note (Senior Backend): each client gets its own bounded queue and its
own writer task. A broadcast enqueues and returns immediately, so one analyst
on hotel wifi cannot back-pressure the discovery pipeline. If a client's queue
fills, we drop that client's oldest events and mark the gap rather than block
-- a stalled scan is worse than a lossy view, and the client can re-fetch state
over REST.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Optional

from .store import ChangeEvent, TargetStore

log = logging.getLogger(__name__)

QUEUE_MAX = 512
REPLAY_ON_CONNECT = 100


class ClientSession:
    def __init__(self, websocket: Any, client_id: str,
                 target_filter: Optional[str] = None,
                 scope: Optional[Callable[[str], bool]] = None) -> None:
        self.ws = websocket
        self.client_id = client_id
        self.target_filter = target_filter
        self.scope = scope
        """RC-16: a predicate deciding which targets this client may see.

        Scope was enforced on writes only, so a principal restricted to
        10.10.10.0/24 could still subscribe to the live event stream for
        every other host in the graph. Read access is how you learn what to
        attack; restricting writes alone is half a control.
        """
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=QUEUE_MAX)
        self.dropped = 0
        self._task: Optional[asyncio.Task] = None

    def wants(self, event: ChangeEvent) -> bool:
        if self.scope is not None and not self.scope(event.target):
            return False
        return self.target_filter in (None, event.target)

    def offer(self, message: dict) -> None:
        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull:
            try:
                self.queue.get_nowait()
                self.dropped += 1
            except asyncio.QueueEmpty:  # pragma: no cover - racy, harmless
                pass
            self.queue.put_nowait(message)

    async def _pump(self) -> None:
        try:
            while True:
                message = await self.queue.get()
                if self.dropped:
                    message = {**message, "_dropped_before": self.dropped}
                    self.dropped = 0
                await self.ws.send_json(message)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.info("client %s write failed; closing session", self.client_id)

    def start(self) -> None:
        self._task = asyncio.create_task(self._pump(),
                                         name=f"ws-pump-{self.client_id}")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


class ConnectionManager:
    """Tracks connected analyst windows and broadcasts store changes."""

    def __init__(self, store: TargetStore) -> None:
        self.store = store
        self.sessions: dict[str, ClientSession] = {}
        self._unsubscribe = store.subscribe(self._on_change)

    @property
    def client_count(self) -> int:
        return len(self.sessions)

    async def connect(self, websocket: Any, client_id: str,
                      target_filter: Optional[str] = None,
                      scope: Optional[Callable[[str], bool]] = None
                      ) -> ClientSession:
        await websocket.accept()
        session = ClientSession(websocket, client_id, target_filter, scope)
        self.sessions[client_id] = session
        session.start()
        session.offer({
            "type": "hello", "client_id": client_id,
            "target_filter": target_filter,
            "peers": self.client_count,
        })
        recent = list(self.store.event_log)[-REPLAY_ON_CONNECT:]
        for event in recent:
            if session.wants(event):
                session.offer(self._encode(event, replay=True))
        log.info("analyst %s connected (%d total)", client_id,
                 self.client_count)
        return session

    async def disconnect(self, client_id: str) -> None:
        session = self.sessions.pop(client_id, None)
        if session is not None:
            await session.stop()
            log.info("analyst %s disconnected (%d remaining)", client_id,
                     self.client_count)

    async def broadcast(self, message: dict,
                        target: Optional[str] = None) -> int:
        sent = 0
        for session in list(self.sessions.values()):
            if target is not None and session.target_filter not in (None, target):
                continue
            if (target is not None and session.scope is not None
                    and not session.scope(target)):
                continue
            session.offer(message)
            sent += 1
        return sent

    async def _on_change(self, event: ChangeEvent) -> None:
        await self.broadcast(self._encode(event), target=event.target)

    @staticmethod
    def _encode(event: ChangeEvent, *, replay: bool = False) -> dict:
        return {
            "type": "change",
            "replay": replay,
            "event_id": event.event_id,
            "kind": event.kind.value,
            "ts": event.ts.isoformat(),
            "target": event.target,
            "path": event.path,
            "payload": event.payload,
        }

    async def shutdown(self) -> None:
        self._unsubscribe()
        for client_id in list(self.sessions):
            await self.disconnect(client_id)
