"""WebSocket fan-out for live events and alerts.

Ingestion runs in worker threads (sync endpoints, background noise generator), while
WebSockets live on the asyncio loop. ``publish`` is thread-safe: it hands messages to
the loop, where a single pump task broadcasts them to every connected client.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

from fastapi import WebSocket

log = logging.getLogger(__name__)


class Broadcaster:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._queue: asyncio.Queue[str] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=5000)
        self._task = asyncio.create_task(self._pump())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        for ws in list(self._clients):
            with contextlib.suppress(Exception):
                await ws.close()
        self._clients.clear()
        self._loop = None

    async def connect(self, ws: WebSocket) -> None:
        """Register an already-accepted, authenticated socket."""
        self._clients.add(ws)
        await ws.send_text(json.dumps({"type": "hello", "data": {}}))

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def publish(self, kind: str, data: Any) -> None:
        if self._loop is None or self._queue is None or not self._clients:
            return
        message = json.dumps({"type": kind, "data": data}, default=str)
        queue = self._queue

        def _put() -> None:
            if queue.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()  # drop the oldest message rather than block ingest
            queue.put_nowait(message)

        try:
            self._loop.call_soon_threadsafe(_put)
        except RuntimeError:  # loop closed during shutdown
            pass

    async def _pump(self) -> None:
        assert self._queue is not None
        while True:
            message = await self._queue.get()
            dead = []
            for ws in list(self._clients):
                try:
                    await ws.send_text(message)
                except Exception:  # noqa: BLE001 - any send failure means the client is gone
                    dead.append(ws)
            for ws in dead:
                self.disconnect(ws)


broadcaster = Broadcaster()
