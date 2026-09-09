"""WebSocket fan-out to connected SOC dashboards.

One-way push: threats, agent status changes, and RL updates. A dead or slow socket
must never block ingest, so every send is guarded and failures simply drop the
connection.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import WebSocket

log = logging.getLogger("vigil.ws")


class ConnectionManager:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        log.info("dashboard connected (%d live)", len(self._clients))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)
        log.info("dashboard disconnected (%d live)", len(self._clients))

    @property
    def count(self) -> int:
        return len(self._clients)

    async def broadcast(self, message: dict[str, Any]) -> int:
        """Send to every connected dashboard. Returns how many received it."""
        async with self._lock:
            targets = list(self._clients)
        if not targets:
            return 0

        results = await asyncio.gather(
            *(ws.send_json(message) for ws in targets), return_exceptions=True
        )
        dead = [ws for ws, r in zip(targets, results) if isinstance(r, Exception)]
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)
            log.info("dropped %d unreachable dashboard connection(s)", len(dead))
        return len(targets) - len(dead)
