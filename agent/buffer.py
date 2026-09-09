"""Thread-safe event buffer between the collectors and the transport.

Collector threads append; the flush loop drains. Two properties matter for an agent
that has to survive a server outage without becoming a liability on the endpoint:

* **Bounded.** The buffer has a hard cap. When it is full the *oldest* events are
  dropped and counted — an agent that grew without limit while the SOC server was
  down would eventually take the monitored workstation with it, which is a worse
  outcome than a gap in the timeline. The drop count is reported so the gap is
  visible rather than silent.
* **Requeue on failure.** A batch that fails to send goes back to the *front* of
  the queue, preserving order, so a transient network error costs a retry rather
  than the data.
"""

from __future__ import annotations

import logging
import threading
from collections import deque

from vigil.schema import Event

log = logging.getLogger("vigil.agent.buffer")


class EventBuffer:
    def __init__(self, max_size: int = 20000):
        self.max_size = max(1, int(max_size))
        self._items: deque[Event] = deque()
        self._lock = threading.RLock()
        self.dropped = 0
        self.accepted = 0
        self._warned_full = False

    # ── producer side (collector threads) ──
    def add(self, event: Event) -> None:
        with self._lock:
            self._items.append(event)
            self.accepted += 1
            self._trim()

    def extend(self, events: list[Event]) -> None:
        with self._lock:
            self._items.extend(events)
            self.accepted += len(events)
            self._trim()

    def _trim(self) -> None:
        overflow = len(self._items) - self.max_size
        if overflow <= 0:
            return
        for _ in range(overflow):
            self._items.popleft()
        self.dropped += overflow
        if not self._warned_full:
            log.warning(
                "event buffer full at %d events — dropping the oldest. The server is "
                "probably unreachable; raise buffer_size if this is expected.",
                self.max_size,
            )
            self._warned_full = True

    # ── consumer side (flush loop) ──
    def drain(self, max_items: int) -> list[Event]:
        """Remove and return up to ``max_items`` events, oldest first."""
        with self._lock:
            n = min(max(0, int(max_items)), len(self._items))
            return [self._items.popleft() for _ in range(n)]

    def requeue(self, events: list[Event]) -> None:
        """Put a failed batch back at the front, preserving original order."""
        if not events:
            return
        with self._lock:
            self._items.extendleft(reversed(events))
            self._trim()

    # ── introspection ──
    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    @property
    def full(self) -> bool:
        with self._lock:
            return len(self._items) >= self.max_size

    def stats(self) -> dict:
        with self._lock:
            return {
                "pending": len(self._items),
                "capacity": self.max_size,
                "accepted": self.accepted,
                "dropped": self.dropped,
            }
