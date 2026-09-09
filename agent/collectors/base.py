"""Collector base class and the shared emit context.

Every collector runs on its own daemon thread and pushes :class:`vigil.schema.Event`
objects into the agent's buffer through :meth:`CollectorContext.emit`. Collectors
never talk to the network and never read file contents — they observe metadata and
hand it on.

The base class also provides :meth:`PollingCollector` for the two collectors that
work by diffing periodic snapshots (USB and logon), so the thread, the interval
and the error handling live in one place.
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from vigil.schema import Event

log = logging.getLogger("vigil.agent.collector")


@dataclass
class CollectorContext:
    """Identity and plumbing shared by every collector."""

    agent_id: str
    host: str
    user: str
    emit: Callable[[Event], None]
    # True when the given path lives on removable media. Supplied by the USB
    # collector so the file collector can mark writes to a USB stick.
    is_removable: Callable[[str], bool] = field(default=lambda _path: False)

    def event(self, log_type: str, action: str, *, path: str | None = None,
              size_bytes: int = 0, user: str | None = None,
              detail: dict[str, Any] | None = None, ts=None) -> Event:
        """Build an event pre-filled with this endpoint's identity."""
        kwargs: dict[str, Any] = {
            "agent_id": self.agent_id,
            "host": self.host,
            "user": user or self.user,
            "log_type": log_type,
            "action": action,
            "path": path,
            "size_bytes": int(size_bytes or 0),
            "detail": detail or {},
        }
        if ts is not None:
            kwargs["ts"] = ts
        return Event(**kwargs)

    def send(self, *args, **kwargs) -> None:
        """Build an event and hand it straight to the buffer."""
        self.emit(self.event(*args, **kwargs))


class Collector(ABC):
    """A source of endpoint events."""

    name = "collector"

    def __init__(self, ctx: CollectorContext):
        self.ctx = ctx
        self.emitted = 0
        self._errors = 0

    @abstractmethod
    def start(self) -> None:
        """Begin collecting. Must not block."""

    @abstractmethod
    def stop(self) -> None:
        """Stop collecting and release OS resources. Must be idempotent."""

    def emit(self, event: Event) -> None:
        self.ctx.emit(event)
        self.emitted += 1

    @property
    def available(self) -> bool:
        """False when this collector cannot run on this platform (it is then skipped)."""
        return True

    def stats(self) -> dict[str, Any]:
        return {"name": self.name, "emitted": self.emitted, "errors": self._errors}

    def _note_error(self, exc: Exception) -> None:
        """Record and log a collection error without ever killing the thread.

        A collector that dies silently is worse than one that logs and carries on:
        the agent would look healthy while collecting nothing.
        """
        self._errors += 1
        level = logging.WARNING if self._errors <= 3 else logging.DEBUG
        log.log(level, "%s: %s: %s", self.name, type(exc).__name__, exc)


class PollingCollector(Collector):
    """A collector that works by diffing snapshots on a fixed interval."""

    def __init__(self, ctx: CollectorContext, interval_s: float):
        super().__init__(ctx)
        self.interval_s = max(0.2, float(interval_s))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ── subclass hooks ──
    @abstractmethod
    def snapshot(self) -> Any:
        """Current observable state (a set or dict that supports equality)."""

    @abstractmethod
    def diff(self, previous: Any, current: Any) -> None:
        """Emit events for the transition from ``previous`` to ``current``."""

    # ── lifecycle ──
    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=self.name, daemon=True)
        self._thread.start()
        log.info("%s started (poll every %.1fs)", self.name, self.interval_s)

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=self.interval_s + 2.0)

    def _run(self) -> None:
        try:
            previous = self.snapshot()
        except Exception as exc:
            self._note_error(exc)
            previous = None

        while not self._stop.wait(self.interval_s):
            try:
                current = self.snapshot()
            except Exception as exc:
                self._note_error(exc)
                continue
            if previous is not None and current != previous:
                try:
                    self.diff(previous, current)
                except Exception as exc:
                    self._note_error(exc)
            previous = current
