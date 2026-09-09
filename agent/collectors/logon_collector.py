"""Logon/session collector — the poster's "logon activity" signal.

Sessions are read from ``psutil.users()`` and diffed on an interval. This works
without administrator rights on every platform, which keeps the agent a plain
user-space process.

**What this does and does not see.** ``psutil.users()`` reports *interactive
sessions*, so it catches sign-in and sign-out, remote-desktop connections, and
fast-user-switching. It does **not** see a workstation lock/unlock, and it does not
distinguish a failed logon attempt — those live in the Windows Security event log
(4624/4634/4625), which requires elevation to read. The README documents that as
the optional elevated upgrade path; the unprivileged signal is enough for the
after-hours-session feature the detector actually uses.

The first snapshot is taken at construction and deliberately **not** emitted: the
session that started the agent is pre-existing state, not a logon event, and
reporting it would put a phantom logon in every agent's first batch.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import psutil

from agent.collectors.base import CollectorContext, PollingCollector
from vigil.schema import LOG_LOGON, LOGON_OFF, LOGON_ON

log = logging.getLogger("vigil.agent.logon")


def _session_key(u) -> tuple:
    """Identity of a session: user + terminal + start time.

    The start time is part of the key on purpose — sign out and back in on the same
    terminal is two sessions, and without it the pair would cancel out silently.
    """
    return (u.name or "", u.terminal or "", round(float(u.started or 0.0)))


def snapshot_sessions() -> dict[tuple, dict]:
    """Current interactive sessions, keyed by :func:`_session_key`."""
    out = {}
    for u in psutil.users():
        started = float(u.started or 0.0)
        out[_session_key(u)] = {
            "user": u.name or "",
            "terminal": u.terminal or "",
            "remote_host": u.host or "",
            "started_at": (
                datetime.fromtimestamp(started, tz=timezone.utc).isoformat()
                if started else ""
            ),
            "pid": u.pid,
        }
    return out


class LogonCollector(PollingCollector):
    """Emits a ``logon`` Logon/Logoff event per interactive session change."""

    name = "logon"

    def __init__(self, ctx: CollectorContext, interval_s: float = 5.0,
                 scan=snapshot_sessions):
        super().__init__(ctx, interval_s)
        self._scan = scan
        try:
            self._sessions = dict(self._scan())
        except Exception as exc:
            self._note_error(exc)
            self._sessions = {}
        if self._sessions:
            log.info("logon: %d session(s) already active at startup (not reported "
                     "as logons)", len(self._sessions))

    @property
    def active_users(self) -> tuple[str, ...]:
        return tuple(sorted({s["user"] for s in self._sessions.values() if s["user"]}))

    def snapshot(self) -> dict[tuple, dict]:
        return self._scan()

    def diff(self, previous: dict[tuple, dict], current: dict[tuple, dict]) -> None:
        self._sessions = dict(current)

        for key in sorted(set(current) - set(previous), key=str):
            info = current[key]
            log.info("logon: %s signed in (%s)", info["user"], info["terminal"] or "local")
            self.emit(self.ctx.event(LOG_LOGON, LOGON_ON, user=info["user"], detail=info))

        for key in sorted(set(previous) - set(current), key=str):
            info = previous[key]
            log.info("logon: %s signed out", info["user"])
            self.emit(self.ctx.event(LOG_LOGON, LOGON_OFF, user=info["user"], detail=info))

    @property
    def available(self) -> bool:
        try:
            self._scan()
            return True
        except Exception:
            return False

    def stats(self) -> dict:
        return {**super().stats(), "active_sessions": len(self._sessions),
                "active_users": list(self.active_users)}
