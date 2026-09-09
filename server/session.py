"""In-memory registry of live agent sessions.

Session keys are **deliberately never persisted**. A server restart therefore
invalidates every session and forces a fresh ML-KEM handshake — which is the
behaviour you want from a key-agreement protocol, and means a stolen database
file contains no key material capable of decrypting captured traffic.

Also the home of replay protection: each session tracks the highest sequence
number it has accepted, so a captured batch cannot be replayed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Session:
    agent_id: str
    session_key: bytes
    established_at: datetime = field(default_factory=_now)
    last_seq: int = 0
    batches: int = 0
    events: int = 0
    last_seen: datetime = field(default_factory=_now)

    def info(self) -> dict:
        """Serialisable view — never includes the session key."""
        return {
            "agent_id": self.agent_id,
            "established_at": self.established_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "last_seq": self.last_seq,
            "batches": self.batches,
            "events": self.events,
            "key_bits": len(self.session_key) * 8,
        }


class SessionRegistry:
    """Thread-safe map of ``agent_id -> Session``."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}

    def establish(self, agent_id: str, session_key: bytes) -> Session:
        """Start a new session, replacing any previous one for this agent.

        A re-handshake resets the sequence counter, which is safe because the
        session key is new: a batch captured under the old key can no longer be
        decrypted, so it cannot be replayed into the new session.
        """
        with self._lock:
            s = Session(agent_id=agent_id, session_key=session_key)
            self._sessions[agent_id] = s
            return s

    def get(self, agent_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(agent_id)

    def record_batch(self, agent_id: str, seq: int, n_events: int) -> None:
        with self._lock:
            s = self._sessions.get(agent_id)
            if s is None:
                return
            s.last_seq = seq
            s.batches += 1
            s.events += n_events
            s.last_seen = _now()

    def drop(self, agent_id: str) -> None:
        with self._lock:
            self._sessions.pop(agent_id, None)

    def all_info(self) -> list[dict]:
        with self._lock:
            return [s.info() for s in self._sessions.values()]

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
