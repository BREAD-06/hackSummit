"""Storage abstraction for the detection server.

The pipeline talks only to this interface, so the backing store can be swapped
without touching detection/RL/response logic. VIGIL ships with
:class:`server.db.sqlite_store.SQLiteStorage` (zero-install, single file); a
MongoDB implementation could be dropped in later by implementing this same ABC.

Durable state only. Live per-agent secure-channel sessions (the AES key and the
replay sequence counter) are deliberately kept **in memory** by the ingest layer
so session keys never touch disk and a restart forces a fresh handshake.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Storage(ABC):
    # ── lifecycle ──
    @abstractmethod
    def init_schema(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    # ── agents (enrolled endpoints) ──
    @abstractmethod
    def upsert_agent(self, agent_id: str, verify_key: bytes, host: str) -> None: ...

    @abstractmethod
    def get_agent(self, agent_id: str) -> dict | None:
        """Agent metadata **without** the raw verify key (safe to return over the API)."""

    @abstractmethod
    def get_agent_verify_key(self, agent_id: str) -> bytes | None:
        """The agent's raw ML-DSA public key. Internal use only — never serialise it."""

    @abstractmethod
    def list_agents(self) -> list[dict]: ...

    @abstractmethod
    def touch_agent(self, agent_id: str) -> None:
        """Update an agent's last-seen timestamp."""

    # ── enrollment tokens (one-time secrets for first contact) ──
    @abstractmethod
    def add_enroll_token(self, token: str) -> None: ...

    @abstractmethod
    def consume_enroll_token(self, token: str, agent_id: str) -> bool:
        """Return True and mark used if the token is valid and unused."""

    # ── raw events ──
    @abstractmethod
    def insert_events(self, events: list[dict]) -> None: ...

    @abstractmethod
    def count_events(self) -> int: ...

    @abstractmethod
    def recent_events(self, limit: int = 100) -> list[dict]: ...

    # ── threats ──
    @abstractmethod
    def insert_threat(self, threat: dict) -> int: ...

    @abstractmethod
    def upsert_threat(self, threat: dict) -> tuple[int, bool]:
        """Insert a threat, or update the still-open record for the same window.

        A behaviour window is re-evaluated on every incoming batch for as long as
        it stays open, so this must collapse repeated evaluations of one incident
        into a single row. Returns ``(threat_id, created)``.

        Implementations must **not** overwrite a threat an analyst has already
        decided on (status other than ``"open"``).
        """

    @abstractmethod
    def find_open_threat(self, window_key: str) -> dict | None:
        """The still-open threat for a window key, if any."""

    @abstractmethod
    def update_threat_status(self, threat_id: int, status: str) -> None: ...

    @abstractmethod
    def get_threat(self, threat_id: int) -> dict | None: ...

    @abstractmethod
    def list_threats(self, limit: int = 200, status: str | None = None) -> list[dict]: ...

    @abstractmethod
    def summary(self) -> dict[str, Any]: ...

    @abstractmethod
    def timeline(self) -> list[dict]: ...

    @abstractmethod
    def user_stats(self) -> list[dict]: ...

    @abstractmethod
    def scores(self, limit: int = 500) -> list[dict]: ...

    # ── Q-table (RL) ──
    @abstractmethod
    def get_qrow(self, state: str) -> dict | None: ...

    @abstractmethod
    def upsert_qrow(self, row: dict) -> None: ...

    @abstractmethod
    def all_qrows(self) -> list[dict]: ...

    # ── admin feedback ──
    @abstractmethod
    def insert_feedback(self, feedback: dict) -> None: ...

    @abstractmethod
    def list_feedback(self, limit: int = 200) -> list[dict]: ...
