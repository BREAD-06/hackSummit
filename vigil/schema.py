"""Canonical event model shared by the agent (producer) and server (consumer).

Every signal the endpoint agent collects — a file operation, a USB
connect/disconnect, a logon/logoff — is normalised into a single :class:`Event`
shape. Batches of events are what travel (encrypted) across the secure channel.

Only *metadata* is ever captured: a file's path, extension and size, never its
contents (matching the poster's "no raw data access — privacy preserved").
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

# ── log types ────────────────────────────────────────────────────────────────
LOG_FILE = "file"
LOG_DEVICE = "device"
LOG_LOGON = "logon"
LOG_HTTP = "http"     # not collected live, but supported for replay/CERT compatibility
LOG_EMAIL = "email"   # ditto

# ── actions ──────────────────────────────────────────────────────────────────
FILE_ACTIONS = {"create", "modify", "delete", "move"}
DEVICE_CONNECT = "Connect"
DEVICE_DISCONNECT = "Disconnect"
LOGON_ON = "Logon"
LOGON_OFF = "Logoff"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Event(BaseModel):
    """A single normalised endpoint event (metadata only)."""

    event_id: str = Field(default_factory=lambda: uuid4().hex)
    ts: datetime = Field(default_factory=_utcnow)
    agent_id: str
    host: str = ""
    user: str = ""
    log_type: str                       # one of the LOG_* constants
    action: str = ""                    # create/modify/... | Connect/Disconnect | Logon/Logoff
    path: str | None = None             # file path or URL (never file contents)
    size_bytes: int = 0                 # file size / email size in bytes
    detail: dict = Field(default_factory=dict)


class EventBatch(BaseModel):
    """A batch of events flushed together by the agent."""

    agent_id: str
    host: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    events: list[Event] = Field(default_factory=list)

    # ── canonical (de)serialisation used by the secure channel ──
    def to_json_bytes(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> "EventBatch":
        return cls.model_validate_json(raw.decode("utf-8"))
