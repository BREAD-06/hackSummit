"""Stage 3 — Trigger: normalise, enrich, persist, and window incoming events.

This is the first stage that touches decrypted data. It does three things:

1. **Enrich** each event with cheap, explainable context — is the path business
   sensitive? does it live on a removable drive? what extension is it? None of
   this reads file *contents*; it is all derived from the path string.
2. **Persist** the raw event metadata as an audit trail.
3. **Window** the events into ``(agent, user, host, hour)`` behaviour windows via
   :class:`vigil.features.RollingFeatureStore`, and accumulate the rule-only
   "extras" (sensitive hits, removable writes, deletes) alongside them.

Extras are kept *separate* from :data:`vigil.features.LIVE_FEATURE_COLS` on
purpose: the ML model must only ever see the columns it was trained on, while the
rule/severity layer is free to use richer context.
"""

from __future__ import annotations

import ntpath
import os
import re
from dataclasses import dataclass, field

from vigil import schema
from vigil.features import RollingFeatureStore, Window, hour_window_start
from vigil.schema import Event, EventBatch

# Windows drive letters that conventionally are not the system disk. Used only as
# a hint; the agent also tags removable media authoritatively at collection time.
_NON_SYSTEM_DRIVE = re.compile(r"^[D-Zd-z]:[\\/]")

# Extras accumulated per window for rules and severity (never fed to the model).
EXTRA_COLS = (
    "sensitive_count",
    "removable_write_count",
    "delete_count",
    "distinct_dirs",
    "max_file_bytes",
)


def path_ext(path: str | None) -> str:
    if not path:
        return ""
    return os.path.splitext(path)[1].lower()


def is_sensitive_path(path: str | None, hints: list[str], dirs: list[str]) -> bool:
    """True if a path looks business-sensitive, by configured directory or keyword."""
    if not path:
        return False
    p = path.replace("/", "\\").lower()
    for d in dirs:
        if p.startswith(d.replace("/", "\\").lower().rstrip("\\")):
            return True
    return any(h.lower() in p for h in hints)


def is_removable_path(path: str | None, detail: dict | None = None) -> bool:
    """True if the file lives on removable media.

    Trusts the agent's own ``detail['removable']`` tag when present (the collector
    asks the OS directly); otherwise falls back to a drive-letter heuristic.
    """
    if detail and detail.get("removable") is not None:
        return bool(detail["removable"])
    if not path:
        return False
    return bool(_NON_SYSTEM_DRIVE.match(path))


@dataclass
class WindowExtras:
    """Rule-only context accumulated for one behaviour window."""

    sensitive_count: float = 0.0
    removable_write_count: float = 0.0
    delete_count: float = 0.0
    max_file_bytes: float = 0.0
    dirs: set[str] = field(default_factory=set)

    def add(self, ev: Event, sensitive: bool, removable: bool) -> None:
        if ev.log_type != schema.LOG_FILE:
            return
        if sensitive:
            self.sensitive_count += 1
        if removable:
            self.removable_write_count += 1
        if ev.action == "delete":
            self.delete_count += 1
        self.max_file_bytes = max(self.max_file_bytes, float(ev.size_bytes or 0))
        if ev.path:
            self.dirs.add(ntpath.dirname(ev.path).lower())

    def as_dict(self) -> dict[str, float]:
        return {
            "sensitive_count": self.sensitive_count,
            "removable_write_count": self.removable_write_count,
            "delete_count": self.delete_count,
            "distinct_dirs": float(len(self.dirs)),
            "max_file_bytes": self.max_file_bytes,
        }


@dataclass
class TriggerResult:
    events: list[Event]
    windows: list[Window]
    extras: dict[tuple, dict[str, float]]
    persisted: int


class TriggerStage:
    """Normalises and windows a decrypted batch. Holds the live feature state."""

    def __init__(self, storage, sensitive_hints: list[str] | None = None,
                 sensitive_dirs: list[str] | None = None, persist: bool = True):
        self.storage = storage
        self.hints = list(sensitive_hints or [])
        self.dirs = list(sensitive_dirs or [])
        self.persist = persist
        self.features = RollingFeatureStore()
        self._extras: dict[tuple, WindowExtras] = {}

    # ── enrichment ──
    def enrich(self, ev: Event, policy: Any = None) -> Event:
        """Attach explainable context to an event, in place."""
        if ev.log_type == schema.LOG_FILE:
            hints = policy.monitoring.sensitive_keywords if policy else self.hints
            dirs = policy.monitoring.sensitive_dirs if policy else self.dirs
            sensitive = is_sensitive_path(ev.path, hints, dirs)
            
            # Check if USB is disabled by policy
            if policy and getattr(policy.threat_rules, "usb_policy", None) == "disabled":
                removable = False
            else:
                removable = is_removable_path(ev.path, ev.detail)

            ev.detail = {
                **(ev.detail or {}),
                "ext": path_ext(ev.path),
                "sensitive": sensitive,
                "removable": removable,
            }
        return ev

    # ── main entry point ──
    def process(self, batch: EventBatch, agent_id: str | None = None, policy: Any = None) -> TriggerResult:
        """Enrich, persist and window a batch. Returns the windows it touched."""
        agent_id = agent_id or batch.agent_id
        events: list[Event] = []
        for ev in batch.events:
            # The authenticated channel identity always wins over the payload's
            # claim, so a compromised agent cannot attribute events to another host.
            ev.agent_id = agent_id
            if not ev.host:
                ev.host = batch.host
            events.append(self.enrich(ev, policy=policy))


        persisted = 0
        if self.persist and events:
            self.storage.insert_events([_event_row(e) for e in events])
            persisted = len(events)

        windows = self.features.update(events)

        # Accumulate extras against the same window keys the feature store uses.
        for ev in events:
            key = (ev.agent_id, ev.user, ev.host, hour_window_start(ev.ts).isoformat())
            ex = self._extras.setdefault(key, WindowExtras())
            d = ev.detail or {}
            ex.add(ev, bool(d.get("sensitive")), bool(d.get("removable")))

        extras = {w.key: self._extras.get(w.key, WindowExtras()).as_dict() for w in windows}
        return TriggerResult(events=events, windows=windows, extras=extras, persisted=persisted)

    def extras_for(self, window: Window) -> dict[str, float]:
        return self._extras.get(window.key, WindowExtras()).as_dict()


def _event_row(ev: Event) -> dict:
    """Event -> storage row (timestamps as ISO-8601 text for portability)."""
    return {
        "event_id": ev.event_id,
        "ts": ev.ts.isoformat(),
        "agent_id": ev.agent_id,
        "host": ev.host,
        "user": ev.user,
        "log_type": ev.log_type,
        "action": ev.action,
        "path": ev.path,
        "size_bytes": int(ev.size_bytes or 0),
        "detail": ev.detail or {},
    }
