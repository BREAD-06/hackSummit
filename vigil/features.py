"""Feature engineering — turns a stream of events into model-ready feature rows.

The unit of analysis is a **behaviour window**: everything a given user did on a
given host during one calendar hour. Features are simple, interpretable counts
(how many files touched, how many bytes, whether a USB appeared, whether it was
after hours). This mirrors the original ``AnalysisAgent`` but works on live
:class:`vigil.schema.Event` objects and produces exactly the columns the live
model is trained on — so training and inference can never disagree.

Two entry points share one contribution function (:func:`_contribution`):

- :class:`RollingFeatureStore` — incremental, dict-based, used by the live
  server (fast, no pandas per event).
- :func:`aggregate_frame` — pandas-based batch aggregation, used for model
  training and offline analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from vigil import schema
from vigil.schema import Event

# Columns the live Isolation Forest is trained and scored on, in this exact order.
LIVE_FEATURE_COLS = [
    "hour",
    "day_of_week",
    "is_after_hours",
    "logon_count",
    "logoff_count",
    "usb_connect",
    "usb_disconnect",
    "file_count",
    "file_bytes_total",
]

# Counting columns (everything except the time-derived hour/day/after-hours).
_COUNT_COLS = [
    "logon_count",
    "logoff_count",
    "usb_connect",
    "usb_disconnect",
    "file_count",
    "file_bytes_total",
]

AFTER_HOURS_START = 20  # after 20:00 is "after hours"
AFTER_HOURS_END = 7     # before 07:00 is "after hours"


def is_after_hours(hour: int) -> int:
    return int(hour < AFTER_HOURS_END or hour > AFTER_HOURS_START)


def hour_window_start(ts: datetime) -> datetime:
    """Truncate a timestamp to the start of its hour (keeps tzinfo)."""
    return ts.replace(minute=0, second=0, microsecond=0)


def _contribution(ev: Event) -> dict[str, float]:
    """Per-event increments to the counting columns."""
    c = {k: 0.0 for k in _COUNT_COLS}
    lt, act = ev.log_type, ev.action
    if lt == schema.LOG_LOGON:
        if act == schema.LOGON_ON:
            c["logon_count"] = 1.0
        elif act == schema.LOGON_OFF:
            c["logoff_count"] = 1.0
    elif lt == schema.LOG_DEVICE:
        if act == schema.DEVICE_CONNECT:
            c["usb_connect"] = 1.0
        elif act == schema.DEVICE_DISCONNECT:
            c["usb_disconnect"] = 1.0
    elif lt == schema.LOG_FILE:
        c["file_count"] = 1.0
        c["file_bytes_total"] = float(ev.size_bytes or 0)
    return c


@dataclass
class Window:
    """One (agent, user, host, hour) behaviour window with accumulated counts."""

    agent_id: str
    user: str
    host: str
    window_start: datetime
    counts: dict[str, float] = field(default_factory=lambda: {k: 0.0 for k in _COUNT_COLS})

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.agent_id, self.user, self.host, self.window_start.isoformat())

    @property
    def hour(self) -> int:
        return self.window_start.hour

    @property
    def day_of_week(self) -> int:
        return self.window_start.weekday()  # 0=Monday .. 6=Sunday

    def add(self, ev: Event) -> None:
        for k, v in _contribution(ev).items():
            self.counts[k] += v

    def feature_dict(self) -> dict[str, float]:
        d = {
            "hour": float(self.hour),
            "day_of_week": float(self.day_of_week),
            "is_after_hours": float(is_after_hours(self.hour)),
        }
        d.update(self.counts)
        return d

    def vector(self) -> list[float]:
        d = self.feature_dict()
        return [d[c] for c in LIVE_FEATURE_COLS]


class RollingFeatureStore:
    """In-memory accumulator of behaviour windows for the live pipeline."""

    def __init__(self) -> None:
        self._windows: dict[tuple, Window] = {}

    def update(self, events: list[Event]) -> list[Window]:
        """Apply events; return the distinct windows that were touched."""
        touched: dict[tuple, Window] = {}
        for ev in events:
            ws = hour_window_start(ev.ts)
            key = (ev.agent_id, ev.user, ev.host, ws.isoformat())
            win = self._windows.get(key)
            if win is None:
                win = Window(ev.agent_id, ev.user, ev.host, ws)
                self._windows[key] = win
            win.add(ev)
            touched[key] = win
        return list(touched.values())

    def get(self, key: tuple) -> Window | None:
        return self._windows.get(key)

    def all_windows(self) -> list[Window]:
        return list(self._windows.values())


def aggregate_frame(events: list[Event]):
    """Aggregate a list of events into a per-window feature DataFrame.

    Used for training and offline evaluation. Requires pandas (server side).
    """
    import pandas as pd

    if not events:
        return pd.DataFrame(columns=["agent_id", "user", "host", "window_start", *LIVE_FEATURE_COLS])

    rows = []
    for ev in events:
        ws = hour_window_start(ev.ts)
        row = {
            "agent_id": ev.agent_id,
            "user": ev.user,
            "host": ev.host,
            "window_start": ws,
        }
        row.update(_contribution(ev))
        rows.append(row)

    df = pd.DataFrame(rows)
    grouped = (
        df.groupby(["agent_id", "user", "host", "window_start"])[_COUNT_COLS]
        .sum()
        .reset_index()
    )
    grouped["hour"] = grouped["window_start"].dt.hour
    grouped["day_of_week"] = grouped["window_start"].dt.weekday
    grouped["is_after_hours"] = grouped["hour"].apply(is_after_hours)
    return grouped[["agent_id", "user", "host", "window_start", *LIVE_FEATURE_COLS]]
