"""Tests for event feature engineering and the rolling window store."""

from datetime import datetime, timezone

from vigil import schema
from vigil.features import (
    LIVE_FEATURE_COLS,
    RollingFeatureStore,
    aggregate_frame,
    hour_window_start,
    is_after_hours,
)
from vigil.schema import Event


def _ev(log_type, action="", *, hour=22, size=0, user="EXFIL001", host="PC-1", day=1):
    ts = datetime(2026, 1, day, hour, 30, 0, tzinfo=timezone.utc)
    return Event(agent_id="AGENT-01", host=host, user=user, log_type=log_type,
                 action=action, size_bytes=size, ts=ts)


def test_is_after_hours_boundaries():
    assert is_after_hours(3) == 1
    assert is_after_hours(22) == 1
    assert is_after_hours(7) == 0
    assert is_after_hours(20) == 0
    assert is_after_hours(13) == 0


def test_hour_window_start_truncates():
    ws = hour_window_start(datetime(2026, 1, 1, 22, 47, 33, tzinfo=timezone.utc))
    assert (ws.minute, ws.second, ws.microsecond) == (0, 0, 0)
    assert ws.hour == 22


def test_rolling_store_accumulates_one_window():
    store = RollingFeatureStore()
    events = [
        _ev(schema.LOG_LOGON, schema.LOGON_ON),
        _ev(schema.LOG_DEVICE, schema.DEVICE_CONNECT),
        _ev(schema.LOG_FILE, "create", size=1000),
        _ev(schema.LOG_FILE, "create", size=2000),
    ]
    touched = store.update(events)
    assert len(touched) == 1
    win = touched[0]
    fd = win.feature_dict()
    assert fd["logon_count"] == 1
    assert fd["usb_connect"] == 1
    assert fd["file_count"] == 2
    assert fd["file_bytes_total"] == 3000
    assert fd["is_after_hours"] == 1
    assert fd["hour"] == 22


def test_rolling_store_splits_by_hour_and_user():
    store = RollingFeatureStore()
    store.update([
        _ev(schema.LOG_FILE, "create", hour=22, user="A"),
        _ev(schema.LOG_FILE, "create", hour=23, user="A"),  # different hour
        _ev(schema.LOG_FILE, "create", hour=22, user="B"),  # different user
    ])
    assert len(store.all_windows()) == 3


def test_vector_matches_feature_order():
    store = RollingFeatureStore()
    win = store.update([_ev(schema.LOG_FILE, "create", size=500)])[0]
    fd = win.feature_dict()
    assert win.vector() == [fd[c] for c in LIVE_FEATURE_COLS]


def test_aggregate_frame_matches_rolling_store():
    """The two code paths must produce identical feature values."""
    events = [
        _ev(schema.LOG_LOGON, schema.LOGON_ON, hour=22),
        _ev(schema.LOG_FILE, "create", hour=22, size=1000),
        _ev(schema.LOG_FILE, "modify", hour=22, size=2500),
        _ev(schema.LOG_DEVICE, schema.DEVICE_CONNECT, hour=22),
        _ev(schema.LOG_DEVICE, schema.DEVICE_DISCONNECT, hour=22),
    ]
    store = RollingFeatureStore()
    win = store.update(events)[0]
    rolling = win.feature_dict()

    frame = aggregate_frame(events)
    assert len(frame) == 1
    row = frame.iloc[0]
    for col in LIVE_FEATURE_COLS:
        assert float(row[col]) == float(rolling[col]), col


def test_aggregate_frame_empty():
    frame = aggregate_frame([])
    assert len(frame) == 0
    for col in LIVE_FEATURE_COLS:
        assert col in frame.columns
