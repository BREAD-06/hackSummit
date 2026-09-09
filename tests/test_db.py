"""Storage-layer tests — schema, agents, tokens, events, threats, Q-rows, feedback."""

from __future__ import annotations

import pytest

from server.db.sqlite_store import SQLiteStorage


@pytest.fixture()
def store(tmp_path):
    s = SQLiteStorage(str(tmp_path / "test.db"))
    s.init_schema()
    yield s
    s.close()


def test_init_schema_is_idempotent(store):
    store.init_schema()
    store.init_schema()
    assert store.count_events() == 0


def test_agent_enroll_and_verify_key_roundtrip(store):
    key = bytes(range(256)) * 5  # 1280 bytes of binary, like a real ML-DSA key
    store.upsert_agent("AGENT-1", key, "WKS-1")

    meta = store.get_agent("AGENT-1")
    assert meta["agent_id"] == "AGENT-1"
    assert meta["host"] == "WKS-1"
    # The API-facing dict must never carry the raw key material.
    assert "verify_key" not in meta
    assert meta["verify_key_len"] == len(key)

    # ...but the internal accessor returns it byte-for-byte.
    assert store.get_agent_verify_key("AGENT-1") == key
    assert store.get_agent_verify_key("nope") is None


def test_agent_upsert_replaces_key_and_lists(store):
    store.upsert_agent("A", b"old", "H1")
    store.upsert_agent("A", b"newkey", "H2")
    assert store.get_agent_verify_key("A") == b"newkey"
    assert store.get_agent("A")["host"] == "H2"
    assert len(store.list_agents()) == 1

    store.upsert_agent("B", b"k", "H3")
    assert {a["agent_id"] for a in store.list_agents()} == {"A", "B"}


def test_touch_agent_updates_last_seen(store):
    store.upsert_agent("A", b"k", "H")
    before = store.get_agent("A")["last_seen"]
    store.touch_agent("A")
    assert store.get_agent("A")["last_seen"] >= before


def test_enroll_token_is_single_use(store):
    store.add_enroll_token("tok-abc")
    assert store.consume_enroll_token("tok-abc", "AGENT-1") is True
    # replay of the same token must fail
    assert store.consume_enroll_token("tok-abc", "AGENT-2") is False
    # unknown token must fail
    assert store.consume_enroll_token("does-not-exist", "AGENT-3") is False


def test_insert_events_and_counts(store):
    store.insert_events([])          # no-op, must not raise
    assert store.count_events() == 0

    store.insert_events([
        {"event_id": "e1", "ts": "2026-02-03T22:15:00+00:00", "agent_id": "A",
         "host": "H", "user": "jdoe", "log_type": "file", "action": "create",
         "path": r"C:\x.zip", "size_bytes": 2469606195, "detail": {"sensitive": True}},
        {"event_id": "e2", "ts": "2026-02-03T22:16:00+00:00", "agent_id": "A",
         "host": "H", "user": "jdoe", "log_type": "device", "action": "Connect",
         "path": None, "size_bytes": None, "detail": None},
    ])
    assert store.count_events() == 2

    recent = store.recent_events(limit=10)
    assert len(recent) == 2
    assert recent[0]["event_id"] == "e2"          # newest first
    assert recent[0]["size_bytes"] == 0           # None coerced to 0
    assert recent[1]["size_bytes"] == 2469606195  # 2.3 GB survives as INTEGER


def _threat(**over):
    t = {
        "window_key": "A|jdoe|H|2026-02-03T22:00:00+00:00",
        "agent_id": "A", "user": "jdoe", "host": "H",
        "window_start": "2026-02-03T22:00:00+00:00",
        "hour": 22, "day_of_week": 1,
        "anomaly_score": -0.11, "is_anomaly": True,
        "state": "ah1|usb1|vol3|anom1", "action": "BLOCK", "severity": "CRITICAL",
        "rules_fired": ["after_hours_usb", "large_transfer"],
        "features": {"file_count": 40.0, "file_bytes_total": 2.4e9},
    }
    t.update(over)
    return t


def test_threat_insert_get_and_json_columns(store):
    tid = store.insert_threat(_threat())
    assert isinstance(tid, int) and tid > 0

    got = store.get_threat(tid)
    assert got["severity"] == "CRITICAL"
    assert got["status"] == "open"
    assert got["is_anomaly"] is True
    # JSON columns come back as real Python structures, not strings
    assert got["rules_fired"] == ["after_hours_usb", "large_transfer"]
    assert got["features"]["file_count"] == 40.0
    assert store.get_threat(999999) is None


def test_threat_status_update_and_filtered_list(store):
    t1 = store.insert_threat(_threat())
    store.insert_threat(_threat(user="asmith", severity="HIGH"))

    store.update_threat_status(t1, "blocked")
    assert store.get_threat(t1)["status"] == "blocked"

    assert len(store.list_threats()) == 2
    assert [t["id"] for t in store.list_threats(status="blocked")] == [t1]
    assert len(store.list_threats(status="open")) == 1


def test_summary_timeline_users_scores(store):
    store.upsert_agent("A", b"k", "H")
    store.insert_events([{"event_id": "e", "ts": "x", "agent_id": "A", "host": "H",
                          "user": "jdoe", "log_type": "file", "action": "create",
                          "path": "p", "size_bytes": 1, "detail": {}}])
    store.insert_threat(_threat())
    store.insert_threat(_threat(user="asmith", severity="LOW", hour=10,
                                anomaly_score=0.05, is_anomaly=False))

    s = store.summary()
    assert s["total_threats"] == 2
    assert s["total_events"] == 1
    assert s["total_agents"] == 1
    assert s["by_severity"] == {"CRITICAL": 1, "LOW": 1}
    assert s["by_status"] == {"open": 2}

    tl = store.timeline()
    assert len(tl) == 24                                  # every hour present
    assert [x["hour"] for x in tl] == list(range(24))
    assert next(x["count"] for x in tl if x["hour"] == 22) == 1
    assert next(x["count"] for x in tl if x["hour"] == 3) == 0

    users = store.user_stats()
    assert {u["user"] for u in users} == {"jdoe", "asmith"}
    # sorted most-anomalous (lowest score) first
    assert users[0]["user"] == "jdoe"
    assert users[0]["high_sev"] == 1

    sc = store.scores()
    assert len(sc) == 2
    assert {type(x["anomaly_score"]) for x in sc} == {float}


def test_qrow_upsert_and_read(store):
    assert store.get_qrow("s1") is None

    store.upsert_qrow({"state": "s1", "q_dismiss": -0.5, "q_alert": 0.2,
                       "q_block": 0.9, "n_dismiss": 1, "n_alert": 2, "n_block": 3})
    row = store.get_qrow("s1")
    assert row["q_block"] == pytest.approx(0.9)
    assert row["n_alert"] == 2

    # upsert on the same state must overwrite, not duplicate
    store.upsert_qrow({"state": "s1", "q_dismiss": 0.0, "q_alert": 0.0, "q_block": 1.5})
    assert store.get_qrow("s1")["q_block"] == pytest.approx(1.5)
    assert store.get_qrow("s1")["n_block"] == 0
    assert len(store.all_qrows()) == 1

    store.upsert_qrow({"state": "s0"})
    assert [r["state"] for r in store.all_qrows()] == ["s0", "s1"]


def test_feedback_log(store):
    tid = store.insert_threat(_threat())
    store.insert_feedback({"threat_id": tid, "admin_action": "block", "reward": 1.0,
                           "state": "ah1|usb1|vol3|anom1", "action": "BLOCK"})
    store.insert_feedback({"threat_id": tid, "admin_action": "dismiss", "reward": -1.0,
                           "state": "ah1|usb1|vol3|anom1", "action": "BLOCK"})
    fb = store.list_feedback()
    assert len(fb) == 2
    assert fb[0]["admin_action"] == "dismiss"      # newest first
    assert fb[0]["reward"] == pytest.approx(-1.0)
    assert fb[1]["reward"] == pytest.approx(1.0)


def test_persists_across_reopen(tmp_path):
    path = str(tmp_path / "persist.db")
    s1 = SQLiteStorage(path)
    s1.init_schema()
    s1.upsert_agent("A", b"key-bytes", "H")
    tid = s1.insert_threat(_threat())
    s1.close()

    s2 = SQLiteStorage(path)
    s2.init_schema()
    assert s2.get_agent_verify_key("A") == b"key-bytes"
    assert s2.get_threat(tid)["severity"] == "CRITICAL"
    s2.close()
