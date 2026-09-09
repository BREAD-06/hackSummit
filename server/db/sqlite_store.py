"""SQLite implementation of :class:`server.db.base.Storage`.

Zero-install and single-file, so the whole server deploys onto another computer
with nothing but ``pip install``. A single connection (``check_same_thread=False``)
is guarded by a re-entrant lock; WAL mode is enabled for concurrent reads. All
JSON-ish columns (features, rules, detail) are stored as TEXT via ``json.dumps``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

from server.db.base import Storage


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SQLiteStorage(Storage):
    def __init__(self, path: str = "data/vigil.db"):
        self.path = path
        if os.path.dirname(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    # ── lifecycle ──────────────────────────────────────────────────────────
    def init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id    TEXT PRIMARY KEY,
                    verify_key  BLOB NOT NULL,
                    host        TEXT,
                    enrolled_at TEXT NOT NULL,
                    last_seen   TEXT
                );
                CREATE TABLE IF NOT EXISTS enroll_tokens (
                    token      TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    used_by    TEXT,
                    used_at    TEXT
                );
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id    TEXT,
                    ts          TEXT,
                    agent_id    TEXT,
                    host        TEXT,
                    user        TEXT,
                    log_type    TEXT,
                    action      TEXT,
                    path        TEXT,
                    size_bytes  INTEGER,
                    detail      TEXT,
                    received_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
                CREATE TABLE IF NOT EXISTS threats (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    window_key    TEXT,
                    agent_id      TEXT,
                    user          TEXT,
                    host          TEXT,
                    window_start  TEXT,
                    hour          INTEGER,
                    day_of_week   INTEGER,
                    anomaly_score REAL,
                    is_anomaly    INTEGER,
                    state         TEXT,
                    action        TEXT,
                    severity      TEXT,
                    rules_fired   TEXT,
                    features      TEXT,
                    status        TEXT NOT NULL DEFAULT 'open',
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
                -- Supports the per-window upsert: one incident per open window.
                CREATE INDEX IF NOT EXISTS idx_threats_window ON threats(window_key, status);
                CREATE TABLE IF NOT EXISTS qtable (
                    state      TEXT PRIMARY KEY,
                    q_dismiss  REAL NOT NULL DEFAULT 0,
                    q_alert    REAL NOT NULL DEFAULT 0,
                    q_block    REAL NOT NULL DEFAULT 0,
                    n_dismiss  INTEGER NOT NULL DEFAULT 0,
                    n_alert    INTEGER NOT NULL DEFAULT 0,
                    n_block    INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id    INTEGER,
                    admin_action TEXT,
                    reward       REAL,
                    state        TEXT,
                    action       TEXT,
                    created_at   TEXT NOT NULL
                );
                """
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── agents ───────────────────────────────────────────────────────────────
    def upsert_agent(self, agent_id: str, verify_key: bytes, host: str) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO agents (agent_id, verify_key, host, enrolled_at, last_seen)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(agent_id) DO UPDATE SET verify_key=excluded.verify_key,
                       host=excluded.host, last_seen=excluded.last_seen""",
                (agent_id, verify_key, host, _now(), _now()),
            )
            self._conn.commit()

    def get_agent(self, agent_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            return _agent_to_dict(row) if row else None

    def get_agent_verify_key(self, agent_id: str) -> bytes | None:
        """Raw ML-DSA public key for signature verification (internal use only)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT verify_key FROM agents WHERE agent_id=?", (agent_id,)
            ).fetchone()
            return bytes(row["verify_key"]) if row else None

    def list_agents(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM agents ORDER BY enrolled_at").fetchall()
            return [_agent_to_dict(r) for r in rows]

    def touch_agent(self, agent_id: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE agents SET last_seen=? WHERE agent_id=?", (_now(), agent_id))
            self._conn.commit()

    # ── enroll tokens ──────────────────────────────────────────────────────────
    def add_enroll_token(self, token: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO enroll_tokens (token, created_at) VALUES (?, ?)",
                (token, _now()),
            )
            self._conn.commit()

    def consume_enroll_token(self, token: str, agent_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT token, used_by FROM enroll_tokens WHERE token=?", (token,)
            ).fetchone()
            if row is None or row["used_by"] is not None:
                return False
            self._conn.execute(
                "UPDATE enroll_tokens SET used_by=?, used_at=? WHERE token=?",
                (agent_id, _now(), token),
            )
            self._conn.commit()
            return True

    # ── events ──────────────────────────────────────────────────────────────────
    def insert_events(self, events: list[dict]) -> None:
        if not events:
            return
        with self._lock:
            self._conn.executemany(
                """INSERT INTO events
                   (event_id, ts, agent_id, host, user, log_type, action, path, size_bytes, detail, received_at)
                   VALUES (:event_id, :ts, :agent_id, :host, :user, :log_type, :action, :path, :size_bytes, :detail, :received_at)""",
                [
                    {
                        "event_id": e.get("event_id"),
                        "ts": e.get("ts"),
                        "agent_id": e.get("agent_id"),
                        "host": e.get("host"),
                        "user": e.get("user"),
                        "log_type": e.get("log_type"),
                        "action": e.get("action"),
                        "path": e.get("path"),
                        "size_bytes": int(e.get("size_bytes") or 0),
                        "detail": json.dumps(e.get("detail") or {}),
                        "received_at": _now(),
                    }
                    for e in events
                ],
            )
            self._conn.commit()

    def count_events(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"])

    def recent_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── threats ───────────────────────────────────────────────────────────────
    def insert_threat(self, t: dict) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO threats
                   (window_key, agent_id, user, host, window_start, hour, day_of_week,
                    anomaly_score, is_anomaly, state, action, severity, rules_fired, features,
                    status, created_at, updated_at)
                   VALUES (:window_key, :agent_id, :user, :host, :window_start, :hour, :day_of_week,
                    :anomaly_score, :is_anomaly, :state, :action, :severity, :rules_fired, :features,
                    :status, :created_at, :updated_at)""",
                {
                    "window_key": t.get("window_key"),
                    "agent_id": t.get("agent_id"),
                    "user": t.get("user"),
                    "host": t.get("host"),
                    "window_start": t.get("window_start"),
                    "hour": int(t.get("hour", 0)),
                    "day_of_week": int(t.get("day_of_week", 0)),
                    "anomaly_score": float(t.get("anomaly_score", 0.0)),
                    "is_anomaly": int(bool(t.get("is_anomaly"))),
                    "state": t.get("state"),
                    "action": t.get("action"),
                    "severity": t.get("severity"),
                    "rules_fired": json.dumps(t.get("rules_fired") or []),
                    "features": json.dumps(t.get("features") or {}),
                    "status": t.get("status", "open"),
                    "created_at": _now(),
                    "updated_at": _now(),
                },
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def find_open_threat(self, window_key: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM threats WHERE window_key=? AND status='open' "
                "ORDER BY id DESC LIMIT 1",
                (window_key,),
            ).fetchone()
            return _threat_to_dict(row) if row else None

    def upsert_threat(self, t: dict) -> tuple[int, bool]:
        """Insert, or update the open threat for the same window. Returns (id, created)."""
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM threats WHERE window_key=? AND status='open' "
                "ORDER BY id DESC LIMIT 1",
                (t.get("window_key"),),
            ).fetchone()
            if existing is None:
                return self.insert_threat(t), True

            threat_id = int(existing["id"])
            self._conn.execute(
                """UPDATE threats SET
                       anomaly_score=:anomaly_score, is_anomaly=:is_anomaly,
                       state=:state, action=:action, severity=:severity,
                       rules_fired=:rules_fired, features=:features,
                       hour=:hour, day_of_week=:day_of_week, updated_at=:updated_at
                   WHERE id=:id AND status='open'""",
                {
                    "id": threat_id,
                    "anomaly_score": float(t.get("anomaly_score", 0.0)),
                    "is_anomaly": int(bool(t.get("is_anomaly"))),
                    "state": t.get("state"),
                    "action": t.get("action"),
                    "severity": t.get("severity"),
                    "rules_fired": json.dumps(t.get("rules_fired") or []),
                    "features": json.dumps(t.get("features") or {}),
                    "hour": int(t.get("hour", 0)),
                    "day_of_week": int(t.get("day_of_week", 0)),
                    "updated_at": _now(),
                },
            )
            self._conn.commit()
            return threat_id, False

    def update_threat_status(self, threat_id: int, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE threats SET status=?, updated_at=? WHERE id=?",
                (status, _now(), threat_id),
            )
            self._conn.commit()

    def get_threat(self, threat_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM threats WHERE id=?", (threat_id,)).fetchone()
            return _threat_to_dict(row) if row else None

    def list_threats(self, limit: int = 200, status: str | None = None) -> list[dict]:
        with self._lock:
            if status:
                rows = self._conn.execute(
                    "SELECT * FROM threats WHERE status=? ORDER BY id DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            return [_threat_to_dict(r) for r in rows]

    def summary(self) -> dict[str, Any]:
        with self._lock:
            total = int(self._conn.execute("SELECT COUNT(*) c FROM threats").fetchone()["c"])
            by_sev = {
                r["severity"]: r["c"]
                for r in self._conn.execute(
                    "SELECT severity, COUNT(*) c FROM threats GROUP BY severity"
                ).fetchall()
            }
            by_status = {
                r["status"]: r["c"]
                for r in self._conn.execute(
                    "SELECT status, COUNT(*) c FROM threats GROUP BY status"
                ).fetchall()
            }
            events = self.count_events()
            agents = int(self._conn.execute("SELECT COUNT(*) c FROM agents").fetchone()["c"])
            return {
                "total_threats": total,
                "total_events": events,
                "total_agents": agents,
                "by_severity": by_sev,
                "by_status": by_status,
            }

    def timeline(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT hour, COUNT(*) c FROM threats GROUP BY hour"
            ).fetchall()
            counts = {int(r["hour"]): int(r["c"]) for r in rows}
            return [{"hour": h, "count": counts.get(h, 0)} for h in range(24)]

    def user_stats(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT user,
                          COUNT(*) threat_windows,
                          MIN(anomaly_score) min_anomaly_score,
                          SUM(CASE WHEN severity IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) high_sev,
                          MAX(updated_at) last_seen
                   FROM threats GROUP BY user ORDER BY min_anomaly_score ASC""",
            ).fetchall()
            return [dict(r) for r in rows]

    def scores(self, limit: int = 500) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT anomaly_score, severity, user, is_anomaly FROM threats ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── qtable ──────────────────────────────────────────────────────────────────
    def get_qrow(self, state: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM qtable WHERE state=?", (state,)).fetchone()
            return dict(row) if row else None

    def upsert_qrow(self, row: dict) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO qtable (state, q_dismiss, q_alert, q_block, n_dismiss, n_alert, n_block, updated_at)
                   VALUES (:state, :q_dismiss, :q_alert, :q_block, :n_dismiss, :n_alert, :n_block, :updated_at)
                   ON CONFLICT(state) DO UPDATE SET
                       q_dismiss=excluded.q_dismiss, q_alert=excluded.q_alert, q_block=excluded.q_block,
                       n_dismiss=excluded.n_dismiss, n_alert=excluded.n_alert, n_block=excluded.n_block,
                       updated_at=excluded.updated_at""",
                {
                    "state": row["state"],
                    "q_dismiss": float(row.get("q_dismiss", 0.0)),
                    "q_alert": float(row.get("q_alert", 0.0)),
                    "q_block": float(row.get("q_block", 0.0)),
                    "n_dismiss": int(row.get("n_dismiss", 0)),
                    "n_alert": int(row.get("n_alert", 0)),
                    "n_block": int(row.get("n_block", 0)),
                    "updated_at": _now(),
                },
            )
            self._conn.commit()

    def all_qrows(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM qtable ORDER BY state").fetchall()
            return [dict(r) for r in rows]

    # ── feedback ──────────────────────────────────────────────────────────────────
    def insert_feedback(self, fb: dict) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO feedback (threat_id, admin_action, reward, state, action, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    fb.get("threat_id"),
                    fb.get("admin_action"),
                    float(fb.get("reward", 0.0)),
                    fb.get("state"),
                    fb.get("action"),
                    _now(),
                ),
            )
            self._conn.commit()

    def list_feedback(self, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM feedback ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]


# ── row -> dict helpers (decode JSON columns / hide raw key blob) ────────────
def _agent_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    # Do not leak the raw verify-key blob over the API; expose only its length.
    d["verify_key_len"] = len(d.pop("verify_key", b"") or b"")
    return d


def _threat_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["rules_fired"] = json.loads(d.get("rules_fired") or "[]")
    d["features"] = json.loads(d.get("features") or "{}")
    d["is_anomaly"] = bool(d.get("is_anomaly"))
    return d
