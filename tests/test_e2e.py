"""End-to-end tests — the poster's whole arc, and the tools that drive it.

What separates these from :mod:`tests.test_api` and :mod:`tests.test_agent` is the
level they work at. Those two mock the socket (``TestClient``) and drive the
channel or the transport directly, one behaviour per test. These run a **real
uvicorn server on a real port** and drive it with the **shipped command-line
tools**, so what is under test is the thing an operator actually types:

    python -m server.main
    python -m tools.replay
    python scripts/smoke_test.py

That distinction matters because the failures this level catches are the ones the
lower levels structurally cannot: a tool whose argument parsing accepts a
nonsensical combination, a learned policy silently reset to the cold-start prior
on reboot, or a console that dies the moment its output is redirected to a log
file. Every one of those leaves the unit tests green.
"""

from __future__ import annotations

import importlib.util
import io
import os
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from server.config import ServerConfig
from server.db.sqlite_store import SQLiteStorage
from server.keygen import generate as generate_server_keys
from server.main import create_app
from server.ml.train import train
from server.rl.qlearning import BLOCK, DISMISS
from tools import replay, synth
from vigil.console import enable_utf8

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXFIL_STATE = "ah1|usb1|vol3|anom1"


# ── a real server on a real port ──────────────────────────────────────────────
def _free_port() -> int:
    """Bind :0 and let the OS pick, so a parallel run cannot collide on 8000."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_healthy(base_url: str, server, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{base_url}/api/health", timeout=2.0)
            if resp.status_code == 200:
                return resp.json()
        except httpx.HTTPError:
            pass                      # not listening yet
        time.sleep(0.1)
    raise RuntimeError(f"server never became healthy (started={server.started})")


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    """A provisioned detection server, served by real uvicorn over real TCP.

    Threaded rather than a subprocess so a failure surfaces as a Python traceback
    instead of an exit code. That is only safe because ``SQLiteStorage`` holds its
    connection with ``check_same_thread=False`` behind an ``RLock``.
    """
    import uvicorn

    root = tmp_path_factory.mktemp("vigil-e2e")
    cfg = ServerConfig(
        host="127.0.0.1",
        port=_free_port(),
        db_path=str(root / "vigil.db"),
        model_path=str(root / "model.pkl"),
        keys_dir=str(root / "keys"),
        require_enroll_token=True,
        rl_epsilon=0.0,
    )
    generate_server_keys(cfg)
    train(source="synthetic", out=cfg.model_path, users=12, days=14,
          n_estimators=100, check=False)

    storage = SQLiteStorage(cfg.db_path)
    storage.init_schema()
    server = uvicorn.Server(uvicorn.Config(
        create_app(cfg, storage=storage),
        host=cfg.host, port=cfg.port, log_level="warning",
    ))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://{cfg.host}:{cfg.port}"
    try:
        _wait_until_healthy(base_url, server)
        yield {"base_url": base_url, "cfg": cfg, "root": root}
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _get(base_url: str, path: str, **params):
    resp = httpx.get(f"{base_url}{path}", params=params or None, timeout=20.0)
    resp.raise_for_status()
    return resp.json()


def _threats(base_url: str, agent_id: str) -> list[dict]:
    return [t for t in _get(base_url, "/api/threats", limit=2000)
            if t["agent_id"] == agent_id]


def _q(base_url: str, state: str) -> dict[str, float]:
    table = _get(base_url, "/api/rl/qtable")["table"]
    return next(row for row in table if row["state"] == state)["q"]


# ── the arc the poster describes ──────────────────────────────────────────────
def test_the_poster_arc_end_to_end(live_server):
    """Collect -> encrypt -> detect -> verify -> respond -> alert -> learn.

    One test on purpose. The seven stages are only worth anything as a chain, and a
    suite that checks each link separately can pass while the chain is broken —
    which is exactly the shape of bug that survives a green unit suite.
    """
    base_url = live_server["base_url"]
    agent_id = "AGENT-E2E"

    # ── stages 1-2: the endpoint enrolls, handshakes, and streams sealed batches ──
    exit_code = replay.main([
        "--server", base_url,
        "--agent-id", agent_id,
        "--scenario", "exfiltration",
        "--baseline-users", "4",
        "--baseline-days", "1",
        "--keys-dir", str(live_server["root"] / "keys-e2e"),
    ])
    assert exit_code == 0, "the replay tool failed against a healthy server"

    # ── stages 3-6: the after-hours USB exfiltration is caught and contained ──
    threats = _threats(base_url, agent_id)
    critical = [t for t in threats if t["severity"] == "CRITICAL"]
    assert critical, f"the scenario raised no CRITICAL threat (got {threats})"

    # The scenario spans two windows; the transfer window carries the volume.
    incident = min(critical, key=lambda t: t["anomaly_score"])
    assert incident["user"] == "jdoe"
    assert incident["action"] == BLOCK
    assert incident["state"] == EXFIL_STATE
    assert incident["is_anomaly"] is True
    assert {"after_hours", "removable_device", "large_transfer"} <= set(
        incident["rules_fired"])

    # Ordinary work in the same stream must not have been swept up with it. This is
    # the number that decides whether an analyst trusts the console at all. (Any
    # later replay only inflates the denominator, so the bound is order-safe.)
    windows = _get(base_url, "/api/summary")["live_windows"]
    assert windows > 0
    assert len(threats) / windows < 0.15, (
        f"{len(threats)} threats from {windows} behaviour windows — the console is "
        f"mostly benign traffic")

    # ── stage 7: the analyst confirms it, and the policy learns ──
    q_before = _q(base_url, EXFIL_STATE)
    verdict = httpx.post(f"{base_url}/api/feedback",
                         json={"threat_id": incident["id"], "action": "block"},
                         timeout=20.0).json()
    assert verdict["status"] == "blocked"
    assert verdict["learning"]["reward"] == pytest.approx(1.0)
    assert _q(base_url, EXFIL_STATE)[BLOCK] > q_before[BLOCK]

    # The incident is closed, and the verdict is on the audit trail.
    assert _get(base_url, f"/api/threats/{incident['id']}")["status"] == "blocked"
    logged = _get(base_url, "/api/rl/feedback")
    assert any(row["threat_id"] == incident["id"] for row in logged)


def test_benign_replay_alone_raises_nothing_critical(live_server):
    """The control case: no scenario injected, so nothing should be contained."""
    agent_id = "AGENT-QUIET"
    assert replay.main([
        "--server", live_server["base_url"],
        "--agent-id", agent_id,
        "--scenario", "none",
        "--baseline-users", "5",
        "--baseline-days", "2",
        "--keys-dir", str(live_server["root"] / "keys-quiet"),
    ]) == 0

    severities = {t["severity"] for t in _threats(live_server["base_url"], agent_id)}
    assert "CRITICAL" not in severities, f"benign traffic produced {severities}"


# ── the property that makes a SOC deployment survivable ───────────────────────
def test_a_learned_policy_is_not_reset_by_a_restart(tmp_path):
    """Analyst feedback must outlive the process, or a reboot costs the SOC its training.

    The trap here is quiet. Q-table rows are filled from the rule-based prior
    *lazily*, the first time a state is read — and ``/api/rl/qtable`` reads all 32
    on every dashboard poll. Seeding that wrote instead of filling gaps would erase
    weeks of verdicts on the next service restart, and nothing at the unit level
    would notice: the table would still be complete, still 32 rows, still coherent.
    """
    cfg = ServerConfig(
        db_path=str(tmp_path / "vigil.db"),
        model_path=str(tmp_path / "model.pkl"),
        keys_dir=str(tmp_path / "keys"),
        rl_epsilon=0.0,
    )
    generate_server_keys(cfg)
    train(source="synthetic", out=cfg.model_path, users=6, days=7,
          n_estimators=60, check=False)

    def boot():
        """A cold start against the same database — what a service restart is."""
        storage = SQLiteStorage(cfg.db_path)
        storage.init_schema()
        return create_app(cfg, storage=storage)     # lifespan closes the storage

    # A state the prior dismisses, taught to escalate by repeated analyst overrides.
    state = "ah0|usb0|vol1|anom0"
    app = boot()
    with TestClient(app) as client:
        learner = app.state.pipeline.learner
        assert learner.greedy_action(state) == DISMISS
        for _ in range(12):
            learner.apply_feedback(state, learner.greedy_action(state), "block")
        learned = learner.q_values(state)
        assert learner.greedy_action(state) != DISMISS
        assert client.get("/api/rl/qtable").status_code == 200   # the poll that reseeds

    app2 = boot()
    with TestClient(app2) as client:
        reloaded = app2.state.pipeline.learner
        assert reloaded.q_values(state)[BLOCK] == pytest.approx(learned[BLOCK], abs=1e-9)
        assert reloaded.greedy_action(state) != DISMISS

        table = client.get("/api/rl/qtable").json()["table"]
        row = next(r for r in table if r["state"] == state)
        # The API rounds to 4dp for display; the stored value is exact.
        assert row["q"][BLOCK] == pytest.approx(learned[BLOCK], abs=5e-5)
        assert row["untrained"] is False
        # ...while every state nobody has ruled on is still populated from the prior.
        assert len(table) == 32
        assert all(r["q"] for r in table)


# ── the smoke test is itself a shipped program ────────────────────────────────
def _load_smoke_test():
    """Import ``scripts/smoke_test.py`` by path — ``scripts/`` is not a package."""
    path = os.path.join(REPO_ROOT, "scripts", "smoke_test.py")
    spec = importlib.util.spec_from_file_location("vigil_smoke_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_smoke_test_script_reports_success(capsys):
    """``scripts/smoke_test.py`` is the first thing a new deployment runs.

    A smoke test that can report a false pass is worse than shipping none at all,
    so the suite runs the real thing and requires both exit code 0 and a clean
    report — a check that silently skipped would still exit 0.
    """
    assert _load_smoke_test().main([]) == 0
    out = capsys.readouterr().out
    assert "PASSED" in out
    assert "FAIL" not in out, "a check failed inside a run that still exited 0"


# ── replay's own argument handling and event preparation ──────────────────────
def test_replay_preserves_hour_of_day_when_moving_a_scenario_to_today():
    """After-hours is part of what makes the scenario severe — re-anchoring keeps it.

    Shifting the 22:15 burst to "now" would quietly demote a CRITICAL demo to
    MEDIUM and leave the operator with no idea why the poster's case study stopped
    reproducing.
    """
    original = synth.exfiltration_events()
    before = datetime.now(timezone.utc).date()
    events = replay.shift_onto_today(synth.exfiltration_events())
    after = datetime.now(timezone.utc).date()

    assert (events[0].ts.hour, events[0].ts.minute) == (22, 15)
    assert events[0].ts.date() in {before, after}
    # ...and the relative spacing within the scenario is untouched.
    assert [e.ts - events[0].ts for e in events] == \
           [e.ts - original[0].ts for e in original]


def test_replay_hour_override_moves_the_scenario_into_business_hours():
    """``--hour 10`` is how you demonstrate that after-hours actually matters."""
    events = replay.shift_onto_today(synth.exfiltration_events(), hour=10)
    assert (events[0].ts.hour, events[0].ts.minute) == (10, 15)


def test_replay_baseline_history_ends_today():
    """The benign window has to overlap the scenario's, or the timeline has a gap."""
    events = replay.baseline_events("A", users=2, days=2)
    assert events
    first, last = min(e.ts for e in events), max(e.ts for e in events)
    assert last - first < timedelta(days=3)
    assert last <= datetime.now(timezone.utc) + timedelta(minutes=1)


def test_replay_baseline_can_be_skipped():
    assert replay.baseline_events("A", users=0, days=2) == []
    assert replay.baseline_events("A", users=2, days=0) == []


def test_replay_severity_aggregation_keeps_the_worst():
    assert replay._worse(None, None) is None
    assert replay._worse("LOW", None) == "LOW"
    assert replay._worse("MEDIUM", "CRITICAL") == "CRITICAL"
    assert replay._worse("CRITICAL", "LOW") == "CRITICAL"
    # An unrecognised severity must not silently outrank a real one.
    assert replay._worse("HIGH", "banana") == "HIGH"


def test_replay_merge_sums_counters_and_escalates_severity():
    a = {"events": 2, "threats": 1, "highest_severity": "LOW"}
    b = {"events": 3, "threats": 0, "highest_severity": "HIGH"}
    assert replay._merge(a, b) == {"events": 5, "threats": 1,
                                   "highest_severity": "HIGH"}


def test_replay_batches_cover_every_event_exactly_once():
    """Batching is where a stream quietly loses or duplicates its tail."""
    events = synth.exfiltration_events()
    chunks = list(replay.batched(events, 7))
    assert sum(len(c) for c in chunks) == len(events)
    assert [e for c in chunks for e in c] == events


@pytest.mark.parametrize("argv", [
    ["--hour", "24"],                                # not a real hour
    ["--hour", "-1"],
    ["--user", "bob"],                               # ambiguous across two scenarios
    ["--host", "PC-1", "--scenario", "all"],
    ["--scenario", "none", "--baseline-days", "0"],   # nothing to send at all
])
def test_replay_rejects_nonsensical_arguments(argv):
    """Validation has to fail before any key is written or token minted.

    These all reach a *running server* otherwise, so a late failure means a
    half-enrolled throwaway endpoint left behind on the operator's SOC box.
    """
    with pytest.raises(SystemExit) as exc:
        replay.main(argv)
    assert exc.value.code == 2


# ── the console fix, at the level the bug actually bit ────────────────────────
def test_console_survives_a_legacy_codepage_pipe(monkeypatch):
    """A watched path with an accent must not take down an unattended agent.

    Windows hands a *pipe* the legacy code page (cp1252), not UTF-8, so this is the
    state of ``sys.stdout`` whenever the agent is redirected to a log file or run
    under Task Scheduler — which is how it runs in production. Before
    ``enable_utf8`` this died with ``UnicodeEncodeError`` on the first
    ``résumé.docx`` it logged.
    """
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout",
                        io.TextIOWrapper(raw, encoding="cp1252", newline=""))
    monkeypatch.setattr(sys, "stderr",
                        io.TextIOWrapper(io.BytesIO(), encoding="cp1252"))
    message = "C:\\Users\\a\\Documents\\résumé.docx — 2.3 GB"

    enable_utf8()
    print(message, end="")
    sys.stdout.flush()

    assert raw.getvalue().decode("utf-8") == message


def test_console_is_line_buffered_so_a_piped_log_stays_live(monkeypatch):
    """Block buffering makes a running agent look hung, and loses the final lines.

    A pipe is block-buffered at 8 KB, so progress output sits unwritten for minutes
    and a crash takes the diagnostic lines leading up to it — the ones you needed.
    """
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    enable_utf8()
    print("collector started")
    assert b"collector started" in raw.getvalue(), "the line sat in the buffer"
