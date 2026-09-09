"""API integration tests — the real agent -> server path, in-process.

These drive the actual PQC secure channel (``vigil.pqc.channel.SecureClient``)
against the actual FastAPI app over ``TestClient``, so nothing about
enrollment, the ML-KEM handshake, signing, replay protection, or the pipeline is
mocked. Only the socket is.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from server.config import ServerConfig
from server.db.sqlite_store import SQLiteStorage
from server.keygen import generate
from server.main import create_app
from server.ml.train import train
from server.rl.qlearning import ACTIONS, BLOCK
from tools.synth import exfiltration_events, normal_events
from vigil.pqc import channel, sig
from vigil.schema import EventBatch

AGENT_ID = "AGENT-TEST"
HOST = "WKS-4471"


# ── fixtures ──────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def env(tmp_path_factory):
    """A fully provisioned server: PQC keys, a trained model, an empty database."""
    root = tmp_path_factory.mktemp("vigil-api")
    cfg = ServerConfig(
        db_path=str(root / "vigil.db"),
        model_path=str(root / "model.pkl"),
        keys_dir=str(root / "keys"),
        require_enroll_token=True,
        rl_epsilon=0.0,
    )
    generate(cfg)
    train(source="synthetic", out=cfg.model_path, users=12, days=14,
          n_estimators=100, check=False)

    storage = SQLiteStorage(cfg.db_path)
    storage.init_schema()
    app = create_app(cfg, storage=storage)
    with TestClient(app) as client:
        yield {"cfg": cfg, "app": app, "client": client, "storage": storage}


@pytest.fixture
def agent_keys():
    pk, sk = sig.generate_keypair()
    return pk, sk


def _token(env) -> str:
    r = env["client"].post("/api/enroll-token")
    assert r.status_code == 200
    return r.json()["token"]


def _enroll(env, agent_id: str, verify_key: bytes, token: str | None = None):
    return env["client"].post("/api/agent/enroll", json={
        "agent_id": agent_id,
        "host": HOST,
        "token": token if token is not None else _token(env),
        "verify_key_b64": base64.b64encode(verify_key).decode(),
    })


def _connect(env, agent_id: str, keys) -> channel.SecureClient:
    """Enroll + handshake, returning a ready-to-seal client."""
    pk, sk = keys
    r = _enroll(env, agent_id, pk)
    assert r.status_code == 200, r.text
    server_ek = base64.b64decode(r.json()["server_kem_public_b64"])

    client = channel.SecureClient(agent_id, sk, server_ek)
    r = env["client"].post("/api/agent/handshake", json=client.handshake())
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "established"
    return client


def _send(env, secure: channel.SecureClient, events):
    batch = EventBatch(agent_id=secure.agent_id, host=HOST, events=events)
    sealed = secure.seal(batch.to_json_bytes())
    return env["client"].post("/api/agent/events", json=sealed)


# ── enrollment ────────────────────────────────────────────────────────────────
def test_enroll_returns_the_server_kem_key_and_fingerprint(env, agent_keys):
    pk, _ = agent_keys
    r = _enroll(env, "AGENT-ENROLL-1", pk)
    assert r.status_code == 200
    body = r.json()
    assert body["kem_algorithm"] == "ML-KEM-512"
    assert body["sig_algorithm"] == "ML-DSA-44"
    assert len(base64.b64decode(body["server_kem_public_b64"])) == 800
    assert len(body["server_kem_fingerprint"]) == 16


def test_enroll_requires_a_valid_token(env, agent_keys):
    pk, _ = agent_keys
    r = _enroll(env, "AGENT-NO-TOKEN", pk, token="not-a-real-token")
    assert r.status_code == 401


def test_enroll_token_cannot_be_reused(env, agent_keys):
    pk, _ = agent_keys
    token = _token(env)
    assert _enroll(env, "AGENT-TOK-A", pk, token=token).status_code == 200
    assert _enroll(env, "AGENT-TOK-B", pk, token=token).status_code == 401


def test_enroll_rejects_a_wrong_length_key(env):
    r = _enroll(env, "AGENT-BAD-KEY", b"too-short")
    assert r.status_code == 400
    assert "1312" in r.json()["detail"]


def test_reenrolling_with_a_different_key_is_refused(env, agent_keys):
    """An impostor must not be able to swap out a known agent's identity key."""
    pk, _ = agent_keys
    assert _enroll(env, "AGENT-STABLE", pk).status_code == 200
    other_pk, _ = sig.generate_keypair()
    r = _enroll(env, "AGENT-STABLE", other_pk)
    assert r.status_code == 409
    # ...and the original key still stands.
    assert env["storage"].get_agent_verify_key("AGENT-STABLE") == pk


def test_the_stored_verify_key_is_never_exposed_over_the_api(env, agent_keys):
    pk, _ = agent_keys
    _enroll(env, "AGENT-REDACT", pk)
    agents = env["client"].get("/api/agents").json()
    entry = next(a for a in agents if a["agent_id"] == "AGENT-REDACT")
    assert "verify_key" not in entry
    assert entry["verify_key_len"] == 1312


# ── handshake ─────────────────────────────────────────────────────────────────
def test_handshake_establishes_a_session(env, agent_keys):
    secure = _connect(env, "AGENT-HS", agent_keys)
    assert secure.established
    agents = env["client"].get("/api/agents").json()
    entry = next(a for a in agents if a["agent_id"] == "AGENT-HS")
    assert entry["online"] is True
    assert entry["session"]["key_bits"] == 256


def test_handshake_from_an_unknown_agent_is_rejected(env, agent_keys):
    _, sk = agent_keys
    keys = env["app"].state.keys
    secure = channel.SecureClient("AGENT-GHOST", sk, keys["kem_public"])
    r = env["client"].post("/api/agent/handshake", json=secure.handshake())
    assert r.status_code == 401


def test_handshake_with_a_forged_signature_is_rejected(env, agent_keys):
    pk, sk = agent_keys
    r = _enroll(env, "AGENT-FORGE", pk)
    server_ek = base64.b64decode(r.json()["server_kem_public_b64"])

    # Sign with a key the server has never seen for this agent.
    _, impostor_sk = sig.generate_keypair()
    impostor = channel.SecureClient("AGENT-FORGE", impostor_sk, server_ek)
    r = env["client"].post("/api/agent/handshake", json=impostor.handshake())
    assert r.status_code == 401
    assert r.json()["detail"] == "authentication failed"


# ── ingest ────────────────────────────────────────────────────────────────────
def test_events_before_a_handshake_are_refused(env, agent_keys):
    pk, sk = agent_keys
    r = _enroll(env, "AGENT-NOHS", pk)
    server_ek = base64.b64decode(r.json()["server_kem_public_b64"])
    secure = channel.SecureClient("AGENT-NOHS", sk, server_ek)
    secure._session_key = b"\x00" * 32          # pretend we have a key
    r = _send(env, secure, [])
    assert r.status_code == 409


def test_benign_batch_is_accepted_without_raising_a_critical(env, agent_keys):
    secure = _connect(env, "AGENT-BENIGN", agent_keys)
    events = normal_events(num_users=2, days=1, agent_id="AGENT-BENIGN", seed=5)
    r = _send(env, secure, events[:400])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "accepted"
    assert body["events_received"] == len(events[:400])
    assert body["windows_evaluated"] > 0
    assert body["highest_severity"] != "CRITICAL"


def test_a_replayed_batch_is_rejected(env, agent_keys):
    secure = _connect(env, "AGENT-REPLAY", agent_keys)
    batch = EventBatch(agent_id="AGENT-REPLAY", host=HOST, events=[])
    sealed = secure.seal(batch.to_json_bytes())

    assert env["client"].post("/api/agent/events", json=sealed).status_code == 200
    again = env["client"].post("/api/agent/events", json=sealed)
    assert again.status_code == 409
    assert "replay" in again.json()["detail"].lower()


def test_a_tampered_ciphertext_is_rejected_before_decryption(env, agent_keys):
    secure = _connect(env, "AGENT-TAMPER", agent_keys)
    batch = EventBatch(agent_id="AGENT-TAMPER", host=HOST, events=[])
    sealed = secure.seal(batch.to_json_bytes())

    raw = bytearray(base64.b64decode(sealed["ciphertext"]))
    raw[0] ^= 0xFF
    sealed["ciphertext"] = base64.b64encode(bytes(raw)).decode()

    r = env["client"].post("/api/agent/events", json=sealed)
    assert r.status_code == 401                       # signature fails first
    assert r.json()["detail"] == "authentication failed"


def test_events_are_attributed_to_the_authenticated_agent(env, agent_keys):
    """A compromised endpoint must not be able to blame another agent."""
    secure = _connect(env, "AGENT-ATTRIB", agent_keys)
    events = normal_events(num_users=1, days=1, agent_id="SOMEONE-ELSE", seed=3)[:50]
    assert all(e.agent_id == "SOMEONE-ELSE" for e in events)

    r = _send(env, secure, events)
    assert r.status_code == 200
    assert r.json()["agent_id"] == "AGENT-ATTRIB"

    stored = env["storage"].recent_events(limit=50)
    assert stored and all(row["agent_id"] == "AGENT-ATTRIB" for row in stored)


# ── the poster scenario, end to end ───────────────────────────────────────────
@pytest.fixture(scope="module")
def exfil(env):
    """Stream the after-hours USB exfiltration scenario through the real channel."""
    pk, sk = sig.generate_keypair()
    secure = _connect(env, AGENT_ID, (pk, sk))
    events = exfiltration_events(agent_id=AGENT_ID, host=HOST)
    r = _send(env, secure, events)
    assert r.status_code == 200, r.text
    return r.json()


def test_exfiltration_scenario_raises_a_blocking_threat(env, exfil):
    assert exfil["anomalies"] >= 1
    assert exfil["threats"] >= 1
    assert exfil["highest_severity"] in ("HIGH", "CRITICAL")

    threats = [t for t in env["client"].get("/api/threats").json() if t["user"] == "jdoe"]
    # The scenario spans two hour windows (the transfer, then the disconnect and
    # logoff); the transfer window is the one that carries the volume.
    worst = min(threats, key=lambda t: t["anomaly_score"])
    assert worst["is_anomaly"] is True
    assert worst["action"] == BLOCK
    assert worst["severity"] == "CRITICAL"
    assert worst["state"] == "ah1|usb1|vol3|anom1"
    assert {"after_hours", "removable_device", "large_transfer"} <= set(worst["rules_fired"])


def test_a_block_decision_emits_a_simulated_containment_directive(env, exfil):
    assert exfil["directives"], "a BLOCK decision must produce a directive"
    d = exfil["directives"][0]
    assert d["type"] == "CONTAIN"
    assert d["mode"] == "simulated"          # documented, non-destructive
    assert "notify_user" in d["steps"]


def test_re_evaluating_a_window_updates_rather_than_duplicates(env, agent_keys):
    """An open window is re-scored on every batch; that must stay one incident."""
    secure = _connect(env, "AGENT-DEDUP", agent_keys)
    events = exfiltration_events(agent_id="AGENT-DEDUP", host="WKS-DEDUP", user="dupe")

    _send(env, secure, events[: len(events) // 2])
    _send(env, secure, events[len(events) // 2 :])

    keys = [t["window_key"] for t in env["client"].get("/api/threats?limit=2000").json()
            if t["user"] == "dupe"]
    assert keys, "the scenario should raise at least one threat"
    assert len(keys) == len(set(keys)), f"duplicate incidents for one window: {keys}"


# ── dashboard reads ───────────────────────────────────────────────────────────
def test_health_reports_the_pqc_suite_and_live_state(env, exfil):
    body = env["client"].get("/api/health").json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert body["agents_enrolled"] >= 1
    assert body["sessions_active"] >= 1
    assert body["events_stored"] > 0
    assert body["pqc"] == {"kem": "ML-KEM-512", "sig": "ML-DSA-44", "aead": "AES-256-GCM"}


def test_summary_always_reports_every_severity_and_status_bucket(env, exfil):
    body = env["client"].get("/api/summary").json()
    assert set(body["by_severity"]) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(body["by_status"]) == {"open", "blocked", "dismissed"}
    assert body["total_threats"] >= 1
    assert body["critical_threats"] >= 1


def test_pushed_summary_has_the_same_shape_as_the_rest_one(env, exfil):
    """A summary that arrives over the socket must not be a poorer relation.

    When these two drifted, the dashboard's headline count flickered to zero on
    every connect — the pushed payload was missing ``open_threats`` entirely.
    """
    rest = env["client"].get("/api/summary").json()
    with env["client"].websocket_connect("/api/ws") as ws:
        hello = ws.receive_json()
    assert hello["type"] == "hello"
    assert set(hello["data"]["summary"]) == set(rest)


def test_threat_detail_includes_the_current_policy_view(env, exfil):
    threat_id = env["client"].get("/api/threats").json()[0]["id"]
    body = env["client"].get(f"/api/threats/{threat_id}").json()
    assert body["id"] == threat_id
    assert body["policy"]["state"] == body["state"]
    assert body["policy"]["action"] in ACTIONS


def test_unknown_threat_is_a_404(env):
    assert env["client"].get("/api/threats/999999").status_code == 404


def test_threats_rejects_an_unknown_status_filter(env):
    assert env["client"].get("/api/threats?status=nonsense").status_code == 400


def test_timeline_covers_all_twenty_four_hours(env, exfil):
    body = env["client"].get("/api/timeline").json()
    assert [row["hour"] for row in body] == list(range(24))
    assert sum(row["count"] for row in body) >= 1


def test_scores_endpoint_reports_the_decision_threshold(env, exfil):
    body = env["client"].get("/api/scores").json()
    assert isinstance(body["threshold"], float)
    assert body["scores"]


def test_users_endpoint_ranks_exfiltrating_users_worst_first(env, exfil):
    rows = env["client"].get("/api/users").json()
    scores = [r["min_anomaly_score"] for r in rows]
    assert scores == sorted(scores), "users must be ordered worst-first"

    jdoe = next(r for r in rows if r["user"] == "jdoe")
    assert jdoe["high_sev"] >= 1
    assert jdoe["min_anomaly_score"] < env["client"].get("/api/scores").json()["threshold"]


def test_pqc_endpoint_documents_the_standardised_algorithms(env):
    body = env["client"].get("/api/pqc").json()
    assert body["kem"]["standard"] == "NIST FIPS 203"
    assert body["signature"]["standard"] == "NIST FIPS 204"
    assert body["aead"]["algorithm"] == "AES-256-GCM"
    assert body["aead"]["key_bytes"] == 32
    assert body["protocol"]["session_keys_persisted"] is False


def test_config_endpoint_never_leaks_key_material(env):
    body = env["client"].get("/api/config").text
    assert "secret" not in body.lower().replace("kem_secret_path", "")
    assert env["client"].get("/api/config").json()["feature_cols"][0] == "hour"


def test_model_endpoint_reports_the_trained_feature_contract(env):
    body = env["client"].get("/api/model").json()
    assert body["type"] == "IsolationForest"
    assert body["n_features"] == len(body["feature_cols"])


# ── the RL feedback loop ──────────────────────────────────────────────────────
def test_confirming_a_threat_rewards_the_policy_and_closes_the_incident(env, exfil):
    threats = env["client"].get("/api/threats?status=open").json()
    target = min((t for t in threats if t["user"] == "jdoe"),
                 key=lambda t: t["anomaly_score"])
    state = target["state"]

    before = env["client"].get("/api/rl/qtable").json()["table"]
    q_before = next(r for r in before if r["state"] == state)["q"][BLOCK]

    r = env["client"].post("/api/feedback", json={"threat_id": target["id"], "action": "block"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "blocked"
    assert body["learning"]["reward"] == 1.0
    assert body["learning"]["policy_after"] == BLOCK

    after = env["client"].get("/api/rl/qtable").json()["table"]
    q_after = next(r for r in after if r["state"] == state)["q"][BLOCK]
    assert q_after > q_before, "confirming a block must reinforce it"

    assert env["client"].get(f"/api/threats/{target['id']}").json()["status"] == "blocked"


def test_feedback_is_logged_for_audit(env, exfil):
    rows = env["client"].get("/api/rl/feedback").json()
    assert rows and rows[0]["admin_action"] in ("block", "dismiss")
    assert rows[0]["reward"] is not None


def test_dismissing_a_threat_moves_the_policy_away_from_blocking(env, agent_keys):
    secure = _connect(env, "AGENT-FP", agent_keys)
    events = exfiltration_events(agent_id="AGENT-FP", host="WKS-FP", user="falsepos")
    assert _send(env, secure, events).status_code == 200

    target = min((t for t in env["client"].get("/api/threats?limit=2000").json()
                  if t["user"] == "falsepos"), key=lambda t: t["anomaly_score"])
    state = target["state"]
    q_before = env["client"].get("/api/rl/stats").json()
    assert q_before["policy"][state] == BLOCK

    r = env["client"].post("/api/feedback",
                           json={"threat_id": target["id"], "action": "dismiss"})
    assert r.status_code == 200
    learning = r.json()["learning"]
    assert learning["reward"] == -1.0
    assert learning["q_after"][BLOCK] < learning["q_before"][BLOCK]


def test_feedback_rejects_an_invalid_verdict(env, exfil):
    threat_id = env["client"].get("/api/threats").json()[0]["id"]
    r = env["client"].post("/api/feedback", json={"threat_id": threat_id, "action": "maybe"})
    assert r.status_code == 400


def test_feedback_on_a_missing_threat_is_a_404(env):
    r = env["client"].post("/api/feedback", json={"threat_id": 999999, "action": "block"})
    assert r.status_code == 404


def test_qtable_exposes_the_whole_policy_for_the_dashboard(env):
    body = env["client"].get("/api/rl/qtable").json()
    assert body["states"] == 32
    assert len(body["table"]) == 32
    row = body["table"][0]
    assert set(row) >= {"state", "after_hours", "usb", "volume", "ml_anomaly",
                        "q", "visits", "best_action", "risk_prior", "untrained"}


# ── live push ─────────────────────────────────────────────────────────────────
def test_dashboard_websocket_receives_a_hello_then_live_threats(env, agent_keys):
    with env["client"].websocket_connect("/api/ws") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        assert hello["data"]["pqc"]["kem"] == "ML-KEM-512"

        secure = _connect(env, "AGENT-WS", agent_keys)
        events = exfiltration_events(agent_id="AGENT-WS", host="WKS-WS", user="wsuser")
        assert _send(env, secure, events).status_code == 200

        kinds = []
        for _ in range(4):
            kinds.append(ws.receive_json()["type"])
            if "threat" in kinds:
                break
        assert "threat" in kinds, kinds


def test_websocket_broadcast_survives_a_dropped_dashboard(env, agent_keys):
    """A dead socket must never break ingest for everyone else."""
    with env["client"].websocket_connect("/api/ws") as ws:
        ws.receive_json()
    # The manager notices on the next send; ingest must still succeed.
    secure = _connect(env, "AGENT-WS2", agent_keys)
    assert _send(env, secure, []).status_code == 200
