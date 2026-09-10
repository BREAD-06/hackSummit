"""SOC-facing API — everything the React dashboard reads and writes.

Read paths (`/api/summary`, `/threats`, `/timeline`, `/users`, `/scores`, `/agents`,
`/rl/*`, `/model`, `/pqc`, `/events/recent`) are plain queries against storage.

The one write path that matters is ``POST /api/feedback``: an analyst's
Block/Dismiss verdict. That is the reward signal for the Q-learning policy — the
loop the whole design turns on — so it both closes the incident and moves the
decision boundary, and reports whether the policy actually changed.
"""

from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from server.keygen import fingerprint
from server.pipeline.response import SEVERITIES, json_safe
from server.rl.qlearning import ACTIONS, ADMIN_BLOCK, ADMIN_DISMISS, all_states
from vigil.features import AFTER_HOURS_END, AFTER_HOURS_START, LIVE_FEATURE_COLS
from vigil.pqc import aead, kem, sig

log = logging.getLogger("vigil.soc_api")
router = APIRouter(prefix="/api", tags=["soc"])

OPEN, BLOCKED, DISMISSED = "open", "blocked", "dismissed"
STATUSES = (OPEN, BLOCKED, DISMISSED)


class FeedbackRequest(BaseModel):
    threat_id: int = Field(ge=1)
    action: str = Field(description=f"'{ADMIN_BLOCK}' or '{ADMIN_DISMISS}'")


def _state(request: Request):
    return request.app.state


def dashboard_summary(state) -> dict:
    """The summary shape the dashboard expects — from storage plus live state.

    One function, used by the REST route *and* every WebSocket broadcast. When the
    two drifted apart, a pushed summary silently lacked ``open_threats`` and the
    dashboard's headline number flickered to zero until the next poll corrected it.
    """
    data = state.storage.summary()
    data["by_severity"] = {sev: data["by_severity"].get(sev, 0) for sev in SEVERITIES}
    data["by_status"] = {s: data["by_status"].get(s, 0) for s in STATUSES}
    data["open_threats"] = data["by_status"][OPEN]
    data["critical_threats"] = data["by_severity"]["CRITICAL"]
    data["sessions_active"] = len(state.sessions)
    data["live_windows"] = len(state.pipeline.trigger.features.all_windows())
    return data


# ── health & metadata ─────────────────────────────────────────────────────────
@router.get("/health")
def health(request: Request):
    """Liveness plus everything needed to tell a half-provisioned server apart."""
    st = _state(request)
    return {
        "status": "ok",
        "version": st.version,
        "started_at": st.started_at.isoformat(),
        "model_loaded": st.model is not None,
        "agents_enrolled": len(st.storage.list_agents()),
        "sessions_active": len(st.sessions),
        "dashboards_connected": st.ws.count,
        "events_stored": st.storage.count_events(),
        "pqc": {"kem": kem.ALGORITHM, "sig": sig.ALGORITHM, "aead": aead.ALGORITHM},
    }


@router.get("/config")
def config(request: Request):
    """Effective server configuration (no secrets — key material is never in here)."""
    st = _state(request)
    return {
        "config": st.config.summary(),
        "after_hours": {"start_hour": AFTER_HOURS_START, "end_hour": AFTER_HOURS_END},
        "feature_cols": LIVE_FEATURE_COLS,
        "severities": list(SEVERITIES),
        "statuses": list(STATUSES),
        "actions": list(ACTIONS),
    }


@router.get("/pqc")
def pqc(request: Request):
    """Post-quantum crypto posture — the dashboard's "secure transmission" panel."""
    st = _state(request)
    keys = st.keys
    return {
        "kem": {
            "algorithm": kem.ALGORITHM, "standard": kem.STANDARD,
            "classical_equivalent_bits": kem.CLASSICAL_EQUIV_BITS,
            "public_key_bytes": kem.EK_LEN, "ciphertext_bytes": kem.CT_LEN,
            "shared_secret_bytes": kem.SS_LEN,
            "fingerprint": fingerprint(keys["kem_public"]),
        },
        "signature": {
            "algorithm": sig.ALGORITHM, "standard": sig.STANDARD,
            "classical_equivalent_bits": sig.CLASSICAL_EQUIV_BITS,
            "public_key_bytes": sig.PK_LEN, "signature_bytes": sig.SIG_LEN,
            "fingerprint": fingerprint(keys["sig_public"]),
        },
        "aead": {
            "algorithm": aead.ALGORITHM, "kdf": aead.KDF,
            "key_bytes": aead.KEY_LEN, "nonce_bytes": aead.NONCE_LEN,
        },
        "protocol": {
            "order": "encrypt-then-sign / verify-then-decrypt",
            "replay_protection": "monotonic per-session sequence numbers",
            "session_keys_persisted": False,
            "enrollment": "one-time token + trust-on-first-use key pinning",
        },
        "sessions_active": len(st.sessions),
    }


@router.get("/model")
def model_info(request: Request):
    return _state(request).pipeline.detection.info()


# ── dashboard reads ───────────────────────────────────────────────────────────
@router.get("/summary")
def summary(request: Request):
    return dashboard_summary(_state(request))


@router.get("/threats")
def threats(
    request: Request,
    limit: int = Query(200, ge=1, le=2000),
    status_filter: str | None = Query(None, alias="status"),
):
    if status_filter is not None and status_filter not in STATUSES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"status must be one of {', '.join(STATUSES)}",
        )
    return _state(request).storage.list_threats(limit=limit, status=status_filter)


@router.get("/threats/{threat_id}")
def threat_detail(threat_id: int, request: Request):
    st = _state(request)
    threat = st.storage.get_threat(threat_id)
    if threat is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"threat {threat_id} not found")
    # Show the policy's current view of this state, so an analyst can see what the
    # system would decide now — after any learning that has happened since.
    if threat.get("state"):
        threat["policy"] = st.pipeline.learner.decide(threat["state"])
    return threat


@router.get("/timeline")
def timeline(request: Request):
    return _state(request).storage.timeline()


@router.get("/users")
def users(request: Request):
    return _state(request).storage.user_stats()


@router.get("/scores")
def scores(request: Request, limit: int = Query(500, ge=1, le=5000)):
    st = _state(request)
    return {
        "threshold": st.pipeline.detection.threshold,
        "scores": st.storage.scores(limit=limit),
    }


@router.get("/agents")
def agents(request: Request):
    """Enrolled endpoints, merged with live session state (health panel)."""
    st = _state(request)
    live = {s["agent_id"]: s for s in st.sessions.all_info()}
    out = []
    for agent in st.storage.list_agents():
        session = live.get(agent["agent_id"])
        out.append({
            **agent,
            "online": session is not None,
            "session": session,
        })
    return out


@router.get("/events/recent")
def recent_events(request: Request, limit: int = Query(100, ge=1, le=1000)):
    return _state(request).storage.recent_events(limit=limit)


# ── RL insights ───────────────────────────────────────────────────────────────
@router.get("/rl/qtable")
def qtable(request: Request):
    st = _state(request)
    return {"states": len(all_states()), "table": st.pipeline.learner.table()}


@router.get("/rl/stats")
def rl_stats(request: Request):
    return _state(request).pipeline.learner.stats()


@router.get("/rl/feedback")
def rl_feedback(request: Request, limit: int = Query(200, ge=1, le=2000)):
    return _state(request).storage.list_feedback(limit=limit)


@router.post("/rl/reset")
async def rl_reset(request: Request):
    """Discard learned Q-values and fall back to the rule-based prior.

    Destructive to the learned policy, so it is a deliberate POST rather than
    something the dashboard can trigger by accident.
    """
    st = _state(request)
    await run_in_threadpool(st.pipeline.learner.reset)
    log.warning("Q-table reset to the rule-based prior by dashboard request")
    stats = st.pipeline.learner.stats()
    await st.ws.broadcast({"type": "rl_reset", "data": stats})
    return {"status": "reset", "rl": stats}


# ── the feedback loop ─────────────────────────────────────────────────────────
@router.post("/feedback")
async def feedback(req: FeedbackRequest, request: Request):
    """Apply an analyst verdict: close the incident and reward the policy."""
    st = _state(request)
    try:
        result = await run_in_threadpool(
            st.pipeline.apply_feedback, req.threat_id, req.action
        )
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"threat {req.threat_id} not found")
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    payload = json_safe(result)
    await st.ws.broadcast({"type": "feedback", "data": payload})
    await st.ws.broadcast({"type": "summary", "data": dashboard_summary(st)})
    if payload["policy_changed"]:
        await st.ws.broadcast({"type": "rl_update", "data": st.pipeline.learner.stats()})
    return payload


# ── enrollment tokens (admin action) ──────────────────────────────────────────
@router.post("/enroll-token")
def enroll_token(request: Request):
    """Mint a one-time enrollment token for a new endpoint."""
    st = _state(request)
    token = secrets.token_urlsafe(24)
    st.storage.add_enroll_token(token)
    log.info("minted an enrollment token via the dashboard")
    return {
        "token": token,
        "single_use": True,
        "usage": "put this in agent_config.yaml as enroll_token on the endpoint",
    }


# ── policy engine (enterprise administration) ───────────────────────────────
@router.get("/policy")
def get_policy(request: Request):
    """Retrieve the active enterprise security and threat policy."""
    st = _state(request)
    return st.pipeline.get_policy()


@router.put("/policy")
async def update_policy(request: Request):
    """Update enterprise threat, monitoring, and response policy rules."""
    st = _state(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid JSON payload")
    if not isinstance(body, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "payload must be a JSON object")

    new_policy = st.pipeline.update_policy(body)
    await st.ws.broadcast({"type": "policy_update", "data": new_policy})
    return new_policy


@router.post("/policy/reset")
async def reset_policy_config(request: Request):
    """Reset the enterprise policy to system default configuration."""
    st = _state(request)
    default_policy = st.pipeline.reset_policy()
    await st.ws.broadcast({"type": "policy_update", "data": default_policy})
    return default_policy


# ── live push ─────────────────────────────────────────────────────────────────

@router.websocket("/ws")
async def dashboard_socket(websocket: WebSocket):
    """Live threat feed. Push-only: inbound frames are read solely to notice hangups."""
    st = websocket.app.state
    await st.ws.connect(websocket)
    try:
        await websocket.send_json({
            "type": "hello",
            "data": {
                "version": st.version,
                "summary": dashboard_summary(st),
                "pqc": {"kem": kem.ALGORITHM, "sig": sig.ALGORITHM, "aead": aead.ALGORITHM},
            },
        })
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # a broken socket must not surface as a server error
        log.debug("dashboard socket closed: %s", exc)
    finally:
        await st.ws.disconnect(websocket)
