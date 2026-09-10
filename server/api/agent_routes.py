"""Agent-facing API — the post-quantum ingest path (stages 1-2 of the pipeline).

Three endpoints, in the order an endpoint agent calls them:

``POST /api/agent/enroll``
    First contact. The agent presents a one-time token and its ML-DSA-44 public
    key; the server stores that key and returns its own ML-KEM-512 encapsulation
    key plus a fingerprint the agent can pin.

``POST /api/agent/handshake``
    The agent encapsulates against the server's KEM key and signs the ciphertext.
    The server verifies the signature, decapsulates, derives the AES-256-GCM
    session key with HKDF, and holds it **in memory only**.

``POST /api/agent/events``
    Encrypted, signed, sequence-numbered event batches. Verified and replay-checked
    before decryption, then fed to the streaming pipeline. Any containment
    directives come back in the response.

Failure responses are deliberately terse — a caller that cannot authenticate does
not get to learn *why* from the error body (the detail is logged server-side).
"""

from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from server.api.soc_routes import dashboard_summary
from server.keygen import fingerprint
from server.pipeline.response import json_safe
from vigil.pqc import aead, channel, kem, sig
from vigil.schema import EventBatch

log = logging.getLogger("vigil.agent_api")
router = APIRouter(prefix="/api/agent", tags=["agent"])

_AUTH_FAILED = "authentication failed"


# ── request models ────────────────────────────────────────────────────────────
class EnrollRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    host: str = ""
    token: str = ""
    verify_key_b64: str = Field(description="agent ML-DSA-44 public key, base64")


class HandshakeRequest(BaseModel):
    agent_id: str
    kem_ct: str
    nonce: str
    ts: int
    signature: str


class SealedBatchRequest(BaseModel):
    agent_id: str
    seq: int
    nonce: str
    ciphertext: str
    signature: str


# ── helpers ───────────────────────────────────────────────────────────────────
def _state(request: Request):
    return request.app.state


def _verify_key(request: Request, agent_id: str) -> bytes:
    key = _state(request).storage.get_agent_verify_key(agent_id)
    if key is None:
        log.warning("unknown agent_id %r", agent_id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _AUTH_FAILED)
    return key


# ── endpoints ─────────────────────────────────────────────────────────────────
@router.post("/enroll")
async def enroll(req: EnrollRequest, request: Request):
    """Register an endpoint's signing key and hand back the server's KEM key."""
    st = _state(request)
    cfg, storage = st.config, st.storage

    try:
        verify_key = base64.b64decode(req.verify_key_b64, validate=True)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "verify_key_b64 is not valid base64")
    if len(verify_key) != sig.PK_LEN:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"verify key must be {sig.PK_LEN} bytes for {sig.ALGORITHM}, got {len(verify_key)}",
        )

    existing = storage.get_agent(req.agent_id)
    if existing and not cfg.allow_reenroll:
        # Re-enrolling would silently replace an endpoint's identity key, which is
        # exactly what an attacker impersonating a known agent would try.
        if storage.get_agent_verify_key(req.agent_id) != verify_key:
            log.warning("re-enroll attempt for %r with a different key — rejected", req.agent_id)
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"agent '{req.agent_id}' is already enrolled with a different key; "
                f"set allow_reenroll to rotate it",
            )
    elif cfg.require_enroll_token:
        if not req.token or not storage.consume_enroll_token(req.token, req.agent_id):
            log.warning("enrollment rejected for %r: invalid or used token", req.agent_id)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or already-used enrollment token")

    storage.upsert_agent(req.agent_id, verify_key, req.host)
    log.info("enrolled agent %r (host=%r, key fp=%s)",
             req.agent_id, req.host, fingerprint(verify_key))

    await st.ws.broadcast({"type": "agent_enrolled",
                           "data": {"agent_id": req.agent_id, "host": req.host}})

    server_ek = st.keys["kem_public"]
    return {
        "agent_id": req.agent_id,
        "kem_algorithm": kem.ALGORITHM,
        "sig_algorithm": sig.ALGORITHM,
        "aead_algorithm": aead.ALGORITHM,
        "server_kem_public_b64": base64.b64encode(server_ek).decode(),
        "server_kem_fingerprint": fingerprint(server_ek),
        "server_sig_public_b64": base64.b64encode(st.keys["sig_public"]).decode(),
        "server_sig_fingerprint": fingerprint(st.keys["sig_public"]),
    }


@router.post("/handshake")
async def handshake(req: HandshakeRequest, request: Request):
    """Establish an AES-256-GCM session key via ML-KEM-512 encapsulation."""
    st = _state(request)
    verify_key = _verify_key(request, req.agent_id)

    try:
        session_key = channel.server_accept_handshake(
            st.keys["kem_secret"],
            req.model_dump(),
            verify_key,
            max_clock_skew_s=st.config.max_clock_skew_s,
        )
    except channel.SignatureError as exc:
        log.warning("handshake signature failure for %r: %s", req.agent_id, exc)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _AUTH_FAILED)
    except channel.ChannelError as exc:
        log.warning("handshake rejected for %r: %s", req.agent_id, exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    session = st.sessions.establish(req.agent_id, session_key)
    st.storage.touch_agent(req.agent_id)
    log.info("session established with %r (%s + %s, %d-bit key)",
             req.agent_id, kem.ALGORITHM, aead.ALGORITHM, len(session_key) * 8)

    await st.ws.broadcast({"type": "agent_online", "data": session.info()})
    return {
        "status": "established",
        "agent_id": req.agent_id,
        "established_at": session.established_at.isoformat(),
        "aead_algorithm": aead.ALGORITHM,
        "kdf": aead.KDF,
        "next_seq": session.last_seq + 1,
    }


@router.post("/events")
async def events(req: SealedBatchRequest, request: Request):
    """Ingest one sealed event batch: verify -> replay-check -> decrypt -> pipeline."""
    st = _state(request)
    verify_key = _verify_key(request, req.agent_id)

    session = st.sessions.get(req.agent_id)
    if session is None:
        # Tell the agent to re-handshake rather than failing opaquely; this is the
        # normal path after a server restart, since session keys are never stored.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "no active session; perform a handshake first",
        )

    try:
        plaintext, seq = channel.server_open_batch(
            session.session_key, req.model_dump(), verify_key, session.last_seq
        )
    except channel.SignatureError as exc:
        log.warning("batch signature failure from %r: %s", req.agent_id, exc)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _AUTH_FAILED)
    except channel.ReplayError as exc:
        log.warning("replay rejected from %r: %s", req.agent_id, exc)
        raise HTTPException(status.HTTP_409_CONFLICT, "replayed or out-of-order batch")
    except channel.DecryptError as exc:
        log.warning("decrypt failure from %r: %s", req.agent_id, exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "batch could not be decrypted")

    try:
        batch = EventBatch.from_json_bytes(plaintext)
    except Exception as exc:
        log.warning("malformed batch payload from %r: %s", req.agent_id, exc)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "malformed event batch")

    # The batch decrypted and verified, so the sequence number is committed even if
    # the pipeline then errors — otherwise a crash would reopen a replay window.
    st.sessions.record_batch(req.agent_id, seq, len(batch.events))

    result = await run_in_threadpool(st.pipeline.process_batch, batch, req.agent_id)

    for envelope in result.broadcasts:
        await st.ws.broadcast(json_safe(envelope))
    if result.broadcasts:
        await st.ws.broadcast({"type": "summary", "data": dashboard_summary(st)})

    return {
        "status": "accepted",
        "seq": seq,
        **result.summary(),
        "directives": json_safe(result.directives),
        "policy": result.policy,
    }

