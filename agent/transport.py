"""Agent transport — enrollment, the ML-KEM handshake, and sealed batch delivery.

This is the client half of the post-quantum channel. All the cryptography lives in
:mod:`vigil.pqc.channel`; this module owns the network concerns around it:

* **Enrollment** presents the one-time token and this endpoint's ML-DSA public key,
  and receives the server's ML-KEM encapsulation key. If a fingerprint is pinned in
  the config it is checked here — that is what stops a machine-in-the-middle from
  substituting its own key on first contact.
* **Handshake** encapsulates against that key and derives the AES-256-GCM session
  key. Session keys live only in memory, on both sides.
* **Send** seals a batch and posts it. A ``409`` meaning "no active session" is the
  expected response after the server restarts, so the transport re-handshakes and
  retries once rather than treating it as an error.

Nothing here retries blindly: sequence numbers must stay monotonic, so a batch that
was possibly accepted is never re-sealed under the same sequence number.
"""

from __future__ import annotations

import base64
import hashlib
import logging

import httpx

from agent.config import AgentConfig
from vigil.pqc import channel, sig
from vigil.schema import Event, EventBatch

log = logging.getLogger("vigil.agent.transport")


class TransportError(Exception):
    """Any failure to deliver telemetry to the detection server."""


class EnrollmentError(TransportError):
    """The server refused this endpoint's enrollment (bad or used token, key clash)."""


class FingerprintMismatch(EnrollmentError):
    """The server's KEM key does not match the pinned fingerprint.

    This is the machine-in-the-middle case. It is fatal by design: the agent will
    not fall back to trusting whatever key it was handed.
    """


def fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


class Transport:
    def __init__(self, cfg: AgentConfig, sign_public: bytes, sign_secret: bytes,
                 client: httpx.Client | None = None):
        self.cfg = cfg
        self._sign_public = sign_public
        self._sign_secret = sign_secret
        self.base_url = cfg.server_url.rstrip("/")
        self._owns_client = client is None
        self._http = client or httpx.Client(
            base_url=self.base_url,
            timeout=cfg.request_timeout_s,
            verify=cfg.verify_tls,
        )
        self._secure: channel.SecureClient | None = None
        self.server_ek: bytes | None = None
        self.enrolled = False
        self.batches_sent = 0
        self.events_sent = 0

    # ── lifecycle ──
    @property
    def connected(self) -> bool:
        return self._secure is not None and self._secure.established

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    # ── stage 1: enrollment ──
    def enroll(self) -> dict:
        """Register this endpoint's signing key; learn the server's KEM key."""
        payload = {
            "agent_id": self.cfg.agent_id,
            "host": self.cfg.host,
            "token": self.cfg.enroll_token,
            "verify_key_b64": base64.b64encode(self._sign_public).decode(),
        }
        try:
            resp = self._http.post("/api/agent/enroll", json=payload)
        except httpx.HTTPError as exc:
            raise TransportError(f"cannot reach the detection server at {self.base_url}: {exc}") from exc

        if resp.status_code == 401:
            raise EnrollmentError(
                "the server rejected the enrollment token. Mint a fresh one on the "
                "server with `python -m server.keygen --new-token` and put it in "
                "agent_config.yaml as enroll_token."
            )
        if resp.status_code == 409:
            raise EnrollmentError(
                f"agent_id '{self.cfg.agent_id}' is already enrolled with a different "
                f"signing key. Either restore this endpoint's original keys/ directory, "
                f"or have the admin allow re-enrollment on the server."
            )
        if resp.status_code != 200:
            raise EnrollmentError(f"enrollment failed ({resp.status_code}): {resp.text}")

        body = resp.json()
        server_ek = base64.b64decode(body["server_kem_public_b64"])
        actual = fingerprint(server_ek)

        pinned = (self.cfg.server_kem_fingerprint or "").strip().lower()
        if pinned and pinned != actual:
            raise FingerprintMismatch(
                f"server KEM fingerprint mismatch: pinned {pinned}, got {actual}. "
                f"Refusing to enroll — this is what a machine-in-the-middle looks like."
            )
        if not pinned:
            log.warning("no server_kem_fingerprint pinned — trusting %s on first use. "
                        "Copy this into agent_config.yaml to pin it.", actual)

        self.server_ek = server_ek
        self.enrolled = True
        log.info("enrolled as %s with %s (server KEM fp %s)",
                 self.cfg.agent_id, body.get("sig_algorithm", sig.ALGORITHM), actual)
        return body

    # ── stage 2: handshake ──
    def handshake(self) -> dict:
        """Establish a fresh AES-256-GCM session key via ML-KEM encapsulation."""
        if self.server_ek is None:
            self.enroll()
        assert self.server_ek is not None

        secure = channel.SecureClient(self.cfg.agent_id, self._sign_secret, self.server_ek)
        message = secure.handshake()
        try:
            resp = self._http.post("/api/agent/handshake", json=message)
        except httpx.HTTPError as exc:
            raise TransportError(f"handshake could not reach the server: {exc}") from exc

        if resp.status_code == 401:
            raise TransportError(
                "the server could not authenticate this agent. Its stored public key "
                "does not match the local keys/ directory — re-enrollment is needed."
            )
        if resp.status_code != 200:
            raise TransportError(f"handshake failed ({resp.status_code}): {resp.text}")

        self._secure = secure
        body = resp.json()
        log.info("secure session established (%s + %s)",
                 body.get("aead_algorithm", "AES-256-GCM"), body.get("kdf", "HKDF-SHA256"))
        return body

    def connect(self) -> dict:
        """Enroll if needed, then handshake. Safe to call repeatedly."""
        if not self.enrolled:
            self.enroll()
        return self.handshake()

    # ── stage 3: sealed delivery ──
    def send(self, events: list[Event]) -> dict:
        """Seal and deliver one batch. Returns the server's response body.

        Raises :class:`TransportError` if delivery failed, in which case the caller
        should requeue the events.
        """
        if self._secure is None or not self._secure.established:
            self.handshake()
        assert self._secure is not None

        batch = EventBatch(agent_id=self.cfg.agent_id, host=self.cfg.host, events=events)
        payload = batch.to_json_bytes()

        body = self._post_sealed(self._secure.seal(payload))
        if body is None:
            # The session was gone (server restarted). Re-key and seal again — the new
            # session has its own sequence space, so this is not a replay.
            log.info("server has no session for us; re-handshaking")
            self.handshake()
            body = self._post_sealed(self._secure.seal(payload))
            if body is None:
                raise TransportError("server rejected the batch even after re-handshaking")

        self.batches_sent += 1
        self.events_sent += len(events)
        return body

    def _post_sealed(self, sealed: dict) -> dict | None:
        """POST a sealed batch. Returns ``None`` if the session must be re-established."""
        try:
            resp = self._http.post("/api/agent/events", json=sealed)
        except httpx.HTTPError as exc:
            raise TransportError(f"cannot reach the detection server: {exc}") from exc

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 409:
            detail = ""
            try:
                detail = resp.json().get("detail", "")
            except ValueError:
                pass
            if "session" in detail.lower():
                return None
            # A replay rejection means our sequence number is behind the server's.
            # Re-handshaking resets both sides, which is the only safe recovery.
            raise TransportError(f"server rejected the batch: {detail or resp.text}")
        if resp.status_code == 401:
            raise TransportError(
                "the server refused to authenticate this batch — the agent's signing "
                "key no longer matches the one it enrolled with."
            )
        raise TransportError(f"batch delivery failed ({resp.status_code}): {resp.text}")

    # ── introspection ──
    def stats(self) -> dict:
        return {
            "server_url": self.base_url,
            "enrolled": self.enrolled,
            "session_active": self.connected,
            "batches_sent": self.batches_sent,
            "events_sent": self.events_sent,
            "server_kem_fingerprint": fingerprint(self.server_ek) if self.server_ek else None,
        }
