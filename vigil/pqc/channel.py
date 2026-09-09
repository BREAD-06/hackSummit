"""The VIGIL AI secure channel — ties KEM + signatures + AEAD into a protocol.

Two message types cross the wire, both carried as JSON-friendly dicts (bytes are
base64-encoded):

1. **Handshake** — sent once when an agent connects. The agent encapsulates
   against the server's public ML-KEM key to agree on a shared secret, derives an
   AES session key from it, and signs the handshake so the server can
   authenticate the agent.

2. **SealedBatch** — sent for every batch of collected events. The JSON payload
   is encrypted with the AES session key and signed with the agent's ML-DSA key.

Design choices for correctness:

- **Encrypt-then-sign, verify-then-decrypt.** The server verifies the ML-DSA
  signature *before* attempting AES-GCM decryption, so forged or corrupted
  traffic is rejected without ever feeding attacker-controlled bytes to the
  cipher.
- **Length-prefixed framing** of everything that gets signed (:func:`_frame`),
  so concatenation is unambiguous and a signature can never be "shifted" between
  fields.
- **Monotonic sequence numbers** give replay protection: the server refuses any
  batch whose sequence number is not strictly greater than the last one seen.

The classes here hold no network or database state; the agent's networking lives
in ``agent.transport`` and the server's per-agent session state is persisted by
``server.db``. That keeps this module fully unit-testable in-process.
"""

from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass, asdict

from vigil.pqc import aead, kem, sig


# ── errors ──────────────────────────────────────────────────────────────────
class ChannelError(Exception):
    """Base class for all secure-channel failures."""


class SignatureError(ChannelError):
    """The ML-DSA signature did not verify."""


class ReplayError(ChannelError):
    """A batch's sequence number was not strictly increasing (possible replay)."""


class DecryptError(ChannelError):
    """AES-GCM authentication/decryption failed."""


# ── helpers ─────────────────────────────────────────────────────────────────
def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _frame(*parts: bytes) -> bytes:
    """Concatenate byte parts with 4-byte big-endian length prefixes.

    Unambiguous: ``_frame(b"ab", b"c") != _frame(b"a", b"bc")``.
    """
    out = bytearray()
    for p in parts:
        out += len(p).to_bytes(4, "big")
        out += p
    return bytes(out)


def _handshake_signing_bytes(agent_id: str, kem_ct: bytes, nonce: bytes, ts: int) -> bytes:
    return _frame(
        b"vigil-ai/handshake/v1",
        agent_id.encode("utf-8"),
        kem_ct,
        nonce,
        str(ts).encode("ascii"),
    )


def _batch_signing_bytes(agent_id: str, seq: int, nonce: bytes, ciphertext: bytes) -> bytes:
    return _frame(
        b"vigil-ai/batch/v1",
        agent_id.encode("utf-8"),
        seq.to_bytes(8, "big"),
        nonce,
        ciphertext,
    )


def _batch_aad(agent_id: str, seq: int) -> bytes:
    """Additional authenticated data binding a ciphertext to (agent, seq)."""
    return _frame(agent_id.encode("utf-8"), seq.to_bytes(8, "big"))


# ── wire messages ───────────────────────────────────────────────────────────
@dataclass
class Handshake:
    agent_id: str
    kem_ct: str      # base64 — ML-KEM ciphertext
    nonce: str       # base64 — random handshake nonce
    ts: int          # unix seconds
    signature: str   # base64 — ML-DSA signature over the framed fields

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Handshake":
        return cls(
            agent_id=str(d["agent_id"]),
            kem_ct=str(d["kem_ct"]),
            nonce=str(d["nonce"]),
            ts=int(d["ts"]),
            signature=str(d["signature"]),
        )


@dataclass
class SealedBatch:
    agent_id: str
    seq: int
    nonce: str        # base64 — AES-GCM nonce
    ciphertext: str   # base64 — AES-GCM ciphertext (includes tag)
    signature: str    # base64 — ML-DSA signature over the framed fields

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "SealedBatch":
        return cls(
            agent_id=str(d["agent_id"]),
            seq=int(d["seq"]),
            nonce=str(d["nonce"]),
            ciphertext=str(d["ciphertext"]),
            signature=str(d["signature"]),
        )


# ── client (endpoint agent) side ─────────────────────────────────────────────
class SecureClient:
    """Agent-side secure channel. Stateful: holds the session key and sequence.

    Usage::

        client = SecureClient(agent_id, sign_key, server_ek)
        handshake = client.handshake()          # -> dict, POST to /api/agent/handshake
        sealed = client.seal(json_bytes)        # -> dict, POST to /api/agent/events
    """

    def __init__(self, agent_id: str, sign_key: bytes, server_ek: bytes):
        self.agent_id = agent_id
        self._sign_key = sign_key
        self._server_ek = server_ek
        self._session_key: bytes | None = None
        self._seq = 0

    @property
    def established(self) -> bool:
        return self._session_key is not None

    def handshake(self) -> dict:
        """Perform KEM encapsulation and produce a signed handshake message.

        Side effect: stores the derived session key so later :meth:`seal` calls
        work. Calling it again rekeys the session and resets the sequence.
        """
        shared_secret, kem_ct = kem.encapsulate(self._server_ek)
        self._session_key = aead.derive_session_key(shared_secret, self.agent_id)
        self._seq = 0

        nonce = os.urandom(16)
        ts = int(time.time())
        signature = sig.sign(
            self._sign_key,
            _handshake_signing_bytes(self.agent_id, kem_ct, nonce, ts),
        )
        return Handshake(
            agent_id=self.agent_id,
            kem_ct=_b64e(kem_ct),
            nonce=_b64e(nonce),
            ts=ts,
            signature=_b64e(signature),
        ).to_dict()

    def seal(self, plaintext: bytes) -> dict:
        """Encrypt + sign a payload into a :class:`SealedBatch` dict."""
        if self._session_key is None:
            raise ChannelError("handshake() must be called before seal()")
        self._seq += 1
        seq = self._seq
        aad = _batch_aad(self.agent_id, seq)
        nonce, ciphertext = aead.encrypt(self._session_key, plaintext, aad)
        signature = sig.sign(
            self._sign_key,
            _batch_signing_bytes(self.agent_id, seq, nonce, ciphertext),
        )
        return SealedBatch(
            agent_id=self.agent_id,
            seq=seq,
            nonce=_b64e(nonce),
            ciphertext=_b64e(ciphertext),
            signature=_b64e(signature),
        ).to_dict()


# ── server side (stateless — session state is persisted by the caller) ───────
def server_accept_handshake(
    kem_decapsulation_key: bytes,
    handshake: dict,
    agent_verify_key: bytes,
    max_clock_skew_s: int = 300,
) -> bytes:
    """Authenticate a handshake and return the derived AES session key.

    The caller (``server.api.agent_routes``) persists the returned key against
    the agent id. Raises :class:`SignatureError` if the agent signature is
    invalid, or :class:`ChannelError` if the timestamp is implausible.
    """
    hs = Handshake.from_dict(handshake)
    kem_ct = _b64d(hs.kem_ct)
    nonce = _b64d(hs.nonce)
    signature = _b64d(hs.signature)

    signing_bytes = _handshake_signing_bytes(hs.agent_id, kem_ct, nonce, hs.ts)
    if not sig.verify(agent_verify_key, signing_bytes, signature):
        raise SignatureError("handshake signature verification failed")

    now = int(time.time())
    if abs(now - hs.ts) > max_clock_skew_s:
        raise ChannelError(
            f"handshake timestamp out of range (skew {now - hs.ts}s > {max_clock_skew_s}s)"
        )

    shared_secret = kem.decapsulate(kem_decapsulation_key, kem_ct)
    return aead.derive_session_key(shared_secret, hs.agent_id)


def server_open_batch(
    session_key: bytes,
    sealed: dict,
    agent_verify_key: bytes,
    last_seq: int,
) -> tuple[bytes, int]:
    """Verify, replay-check, and decrypt a sealed batch.

    Returns ``(plaintext, seq)``. The caller persists ``seq`` as the new
    ``last_seq`` for this agent. Raises :class:`SignatureError`,
    :class:`ReplayError`, or :class:`DecryptError`.
    """
    sb = SealedBatch.from_dict(sealed)
    nonce = _b64d(sb.nonce)
    ciphertext = _b64d(sb.ciphertext)
    signature = _b64d(sb.signature)

    # 1. authenticity + integrity, BEFORE touching the cipher
    signing_bytes = _batch_signing_bytes(sb.agent_id, sb.seq, nonce, ciphertext)
    if not sig.verify(agent_verify_key, signing_bytes, signature):
        raise SignatureError("batch signature verification failed")

    # 2. replay protection
    if sb.seq <= last_seq:
        raise ReplayError(f"non-increasing sequence: got {sb.seq}, last was {last_seq}")

    # 3. confidentiality
    try:
        plaintext = aead.decrypt(session_key, nonce, ciphertext, _batch_aad(sb.agent_id, sb.seq))
    except Exception as exc:  # cryptography raises InvalidTag / ValueError
        raise DecryptError(f"AES-GCM decryption failed: {exc}") from exc

    return plaintext, sb.seq
