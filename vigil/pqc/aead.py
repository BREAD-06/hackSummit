"""Authenticated symmetric encryption for the secure channel.

The ML-KEM shared secret (32 bytes of raw entropy) is run through HKDF-SHA256 to
derive a clean 256-bit AES key that is bound to the agent's identity via the HKDF
``info`` parameter. Each message is then sealed with AES-256-GCM using a fresh
random 96-bit nonce and additional-authenticated-data (AAD) that binds the
ciphertext to the sending agent and message sequence number.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHM = "AES-256-GCM"       # NIST SP 800-38D authenticated encryption
KDF = "HKDF-SHA256"             # RFC 5869 key derivation
NONCE_LEN = 12   # AES-GCM standard nonce length (96 bits)
KEY_LEN = 32     # AES-256

_HKDF_INFO_PREFIX = b"vigil-ai/session-key/v1/"


def derive_session_key(shared_secret: bytes, agent_id: str) -> bytes:
    """Derive a 256-bit AES session key from a KEM shared secret.

    Binding ``agent_id`` into the HKDF ``info`` means two different agents that
    (astronomically improbably) produced the same shared secret would still get
    different session keys, and it documents intent.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=_HKDF_INFO_PREFIX + agent_id.encode("utf-8"),
    ).derive(shared_secret)


def encrypt(session_key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt ``plaintext`` under ``session_key``.

    Returns ``(nonce, ciphertext)``; the ciphertext already includes the GCM
    authentication tag. ``aad`` is authenticated but not encrypted.
    """
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt(session_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt and verify. Raises ``cryptography.exceptions.InvalidTag`` if the
    ciphertext, nonce, or AAD were tampered with (or the key is wrong)."""
    return AESGCM(session_key).decrypt(nonce, ciphertext, aad)
