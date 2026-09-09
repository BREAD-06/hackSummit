"""ML-DSA-44 (Dilithium2) digital signatures.

Thin wrappers around ``dilithium_py.ml_dsa.ML_DSA_44``. The endpoint agent owns a
long-lived signing keypair; the server stores each agent's public key at
enrollment and uses it to authenticate every handshake and event batch.

Key/signature sizes (bytes) for ML-DSA-44:
    verification key (public) : 1312
    signing key      (secret) : 2560
    signature                 : 2420
"""

from __future__ import annotations

from dilithium_py.ml_dsa import ML_DSA_44

ALGORITHM = "ML-DSA-44"         # FIPS 204 — the standardised form of Dilithium2
STANDARD = "NIST FIPS 204"
CLASSICAL_EQUIV_BITS = 128      # NIST PQC security category 2
PK_LEN = 1312   # verification (public) key length
SK_LEN = 2560   # signing (secret) key length
SIG_LEN = 2420  # signature length


def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(verify_key, sign_key)`` = ``(public, secret)``."""
    pk, sk = ML_DSA_44.keygen()
    return pk, sk


def sign(sign_key: bytes, message: bytes) -> bytes:
    """Sign ``message`` with the secret signing key."""
    return ML_DSA_44.sign(sign_key, message)


def verify(verify_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return ``True`` iff ``signature`` is a valid ML-DSA-44 signature.

    Never raises on a bad signature or a malformed input — a wrong-length
    signature simply returns ``False`` — so callers can treat the boolean as the
    single source of truth.
    """
    try:
        return bool(ML_DSA_44.verify(verify_key, message, signature))
    except (ValueError, TypeError):
        return False
