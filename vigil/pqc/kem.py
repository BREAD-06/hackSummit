"""ML-KEM-512 (Kyber-512) key encapsulation.

Thin, well-documented wrappers around ``kyber_py.ml_kem.ML_KEM_512`` so the rest
of the codebase never touches the library directly.

Key/ciphertext sizes (bytes) for ML-KEM-512:
    encapsulation key (public) : 800
    decapsulation key (secret) : 1632
    ciphertext                 : 768
    shared secret              : 32
"""

from __future__ import annotations

from kyber_py.ml_kem import ML_KEM_512

# Public constants (used by tests and for sanity checks on stored keys).
ALGORITHM = "ML-KEM-512"        # FIPS 203 — the standardised form of Kyber-512
STANDARD = "NIST FIPS 203"
CLASSICAL_EQUIV_BITS = 128      # NIST PQC security category 1
EK_LEN = 800   # encapsulation (public) key length
DK_LEN = 1632  # decapsulation (secret) key length
CT_LEN = 768   # ciphertext length
SS_LEN = 32    # shared-secret length


def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(encapsulation_key, decapsulation_key)`` = ``(public, secret)``."""
    ek, dk = ML_KEM_512.keygen()
    return ek, dk


def encapsulate(encapsulation_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate against a public key.

    Returns ``(shared_secret, ciphertext)``. The caller keeps ``shared_secret``
    and transmits ``ciphertext`` to the holder of the matching secret key.
    """
    shared_secret, ciphertext = ML_KEM_512.encaps(encapsulation_key)
    return shared_secret, ciphertext


def decapsulate(decapsulation_key: bytes, ciphertext: bytes) -> bytes:
    """Recover the shared secret from a ciphertext using the secret key."""
    return ML_KEM_512.decaps(decapsulation_key, ciphertext)
