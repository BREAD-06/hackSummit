"""Post-quantum cryptography for VIGIL AI.

The endpoint agent and the detection server communicate over a channel that is
secured entirely with NIST-standardised post-quantum primitives:

- **ML-KEM-512** (FIPS 203, the standardised form of *Kyber-512*) — key
  encapsulation, used once per session to agree on a shared secret.
- **HKDF-SHA256** — derives a 256-bit AES session key from that shared secret.
- **AES-256-GCM** — authenticated encryption of every event batch.
- **ML-DSA-44** (FIPS 204, the standardised form of *Dilithium2*) — the agent
  signs every message so the server can prove who sent it (authenticity) and
  that nothing was altered in transit (integrity).

All four are pure-Python (``kyber-py``, ``dilithium-py``, ``cryptography``) — no
native ``liboqs`` build is required, so the agent stays lightweight and portable.
"""

from vigil.pqc import kem, sig, aead, channel

__all__ = ["kem", "sig", "aead", "channel"]
