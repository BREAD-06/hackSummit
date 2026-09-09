"""Unit tests for the post-quantum primitives (KEM, signatures, AEAD)."""

import os

import pytest

from vigil.pqc import aead, kem, sig


# ── ML-KEM-512 ────────────────────────────────────────────────────────────────
def test_kem_roundtrip_shared_secret_matches():
    ek, dk = kem.generate_keypair()
    assert len(ek) == kem.EK_LEN
    assert len(dk) == kem.DK_LEN

    ss_a, ct = kem.encapsulate(ek)
    assert len(ct) == kem.CT_LEN
    assert len(ss_a) == kem.SS_LEN

    ss_b = kem.decapsulate(dk, ct)
    assert ss_a == ss_b


def test_kem_distinct_keys_yield_distinct_secrets():
    ek1, _ = kem.generate_keypair()
    ek2, _ = kem.generate_keypair()
    ss1, _ = kem.encapsulate(ek1)
    ss2, _ = kem.encapsulate(ek2)
    assert ss1 != ss2


def test_kem_wrong_secret_key_gives_different_secret():
    # ML-KEM implicit rejection: decapsulating with the wrong key yields a
    # (deterministic) different secret rather than an error.
    ek, _dk = kem.generate_keypair()
    _ek2, dk2 = kem.generate_keypair()
    ss_a, ct = kem.encapsulate(ek)
    ss_wrong = kem.decapsulate(dk2, ct)
    assert ss_wrong != ss_a


# ── ML-DSA-44 ─────────────────────────────────────────────────────────────────
def test_sig_verify_valid():
    pk, sk = sig.generate_keypair()
    assert len(pk) == sig.PK_LEN
    msg = b"vigil event batch"
    signature = sig.sign(sk, msg)
    assert len(signature) == sig.SIG_LEN
    assert sig.verify(pk, msg, signature) is True


def test_sig_rejects_tampered_message():
    pk, sk = sig.generate_keypair()
    signature = sig.sign(sk, b"original")
    assert sig.verify(pk, b"tampered", signature) is False


def test_sig_rejects_wrong_key():
    _pk1, sk1 = sig.generate_keypair()
    pk2, _sk2 = sig.generate_keypair()
    signature = sig.sign(sk1, b"msg")
    assert sig.verify(pk2, b"msg", signature) is False


def test_sig_rejects_malformed_signature_without_raising():
    pk, _sk = sig.generate_keypair()
    assert sig.verify(pk, b"msg", b"too-short") is False


# ── AES-256-GCM + HKDF ────────────────────────────────────────────────────────
def test_aead_roundtrip():
    key = aead.derive_session_key(os.urandom(32), "AGENT-01")
    assert len(key) == aead.KEY_LEN
    nonce, ct = aead.encrypt(key, b'{"n":1}', aad=b"AGENT-01")
    assert len(nonce) == aead.NONCE_LEN
    assert aead.decrypt(key, nonce, ct, aad=b"AGENT-01") == b'{"n":1}'


def test_aead_rejects_tampered_ciphertext():
    key = aead.derive_session_key(os.urandom(32), "AGENT-01")
    nonce, ct = aead.encrypt(key, b"secret", aad=b"AGENT-01")
    flipped = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(Exception):
        aead.decrypt(key, nonce, flipped, aad=b"AGENT-01")


def test_aead_rejects_wrong_aad():
    key = aead.derive_session_key(os.urandom(32), "AGENT-01")
    nonce, ct = aead.encrypt(key, b"secret", aad=b"AGENT-01")
    with pytest.raises(Exception):
        aead.decrypt(key, nonce, ct, aad=b"AGENT-02")


def test_derive_session_key_is_deterministic_and_agent_bound():
    ss = os.urandom(32)
    assert aead.derive_session_key(ss, "A") == aead.derive_session_key(ss, "A")
    assert aead.derive_session_key(ss, "A") != aead.derive_session_key(ss, "B")
