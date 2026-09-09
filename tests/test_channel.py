"""End-to-end tests for the secure channel protocol (handshake + sealed batches).

These exercise the exact client/server functions the network layer calls, but
entirely in-process so there is no FastAPI or socket involved.
"""

import pytest

from vigil.pqc import kem, sig
from vigil.pqc import channel
from vigil.pqc.channel import (
    ChannelError,
    DecryptError,
    ReplayError,
    SecureClient,
    SignatureError,
    server_accept_handshake,
    server_open_batch,
)


@pytest.fixture
def wired():
    """A fully wired client/server pair sharing the right keys."""
    ek, dk = kem.generate_keypair()                 # server KEM keypair
    agent_pk, agent_sk = sig.generate_keypair()     # agent signing keypair
    client = SecureClient("AGENT-01", agent_sk, ek)
    return {"ek": ek, "dk": dk, "agent_pk": agent_pk, "agent_sk": agent_sk, "client": client}


def test_full_handshake_then_batch_roundtrip(wired):
    client = wired["client"]

    hs = client.handshake()
    session_key = server_accept_handshake(wired["dk"], hs, wired["agent_pk"])
    assert len(session_key) == 32

    payload = b'{"events":[{"type":"file","action":"create"}]}'
    sealed = client.seal(payload)
    plaintext, seq = server_open_batch(session_key, sealed, wired["agent_pk"], last_seq=0)
    assert plaintext == payload
    assert seq == 1


def test_multiple_batches_increment_sequence(wired):
    client = wired["client"]
    session_key = server_accept_handshake(wired["dk"], client.handshake(), wired["agent_pk"])

    last = 0
    for i in range(1, 6):
        sealed = client.seal(f'{{"n":{i}}}'.encode())
        pt, seq = server_open_batch(session_key, sealed, wired["agent_pk"], last_seq=last)
        assert seq == i
        assert pt == f'{{"n":{i}}}'.encode()
        last = seq


def test_replay_is_rejected(wired):
    client = wired["client"]
    session_key = server_accept_handshake(wired["dk"], client.handshake(), wired["agent_pk"])

    sealed = client.seal(b'{"n":1}')
    _pt, seq = server_open_batch(session_key, sealed, wired["agent_pk"], last_seq=0)
    # Re-submitting the same batch (or any seq <= last) must fail.
    with pytest.raises(ReplayError):
        server_open_batch(session_key, sealed, wired["agent_pk"], last_seq=seq)


def test_tampered_ciphertext_fails_signature(wired):
    client = wired["client"]
    session_key = server_accept_handshake(wired["dk"], client.handshake(), wired["agent_pk"])

    sealed = client.seal(b'{"n":1}')
    # Flip a byte in the base64 ciphertext -> signature no longer matches.
    bad = dict(sealed)
    ct = bytearray(__import__("base64").b64decode(bad["ciphertext"]))
    ct[0] ^= 0x01
    bad["ciphertext"] = __import__("base64").b64encode(bytes(ct)).decode()
    with pytest.raises(SignatureError):
        server_open_batch(session_key, bad, wired["agent_pk"], last_seq=0)


def test_forged_signature_from_wrong_agent_rejected(wired):
    client = wired["client"]
    session_key = server_accept_handshake(wired["dk"], client.handshake(), wired["agent_pk"])
    sealed = client.seal(b'{"n":1}')

    # Server checks against a DIFFERENT agent's public key -> rejected.
    other_pk, _ = sig.generate_keypair()
    with pytest.raises(SignatureError):
        server_open_batch(session_key, sealed, other_pk, last_seq=0)


def test_handshake_wrong_agent_key_rejected(wired):
    client = wired["client"]
    hs = client.handshake()
    other_pk, _ = sig.generate_keypair()
    with pytest.raises(SignatureError):
        server_accept_handshake(wired["dk"], hs, other_pk)


def test_seal_before_handshake_raises(wired):
    fresh = SecureClient("AGENT-99", wired["agent_sk"], wired["ek"])
    with pytest.raises(ChannelError):
        fresh.seal(b"{}")


def test_wrong_session_key_fails_decrypt(wired):
    """Signature valid but session key wrong -> AES-GCM auth fails."""
    client = wired["client"]
    server_accept_handshake(wired["dk"], client.handshake(), wired["agent_pk"])
    sealed = client.seal(b'{"n":1}')
    wrong_key = b"\x00" * 32
    with pytest.raises(DecryptError):
        server_open_batch(wrong_key, sealed, wired["agent_pk"], last_seq=0)
