"""Endpoint-agent key provisioning.

The agent holds exactly one long-term keypair: **ML-DSA-44** (FIPS 204, the
standardised Dilithium2). It is this machine's identity — the server pins the
public half at enrollment and verifies every handshake and every batch against it.

The agent needs no KEM keypair of its own: it *encapsulates* against the server's
public ML-KEM key, so only the server can recover the shared secret.

Usage::

    python -m agent.keygen            # generate (refuses to overwrite)
    python -m agent.keygen --force    # rotate: requires re-enrollment on the server
    python -m agent.keygen --show     # print the public fingerprint
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat

from agent.config import AgentConfig
from vigil.console import enable_utf8
from vigil.pqc import sig


def fingerprint(public_key: bytes) -> str:
    """Short, human-comparable identity for a public key (SHA-256, first 16 hex)."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def keys_exist(cfg: AgentConfig) -> bool:
    return os.path.exists(cfg.sign_secret_path) and os.path.exists(cfg.sign_public_path)


def _write(path: str, data: bytes, secret: bool = False) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    if secret:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except OSError:
            # Windows ACLs don't map onto POSIX modes; the file still lands in the
            # user's own profile, which is the practical protection there.
            pass


def generate(cfg: AgentConfig, force: bool = False) -> dict:
    if keys_exist(cfg) and not force:
        raise SystemExit(
            f"[keygen] Agent keys already exist in '{cfg.keys_dir}'.\n"
            f"         Rotating them means the server will refuse this agent_id until\n"
            f"         an admin allows re-enrollment. Re-run with --force if intended."
        )

    pk, sk = sig.generate_keypair()
    _write(cfg.sign_public_path, pk)
    _write(cfg.sign_secret_path, sk, secret=True)

    fp = fingerprint(pk)
    print(f"[keygen] {sig.ALGORITHM} ({sig.STANDARD})")
    print(f"[keygen]   public {len(pk)}B -> {cfg.sign_public_path}")
    print(f"[keygen]   secret {len(sk)}B -> {cfg.sign_secret_path}  (keep this private)")
    print(f"[keygen]   fingerprint {fp}")
    return {"algorithm": sig.ALGORITHM, "fingerprint": fp,
            "public_bytes": len(pk), "secret_bytes": len(sk)}


def load_keys(cfg: AgentConfig) -> tuple[bytes, bytes]:
    """Return ``(public_key, secret_key)``, with an actionable error if missing."""
    if not keys_exist(cfg):
        raise FileNotFoundError(
            f"Agent keys not found in '{cfg.keys_dir}'. Generate them first:\n"
            f"    python -m agent.keygen"
        )
    with open(cfg.sign_public_path, "rb") as fh:
        pk = fh.read()
    with open(cfg.sign_secret_path, "rb") as fh:
        sk = fh.read()
    if len(pk) != sig.PK_LEN or len(sk) != sig.SK_LEN:
        raise ValueError(
            f"Agent key files look corrupt: expected {sig.PK_LEN}/{sig.SK_LEN} bytes "
            f"for {sig.ALGORITHM}, found {len(pk)}/{len(sk)}. Regenerate with "
            f"`python -m agent.keygen --force`."
        )
    return pk, sk


def main() -> None:
    enable_utf8()
    ap = argparse.ArgumentParser(description="Provision this endpoint's signing key.")
    ap.add_argument("--config", default=None, help="path to agent_config.yaml")
    ap.add_argument("--force", action="store_true", help="rotate an existing keypair")
    ap.add_argument("--show", action="store_true",
                    help="print the existing public fingerprint and exit")
    args = ap.parse_args()

    cfg = AgentConfig.load(args.config)

    if args.show:
        pk, _ = load_keys(cfg)
        print(f"[keygen] agent_id    {cfg.agent_id}")
        print(f"[keygen] algorithm   {sig.ALGORITHM}")
        print(f"[keygen] fingerprint {fingerprint(pk)}")
        return

    generate(cfg, force=args.force)
    print("[keygen] next: set server_url + enroll_token in agent_config.yaml, then")
    print("[keygen]       python -m agent.main")


if __name__ == "__main__":
    main()
