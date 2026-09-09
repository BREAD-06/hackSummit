"""Server key provisioning — the root of trust for the post-quantum channel.

Generates the server's two long-term keypairs:

* **ML-KEM-512** (FIPS 203, the standardised Kyber-512) — agents encapsulate
  against the public encapsulation key to establish an AES-256-GCM session key.
* **ML-DSA-44** (FIPS 204, the standardised Dilithium2) — the server's signing
  identity, published so an agent can pin who it is talking to.

Usage::

    python -m server.keygen                  # generate (refuses to overwrite)
    python -m server.keygen --force          # rotate: all agents must re-handshake
    python -m server.keygen --bundle out.json  # write the agent bootstrap bundle
    python -m server.keygen --new-token       # mint a one-time enrollment token

Secret keys are written with owner-only permissions where the OS supports it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat

from server.config import ServerConfig
from vigil.console import enable_utf8
from vigil.pqc import kem, sig


def _write(path: str, data: bytes, secret: bool = False) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    if secret:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except OSError:
            # Windows ACLs don't map onto POSIX modes; the file still lands in
            # the user's profile, which is the practical protection there.
            pass


def fingerprint(public_key: bytes) -> str:
    """Short, human-comparable identity for a public key (SHA-256, first 16 hex)."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def keys_exist(cfg: ServerConfig) -> bool:
    return all(os.path.exists(p) for p in (
        cfg.kem_secret_path, cfg.kem_public_path,
        cfg.sig_secret_path, cfg.sig_public_path,
    ))


def generate(cfg: ServerConfig, force: bool = False) -> dict:
    if keys_exist(cfg) and not force:
        raise SystemExit(
            f"[keygen] Keys already exist in '{cfg.keys_dir}'.\n"
            f"         Rotating them forces every enrolled agent to re-handshake.\n"
            f"         Re-run with --force if that is what you want."
        )

    ek, dk = kem.generate_keypair()
    pk, sk = sig.generate_keypair()

    _write(cfg.kem_public_path, ek)
    _write(cfg.kem_secret_path, dk, secret=True)
    _write(cfg.sig_public_path, pk)
    _write(cfg.sig_secret_path, sk, secret=True)

    info = {
        "keys_dir": cfg.keys_dir,
        "kem": {"algorithm": kem.ALGORITHM, "public_bytes": len(ek),
                "secret_bytes": len(dk), "fingerprint": fingerprint(ek)},
        "sig": {"algorithm": sig.ALGORITHM, "public_bytes": len(pk),
                "secret_bytes": len(sk), "fingerprint": fingerprint(pk)},
    }
    print(f"[keygen] {kem.ALGORITHM}: public {len(ek)}B  secret {len(dk)}B  "
          f"fp={info['kem']['fingerprint']}")
    print(f"[keygen] {sig.ALGORITHM}: public {len(pk)}B  secret {len(sk)}B  "
          f"fp={info['sig']['fingerprint']}")
    print(f"[keygen] wrote 4 files to '{cfg.keys_dir}' (secret keys are owner-only)")
    return info


def load_keys(cfg: ServerConfig) -> dict[str, bytes]:
    """Read the server keypairs. Raises a actionable error if provisioning was skipped."""
    if not keys_exist(cfg):
        raise FileNotFoundError(
            f"Server keys not found in '{cfg.keys_dir}'. Generate them first:\n"
            f"    python -m server.keygen"
        )
    with open(cfg.kem_public_path, "rb") as fh:
        kem_public = fh.read()
    with open(cfg.kem_secret_path, "rb") as fh:
        kem_secret = fh.read()
    with open(cfg.sig_public_path, "rb") as fh:
        sig_public = fh.read()
    with open(cfg.sig_secret_path, "rb") as fh:
        sig_secret = fh.read()
    return {"kem_public": kem_public, "kem_secret": kem_secret,
            "sig_public": sig_public, "sig_secret": sig_secret}


def bundle(cfg: ServerConfig, server_url: str | None = None) -> dict:
    """The bootstrap bundle an endpoint needs to trust this server.

    Copy it to the monitored machine and point ``agent_config.yaml`` at it. The
    agent pins the KEM fingerprint, so a machine-in-the-middle cannot substitute
    its own key during enrollment.
    """
    keys = load_keys(cfg)
    return {
        "server_url": server_url or f"http://<SERVER-LAN-IP>:{cfg.port}",
        "kem_algorithm": kem.ALGORITHM,
        "sig_algorithm": sig.ALGORITHM,
        "server_kem_public_b64": base64.b64encode(keys["kem_public"]).decode(),
        "server_kem_fingerprint": fingerprint(keys["kem_public"]),
        "server_sig_public_b64": base64.b64encode(keys["sig_public"]).decode(),
        "server_sig_fingerprint": fingerprint(keys["sig_public"]),
    }


def new_token(cfg: ServerConfig) -> str:
    """Mint a one-time enrollment token and store it in the database."""
    from server.db.sqlite_store import SQLiteStorage

    token = secrets.token_urlsafe(24)
    store = SQLiteStorage(cfg.db_path)
    store.init_schema()
    store.add_enroll_token(token)
    store.close()
    return token


def main() -> None:
    enable_utf8()
    ap = argparse.ArgumentParser(description="Provision VIGIL AI server keys.")
    ap.add_argument("--config", default=None, help="path to server_config.yaml")
    ap.add_argument("--force", action="store_true",
                    help="rotate existing keys (all agents must re-enroll/handshake)")
    ap.add_argument("--bundle", nargs="?", const="agent_bootstrap.json", default=None,
                    metavar="PATH", help="write the agent bootstrap bundle and exit")
    ap.add_argument("--server-url", default=None, help="URL to embed in the bundle")
    ap.add_argument("--new-token", action="store_true",
                    help="mint a one-time enrollment token and exit")
    args = ap.parse_args()

    cfg = ServerConfig.load(args.config)

    if args.new_token:
        print(f"[keygen] enrollment token: {new_token(cfg)}")
        print("[keygen] give this to exactly one endpoint; it can only be used once.")
        return

    if args.bundle:
        data = bundle(cfg, args.server_url)
        with open(args.bundle, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print(f"[keygen] wrote bootstrap bundle -> {args.bundle}")
        print(f"[keygen] KEM fingerprint {data['server_kem_fingerprint']} "
              f"(verify this on the endpoint)")
        return

    generate(cfg, force=args.force)
    print("[keygen] next: python -m server.ml.train   then   python -m server.main")


if __name__ == "__main__":
    main()
