"""One-box demo: boot the real server, then drive it through the real PQC channel.

Everything here is the production code path. The script provisions a *separate*
demo workspace (its own keys, database, and model), launches
``python -m server.main`` as a real uvicorn subprocess, waits for it to become
healthy, and then runs :mod:`tools.replay` against it over HTTP — enrolling,
handshaking with ML-KEM-512, and posting AES-256-GCM-sealed batches.

    python scripts/run_local_demo.py

Then open http://127.0.0.1:8000 and click Block or Dismiss on a threat. The
server stays in the foreground until Ctrl-C.

The demo workspace is deliberately not the default one: an experiment should
never be able to corrupt a real deployment's database or, worse, rotate the keys
that enrolled endpoints have already pinned.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

import httpx

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from server.config import ServerConfig            # noqa: E402
from server.keygen import generate as generate_server_keys  # noqa: E402
from server.keygen import keys_exist              # noqa: E402
from vigil.console import enable_utf8             # noqa: E402


def demo_config(root: str, port: int) -> ServerConfig:
    return ServerConfig(
        host="127.0.0.1",
        port=port,
        db_path=os.path.join(root, "vigil.db"),
        model_path=os.path.join(root, "model.pkl"),
        keys_dir=os.path.join(root, "keys"),
        # The demo mints its own tokens through the API, so leave the requirement on:
        # running with it off would rehearse a configuration nobody should deploy.
        require_enroll_token=True,
    )


def provision(cfg: ServerConfig, users: int, days: int) -> None:
    """Create whatever the demo workspace is missing. Idempotent."""
    os.makedirs(os.path.dirname(cfg.db_path) or ".", exist_ok=True)

    if keys_exist(cfg):
        print(f"[demo] reusing PQC keys in {cfg.keys_dir}")
    else:
        print(f"[demo] generating ML-KEM-512 + ML-DSA-44 keys in {cfg.keys_dir}")
        generate_server_keys(cfg)

    if os.path.exists(cfg.model_path):
        print(f"[demo] reusing detection model {cfg.model_path}")
    else:
        from server.ml.train import train

        print(f"[demo] training the Isolation Forest ({users} users x {days} days "
              f"of synthetic benign activity)")
        train(source="synthetic", out=cfg.model_path, users=users, days=days,
              n_estimators=150, check=False)


def server_env(cfg: ServerConfig) -> dict:
    """Env overrides for the child server. ``VIGIL_*`` wins over any YAML on disk."""
    env = dict(os.environ)
    env.update({
        "VIGIL_HOST": cfg.host,
        "VIGIL_PORT": str(cfg.port),
        "VIGIL_DB_PATH": cfg.db_path,
        "VIGIL_MODEL_PATH": cfg.model_path,
        "VIGIL_KEYS_DIR": cfg.keys_dir,
        "PYTHONUNBUFFERED": "1",
    })
    return env


def wait_for_health(base_url: str, timeout: float, proc: subprocess.Popen) -> dict:
    """Poll until the server answers, or the child dies, or we run out of patience."""
    deadline = time.monotonic() + timeout
    last_error = "no response"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(
                f"[demo] the server exited during startup (code {proc.returncode}). "
                f"Its output is above."
            )
        try:
            resp = httpx.get(f"{base_url}/api/health", timeout=2.0)
            if resp.status_code == 200:
                return resp.json()
            last_error = f"HTTP {resp.status_code}"
        except httpx.HTTPError as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise SystemExit(f"[demo] server did not become healthy within {timeout:.0f}s "
                     f"({last_error})")


def dashboard_note() -> None:
    dist = os.path.join(REPO_ROOT, "frontend", "dist", "index.html")
    if os.path.isfile(dist):
        return
    print("[demo] the React dashboard is not built yet — the server will serve the")
    print("[demo] JSON API only. To get the SOC console:")
    print("[demo]     cd frontend && npm install && npm run build")


def main(argv: list[str] | None = None) -> int:
    enable_utf8()
    ap = argparse.ArgumentParser(description="Run the whole VIGIL AI stack on one box.")
    ap.add_argument("--dir", default=os.path.join(REPO_ROOT, "demo"),
                    help="demo workspace: keys, database, model (default: ./demo)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--reset", action="store_true",
                    help="delete the demo workspace first (fresh keys, empty database)")
    ap.add_argument("--train-users", type=int, default=25)
    ap.add_argument("--train-days", type=int, default=20)
    ap.add_argument("--baseline-days", type=int, default=2,
                    help="days of benign traffic to replay before the scenarios")
    ap.add_argument("--pace", type=float, default=0.0,
                    help="seconds between sealed batches, to watch alerts arrive live")
    ap.add_argument("--no-replay", action="store_true",
                    help="just boot the server; inject nothing")
    ap.add_argument("--startup-timeout", type=float, default=90.0)
    args = ap.parse_args(argv)

    if args.reset and os.path.isdir(args.dir):
        print(f"[demo] removing {args.dir}")
        shutil.rmtree(args.dir)

    cfg = demo_config(args.dir, args.port)
    provision(cfg, args.train_users, args.train_days)
    dashboard_note()

    base_url = f"http://{cfg.host}:{cfg.port}"
    print(f"[demo] starting the detection server on {base_url}")
    proc = subprocess.Popen(
        [sys.executable, "-m", "server.main"],
        cwd=REPO_ROOT, env=server_env(cfg),
    )

    try:
        health = wait_for_health(base_url, args.startup_timeout, proc)
        print(f"[demo] server healthy — PQC {health['pqc']['kem']} + "
              f"{health['pqc']['aead']} + {health['pqc']['sig']}")

        if not args.no_replay:
            from tools import replay

            print("[demo] replaying synthetic activity through the secure channel")
            code = replay.main([
                "--server", base_url,
                "--agent-id", "AGENT-DEMO",
                "--baseline-days", str(args.baseline_days),
                "--pace", str(args.pace),
                "--keys-dir", os.path.join(args.dir, "keys-replay"),
            ])
            if code != 0:
                print(f"[demo] replay failed (exit {code})", file=sys.stderr)

        print()
        print("─" * 78)
        print(f"[demo] dashboard  {base_url}")
        print(f"[demo] API docs   {base_url}/docs")
        print(f"[demo] workspace  {args.dir}")
        print("[demo] Click Block or Dismiss on a threat to move the Q-learning policy.")
        print("[demo] Ctrl-C to stop the server.")
        print("─" * 78)
        proc.wait()
    except KeyboardInterrupt:
        print("\n[demo] stopping")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
