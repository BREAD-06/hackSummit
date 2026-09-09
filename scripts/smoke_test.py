"""Installation smoke test — the whole arc, in-process, in under a minute.

No network, no ports, no subprocess: this boots the real FastAPI app against a
throwaway workspace and drives it through :class:`agent.transport.Transport`, so
what gets exercised is the production path — ML-KEM-512 handshake, ML-DSA-44
signatures, AES-256-GCM sealing, trigger, Isolation Forest, Q-learning
verification, response, WebSocket push, and the analyst feedback loop.

    python scripts/smoke_test.py

Run this first on a new machine. It answers "is this deployment actually
working?" without needing a second computer, a USB stick, or a browser. Exit
code 0 means every check passed; anything else means stop and read the failure.

It is deliberately not a substitute for ``pytest tests/`` — the test suite covers
the failure modes (tamper, replay, impostor keys). This covers the happy path
end to end, which is the thing a fresh install most often gets wrong.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time
import traceback

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from vigil.console import enable_utf8  # noqa: E402

PASS, FAIL = "ok  ", "FAIL"


class Checks:
    """A running tally that reports the first failing expectation per step."""

    def __init__(self) -> None:
        self.failures: list[str] = []

    def step(self, name: str) -> None:
        print(f"  ..   {name}", end="\r", flush=True)
        self._current = name

    def ok(self, detail: str = "") -> None:
        print(f"  {PASS} {self._current}" + (f" — {detail}" if detail else ""))

    def fail(self, detail: str) -> None:
        print(f"  {FAIL} {self._current} — {detail}")
        self.failures.append(f"{self._current}: {detail}")

    def expect(self, condition: bool, detail: str) -> bool:
        if not condition:
            self.fail(detail)
        return condition


def run(workspace: str, checks: Checks, keep: bool = False) -> None:
    from fastapi.testclient import TestClient

    from agent.config import AgentConfig
    from agent.keygen import generate as generate_agent_keys
    from agent.keygen import load_keys as load_agent_keys
    from agent.transport import Transport
    from server.config import ServerConfig
    from server.db.sqlite_store import SQLiteStorage
    from server.keygen import generate as generate_server_keys
    from server.main import create_app
    from server.ml.train import train
    from server.rl.qlearning import BLOCK
    from tools import synth
    from vigil.pqc import aead, kem, sig

    # ── 1. post-quantum primitives ────────────────────────────────────────────
    checks.step("post-quantum primitives round-trip")
    ek, dk = kem.generate_keypair()
    shared, ct = kem.encapsulate(ek)
    if checks.expect(kem.decapsulate(dk, ct) == shared, "ML-KEM shared secrets differ"):
        pk, sk = sig.generate_keypair()
        message = b"vigil smoke test"
        signature = sig.sign(sk, message)
        good = sig.verify(pk, message, signature)
        bad = sig.verify(pk, b"tampered", signature)
        key = aead.derive_session_key(shared, "AGENT-SMOKE")
        nonce, box = aead.encrypt(key, b"payload", aad=b"aad")
        opened = aead.decrypt(key, nonce, box, aad=b"aad")
        if checks.expect(good and not bad, "ML-DSA verification is not discriminating") \
                and checks.expect(opened == b"payload", "AES-256-GCM round-trip failed"):
            checks.ok(f"{kem.ALGORITHM} · {sig.ALGORITHM} · {aead.ALGORITHM}")

    # ── 2. provisioning ───────────────────────────────────────────────────────
    checks.step("server keys and detection model")
    cfg = ServerConfig(
        db_path=os.path.join(workspace, "vigil.db"),
        model_path=os.path.join(workspace, "model.pkl"),
        keys_dir=os.path.join(workspace, "keys"),
        require_enroll_token=True,
        rl_epsilon=0.0,
    )
    generate_server_keys(cfg)
    train(source="synthetic", out=cfg.model_path, users=12, days=14,
          n_estimators=100, check=False)
    checks.expect(os.path.exists(cfg.model_path), "no model file was written")
    checks.ok(f"{os.path.getsize(cfg.model_path) // 1024} KB model")

    # ── 3. the server ─────────────────────────────────────────────────────────
    checks.step("detection server boots")
    storage = SQLiteStorage(cfg.db_path)
    storage.init_schema()
    with TestClient(create_app(cfg, storage=storage)) as client:
        health = client.get("/api/health").json()
        checks.expect(health["status"] == "ok", f"health is {health.get('status')!r}")
        checks.expect(health["model_loaded"] is True, "the model did not load")
        checks.ok(f"v{health['version']}, PQC {health['pqc']['kem']}")

        # ── 4. enrollment + handshake, through the real transport ─────────────
        checks.step("endpoint enrolls and establishes a session")
        token = client.post("/api/enroll-token").json()["token"]
        agent_cfg = AgentConfig(
            agent_id="AGENT-SMOKE",
            server_url=str(client.base_url),
            enroll_token=token,
            keys_dir=os.path.join(workspace, "agent-keys"),
            collect_files=False, collect_usb=False, collect_logon=False,
            apply_directives=False,
        )
        generate_agent_keys(agent_cfg)
        apk, ask = load_agent_keys(agent_cfg)
        transport = Transport(agent_cfg, apk, ask, client=client)
        info = transport.connect()
        checks.expect(info["status"] == "established", "handshake did not establish")
        checks.expect(len(transport.server_ek or b"") == 800,
                      "the server's ML-KEM key is the wrong size")
        checks.ok(f"{info['aead_algorithm']} keyed via {kem.ALGORITHM}, "
                  f"fp {transport.stats()['server_kem_fingerprint']}")

        # ── 5. an impostor is refused ─────────────────────────────────────────
        checks.step("an unenrolled endpoint is refused")
        from vigil.pqc import channel

        _, impostor_sk = sig.generate_keypair()
        impostor = channel.SecureClient("AGENT-GHOST", impostor_sk, transport.server_ek)
        refused = client.post("/api/agent/handshake", json=impostor.handshake())
        if checks.expect(refused.status_code == 401,
                         f"expected 401, got {refused.status_code}"):
            checks.ok("401 authentication failed")

        # ── 6. benign traffic stays quiet ─────────────────────────────────────
        checks.step("benign activity does not raise a critical alert")
        benign = synth.normal_events(num_users=3, days=1,
                                     agent_id=agent_cfg.agent_id, seed=5)
        body = transport.send(benign[:400])
        checks.expect(body["status"] == "accepted", "benign batch was not accepted")
        checks.expect(body["windows_evaluated"] > 0, "no behaviour windows were built")
        if checks.expect(body["highest_severity"] != "CRITICAL",
                         f"benign traffic produced {body['highest_severity']}"):
            checks.ok(f"{body['events_received']} events, "
                      f"{body['windows_evaluated']} windows, "
                      f"highest severity {body['highest_severity'] or 'none'}")

        # ── 7. the poster scenario is caught, and pushed live ─────────────────
        checks.step("after-hours USB exfiltration is detected and pushed live")
        with client.websocket_connect("/api/ws") as ws:
            hello = ws.receive_json()
            checks.expect(hello["type"] == "hello", f"first frame was {hello['type']!r}")

            events = synth.exfiltration_events(agent_id=agent_cfg.agent_id,
                                               host="WKS-SMOKE", user="smokeuser")
            body = transport.send(events)
            pushed = []
            for _ in range(4):
                pushed.append(ws.receive_json()["type"])
                if "threat" in pushed:
                    break

        checks.expect(body["threats"] >= 1, "the scenario raised no threat")
        checks.expect(body["highest_severity"] == "CRITICAL",
                      f"highest severity was {body['highest_severity']!r}, expected CRITICAL")
        checks.expect("threat" in pushed, f"no threat pushed over the socket: {pushed}")
        if checks.expect(bool(body["directives"]), "a BLOCK produced no directive"):
            directive = body["directives"][0]
            checks.expect(directive["mode"] == "simulated",
                          f"directive mode is {directive['mode']!r}, must be simulated")
            checks.ok(f"CRITICAL, {len(body['directives'])} simulated directive(s), "
                      f"pushed as {pushed[-1]!r}")

        # ── 8. the analyst feedback loop moves the policy ─────────────────────
        checks.step("analyst feedback updates the Q-learning policy")
        threats = [t for t in client.get("/api/threats?status=open").json()
                   if t["user"] == "smokeuser"]
        if checks.expect(bool(threats), "no open threat to give feedback on"):
            target = min(threats, key=lambda t: t["anomaly_score"])
            state = target["state"]
            before = next(r for r in client.get("/api/rl/qtable").json()["table"]
                          if r["state"] == state)["q"][BLOCK]
            result = client.post("/api/feedback",
                                 json={"threat_id": target["id"], "action": "block"}).json()
            after = next(r for r in client.get("/api/rl/qtable").json()["table"]
                         if r["state"] == state)["q"][BLOCK]
            checks.expect(result["status"] == "blocked",
                          f"threat status is {result['status']!r}")
            checks.expect(after > before,
                          f"Q({state}, BLOCK) did not increase: {before} -> {after}")
            if checks.expect(
                    client.get(f"/api/threats/{target['id']}").json()["status"] == "blocked",
                    "the threat was not closed"):
                checks.ok(f"Q({state}, BLOCK) {before:+.3f} -> {after:+.3f}, "
                          f"reward {result['learning']['reward']:+.1f}")

        # ── 9. everything the dashboard reads ─────────────────────────────────
        checks.step("dashboard endpoints all answer")
        for path in ("/api/summary", "/api/threats", "/api/timeline", "/api/scores",
                     "/api/users", "/api/agents", "/api/events/recent", "/api/pqc",
                     "/api/model", "/api/config", "/api/rl/qtable", "/api/rl/stats",
                     "/api/rl/feedback"):
            resp = client.get(path)
            if not checks.expect(resp.status_code == 200,
                                 f"{path} returned {resp.status_code}"):
                break
        else:
            summary = client.get("/api/summary").json()
            timeline = client.get("/api/timeline").json()
            checks.expect(len(timeline) == 24, "the timeline is not 24 hours long")
            checks.ok(f"{summary['total_threats']} threats, "
                      f"{summary['total_events']} events stored")

        # ── 10. the raw audit trail is metadata only ──────────────────────────
        checks.step("stored events carry metadata only, never file contents")
        rows = client.get("/api/events/recent?limit=50").json()
        if checks.expect(bool(rows), "no events were persisted"):
            forbidden = {"content", "contents", "data", "body", "bytes"}
            leaked = sorted(forbidden & set().union(*(set(r) for r in rows)))
            if checks.expect(not leaked, f"event rows expose {leaked}"):
                checks.ok(f"{len(rows)} rows, fields: "
                          f"{', '.join(sorted(rows[0]))[:60]}…")

        transport.close()

    # ── 11. session keys were never written down ───────────────────────────────
    checks.step("session keys were never persisted")
    with open(cfg.db_path, "rb") as fh:
        blob = fh.read()
    # The 32-byte AES key is indistinguishable from noise, so it cannot be searched
    # for directly. What *is* checkable is the structural guarantee: no schema
    # anywhere in the file names a session key, so there is nowhere to have put it.
    if checks.expect(b"session_key" not in blob.lower(),
                     "the database schema mentions session_key"):
        checks.ok(f"{len(blob) // 1024} KB database, no session-key column")

    if keep:
        print(f"\n  workspace kept at {workspace}")


def main(argv: list[str] | None = None) -> int:
    enable_utf8()
    ap = argparse.ArgumentParser(description="Verify a VIGIL AI installation end to end.")
    ap.add_argument("--keep", action="store_true", help="do not delete the temp workspace")
    args = ap.parse_args(argv)

    print("VIGIL AI — installation smoke test")
    print("─" * 78)
    workspace = tempfile.mkdtemp(prefix="vigil-smoke-")
    checks = Checks()
    started = time.monotonic()
    try:
        run(workspace, checks, keep=args.keep)
    except Exception:
        print(f"  {FAIL} unhandled error")
        traceback.print_exc()
        checks.failures.append("unhandled exception (traceback above)")
    finally:
        if not args.keep:
            shutil.rmtree(workspace, ignore_errors=True)

    elapsed = time.monotonic() - started
    print("─" * 78)
    if checks.failures:
        print(f"FAILED — {len(checks.failures)} problem(s) in {elapsed:.1f}s")
        for line in checks.failures:
            print(f"  · {line}")
        print("\nNext: run `pytest tests/ -q` for the detailed failure modes.")
        return 1
    print(f"PASSED — every check green in {elapsed:.1f}s")
    print("This installation can detect, verify, respond, and learn. Next:")
    print("  python scripts/run_local_demo.py     # the same thing, with a dashboard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
