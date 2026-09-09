"""Replay synthetic endpoint activity through the *real* agent -> server path.

This is not a database seeder and not a test fixture. It enrolls a throwaway
endpoint, performs the ML-KEM-512 handshake, and posts AES-256-GCM-sealed,
ML-DSA-44-signed batches to a **running** detection server using
:class:`agent.transport.Transport` — the same class :mod:`agent.main` uses. Every
stage on the server side is the production code path: trigger, Isolation Forest,
Q-learning verification, response, WebSocket push. The only synthetic part is
where the events came from.

Why it exists: the poster's case study is an after-hours USB exfiltration of
2.3 GB of confidential data. You cannot rehearse that on a demo machine by
actually doing it, and a screenshot of a mocked alert proves nothing.

    python -m tools.replay                       # against http://127.0.0.1:8000
    python -m tools.replay --server http://192.168.1.20:8000 --token <enroll-token>

Two days of benign activity from six users are sent *first* by default. That
traffic matters as much as the attack does: it is what shows the detector
staying quiet on ordinary work, and it gives the score histogram and the 24-hour
timeline a real distribution to sit against.

If ``--token`` is omitted the tool mints one via ``POST /api/enroll-token``,
which the server exposes unauthenticated (see the README's "What this is not"
section). Pass a token explicitly against anything but your own demo box.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

from agent.config import AgentConfig
from agent.keygen import generate as generate_agent_keys
from agent.keygen import keys_exist, load_keys
from agent.transport import Transport, TransportError
from tools import synth
from vigil.console import enable_utf8
from vigil.schema import Event

SCENARIOS = dict(synth.SCENARIOS)
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ── event preparation ─────────────────────────────────────────────────────────
def shift_onto_today(events: list[Event], hour: int | None = None) -> list[Event]:
    """Move a scenario onto today's date, preserving hour-of-day and spacing.

    The hour is preserved deliberately. After-hours is one of the four features
    that make the exfiltration scenario critical, so re-anchoring a 22:15 burst
    to "now" would quietly turn a CRITICAL demo into a MEDIUM one and leave you
    wondering why. ``--hour`` overrides it, and the tool says what it chose.
    """
    if not events:
        return events
    first = events[0].ts
    today = datetime.now(timezone.utc)
    anchor = first.replace(year=today.year, month=today.month, day=today.day)
    if hour is not None:
        anchor = anchor.replace(hour=hour)
    delta = anchor - first
    for ev in events:
        ev.ts = ev.ts + delta
    return events


def baseline_events(agent_id: str, users: int, days: int) -> list[Event]:
    """Benign history ending today, so the dashboard has a normal to compare to."""
    if users < 1 or days < 1:
        return []
    start = datetime.now(timezone.utc) - timedelta(days=days)
    return synth.normal_events(
        num_users=users, days=days, agent_id=agent_id,
        start=start.replace(tzinfo=None),
    )


def scenario_events(name: str, agent_id: str, user: str | None, host: str | None,
                    date_mode: str, hour: int | None) -> list[Event]:
    kwargs = {"agent_id": agent_id}
    if user:
        kwargs["user"] = user
    if host:
        kwargs["host"] = host
    events = SCENARIOS[name](**kwargs)
    if date_mode == "today" or hour is not None:
        events = shift_onto_today(events, hour)
    return events


# ── delivery ──────────────────────────────────────────────────────────────────
def batched(events: list[Event], size: int):
    for i in range(0, len(events), size):
        yield events[i:i + size]


def stream(transport: Transport, events: list[Event], label: str,
           batch_size: int, pace: float, quiet: bool = False) -> dict:
    """Seal and send ``events`` in batches; return the aggregated server verdict."""
    totals = {"batches": 0, "events": 0, "windows": 0, "anomalies": 0,
              "threats": 0, "highest_severity": None, "directives": 0}
    if not events:
        return totals

    chunks = list(batched(events, batch_size))
    for n, chunk in enumerate(chunks, 1):
        body = transport.send(chunk)
        totals["batches"] += 1
        totals["events"] += body.get("events_received", len(chunk))
        totals["windows"] += body.get("windows_evaluated", 0)
        totals["anomalies"] += body.get("anomalies", 0)
        totals["threats"] += body.get("threats", 0)
        totals["directives"] += len(body.get("directives") or [])
        totals["highest_severity"] = _worse(totals["highest_severity"],
                                            body.get("highest_severity"))
        if not quiet:
            print(f"  [{label}] batch {n}/{len(chunks)}  seq={body['seq']}  "
                  f"{body.get('events_received', 0)} events  "
                  f"{body.get('windows_evaluated', 0)} windows  "
                  f"{body.get('anomalies', 0)} anomalous  "
                  f"{body.get('threats', 0)} threats")
        if pace and n < len(chunks):
            time.sleep(pace)
    return totals


def _worse(a: str | None, b: str | None) -> str | None:
    """The higher of two severities, either of which may be ``None``."""
    ranked = [s for s in (a, b) if s in SEVERITY_ORDER]
    if not ranked:
        return None
    return max(ranked, key=SEVERITY_ORDER.index)


# ── reporting ─────────────────────────────────────────────────────────────────
def fetch_threats(base_url: str, agent_id: str, timeout: float = 15.0) -> list[dict]:
    """What the dashboard now shows for this replay, worst score first."""
    try:
        resp = httpx.get(f"{base_url.rstrip('/')}/api/threats",
                         params={"limit": 500}, timeout=timeout)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        print(f"[replay] could not read back /api/threats: {exc}", file=sys.stderr)
        return []
    rows = [t for t in resp.json() if t.get("agent_id") == agent_id]
    return sorted(rows, key=lambda t: t["anomaly_score"])


def print_report(base_url: str, agent_id: str, totals: dict) -> None:
    print()
    print("─" * 78)
    print(f"[replay] delivered {totals['events']} events in {totals['batches']} "
          f"sealed batches over {totals['windows']} behaviour windows")
    print(f"[replay] {totals['anomalies']} windows scored below the model's threshold, "
          f"{totals['threats']} threat records written")

    threats = fetch_threats(base_url, agent_id)
    if not threats:
        print("[replay] no threats recorded — benign traffic only, which is the "
              "correct outcome for a baseline-only run.")
        return

    print()
    print(f"{'SEV':<9} {'ACTION':<8} {'SCORE':>7}  {'USER':<10} {'HOST':<12} "
          f"{'STATE':<20} RULES")
    for t in threats:
        print(f"{t['severity']:<9} {t['action']:<8} {t['anomaly_score']:>7.3f}  "
              f"{t['user']:<10} {t['host']:<12} {t['state']:<20} "
              f"{','.join(t['rules_fired']) or '-'}")

    worst = threats[0]
    print()
    print(f"[replay] worst window: threat #{worst['id']} — {worst['severity']}, "
          f"policy chose {worst['action']}")
    if totals["directives"]:
        print(f"[replay] {totals['directives']} containment directive(s) returned to the "
              f"endpoint (simulated: notify + audit, never destructive)")
    print(f"[replay] open the dashboard and click Block or Dismiss on threat "
          f"#{worst['id']} to move the Q-learning policy for state "
          f"{worst['state']}")


# ── main ──────────────────────────────────────────────────────────────────────
def build_config(args) -> AgentConfig:
    """A throwaway endpoint identity — never the real agent's keys or config."""
    return AgentConfig(
        agent_id=args.agent_id,
        server_url=args.server,
        enroll_token=args.token or "",
        keys_dir=args.keys_dir,
        server_kem_fingerprint=args.fingerprint or "",
        request_timeout_s=args.timeout,
        verify_tls=not args.insecure,
        apply_directives=False,      # the replay tool is not a real endpoint
    )


def mint_token(base_url: str, timeout: float) -> str:
    """Ask the server for a one-time enrollment token."""
    resp = httpx.post(f"{base_url.rstrip('/')}/api/enroll-token", timeout=timeout)
    resp.raise_for_status()
    return resp.json()["token"]


def main(argv: list[str] | None = None) -> int:
    enable_utf8()
    ap = argparse.ArgumentParser(
        description="Replay synthetic activity through the real PQC agent -> server path.",
        epilog="The server must already be running: python -m server.main",
    )
    ap.add_argument("--server", default="http://127.0.0.1:8000",
                    help="detection server base URL (default: %(default)s)")
    ap.add_argument("--token", default=None,
                    help="one-time enrollment token; minted automatically if omitted")
    ap.add_argument("--agent-id", default="AGENT-REPLAY",
                    help="endpoint identity to enroll as (default: %(default)s)")
    ap.add_argument("--scenario", choices=[*SCENARIOS, "all", "none"], default="all",
                    help="threat scenario(s) to inject (default: %(default)s)")
    ap.add_argument("--baseline-users", type=int, default=6,
                    help="benign users to generate first (default: %(default)s)")
    ap.add_argument("--baseline-days", type=int, default=2,
                    help="days of benign history, ending today (0 to skip)")
    ap.add_argument("--date", choices=["today", "keep"], default="today",
                    help="'today' re-anchors scenarios onto today's date, keeping "
                         "their hour-of-day (default: %(default)s)")
    ap.add_argument("--hour", type=int, default=None, metavar="H",
                    help="override the scenario hour of day (0-23). Hours 20-06 are "
                         "after-hours, which is part of what makes the scenario severe")
    ap.add_argument("--user", default=None, help="override the acting user (single scenario only)")
    ap.add_argument("--host", default=None, help="override the hostname (single scenario only)")
    ap.add_argument("--batch", type=int, default=250, help="events per sealed batch")
    ap.add_argument("--pace", type=float, default=0.0, metavar="SECONDS",
                    help="pause between batches, to watch alerts arrive live")
    ap.add_argument("--keys-dir", default="keys/replay",
                    help="where this throwaway endpoint's ML-DSA keys live")
    ap.add_argument("--fingerprint", default=None,
                    help="pin the server's ML-KEM public-key fingerprint")
    ap.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout, seconds")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (https servers with self-signed certs)")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable report")
    args = ap.parse_args(argv)

    if args.hour is not None and not 0 <= args.hour <= 23:
        ap.error("--hour must be between 0 and 23")
    names = [] if args.scenario == "none" else (
        list(SCENARIOS) if args.scenario == "all" else [args.scenario])
    if (args.user or args.host) and len(names) != 1:
        ap.error("--user/--host apply to one scenario; pass --scenario exfiltration "
                 "or --scenario staging")
    if not names and args.baseline_days < 1:
        ap.error("nothing to send: --scenario none needs --baseline-days >= 1")

    cfg = build_config(args)
    if not keys_exist(cfg):
        print(f"[replay] provisioning throwaway endpoint keys in {cfg.keys_dir}")
        generate_agent_keys(cfg)
    pk, sk = load_keys(cfg)

    if not cfg.enroll_token:
        try:
            cfg.enroll_token = mint_token(args.server, args.timeout)
            print("[replay] minted a one-time enrollment token from the server")
        except httpx.HTTPError as exc:
            print(f"[replay] could not reach {args.server}: {exc}", file=sys.stderr)
            print("[replay] is the detection server running? python -m server.main",
                  file=sys.stderr)
            return 2

    transport = Transport(cfg, pk, sk)
    try:
        info = transport.connect()
    except TransportError as exc:
        print(f"[replay] {exc}", file=sys.stderr)
        return 2

    print(f"[replay] enrolled as {cfg.agent_id} -> {transport.base_url}")
    print(f"[replay] secure channel: {info.get('aead_algorithm')} keyed by "
          f"ML-KEM-512, batches signed with ML-DSA-44")
    print(f"[replay] server KEM fingerprint {transport.stats()['server_kem_fingerprint']}")

    totals = {"batches": 0, "events": 0, "windows": 0, "anomalies": 0,
              "threats": 0, "highest_severity": None, "directives": 0}
    try:
        base = baseline_events(cfg.agent_id, args.baseline_users, args.baseline_days)
        if base:
            print(f"[replay] {len(base)} benign events "
                  f"({args.baseline_users} users x {args.baseline_days} days)")
            totals = _merge(totals, stream(transport, base, "benign", args.batch, args.pace))

        for name in names:
            events = scenario_events(name, cfg.agent_id, args.user, args.host,
                                     args.date, args.hour)
            when = events[0].ts.strftime("%Y-%m-%d %H:%M UTC") if events else "-"
            print(f"[replay] scenario '{name}': {len(events)} events at {when}")
            totals = _merge(totals, stream(transport, events, name, args.batch, args.pace))
    except TransportError as exc:
        print(f"[replay] delivery failed: {exc}", file=sys.stderr)
        return 1
    finally:
        transport.close()

    if args.json:
        print(json.dumps({
            "agent_id": cfg.agent_id,
            "server": transport.base_url,
            **totals,
            "threats_detail": fetch_threats(args.server, cfg.agent_id),
        }, indent=2, default=str))
    else:
        print_report(args.server, cfg.agent_id, totals)
    return 0


def _merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for key, value in b.items():
        if key == "highest_severity":
            out[key] = _worse(a.get(key), value)
        else:
            out[key] = a.get(key, 0) + value
    return out


if __name__ == "__main__":
    raise SystemExit(main())
