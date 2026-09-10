"""VIGIL AI Endpoint Agent — collect, buffer, seal, send.

Runs as a plain user-space process on the monitored Windows PC:

    python -m agent.keygen        # once: create this endpoint's ML-DSA identity
    python -m agent.main          # enroll, handshake, then stream continuously

Three collectors (file activity, removable media, interactive sessions) feed a
bounded buffer. Every ``flush_interval_s`` the buffer is drained, sealed with
AES-256-GCM under an ML-KEM-512 session key, signed with ML-DSA-44, and POSTed to
the detection server. A failed send requeues the batch and backs off, so a server
restart or a flaky link costs latency, not data.

Containment directives that come back on a ``BLOCK`` decision are **advisory**: the
agent writes an audit record and shows the user a security notice. It does not
disable networking, kill sessions, or delete anything — see the README section on
simulated response.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone

from agent.buffer import EventBuffer
from agent.collectors import CollectorContext, FileCollector, LogonCollector, UsbCollector
from agent.config import AgentConfig
from agent.keygen import fingerprint, load_keys
from agent.transport import EnrollmentError, Transport, TransportError
from vigil.console import enable_utf8
from vigil.pqc import aead, kem, sig

log = logging.getLogger("vigil.agent")

BANNER = r"""
 VIGIL AI — Endpoint Agent
 post-quantum telemetry: {kem} + {aead} + {sigalg}
""".strip("\n")


def configure_logging(level: str = "info") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)-20s %(message)s",
        datefmt="%H:%M:%S",
    )


class EndpointAgent:
    """Owns the collectors, the buffer, and the flush loop."""

    def __init__(self, cfg: AgentConfig, transport: Transport | None = None):
        self.cfg = cfg
        self.buffer = EventBuffer(cfg.buffer_size)
        self._stop = threading.Event()
        self._backoff = 0.0
        self.flushes = 0
        self.failures = 0
        self.directives_received = 0
        self.started_at = datetime.now(timezone.utc)

        self._sign_public, self._sign_secret = load_keys(cfg)
        self.transport = transport or Transport(cfg, self._sign_public, self._sign_secret)

        # The USB collector must exist before the file collector, because it is what
        # answers "is this path on removable media?".
        self.usb = UsbCollector(self._context(), interval_s=cfg.usb_poll_s) \
            if cfg.collect_usb else None

        ctx = self._context(is_removable=self.usb.is_removable_path if self.usb else None)
        self.files = FileCollector(
            ctx, watch_dirs=cfg.watch_dirs, exclude_patterns=cfg.exclude_patterns,
            debounce_s=cfg.modify_debounce_s,
        ) if cfg.collect_files else None
        self.logon = LogonCollector(self._context(), interval_s=cfg.logon_poll_s) \
            if cfg.collect_logon else None

        self.collectors = [c for c in (self.files, self.usb, self.logon) if c is not None]
        self.active_policy: dict = {}

    def _context(self, is_removable=None) -> CollectorContext:
        return CollectorContext(
            agent_id=self.cfg.agent_id,
            host=self.cfg.host,
            user=self.cfg.effective_user,
            emit=self.buffer.add,
            is_removable=is_removable or (lambda _path: False),
        )

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start_collectors(self) -> None:
        for collector in self.collectors:
            if not collector.available:
                log.warning("%s collector is not available on this platform — skipping",
                            collector.name)
                continue
            collector.start()

    def stop(self) -> None:
        self._stop.set()

    def shutdown(self) -> None:
        """Stop collecting, then make a final attempt to deliver what is buffered."""
        for collector in self.collectors:
            try:
                collector.stop()
            except Exception as exc:
                log.warning("error stopping the %s collector: %s", collector.name, exc)

        pending = len(self.buffer)
        if pending and self.transport.connected:
            log.info("flushing %d buffered event(s) before exit", pending)
            try:
                self.flush_once()
            except TransportError as exc:
                log.warning("final flush failed, %d event(s) lost: %s", pending, exc)
        self.transport.close()

    # ── the flush loop ───────────────────────────────────────────────────────
    def flush_once(self) -> dict | None:
        """Drain up to one batch and deliver it. Requeues on failure."""
        events = self.buffer.drain(self.cfg.max_batch)
        if not events:
            return None
        try:
            body = self.transport.send(events)
        except TransportError:
            self.buffer.requeue(events)
            raise
        self.flushes += 1
        self._log_result(events, body)
        self._handle_directives(body.get("directives") or [])
        if "policy" in body:
            self._apply_policy(body["policy"])
        return body


    def _log_result(self, events: list, body: dict) -> None:
        severity = body.get("highest_severity")
        threats = body.get("threats", 0)
        if threats:
            log.warning("sent %d event(s) -> %d threat(s), highest %s",
                        len(events), threats, severity)
        else:
            log.info("sent %d event(s) -> %d window(s) evaluated, no threats",
                     len(events), body.get("windows_evaluated", 0))

    def run(self) -> int:
        """Connect, collect, and stream until interrupted. Returns an exit code."""
        try:
            self.transport.connect()
        except EnrollmentError as exc:
            log.error("enrollment failed: %s", exc)
            return 2
        except TransportError as exc:
            log.error("%s", exc)
            log.error("is the detection server running and reachable at %s?",
                      self.cfg.server_url)
            return 2

        self.start_collectors()
        log.info("streaming to %s every %.1fs (batch <= %d events)",
                 self.cfg.server_url, self.cfg.flush_interval_s, self.cfg.max_batch)

        while not self._stop.wait(self._next_interval()):
            self._sync_removable_watches()
            try:
                self.flush_once()
                self._backoff = 0.0
            except TransportError as exc:
                self.failures += 1
                self._backoff = min(
                    self.cfg.max_backoff_s,
                    max(self.cfg.retry_backoff_s, self._backoff * 2 or self.cfg.retry_backoff_s),
                )
                log.warning("delivery failed (%s) — %d event(s) held, retrying in %.0fs",
                            exc, len(self.buffer), self._backoff)

        log.info("shutting down")
        self.shutdown()
        return 0

    def _next_interval(self) -> float:
        return self._backoff or self.cfg.flush_interval_s

    def _sync_removable_watches(self) -> None:
        """Watch removable volumes for file activity while they are plugged in.

        This is what turns "a USB stick was connected" into "2.3 GB was copied to a
        USB stick" — without it, writes to E:\\ would never be observed at all.
        """
        if not (self.cfg.watch_removable and self.files and self.usb):
            return
        present = {os.path.abspath(r) for r in self.usb.removable_roots}
        watched = set(self.files.watching)
        configured = {os.path.abspath(d) for d in self.cfg.watch_dirs}

        for root in present - watched:
            self.files.watch(root)
        # Excluding `configured` is what keeps this from ever unwatching a directory
        # the operator asked for; everything else in `watched` was added right here.
        for root in watched - present - configured:
            self.files.unwatch(root)

    # ── response directives (advisory, never destructive) ────────────────────
    def _handle_directives(self, directives: list[dict]) -> None:
        if not directives:
            return
        self.directives_received += len(directives)
        if not self.cfg.apply_directives:
            log.info("received %d containment directive(s); apply_directives is off",
                     len(directives))
            return

        for d in directives:
            self._write_audit_record(d)
            if self.cfg.notify_user:
                self._notify_user(d)
            log.warning("containment directive %s (%s, mode=%s) applied: %s",
                        d.get("directive_id"), d.get("severity"), d.get("mode"),
                        ", ".join(d.get("steps", [])))

    def _write_audit_record(self, directive: dict) -> None:
        path = self.cfg.directive_log
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "agent_id": self.cfg.agent_id,
                    "host": self.cfg.host,
                    "directive": directive,
                }) + "\n")
        except OSError as exc:
            log.warning("could not write the directive audit record to %s: %s", path, exc)

    def _notify_user(self, directive: dict) -> None:
        message = directive.get("message") or "Unusual activity was reported to security."
        # Console only, deliberately: a blocking dialog on someone's workstation is a
        # denial of service, and a background agent has no business owning the screen.
        print("\n" + "=" * 72, file=sys.stderr)
        print(" SECURITY NOTICE", file=sys.stderr)
        print(" " + message, file=sys.stderr)
        print("=" * 72 + "\n", file=sys.stderr)

    def _apply_policy(self, policy: dict | None) -> None:
        """Apply dynamic policy sync from the detection server."""
        if not policy or not isinstance(policy, dict):
            return
        self.active_policy = policy
        collect_usb = policy.get("collect_usb", True)
        usb_policy = policy.get("usb_policy", "alert")

        # If policy disables USB collection, stop the USB collector; if enabled, start it
        if self.usb and self.usb.available:
            if (not collect_usb or usb_policy == "disabled") and self.usb.running:
                try:
                    self.usb.stop()
                    log.info("policy: USB monitoring disabled by company policy — paused USB collector")
                except Exception as exc:
                    log.warning("error pausing USB collector: %s", exc)
            elif collect_usb and usb_policy != "disabled" and not self.usb.running and self.cfg.collect_usb:
                try:
                    self.usb.start()
                    log.info("policy: USB monitoring active — resumed USB collector")
                except Exception as exc:
                    log.warning("error resuming USB collector: %s", exc)

    # ── introspection ────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "agent_id": self.cfg.agent_id,
            "host": self.cfg.host,
            "user": self.cfg.effective_user,
            "started_at": self.started_at.isoformat(),
            "flushes": self.flushes,
            "failures": self.failures,
            "directives_received": self.directives_received,
            "buffer": self.buffer.stats(),
            "transport": self.transport.stats(),
            "collectors": [c.stats() for c in self.collectors],
        }


# ── CLI ──────────────────────────────────────────────────────────────────────
def _print_startup(cfg: AgentConfig, agent: EndpointAgent) -> None:
    print(BANNER.format(kem=kem.ALGORITHM, aead=aead.ALGORITHM, sigalg=sig.ALGORITHM))
    print(f" agent_id   {cfg.agent_id}")
    print(f" host/user  {cfg.host} / {cfg.effective_user}")
    print(f" server     {cfg.server_url}")
    print(f" identity   {sig.ALGORITHM} fp {fingerprint(agent._sign_public)}")
    print(f" collecting {', '.join(c.name for c in agent.collectors) or 'nothing'}")
    if agent.files:
        for directory in agent.files.watch_dirs:
            print(f"   watch    {directory}")
    print(" metadata only — file contents are never read\n")


def main(argv: list[str] | None = None) -> int:
    enable_utf8()
    ap = argparse.ArgumentParser(description="Run the VIGIL AI endpoint agent.")
    ap.add_argument("--config", default=None, help="path to agent_config.yaml")
    ap.add_argument("--server", default=None, help="override server_url")
    ap.add_argument("--agent-id", default=None, help="override agent_id")
    ap.add_argument("--token", default=None, help="override the enrollment token")
    ap.add_argument("--watch", action="append", default=None, metavar="DIR",
                    help="watch this directory (repeatable; replaces watch_dirs)")
    ap.add_argument("--once", action="store_true",
                    help="collect for one interval, send a single batch, then exit")
    ap.add_argument("--check", action="store_true",
                    help="validate the config and connectivity, then exit")
    args = ap.parse_args(argv)

    cfg = AgentConfig.load(args.config)
    if args.server:
        cfg.server_url = args.server
    if args.agent_id:
        cfg.agent_id = args.agent_id
    if args.token:
        cfg.enroll_token = args.token
    if args.watch:
        cfg.watch_dirs = args.watch

    configure_logging(cfg.log_level)

    problems = cfg.validate()
    if problems:
        print("[agent] configuration problems:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("\n[agent] copy agent_config.example.yaml to agent_config.yaml and edit it.",
              file=sys.stderr)
        return 2

    try:
        agent = EndpointAgent(cfg)
    except (FileNotFoundError, ValueError) as exc:
        # Missing or corrupt keys — both carry their own remediation instructions.
        print(f"[agent] {exc}", file=sys.stderr)
        return 2

    _print_startup(cfg, agent)

    if args.check:
        try:
            agent.transport.connect()
        except TransportError as exc:
            print(f"[agent] connectivity check FAILED: {exc}", file=sys.stderr)
            return 2
        print("[agent] connectivity check OK — enrolled and session established")
        agent.transport.close()
        return 0

    def _handle_signal(signum, _frame):
        log.info("received signal %s", signum)
        agent.stop()

    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        signum = getattr(signal, sig_name, None)
        if signum is not None:
            try:
                signal.signal(signum, _handle_signal)
            except (ValueError, OSError):
                pass       # not the main thread, or unsupported on this platform

    if args.once:
        try:
            agent.transport.connect()
        except TransportError as exc:
            print(f"[agent] {exc}", file=sys.stderr)
            return 2
        agent.start_collectors()
        log.info("collecting for %.1fs, then sending one batch", cfg.flush_interval_s)
        time.sleep(cfg.flush_interval_s)
        if agent.files:
            agent.files.flush_pending(force=True)
        try:
            body = agent.flush_once()
        except TransportError as exc:
            print(f"[agent] delivery failed: {exc}", file=sys.stderr)
            agent.shutdown()
            return 1
        print(json.dumps(body or {"status": "nothing to send"}, indent=2))
        agent.shutdown()
        return 0

    return agent.run()


if __name__ == "__main__":
    raise SystemExit(main())
