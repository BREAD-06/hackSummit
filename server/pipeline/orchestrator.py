"""The streaming pipeline — stages 3 through 6, wired together.

One decrypted batch in, threats and directives out::

    EventBatch
        -> TriggerStage      normalise, enrich, persist, window
        -> DetectionStage    Isolation Forest score per touched window
        -> VerificationStage Q-learning decision (dismiss / alert / block)
        -> ResponseStage     severity, persist, directive
        -> broadcast         WebSocket push to the SOC dashboard

Processing is synchronous and CPU-bound (scikit-learn), so the API layer runs it in
a worker thread and awaits the broadcast afterwards. A single lock serialises
pipeline runs: the rolling feature store and the Q-table are shared mutable state,
and correctness matters more here than ingest throughput on a LAN.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from server.config import ServerConfig
from server.db.base import Storage
from server.ml.model import DetectionModel
from server.pipeline.detection import DetectionStage
from server.pipeline.response import ResponseStage, Threat, threat_event
from server.pipeline.trigger import TriggerStage
from server.pipeline.verification import VerificationStage
from server.policy.engine import PolicyEngine
from server.rl.qlearning import ADMIN_BLOCK, ADMIN_DISMISS, QLearner
from vigil.schema import EventBatch

log = logging.getLogger("vigil.pipeline")


@dataclass
class IngestResult:
    """What one batch produced — returned to the agent and pushed to the dashboard."""

    agent_id: str
    events_received: int
    events_persisted: int
    windows_evaluated: int
    anomalies: int
    threats: list[Threat] = field(default_factory=list)
    directives: list[dict] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)
    # Ready-made WebSocket envelopes ("threat" for new, "threat_update" for a
    # re-evaluated window), so the API layer never has to re-derive newness.
    broadcasts: list[dict] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "events_received": self.events_received,
            "windows_evaluated": self.windows_evaluated,
            "anomalies": self.anomalies,
            "threats": len(self.threats),
            "highest_severity": max(
                (t.severity for t in self.threats),
                key=lambda s: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s),
                default=None,
            ),
        }


class Pipeline:
    """Owns the four stages, the enterprise policy engine, and the shared live state."""

    def __init__(self, storage: Storage, model: DetectionModel, config: ServerConfig):
        self.storage = storage
        self.config = config
        self._lock = threading.RLock()
        self.policy_engine = PolicyEngine(storage)

        self.learner = QLearner(
            storage,
            alpha=config.rl_alpha,
            gamma=config.rl_gamma,
            epsilon=config.rl_epsilon,
            safe_exploration=config.rl_safe_exploration,
        )
        self.trigger = TriggerStage(
            storage,
            sensitive_hints=config.sensitive_hints,
            sensitive_dirs=config.sensitive_dirs,
            persist=config.persist_events,
        )
        self.detection = DetectionStage(model)
        self.verification = VerificationStage(self.learner)
        self.response = ResponseStage(storage, emit_directives=config.emit_directives)

        # Populate the Q-table so the dashboard shows the full policy from boot.
        seeded = self.learner.seed_all()
        if seeded:
            log.info("seeded %d Q-table states from the rule-based prior", seeded)

    # ── ingest ────────────────────────────────────────────────────────────────
    def process_batch(self, batch: EventBatch, agent_id: str | None = None) -> IngestResult:
        """Run one batch through every stage. Thread-safe; CPU-bound."""
        agent_id = agent_id or batch.agent_id
        with self._lock:
            triggered = self.trigger.process(batch, agent_id=agent_id, policy=self.policy_engine.current)
            detections = self.detection.score_many(triggered.windows, policy=self.policy_engine)

            result = IngestResult(
                agent_id=agent_id,
                events_received=len(triggered.events),
                events_persisted=triggered.persisted,
                windows_evaluated=len(detections),
                anomalies=sum(1 for d in detections if d.is_anomaly),
                policy=self.policy_engine.agent_policy_dict(),
            )

            for detection in detections:
                extras = triggered.extras.get(detection.window_key, {})
                verdict = self.verification.verify(detection, extras, policy=self.policy_engine)
                if not self.response.should_record(detection, verdict):
                    continue
                threat, created = self.response.record(
                    self.response.build(detection, verdict)
                )
                result.threats.append(threat)
                result.broadcasts.append(threat_event(threat, created))
                if created:
                    log.info(
                        "threat #%s %s %s user=%s host=%s risk=%.1f rules=%s",
                        threat.id, threat.severity, threat.action,
                        threat.user, threat.host, threat.risk,
                        ",".join(threat.rules_fired) or "-",
                    )
                directive = self.response.directive(threat, policy=self.policy_engine)
                if directive:
                    result.directives.append(directive)

            self.storage.touch_agent(agent_id)
            return result


    # ── analyst feedback (the RL reward loop) ─────────────────────────────────
    def apply_feedback(self, threat_id: int, admin_action: str) -> dict[str, Any]:
        """Apply an analyst verdict: update the threat, reward the policy, learn.

        This is the loop the whole design turns on — the only place the system's
        decision boundary changes based on human judgement.
        """
        verdict = str(admin_action).strip().lower()
        if verdict not in (ADMIN_BLOCK, ADMIN_DISMISS):
            raise ValueError(
                f"admin action must be '{ADMIN_BLOCK}' or '{ADMIN_DISMISS}', got {admin_action!r}"
            )

        with self._lock:
            threat = self.storage.get_threat(threat_id)
            if threat is None:
                raise KeyError(f"threat {threat_id} not found")

            state = threat.get("state")
            action = threat.get("action")
            if not state or not action:
                raise ValueError(f"threat {threat_id} has no recorded decision to learn from")

            learned = self.verification.apply_feedback(state, action, verdict)
            status = self.response.apply_status(threat_id, verdict)
            self.response.log_feedback(threat_id, verdict, learned["reward"], state, action)

            log.info(
                "feedback threat #%s %s -> %s %+.1f%s  policy %s -> %s",
                threat_id, verdict, learned["action"], learned["reward"],
                "" if learned["endorsed_reward"] is None else
                f", {learned['endorsed_action']} {learned['endorsed_reward']:+.1f}",
                learned["policy_before"], learned["policy_after"],
            )
            return {
                "threat_id": threat_id,
                "status": status,
                "learning": learned,
                "policy_changed": learned["policy_before"] != learned["policy_after"],
            }

    # ── policy engine ─────────────────────────────────────────────────────────
    def get_policy(self) -> dict[str, Any]:
        return self.policy_engine.get_policy()

    def update_policy(self, updates: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            return self.policy_engine.update_policy(updates)

    def reset_policy(self) -> dict[str, Any]:
        with self._lock:
            return self.policy_engine.reset_policy()

    # ── introspection ─────────────────────────────────────────────────────────
    def info(self) -> dict[str, Any]:
        return {
            "model": self.detection.info(),
            "rl": self.learner.stats(),
            "live_windows": len(self.trigger.features.all_windows()),
            "policy": self.policy_engine.get_policy(),
        }

