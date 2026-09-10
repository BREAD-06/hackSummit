"""Stage 6 — Response: severity, persistence, dashboard push, endpoint directive.

Turns a detection plus a verdict into the record an analyst actually sees, decides
how loudly to shout about it, and — for a ``BLOCK`` decision — emits a containment
directive back to the endpoint agent.

**On containment being simulated.** The directive tells the agent to warn the user
and write a local audit record; it does *not* execute OS-level network isolation or
kill sessions. Automated enforcement against a real workstation is destructive and
out of scope for this project, so it is represented honestly as a directive with
``mode: "simulated"`` rather than pretended. Everything up to that boundary —
detection, decision, learning, alerting, audit trail — is real.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from server.pipeline.detection import Detection
from server.pipeline.verification import Verdict
from server.rl.qlearning import ALERT, BLOCK, DISMISS

LOW, MEDIUM, HIGH, CRITICAL = "LOW", "MEDIUM", "HIGH", "CRITICAL"
SEVERITIES = (LOW, MEDIUM, HIGH, CRITICAL)

# How much each rule contributes to severity. Rules that indicate data actually
# leaving the machine (bulk transfer, sensitive access, mass delete) weigh double.
RULE_WEIGHTS = {
    "after_hours": 1,
    "removable_device": 1,
    "high_file_volume": 1,
    "write_to_removable": 1,
    "large_transfer": 2,
    "sensitive_path_access": 2,
    "mass_delete": 2,
    "ml_anomaly": 2,
}
_ESCALATE_WEIGHT = 5   # combined rule weight at which severity steps up


def rule_weight(rules: list[str]) -> int:
    return sum(RULE_WEIGHTS.get(r, 0) for r in rules)


def severity_for(action: str, risk: float, rules: list[str]) -> str:
    """Severity from the chosen action, the model's risk, and the rules that fired."""
    weight = rule_weight(rules)
    corroborated = weight >= _ESCALATE_WEIGHT
    if action == BLOCK:
        return CRITICAL if (corroborated or risk >= 80) else HIGH
    if action == ALERT:
        return HIGH if (corroborated or risk >= 75) else MEDIUM
    return MEDIUM if corroborated else LOW


@dataclass
class Threat:
    """A analyst-facing threat record (also the WebSocket payload)."""

    window_key: str
    agent_id: str
    user: str
    host: str
    window_start: str
    hour: int
    day_of_week: int
    anomaly_score: float
    risk: float
    is_anomaly: bool
    state: str
    action: str
    severity: str
    confidence: float
    explored: bool
    rules_fired: list[str]
    features: dict[str, Any]
    status: str = "open"
    id: int | None = None
    detected_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    def as_row(self) -> dict[str, Any]:
        """Shape expected by :meth:`server.db.base.Storage.upsert_threat`."""
        return {
            "window_key": self.window_key,
            "agent_id": self.agent_id,
            "user": self.user,
            "host": self.host,
            "window_start": self.window_start,
            "hour": self.hour,
            "day_of_week": self.day_of_week,
            "anomaly_score": self.anomaly_score,
            "is_anomaly": self.is_anomaly,
            "state": self.state,
            "action": self.action,
            "severity": self.severity,
            "rules_fired": self.rules_fired,
            # `features` carries the model inputs plus the display/decision context,
            # so a threat row is self-explanatory long after the window has closed.
            "features": {
                **self.features,
                "risk": self.risk,
                "confidence": self.confidence,
                "explored": self.explored,
            },
            "status": self.status,
        }


class ResponseStage:
    def __init__(self, storage, emit_directives: bool = True):
        self.storage = storage
        self.emit_directives = emit_directives

    # ── which windows deserve a threat record ──
    @staticmethod
    def should_record(detection: Detection, verdict: Verdict) -> bool:
        """Record anything the model flagged or the policy escalated.

        Quiet, dismissed windows stay in the event log only — otherwise the threat
        table fills with non-events and the dashboard becomes useless. Dismissed
        *anomalies* are still recorded so an analyst can audit what the policy
        chose to ignore.
        """
        return bool(detection.is_anomaly or verdict.action != DISMISS)

    # ── build & persist ──
    def build(self, detection: Detection, verdict: Verdict) -> Threat:
        return Threat(
            window_key="|".join(str(p) for p in detection.window_key),
            agent_id=detection.agent_id,
            user=detection.user,
            host=detection.host,
            window_start=detection.window_start,
            hour=detection.hour,
            day_of_week=detection.day_of_week,
            anomaly_score=detection.anomaly_score,
            risk=detection.risk,
            is_anomaly=detection.is_anomaly,
            state=verdict.state,
            action=verdict.action,
            severity=severity_for(verdict.action, detection.risk, verdict.rules_fired),
            confidence=verdict.confidence,
            explored=verdict.explored,
            rules_fired=verdict.rules_fired,
            features={**detection.features, **verdict.rule_context},
            detected_at=datetime.now(timezone.utc).isoformat(),
        )

    def record(self, threat: Threat) -> tuple[Threat, bool]:
        """Persist a threat, updating the open record for the same window if present.

        A behaviour window stays open for an hour and is re-evaluated on every
        batch, so inserting blindly would produce a stream of duplicates for one
        incident. Analyst-decided threats are never overwritten.
        """
        threat_id, created = self.storage.upsert_threat(threat.as_row())
        threat.id = threat_id
        return threat, created

    # ── endpoint directive (simulated containment) ──
    def directive(self, threat: Threat, policy: Any = None) -> dict[str, Any] | None:
        if not self.emit_directives or threat.action != BLOCK:
            return None
        if policy and hasattr(policy, "should_emit_directive"):
            if not policy.should_emit_directive(threat.action):
                return None
        mode = "simulated"
        if policy and hasattr(policy, "current"):
            mode = getattr(policy.current.response_actions, "containment_mode", "simulated")
        return {
            "directive_id": f"d-{threat.id}",
            "threat_id": threat.id,
            "type": "CONTAIN",
            "mode": mode,
            "severity": threat.severity,

            "user": threat.user,
            "host": threat.host,
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "reason": threat.rules_fired,
            # What the agent is instructed to actually do. Deliberately non-destructive.
            "steps": ["notify_user", "write_local_audit_record", "flag_session"],
            "message": (
                f"Security notice: unusual data movement was detected on {threat.host} "
                f"({', '.join(threat.rules_fired) or 'anomalous activity'}). "
                f"This activity has been reported to the security team."
            ),
        }

    # ── analyst feedback ──
    def apply_status(self, threat_id: int, admin_action: str) -> str:
        status = "blocked" if admin_action == "block" else "dismissed"
        self.storage.update_threat_status(threat_id, status)
        return status

    def log_feedback(self, threat_id: int, admin_action: str, reward: float,
                     state: str, action: str) -> None:
        self.storage.insert_feedback({
            "threat_id": threat_id, "admin_action": admin_action,
            "reward": reward, "state": state, "action": action,
        })


def threat_event(threat: Threat, created: bool) -> dict[str, Any]:
    """WebSocket envelope for a new or updated threat."""
    return {
        "type": "threat" if created else "threat_update",
        "data": threat.as_dict(),
    }


def json_safe(obj: Any) -> Any:
    """Round-trip through JSON so numpy/bool scalars become plain Python types."""
    return json.loads(json.dumps(obj, default=float))
