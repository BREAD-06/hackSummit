"""Enterprise Policy Engine for VIGIL AI.

Allows organizations to define:
1. What to monitor (file operations, USB devices, logon events, sensitive paths).
2. What counts as a threat (USB allowed/blocked/disabled, after-hours policy, volume limits, anomaly sensitivity).
3. What action to take (automated containment, maximum autonomous action).

Fully connects with Endpoint Agent, Isolation Forest, Q-Learning, and Response System.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from server.db.base import Storage

log = logging.getLogger("vigil.policy")

# USB Policy modes:
# - "blocked": Immediate high-severity threat and mandatory containment recommendation.
# - "alert": Standard threat signal (participates in Q-learning and threat rules).
# - "allowed": Monitored and audited, but treated as legitimate (does not trigger threats or set RL usb=1).
# - "disabled": Not monitored; agent turns off USB watching and server ignores all USB signals.
USB_BLOCKED = "blocked"
USB_ALERT = "alert"
USB_ALLOWED = "allowed"
USB_DISABLED = "disabled"
USB_POLICIES = (USB_BLOCKED, USB_ALERT, USB_ALLOWED, USB_DISABLED)

# After-Hours modes:
# - "alert": Standard threat signal for off-hours operations.
# - "audit": Logged in telemetry, but does not fire rule.
# - "disabled": Completely ignored (useful for 24/7 or remote teams).
AFTER_HOURS_ALERT = "alert"
AFTER_HOURS_AUDIT = "audit"
AFTER_HOURS_DISABLED = "disabled"
AFTER_HOURS_POLICIES = (AFTER_HOURS_ALERT, AFTER_HOURS_AUDIT, AFTER_HOURS_DISABLED)

# Anomaly sensitivity:
ANOMALY_LOW = "low"         # Stricter: flags only extreme anomalies (score < threshold * 0.8)
ANOMALY_MEDIUM = "medium"   # Standard Isolation Forest threshold (factor 1.0)
ANOMALY_HIGH = "high"       # More sensitive: flags subtler anomalies (factor 1.25)


@dataclass
class MonitoringScope:
    collect_files: bool = True
    collect_usb: bool = True
    collect_logon: bool = True
    watch_dirs: list[str] = field(default_factory=lambda: ["Documents", "Downloads", "Desktop"])
    sensitive_keywords: list[str] = field(
        default_factory=lambda: [
            "confidential", "secret", "password", "leak", "proprietary",
            "internal", "private", "salary", "patent", "financial",
        ]
    )
    sensitive_dirs: list[str] = field(
        default_factory=lambda: [
            "C:\\Confidential", "C:\\Finance", "C:\\Users\\Public\\Documents",
        ]
    )


@dataclass
class ThreatRules:
    usb_policy: str = USB_ALERT
    after_hours_policy: str = AFTER_HOURS_ALERT
    file_volume_threshold_mb: float = 250.0
    burst_file_count: int = 100
    mass_delete_threshold: int = 20
    anomaly_sensitivity: str = ANOMALY_MEDIUM


@dataclass
class ResponseActions:
    auto_containment: bool = True
    max_autonomous_action: str = "BLOCK"   # "BLOCK", "ALERT", "DISMISS"
    containment_mode: str = "simulated"    # "simulated"


@dataclass
class PolicyConfig:
    version: int = 1
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    monitoring: MonitoringScope = field(default_factory=MonitoringScope)
    threat_rules: ThreatRules = field(default_factory=ThreatRules)
    response_actions: ResponseActions = field(default_factory=ResponseActions)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyConfig:
        if not data:
            return cls()
        mon = data.get("monitoring", {})
        thr = data.get("threat_rules", {})
        resp = data.get("response_actions", {})

        return cls(
            version=int(data.get("version", 1)),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
            monitoring=MonitoringScope(
                collect_files=bool(mon.get("collect_files", True)),
                collect_usb=bool(mon.get("collect_usb", True)),
                collect_logon=bool(mon.get("collect_logon", True)),
                watch_dirs=list(mon.get("watch_dirs", ["Documents", "Downloads", "Desktop"])),
                sensitive_keywords=list(mon.get("sensitive_keywords", [
                    "confidential", "secret", "password", "leak", "proprietary",
                    "internal", "private", "salary", "patent", "financial",
                ])),
                sensitive_dirs=list(mon.get("sensitive_dirs", [
                    "C:\\Confidential", "C:\\Finance", "C:\\Users\\Public\\Documents",
                ])),
            ),
            threat_rules=ThreatRules(
                usb_policy=str(thr.get("usb_policy", USB_ALERT)).lower(),
                after_hours_policy=str(thr.get("after_hours_policy", AFTER_HOURS_ALERT)).lower(),
                file_volume_threshold_mb=float(thr.get("file_volume_threshold_mb", 250.0)),
                burst_file_count=int(thr.get("burst_file_count", 100)),
                mass_delete_threshold=int(thr.get("mass_delete_threshold", 20)),
                anomaly_sensitivity=str(thr.get("anomaly_sensitivity", ANOMALY_MEDIUM)).lower(),
            ),
            response_actions=ResponseActions(
                auto_containment=bool(resp.get("auto_containment", True)),
                max_autonomous_action=str(resp.get("max_autonomous_action", "BLOCK")).upper(),
                containment_mode=str(resp.get("containment_mode", "simulated")).lower(),
            ),
        )


class PolicyEngine:
    """Manages company-specific policy rules and provides evaluation hooks for the pipeline."""

    def __init__(self, storage: Storage):
        self.storage = storage
        self._policy: PolicyConfig = self._load()

    def _load(self) -> PolicyConfig:
        stored = self.storage.get_policy("default")
        if stored:
            try:
                return PolicyConfig.from_dict(stored)
            except Exception as exc:
                log.warning("could not deserialize stored policy: %s — falling back to default", exc)
        cfg = PolicyConfig()
        try:
            self.storage.set_policy(cfg.to_dict(), "default")
        except Exception as exc:
            log.warning("could not persist default policy: %s", exc)
        return cfg

    @property
    def current(self) -> PolicyConfig:
        return self._policy

    def get_policy(self) -> dict[str, Any]:
        return self._policy.to_dict()

    def update_policy(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Update active policy, persist to storage, and return the new policy dict."""
        current_dict = self._policy.to_dict()

        # Deep merge updates
        for section in ("monitoring", "threat_rules", "response_actions"):
            if section in updates and isinstance(updates[section], dict):
                current_dict[section].update(updates[section])

        current_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
        current_dict["version"] = current_dict.get("version", 1) + 1

        new_policy = PolicyConfig.from_dict(current_dict)
        self.storage.set_policy(new_policy.to_dict(), "default")
        self._policy = new_policy
        log.info("updated policy: USB=%s, AfterHours=%s, AutoContainment=%s",
                 new_policy.threat_rules.usb_policy,
                 new_policy.threat_rules.after_hours_policy,
                 new_policy.response_actions.auto_containment)
        return self._policy.to_dict()

    def reset_policy(self) -> dict[str, Any]:
        """Reset policy to system defaults."""
        default_policy = PolicyConfig()
        self.storage.set_policy(default_policy.to_dict(), "default")
        self._policy = default_policy
        log.info("reset policy to default configuration")
        return self._policy.to_dict()

    # ── Agent Policy Digest ──
    def agent_policy_dict(self) -> dict[str, Any]:
        """Returns collection directives suitable for syncing to endpoint agents."""
        mon = self._policy.monitoring
        thr = self._policy.threat_rules
        # If USB is disabled in threat rules, agent shouldn't collect USB either
        collect_usb = mon.collect_usb and (thr.usb_policy != USB_DISABLED)
        return {
            "collect_files": mon.collect_files,
            "collect_usb": collect_usb,
            "collect_logon": mon.collect_logon,
            "watch_dirs": mon.watch_dirs,
            "usb_policy": thr.usb_policy,
            "version": self._policy.version,
        }

    # ── Pipeline Evaluation Hooks ──
    def is_usb_threat(self) -> bool:
        """True if USB activity should participate in threat scoring."""
        return self._policy.threat_rules.usb_policy in (USB_BLOCKED, USB_ALERT)

    def is_usb_auto_blocked(self) -> bool:
        """True if USB activity should immediately trigger BLOCK."""
        return self._policy.threat_rules.usb_policy == USB_BLOCKED

    def is_after_hours_threat(self) -> bool:
        """True if after-hours activity should fire a threat rule."""
        return self._policy.threat_rules.after_hours_policy == AFTER_HOURS_ALERT

    def filter_fired_rules(self, raw_rules: list[str]) -> list[str]:
        """Filter fired heuristic rules based on company policy."""
        rules = list(raw_rules)
        thr = self._policy.threat_rules

        # Filter USB rules if USB is allowed or disabled
        if thr.usb_policy in (USB_ALLOWED, USB_DISABLED):
            rules = [r for r in rules if r not in ("removable_device", "write_to_removable")]

        # Filter after hours rule if disabled or audit-only
        if thr.after_hours_policy in (AFTER_HOURS_AUDIT, AFTER_HOURS_DISABLED):
            rules = [r for r in rules if r != "after_hours"]

        return rules

    def adjust_anomaly_decision(self, anomaly_score: float, model_threshold: float, model_is_anomaly: bool) -> bool:
        """Apply sensitivity factor to Isolation Forest decision."""
        sens = self._policy.threat_rules.anomaly_sensitivity
        if sens == ANOMALY_LOW:
            # Stricter: only flag if it's 20% more extreme than the threshold
            cutoff = model_threshold - abs(model_threshold) * 0.2
            return anomaly_score < cutoff
        elif sens == ANOMALY_HIGH:
            # More sensitive: flags if close to threshold
            cutoff = model_threshold + abs(model_threshold) * 0.2
            return anomaly_score < cutoff
        return model_is_anomaly

    def enforce_action(self, recommended_action: str, has_usb: bool = False) -> str:
        """Apply policy restrictions to the Q-learning recommendation."""
        action = recommended_action

        # If USB is configured as strictly blocked and USB was present, enforce BLOCK
        if self.is_usb_auto_blocked() and has_usb:
            action = "BLOCK"

        # Check maximum allowed autonomous action
        max_action = self._policy.response_actions.max_autonomous_action
        action_rank = {"DISMISS": 0, "ALERT": 1, "BLOCK": 2}
        if action_rank.get(action, 0) > action_rank.get(max_action, 2):
            action = max_action

        return action

    def should_emit_directive(self, action: str) -> bool:
        """Check if containment directives should be sent to the endpoint."""
        if action != "BLOCK":
            return False
        return self._policy.response_actions.auto_containment
