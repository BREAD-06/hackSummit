"""Stage 5 — Verification: decide what to do about a flagged window.

Wraps :class:`server.rl.qlearning.QLearner`. The detection stage says *"unusual"*;
this stage says *"dismiss / alert / block"*, and it is the stage that learns from
the SOC analyst.

The rule context (:func:`server.rl.qlearning.fired_rules`) is computed from the
window features **plus** the trigger stage's extras, so an analyst sees concrete
reasons ("after hours", "write to removable", "sensitive path access") next to the
model's opinion rather than a bare anomaly score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from server.pipeline.detection import Detection
from server.rl.qlearning import QLearner, discretize, fired_rules


@dataclass
class Verdict:
    state: str
    action: str
    greedy_action: str
    explored: bool
    q_values: dict[str, float]
    confidence: float
    rules_fired: list[str]
    rule_context: dict[str, float]

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class VerificationStage:
    def __init__(self, learner: QLearner):
        self.learner = learner

    def verify(self, detection: Detection, extras: dict[str, float] | None = None) -> Verdict:
        # Rules see the full picture; the RL state stays in the small 32-cell space.
        context = {
            **detection.features,
            **(extras or {}),
            "is_anomaly": detection.is_anomaly,
        }
        state = discretize(context)
        decision = self.learner.decide(state)
        return Verdict(
            state=state,
            action=decision["action"],
            greedy_action=decision["greedy_action"],
            explored=decision["explored"],
            q_values=decision["q_values"],
            confidence=decision["confidence"],
            rules_fired=fired_rules(context),
            rule_context={k: float(v) for k, v in (extras or {}).items()},
        )

    def apply_feedback(self, state: str, action: str, admin_action: str) -> dict[str, Any]:
        return self.learner.apply_feedback(state, action, admin_action)
