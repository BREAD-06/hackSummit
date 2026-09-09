"""Q-learning verification — stage 5 of the pipeline.

The detection model (Isolation Forest) answers *"is this window statistically
unusual?"*. That is not enough to act on: plenty of unusual behaviour is
legitimate. This stage decides **what to do** about a flagged window, and it
learns that decision from the SOC analyst.

Design
------
**State** — a window is discretised into four interpretable dimensions, giving a
small, fully-enumerable table of ``2 x 2 x 4 x 2 = 32`` states::

    ah{0,1}    after hours?
    usb{0,1}   removable device active in this window?
    vol{0..3}  data volume bucket: none / low / medium / high
    anom{0,1}  did the ML model flag it?

A tiny state space is a deliberate choice: it converges after a handful of
analyst clicks (unlike a deep RL policy that would need thousands), and every
cell is human-readable on the dashboard.

**Actions** — ``DISMISS`` (log only), ``ALERT`` (raise to the SOC), ``BLOCK``
(raise + emit a containment directive to the endpoint).

**Cold start** — an untrained Q-table would act randomly on day one, which is
unacceptable for a security control. Instead every state is seeded from a
rule-based risk prior (ported from the project's original
``agents/verification_agent.py`` heuristics), so the policy starts out sensible
and *then* improves from feedback.

**Learning** — analyst feedback on a threat is the reward signal::

    Q(s,a) <- Q(s,a) + alpha * [ r + gamma * max_a' Q(s',a') - Q(s,a) ]

Each threat window is an independent decision with no successor state, so
``gamma`` defaults to ``0`` (a contextual bandit). It is configurable for
completeness, and the full temporal-difference term is implemented.

A verdict updates *two* cells: the action the policy took, and the action the
analyst endorsed. That second, off-policy update is what lets the policy learn to
block at all — see :meth:`QLearner.apply_feedback`.
"""

from __future__ import annotations

import itertools
import random
from typing import Any

from server.db.base import Storage

# ── actions ──────────────────────────────────────────────────────────────────
DISMISS = "DISMISS"
ALERT = "ALERT"
BLOCK = "BLOCK"
ACTIONS = (DISMISS, ALERT, BLOCK)

# Q-table column name per action, matching the `qtable` schema.
_QCOL = {DISMISS: "q_dismiss", ALERT: "q_alert", BLOCK: "q_block"}
_NCOL = {DISMISS: "n_dismiss", ALERT: "n_alert", BLOCK: "n_block"}

# ── admin verdicts ───────────────────────────────────────────────────────────
ADMIN_BLOCK = "block"      # analyst confirms: this was a real threat
ADMIN_DISMISS = "dismiss"  # analyst rejects: this was a false positive

# The action the analyst's verdict endorses. Clicking "Block" says the correct
# response was BLOCK; clicking "Dismiss" says it was DISMISS.
ENDORSED_ACTION = {ADMIN_BLOCK: BLOCK, ADMIN_DISMISS: DISMISS}

# Reward for the action the policy *took*, given the analyst's verdict.
# The poster's headline case is the diagonal: confirmed BLOCK = +1, rejected = -1.
# Off-diagonal entries are what let the policy learn in both directions — a
# DISMISS that the analyst overturns is punished just as a false BLOCK is.
REWARDS: dict[str, dict[str, float]] = {
    ADMIN_BLOCK: {BLOCK: +1.0, ALERT: +0.5, DISMISS: -1.0},
    ADMIN_DISMISS: {BLOCK: -1.0, ALERT: -0.3, DISMISS: +1.0},
}

# ── volume buckets (bytes moved within one behaviour window) ──────────────────
# Calibrated against the measured benign distribution (`tools.synth.normal_events`,
# 1,892 windows), not chosen by intuition. A threshold that ordinary work crosses
# routinely is not a signal — it is noise with a scary name, and it costs an
# analyst a click every time. The percentiles below are what these edges cut at:
#
#     bytes moved in one hour     50MB   250MB   500MB    2GB     4GB
#     benign windows above it     35.5%   28%     19%    1.7%    0.2%
#
# So "high" is set at 2 GB, where it means the same thing as the ML model's
# `contamination=0.02`: rarer than 2% of normal behaviour.
MB = 1024 * 1024
VOLUME_NAMES = ("none", "low", "medium", "high")
VOL_LOW_MAX = 250 * MB     # ordinary document work (~p72 of benign windows)
VOL_MED_MAX = 2048 * MB    # above this is bulk movement (~p98.3)
BURST_FILE_COUNT = 100     # a burst this large is staging regardless of size (~p98.7)

# Risk weights used only to seed the cold-start prior. Once feedback arrives,
# learned Q-values take over and these no longer drive decisions.
_W_AFTER_HOURS = 0.35
_W_USB = 0.30
_W_VOLUME = (0.00, 0.10, 0.25, 0.45)
_W_ANOMALY = 0.40
_MAX_RISK = _W_AFTER_HOURS + _W_USB + _W_VOLUME[-1] + _W_ANOMALY

# Rewards saturate at +/-1, so the prior is deliberately scaled into a narrower
# band. A belief that came from a hand-written heuristic must be weaker than one
# backed by an actual analyst verdict, otherwise a state that starts at the
# ceiling can never be reinforced (or corrected) by feedback.
PRIOR_STRENGTH = 0.6

# Where the prior's decision boundaries sit, in raw (un-normalised) risk units so
# they read directly against the weights above.
#
# ALERT above 0.50 — strictly more than the strongest *single* signal (vol3 at
#   0.45). One ordinary fact about a window is never worth an analyst's attention;
#   two corroborating ones always are, since the weakest pair (usb+vol2) is 0.55.
#   Set below that line and the dashboard fills with single-signal noise: a 600 MB
#   download, or a USB stick with one document copied to it.
#
# BLOCK above 1.08 — three signals *including* real data movement. Deliberately
#   just above after-hours+usb+anomaly with nothing transferred (1.05): emitting a
#   containment directive over a window where no bytes moved is disproportionate.
PRIOR_ALERT_AT = 0.50 / _MAX_RISK
PRIOR_BLOCK_AT = 1.08 / _MAX_RISK


def volume_bucket(file_bytes_total: float, file_count: float = 0.0) -> int:
    """Bucket a window's data volume into ``0..3`` (none / low / medium / high).

    A large *number* of files is staging behaviour even when the total size is
    modest, so a burst is promoted one bucket.
    """
    b = float(file_bytes_total or 0.0)
    if b <= 0:
        bucket = 0
    elif b <= VOL_LOW_MAX:
        bucket = 1
    elif b <= VOL_MED_MAX:
        bucket = 2
    else:
        bucket = 3
    if float(file_count or 0.0) > BURST_FILE_COUNT and bucket < 3:
        bucket += 1
    return bucket


def discretize(features: dict[str, Any]) -> str:
    """Map a window feature dict to a canonical state key."""
    ah = int(bool(features.get("is_after_hours", 0)))
    usb = int(float(features.get("usb_connect", 0) or 0) > 0
              or float(features.get("usb_disconnect", 0) or 0) > 0)
    vol = volume_bucket(features.get("file_bytes_total", 0),
                        features.get("file_count", 0))
    anom = int(bool(features.get("is_anomaly", 0)))
    return f"ah{ah}|usb{usb}|vol{vol}|anom{anom}"


def parse_state(state: str) -> dict[str, int]:
    """Inverse of :func:`discretize` — used by the dashboard to label Q-table rows."""
    out: dict[str, int] = {}
    for token in state.split("|"):
        for name in ("anom", "usb", "vol", "ah"):
            if token.startswith(name):
                out[name] = int(token[len(name):])
                break
    return out


def all_states() -> list[str]:
    """Every state in the (small, finite) space, in a stable order."""
    return [
        f"ah{ah}|usb{usb}|vol{vol}|anom{anom}"
        for ah, usb, vol, anom in itertools.product((0, 1), (0, 1), (0, 1, 2, 3), (0, 1))
    ]


def state_risk(state: str) -> float:
    """Rule-based risk prior in ``[0, 1]`` for a state (cold start only)."""
    p = parse_state(state)
    risk = (
        _W_AFTER_HOURS * p.get("ah", 0)
        + _W_USB * p.get("usb", 0)
        + _W_VOLUME[p.get("vol", 0)]
        + _W_ANOMALY * p.get("anom", 0)
    )
    return risk / _MAX_RISK


def _ramp(distance: float, span: float) -> float:
    """``distance`` in units of ``span``, clamped to ``[-1, 1]``."""
    if span <= 0:
        return 0.0
    return max(-1.0, min(1.0, distance / span))


def prior_q(state: str) -> dict[str, float]:
    """Cold-start Q-values: DISMISS below ALERT_AT, ALERT between, BLOCK above.

    Each action's value is its signed distance from the risk band it owns, so
    argmax lands in the intended band by construction rather than by three curves
    happening to cross in the right places — while the magnitudes still vary
    smoothly with risk, which both the dashboard heatmap and
    :meth:`QLearner._confidence` read.

    On a boundary all three values tie at 0 and :meth:`QLearner.greedy_action`
    breaks toward the least disruptive action, so a state sitting exactly on an
    edge de-escalates instead of coin-flipping. Everything is scaled by
    :data:`PRIOR_STRENGTH` so a real analyst verdict can always overtake the
    heuristic.
    """
    r = state_risk(state)
    k = PRIOR_STRENGTH
    lo, hi = PRIOR_ALERT_AT, PRIOR_BLOCK_AT
    return {
        DISMISS: round(k * _ramp(lo - r, lo), 4),
        # ALERT owns the middle band, so it is only positive when *both* edges agree.
        ALERT: round(k * min(_ramp(r - lo, lo), _ramp(hi - r, 1.0 - hi)), 4),
        BLOCK: round(k * _ramp(r - hi, 1.0 - hi), 4),
    }


def fired_rules(features: dict[str, Any]) -> list[str]:
    """Human-readable reasons a window looks risky.

    Shown verbatim on the dashboard ("why was I alerted?") and folded into
    severity. Ported from the original rule-based verification agent, restricted
    to signals the endpoint agent actually collects.

    One rule per axis, at the same edges the state buckets use. Two rules reading
    the same number at different thresholds (the old ``large_transfer`` +
    ``bulk_transfer`` pair) put one fact on a card twice, which reads as
    corroboration and counts twice toward severity.
    """
    f = features
    rules = []
    if f.get("is_after_hours"):
        rules.append("after_hours")
    if float(f.get("usb_connect", 0) or 0) > 0:
        rules.append("removable_device")
    if float(f.get("file_count", 0) or 0) > BURST_FILE_COUNT:
        rules.append("high_file_volume")
    if float(f.get("file_bytes_total", 0) or 0) > VOL_MED_MAX:
        rules.append("large_transfer")
    if float(f.get("sensitive_count", 0) or 0) > 0:
        rules.append("sensitive_path_access")
    if float(f.get("removable_write_count", 0) or 0) > 0:
        rules.append("write_to_removable")
    if float(f.get("delete_count", 0) or 0) > 20:
        rules.append("mass_delete")
    if f.get("is_anomaly"):
        rules.append("ml_anomaly")
    return rules


class QLearner:
    """Persistent, rule-seeded Q-learning policy over the 32-state space.

    Rows are read from and written to :class:`~server.db.base.Storage`, so the
    learned policy survives a server restart. States are seeded lazily on first
    access (and eagerly by :meth:`seed_all`, so the dashboard has a full table to
    render before any feedback exists).
    """

    def __init__(
        self,
        storage: Storage,
        alpha: float = 0.3,
        gamma: float = 0.0,
        epsilon: float = 0.0,
        safe_exploration: bool = True,
        rng: random.Random | None = None,
    ):
        self.storage = storage
        self.alpha = float(alpha)
        self.gamma = float(gamma)
        self.epsilon = float(epsilon)
        # Never let exploration *escalate* to BLOCK on a live endpoint: a random
        # containment action against a real user is not an acceptable cost of
        # learning. Exploration may only try a less-disruptive action.
        self.safe_exploration = bool(safe_exploration)
        self._rng = rng or random.Random(1337)

    # ── table access ──────────────────────────────────────────────────────────
    def _row(self, state: str) -> dict:
        row = self.storage.get_qrow(state)
        if row is None:
            q = prior_q(state)
            row = {
                "state": state,
                "q_dismiss": q[DISMISS], "q_alert": q[ALERT], "q_block": q[BLOCK],
                "n_dismiss": 0, "n_alert": 0, "n_block": 0,
            }
            self.storage.upsert_qrow(row)
        return row

    def q_values(self, state: str) -> dict[str, float]:
        row = self._row(state)
        return {a: float(row[_QCOL[a]]) for a in ACTIONS}

    def seed_all(self) -> int:
        """Ensure every state has a row. Returns how many were newly created."""
        created = 0
        for state in all_states():
            if self.storage.get_qrow(state) is None:
                self._row(state)
                created += 1
        return created

    def reset(self) -> None:
        """Wipe learned values back to the rule-based prior (keeps visit counts at 0)."""
        for state in all_states():
            q = prior_q(state)
            self.storage.upsert_qrow({
                "state": state,
                "q_dismiss": q[DISMISS], "q_alert": q[ALERT], "q_block": q[BLOCK],
                "n_dismiss": 0, "n_alert": 0, "n_block": 0,
            })

    # ── policy ────────────────────────────────────────────────────────────────
    def greedy_action(self, state: str) -> str:
        q = self.q_values(state)
        # Ties break toward the least disruptive action (ACTIONS is ordered
        # DISMISS < ALERT < BLOCK), so the policy never escalates on a coin flip.
        return max(ACTIONS, key=lambda a: (q[a], -ACTIONS.index(a)))

    def decide(self, state: str) -> dict[str, Any]:
        """Choose an action for a state. Returns the decision plus its rationale."""
        q = self.q_values(state)
        greedy = self.greedy_action(state)
        action, explored = greedy, False

        if self.epsilon > 0 and self._rng.random() < self.epsilon:
            candidates = list(ACTIONS)
            if self.safe_exploration:
                # only actions no more disruptive than the greedy one
                candidates = ACTIONS[: ACTIONS.index(greedy) + 1]
            candidates = [a for a in candidates if a != greedy] or [greedy]
            action = self._rng.choice(candidates)
            explored = action != greedy

        return {
            "state": state,
            "action": action,
            "greedy_action": greedy,
            "explored": explored,
            "q_values": q,
            "confidence": self._confidence(q, action),
        }

    @staticmethod
    def _confidence(q: dict[str, float], action: str) -> float:
        """Margin between the chosen action and the runner-up, squashed to ``[0, 1]``."""
        others = [v for a, v in q.items() if a != action]
        margin = q[action] - max(others) if others else 0.0
        return round(max(0.0, min(1.0, 0.5 + margin / 2.0)), 4)

    # ── learning ──────────────────────────────────────────────────────────────
    def update(self, state: str, action: str, reward: float,
               next_state: str | None = None) -> dict[str, float]:
        """Apply one temporal-difference update and persist it."""
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action!r}; expected one of {ACTIONS}")
        row = dict(self._row(state))
        old = float(row[_QCOL[action]])

        future = 0.0
        if self.gamma and next_state:
            future = max(self.q_values(next_state).values())

        td_target = float(reward) + self.gamma * future
        row[_QCOL[action]] = old + self.alpha * (td_target - old)
        row[_NCOL[action]] = int(row[_NCOL[action]]) + 1
        self.storage.upsert_qrow(row)
        return {a: float(row[_QCOL[a]]) for a in ACTIONS}

    def apply_feedback(self, state: str, action: str, admin_action: str,
                       next_state: str | None = None) -> dict[str, Any]:
        """Turn an analyst verdict into rewards and learn from it.

        ``admin_action`` is ``"block"`` (the threat was real) or ``"dismiss"``
        (false positive). Two updates are applied, and the second one is what
        makes the feedback loop actually work:

        1. **On-policy** — the action the policy took is rewarded per
           :data:`REWARDS`, which is the ordinary bandit update.
        2. **Off-policy** — the action the analyst *endorsed* is rewarded too,
           when it differs from the one taken.

        Without (2) the policy has a ceiling it can never cross. Safe exploration
        deliberately refuses to escalate, so ``BLOCK`` is only ever tried in a
        state that already prefers it, and an update that touches only the action
        taken leaves ``Q(s, BLOCK)`` pinned at its cold-start prior forever. An
        analyst confirming a threat that the policy merely ``ALERT``-ed would earn
        ``ALERT`` its +0.5 and teach ``BLOCK`` nothing — click "Block" a thousand
        times and the state still never blocks.

        Learning about an action you did not take is exactly what Q-learning's
        off-policy nature permits, and here it is better grounded than usual: an
        analyst verdict is a *label on the correct response*, not just a scalar
        consequence of the response tried. Note this teaches the policy to block
        without letting it ever *initiate* a block — escalation still requires a
        human to have asked for it first.
        """
        verdict = str(admin_action).strip().lower()
        if verdict not in REWARDS:
            raise ValueError(
                f"unknown admin action {admin_action!r}; expected "
                f"{ADMIN_BLOCK!r} or {ADMIN_DISMISS!r}"
            )
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action!r}; expected one of {ACTIONS}")

        reward = REWARDS[verdict][action]
        before = self.q_values(state)
        after = self.update(state, action, reward, next_state=next_state)

        # The endorsed action, unless the policy already chose it — updating the
        # same cell twice for one verdict would count a single click as two.
        endorsed = ENDORSED_ACTION[verdict]
        endorsed_reward = None
        if endorsed != action:
            endorsed_reward = REWARDS[verdict][endorsed]
            after = self.update(state, endorsed, endorsed_reward, next_state=next_state)

        return {
            "state": state,
            "action": action,
            "admin_action": verdict,
            "reward": reward,
            "endorsed_action": endorsed,
            "endorsed_reward": endorsed_reward,
            "q_before": before,
            "q_after": after,
            "policy_before": max(ACTIONS, key=lambda a: (before[a], -ACTIONS.index(a))),
            "policy_after": self.greedy_action(state),
        }

    # ── introspection (dashboard "RL insights" panel) ──────────────────────────
    def table(self) -> list[dict[str, Any]]:
        rows = {r["state"]: r for r in self.storage.all_qrows()}
        out = []
        for state in all_states():
            row = rows.get(state)
            if row is None:
                q, visits = prior_q(state), {a: 0 for a in ACTIONS}
                seeded = True
            else:
                q = {a: float(row[_QCOL[a]]) for a in ACTIONS}
                visits = {a: int(row[_NCOL[a]]) for a in ACTIONS}
                seeded = sum(visits.values()) == 0
            best = max(ACTIONS, key=lambda a: (q[a], -ACTIONS.index(a)))
            labels = parse_state(state)
            out.append({
                "state": state,
                "after_hours": bool(labels.get("ah")),
                "usb": bool(labels.get("usb")),
                "volume": VOLUME_NAMES[labels.get("vol", 0)],
                "ml_anomaly": bool(labels.get("anom")),
                "risk_prior": round(state_risk(state), 4),
                "q": {a: round(v, 4) for a, v in q.items()},
                "visits": visits,
                "total_visits": sum(visits.values()),
                "best_action": best,
                "untrained": seeded,
            })
        return out

    def stats(self) -> dict[str, Any]:
        table = self.table()
        trained = [r for r in table if not r["untrained"]]
        return {
            "n_states": len(table),
            "n_states_trained": len(trained),
            "total_feedback": sum(r["total_visits"] for r in table),
            "alpha": self.alpha,
            "gamma": self.gamma,
            "epsilon": self.epsilon,
            "safe_exploration": self.safe_exploration,
            "policy": {r["state"]: r["best_action"] for r in table},
        }
