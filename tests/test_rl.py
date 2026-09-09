"""RL verification tests — state space, cold-start prior, Q-updates, feedback loop."""

from __future__ import annotations

import random

import pytest

from server.db.sqlite_store import SQLiteStorage
from server.rl.qlearning import (
    ACTIONS,
    ADMIN_BLOCK,
    ADMIN_DISMISS,
    ALERT,
    BLOCK,
    DISMISS,
    MB,
    QLearner,
    all_states,
    discretize,
    fired_rules,
    parse_state,
    prior_q,
    state_risk,
    volume_bucket,
)
from tools.synth import exfiltration_events, normal_events
from vigil.features import RollingFeatureStore


@pytest.fixture()
def learner(tmp_path):
    store = SQLiteStorage(str(tmp_path / "rl.db"))
    store.init_schema()
    yield QLearner(store, alpha=0.5, gamma=0.0, epsilon=0.0)
    store.close()


# ── state space ───────────────────────────────────────────────────────────────
def test_state_space_is_32_and_unique():
    states = all_states()
    assert len(states) == 32
    assert len(set(states)) == 32


def test_discretize_roundtrips_through_parse_state():
    for state in all_states():
        p = parse_state(state)
        assert set(p) == {"ah", "usb", "vol", "anom"}
        assert f"ah{p['ah']}|usb{p['usb']}|vol{p['vol']}|anom{p['anom']}" == state


def test_volume_buckets():
    assert volume_bucket(0) == 0
    assert volume_bucket(5 * MB) == 1
    assert volume_bucket(800 * MB) == 2
    assert volume_bucket(3000 * MB) == 3
    # a large file burst promotes one bucket even at modest total size
    assert volume_bucket(5 * MB, file_count=150) == 2
    assert volume_bucket(3000 * MB, file_count=150) == 3   # cannot exceed 3
    assert volume_bucket(None) == 0                       # missing data is not a crash


def test_volume_buckets_are_calibrated_against_benign_behaviour():
    """"High volume" must be rare in normal activity, or it is not a signal.

    The bucket edges are set from the measured benign distribution rather than
    guessed, so this pins the property that justified them: an hour of ordinary
    work almost never reaches the top bucket. Set ``VOL_MED_MAX`` too low and the
    dashboard fills with 600 MB downloads — which is exactly what it did at the
    original 500 MB.
    """
    store = RollingFeatureStore()
    store.update(normal_events(num_users=20, days=14, seed=77))
    windows = [w.feature_dict() for w in store.all_windows()]
    assert len(windows) > 500, "not enough benign windows to say anything"

    buckets = [volume_bucket(f["file_bytes_total"], f["file_count"]) for f in windows]
    top = sum(1 for b in buckets if b == 3) / len(buckets)
    # Comparable to the detection model's contamination=0.02: "high" means rarer
    # than 1-in-20 hours of normal work, with headroom for a noisier real fleet.
    assert top < 0.05, f"{top:.1%} of benign windows are 'high volume'"
    # ...and it must still be reachable, or the bucket is decorative.
    assert top > 0.0


def test_discretize_flags_the_poster_scenario_as_worst_case():
    store = RollingFeatureStore()
    store.update(exfiltration_events())
    win = store.all_windows()[0]
    f = win.feature_dict() | {"is_anomaly": True}
    assert discretize(f) == "ah1|usb1|vol3|anom1"


def test_discretize_treats_quiet_daytime_window_as_benign_state():
    f = {"is_after_hours": 0, "usb_connect": 0, "file_bytes_total": 2 * MB,
         "file_count": 3, "is_anomaly": False}
    assert discretize(f) == "ah0|usb0|vol1|anom0"


def test_discretize_tolerates_missing_keys():
    assert discretize({}) == "ah0|usb0|vol0|anom0"


def test_usb_disconnect_alone_still_counts_as_device_activity():
    f = {"usb_disconnect": 1}
    assert parse_state(discretize(f))["usb"] == 1


# ── cold start ────────────────────────────────────────────────────────────────
def test_risk_prior_is_monotonic_at_the_extremes():
    assert state_risk("ah0|usb0|vol0|anom0") == 0.0
    assert state_risk("ah1|usb1|vol3|anom1") == pytest.approx(1.0)


def test_prior_policy_dismisses_quiet_and_blocks_the_worst_case():
    assert max(prior_q("ah0|usb0|vol0|anom0"), key=prior_q("ah0|usb0|vol0|anom0").get) == DISMISS
    worst = prior_q("ah1|usb1|vol3|anom1")
    assert max(worst, key=worst.get) == BLOCK


def test_cold_start_policy_is_sensible_across_the_whole_table(learner):
    """Before any feedback the policy must already behave like the original rules."""
    policy = {s: learner.greedy_action(s) for s in all_states()}
    # nothing happening -> never escalate
    assert policy["ah0|usb0|vol0|anom0"] == DISMISS
    # the poster's exfiltration signature -> block
    assert policy["ah1|usb1|vol3|anom1"] == BLOCK
    # after-hours alone is not enough to block someone
    assert policy["ah1|usb0|vol0|anom0"] != BLOCK
    # every state has a valid decision, and BLOCK is reserved for genuine risk
    for state, action in policy.items():
        assert action in ACTIONS
        if action == BLOCK:
            assert state_risk(state) >= 0.5, f"{state} blocks at low risk"
        if action == DISMISS:
            assert state_risk(state) < 0.5, f"{state} dismissed at high risk"


def test_seed_all_populates_then_is_idempotent(learner):
    assert learner.seed_all() == 32
    assert learner.seed_all() == 0
    assert len(learner.storage.all_qrows()) == 32


def test_states_are_seeded_lazily_on_first_read(learner):
    assert learner.storage.get_qrow("ah1|usb1|vol3|anom1") is None
    learner.q_values("ah1|usb1|vol3|anom1")
    assert learner.storage.get_qrow("ah1|usb1|vol3|anom1") is not None


# ── learning ──────────────────────────────────────────────────────────────────
def test_confirming_a_block_reinforces_it(learner):
    state = "ah1|usb1|vol3|anom1"
    before = learner.q_values(state)[BLOCK]
    res = learner.apply_feedback(state, BLOCK, ADMIN_BLOCK)
    assert res["reward"] == pytest.approx(1.0)
    # The prior is deliberately weaker than a real verdict, so confirmation moves
    # the value strictly upward rather than sitting at a ceiling.
    assert res["q_after"][BLOCK] > before
    assert res["policy_after"] == BLOCK
    assert learner.greedy_action(state) == BLOCK


def test_repeated_confirmation_converges_toward_the_reward(learner):
    state = "ah1|usb1|vol3|anom1"
    for _ in range(20):
        learner.apply_feedback(state, BLOCK, ADMIN_BLOCK)
    assert learner.q_values(state)[BLOCK] == pytest.approx(1.0, abs=1e-3)


def test_dismissing_a_block_pushes_the_policy_away_from_blocking(learner):
    state = "ah1|usb1|vol2|anom1"
    # A handful of "this was a false positive" verdicts must change the decision.
    for _ in range(8):
        action = learner.greedy_action(state)
        if action == DISMISS:
            break
        learner.apply_feedback(state, action, ADMIN_DISMISS)
    assert learner.greedy_action(state) != BLOCK


def test_overturned_dismissal_teaches_the_policy_to_escalate(learner):
    """If analysts keep blocking what the policy dismissed, it must learn to escalate."""
    state = "ah0|usb0|vol1|anom0"
    assert learner.greedy_action(state) == DISMISS
    for _ in range(15):
        action = learner.greedy_action(state)
        if action != DISMISS:
            break
        learner.apply_feedback(state, action, ADMIN_BLOCK)
    assert learner.greedy_action(state) != DISMISS


def test_confirmed_alerts_teach_a_state_to_block(learner):
    """The regression this off-policy update exists to prevent.

    ALERT under a block verdict earns +0.5 — a *positive* reward — so the
    on-policy update alone can never lift BLOCK above it. Combined with safe
    exploration (which refuses to try BLOCK unless it is already greedy), a state
    that alerts would alert forever no matter how many times an analyst confirmed
    the threat was real.
    """
    state = "ah1|usb0|vol2|anom0"
    assert learner.greedy_action(state) == ALERT

    for _ in range(10):
        action = learner.greedy_action(state)
        if action == BLOCK:
            break
        assert action == ALERT, "the policy should not have wandered off ALERT"
        learner.apply_feedback(state, action, ADMIN_BLOCK)

    assert learner.greedy_action(state) == BLOCK
    q = learner.q_values(state)
    assert q[BLOCK] > q[ALERT]
    # Escalation was learned, never self-initiated: every action fed back was ALERT.
    assert learner.storage.get_qrow(state)["n_alert"] > 0


def test_safe_exploration_still_never_proposes_a_block_on_its_own(tmp_path):
    """Learning to block must not weaken the guarantee that made it necessary."""
    store = SQLiteStorage(str(tmp_path / "explore.db"))
    store.init_schema()
    ql = QLearner(store, epsilon=1.0, safe_exploration=True,
                  rng=random.Random(7))
    for state in all_states():
        if ql.greedy_action(state) == BLOCK:
            continue
        for _ in range(20):
            assert ql.decide(state)["action"] != BLOCK, state
    store.close()


def test_update_follows_the_q_learning_rule_exactly(learner):
    state = "ah0|usb1|vol2|anom1"
    q0 = learner.q_values(state)[ALERT]
    learner.update(state, ALERT, reward=1.0)
    # gamma = 0, alpha = 0.5  ->  q1 = q0 + 0.5 * (1.0 - q0)
    assert learner.q_values(state)[ALERT] == pytest.approx(q0 + 0.5 * (1.0 - q0))


def test_gamma_includes_the_discounted_future_value(tmp_path):
    store = SQLiteStorage(str(tmp_path / "g.db"))
    store.init_schema()
    ql = QLearner(store, alpha=1.0, gamma=0.9, epsilon=0.0)
    s, s2 = "ah0|usb0|vol0|anom0", "ah1|usb1|vol3|anom1"
    future = max(ql.q_values(s2).values())
    ql.update(s, ALERT, reward=0.0, next_state=s2)
    # alpha = 1  ->  q becomes exactly the TD target: r + gamma * max Q(s')
    assert ql.q_values(s)[ALERT] == pytest.approx(0.9 * future)
    store.close()


def test_visit_counts_increment_per_action(learner):
    state = "ah1|usb0|vol1|anom1"
    learner.apply_feedback(state, ALERT, ADMIN_BLOCK)     # ALERT taken, BLOCK endorsed
    learner.apply_feedback(state, ALERT, ADMIN_DISMISS)   # ALERT taken, DISMISS endorsed
    learner.apply_feedback(state, BLOCK, ADMIN_BLOCK)     # taken == endorsed: one update
    row = learner.storage.get_qrow(state)
    assert row["n_alert"] == 2
    assert row["n_block"] == 2
    assert row["n_dismiss"] == 1
    # Three verdicts, five updates — not six. A verdict that endorses the action
    # already taken must not be counted twice.
    assert row["n_alert"] + row["n_block"] + row["n_dismiss"] == 5


def test_an_endorsed_action_is_not_double_counted(learner):
    state = "ah1|usb1|vol3|anom1"
    res = learner.apply_feedback(state, BLOCK, ADMIN_BLOCK)
    assert res["endorsed_action"] == BLOCK
    assert res["endorsed_reward"] is None, "no second update when it would be redundant"
    assert learner.storage.get_qrow(state)["n_block"] == 1


def test_learning_persists_across_restart(tmp_path):
    path = str(tmp_path / "persist.db")
    s1 = SQLiteStorage(path)
    s1.init_schema()
    ql1 = QLearner(s1, alpha=0.9)
    state = "ah1|usb1|vol3|anom1"
    for _ in range(5):
        ql1.apply_feedback(state, BLOCK, ADMIN_BLOCK)
    learned = ql1.q_values(state)[BLOCK]
    s1.close()

    s2 = SQLiteStorage(path)
    s2.init_schema()
    ql2 = QLearner(s2)
    assert ql2.q_values(state)[BLOCK] == pytest.approx(learned)
    assert ql2.greedy_action(state) == BLOCK
    s2.close()


def test_reset_restores_the_rule_prior(learner):
    state = "ah1|usb1|vol3|anom1"
    for _ in range(5):
        learner.apply_feedback(state, BLOCK, ADMIN_DISMISS)
    assert learner.q_values(state)[BLOCK] != pytest.approx(prior_q(state)[BLOCK])
    learner.reset()
    assert learner.q_values(state)[BLOCK] == pytest.approx(prior_q(state)[BLOCK])
    assert learner.storage.get_qrow(state)["n_block"] == 0


def test_rejects_unknown_actions_and_verdicts(learner):
    with pytest.raises(ValueError, match="unknown action"):
        learner.update("ah0|usb0|vol0|anom0", "QUARANTINE", 1.0)
    with pytest.raises(ValueError, match="unknown admin action"):
        learner.apply_feedback("ah0|usb0|vol0|anom0", ALERT, "maybe")


def test_admin_verdict_is_case_and_space_insensitive(learner):
    res = learner.apply_feedback("ah1|usb1|vol3|anom1", BLOCK, "  BlOcK ")
    assert res["admin_action"] == ADMIN_BLOCK
    assert res["reward"] == pytest.approx(1.0)


# ── decision surface ──────────────────────────────────────────────────────────
def test_decide_reports_its_rationale(learner):
    d = learner.decide("ah1|usb1|vol3|anom1")
    assert d["action"] == BLOCK
    assert d["greedy_action"] == BLOCK
    assert d["explored"] is False
    assert set(d["q_values"]) == set(ACTIONS)
    assert 0.0 <= d["confidence"] <= 1.0


def test_ties_break_toward_the_least_disruptive_action(tmp_path):
    store = SQLiteStorage(str(tmp_path / "tie.db"))
    store.init_schema()
    store.upsert_qrow({"state": "ah0|usb0|vol0|anom0",
                       "q_dismiss": 0.5, "q_alert": 0.5, "q_block": 0.5})
    ql = QLearner(store)
    assert ql.greedy_action("ah0|usb0|vol0|anom0") == DISMISS
    store.close()


def test_exploration_never_escalates_to_block(tmp_path):
    """Random exploration must not contain a real user — safety over learning speed."""
    store = SQLiteStorage(str(tmp_path / "eps.db"))
    store.init_schema()
    ql = QLearner(store, epsilon=1.0, safe_exploration=True, rng=random.Random(0))
    # A state whose greedy action is DISMISS can only ever explore to DISMISS.
    for _ in range(50):
        assert ql.decide("ah0|usb0|vol0|anom0")["action"] == DISMISS
    # A state whose greedy action is ALERT may de-escalate but never escalate.
    alert_state = next(s for s in all_states() if ql.greedy_action(s) == ALERT)
    seen = {ql.decide(alert_state)["action"] for _ in range(100)}
    assert BLOCK not in seen
    store.close()


def test_unsafe_exploration_can_pick_any_action(tmp_path):
    store = SQLiteStorage(str(tmp_path / "eps2.db"))
    store.init_schema()
    ql = QLearner(store, epsilon=1.0, safe_exploration=False, rng=random.Random(3))
    seen = {ql.decide("ah0|usb0|vol0|anom0")["action"] for _ in range(200)}
    assert seen == {ALERT, BLOCK}   # epsilon=1 always leaves the greedy DISMISS


def test_zero_epsilon_is_fully_deterministic(learner):
    for state in all_states():
        actions = {learner.decide(state)["action"] for _ in range(10)}
        assert len(actions) == 1


# ── rules / explanations ──────────────────────────────────────────────────────
def test_fired_rules_explain_the_poster_scenario():
    store = RollingFeatureStore()
    store.update(exfiltration_events())
    f = store.all_windows()[0].feature_dict() | {"is_anomaly": True, "sensitive_count": 12}
    rules = fired_rules(f)
    assert "after_hours" in rules
    assert "removable_device" in rules
    assert "bulk_transfer" not in rules, "one byte threshold, not two overlapping ones"
    assert "large_transfer" in rules
    assert "sensitive_path_access" in rules
    assert "ml_anomaly" in rules


def test_benign_daytime_activity_is_never_blocked(learner):
    """Heavy-but-legitimate daytime work must not be contained.

    A single rule firing is a *signal*, not a verdict: a real workstation can
    move gigabytes at 9am (a large download, a video export). What must not
    happen is the policy escalating that to BLOCK.
    """
    store = RollingFeatureStore()
    store.update(normal_events(num_users=4, days=6, seed=3))
    blocked = []
    for w in store.all_windows():
        f = w.feature_dict() | {"is_anomaly": False}
        if learner.greedy_action(discretize(f)) == BLOCK:
            blocked.append(f)
    assert not blocked, f"{len(blocked)} benign windows would be blocked"


def test_no_single_signal_is_worth_an_alert_on_its_own():
    """The invariant the prior's ALERT boundary encodes.

    One ordinary fact about a window — it happened at 21:00, a USB stick was
    plugged in, a lot of data moved, the model called it unusual — is not a threat.
    Corroboration is. Boundaries set below this line are what turn a SOC console
    into a wall of single-signal noise nobody reads.
    """
    for state in all_states():
        signals = parse_state(state)
        n = (signals["ah"] + signals["usb"] + signals["anom"]
             + (1 if signals["vol"] > 0 else 0))
        best = max(ACTIONS, key=lambda a: (prior_q(state)[a], -ACTIONS.index(a)))
        if n <= 1:
            assert best == DISMISS, f"{state} escalates to {best} on one signal"
        # BLOCK is the strong claim: it needs data movement, not just three flags.
        if best == BLOCK:
            assert signals["vol"] > 0, f"{state} blocks with no data moved"


def test_benign_traffic_does_not_flood_the_console(learner):
    """The alert *rate* on ordinary activity, which is what makes a SOC tool usable.

    An accuracy claim says nothing about workload: a policy that escalates a
    quarter of all behaviour windows is worthless even if every real threat is in
    there somewhere, because no analyst will read the pile. The ML stage flags 2%
    of windows by construction (``contamination=0.02``), so the policy's own
    escalation rate on top of that is the number to hold down.
    """
    store = RollingFeatureStore()
    store.update(normal_events(num_users=12, days=10, seed=21))
    windows = [w.feature_dict() | {"is_anomaly": False} for w in store.all_windows()]
    assert len(windows) > 400

    escalated = [f for f in windows
                 if learner.greedy_action(discretize(f)) != DISMISS]
    rate = len(escalated) / len(windows)
    assert rate < 0.05, (
        f"{rate:.1%} of benign windows escalate ({len(escalated)}/{len(windows)}) — "
        f"an analyst would see one alert every {1 / max(rate, 1e-9):.0f} quiet hours"
    )


def test_after_hours_alone_does_not_fire_transfer_rules():
    """Working late is not exfiltration — quiet after-hours windows stay quiet."""
    f = {"is_after_hours": 1, "file_count": 4, "file_bytes_total": 3 * MB}
    assert fired_rules(f) == ["after_hours"]


def test_fired_rules_on_empty_features():
    assert fired_rules({}) == []


# ── introspection ─────────────────────────────────────────────────────────────
def test_table_exposes_every_state_with_labels(learner):
    table = learner.table()
    assert len(table) == 32
    row = next(r for r in table if r["state"] == "ah1|usb1|vol3|anom1")
    assert row["after_hours"] is True and row["usb"] is True
    assert row["ml_anomaly"] is True and row["volume"] == "high"
    assert row["best_action"] == BLOCK
    assert row["untrained"] is True
    assert row["total_visits"] == 0


def test_table_marks_states_as_trained_after_feedback(learner):
    state = "ah1|usb1|vol3|anom1"
    learner.apply_feedback(state, BLOCK, ADMIN_BLOCK)
    row = next(r for r in learner.table() if r["state"] == state)
    assert row["untrained"] is False
    assert row["total_visits"] == 1


def test_stats_summarise_the_policy(learner):
    learner.apply_feedback("ah1|usb1|vol3|anom1", BLOCK, ADMIN_BLOCK)
    st = learner.stats()
    assert st["n_states"] == 32
    assert st["n_states_trained"] == 1
    assert st["total_feedback"] == 1
    assert st["alpha"] == pytest.approx(0.5)
    assert len(st["policy"]) == 32
