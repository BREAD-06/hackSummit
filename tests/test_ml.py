"""Detection-model tests — training, persistence, scoring, and train/inference parity.

Training a real Isolation Forest is a few seconds, so the fitted model is shared
across the module via a session-scoped fixture.
"""

from __future__ import annotations

import numpy as np
import pytest

from server.ml.model import DetectionModel
from server.ml.train import train
from tools.synth import exfiltration_events, normal_events, staging_events
from vigil import features
from vigil.features import LIVE_FEATURE_COLS, RollingFeatureStore


@pytest.fixture(scope="module")
def model(tmp_path_factory) -> DetectionModel:
    out = tmp_path_factory.mktemp("models") / "iforest.pkl"
    # A small-but-representative corpus keeps the test fast without changing behaviour.
    return train(source="synthetic", out=str(out), users=12, days=14,
                 n_estimators=100, check=False)


def _worst(model: DetectionModel, events):
    store = RollingFeatureStore()
    store.update(events)
    return min((model.score_window(w) for w in store.all_windows()), key=lambda r: r[0])


def test_model_metadata(model):
    info = model.info()
    assert info["type"] == "IsolationForest"
    assert info["feature_cols"] == LIVE_FEATURE_COLS
    assert info["n_features"] == len(LIVE_FEATURE_COLS)
    assert info["meta"]["source"] == "synthetic"
    assert info["meta"]["n_train_windows"] > 500


def test_save_load_roundtrip_gives_identical_scores(model, tmp_path):
    path = str(tmp_path / "rt.pkl")
    model.save(path)
    reloaded = DetectionModel.load(path)

    assert reloaded.threshold == model.threshold
    assert reloaded.feature_cols == model.feature_cols

    store = RollingFeatureStore()
    store.update(normal_events(num_users=2, days=2, seed=5))
    for w in store.all_windows():
        assert reloaded.score_window(w) == model.score_window(w)


def test_load_missing_model_raises_with_guidance(tmp_path):
    with pytest.raises(FileNotFoundError, match="server.ml.train"):
        DetectionModel.load(str(tmp_path / "absent.pkl"))


def test_exfiltration_scenario_is_flagged(model):
    score, flagged = _worst(model, exfiltration_events())
    assert flagged is True
    assert score < model.threshold


def test_staging_scenario_is_flagged(model):
    score, flagged = _worst(model, staging_events())
    assert flagged is True


def test_benign_holdout_false_positive_rate_is_low(model):
    store = RollingFeatureStore()
    store.update(normal_events(num_users=8, days=10, seed=4242))
    results = [model.score_window(w) for w in store.all_windows()]
    assert len(results) > 200
    fpr = sum(1 for _s, f in results if f) / len(results)
    # Trained at contamination=0.02; anything under 10% on held-out users means the
    # model learned "normal" rather than memorising the training set.
    assert fpr < 0.10, f"false-positive rate too high: {fpr:.2%}"


def test_threat_scores_worse_than_typical_benign(model):
    exfil_score, _ = _worst(model, exfiltration_events())
    store = RollingFeatureStore()
    store.update(normal_events(num_users=6, days=6, seed=808))
    benign = np.array([s for s, _f in (model.score_window(w) for w in store.all_windows())])
    # The attack must be more anomalous than the vast majority of benign windows.
    assert exfil_score < np.percentile(benign, 5)


def test_empty_input_scores_empty(model):
    assert model.score_feature_dicts([]) == []


def test_missing_features_default_to_zero(model):
    """A partial feature dict must not raise — absent keys are treated as 0."""
    (score, flagged) = model.score_feature_dicts([{"hour": 3.0}])[0]
    assert isinstance(score, float) and isinstance(flagged, bool)


def test_scoring_is_column_order_independent(model):
    """Feature dicts are looked up by name, so key order cannot shift the result."""
    store = RollingFeatureStore()
    store.update(exfiltration_events())
    fd = store.all_windows()[0].feature_dict()
    shuffled = dict(reversed(list(fd.items())))
    assert model.score_feature_dicts([shuffled]) == model.score_feature_dicts([fd])


def test_live_and_training_paths_produce_identical_vectors():
    """The rolling store (live) and aggregate_frame (training) must agree exactly.

    This is the guard against train/inference feature drift: both go through
    ``vigil.features._contribution``, and this test proves they stay aligned.
    """
    events = normal_events(num_users=3, days=4, seed=31) + exfiltration_events()

    store = RollingFeatureStore()
    store.update(events)
    live = {
        (w.agent_id, w.user, w.host, w.window_start.isoformat()): tuple(w.vector())
        for w in store.all_windows()
    }

    frame = features.aggregate_frame(events)
    batch = {
        (r.agent_id, r.user, r.host, r.window_start.isoformat()):
            tuple(float(getattr(r, c)) for c in LIVE_FEATURE_COLS)
        for r in frame.itertuples(index=False)
    }

    assert live.keys() == batch.keys()
    assert live == batch
