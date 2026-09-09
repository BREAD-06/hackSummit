"""Isolation Forest wrapper for scoring live behaviour windows.

The model is persisted as a bundle (``joblib``) containing the fitted estimator,
the exact feature column order it was trained on, and a decision-function
threshold calibrated at training time. Scoring converts a window's feature dict
into a plain numpy row (no pandas feature-name coupling), so training and
inference use identical inputs.

Convention: ``decision_function`` returns higher = more normal, lower = more
anomalous. A window is anomalous when its score is **below** the stored
threshold.
"""

from __future__ import annotations

import os

import joblib
import numpy as np

from vigil.features import LIVE_FEATURE_COLS

DEFAULT_MODEL_PATH = "models/vigil_iforest.pkl"


class DetectionModel:
    def __init__(self, model, feature_cols: list[str], threshold: float, meta: dict | None = None):
        self.model = model
        self.feature_cols = feature_cols
        self.threshold = float(threshold)
        self.meta = meta or {}

    # ── persistence ──
    @classmethod
    def load(cls, path: str = DEFAULT_MODEL_PATH) -> "DetectionModel":
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Model not found at '{path}'. Train it first:\n"
                f"    python -m server.ml.train --source synthetic"
            )
        bundle = joblib.load(path)
        return cls(
            model=bundle["model"],
            feature_cols=bundle["feature_cols"],
            threshold=bundle["threshold"],
            meta=bundle.get("meta", {}),
        )

    def save(self, path: str = DEFAULT_MODEL_PATH) -> None:
        if os.path.dirname(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "feature_cols": self.feature_cols,
                "threshold": self.threshold,
                "meta": self.meta,
            },
            path,
        )

    # ── scoring ──
    def _matrix(self, feature_dicts: list[dict]) -> np.ndarray:
        return np.asarray(
            [[float(fd.get(c, 0.0)) for c in self.feature_cols] for fd in feature_dicts],
            dtype=float,
        )

    def score_feature_dicts(self, feature_dicts: list[dict]) -> list[tuple[float, bool]]:
        if not feature_dicts:
            return []
        X = self._matrix(feature_dicts)
        scores = self.model.decision_function(X)
        return [(float(s), bool(s < self.threshold)) for s in scores]

    def score_window(self, window) -> tuple[float, bool]:
        """Score a :class:`vigil.features.Window`. Returns ``(anomaly_score, is_anomaly)``."""
        (result,) = self.score_feature_dicts([window.feature_dict()])
        return result

    def info(self) -> dict:
        return {
            "type": "IsolationForest",
            "n_estimators": int(getattr(self.model, "n_estimators", 0)),
            "contamination": (
                float(self.model.contamination)
                if isinstance(getattr(self.model, "contamination", None), float)
                else str(getattr(self.model, "contamination", "auto"))
            ),
            "n_features": int(getattr(self.model, "n_features_in_", len(self.feature_cols))),
            "feature_cols": self.feature_cols,
            "threshold": self.threshold,
            "meta": self.meta,
        }
