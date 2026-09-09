"""Stage 4 — Detection: score behaviour windows with the Isolation Forest.

A thin, deliberately boring stage. All it does is hand a window's feature dict to
the trained model and report the anomaly score. Keeping it thin is what makes the
train/inference contract easy to hold: the model sees exactly
:data:`vigil.features.LIVE_FEATURE_COLS` and nothing else.

The raw Isolation Forest ``decision_function`` output is unbounded and centred on
zero, which is meaningless on a dashboard. :func:`normalised_score` maps it to a
0-100 "risk" number for display, while the raw score stays the source of truth
for the threshold comparison.
"""

from __future__ import annotations

from dataclasses import dataclass

from server.ml.model import DetectionModel
from vigil.features import Window

# decision_function values beyond this magnitude are treated as saturated when
# mapping to the 0-100 display scale.
_DISPLAY_SPAN = 0.25


def normalised_score(raw: float, threshold: float) -> float:
    """Map a raw anomaly score to a 0-100 risk value for display.

    50 sits exactly at the decision threshold, so "above 50" means "the model
    considers this anomalous" without the analyst needing to know the sign
    convention of an Isolation Forest.
    """
    delta = threshold - float(raw)          # positive = more anomalous than threshold
    scaled = 50.0 + 50.0 * (delta / _DISPLAY_SPAN)
    return round(max(0.0, min(100.0, scaled)), 2)


@dataclass
class Detection:
    window_key: tuple
    agent_id: str
    user: str
    host: str
    window_start: str
    hour: int
    day_of_week: int
    features: dict[str, float]
    anomaly_score: float
    is_anomaly: bool
    risk: float

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["window_key"] = "|".join(str(p) for p in self.window_key)
        return d


class DetectionStage:
    def __init__(self, model: DetectionModel):
        self.model = model

    @property
    def threshold(self) -> float:
        return self.model.threshold

    def score(self, window: Window) -> Detection:
        features = window.feature_dict()
        raw, is_anomaly = self.model.score_feature_dicts([features])[0]
        return Detection(
            window_key=window.key,
            agent_id=window.agent_id,
            user=window.user,
            host=window.host,
            window_start=window.window_start.isoformat(),
            hour=window.hour,
            day_of_week=window.day_of_week,
            features=features,
            anomaly_score=raw,
            is_anomaly=is_anomaly,
            risk=normalised_score(raw, self.model.threshold),
        )

    def score_many(self, windows: list[Window]) -> list[Detection]:
        """Batch-score windows in a single model call (one matrix, not N)."""
        if not windows:
            return []
        feature_dicts = [w.feature_dict() for w in windows]
        results = self.model.score_feature_dicts(feature_dicts)
        return [
            Detection(
                window_key=w.key, agent_id=w.agent_id, user=w.user, host=w.host,
                window_start=w.window_start.isoformat(), hour=w.hour,
                day_of_week=w.day_of_week, features=f, anomaly_score=raw,
                is_anomaly=flag, risk=normalised_score(raw, self.model.threshold),
            )
            for w, f, (raw, flag) in zip(windows, feature_dicts, results)
        ]

    def info(self) -> dict:
        return self.model.info()
