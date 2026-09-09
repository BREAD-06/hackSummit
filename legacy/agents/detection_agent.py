# detection_agent.py
# Runs the trained Isolation Forest model to score each per-user-hour feature row.
# Supports two modes:
#   - Normal mode  : uses the model's built-in contamination threshold (predict == -1)
#   - Score mode   : flags the bottom `score_percentile`% by anomaly_score
#                    (better for small test datasets like r4.2-1)

import joblib
import numpy as np
import pandas as pd

# Must stay in sync with analysis_agent.py FEATURE_COLS and models/train_model.py
FEATURE_COLS = [
    "hour",
    "day_of_week",
    "is_after_hours",
    "logon_count",
    "logoff_count",
    "usb_connect",
    "usb_disconnect",
    "file_count",
    "http_count",
    "email_count",
    "email_size_total",
    "email_attachments_total",
]


class DetectionAgent:
    def __init__(
        self,
        model_path: str = "models/isolation_forest.pkl",
        score_percentile: float | None = None,
    ):
        """
        Args:
            model_path       : path to the saved Isolation Forest .pkl file.
            score_percentile : if set (e.g. 20.0), flag the bottom N% of rows by
                               anomaly_score instead of using the model threshold.
                               Useful when evaluating on a small test set.
        """
        self.model_path       = model_path
        self.score_percentile = score_percentile
        self.model            = None

    def load_model(self):
        self.model = joblib.load(self.model_path)
        print(f"[DetectionAgent] Model loaded from {self.model_path}")

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        if self.model is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        X = df[FEATURE_COLS].fillna(0)
        df = df.copy()
        df["anomaly_score"] = self.model.decision_function(X)  # lower = more anomalous

        if self.score_percentile is not None:
            # Flag the bottom N% by score (relative ranking, dataset-size independent)
            threshold = np.percentile(df["anomaly_score"], self.score_percentile)
            df["is_anomaly"] = df["anomaly_score"] <= threshold
            print(
                f"[DetectionAgent] Score-percentile mode: flagging bottom "
                f"{self.score_percentile}% (threshold={threshold:.4f})"
            )
        else:
            # Standard mode: use the model's contamination threshold
            df["is_anomaly"] = self.model.predict(X) == -1

        return df

    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        self.load_model()
        result = self.predict(df)
        anomalies = int(result["is_anomaly"].sum())
        print(f"[DetectionAgent] {anomalies:,} anomalies flagged out of {len(result):,} records.")
        return result


if __name__ == "__main__":
    print("[DetectionAgent] Run via pipeline.py")
