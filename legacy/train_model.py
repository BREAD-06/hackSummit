# train_model.py
# Trains an Isolation Forest on aggregated CERT r4.2 features and saves the model.

import os
import sys
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

# Allow running from the project root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.monitoring_agent import MonitoringAgent
from agents.analysis_agent import AnalysisAgent, FEATURE_COLS

MODEL_PATH  = "models/isolation_forest.pkl"
DATA_DIR    = "data/cert_r4.2"


def build_features(data_dir: str = DATA_DIR) -> pd.DataFrame:
    """Load CERT CSVs and produce the feature table."""
    raw     = MonitoringAgent(data_dir=data_dir).run()
    features = AnalysisAgent().run(raw)
    return features


def train(df: pd.DataFrame, contamination: float = 0.05) -> IsolationForest:
    X = df[FEATURE_COLS].fillna(0)
    print(f"[train_model] Training on {len(X):,} samples × {len(FEATURE_COLS)} features …")
    model = IsolationForest(
        n_estimators=300,
        contamination=contamination,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)
    return model


def main():
    os.makedirs("models", exist_ok=True)
    df = build_features()
    model = train(df)
    joblib.dump(model, MODEL_PATH)
    print(f"[train_model] Model saved to '{MODEL_PATH}'.")

    # Quick sanity check
    from sklearn.ensemble import IsolationForest as IF
    X = df[FEATURE_COLS].fillna(0)
    preds = model.predict(X)
    n_anomalies = int((preds == -1).sum())
    pct = n_anomalies / len(preds) * 100
    print(f"[train_model] Flagged {n_anomalies:,} anomalies ({pct:.2f}%) on training set.")


if __name__ == "__main__":
    main()
