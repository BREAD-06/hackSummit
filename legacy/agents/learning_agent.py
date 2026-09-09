# learning_agent.py
# Periodically retrains the model with the latest aggregated feature data.

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from agents.analysis_agent import FEATURE_COLS


class LearningAgent:
    def __init__(
        self,
        model_path: str = "models/isolation_forest.pkl",
        contamination: float = 0.05,
    ):
        self.model_path    = model_path
        self.contamination = contamination

    def retrain(self, df: pd.DataFrame) -> IsolationForest:
        X = df[FEATURE_COLS].fillna(0)
        model = IsolationForest(
            n_estimators=300,
            contamination=self.contamination,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X)
        joblib.dump(model, self.model_path)
        print(f"[LearningAgent] Model retrained on {len(X):,} samples and saved to {self.model_path}.")
        return model

    def run(self, df: pd.DataFrame):
        return self.retrain(df)


if __name__ == "__main__":
    print("[LearningAgent] Run via pipeline.py")
