# pipeline.py
# Orchestrates all agents in sequence: Monitor → Analyse → Detect → Verify → Respond → Learn

from agents.monitoring_agent import MonitoringAgent
from agents.analysis_agent import AnalysisAgent
from agents.detection_agent import DetectionAgent
from agents.verification_agent import VerificationAgent
from agents.response_agent import ResponseAgent
from agents.learning_agent import LearningAgent


def run_pipeline(
    data_dir: str = "data/r4.2-1",
    model_path: str = "models/isolation_forest.pkl",
    score_percentile: float | None = 20.0,
    retrain: bool = False,
) -> dict:
    print("\n=== Insider Threat AI Pipeline (CERT r4.2) ===\n")

    # 1. Load all 5 CERT CSV files
    monitor = MonitoringAgent(data_dir=data_dir)
    raw_df = monitor.run()

    # 2. Feature-engineer into per-user-hour table
    analyser = AnalysisAgent()
    df_features = analyser.run(raw_df)

    # 3. Detect anomalies with Isolation Forest
    detector = DetectionAgent(model_path=model_path, score_percentile=score_percentile)
    df_scored = detector.run(df_features)

    # 4. Verify flagged rows with rule-based checks
    verifier = VerificationAgent()
    df_verified = verifier.run(df_scored)

    # 5. Respond to confirmed threats
    responder = ResponseAgent()
    responder.run(df_verified)

    # 6. Optionally retrain model on new data
    if retrain:
        learner = LearningAgent(model_path=model_path)
        learner.run(df_features)

    confirmed = int(df_verified["confirmed_threat"].sum()) if "confirmed_threat" in df_verified.columns else 0

    summary = {
        "total":       len(df_features),
        "anomalies":   int(df_scored["is_anomaly"].sum()),
        "confirmed":   confirmed,
        "verified_df": df_verified,
    }

    print("\n=== Pipeline Complete ===")
    print(f"  Feature rows     : {summary['total']:,}")
    print(f"  Anomalies found  : {summary['anomalies']:,}")
    print(f"  Confirmed threats: {summary['confirmed']:,}")
    return summary


if __name__ == "__main__":
    run_pipeline()
