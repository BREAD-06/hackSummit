# test_model.py
# Evaluates the trained Isolation Forest on the r4.2-1 test dataset.
# Prints a detailed per-user threat report and saves results to data/test_results.csv

import os
import sys
import pandas as pd

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.monitoring_agent import MonitoringAgent
from agents.analysis_agent   import AnalysisAgent, FEATURE_COLS
from agents.detection_agent  import DetectionAgent
from agents.verification_agent import VerificationAgent

TEST_DATA_DIR = "data/r4.2-1"
MODEL_PATH    = "models/isolation_forest.pkl"
OUTPUT_CSV    = "data/test_results.csv"


def run_test(data_dir: str = TEST_DATA_DIR, model_path: str = MODEL_PATH) -> pd.DataFrame:
    print("\n" + "=" * 60)
    print("  Insider Threat AI — Model Evaluation on r4.2-1")
    print("=" * 60 + "\n")

    # 1. Load test data
    raw_df = MonitoringAgent(data_dir=data_dir).run()

    # 2. Feature engineering (same pipeline as training)
    df_features = AnalysisAgent().run(raw_df)

    # 3. Run the trained model (inference only — no retraining)
    # Use score_percentile=20: flag the bottom 20% most anomalous user-hour rows.
    # This is appropriate for r4.2-1 which is a curated set of known insider threat cases —
    # the global contamination threshold from training on 64K rows doesn't apply to this small set.
    df_scored = DetectionAgent(model_path=model_path, score_percentile=20).run(df_features)

    # 4. Rule-based verification
    df_verified = VerificationAgent().run(df_scored)

    # ── Summary ───────────────────────────────────────────────────────────────
    total        = len(df_features)
    n_anomalies  = int(df_scored["is_anomaly"].sum())
    n_confirmed  = int(df_verified["confirmed_threat"].sum()) if "confirmed_threat" in df_verified.columns else 0

    print("\n" + "-" * 60)
    print(f"  Total feature rows (user x hour) : {total:,}")
    print(f"  Anomalies flagged by model        : {n_anomalies:,}  ({n_anomalies/total*100:.1f}%)")
    print(f"  Confirmed threats (rule-verified) : {n_confirmed:,}  ({n_confirmed/total*100:.1f}%)")
    print("-" * 60)

    # ── Per-user threat breakdown ─────────────────────────────────────────────
    if not df_verified.empty and "user" in df_verified.columns:
        print("\n  High-Risk Users (confirmed threats):\n")
        user_summary = (
            df_verified[df_verified["confirmed_threat"]]
            .groupby("user")
            .agg(
                threat_hours   = ("confirmed_threat", "sum"),
                avg_anomaly_score = ("anomaly_score", "mean"),
                after_hours_hits  = ("is_after_hours", "sum"),
                usb_events        = ("usb_connect", "sum"),
                file_ops          = ("file_count", "sum"),
                emails_sent       = ("email_count", "sum"),
                http_requests     = ("http_count", "sum"),
            )
            .sort_values("threat_hours", ascending=False)
            .reset_index()
        )

        if user_summary.empty:
            print("  No confirmed threats found in the test dataset.")
        else:
            pd.set_option("display.max_columns", None)
            pd.set_option("display.width", 120)
            print(user_summary.to_string(index=False))

    # ── Save results ──────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    df_verified.to_csv(OUTPUT_CSV, index=False)
    print(f"\n  Full results saved to: {OUTPUT_CSV}\n")

    return df_verified


if __name__ == "__main__":
    run_test()
