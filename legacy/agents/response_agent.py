# Triggers automated responses (alerts, account locks, notifications) for confirmed threats.

import json
import pandas as pd
from datetime import datetime


class ResponseAgent:
    def __init__(self, alert_log: str = "data/alerts.jsonl"):
        self.alert_log = alert_log

    @staticmethod
    def _json_default(obj):
        """Convert non-serializable types (Timestamp, numpy scalars, etc.) to JSON-safe values."""
        import pandas as pd
        import numpy as np
        if isinstance(obj, (pd.Timestamp,)):
            return obj.isoformat()
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        if isinstance(obj, (np.bool_,)):
            return bool(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def _write_alert(self, record: dict):
        record["alerted_at"] = datetime.utcnow().isoformat()
        with open(self.alert_log, "a") as f:
            f.write(json.dumps(record, default=self._json_default) + "\n")

    def respond(self, df: pd.DataFrame):
        if "confirmed_threat" not in df.columns:
            return
        threats = df[df["confirmed_threat"]]
        for _, row in threats.iterrows():
            alert = row.to_dict()
            self._write_alert(alert)
            user = alert.get("user", "unknown")
            print(f"[ResponseAgent] ALERT — Suspicious activity by '{user}'. Alert logged.")

    def run(self, df: pd.DataFrame):
        self.respond(df)
        print(f"[ResponseAgent] Response cycle complete.")


if __name__ == "__main__":
    print("[ResponseAgent] Run via pipeline.py")
