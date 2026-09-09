# verification_agent.py
# Cross-validates flagged anomalies using rule-based heuristics on real CERT r4.2 features.

import pandas as pd


# Rules are callables that take a Series row and return True if the rule fires.
RULES = {
    # Activity outside of normal business hours (before 7am or after 8pm)
    "after_hours": lambda row: bool(row.get("is_after_hours", 0)),

    # Any USB device connected in this user-hour window
    "usb_activity": lambda row: row.get("usb_connect", 0) > 0,

    # Unusually high file access volume (top indicator of data staging)
    "high_file_volume": lambda row: row.get("file_count", 0) > 50,

    # Sending many emails in a single hour (possible exfiltration via email)
    "mass_email": lambda row: row.get("email_count", 0) > 20,

    # Large email size total in one hour (attachments / bulk data)
    "large_email_size": lambda row: row.get("email_size_total", 0) > 5_000_000,

    # Unusual browsing volume
    "excessive_browsing": lambda row: row.get("http_count", 0) > 100,
}


class VerificationAgent:
    def __init__(self, rules: dict | None = None):
        self.rules = rules or RULES

    def verify(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply rules only to rows already flagged as anomalies."""
        flagged = df[df["is_anomaly"]].copy()
        if flagged.empty:
            flagged["confirmed_threat"] = pd.Series(dtype=bool)
            return flagged

        for rule_name, rule_fn in self.rules.items():
            flagged[f"rule_{rule_name}"] = flagged.apply(rule_fn, axis=1)

        rule_cols = [c for c in flagged.columns if c.startswith("rule_")]
        flagged["confirmed_threat"] = flagged[rule_cols].any(axis=1)
        return flagged

    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        result = self.verify(df)
        confirmed = int(result["confirmed_threat"].sum()) if "confirmed_threat" in result.columns else 0
        print(f"[VerificationAgent] {confirmed:,} confirmed threats after rule checks.")
        return result


if __name__ == "__main__":
    print("[VerificationAgent] Run via pipeline.py")
