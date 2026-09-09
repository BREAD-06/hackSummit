# analysis_agent.py
# Feature-engineers the raw merged CERT r4.2 DataFrame into a per-user-hour feature table
# suitable for Isolation Forest anomaly detection.

import pandas as pd


# Features produced by this agent — must stay in sync with detection_agent.py FEATURE_COLS
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


class AnalysisAgent:
    def __init__(self):
        pass

    # ------------------------------------------------------------------
    # Private helpers — one per log type
    # ------------------------------------------------------------------

    def _logon_features(self, df: pd.DataFrame) -> pd.DataFrame:
        sub = df[df["log_type"] == "logon"].copy()
        sub["logon_count"]  = (sub["activity"] == "Logon").astype(int)
        sub["logoff_count"] = (sub["activity"] == "Logoff").astype(int)
        return sub[["user", "hour", "day_of_week", "logon_count", "logoff_count"]]

    def _device_features(self, df: pd.DataFrame) -> pd.DataFrame:
        sub = df[df["log_type"] == "device"].copy()
        sub["usb_connect"]    = (sub["activity"] == "Connect").astype(int)
        sub["usb_disconnect"] = (sub["activity"] == "Disconnect").astype(int)
        return sub[["user", "hour", "day_of_week", "usb_connect", "usb_disconnect"]]

    def _file_features(self, df: pd.DataFrame) -> pd.DataFrame:
        sub = df[df["log_type"] == "file"].copy()
        sub["file_count"] = 1
        return sub[["user", "hour", "day_of_week", "file_count"]]

    def _http_features(self, df: pd.DataFrame) -> pd.DataFrame:
        sub = df[df["log_type"] == "http"].copy()
        sub["http_count"] = 1
        return sub[["user", "hour", "day_of_week", "http_count"]]

    def _email_features(self, df: pd.DataFrame) -> pd.DataFrame:
        sub = df[df["log_type"] == "email"].copy()
        sub["email_count"]            = 1
        sub["email_size_total"]       = pd.to_numeric(sub["size"], errors="coerce").fillna(0)
        sub["email_attachments_total"] = pd.to_numeric(sub["attachments"], errors="coerce").fillna(0)
        return sub[["user", "hour", "day_of_week", "email_count", "email_size_total", "email_attachments_total"]]

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def preprocess(self, raw_df: pd.DataFrame) -> pd.DataFrame:
        """
        Takes the raw merged DataFrame from MonitoringAgent.
        Returns a per-user-hour aggregated feature table.
        """
        df = raw_df.copy()

        # Parse dates if not already datetime
        if not pd.api.types.is_datetime64_any_dtype(df["date"]):
            df["date"] = pd.to_datetime(df["date"], dayfirst=False)

        df["hour"]        = df["date"].dt.hour
        df["day_of_week"] = df["date"].dt.dayofweek  # 0=Monday … 6=Sunday

        # Build partial feature frames per log type
        parts = [
            self._logon_features(df),
            self._device_features(df),
            self._file_features(df),
            self._http_features(df),
            self._email_features(df),
        ]

        # Merge all parts on [user, hour, day_of_week] via outer join then aggregate
        combined = pd.concat(parts, ignore_index=True, sort=False)
        agg_cols = [c for c in FEATURE_COLS if c not in ("hour", "day_of_week", "is_after_hours")]
        features = (
            combined
            .groupby(["user", "hour", "day_of_week"])[agg_cols]
            .sum()
            .reset_index()
        )

        # Derived flag
        features["is_after_hours"] = (
            (features["hour"] < 7) | (features["hour"] > 20)
        ).astype(int)

        # Ensure all feature columns exist (fill with 0 if a log type had no data)
        for col in FEATURE_COLS:
            if col not in features.columns:
                features[col] = 0

        features = features.fillna(0)
        return features

    def run(self, raw_df: pd.DataFrame) -> pd.DataFrame:
        features = self.preprocess(raw_df)
        print(
            f"[AnalysisAgent] Feature table: {len(features):,} rows × {features.shape[1]} columns "
            f"| {features['user'].nunique():,} unique users"
        )
        return features


if __name__ == "__main__":
    from agents.monitoring_agent import MonitoringAgent
    raw = MonitoringAgent().run()
    agent = AnalysisAgent()
    df = agent.run(raw)
    print(df.head())
