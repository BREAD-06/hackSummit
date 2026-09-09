# monitoring_agent.py
# Loads CERT log data and returns a single merged DataFrame.
# Supports two dataset formats:
#   - r4.2  : one CSV per log type (logon.csv, device.csv, etc.) WITH a header row
#   - r4.2-1: one CSV per user (r4.2-1-USER.csv), NO header, all log types mixed

import os
import glob
import pandas as pd


# ── r4.2 format (original training data) ──────────────────────────────────────
CERT_FILES = {
    "logon":  {"file": "logon.csv",  "cols": ["date", "user", "pc", "activity"]},
    "device": {"file": "device.csv", "cols": ["date", "user", "pc", "activity"]},
    "file":   {"file": "file.csv",   "cols": ["date", "user", "pc"]},
    "http":   {"file": "http.csv",   "cols": ["date", "user", "pc"]},
    "email":  {"file": "email.csv",  "cols": ["date", "user", "pc", "size", "attachments"]},
}

CHUNK_SIZE = 200_000

# ── r4.2-1 format column layout ───────────────────────────────────────────────
# Each row: log_type, id, date, user, pc, [field5], [field6]
R421_COLS = ["log_type", "id", "date", "user", "pc", "field5", "field6"]


def _detect_format(data_dir: str) -> str:
    """Return 'r4.2' if standard per-type CSVs exist, else 'r4.2-1'."""
    if os.path.exists(os.path.join(data_dir, "logon.csv")):
        return "r4.2"
    per_user = glob.glob(os.path.join(data_dir, "*.csv"))
    if per_user:
        return "r4.2-1"
    return "unknown"


class MonitoringAgent:
    def __init__(self, data_dir: str = "data/cert_r4.2"):
        self.data_dir = data_dir

    # ── r4.2 loader (original format) ─────────────────────────────────────────

    def _load_r42_file(self, name: str, spec: dict) -> pd.DataFrame:
        path = os.path.join(self.data_dir, spec["file"])
        if not os.path.exists(path):
            print(f"[MonitoringAgent] WARNING: {path} not found — skipping.")
            return pd.DataFrame()
        cols = spec["cols"]
        frames = []
        try:
            for chunk in pd.read_csv(path, usecols=cols, chunksize=CHUNK_SIZE, low_memory=False):
                frames.append(chunk)
        except Exception as e:
            print(f"[MonitoringAgent] ERROR reading {spec['file']}: {e}")
            return pd.DataFrame()
        df = pd.concat(frames, ignore_index=True)
        df["log_type"] = name
        return df

    def _load_r42(self) -> pd.DataFrame:
        frames = []
        for name, spec in CERT_FILES.items():
            df = self._load_r42_file(name, spec)
            if not df.empty:
                frames.append(df)
                print(f"[MonitoringAgent]  {spec['file']:<12} -> {len(df):>10,} rows")
        if not frames:
            raise FileNotFoundError(
                f"No CERT CSV files found in '{self.data_dir}'. "
                "Please extract the r4.2 dataset there."
            )
        return pd.concat(frames, ignore_index=True, sort=False)

    # ── r4.2-1 loader (per-user format) ───────────────────────────────────────

    def _load_r421_file(self, path: str) -> pd.DataFrame:
        """Parse a single per-user r4.2-1 CSV (no header, variable columns)."""
        try:
            # Read up to 7 columns; rows with fewer cols get NaN padding
            df = pd.read_csv(
                path,
                header=None,
                names=R421_COLS,
                on_bad_lines="skip",
                low_memory=False,
            )
        except Exception as e:
            print(f"[MonitoringAgent] ERROR reading {os.path.basename(path)}: {e}")
            return pd.DataFrame()

        # Normalise log_type to lowercase so matching works downstream
        df["log_type"] = df["log_type"].str.strip().str.lower()

        # Map r4.2-1 columns -> standard schema expected by AnalysisAgent
        # activity comes from field5 for logon/device; emails have size/attachments in field5/field6
        df["activity"]    = df["field5"]
        df["size"]        = pd.to_numeric(df["field5"], errors="coerce")   # email only
        df["attachments"] = pd.to_numeric(df["field6"], errors="coerce")   # email only

        return df[["log_type", "date", "user", "pc", "activity", "size", "attachments"]]

    def _load_r421(self) -> pd.DataFrame:
        csv_files = sorted(glob.glob(os.path.join(self.data_dir, "*.csv")))
        if not csv_files:
            raise FileNotFoundError(
                f"No CSV files found in '{self.data_dir}'. "
                "Please extract the r4.2-1 dataset there."
            )
        frames = []
        for path in csv_files:
            df = self._load_r421_file(path)
            if not df.empty:
                frames.append(df)

        if not frames:
            raise FileNotFoundError(f"All CSVs in '{self.data_dir}' were empty or unreadable.")

        combined = pd.concat(frames, ignore_index=True, sort=False)
        print(f"[MonitoringAgent]  Loaded {len(csv_files)} per-user files -> {len(combined):,} total rows")

        # Show breakdown by log type
        for lt, cnt in combined["log_type"].value_counts().items():
            print(f"[MonitoringAgent]    {lt:<10} : {cnt:>8,} rows")
        return combined

    # ── Public interface ───────────────────────────────────────────────────────

    def collect_logs(self) -> pd.DataFrame:
        fmt = _detect_format(self.data_dir)
        print(f"[MonitoringAgent] Detected dataset format: {fmt}")
        if fmt == "r4.2":
            return self._load_r42()
        elif fmt == "r4.2-1":
            return self._load_r421()
        else:
            raise FileNotFoundError(
                f"No recognised CERT dataset found in '{self.data_dir}'. "
                "Expected either logon.csv (r4.2) or per-user *.csv files (r4.2-1)."
            )

    def run(self) -> pd.DataFrame:
        print(f"[MonitoringAgent] Loading logs from '{self.data_dir}' ...")
        df = self.collect_logs()
        print(f"[MonitoringAgent] Total raw records loaded: {len(df):,}")
        return df


if __name__ == "__main__":
    agent = MonitoringAgent("data/r4.2-1")
    df = agent.run()
    print(df["log_type"].value_counts())
