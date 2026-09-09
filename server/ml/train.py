"""Train the live Isolation Forest anomaly model.

The default source is **synthetic** — a large corpus of benign 9-to-5 behaviour
from :mod:`tools.synth` — so a usable model always exists with zero downloads and
the server runs out of the box. ``--source cert`` additionally folds in the real
CERT r4.2 ``logon``/``device``/``file`` logs if you have extracted them locally
(slower: every row is turned into a real :class:`~vigil.schema.Event`).

Run from the repo root::

    python -m server.ml.train
    python -m server.ml.train --source both --cert-dir data/cert_r4.2

Both sources are aggregated through the *same* :mod:`vigil.features` code the
live server uses, so the model can never see features shaped differently at
training time than at inference time.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import timezone

import numpy as np

# Allow `python server/ml/train.py` as well as `python -m server.ml.train`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server.ml.model import DEFAULT_MODEL_PATH, DetectionModel  # noqa: E402
from vigil import features, schema  # noqa: E402
from vigil.console import enable_utf8  # noqa: E402
from vigil.features import LIVE_FEATURE_COLS, RollingFeatureStore  # noqa: E402
from vigil.schema import Event  # noqa: E402

# CERT r4.2 files we can map onto the live feature set. http/email are ignored on
# purpose: the endpoint agent does not collect them, so training on them would
# create features the live pipeline can never produce.
_CERT_SPECS = {
    schema.LOG_LOGON: ("logon.csv", ["date", "user", "pc", "activity"]),
    schema.LOG_DEVICE: ("device.csv", ["date", "user", "pc", "activity"]),
    schema.LOG_FILE: ("file.csv", ["date", "user", "pc"]),
}


def _windows_to_frame(windows):
    """Turn behaviour windows into a feature DataFrame (same columns as training)."""
    import pandas as pd

    rows = []
    for w in windows:
        row = {"agent_id": w.agent_id, "user": w.user, "host": w.host, "window_start": w.window_start}
        row.update(w.feature_dict())
        rows.append(row)
    if not rows:
        return pd.DataFrame(columns=["agent_id", "user", "host", "window_start", *LIVE_FEATURE_COLS])
    return pd.DataFrame(rows)[["agent_id", "user", "host", "window_start", *LIVE_FEATURE_COLS]]


def _synthetic_frame(users: int, days: int):
    from tools.synth import normal_events

    events = normal_events(num_users=users, days=days)
    frame = features.aggregate_frame(events)
    print(f"[train] synthetic: {len(events):,} events -> {len(frame):,} windows "
          f"({users} users x {days} days)")
    return frame


def _cert_frame(cert_dir: str):
    """Stream the CERT CSVs into a rolling feature store, chunk by chunk.

    Memory-bounded: each chunk collapses into windows immediately, so only the
    (much smaller) window table is retained.
    """
    import pandas as pd

    if not os.path.isdir(cert_dir):
        print(f"[train] CERT: directory '{cert_dir}' not found — skipping CERT source.")
        return None

    store = RollingFeatureStore()
    total = 0
    for log_type, (fname, cols) in _CERT_SPECS.items():
        path = os.path.join(cert_dir, fname)
        if not os.path.exists(path):
            print(f"[train] CERT: {fname} not found — skipping.")
            continue
        wanted = set(cols)
        rows_here = 0
        for chunk in pd.read_csv(path, usecols=lambda c: c in wanted,
                                chunksize=200_000, low_memory=False):
            ts = pd.to_datetime(chunk["date"], errors="coerce", format="mixed")
            keep = ts.notna()
            ts = ts[keep]
            users = chunk.loc[keep, "user"].astype(str)
            hosts = chunk.loc[keep, "pc"].astype(str)
            if "activity" in chunk.columns:
                acts = chunk.loc[keep, "activity"].astype(str)
            else:
                acts = pd.Series([""] * len(ts), index=ts.index)

            evs = [
                Event.model_construct(
                    event_id="", ts=t.to_pydatetime().replace(tzinfo=timezone.utc),
                    agent_id="CERT", host=h, user=u, log_type=log_type,
                    action=a, path=None, size_bytes=0, detail={},
                )
                for t, u, h, a in zip(ts, users, hosts, acts)
            ]
            store.update(evs)
            rows_here += len(evs)
        print(f"[train] CERT: {fname} -> {rows_here:,} events")
        total += rows_here

    if total == 0:
        return None
    frame = _windows_to_frame(store.all_windows())
    print(f"[train] CERT: {total:,} events -> {len(frame):,} windows")
    return frame


def train(source: str = "synthetic", cert_dir: str = "data/cert_r4.2",
          out: str = DEFAULT_MODEL_PATH, contamination: float = 0.02,
          n_estimators: int = 200, users: int = 40, days: int = 30,
          check: bool = True) -> DetectionModel:
    import pandas as pd
    from sklearn.ensemble import IsolationForest

    frames = []
    if source in ("synthetic", "both"):
        frames.append(_synthetic_frame(users, days))
    if source in ("cert", "both"):
        frames.append(_cert_frame(cert_dir))
    frames = [f for f in frames if f is not None and len(f) > 0]
    if not frames:
        raise SystemExit("[train] No training data produced. Check --source / --cert-dir.")

    df = pd.concat([f[LIVE_FEATURE_COLS] for f in frames], ignore_index=True)
    X = df[LIVE_FEATURE_COLS].fillna(0).to_numpy(dtype=float)
    print(f"[train] fitting IsolationForest on {len(X):,} windows x {len(LIVE_FEATURE_COLS)} features")

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)

    # Calibrate the decision threshold on the training distribution itself, so
    # "anomalous" means "in the bottom `contamination` fraction of normal".
    scores = model.decision_function(X)
    threshold = float(np.percentile(scores, contamination * 100.0))
    n_flagged = int((scores < threshold).sum())
    print(f"[train] threshold={threshold:.5f} -> flags {n_flagged:,}/{len(X):,} training windows "
          f"({n_flagged / len(X) * 100:.2f}%)")

    dm = DetectionModel(
        model=model,
        feature_cols=list(LIVE_FEATURE_COLS),
        threshold=threshold,
        meta={
            "source": source,
            "n_train_windows": int(len(X)),
            "contamination": float(contamination),
            "n_estimators": int(n_estimators),
        },
    )
    dm.save(out)
    print(f"[train] saved model -> {out}")
    if check:
        sanity_check(dm)
    return dm


def _worst_window(dm: DetectionModel, events) -> tuple[float, bool]:
    """Score every window the events touch and return the most anomalous result."""
    store = RollingFeatureStore()
    store.update(events)
    return min((dm.score_window(w) for w in store.all_windows()), key=lambda r: r[0])


def sanity_check(dm: DetectionModel) -> dict:
    """Check that the threat scenarios are caught and benign traffic mostly is not."""
    from tools.synth import SCENARIOS, normal_events

    report = {"threshold": dm.threshold, "scenarios": {}}
    for name, factory in SCENARIOS.items():
        score, flagged = _worst_window(dm, factory())
        report["scenarios"][name] = {"score": score, "flagged": flagged}
        print(f"[train] sanity: {name:<13} score={score:+.4f} flagged={flagged} "
              f"(threshold={dm.threshold:+.4f})")

    # Held-out benign users (different seed) — measures the live false-positive rate.
    holdout = RollingFeatureStore()
    holdout.update(normal_events(num_users=8, days=10, seed=999))
    results = [dm.score_window(w) for w in holdout.all_windows()]
    flagged = sum(1 for _s, f in results if f)
    fpr = flagged / max(len(results), 1)
    report["holdout"] = {"windows": len(results), "flagged": flagged, "fpr": fpr}
    print(f"[train] sanity: held-out benign windows flagged {flagged}/{len(results)} "
          f"({fpr * 100:.2f}% false-positive rate)")

    missed = [n for n, r in report["scenarios"].items() if not r["flagged"]]
    if missed:
        print(f"[train] WARNING: scenario(s) NOT flagged by ML: {', '.join(missed)}. "
              f"The RL verification rules still catch these, but consider raising "
              f"--contamination.")
    return report


def main() -> None:
    enable_utf8()
    ap = argparse.ArgumentParser(description="Train the VIGIL AI Isolation Forest model.")
    ap.add_argument("--source", choices=["synthetic", "cert", "both"], default="synthetic")
    ap.add_argument("--cert-dir", default="data/cert_r4.2")
    ap.add_argument("--out", default=DEFAULT_MODEL_PATH)
    ap.add_argument("--contamination", type=float, default=0.02)
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--users", type=int, default=40, help="synthetic users")
    ap.add_argument("--days", type=int, default=30, help="synthetic days")
    args = ap.parse_args()
    train(source=args.source, cert_dir=args.cert_dir, out=args.out,
          contamination=args.contamination, n_estimators=args.n_estimators,
          users=args.users, days=args.days)


if __name__ == "__main__":
    main()
