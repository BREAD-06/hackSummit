# main.py  ─  FastAPI backend for Insider Threat AI
# React-ready: CORS enabled, all responses are JSON, state cached in-memory.
# Run from project root:  python -m uvicorn api.main:app --reload --port 8000

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pipeline import run_pipeline

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Insider Threat AI API",
    version="2.0.0",
    description="REST API for the Insider Threat AI detection system. "
                "All endpoints return JSON — React-ready.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5174", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Dataset registry ──────────────────────────────────────────────────────────
DATASETS: dict = {
    "cert_r42_1": {
        "name": "CERT r4.2-1 — Known Insider Cases",
        "data_dir": "data/r4.2-1",
        "score_percentile": 20.0,
        "description": "30 real insider threat cases from the CERT r4.2 benchmark dataset.",
        "type": "real",
    },
    "exfiltration": {
        "name": "Data Exfiltration Scenario",
        "data_dir": "data/test_scenarios/exfiltration",
        "score_percentile": 20.0,
        "description": "Synthetic: after-hours USB activity, mass file access, suspicious URLs.",
        "type": "synthetic",
    },
    "email_leak": {
        "name": "Email Leak Scenario",
        "data_dir": "data/test_scenarios/email_leak",
        "score_percentile": 20.0,
        "description": "Synthetic: mass emails with large attachments during off-hours.",
        "type": "synthetic",
    },
    "normal": {
        "name": "Normal Behavior Baseline",
        "data_dir": "data/test_scenarios/normal",
        "score_percentile": 20.0,
        "description": "Synthetic: 10 normal employees — model should NOT over-flag these.",
        "type": "synthetic",
    },
}

# ── In-memory result cache ─────────────────────────────────────────────────────
_cache: dict = {}


def _to_python(obj):
    """Recursively convert numpy scalars/bools to Python native types."""
    if isinstance(obj, dict):
        return {k: _to_python(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_python(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    return obj


def _require_cache():
    if "last_run" not in _cache:
        raise HTTPException(
            status_code=404,
            detail="No pipeline results found. Call POST /api/pipeline/run first.",
        )
    return _cache["last_run"]


# ── Request models ─────────────────────────────────────────────────────────────
class RunRequest(BaseModel):
    dataset_id: str = "cert_r42_1"
    model_path: str = "models/isolation_forest.pkl"
    retrain: bool = False


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["System"])
def health():
    """Health check — always returns 200 OK."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/datasets", tags=["Datasets"])
def list_datasets():
    """List all registered datasets and whether their data directory exists."""
    result = []
    for key, info in DATASETS.items():
        result.append({
            "id": key,
            "name": info["name"],
            "description": info["description"],
            "type": info["type"],
            "data_dir": info["data_dir"],
            "available": os.path.exists(info["data_dir"]),
        })
    return {"datasets": result}


@app.get("/api/model/info", tags=["Model"])
def model_info(model_path: str = "models/isolation_forest.pkl"):
    """Return metadata about the loaded Isolation Forest model."""
    if not os.path.exists(model_path):
        raise HTTPException(status_code=404, detail=f"Model not found: {model_path}")
    import joblib
    model = joblib.load(model_path)
    return {
        "model_path": model_path,
        "type": "IsolationForest",
        "n_estimators": int(model.n_estimators),
        "contamination": float(model.contamination) if isinstance(model.contamination, float) else str(model.contamination),
        "max_samples": str(model.max_samples),
        "n_features": int(model.n_features_in_),
        "trained": True,
    }


@app.post("/api/pipeline/run", tags=["Pipeline"])
def pipeline_run(req: RunRequest):
    """
    Run the full detection pipeline on a dataset.
    Results are cached and available via /api/results/* endpoints.
    """
    if req.dataset_id not in DATASETS:
        raise HTTPException(status_code=400, detail=f"Unknown dataset_id '{req.dataset_id}'. "
                            f"Valid options: {list(DATASETS.keys())}")

    ds = DATASETS[req.dataset_id]
    if not os.path.exists(ds["data_dir"]):
        raise HTTPException(status_code=404,
                            detail=f"Dataset directory not found: {ds['data_dir']}. "
                                   "Run generate_test_data.py to create synthetic datasets.")

    try:
        result = run_pipeline(
            data_dir=ds["data_dir"],
            model_path=req.model_path,
            score_percentile=ds["score_percentile"],
            retrain=req.retrain,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    df = result["verified_df"]
    threats_raw = df.to_dict(orient="records") if not df.empty else []
    threats_clean = [_to_python(t) for t in threats_raw]

    _cache["last_run"] = {
        "dataset_id": req.dataset_id,
        "dataset_name": ds["name"],
        "run_at": datetime.utcnow().isoformat(),
        "total": result["total"],
        "anomalies": result["anomalies"],
        "confirmed": result["confirmed"],
        "threats": threats_clean,
    }

    return {
        "success": True,
        "dataset": ds["name"],
        "run_at": _cache["last_run"]["run_at"],
        "total": result["total"],
        "anomalies": result["anomalies"],
        "confirmed": result["confirmed"],
    }


@app.get("/api/results/summary", tags=["Results"])
def results_summary():
    """KPI summary of the latest pipeline run."""
    r = _require_cache()
    return {
        "dataset": r["dataset_name"],
        "run_at": r["run_at"],
        "total": r["total"],
        "anomalies": r["anomalies"],
        "confirmed": r["confirmed"],
        "anomaly_rate_pct": round(r["anomalies"] / max(r["total"], 1) * 100, 2),
        "confirmation_rate_pct": round(r["confirmed"] / max(r["anomalies"], 1) * 100, 2),
    }


@app.get("/api/results/threats", tags=["Results"])
def results_threats(confirmed_only: bool = True):
    """Individual threat records. Pass confirmed_only=false for all anomalies."""
    r = _require_cache()
    data = r["threats"]
    if confirmed_only:
        data = [t for t in data if t.get("confirmed_threat", False)]
    return {"count": len(data), "threats": data}


@app.get("/api/results/users", tags=["Results"])
def results_users():
    """Per-user aggregated threat statistics, sorted by anomaly score (most suspicious first)."""
    r = _require_cache()
    confirmed = [t for t in r["threats"] if t.get("confirmed_threat", False)]

    user_map: dict = {}
    for t in confirmed:
        u = t.get("user", "unknown")
        if u not in user_map:
            user_map[u] = {
                "user": u,
                "threat_windows": 0,
                "min_anomaly_score": 9999.0,
                "after_hours_hits": 0,
                "usb_events": 0,
                "file_ops": 0,
                "emails_sent": 0,
                "http_requests": 0,
                "active_rules": set(),
            }
        m = user_map[u]
        m["threat_windows"] += 1
        m["min_anomaly_score"] = min(m["min_anomaly_score"], float(t.get("anomaly_score", 0)))
        m["after_hours_hits"] += int(t.get("is_after_hours", 0))
        m["usb_events"]       += int(t.get("usb_connect", 0))
        m["file_ops"]         += int(t.get("file_count", 0))
        m["emails_sent"]      += int(t.get("email_count", 0))
        m["http_requests"]    += int(t.get("http_count", 0))
        fired = [k.replace("rule_", "") for k, v in t.items() if k.startswith("rule_") and v]
        m["active_rules"].update(fired)

    users = []
    for m in user_map.values():
        m["active_rules"] = sorted(m["active_rules"])
        users.append(m)

    users.sort(key=lambda x: x["min_anomaly_score"])
    return {"count": len(users), "users": users}


@app.get("/api/results/timeline", tags=["Results"])
def results_timeline():
    """Hourly breakdown of confirmed threat events (for charting)."""
    r = _require_cache()
    confirmed = [t for t in r["threats"] if t.get("confirmed_threat", False)]
    hourly = {h: 0 for h in range(24)}
    for t in confirmed:
        h = int(t.get("hour", 0))
        hourly[h] = hourly.get(h, 0) + 1
    return {"timeline": [{"hour": h, "count": hourly[h]} for h in range(24)]}


@app.get("/api/results/scores", tags=["Results"])
def results_scores():
    """Anomaly score distribution for all flagged rows (for histogram charting)."""
    r = _require_cache()
    data = [
        {
            "anomaly_score": float(t.get("anomaly_score", 0)),
            "confirmed": bool(t.get("confirmed_threat", False)),
            "user": t.get("user", ""),
        }
        for t in r["threats"]
    ]
    return {"count": len(data), "scores": data}


# ── Dev entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    # Run from project root: python api/main.py
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
