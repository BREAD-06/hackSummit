"""VIGIL AI Detection Server — FastAPI assembly and entry point.

Run it::

    python -m server.keygen                        # once: provision PQC keys
    python -m server.ml.train --source synthetic   # once: train the detector
    python -m server.main                          # serve on 0.0.0.0:8000

Everything shared lives on ``app.state`` (config, storage, keys, sessions, model,
pipeline, ws), so routes stay thin and tests can build an app against a temporary
database with :func:`create_app`.

If a built React dashboard is present in ``frontend/dist``, it is served at ``/``;
otherwise ``/`` returns a short JSON pointer to the API. The server is useful
either way — the dashboard is a client, not a dependency.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from server.api.agent_routes import router as agent_router
from server.api.soc_routes import router as soc_router
from server.api.ws import ConnectionManager
from server.config import ServerConfig
from server.db.sqlite_store import SQLiteStorage
from server.keygen import keys_exist, load_keys
from server.ml.model import DetectionModel
from server.pipeline import Pipeline
from server.session import SessionRegistry
from vigil.console import enable_utf8
from vigil.pqc import aead, kem, sig

VERSION = "1.0.0"

log = logging.getLogger("vigil.server")


def frontend_dist() -> str | None:
    """Locate the built dashboard, or ``None`` if it has not been built.

    Resolved against the *installation* first and the working directory second,
    because ``python -m server.main`` run from anywhere but the repo root would
    otherwise silently serve the JSON stub instead of the dashboard — a confusing
    failure on a fresh deployment. ``VIGIL_FRONTEND_DIST`` overrides both.
    """
    override = os.environ.get("VIGIL_FRONTEND_DIST")
    candidates = [override] if override else []
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates += [
        os.path.join(repo_root, "frontend", "dist"),
        os.path.abspath(os.path.join("frontend", "dist")),
    ]
    for path in candidates:
        if path and os.path.isdir(path) and os.path.isfile(os.path.join(path, "index.html")):
            return path
    return None


def configure_logging(level: str = "info") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)-18s %(message)s",
        datefmt="%H:%M:%S",
    )


def create_app(config: ServerConfig | None = None, storage=None) -> FastAPI:
    """Build the application. ``storage`` may be injected for tests."""
    cfg = config or ServerConfig.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        log.info("VIGIL AI detection server %s starting", VERSION)
        log.info("PQC channel: %s + %s + %s (%s)",
                 kem.ALGORITHM, sig.ALGORITHM, aead.ALGORITHM, aead.KDF)
        log.info("database=%s  model=%s  keys=%s",
                 cfg.db_path, cfg.model_path, cfg.keys_dir)
        if not cfg.require_enroll_token:
            log.warning("enrollment tokens are DISABLED — any host on the network "
                        "can enroll an agent. Use this for local demos only.")
        yield
        app.state.storage.close()
        log.info("detection server stopped")

    app = FastAPI(
        title="VIGIL AI — Insider Threat Detection Server",
        description=(
            "Real-time insider-threat detection: post-quantum-secured endpoint "
            "telemetry, Isolation Forest anomaly detection, and a Q-learning "
            "verification policy trained by analyst feedback."
        ),
        version=VERSION,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── shared state ──
    store = storage
    if store is None:
        store = SQLiteStorage(cfg.db_path)
        store.init_schema()

    model = DetectionModel.load(cfg.model_path)

    app.state.version = VERSION
    app.state.started_at = datetime.now(timezone.utc)
    app.state.config = cfg
    app.state.storage = store
    app.state.keys = load_keys(cfg)
    app.state.sessions = SessionRegistry()
    app.state.model = model
    app.state.pipeline = Pipeline(store, model, cfg)
    app.state.ws = ConnectionManager()

    app.include_router(agent_router)
    app.include_router(soc_router)

    # ── dashboard (optional) ──
    dist = frontend_dist()
    if dist:
        assets = os.path.join(dist, "assets")
        if os.path.isdir(assets):
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/", include_in_schema=False)
        def dashboard():
            return FileResponse(os.path.join(dist, "index.html"))

        log.info("serving the built dashboard from %s", dist)
    else:
        @app.get("/", include_in_schema=False)
        def index():
            return JSONResponse({
                "name": "VIGIL AI Detection Server",
                "version": VERSION,
                "docs": "/docs",
                "health": "/api/health",
                "dashboard": (
                    "not built — run `npm install && npm run build` in frontend/, "
                    "or `npm run dev` for the live dev server"
                ),
            })

    return app


def main() -> None:
    import argparse

    import uvicorn

    enable_utf8()
    ap = argparse.ArgumentParser(description="Run the VIGIL AI detection server.")
    ap.add_argument("--config", default=None, help="path to server_config.yaml")
    ap.add_argument("--host", default=None, help="override the bind address")
    ap.add_argument("--port", type=int, default=None, help="override the port")
    ap.add_argument("--reload", action="store_true", help="auto-reload (development)")
    args = ap.parse_args()

    cfg = ServerConfig.load(args.config)
    if args.host:
        cfg.host = args.host
    if args.port:
        cfg.port = args.port

    configure_logging(cfg.log_level)

    # Fail loudly here, before uvicorn binds, so a missing prerequisite reads as an
    # actionable message instead of a traceback on the first agent connection.
    if not keys_exist(cfg):
        raise SystemExit(
            f"[server] No PQC keys in '{cfg.keys_dir}'. Run:\n"
            f"    python -m server.keygen"
        )
    if not os.path.exists(cfg.model_path):
        raise SystemExit(
            f"[server] No detection model at '{cfg.model_path}'. Run:\n"
            f"    python -m server.ml.train --source synthetic"
        )

    print(f"[server] VIGIL AI {VERSION}  ->  http://{cfg.host}:{cfg.port}")
    print(f"[server] dashboard API http://{cfg.host}:{cfg.port}/api/health   docs /docs")
    print(f"[server] PQC: {kem.ALGORITHM} + {aead.ALGORITHM} + {sig.ALGORITHM}")

    if args.reload:
        uvicorn.run("server.main:app", host=cfg.host, port=cfg.port, reload=True,
                    log_level=cfg.log_level)
    else:
        uvicorn.run(create_app(cfg), host=cfg.host, port=cfg.port, log_level=cfg.log_level)


def __getattr__(name: str):
    """Build ``app`` lazily, on first attribute access.

    This lets ``uvicorn server.main:app`` work while keeping a plain
    ``import server.main`` (from tests, or ``python -m server.main``) free of any
    requirement that keys and a model already exist.
    """
    if name == "app":
        instance = create_app()
        globals()["app"] = instance
        return instance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    main()
