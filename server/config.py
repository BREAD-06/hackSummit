"""Detection-server configuration.

Resolution order (later wins): built-in defaults -> YAML file -> ``VIGIL_*``
environment variables. Kept to a dataclass plus PyYAML so the server has no
settings-framework dependency and the effective config can be printed at boot.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import Any

DEFAULT_CONFIG_PATH = "server_config.yaml"

# Path fragments that mark a file as business-sensitive. Matched case-insensitively
# against the whole path, and extended by `sensitive_dirs` from the config file.
DEFAULT_SENSITIVE_HINTS = [
    "confidential", "classified", "restricted", "secret",
    "finance", "payroll", "hr", "human resources",
    "legal", "contracts", "records", "salary",
    "credential", "password", "private key", "id_rsa", ".pem",
]


@dataclass
class ServerConfig:
    # ── network ──
    host: str = "0.0.0.0"          # bind all interfaces so endpoints on the LAN can reach us
    port: int = 8000
    cors_origins: list[str] = field(default_factory=lambda: ["*"])

    # ── storage & model ──
    db_path: str = "data/vigil.db"
    model_path: str = "models/vigil_iforest.pkl"
    keys_dir: str = "keys/server"

    # ── secure channel ──
    require_enroll_token: bool = True   # set False only for a local demo
    max_clock_skew_s: int = 300         # handshake timestamp tolerance
    allow_reenroll: bool = False        # re-enrolling an existing agent_id rotates its key

    # ── reinforcement learning ──
    rl_alpha: float = 0.3
    rl_gamma: float = 0.0               # each window is an independent decision
    rl_epsilon: float = 0.0             # exploration off by default on a live control
    rl_safe_exploration: bool = True    # exploration may never escalate to BLOCK

    # ── enrichment ──
    sensitive_dirs: list[str] = field(default_factory=list)
    sensitive_hints: list[str] = field(default_factory=lambda: list(DEFAULT_SENSITIVE_HINTS))

    # ── behaviour ──
    persist_events: bool = True         # keep raw event metadata (audit trail)
    emit_directives: bool = True        # send containment directives back to the agent
    log_level: str = "info"

    # ── derived ──
    @property
    def kem_secret_path(self) -> str:
        return os.path.join(self.keys_dir, "server_kem_secret.bin")

    @property
    def kem_public_path(self) -> str:
        return os.path.join(self.keys_dir, "server_kem_public.bin")

    @property
    def sig_secret_path(self) -> str:
        return os.path.join(self.keys_dir, "server_sig_secret.bin")

    @property
    def sig_public_path(self) -> str:
        return os.path.join(self.keys_dir, "server_sig_public.bin")

    # ── loading ──
    @classmethod
    def load(cls, path: str | None = None) -> "ServerConfig":
        cfg = cls()
        path = path or os.environ.get("VIGIL_CONFIG", DEFAULT_CONFIG_PATH)
        if path and os.path.exists(path):
            import yaml

            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            cfg = cfg.merged(data)
        return cfg.with_env()

    def merged(self, data: dict[str, Any]) -> "ServerConfig":
        known = {f.name for f in fields(self)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(
                f"Unknown config key(s): {', '.join(sorted(unknown))}. "
                f"Valid keys: {', '.join(sorted(known))}"
            )
        return ServerConfig(**{**self.as_dict(), **data})

    def with_env(self) -> "ServerConfig":
        """Apply ``VIGIL_<FIELD>`` overrides (lists are comma-separated)."""
        out = self.as_dict()
        for f in fields(self):
            raw = os.environ.get(f"VIGIL_{f.name.upper()}")
            if raw is None:
                continue
            out[f.name] = _coerce(raw, out[f.name])
        return ServerConfig(**out)

    def as_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def summary(self) -> dict[str, Any]:
        """Config as shown at boot and on ``/api/health`` (no secrets involved)."""
        d = self.as_dict()
        d["sensitive_hints"] = len(self.sensitive_hints)
        return d


def _coerce(raw: str, current: Any) -> Any:
    if isinstance(current, bool):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(current, int) and not isinstance(current, bool):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    if isinstance(current, list):
        return [p.strip() for p in raw.split(",") if p.strip()]
    return raw
