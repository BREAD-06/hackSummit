"""Endpoint-agent configuration.

Resolution order (later wins): built-in defaults -> ``agent_config.yaml`` ->
``VIGIL_AGENT_*`` environment variables -> command-line flags.

The defaults are deliberately conservative: the agent watches the current user's
own document folders, collects **metadata only**, and never reads file contents.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field, fields
from typing import Any

DEFAULT_CONFIG_PATH = "agent_config.yaml"

# Noise that every filesystem produces and no analyst wants to see. Matched
# case-insensitively as substrings of the full path.
DEFAULT_EXCLUDES = [
    "\\appdata\\", "/appdata/",
    "\\$recycle.bin", "/.trash",
    "\\.git\\", "/.git/",
    "\\node_modules\\", "/node_modules/",
    "\\__pycache__\\", "/__pycache__/",
    "\\.venv\\", "/.venv/",
    ".tmp", ".temp", ".partial", ".crdownload", ".swp", "~$", ".lock",
]


def default_agent_id() -> str:
    """Stable per-machine identifier: ``AGENT-<HOSTNAME>``."""
    return f"AGENT-{socket.gethostname().upper()}"


def default_watch_dirs() -> list[str]:
    """The current user's own document folders, if they exist."""
    home = os.path.expanduser("~")
    candidates = [os.path.join(home, name) for name in
                  ("Documents", "Downloads", "Desktop")]
    return [p for p in candidates if os.path.isdir(p)]


@dataclass
class AgentConfig:
    # ── identity & server ──
    agent_id: str = field(default_factory=default_agent_id)
    server_url: str = "http://127.0.0.1:8000"
    enroll_token: str = ""
    keys_dir: str = "keys/agent"
    # Pin the server's ML-KEM public-key fingerprint (from `server.keygen --bundle`).
    # Left empty, the first enrollment is trust-on-first-use.
    server_kem_fingerprint: str = ""

    # ── what to collect ──
    collect_files: bool = True
    collect_usb: bool = True
    collect_logon: bool = True
    watch_dirs: list[str] = field(default_factory=default_watch_dirs)
    watch_removable: bool = True          # auto-watch removable drives as they appear
    exclude_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    user: str = ""                        # override the reported user (default: OS user)

    # ── timing ──
    flush_interval_s: float = 5.0         # how often to seal and send a batch
    usb_poll_s: float = 2.0
    logon_poll_s: float = 5.0
    modify_debounce_s: float = 1.0        # collapse repeated writes to one file
    max_batch: int = 500                  # events per sealed batch
    buffer_size: int = 20000              # in-memory cap before oldest are dropped

    # ── networking ──
    request_timeout_s: float = 15.0
    retry_backoff_s: float = 2.0
    max_backoff_s: float = 60.0
    verify_tls: bool = True               # only relevant when server_url is https

    # ── response directives ──
    apply_directives: bool = True
    directive_log: str = "logs/agent_directives.log"
    notify_user: bool = True              # show the security notice (console + toast)

    log_level: str = "info"

    # ── derived ──
    @property
    def sign_secret_path(self) -> str:
        return os.path.join(self.keys_dir, "agent_sig_secret.bin")

    @property
    def sign_public_path(self) -> str:
        return os.path.join(self.keys_dir, "agent_sig_public.bin")

    @property
    def effective_user(self) -> str:
        return self.user or os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"

    @property
    def host(self) -> str:
        return socket.gethostname()

    # ── loading ──
    @classmethod
    def load(cls, path: str | None = None) -> "AgentConfig":
        cfg = cls()
        path = path or os.environ.get("VIGIL_AGENT_CONFIG", DEFAULT_CONFIG_PATH)
        if path and os.path.exists(path):
            import yaml

            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            cfg = cfg.merged(data)
        return cfg.with_env()

    def merged(self, data: dict[str, Any]) -> "AgentConfig":
        known = {f.name for f in fields(self)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(
                f"Unknown agent config key(s): {', '.join(sorted(unknown))}. "
                f"Valid keys: {', '.join(sorted(known))}"
            )
        return AgentConfig(**{**self.as_dict(), **data})

    def with_env(self) -> "AgentConfig":
        """Apply ``VIGIL_AGENT_<FIELD>`` overrides (lists are comma-separated)."""
        out = self.as_dict()
        for f in fields(self):
            raw = os.environ.get(f"VIGIL_AGENT_{f.name.upper()}")
            if raw is None:
                continue
            out[f.name] = _coerce(raw, out[f.name])
        return AgentConfig(**out)

    def as_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def summary(self) -> dict[str, Any]:
        """What the agent prints at startup. Excludes the enrollment token."""
        d = self.as_dict()
        d["enroll_token"] = "<set>" if self.enroll_token else "<none>"
        d["user"] = self.effective_user
        d["host"] = self.host
        return d

    def validate(self) -> list[str]:
        """Return human-readable problems; empty means the config is usable."""
        problems = []
        if not self.server_url.startswith(("http://", "https://")):
            problems.append(f"server_url must start with http:// or https:// (got {self.server_url!r})")
        if not (self.collect_files or self.collect_usb or self.collect_logon):
            problems.append("all collectors are disabled — the agent would send nothing")
        if self.collect_files and not self.watch_dirs:
            problems.append(
                "collect_files is on but watch_dirs is empty; set watch_dirs in agent_config.yaml"
            )
        for d in self.watch_dirs:
            if not os.path.isdir(d):
                problems.append(f"watch_dirs entry does not exist: {d}")
        if self.max_batch < 1:
            problems.append("max_batch must be at least 1")
        if self.flush_interval_s <= 0:
            problems.append("flush_interval_s must be positive")
        return problems


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
