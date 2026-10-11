"""Settings read from the environment of the MCP process, set by a human in the agent's MCP config, never by the model.

Config and state are kept apart: the operator's config directory is only ever read, everything the guard learns or
records goes to the state directory (default ~/.sentinel-guard/state, never the current directory: MCP hosts may
start the server without a cwd).
"""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

PLACEHOLDER = re.compile(r"\$\{[^}]*\}")
DEFAULT_API = "https://rpc.petroi.fr"
DEFAULT_EXPLORER = "https://explorer.petroi.fr"
CONFIG_FILES = ("mandates.json", "authorities.json", "allowlist.json", "brands.json", "domains.json", "addresses.json",
                "history.json", "facilitators.json", "tools_inventory.json")
STATE_FILES = ("threats.json", "nonces.json", "decisions.jsonl", "pending.json", "spend.json", "visas.json", "registry_events.jsonl")
LLM_DEFAULT_MODEL = {"anthropic": "claude-sonnet-5", "bedrock": "us.anthropic.claude-sonnet-4-6"}


def env(name: str, default: str | None = None) -> str | None:
    """An env value, or `default` when unset, blank, or an unresolved `${...}` placeholder (Hermes leaves those literal)."""
    v = os.environ.get(name)
    if v is None or not v.strip() or PLACEHOLDER.fullmatch(v.strip()):
        return default
    return v.strip()


def env_float(name: str, default: float) -> float:
    try:
        return float(env(name) or default)
    except ValueError:
        return default


def env_int(name: str, default: int) -> int:
    try:
        return int(env(name) or default)
    except ValueError:
        return default


def read_json(directory, name: str, default: Any) -> Any:
    """A config file, or `default` when absent: a missing file means empty, never an error."""
    if directory is None:
        return default
    p = directory / name
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else default


def write_atomic(path: Path, text: str) -> None:
    """Write then rename: another process (the CLI next to a running server) never reads a half-written state file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def home_dir() -> Path:
    return Path.home() / ".sentinel-guard"


def sample_config_dir():
    """The synthetic example config shipped inside the package (read through importlib.resources)."""
    return resources.files("sentinel_guard") / "data"


def user_config_dir() -> Path:
    return home_dir() / "config"


def resolve_config_dir():
    """SENTINEL_CONFIG_DIR, else the user config `sentinel-guard init` wrote, else the shipped example config."""
    explicit = env("SENTINEL_CONFIG_DIR")
    if explicit:
        return Path(explicit).expanduser()
    if (user_config_dir() / "mandates.json").is_file():
        return user_config_dir()
    return sample_config_dir()


def resolve_state_dir() -> Path:
    explicit = env("SENTINEL_STATE_DIR")
    return Path(explicit).expanduser() if explicit else home_dir() / "state"


@dataclass
class Settings:
    config_dir: Any = None  # Path or importlib Traversable, read only
    state_dir: Path | None = None
    mode: str = "local"  # local | connected
    api: str = DEFAULT_API
    api_key: str | None = field(default=None, repr=False)
    explorer: str = DEFAULT_EXPLORER
    amount_decimals: int = 18
    api_timeout: float = 45.0
    registry_timeout: float = 3.0
    registry_ttl: float = 30.0
    unregistered: str = "review"  # review | block
    issuer: str | None = None
    approver_token: str | None = field(default=None, repr=False)
    http_token: str | None = field(default=None, repr=False)
    llm: str = "off"  # off | anthropic | bedrock
    llm_model: str | None = None
    llm_timeout: float = 20.0

    @property
    def connected(self) -> bool:
        return self.mode == "connected"

    @classmethod
    def from_env(cls, **overrides: Any) -> "Settings":
        key = env("SENTINEL_API_KEY")
        api = env("SENTINEL_API", DEFAULT_API) or DEFAULT_API
        mode = (env("SENTINEL_MODE") or "").lower().replace("_", "-")
        if api.lower() == "off" or mode in ("local", "local-only", "offline"):
            mode = "local"
        elif mode == "connected" or (not mode and key):
            mode = "connected"
        else:
            mode = "local"
        unregistered = (env("SENTINEL_UNREGISTERED") or "review").lower()
        llm = (env("SENTINEL_LLM") or "off").lower()
        if llm in ("0", "false", "no", "none", ""):
            llm = "off"
        s = cls(
            config_dir=resolve_config_dir(), state_dir=resolve_state_dir(), mode=mode, api=api.rstrip("/"), api_key=key,
            explorer=(env("SENTINEL_EXPLORER", DEFAULT_EXPLORER) or DEFAULT_EXPLORER).rstrip("/"),
            amount_decimals=env_int("SENTINEL_AMOUNT_DECIMALS", 18), api_timeout=env_float("SENTINEL_API_TIMEOUT", 45.0),
            unregistered=unregistered if unregistered in ("review", "block") else "review",
            issuer=(env("SENTINEL_ISSUER") or "").lower() or None, approver_token=env("SENTINEL_APPROVER_TOKEN"),
            http_token=env("SENTINEL_HTTP_TOKEN"), llm=llm, llm_model=env("SENTINEL_LLM_MODEL"),
            llm_timeout=env_float("SENTINEL_LLM_TIMEOUT", 20.0),
        )
        for k, v in overrides.items():
            setattr(s, k, v)
        return s
