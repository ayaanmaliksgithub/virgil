"""Persisted CLI config — `~/.config/virgil/config.json`.

Precedence for each setting: env var > config file > built-in default.
JSON over TOML to avoid a stdlib gap on Python 3.10 (`tomllib` is 3.11+).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


CONFIG_DIR = Path(os.environ.get("VIRGIL_CONFIG_DIR", str(Path.home() / ".config" / "virgil")))
CONFIG_PATH = CONFIG_DIR / "config.json"

DEFAULT_API_URL = "https://virgilhq.app/api"
DEFAULT_WEB_URL = "https://virgilhq.app"
DEFAULT_FAIL_ON = "critical"
DEFAULT_POST_SCAN_VIEW = "triage"

# Keys we know about — used by `virgil config set` to reject typos before
# they end up silently ignored on disk.
KNOWN_KEYS = {"api_url", "web_url", "default_fail_on", "default_post_scan_view"}


def load() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save(data: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def get(key: str, default: Any = None) -> Any:
    return load().get(key, default)


def set_(key: str, value: str) -> None:
    data = load()
    data[key] = value
    save(data)


def unset(key: str) -> bool:
    data = load()
    if key not in data:
        return False
    del data[key]
    save(data)
    return True


def api_url() -> str:
    return os.environ.get("VIRGIL_API") or get("api_url") or DEFAULT_API_URL


def web_url() -> str:
    return os.environ.get("VIRGIL_WEB") or get("web_url") or DEFAULT_WEB_URL


def default_fail_on() -> str:
    return os.environ.get("VIRGIL_FAIL_ON") or get("default_fail_on") or DEFAULT_FAIL_ON


def default_post_scan_view() -> str:
    return (
        os.environ.get("VIRGIL_SHOW")
        or get("default_post_scan_view")
        or DEFAULT_POST_SCAN_VIEW
    )
