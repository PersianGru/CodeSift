"""Small persistent state in the data dir (e.g. when `update` last checked)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codesift.paths import Paths

STATE_NAME = "state.json"


def _path(paths: Paths) -> Path:
    return paths.data / STATE_NAME


def load_state(paths: Paths) -> dict[str, Any]:
    try:
        data = json.loads(_path(paths).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(paths: Paths, **values: Any) -> None:
    state = load_state(paths)
    state.update(values)
    path = _path(paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8", newline="\n")


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
