"""Minimal KEY=VALUE env-file parser (no shell expansion, nothing is executed)."""

from __future__ import annotations

import re
from pathlib import Path

_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_env_text(text: str) -> dict[str, str]:
    """Parse env-file text. Supports comments, `export KEY=...`, single/double quotes and
    trailing ` # comment` on unquoted values. Invalid lines are ignored."""
    result: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        if not _KEY.match(key):
            continue
        value = value.strip()
        if value[:1] in ("'", '"'):
            quote = value[0]
            end = value.find(quote, 1)
            value = value[1:end] if end != -1 else value[1:]
        else:
            hash_pos = value.find(" #")
            if value.startswith("#"):
                value = ""
            elif hash_pos != -1:
                value = value[:hash_pos].rstrip()
        result[key] = value
    return result


def load_env_file(path: Path) -> dict[str, str]:
    return parse_env_text(path.read_text(encoding="utf-8-sig"))
