"""Owner-only files for settings and secrets, masking for display, legacy migration.

Every file written here is created through a temp file that is restricted to the current user
(Windows ACL / mode 600) *before* it is moved into place, so a secret is never readable by others,
not even briefly. Values are never printed; `describe()` shows only "set (len N)" / "empty"."""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codesift.config import GATEWAY_KEYS, LEGACY_KEYS, LLM_KEY, ConfigError
from codesift.envfile import load_env_file
from codesift.paths import Paths

_SAFE_VALUE = "".join(chr(c) for c in range(32, 127) if chr(c) not in "\"'\\")


class StoreError(Exception):
    """File could not be written/read. Never contains a secret value."""


def restrict(path: Path) -> str:
    """Owner-only permissions with the installer's helper (icacls on Windows, chmod 600 elsewhere)."""
    from codesift.install import InstallError, restrict_to_user

    try:
        return restrict_to_user(path)
    except InstallError as exc:
        raise StoreError(str(exc)) from None


def restrict_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        path.chmod(0o700)
    else:
        restrict(path)


def write_private(path: Path, text: str) -> str:
    """Atomically write `text` to an owner-only file. Returns the permission note."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    note = restrict(tmp)
    tmp.replace(path)
    return note


def _check_value(key: str, value: str) -> None:
    if any(c not in _SAFE_VALUE and c != " " for c in value) or value != value.strip():
        raise StoreError(f"{key}: value contains characters that cannot be stored safely (quotes/control)")


def write_env(path: Path, values: Mapping[str, str], header: str = "") -> str:
    lines = [f"# {line}" for line in header.splitlines()] if header else []
    for key, value in values.items():
        _check_value(key, value)
        lines.append(f"{key}={value}")
    return write_private(path, "\n".join(lines) + "\n")


def read_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    try:
        return load_env_file(path)
    except (OSError, UnicodeDecodeError) as exc:
        raise StoreError(f"{path}: unreadable ({type(exc).__name__})") from None


def write_json(path: Path, data: Any) -> str:
    return write_private(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def describe(value: str | None) -> str:
    """Display form of a secret: never the value itself."""
    if value is None:
        return "not set"
    if value == "":
        return "empty"
    return f"set (len {len(value)})"


def owner_only(path: Path) -> bool | None:
    """True/False on POSIX (no group/other bits); None where it cannot be checked cheaply (Windows)."""
    if not path.exists():
        return None
    if os.name == "nt":
        return None
    return not (stat.S_IMODE(path.stat().st_mode) & 0o077)


def migrate_legacy_gateway(paths: Paths) -> bool:
    """Copy the 0.1.0 credentials file into gateway.env under the new names, if gateway.env does not
    exist yet. The old file is left in place (other tools may read it); gateway.env wins from now on.
    Returns True when something was migrated. Never prints values or the legacy key names."""
    if paths.gateway_file.exists() or not paths.credentials_file.is_file():
        return False
    old = read_env(paths.credentials_file)
    new = {key: old[legacy] for key, legacy in LEGACY_KEYS.items() if old.get(legacy)}
    if not new:
        return False
    write_env(paths.gateway_file, new, "LLM gateway settings (migrated). Edit with `sift setup --llm`.")
    return True


def save_gateway(paths: Paths, values: Mapping[str, str]) -> str:
    unknown = [k for k in values if k not in GATEWAY_KEYS]
    if unknown:
        raise ConfigError(f"unknown gateway setting(s): {', '.join(unknown)}")
    ordered = {k: values[k] for k in GATEWAY_KEYS if k in values and (values[k] != "" or k == LLM_KEY)}
    return write_env(
        paths.gateway_file, ordered, "LLM gateway settings. Edit with `sift setup --llm`. Never commit."
    )
