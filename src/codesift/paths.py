"""User-level install locations (no admin rights, nothing system-wide).

Windows                                   Linux / macOS
  data   %USERPROFILE%\\.codesift            $XDG_DATA_HOME/codesift  (~/.local/share/codesift)
  config %USERPROFILE%\\.codesift\\config     $XDG_CONFIG_HOME/codesift (~/.config/codesift)
  runs   %USERPROFILE%\\.codesift\\runs       $XDG_CACHE_HOME/codesift/runs (~/.cache/codesift/runs)
  shim   %USERPROFILE%\\.codesift\\bin        ~/.local/bin

Windows deliberately avoids %LOCALAPPDATA% / %APPDATA%: packaged (MSIX) apps, such as some
desktop apps that host a terminal, silently redirect writes there into a private per-app folder, so
an install made from one app would be invisible to every other terminal (ADR-0002).

Overrides: CODESIFT_HOME (data + runs + shim), CODESIFT_CONFIG (config dir) and CODESIFT_RUNS (runs).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

APP = "codesift"
COMMAND = "sift"


@dataclass(frozen=True)
class Paths:
    data: Path
    config: Path
    runs: Path
    bin: Path
    skill: Path

    @property
    def venv(self) -> Path:
        return self.data / "venv"

    @property
    def tools(self) -> Path:
        return self.data / "tools"

    @property
    def cache(self) -> Path:
        return self.data / "cache"

    @property
    def config_file(self) -> Path:
        return self.config / "config.toml"

    @property
    def credentials_file(self) -> Path:
        """0.1.0 credentials file: read only as a fallback and migrated by `sift setup` (ADR-0014)."""
        return self.config / "bifrost.env"

    @property
    def gateway_file(self) -> Path:
        return self.config / "gateway.env"

    @property
    def anthropic_file(self) -> Path:
        return self.config / "anthropic.env"

    @property
    def vm_file(self) -> Path:
        return self.config / "vm.toml"

    @property
    def fix_file(self) -> Path:
        return self.config / "fix.toml"

    @property
    def consent_file(self) -> Path:
        return self.config / "consent.json"

    @property
    def keys_dir(self) -> Path:
        return self.config / "keys"

    @property
    def vm_known_hosts(self) -> Path:
        return self.config / "vm_known_hosts"

    @property
    def validate_runs(self) -> Path:
        return self.runs / "validate"

    @property
    def skill_file(self) -> Path:
        return self.skill / "SKILL.md"


def _home(env: Mapping[str, str]) -> Path:
    for key in ("USERPROFILE", "HOME"):
        value = env.get(key)
        if value:
            return Path(value)
    return Path.home()


def get_paths(env: Mapping[str, str] | None = None, platform: str | None = None) -> Paths:
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = _home(env)

    if platform == "win32":
        data = home / f".{APP}"
        config = data / "config"
        runs = data / "runs"
        bin_dir = data / "bin"
    else:
        data = Path(env.get("XDG_DATA_HOME") or home / ".local" / "share") / APP
        config = Path(env.get("XDG_CONFIG_HOME") or home / ".config") / APP
        runs = Path(env.get("XDG_CACHE_HOME") or home / ".cache") / APP / "runs"
        bin_dir = home / ".local" / "bin"

    override_home = env.get("CODESIFT_HOME")
    if override_home:
        data = Path(override_home)
        runs = data / "runs"
        bin_dir = data / "bin"
    override_config = env.get("CODESIFT_CONFIG")
    if override_config:
        config = Path(override_config)
    override_runs = env.get("CODESIFT_RUNS")
    if override_runs:
        runs = Path(override_runs)

    skill = home / ".claude" / "skills" / COMMAND
    return Paths(data=data, config=config, runs=runs, bin=bin_dir, skill=skill)
