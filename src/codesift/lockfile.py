"""tools.lock.json: pinned scanner binaries, rules commit and Python scanner pins.

Schema (version 1):
{
  "schema": 1,
  "updated": "YYYY-MM-DD",
  "cooldown_days": 7,
  "tools": {
    "<name>": {
      "repo": "owner/name", "tag": "v1.2.3", "version": "1.2.3", "published": "YYYY-MM-DD",
      "checksum_source": "<checksums asset name>" | "github-asset-digest",
      "platforms": {"<platform>": {"asset": "...", "url": "https://github.com/...", "sha256": "...",
                                   "size": 123}}
    }
  },
  "rules": {"repo": "owner/name", "commit": "<sha>", "date": "YYYY-MM-DD", "license": "...",
            "archived": true, "rulesets": [...], "tree_sha256": "..."},
  "python": {"<package>": "<version>", ...}      # top-level pins; full hashed set in requirements.lock
}
"""

from __future__ import annotations

import json
import platform as _platform
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from codesift.paths import Paths

LOCK_NAME = "tools.lock.json"
PREV_LOCK_NAME = "tools.lock.prev.json"
PY_LOCK_NAME = "requirements.lock"
PLATFORMS = ("windows-x64", "linux-x64", "linux-arm64", "darwin-arm64")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class LockError(Exception):
    pass


@dataclass
class PlatformAsset:
    asset: str
    url: str
    sha256: str
    size: int


@dataclass
class ToolLock:
    repo: str
    tag: str
    version: str
    published: str
    checksum_source: str
    platforms: dict[str, PlatformAsset] = field(default_factory=dict)


@dataclass
class RulesLock:
    repo: str
    commit: str
    date: str
    license: str
    archived: bool
    rulesets: list[str]
    tree_sha256: str


@dataclass
class Lock:
    updated: str
    cooldown_days: int = 7
    tools: dict[str, ToolLock] = field(default_factory=dict)
    rules: RulesLock | None = None
    python: dict[str, str] = field(default_factory=dict)
    schema: int = 1

    def to_json(self) -> str:
        data: dict[str, Any] = {
            "schema": self.schema,
            "updated": self.updated,
            "cooldown_days": self.cooldown_days,
            "tools": {k: asdict(v) for k, v in sorted(self.tools.items())},
            "rules": asdict(self.rules) if self.rules else None,
            "python": dict(sorted(self.python.items())),
        }
        return json.dumps(data, indent=2) + "\n"


def current_platform() -> str:
    machine = _platform.machine().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)
    osname = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(sys.platform, sys.platform)
    return f"{osname}-{arch}"


def _req(d: dict[str, Any], key: str, typ: type, where: str) -> Any:
    if key not in d or not isinstance(d[key], typ):
        raise LockError(f"{where}: missing or invalid {key!r}")
    return d[key]


def parse_lock(data: Any) -> Lock:
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise LockError("unsupported lock file (schema must be 1)")
    lock = Lock(
        updated=_req(data, "updated", str, "lock"), cooldown_days=_req(data, "cooldown_days", int, "lock")
    )
    for name, t in _req(data, "tools", dict, "lock").items():
        where = f"tools.{name}"
        if not isinstance(t, dict):
            raise LockError(f"{where}: must be an object")
        tool = ToolLock(
            repo=_req(t, "repo", str, where),
            tag=_req(t, "tag", str, where),
            version=_req(t, "version", str, where),
            published=_req(t, "published", str, where),
            checksum_source=_req(t, "checksum_source", str, where),
        )
        for plat, a in _req(t, "platforms", dict, where).items():
            pw = f"{where}.platforms.{plat}"
            if not isinstance(a, dict):
                raise LockError(f"{pw}: must be an object")
            asset = PlatformAsset(
                asset=_req(a, "asset", str, pw),
                url=_req(a, "url", str, pw),
                sha256=_req(a, "sha256", str, pw).lower(),
                size=_req(a, "size", int, pw),
            )
            if not _SHA256.match(asset.sha256):
                raise LockError(f"{pw}: sha256 is not a 64-char hex digest")
            prefix = f"https://github.com/{tool.repo}/releases/download/{tool.tag}/"
            if not asset.url.startswith(prefix):
                raise LockError(f"{pw}: url must start with {prefix}")
            tool.platforms[plat] = asset
        lock.tools[name] = tool
    rules = data.get("rules")
    if rules is not None:
        if not isinstance(rules, dict):
            raise LockError("rules: must be an object")
        lock.rules = RulesLock(
            repo=_req(rules, "repo", str, "rules"),
            commit=_req(rules, "commit", str, "rules"),
            date=_req(rules, "date", str, "rules"),
            license=_req(rules, "license", str, "rules"),
            archived=_req(rules, "archived", bool, "rules"),
            rulesets=_req(rules, "rulesets", list, "rules"),
            tree_sha256=_req(rules, "tree_sha256", str, "rules"),
        )
    py = data.get("python", {})
    if not isinstance(py, dict) or not all(isinstance(v, str) for v in py.values()):
        raise LockError("python: must map package -> version")
    lock.python = dict(py)
    return lock


def load_lock(path: Path) -> Lock:
    try:
        return parse_lock(json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError:
        raise LockError(f"{path} not found") from None
    except ValueError as exc:
        raise LockError(f"{path}: invalid JSON: {exc}") from None


def save_lock(lock: Lock, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(lock.to_json(), encoding="utf-8", newline="\n")
    tmp.replace(path)


def source_root() -> Path | None:
    """The CodeSift source checkout, when running from one (editable/dev install)."""
    root = Path(__file__).resolve().parents[2]
    return root if (root / "pyproject.toml").is_file() and (root / "src" / "codesift").is_dir() else None


def active_lock_path(paths: Paths) -> Path:
    """Installed lock in the data dir; falls back to the source checkout's lock (development)."""
    installed = paths.data / LOCK_NAME
    if installed.is_file():
        return installed
    src = source_root()
    if src is not None:
        return src / LOCK_NAME
    return installed
