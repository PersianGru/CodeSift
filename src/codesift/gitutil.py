"""Read-only git helpers. Git runs with repository-controlled command hooks disabled
(fsmonitor, external diff, textconv), so scanning an untrusted repo cannot execute its config."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

SAFE_CONFIG = {
    "core.fsmonitor": "false",
    "diff.external": "",
    "core.pager": "cat",
    "protocol.allow": "never",
}


def safe_git_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Environment that makes every git process (ours and the scanners') ignore risky repo config."""
    env = dict(os.environ if base is None else base)
    existing = int(env.get("GIT_CONFIG_COUNT", "0") or 0)
    for i, (key, value) in enumerate(SAFE_CONFIG.items(), start=existing):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    env["GIT_CONFIG_COUNT"] = str(existing + len(SAFE_CONFIG))
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"  # never write the index from read-only commands
    return env


def git(root: Path, *args: str, timeout: float = 60) -> str | None:
    exe = shutil.which("git")
    if exe is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603
            [exe, "-C", str(root), "--no-pager", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=safe_git_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if proc.returncode == 0 else None


@dataclass
class GitInfo:
    is_repo: bool
    toplevel: Path | None = None
    commit: str = ""
    branch: str = ""
    dirty: bool = False


def git_info(root: Path) -> GitInfo:
    top = git(root, "rev-parse", "--show-toplevel")
    if top is None:
        return GitInfo(False)
    commit = (git(root, "rev-parse", "--short=12", "HEAD") or "").strip()
    branch = (git(root, "rev-parse", "--abbrev-ref", "HEAD") or "").strip()
    status = git(root, "status", "--porcelain", "--untracked-files=no") or ""
    return GitInfo(True, Path(top.strip()), commit, branch, bool(status.strip()))


def list_files(root: Path) -> list[str] | None:
    """Tracked + untracked-not-ignored files relative to `root` (respects .gitignore), or None."""
    out = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ".")
    if out is None:
        return None
    return sorted({p for p in out.split("\0") if p})


def changed_files(root: Path, since: str) -> list[str] | None:
    """Files changed between `since` and the working tree (committed + uncommitted), root-relative."""
    if since.startswith("-"):
        return None  # never let a ref be parsed as an option
    out = git(root, "diff", "--name-only", "--no-ext-diff", "--no-textconv", "--relative", "-z", since, "--")
    if out is None:
        return None
    return sorted({p for p in out.split("\0") if p})


def ref_exists(root: Path, ref: str) -> bool:
    return (
        not ref.startswith("-")
        and git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}") is not None
    )
