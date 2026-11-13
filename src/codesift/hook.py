"""Git pre-push hook: `sift hook install | uninstall | status`.

- Installs into the repository's hooks dir as git resolves it (respects core.hooksPath).
- An existing pre-push hook is renamed to `pre-push.local` and called first (chained), never
  overwritten silently.
- The hook runs `sift scan --fast --no-llm --threshold high --since <remote sha>` and blocks the
  push only on new (non-baselined) high/critical findings. If CodeSift or a tool is missing or fails,
  it warns and ALLOWS the push: it must never brick a repository. `git push --no-verify` is the
  user's escape hatch (CodeSift and assistants never use it)."""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from codesift.gitutil import git

MARKER = "# codesift-managed-hook v1"
LOCAL = "pre-push.local"

HOOK_TEMPLATE = r"""#!/bin/sh
{marker}
# Installed by `sift hook install`. Remove with `sift hook uninstall`.
# Blocks a push only on NEW high/critical findings (not in .codesift-baseline.json).
# Emergency escape hatch for the repository owner: git push --no-verify

CODESIFT_PY="{python}"
HOOK_DIR=$(cd "$(dirname "$0")" && pwd)
INPUT=$(cat)

if [ -x "$HOOK_DIR/{local}" ]; then
    printf '%s\n' "$INPUT" | "$HOOK_DIR/{local}" "$@" || exit $?
fi

if [ -n "$CODESIFT_SKIP_HOOK" ]; then
    echo "sift: CODESIFT_SKIP_HOOK is set - pre-push scan skipped" >&2
    exit 0
fi
if [ ! -x "$CODESIFT_PY" ] && [ ! -f "$CODESIFT_PY" ]; then
    echo "sift: not installed at $CODESIFT_PY - push allowed without a scan" >&2
    exit 0
fi

ZERO=0000000000000000000000000000000000000000
status=0
printf '%s\n' "$INPUT" | {{
while read -r local_ref local_sha remote_ref remote_sha; do
    [ -z "$local_sha" ] && continue
    case "$local_sha" in *[!0]*) ;; *) continue ;; esac   # branch deletion: nothing to scan
    since=""
    case "$remote_sha" in
        *[!0]*) git cat-file -e "$remote_sha^{{commit}}" 2>/dev/null && since="$remote_sha" ;;
    esac
    if [ -n "$since" ]; then
        "$CODESIFT_PY" -m codesift scan . --fast --no-llm --threshold high --since "$since"
    else
        "$CODESIFT_PY" -m codesift scan . --fast --no-llm --threshold high
    fi
    rc=$?
    if [ $rc -eq 1 ]; then
        echo "" >&2
        echo "sift: push blocked - new high/critical findings in $local_ref (see the summary above)." >&2
        echo "  Fix them, or accept a false positive (with the owner's OK):" >&2
        echo "    sift baseline accept <ID> --reason \"...\"" >&2
        status=1
    elif [ $rc -ne 0 ]; then
        echo "sift: scan could not complete (exit $rc) - push allowed; run 'sift doctor'." >&2
    fi
done
exit $status
}}
"""


class HookError(Exception):
    pass


@dataclass
class HookStatus:
    hooks_dir: Path
    installed: bool
    chained: bool
    foreign_hook: bool
    python: str


def hooks_dir(root: Path) -> Path:
    out = git(root, "rev-parse", "--git-path", "hooks")
    if out is None:
        raise HookError(f"{root} is not inside a git repository")
    path = Path(out.strip())
    return path if path.is_absolute() else (root / path).resolve()


def _python_for_hook() -> str:
    """The interpreter that runs CodeSift now (the installed venv when called via the shim)."""
    return Path(sys.executable).resolve().as_posix()


def _is_ours(path: Path) -> bool:
    try:
        return MARKER in path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def render(python: str) -> str:
    return HOOK_TEMPLATE.format(marker=MARKER, python=python, local=LOCAL)


def install(root: Path, python: str | None = None) -> list[str]:
    hdir = hooks_dir(root)
    hdir.mkdir(parents=True, exist_ok=True)
    hook = hdir / "pre-push"
    local = hdir / LOCAL
    log = []
    if hook.exists() and not _is_ours(hook):
        if local.exists():
            raise HookError(f"both {hook.name} and {local.name} exist in {hdir}; resolve them by hand first")
        hook.rename(local)
        log.append(f"existing pre-push hook kept as {local} and chained (runs first)")
    hook.write_text(render(python or _python_for_hook()), encoding="utf-8", newline="\n")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    log.append(f"installed {hook}")
    return log


def uninstall(root: Path) -> list[str]:
    hdir = hooks_dir(root)
    hook = hdir / "pre-push"
    local = hdir / LOCAL
    log = []
    if hook.exists() and not _is_ours(hook):
        raise HookError(f"{hook} was not installed by CodeSift - left untouched")
    if hook.exists():
        hook.unlink()
        log.append(f"removed {hook}")
    if local.exists():
        local.rename(hook)
        log.append(f"restored the previous hook from {local.name}")
    if not log:
        log.append("no sift hook installed")
    return log


def status(root: Path) -> HookStatus:
    hdir = hooks_dir(root)
    hook = hdir / "pre-push"
    python = ""
    if _is_ours(hook):
        for line in hook.read_text(encoding="utf-8").splitlines():
            if line.startswith("CODESIFT_PY="):
                python = line.split("=", 1)[1].strip('"')
    return HookStatus(
        hooks_dir=hdir,
        installed=_is_ours(hook),
        chained=(hdir / LOCAL).exists(),
        foreign_hook=hook.exists() and not _is_ours(hook),
        python=python,
    )


def describe(st: HookStatus) -> str:
    lines = [f"hooks dir: {st.hooks_dir}"]
    if st.installed:
        ok = os.path.isfile(st.python)
        lines.append(f"CodeSift pre-push hook: installed (python {st.python}{'' if ok else ' - MISSING'})")
        lines.append(f"chained previous hook: {'yes (pre-push.local)' if st.chained else 'no'}")
    elif st.foreign_hook:
        lines.append(
            "CodeSift pre-push hook: not installed (another pre-push hook exists; install will chain it)"
        )
    else:
        lines.append("CodeSift pre-push hook: not installed")
    return "\n".join(lines)
