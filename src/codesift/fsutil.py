"""Filesystem helpers that survive Windows quirks."""

from __future__ import annotations

import shutil
import time
from pathlib import Path


def replace_dir(src: Path, dst: Path, attempts: int = 6, delay_s: float = 0.5) -> None:
    """Move a freshly written directory into place. On Windows a virus scanner or the search indexer
    can hold new files for a moment, making renames fail with "Access denied": retry, then fall back
    to copy + delete."""
    shutil.rmtree(dst, ignore_errors=True)
    for attempt in range(attempts):
        try:
            src.rename(dst)
            return
        except PermissionError:
            if attempt < attempts - 1:
                time.sleep(delay_s * (attempt + 1))
    shutil.copytree(src, dst)
    shutil.rmtree(src, ignore_errors=True)


def rmtree_force(path: Path) -> None:
    """Delete a tree, clearing read-only flags (git object files on Windows) on the way."""
    import os
    import stat

    def retry(func: object, target: str, _exc: object) -> None:
        try:
            os.chmod(target, stat.S_IWRITE)
            if callable(func):
                func(target)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=retry)  # onerror: still supported on 3.11-3.13
