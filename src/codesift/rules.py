"""opengrep rules: vendoring from a pinned commit, integrity hash, location lookup."""

from __future__ import annotations

import hashlib
import io
import shutil
import tarfile
from pathlib import Path, PurePosixPath

from codesift.fsutil import replace_dir
from codesift.lockfile import RulesLock, source_root
from codesift.net import fetch
from codesift.paths import Paths

RULES_REPO = "opengrep/opengrep-rules"
RULES_LICENSE = "LGPL-2.1 with Commons Clause (inherited from semgrep-rules)"
# Languages CodeSift covers. generic/secrets is left out on purpose: gitleaks owns secret detection.
RULESETS = ("python", "javascript", "typescript", "php", "go", "generic", "dockerfile", "yaml", "bash")
EXCLUDE_PREFIXES = ("generic/secrets/",)
VENDOR_DIR = "opengrep-rules"
MAX_TARBALL = 150_000_000


class RulesError(Exception):
    pass


def _wanted(rel: PurePosixPath) -> bool:
    if not rel.parts or rel.parts[0] not in RULESETS:
        return False
    s = rel.as_posix()
    if s.startswith(EXCLUDE_PREFIXES):
        return False
    name = rel.name
    if not name.endswith((".yaml", ".yml")):
        return False
    return not (".test." in name or ".fixed." in name or name.startswith("."))


def tree_sha256(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        h.update(rel.encode() + b"\0" + hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n")
    return h.hexdigest()


def vendor(commit: str, dest: Path, repo: str = RULES_REPO) -> tuple[int, str]:
    """Download the repo tarball at `commit` and copy only rule YAML files of RULESETS into
    dest/opengrep-rules. Returns (file count, tree sha256)."""
    if len(commit) != 40 or not all(c in "0123456789abcdef" for c in commit):
        raise RulesError("rules commit must be a full 40-char sha")
    data = fetch(f"https://api.github.com/repos/{repo}/tarball/{commit}", max_bytes=MAX_TARBALL, timeout=300)
    target = dest / VENDOR_DIR
    staging = dest / (VENDOR_DIR + ".staging")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for member in tf:
                if not member.isreg():
                    continue
                parts = PurePosixPath(member.name).parts
                if len(parts) < 2 or any(p in ("..", "") for p in parts) or member.name.startswith("/"):
                    continue
                rel = PurePosixPath(*parts[1:])  # strip "<owner>-<repo>-<sha>/"
                if not _wanted(rel):
                    continue
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                content = fh.read()
                if b"rules:" not in content:
                    continue
                out = staging.joinpath(*rel.parts)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(content.replace(b"\r\n", b"\n"))
                count += 1
        if count == 0:
            raise RulesError("no rule files found in the rules tarball")
        digest = tree_sha256(staging)
        replace_dir(staging, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return count, digest


def rules_dir(paths: Paths, lock: RulesLock) -> Path | None:
    """Installed rules for the locked commit, else the source checkout's vendored copy."""
    candidates = [paths.data / "rules" / lock.commit / VENDOR_DIR]
    src = source_root()
    if src is not None:
        candidates.append(src / "rules" / VENDOR_DIR)
    for c in candidates:
        if c.is_dir():
            return c
    return None


def verify_rules(path: Path, lock: RulesLock) -> bool:
    return tree_sha256(path) == lock.tree_sha256
