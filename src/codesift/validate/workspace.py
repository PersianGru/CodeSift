"""The workspace: a filtered copy of the project in CodeSift's runs folder. The project itself is
never written (RULES.md rule 2).

Only tracked files are copied (`git ls-files`, or the scanner's file list outside git), minus `.git`,
files with a secret finding, `never_send` globs, `.env*`, keys/certificates, credential-looking names,
oversized files, symlinks and special files. A private git repository in the workspace records the
baseline so every diff is exact. Its git runs with an empty template (no hooks), no global or system
config, and the hardened settings of `gitutil.safe_git_env`."""

from __future__ import annotations

import fnmatch
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from codesift.gitutil import list_files, safe_git_env
from codesift.validate import ValidateError
from codesift.validate.pack import PackError, pack_tree, safe_unpack

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 20_000
SENSITIVE_GLOBS = (
    ".env",
    ".env.*",
    "*.env",
    ".envrc",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.kdbx",
    "*.ppk",
    "*.asc",
    "*.gpg",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".htpasswd",
    "*credential*",
    "*secret*",
    "*.tfstate",
    "*.tfstate.*",
    "*.tfvars",
    "kubeconfig",
    "*.kubeconfig",
)
SENSITIVE_DIRS = (".git", ".ssh", ".aws", ".gnupg", ".docker", ".kube", ".azure", ".config")


def glob_match(rel: str, globs: list[str] | tuple[str, ...]) -> bool:
    """`*` crosses directories (fnmatch); patterns without `/` also match any path component."""
    parts = PurePosixPath(rel).parts
    for g in globs:
        g = g.strip()
        if not g:
            continue
        if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, g.rstrip("/") + "/*"):
            return True
        if "/" not in g and any(fnmatch.fnmatch(p, g) for p in parts):
            return True
    return False


def exclusion_reason(rel: str, never_send: list[str], secret_paths: set[str]) -> str | None:
    p = PurePosixPath(rel)
    low = rel.lower()
    if any(part in SENSITIVE_DIRS for part in p.parts[:-1]) or p.name == ".git":
        return "sensitive folder"
    if rel in secret_paths:
        return "has a secret finding"
    if glob_match(rel, never_send):
        return "never_send"
    if glob_match(low, [g.lower() for g in SENSITIVE_GLOBS]):
        return "sensitive file name"
    return None


@dataclass
class Workspace:
    root: Path
    files: list[str] = field(default_factory=list)
    excluded: dict[str, str] = field(default_factory=dict)
    base_commit: str = ""

    # -- private git ---------------------------------------------------------------------------

    def git(self, *args: str, stdin: bytes | None = None, check: bool = True, timeout: float = 120) -> str:
        exe = shutil.which("git")
        if exe is None:
            raise ValidateError("git is required for the workspace")
        env = safe_git_env()
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = "codesift"
        env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = "codesift@localhost"
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = "2000-01-01T00:00:00Z"
        cmd = [
            exe,
            "-C",
            str(self.root),
            "-c",
            "core.hooksPath=" + str(self.root / ".git" / "no-hooks"),
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=false",
            "--no-pager",
            *args,
        ]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed git argv in our own workspace
                cmd, input=stdin, capture_output=True, timeout=timeout, env=env, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValidateError(f"git {args[0]} failed: {type(exc).__name__}") from None
        if check and proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            raise ValidateError(f"git {args[0]} failed: {(err[-1] if err else 'no details')[:200]}")
        return proc.stdout.decode("utf-8", "surrogateescape")

    def init(self) -> None:
        self.git("init", "-q", "--template=")
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "--no-verify", "-m", "codesift baseline")
        self.base_commit = self.git("rev-parse", "HEAD").strip()

    def diff(self) -> str:
        """Exact diff of the current workspace against the baseline commit."""
        self.git("add", "-A")
        return self.git(
            "diff", "--cached", "--no-color", "--no-ext-diff", "--no-textconv", "-M", self.base_commit
        )

    def changed_files(self) -> list[str]:
        self.git("add", "-A")
        out = self.git("diff", "--cached", "--name-only", "--no-renames", "-z", self.base_commit)
        return sorted(p for p in out.split("\0") if p)

    def reset(self) -> None:
        self.git("reset", "-q", "--hard", self.base_commit)
        self.git("clean", "-q", "-f", "-d", "-x")

    def apply_patch(self, patch: str) -> None:
        if not patch.strip():
            raise ValidateError("the patch is empty")
        self.git(
            "apply", "--index", "--whitespace=nowarn", "-", stdin=patch.encode("utf-8", "surrogateescape")
        )

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "--no-verify", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def tar(self, extra: dict[str, bytes] | None = None) -> bytes:
        try:
            return pack_tree(self.root, extra=extra)
        except PackError as exc:
            raise ValidateError(f"cannot pack the workspace: {exc}") from None

    def read(self, rel: str, limit: int = MAX_FILE_BYTES) -> str:
        target = (self.root / rel).resolve()
        if not target.is_relative_to(self.root.resolve()) or not target.is_file():
            raise ValidateError(f"{rel} is not a file in the workspace")
        return target.read_bytes()[:limit].decode("utf-8", "replace")


def _copy_regular(src: Path, dst: Path) -> bool:
    try:
        st = src.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as fin, dst.open("wb") as fout:
        shutil.copyfileobj(fin, fout, 65536)
    return True


def tracked_files(root: Path) -> list[str] | None:
    """Tracked files only (never untracked/ignored ones)."""
    from codesift.gitutil import git

    out = git(root, "ls-files", "-z", "--cached", "--", ".")
    if out is None:
        return None
    return sorted({p for p in out.split("\0") if p})


def create_workspace(
    project: Path,
    dest: Path,
    *,
    never_send: list[str],
    secret_paths: set[str],
    source: str = "worktree",
    ref: str = "HEAD",
) -> Workspace:
    """Copy the project into `dest` (which must not exist) and commit a private baseline.

    source="worktree": tracked files as they are now (what the scan saw).
    source="tree": the content of git `ref` (via `git archive`), e.g. HEAD before a change."""
    project = project.resolve()
    if dest.exists():
        raise ValidateError(f"workspace {dest} already exists")
    dest.mkdir(parents=True)
    ws = Workspace(root=dest)
    if source == "tree":
        _from_tree(project, ws, ref, never_send, secret_paths)
    else:
        files = tracked_files(project)
        if files is None:  # not a git repository: the scanner's file list with its excludes
            from codesift.detect import _walk, path_excluded

            files = [f for f in _walk(project) if not path_excluded(f, [])]
        if len(files) > MAX_FILES:
            raise ValidateError(f"the project has more than {MAX_FILES} files")
        for rel in files:
            reason = exclusion_reason(rel, never_send, secret_paths)
            src = project / rel
            if reason is None and src.is_symlink():
                reason = "symlink"
            if reason is None and not _copy_regular(src, dest / rel):
                reason = "not a regular file or too large"
            if reason:
                ws.excluded[rel] = reason
            else:
                ws.files.append(rel)
    ws.init()
    return ws


def _from_tree(project: Path, ws: Workspace, ref: str, never_send: list[str], secret_paths: set[str]) -> None:
    from codesift.gitutil import ref_exists

    if not ref_exists(project, ref):
        raise ValidateError(f"unknown git ref {ref!r}")
    exe = shutil.which("git")
    if exe is None:
        raise ValidateError("git is required")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, validated ref
            [exe, "-C", str(project), "--no-pager", "archive", "--format=tar", ref],
            capture_output=True,
            timeout=300,
            env=safe_git_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValidateError("git archive failed") from None
    if proc.returncode != 0:
        raise ValidateError("git archive failed")

    def accept(rel: str) -> bool:
        reason = exclusion_reason(rel, never_send, secret_paths)
        if reason:
            ws.excluded[rel] = reason
        return reason is None

    skipped: list[tuple[str, str]] = []
    try:
        ws.files = safe_unpack(
            proc.stdout, ws.root, strict=False, accept=accept, skipped=skipped, max_file=MAX_FILE_BYTES
        )
    except PackError as exc:
        raise ValidateError(f"cannot copy {ref}: {exc}") from None
    for rel, why in skipped:
        ws.excluded[rel] = why


def project_diff(project: Path, base: str = "HEAD", target: str | None = None) -> str:
    """Read-only: the project's change as a patch (working tree vs `base`, or `base`..`target`).
    Byte-exact (CRLF kept), so the patch applies to the workspace copy."""
    for ref in (base, target):
        if ref is not None and ref.startswith("-"):
            raise ValidateError("refs must not start with '-'")
    exe = shutil.which("git")
    if exe is None:
        raise ValidateError("git is required")
    args = [
        exe,
        "-C",
        str(project),
        "--no-pager",
        "diff",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "-M",
        base,
    ]
    if target is not None:
        args.append(target)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, refs checked above
            [*args, "--"], capture_output=True, timeout=120, env=safe_git_env(), check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValidateError("cannot read the project's diff") from None
    if proc.returncode != 0:
        raise ValidateError("cannot read the project's diff (is it a git repository?)")
    return proc.stdout.decode("utf-8", "surrogateescape")


def merge_base(project: Path, a: str, b: str) -> str:
    from codesift.gitutil import git

    if a.startswith("-") or b.startswith("-"):
        raise ValidateError("refs must not start with '-'")
    out = git(project, "merge-base", a, b)
    if not out:
        raise ValidateError(f"no common ancestor of {a} and {b}")
    return out.strip()


def is_git(project: Path) -> bool:
    return list_files(project) is not None
