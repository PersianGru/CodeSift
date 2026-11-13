from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from codesift import hook
from test_integration import _installed

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **GIT_ENV}
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, env=env, check=check, timeout=300
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    return root


def test_install_status_uninstall(repo: Path) -> None:
    log = hook.install(repo, python="/opt/py/bin/python")
    target = repo / ".git" / "hooks" / "pre-push"
    assert target.is_file() and hook.MARKER in target.read_text(encoding="utf-8")
    assert b"\r\n" not in target.read_bytes() and any("installed" in x for x in log)
    st = hook.status(repo)
    assert st.installed and not st.chained and st.python == "/opt/py/bin/python"
    hook.install(repo, python="/opt/py/bin/python")  # idempotent, no chaining of itself
    assert not (repo / ".git" / "hooks" / hook.LOCAL).exists()
    hook.uninstall(repo)
    assert not target.exists() and not hook.status(repo).installed


def test_existing_hook_is_chained_and_restored(repo: Path) -> None:
    hooks = repo / ".git" / "hooks"
    original = "#!/bin/sh\necho original\n"
    (hooks / "pre-push").write_text(original, encoding="utf-8")
    log = hook.install(repo, python="/x/python")
    assert (hooks / hook.LOCAL).read_text(encoding="utf-8") == original
    assert any("chained" in x for x in log)
    assert hook.status(repo).chained
    hook.uninstall(repo)
    assert (hooks / "pre-push").read_text(encoding="utf-8") == original
    assert not (hooks / hook.LOCAL).exists()


def test_foreign_hook_never_removed(repo: Path) -> None:
    hooks = repo / ".git" / "hooks"
    (hooks / "pre-push").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    with pytest.raises(hook.HookError, match="not installed by CodeSift"):
        hook.uninstall(repo)
    assert (hooks / "pre-push").exists()


def test_core_hooks_path_respected(repo: Path) -> None:
    git(repo, "config", "core.hooksPath", ".githooks")
    hook.install(repo, python="/x/python")
    assert (repo / ".githooks" / "pre-push").is_file()
    assert not (repo / ".git" / "hooks" / "pre-push").exists()
    assert hook.hooks_dir(repo) == (repo / ".githooks").resolve()


def test_not_a_repo(tmp_path: Path) -> None:
    with pytest.raises(hook.HookError):
        hook.status(tmp_path)


# ---------------------------------------------------------------- real pushes


def _remote(tmp_path: Path, repo: Path) -> Path:
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    git(repo, "remote", "add", "origin", str(bare))
    return bare


@pytest.mark.skipif(not _installed(), reason="CodeSift tools not installed")
def test_hook_blocks_new_high_and_allows_clean_push(tmp_path: Path, repo: Path) -> None:
    _remote(tmp_path, repo)
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    (repo / "util.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "clean")
    hooks = repo / ".git" / "hooks"
    (hooks / "pre-push").write_text(
        '#!/bin/sh\ncat > "$(dirname "$0")/../chained-stdin.txt"\nexit 0\n', encoding="utf-8"
    )
    (hooks / "pre-push").chmod(0o755)
    hook.install(repo, python=Path(sys.executable).as_posix())

    clean = git(repo, "push", "-q", "origin", "main", check=False)
    assert clean.returncode == 0, clean.stderr
    assert "refs/heads/main" in (repo / ".git" / "chained-stdin.txt").read_text(encoding="utf-8")

    (repo / "web.py").write_text(
        "import subprocess\nfrom flask import request\n\n\ndef run():\n"
        "    return subprocess.check_output('ping ' + request.args['h'], shell=True)\n",
        encoding="utf-8",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "add endpoint")
    blocked = git(repo, "push", "-q", "origin", "main", check=False)
    assert blocked.returncode != 0
    assert "push blocked" in blocked.stderr
    remote_head = git(repo, "ls-remote", "origin", "refs/heads/main").stdout.split()[0]
    assert remote_head != git(repo, "rev-parse", "HEAD").stdout.strip()


def test_hook_allows_push_when_codesift_missing(tmp_path: Path, repo: Path) -> None:
    _remote(tmp_path, repo)
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "a")
    hook.install(repo, python=(tmp_path / "no" / "python").as_posix())
    result = git(repo, "push", "-q", "origin", "main", check=False)
    assert result.returncode == 0
    assert "push allowed without a scan" in result.stderr
