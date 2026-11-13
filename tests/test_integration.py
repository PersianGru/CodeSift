"""End-to-end scans with the real, installed scanners on a temp copy of the fixtures.

Skipped when CodeSift's tools are not installed (`sift install`). The planted secret is
generated at test time; nothing secret-shaped is committed to this repository."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from codesift import baseline
from codesift.lockfile import LockError, active_lock_path, load_lock
from codesift.paths import Paths, get_paths
from codesift.scan import ScanOptions, scan
from codesift.tools import ToolError, resolve_tool

FIXTURES = Path(__file__).parent / "fixtures"


def _installed() -> bool:
    paths = get_paths()
    try:
        lock = load_lock(active_lock_path(paths))
        for name in lock.tools:
            resolve_tool(name, lock, paths.tools)
    except (LockError, ToolError):
        return False
    return (paths.venv / ("Scripts" if os.name == "nt" else "bin")).is_dir()


pytestmark = pytest.mark.skipif(not _installed(), reason="CodeSift tools not installed")


def _git(root: Path, *args: str) -> None:
    env = dict(os.environ)
    env.update(
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.invalid",
    )
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


def _snapshot(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file()
    }


def _files_containing(base: Path, needle: str) -> list[str]:
    hits = []
    data = needle.encode()
    for p in base.rglob("*"):
        if p.is_file() and data in p.read_bytes():
            hits.append(p.relative_to(base).as_posix())
    return hits


@pytest.fixture
def real_paths(tmp_path: Path) -> Paths:
    base = get_paths()
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    return Paths(data=base.data, config=cfg, runs=tmp_path / "runs", bin=base.bin, skill=tmp_path / "skill")


@pytest.fixture
def project(tmp_path: Path, fake_secret: Callable[[str], str]) -> tuple[Path, str]:
    root = tmp_path / "proj"
    for part in ("python", "docker", "workflow"):
        shutil.copytree(FIXTURES / part, root / part)
    _git(root.parent, "init", "-q", "-b", "main", str(root))
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "fixtures")
    secret = fake_secret("github")
    (root / "python" / "settings.py").write_text(f'GITHUB_TOKEN = "{secret}"\n', encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "oops")
    return root, secret


def test_full_scan_offline(project: tuple[Path, str], real_paths: Paths) -> None:
    root, secret = project
    before = _snapshot(root)
    outcome = scan(ScanOptions(path=str(root), no_llm=True, offline=True), real_paths)

    assert _snapshot(root) == before, "scan modified the project"
    status = {r.name: r for r in outcome.results}
    assert status["osv-scanner"].status == "skipped" and status["osv-scanner"].reason == "--offline"
    for name in ("gitleaks", "opengrep", "trivy", "ruff", "bandit", "zizmor"):
        assert status[name].status == "ok", (name, status[name].reason)

    leaks = [f for f in outcome.findings if f.tool == "gitleaks"]
    assert leaks and leaks[0].path == "python/settings.py"
    rules = {r for f in outcome.findings for r in f.rules}
    assert any("subprocess" in r or "S602" in r or "B602" in r for r in rules)
    assert any(r.startswith("trivy:") for r in rules)
    assert any(r.startswith("zizmor:") for r in rules)

    assert outcome.exit_code == 1
    assert len(outcome.summary_path.read_text(encoding="utf-8").splitlines()) <= 150
    # The planted secret must not appear anywhere CodeSift wrote.
    assert _files_containing(outcome.run_dir, secret) == []
    assert _files_containing(outcome.run_dir, secret[4:20]) == []


def test_incremental_and_baseline(project: tuple[Path, str], real_paths: Paths) -> None:
    root, secret = project
    app = root / "python" / "app.py"
    extra = "\n\ndef again(x):\n    return eval(x)\n"
    app.write_text(app.read_text(encoding="utf-8") + extra, encoding="utf-8")
    _git(root, "commit", "-q", "-am", "more eval")

    only = ["gitleaks,ruff,bandit,osv-scanner,trivy"]
    inc = scan(ScanOptions(path=str(root), no_llm=True, offline=True, since="HEAD~1", only=only), real_paths)
    status = {r.name: r for r in inc.results}
    assert status["trivy"].status == "skipped" and "changed" in status["trivy"].reason
    assert status["osv-scanner"].status == "skipped"
    assert {f.path for f in inc.findings} == {"python/app.py"}
    assert not [f for f in inc.findings if f.tool == "gitleaks"]  # the secret is older than HEAD~1

    full = scan(ScanOptions(path=str(root), no_llm=True, offline=True, only=["ruff,bandit"]), real_paths)
    target = next(f for f in full.findings if f.severity >= 3)
    baseline.accept(root, full.findings, [target.id], "test: accepted", None)
    again = scan(ScanOptions(path=str(root), no_llm=True, offline=True, only=["ruff,bandit"]), real_paths)
    match = [f for f in again.findings if target.fingerprint in f.all_fingerprints]
    assert match and match[0].baseline and match[0].baseline_reason == "test: accepted"
    assert _files_containing(real_paths.runs, secret) == []
