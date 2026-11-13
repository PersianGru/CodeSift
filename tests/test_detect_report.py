from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from codesift.detect import detect, path_excluded
from codesift.finding import Finding, fingerprint
from codesift.gitutil import SAFE_CONFIG, safe_git_env
from codesift.models import Severity
from codesift.report import RunInfo, project_slug, render_summary, write_report
from codesift.runners.base import RunResult
from codesift.scan import select_runners


def _touch(root: Path, rel: str, text: str = "x\n") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_detect_ecosystems_and_excludes(tmp_path: Path) -> None:
    for rel in (
        "app.py",
        "web/index.ts",
        "web/package-lock.json",
        "api/index.php",
        "svc/go.mod",
        "Dockerfile",
        "compose.yaml",
        ".github/workflows/ci.yml",
        "node_modules/lib/index.js",
        "vendor/x/y.php",
        "build/out.py",
        "docs/skip/me.go",
    ):
        _touch(tmp_path, rel)
    det = detect(tmp_path, ["docs/skip/**"])
    assert {
        "python",
        "js",
        "php",
        "go",
        "docker",
        "compose",
        "actions",
        "deps",
        "iac",
        "yaml",
    } <= det.ecosystems
    assert "node_modules/lib/index.js" not in det.files
    assert "vendor/x/y.php" not in det.files
    assert "docs/skip/me.go" not in det.files


def test_path_excluded_rules() -> None:
    assert path_excluded("a/node_modules/b.js", [])
    assert not path_excluded("tests/test_a.py", [])
    assert path_excluded("tests/test_a.py", [], exclude_tests=True)
    assert path_excluded("pkg/a_test.go", [], exclude_tests=True)
    assert path_excluded("gen/x.py", ["gen/**"])
    assert path_excluded("deep/gen/x.py", ["gen"])
    assert not path_excluded("src/app.py", ["gen/**"])


def test_safe_git_env_disables_repo_hooks() -> None:
    env = safe_git_env({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "a.b", "GIT_CONFIG_VALUE_0": "c"})
    keys = {env[f"GIT_CONFIG_KEY_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert set(SAFE_CONFIG) <= keys and "a.b" in keys
    assert env["GIT_OPTIONAL_LOCKS"] == "0"


def test_select_runners() -> None:
    runners, off = select_runners([], ["trivy"], ["pip-audit"], ["zizmor"])
    names = [r.name for r in runners]
    assert "trivy" not in names and off["trivy"] == "--skip"
    assert "pip-audit" in names and "zizmor" not in names and "composer-audit" in off
    only, off2 = select_runners(["gitleaks", "govulncheck"], [], [], [])
    assert [r.name for r in only] == ["gitleaks", "govulncheck"] and off2 == {}


def _finding(i: int, sev: Severity) -> Finding:
    x = Finding(
        tool="bandit",
        rule=f"B{i:03d}",
        severity=sev,
        path=f"src/m{i}.py",
        line=i,
        message="m" * 300,
        fingerprint=fingerprint("bandit", str(i), "p", str(i)),
    )
    x.id = f"F{i:03d}"
    return x


def test_summary_stays_short(tmp_path: Path) -> None:
    findings = [_finding(i, Severity.HIGH if i % 3 else Severity.MEDIUM) for i in range(1, 200)]
    findings += [_finding(i, Severity.LOW) for i in range(200, 260)]
    info = RunInfo(
        root=tmp_path,
        started=datetime.now(UTC),
        duration_s=3,
        mode="full",
        threshold=Severity.HIGH,
        warnings=["w1"],
        errors=["e1"],
    )
    results = [
        RunResult(name="bandit", version="1"),
        RunResult(name="trivy", status="skipped", reason="none"),
    ]
    text = render_summary(info, results, findings, tmp_path / "report.json")
    lines = text.splitlines()
    assert len(lines) <= 150
    assert "more finding(s) not shown" in text
    assert "Low/info findings (60)" in text
    assert "## Errors" in text and "trivy (none)" in text
    assert "## Not triaged" not in text  # LLM did not run
    path = write_report(tmp_path, info, results, findings)
    assert path.read_bytes().count(b"\r\n") == 0


def test_project_slug_is_stable(tmp_path: Path) -> None:
    assert project_slug(tmp_path) == project_slug(tmp_path / ".")
    assert project_slug(tmp_path).startswith(tmp_path.name[:10])


def test_post_filter_drops_git_ignored_files() -> None:
    from codesift.normalize import HIDDEN  # noqa: F401  (import check only)
    from codesift.runners.python import Bandit
    from codesift.scan import _post_filter

    def mk(path: str, tool: str = "bandit", source: str = "") -> Finding:
        x = Finding(
            tool=tool,
            rule="B1",
            severity=Severity.HIGH,
            path=path,
            line=1,
            message="m",
            fingerprint=fingerprint(tool, "B1", path, "x"),
            extra={"source": source},
        )
        return x

    findings = [mk("src/a.py"), mk(".local/patch.py"), mk("old/secret.txt", "gitleaks", "history")]
    kept = _post_filter(Bandit, findings, [], {"src/a.py"})
    assert [f.path for f in kept] == ["src/a.py", "old/secret.txt"]
    assert len(_post_filter(Bandit, findings, [], None)) == 3


def test_unlocked_manifests() -> None:
    from codesift.detect import unlocked_manifests

    files = [
        "backend/pyproject.toml",
        "web/package.json",
        "web/package-lock.json",
        "tools/pyproject.toml",
        "tools/uv.lock",
        "package.json",
        "php/composer.json",
    ]
    assert unlocked_manifests(files) == ["backend/pyproject.toml", "package.json", "php/composer.json"]


def test_unlocked_manifests_skips_manifests_without_dependencies(tmp_path: Path) -> None:
    from codesift.detect import unlocked_manifests

    (tmp_path / "lib").mkdir()
    (tmp_path / "app").mkdir()
    (tmp_path / "lib" / "pyproject.toml").write_text('[project]\nname = "lib"\n', encoding="utf-8")
    (tmp_path / "app" / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["httpx>=0.27"]\n', encoding="utf-8"
    )
    (tmp_path / "package.json").write_text('{"name": "x", "scripts": {}}', encoding="utf-8")
    (tmp_path / "composer.json").write_text('{"require": {"php": ">=8.2"}}', encoding="utf-8")
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "package.json").write_text("{not json", encoding="utf-8")
    files = [
        "lib/pyproject.toml",
        "app/pyproject.toml",
        "package.json",
        "composer.json",
        "broken/package.json",
    ]
    assert unlocked_manifests(files, tmp_path) == ["app/pyproject.toml", "broken/package.json"]
