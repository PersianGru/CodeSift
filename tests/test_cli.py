from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from codesift import __version__
from codesift.cli import main
from codesift.doctor import FAIL, OK, run_checks
from codesift.paths import Paths


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_help_lists_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    out = capsys.readouterr().out
    for cmd in ("scan", "report", "baseline", "init", "hook", "update", "doctor", "install"):
        assert cmd in out


def test_hook_outside_git_repo_exits_2(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["hook", "status"]) == 2
    assert "not inside a git repository" in capsys.readouterr().err


def test_init_writes_once(tmp_path: Path) -> None:
    assert main(["init", str(tmp_path)]) == 0
    target = tmp_path / ".codesift.toml"
    assert target.is_file()
    assert b"\r\n" not in target.read_bytes()
    before = target.read_text(encoding="utf-8")
    assert main(["init", str(tmp_path)]) == 2
    assert target.read_text(encoding="utf-8") == before


def test_doctor_never_shows_key(paths: Paths, fake_secret: Callable[[str], str]) -> None:
    key = fake_secret("generic")
    paths.credentials_file.write_text(
        f"BIFROST_BASE_URL=https://gw.example.com/v1\nBIFROST_API_KEY={key}\n", encoding="utf-8"
    )
    checks = run_checks(paths, env={})
    text = repr(checks)
    assert key not in text
    creds = next(c for c in checks if c.name == "LLM gateway")
    assert creds.status == OK
    assert f"key set (len {len(key)})" in creds.detail


def test_doctor_flags_http_url(paths: Paths) -> None:
    paths.credentials_file.write_text(
        "BIFROST_BASE_URL=http://gw.example.com/v1\nBIFROST_API_KEY=abcdef1234\n", encoding="utf-8"
    )
    checks = run_checks(paths, env={})
    creds = next(c for c in checks if c.name == "LLM gateway")
    assert creds.status == FAIL
