from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from codesift import install as inst
from codesift.config import ConfigError, load_credentials
from codesift.paths import Paths


def _src(tmp_path: Path) -> Path:
    src = tmp_path / "src-checkout"
    (src / "skill").mkdir(parents=True, exist_ok=True)
    (src / "skill" / "SKILL.md").write_text("---\nname: sift\n---\nbody\n", encoding="utf-8")
    return src


def test_shims_point_at_the_venv(paths: Paths) -> None:
    log: list[str] = []
    written = inst.install_shims(paths, log)
    sh = (paths.bin / "sift").read_text(encoding="utf-8")
    assert sh.startswith("#!/bin/sh") and '-m codesift "$@"' in sh and paths.venv.as_posix() in sh
    if os.name == "nt":
        cmd = (paths.bin / "sift.cmd").read_bytes()
        assert b"\r\n" in cmd and b"-m codesift %*" in cmd
        assert len(written) == 2


def test_skill_installed_but_foreign_skill_kept(paths: Paths, tmp_path: Path) -> None:
    log: list[str] = []
    inst.install_skill(paths, _src(tmp_path), log)
    assert "name: sift" in paths.skill_file.read_text(encoding="utf-8")
    paths.skill_file.write_text("---\nname: something-else\n---\n", encoding="utf-8")
    inst.install_skill(paths, _src(tmp_path), log)
    assert "something-else" in paths.skill_file.read_text(encoding="utf-8")
    assert "NOT installed" in log[-1]


def test_default_config_written_once(paths: Paths) -> None:
    inst.ensure_config(paths, [])
    paths.config_file.write_text("threshold = 'low'\n", encoding="utf-8")
    inst.ensure_config(paths, [])
    assert paths.config_file.read_text(encoding="utf-8") == "threshold = 'low'\n"


def test_copy_credentials(paths: Paths, tmp_path: Path, fake_secret: Callable[[str], str]) -> None:
    key = fake_secret("generic")
    other = fake_secret("generic")
    source = tmp_path / "dev.env"
    source.write_text(
        f"BIFROST_BASE_URL=https://gw.example.com/v1\nBIFROST_API_KEY={key}\nGITHUB_TOKEN={other}\n",
        encoding="utf-8",
    )
    log: list[str] = []
    inst.copy_credentials(paths, source, log)
    text = paths.gateway_file.read_text(encoding="utf-8")
    assert key in text and other not in text and "GITHUB_TOKEN" not in text
    assert "CODESIFT_LLM_API_KEY" in text
    assert key not in " ".join(log)
    creds = load_credentials(paths, env={})
    assert creds is not None and creds.api_key == key
    if os.name != "nt":
        assert paths.gateway_file.stat().st_mode & 0o777 == 0o600


def test_copy_credentials_rejects_http(paths: Paths, tmp_path: Path) -> None:
    source = tmp_path / "dev.env"
    source.write_text(
        "BIFROST_BASE_URL=http://gw.example.com/v1\nBIFROST_API_KEY=abcdefghijkl\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        inst.copy_credentials(paths, source, [])
    assert not paths.gateway_file.exists()


def test_user_path_add_remove(paths: Paths, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name != "nt":
        pytest.skip("user PATH registry handling is Windows-only")
    state = {"entries": [r"C:\Tools", r"%USERPROFILE%\bin"]}
    monkeypatch.setattr(inst, "user_path_entries", lambda: list(state["entries"]))
    monkeypatch.setattr(inst, "_set_user_path", lambda e: state.__setitem__("entries", list(e)))
    log: list[str] = []
    inst.add_to_user_path(paths.bin, log)
    inst.add_to_user_path(paths.bin, log)
    assert state["entries"].count(str(paths.bin)) == 1 and "already" in log[-1]
    inst.remove_from_user_path(paths.bin, log)
    assert state["entries"] == [r"C:\Tools", r"%USERPROFILE%\bin"]


def test_uninstall_keeps_runs_and_config_unless_purged(paths: Paths, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inst, "remove_from_user_path", lambda d, log: None)
    for d in ("venv", "tools", "lib", "rules", "cache"):
        (paths.data / d).mkdir(parents=True)
    (paths.runs / "p").mkdir(parents=True)
    inst.install_shims(paths, [])
    paths.skill.mkdir(parents=True)
    paths.skill_file.write_text("---\nname: sift\n---\n", encoding="utf-8")
    inst.ensure_config(paths, [])
    log = inst.uninstall(paths)
    assert not (paths.data / "venv").exists() and not (paths.bin / "sift").exists()
    assert not paths.skill.exists()
    assert paths.runs.exists() and paths.config_file.exists() and "--purge" in log[-1]
    inst.uninstall(paths, purge=True)
    assert not paths.runs.exists() and not paths.config.exists()
