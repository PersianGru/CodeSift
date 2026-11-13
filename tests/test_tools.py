from __future__ import annotations

import json
from pathlib import Path

import pytest

from codesift import tools
from codesift.lockfile import LockError, load_lock, parse_lock, save_lock
from codesift.net import NetworkError
from codesift.tools import MANIFEST, ToolError, install_tool, parse_checksums, resolve_tool
from helpers import FakeDownloads, lock_with, make_tgz, make_zip, sha

BINARY = b"\x7fELF fake scanner binary"


def test_install_from_zip_and_verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = make_zip({"README.md": b"readme", "gitleaks.exe": BINARY})
    lock = lock_with("gitleaks", "gitleaks/gitleaks", "8.0.0", "windows-x64", "g.zip", archive)
    fake = FakeDownloads({lock.tools["gitleaks"].platforms["windows-x64"].url: archive})
    monkeypatch.setattr(tools, "download", fake)

    path = install_tool("gitleaks", lock, tmp_path, "windows-x64")
    assert path.read_bytes() == BINARY
    manifest = json.loads((path.parent / MANIFEST).read_text(encoding="utf-8"))
    assert manifest["binary_sha256"] == sha(BINARY)
    assert not (path.parent / "README.md").exists()
    # idempotent: second call verifies and does not download again
    install_tool("gitleaks", lock, tmp_path, "windows-x64")
    assert len(fake.calls) == 1


def test_tar_extraction_ignores_traversal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = make_tgz({"../../evil": b"x", "/abs/evil": b"y", "dir/trivy": BINARY})
    lock = lock_with("trivy", "aquasecurity/trivy", "0.1.0", "linux-x64", "t.tar.gz", archive)
    monkeypatch.setattr(
        tools, "download", FakeDownloads({lock.tools["trivy"].platforms["linux-x64"].url: archive})
    )
    path = install_tool("trivy", lock, tmp_path / "tools", "linux-x64")
    assert path.read_bytes() == BINARY
    assert not (tmp_path / "evil").exists()
    written = sorted(p.name for p in path.parent.iterdir())
    assert written == sorted([MANIFEST, "trivy"])


def test_archive_without_binary_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = make_zip({"other.exe": BINARY})
    lock = lock_with("gitleaks", "gitleaks/gitleaks", "8.0.0", "windows-x64", "g.zip", archive)
    monkeypatch.setattr(
        tools, "download", FakeDownloads({lock.tools["gitleaks"].platforms["windows-x64"].url: archive})
    )
    with pytest.raises(ToolError, match="expected one"):
        install_tool("gitleaks", lock, tmp_path, "windows-x64")


def test_checksum_mismatch_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lock = lock_with("osv-scanner", "google/osv-scanner", "2.0.0", "linux-x64", "osv", BINARY)
    url = lock.tools["osv-scanner"].platforms["linux-x64"].url
    monkeypatch.setattr(tools, "download", FakeDownloads({url: BINARY + b"tampered"}))
    with pytest.raises(NetworkError, match="checksum mismatch"):
        install_tool("osv-scanner", lock, tmp_path, "linux-x64")
    assert not (tmp_path / "osv-scanner" / "2.0.0").exists()


def test_tampered_binary_refused_at_run_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lock = lock_with("osv-scanner", "google/osv-scanner", "2.0.0", "linux-x64", "osv", BINARY)
    url = lock.tools["osv-scanner"].platforms["linux-x64"].url
    monkeypatch.setattr(tools, "download", FakeDownloads({url: BINARY}))
    path = install_tool("osv-scanner", lock, tmp_path, "linux-x64")
    assert resolve_tool("osv-scanner", lock, tmp_path, "linux-x64") == path
    path.write_bytes(BINARY + b"backdoor")
    with pytest.raises(ToolError, match="refusing to run"):
        resolve_tool("osv-scanner", lock, tmp_path, "linux-x64")


def test_lock_change_invalidates_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lock = lock_with("osv-scanner", "google/osv-scanner", "2.0.0", "linux-x64", "osv", BINARY)
    url = lock.tools["osv-scanner"].platforms["linux-x64"].url
    monkeypatch.setattr(tools, "download", FakeDownloads({url: BINARY}))
    install_tool("osv-scanner", lock, tmp_path, "linux-x64")
    lock.tools["osv-scanner"].platforms["linux-x64"].sha256 = "0" * 64
    with pytest.raises(ToolError, match="does not match the lock"):
        resolve_tool("osv-scanner", lock, tmp_path, "linux-x64")


def test_not_installed(tmp_path: Path) -> None:
    lock = lock_with("trivy", "aquasecurity/trivy", "0.1.0", "linux-x64", "t", BINARY)
    with pytest.raises(ToolError, match="not installed"):
        resolve_tool("trivy", lock, tmp_path, "linux-x64")


def test_parse_checksums() -> None:
    a, b = "a" * 64, "B" * 64
    text = f"{a}  tool_linux.tar.gz\n{b} *tool_windows.zip\ngarbage\n"
    assert parse_checksums(text) == {"tool_linux.tar.gz": a, "tool_windows.zip": "b" * 64}


# ---------------------------------------------------------------- lock file


def test_lock_roundtrip(tmp_path: Path) -> None:
    lock = lock_with("trivy", "aquasecurity/trivy", "0.1.0", "linux-x64", "t", BINARY)
    lock.python = {"ruff": "0.1.0"}
    path = tmp_path / "tools.lock.json"
    save_lock(lock, path)
    again = load_lock(path)
    assert again.tools["trivy"].platforms["linux-x64"].sha256 == sha(BINARY)
    assert again.python == {"ruff": "0.1.0"}
    assert b"\r\n" not in path.read_bytes()


def test_lock_rejects_foreign_url_and_bad_sha() -> None:
    good = json.loads(lock_with("trivy", "aquasecurity/trivy", "0.1.0", "linux-x64", "t", BINARY).to_json())
    bad_url = json.loads(json.dumps(good))
    bad_url["tools"]["trivy"]["platforms"]["linux-x64"]["url"] = "https://evil.example/t"
    with pytest.raises(LockError, match="url must start with"):
        parse_lock(bad_url)
    bad_sha = json.loads(json.dumps(good))
    bad_sha["tools"]["trivy"]["platforms"]["linux-x64"]["sha256"] = "xyz"
    with pytest.raises(LockError, match="sha256"):
        parse_lock(bad_sha)
    with pytest.raises(LockError):
        parse_lock({"schema": 2})


def test_repo_lock_is_valid_and_complete() -> None:
    root = Path(__file__).resolve().parents[1]
    lock = load_lock(root / "tools.lock.json")
    assert set(lock.tools) == set(tools.TOOL_SPECS)
    for tool in lock.tools.values():
        assert set(tool.platforms) == {"windows-x64", "linux-x64", "linux-arm64", "darwin-arm64"}
    assert lock.rules is not None and len(lock.rules.commit) == 40
    assert {"ruff", "bandit", "pip-audit", "zizmor"} <= set(lock.python)
