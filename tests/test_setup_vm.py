from __future__ import annotations

from pathlib import Path

import pytest

from codesift import setup_wizard as sw
from codesift.vm import keys as vm_keys
from codesift.paths import Paths
from codesift.vm.config import load_vm_config
from codesift.vm.keys import HostKey
from test_setup_wizard import Script

HOSTKEY = HostKey("ssh-ed25519", "A" * 68)
PUB = "ssh-ed25519 " + "B" * 68 + " codesift-sandbox"


@pytest.fixture
def fake_ssh(monkeypatch: pytest.MonkeyPatch, paths: Paths) -> list[str]:
    calls: list[str] = []

    def keygen(keys_dir: Path) -> tuple[Path, str]:
        calls.append("keygen")
        keys_dir.mkdir(parents=True, exist_ok=True)
        key = keys_dir / "codesift_sandbox_ed25519"
        key.write_text("PRIVATE-KEY-MATERIAL", encoding="utf-8")
        key.with_suffix(".pub").write_text(PUB + "\n", encoding="utf-8")
        return key, PUB

    def keyscan(host: str, port: int, timeout: int = 15) -> list[HostKey]:
        calls.append(f"keyscan {host}:{port}")
        return [HOSTKEY]

    monkeypatch.setattr(vm_keys, "generate_key", keygen)
    monkeypatch.setattr(vm_keys, "scan_host_keys", keyscan)
    return calls


def test_vm_step_generates_key_and_pins(paths: Paths, fake_ssh: list[str]) -> None:
    answers = ["192.168.0.50", "22", "codesift", "docker", "", "y", "y", "yes", "n"]
    script = Script(answers, [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 0
    cfg = load_vm_config(paths)
    assert cfg.host == "192.168.0.50" and cfg.user == "codesift" and not cfg.key_user_supplied
    assert cfg.host_key_fingerprint == HOSTKEY.fingerprint
    assert paths.vm_known_hosts.read_text(encoding="utf-8").startswith("192.168.0.50 ssh-ed25519 ")
    assert PUB in script.text and 'restrict,command="/usr/local/bin/codesift-gate"' in script.text
    assert "PRIVATE-KEY-MATERIAL" not in script.text
    assert "keyscan 192.168.0.50:22" in fake_ssh
    assert "password" not in paths.vm_file.read_text(encoding="utf-8").replace("No password", "")


def test_vm_step_requires_literal_yes_to_pin(paths: Paths, fake_ssh: list[str]) -> None:
    answers = ["vm.example.test", "22", "codesift", "docker", "", "y", "y", "y"]  # 'y' is not 'yes'
    script = Script(answers, [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 2
    assert not paths.vm_file.exists()
    assert "not pinned" in script.text


def test_vm_step_existing_key_path(paths: Paths, fake_ssh: list[str], tmp_path: Path) -> None:
    key = tmp_path / "my_key"
    key.write_text("SECRET-KEY", encoding="utf-8")
    answers = ["vm.example.test", "2222", "codesift", "podman", "", "y", "n", str(key), "yes", "n"]
    script = Script(answers, [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 0
    cfg = load_vm_config(paths)
    assert cfg.key_user_supplied and Path(cfg.key_path) == key.resolve() and cfg.port == 2222
    assert "keygen" not in fake_ssh
    assert "SECRET-KEY" not in script.text
    assert paths.vm_known_hosts.read_text(encoding="utf-8").startswith("[vm.example.test]:2222 ")


def test_vm_step_rejects_injection_then_accepts(paths: Paths, fake_ssh: list[str]) -> None:
    answers = [
        "-oProxyCommand=calc",
        "vm.example.test",
        "22",
        "Root",
        "codesift",
        "docker",
        "",
        "y",
        "y",
        "yes",
        "n",
    ]
    script = Script(answers, [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 0
    assert "must not start with '-'" in script.text


def test_vm_rerun_keeps_key_and_pin(paths: Paths, fake_ssh: list[str]) -> None:
    first = Script(["vm.example.test", "22", "codesift", "docker", "", "y", "y", "yes", "n"], [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, first.io()) == 0
    fake_ssh.clear()
    second = Script(["", "", "", "", "", "y", "y", "y", "n"], [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, second.io()) == 0
    assert fake_ssh == []  # no new key, no new scan


def test_vm_noninteractive(paths: Paths, fake_ssh: list[str]) -> None:
    opts = sw.SetupOptions(
        parts=["vm"],
        non_interactive=True,
        vm_host="vm.example.test",
        vm_user="codesift",
        vm_pin_fingerprint="SHA256:" + "x" * 43,
    )
    script = Script([], [])
    assert sw.run_setup(opts, paths, {}, script.io()) == 2
    assert "does not match" in script.text
    opts.vm_pin_fingerprint = HOSTKEY.fingerprint
    assert sw.run_setup(opts, paths, {}, Script([], []).io()) == 0
    assert load_vm_config(paths).host_key_fingerprint == HOSTKEY.fingerprint
    opts.vm_pin_fingerprint = None
    assert sw.run_setup(opts, paths, {}, Script([], []).io()) == 2


def test_show_and_reset_vm(paths: Paths, fake_ssh: list[str]) -> None:
    sw.run_setup(
        sw.SetupOptions(parts=["vm"]),
        paths,
        {},
        Script(["vm.example.test", "22", "codesift", "docker", "", "y", "y", "yes", "n"], []).io(),
    )
    shown = "\n".join(sw.show_state(paths, {}))
    assert "codesift@vm.example.test:22" in shown and "PRIVATE" not in shown
    assert sw.run_setup(sw.SetupOptions(reset="vm"), paths, {}, Script([], []).io()) == 0
    assert not paths.vm_file.exists() and not paths.keys_dir.exists()
