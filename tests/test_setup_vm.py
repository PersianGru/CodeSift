from __future__ import annotations

import base64
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from codesift import setup_wizard as sw
from codesift.paths import Paths
from codesift.vm import SandboxError, bootstrap
from codesift.vm import commands as vm_commands
from codesift.vm import keys as vm_keys
from codesift.vm.config import load_vm_config, save_vm_config
from codesift.vm.keys import HostKey
from codesift.vm.sshargs import ArgError
from test_setup_wizard import Script

HOSTKEY = HostKey("ssh-ed25519", "A" * 68)
PUB = "ssh-ed25519 " + "B" * 68 + " codesift-sandbox"


@dataclass
class Fake:
    calls: list[str]
    admin_argv: list[list[str]]
    ssh_dir: Path
    admin_rc: int = 0
    doctor_ok: bool = True


@pytest.fixture
def fake_ssh(monkeypatch: pytest.MonkeyPatch, paths: Paths, tmp_path: Path) -> Fake:
    ssh_dir = tmp_path / "user-ssh"
    fake = Fake([], [], ssh_dir)

    def keygen(keys_dir: Path) -> tuple[Path, str]:
        fake.calls.append(f"keygen {keys_dir}")
        keys_dir.mkdir(parents=True, exist_ok=True)
        key = keys_dir / vm_keys.KEY_NAME
        key.write_text("PRIVATE-KEY-MATERIAL", encoding="utf-8")
        key.with_name(key.name + ".pub").write_text(PUB + "\n", encoding="utf-8")
        return key, PUB

    def keyscan(host: str, port: int, timeout: int = 15) -> list[HostKey]:
        fake.calls.append(f"keyscan {host}:{port}")
        return [HOSTKEY]

    def runner(argv: list[str]) -> int:
        fake.admin_argv.append(argv)
        return fake.admin_rc

    def pull(p: Paths, ref: str | None, out: Callable[[str], None]) -> int:
        fake.calls.append("pull")
        cfg = load_vm_config(p)
        cfg.image_id = "sha256:" + "a" * 64
        save_vm_config(p, cfg)
        return 0

    def doctor(p: Paths) -> list[str]:
        fake.calls.append("doctor")
        return ["[ok  ] connection"] + (["self-test PASSED"] if fake.doctor_ok else ["self-test FAILED"])

    monkeypatch.setattr(vm_keys, "generate_key", keygen)
    monkeypatch.setattr(vm_keys, "scan_host_keys", keyscan)
    monkeypatch.setattr(bootstrap, "runner", runner)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "ssh")
    monkeypatch.setattr(bootstrap, "default_ssh_dir", lambda: ssh_dir)
    monkeypatch.setattr(vm_commands, "cmd_image_pull", pull)
    monkeypatch.setattr(vm_commands, "doctor_lines", doctor)
    return fake


def _admin_script_of(argv: list[str]) -> str:
    b64 = re.search(r"printf %s '([A-Za-z0-9+/=]+)' \| base64 -d", argv[-1])
    assert b64, argv[-1]
    return base64.b64decode(b64.group(1)).decode()


def test_vm_step_password_admin_does_everything(paths: Paths, fake_ssh: Fake) -> None:
    # host, port, pin, admin user, password, key folder (Enter = the user's SSH folder)
    answers = ["192.168.0.50", "", "yes", "", "password", ""]
    script = Script(answers, [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 0, script.text
    cfg = load_vm_config(paths)
    assert cfg.host == "192.168.0.50" and cfg.user == "codesift" and not cfg.key_user_supplied
    assert Path(cfg.key_path) == fake_ssh.ssh_dir / vm_keys.KEY_NAME
    assert cfg.host_key_fingerprint == HOSTKEY.fingerprint and cfg.image_id
    assert fake_ssh.calls[-2:] == ["pull", "doctor"]
    [argv] = fake_ssh.admin_argv
    opts = [argv[i + 1] for i, a in enumerate(argv) if a == "-o"]
    assert "PubkeyAuthentication=no" in opts and "StrictHostKeyChecking=yes" in opts
    assert "ForwardAgent=no" in opts and not any(o.startswith("IdentityFile") for o in opts)
    assert argv[1:4] == ["-F", "none", "-t"] and argv[-2] == "root@192.168.0.50"
    remote = _admin_script_of(argv)
    assert "U='codesift'" in remote and PUB.rsplit(" ", 1)[0] in remote
    assert 'command="/usr/local/bin/codesift-gate"' in remote
    assert "PRIVATE-KEY-MATERIAL" not in script.text + " ".join(argv)
    assert "self-test passed" in script.text


def test_vm_step_key_admin(paths: Paths, fake_ssh: Fake, tmp_path: Path) -> None:
    fake_ssh.ssh_dir.mkdir()
    admin_key = fake_ssh.ssh_dir / "id_ed25519"
    admin_key.write_text("ADMIN-SECRET-KEY", encoding="utf-8")
    store = tmp_path / "keys elsewhere"
    # host, port, pin, admin user, how (Enter = key, found), key path (Enter = found), folder
    answers = ["vm.example.test", "2222", "yes", "ubuntu", "", "", str(store)]
    script = Script(answers, [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 0, script.text
    [argv] = fake_ssh.admin_argv
    opts = [argv[i + 1] for i, a in enumerate(argv) if a == "-o"]
    assert "IdentitiesOnly=yes" in opts and "PreferredAuthentications=publickey" in opts
    assert any(o.startswith("IdentityFile=") and "id_ed25519" in o for o in opts)
    assert argv[-2] == "ubuntu@vm.example.test" and argv[argv.index("-p") + 1] == "2222"
    assert "ADMIN-SECRET-KEY" not in script.text
    assert Path(load_vm_config(paths).key_path) == store / vm_keys.KEY_NAME
    assert paths.vm_known_hosts.read_text(encoding="utf-8").startswith("[vm.example.test]:2222 ")


def test_vm_step_reuses_existing_key_in_folder(paths: Paths, fake_ssh: Fake) -> None:
    fake_ssh.ssh_dir.mkdir()
    (fake_ssh.ssh_dir / vm_keys.KEY_NAME).write_text("PRIVATE-KEY-MATERIAL", encoding="utf-8")
    (fake_ssh.ssh_dir / (vm_keys.KEY_NAME + ".pub")).write_text(PUB + chr(10), encoding="utf-8")
    script = Script(["192.168.0.50", "", "yes", "", "password", ""], [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 0
    assert not any(c.startswith("keygen") for c in fake_ssh.calls)
    assert "using the existing key" in script.text


def test_vm_step_requires_literal_yes_to_pin(paths: Paths, fake_ssh: Fake) -> None:
    script = Script(["vm.example.test", "22", "y"], [])  # 'y' is not 'yes'
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 2
    assert not paths.vm_file.exists() and fake_ssh.admin_argv == []
    assert "not pinned" in script.text


def test_vm_step_admin_failure_saves_nothing(paths: Paths, fake_ssh: Fake) -> None:
    fake_ssh.admin_rc = bootstrap.NO_ROOT_RC
    script = Script(["192.168.0.50", "", "yes", "pi", "password", ""], [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 2
    assert "not root and has no sudo or doas" in script.text
    assert not paths.vm_file.exists()
    fake_ssh.admin_rc = 255
    script = Script(["192.168.0.50", "", "yes", "", "password", ""], [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 2
    assert "could not log in as root@192.168.0.50" in script.text


def test_vm_step_rejects_injection_then_accepts(paths: Paths, fake_ssh: Fake) -> None:
    answers = [
        "-oProxyCommand=calc",
        "vm.example.test",
        "22",
        "yes",
        "-oProxyCommand=x",
        "root",
        "pw",
        "password",
        "",
    ]
    script = Script(answers, [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 0, script.text
    assert "must not start with '-'" in script.text and "type key or password" in script.text
    assert all("ProxyCommand" not in a for a in fake_ssh.admin_argv[0])


def test_vm_rerun_only_rechecks(paths: Paths, fake_ssh: Fake) -> None:
    first = Script(["vm.example.test", "22", "yes", "", "password", ""], [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, first.io()) == 0
    fake_ssh.calls.clear()
    fake_ssh.admin_argv.clear()
    second = Script([""], [])  # "Only re-check it?" -> yes
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, second.io()) == 0
    assert fake_ssh.calls == ["doctor"] and fake_ssh.admin_argv == []


def test_vm_failed_selftest_is_reported(paths: Paths, fake_ssh: Fake) -> None:
    fake_ssh.doctor_ok = False
    script = Script(["vm.example.test", "22", "yes", "", "password", ""], [])
    sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io())
    assert "self-test FAILED" in script.text


def test_remote_command_is_quoted_and_becomes_root() -> None:
    cmd = bootstrap.remote_command("echo 'it''s' $HOME `x`\n")
    assert cmd.count("'") % 2 == 0 and "$HOME" not in cmd and "`" not in cmd
    assert "sudo" in cmd and "doas" in cmd and cmd.endswith("| base64 -d | $S sh -s")
    with pytest.raises(SandboxError):
        bootstrap.remote_command("x" * (bootstrap.MAX_SCRIPT + 1))


def test_admin_user_validation() -> None:
    for good in ("root", "ec2-user", "first.last", "pi"):
        assert bootstrap.validate_admin_user(good) == good
    for bad in ("", "-oProxyCommand=x", "a b", "root;id", ".hidden", "x" * 33, "Root"):
        with pytest.raises(ArgError):
            bootstrap.validate_admin_user(bad)


def test_vm_noninteractive(paths: Paths, fake_ssh: Fake) -> None:
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


def test_show_and_reset_vm(paths: Paths, fake_ssh: Fake) -> None:
    script = Script(["vm.example.test", "22", "yes", "", "password", ""], [])
    assert sw.run_setup(sw.SetupOptions(parts=["vm"]), paths, {}, script.io()) == 0
    shown = "\n".join(sw.show_state(paths, {}))
    assert "codesift@vm.example.test:22" in shown and "PRIVATE" not in shown
    key = fake_ssh.ssh_dir / vm_keys.KEY_NAME
    other = fake_ssh.ssh_dir / "id_ed25519"
    other.write_text("users own key", encoding="utf-8")
    assert sw.run_setup(sw.SetupOptions(reset="vm"), paths, {}, Script([], []).io()) == 0
    assert not paths.vm_file.exists() and not key.exists() and other.exists()
