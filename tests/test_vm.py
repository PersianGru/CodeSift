from __future__ import annotations

import io
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from codesift.paths import Paths
from codesift.vm import SandboxError
from codesift.vm import commands as vmc
from codesift.vm import transport as transport_mod
from codesift.vm.admin import (
    GATE_DENY_RC,
    admin_script,
    authorized_keys_line,
    gate_allows,
    render_gate,
    shipped_gate,
)
from codesift.vm.config import load_vm_config, render, save_vm_config
from codesift.vm.keys import HostKey, fingerprint, known_hosts_line, pinned_fingerprints
from codesift.vm.sandbox import (
    FORBIDDEN,
    LABEL,
    Sandbox,
    assert_safe,
    container_argv,
    new_job_id,
    parse_result,
    wrapper_script,
)
from codesift.vm.selftest import ensure_selftest, run_selftest
from codesift.vm.sshargs import (
    MANDATORY_OPTIONS,
    ArgError,
    build_ssh_argv,
    quote_remote,
    validate_host,
    validate_key_path,
    validate_port,
    validate_user,
)
from codesift.vm.transport import ExecResult, FakeTransport, SshTransport, clean_text
from fake_vm import IMAGE_ID, FakeVM, vm_config

SRC = Path(__file__).resolve().parents[1] / "src" / "codesift"
PUBKEY = "ssh-ed25519 " + "A" * 68 + " codesift-sandbox"

# ---------------------------------------------------------------- ssh args


@pytest.mark.parametrize(
    "host",
    ["-oProxyCommand=calc", "host name", "host\nname", "", "a;b", "$(id)", "`id`", "-v", "host\x00", "1.2.3"],
)
def test_host_injection_rejected(host: str) -> None:
    with pytest.raises(ArgError):
        validate_host(host)


@pytest.mark.parametrize("host", ["vm.example.com", "192.168.0.50", "fd00::1", "[fd00::1]", "vm-1"])
def test_host_ok(host: str) -> None:
    assert validate_host(host)


@pytest.mark.parametrize("user", ["-oX", "Root", "a b", "", "x" * 40, "u;id", "1user"])
def test_user_rejected(user: str) -> None:
    with pytest.raises(ArgError):
        validate_user(user)


@pytest.mark.parametrize("port", [0, 65536, "22x", "-1", True, None])
def test_port_rejected(port: object) -> None:
    with pytest.raises(ArgError):
        validate_port(port)  # type: ignore[arg-type]  # deliberately wrong types


def test_key_path_rules(tmp_path: Path) -> None:
    keys = tmp_path / "keys"
    keys.mkdir()
    key = keys / "k"
    key.write_text("x", encoding="utf-8")
    outside = tmp_path / "other"
    outside.write_text("x", encoding="utf-8")
    assert validate_key_path(key, [keys]) == key.resolve()
    with pytest.raises(ArgError, match="outside"):
        validate_key_path(outside, [keys])
    assert validate_key_path(outside, user_supplied=True) == outside.resolve()
    for bad in ["-oX", "relative/key", str(tmp_path / "missing"), str(keys) + '"x']:
        with pytest.raises(ArgError):
            validate_key_path(bad, [keys], user_supplied=True)


def test_ssh_argv_has_every_option(tmp_path: Path) -> None:
    argv = build_ssh_argv(
        "ssh",
        host="vm.example.com",
        port=2222,
        user="codesift",
        key_path=tmp_path / "my key",
        known_hosts=tmp_path / "kh",
        remote=["docker", "ps", "-q", "--filter", "label=codesift.job"],
    )
    opts = [argv[i + 1] for i, a in enumerate(argv) if a == "-o"]
    for option in MANDATORY_OPTIONS:
        assert option in opts
    assert any(o.startswith("UserKnownHostsFile=") for o in opts)
    assert any(o.startswith('IdentityFile="') for o in opts)  # quoted because of the space
    assert argv[argv.index("--") + 1] == "codesift@vm.example.com"
    assert argv[-1] == "docker ps -q --filter label=codesift.job"
    assert "-F" in argv and argv[argv.index("-F") + 1] == "none"
    assert argv.index("-p") < argv.index("--")


def test_quote_remote() -> None:
    assert quote_remote(["sh", "-c", "echo 'hi'; rm -rf /"]) == "sh -c 'echo '\"'\"'hi'\"'\"'; rm -rf /'"
    with pytest.raises(ArgError):
        quote_remote(["echo", "a\nb"])


def test_no_shell_true_anywhere() -> None:
    for path in SRC.rglob("*.py"):
        assert "shell=True" not in path.read_text(encoding="utf-8"), path


# ---------------------------------------------------------------- transport


def test_clean_text_strips_escapes() -> None:
    raw = b"ok\x1b[31mRED\x1b[0m \x1b]0;title\x07bell\x07\x00nul\r\nnext\x9b"
    assert clean_text(raw[:-1]) == "okRED bellnul\nnext"
    assert clean_text(raw).endswith("�")  # invalid UTF-8 is replaced, never passed through
    assert clean_text("c1\u009bend") == "c1end"
    assert clean_text("x" * 50, 10).startswith("x" * 10) and "truncated" in clean_text("x" * 50, 10)


def _stub_transport(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str) -> SshTransport:
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "k").write_text("x", encoding="utf-8")
    kh = tmp_path / "kh"
    kh.write_text("x", encoding="utf-8")
    cfg = vm_config(key_path=str(keys / "k"), known_hosts_path=str(kh))
    t = SshTransport(cfg, keys, ssh="ssh")
    monkeypatch.setattr(transport_mod, "build_ssh_argv", lambda *a, **k: [sys.executable, "-c", script])
    return t


def test_ssh_transport_caps_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    t = _stub_transport(
        tmp_path,
        monkeypatch,
        "import sys; d=sys.stdin.buffer.read(); sys.stdout.buffer.write(b'y'*500000 + d); "
        "sys.stderr.write('\\x1b[31merr\\x1b[0m')",
    )
    res = t.run(["echo"], stdin=b"INPUT", timeout=30, max_output=1000)
    assert len(res.stdout) == 1000 and res.truncated
    assert res.stderr == "err"
    assert res.returncode == 0 and not res.timed_out


def test_ssh_transport_timeout_kills(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    t = _stub_transport(tmp_path, monkeypatch, "import time; time.sleep(30)")
    res = t.run(["sleep"], timeout=1)
    assert res.timed_out and res.duration_s < 20


def test_ssh_transport_requires_pinned_host(tmp_path: Path) -> None:
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "k").write_text("x", encoding="utf-8")
    cfg = vm_config(key_path=str(keys / "k"), known_hosts_path=str(tmp_path / "missing"))
    with pytest.raises(SandboxError, match="not pinned"):
        SshTransport(cfg, keys, ssh="ssh")


# ---------------------------------------------------------------- container argv


EXPECTED_FLAGS = [
    "--rm",
    "-i",
    "--pull=never",
    "--network",
    "none",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--read-only",
    "--user",
    "65534:65534",
    "--workdir",
    "/work",
]


def test_container_argv_exact() -> None:
    cfg = vm_config()
    jid = new_job_id()
    argv = container_argv(cfg, jid, wrapper_script("pytest -q", 60, 1024))
    assert argv[:2] == ["docker", "run"]
    for flag in EXPECTED_FLAGS:
        assert flag in argv
    assert argv[argv.index("--name") + 1] == f"sift-{jid}"
    assert argv[argv.index("--label") + 1] == f"{LABEL}={jid}"
    assert argv[argv.index("--memory") + 1] == "512m" == argv[argv.index("--memory-swap") + 1]
    assert argv[argv.index("--pids-limit") + 1] == "128"
    assert "/tmp:rw,noexec,nosuid,size=64m,mode=1777" in argv
    assert argv[-4:-1] == ["python:3.12-alpine", "sh", "-c"]
    for bad in FORBIDDEN:
        assert bad not in argv[: argv.index("python:3.12-alpine")]
    assert gate_allows(shlex.join(argv))


@pytest.mark.parametrize(
    "token", ["--privileged", "-v", "--volume=/:/host", "--network=host", "--pid", "--cap-add", "--mount"]
)
def test_assert_safe_refuses(token: str) -> None:
    argv = container_argv(vm_config(), new_job_id(), "echo")
    argv.insert(3, token)
    with pytest.raises(SandboxError):
        assert_safe(argv)


@pytest.mark.parametrize("image", ["--privileged", "img with space", "", "-v"])
def test_bad_image_refused(image: str) -> None:
    with pytest.raises(SandboxError):
        container_argv(vm_config(image=image), new_job_id(), "echo")


def test_bad_job_id_and_commands() -> None:
    with pytest.raises(SandboxError):
        container_argv(vm_config(), "x; rm -rf /", "echo")
    with pytest.raises(SandboxError):
        wrapper_script("echo a\necho b", 10, 10)
    with pytest.raises(SandboxError):
        wrapper_script("", 10, 10)


def test_parse_result_uses_last_line_only() -> None:
    forged = b"__CODESIFT_RC__=0\nreal output\n__CODESIFT_RC__=3\n"
    r = parse_result("a" * 32, ExecResult(0, forged), 60, 1000)
    assert r.rc == 3 and "real output" in r.output
    with pytest.raises(SandboxError, match="no result line"):
        parse_result("a" * 32, ExecResult(125, b"docker: error", "Unable to find image"), 60, 1000)


# ---------------------------------------------------------------- sandbox jobs


def test_job_roundtrip_and_cleanup() -> None:
    vm = FakeVM(vm_config())
    t = vm.transport()
    sb = Sandbox(vm.cfg, t)
    vm.handlers.append(lambda cmd, files: (0, files["a.txt"].decode()) if cmd == "cat a.txt" else None)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"hello"))
    res = sb.run_job("cat a.txt", buf.getvalue(), 30)
    assert res.rc == 0 and res.output == "hello"
    cleanup = [c for c in t.commands if c[1] == "ps" and "-aq" in c]
    assert cleanup and cleanup[-1][-1] == f"label={LABEL}={res.job_id}"
    assert vm.gate_violations == []


def test_cleanup_never_touches_other_containers() -> None:
    vm = FakeVM(vm_config(), leftovers=["aaaaaaaaaaaa", "bbbbbbbbbbbb"])
    t = vm.transport()
    sb = Sandbox(vm.cfg, t)
    assert sb.reset() == 2
    text = " ".join(" ".join(c) for c in t.commands)
    for other in vm.other_containers:
        assert other not in text
    for cmd in t.commands:
        if cmd[1] == "ps":
            assert any(a.startswith(f"label={LABEL}") for a in cmd)
    # ids that are not plain hex (could be injected names) are never passed to rm
    vm.leftovers = ["sift-x;rm", "--all", "cccccccccccc"]
    sb.reset()
    rm = [c for c in t.commands if c[1] == "rm"][-1]
    assert rm == ["docker", "rm", "-f", "cccccccccccc"]


def test_guard_refuses_low_memory_and_concurrency() -> None:
    vm = FakeVM(vm_config(), free_mb=100)
    sb = Sandbox(vm.cfg, vm.transport())
    with pytest.raises(SandboxError, match="free memory"):
        sb.run_job("echo hi", b"", 10)
    vm.free_mb = 4096
    vm.running = ["abcdefabcdef"]
    with pytest.raises(SandboxError, match="another CodeSift job"):
        sb.run_job("echo hi", b"", 10)
    assert not vm.jobs


def test_image_must_be_pinned_and_unchanged() -> None:
    vm = FakeVM(vm_config(image_id=""))
    with pytest.raises(SandboxError, match="not pinned"):
        Sandbox(vm.cfg, vm.transport()).run_job("echo", b"", 5)
    vm = FakeVM(vm_config(), image_id="sha256:" + "cd" * 32)
    with pytest.raises(SandboxError, match="changed"):
        Sandbox(vm.cfg, vm.transport()).run_job("echo", b"", 5)


def test_fail_closed_when_ssh_down() -> None:
    vm = FakeVM(vm_config(), ssh_down=True)
    with pytest.raises(SandboxError, match="SSH connection failed"):
        Sandbox(vm.cfg, vm.transport()).run_job("echo", b"", 5)
    assert not vm.jobs


def test_host_key_mismatch_message() -> None:
    t = FakeTransport().on(
        lambda a: True,
        ExecResult(
            255, b"", "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! Host key verification failed."
        ),
    )
    with pytest.raises(SandboxError) as err:
        Sandbox(vm_config(), t).run_job("echo", b"", 5)
    assert "does not match the pinned key" in str(err.value) and "re-pin" in err.value.fix


def test_unsafe_tar_rejected_inside_container() -> None:
    from codesift.vm.selftest import evil_tar

    vm = FakeVM(vm_config())
    res = Sandbox(vm.cfg, vm.transport()).run_job("echo x", evil_tar(), 5)
    assert res.rejected and res.rc == 125


# ---------------------------------------------------------------- self-test


def test_selftest_healthy(tmp_path: Path) -> None:
    vm = FakeVM(vm_config())
    report = run_selftest(Sandbox(vm.cfg, vm.transport()))
    assert report.passed, report.lines()
    assert len(report.items) == 12
    assert vm.gate_violations == []


@pytest.mark.parametrize(
    "broken", ["start", "root", "caps", "rofs", "net", "memory", "pids", "timeout", "cap"]
)
def test_selftest_detects(broken: str) -> None:
    vm = FakeVM(vm_config(), broken={broken})
    report = run_selftest(Sandbox(vm.cfg, vm.transport()))
    assert not report.passed
    failed = [i for i in report.items if i.status == "fail"]
    assert len(failed) == 1 and failed[0].fix


def test_selftest_cleanup_and_preflight() -> None:
    vm = FakeVM(vm_config(), running=["abcdefabcdef"])
    report = run_selftest(Sandbox(vm.cfg, vm.transport()))
    assert not report.passed and report.items[0].name == "preflight"


def test_ensure_selftest_caches_and_refuses(tmp_path: Path) -> None:
    vm = FakeVM(vm_config())
    sb = Sandbox(vm.cfg, vm.transport())
    ensure_selftest(sb, tmp_path, now=1000.0)
    jobs = len(vm.jobs)
    assert ensure_selftest(sb, tmp_path, now=1300.0).cached
    assert len(vm.jobs) == jobs
    ensure_selftest(sb, tmp_path, now=1000.0 + 601)  # expired: runs again
    assert len(vm.jobs) > jobs
    bad = FakeVM(vm_config(memory_mb=1024), broken={"net"})
    with pytest.raises(SandboxError, match="self-test failed"):
        ensure_selftest(Sandbox(bad.cfg, bad.transport()), tmp_path / "other", now=5000.0)


# ---------------------------------------------------------------- gate


def test_shipped_gate_is_rendered() -> None:
    assert shipped_gate() == render_gate()


GOOD = [
    "cat /proc/meminfo",
    "docker ps -q --filter label=codesift.job",
    "podman ps -aq --filter label=codesift.job=" + "a" * 32,
    "docker rm -f abcdefabcdef 0123456789abcdef",
    "docker image inspect --format '{{.Id}}' python:3.12-alpine",
    "docker version --format '{{.Client.Version}}'",
    "docker image pull python:3.12-alpine",
    "docker build --tag sift-tools:1 -",
]
BAD = [
    "",
    "sh",
    "cat /etc/shadow",
    "cat /proc/meminfo; id",
    "docker ps",
    "docker ps -q --filter label=codesift.job; rm -rf /",
    "docker rm -f abcdefabcdef; reboot",
    "docker rm -f --all",
    "docker run --rm -i --privileged alpine sh",
    "docker exec -it x sh",
    "docker image inspect --format '{{.Id}}' $(id)",
    "docker build --tag evil -",
    "docker image pull -q evil",
    "cat /proc/meminfo\nid",
]


@pytest.mark.parametrize("cmd", GOOD)
def test_gate_allows(cmd: str) -> None:
    assert gate_allows(cmd)


@pytest.mark.parametrize("cmd", BAD)
def test_gate_denies(cmd: str) -> None:
    assert not gate_allows(cmd)


def _run_argv(**changes: str) -> str:
    argv = container_argv(vm_config(), new_job_id(), wrapper_script("pytest -q 'a b'", 60, 1024))
    line = shlex.join(argv)
    for old, new in changes.items():
        line = line.replace(old.replace("_", "-"), new)
    return line


def test_gate_run_shapes() -> None:
    assert gate_allows(_run_argv())
    line = _run_argv()
    assert not gate_allows(line.replace("--network none", "--network host"))
    assert not gate_allows(line.replace("--read-only ", ""))
    assert not gate_allows(line.replace("--cap-drop ALL", "--cap-add ALL"))
    assert not gate_allows(line.replace("--rm -i", "--rm -i -v /:/host"))
    assert not gate_allows(line + "; id")
    assert not gate_allows(line + " extra")
    assert not gate_allows(line.replace("sh -c '", "sh -c 'x' ; id; echo '"))
    assert gate_allows(line, images=["python:3.12-alpine"])
    assert not gate_allows(line, images=["other:1"])


@pytest.mark.skipif(shutil.which("sh") is None or shutil.which("grep") is None, reason="no POSIX sh")
def test_gate_script_executes_allow_and_deny(tmp_path: Path) -> None:
    gate = tmp_path / "codesift-gate"
    gate.write_text(render_gate(), encoding="utf-8", newline="\n")
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    for name in ("docker", "podman", "cat"):
        stub = stub_dir / name
        stub.write_text(f'#!/bin/sh\necho "STUB-{name} $*"\n', encoding="utf-8", newline="\n")
        stub.chmod(0o755)
    sh = shutil.which("sh")
    assert sh
    env = dict(os.environ)
    env["PATH"] = str(stub_dir) + os.pathsep + env.get("PATH", "")
    cases = [(c, True) for c in GOOD[:4]] + [(c, False) for c in BAD[1:10]] + [(_run_argv(), True)]
    for cmd, allowed in cases:
        env["SSH_ORIGINAL_COMMAND"] = cmd
        proc = subprocess.run(
            [sh, str(gate)], env=env, capture_output=True, text=True, timeout=30, check=False
        )
        if allowed:
            assert proc.returncode == 0 and "STUB-" in proc.stdout, (cmd, proc.stderr)
        else:
            assert proc.returncode == GATE_DENY_RC and "STUB-" not in proc.stdout, cmd


def test_admin_script() -> None:
    cfg = vm_config()
    text = admin_script(cfg, PUBKEY)
    assert 'restrict,command="/usr/local/bin/codesift-gate" ' + PUBKEY in text
    assert render_gate().rstrip() in text
    assert "root-equivalent" in text
    with pytest.raises(SandboxError):
        authorized_keys_line("ssh-rsa AAAA evil\ncommand=x")
    with pytest.raises(SandboxError):
        admin_script(cfg, PUBKEY + "\nssh-ed25519 AAAA")


# ---------------------------------------------------------------- config and keys


def test_vm_config_roundtrip(paths: Paths) -> None:
    cfg = vm_config(key_path=str(paths.keys_dir / "k"), known_hosts_path=str(paths.vm_known_hosts))
    save_vm_config(paths, cfg)
    loaded = load_vm_config(paths)
    assert loaded == cfg
    assert "password =" not in render(cfg).lower()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("host", "-oX"),
        ("memory_mb", 10),
        ("pids", 999999),
        ("runtime", "lxc"),
        ("image", "a b"),
        ("max_concurrent", 2),
    ],
)
def test_vm_config_invalid(paths: Paths, field: str, value: object) -> None:
    cfg = vm_config(key_path="/k", known_hosts_path="/kh")
    text = render(cfg).replace(f"{field} = ", f"{field}_old = ")
    text += f"{field} = {value!r}\n".replace("'", '"')
    paths.vm_file.write_text(text, encoding="utf-8")
    with pytest.raises(SandboxError):
        load_vm_config(paths)


def test_fingerprint_matches_ssh_keygen(tmp_path: Path) -> None:
    keygen = shutil.which("ssh-keygen")
    if keygen is None:
        pytest.skip("ssh-keygen not installed")
    key = tmp_path / "k"
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True, timeout=60)
    pub = (tmp_path / "k.pub").read_text(encoding="utf-8").split()
    out = subprocess.run([keygen, "-lf", str(tmp_path / "k.pub")], capture_output=True, text=True, check=True)
    assert fingerprint(pub[1]) == out.stdout.split()[1]
    line = known_hosts_line("vm.example.test", 2222, HostKey(pub[0], pub[1]))
    assert line.startswith("[vm.example.test]:2222 ssh-ed25519 ")
    kh = tmp_path / "kh"
    kh.write_text(line + "\n", encoding="utf-8")
    assert pinned_fingerprints(kh) == [fingerprint(pub[1])]


def test_keyscan_output_parsed_strictly(monkeypatch: pytest.MonkeyPatch) -> None:
    from codesift.vm import keys

    good = "vm ssh-ed25519 " + "A" * 68
    junk = "\x1b[31mvm ssh-ed25519 AAAA;rm\n# comment\nvm ssh-dss " + "B" * 60
    monkeypatch.setattr(keys, "_tool", lambda name: name)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, (junk + "\n" + good + "\n").encode(), b""),
    )
    found = keys.scan_host_keys("vm.example.test", 22)
    assert found == [HostKey("ssh-ed25519", "A" * 68)]


def test_host_key_falls_back_to_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows' ssh-keyscan 9.5 returns nothing for OpenSSH 10 servers; an ssh handshake that
    offers no credentials records the key into a throw-away known_hosts file instead."""
    from codesift.vm import keys

    calls: list[list[str]] = []

    def run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        if argv[0] == "ssh-keyscan":
            return subprocess.CompletedProcess(argv, 1, b"", b"choose_kex: unsupported KEX method")
        opts = dict(argv[i + 1].split("=", 1) for i, a in enumerate(argv) if a == "-o")
        if opts["HostKeyAlgorithms"] == "ssh-ed25519":
            line = "vm ssh-ed25519 " + "A" * 68
            Path(opts["UserKnownHostsFile"]).write_text(line + chr(10), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 255, b"", b"Permission denied")

    monkeypatch.setattr(keys, "_tool", lambda name: name)
    monkeypatch.setattr(keys.shutil, "which", lambda name: name)
    monkeypatch.setattr(subprocess, "run", run)
    assert keys.scan_host_keys("vm.example.test", 2222) == [HostKey("ssh-ed25519", "A" * 68)]
    ssh_calls = [c for c in calls if c[0] == "ssh"]
    assert len(ssh_calls) == 2
    for argv in ssh_calls:
        opts = dict(argv[i + 1].split("=", 1) for i, a in enumerate(argv) if a == "-o")
        assert argv[1:3] == ["-F", "none"] and "-p" in argv and argv[argv.index("-p") + 1] == "2222"
        assert opts["PreferredAuthentications"] == "none"
        assert opts["PubkeyAuthentication"] == opts["PasswordAuthentication"] == "no"
        assert opts["IdentityAgent"] == "none" and opts["ForwardAgent"] == "no"
        assert argv[-3:] == ["--", "codesift-hostkey-probe@vm.example.test", "true"]
        assert "-i" not in argv


def test_host_key_none_anywhere_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from codesift.vm import keys

    monkeypatch.setattr(keys, "_tool", lambda name: name)
    monkeypatch.setattr(keys.shutil, "which", lambda name: name)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 255, b"", b""))
    with pytest.raises(SandboxError, match="no host key"):
        keys.scan_host_keys("vm.example.test", 22)


# ---------------------------------------------------------------- commands


def _configured(paths: Paths, monkeypatch: pytest.MonkeyPatch, vm: FakeVM) -> None:
    paths.keys_dir.mkdir(parents=True, exist_ok=True)
    key = paths.keys_dir / "codesift_sandbox_ed25519"
    key.write_text("private", encoding="utf-8")
    (paths.keys_dir / "codesift_sandbox_ed25519.pub").write_text(PUBKEY + "\n", encoding="utf-8")
    paths.vm_known_hosts.write_text("vm ssh-ed25519 " + "A" * 68 + "\n", encoding="utf-8")
    vm.cfg.key_path, vm.cfg.known_hosts_path = str(key), str(paths.vm_known_hosts)
    save_vm_config(paths, vm.cfg)
    monkeypatch.setattr(vmc, "make_transport", lambda cfg, p: vm.transport())


def test_vm_commands(paths: Paths, monkeypatch: pytest.MonkeyPatch) -> None:
    vm = FakeVM(vm_config(image_id=""), leftovers=["aaaaaaaaaaaa"])
    _configured(paths, monkeypatch, vm)
    out: list[str] = []
    assert vmc.cmd_doctor(paths, out.append) == 2  # image not pinned -> refuse
    assert vmc.cmd_image_pull(paths, None, out.append) == 0
    assert load_vm_config(paths).image_id == IMAGE_ID
    out.clear()
    assert vmc.cmd_doctor(paths, out.append) == 0, out
    assert out[-1] == "self-test PASSED"
    assert vmc.cmd_status(paths, out.append) == 0
    assert vmc.cmd_reset(paths, out.append) == 0
    assert vmc.cmd_admin_script(paths, False, out.append) == 0
    assert any("codesift-gate" in line for line in out)
    dockerfile = paths.config / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-alpine\n", encoding="utf-8")
    assert vmc.cmd_image_build(paths, str(dockerfile), "evil", out.append) == 2
    assert vmc.cmd_image_build(paths, str(dockerfile), "sift-tools:1", out.append) == 0
    assert vm.gate_violations == []


def test_doctor_reports_vm_section(paths: Paths, monkeypatch: pytest.MonkeyPatch) -> None:
    from codesift.doctor import FAIL, TODO, run_checks

    checks = {c.name: c for c in run_checks(paths, env={})}
    assert checks["sandbox VM"].status == TODO
    vm = FakeVM(vm_config())
    _configured(paths, monkeypatch, vm)
    checks = {c.name: c for c in run_checks(paths, env={})}
    assert checks["sandbox VM"].status == "ok"
    assert checks["VM host key"].status == FAIL  # fingerprint not recorded in this fake config
    assert checks["VM self-test"].status == TODO
    assert "private" not in repr(checks)


def test_admin_script_is_idempotent_and_alpine_safe() -> None:
    from codesift.vm.admin import admin_script
    from codesift.vm.config import VMConfig

    text = admin_script(VMConfig(host="vm", user="codesift"), PUBKEY)
    assert "passwd -l" not in text and "chpasswd -e" in text  # locked accounts break key login on Alpine
    assert 'grep -qxF "$KEYLINE"' in text  # the key is added once, however often it runs
    assert "docker info" in text and "install_pkg docker" in text
    assert "sshd -T" in text and "set -eu" in text
    podman = admin_script(VMConfig(host="vm", user="codesift", runtime="podman"), PUBKEY)
    assert "/etc/subuid" in podman and "docker" not in podman.split("# 3.")[0].split("# 2.")[1]
