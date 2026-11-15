"""Automatic VM setup from `sift setup --vm`: one SSH login as the VM's admin runs the reviewed setup
script (`admin.admin_script`) as root, then everything else uses CodeSift's own restricted key.

- The admin's password or key passphrase is typed into ssh's own prompt (and sudo's / doas's, if
  asked). CodeSift never sees, stores or passes it: ssh runs attached to the console.
- The admin's key file is only passed to ssh as a path; it is never read.
- The connection trusts only the host key the user just confirmed (StrictHostKeyChecking=yes against
  CodeSift's pinned known_hosts), ignores the user's ssh config and forwards nothing.
- The script travels base64-encoded inside the remote command and is piped into `sh -s` under sudo or
  doas when the admin is not root, so no temporary file is written on the VM."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from codesift.vm import SandboxError
from codesift.vm.sshargs import ArgError, option_path, validate_host, validate_key_path, validate_port

# Admin accounts are usually ordinary names (root, ubuntu, ec2-user, pi, admin...): same rule as
# CodeSift's own user plus a dot, which some distros allow.
_ADMIN_OK = set("abcdefghijklmnopqrstuvwxyz0123456789_-.")
NO_ROOT_RC = 3
MAX_SCRIPT = 24000  # bytes; keeps the remote command far below every OS command-line limit

COMMON_KEYS = ("id_ed25519", "id_ecdsa", "id_rsa")


def default_ssh_dir() -> Path:
    """The user's SSH folder on every OS: %USERPROFILE%\\.ssh on Windows, ~/.ssh on macOS/Linux/BSD."""
    if sys.platform == "win32":
        profile = os.environ.get("USERPROFILE")
        if profile:
            return Path(profile) / ".ssh"
    return Path.home() / ".ssh"


def find_admin_key(ssh_dir: Path | None = None) -> Path | None:
    """The first usual private key that exists (only its existence is checked; it is never read)."""
    folder = ssh_dir or default_ssh_dir()
    for name in COMMON_KEYS:
        candidate = folder / name
        if candidate.is_file():
            return candidate
    return None


def validate_admin_user(name: str) -> str:
    if not name or name.startswith(("-", ".")) or len(name) > 32 or not set(name) <= _ADMIN_OK:
        raise ArgError("admin user must be a plain user name (letters, digits, '_', '-', '.')")
    return name


@dataclass(frozen=True)
class AdminLogin:
    host: str
    port: int
    user: str
    key_path: Path | None  # None = password (typed into ssh's own prompt)


def remote_command(script: str) -> str:
    """POSIX sh run by the admin's login shell: become root (already root, sudo or doas) and feed the
    script to `sh -s`. Every interpolated value is base64, so nothing in it can break the quoting."""
    data = script.encode("utf-8")
    if len(data) > MAX_SCRIPT:
        raise SandboxError("the VM setup script is unexpectedly large")
    b64 = base64.b64encode(data).decode("ascii")
    return (
        'S=; if [ "$(id -u)" != 0 ]; then '
        "if command -v sudo >/dev/null 2>&1; then S=sudo; "
        "elif command -v doas >/dev/null 2>&1; then S=doas; "
        "else echo 'codesift: this account is not root and has neither sudo nor doas' >&2; "
        f"exit {NO_ROOT_RC}; "
        "fi; fi; "
        f"printf %s '{b64}' | base64 -d | $S sh -s"
    )


def admin_argv(ssh: str, login: AdminLogin, known_hosts: Path, script: str) -> list[str]:
    host = validate_host(login.host)
    port = validate_port(login.port)
    user = validate_admin_user(login.user)
    opts = [
        "StrictHostKeyChecking=yes",
        f"UserKnownHostsFile={option_path(known_hosts)}",
        "GlobalKnownHostsFile=none",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "ConnectTimeout=15",
        "ServerAliveInterval=15",
        "ServerAliveCountMax=4",
        "NumberOfPasswordPrompts=3",
        "LogLevel=ERROR",
    ]
    if login.key_path is not None:
        key = validate_key_path(login.key_path, user_supplied=True)
        opts += [
            "IdentitiesOnly=yes",
            f"IdentityFile={option_path(key)}",
            "PreferredAuthentications=publickey",
            "PasswordAuthentication=no",
        ]
    else:
        opts += [
            "PubkeyAuthentication=no",
            "PreferredAuthentications=keyboard-interactive,password",
        ]
    argv = [ssh, "-F", "none", "-t"]  # a terminal, so sudo/doas can ask for a password
    for option in opts:
        argv += ["-o", option]
    return [*argv, "-p", str(port), "--", f"{user}@{host}", remote_command(script)]


def _run_attached(argv: list[str]) -> int:
    env = {k: v for k, v in os.environ.items() if k not in ("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY")}
    try:
        # Attached to the console on purpose: the user types passwords into ssh/sudo, not into CodeSift.
        return subprocess.run(argv, env=env, timeout=900, check=False).returncode  # noqa: S603
    except subprocess.TimeoutExpired:
        return 124


runner: Callable[[list[str]], int] = _run_attached


def run_admin_setup(login: AdminLogin, known_hosts: Path, script: str) -> None:
    ssh = shutil.which("ssh")
    if ssh is None:
        raise SandboxError("the `ssh` client is not installed or not on PATH", fix="install OpenSSH")
    try:
        argv = admin_argv(ssh, login, known_hosts, script)
    except ArgError as exc:
        raise SandboxError(f"unsafe SSH argument: {exc}") from None
    rc = runner(argv)
    if rc == 0:
        return
    if rc == NO_ROOT_RC:
        raise SandboxError(
            f"{login.user} is not root and has no sudo or doas on the VM",
            fix="use root or an account that can use sudo",
        )
    if rc == 255:
        raise SandboxError(
            f"could not log in as {login.user}@{login.host}",
            fix="check the admin user name, password or key, and that SSH accepts it",
        )
    if rc == 124:
        raise SandboxError("the VM setup did not finish within 15 minutes")
    raise SandboxError(
        f"the VM setup script stopped with exit code {rc} (its messages are above)",
        fix="fix what it reports and run `sift setup --vm` again - it is safe to repeat",
    )
