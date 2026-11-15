"""SSH key pair generation and host-key pinning for the sandbox VM.

- `generate_key` runs `ssh-keygen -t ed25519` into CodeSift's own keys folder (no passphrase: the
  key is dedicated to the sandbox and restricted on the VM by the gate). The private key is never
  read or printed; only the public key is shown.
- `scan_host_keys` runs `ssh-keyscan`; its output is untrusted and parsed strictly. Some
  `ssh-keyscan` builds (Windows' OpenSSH 9.5) cannot talk to newer servers, so when it returns no
  key the host key is read by an `ssh` handshake that offers no credentials at all, recorded into a
  throw-away known_hosts file.
- `fingerprint` computes OpenSSH's SHA256 fingerprint locally; the user must confirm it by typing
  `yes` before it is pinned into `vm_known_hosts`."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from codesift.vm import SandboxError
from codesift.vm.sshargs import validate_host, validate_port

KEY_NAME = "codesift_sandbox_ed25519"
_KEYSCAN_LINE = re.compile(
    r"^(?P<host>\S+) (?P<type>ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) "
    r"(?P<key>[A-Za-z0-9+/]{40,2000}={0,2})$"
)


@dataclass(frozen=True)
class HostKey:
    key_type: str
    key_b64: str

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.key_b64)


def fingerprint(key_b64: str) -> str:
    try:
        raw = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        raise SandboxError("invalid host key encoding") from None
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def _tool(name: str) -> str:
    exe = shutil.which(name)
    if exe is None:
        raise SandboxError(f"`{name}` is not installed or not on PATH", fix="install the OpenSSH client")
    return exe


def generate_key(keys_dir: Path) -> tuple[Path, str]:
    """Create a new ed25519 key pair. Returns (private key path, public key line)."""
    from codesift.secrets_store import restrict, restrict_dir

    restrict_dir(keys_dir)
    private = keys_dir / KEY_NAME
    public = private.with_suffix(".pub")
    if private.exists():
        raise SandboxError(f"{private} already exists - reuse it or remove it with `sift setup --reset vm`")
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [_tool("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C", "codesift-sandbox", "-f", str(private)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0 or not private.is_file() or not public.is_file():
        raise SandboxError("ssh-keygen failed to create the key pair")
    restrict(private)  # Windows OpenSSH refuses keys with open permissions
    return private, public.read_text(encoding="utf-8").strip()


def public_key_of(private: Path) -> str:
    public = private.with_name(private.name + ".pub")
    if public.is_file():
        return public.read_text(encoding="utf-8").strip()
    raise SandboxError("public key not found next to the private key (expected <key>.pub)")


def scan_host_keys(host: str, port: int, timeout: int = 15) -> list[HostKey]:
    host = validate_host(host)
    port = validate_port(port)
    proc = subprocess.run(  # noqa: S603 - fixed argv, validated host/port, no shell
        [_tool("ssh-keyscan"), "-T", str(timeout), "-p", str(port), "-t", "ed25519,rsa", "--", host],
        capture_output=True,
        timeout=timeout + 15,
        check=False,
    )
    keys = _parse_keys(proc.stdout.decode("utf-8", "replace"))
    if not keys:
        keys = _handshake_host_keys(host, port, timeout)
    if not keys:
        raise SandboxError(
            "no host key received from the VM", fix="check host, port and that sshd is running"
        )
    return keys


def _parse_keys(text: str) -> list[HostKey]:
    keys: list[HostKey] = []
    for line in text.splitlines()[:20]:
        m = _KEYSCAN_LINE.match(line.strip())
        if m:
            keys.append(HostKey(m.group("type"), m.group("key")))
    return keys


# Host key algorithm offered -> what is recorded in known_hosts.
_HANDSHAKE_ALGS = ("ssh-ed25519", "rsa-sha2-512")


def _handshake_argv(
    ssh: str, host: str, port: int, timeout: int, alg: str, kh: Path, empty: Path
) -> list[str]:
    """`ssh` that records the server's host key and then fails auth: it offers no key, no password,
    no agent and no forwarding, and ignores the user's ssh config."""
    opts = {
        "BatchMode": "yes",
        "StrictHostKeyChecking": "accept-new",
        "UserKnownHostsFile": str(kh),
        "GlobalKnownHostsFile": str(empty),
        "HashKnownHosts": "no",
        "HostKeyAlgorithms": alg,
        "PreferredAuthentications": "none",
        "PubkeyAuthentication": "no",
        "PasswordAuthentication": "no",
        "KbdInteractiveAuthentication": "no",
        "IdentitiesOnly": "yes",
        "IdentityAgent": "none",
        "ForwardAgent": "no",
        "ClearAllForwardings": "yes",
        "ControlMaster": "no",
        "ControlPath": "none",
        "ConnectTimeout": str(timeout),
    }
    argv = [ssh, "-F", "none", "-T", "-p", str(port)]
    for k, v in opts.items():
        argv += ["-o", f"{k}={v}"]
    return [*argv, "--", f"codesift-hostkey-probe@{host}", "true"]


def _handshake_host_keys(host: str, port: int, timeout: int) -> list[HostKey]:
    ssh = shutil.which("ssh")
    if ssh is None:
        return []
    keys: list[HostKey] = []
    with tempfile.TemporaryDirectory(prefix="codesift-hk-") as tmp:
        empty = Path(tmp) / "empty"
        empty.write_text("", encoding="utf-8")
        for alg in _HANDSHAKE_ALGS:
            kh = Path(tmp) / f"kh-{alg}"
            try:
                subprocess.run(  # noqa: S603 - fixed argv, validated host/port, no shell
                    _handshake_argv(ssh, host, port, timeout, alg, kh, empty),
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    timeout=timeout + 15,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                continue
            if kh.exists():
                keys += _parse_keys(kh.read_text(encoding="utf-8", errors="replace"))
    return keys


def known_hosts_line(host: str, port: int, key: HostKey) -> str:
    host = validate_host(host)
    name = host if port == 22 else f"[{host}]:{port}"
    return f"{name} {key.key_type} {key.key_b64}"


def pin_host_key(path: Path, host: str, port: int, keys: list[HostKey]) -> str:
    from codesift.secrets_store import write_private

    lines = [known_hosts_line(host, port, k) for k in keys]
    return write_private(path, "\n".join(lines) + "\n")


def pinned_fingerprints(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 3:
            try:
                out.append(fingerprint(parts[2]))
            except SandboxError:
                continue
    return out
