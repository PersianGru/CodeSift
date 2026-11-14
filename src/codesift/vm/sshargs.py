"""Strict validators and the SSH argv builder. Nothing user- or VM-supplied can become an ssh option:
every value is checked, the destination follows `--`, and every remote word is shlex-quoted."""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Sequence
from pathlib import Path

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_BAD = re.compile(r"[\s\x00-\x1f\x7f]")
_PATH_BAD = re.compile(r"[\x00-\x1f\x7f\"]")

# Mandatory options, in this order, on every connection (ADR-0012).
MANDATORY_OPTIONS = (
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "IdentitiesOnly=yes",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ClearAllForwardings=yes",
    "RequestTTY=no",
    "ConnectTimeout=10",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=3",
    "LogLevel=ERROR",
)


class ArgError(ValueError):
    """A value would be unsafe on an ssh command line."""


def _plain(value: str, what: str) -> str:
    if not value:
        raise ArgError(f"{what} is empty")
    if value.startswith("-"):
        raise ArgError(f"{what} must not start with '-'")
    if _BAD.search(value):
        raise ArgError(f"{what} must not contain whitespace or control characters")
    return value


def validate_host(host: str) -> str:
    _plain(host, "VM host")
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    if not _HOSTNAME.match(host) or host.replace(".", "").isdigit():
        raise ArgError("VM host must be a host name or an IP address")
    return host


def validate_user(user: str) -> str:
    _plain(user, "VM user")
    if not _USER.match(user):
        raise ArgError("VM user must match ^[a-z_][a-z0-9_-]{0,31}$")
    return user


def validate_port(port: int | str) -> int:
    if isinstance(port, bool):
        raise ArgError("SSH port must be a number")
    try:
        value = int(port)
    except (TypeError, ValueError):
        raise ArgError("SSH port must be a number") from None
    if not 1 <= value <= 65535:
        raise ArgError("SSH port must be between 1 and 65535")
    return value


def validate_key_path(
    path: str | Path, allowed_dirs: Sequence[Path] = (), user_supplied: bool = False
) -> Path:
    """The key must exist and be a regular file. Unless the user typed the path themselves, it must lie
    inside one of `allowed_dirs` (CodeSift's own keys folder). Its content is never read."""
    text = str(path)
    if not text or text.startswith("-") or _PATH_BAD.search(text):
        raise ArgError("key path is empty, starts with '-' or contains quotes/control characters")
    p = Path(text).expanduser()
    if not p.is_absolute():
        raise ArgError("key path must be absolute")
    if not p.is_file() or p.is_symlink():
        raise ArgError("key path is not a regular file")
    resolved = p.resolve()
    if not user_supplied and not any(resolved.is_relative_to(d.resolve()) for d in allowed_dirs):
        raise ArgError("key path is outside CodeSift's keys folder")
    return resolved


def quote_remote(argv: Sequence[str]) -> str:
    """One remote command line, every word quoted (the remote side runs it through `sh`)."""
    if not argv:
        raise ArgError("empty remote command")
    for word in argv:
        if "\n" in word or "\r" in word or "\x00" in word:
            raise ArgError("remote command words must not contain newlines or NUL")
    return shlex.join(argv)


def option_path(path: Path) -> str:
    """A path as an ssh -o value: forward slashes, double-quoted when it contains spaces."""
    text = str(path)
    if not text or text.startswith("-") or _PATH_BAD.search(text):
        raise ArgError("path is not safe as an ssh option value")
    text = text.replace("\\", "/")
    return f'"{text}"' if " " in text else text


def build_ssh_argv(
    ssh: str,
    *,
    host: str,
    port: int,
    user: str,
    key_path: Path,
    known_hosts: Path,
    remote: Sequence[str],
) -> list[str]:
    host = validate_host(host)
    user = validate_user(user)
    port = validate_port(port)
    argv = [ssh]
    for option in MANDATORY_OPTIONS[:2]:
        argv += ["-o", option]
    argv += ["-o", f"UserKnownHostsFile={option_path(known_hosts)}", "-o", "GlobalKnownHostsFile=none"]
    for option in MANDATORY_OPTIONS[2:3]:
        argv += ["-o", option]
    argv += ["-o", f"IdentityFile={option_path(key_path)}"]
    for option in MANDATORY_OPTIONS[3:]:
        argv += ["-o", option]
    argv += ["-F", "none", "-p", str(port), "--", f"{user}@{host}", quote_remote(remote)]
    return argv
