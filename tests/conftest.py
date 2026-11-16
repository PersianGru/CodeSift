from __future__ import annotations

import secrets
import socket
import string
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codesift.paths import Paths, get_paths


def _rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


@pytest.fixture
def fake_secret() -> Callable[[str], str]:
    """Build secret-shaped strings at test time (never committed). Prefixes are assembled from
    parts so the source itself contains no secret-shaped literal."""

    def make(kind: str = "generic") -> str:
        if kind == "github":
            return "gh" + "p_" + _rand(36)
        if kind == "aws":
            return "AK" + "IA" + _rand(16, string.ascii_uppercase + string.digits)
        if kind == "openai":
            return "s" + "k-" + _rand(40)
        return _rand(40)

    return make


LOOPBACK = ("127.0.0.1", "::1", "localhost")


# The real install (scanner binaries), read before any test overrides CODESIFT_HOME. Tests that run
# the installed scanners take only `data` and `bin` from it; runs and config stay in tmp_path.
INSTALLED_PATHS = get_paths()


class NetworkBlocked(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never touch the real network: any non-loopback connect fails loudly. Loopback stays
    open for the in-process mock LLM gateway."""
    orig_connect = socket.socket.connect
    orig_create = socket.create_connection

    def _loopback(address: object) -> bool:
        host = address[0] if isinstance(address, tuple) and address else ""
        return host in LOOPBACK

    def connect(self: socket.socket, address: Any) -> None:
        if not _loopback(address):
            raise NetworkBlocked(f"network access attempted in a test: {address!r}")
        orig_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> int:
        raise NetworkBlocked("network access attempted in a test")

    def create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
        if not _loopback(address):
            raise NetworkBlocked(f"network access attempted in a test: {address!r}")
        return orig_create(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "create_connection", create_connection)


@pytest.fixture(autouse=True)
def _isolated_codesift_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Child processes (git hooks, the CLI) inherit the environment: point them away from the real
    ~/.codesift so a test never reads the user's settings or leaves runs there."""
    monkeypatch.setenv("CODESIFT_HOME", str(tmp_path / "env-home"))
    monkeypatch.setenv("CODESIFT_CONFIG", str(tmp_path / "env-config"))
    monkeypatch.setenv("CODESIFT_RUNS", str(tmp_path / "env-runs"))


@pytest.fixture
def paths(tmp_path: Path) -> Paths:
    # Every location - including the user's home (Claude skill dir) - points into tmp_path.
    user_home = tmp_path / "user-home"
    env = {
        "CODESIFT_HOME": str(tmp_path / "home"),
        "CODESIFT_CONFIG": str(tmp_path / "config"),
        "USERPROFILE": str(user_home),
        "HOME": str(user_home),
    }
    p = get_paths(env)
    p.config.mkdir(parents=True)
    for location in (p.data, p.config, p.runs, p.bin, p.skill):
        assert location.is_relative_to(tmp_path), f"test path escapes tmp_path: {location}"
    return p
