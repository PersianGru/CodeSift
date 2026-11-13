from __future__ import annotations

from pathlib import Path

import pytest

from codesift import net
from codesift.net import NetworkError, check_url, fetch, set_offline
from conftest import NetworkBlocked


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/x",
        "https://evil.example.com/x",
        "file:///etc/passwd",
        "https://user:pw@github.com/x",
        "https://github.com.evil.example/x",
    ],
)
def test_check_url_rejects(url: str) -> None:
    with pytest.raises(NetworkError):
        check_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://api.github.com/repos/a/b",
        "https://github.com/a/b/releases/download/v1/x",
        "https://pypi.org/pypi/ruff/json",
        "https://files.pythonhosted.org/packages/x.whl",
    ],
)
def test_check_url_allows(url: str) -> None:
    check_url(url)


def test_offline_mode_blocks_before_any_socket() -> None:
    set_offline(True)
    try:
        with pytest.raises(NetworkError, match="offline"):
            fetch("https://api.github.com/repos/a/b")
    finally:
        set_offline(False)


def test_redirect_to_foreign_host_refused() -> None:
    handler = net._PolicyRedirect()
    import urllib.request

    req = urllib.request.Request("https://github.com/a/b/releases/download/v1/x")
    with pytest.raises(NetworkError, match="allow-list"):
        handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example.com/payload")


def test_auth_header_dropped_on_cross_host_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.request

    handler = net._PolicyRedirect()
    req = urllib.request.Request("https://api.github.com/repos/a/b/tarball/x")
    req.add_header("Authorization", "Bearer abcdefghijkl")
    new = handler.redirect_request(req, None, 302, "Found", {}, "https://codeload.github.com/a/b/tar.gz/x")
    assert new is not None
    assert not new.has_header("Authorization")


def test_tests_cannot_reach_network() -> None:
    import socket

    with pytest.raises(NetworkBlocked):
        socket.create_connection(("example.com", 443))


def test_token_only_sent_to_github_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "tok_" + "x" * 20)
    api = net._request("https://api.github.com/repos/a/b")
    assert api.has_header("Authorization")
    other = net._request("https://pypi.org/pypi/ruff/json")
    assert not other.has_header("Authorization")
