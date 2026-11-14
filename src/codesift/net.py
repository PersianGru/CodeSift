"""The only place CodeSift opens HTTP connections for install/update (the LLM gateway has its own client).

Every request is HTTPS to an allow-listed host, redirects included. Tokens travel in headers only.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from codesift import __version__

# Hosts used by `install` and `update` (RULES.md §3). LLM gateway and osv/trivy traffic happen elsewhere.
ALLOWED_HOSTS = frozenset(
    {
        "api.github.com",
        "github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "pypi.org",
        "files.pythonhosted.org",
    }
)
USER_AGENT = f"codesift/{__version__}"
CHUNK = 1 << 16


class NetworkError(Exception):
    """Network failure or policy violation. Messages never contain tokens."""


class _OfflineGuard:
    offline = False


def set_offline(value: bool) -> None:
    _OfflineGuard.offline = value


def check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise NetworkError(f"refusing non-HTTPS URL: {parts.scheme}://{parts.hostname}")
    if (parts.hostname or "") not in ALLOWED_HOSTS:
        raise NetworkError(f"refusing request to host not on the allow-list: {parts.hostname}")
    if parts.username or parts.password:
        raise NetworkError("refusing URL with embedded credentials")


class _PolicyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        check_url(newurl)
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        # Never forward credentials to a different host (e.g. GitHub -> asset CDN).
        if new is not None and urlsplit(newurl).hostname != urlsplit(req.full_url).hostname:
            new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(_PolicyRedirect())


def github_token() -> str | None:
    """Optional token for higher GitHub API rate limits. Read from the environment only."""
    return os.environ.get("CODESIFT_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or None


def _request(url: str, accept: str | None = None) -> urllib.request.Request:
    if _OfflineGuard.offline:
        raise NetworkError("offline mode: network access disabled")
    check_url(url)
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    host = urlsplit(url).hostname
    token = github_token()
    if token and host == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    return urllib.request.Request(url, headers=headers)  # noqa: S310 - scheme/host checked above


def _rate_limited(exc: urllib.error.HTTPError) -> bool:
    if exc.code not in (403, 429):
        return False
    headers = exc.headers
    return headers is not None and (
        headers.get("X-RateLimit-Remaining") == "0" or headers.get("Retry-After") is not None
    )


def _host(url: str) -> str:
    return urlsplit(url).hostname or "?"


def fetch(url: str, *, timeout: float = 30, max_bytes: int = 5_000_000, accept: str | None = None) -> bytes:
    req = _request(url, accept)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            data: bytes = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        if _rate_limited(exc):
            raise NetworkError(
                "GitHub API rate limit reached (60 requests/hour without a token) - retry later, or set "
                "GITHUB_TOKEN / CODESIFT_GITHUB_TOKEN in the environment (read-only, public repos)"
            ) from None
        raise NetworkError(f"HTTP {exc.code} from {_host(url)} for {urlsplit(url).path}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise NetworkError(f"cannot reach {_host(url)}: {reason}") from None
    if len(data) > max_bytes:
        raise NetworkError(f"response from {_host(url)} larger than {max_bytes} bytes")
    return data


def fetch_json(url: str, *, timeout: float = 30, max_bytes: int = 50_000_000) -> Any:
    accept = "application/vnd.github+json" if _host(url) == "api.github.com" else "application/json"
    data = fetch(url, timeout=timeout, accept=accept, max_bytes=max_bytes)
    try:
        return json.loads(data)
    except ValueError:
        raise NetworkError(f"invalid JSON from {_host(url)}") from None


def download(url: str, dest: Path, *, sha256: str, max_bytes: int, timeout: float = 120) -> None:
    """Stream `url` to `dest`, verifying size and sha256. On any failure `dest` does not exist."""
    req = _request(url, accept="application/octet-stream")
    tmp = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    size = 0
    try:
        with _OPENER.open(req, timeout=timeout) as resp, tmp.open("wb") as out:
            while True:
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise NetworkError(f"download from {_host(url)} exceeds {max_bytes} bytes")
                digest.update(chunk)
                out.write(chunk)
        actual = digest.hexdigest()
        if actual != sha256.lower():
            raise NetworkError(
                f"checksum mismatch for {dest.name}: expected {sha256[:16]}…, "
                f"got {actual[:16]}… - refusing it"
            )
        tmp.replace(dest)
    except urllib.error.HTTPError as exc:
        raise NetworkError(f"HTTP {exc.code} downloading {dest.name} from {_host(url)}") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        reason = getattr(exc, "reason", exc)
        raise NetworkError(f"cannot download {dest.name} from {_host(url)}: {reason}") from None
    finally:
        if tmp.exists():
            tmp.unlink()
