"""Fixer backend: the Claude API (https://api.anthropic.com/v1/messages) - opt-in with consent.

The key travels only in the `x-api-key` header (never in a URL or on a command line); redirects are
refused; responses are size-capped; every error message is scrubbed of the key. Only redacted
excerpts are sent (the same request as the gateway fixer)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from codesift import __version__
from codesift.fix.base import EditError, FixRequest, FixResult, Usage, apply_edits, parse_edits
from codesift.fix.prompts import REVIEW_PROMPT, SYSTEM_PROMPT, user_message
from codesift.redact import Redactor

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
ALLOWED_HOSTS = frozenset({"api.anthropic.com"})
MAX_RESPONSE = 2_000_000


class ApiError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise ApiError("refusing an HTTP redirect from the Claude API")


def check_url(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme == "https" and host in ALLOWED_HOSTS:
        return url
    if parts.scheme == "http" and host in ("127.0.0.1", "localhost"):  # in-process test server only
        return url
    raise ApiError(f"refusing Claude API host {host or '?'} (only api.anthropic.com)")


@dataclass
class ClaudeApiClient:
    api_key: str = field(repr=False)
    url: str = API_URL
    timeout_s: float = 180

    def __post_init__(self) -> None:
        self.url = check_url(self.url)
        self.redactor = Redactor([self.api_key])
        self.opener = urllib.request.build_opener(_NoRedirect())

    def messages(self, model: str, system: str, user: str, max_tokens: int) -> tuple[str, Usage, str]:
        if not model:
            raise ApiError("no Claude API model configured (fix.toml [claude_api] model)")
        body = json.dumps(
            {
                "model": model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }
        ).encode()
        req = urllib.request.Request(  # noqa: S310 - URL checked against the host allow-list
            self.url,
            data=body,
            method="POST",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": API_VERSION,
                "content-type": "application/json",
                "user-agent": f"codesift/{__version__}",
            },
        )
        try:
            with self.opener.open(req, timeout=self.timeout_s) as resp:
                raw = resp.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(2000).decode("utf-8", "replace") if exc.fp else ""
            raise ApiError(f"HTTP {exc.code}: {self._clean(detail)}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ApiError(
                f"cannot reach the Claude API: {self._clean(str(getattr(exc, 'reason', exc)))}"
            ) from None
        if len(raw) > MAX_RESPONSE:
            raise ApiError("Claude API response too large")
        try:
            data = json.loads(raw)
        except ValueError:
            raise ApiError("Claude API returned non-JSON") from None
        text = "".join(
            str(b.get("text", ""))
            for b in data.get("content", [])
            if isinstance(b, dict) and b.get("type") == "text"
        )
        u = data.get("usage") or {}
        usage = Usage(int(u.get("input_tokens") or 0), int(u.get("output_tokens") or 0))
        return text, usage, str(data.get("model") or model)

    def _clean(self, text: str) -> str:
        return self.redactor.scrub(" ".join(text.split()))[:300]


@dataclass
class ClaudeApiFixer:
    client: ClaudeApiClient
    model: str
    redactor: Redactor = field(default_factory=Redactor)
    max_tokens: int = 4096
    name: str = "claude-api"

    def fix(self, request: FixRequest) -> FixResult:
        prompt = self.redactor.scrub(user_message(request))
        usage = Usage()
        for round_ in range(2):
            try:
                text, used, model = self.client.messages(self.model, SYSTEM_PROMPT, prompt, self.max_tokens)
            except ApiError as exc:
                return FixResult(False, error=self.redactor.scrub(str(exc)), model=self.model, usage=usage)
            usage.add(used)
            try:
                edits, explanation = parse_edits(text)
                applied = apply_edits(request.workspace, edits, request.allowed_paths)
                return FixResult(True, explanation, model=model, usage=usage, applied=applied)
            except (EditError, UnicodeDecodeError) as exc:
                if round_ == 1:
                    return FixResult(False, error=f"invalid edits: {exc}", model=model, usage=usage)
                prompt += f"\n\nYour previous answer was rejected: {exc}. Answer with the JSON object only."
        return FixResult(False, error="no answer", model=self.model, usage=usage)

    def review(self, diff: str) -> str:
        text, _, _ = self.client.messages(self.model, REVIEW_PROMPT, self.redactor.scrub(diff)[:30000], 600)
        return text
