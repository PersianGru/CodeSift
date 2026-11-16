"""LLM gateway client (any OpenAI-compatible base URL): one request at a time, timeouts, retries with backoff,
Retry-After, empty-content handling for thinking models, one-way fallback to a second model.

Answers are streamed (server-sent events): a gateway proxy may cut a silent request after ~90 s
(HTTP 504), while a stream of reasoning tokens keeps it alive. A thinking model reviewing 400 lines
needs several minutes. The whole call still has a hard deadline (`timeout`).

The API key travels only in the Authorization header; redirects to another host are refused; every
error message is scrubbed of the key."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from codesift import __version__, telemetry
from codesift.config import Credentials
from codesift.redact import Redactor

MAX_RETRY_AFTER_S = 120
MAX_RESPONSE_BYTES = 2_000_000  # answer text (non-streamed body, or streamed content)
MAX_STREAM_BYTES = 64_000_000  # raw event bytes of one streamed answer (reasoning is verbose)
IDLE_TIMEOUT_S = 120  # no byte at all for this long: the stream is dead


class LLMError(Exception):
    """Transport/model failure. `load_failure` marks errors that justify switching models."""

    def __init__(self, message: str, load_failure: bool = False) -> None:
        super().__init__(message)
        self.load_failure = load_failure


class _NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        old, new = urlsplit(req.full_url), urlsplit(newurl)
        if (old.scheme, old.hostname, old.port) != (new.scheme, new.hostname, new.port):
            raise LLMError(f"refusing redirect from the LLM gateway host to {new.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass
class ChatResult:
    content: str
    model: str
    latency_s: float
    finish_reason: str = ""
    usage: dict[str, Any] = field(default_factory=dict)


@dataclass
class ClientSettings:
    timeout_s: float = 180
    retries: int = 2
    backoff_s: tuple[float, ...] = (5, 20)
    max_tokens: int = 2048
    stream: bool = True


class GatewayClient:
    def __init__(
        self,
        creds: Credentials,
        settings: ClientSettings | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base = creds.base_url.rstrip("/")
        self._key = creds.api_key
        self.settings = settings or ClientSettings()
        self._sleep = sleep
        self._redactor = Redactor([creds.api_key])
        self._opener = urllib.request.build_opener(_NoCrossHostRedirect())
        self.json_mode = True  # switched off if the gateway rejects response_format
        self.stream = self.settings.stream  # switched off if the gateway rejects stream
        self.reasoning_control = True  # switched off if the gateway rejects reasoning_effort
        self.calls = 0

    # -- low level -----------------------------------------------------------------------------

    def _headers(self, accept: str) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": accept,
            "User-Agent": f"codesift/{__version__}",
        }
        if self._key:  # some local gateways need no key: then no Authorization header at all
            headers["Authorization"] = f"Bearer {self._key}"
        return headers

    def _request(self, method: str, path: str, body: dict[str, Any] | None, timeout: float) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(  # noqa: S310 - base URL validated (https / opt-in loopback http)
            self.base + path,
            data=data,
            method=method,
            headers=self._headers("application/json"),
        )
        self.calls += 1
        with self._opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LLMError("LLM gateway response too large")
        try:
            return json.loads(raw)
        except ValueError:
            raise LLMError("LLM gateway returned non-JSON") from None

    def _stream(self, body: dict[str, Any], timeout: float) -> dict[str, Any]:
        """POST a streamed chat completion and assemble it into the non-streamed response shape."""
        req = urllib.request.Request(  # noqa: S310 - base URL validated (https / opt-in loopback http)
            self.base + "/chat/completions",
            data=json.dumps(body).encode(),
            method="POST",
            headers=self._headers("text/event-stream"),
        )
        self.calls += 1
        deadline = time.monotonic() + timeout
        content: list[str] = []
        size = raw_size = 0
        model, finish = "", ""
        usage: dict[str, Any] = {}
        with self._opener.open(req, timeout=min(timeout, IDLE_TIMEOUT_S)) as resp:
            if "json" in str(resp.headers.get("Content-Type", "")):
                raw = resp.read(MAX_RESPONSE_BYTES + 1)  # gateway ignored stream=true
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise LLMError("LLM gateway response too large")
                try:
                    return dict(json.loads(raw))
                except ValueError:
                    raise LLMError("LLM gateway returned non-JSON") from None
            for line in resp:
                raw_size += len(line)
                if raw_size > MAX_STREAM_BYTES:
                    raise LLMError("LLM gateway stream too large")
                if time.monotonic() > deadline:
                    raise TimeoutError("timed out (whole answer)")
                text = line.decode("utf-8", "replace").strip()
                if not text.startswith("data:"):
                    continue
                payload = text[5:].strip()
                if payload == "[DONE]":
                    break
                try:
                    event = json.loads(payload)
                except ValueError:
                    continue
                if not isinstance(event, dict):
                    continue
                if event.get("error"):
                    raise LLMError(f"stream error: {self._clean(json.dumps(event['error']))}")
                model = str(event.get("model") or model)
                usage = dict(event.get("usage") or usage)
                for choice in event.get("choices") or []:
                    delta = choice.get("delta") or {}
                    piece = str(delta.get("content") or "")
                    size += len(piece)
                    if size > MAX_RESPONSE_BYTES:
                        raise LLMError("LLM gateway response too large")
                    content.append(piece)
                    finish = str(choice.get("finish_reason") or finish)
        message = {"role": "assistant", "content": "".join(content)}
        return {"model": model, "choices": [{"message": message, "finish_reason": finish}], "usage": usage}

    def _clean(self, text: str) -> str:
        title = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if title:
            text = title.group(1)  # HTML error page from a proxy: keep only its title
        return self._redactor.scrub(" ".join(text.split()))[:300]

    # -- API -----------------------------------------------------------------------------------

    def models(self, timeout: float = 30) -> list[str]:
        try:
            data = self._request("GET", "/models", None, timeout)
        except urllib.error.HTTPError as exc:
            raise LLMError(f"GET /models: HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMError(
                f"cannot reach the LLM gateway: {self._clean(str(getattr(exc, 'reason', exc)))}"
            ) from None
        return [str(m.get("id")) for m in (data.get("data") or []) if isinstance(m, dict)]

    def chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        *,
        max_tokens: int | None = None,
        timeout: float | None = None,
        json_mode: bool = True,
        think: bool = True,
        retries: int | None = None,
    ) -> ChatResult:
        """One chat completion with retries. Raises LLMError when all attempts fail.

        `think=False` asks for `reasoning_effort: "none"` (the only switch that turns qwen3.8's
        reasoning off through an OpenAI-compatible gateway; a `/no_think` tag in the prompt is ignored)."""
        budget = max_tokens or self.settings.max_tokens
        timeout = timeout or self.settings.timeout_s
        attempts = (self.settings.retries if retries is None else retries) + 1
        last: LLMError | None = None
        grew_budget = False
        attempt = 0
        while attempt < attempts:
            body: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": 0,
                "max_tokens": budget,
                "stream": self.stream,
            }
            if json_mode and self.json_mode:
                body["response_format"] = {"type": "json_object"}
            if not think and self.reasoning_control:
                body["reasoning_effort"] = "none"
            start = time.monotonic()
            prompt_chars = sum(len(str(m.get("content", ""))) for m in messages)
            telemetry.signal("llm.request", model=model, prompt_chars=prompt_chars, max_tokens=budget)
            try:
                if self.stream:
                    data = self._stream(body, timeout)
                else:
                    data = self._request("POST", "/chat/completions", body, timeout)
            except urllib.error.HTTPError as exc:
                detail = _read_error(exc)
                telemetry.signal(
                    "llm.response",
                    model=model,
                    ok=False,
                    error=f"HTTP {exc.code}",
                    latency_s=round(time.monotonic() - start, 2),
                )
                if exc.code == 400 and "response_format" in detail and self.json_mode:
                    self.json_mode = False  # gateway/model without JSON mode: plain prompt-only JSON
                    continue
                if exc.code == 400 and "reasoning_effort" in detail and self.reasoning_control:
                    self.reasoning_control = False
                    continue
                if exc.code == 400 and "stream" in detail.lower() and self.stream:
                    self.stream = False
                    continue
                load = exc.code in (404, 500, 502, 503) and any(
                    w in detail.lower() for w in ("model", "load", "not found", "memory")
                )
                last = LLMError(
                    f"HTTP {exc.code}: {self._clean(detail)}", load_failure=load or exc.code == 404
                )
                if exc.code == 404:
                    raise last from None  # unknown model: retrying will not help
                wait = self._retry_after(exc) if exc.code in (429, 503) else None
                attempt += 1
                if attempt < attempts:
                    self._sleep(wait if wait is not None else self._backoff(attempt))
                continue
            except (TimeoutError, urllib.error.URLError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                timed_out = isinstance(exc, TimeoutError) or "timed out" in str(reason).lower()
                telemetry.signal(
                    "llm.response",
                    model=model,
                    ok=False,
                    error="timeout" if timed_out else "connection",
                    latency_s=round(time.monotonic() - start, 2),
                )
                last = LLMError(
                    f"{'timeout after ' + str(int(timeout)) + 's' if timed_out else 'connection error'}: "
                    f"{self._clean(str(reason))}",
                    load_failure=timed_out,
                )
                attempt += 1
                if attempt < attempts:
                    self._sleep(self._backoff(attempt))
                continue
            latency = time.monotonic() - start
            choice = (data.get("choices") or [{}])[0]
            message = choice.get("message") or {}
            content = str(message.get("content") or "").strip()
            raw_usage = data.get("usage")
            usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
            telemetry.signal(
                "llm.response",
                model=model,
                served_by=str(data.get("model") or model),
                ok=bool(content),
                error="" if content else "empty answer",
                latency_s=round(latency, 2),
                tokens_in=int(usage.get("prompt_tokens") or 0),
                tokens_out=int(usage.get("completion_tokens") or 0),
                answer_chars=len(content),
            )
            if not content:
                # Thinking models can spend the whole budget on reasoning: retry once, bigger budget.
                if not grew_budget:
                    grew_budget = True
                    budget *= 2
                    continue
                last = LLMError("empty answer (reasoning only)")
                attempt += 1
                continue
            return ChatResult(
                content=content,
                model=str(data.get("model") or model),
                latency_s=latency,
                finish_reason=str(choice.get("finish_reason") or ""),
                usage=dict(data.get("usage") or {}),
            )
        raise last or LLMError("no answer")

    def _backoff(self, attempt: int) -> float:
        steps = self.settings.backoff_s or (0,)
        return steps[min(attempt - 1, len(steps) - 1)]

    @staticmethod
    def _retry_after(exc: urllib.error.HTTPError) -> float | None:
        value = exc.headers.get("Retry-After") if exc.headers else None
        if value is None:
            return None
        try:
            return max(0.0, min(float(value), MAX_RETRY_AFTER_S))
        except ValueError:
            return None


def _read_error(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read(2000).decode("utf-8", "replace")
    except OSError:
        return ""


class ModelSession:
    """One model per run; switches once to the fallback after two load failures/timeouts."""

    def __init__(self, client: GatewayClient, primary: str, fallback: str | None) -> None:
        self.client = client
        self.model = primary
        self.fallback = fallback if fallback and fallback != primary else None
        self.switched = False
        self.failures = 0
        self.dead = False
        self.events: list[str] = []

    def warm_up(self, timeout: float) -> float:
        """Ping without reasoning. Returns latency; switches to the fallback if the primary cannot answer."""
        while True:
            try:
                start = time.monotonic()
                self.client.chat(
                    self.model,
                    [{"role": "user", "content": 'Reply with JSON only: {"ok": true}'}],
                    max_tokens=256,
                    timeout=timeout,
                    think=False,
                )
                return time.monotonic() - start
            except LLMError as exc:
                self.events.append(f"warm-up of {self.model} failed: {exc}")
                if not self._switch():
                    self.dead = True
                    raise

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> ChatResult:
        while True:
            try:
                result = self.client.chat(self.model, messages, **kwargs)
                self.failures = 0
                return result
            except LLMError as exc:
                if not exc.load_failure:
                    raise
                self.failures += 1
                self.events.append(f"{self.model}: {exc}")
                if self.failures < 2:
                    raise
                if not self._switch():
                    self.dead = True
                    raise

    def _switch(self) -> bool:
        if self.switched or self.fallback is None:
            return False
        self.events.append(f"switching from {self.model} to fallback {self.fallback}")
        self.model, self.switched, self.failures = self.fallback, True, 0
        return True


# 0.1.0 name, kept so existing code and tests keep working (ADR-0014).
BifrostClient = GatewayClient
