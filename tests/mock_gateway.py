"""In-process mock of an OpenAI-compatible LLM gateway for tests (loopback only).

Behaviour is scripted per request: push actions onto `server.script`; when the script is empty the
default action answers a valid triage JSON that quotes the first flagged (">>") line of the excerpt."""

from __future__ import annotations

import contextlib
import json
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

Action = Callable[["Handler", dict[str, Any]], None]


def flagged_line(body: dict[str, Any]) -> str:
    text = "\n".join(str(m.get("content", "")) for m in body.get("messages", []) if m.get("role") == "user")
    for line in text.splitlines():
        m = re.match(r"^>>\s*\d+ \| (.*)$", line)
        if m:
            return m.group(1)
    return ""


def triage_answer(
    verdict: str = "likely_real", quoted: str | None = None, **extra: str
) -> Callable[[dict[str, Any]], str]:
    def make(body: dict[str, Any]) -> str:
        return json.dumps(
            {
                "verdict": verdict,
                "severity_suggestion": extra.get("severity", "high"),
                "reason": extra.get("reason", "User input reaches the sink without validation."),
                "quoted_line": quoted if quoted is not None else flagged_line(body),
                "fix": extra.get("fix", "Validate the input."),
            }
        )

    return make


@dataclass
class MockState:
    script: deque[Action] = field(default_factory=deque)
    requests: list[dict[str, Any]] = field(default_factory=list)
    headers: list[dict[str, str]] = field(default_factory=list)
    models: list[str] = field(default_factory=lambda: ["primary-model", "fallback-model"])
    default: Callable[[dict[str, Any]], str] = field(default_factory=triage_answer)


class Handler(BaseHTTPRequestHandler):
    state: MockState
    wants_stream = False

    def log_message(self, *args: Any) -> None:  # silence
        pass

    def send_json(self, code: int, payload: Any, headers: dict[str, str] | None = None) -> None:
        if code == 200 and self.wants_stream and isinstance(payload, dict) and "choices" in payload:
            self.send_events(_as_events(payload))
            return
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_events(self, events: list[Any], delay: float = 0.0) -> None:
        """Server-sent events, like an OpenAI-compatible gateway with stream=true."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event in [*events, "[DONE]"]:
            text = event if isinstance(event, str) else json.dumps(event)
            self.wfile.write(f"data: {text}\n\n".encode())
            self.wfile.flush()
            if delay:
                time.sleep(delay)
        self.close_connection = True

    def do_GET(self) -> None:
        self.state.headers.append(dict(self.headers))
        if self.path.endswith("/models"):
            self.send_json(200, {"data": [{"id": m} for m in self.state.models]})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.state.requests.append(body)
        self.state.headers.append(dict(self.headers))
        self.wants_stream = bool(body.get("stream"))
        if self.state.script:
            self.state.script.popleft()(self, body)
        else:
            reply(self.state.default(body))(self, body)


def _as_events(payload: dict[str, Any]) -> list[Any]:
    """Split a completion into stream chunks: role, reasoning, content in two pieces, finish+usage."""
    choice = (payload.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    content = str(msg.get("content") or "")
    model = payload.get("model")
    half = len(content) // 2
    deltas: list[dict[str, Any]] = [{"role": "assistant"}]
    if msg.get("reasoning_content"):
        deltas.append({"reasoning_content": msg["reasoning_content"]})
    deltas += [{"content": part} for part in (content[:half], content[half:]) if part]
    events: list[Any] = [{"model": model, "choices": [{"delta": d}]} for d in deltas]
    events.append(
        {
            "model": model,
            "choices": [{"delta": {}, "finish_reason": choice.get("finish_reason", "stop")}],
            "usage": payload.get("usage") or {},
        }
    )
    return events


def trickle(content: str, events: int, delay: float) -> Action:
    """A streamed answer that needs `events * delay` seconds: reasoning chunks, then the content."""

    def act(h: Handler, body: dict[str, Any]) -> None:
        chunks: list[Any] = [{"choices": [{"delta": {"reasoning_content": "hmm "}}]} for _ in range(events)]
        chunks.append({"model": body.get("model"), "choices": [{"delta": {"content": content}}]})
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            h.send_events(chunks, delay)

    return act


def completion(content: str, model: str = "primary-model", reasoning: str = "") -> dict[str, Any]:
    msg: dict[str, Any] = {"role": "assistant", "content": content}
    if reasoning:
        msg["reasoning_content"] = reasoning
    return {"model": model, "choices": [{"message": msg, "finish_reason": "stop"}], "usage": {}}


def reply(content: str | Callable[[dict[str, Any]], str]) -> Action:
    def act(h: Handler, body: dict[str, Any]) -> None:
        text = content(body) if callable(content) else content
        h.send_json(200, completion(text, model=str(body.get("model"))))

    return act


def reasoning_only() -> Action:
    def act(h: Handler, body: dict[str, Any]) -> None:
        h.send_json(200, completion("", model=str(body.get("model")), reasoning="thinking " * 50))

    return act


def status(code: int, payload: Any = None, headers: dict[str, str] | None = None) -> Action:
    def act(h: Handler, body: dict[str, Any]) -> None:
        h.send_json(code, payload if payload is not None else {"error": f"status {code}"}, headers)

    return act


def slow(seconds: float, then: Action | None = None) -> Action:
    def act(h: Handler, body: dict[str, Any]) -> None:
        time.sleep(seconds)
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            (then or reply(triage_answer()))(h, body)

    return act


@contextmanager
def mock_gateway() -> Iterator[tuple[str, MockState]]:
    state = MockState()
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1", state
    finally:
        server.shutdown()
        server.server_close()


mock_bifrost = mock_gateway  # 0.1.0 name
