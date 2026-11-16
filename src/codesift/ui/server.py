"""`sift ui` server: stdlib only, 127.0.0.1 only, token cookie, Host/Origin/CSRF checks, strict CSP.

Flow: the start URL carries a random token once (`/?token=...`); that request sets an HttpOnly,
SameSite=Strict cookie and redirects to `/`. Every other request needs the cookie. POST needs a
matching Origin and the custom `X-CodeSift-CSRF: 1` header. Static files come from a fixed
allow-list. No external requests: everything (including three.js) is served from this package."""

from __future__ import annotations

import hmac
import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from codesift.ui.state import DEMO_ID, Runs, StateError
from codesift.validate.events import read_events

COOKIE = "sift_ui"
CSRF_HEADER = "X-CodeSift-CSRF"
MAX_BODY = 16 * 1024
SSE_MAX_S = 6 * 3600
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data: blob:; script-src 'self'; style-src 'self'; "
        "connect-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
STATIC: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/realm.js": ("realm.js", "text/javascript; charset=utf-8"),
    "/static/world.js": ("world.js", "text/javascript; charset=utf-8"),
    "/static/map2d.js": ("map2d.js", "text/javascript; charset=utf-8"),
    "/static/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
    "/static/vendor/three.min.js": ("vendor/three.min.js", "text/javascript; charset=utf-8"),
}
_THREE_ADDONS = ("GLTFLoader", "SkeletonUtils")
for _name in _THREE_ADDONS:
    STATIC[f"/static/vendor/three-{_name}.js"] = (
        f"vendor/three-{_name}.js",
        "text/javascript; charset=utf-8",
    )
# KayKit models (CC0, Kay Lousberg) for the fantasy 3D view, packed by scripts/pack_kaykit.py
KAYKIT = (
    "anims",
    "props",
    "knight",
    "barbarian",
    "mage",
    "ranger",
    "rogue",
    "rogue_hooded",
    "skeleton_warrior",
    "skeleton_mage",
    "skeleton_rogue",
    "skeleton_minion",
)
for _name in KAYKIT:
    STATIC[f"/static/vendor/kaykit-{_name}.glb"] = (f"vendor/kaykit-{_name}.glb", "model/gltf-binary")
_API = re.compile(r"^/api/(run|stream|patch)/([A-Za-z0-9._~-]{1,170})(?:/([A-Za-z0-9._-]{1,40}))?$")


class BindError(Exception):
    pass


def static_bytes(name: str) -> bytes:
    return resources.files("codesift.ui").joinpath("static").joinpath(name).read_bytes()


@dataclass
class UIConfig:
    runs: Runs
    token: str
    port: int = 0
    ci: bool = False
    demo_speed: float = 1.0


def make_handler(cfg: UIConfig, stop: threading.Event) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "codesift-ui"
        sys_version = ""

        def log_message(self, *args: Any) -> None:  # never log URLs (the first one carries the token)
            pass

        # -- responses ---------------------------------------------------------------------

        def _send(self, code: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(code)
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, data: Any) -> None:
            self._send(code, json.dumps(data).encode(), "application/json; charset=utf-8")

        def _text(self, code: int, text: str) -> None:
            self._send(code, text.encode(), "text/plain; charset=utf-8")

        # -- checks ------------------------------------------------------------------------

        def _host_ok(self) -> bool:
            port = cfg.port
            return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

        def _cookie_ok(self) -> bool:
            raw = self.headers.get("Cookie", "")
            for part in raw.split(";"):
                name, _, value = part.strip().partition("=")
                if name == COOKIE and hmac.compare_digest(value.encode(), cfg.token.encode()):
                    return True
            return False

        def _origin_ok(self) -> bool:
            port = cfg.port
            return self.headers.get("Origin", "") in (f"http://127.0.0.1:{port}", f"http://localhost:{port}")

        # -- GET ---------------------------------------------------------------------------

        def do_GET(self) -> None:
            if not self._host_ok():
                self._text(421, "wrong host")
                return
            url = urlsplit(self.path)
            if url.path == "/" and url.query:
                token = parse_qs(url.query).get("token", [""])[0]
                if hmac.compare_digest(token.encode(), cfg.token.encode()):
                    cookie = f"{COOKIE}={cfg.token}; HttpOnly; SameSite=Strict; Path=/"
                    self._send(303, b"", "text/plain", {"Location": "/", "Set-Cookie": cookie})
                    return
                self._text(403, "invalid token - use the URL printed by `sift ui`")
                return
            if not self._cookie_ok():
                self._text(401, "open the URL printed by `sift ui` (it carries a one-time token)")
                return
            if url.query:
                self._text(400, "query strings are not used")
                return
            if url.path in STATIC:
                name, ctype = STATIC[url.path]
                try:
                    self._send(200, static_bytes(name), ctype)
                except (FileNotFoundError, OSError):
                    self._text(404, "missing asset")
                return
            if url.path == "/api/config":
                self._json(
                    200,
                    {
                        "ci": cfg.ci,
                        "demo": cfg.runs.demo is not None,
                        "replay": cfg.runs.replay_dir is not None,
                    },
                )
                return
            if url.path == "/api/runs":
                self._json(200, {"runs": cfg.runs.list_runs()})
                return
            self._api_get(url.path)

        def _api_get(self, path: str) -> None:
            m = _API.match(path)
            if not m:
                self._text(404, "not found")
                return
            kind, rid, sub = m.groups()
            try:
                if kind == "run" and sub == "report":
                    self._json(200, cfg.runs.report(rid))
                elif kind == "run" and sub == "events":
                    self._send(200, cfg.runs.events_text(rid).encode(), "application/x-ndjson; charset=utf-8")
                elif kind == "run" and sub == "decisions":
                    self._json(200, {"decisions": cfg.runs.decisions(rid)})
                elif kind == "patch" and sub:
                    self._send(200, cfg.runs.patch(rid, sub).encode(), "text/plain; charset=utf-8")
                elif kind == "stream" and sub is None:
                    self._stream(rid)
                else:
                    self._text(404, "not found")
            except StateError as exc:
                self._text(404, str(exc))

        def _stream(self, rid: str) -> None:
            """Server-sent events: the demo stream, or a tail of events.jsonl."""
            self.send_response(200)
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.end_headers()
            start = time.monotonic()

            def send(ev: dict[str, Any]) -> None:
                self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
                self.wfile.flush()

            try:
                if rid == DEMO_ID and cfg.runs.demo is not None:
                    demo = cfg.runs.demo
                    for ev, delay in zip(demo.events, demo.delays, strict=True):
                        if stop.is_set():
                            return
                        time.sleep(delay / max(cfg.demo_speed, 0.1))
                        send(dict(ev, ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
                    return
                path = cfg.runs.resolve(rid) / "events.jsonl"
                offset, idle = 0, 0.0
                while not stop.is_set() and time.monotonic() - start < SSE_MAX_S:
                    events, offset = read_events(path, offset)
                    for ev in events:
                        send(ev)
                        if ev.get("type") == "run.end":
                            return
                    if not events:
                        idle += 0.5
                        if idle >= 15:
                            self.wfile.write(b": keep-alive\n\n")
                            self.wfile.flush()
                            idle = 0
                        time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, StateError):
                return

        # -- POST --------------------------------------------------------------------------

        def do_POST(self) -> None:
            if not self._host_ok():
                self._text(421, "wrong host")
                return
            if not self._cookie_ok():
                self._text(401, "not authenticated")
                return
            if not self._origin_ok() or self.headers.get(CSRF_HEADER) != "1":
                self._text(403, "cross-site request refused")
                return
            if self.path != "/api/decision":
                self._text(404, "not found")
                return
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._text(415, "JSON only")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_BODY:
                self._text(413, "body too large or missing")
                return
            try:
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError
                record = cfg.runs.decide(
                    str(body.get("run", "")),
                    str(body.get("finding", "")),
                    str(body.get("action", "")),
                    str(body.get("note", "")),
                )
            except (ValueError, StateError) as exc:
                self._text(400, str(exc) or "invalid request")
                return
            self._json(200, {"ok": True, "decision": record, "applied": False})

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_PUT(self) -> None:
            self._text(405, "method not allowed")

        do_DELETE = do_PATCH = do_OPTIONS = do_PUT

    return Handler


class UIServer:
    def __init__(self, cfg: UIConfig, host: str = "127.0.0.1") -> None:
        if host != "127.0.0.1":
            raise BindError("sift ui binds to 127.0.0.1 only")
        self.stop = threading.Event()
        self.httpd = ThreadingHTTPServer((host, cfg.port), make_handler(cfg, self.stop))
        self.httpd.daemon_threads = True
        self.cfg = cfg
        self.port = int(self.httpd.server_address[1])
        cfg.port = self.port

    @property
    def start_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?token={self.cfg.token}"

    def serve_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        return t

    def shutdown(self) -> None:
        self.stop.set()
        self.httpd.shutdown()
        self.httpd.server_close()


def new_token() -> str:
    return secrets.token_urlsafe(24)  # 192 bits


def run_ui(
    runs: Runs,
    *,
    port: int = 0,
    open_browser: bool = False,
    ci: bool = False,
    out: Callable[[str], None] = print,
    wait: Callable[[], None] | None = None,
) -> int:
    server = UIServer(UIConfig(runs=runs, token=new_token(), port=port, ci=ci))
    server.serve_in_thread()
    out("sift ui is running on this machine only (127.0.0.1). Open this URL (it works once per browser):")
    out(f"  {server.start_url}")
    out("Press Ctrl-C to stop. Decisions are recorded; patches are never applied.")
    import sys

    sys.stdout.flush()
    if open_browser:
        import webbrowser

        webbrowser.open(server.start_url)
    try:
        if wait is not None:
            wait()
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        out("stopping")
    finally:
        server.shutdown()
    return 0


def replay_dir(path: str) -> Path:
    p = Path(path).resolve()
    if not (p / "events.jsonl").is_file():
        raise StateError(f"{p} has no events.jsonl")
    return p
