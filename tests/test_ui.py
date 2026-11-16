from __future__ import annotations

import hashlib
import http.client
import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from codesift.paths import Paths
from codesift.redact import Redactor
from codesift.ui.server import STATIC, BindError, UIConfig, UIServer, static_bytes
from codesift.ui.state import DemoRun, Runs
from codesift.validate.events import EventLog

STATIC_DIR = Path(__file__).resolve().parents[1] / "src" / "codesift" / "ui" / "static"


class Client:
    def __init__(self, server: UIServer) -> None:
        self.port = server.port
        self.token = server.cfg.token
        self.cookie = ""

    def req(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        host: str | None = None,
    ) -> http.client.HTTPResponse:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if self.cookie:
            h["Cookie"] = self.cookie
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        return conn.getresponse()

    def login(self) -> None:
        r = self.req("GET", f"/?token={self.token}")
        assert r.status == 303 and r.getheader("Location") == "/"
        cookie = r.getheader("Set-Cookie") or ""
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
        self.cookie = cookie.split(";", 1)[0]

    def post_decision(self, payload: dict[str, str], **headers: str) -> http.client.HTTPResponse:
        h = {
            "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{self.port}",
            "X-CodeSift-CSRF": "1",
        }
        h.update(headers)
        return self.req("POST", "/api/decision", json.dumps(payload).encode(), h)


def _real_run(paths: Paths) -> Path:
    run = paths.validate_runs / "proj-1234abcd" / "20261114-100000"
    run.mkdir(parents=True)
    log = EventLog(run / "events.jsonl", "20261114-100000", Redactor())
    log.emit("run.start", mode="fix")
    log.emit("finding.outcome", "F001", outcome="fixed_verified")
    log.emit("run.end", exit_code=0)
    (run / "fix-report.json").write_text(
        json.dumps(
            {"run": {"project": "proj", "mode": "fix", "started": "x", "exit_code": 0}, "findings": []}
        ),
        encoding="utf-8",
    )
    (run / "F001.patch").write_text("diff --git a/x b/x\n", encoding="utf-8")
    return run


@pytest.fixture
def server(paths: Paths) -> Iterator[UIServer]:
    _real_run(paths)
    runs = Runs(paths, demo=DemoRun())
    srv = UIServer(UIConfig(runs=runs, token="t" * 32, demo_speed=1000))
    srv.serve_in_thread()
    try:
        yield srv
    finally:
        srv.shutdown()


def test_bind_is_loopback_only(paths: Paths) -> None:
    for host in ("0.0.0.0", "::", "192.168.1.5", "localhost"):  # noqa: S104 - asserting these are refused
        with pytest.raises(BindError):
            UIServer(UIConfig(runs=Runs(paths), token="x" * 32), host=host)


def test_token_cookie_flow_and_headers(server: UIServer) -> None:
    c = Client(server)
    assert c.req("GET", "/").status == 401
    assert c.req("GET", "/?token=wrong").status == 403
    c.login()
    r = c.req("GET", "/")
    body = r.read().decode()
    assert r.status == 200 and "CodeSift" in body
    csp = r.getheader("Content-Security-Policy") or ""
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and "style-src 'self'" in csp
    assert r.getheader("X-Content-Type-Options") == "nosniff"
    assert r.getheader("Referrer-Policy") == "no-referrer" and r.getheader("Cache-Control") == "no-store"
    assert c.req("GET", "/api/runs").status == 200
    c.cookie = "sift_ui=" + "u" * 32
    assert c.req("GET", "/api/runs").status == 401


def test_host_check_blocks_rebinding(server: UIServer) -> None:
    c = Client(server)
    c.login()
    assert c.req("GET", "/api/runs", host="evil.example.com").status == 421
    assert c.req("GET", "/api/runs", host=f"localhost:{server.port}").status == 200


@pytest.mark.parametrize(
    "path",
    [
        "/static/../server.py",
        "/static/%2e%2e/server.py",
        "/static/vendor/../../state.py",
        "/static/app.js/../../state.py",
        "/static/vendor/THIRD_PARTY.md",
        "//etc/passwd",
        "/static/app.css?x=1",
    ],
)
def test_static_traversal(server: UIServer, path: str) -> None:
    c = Client(server)
    c.login()
    r = c.req("GET", path)
    assert r.status in (400, 404)
    assert b"import " not in r.read()


def test_api_and_patches(server: UIServer) -> None:
    c = Client(server)
    c.login()
    runs = json.loads(c.req("GET", "/api/runs").read())["runs"]
    ids = [r["id"] for r in runs]
    assert "demo" in ids and "fix~proj-1234abcd~20261114-100000" in ids
    rid = "fix~proj-1234abcd~20261114-100000"
    assert c.req("GET", f"/api/run/{rid}/report").status == 200
    events = c.req("GET", f"/api/run/{rid}/events").read().decode().splitlines()
    assert json.loads(events[-1])["type"] == "run.end"
    assert c.req("GET", f"/api/patch/{rid}/F001").read().startswith(b"diff --git")
    for bad in (
        f"/api/patch/{rid}/..",
        "/api/run/..~../report",
        "/api/patch/x~y/F001",
        f"/api/patch/{rid}/F001.patch",
    ):
        assert c.req("GET", bad).status == 404


def test_decision_csrf_and_never_applies(server: UIServer, paths: Paths) -> None:
    c = Client(server)
    c.login()
    rid = "fix~proj-1234abcd~20261114-100000"
    payload = {"run": rid, "finding": "F001", "action": "approve", "note": "looks good"}
    assert c.post_decision(payload, **{"X-CodeSift-CSRF": ""}).status == 403
    assert c.post_decision(payload, Origin="https://evil.example.com").status == 403
    assert c.post_decision({**payload, "action": "merge"}).status == 400
    r = c.post_decision(payload)
    data = json.loads(r.read())
    assert r.status == 200 and data["applied"] is False
    saved = json.loads(
        (paths.validate_runs / "proj-1234abcd" / "20261114-100000" / "decisions.json").read_text(
            encoding="utf-8"
        )
    )
    assert saved["decisions"][0]["action"] == "approve"
    big = c.req(
        "POST",
        "/api/decision",
        b"x" * 20000,
        {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{c.port}", "X-CodeSift-CSRF": "1"},
    )
    assert big.status == 413
    c.cookie = ""
    assert c.post_decision(payload).status == 401


def test_demo_stream_and_replay(server: UIServer, paths: Paths) -> None:
    c = Client(server)
    c.login()
    r = c.req("GET", "/api/stream/demo")
    assert r.getheader("Content-Type", "").startswith("text/event-stream")
    events = [json.loads(line[6:]) for line in r.read().decode().splitlines() if line.startswith("data: ")]
    assert events[0]["type"] == "run.start" and events[-1]["type"] == "run.end"
    assert {e["data"]["bug_type"] for e in events if e["type"] == "finding.detected"} >= {
        "sqli",
        "xss",
        "cmdi",
        "secret",
    }
    rid = "fix~proj-1234abcd~20261114-100000"
    tail = c.req("GET", f"/api/stream/{rid}").read().decode()
    assert '"run.end"' in tail
    replay = Runs(paths, replay_dir=paths.validate_runs / "proj-1234abcd" / "20261114-100000")
    srv = UIServer(UIConfig(runs=replay, token="r" * 32))
    srv.serve_in_thread()
    try:
        rc = Client(srv)
        rc.login()
        assert json.loads(rc.req("GET", "/api/runs").read())["runs"][0]["id"] == "replay"
        assert '"run.end"' in rc.req("GET", "/api/stream/replay").read().decode()
    finally:
        srv.shutdown()


# an absolute URL, or a scheme-relative one inside a string ("//host.tld"); not a regex like /x//i.test
_URL = re.compile(r"(?:https?:|[\"'`(])//[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _code_lines(text: str) -> str:
    """Drop comments: the vendored three.js add-ons cite their sources in comments. A trailing comment
    starts with whitespace + `//`, so the `//` inside a real URL in code (`"https://..."`) is kept."""
    kept = []
    for line in text.splitlines():
        if line.strip().startswith(("//", "*", "/*")):
            continue
        kept.append(re.sub(r"\s//.*$", "", line))
    return "\n".join(kept)


def test_no_external_urls_in_served_files() -> None:
    for route, (name, ctype) in STATIC.items():
        if not ctype.startswith("text/"):
            continue  # binary models: checked by test_kaykit_models_are_what_the_realm_uses
        text = _code_lines(static_bytes(name).decode("utf-8", "replace"))
        found = {u for u in _URL.findall(text) if "www.w3.org" not in u}  # XML namespace ids, not requests
        assert not found, (route, sorted(found)[:5])


def test_vendor_hashes_match_third_party_record() -> None:
    record = (STATIC_DIR / "vendor" / "THIRD_PARTY.md").read_text(encoding="utf-8")
    rows = dict(
        re.findall(r"^\| `([A-Za-z0-9._-]+\.(?:js|glb))` \|.*`([0-9a-f]{64})` \|$", record, re.MULTILINE)
    )
    shipped = {p.name for p in (STATIC_DIR / "vendor").iterdir() if p.suffix in (".js", ".glb")}
    assert "three.min.js" in rows and set(rows) == shipped, (sorted(rows), sorted(shipped))
    for name, digest in rows.items():
        assert hashlib.sha256((STATIC_DIR / "vendor" / name).read_bytes()).hexdigest() == digest, name
    served = {name for name, _ in STATIC.values()}
    assert {f"vendor/{n}" for n in shipped} <= served
    assert (STATIC_DIR / "vendor" / "LICENSE.three.txt").is_file()


def test_no_inline_script_or_style() -> None:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)
    assert "<style" not in html and " style=" not in html and "onclick" not in html.lower()
    for js in ("app.js", "world.js", "map2d.js", "realm.js", "dashboard.js"):
        assert "innerHTML" not in (STATIC_DIR / js).read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("name", ["app.js", "world.js", "map2d.js", "realm.js", "dashboard.js"])
def test_js_syntax(name: str) -> None:
    node = shutil.which("node")
    assert node
    proc = subprocess.run(
        [node, "--check", str(STATIC_DIR / name)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


def _glb_json(name: str) -> dict[str, Any]:
    data = (STATIC_DIR / "vendor" / name).read_bytes()
    assert data[:4] == b"glTF"
    size = int.from_bytes(data[12:16], "little")
    assert data[16:20] == b"JSON"
    doc = json.loads(data[20 : 20 + size])
    assert isinstance(doc, dict)
    return doc


def test_kaykit_models_are_what_the_realm_uses() -> None:
    realm = (STATIC_DIR / "realm.js").read_text(encoding="utf-8")
    clips = {a["name"] for a in _glb_json("kaykit-anims.glb")["animations"]}
    props = {n["name"] for n in _glb_json("kaykit-props.glb")["nodes"] if "children" in n and "mesh" not in n}
    used_clips = set(re.findall(r'play\("([A-Za-z0-9_]+)"', realm))
    used_clips |= set(
        re.findall(r'"((?:Melee|Ranged|Skeletons)_[A-Za-z0-9_]+|Lockpicking|Interact|Use_Item)"', realm)
    )
    assert used_clips and used_clips <= clips, sorted(used_clips - clips)
    used_props = set(re.findall(r'prop\("([A-Za-z0-9_]+)"', realm))
    used_props |= set(re.findall(r'(?<![A-Za-z])[rl]: "([A-Za-z0-9_]+)"', realm))
    assert used_props and used_props <= props, sorted(used_props - props)
    models = set(
        re.findall(
            r'"((?:skeleton_)?(?:knight|barbarian|mage|ranger|rogue|rogue_hooded|warrior|minion))"', realm
        )
    )
    for m in models | {"knight", "rogue_hooded", "skeleton_mage"}:
        assert _glb_json(f"kaykit-{m}.glb")["skins"], m  # rigged, so the clips can drive it
