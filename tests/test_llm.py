from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from codesift.config import Credentials, LLMSettings
from codesift.finding import Finding, fingerprint
from codesift.llm import BifrostClient, ClientSettings, LLMError, ModelSession
from codesift.models import Severity
from codesift.normalize import HIDDEN
from codesift.redact import Redactor
from codesift.review import run_review
from codesift.triage import (
    Excerpt,
    InvalidAnswer,
    TriageCache,
    TriageStats,
    build_excerpt,
    triage_findings,
    validate,
)
from mock_bifrost import (
    MockState,
    mock_bifrost,
    reasoning_only,
    reply,
    slow,
    status,
    triage_answer,
    trickle,
)

CODE = "\n".join(
    [
        "import subprocess",
        "",
        "def run(request):",
        "    cmd = request.args.get('cmd')",
        "    return subprocess.check_output('echo ' + cmd, shell=True)",
        "",
        "def other():",
        "    return 1",
    ]
)


@pytest.fixture
def server() -> Iterator[tuple[str, MockState]]:
    with mock_bifrost() as s:
        yield s


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text(CODE + "\n", encoding="utf-8")
    return root


def finding(
    line: int = 5, sev: Severity = Severity.HIGH, tool: str = "bandit", path: str = "app.py"
) -> Finding:
    f = Finding(
        tool=tool,
        rule="B602",
        severity=sev,
        path=path,
        line=line,
        message="shell=True",
        fingerprint=fingerprint(tool, "B602", path, str(line)),
        cwe=["CWE-78"],
    )
    f.id = f"F{line:03d}"
    return f


class RecordingClient(BifrostClient):
    sleeps: list[float]


def client(url: str, key: str = "k" * 30, timeout: float = 5, retries: int = 2) -> RecordingClient:
    sleeps: list[float] = []
    settings = ClientSettings(timeout_s=timeout, retries=retries, backoff_s=(0, 0))
    c = RecordingClient(Credentials(base_url=url, api_key=key), settings, sleep=sleeps.append)
    c.sleeps = sleeps
    return c


def run_triage(
    root: Path,
    url: str,
    findings: list[Finding],
    tmp: Path,
    *,
    max_findings: int = 60,
    timeout: int = 5,
    retries: int = 2,
) -> tuple[ModelSession, TriageStats]:
    settings = LLMSettings(call_timeout_s=timeout, total_budget_s=60)
    session = ModelSession(
        client(url, timeout=settings.call_timeout_s, retries=retries),
        "primary-model",
        "fallback-model",
    )
    stats = triage_findings(
        findings,
        root=root,
        session=session,
        settings=settings,
        cache=TriageCache(tmp / "cache"),
        redactor=Redactor(),
        ecosystems=["python"],
        max_findings=max_findings,
    )
    return session, stats


# ---------------------------------------------------------------- client


def test_models_and_auth_header(server: tuple[str, MockState]) -> None:
    url, state = server
    key = "secret-key-" + "x" * 20
    assert BifrostClient(Credentials(url, key)).models() == ["primary-model", "fallback-model"]
    assert state.headers[-1]["Authorization"] == f"Bearer {key}"
    assert key not in url


def test_retry_after_is_respected(server: tuple[str, MockState]) -> None:
    url, state = server
    state.script.extend([status(429, headers={"Retry-After": "3"}), reply('{"ok": true}')])
    c = client(url)
    result = c.chat("primary-model", [{"role": "user", "content": "x"}])
    assert result.content == '{"ok": true}'
    assert c.sleeps == [3.0]


def test_empty_content_gets_bigger_budget(server: tuple[str, MockState]) -> None:
    url, state = server
    state.script.extend([reasoning_only(), reply('{"ok": 1}')])
    c = client(url)
    c.chat("primary-model", [{"role": "user", "content": "x"}], max_tokens=2048)
    assert [r["max_tokens"] for r in state.requests] == [2048, 4096]
    assert state.requests[0]["temperature"] == 0 and state.requests[0]["response_format"] == {
        "type": "json_object"
    }


def test_json_mode_dropped_when_rejected(server: tuple[str, MockState]) -> None:
    url, state = server
    state.script.extend([status(400, {"error": "response_format not supported"}), reply("{}")])
    c = client(url)
    c.chat("primary-model", [{"role": "user", "content": "x"}])
    assert "response_format" not in state.requests[1] and not c.json_mode


def test_errors_never_contain_the_key(server: tuple[str, MockState]) -> None:
    url, state = server
    key = "verysecretkey-" + "z" * 20
    state.script.extend([status(500, {"error": f"bad auth {key}"})] * 3)
    with pytest.raises(LLMError) as exc:
        client(url, key=key).chat("primary-model", [{"role": "user", "content": "x"}])
    assert key not in str(exc.value)


def test_timeout_then_fallback(server: tuple[str, MockState]) -> None:
    url, state = server
    state.script.extend([slow(1.5), slow(1.5), reply('{"ok": true}')])
    session = ModelSession(client(url, timeout=0.5, retries=0), "primary-model", "fallback-model")
    with pytest.raises(LLMError):
        session.chat([{"role": "user", "content": "x"}])
    result = session.chat([{"role": "user", "content": "x"}])  # second failure switches, then answers
    assert session.model == "fallback-model" and session.switched
    assert result.content == '{"ok": true}'
    assert state.requests[-1]["model"] == "fallback-model"


def test_cold_start_warm_up_within_timeout(server: tuple[str, MockState]) -> None:
    url, state = server
    state.script.append(slow(0.8, reply('{"ok": true}')))
    session = ModelSession(client(url, timeout=3), "primary-model", None)
    assert session.warm_up(3) >= 0.7


def test_redirect_to_other_host_refused(server: tuple[str, MockState]) -> None:
    url, state = server
    state.script.append(status(302, {}, {"Location": "https://evil.example/v1/chat/completions"}))
    with pytest.raises(LLMError, match="redirect"):
        client(url, retries=0).chat("primary-model", [{"role": "user", "content": "x"}])


# ---------------------------------------------------------------- validation


def test_validate_answers() -> None:
    ex = Excerpt(
        text="", lines=["x = 1", "    return subprocess.check_output('echo ' + cmd, shell=True)"], digest="d"
    )
    good = json.dumps(
        {
            "verdict": "likely_real",
            "severity_suggestion": "high",
            "reason": "r",
            "quoted_line": "return subprocess.check_output('echo ' + cmd, shell=True)",
            "fix": "f",
        }
    )
    assert validate(good, ex)["verdict"] == "likely_real"
    assert validate("```json\n" + good + "\n```", ex)["verdict"] == "likely_real"
    with pytest.raises(InvalidAnswer, match="JSON"):
        validate("I think it is real", ex)
    with pytest.raises(InvalidAnswer, match="verdict"):
        validate(good.replace("likely_real", "definitely"), ex)
    with pytest.raises(InvalidAnswer, match="does not appear"):
        validate(good.replace("check_output", "run_command"), ex)
    with pytest.raises(InvalidAnswer, match="empty"):
        validate(json.dumps({"verdict": "unsure", "reason": "r", "quoted_line": HIDDEN}), ex)


def test_excerpt_context_and_secret_lines(project: Path) -> None:
    ex = build_excerpt(project, finding(line=5), Redactor(), context=1, hidden_lines={4})
    assert ex is not None
    assert ex.text.splitlines()[0].strip().startswith("3 |")  # extended up to `def run`
    assert HIDDEN in ex.lines and ">>    5 |" in ex.text


# ---------------------------------------------------------------- triage driver


def test_triage_done_then_cached(project: Path, server: tuple[str, MockState], tmp_path: Path) -> None:
    url, state = server
    f1 = finding()
    _, stats = run_triage(project, url, [f1], tmp_path)
    assert f1.triage.status == "done" and f1.triage.verdict == "likely_real"
    sent = len(state.requests)
    f2 = finding()
    run_triage(project, url, [f2], tmp_path)
    assert f2.triage.status == "cached" and len(state.requests) == sent
    assert "1 triaged" in stats.describe()


def test_invalid_then_valid(project: Path, server: tuple[str, MockState], tmp_path: Path) -> None:
    url, state = server
    state.script.extend([reply("not json at all"), reply(triage_answer())])
    f = finding()
    run_triage(project, url, [f], tmp_path)
    assert f.triage.status == "done" and len(state.requests) == 2
    assert "rejected" in state.requests[1]["messages"][-1]["content"]


def test_hallucinated_quote_fails(project: Path, server: tuple[str, MockState], tmp_path: Path) -> None:
    url, state = server
    state.default = triage_answer(quoted="os.system(user_input)  # not in the file")
    f = finding()
    _, stats = run_triage(project, url, [f], tmp_path)
    assert f.triage.status == "failed" and "does not appear" in f.triage.note
    assert stats.failed == 1


def test_llm_cannot_hide_high_findings(project: Path, server: tuple[str, MockState], tmp_path: Path) -> None:
    url, state = server
    state.default = triage_answer("likely_false_positive", severity="info")
    f = finding(sev=Severity.HIGH)
    f.needs_review = True
    findings = [f]
    run_triage(project, url, findings, tmp_path)
    assert findings == [f] and f.severity is Severity.HIGH and f.needs_review
    assert f.triage.verdict == "likely_false_positive" and f.triage.severity_suggestion == "info"


def test_caps_skips_and_unavailable(project: Path, server: tuple[str, MockState], tmp_path: Path) -> None:
    url, _state = server
    findings = [
        finding(line=5),
        finding(line=4),
        finding(line=3, sev=Severity.LOW),
        finding(line=0, tool="osv-scanner", path="requirements.txt"),
    ]
    findings[3].category = "vulnerable-dependency"
    run_triage(project, url, findings, tmp_path, max_findings=1)
    assert [f.triage.status for f in findings] == ["done", "skipped", "skipped", "skipped"]
    assert "cap" in findings[1].triage.note and "low" in findings[2].triage.note
    assert findings[3].triage.note == "dependency advisory"


def test_secrets_never_sent(project: Path, server: tuple[str, MockState], tmp_path: Path) -> None:
    url, state = server
    leak = finding(line=4, tool="gitleaks")
    leak.category = "secret"
    other = finding(line=5)
    run_triage(project, url, [leak, other], tmp_path)
    assert leak.triage.note == "secrets are never sent to the LLM"
    sent = json.dumps(state.requests)
    assert "request.args.get('cmd')" not in sent  # the gitleaks line is hidden in the other excerpt


def test_both_models_down(project: Path, server: tuple[str, MockState], tmp_path: Path) -> None:
    url, state = server
    state.default = lambda body: (_ for _ in ()).throw(RuntimeError())  # never used
    state.script.extend([slow(2.5)] * 12)
    findings = [finding(line=5), finding(line=4), finding(line=3)]
    session, stats = run_triage(project, url, findings, tmp_path, timeout=1, retries=0)
    assert session.dead
    assert all(f.triage.status in ("failed", "skipped") for f in findings)
    assert stats.describe().startswith(("unavailable", "partial"))


# ---------------------------------------------------------------- review


def test_review_drops_unverifiable_issues(tmp_path: Path, server: tuple[str, MockState]) -> None:
    url, state = server
    root = tmp_path / "repo"
    (root / "lic").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    target = root / "lic" / "verify.py"
    target.write_text("def verify(token):\n    return True\n", encoding="utf-8")
    env = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "-C", str(root), *env, "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), *env, "commit", "-qm", "a"], check=True)
    target.write_text(
        "def verify(token):\n    log.info('token=%s', token)\n    return True\n", encoding="utf-8"
    )
    issues = {
        "issues": [
            {
                "file": "lic/verify.py",
                "quoted_line": "log.info('token=%s', token)",
                "title": "token logged",
                "severity": "high",
                "explanation": "e",
                "fix": "f",
            },
            {
                "file": "lic/verify.py",
                "quoted_line": "requests.get(url, verify=False)",
                "title": "made up",
                "severity": "high",
                "explanation": "e",
                "fix": "f",
            },
        ]
    }
    state.script.append(reply(json.dumps(issues)))
    session = ModelSession(client(url), "primary-model", None)
    result = run_review(
        root, ["lic/verify.py", "other.py"], ["lic/**"], None, "HEAD", session, Redactor(), 5, 2048
    )
    assert [i.title for i in result.issues] == ["token logged"] and result.dropped == 1
    assert result.issues[0].line == 2


def test_fake_secret_never_reaches_llm(
    project: Path, server: tuple[str, MockState], tmp_path: Path, fake_secret: Callable[[str], str]
) -> None:
    url, state = server
    secret = fake_secret("github")
    (project / "app.py").write_text(
        CODE.replace("request.args.get('cmd')", f"'{secret}'") + "\n", encoding="utf-8"
    )
    run_triage(project, url, [finding()], tmp_path)
    assert secret not in json.dumps(state.requests)


def test_fallback_verdicts_flagged_as_weak() -> None:
    stats = TriageStats(model="fallback-model", triaged=3, fallback_used=True)
    assert "FALLBACK MODEL" in stats.describe()
    assert "FALLBACK" not in TriageStats(model="primary-model", triaged=3).describe()


def test_review_checklist_location_rules(tmp_path: Path, server: tuple[str, MockState]) -> None:
    url, state = server
    root = tmp_path / "proj"
    (root / "lic").mkdir(parents=True)
    (root / "lic" / "a.py").write_text("def verify(token):\n    return True\n", encoding="utf-8")
    outside = tmp_path / "private-notes.md"
    outside.write_text("TOP-SECRET-CHECKLIST-MARKER\n", encoding="utf-8")
    session = ModelSession(client(url), "primary-model", None)
    state.default = lambda body: json.dumps({"issues": []})
    # From .codesift.toml (relative or absolute): must stay inside the project.
    result = run_review(root, ["lic/a.py"], ["lic/**"], str(outside), None, session, Redactor(), 5, 2048)
    assert "not found inside the project" in result.note
    assert "TOP-SECRET-CHECKLIST-MARKER" not in json.dumps(state.requests)
    # From the user's command line: allowed anywhere.
    run_review(
        root,
        ["lic/a.py"],
        ["lic/**"],
        str(outside),
        None,
        session,
        Redactor(),
        5,
        2048,
        checklist_external=True,
    )
    assert "TOP-SECRET-CHECKLIST-MARKER" in json.dumps(state.requests[-1])


def test_excerpt_includes_related_definitions(tmp_path: Path) -> None:
    root = tmp_path / "p"
    root.mkdir()
    body = ["import yaml", "", "class SafeishLoader(yaml.SafeLoader):", "    pass", ""]
    body += [f"x{i} = {i}" for i in range(60)]
    body += ["def load(text):", "    return yaml.load(text, Loader=SafeishLoader)"]
    (root / "m.py").write_text("\n".join(body) + "\n", encoding="utf-8")
    f = finding(line=len(body), path="m.py")
    ex = build_excerpt(root, f, Redactor(), context=5, hidden_lines=set())
    assert ex is not None
    assert "related definitions" in ex.text and "class SafeishLoader(yaml.SafeLoader):" in ex.lines


def test_policy_rules_not_sent(project: Path, server: tuple[str, MockState], tmp_path: Path) -> None:
    url, state = server
    f = finding(tool="zizmor")
    f.rules = ["zizmor:unpinned-uses"]
    run_triage(project, url, [f], tmp_path)
    assert f.triage.status == "skipped" and "deterministic" in f.triage.note
    assert not [r for r in state.requests if "Finding:" in json.dumps(r)]


def test_pack_chunks_splits_and_packs() -> None:
    from codesift.review import CHUNK_OVERLAP, MAX_DIFF_LINES, pack_chunks

    small = [("a.py", ["+a"] * 100), ("b.py", ["+b"] * 100)]
    big = [("big.py", ["+x"] * (MAX_DIFF_LINES * 2))]
    chunks = pack_chunks(small + big + [("c.py", ["+c"] * 50)])
    assert len(chunks[0]) == 200  # a + b packed together
    assert all(len(c) <= MAX_DIFF_LINES + 1 for c in chunks)
    assert chunks[2][0] == "+++ b/big.py (continued)"
    covered = sum(len(c) for c in chunks[1:-1]) - (len(chunks) - 3)  # minus repeated headers
    assert covered >= MAX_DIFF_LINES * 2 + CHUNK_OVERLAP


def test_proxy_error_page_reduced_to_title(server: tuple[str, MockState]) -> None:
    url, state = server
    page = "<html><head><title>504 Gateway Time-out</title></head><body><h1>504</h1></body></html>"
    state.script.extend([status(504, page)] * 3)
    with pytest.raises(LLMError) as exc:
        client(url).chat("primary-model", [{"role": "user", "content": "x"}])
    assert "504 Gateway Time-out" in str(exc.value) and "<html>" not in str(exc.value)


def test_streamed_answer_keeps_slow_reasoning_alive(server: tuple[str, MockState]) -> None:
    url, state = server
    # 2 s of reasoning chunks, then the answer: assembled from the events
    state.script.append(trickle('{"ok": true}', events=8, delay=0.25))
    result = client(url).chat("primary-model", [{"role": "user", "content": "x"}], timeout=5)
    assert result.content == '{"ok": true}' and result.model == "primary-model"
    assert state.requests[0]["stream"] is True
    assert "text/event-stream" in state.headers[0]["Accept"]


def test_stream_has_a_whole_call_deadline(server: tuple[str, MockState]) -> None:
    url, state = server
    state.script.append(trickle('{"ok": true}', events=40, delay=0.1))  # 4 s, never idle
    with pytest.raises(LLMError, match="timeout") as exc:
        client(url, retries=0).chat("primary-model", [{"role": "user", "content": "x"}], timeout=1)
    assert exc.value.load_failure


def test_think_off_uses_reasoning_effort_and_survives_rejection(server: tuple[str, MockState]) -> None:
    url, state = server
    state.script.extend([status(400, {"error": "unknown field reasoning_effort"}), reply("{}")])
    c = client(url)
    c.chat("primary-model", [{"role": "user", "content": "x"}], think=False)
    assert state.requests[0]["reasoning_effort"] == "none"
    assert "reasoning_effort" not in state.requests[1] and not c.reasoning_control
    c.chat("primary-model", [{"role": "user", "content": "x"}])  # thinking on: no field at all
    assert "reasoning_effort" not in state.requests[2]


def test_stream_dropped_when_rejected(server: tuple[str, MockState]) -> None:
    url, state = server
    state.script.extend([status(400, {"error": "stream is not supported"}), reply('{"a": 1}')])
    c = client(url)
    assert c.chat("primary-model", [{"role": "user", "content": "x"}]).content == '{"a": 1}'
    assert state.requests[1]["stream"] is False and not c.stream


def test_warm_up_does_not_think(server: tuple[str, MockState]) -> None:
    url, state = server
    ModelSession(client(url), "primary-model", None).warm_up(3)
    assert state.requests[0]["reasoning_effort"] == "none"
    assert "no_think" not in json.dumps(state.requests[0])


def test_review_budget_lists_unreviewed_files(tmp_path: Path, server: tuple[str, MockState]) -> None:
    from codesift.report import _review_block

    url, state = server
    root = tmp_path / "proj"
    (root / "lic").mkdir(parents=True)
    for name in ("a", "b", "c"):  # 300 lines each: one request per file
        body = "\n".join(f"x_{name}_{i} = {i}" for i in range(300))
        (root / "lic" / f"{name}.py").write_text(body + "\n", encoding="utf-8")
    state.default = lambda body: json.dumps({"issues": []})
    state.script.append(status(500, {"error": "boom"}))  # first request fails, is not retried
    now = [0.0]

    def clock() -> float:
        now[0] += 40  # every look at the clock costs 40 s (two looks per request)
        return now[0]

    session = ModelSession(client(url), "primary-model", None)
    files = ["lic/a.py", "lic/b.py", "lic/c.py"]
    result = run_review(
        root, files, ["lic/**"], None, None, session, Redactor(), 600, 2048, budget_s=200, clock=clock
    )
    assert result.chunks == 3 and result.failed == 1 and result.done == 1
    assert len(state.requests) == 2  # no retry of the failed request
    assert result.not_reviewed == ["lic/c.py"] and "time budget" in result.note
    text = "\n".join(_review_block(result.to_dict()))
    assert "1 of 3 request(s) answered" in text and "**not reviewed**" in text and "lic/c.py" in text


def test_workflow_excerpt_is_the_whole_file(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    (root / ".github" / "workflows").mkdir(parents=True)
    body = ["permissions:", "  contents: write", "jobs:"] + [f"  # filler {i}" for i in range(80)]
    body += ["  release:", "    runs-on: ubuntu-latest"]
    (root / ".github" / "workflows" / "r.yml").write_text("\n".join(body) + "\n", encoding="utf-8")
    wf = finding(line=2, tool="zizmor", path=".github/workflows/r.yml")
    wf.category = "ci-workflow"
    excerpt = build_excerpt(root, wf, Redactor(), 30, set())
    assert excerpt is not None and "release:" in excerpt.text
