"""Real activity for `sift ui`: telemetry signals, their events, scan runs in the UI list."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from codesift import telemetry
from codesift.activity import forwarder, recording, topology
from codesift.config import Credentials
from codesift.gateway import GatewayClient
from codesift.paths import Paths
from codesift.redact import Redactor
from codesift.ui.state import Runs
from codesift.validate.events import EventLog, read_events
from codesift.vm.transport import describe_command
from mock_gateway import mock_gateway, reply, status


def test_signal_without_listener_is_a_no_op() -> None:
    telemetry.signal("llm.request", model="m")  # nothing listens: must not fail


def test_signal_labels_and_survives_a_broken_listener() -> None:
    got: list[tuple[str, dict[str, Any]]] = []

    def broken(kind: str, data: dict[str, Any]) -> None:
        raise RuntimeError("listener bug")

    with telemetry.listening(broken), telemetry.listening(lambda k, d: got.append((k, d))):
        with telemetry.doing("triage", "F003"):
            telemetry.signal("llm.request", model="m")
        telemetry.signal("vm.command", op="job")
    assert got == [
        ("llm.request", {"model": "m", "purpose": "triage", "finding": "F003"}),
        ("vm.command", {"op": "job"}),
    ]
    telemetry.signal("vm.command", op="job")  # listeners removed after the block
    assert len(got) == 2


def test_describe_command_never_returns_arguments() -> None:
    assert describe_command(["cat", "/proc/meminfo"]) == ("free memory", "")
    assert describe_command(["docker", "image", "pull", "python:3.12-alpine"]) == ("image pull", "")
    job = "0123456789abcdef0123456789abcdef"
    run = ["docker", "run", "--rm", "-i", "--name", f"sift-{job}", "python:3.12-alpine", "sh", "-c", "x"]
    assert describe_command(run) == ("job", job[:8])
    assert describe_command(["docker", "run", "--name", "evil;rm"]) == ("job", "")
    assert describe_command(["sh", "-c", "anything"]) == ("other", "")


def test_forwarder_writes_valid_events_and_drops_bad_ones(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "events.jsonl", "r1", Redactor())
    forward = forwarder(log)
    forward("llm.request", {"model": "m", "finding": "F001", "prompt_chars": 10})
    forward("llm.response", {"model": "m"})  # missing ok/latency: dropped, never raised
    forward("vm.result", {"op": "job", "rc": 0, "duration_s": 1.0, "finding": "not-an-id"})
    events, _ = read_events(tmp_path / "events.jsonl")
    assert [(e["type"], e.get("finding")) for e in events] == [("llm.request", "F001"), ("vm.result", None)]


def test_gateway_calls_are_recorded_without_content(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "events.jsonl", "r1", Redactor())
    with mock_gateway() as (url, state), recording(log):
        state.script.extend([status(503), reply('{"ok": true}')])
        client = GatewayClient(Credentials(url, "k"))
        client._sleep = lambda s: None
        with telemetry.doing("triage", "F002"):
            client.chat("primary-model", [{"role": "user", "content": "SECRET-PROMPT-TEXT"}])
    events, _ = read_events(tmp_path / "events.jsonl")
    kinds = [(e["type"], e["data"].get("ok")) for e in events]
    assert kinds == [
        ("llm.request", None),
        ("llm.response", False),
        ("llm.request", None),
        ("llm.response", True),
    ]
    assert all(e["finding"] == "F002" and e["data"]["purpose"] == "triage" for e in events)
    assert events[1]["data"]["error"] == "HTTP 503" and events[3]["data"]["model"] == "primary-model"
    text = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    assert "SECRET-PROMPT-TEXT" not in text and '{\\"ok\\": true}' not in text


def test_topology_without_settings_is_empty(paths: Paths) -> None:
    assert topology(paths, ["ruff"]) == {"scanners": ["ruff"]}


def test_scan_runs_are_listed_and_live(paths: Paths) -> None:
    run = paths.runs / "proj-1234abcd" / "20261116-120000"
    log = EventLog(run / "events.jsonl", run.name, Redactor())
    log.emit("run.start", kind="scan", mode="full", project="proj", topology={"scanners": ["ruff"]})
    log.emit("scanner.start", name="ruff")
    (run.parent / "latest").write_text(run.name, encoding="utf-8")  # not a run
    runs = Runs(paths)
    [listed] = runs.list_runs()
    assert listed["id"] == "scan~proj-1234abcd~20261116-120000" and listed["kind"] == "scan"
    assert listed["live"] is True and listed["project"] == "proj" and listed["mode"] == "full"
    log.emit("run.end", exit_code=0)
    assert runs.list_runs()[0]["live"] is False
    (run / "report.json").write_text(
        json.dumps(
            {
                "run": {"mode": "full"},
                "findings": [
                    {
                        "id": "F001",
                        "severity": "high",
                        "path": "a.py",
                        "line": 3,
                        "rules": ["r1"],
                        "tool": "ruff",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report = runs.report(listed["id"])
    assert report["kind"] == "scan" and report["findings"][0]["path"] == "a.py"
    assert "scanner.start" in runs.events_text(listed["id"])
