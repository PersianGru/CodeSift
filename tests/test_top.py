"""`sift top`: the terminal HUD is built only from a run's events, fits any terminal size, and
follows new runs. No terminal, network or VM is used here."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

from codesift.cli import main
from codesift.paths import get_paths
from codesift.ui.state import Runs
from codesift.ui.top import Board, Follower, paint, render, run_top


def _ev(seq: int, type_: str, finding: str | None = None, **data: Any) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "v": 1,
        "ts": f"2026-11-16T10:00:{seq:02d}Z",
        "run": "r1",
        "seq": seq,
        "type": type_,
    }
    ev["data"] = data
    if finding:
        ev["finding"] = finding
    return ev


SCAN = [
    _ev(
        0,
        "run.start",
        kind="scan",
        mode="full",
        project="demo",
        dry_run=False,
        topology={
            "scanners": ["gitleaks", "opengrep", "trivy"],
            "llm": {"host": "llm.example.invalid", "model": "ollama/model-a", "fallback": ""},
            "vm": {"host": "10.0.0.9", "user": "codesift", "runtime": "docker", "image": "x"},
        },
    ),
    _ev(
        1, "scanner.result", name="trivy", status="skipped", findings=0, duration_s=0, reason="no Dockerfile"
    ),
    _ev(2, "scanner.start", name="gitleaks"),
    _ev(3, "scanner.start", name="opengrep"),
    _ev(4, "scanner.result", name="gitleaks", status="ok", findings=0, duration_s=0.7, reason=""),
    _ev(5, "scanner.result", name="opengrep", status="ok", findings=2, duration_s=20.2, reason=""),
    _ev(6, "finding.detected", "F001", path="app/db.py", line=4, severity="high", tool="opengrep"),
    _ev(7, "finding.detected", "F002", path="a/b.php", line=9, severity="low", tool="opengrep"),
    _ev(8, "llm.request", "F001", model="ollama/model-a", prompt_chars=4000, purpose="triage"),
    _ev(
        9,
        "llm.response",
        "F001",
        model="ollama/model-a",
        ok=True,
        latency_s=1.5,
        tokens_in=900,
        tokens_out=40,
    ),
    _ev(10, "llm.request", model="ollama/model-a", prompt_chars=30),
    _ev(11, "llm.response", model="ollama/model-a", ok=False, error="timeout", latency_s=30.0),
    _ev(12, "run.end", exit_code=1, findings=2),
]


def test_board_counts_only_what_the_events_say() -> None:
    b = Board()
    for ev in SCAN:
        b.apply(ev, 0.0)
    assert [h.name for h in b.heroes.values()] == ["gitleaks", "opengrep", "trivy"]
    assert b.heroes["trivy"].status == "skipped" and b.heroes["opengrep"].found == 2
    assert set(b.monsters) == {"F001", "F002"} and b.monsters["F001"].severity == "high"
    assert (b.llm_calls, b.llm_failed, b.tokens_in, b.tokens_out, b.llm_inflight) == (2, 1, 900, 40, 0)
    assert b.vm_jobs == 0 and b.vm_host == "10.0.0.9"
    assert b.exit_code == 1 and b.ended
    text = " ".join("".join(t for t, _ in segs) for _, segs in b.log)
    assert "Mage opengrep returns · 2 found" in text and "is silent · timeout" in text


def test_fix_events_show_fates_and_the_dungeon() -> None:
    b = Board()
    for ev in [
        _ev(0, "run.start", kind="fix", mode="fix", project="demo", dry_run=False, topology={}),
        _ev(1, "finding.detected", "F001", path="x.py", line=1, severity="critical"),
        _ev(2, "vm.command", op="job", job="c0ffee12"),
        _ev(3, "vm.result", op="job", job="c0ffee12", rc=0, duration_s=2.5),
        _ev(4, "vm.command", op="free memory"),
        _ev(5, "vm.result", op="free memory", rc=1, duration_s=0.1),
        _ev(6, "verify.result", "F001", gate="tests", status="pass"),
        _ev(7, "finding.outcome", "F001", outcome="fixed_verified"),
    ]:
        b.apply(ev, 0.0)
    assert (b.vm_jobs, b.vm_commands, b.vm_failed, b.vm_inflight) == (1, 2, 1, 0)
    assert b.monsters["F001"].outcome == "fixed_verified"
    assert "slain" in "".join(t for t, _ in b.log[0][1])


def test_render_fits_every_terminal_size() -> None:
    b = Board()
    for ev in SCAN:
        b.apply(ev, 0.0)
    for width, height in [(160, 50), (120, 40), (80, 24), (40, 12), (20, 5)]:
        frame = render(b, width, height, 0.0)
        assert len(frame) == max(12, height)
        assert all(sum(len(t) for t, _ in line) == max(40, width) for line in frame)
    plain = paint(render(b, 120, 40, 0.0), color=False, ascii_only=True)
    assert plain.isascii() and "BESTIARY 2" in plain and "Skeleton Warrior" in plain
    assert "\x1b[" in paint(render(b, 120, 40, 0.0), color=True, ascii_only=False)


def test_empty_board_renders() -> None:
    text = paint(render(Board(), 100, 30, 0.0), color=False, ascii_only=False)
    assert "waiting for a run" in text and "no monsters sighted" in text


def _write_run(base: Path, slug: str, run: str, events: list[dict[str, Any]]) -> Path:
    folder = base / slug / run
    folder.mkdir(parents=True)
    path = folder / "events.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8", newline="\n")
    return path


def test_follower_tails_and_switches_to_new_runs() -> None:
    paths = get_paths()  # isolated to tmp_path by conftest
    log = _write_run(paths.runs, "demo-1a2b3c4d", "20261116-100000", SCAN[:4])
    f = Follower(Runs(paths), clock=lambda: 50.0)
    f.refresh()
    assert f.current.startswith("scan~demo-1a2b3c4d~") and f.board.heroes["gitleaks"].status == "running"
    with log.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(SCAN[4]) + "\n")
    f.pump()
    assert f.board.heroes["gitleaks"].status == "ok" and f.board.heroes["gitleaks"].changed == 50.0

    f.paused = True
    with log.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(SCAN[5]) + "\n")
    f.pump()
    assert f.board.heroes["opengrep"].status == "running"  # paused: nothing new applied
    f.paused = False
    f.pump()
    assert f.board.heroes["opengrep"].status == "ok"

    newer = [dict(SCAN[0], ts="2026-11-16T11:00:00Z")]
    _write_run(paths.runs, "demo-1a2b3c4d", "20261116-110000", newer)
    f.refresh()
    assert f.current.endswith("20261116-110000")  # following: the new run takes over
    f.step(1)
    assert f.current.endswith("20261116-100000") and not f.follow
    _write_run(paths.runs, "demo-1a2b3c4d", "20261116-120000", [dict(SCAN[0], ts="2026-11-16T12:00:00Z")])
    f.refresh()
    assert f.current.endswith("20261116-100000")  # pinned: stays on the chosen run
    f.step(-5)
    assert f.current.endswith("20261116-120000") and f.follow


def test_run_top_once_and_cli() -> None:
    paths = get_paths()
    _write_run(paths.runs, "demo-1a2b3c4d", "20261116-100000", SCAN)
    out = io.StringIO()
    assert run_top(Runs(paths), once=True, stream=out) == 0
    assert "demo · scan full" in out.getvalue() and "\x1b[" not in out.getvalue()
    assert main(["top", "--once", "--ascii"]) == 0


def test_run_top_needs_a_terminal(capsys: Any) -> None:
    assert run_top(Runs(get_paths()), stream=io.StringIO()) == 2
    assert "interactive terminal" in capsys.readouterr().err


def test_demo_plays_at_its_own_pace() -> None:
    from codesift.ui.state import DemoRun

    now = [100.0]
    runs = Runs(get_paths(), demo=DemoRun())
    f = Follower(runs, clock=lambda: now[0])
    f.refresh()
    assert f.current == "demo" and f.board.kind == "fix"  # run.start is due at once
    now[0] += 5
    f.pump()
    assert f.board.heroes["ruff"].status == "ok" and not f.board.monsters  # findings come later
    f.paused = True
    now[0] += 500
    f.pump()
    assert not f.board.ended  # paused: the demo waits
    f.paused = False
    f.pump()
    assert not f.board.ended
    now[0] += 500
    f.pump()
    assert f.board.ended and f.board.exit_code == 1 and len(f.board.monsters) == 12
    assert f.board.monsters["F001"].outcome == "fixed_verified" and f.board.vm_jobs == 18
    text = paint(render(f.board, 120, 40, now[0]), color=False, ascii_only=False)
    assert "demo-realm · fix " in text and "fix fix" not in text
