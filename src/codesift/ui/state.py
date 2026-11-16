"""Run discovery, report/event/patch loading, decisions, and the synthetic `--demo` run.

Run ids in the API are `<project-slug>~<run-id>` (validated; never joined into paths unchecked).
Decisions only append to the run's `decisions.json`; nothing here can apply a patch."""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codesift.paths import Paths
from codesift.redact import Redactor
from codesift.validate.events import DISTRICT_NAMES, read_events

RUN_ID = re.compile(r"^(scan|fix)~([A-Za-z0-9._-]{1,80})~([A-Za-z0-9._-]{1,80})$")
FINDING_ID = re.compile(r"^(?:[A-Z]{1,8}[0-9]{1,6}|combined)$")
ACTIONS = ("approve", "reject", "retry")
MAX_NOTE = 500
DEMO_ID = "demo"
REPLAY_ID = "replay"


class StateError(Exception):
    pass


@dataclass
class Runs:
    paths: Paths
    replay_dir: Path | None = None
    demo: DemoRun | None = None
    redactor: Redactor = field(default_factory=Redactor)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def list_runs(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if self.demo is not None:
            out.append(
                {
                    "id": DEMO_ID,
                    "project": "demo-city",
                    "mode": "fix",
                    "started": self.demo.started,
                    "exit_code": None,
                }
            )
        if self.replay_dir is not None:
            out.append(self._summary(REPLAY_ID, self.replay_dir))
        found: list[dict[str, Any]] = []
        for kind, base in (("fix", self.paths.validate_runs), ("scan", self.paths.runs)):
            if not base.is_dir():
                continue
            for slug in sorted(base.iterdir()):
                if (
                    not slug.is_dir()
                    or slug.name.startswith("_")
                    or not RUN_ID.match(f"{kind}~{slug.name}~x")
                ):
                    continue
                for run in sorted(slug.iterdir(), reverse=True)[:20]:
                    if not run.is_dir() or run.name == "latest":
                        continue
                    if (run / "fix-report.json").is_file() or (run / "events.jsonl").is_file():
                        found.append(self._summary(f"{kind}~{slug.name}~{run.name}", run))
        found.sort(key=lambda r: str(r["started"]), reverse=True)  # newest first, scans and fixes mixed
        return (out + found)[:200]

    def _summary(self, rid: str, run: Path) -> dict[str, Any]:
        report = _read_json(run / "fix-report.json") or {}
        info = report.get("run", {}) if isinstance(report, dict) else {}
        first = _first_event(run / "events.jsonl")
        start = first.get("data", {}) if first.get("type") == "run.start" else {}
        live = (run / "events.jsonl").is_file() and not _has_end(run / "events.jsonl")
        return {
            "id": rid,
            "kind": rid.split("~", 1)[0] if "~" in rid else "fix",
            "project": info.get("project") or start.get("project") or run.parent.name,
            "mode": info.get("mode") or start.get("mode") or "?",
            "started": info.get("started") or first.get("ts") or run.name,
            "exit_code": info.get("exit_code"),
            "live": live,
        }

    def resolve(self, rid: str) -> Path:
        if rid == REPLAY_ID and self.replay_dir is not None:
            return self.replay_dir
        m = RUN_ID.match(rid)
        if not m:
            raise StateError("unknown run")
        kind, slug, run = m.groups()
        base = (self.paths.validate_runs if kind == "fix" else self.paths.runs).resolve()
        path = (base / slug / run).resolve()
        if not path.is_relative_to(base) or not path.is_dir():
            raise StateError("unknown run")
        return path

    def report(self, rid: str) -> dict[str, Any]:
        if rid == DEMO_ID and self.demo is not None:
            return self.demo.report()
        run = self.resolve(rid)
        data = _read_json(run / "fix-report.json")
        if isinstance(data, dict):
            return data
        scan = _read_json(run / "report.json")
        return scan_view(scan) if isinstance(scan, dict) else {}

    def events_text(self, rid: str) -> str:
        if rid == DEMO_ID and self.demo is not None:
            return "".join(json.dumps(e) + "\n" for e in self.demo.events)
        path = self.resolve(rid) / "events.jsonl"
        events, _ = read_events(path)
        return "".join(json.dumps(e) + "\n" for e in events)

    def patch(self, rid: str, finding: str) -> str:
        if not FINDING_ID.match(finding):
            raise StateError("unknown finding")
        if rid == DEMO_ID and self.demo is not None:
            return self.demo.patches.get(finding, "")
        path = self.resolve(rid) / f"{finding}.patch"
        if not path.is_file():
            raise StateError("no patch for this finding")
        return path.read_text(encoding="utf-8", errors="replace")[:200_000]

    def decide(self, rid: str, finding: str, action: str, note: str) -> dict[str, Any]:
        """Append a reviewer decision. Never applies, merges or touches the project."""
        if action not in ACTIONS:
            raise StateError("action must be approve, reject or retry")
        if not FINDING_ID.match(finding):
            raise StateError("unknown finding")
        record = {
            "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finding": finding,
            "action": action,
            "note": self.redactor.scrub(" ".join(str(note).split()))[:MAX_NOTE],
        }
        if rid == DEMO_ID and self.demo is not None:
            self.demo.decisions.append(record)
            return record
        path = self.resolve(rid) / "decisions.json"
        with self._lock:
            data = _read_json(path)
            items = data.get("decisions", []) if isinstance(data, dict) else []
            items.append(record)
            tmp = path.with_name("decisions.json.tmp")
            tmp.write_text(
                json.dumps({"decisions": items[-1000:]}, indent=2) + "\n", encoding="utf-8", newline="\n"
            )
            tmp.replace(path)
        return record

    def decisions(self, rid: str) -> list[dict[str, Any]]:
        if rid == DEMO_ID and self.demo is not None:
            return list(self.demo.decisions)
        data = _read_json(self.resolve(rid) / "decisions.json")
        return list(data.get("decisions", [])) if isinstance(data, dict) else []


def scan_view(report: dict[str, Any]) -> dict[str, Any]:
    """A scan's report.json in the shape the UI reads (findings with id/severity/path/line/rule)."""
    findings: list[dict[str, Any]] = []
    for f in report.get("findings", []):
        if not isinstance(f, dict):
            continue
        findings.append(
            {
                "id": f.get("id"),
                "severity": f.get("severity"),
                "path": f.get("path"),
                "line": f.get("line"),
                "rule": ", ".join(f.get("rules", [])[:3]) if isinstance(f.get("rules"), list) else "",
                "tool": f.get("tool"),
                "verdict": (
                    (f.get("triage") or {}).get("verdict", "") if isinstance(f.get("triage"), dict) else ""
                ),
                "gates": {},
            }
        )
    run = report.get("run", {}) if isinstance(report.get("run"), dict) else {}
    return {
        "schema": 1,
        "kind": "scan",
        "run": run,
        "findings": findings,
        "scanners": report.get("scanners", []),
    }


def _first_event(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            line = fh.readline(65536)
        data = json.loads(line.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, UnicodeDecodeError):
        return {}


def _has_end(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 4096))
            return b'"run.end"' in fh.read()
    except OSError:
        return True


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------- demo

DEMO_FINDINGS = [
    ("F001", "app/db/users.py", 42, "critical", "sqli", "db", ["CWE-89"], "fixed_verified", ["gateway"]),
    (
        "F002",
        "web/templates/profile.html",
        17,
        "high",
        "xss",
        "web",
        ["CWE-79"],
        "fixed_unproven",
        ["gateway"],
    ),
    (
        "F003",
        "tools/ping.py",
        9,
        "critical",
        "cmdi",
        "tools",
        ["CWE-78"],
        "fixed_verified",
        ["gateway", "claude-cli"],
    ),
    (
        "F004",
        "uploads/storage.py",
        31,
        "high",
        "traversal",
        "uploads",
        ["CWE-22"],
        "rejected_tests",
        ["gateway"],
    ),
    ("F005", "config/settings.py", 5, "high", "secret", "config", ["CWE-798"], "inconclusive", []),
    ("F006", "package-lock.json", 0, "medium", "dependency", "vendor", [], "rejected_policy", ["claude-api"]),
    ("F007", "src/report.py", 88, "medium", "glitch", "annex", [], "fixed_verified", ["gateway"]),
]


def _gates(outcome: str) -> dict[str, str]:
    g = {"policy": "pass", "poc": "unavailable", "tests": "pass", "rescan": "pass"}
    if outcome == "fixed_verified":
        g["poc"] = "pass"
    if outcome == "fixed_unproven":
        g["tests"] = "unavailable"
    if outcome == "rejected_tests":
        g["tests"] = "fail"
    if outcome == "rejected_policy":
        g = {"policy": "fail", "poc": "skipped", "tests": "skipped", "rescan": "skipped"}
    if outcome == "inconclusive":
        g = {"policy": "skipped", "poc": "unavailable", "tests": "skipped", "rescan": "skipped"}
    return g


@dataclass
class DemoRun:
    """A synthetic run: no scan, no VM, no model. Events carry the same schema as real runs."""

    started: str = field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    events: list[dict[str, Any]] = field(default_factory=list)
    patches: dict[str, str] = field(default_factory=dict)
    decisions: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        seq = 0

        def ev(type_: str, finding: str | None = None, **data: Any) -> None:
            nonlocal seq
            e: dict[str, Any] = {
                "v": 1,
                "ts": self.started,
                "run": DEMO_ID,
                "seq": seq,
                "type": type_,
                "data": data,
            }
            if finding:
                e["finding"] = finding
            self.events.append(e)
            seq += 1

        ev("run.start", mode="fix", dry_run=False, project="demo-city")
        ev("selftest.result", passed=True, cached=False)
        for fid, path, line, sev, bug, district, cwe, _o, _b in DEMO_FINDINGS:
            ev("finding.selected", fid)
            ev(
                "finding.detected",
                fid,
                path=path,
                line=line,
                category=bug,
                cwe=cwe,
                severity=sev,
                bug_type=bug,
                district=district,
                rule="demo:" + bug,
            )
        used = 0
        for fid, path, _line, _sev, _bug, _d, _cwe, outcome, backends in DEMO_FINDINGS:
            ev("stage.enter", fid, stage="triage")
            ev("stage.exit", fid, stage="triage")
            for n, backend in enumerate(backends, start=1):
                ev("stage.enter", fid, stage="fix", backend=backend, attempt=n)
                ev("fix.attempt", fid, backend=backend, attempt=n)
                used += 1800
                ev("fix.result", fid, backend=backend, attempt=n, ok=True)
                ev("budget.update", tokens_used=used, tokens_limit=200000, time_limit_s=3600, exhausted=False)
                ev("stage.exit", fid, stage="fix")
            gates = _gates(outcome)
            if backends:
                ev("stage.enter", fid, stage="policy")
                ev(
                    "policy.verdict",
                    fid,
                    ok=gates["policy"] == "pass",
                    codes=[] if gates["policy"] == "pass" else ["touches_lockfile"],
                )
                ev("stage.exit", fid, stage="policy")
            if gates["policy"] == "pass" or outcome == "inconclusive":
                ev("stage.enter", fid, stage="sandbox")
                ev("sandbox.start", fid, label=f"poc-after-{fid}")
                ev("sandbox.result", fid, rc=1, duration_s=2.4, label=f"poc-after-{fid}")
                ev("stage.exit", fid, stage="sandbox")
                ev("stage.enter", fid, stage="verify")
                for gate in ("poc", "tests", "rescan"):
                    ev("verify.result", fid, gate=gate, status=gates[gate])
                ev("stage.exit", fid, stage="verify")
            ev("finding.outcome", fid, outcome=outcome)
            if outcome.startswith("fixed"):
                self.patches[fid] = (
                    f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,1 @@\n"
                    f"-unsafe_call(user_input)  # demo\n+safe_call(validated(user_input))  # demo\n"
                )
        ev("run.end", exit_code=1)

    def report(self) -> dict[str, Any]:
        findings = []
        for fid, path, line, sev, bug, _d, cwe, outcome, backends in DEMO_FINDINGS:
            findings.append(
                {
                    "id": fid,
                    "severity": sev,
                    "path": path,
                    "line": line,
                    "rule": "demo:" + bug,
                    "cwe": cwe,
                    "bug_type": bug,
                    "outcome": outcome,
                    "gates": {k: {"status": v, "detail": "demo"} for k, v in _gates(outcome).items()},
                    "attempts": [
                        {"backend": b, "attempt": i + 1, "result": outcome} for i, b in enumerate(backends)
                    ],
                    "patch": f"{fid}.patch" if fid in self.patches else None,
                }
            )
        return {
            "schema": 1,
            "run": {
                "id": DEMO_ID,
                "mode": "fix",
                "project": "demo-city",
                "started": self.started,
                "exit_code": 1,
            },
            "budget": {"tokens_used": 1800 * 7, "tokens_limit": 200000, "exhausted": False},
            "sandbox": {"state": "demo (no VM)"},
            "findings": findings,
            "districts": DISTRICT_NAMES,
            "notes": ["Synthetic demo run: no scan, no VM, no model was contacted."],
        }
