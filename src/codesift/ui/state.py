"""Run discovery, report/event/patch loading, decisions, and the synthetic `--demo` run.

Run ids in the API are `<project-slug>~<run-id>` (validated; never joined into paths unchecked).
Decisions only append to the run's `decisions.json`; nothing here can apply a patch."""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
                    "project": "demo-realm",
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


DEMO_TOOLS = {"F001": "opengrep", "F002": "opengrep", "F003": "bandit", "F004": "opengrep",
              "F005": "gitleaks", "F006": "osv-scanner", "F007": "ruff"}  # fmt: skip
# found but not selected for fixing (below the fix threshold)
DEMO_EXTRA = [
    ("F008", "docker/Dockerfile", 3, "medium", "glitch", "trivy"),
    ("F009", ".github/workflows/ci.yml", 12, "medium", "glitch", "zizmor"),
    ("F010", "app/util/log.py", 7, "low", "glitch", "bandit"),
    ("F011", "app/util/fmt.py", 19, "low", "glitch", "ruff"),
    ("F012", "tests/test_api.py", 5, "info", "glitch", "ruff"),
]
DEMO_SCANNERS = [  # name, seconds after start it reports, findings, skipped reason
    ("gitleaks", 2.5, 1, ""),
    ("ruff", 1.2, 3, ""),
    ("bandit", 3.5, 2, ""),
    ("osv-scanner", 5.0, 1, ""),
    ("trivy", 6.5, 1, ""),
    ("opengrep", 11.0, 3, ""),
    ("zizmor", 4.0, 1, ""),
    ("pip-audit", 0.0, 0, "opt-in (enable in .codesift.toml)"),
    ("govulncheck", 0.0, 0, "no go.mod"),
]
DEMO_PRIMARY = "demo/oracle-large"
DEMO_FALLBACK = "demo/oracle-small"


@dataclass
class DemoRun:
    """A synthetic run: no scan, no VM, no model. Events carry the same schema as real runs and come
    with a delay each (`delays`), so the views can be tuned on a run that uses every kind of event."""

    started: str = field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    events: list[dict[str, Any]] = field(default_factory=list)
    delays: list[float] = field(default_factory=list)
    patches: dict[str, str] = field(default_factory=dict)
    decisions: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        timeline: list[tuple[float, str, str | None, dict[str, Any]]] = []
        clock = 0.0

        def at(when: float, type_: str, finding: str | None = None, **data: Any) -> None:
            timeline.append((when, type_, finding, data))

        def vm(when: float, op: str, took: float, rc: int = 0, job: str = "") -> None:
            extra = {"job": job} if job else {}
            at(when, "vm.command", op=op, **extra)
            at(when + took, "vm.result", op=op, rc=rc, duration_s=took, **extra)

        def llm(when: float, fid: str | None, purpose: str, chars: int, took: float, out: int,
                model: str = DEMO_PRIMARY, ok: bool = True, error: str = "") -> None:  # fmt: skip
            at(when, "llm.request", fid, model=model, prompt_chars=chars, max_tokens=2048, purpose=purpose)
            reply: dict[str, Any] = {"model": model, "ok": ok, "latency_s": took, "purpose": purpose}
            if ok:
                reply.update(tokens_in=chars // 4, tokens_out=out)
            else:
                reply["error"] = error
            at(when + took, "llm.response", fid, **reply)

        topology = {
            "scanners": [s[0] for s in DEMO_SCANNERS],
            "llm": {"host": "gateway.demo.invalid", "model": DEMO_PRIMARY, "fallback": DEMO_FALLBACK},
            "vm": {
                "host": "10.0.0.42",
                "user": "codesift",
                "runtime": "docker",
                "image": "python:3.12-alpine",
            },
        }
        at(0.0, "run.start", mode="fix", kind="fix", dry_run=False, project="demo-realm", topology=topology)
        # the scan: each hero rides out, comes back with what it found
        for name, took, _found, reason in DEMO_SCANNERS:
            if reason:
                at(
                    0.3,
                    "scanner.result",
                    name=name,
                    status="skipped",
                    findings=0,
                    duration_s=0,
                    reason=reason,
                )
            else:
                at(0.6 + DEMO_SCANNERS.index((name, took, _found, reason)) * 0.25, "scanner.start", name=name)
        for name, took, found, reason in DEMO_SCANNERS:
            if not reason:
                at(
                    1.5 + took,
                    "scanner.result",
                    name=name,
                    status="ok",
                    findings=found,
                    duration_s=took,
                    reason="",
                )
        clock = 13.5
        findings = [(f[0], f[1], f[2], f[3], f[4], f[5], f[6], DEMO_TOOLS[f[0]]) for f in DEMO_FINDINGS]
        findings += [(e[0], e[1], e[2], e[3], e[4], "app", [], e[5]) for e in DEMO_EXTRA]
        for i, (fid, path, line, sev, bug, district, cwe, tool) in enumerate(findings):
            at(clock + i * 0.35, "finding.detected", fid, path=path, line=line, category=bug, cwe=cwe,
               severity=sev, bug_type=bug, district=district, rule="demo:" + bug, tool=tool)  # fmt: skip
        clock += len(findings) * 0.35 + 0.5
        # triage: one question per serious finding; one times out and the fallback answers
        for i, f in enumerate(DEMO_FINDINGS):
            fid = f[0]
            if fid == "F004":
                llm(clock, fid, "triage", 5200, 6.0, 0, ok=False, error="timeout")
                llm(clock + 6.2, fid, "triage", 5200, 1.4, 64, model=DEMO_FALLBACK)
                clock += 8.0
            else:
                llm(clock, fid, "triage", 3800 + i * 400, 1.2 + (i % 3) * 0.6, 90 + i * 12)
                clock += 1.6 + (i % 3) * 0.6
        # the sandbox wakes up
        vm(clock, "free memory", 0.4)
        vm(clock + 0.5, "runtime version", 0.3)
        vm(clock + 0.9, "image check", 0.6)
        at(clock + 1.6, "selftest.result", passed=True, cached=False)
        clock += 2.2
        used = 0
        jobs = 0
        for fid, _path, _line, _sev, _bug, _d, _cwe, outcome, backends in DEMO_FINDINGS:
            at(clock, "finding.selected", fid)
            at(clock, "stage.enter", fid, stage="triage")
            at(clock + 0.2, "stage.exit", fid, stage="triage")
            clock += 0.4
            for n, backend in enumerate(backends, start=1):
                at(clock, "stage.enter", fid, stage="fix", backend=backend, attempt=n)
                at(clock, "fix.attempt", fid, backend=backend, attempt=n)
                if backend == "gateway":
                    llm(clock + 0.2, fid, "fix", 14000, 4.5, 900)
                clock += 5.0
                used += 4400
                at(clock, "fix.result", fid, backend=backend, attempt=n, ok=True)
                at(
                    clock,
                    "budget.update",
                    tokens_used=used,
                    tokens_limit=200000,
                    time_limit_s=3600,
                    exhausted=False,
                )
                at(clock, "stage.exit", fid, stage="fix")
                clock += 0.3
            gates = _gates(outcome)
            if backends:
                at(clock, "stage.enter", fid, stage="policy")
                ok = gates["policy"] == "pass"
                at(clock + 0.3, "policy.verdict", fid, ok=ok, codes=[] if ok else ["touches_lockfile"])
                at(clock + 0.4, "stage.exit", fid, stage="policy")
                clock += 0.6
            if gates["policy"] == "pass" or outcome == "inconclusive":
                at(clock, "stage.enter", fid, stage="sandbox")
                for label in ("tests-before", "tests-after", f"poc-after-{fid}"):
                    jobs += 1
                    job = f"{0xC0FFEE00 + jobs:08x}"
                    took = 2.0 + (jobs % 3) * 0.8
                    rc = 1 if (label.startswith("tests-after") and outcome == "rejected_tests") else 0
                    at(clock, "sandbox.start", fid, label=label)
                    vm(clock + 0.1, "job", took, rc=rc, job=job)
                    at(clock + took + 0.2, "sandbox.result", fid, rc=rc, duration_s=took, label=label)
                    clock += took + 0.5
                at(clock, "stage.exit", fid, stage="sandbox")
                at(clock, "stage.enter", fid, stage="verify")
                for gate in ("poc", "tests", "rescan"):
                    clock += 0.4
                    at(clock, "verify.result", fid, gate=gate, status=gates[gate])
                at(clock, "stage.exit", fid, stage="verify")
            clock += 0.5
            at(clock, "finding.outcome", fid, outcome=outcome)
            clock += 1.0
            if outcome.startswith("fixed"):
                self.patches[fid] = (
                    f"diff --git a/{_path} b/{_path}\n--- a/{_path}\n+++ b/{_path}\n@@ -1,1 +1,1 @@\n"
                    f"-unsafe_call(user_input)  # demo\n+safe_call(validated(user_input))  # demo\n"
                )
        at(clock + 0.5, "run.end", exit_code=1)

        timeline.sort(key=lambda e: e[0])  # stable: same-time events keep their order
        base = datetime.strptime(self.started, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        last = 0.0
        for seq, (when, type_, finding, data) in enumerate(timeline):
            ev: dict[str, Any] = {
                "v": 1,
                "ts": (base + timedelta(seconds=when)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "run": DEMO_ID,
                "seq": seq,
                "type": type_,
                "data": data,
            }
            if finding:
                ev["finding"] = finding
            self.events.append(ev)
            self.delays.append(max(0.0, when - last))
            last = when

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
                    "tool": DEMO_TOOLS[fid],
                }
            )
        for fid, path, line, sev, bug, tool in DEMO_EXTRA:
            findings.append(
                {"id": fid, "severity": sev, "path": path, "line": line, "rule": "demo:" + bug, "tool": tool,
                 "bug_type": bug, "gates": {}, "attempts": [], "patch": None}
            )  # fmt: skip
        return {
            "schema": 1,
            "run": {
                "id": DEMO_ID,
                "mode": "fix",
                "project": "demo-realm",
                "started": self.started,
                "exit_code": 1,
            },
            "budget": {"tokens_used": 4400 * 8, "tokens_limit": 200000, "exhausted": False},
            "sandbox": {"state": "demo (no VM)"},
            "findings": findings,
            "districts": DISTRICT_NAMES,
            "notes": ["Synthetic demo run: no scan, no VM, no model was contacted."],
        }
