"""`events.jsonl`: the contract between the engine and the UI (docs/events-schema.md).

One JSON object per line, schema version 1, validated on write. Every string passes through the
Redactor and is capped; no code and no secrets are ever written. `read_events` tolerates a truncated
last line, so the UI can tail a file that is still being written."""

from __future__ import annotations

import json
import re
import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from codesift.finding import Finding
from codesift.redact import Redactor

SCHEMA_VERSION = 1
MAX_STRING = 300
MAX_LIST = 50

TYPES = frozenset(
    {
        "run.start",
        "run.end",
        "finding.selected",
        "finding.detected",
        "stage.enter",
        "stage.exit",
        "fix.attempt",
        "fix.result",
        "policy.verdict",
        "sandbox.start",
        "sandbox.result",
        "verify.result",
        "finding.outcome",
        "budget.update",
        "selftest.result",
        "error",
        # real activity (both scan and fix runs): scanners, LLM calls, VM commands
        "scanner.start",
        "scanner.result",
        "llm.request",
        "llm.response",
        "vm.command",
        "vm.result",
    }
)
STAGES = frozenset({"triage", "fix", "policy", "sandbox", "verify", "judge"})
OUTCOMES = (
    "fixed_verified",
    "fixed_unproven",
    "rejected_policy",
    "rejected_tests",
    "rejected_rescan",
    "rejected_poc",
    "inconclusive",
    "fixer_failed",
    "budget_exhausted",
)
GATE_STATUSES = frozenset({"pass", "fail", "unavailable", "skipped"})
BUG_TYPES = ("sqli", "xss", "cmdi", "traversal", "secret", "dependency", "glitch")

REQUIRED: dict[str, tuple[str, ...]] = {
    "finding.detected": ("path", "line", "category", "cwe", "severity", "bug_type", "district"),
    "stage.enter": ("stage",),
    "stage.exit": ("stage",),
    "finding.outcome": ("outcome",),
    "sandbox.result": ("rc", "duration_s"),
    "verify.result": ("gate", "status"),
    "policy.verdict": ("ok",),
    "fix.attempt": ("backend", "attempt"),
    "fix.result": ("backend", "attempt", "ok"),
    "scanner.start": ("name",),
    "scanner.result": ("name", "status", "findings", "duration_s"),
    "llm.request": ("model",),
    "llm.response": ("model", "ok", "latency_s"),
    "vm.command": ("op",),
    "vm.result": ("op", "rc", "duration_s"),
}
FINDING_TYPES = frozenset(
    {
        "finding.selected",
        "finding.detected",
        "fix.attempt",
        "fix.result",
        "policy.verdict",
        "verify.result",
        "finding.outcome",
    }
)
_RUN_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_FINDING_ID = re.compile(r"^[A-Z]{1,8}[0-9]{1,6}$")


class EventError(ValueError):
    pass


# ---------------------------------------------------------------- classification (shared with the UI)

DEFAULT_DISTRICTS: dict[str, tuple[str, ...]] = {
    "db": ("db", "models", "sql", "migrations"),
    "web": ("web", "templates", "static", "frontend"),
    "tools": ("tools", "scripts", "bin"),
    "uploads": ("upload", "uploads", "files", "storage"),
    "config": ("config", "settings", ".github", "ci", "dockerfile"),
    "vendor": ("vendor", "node_modules", "third_party"),
}
DISTRICT_NAMES = {
    "db": "db/ Data Vault",
    "web": "web/ Neon Market",
    "tools": "tools/ Workshop Row",
    "uploads": "uploads/ Storage Yard",
    "config": "config/ Config Bank",
    "vendor": "vendor/ Supply Docks",
    "annex": "Annex",
}
_MANIFESTS = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "pipfile",
    "pipfile.lock",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "gemfile",
    "gemfile.lock",
)


def district_of(path: str, overrides: dict[str, list[str]] | None = None) -> str:
    """District key for a project-relative path (configurable with [ui.districts])."""
    p = PurePosixPath(path.lower())
    if p.name in _MANIFESTS or p.name.startswith("requirements"):
        return "vendor"
    table: dict[str, tuple[str, ...]] = dict(DEFAULT_DISTRICTS)
    for key, given in (overrides or {}).items():
        table[key] = tuple(x.lower().strip("/") for x in given)
    parts = p.parts
    for key, prefixes in table.items():
        if any(part in prefixes for part in parts[:-1]) or p.name in prefixes:
            return key
    if p.name.startswith("dockerfile") or p.name in ("compose.yaml", "docker-compose.yml"):
        return "config"
    return "annex"


def bug_type_of(f: Finding) -> str:
    cwes = {c.upper() for c in f.cwe}
    cat = (f.category or "").lower()
    tool = f.tool.lower()
    if tool == "gitleaks" or cwes & {"CWE-798", "CWE-259", "CWE-321", "CWE-312"} or "secret" in cat:
        return "secret"
    if tool in ("osv-scanner", "pip-audit", "composer-audit", "govulncheck") or "depend" in cat:
        return "dependency"
    if "CWE-89" in cwes or "sql" in cat:
        return "sqli"
    if "CWE-79" in cwes or "xss" in cat:
        return "xss"
    if cwes & {"CWE-78", "CWE-77"} or "command" in cat:
        return "cmdi"
    if cwes & {"CWE-22", "CWE-23", "CWE-73"} or "traversal" in cat or "path" in cat:
        return "traversal"
    return "glitch"


# ---------------------------------------------------------------- writing


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(value: Any, redactor: Redactor, depth: int = 0) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        text = redactor.scrub(" ".join(value.split()))
        return text if len(text) <= MAX_STRING else text[: MAX_STRING - 1] + "…"
    if isinstance(value, list | tuple):
        return [_clean(v, redactor, depth + 1) for v in list(value)[:MAX_LIST]]
    if isinstance(value, dict) and depth < 3:
        return {str(k)[:40]: _clean(v, redactor, depth + 1) for k, v in list(value.items())[:MAX_LIST]}
    raise EventError(f"unsupported event value type {type(value).__name__}")


def validate_event(ev: dict[str, Any]) -> None:
    if ev.get("v") != SCHEMA_VERSION:
        raise EventError("wrong schema version")
    if ev.get("type") not in TYPES:
        raise EventError(f"unknown event type {ev.get('type')!r}")
    if not isinstance(ev.get("run"), str) or not _RUN_ID.match(ev["run"]):
        raise EventError("invalid run id")
    if not isinstance(ev.get("seq"), int) or ev["seq"] < 0:
        raise EventError("invalid seq")
    if not isinstance(ev.get("ts"), str):
        raise EventError("invalid ts")
    finding = ev.get("finding")
    if finding is not None and not (isinstance(finding, str) and _FINDING_ID.match(finding)):
        raise EventError("invalid finding id")
    if ev["type"] in FINDING_TYPES and finding is None:
        raise EventError(f"{ev['type']} needs a finding id")
    data = ev.get("data")
    if not isinstance(data, dict):
        raise EventError("data must be an object")
    for key in REQUIRED.get(ev["type"], ()):
        if key not in data:
            raise EventError(f"{ev['type']} needs data.{key}")
    if ev["type"] in ("stage.enter", "stage.exit") and data["stage"] not in STAGES:
        raise EventError(f"unknown stage {data['stage']!r}")
    if ev["type"] == "finding.outcome" and data["outcome"] not in OUTCOMES:
        raise EventError(f"unknown outcome {data['outcome']!r}")
    if ev["type"] == "verify.result" and data["status"] not in GATE_STATUSES:
        raise EventError(f"unknown gate status {data['status']!r}")
    if ev["type"] == "finding.detected" and data["bug_type"] not in BUG_TYPES:
        raise EventError(f"unknown bug type {data['bug_type']!r}")


@dataclass
class EventLog:
    path: Path
    run_id: str
    redactor: Redactor

    def __post_init__(self) -> None:
        self.seq = 0
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def note(self, type_: str, finding: str | None = None, /, **data: Any) -> None:
        """Like `emit`, for runs where events only feed the UI: a bad event or a full disk is dropped
        instead of stopping the run."""
        with suppress(EventError, OSError):
            self.emit(type_, finding, **data)

    def emit(self, type_: str, finding: str | None = None, /, **data: Any) -> dict[str, Any]:
        with self._lock:
            ev: dict[str, Any] = {
                "v": SCHEMA_VERSION,
                "ts": _now(),
                "run": self.run_id,
                "seq": self.seq,
                "type": type_,
            }
            if finding is not None:
                ev["finding"] = finding
            ev["data"] = _clean(data, self.redactor)
            validate_event(ev)
            line = json.dumps(ev, ensure_ascii=False, separators=(",", ":"))
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(line + "\n")
            self.seq += 1
            return ev


def read_events(path: Path, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    """Read complete lines from `offset`. Returns (valid events, new offset). A last line without a
    newline (still being written) is left for the next read; invalid lines are skipped."""
    try:
        with path.open("rb") as fh:
            fh.seek(offset)
            data = fh.read(8 * 1024 * 1024)
    except OSError:
        return [], offset
    end = data.rfind(b"\n")
    if end == -1:
        return [], offset
    events: list[dict[str, Any]] = []
    for raw in data[: end + 1].splitlines():
        try:
            ev = json.loads(raw.decode("utf-8"))
            if isinstance(ev, dict):
                validate_event(ev)
                events.append(ev)
        except (ValueError, UnicodeDecodeError):
            continue
    return events, offset + end + 1
