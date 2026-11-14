"""Run artifacts: fix-report.json, fix-report.md (<= 150 lines), patches, sandbox logs, audit log.
Everything passes through the Redactor; reports carry metadata, verdicts and diffs, never secrets."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codesift import __version__
from codesift.redact import Redactor

KEEP_RUNS = 20
MAX_MD_LINES = 150
MAX_LOG = 64 * 1024
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def new_run_dir(base: Path) -> tuple[str, Path]:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    run_id, n = stamp, 1
    while (base / run_id).exists():
        n += 1
        run_id = f"{stamp}-{n}"
    path = base / run_id
    (path / "sandbox").mkdir(parents=True)
    return run_id, path


def prune(base: Path, keep: int = KEEP_RUNS) -> None:
    runs = sorted(p for p in base.iterdir() if p.is_dir()) if base.is_dir() else []
    for old in runs[:-keep] if len(runs) > keep else []:
        shutil.rmtree(old, ignore_errors=True)


@dataclass
class FindingReport:
    id: str
    severity: str
    path: str
    line: int
    rule: str
    cwe: list[str]
    bug_type: str
    outcome: str = ""
    gates: dict[str, dict[str, str]] = field(default_factory=dict)
    attempts: list[dict[str, Any]] = field(default_factory=list)
    patch: str | None = None
    note: str = ""
    review: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class RunReport:
    run_id: str
    mode: str  # validate | fix
    root: Path
    started: str
    base_commit: str = ""
    dry_run: bool = False
    exit_code: int = 0
    duration_s: float = 0.0
    sandbox: dict[str, Any] = field(default_factory=dict)
    budget: dict[str, Any] = field(default_factory=dict)
    findings: list[FindingReport] = field(default_factory=list)
    regression: dict[str, Any] | None = None
    excluded_files: int = 0
    notes: list[str] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "codesift": __version__,
            "run": {
                "id": self.run_id,
                "mode": self.mode,
                "project": self.root.name,
                "root": str(self.root),
                "started": self.started,
                "duration_s": round(self.duration_s, 1),
                "base_commit": self.base_commit,
                "dry_run": self.dry_run,
                "exit_code": self.exit_code,
            },
            "sandbox": self.sandbox,
            "budget": self.budget,
            "findings": [f.to_dict() for f in self.findings],
            "regression": self.regression,
            "excluded_files": self.excluded_files,
            "notes": self.notes,
            "plan": self.plan,
        }


def write_json(path: Path, data: Any, redactor: Redactor) -> None:
    text = redactor.scrub(json.dumps(data, indent=2, ensure_ascii=False))
    path.write_text(text + "\n", encoding="utf-8", newline="\n")


def write_text(path: Path, text: str, redactor: Redactor, limit: int | None = None) -> None:
    text = redactor.scrub(text)
    if limit is not None and len(text) > limit:
        text = text[:limit] + "\n…(truncated)\n"
    path.write_text(text, encoding="utf-8", errors="surrogateescape", newline="\n")


def safe_file_name(name: str) -> str:
    return _SAFE.sub("-", name)[:80] or "x"


MARK = {"pass": "✓", "fail": "✗", "unavailable": "unavailable", "skipped": "—"}


def render_md(report: RunReport) -> str:
    lines = [
        f"# CodeSift {report.mode} — {report.root.name}",
        "",
        f"- Run `{report.run_id}` · {report.started}"
        + (f" · base `{report.base_commit[:12]}`" if report.base_commit else "")
        + (" · **dry run**" if report.dry_run else "")
        + f" · exit {report.exit_code}",
        f"- Sandbox: {report.sandbox.get('state', 'not used')}",
    ]
    if report.budget:
        lines.append(
            f"- Budget: {report.budget.get('tokens_used', 0)}/{report.budget.get('tokens_limit', 0)} tokens"
            + (" · **exhausted**" if report.budget.get("exhausted") else "")
        )
    if report.excluded_files:
        lines.append(
            f"- {report.excluded_files} file(s) kept out of the workspace (secrets, keys, never_send)"
        )
    lines.append("- Patches are never applied. Review them and apply yourself if you agree.")
    lines.append("")
    if report.plan:
        lines += ["## Plan (dry run)", *[f"- {p}" for p in report.plan[:40]], ""]
    if report.findings:
        lines += [
            "| finding | severity | outcome | policy | poc | tests | rescan |",
            "|---|---|---|---|---|---|---|",
        ]
        for f in report.findings:
            g = [
                MARK.get(f.gates.get(n, {}).get("status", "skipped"), "?")
                for n in ("policy", "poc", "tests", "rescan")
            ]
            lines.append(
                f"| {f.id} `{f.path}:{f.line}` | {f.severity} | **{f.outcome or 'planned'}** | "
                + " | ".join(g)
                + " |"
            )
        lines.append("")
        for f in report.findings:
            lines.append(f"### {f.id} · {f.outcome or 'planned'}")
            for name, gate in f.gates.items():
                if gate.get("detail"):
                    lines.append(f"- {name}: {gate['status']} — {gate['detail']}")
            if f.attempts:
                tries = ", ".join(
                    f"{a.get('backend')}#{a.get('attempt')} {a.get('result')}" for a in f.attempts[:6]
                )
                lines.append(f"- attempts: {tries}")
            if f.patch:
                lines.append(f"- patch: `{f.patch}`")
            if f.note:
                lines.append(f"- note: {f.note}")
            if f.review:
                lines.append(f"- independent review (advice only): {f.review[:300]}")
            lines.append("")
    if report.regression is not None:
        lines.append("## Regression check")
        for name, gate in report.regression.items():
            lines.append(f"- {name}: {gate.get('status')} — {gate.get('detail', '')}")
        lines.append("")
    if report.notes:
        lines += ["## Notes", *[f"- {n}" for n in report.notes[:15]], ""]
    if len(lines) > MAX_MD_LINES:
        lines = [*lines[: MAX_MD_LINES - 1], "…(more in fix-report.json)"]
    return "\n".join(lines).rstrip() + "\n"


class AuditLog:
    """Append-only: command, backend, model, token counts, durations, verdicts. No code, no secrets."""

    def __init__(self, path: Path, run_id: str, redactor: Redactor) -> None:
        self.path, self.run_id, self.redactor = path, run_id, redactor

    def write(self, event: str, **data: Any) -> None:
        allowed = {k: v for k, v in data.items() if isinstance(v, str | int | float | bool) or v is None}
        rec = {
            "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "run": self.run_id,
            "event": event,
            **allowed,
        }
        line = self.redactor.scrub(json.dumps(rec, ensure_ascii=False))
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
