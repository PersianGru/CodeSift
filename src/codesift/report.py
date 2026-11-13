"""Run directories, report.json and the short summary.md."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codesift import __version__
from codesift.finding import Finding
from codesift.models import Severity
from codesift.runners.base import RunResult

KEEP_RUNS = 20
SUMMARY_MAX_LINES = 150
LATEST = "latest"


def project_slug(root: Path) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", root.name or "root").strip("-")[:40] or "project"
    digest = hashlib.sha256(str(root.resolve()).lower().encode()).hexdigest()[:8]
    return f"{name}-{digest}"


def new_run_dir(runs_root: Path, root: Path) -> Path:
    base = runs_root / project_slug(root)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    run = base / stamp
    n = 1
    while run.exists():
        n += 1
        run = base / f"{stamp}-{n}"
    (run / "raw").mkdir(parents=True)
    return run


def mark_latest(run: Path) -> None:
    (run.parent / LATEST).write_text(run.name + "\n", encoding="utf-8", newline="\n")


def latest_run(runs_root: Path, root: Path) -> Path | None:
    base = runs_root / project_slug(root)
    pointer = base / LATEST
    if pointer.is_file():
        run = base / pointer.read_text(encoding="utf-8").strip()
        if (run / "report.json").is_file():
            return run
    runs = sorted(p for p in base.glob("*") if (p / "report.json").is_file()) if base.is_dir() else []
    return runs[-1] if runs else None


def prune_runs(runs_root: Path, root: Path, keep: int = KEEP_RUNS) -> int:
    base = runs_root / project_slug(root)
    runs = sorted(p for p in base.iterdir() if p.is_dir()) if base.is_dir() else []
    removed = 0
    for old in runs[:-keep] if len(runs) > keep else []:
        shutil.rmtree(old, ignore_errors=True)
        removed += 1
    return removed


@dataclass
class RunInfo:
    root: Path
    started: datetime
    duration_s: float
    mode: str  # full | fast | since
    threshold: Severity
    commit: str = ""
    branch: str = ""
    dirty: bool = False
    since: str | None = None
    offline: bool = False
    llm: str = "not run"
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    expired_baseline: list[str] = field(default_factory=list)
    exit_code: int = 0
    verbose: bool = False
    review: dict[str, Any] | None = None


def counts(findings: list[Finding]) -> dict[str, int]:
    c = {s.label: 0 for s in sorted(Severity, reverse=True)}
    c["baselined"] = 0
    for f in findings:
        if f.baseline:
            c["baselined"] += 1
        else:
            c[f.severity.label] += 1
    return c


def at_or_above(findings: list[Finding], threshold: Severity) -> list[Finding]:
    return [f for f in findings if not f.baseline and f.severity >= threshold]


def write_report(run: Path, info: RunInfo, results: list[RunResult], findings: list[Finding]) -> Path:
    data: dict[str, Any] = {
        "schema": 1,
        "codesift": __version__,
        "project": {
            "root": str(info.root),
            "name": info.root.name,
            "commit": info.commit,
            "branch": info.branch,
            "dirty": info.dirty,
        },
        "run": {
            "started": info.started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_s": round(info.duration_s, 1),
            "mode": info.mode,
            "since": info.since,
            "offline": info.offline,
            "threshold": info.threshold.label,
            "llm": info.llm,
            "exit_code": info.exit_code,
        },
        "scanners": [r.summary() for r in results],
        "counts": counts(findings),
        "warnings": info.warnings,
        "errors": info.errors,
        "expired_baseline": info.expired_baseline,
        "review": info.review,
        "findings": [f.to_dict() for f in findings],
    }
    path = run / "report.json"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def load_report(run: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((run / "report.json").read_text(encoding="utf-8"))
    return data


def _one_line(text: str, limit: int = 160) -> str:
    s = " ".join(text.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _finding_block(f: Finding) -> list[str]:
    tools = ", ".join(r for r in f.rules[:4]) + (f" (+{len(f.rules) - 4})" if len(f.rules) > 4 else "")
    cwe = f" · {', '.join(f.cwe[:2])}" if f.cwe else ""
    lines = [
        f"### {f.id} · {f.severity.label} · `{f.location}`",
        f"{tools}{cwe} · confidence {f.confidence}",
        f"{_one_line(f.message)}",
    ]
    t = f.triage
    if t.status in ("done", "cached") and t.verdict:
        verdict = t.verdict.replace("_", " ")
        suggestion = ""
        if t.severity_suggestion and t.severity_suggestion != f.severity.label:
            suggestion = f" (suggests {t.severity_suggestion})"
        lines.append(f"LLM: **{verdict}**{suggestion} — {_one_line(t.reason, 200)}")
        if t.fix:
            lines.append(f"Fix: {_one_line(t.fix, 200)}")
    elif t.status == "failed":
        lines.append(f"LLM: triage failed ({_one_line(t.note, 80)}) — review manually")
    if f.needs_review:
        lines[0] += " · **needs review**"
    return lines


def _review_block(review: dict[str, Any]) -> list[str]:
    out = ["## AI logic review — unverified", ""]
    files = review.get("files") or []
    total = int(review.get("requests") or 0)
    done = int(review.get("requests_done", total) or 0)
    progress = f" · {done} of {total} request(s) answered" if total and done < total else ""
    out.append(f"Base `{review.get('base')}` · {len(files)} critical file(s){progress}")
    issues = review.get("issues") or []
    for issue in issues[:10]:
        where = f"{issue.get('file')}:{issue.get('line')}" if issue.get("line") else str(issue.get("file"))
        out.append(
            f"- **{issue.get('severity')}** `{where}` — {_one_line(str(issue.get('title')), 100)}: "
            f"{_one_line(str(issue.get('explanation')), 180)}"
        )
    if len(issues) > 10:
        out.append(f"- …{len(issues) - 10} more in report.json")
    if not issues:
        out.append("- no issues reported" + (f" ({review.get('note')})" if review.get("note") else ""))
    if review.get("dropped_unverifiable"):
        out.append(f"- {review['dropped_unverifiable']} issue(s) dropped: quoted line not found in the diff")
    if review.get("error"):
        out.append(f"- error: {_one_line(str(review['error']), 160)}")
    skipped = review.get("not_reviewed") or []
    if skipped:
        shown = ", ".join(f"`{s}`" for s in skipped[:8]) + (
            f" (+{len(skipped) - 8})" if len(skipped) > 8 else ""
        )
        out.append(f"- **not reviewed** ({review.get('note')}): {shown}")
    out.append("")
    return out


def render_summary(
    info: RunInfo, results: list[RunResult], findings: list[Finding], report_path: Path
) -> str:
    c = counts(findings)
    ran = [f"{r.name} {r.version}".strip() for r in results if r.status == "ok"]
    skipped = [f"{r.name} ({r.reason})" for r in results if r.status == "skipped"]
    failed = [r for r in results if r.status == "error"]
    above = at_or_above(findings, info.threshold)
    head = [
        f"# CodeSift summary — {info.root.name}",
        "",
        f"- Run: {info.started.strftime('%Y-%m-%d %H:%M UTC')} · {info.mode}"
        + (f" since `{info.since}`" if info.since else "")
        + (
            f" · commit `{info.commit}`{' (uncommitted changes)' if info.dirty else ''}"
            if info.commit
            else ""
        )
        + f" · {info.duration_s:.0f}s",
        f"- Scanners: {', '.join(ran) or 'none'}",
    ]
    if skipped:
        head.append(f"- Skipped: {'; '.join(skipped)}")
    head += [
        f"- LLM triage: {info.llm}",
        f"- Threshold `{info.threshold.label}`: {len(above)} finding(s) at or above → exit {info.exit_code}",
    ]
    for w in info.warnings:
        head.append(f"- ⚠ {w}")
    head += [
        "",
        "| critical | high | medium | low | info | baselined |",
        "|---|---|---|---|---|---|",
        f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} | {c['baselined']} |",
        "",
    ]

    tail: list[str] = []
    not_triaged = [f for f in findings if not f.baseline and f.triage.status in ("skipped", "failed")]
    if not_triaged and info.llm.startswith(("done", "partial")):
        tail += [
            "## Not triaged",
            f"{len(not_triaged)} finding(s): {', '.join(f.id for f in not_triaged[:30])}",
            "",
        ]
    if info.review is not None:
        tail += _review_block(info.review)
    if failed or info.errors:
        tail.append("## Errors")
        tail += [f"- {r.name}: {_one_line(r.reason, 200)}" for r in failed]
        tail += [f"- {_one_line(e, 200)}" for e in info.errors]
        tail.append("")
    if info.expired_baseline:
        tail += ["## Expired baseline entries", *[f"- {e}" for e in info.expired_baseline[:10]], ""]
    tail += [
        "## Next steps",
        f"- Full details: `{report_path}`",
        '- Accept a false positive (with the owner\'s OK): `sift baseline accept <ID> --reason "…"`',
    ]

    visible = [f for f in findings if not f.baseline]
    if not info.verbose:
        visible = [f for f in visible if f.severity >= Severity.MEDIUM]
    body: list[str] = []
    budget = SUMMARY_MAX_LINES - len(head) - len(tail) - 4
    shown = 0
    current_group = ""
    for f in visible:
        group = "Critical / High" if f.severity >= Severity.HIGH else f.severity.label.capitalize()
        block = _finding_block(f)
        extra = 2 if group != current_group else 0
        if len(body) + len(block) + extra + 1 > budget:
            break
        if group != current_group:
            body += [f"## {group}", ""]
            current_group = group
        body += [*block, ""]
        shown += 1
    hidden = len(visible) - shown
    if hidden > 0:
        body += [f"…and {hidden} more finding(s) not shown — see report.json.", ""]
    if not info.verbose and (c["low"] or c["info"]):
        body += [
            f"Low/info findings ({c['low'] + c['info']}) are counted only; use `--verbose` to list them.",
            "",
        ]
    if not visible and not hidden:
        body += ["No findings at medium or above.", ""]
    return "\n".join(head + body + tail).rstrip() + "\n"


def write_summary(run: Path, text: str) -> Path:
    path = run / "summary.md"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path
