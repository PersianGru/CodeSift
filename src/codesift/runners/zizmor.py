"""zizmor: GitHub Actions workflow security. Always --offline (no GitHub API calls, no token)."""

from __future__ import annotations

import json
import re
from typing import Any

from codesift.detect import is_workflow
from codesift.finding import Finding, fingerprint
from codesift.models import Severity
from codesift.runners.base import Context, Runner, RunnerError, scrub_file

SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "unknown": Severity.LOW,
}


class Zizmor(Runner):
    name = "zizmor"
    venv_tool = "zizmor"

    def applies(self, ctx: Context) -> str | None:
        if not ctx.detection.has("actions"):
            return "no .github/workflows"
        if ctx.incremental and not any(is_workflow(f) for f in ctx.changed or []):
            return "no workflow changed"
        return None

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.raw_dir / "zizmor.json"
        argv = [
            str(self.executable(ctx)),
            "--offline",
            "--no-exit-codes",
            "--no-progress",
            "--color",
            "never",
            "--format",
            "json",
        ]
        # Explicit files: given a directory inside a git repo, zizmor only looks at the repo
        # root's .github/workflows.
        workflows = [f for f in (ctx.changed or ctx.detection.files) if is_workflow(f)]
        argv += [str(ctx.root / f) for f in workflows if (ctx.root / f).is_file()]
        self.exec(ctx, argv, stdout_file=out, env_extra={"NO_COLOR": "1"})
        findings = self.parse(ctx, out.read_text(encoding="utf-8"))
        scrub_file(ctx, out)
        return findings

    def parse(self, ctx: Context, text: str) -> list[Finding]:
        try:
            items = json.loads(text or "[]")
        except ValueError:
            raise RunnerError("zizmor wrote invalid JSON") from None
        findings = []
        for item in items:
            det = item.get("determinations") or {}
            loc = _primary(item.get("locations") or [])
            if loc is None:
                continue
            key = ((loc.get("symbolic") or {}).get("key") or {}).get("Local") or {}
            rel = ctx.rel(str(key.get("given_path") or key.get("verbatim_path") or key.get("path") or ""))
            concrete = (loc.get("concrete") or {}).get("location") or {}
            start = int((concrete.get("start_point") or {}).get("row", -1)) + 1
            end = int((concrete.get("end_point") or {}).get("row", start - 1)) + 1
            feature = str((loc.get("concrete") or {}).get("feature", ""))
            annotation = str((loc.get("symbolic") or {}).get("annotation", ""))
            rule = str(item.get("ident", "?"))
            conf = str(det.get("confidence", "medium")).lower()
            severity = SEVERITY.get(str(det.get("severity", "")).lower(), Severity.MEDIUM)
            if rule == "unpinned-uses" and _github_owned(feature):
                # GitHub's own actions: hygiene, not third-party supply-chain risk
                severity = min(severity, Severity.MEDIUM)
            findings.append(
                Finding(
                    tool=self.name,
                    rule=rule,
                    severity=severity,
                    path=rel,
                    line=max(start, 1),
                    end_line=max(end, start, 1),
                    message=f"{item.get('desc', rule)}: {annotation}"[:300],
                    fingerprint=fingerprint(self.name, rule, rel, feature),
                    confidence=conf if conf in ("low", "medium", "high") else "medium",
                    category="ci-workflow",
                    snippet=ctx.redactor.scrub(feature)[:800],
                    extra={"url": item.get("url", "")},
                )
            )
        return findings


_USES = re.compile(r"uses:\s*['\"]?([A-Za-z0-9_.-]+)/")


def _github_owned(feature: str) -> bool:
    m = _USES.search(feature)
    return bool(m and m.group(1).lower() in ("actions", "github"))


def _primary(locations: list[dict[str, Any]]) -> dict[str, Any] | None:
    for loc in locations:
        if (loc.get("symbolic") or {}).get("kind") == "Primary":
            return loc
    return locations[0] if locations else None
