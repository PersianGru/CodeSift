"""gitleaks: secrets in the working tree and git history. Always runs. Output is redacted by
gitleaks itself (--redact) and masked again by CodeSift."""

from __future__ import annotations

import json
from pathlib import Path

from codesift.detect import DEFAULT_EXCLUDE_DIRS
from codesift.finding import Finding, fingerprint
from codesift.models import Severity
from codesift.runners.base import Context, Runner, RunnerError, scrub_file

GITLEAKS_EXIT = 7  # our "leaks found" exit code, distinct from errors (1)


def _config(ctx: Context) -> Path:
    """Default rules + CodeSift's path allow-list; extends the project's own .gitleaks.toml if any."""
    path = ctx.work_dir / "gitleaks.toml"
    project_cfg = ctx.root / ".gitleaks.toml"
    lines = ["[extend]"]
    if project_cfg.is_file():
        lines.append(f"path = '''{project_cfg.as_posix()}'''")
    else:
        lines.append("useDefault = true")
    regexes = [rf"(^|/){d.replace('.', '[.]')}/" for d in DEFAULT_EXCLUDE_DIRS if d != ".git"]
    for glob in ctx.exclude_globs:
        regexes.append(_glob_to_regex(glob))
    lines += ["", "[[allowlists]]", 'description = "CodeSift excludes"', "paths = ["]
    lines += [f"  '''{r}'''," for r in regexes if "'''" not in r]
    lines.append("]")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


def _glob_to_regex(glob: str) -> str:
    out = []
    i = 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(.*/)?")
            i += 3
            continue
        if glob.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        out.append({"*": "[^/]*", "?": "[^/]", ".": "[.]"}.get(c, "\\" + c if c in "+()[]{}^$|\\" else c))
        i += 1
    return "^" + "".join(out) + "($|/)"


class Gitleaks(Runner):
    name = "gitleaks"
    binary_tool = "gitleaks"

    def run(self, ctx: Context) -> list[Finding]:
        exe = str(self.executable(ctx))
        cfg = _config(ctx)
        common = [
            "--config",
            str(cfg),
            "--redact",
            "--no-banner",
            "--no-color",
            "--log-level",
            "error",
            "--exit-code",
            str(GITLEAKS_EXIT),
            "--report-format",
            "json",
            "--max-target-megabytes",
            "5",
            "--gitleaks-ignore-path",
            str(ctx.root),
        ]
        jobs: list[tuple[str, list[str]]] = []
        if ctx.git.is_repo:
            history = [exe, "git", str(ctx.root)]
            if ctx.since:
                history += ["--log-opts", f"{ctx.since}..HEAD"]
            jobs.append(("history", history))
            if not ctx.since:
                jobs.append(("unstaged", [exe, "git", str(ctx.root), "--pre-commit"]))
                jobs.append(("staged", [exe, "git", str(ctx.root), "--pre-commit", "--staged"]))
        else:
            jobs.append(("files", [exe, "dir", str(ctx.root)]))

        findings: list[Finding] = []
        for label, argv in jobs:
            report = ctx.raw_dir / f"gitleaks-{label}.json"
            self.exec(ctx, [*argv, *common, "--report-path", str(report)], ok_codes=(0, GITLEAKS_EXIT))
            scrub_file(ctx, report)
            findings += self.parse(ctx, report, label)
        return findings

    def parse(self, ctx: Context, report: Path, label: str) -> list[Finding]:
        try:
            data = json.loads(report.read_text(encoding="utf-8") or "[]")
        except ValueError:
            raise RunnerError(f"gitleaks wrote invalid JSON to {report.name}") from None
        out = []
        for item in data or []:
            rel = ctx.rel(str(item.get("File", "")))
            rule = str(item.get("RuleID", "secret"))
            match = ctx.redactor.scrub(str(item.get("Match", "")))
            commit = str(item.get("Commit", ""))[:12]
            where = f"commit {commit}" if commit and label == "history" else "working tree"
            line = int(item.get("StartLine", 0) or 0)
            out.append(
                Finding(
                    tool=self.name,
                    rule=rule,
                    severity=Severity.HIGH,
                    path=rel,
                    line=line,
                    end_line=int(item.get("EndLine", 0) or 0),
                    message=f"{item.get('Description', 'secret')} ({where})",
                    fingerprint=fingerprint(self.name, rule, rel, match),
                    confidence="medium",
                    category="secret",
                    cwe=["CWE-798"],
                    snippet=match[:300],
                    extra={
                        "commit": commit,
                        "source": label,
                        "entropy": round(float(item.get("Entropy", 0)), 2),
                    },
                )
            )
        return out
