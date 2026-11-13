"""Python scanners from codesift's venv: ruff (flake8-bandit `S` rules), bandit, pip-audit (opt-in).

ruff S### and bandit B### share numbers; both map to the same alias (bandit:B###) so the dedupe step
merges them. Severities follow bandit's defaults (documented in docs/severity.md)."""

from __future__ import annotations

import json
from pathlib import PurePosixPath

from codesift.detect import DEFAULT_EXCLUDE_DIRS, PY_EXT, TEST_DIRS, TEST_FILE_GLOBS, is_requirements
from codesift.finding import Finding, fingerprint, normalize_cwes
from codesift.models import Severity
from codesift.runners.base import MAX_FILE_TARGETS, Context, Runner, RunnerError, scrub_file

H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW
# bandit test id -> (severity, CWE). Unlisted ids default to medium.
BANDIT_TABLE: dict[str, tuple[Severity, int]] = {
    "B101": (L, 703), "B102": (M, 78), "B103": (M, 732), "B104": (M, 605), "B105": (L, 259),
    "B106": (L, 259), "B107": (L, 259), "B108": (M, 377), "B110": (L, 703), "B112": (L, 703),
    "B113": (M, 400), "B201": (H, 94), "B202": (H, 22), "B301": (M, 502), "B302": (M, 502),
    "B303": (M, 327), "B304": (H, 327), "B305": (M, 327), "B306": (M, 377), "B307": (M, 78),
    "B308": (M, 79), "B310": (M, 22), "B311": (L, 330), "B312": (H, 319), "B313": (M, 20),
    "B314": (M, 20), "B315": (M, 20), "B316": (M, 20), "B317": (M, 20), "B318": (M, 20),
    "B319": (M, 20), "B320": (M, 20), "B321": (H, 319), "B323": (M, 295), "B324": (H, 327),
    "B401": (H, 319), "B402": (H, 319), "B403": (L, 502), "B404": (L, 78), "B405": (L, 20),
    "B406": (L, 20), "B407": (L, 20), "B408": (L, 20), "B409": (L, 20), "B410": (L, 20),
    "B411": (H, 20), "B412": (H, 319), "B413": (H, 327), "B415": (H, 327), "B501": (H, 295),
    "B502": (H, 327), "B503": (M, 327), "B504": (L, 327), "B505": (H, 326), "B506": (M, 20),
    "B507": (H, 295), "B508": (M, 319), "B509": (M, 319), "B601": (M, 78), "B602": (H, 78),
    "B603": (L, 78), "B604": (M, 78), "B605": (H, 78), "B606": (L, 78), "B607": (L, 78),
    "B608": (M, 89), "B609": (H, 78), "B610": (M, 89), "B611": (M, 89), "B612": (M, 94),
    "B613": (M, 838), "B614": (M, 502), "B615": (M, 494), "B701": (H, 94), "B702": (M, 80),
    "B703": (M, 80), "B704": (M, 79),
}  # fmt: skip


# Extra CWEs other tools use for the same issue (so dedupe can merge them).
EXTRA_CWES: dict[str, tuple[int, ...]] = {
    "B201": (489,),
    "B307": (95,),
    "B506": (502,),
    "B608": (704,),
    "B602": (77,),
    "B605": (77,),
}


def _bandit_meta(code: str) -> tuple[Severity, list[str]]:
    sev, cwe = BANDIT_TABLE.get(code, (Severity.MEDIUM, 0))
    cwes = ([cwe] if cwe else []) + list(EXTRA_CWES.get(code, ()))
    return sev, [f"CWE-{c}" for c in cwes]


def _py_targets(ctx: Context) -> list[str] | None:
    """Changed python files (incremental) or None for a whole-project scan."""
    if not ctx.incremental:
        return None
    files = ctx.changed_matching(exclude_tests=True, exts=PY_EXT)
    return files if len(files) <= MAX_FILE_TARGETS else None


def _excludes(ctx: Context) -> list[str]:
    return [*DEFAULT_EXCLUDE_DIRS, *TEST_DIRS, *TEST_FILE_GLOBS, *ctx.exclude_globs]


class Ruff(Runner):
    name = "ruff"
    excludes_tests = True
    venv_tool = "ruff"

    def applies(self, ctx: Context) -> str | None:
        if not ctx.detection.files_with(PY_EXT):
            return "no Python files"
        if ctx.incremental and not _py_targets(ctx):
            return "no changed Python files"
        return None

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.raw_dir / "ruff.json"
        argv = [
            str(self.executable(ctx)),
            "check",
            "--isolated",  # ignore the project's ruff config: consistent rules, nothing can disable S
            "--no-cache",  # never write .ruff_cache into the project
            "--select",
            "S",
            "--output-format",
            "json",
            "--exit-zero",
            "--force-exclude",
            "--extend-exclude",
            ",".join(_excludes(ctx)),
        ]
        targets = _py_targets(ctx)
        argv += [str(ctx.root / t) for t in targets] if targets else [str(ctx.root)]
        self.exec(ctx, argv, stdout_file=out)
        findings = self.parse(ctx, out.read_text(encoding="utf-8"))
        scrub_file(ctx, out)
        return findings

    def parse(self, ctx: Context, text: str) -> list[Finding]:
        try:
            items = json.loads(text or "[]")
        except ValueError:
            raise RunnerError("ruff wrote invalid JSON") from None
        findings = []
        for item in items:
            code = str(item.get("code") or "")
            if not code.startswith("S"):
                continue
            bandit_id = "B" + code[1:]
            sev, cwe = _bandit_meta(bandit_id)
            rel = ctx.rel(str(item.get("filename", "")))
            start = int((item.get("location") or {}).get("row") or 0)
            end = int((item.get("end_location") or {}).get("row") or start)
            snippet = self.snippet(ctx, rel, start, end)
            findings.append(
                Finding(
                    tool=self.name,
                    rule=code,
                    severity=sev,
                    path=rel,
                    line=start,
                    end_line=end,
                    message=str(item.get("message", ""))[:300],
                    fingerprint=fingerprint(self.name, code, rel, snippet),
                    confidence="medium",
                    category=str(item.get("name", "")),
                    cwe=cwe,
                    snippet=snippet,
                    aliases=[f"bandit:{bandit_id}"],
                )
            )
        return findings


class Bandit(Runner):
    name = "bandit"
    excludes_tests = True
    venv_tool = "bandit"

    def applies(self, ctx: Context) -> str | None:
        if not ctx.detection.files_with(PY_EXT):
            return "no Python files"
        if ctx.incremental and not _py_targets(ctx):
            return "no changed Python files"
        return None

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.raw_dir / "bandit.json"
        targets = _py_targets(ctx)
        argv = [str(self.executable(ctx)), "-f", "json", "-o", str(out), "-q", "--exit-zero"]
        if targets:
            argv += [str(ctx.root / t) for t in targets]
        else:
            # bandit matches these with fnmatch; CodeSift also post-filters every path (scan.py)
            excludes = [
                f"*{sep}{d}{sep}*" for d in (*DEFAULT_EXCLUDE_DIRS, *TEST_DIRS) for sep in ("/", "\\")
            ]
            argv += ["-r", str(ctx.root), "-x", ",".join(excludes)]
        self.exec(ctx, argv)
        text = out.read_text(encoding="utf-8") if out.is_file() else "{}"
        findings = self.parse(ctx, text)
        scrub_file(ctx, out)
        return findings

    def parse(self, ctx: Context, text: str) -> list[Finding]:
        try:
            data = json.loads(text or "{}")
        except ValueError:
            raise RunnerError("bandit wrote invalid JSON") from None
        findings = []
        for r in data.get("results") or []:
            test_id = str(r.get("test_id", "B000"))
            rel = ctx.rel(str(r.get("filename", "")))
            start = int(r.get("line_number") or 0)
            line_range = r.get("line_range") or [start]
            end = int(max(line_range)) if line_range else start
            table_sev, table_cwe = _bandit_meta(test_id)
            sev = {"HIGH": H, "MEDIUM": M, "LOW": L}.get(str(r.get("issue_severity", "")).upper(), table_sev)
            snippet = self.snippet(ctx, rel, start, end)
            findings.append(
                Finding(
                    tool=self.name,
                    rule=test_id,
                    severity=sev,
                    path=rel,
                    line=start,
                    end_line=end,
                    message=str(r.get("issue_text", ""))[:300],
                    fingerprint=fingerprint(self.name, test_id, rel, snippet),
                    confidence=str(r.get("issue_confidence", "medium")).lower(),
                    category=str(r.get("test_name", "")),
                    cwe=list(dict.fromkeys([*normalize_cwes(r.get("issue_cwe")), *table_cwe])),
                    snippet=snippet,
                    aliases=[f"bandit:{test_id}"],
                )
            )
        return findings


class PipAudit(Runner):
    """Opt-in (`enable = ["pip-audit"]`): osv-scanner already covers pinned requirements files.
    Runs in a mode that never installs or resolves anything (--no-deps --disable-pip) and queries
    the OSV service only."""

    name = "pip-audit"
    venv_tool = "pip-audit"
    opt_in = True
    needs_network = True

    def _files(self, ctx: Context) -> list[str]:
        return [f for f in ctx.detection.files if is_requirements(PurePosixPath(f).name)]

    def applies(self, ctx: Context) -> str | None:
        return None if self._files(ctx) else "no requirements*.txt files"

    def run(self, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for i, rel in enumerate(self._files(ctx)):
            out = ctx.raw_dir / f"pip-audit-{i}.json"
            argv = [
                str(self.executable(ctx)),
                "-r",
                str(ctx.root / rel),
                "--no-deps",
                "--disable-pip",
                "--vulnerability-service",
                "osv",
                "--progress-spinner",
                "off",
                "--format",
                "json",
                "--output",
                str(out),
            ]
            self.exec(ctx, argv, ok_codes=(0, 1))
            scrub_file(ctx, out)
            findings += self.parse(ctx, out.read_text(encoding="utf-8") if out.is_file() else "{}", rel)
        return findings

    def parse(self, ctx: Context, text: str, rel: str) -> list[Finding]:
        try:
            data = json.loads(text or "{}")
        except ValueError:
            raise RunnerError("pip-audit wrote invalid JSON") from None
        findings = []
        for dep in data.get("dependencies") or []:
            vulns = dep.get("vulns") or []
            if not vulns:
                continue
            name, version = dep.get("name", "?"), dep.get("version", "?")
            ids = [str(v.get("id")) for v in vulns]
            findings.append(
                Finding(
                    tool=self.name,
                    rule=ids[0] if len(ids) == 1 else f"{len(ids)}-advisories",
                    severity=Severity.MEDIUM,  # pip-audit gives no CVSS; osv-scanner's grading wins on merge
                    path=rel,
                    line=0,
                    message=f"{name} {version} (PyPI): {len(ids)} known vulnerabilities",
                    fingerprint=fingerprint(
                        "osv-scanner", "dependency", rel, f"PyPI:{name.lower()}@{version}"
                    ),
                    confidence="high",
                    category="vulnerable-dependency",
                    cwe=["CWE-1395"],
                    snippet=f"{name}=={version}",
                    extra={"package": name, "version": version, "advisories": ids[:20]},
                )
            )
        return findings
