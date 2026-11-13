"""trivy config: Dockerfile / Kubernetes / Terraform / Helm misconfigurations.
Downloads its check bundle from its registry unless --offline (then the built-in checks are used)."""

from __future__ import annotations

import json

from codesift.detect import DEFAULT_EXCLUDE_DIRS, is_iac
from codesift.finding import Finding, fingerprint
from codesift.models import Severity
from codesift.runners.base import Context, Runner, RunnerError, scrub_file

SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}
# Image-hygiene checks that trivy rates HIGH but carry no direct security impact (docs/severity.md).
OVERRIDES = {"DS-0029": Severity.LOW, "DS029": Severity.LOW}


class Trivy(Runner):
    name = "trivy"
    binary_tool = "trivy"

    def applies(self, ctx: Context) -> str | None:
        if not (ctx.detection.has("docker") or ctx.detection.has("iac")):
            return "no Dockerfile / Kubernetes / Terraform / Helm files"
        if ctx.incremental and not any(is_iac(f) for f in ctx.changed or []):
            return "no Dockerfile / IaC file changed"
        return None

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.raw_dir / "trivy.json"
        cache = ctx.paths.data / "cache" / "trivy"
        cache.mkdir(parents=True, exist_ok=True)
        argv = [
            str(self.executable(ctx)),
            "config",
            "--format",
            "json",
            "--output",
            str(out),
            "--quiet",
            "--cache-dir",
            str(cache),
            "--disable-telemetry",
            "--skip-version-check",
        ]
        if ctx.offline:
            argv.append("--skip-check-update")
        skip = [f"**/{d}" for d in DEFAULT_EXCLUDE_DIRS] + list(ctx.exclude_globs)
        argv += ["--skip-dirs", ",".join(skip)]
        argv.append(str(ctx.root))
        self.exec(ctx, argv)
        scrub_file(ctx, out)
        return self.parse(ctx, out.read_text(encoding="utf-8") if out.is_file() else "{}")

    def parse(self, ctx: Context, text: str) -> list[Finding]:
        try:
            data = json.loads(text or "{}")
        except ValueError:
            raise RunnerError("trivy wrote invalid JSON") from None
        findings = []
        for result in data.get("Results") or []:
            rel = ctx.rel(str(result.get("Target", "")))
            for m in result.get("Misconfigurations") or []:
                if m.get("Status", "FAIL") != "FAIL":
                    continue
                cause = m.get("CauseMetadata") or {}
                start = int(cause.get("StartLine") or 0)
                end = int(cause.get("EndLine") or start)
                code_lines = [
                    str(x.get("Content", "")) for x in ((cause.get("Code") or {}).get("Lines") or [])
                ]
                code = "\n".join(code_lines) if code_lines else ""
                rule = str(m.get("ID") or m.get("AVDID") or "?")
                msg = str(m.get("Message") or m.get("Title") or "")
                findings.append(
                    Finding(
                        tool=self.name,
                        rule=rule,
                        severity=OVERRIDES.get(
                            rule, SEVERITY.get(str(m.get("Severity", "")).upper(), Severity.MEDIUM)
                        ),
                        path=rel,
                        line=start,
                        end_line=end,
                        message=f"{m.get('Title', rule)}: {msg}"[:300],
                        fingerprint=fingerprint(self.name, rule, rel, code or msg),
                        confidence="high",
                        category="misconfiguration",
                        snippet=(
                            ctx.redactor.scrub(code)[:1000] if code else self.snippet(ctx, rel, start, end)
                        ),
                        extra={
                            "url": m.get("PrimaryURL", ""),
                            "resolution": str(m.get("Resolution", ""))[:200],
                        },
                    )
                )
        return findings
