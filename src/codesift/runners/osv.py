"""osv-scanner: known-vulnerable dependencies from lockfiles/manifests. Sends package names and
versions (never code) to api.osv.dev. Transitive resolution via deps.dev is disabled (--no-resolve)
so no other host is contacted."""

from __future__ import annotations

import json
from typing import Any

from codesift.detect import DEFAULT_EXCLUDE_DIRS, is_dependency_file
from codesift.finding import Finding, fingerprint
from codesift.models import Severity
from codesift.runners.base import Context, Runner, RunnerError, scrub_file

OSV_EXIT_VULNS = 1


def cvss_severity(score: Any) -> Severity:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return Severity.MEDIUM  # unknown score: never hide it as low
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    if value > 0:
        return Severity.LOW
    return Severity.MEDIUM


class OsvScanner(Runner):
    name = "osv-scanner"
    binary_tool = "osv-scanner"
    needs_network = True

    def applies(self, ctx: Context) -> str | None:
        if not ctx.detection.has("deps"):
            return "no lockfiles or manifests found"
        if ctx.incremental and not any(is_dependency_file(f) for f in ctx.changed or []):
            return "no dependency file changed"
        return None

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.raw_dir / "osv-scanner.json"
        argv = [
            str(self.executable(ctx)),
            "scan",
            "source",
            "-r",
            "--no-resolve",
            "--no-call-analysis=all",
            "--allow-no-lockfiles",
            "--format",
            "json",
            "--output-file",
            str(out),
            "--verbosity",
            "error",
        ]
        for d in DEFAULT_EXCLUDE_DIRS:
            if d != ".git":
                argv += ["--x-exclude", d]
        for glob in ctx.exclude_globs:
            argv += ["--x-exclude", f"g:{glob}"]
        argv.append(str(ctx.root))
        self.exec(ctx, argv, ok_codes=(0, OSV_EXIT_VULNS, 128))
        scrub_file(ctx, out)
        return self.parse(ctx, out.read_text(encoding="utf-8") if out.is_file() else "{}")

    def parse(self, ctx: Context, text: str) -> list[Finding]:
        try:
            data = json.loads(text or "{}")
        except ValueError:
            raise RunnerError("osv-scanner wrote invalid JSON") from None
        findings = []
        for result in data.get("results") or []:
            rel = ctx.rel(str((result.get("source") or {}).get("path", "")))
            for pkg in result.get("packages") or []:
                info = pkg.get("package") or {}
                name, version, eco = (
                    info.get("name", "?"),
                    info.get("version", "?"),
                    info.get("ecosystem", ""),
                )
                groups = pkg.get("groups") or []
                vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
                if not groups and not vulns:
                    continue
                ids: list[str] = []
                worst = Severity.INFO
                for g in groups:
                    gid = sorted(g.get("ids") or [], key=lambda x: (not x.startswith(("GHSA", "CVE")), x))
                    ids.append(gid[0] if gid else "?")
                    worst = max(worst, cvss_severity(g.get("max_severity")))
                if not groups:
                    ids = sorted(str(k) for k in vulns)
                    worst = Severity.MEDIUM
                summaries = [str(v.get("summary", "")) for v in vulns.values() if v.get("summary")]
                first = summaries[0][:120] if summaries else ""
                fixed = _fixed_versions(pkg)
                noun = "vulnerability" if len(ids) == 1 else "vulnerabilities"
                message = f"{name} {version} ({eco}): {len(ids)} known {noun}"
                if first:
                    message += f" - e.g. {first}"
                findings.append(
                    Finding(
                        tool=self.name,
                        rule=ids[0] if len(ids) == 1 else f"{len(ids)}-advisories",
                        severity=worst,
                        path=rel,
                        line=0,
                        message=message,
                        fingerprint=fingerprint(self.name, "dependency", rel, f"{eco}:{name}@{version}"),
                        confidence="high",
                        category="vulnerable-dependency",
                        cwe=["CWE-1395"],
                        snippet=f"{name}=={version}",
                        extra={
                            "package": name,
                            "version": version,
                            "ecosystem": eco,
                            "advisories": ids[:20],
                            "fixed_in": fixed[:5],
                        },
                    )
                )
        return findings


def _fixed_versions(pkg: dict[str, Any]) -> list[str]:
    fixed: set[str] = set()
    for v in pkg.get("vulnerabilities") or []:
        for aff in v.get("affected") or []:
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if "fixed" in ev:
                        fixed.add(str(ev["fixed"]))
    return sorted(fixed)
