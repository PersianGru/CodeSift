"""Opt-in runners that use tools from the user's PATH (not pinned by CodeSift):
composer audit (PHP) and govulncheck (Go). Both are off unless enabled in .codesift.toml, because
they contact hosts outside CodeSift's network allow-list (packagist.org, vuln.go.dev / Go proxy) and
osv-scanner already covers composer.lock and go.mod."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from codesift.finding import Finding, fingerprint
from codesift.models import Severity
from codesift.runners.base import Context, Runner, RunnerError, scrub_file

SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class PathRunner(Runner):
    command = ""
    opt_in = True
    needs_network = True

    def executable(self, ctx: Context) -> Path:
        exe = shutil.which(self.command)
        if exe is None:
            raise RunnerError(f"{self.command} is not installed / not on PATH")
        return Path(exe)

    def version(self, ctx: Context) -> str:
        return "system"


class ComposerAudit(PathRunner):
    name = "composer-audit"
    command = "composer"

    def applies(self, ctx: Context) -> str | None:
        if not (ctx.root / "composer.lock").is_file():
            return "no composer.lock in the project root"
        return None if shutil.which(self.command) else "composer not installed"

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.raw_dir / "composer-audit.json"
        argv = [
            str(self.executable(ctx)),
            "audit",
            "--locked",
            "--format=json",
            "--no-plugins",
            "--no-scripts",
            "--no-interaction",
            f"--working-dir={ctx.root}",
        ]
        self.exec(ctx, argv, stdout_file=out, ok_codes=(0, 1, 2, 3))
        scrub_file(ctx, out)
        return self.parse(ctx, out.read_text(encoding="utf-8") if out.is_file() else "{}")

    def parse(self, ctx: Context, text: str) -> list[Finding]:
        try:
            data = json.loads(text or "{}")
        except ValueError:
            raise RunnerError("composer audit wrote invalid JSON") from None
        advisories = data.get("advisories") or {}
        if isinstance(advisories, list):  # composer prints [] when there is nothing
            advisories = {}
        findings = []
        for package, items in advisories.items():
            items = list(items.values()) if isinstance(items, dict) else list(items)
            if not items:
                continue
            ids = [str(a.get("cve") or a.get("advisoryId") or "?") for a in items]
            worst = max(SEVERITY.get(str(a.get("severity", "")).lower(), Severity.MEDIUM) for a in items)
            findings.append(
                Finding(
                    tool=self.name,
                    rule=ids[0] if len(ids) == 1 else f"{len(ids)}-advisories",
                    severity=worst,
                    path="composer.lock",
                    line=0,
                    message=f"{package}: {len(ids)} advisories - e.g. {str(items[0].get('title', ''))[:120]}",
                    fingerprint=fingerprint(self.name, "dependency", "composer.lock", package),
                    confidence="high",
                    category="vulnerable-dependency",
                    cwe=["CWE-1395"],
                    snippet=package,
                    extra={"package": package, "advisories": ids[:20]},
                )
            )
        return findings


class Govulncheck(PathRunner):
    name = "govulncheck"
    command = "govulncheck"

    def applies(self, ctx: Context) -> str | None:
        if not (ctx.root / "go.mod").is_file():
            return "no go.mod in the project root"
        return None if shutil.which(self.command) else "govulncheck not installed"

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.raw_dir / "govulncheck.json"
        argv = [str(self.executable(ctx)), "-C", str(ctx.root), "-json", "./..."]
        # Never download modules or toolchains while scanning.
        env = {"GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local", "GOPROXY": "off"}
        self.exec(ctx, argv, stdout_file=out, ok_codes=(0, 3), env_extra=env)
        scrub_file(ctx, out)
        return self.parse(ctx, out.read_text(encoding="utf-8") if out.is_file() else "")

    def parse(self, ctx: Context, text: str) -> list[Finding]:
        osv: dict[str, dict[str, Any]] = {}
        called: dict[str, dict[str, Any]] = {}
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(text):
            while idx < len(text) and text[idx].isspace():
                idx += 1
            if idx >= len(text):
                break
            try:
                obj, idx = decoder.raw_decode(text, idx)
            except ValueError:
                raise RunnerError("govulncheck wrote invalid JSON") from None
            if "osv" in obj:
                osv[obj["osv"]["id"]] = obj["osv"]
            elif "finding" in obj:
                f = obj["finding"]
                trace = f.get("trace") or []
                if trace and trace[0].get("function"):  # only symbol-level (reachable) findings
                    called.setdefault(f["osv"], f)
        findings = []
        for vid, f in called.items():
            frame = (f.get("trace") or [{}])[-1]
            pos = frame.get("position") or {}
            rel = ctx.rel(str(pos.get("filename", ""))) if pos else "go.mod"
            line = int(pos.get("line", 0) or 0)
            summary = str((osv.get(vid) or {}).get("summary", ""))
            findings.append(
                Finding(
                    tool=self.name,
                    rule=vid,
                    severity=Severity.HIGH,  # reachable vulnerable code
                    path=rel,
                    line=line,
                    message=f"reachable vulnerable code ({vid}): {summary}"[:300],
                    fingerprint=fingerprint(self.name, vid, rel, str(frame.get("function", ""))),
                    confidence="high",
                    category="vulnerable-dependency",
                    cwe=["CWE-1395"],
                    snippet=self.snippet(ctx, rel, line, line),
                    extra={"module": (f.get("trace") or [{}])[0].get("module", "")},
                )
            )
        return findings
