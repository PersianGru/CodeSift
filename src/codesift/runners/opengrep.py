"""opengrep: code patterns. Uses only the *security* rules of the detected languages (rule loading
dominates run time), prepared once per rules commit + language set in the cache dir."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

from codesift.detect import (
    DEFAULT_EXCLUDE_DIRS,
    GO_EXT,
    JS_EXT,
    PHP_EXT,
    PY_EXT,
    SHELL_EXT,
    TEST_DIRS,
    TEST_FILE_GLOBS,
)
from codesift.finding import Finding, cap, fingerprint, lower, normalize_cwes
from codesift.models import Severity
from codesift.rules import RULESETS
from codesift.runners.base import MAX_FILE_TARGETS, Context, Runner, RunnerError, scrub_file

LEVEL = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
ECO_RULESETS = {
    "python": ("python",),
    "js": ("javascript", "typescript"),
    "php": ("php",),
    "go": ("go",),
    "docker": ("dockerfile",),
    "yaml": ("yaml",),
    "shell": ("bash",),
}
CODE_EXT = PY_EXT + JS_EXT + PHP_EXT + GO_EXT + SHELL_EXT + (".yml", ".yaml", ".html", ".conf")


def rulesets_for(ecosystems: set[str]) -> list[str]:
    chosen = {"generic"}
    for eco, sets in ECO_RULESETS.items():
        if eco in ecosystems:
            chosen.update(sets)
    return sorted(chosen)


def prepare_rules(rules_dir: Path, cache_root: Path, rulesets: list[str], commit: str) -> Path:
    """Copy the security rules of the chosen rulesets into a cache dir (once) and return it."""
    key = hashlib.sha256(f"{commit}|{','.join(rulesets)}|v1".encode()).hexdigest()[:16]
    dest = cache_root / "opengrep-rules" / key
    marker = dest / ".complete"
    if marker.is_file():
        return dest
    # Built in place; the marker (written last) says it is complete. No directory rename: on Windows a
    # virus scanner or indexer briefly holding the fresh files makes renames fail with "Access denied".
    staging = dest
    shutil.rmtree(dest, ignore_errors=True)
    count = 0
    for ruleset in rulesets:
        base = rules_dir / ruleset
        if not base.is_dir():
            continue
        for path in base.rglob("*.y*ml"):
            rel = path.relative_to(rules_dir)
            if "security" not in rel.parts:
                continue
            target = staging / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            count += 1
    if count == 0:
        raise RunnerError(f"no security rules found in {rules_dir} for {', '.join(rulesets)}")
    marker.write_text(str(count), encoding="utf-8")
    return dest


def clean_rule_id(check_id: str) -> str:
    """Drop the path-derived prefix opengrep puts in front of rule ids."""
    parts = check_id.split(".")
    for i, part in enumerate(parts):
        if part in RULESETS or part == "custom":
            return ".".join(parts[i:])
    return check_id


def opengrep_severity(level: str, metadata: dict[str, object]) -> Severity:
    sev = LEVEL.get(level.upper(), Severity.MEDIUM)
    subcats = metadata.get("subcategory") or []
    if isinstance(subcats, list) and "audit" in [str(s).lower() for s in subcats]:
        sev = cap(sev, Severity.MEDIUM)  # audit rules flag patterns, not proven data flow
    if str(metadata.get("confidence", "")).upper() == "LOW":
        sev = lower(sev)
    return sev


class Opengrep(Runner):
    name = "opengrep"
    excludes_tests = True
    binary_tool = "opengrep"

    def applies(self, ctx: Context) -> str | None:
        if ctx.rules_dir is None:
            return "rules not installed (run `sift install`)"
        if ctx.incremental and not ctx.changed_matching(exclude_tests=True, exts=CODE_EXT):
            return "no changed source files"
        return None

    def run(self, ctx: Context) -> list[Finding]:
        if ctx.rules_dir is None:
            raise RunnerError("rules not installed")
        commit = ctx.lock.rules.commit if ctx.lock.rules else "dev"
        rules = prepare_rules(
            ctx.rules_dir, ctx.paths.data / "cache", rulesets_for(ctx.detection.ecosystems), commit
        )
        out = ctx.raw_dir / "opengrep.json"
        threads = max(1, min(6, (os.cpu_count() or 2) // 2))
        argv = [
            str(self.executable(ctx)),
            "scan",
            "--config",
            str(rules),
            "--json-output",
            str(out),
            "--quiet",
            "--disable-version-check",
            "--x-ignore-semgrepignore-files",
            "--exclude-minified-files",
            "-j",
            str(threads),
            "--timeout",
            "30",
        ]
        for extra in ctx.extra_rules_dirs:
            argv += ["--config", str(extra)]
        for pattern in [*DEFAULT_EXCLUDE_DIRS, *TEST_DIRS, *TEST_FILE_GLOBS, *ctx.exclude_globs]:
            argv.append(f"--exclude={pattern}")
        targets = ctx.changed_matching(exclude_tests=True, exts=CODE_EXT) if ctx.incremental else []
        if targets and len(targets) <= MAX_FILE_TARGETS:
            argv += [str(ctx.root / t) for t in targets]
        else:
            argv.append(str(ctx.root))
        self.exec(ctx, argv, ok_codes=(0, 1, 2))
        if not out.is_file():
            raise RunnerError("opengrep produced no output")
        text = out.read_text(encoding="utf-8")
        findings = self.parse(ctx, text)
        scrub_file(ctx, out)
        return findings

    def parse(self, ctx: Context, text: str) -> list[Finding]:
        try:
            data = json.loads(text or "{}")
        except ValueError:
            raise RunnerError("opengrep wrote invalid JSON") from None
        findings = []
        for r in data.get("results") or []:
            extra = r.get("extra") or {}
            md = extra.get("metadata") or {}
            rel = ctx.rel(str(r.get("path", "")))
            start = int((r.get("start") or {}).get("line") or 0)
            end = int((r.get("end") or {}).get("line") or start)
            rule = clean_rule_id(str(r.get("check_id", "?")))
            snippet = self.snippet(ctx, rel, start, end)
            conf = str(md.get("confidence", "medium")).lower()
            findings.append(
                Finding(
                    tool=self.name,
                    rule=rule,
                    severity=opengrep_severity(str(extra.get("severity", "")), md),
                    path=rel,
                    line=start,
                    end_line=end,
                    message=" ".join(str(extra.get("message", "")).split())[:300],
                    fingerprint=fingerprint(self.name, rule, rel, snippet),
                    confidence=conf if conf in ("low", "medium", "high") else "medium",
                    category=str(
                        md.get("vulnerability_class", [""])[0] if md.get("vulnerability_class") else ""
                    )
                    or rule.split(".")[-1],
                    cwe=normalize_cwes(md.get("cwe", [])),
                    snippet=snippet,
                    extra={"references": list(md.get("references", []))[:2]},
                )
            )
        errors = [e for e in data.get("errors") or [] if str(e.get("level", "")).lower() == "error"]
        if errors and not findings and not (data.get("paths") or {}).get("scanned"):
            raise RunnerError(f"opengrep reported {len(errors)} error(s); see raw/opengrep.json")
        return findings
