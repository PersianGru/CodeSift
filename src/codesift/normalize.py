"""Post-processing of runner output: secret-line hiding, dedupe, ordering, IDs."""

from __future__ import annotations

from typing import Any

from codesift.finding import Finding
from codesift.models import Severity
from codesift.redact import Redactor

HIDDEN = "[line hidden: gitleaks found a secret here]"
CONF_RANK = {"high": 2, "medium": 1, "low": 0}


def hide_secret_lines(findings: list[Finding]) -> None:
    """No snippet of any other tool may show a line on which gitleaks found a secret."""
    secret_lines: dict[str, set[int]] = {}
    for f in findings:
        if f.tool == "gitleaks" and f.extra.get("source") != "history" and f.line:
            secret_lines.setdefault(f.path, set()).update(range(f.line, f.end_line + 1))
    for f in findings:
        if f.tool == "gitleaks" or not f.snippet or f.path not in secret_lines:
            continue
        hidden = secret_lines[f.path]
        lines = f.snippet.split("\n")
        f.snippet = "\n".join(HIDDEN if (f.line + i) in hidden else text for i, text in enumerate(lines))


def scrub_findings(findings: list[Finding], redactor: Redactor) -> None:
    """Final masking pass over every free-text field (tools echo matched strings in messages,
    e.g. bandit's "Possible hardcoded password: '…'")."""

    def clean(value: Any) -> Any:
        if isinstance(value, str):
            return redactor.scrub(value)
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items()}
        return value

    for f in findings:
        f.message = redactor.scrub(f.message)
        f.snippet = redactor.scrub(f.snippet)
        f.category = redactor.scrub(f.category)
        f.extra = clean(f.extra)


def _related(a: Finding, b: Finding) -> bool:
    if a.path != b.path or not a.path:
        return False
    if a.line == 0 or b.line == 0:
        if a.line == b.line == 0:
            return a.fingerprint == b.fingerprint
        # a whole-file finding (e.g. trivy's Dockerfile checks) and a line finding of the same kind
        return bool(families(a) & families(b) & FILE_LEVEL_FAMILIES)
    if a.line > b.end_line or b.line > a.end_line:
        return False
    if set(a.aliases) & set(b.aliases):
        return True
    if a.cwe and b.cwe and set(a.cwe) & set(b.cwe):
        return True
    return bool(families(a) & families(b))


# Issue families: tools label the same weakness with different CWEs (e.g. eval = CWE-78 in bandit,
# CWE-95 in opengrep). Matching on these keywords in rule ids/categories lets dedupe merge them.
FAMILIES: dict[str, tuple[str, ...]] = {
    "sql": ("sql",),
    "command": (
        "subprocess",
        "shell",
        "exec-",
        "command",
        "os-system",
        "tainted-exec",
        "child-process",
        "b60",
    ),
    "eval": ("eval", "code-injection", "exec-detected"),
    "deserialization": ("pickle", "deserializ", "unserialize", "marshal"),
    "yaml": ("yaml",),
    "xss": ("xss", "innerhtml", "echoed", "raw-html", "html-format", "autoescape"),
    "tls": ("cert-validation", "verify", "ssl", "tls", "insecure-skip", "b501"),
    "debug": ("debug",),
    "weak-hash": ("md5", "sha1", "weak-hash", "insecure-hash"),
    "redirect": ("redirect",),
    "path": ("path-traversal", "file-inclusion", "tainted-filename"),
    "secret": ("secret", "password", "hardcoded", "credential", "api-key"),
    "unpinned-action": ("unpinned-uses", "not-pinned-to-commit-sha"),
    "container-root": ("ds-0002", "ds002", "missing-user", "root-user"),
}
# Families whose findings are about a whole file, so a line-less report may merge with a line report.
FILE_LEVEL_FAMILIES = {"container-root"}


def families(f: Finding) -> set[str]:
    text = " ".join([*f.rules, f.category]).lower()
    return {name for name, words in FAMILIES.items() if any(w in text for w in words)}


def _rank(f: Finding) -> tuple[int, int, int]:
    # Prefer the most severe, then most confident, then dataflow-ish tools as the primary record.
    tool_pref = {"opengrep": 3, "bandit": 2, "trivy": 2, "zizmor": 2, "ruff": 1}.get(f.tool, 2)
    return (int(f.severity), CONF_RANK.get(f.confidence, 1), tool_pref)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge reports of the same issue (same path, overlapping lines, shared CWE or alias, or the
    same fingerprint) into one finding that lists every tool and rule."""
    by_fp: dict[str, Finding] = {}
    unique: list[Finding] = []
    for f in findings:  # exact duplicates first (e.g. same secret in several commits)
        if f.fingerprint in by_fp:
            continue
        by_fp[f.fingerprint] = f
        unique.append(f)

    unique.sort(key=lambda f: (f.path, f.line, -int(f.severity)))
    merged: list[Finding] = []
    open_by_path: dict[str, list[Finding]] = {}
    for f in unique:
        target = next((g for g in open_by_path.get(f.path, []) if _related(g, f)), None)
        if target is None:
            merged.append(f)
            open_by_path.setdefault(f.path, []).append(f)
            continue
        primary, other = (f, target) if _rank(f) > _rank(target) else (target, f)
        if primary is f:  # swap content into the existing object so references stay valid
            target_copy = Finding.from_dict(target.to_dict())
            _absorb(f, target_copy)
            _replace(target, f)
        else:
            _absorb(target, other)
    return merged


def _absorb(primary: Finding, other: Finding) -> None:
    for tool in other.tools:
        if tool not in primary.tools:
            primary.tools.append(tool)
    for rule in other.rules:
        if rule not in primary.rules:
            primary.rules.append(rule)
    for fp in other.all_fingerprints:
        if fp not in primary.all_fingerprints:
            primary.alt_fingerprints.append(fp)
    for cwe in other.cwe:
        if cwe not in primary.cwe:
            primary.cwe.append(cwe)
    for alias in other.aliases:
        if alias not in primary.aliases:
            primary.aliases.append(alias)
    primary.end_line = max(primary.end_line, other.end_line)
    if CONF_RANK.get(other.confidence, 1) > CONF_RANK.get(primary.confidence, 1):
        primary.confidence = other.confidence


def _replace(target: Finding, source: Finding) -> None:
    for key, value in vars(source).items():
        setattr(target, key, value)


def order_and_number(findings: list[Finding]) -> list[Finding]:
    findings.sort(
        key=lambda f: (f.baseline, -int(f.severity), -CONF_RANK.get(f.confidence, 1), f.path, f.line, f.rule)
    )
    width = max(3, len(str(len(findings))))
    for i, f in enumerate(findings, start=1):
        f.id = f"F{i:0{width}d}"
    return findings


# Deterministic, per-occurrence policy rules: one finding per file instead of one per line.
GROUPED_RULES = {("zizmor", "unpinned-uses")}


def group_policy_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse non-baselined occurrences of GROUPED_RULES per file and severity. The group keeps
    every fingerprint, so accepting it covers today's occurrences while a new one shows up again."""
    out: list[Finding] = []
    groups: dict[tuple[str, str, str, int], Finding] = {}
    for f in findings:
        key = (f.tool, f.rule, f.path, int(f.severity))
        if (f.tool, f.rule) not in GROUPED_RULES or f.baseline:
            out.append(f)
            continue
        head = groups.get(key)
        if head is None:
            groups[key] = f
            f.extra["lines"] = [f.line]
            out.append(f)
            continue
        head.extra["lines"].append(f.line)
        head.alt_fingerprints.extend(fp for fp in f.all_fingerprints if fp not in head.all_fingerprints)
        head.end_line = max(head.end_line, f.end_line)
    for head in groups.values():
        lines = head.extra["lines"]
        if len(lines) > 1:
            shown = ", ".join(map(str, lines[:12]))
            head.message = f"{len(lines)} occurrences (lines {shown}): {head.message}"
    return out


def mark_review(findings: list[Finding]) -> None:
    """High/critical findings always need a human look, whatever the LLM says (RULES.md §5)."""
    for f in findings:
        f.needs_review = f.severity >= Severity.HIGH and not f.baseline
