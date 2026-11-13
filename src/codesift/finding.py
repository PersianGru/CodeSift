"""Normalized finding (docs/architecture.md, report.json schema)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from codesift.models import Severity

_WS = re.compile(r"\s+")


def fingerprint(tool: str, rule: str, path: str, code: str) -> str:
    """Stable across edits elsewhere in the file: no line numbers, whitespace-insensitive."""
    normalized = _WS.sub("", code)
    return hashlib.sha256(f"{tool}|{rule}|{path}|{normalized}".encode()).hexdigest()


@dataclass
class Triage:
    verdict: str = ""  # likely_real | likely_false_positive | unsure
    reason: str = ""
    quoted_line: str = ""
    fix: str = ""
    severity_suggestion: str = ""
    model: str = ""
    status: str = "skipped"  # done | skipped | failed | cached
    note: str = ""


@dataclass
class Finding:
    tool: str
    rule: str
    severity: Severity
    path: str  # project-relative, forward slashes ("" for project-wide)
    line: int  # 1-based, 0 = not applicable (e.g. dependency findings)
    message: str
    fingerprint: str
    end_line: int = 0
    confidence: str = "medium"  # low | medium | high
    category: str = ""
    cwe: list[str] = field(default_factory=list)
    snippet: str = ""
    aliases: list[str] = field(default_factory=list)  # cross-tool equivalence keys (e.g. bandit:B602)
    extra: dict[str, Any] = field(default_factory=dict)  # tool-specific, small
    # filled in later
    id: str = ""
    tools: list[str] = field(default_factory=list)  # all tools that reported it (after dedupe)
    rules: list[str] = field(default_factory=list)
    alt_fingerprints: list[str] = field(default_factory=list)
    baseline: bool = False
    baseline_reason: str = ""
    needs_review: bool = False
    triage: Triage = field(default_factory=Triage)

    def __post_init__(self) -> None:
        if not self.end_line or self.end_line < self.line:
            self.end_line = self.line
        if not self.tools:
            self.tools = [self.tool]
        if not self.rules:
            self.rules = [f"{self.tool}:{self.rule}"]

    @property
    def location(self) -> str:
        if not self.path:
            return "(project)"
        return f"{self.path}:{self.line}" if self.line else self.path

    @property
    def all_fingerprints(self) -> list[str]:
        return [self.fingerprint, *self.alt_fingerprints]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        order = [
            "id",
            "fingerprint",
            "tool",
            "rule",
            "severity",
            "confidence",
            "category",
            "cwe",
            "path",
            "line",
            "end_line",
            "message",
            "snippet",
            "baseline",
            "baseline_reason",
            "needs_review",
            "triage",
            "tools",
            "rules",
            "alt_fingerprints",
            "aliases",
            "extra",
        ]
        return {k: d[k] for k in order}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        triage = Triage(**d.get("triage", {}))
        f = cls(
            tool=d["tool"],
            rule=d["rule"],
            severity=Severity.parse(d["severity"]),
            path=d["path"],
            line=int(d["line"]),
            message=d["message"],
            fingerprint=d["fingerprint"],
            end_line=int(d.get("end_line", 0)),
            confidence=d.get("confidence", "medium"),
            category=d.get("category", ""),
            cwe=list(d.get("cwe", [])),
            snippet=d.get("snippet", ""),
            aliases=list(d.get("aliases", [])),
            extra=dict(d.get("extra", {})),
            id=d.get("id", ""),
            tools=list(d.get("tools", [])),
            rules=list(d.get("rules", [])),
            alt_fingerprints=list(d.get("alt_fingerprints", [])),
            baseline=bool(d.get("baseline", False)),
            baseline_reason=d.get("baseline_reason", ""),
            needs_review=bool(d.get("needs_review", False)),
        )
        f.triage = triage
        return f


_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def normalize_cwes(values: Any) -> list[str]:
    """Accept 'CWE-78: ...', 78, ['CWE-78'], {'id': 78} and return ['CWE-78', ...] (unique, ordered)."""
    out: list[str] = []
    items = values if isinstance(values, list) else [values]
    for item in items:
        if isinstance(item, dict):
            item = item.get("id")
        if isinstance(item, int) and item > 0:
            out.append(f"CWE-{item}")
        elif isinstance(item, str):
            out.extend(f"CWE-{m}" for m in _CWE.findall(item))
    return list(dict.fromkeys(out))


def lower(sev: Severity, steps: int = 1) -> Severity:
    return Severity(max(Severity.LOW, sev - steps)) if sev > Severity.LOW else sev


def cap(sev: Severity, maximum: Severity) -> Severity:
    return min(sev, maximum)
