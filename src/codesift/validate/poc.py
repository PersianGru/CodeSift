"""Proofs of concept for the PoC gates. They run ONLY inside the sandbox (RULES.md rule 11).

Only project-supplied PoCs are supported: commands from `[validate.poc]`, keyed by CWE
(exit 0 = the vulnerable behaviour was reproduced, non-zero = blocked). Canned probes and
model-drafted PoCs are not part of this release (ADR-0016); for those findings the PoC gates are
"unavailable", never a pass.

A PoC that does not reproduce on the baseline makes the finding *inconclusive*, never "safe"."""

from __future__ import annotations

from dataclasses import dataclass, field

from codesift.config import ValidateSettings
from codesift.finding import Finding


@dataclass
class PocPlan:
    kind: str  # project
    command: str
    files: dict[str, bytes] = field(default_factory=dict)
    note: str = ""


def plan_for(finding: Finding, settings: ValidateSettings, mode: str) -> tuple[PocPlan | None, str]:
    """Returns (plan, reason). No plan -> the PoC gates are "unavailable" (never a pass)."""
    if mode == "none":
        return None, "PoCs disabled (--poc none)"
    if mode != "project":
        return None, f"PoC mode {mode!r} is not available in this release (ADR-0016)"
    for cwe in (c.upper() for c in finding.cwe):
        if cwe in settings.poc:
            return PocPlan("project", settings.poc[cwe], note=f"project PoC for {cwe}"), ""
    return None, "no PoC configured for this finding ([validate.poc])"
