"""Scanner runners. ALL_RUNNERS order = default execution order (gitleaks first)."""

from __future__ import annotations

from codesift.runners.base import Context, Runner, RunnerError, RunResult
from codesift.runners.gitleaks import Gitleaks
from codesift.runners.opengrep import Opengrep
from codesift.runners.optional import ComposerAudit, Govulncheck
from codesift.runners.osv import OsvScanner
from codesift.runners.python import Bandit, PipAudit, Ruff
from codesift.runners.trivy import Trivy
from codesift.runners.zizmor import Zizmor

ALL_RUNNERS: tuple[type[Runner], ...] = (
    Gitleaks,
    OsvScanner,
    Opengrep,
    Trivy,
    Ruff,
    Bandit,
    Zizmor,
    PipAudit,
    ComposerAudit,
    Govulncheck,
)
RUNNER_NAMES = tuple(r.name for r in ALL_RUNNERS)

__all__ = ["ALL_RUNNERS", "RUNNER_NAMES", "Context", "RunResult", "Runner", "RunnerError"]
