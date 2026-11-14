"""Deterministic gates (RULES.md rule 12): project tests before/after, PoC before/after, re-scan.
A gate that cannot run is reported as "unavailable" - never as a pass."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from codesift.finding import Finding
from codesift.models import Severity
from codesift.paths import Paths
from codesift.vm.sandbox import JobResult, Sandbox

PASS, FAIL, UNAVAILABLE, SKIPPED = "pass", "fail", "unavailable", "skipped"
GATES = ("policy", "poc", "tests", "rescan")

_FAILED_PATTERNS = (
    re.compile(r"^FAILED (\S+)", re.MULTILINE),  # pytest -q / -rf
    re.compile(r"^ERROR (\S+)", re.MULTILINE),  # pytest collection errors
    re.compile(r"^--- FAIL: (\S+)", re.MULTILINE),  # go test
    re.compile(r"^\s+[\u2715\u00d7] (.+)$", re.MULTILINE),  # jest
    re.compile(r"^not ok \d+ - (.+)$", re.MULTILINE),  # TAP
)


@dataclass
class Gate:
    status: str = SKIPPED
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "detail": self.detail}


@dataclass
class TestRun:
    rc: int
    failed: set[str] | None  # None = could not be parsed
    detail: str = ""
    job: JobResult | None = None


def parse_failed(output: str) -> set[str] | None:
    found: set[str] = set()
    for pattern in _FAILED_PATTERNS:
        found.update(m.group(1).strip()[:200] for m in pattern.finditer(output))
    return found or None


def run_tests(sandbox: Sandbox, tar: bytes, command: str, timeout: int) -> TestRun:
    job = sandbox.run_job(command, tar, timeout)
    if job.rejected:
        return TestRun(125, None, f"input refused: {job.rejected}", job)
    failed = set() if job.rc == 0 else parse_failed(job.output)
    detail = "passed" if job.rc == 0 else f"exit {job.rc}" + (" (timed out)" if job.timed_out else "")
    return TestRun(job.rc, failed, detail, job)


def tests_gate(before: TestRun | None, after: TestRun | None) -> Gate:
    """No test that passed on the baseline may fail after the patch."""
    if before is None or after is None:
        return Gate(UNAVAILABLE, "no test command configured ([validate] test)")
    if before.job is not None and before.job.timed_out:
        return Gate(UNAVAILABLE, "the baseline test run timed out")
    if after.rc == 0:
        return Gate(PASS, "tests pass after the patch" + (" (they failed before)" if before.rc else ""))
    if before.rc == 0:
        return Gate(FAIL, f"tests passed on the baseline and fail after the patch ({after.detail})")
    if before.failed is None or after.failed is None:
        return Gate(UNAVAILABLE, "tests already failed on the baseline and the failures cannot be compared")
    new = sorted(after.failed - before.failed)
    if new:
        return Gate(FAIL, f"{len(new)} test(s) newly failing: {', '.join(new[:5])}")
    return Gate(PASS, f"no new failures ({len(after.failed)} failed before and after)")


def poc_reproduces(job: JobResult) -> bool | None:
    """True = vulnerable behaviour reproduced (exit 0); False = blocked; None = could not tell."""
    if job.rejected or job.timed_out or job.rc in (125, 126, 127):
        return None
    return job.rc == 0


class Rescanner(Protocol):
    def scan(self, root: Path, since: str | None) -> list[Finding] | None:
        """Findings in `root` (only files changed since `since` when given); None = unavailable."""


@dataclass
class ScanRescanner:
    """The existing static scanners, run locally on the workspace copy (read-only, no LLM, offline)."""

    paths: Paths
    runs_dir: Path
    errors: list[str] = field(default_factory=list)

    def scan(self, root: Path, since: str | None) -> list[Finding] | None:
        from codesift.scan import ScanError, ScanOptions, scan

        paths = Paths(
            data=self.paths.data,
            config=self.paths.config,
            runs=self.runs_dir,
            bin=self.paths.bin,
            skill=self.paths.skill,
        )
        try:
            outcome = scan(ScanOptions(path=str(root), no_llm=True, offline=True, since=since), paths)
        except ScanError as exc:
            self.errors.append(str(exc))
            return None
        failed = [r.name for r in outcome.results if r.status == "error"]
        ran = [r.name for r in outcome.results if r.status == "ok"]
        if not ran:
            self.errors.append("no scanner could run")
            return None
        if failed:
            self.errors.append("scanner errors: " + ", ".join(failed))
        return outcome.findings


def fingerprints(findings: list[Finding]) -> set[str]:
    return {fp for f in findings for fp in f.all_fingerprints}


def rescan_gate(
    finding: Finding | None, baseline: set[str], after: list[Finding] | None, changed: list[str]
) -> Gate:
    if after is None:
        return Gate(UNAVAILABLE, "the re-scan could not run")
    after_fps = fingerprints(after)
    if finding is not None and set(finding.all_fingerprints) & after_fps:
        return Gate(FAIL, f"{finding.id} is still reported after the patch")
    new = [
        f
        for f in after
        if f.severity >= Severity.MEDIUM
        and not f.baseline
        and f.path in changed
        and not set(f.all_fingerprints) & baseline
    ]
    if new:
        shown = ", ".join(f"{f.rules[0]} at {f.location}" for f in new[:3])
        return Gate(FAIL, f"{len(new)} new finding(s) at medium or above: {shown}")
    return Gate(PASS, ("finding gone, " if finding else "") + "no new findings at medium or above")
