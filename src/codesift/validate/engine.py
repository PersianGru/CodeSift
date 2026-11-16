"""Orchestration of `sift validate` and `sift fix`.

validate: copy the project at the base revision, apply the change, and run the deterministic gates.
fix:      copy the project, let the fixer ladder propose patches, run the same gates on each.
Either way the project is never written, nothing is applied, and untrusted code runs only in the
sandbox; if the sandbox is needed and unavailable, the run fails closed (exit 2)."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from codesift import telemetry
from codesift.activity import recording, topology
from codesift.config import ConfigError, ValidateSettings, load_project_config
from codesift.finding import Finding
from codesift.fix.base import Fixer, FixRequest, Usage
from codesift.fsutil import rmtree_force
from codesift.models import Severity
from codesift.paths import Paths
from codesift.redact import Redactor
from codesift.report import project_slug
from codesift.validate import ValidateError
from codesift.validate.events import EventLog, bug_type_of, district_of
from codesift.validate.poc import PocPlan, plan_for
from codesift.validate.policy import check_patch
from codesift.validate.report import (
    MAX_LOG,
    AuditLog,
    FindingReport,
    RunReport,
    new_run_dir,
    prune,
    render_md,
    safe_file_name,
    write_json,
    write_text,
)
from codesift.validate.verify import (
    FAIL,
    PASS,
    SKIPPED,
    UNAVAILABLE,
    Gate,
    Rescanner,
    TestRun,
    fingerprints,
    poc_reproduces,
    rescan_gate,
    run_tests,
    tests_gate,
)
from codesift.validate.workspace import Workspace, create_workspace, merge_base, project_diff
from codesift.vm import SandboxError
from codesift.vm.sandbox import JobResult, Sandbox
from codesift.vm.selftest import ensure_selftest

EXIT_OK, EXIT_NOT_VERIFIED, EXIT_ERROR, EXIT_BUDGET = 0, 1, 2, 4
MAX_FINDINGS_HARD = 50
MAX_CONTENT = 60_000


@dataclass
class EngineOptions:
    mode: str = "validate"  # validate | fix
    finding_ids: list[str] = field(default_factory=list)
    min_severity: Severity = Severity.HIGH
    max_findings: int = 5
    poc_mode: str = "project"
    patch_text: str | None = None
    branch: str | None = None
    dry_run: bool = False
    backend: str | None = None
    budget_tokens: int = 200_000
    budget_s: float = 3600
    finding_budget_s: float = 900
    review_patch: bool = False


@dataclass
class LadderStep:
    backend: str
    fixer: Fixer
    attempts: int
    destination: str = ""  # what leaves the machine, for --dry-run


@dataclass
class EngineDeps:
    rescanner: Rescanner
    sandbox_factory: Callable[[], Sandbox] | None = None
    load_findings: Callable[[Path], list[Finding]] | None = None
    ladder: Callable[[Finding], list[LadderStep]] | None = None
    reviewer: Callable[[Finding, str], str] | None = None
    secrets: list[str] = field(default_factory=list)
    clock: Callable[[], float] = time.monotonic


@dataclass
class Budget:
    tokens_limit: int
    time_limit_s: float
    finding_time_s: float
    clock: Callable[[], float]
    used: Usage = field(default_factory=Usage)
    start: float = 0.0
    exhausted: bool = False

    def __post_init__(self) -> None:
        self.start = self.clock()

    def check(self, finding_start: float) -> str:
        now = self.clock()
        if self.used.total >= self.tokens_limit:
            return "token budget"
        if now - self.start >= self.time_limit_s:
            return "run time budget"
        if now - finding_start >= self.finding_time_s:
            return "per-finding time budget"
        return ""

    def to_dict(self) -> dict[str, object]:
        return {
            "tokens_used": self.used.total,
            "tokens_limit": self.tokens_limit,
            "time_limit_s": self.time_limit_s,
            "exhausted": self.exhausted,
        }


def select_findings(findings: list[Finding], opts: EngineOptions) -> list[Finding]:
    if opts.finding_ids:
        wanted = {i.strip().upper() for i in opts.finding_ids if i.strip()}
        unknown = wanted - {f.id for f in findings}
        if unknown:
            raise ValidateError(f"unknown finding id(s): {', '.join(sorted(unknown))}")
        chosen = [f for f in findings if f.id in wanted]
    else:
        chosen = [
            f
            for f in findings
            if f.severity >= opts.min_severity
            and not f.baseline
            and f.triage.verdict != "likely_false_positive"
            and f.path
        ]
    return chosen[: max(0, min(opts.max_findings, MAX_FINDINGS_HARD))]


def default_load_findings(paths: Paths) -> Callable[[Path], list[Finding]]:
    def load(root: Path) -> list[Finding]:
        from codesift.report import latest_run, load_report
        from codesift.scan import ScanError, ScanOptions, scan

        run = latest_run(paths.runs, root)
        if run is not None:
            return [Finding.from_dict(d) for d in load_report(run).get("findings", [])]
        try:
            return scan(ScanOptions(path=str(root), no_llm=True), paths).findings
        except ScanError as exc:
            raise ValidateError(f"scan failed: {exc}") from None

    return load


class Engine:
    def __init__(self, paths: Paths, root: Path, opts: EngineOptions, deps: EngineDeps) -> None:
        self.paths, self.root, self.opts, self.deps = paths, root.resolve(), opts, deps
        self.redactor = Redactor(deps.secrets)
        self.sandbox: Sandbox | None = None
        self.settings = ValidateSettings()
        self.districts: dict[str, list[str]] = {}
        self.tests_before: TestRun | None = None
        self.baseline_fps: set[str] = set()
        self.cache: dict[str, tuple[list[Finding] | None, Gate | None]] = {}
        self.job_count = 0

    # -- helpers --------------------------------------------------------------------------------

    def _log_job(self, label: str, job: JobResult) -> None:
        self.job_count += 1
        write_text(
            self.run_dir / "sandbox" / f"{safe_file_name(label)}-{job.job_id[:8]}.log",
            f"rc {job.rc} · {job.duration_s:.1f}s"
            + (" · timed out" if job.timed_out else "")
            + "\n\n"
            + job.output,
            self.redactor,
            MAX_LOG,
        )
        self.events.emit("sandbox.result", rc=job.rc, duration_s=round(job.duration_s, 2), label=label)

    def _job(self, label: str, command: str, tar: bytes, finding: str | None = None) -> JobResult:
        assert self.sandbox is not None  # noqa: S101 - guarded by _need_sandbox
        self.events.emit("stage.enter", finding, stage="sandbox")
        self.events.emit("sandbox.start", finding, label=label)
        job = self.sandbox.run_job(command, tar, self.settings.timeout_s)
        self._log_job(label, job)
        self.events.emit("stage.exit", finding, stage="sandbox")
        return job

    def _tests(self, label: str, tar: bytes) -> TestRun:
        assert self.sandbox is not None  # noqa: S101 - guarded by _need_sandbox
        self.events.emit("stage.enter", stage="sandbox")
        run = run_tests(self.sandbox, tar, self.settings.test, self.settings.timeout_s)
        if run.job is not None:
            self._log_job(label, run.job)
        self.events.emit("stage.exit", stage="sandbox")
        return run

    # -- run ------------------------------------------------------------------------------------

    def run(self) -> RunReport:
        base = self.paths.validate_runs / project_slug(self.root)
        self.run_id, self.run_dir = new_run_dir(base)
        self.events = EventLog(self.run_dir / "events.jsonl", self.run_id, self.redactor)
        self.audit = AuditLog(self.run_dir / "audit.jsonl", self.run_id, self.redactor)
        started = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.report = RunReport(self.run_id, self.opts.mode, self.root, started, dry_run=self.opts.dry_run)
        self.budget = Budget(
            self.opts.budget_tokens, self.opts.budget_s, self.opts.finding_budget_s, self.deps.clock
        )
        t0 = self.deps.clock()
        self.events.emit(
            "run.start",
            mode=self.opts.mode,
            kind="fix",
            dry_run=self.opts.dry_run,
            project=self.root.name,
            topology=topology(self.paths),
        )
        self.audit.write("run.start", command=self.opts.mode, dry_run=self.opts.dry_run)
        try:
            with recording(self.events):
                self._run()
        except (ValidateError, SandboxError, ConfigError) as exc:
            self.report.exit_code = EXIT_ERROR
            message = str(exc) + (f" - fix: {exc.fix}" if isinstance(exc, SandboxError) and exc.fix else "")
            self.report.notes.append(self.redactor.scrub(message))
            self.events.emit("error", message=message)
            self.audit.write("error", message=message)
        self.report.duration_s = self.deps.clock() - t0
        self.report.budget = self.budget.to_dict()
        self.report.sandbox.setdefault("state", "not used")
        self.report.sandbox["jobs"] = self.job_count
        self._write()
        # The workspace is a copy of project code: keep only the reviewed artefacts (patches, reports).
        rmtree_force(self.run_dir / "work")
        self.events.emit("run.end", exit_code=self.report.exit_code)
        self.audit.write(
            "run.end", exit_code=self.report.exit_code, duration_s=round(self.report.duration_s, 1)
        )
        prune(base)
        return self.report

    def _write(self) -> None:
        write_json(self.run_dir / "fix-report.json", self.report.to_dict(), self.redactor)
        write_text(self.run_dir / "fix-report.md", render_md(self.report), self.redactor)

    def _run(self) -> None:
        cfg = load_project_config(self.root)
        self.settings, self.districts = cfg.validate, cfg.districts
        loader = self.deps.load_findings or default_load_findings(self.paths)
        all_findings = loader(self.root)
        selected = select_findings(all_findings, self.opts)
        secret_paths = {f.path for f in all_findings if bug_type_of(f) == "secret" and f.path}
        for f in selected:
            self.events.emit("finding.selected", f.id)
            self.events.emit(
                "finding.detected",
                f.id,
                path=f.path,
                line=f.line,
                category=f.category,
                cwe=f.cwe,
                severity=f.severity.label,
                bug_type=bug_type_of(f),
                district=district_of(f.path, self.districts),
                rule=f.rules[0] if f.rules else f.rule,
            )
        self.report.findings = [
            FindingReport(
                f.id,
                f.severity.label,
                f.path,
                f.line,
                f.rules[0] if f.rules else f.rule,
                f.cwe,
                bug_type_of(f),
            )
            for f in selected
        ]

        # 1. workspace
        ws_dir = self.run_dir / "work"
        patch = ""
        if self.opts.mode == "validate":
            base_ref = "HEAD"
            if self.opts.branch:
                base_ref = merge_base(self.root, "HEAD", self.opts.branch)
                patch = project_diff(self.root, base_ref, self.opts.branch)
            elif self.opts.patch_text is not None:
                patch = self.opts.patch_text
            else:
                patch = project_diff(self.root, "HEAD")
            ws = create_workspace(
                self.root,
                ws_dir,
                never_send=self.settings.never_send,
                secret_paths=secret_paths,
                source="tree",
                ref=base_ref,
            )
            if not patch.strip():
                raise ValidateError(
                    "there is no change to validate (working tree equals HEAD; use --patch or --branch)"
                )
        else:
            ws = create_workspace(
                self.root, ws_dir, never_send=self.settings.never_send, secret_paths=secret_paths
            )
        self.report.base_commit = ws.base_commit
        self.report.excluded_files = len(ws.excluded)

        plans = {f.id: plan_for(f, self.settings, self.opts.poc_mode) for f in selected}
        need_sandbox = bool(self.settings.test) or any(p for p, _ in plans.values())
        if self.opts.dry_run:
            self._plan(selected, plans, need_sandbox, ws)
            return

        # 2. sandbox (fail closed)
        if need_sandbox:
            if self.deps.sandbox_factory is None:
                raise SandboxError("no sandbox VM configured", fix="run `sift setup --vm`")
            self.sandbox = self.deps.sandbox_factory()
            if self.settings.image:
                self.sandbox.cfg.image = self.settings.image
            report = ensure_selftest(self.sandbox, self.paths.data)
            self.events.emit("selftest.result", passed=True, cached=report.cached)
            self.report.sandbox["state"] = "self-test passed" + (" (cached)" if report.cached else "")
        else:
            self.report.notes.append(
                "no test command and no PoC configured: nothing needed the sandbox; "
                "add [validate] test / [validate.poc] for verified outcomes"
            )
        if not self.settings.test:
            hint = _suggest_test(ws)
            if hint:
                self.report.notes.append(f'suggestion (not run): set [validate] test = "{hint}"')

        # 3. baseline measurements
        base_tar = ws.tar() if need_sandbox else b""
        if self.settings.test:
            self.tests_before = self._tests("tests-before", base_tar)
        poc_before: dict[str, bool | None] = {}
        for f in selected:
            plan = plans[f.id][0]
            if plan is not None:
                job = self._job(f"poc-before-{f.id}", plan.command, ws.tar(plan.files), f.id)
                poc_before[f.id] = poc_reproduces(job)
        baseline = self.deps.rescanner.scan(ws.root, None)
        self.baseline_fps = fingerprints(all_findings) | fingerprints(baseline or [])

        if self.opts.mode == "validate":
            self._validate(ws, patch, selected, plans, poc_before)
        else:
            self._fix(ws, selected, plans, poc_before)
        self._finish(selected)

    def _plan(
        self,
        selected: list[Finding],
        plans: dict[str, tuple[PocPlan | None, str]],
        need_sandbox: bool,
        ws: Workspace,
    ) -> None:
        p = self.report.plan
        p.append(
            f"workspace: {len(ws.files)} files copied, {len(ws.excluded)} kept out (never sent anywhere)"
        )
        p.append(
            "sandbox VM: " + ("needed (tests/PoCs run there, never here)" if need_sandbox else "not needed")
        )
        for f in selected:
            plan, reason = plans[f.id]
            poc = plan.note if plan else f"unavailable ({reason})"
            p.append(f"{f.id} {f.severity.label} {f.location}: PoC {poc}")
            if self.opts.mode == "fix" and self.deps.ladder is not None:
                for step in self.deps.ladder(f):
                    p.append(f"  {step.backend} x{step.attempts}: {step.destination}")
        p.append("no backend and no VM were contacted (dry run)")

    # -- gates ----------------------------------------------------------------------------------

    def _evaluate(
        self,
        ws: Workspace,
        finding: Finding | None,
        finding_paths: list[str],
        plan: PocPlan | None,
        reproduced: bool | None,
    ) -> tuple[str, dict[str, Gate], list[str]]:
        """Run the gates on the workspace's current diff. Returns (outcome, gates, feedback)."""
        fid = finding.id if finding else None
        gates: dict[str, Gate] = {n: Gate(SKIPPED) for n in ("policy", "poc", "tests", "rescan")}
        diff = ws.diff()
        self.events.emit("stage.enter", fid, stage="policy")
        policy = check_patch(
            diff,
            finding_paths=finding_paths,
            allowed_paths=self.settings.allowed_fix_paths,
            max_lines=self.settings.max_patch_lines,
        )
        gates["policy"] = Gate(PASS if policy.ok else FAIL, "; ".join(policy.messages())[:500] or "ok")
        if fid:
            self.events.emit("policy.verdict", fid, ok=policy.ok, codes=[v.code for v in policy.violations])
        self.events.emit("stage.exit", fid, stage="policy")
        if not policy.ok:
            return "rejected_policy", gates, policy.messages()

        self.events.emit("stage.enter", fid, stage="verify")
        key = hashlib.sha256(diff.encode()).hexdigest()
        changed = ws.changed_files()
        if key not in self.cache:  # one re-scan and one test run per distinct diff
            after = self.deps.rescanner.scan(ws.root, ws.base_commit)
            tests = None
            if self.settings.test:
                tests = tests_gate(self.tests_before, self._tests("tests-after", ws.tar()))
            self.cache[key] = (after, tests)
        after, tests = self.cache[key]
        gates["rescan"] = rescan_gate(finding, self.baseline_fps, after, changed)
        gates["tests"] = (
            tests if tests is not None else Gate(UNAVAILABLE, "no test command configured ([validate] test)")
        )
        if plan is None:
            gates["poc"] = Gate(UNAVAILABLE, "no PoC for this finding")
        elif reproduced is not True:
            gates["poc"] = Gate(UNAVAILABLE, "the PoC did not reproduce on the baseline")
        else:
            job = self._job(f"poc-after-{fid}", plan.command, ws.tar(plan.files), fid)
            still = poc_reproduces(job)
            if still is None:
                gates["poc"] = Gate(UNAVAILABLE, f"the PoC could not run after the patch (rc {job.rc})")
            elif still:
                gates["poc"] = Gate(FAIL, "the PoC still reproduces after the patch")
            else:
                gates["poc"] = Gate(PASS, "the PoC reproduced before and is blocked after")
        for name in ("poc", "tests", "rescan"):
            if fid:
                self.events.emit("verify.result", fid, gate=name, status=gates[name].status)
        self.events.emit("stage.exit", fid, stage="verify")

        feedback = [f"{n}: {g.detail}" for n, g in gates.items() if g.status == FAIL]
        if gates["rescan"].status in (FAIL, UNAVAILABLE):
            return "rejected_rescan", gates, feedback or [f"rescan: {gates['rescan'].detail}"]
        if gates["poc"].status == FAIL:
            return "rejected_poc", gates, feedback
        if gates["tests"].status == FAIL:
            return "rejected_tests", gates, feedback
        proven = gates["poc"].status == PASS or gates["tests"].status == PASS
        return ("fixed_verified" if proven else "fixed_unproven"), gates, []

    # -- modes ----------------------------------------------------------------------------------

    def _validate(
        self,
        ws: Workspace,
        patch: str,
        selected: list[Finding],
        plans: dict[str, tuple[PocPlan | None, str]],
        poc_before: dict[str, bool | None],
    ) -> None:
        ws.apply_patch(patch)
        changed = ws.changed_files()
        touched = [f for f in selected if f.path in changed]
        for fr in self.report.findings:
            if fr.path not in changed:
                fr.outcome = "inconclusive"
                fr.note = "the change does not touch this finding's file"
        scope = sorted({f.path for f in touched}) or changed
        if not touched:
            outcome, gates, _ = self._evaluate(ws, None, scope, None, None)
            self.report.regression = {n: g.to_dict() for n, g in gates.items()}
            self.report.regression["result"] = {
                "status": PASS if outcome.startswith("fixed") else FAIL,
                "detail": outcome,
            }
            self._save_patch("combined", ws.diff())
            return
        for f in touched:
            plan = plans[f.id][0]
            fr = self._fr(f.id)
            if plan is not None and poc_before.get(f.id) is not True:
                fr.outcome, fr.note = "inconclusive", "the PoC did not reproduce on the baseline"
                fr.gates["poc"] = Gate(UNAVAILABLE, fr.note).to_dict()
                continue
            outcome, gates, _ = self._evaluate(ws, f, scope, plan, poc_before.get(f.id))
            fr.outcome, fr.gates = outcome, {n: g.to_dict() for n, g in gates.items()}
        self._save_patch("combined", ws.diff())

    def _fix(
        self,
        ws: Workspace,
        selected: list[Finding],
        plans: dict[str, tuple[PocPlan | None, str]],
        poc_before: dict[str, bool | None],
    ) -> None:
        combined: list[str] = []
        for f in selected:
            fr = self._fr(f.id)
            plan = plans[f.id][0]
            if plan is not None and poc_before.get(f.id) is not True:
                fr.outcome, fr.note = (
                    "inconclusive",
                    "the PoC did not reproduce on the baseline - not fixed, not safe",
                )
                fr.gates["poc"] = Gate(UNAVAILABLE, fr.note).to_dict()
                continue
            fr.outcome = self._fix_one(ws, f, fr, plan, poc_before.get(f.id))
            if fr.outcome.startswith("fixed"):
                combined.append(ws.diff())
                fr.patch = self._save_patch(f.id, combined[-1])
                if self.opts.review_patch and self.deps.reviewer is not None:
                    try:
                        fr.review = self.redactor.scrub(self.deps.reviewer(f, combined[-1]))[:1000]
                    except Exception as exc:  # advice only: a failing reviewer changes nothing
                        fr.review = f"review unavailable ({type(exc).__name__})"
            ws.reset()
        if combined:
            self._save_patch("combined", "".join(combined))

    def _fix_one(
        self, ws: Workspace, f: Finding, fr: FindingReport, plan: PocPlan | None, reproduced: bool | None
    ) -> str:
        if self.deps.ladder is None:
            raise ValidateError("no fixer backend is enabled - run `sift setup --fixers`")
        steps = self.deps.ladder(f)
        if not steps:
            raise ValidateError("no fixer backend is usable for this finding - run `sift setup --fixers`")
        start = self.deps.clock()
        feedback: list[str] = []
        last = "fixer_failed"
        number = 0
        for step in steps:
            for _ in range(step.attempts):
                why = self.budget.check(start)
                if why:
                    self.budget.exhausted = True
                    fr.note = f"stopped: {why} exhausted"
                    self.events.emit("budget.update", **self.budget.to_dict())
                    return "budget_exhausted"
                number += 1
                ws.reset()
                self.events.emit("stage.enter", f.id, stage="fix")
                self.events.emit("fix.attempt", f.id, backend=step.backend, attempt=number)
                try:
                    content = ws.read(f.path, MAX_CONTENT)
                except ValidateError as exc:
                    fr.note = str(exc)
                    return "fixer_failed"
                request = FixRequest(
                    finding=f,
                    path=f.path,
                    content=self.redactor.scrub(content),
                    allowed_paths=[f.path, *self.settings.allowed_fix_paths],
                    workspace=ws.root,
                    feedback=feedback[-5:],
                    attempt=number,
                )
                t = self.deps.clock()
                try:
                    with telemetry.doing("fix", f.id):
                        result = step.fixer.fix(request)
                except Exception as exc:  # a backend bug must not kill the run
                    result_ok, error, model, usage = False, f"{type(exc).__name__}", "", Usage()
                else:
                    result_ok, error, model, usage = result.ok, result.error, result.model, result.usage
                self.budget.used.add(usage)
                self.events.emit("fix.result", f.id, backend=step.backend, attempt=number, ok=result_ok)
                self.events.emit("stage.exit", f.id, stage="fix")
                self.events.emit("budget.update", **self.budget.to_dict())
                attempt = {"backend": step.backend, "attempt": number, "model": model, "tokens": usage.total}
                self.audit.write(
                    "fix.attempt",
                    finding=f.id,
                    backend=step.backend,
                    model=model,
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    duration_s=round(self.deps.clock() - t, 2),
                    ok=result_ok,
                )
                if not result_ok:
                    attempt["result"] = "fixer_failed"
                    fr.attempts.append(attempt)
                    feedback.append(f"the previous attempt failed mechanically: {error[:300]}")
                    continue
                outcome, gates, msgs = self._evaluate(ws, f, [f.path], plan, reproduced)
                attempt["result"] = outcome
                fr.attempts.append(attempt)
                fr.gates = {n: g.to_dict() for n, g in gates.items()}
                self.audit.write("verdict", finding=f.id, backend=step.backend, outcome=outcome)
                if outcome.startswith("fixed"):
                    return outcome
                last = outcome
                feedback.extend(msgs)
        return last

    def _fr(self, fid: str) -> FindingReport:
        return next(fr for fr in self.report.findings if fr.id == fid)

    def _save_patch(self, name: str, diff: str) -> str | None:
        if not diff.strip():
            return None
        fname = f"{safe_file_name(name)}.patch"
        write_text(self.run_dir / fname, diff, self.redactor)
        return fname

    def _finish(self, selected: list[Finding]) -> None:
        for fr in self.report.findings:
            if not fr.outcome:
                fr.outcome = "inconclusive"
            self.events.emit("finding.outcome", fr.id, outcome=fr.outcome)
        outcomes = [fr.outcome for fr in self.report.findings]
        if "budget_exhausted" in outcomes:
            self.report.exit_code = EXIT_BUDGET
        elif self.report.regression is not None and not outcomes:
            ok = self.report.regression["result"]["status"] == PASS
            self.report.exit_code = EXIT_OK if ok else EXIT_NOT_VERIFIED
        elif outcomes and all(o == "fixed_verified" for o in outcomes):
            self.report.exit_code = EXIT_OK
        elif not outcomes:
            self.report.exit_code = EXIT_OK
            self.report.notes.append("no finding selected (min severity / --finding)")
        else:
            self.report.exit_code = EXIT_NOT_VERIFIED


def _suggest_test(ws: Workspace) -> str:
    """Only suggested in the report - never run implicitly."""
    names = set(ws.files)
    if any(n.startswith(("tests/", "test/")) and n.endswith(".py") for n in names):
        return "python -m pytest -q"
    if "package.json" in names:
        return "npm test"
    if "go.mod" in names:
        return "go test ./..."
    return ""


def run_engine(
    paths: Paths, root: Path, opts: EngineOptions, deps: EngineDeps
) -> tuple[int, Path, RunReport]:
    engine = Engine(paths, root, opts, deps)
    report = engine.run()
    return report.exit_code, engine.run_dir, report
