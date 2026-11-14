"""`sift scan`: detect -> scanners -> normalize/dedupe -> baseline -> (LLM triage) -> report."""

from __future__ import annotations

import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from codesift import baseline as baseline_mod
from codesift.config import (
    ConfigError,
    ProjectConfig,
    load_credentials,
    load_project_config,
    load_user_config,
    model_overrides,
)
from codesift.detect import detect, path_excluded, unlocked_manifests
from codesift.finding import Finding
from codesift.gateway import ClientSettings, GatewayClient, LLMError, ModelSession
from codesift.gitutil import changed_files, git, git_info, ref_exists
from codesift.lockfile import LockError, active_lock_path, load_lock
from codesift.models import EXIT_ERROR, EXIT_FINDINGS, EXIT_LLM_UNAVAILABLE, EXIT_OK, Severity
from codesift.normalize import (
    dedupe,
    group_policy_findings,
    hide_secret_lines,
    mark_review,
    order_and_number,
    scrub_findings,
)
from codesift.paths import Paths
from codesift.redact import Redactor
from codesift.report import (
    RunInfo,
    at_or_above,
    latest_run,
    load_report,
    mark_latest,
    new_run_dir,
    prune_runs,
    render_summary,
    write_report,
    write_summary,
)
from codesift.review import ReviewResult, review_base, run_review
from codesift.rules import rules_dir, verify_rules
from codesift.runners import ALL_RUNNERS, RUNNER_NAMES, Context, Runner, RunnerError, RunResult
from codesift.state import load_state, parse_iso
from codesift.tools import ToolError
from codesift.triage import TriageCache, triage_findings

UPDATE_CHECK_MAX_DAYS = 30
TOOL_BEHIND_MAX_DAYS = 60


class ScanError(Exception):
    pass


@dataclass
class ScanOptions:
    path: str = "."
    fast: bool = False
    review: bool = False
    no_llm: bool = False
    require_llm: bool = False
    offline: bool = False
    only: list[str] = field(default_factory=list)
    skip: list[str] = field(default_factory=list)
    threshold: str | None = None
    since: str | None = None
    max_llm: int | None = None
    verbose: bool = False
    critical: list[str] = field(default_factory=list)  # overrides review.critical_paths
    checklist: str | None = None  # overrides review.checklist; may be outside the project
    review_all: bool = False  # review every critical file, not only changed ones
    review_budget_s: int | None = None  # overrides llm.review_budget_s


@dataclass
class ScanOutcome:
    run_dir: Path
    summary_path: Path
    report_path: Path
    exit_code: int
    findings: list[Finding]
    results: list[RunResult]
    info: RunInfo


def parse_tool_list(value: str | None) -> list[str]:
    if not value:
        return []
    names = [v.strip() for v in value.split(",") if v.strip()]
    unknown = [n for n in names if n not in RUNNER_NAMES]
    if unknown:
        raise ScanError(f"unknown scanner(s): {', '.join(unknown)} (known: {', '.join(RUNNER_NAMES)})")
    return names


def select_runners(
    only: list[str], skip: list[str], enable: list[str], disable: list[str]
) -> tuple[list[Runner], dict[str, str]]:
    """Returns (runners to consider, {name: reason} for runners switched off by configuration)."""
    chosen: list[Runner] = []
    off: dict[str, str] = {}
    for cls in ALL_RUNNERS:
        name = cls.name
        if only and name not in only:
            continue  # not mentioned at all with --only
        if name in skip:
            off[name] = "--skip"
        elif name in disable and name not in only:
            off[name] = "disabled in .codesift.toml"
        elif cls.opt_in and name not in enable and name not in only:
            off[name] = "opt-in (enable in .codesift.toml)"
        else:
            chosen.append(cls())
    return chosen, off


def _coverage_warnings(detection: Any, only: list[str]) -> list[str]:
    if only and "osv-scanner" not in ",".join(only):
        return []
    gaps = unlocked_manifests(detection.files, detection.root)
    if not gaps:
        return []
    shown = ", ".join(gaps[:4]) + (f" (+{len(gaps) - 4})" if len(gaps) > 4 else "")
    return [
        f"not covered: dependencies in {shown} have no lockfile, so their versions were not checked "
        "(add a lockfile, or scan the built image)"
    ]


def _warnings(paths: Paths, lock_published: dict[str, str]) -> list[str]:
    state = load_state(paths)
    out = []
    last = parse_iso(state.get("last_update_check"))
    if last is None or (datetime.now(UTC) - last).days > UPDATE_CHECK_MAX_DAYS:
        out.append("tool versions not checked for 30+ days — run `sift update`")
    latest = state.get("latest_seen")
    if isinstance(latest, dict):
        for name, pinned in lock_published.items():
            seen = latest.get(name)
            if not isinstance(seen, dict):
                continue
            try:
                gap = (date.fromisoformat(str(seen.get("published"))) - date.fromisoformat(pinned)).days
            except ValueError:
                continue
            if gap > TOOL_BEHIND_MAX_DAYS:
                out.append(f"{name} is {gap} days behind {seen.get('version')} — run `sift update`")
    return out


def _run_one(runner: Runner, ctx: Context) -> RunResult:
    result = RunResult(name=runner.name, version=runner.version(ctx))
    reason = runner.applies(ctx)
    if reason is not None:
        result.status, result.reason = "skipped", reason
        return result
    start = time.monotonic()
    try:
        result.findings = runner.run(ctx)
    except (RunnerError, ToolError) as exc:
        result.status, result.reason = "error", str(exc)
    except Exception as exc:  # a parser bug must not kill the whole scan
        result.status, result.reason = "error", f"internal error: {type(exc).__name__}: {exc}"
    result.duration_s = time.monotonic() - start
    result.raw_files = sorted(p.name for p in ctx.raw_dir.glob(f"{runner.name}*"))
    return result


def _post_filter(
    runner_cls: type[Runner] | None, findings: list[Finding], globs: list[str], in_scope: set[str] | None
) -> list[Finding]:
    """Drop excluded paths, and - in git repos - files git ignores (e.g. a local secrets folder),
    except gitleaks history findings, which point at files that may no longer exist."""
    tests = bool(runner_cls and runner_cls.excludes_tests)
    kept = []
    for f in findings:
        if f.path and path_excluded(f.path, globs, tests):
            continue
        history = f.tool == "gitleaks" and f.extra.get("source") in ("history", "staged")
        if in_scope is not None and f.path and not history and f.path not in in_scope:
            continue
        kept.append(f)
    return kept


def _llm_phase(
    opts: ScanOptions,
    paths: Paths,
    root: Path,
    detection: Any,
    findings: list[Finding],
    redactor: Redactor,
    previous_commit: str,
    changed: list[str] | None,
    errors: list[str],
) -> tuple[str, ReviewResult | None]:
    """LLM triage (+ optional logic review). Returns (status text, review result)."""
    if opts.no_llm:
        return "not run (--no-llm)", None
    if opts.fast:
        return "not run (--fast)", None
    user_cfg = load_user_config(paths)
    project_cfg: ProjectConfig = load_project_config(root)
    try:
        creds = load_credentials(paths, allow_http_localhost=user_cfg.allow_http_localhost)
    except ConfigError as exc:
        errors.append(f"LLM gateway settings: {exc}")
        return "unavailable (credentials invalid) — findings listed untriaged", None
    if creds is None:
        return "not configured (no LLM gateway — run `sift setup --llm`)", None
    llm_cfg = user_cfg.llm
    for key, value in model_overrides(paths).items():
        setattr(llm_cfg, key, value)
    redactor.add(creds.api_key)
    client = GatewayClient(
        creds,
        ClientSettings(
            timeout_s=llm_cfg.call_timeout_s, retries=llm_cfg.retries, max_tokens=llm_cfg.max_tokens
        ),
    )
    session = ModelSession(client, llm_cfg.model, llm_cfg.fallback_model)
    try:
        session.warm_up(llm_cfg.warmup_timeout_s)
    except LLMError as exc:
        return f"unavailable ({redactor.scrub(str(exc))[:160]}) — findings listed untriaged", None
    think = llm_cfg.think != "off"
    stats = triage_findings(
        findings,
        root=root,
        session=session,
        settings=llm_cfg,
        cache=TriageCache(paths.data / "cache" / "triage"),
        redactor=redactor,
        ecosystems=sorted(detection.ecosystems),
        max_findings=opts.max_llm if opts.max_llm is not None else llm_cfg.max_findings,
        think=think,
    )
    review: ReviewResult | None = None
    if opts.review and not session.dead:
        base = None if opts.review_all else review_base(root, opts.since, previous_commit)
        if base and changed is None:
            listed = git(root, "diff", "--name-only", "--no-ext-diff", "--relative", "-z", base, "--")
            files = sorted({p for p in (listed or "").split("\0") if p and (root / p).is_file()})
        else:
            files = changed if changed is not None else detection.files
        review = run_review(
            root,
            files,
            opts.critical or project_cfg.critical_paths,
            str(Path(opts.checklist).resolve()) if opts.checklist else project_cfg.checklist,
            base,
            session,
            redactor,
            timeout=llm_cfg.review_timeout_s,
            max_tokens=llm_cfg.review_max_tokens,
            checklist_external=bool(opts.checklist),
            budget_s=opts.review_budget_s or llm_cfg.review_budget_s,
        )
    return stats.describe(), review


def scan(opts: ScanOptions, paths: Paths) -> ScanOutcome:
    started = datetime.now(UTC)
    t0 = time.monotonic()
    root = Path(opts.path).resolve()
    if not root.is_dir():
        raise ScanError(f"{root} is not a directory")
    try:
        user_cfg = load_user_config(paths)
        project_cfg = load_project_config(root)
        lock = load_lock(active_lock_path(paths))
    except (ConfigError, LockError) as exc:
        raise ScanError(str(exc)) from None

    threshold = (
        Severity.parse(opts.threshold) if opts.threshold else (project_cfg.threshold or user_cfg.threshold)
    )
    offline = opts.offline or user_cfg.offline
    gi = git_info(root)

    changed: list[str] | None = None
    if opts.since:
        if not gi.is_repo:
            raise ScanError("--since needs a git repository")
        if not ref_exists(root, opts.since):
            raise ScanError(f"--since: unknown git ref {opts.since!r}")
        changed = changed_files(root, opts.since)
        if changed is None:
            raise ScanError(f"could not list files changed since {opts.since}")

    detection = detect(root, project_cfg.exclude)
    errors: list[str] = []
    rdir = rules_dir(paths, lock.rules) if lock.rules else None
    if rdir is not None and lock.rules is not None and not verify_rules(rdir, lock.rules):
        errors.append(f"opengrep rules in {rdir} do not match the lock hash — run `sift install`")
        rdir = None
    extra_rules = []
    for d in project_cfg.rules_dirs:
        p = (root / d).resolve()
        if p.is_dir() and p.is_relative_to(root):
            extra_rules.append(p)
        else:
            errors.append(f"rules dir {d!r} from .codesift.toml not found inside the project")

    runners, off = select_runners(
        parse_tool_list(",".join(opts.only)),
        parse_tool_list(",".join(opts.skip)),
        project_cfg.enable,
        project_cfg.disable,
    )
    previous = latest_run(paths.runs, root)
    previous_commit = str(load_report(previous).get("project", {}).get("commit", "")) if previous else ""
    run = new_run_dir(paths.runs, root)
    work = run / "work"
    work.mkdir()
    ctx = Context(
        root=root,
        detection=detection,
        git=gi,
        paths=paths,
        lock=lock,
        raw_dir=run / "raw",
        work_dir=work,
        exclude_globs=project_cfg.exclude,
        offline=offline,
        since=opts.since,
        changed=changed,
        jobs=user_cfg.jobs,
        timeout=120 if opts.fast else 900,
        redactor=Redactor(),
        rules_dir=rdir,
        extra_rules_dirs=extra_rules,
    )

    results: list[RunResult] = [RunResult(name=n, status="skipped", reason=r) for n, r in off.items()]
    to_run: list[Runner] = []
    for r in runners:
        if r.needs_network and offline:
            results.append(
                RunResult(name=r.name, version=r.version(ctx), status="skipped", reason="--offline")
            )
        else:
            to_run.append(r)
    with ThreadPoolExecutor(max_workers=max(1, user_cfg.jobs)) as pool:
        results += list(pool.map(lambda r: _run_one(r, ctx), to_run))
    shutil.rmtree(work, ignore_errors=True)
    order = {n: i for i, n in enumerate(RUNNER_NAMES)}
    results.sort(key=lambda r: order.get(r.name, 99))

    classes = {cls.name: cls for cls in ALL_RUNNERS}
    scope = set(detection.files) if detection.from_git else None
    raw: list[Finding] = []
    for res in results:
        res.findings = _post_filter(classes.get(res.name), res.findings, project_cfg.exclude, scope)
        raw += res.findings
    hide_secret_lines(raw)
    scrub_findings(raw, ctx.redactor)
    findings = dedupe(raw)
    try:
        expired = baseline_mod.apply(findings, baseline_mod.load(root))
    except baseline_mod.BaselineError as exc:
        errors.append(str(exc))
        expired = []
    findings = group_policy_findings(findings)
    mark_review(findings)
    order_and_number(findings)

    llm, review = _llm_phase(
        opts, paths, root, detection, findings, ctx.redactor, previous_commit, changed, errors
    )

    mode = "since" if opts.since else ("fast" if opts.fast else "full")
    info = RunInfo(
        root=root,
        started=started,
        duration_s=time.monotonic() - t0,
        mode=mode,
        threshold=threshold,
        commit=gi.commit,
        branch=gi.branch,
        dirty=gi.dirty,
        since=opts.since,
        offline=offline,
        llm=llm,
        warnings=_warnings(paths, {n: t.published for n, t in lock.tools.items()})
        + _coverage_warnings(detection, opts.only),
        errors=errors,
        expired_baseline=[f"{e.tool} {e.rule} {e.path} (expired {e.expires})" for e in expired],
        verbose=opts.verbose,
        review=review.to_dict() if review else None,
    )
    failed = any(r.status == "error" for r in results) or bool(errors)
    if at_or_above(findings, threshold):
        info.exit_code = EXIT_FINDINGS
    elif failed:
        info.exit_code = EXIT_ERROR
    elif opts.require_llm and not llm.startswith(("done", "partial")):
        info.exit_code = EXIT_LLM_UNAVAILABLE
    else:
        info.exit_code = EXIT_OK

    report_path = write_report(run, info, results, findings)
    summary_path = write_summary(run, render_summary(info, results, findings, report_path))
    mark_latest(run)
    prune_runs(paths.runs, root)
    return ScanOutcome(run, summary_path, report_path, info.exit_code, findings, results, info)
