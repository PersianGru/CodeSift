"""Command-line interface. Run `sift --help` or `sift <command> --help`."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codesift import __version__
from codesift import baseline as baseline_mod
from codesift import hook as hook_mod
from codesift.config import PROJECT_CONFIG_NAME, PROJECT_TEMPLATE, ConfigError
from codesift.doctor import format_checks, has_failures, run_checks
from codesift.finding import Finding
from codesift.gitutil import git_info
from codesift.install import InstallError, install, uninstall
from codesift.lockfile import Lock, LockError, active_lock_path, load_lock, source_root
from codesift.models import EXIT_ERROR, EXIT_OK, Severity
from codesift.net import NetworkError
from codesift.paths import get_paths
from codesift.pyreqs import PyLockError
from codesift.releases import ReleaseError
from codesift.report import at_or_above, counts, latest_run, load_report
from codesift.rules import RulesError
from codesift.runners import RUNNER_NAMES
from codesift.scan import ScanError, ScanOptions, scan
from codesift.state import now_iso, save_state
from codesift.tools import ToolError
from codesift.update import apply as apply_plan
from codesift.update import check, format_plan, rollback

DESCRIPTION = """\
CodeSift runs free, open-source security scanners on a code project, lets a local LLM
(via a Bifrost gateway) triage the findings, and writes a short summary.md to read.

Read-only on the scanned code. No network scanning. Secrets are always masked.
Start with `sift scan` and read the printed summary; run `sift doctor` if anything fails.
"""

EPILOG = """\
exit codes: 0 nothing at/above threshold, 1 findings at/above threshold,
            2 tool/config error, 3 LLM unavailable (only with --require-llm)
"""

SEVERITIES = [s.label for s in Severity]


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return value


def _add_scan(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("scan", help="scan a project and write summary.md + report.json")
    p.add_argument("path", nargs="?", default=".", help="project root (default: current directory)")
    p.add_argument("--fast", action="store_true", help="scanners only, no LLM, changed files where possible")
    p.add_argument("--review", action="store_true", help="also run the LLM logic review of critical code")
    p.add_argument(
        "--critical", action="append", metavar="GLOB", help="critical-code glob for --review (repeatable)"
    )
    p.add_argument(
        "--checklist", metavar="FILE", help="checklist file for --review (may be outside the project)"
    )
    p.add_argument(
        "--review-all", action="store_true", help="review all critical files, not only changed ones"
    )
    p.add_argument(
        "--review-budget",
        type=_positive_int,
        metavar="MINUTES",
        help="time limit for --review (default 45; about 6 minutes per 400 lines of code)",
    )
    p.add_argument("--no-llm", action="store_true", help="skip LLM triage")
    p.add_argument("--require-llm", action="store_true", help="exit 3 if the LLM is unavailable")
    p.add_argument("--offline", action="store_true", help="no network except Bifrost")
    p.add_argument(
        "--only", metavar="TOOLS", help=f"comma-separated scanners to run ({', '.join(RUNNER_NAMES)})"
    )
    p.add_argument("--skip", metavar="TOOLS", help="comma-separated scanners to skip")
    p.add_argument("--threshold", choices=SEVERITIES, help="severity that makes the exit code 1")
    p.add_argument("--since", metavar="GIT_REF", help="only changes since this git ref")
    p.add_argument("--json", action="store_true", help="print a machine-readable summary on stdout")
    p.add_argument("--max-llm", type=int, metavar="N", help="max findings sent to the LLM")
    p.add_argument("--verbose", action="store_true", help="list low/info and baselined findings too")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sift",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="print CodeSift and tool versions")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    _add_scan(sub)

    p = sub.add_parser("report", help="re-print the latest summary for the current project")
    p.add_argument("--last", action="store_true", help="the latest run (default)")

    p = sub.add_parser("baseline", help="manage accepted findings (.codesift-baseline.json)")
    bsub = p.add_subparsers(dest="baseline_cmd", metavar="<action>", required=True)
    acc = bsub.add_parser("accept", help="accept findings by ID with a reason")
    acc.add_argument("ids", nargs="+", metavar="ID")
    acc.add_argument("--reason", required=True)
    acc.add_argument("--expires", metavar="YYYY-MM-DD")
    bsub.add_parser("list", help="list accepted findings")
    bsub.add_parser("prune", help="remove expired or no-longer-matching entries")

    p = sub.add_parser("init", help=f"write a commented {PROJECT_CONFIG_NAME} in the current project")
    p.add_argument("path", nargs="?", default=".")

    p = sub.add_parser("hook", help="manage the git pre-push hook")
    p.add_argument("action", choices=["install", "uninstall", "status"])

    p = sub.add_parser("update", help="check tools and rules against latest stable releases")
    p.add_argument("--apply", action="store_true", help="download, verify and switch to the new versions")
    p.add_argument("--rollback", action="store_true", help="return to the previous versions")
    p.add_argument(
        "--lock",
        metavar="PATH",
        help="lock file to check/update (default: the installed one; "
        "developers: the checkout's tools.lock.json)",
    )

    p = sub.add_parser("doctor", help="check installation, tools, config and Bifrost (values never shown)")
    p.add_argument("--no-llm", action="store_true", help="skip the Bifrost /models and warm-up checks")
    p = sub.add_parser("install", help="(re)install venv, tools, command shim and Claude skill")
    p.add_argument(
        "--add-to-path", action="store_true", help="add the shim folder to the user PATH (Windows)"
    )
    p.add_argument("--credentials-from", metavar="FILE", help="copy BIFROST_* keys from this env file")
    p.add_argument("--no-skill", action="store_true", help="do not install the Claude Code skill")
    p = sub.add_parser("uninstall", help="remove CodeSift (runs/ and config/ only with --purge)")
    p.add_argument("--purge", action="store_true", help="also delete scan runs and config/credentials")
    return parser


def cmd_init(path: str) -> int:
    root = Path(path).resolve()
    if not root.is_dir():
        print(f"sift init: {root} is not a directory", file=sys.stderr)
        return EXIT_ERROR
    target = root / PROJECT_CONFIG_NAME
    if target.exists():
        print(f"sift init: {target} already exists - not overwritten", file=sys.stderr)
        return EXIT_ERROR
    with target.open("x", encoding="utf-8", newline="\n") as fh:
        fh.write(PROJECT_TEMPLATE)
    print(f"wrote {target}")
    return EXIT_OK


def cmd_doctor(llm: bool = True) -> int:
    checks = run_checks(get_paths(), llm=llm)
    print(format_checks(checks))
    return EXIT_ERROR if has_failures(checks) else EXIT_OK


def cmd_update(apply: bool, do_rollback: bool, lock_arg: str | None) -> int:
    paths = get_paths()
    lock_path = Path(lock_arg).resolve() if lock_arg else active_lock_path(paths)
    venv = paths.venv if paths.venv.is_dir() else None
    try:
        if do_rollback:
            for line in rollback(lock_path, paths, venv):
                print(line)
            print("rolled back")
            return EXIT_OK
        lock = load_lock(lock_path) if lock_path.exists() or not lock_arg else Lock(updated="")
        print(f"checking {lock_path} (cooldown {lock.cooldown_days} days) ...", file=sys.stderr)
        plan = check(lock)
        print(format_plan(plan))
        failed = [r.component for r in plan.rows if r.status == "error"]
        if not failed:
            save_state(paths, last_update_check=now_iso(), latest_seen=plan.latest_seen)
        if not apply:
            return EXIT_ERROR if failed else EXIT_OK
        if failed:
            print(f"sift update: not applying - fix the errors first ({', '.join(failed)})", file=sys.stderr)
            return EXIT_ERROR
        if not plan.has_updates:
            return EXIT_OK
        # In a source checkout, vendored rules live in the repo; otherwise in the data dir.
        src = source_root()
        rules_root = src / "rules" if src is not None and lock_path.parent == src else None
        for line in apply_plan(plan, lock_path, paths, rules_root, venv):
            print(line)
        return EXIT_OK
    except (LockError, ToolError, ReleaseError, NetworkError, PyLockError, RulesError) as exc:
        print(f"sift update: {exc}", file=sys.stderr)
        return EXIT_ERROR


def cmd_install(args: argparse.Namespace) -> int:
    creds = Path(args.credentials_from).resolve() if args.credentials_from else None
    try:
        lines = install(
            get_paths(), add_to_path=args.add_to_path, credentials_from=creds, skill=not args.no_skill
        )
        for line in lines:
            print(line)
    except (InstallError, LockError, ToolError, NetworkError, PyLockError, ConfigError, OSError) as exc:
        print(f"sift install: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print("install complete - run `sift doctor` to check everything")
    return EXIT_OK


def cmd_uninstall(purge: bool) -> int:
    paths = get_paths()
    running_from_venv = Path(sys.executable).resolve().is_relative_to(paths.venv.resolve())
    if running_from_venv and sys.platform == "win32":
        print(
            "sift uninstall: Windows cannot delete the Python that is running. Run it from the "
            "checkout instead: ./install.ps1 -Uninstall  (add -Purge to delete runs and credentials)",
            file=sys.stderr,
        )
        return EXIT_ERROR
    for line in uninstall(paths, purge=purge):
        print(line)
    return EXIT_OK


def cmd_hook(action: str) -> int:
    root = Path(".").resolve()
    try:
        if action == "install":
            for line in hook_mod.install(root):
                print(line)
        elif action == "uninstall":
            for line in hook_mod.uninstall(root):
                print(line)
        else:
            print(hook_mod.describe(hook_mod.status(root)))
    except hook_mod.HookError as exc:
        print(f"sift hook: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def _project_root(path: str | None) -> Path:
    """The project a report/baseline command refers to: the path (default cwd), or its git
    top-level when only that has runs."""
    paths = get_paths()
    root = Path(path or ".").resolve()
    if latest_run(paths.runs, root) is None:
        info = git_info(root)
        if info.toplevel is not None and latest_run(paths.runs, info.toplevel) is not None:
            return info.toplevel.resolve()
    return root


def cmd_scan(args: argparse.Namespace) -> int:
    opts = ScanOptions(
        path=args.path,
        fast=args.fast,
        review=args.review,
        no_llm=args.no_llm,
        require_llm=args.require_llm,
        offline=args.offline,
        only=[args.only] if args.only else [],
        skip=[args.skip] if args.skip else [],
        threshold=args.threshold,
        since=args.since,
        max_llm=args.max_llm,
        verbose=args.verbose,
        critical=args.critical or [],
        checklist=args.checklist,
        review_all=args.review_all,
        review_budget_s=args.review_budget * 60 if args.review_budget else None,
    )
    try:
        outcome = scan(opts, get_paths())
    except ScanError as exc:
        print(f"sift scan: {exc}", file=sys.stderr)
        return EXIT_ERROR
    c = counts(outcome.findings)
    if args.json:
        above = at_or_above(outcome.findings, outcome.info.threshold)
        payload = {
            "summary": str(outcome.summary_path),
            "report": str(outcome.report_path),
            "exit_code": outcome.exit_code,
            "threshold": outcome.info.threshold.label,
            "counts": c,
            "at_or_above_threshold": [f.id for f in above],
            "scanners": [r.summary() for r in outcome.results],
        }
        print(json.dumps(payload, indent=2))
        return outcome.exit_code
    errors = [r.name for r in outcome.results if r.status == "error"]
    print(
        f"sift: {c['critical']} critical, {c['high']} high, {c['medium']} medium, "
        f"{c['low'] + c['info']} low/info, {c['baselined']} baselined"
    )
    for f in [f for f in outcome.findings if not f.baseline][:3]:
        print(f"  {f.id} {f.severity.label:<8} {f.location}  {f.rules[0]}")
    if errors:
        print(f"  scanner errors: {', '.join(errors)} (see summary)")
    print(f"summary: {outcome.summary_path}")
    print(f"exit {outcome.exit_code} (threshold {outcome.info.threshold.label})")
    return outcome.exit_code


def cmd_report(path: str | None) -> int:
    paths = get_paths()
    root = _project_root(path)
    run = latest_run(paths.runs, root)
    if run is None:
        print(f"sift report: no runs for {root} - run `sift scan` first", file=sys.stderr)
        return EXIT_ERROR
    print((run / "summary.md").read_text(encoding="utf-8"), end="")
    print(f"\n(summary: {run / 'summary.md'})")
    return EXIT_OK


def _latest_findings(root: Path) -> tuple[list[Finding], dict[str, Any]] | None:
    run = latest_run(get_paths().runs, root)
    if run is None:
        return None
    data = load_report(run)
    return [Finding.from_dict(d) for d in data.get("findings", [])], data


def cmd_baseline(args: argparse.Namespace) -> int:
    root = _project_root(None)
    try:
        if args.baseline_cmd == "list":
            entries = baseline_mod.load(root)
            if not entries:
                print(f"no baseline entries in {baseline_mod.baseline_path(root)}")
            for e in entries:
                state = " (EXPIRED)" if e.expired() else (f" (expires {e.expires})" if e.expires else "")
                print(f"{e.tool}:{e.rule} {e.path}{state}")
                print(f"    {e.reason} - {e.accepted_by}, {e.accepted_at}")
            return EXIT_OK
        latest = _latest_findings(root)
        if args.baseline_cmd == "accept":
            if latest is None:
                print(
                    "sift baseline: no scan report for this project - run `sift scan` first",
                    file=sys.stderr,
                )
                return EXIT_ERROR
            added = baseline_mod.accept(root, latest[0], args.ids, args.reason, args.expires)
            for e in added:
                print(f"accepted {e.tool}:{e.rule} {e.path}")
            if added:
                print(f"wrote {baseline_mod.baseline_path(root)} - commit it with the change it belongs to")
            else:
                print("nothing new to accept (already in the baseline)")
            return EXIT_OK
        full = latest[0] if latest is not None and latest[1].get("run", {}).get("mode") == "full" else None
        removed = baseline_mod.prune(root, full)
        for e in removed:
            print(f"removed {e.tool}:{e.rule} {e.path} ({'expired' if e.expired() else 'no longer found'})")
        if not removed:
            print("nothing to prune")
        return EXIT_OK
    except baseline_mod.BaselineError as exc:
        print(f"sift baseline: {exc}", file=sys.stderr)
        return EXIT_ERROR


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"sift {__version__}")
        return EXIT_OK
    if args.command is None:
        parser.print_help()
        return EXIT_OK
    if args.command == "init":
        return cmd_init(args.path)
    if args.command == "doctor":
        return cmd_doctor(not args.no_llm)
    if args.command == "update":
        return cmd_update(args.apply, args.rollback, args.lock)
    if args.command == "install":
        return cmd_install(args)
    if args.command == "uninstall":
        return cmd_uninstall(args.purge)
    if args.command == "hook":
        return cmd_hook(args.action)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "report":
        return cmd_report(None)
    if args.command == "baseline":
        return cmd_baseline(args)
    parser.error(f"unknown command {args.command}")
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
