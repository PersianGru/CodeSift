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
(via any OpenAI-compatible LLM gateway) triage the findings, and writes a short summary.md to read.

Read-only on the scanned code. No network scanning. Secrets are always masked.
Start with `sift scan` and read the printed summary; run `sift doctor` if anything fails.
"""

EPILOG = """\
first time: `sift setup` (LLM gateway, sandbox VM, fixers), then `sift scan`.

exit codes (scan): 0 nothing at/above threshold, 1 findings at/above threshold,
                   2 tool/config error, 3 LLM unavailable (only with --require-llm)
exit codes (validate/fix): 0 all fixed_verified, 1 some not verified,
                   2 config/tool/sandbox error, 4 budget exhausted
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
    p.add_argument(
        "--offline", action="store_true", help="no network except a loopback/LAN LLM gateway you configured"
    )
    p.add_argument(
        "--only", metavar="TOOLS", help=f"comma-separated scanners to run ({', '.join(RUNNER_NAMES)})"
    )
    p.add_argument("--skip", metavar="TOOLS", help="comma-separated scanners to skip")
    p.add_argument("--threshold", choices=SEVERITIES, help="severity that makes the exit code 1")
    p.add_argument("--since", metavar="GIT_REF", help="only changes since this git ref")
    p.add_argument("--json", action="store_true", help="print a machine-readable summary on stdout")
    p.add_argument("--max-llm", type=int, metavar="N", help="max findings sent to the LLM")
    p.add_argument("--verbose", action="store_true", help="list low/info and baselined findings too")


def _add_setup(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "setup",
        help="wizard: LLM gateway, sandbox VM and fixer backends (secrets never shown)",
        description="Interactive setup. Run it once; re-run any time (current values are kept). "
        "Secrets are read with hidden input, or from environment variables in --non-interactive mode "
        "(CODESIFT_LLM_API_KEY, CODESIFT_ANTHROPIC_API_KEY) - never from the command line.",
    )
    part = p.add_argument_group("parts (default: all)")
    part.add_argument("--llm", action="store_true", help="only the LLM gateway")
    part.add_argument("--vm", action="store_true", help="only the sandbox VM")
    part.add_argument("--fixers", action="store_true", help="only the fixer backends")
    p.add_argument("--show", action="store_true", help="print the current settings (masked)")
    p.add_argument("--reset", metavar="PART", choices=["llm", "vm", "fixers"], help="remove a part's files")
    ni = p.add_argument_group("non-interactive mode")
    ni.add_argument("--non-interactive", action="store_true", help="read answers from flags/env only")
    ni.add_argument("--llm-base-url", metavar="URL")
    ni.add_argument("--llm-model", metavar="ID")
    ni.add_argument("--llm-fallback-model", metavar="ID")
    ni.add_argument(
        "--llm-trusted-network", action="store_true", help="allow plain http for a loopback/LAN gateway"
    )
    ni.add_argument("--test-connection", action="store_true", help="probe the gateway after saving")
    ni.add_argument("--vm-host", metavar="HOST")
    ni.add_argument("--vm-port", type=int, default=22, metavar="N")
    ni.add_argument("--vm-user", metavar="USER")
    ni.add_argument("--vm-key", metavar="PATH", help="existing private key (default: generate a new one)")
    ni.add_argument("--vm-pin-fingerprint", metavar="SHA256:...", help="host key fingerprint to pin")
    ni.add_argument("--vm-runtime", choices=["docker", "podman"], default="docker")
    ni.add_argument("--vm-image", metavar="REF")
    ni.add_argument(
        "--enable-fixer",
        action="append",
        choices=["gateway", "claude-cli", "claude-api"],
        default=[],
        help="enable a fixer backend (repeatable; external ones need --i-consent)",
    )
    ni.add_argument("--i-consent", action="store_true", help="record consent for the enabled external fixers")
    ni.add_argument("--claude-api-model", metavar="ID")
    ni.add_argument("--claude-cli-path", metavar="PATH")


def _add_vm(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "vm",
        help="sandbox VM: doctor, status, reset, image, admin-script",
        description="The sandbox VM runs project tests, PoCs and patched code in disposable, network-less "
        "containers. Nothing untrusted runs on this machine. Exit 2 when the VM refuses or fails.",
    )
    vsub = p.add_subparsers(dest="vm_cmd", metavar="<action>", required=True)
    vsub.add_parser("setup", help="same as `sift setup --vm`")
    vsub.add_parser("doctor", help="connect and run the isolation self-test (first live contact)")
    vsub.add_parser("status", help="free memory, running CodeSift jobs, pinned image")
    vsub.add_parser("reset", help="remove containers labelled codesift.job (nothing else)")
    img = vsub.add_parser("image", help="pull or build the sandbox image (uses the network on the VM)")
    isub = img.add_subparsers(dest="image_cmd", metavar="<action>", required=True)
    pl = isub.add_parser("pull", help="pull an image on the VM and pin its id")
    pl.add_argument("ref", nargs="?", help="image reference (default: the configured image)")
    bd = isub.add_parser("build", help="build an image from a Dockerfile on the VM and pin its id")
    bd.add_argument("--dockerfile", required=True, metavar="PATH")
    bd.add_argument("--tag", required=True, metavar="sift-NAME[:TAG]")
    adm = vsub.add_parser("admin-script", help="print the VM admin's setup script (never executed here)")
    adm.add_argument("--gate-only", action="store_true", help="print only the forced-command gate script")


VALIDATE_EPILOG = """exit codes: 0 every selected finding fixed_verified (or the regression check passed),
            1 some finding not verified (fixed_unproven, rejected_*, inconclusive, fixer_failed),
            2 configuration/tool error, including a sandbox that is missing or fails its self-test,
            4 budget exhausted (the report is still written)
"""


def _add_validate(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "validate",
        help="prove a change fixes findings without breaking the project (on a copy, in the sandbox)",
        description="Validates a change on a copy of the project: the working tree diff against HEAD "
        "(default), a patch file, or a branch. Tests and PoCs run only in the sandbox VM. The project "
        "is never modified and nothing is applied.",
        epilog=VALIDATE_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("path", nargs="?", default=".", help="project root (default: current directory)")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--patch", metavar="FILE", help="validate this patch file against HEAD")
    src.add_argument("--branch", metavar="REF", help="validate REF's change since its merge-base with HEAD")
    p.add_argument(
        "--finding", metavar="IDS", help="comma-separated finding IDs (default: those the change touches)"
    )
    p.add_argument("--json", action="store_true", help="print the machine-readable summary")

    p = sub.add_parser(
        "fix",
        help="let AI fixers propose patches, verified by deterministic checks (never applied)",
        description="Fixers (LLM gateway model, Claude CLI, Claude API - the external ones only with "
        "recorded consent) propose patches on a copy of the project. A patch counts as fixed only "
        "when the patch policy, project PoCs, tests and re-scan say so. Output is a patch for you to "
        "review; nothing is applied, merged or pushed.",
        epilog=VALIDATE_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("path", nargs="?", default=".", help="project root (default: current directory)")
    p.add_argument("--finding", metavar="IDS", help="comma-separated finding IDs")
    p.add_argument(
        "--min-severity", choices=SEVERITIES, default="high", help="lowest severity to fix (default high)"
    )
    p.add_argument("--max-findings", type=_positive_int, metavar="N", help="cap (default from fix.toml, 5)")
    p.add_argument("--backend", choices=["gateway", "claude-cli", "claude-api"], help="use only this backend")
    p.add_argument(
        "--poc", choices=["none", "project"], default="project", help="PoC source (default project)"
    )
    p.add_argument(
        "--review-patch", action="store_true", help="ask another backend to critique passing diffs"
    )
    p.add_argument("--dry-run", action="store_true", help="plan only: no backend and no VM contacted")
    p.add_argument("--json", action="store_true", help="print the machine-readable summary")
    p.add_argument("--budget-tokens", type=_positive_int, metavar="N", help="token cap for the run")
    p.add_argument("--budget-minutes", type=_positive_int, metavar="N", help="wall-clock cap for the run")


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
    _add_setup(sub)
    _add_vm(sub)
    _add_validate(sub)
    p = sub.add_parser(
        "ui",
        help="local web UI: fantasy 3D realm, light 2D map or table of the run (127.0.0.1, token)",
        description="Serves a local web UI on 127.0.0.1 with a one-time token URL. No external requests. "
        "Review decisions are recorded in the run folder; patches are never applied.",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--run", metavar="DIR", help="replay a past run folder (with events.jsonl)")
    src.add_argument("--demo", action="store_true", help="a synthetic run: no scan, no VM, no model")
    p.add_argument("--port", type=_positive_int, metavar="N", help="port (default: random)")
    p.add_argument("--open", action="store_true", help="open the browser")
    p.add_argument("--ci", action="store_true", help="default to the plain table")

    p = sub.add_parser(
        "top",
        help="live terminal view of the newest scan or fix (game-style HUD, like btop)",
        description="Follows the newest run in the terminal: scanners as the party, findings as monsters, "
        "the LLM gateway as the oracle tower, the sandbox VM as the dungeon. Reads local run files only.",
    )
    p.add_argument("--once", action="store_true", help="print one frame and exit (no keys, no screen switch)")
    p.add_argument("--ascii", action="store_true", help="plain ASCII glyphs for terminals without Unicode")

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

    p = sub.add_parser(
        "doctor", help="check installation, tools, config, LLM gateway, VM and fixers (values never shown)"
    )
    p.add_argument("--no-llm", action="store_true", help="skip the gateway /models and warm-up checks")
    p = sub.add_parser("install", help="(re)install venv, tools, command shim and Claude skill")
    p.add_argument(
        "--add-to-path", action="store_true", help="add the shim folder to the user PATH (Windows)"
    )
    p.add_argument("--credentials-from", metavar="FILE", help="copy LLM gateway settings from this env file")
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


def cmd_setup(args: argparse.Namespace) -> int:
    import os

    from codesift.setup_wizard import PARTS, SetupOptions, run_setup

    parts = [name for name in PARTS if getattr(args, name)] or list(PARTS)
    opts = SetupOptions(
        parts=parts,
        non_interactive=args.non_interactive,
        show=args.show,
        reset=args.reset,
        llm_base_url=args.llm_base_url,
        llm_model=args.llm_model,
        llm_fallback_model=args.llm_fallback_model,
        llm_trusted_network=args.llm_trusted_network,
        vm_host=args.vm_host,
        vm_port=args.vm_port,
        vm_user=args.vm_user,
        vm_key=args.vm_key,
        vm_pin_fingerprint=args.vm_pin_fingerprint,
        vm_runtime=args.vm_runtime,
        vm_image=args.vm_image,
        enable_fixer=args.enable_fixer,
        consent=args.i_consent,
        claude_api_model=args.claude_api_model,
        claude_cli_path=args.claude_cli_path,
        test_connection=args.test_connection,
    )
    return run_setup(opts, get_paths(), os.environ)


def cmd_vm(args: argparse.Namespace) -> int:
    import os

    from codesift.vm import commands as vmc

    paths = get_paths()
    if args.vm_cmd == "setup":
        from codesift.setup_wizard import SetupOptions, run_setup

        return run_setup(SetupOptions(parts=["vm"]), paths, os.environ)
    if args.vm_cmd == "doctor":
        return vmc.cmd_doctor(paths, print)
    if args.vm_cmd == "status":
        return vmc.cmd_status(paths, print)
    if args.vm_cmd == "reset":
        return vmc.cmd_reset(paths, print)
    if args.vm_cmd == "image":
        if args.image_cmd == "pull":
            return vmc.cmd_image_pull(paths, args.ref, print)
        return vmc.cmd_image_build(paths, args.dockerfile, args.tag, print)
    return vmc.cmd_admin_script(paths, args.gate_only, print)


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
    if args.command == "setup":
        return cmd_setup(args)
    if args.command == "vm":
        return cmd_vm(args)
    if args.command == "ui":
        from codesift.ui.server import replay_dir, run_ui
        from codesift.ui.state import DemoRun, Runs, StateError

        try:
            runs = Runs(get_paths(), replay_dir=replay_dir(args.run) if args.run else None)
        except StateError as exc:
            print(f"sift ui: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if args.demo:
            runs.demo = DemoRun()
        return run_ui(runs, port=args.port or 0, open_browser=args.open, ci=args.ci)
    if args.command == "top":
        from codesift.ui.state import Runs as TopRuns
        from codesift.ui.top import run_top

        return run_top(TopRuns(get_paths()), once=args.once, ascii_only=args.ascii)
    if args.command == "fix":
        import os

        from codesift.validate.commands import cmd_fix

        return cmd_fix(
            get_paths(),
            os.environ,
            args.path,
            finding_ids=args.finding.split(",") if args.finding else [],
            min_severity=args.min_severity,
            max_findings=args.max_findings,
            backend=args.backend,
            poc=args.poc,
            review_patch=args.review_patch,
            dry_run=args.dry_run,
            as_json=args.json,
            budget_tokens=args.budget_tokens,
            budget_minutes=args.budget_minutes,
            out=print,
        )
    if args.command == "validate":
        import os

        from codesift.validate.commands import cmd_validate

        return cmd_validate(
            get_paths(),
            os.environ,
            args.path,
            patch_file=args.patch,
            branch=args.branch,
            finding_ids=args.finding.split(",") if args.finding else [],
            as_json=args.json,
            out=print,
        )
    if args.command == "report":
        return cmd_report(None)
    if args.command == "baseline":
        return cmd_baseline(args)
    parser.error(f"unknown command {args.command}")
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
