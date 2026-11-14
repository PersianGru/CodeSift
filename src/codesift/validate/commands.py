"""`sift validate` / `sift fix` command logic (cli.py stays thin)."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from codesift.paths import Paths
from codesift.validate.engine import EngineDeps, EngineOptions, run_engine
from codesift.validate.report import RunReport
from codesift.validate.verify import ScanRescanner
from codesift.vm.sandbox import Sandbox


def known_secrets(paths: Paths, env: Mapping[str, str]) -> list[str]:
    """Values the redactor must mask everywhere in this run (never printed themselves)."""
    from codesift.config import ConfigError, gateway_values
    from codesift.secrets_store import StoreError, read_env

    out: list[str] = []
    try:
        values, _ = gateway_values(paths, env)
        out.append(values.get("CODESIFT_LLM_API_KEY", ""))
    except ConfigError:
        pass
    with contextlib.suppress(StoreError):
        out.append(
            env.get("CODESIFT_ANTHROPIC_API_KEY")
            or read_env(paths.anthropic_file).get("CODESIFT_ANTHROPIC_API_KEY", "")
        )
    return [s for s in out if s]


def default_deps(paths: Paths, env: Mapping[str, str]) -> EngineDeps:
    def sandbox() -> Sandbox:
        from codesift.vm.commands import make_sandbox

        return make_sandbox(paths)

    return EngineDeps(
        rescanner=ScanRescanner(paths, paths.validate_runs / "_rescan"),
        sandbox_factory=sandbox if paths.vm_file.exists() else None,
        secrets=known_secrets(paths, env),
    )


def summary(report: RunReport, run_dir: Path) -> dict[str, Any]:
    """The stable --json shape (docs/validate-and-fix.md)."""
    return {
        "schema": 1,
        "run_id": report.run_id,
        "run_dir": str(run_dir),
        "mode": report.mode,
        "exit_code": report.exit_code,
        "dry_run": report.dry_run,
        "report": str(run_dir / "fix-report.md"),
        "findings": [
            {"id": f.id, "severity": f.severity, "outcome": f.outcome or "planned", "patch": f.patch}
            for f in report.findings
        ],
        "regression": report.regression,
        "notes": report.notes,
    }


def print_result(report: RunReport, run_dir: Path, as_json: bool, out: Callable[[str], None]) -> None:
    if as_json:
        out(json.dumps(summary(report, run_dir), indent=2))
        return
    for f in report.findings:
        out(f"  {f.id} {f.severity:<8} {f.path}:{f.line}  {f.outcome or 'planned'}")
    if report.regression is not None:
        out(f"  regression check: {report.regression['result']['status']}")
    for note in report.notes[:5]:
        out(f"  note: {note}")
    out(f"report: {run_dir / 'fix-report.md'}")
    out(f"exit {report.exit_code} (patches are never applied - review them yourself)")


def cmd_validate(
    paths: Paths,
    env: Mapping[str, str],
    path: str,
    *,
    patch_file: str | None,
    branch: str | None,
    finding_ids: list[str],
    as_json: bool,
    out: Callable[[str], None],
    deps: EngineDeps | None = None,
) -> int:
    root = Path(path).resolve()
    if not root.is_dir():
        out(f"sift validate: {root} is not a directory")
        return 2
    patch_text = None
    if patch_file:
        p = Path(patch_file)
        if not p.is_file() or p.stat().st_size > 4 * 1024 * 1024:
            out(f"sift validate: {patch_file} is not a readable patch file (max 4 MB)")
            return 2
        patch_text = p.read_text(encoding="utf-8", errors="replace")
    if branch is not None and branch.startswith("-"):
        out("sift validate: --branch must not start with '-'")
        return 2
    opts = EngineOptions(
        mode="validate", finding_ids=finding_ids, patch_text=patch_text, branch=branch, max_findings=50
    )
    code, run_dir, report = run_engine(paths, root, opts, deps or default_deps(paths, env))
    print_result(report, run_dir, as_json, out)
    return code
