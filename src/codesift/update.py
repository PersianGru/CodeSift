"""`sift update`: compare pinned tools / rules / Python scanners with the latest stable releases
(7-day cooldown, advisories checked) and, with --apply, switch to them with a self-test and rollback."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from codesift import __version__
from codesift.lockfile import (
    PREV_LOCK_NAME,
    PY_LOCK_NAME,
    Lock,
    LockError,
    RulesLock,
    current_platform,
    load_lock,
    save_lock,
)
from codesift.net import NetworkError
from codesift.paths import Paths
from codesift.pyreqs import (
    BOOTSTRAP,
    SCANNERS,
    PyLockError,
    build_lock_file,
    install_lock,
    pick_pypi,
    venv_python,
)
from codesift.releases import (
    ReleaseError,
    build_tool_lock,
    latest_commit,
    list_releases,
    pick_release,
    tool_advisories,
    version_key,
)
from codesift.rules import RULES_LICENSE, RULES_REPO, RULESETS, vendor
from codesift.state import now_iso, save_state
from codesift.tools import TOOL_SPECS, ToolError, install_tool, prune_versions, resolve_tool, tool_env


@dataclass
class Row:
    component: str
    current: str
    latest: str
    status: str  # current | update | cooldown | advisory | error
    note: str = ""
    link: str = ""


@dataclass
class Plan:
    rows: list[Row] = field(default_factory=list)
    tool_updates: dict[str, str] = field(default_factory=dict)  # name -> tag
    python_pins: dict[str, str] = field(default_factory=dict)
    python_changed: bool = False
    rules_commit: str | None = None
    rules_date: str = ""
    rules_archived: bool = False
    latest_seen: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def has_updates(self) -> bool:
        return bool(self.tool_updates or self.python_changed or self.rules_commit)


def check(lock: Lock, now: datetime | None = None) -> Plan:
    now = now or datetime.now(UTC)
    plan = Plan()
    cooldown = lock.cooldown_days

    for name, spec in TOOL_SPECS.items():
        current = lock.tools.get(name)
        cur_v = current.version if current else "-"
        try:
            eligible, newest = pick_release(list_releases(spec.repo), cooldown, now)
        except (NetworkError, ReleaseError) as exc:
            plan.rows.append(Row(name, cur_v, "?", "error", str(exc)))
            continue
        if eligible is None:
            plan.rows.append(Row(name, cur_v, "?", "error", "no stable release older than the cooldown"))
            continue
        published = eligible.published.strftime("%Y-%m-%d")
        plan.latest_seen[name] = {"version": eligible.version, "published": published}
        note = ""
        if newest and newest.tag != eligible.tag:
            age = (now - newest.published).days
            note = f"{newest.tag} is {age}d old (cooldown {cooldown}d)"
        status = "current"
        if current is None or version_key(eligible.tag) > version_key(current.tag):
            try:
                adv = tool_advisories(name, eligible.version)
            except NetworkError as exc:
                plan.rows.append(Row(name, cur_v, eligible.version, "error", f"advisory check failed: {exc}"))
                continue
            if adv:
                status = "advisory"
                note = "latest eligible has advisories: " + ", ".join(a.ghsa for a in adv)
            else:
                status = "update"
                plan.tool_updates[name] = eligible.tag
        if current is not None and status == "current":
            try:
                adv = tool_advisories(name, current.version)
            except NetworkError:
                adv = []
            if adv:
                status = "advisory"
                note = "pinned version affected by " + ", ".join(f"{a.ghsa} ({a.severity})" for a in adv)
        plan.rows.append(Row(name, cur_v, eligible.version, status, note, eligible.html_url))

    pins: dict[str, str] = {}
    for pkg in (*SCANNERS, *BOOTSTRAP):
        cur = lock.python.get(pkg, "-")
        try:
            eligible_py, newest_py = pick_pypi(pkg, cooldown, now)
        except (NetworkError, PyLockError) as exc:
            plan.rows.append(Row(pkg, cur, "?", "error", str(exc)))
            pins[pkg] = cur
            continue
        note = ""
        if newest_py.version != eligible_py.version:
            note = f"{newest_py.version} is {(now - newest_py.uploaded).days}d old (cooldown {cooldown}d)"
        if cur == "-" or version_key(eligible_py.version) > version_key(cur):
            plan.python_changed = True
            pins[pkg] = eligible_py.version
            status = "update"
        else:
            pins[pkg] = cur
            status = "current"
        link = f"https://pypi.org/project/{pkg}/{eligible_py.version}/"
        plan.rows.append(Row(pkg, cur, eligible_py.version, status, note, link))
    plan.python_pins = pins

    rules = lock.rules
    try:
        sha, date, archived = latest_commit(RULES_REPO)
        cur_sha = rules.commit if rules else "-"
        plan.rules_archived = archived
        note = "repository archived - no further updates" if archived else ""
        status = "current"
        if sha != cur_sha:
            if now - date >= timedelta(days=cooldown) or archived:
                status = "update"
                plan.rules_commit = sha
                plan.rules_date = date.strftime("%Y-%m-%d")
            else:
                status = "cooldown"
                note = f"newest commit is {(now - date).days}d old (cooldown {cooldown}d)"
        plan.rows.append(
            Row("opengrep-rules", cur_sha[:12], sha[:12], status, note, f"https://github.com/{RULES_REPO}")
        )
    except (NetworkError, ReleaseError) as exc:
        plan.rows.append(Row("opengrep-rules", rules.commit[:12] if rules else "-", "?", "error", str(exc)))

    plan.rows.append(Row("CodeSift", __version__, "-", "current", "update with `git pull` + install script"))
    return plan


def format_plan(plan: Plan) -> str:
    w = max(len(r.component) for r in plan.rows)
    lines = [f"{'component':<{w}}  {'pinned':<14} {'latest*':<14} status    note"]
    for r in plan.rows:
        lines.append(f"{r.component:<{w}}  {r.current:<14} {r.latest:<14} {r.status:<9} {r.note}".rstrip())
    lines.append("* latest stable release older than the cooldown")
    links = [f"  {r.component}: {r.link}" for r in plan.rows if r.status in ("update", "advisory") and r.link]
    if links:
        lines.append("release links:")
        lines.extend(links)
    if plan.has_updates:
        lines.append("run `sift update --apply` to download, verify and switch (rollback: --rollback)")
    else:
        lines.append("everything is up to date")
    return "\n".join(lines)


# ---------------------------------------------------------------- apply / rollback


def self_test(lock: Lock, tools_root: Path) -> list[str]:
    """Run each pinned binary's version command from a neutral temp dir. Returns errors."""
    errors = []
    with tempfile.TemporaryDirectory(prefix="codesift-selftest-") as tmp:
        for name, tool in lock.tools.items():
            try:
                binary = resolve_tool(name, lock, tools_root)
            except ToolError as exc:
                errors.append(str(exc))
                continue
            cmd = [str(binary), *TOOL_SPECS[name].version_args]
            try:
                proc = subprocess.run(  # noqa: S603
                    cmd, capture_output=True, text=True, timeout=120, cwd=tmp, env=tool_env(), check=False
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"{name}: cannot run ({type(exc).__name__})")
                continue
            if tool.version not in proc.stdout + proc.stderr:
                errors.append(f"{name}: version check did not report {tool.version} (exit {proc.returncode})")
    return errors


def _copy_if_exists(src: Path, dst: Path) -> None:
    if src.is_file():
        shutil.copy2(src, dst)


def apply(plan: Plan, lock_path: Path, paths: Paths, rules_root: Path | None, venv: Path | None) -> list[str]:
    """Write the new lock (keeping the previous one), install and self-test. Restores on failure."""
    log: list[str] = []
    try:
        old = load_lock(lock_path)
    except LockError:
        if lock_path.exists():
            raise
        old = Lock(updated="")
    new = load_lock(lock_path) if lock_path.exists() else Lock(updated="")

    for name, tag in plan.tool_updates.items():
        releases = [r for r in list_releases(TOOL_SPECS[name].repo) if r.tag == tag]
        if not releases:
            raise ReleaseError(f"{name}: release {tag} disappeared")
        new.tools[name] = build_tool_lock(TOOL_SPECS[name], releases[0])
        log.append(
            f"{name}: {old.tools[name].version if name in old.tools else '-'} -> {new.tools[name].version}"
        )

    py_lock = lock_path.parent / PY_LOCK_NAME
    py_text: str | None = None
    if plan.python_changed or not py_lock.is_file():
        resolver_python = None
        if venv is not None:
            candidate = venv_python(venv)
            resolver_python = str(candidate) if candidate.is_file() else None
        py_text = build_lock_file(plan.python_pins, new.cooldown_days, resolver_python)
        new.python = dict(plan.python_pins)
        log.append("python scanners: " + ", ".join(f"{k}=={v}" for k, v in sorted(new.python.items())))

    if plan.rules_commit:
        dest = rules_root if rules_root is not None else paths.data / "rules" / plan.rules_commit
        count, digest = vendor(plan.rules_commit, dest)
        new.rules = RulesLock(
            repo=RULES_REPO,
            commit=plan.rules_commit,
            date=plan.rules_date,
            license=RULES_LICENSE,
            archived=plan.rules_archived,
            rulesets=list(RULESETS),
            tree_sha256=digest,
        )
        log.append(f"opengrep-rules: {plan.rules_commit[:12]} ({count} rule files)")

    new.updated = datetime.now(UTC).strftime("%Y-%m-%d")

    prev = lock_path.with_name(PREV_LOCK_NAME)
    if lock_path.is_file():
        shutil.copy2(lock_path, prev)
        _copy_if_exists(py_lock, py_lock.with_name(PY_LOCK_NAME + ".prev"))
    save_lock(new, lock_path)
    if py_text is not None:
        py_lock.write_text(py_text, encoding="utf-8", newline="\n")

    try:
        for name in new.tools:
            install_tool(name, new, paths.tools)
        if venv is not None and py_text is not None and venv.is_dir():
            install_lock(venv, py_lock)
        errors = self_test(new, paths.tools)
        if errors:
            raise ToolError("self-test failed: " + "; ".join(errors))
    except (ToolError, NetworkError, PyLockError, OSError) as exc:
        if prev.is_file():
            shutil.copy2(prev, lock_path)
            _copy_if_exists(py_lock.with_name(PY_LOCK_NAME + ".prev"), py_lock)
            log.append("restored the previous lock")
        raise ToolError(f"update failed, nothing switched: {exc}") from None

    for name, tool in new.tools.items():
        keep = {tool.version}
        if name in old.tools:
            keep.add(old.tools[name].version)
        prune_versions(paths.tools, name, keep)
    save_state(paths, last_update_check=now_iso(), last_update_apply=now_iso())
    log.append(f"self-test passed on {current_platform()}")
    return log


def rollback(lock_path: Path, paths: Paths, venv: Path | None) -> list[str]:
    prev = lock_path.with_name(PREV_LOCK_NAME)
    if not prev.is_file():
        raise ToolError("no previous lock to roll back to")
    current = lock_path.with_name(lock_path.name + ".rollback-tmp")
    shutil.copy2(lock_path, current)
    shutil.copy2(prev, lock_path)
    shutil.move(str(current), prev)  # keep the rolled-back-from lock as prev (rollback is reversible)
    py_lock = lock_path.parent / PY_LOCK_NAME
    py_prev = py_lock.with_name(PY_LOCK_NAME + ".prev")
    if py_prev.is_file():
        tmp = py_lock.with_name(PY_LOCK_NAME + ".rollback-tmp")
        shutil.copy2(py_lock, tmp)
        shutil.copy2(py_prev, py_lock)
        shutil.move(str(tmp), py_prev)
    lock = load_lock(lock_path)
    for name in lock.tools:
        install_tool(name, lock, paths.tools)
    if venv is not None and venv.is_dir() and py_lock.is_file():
        install_lock(venv, py_lock)
    errors = self_test(lock, paths.tools)
    if errors:
        raise ToolError("rolled back, but self-test failed: " + "; ".join(errors))
    return [f"{n}: {t.version}" for n, t in sorted(lock.tools.items())]
