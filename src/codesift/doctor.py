"""`sift doctor`: health checks with a fix for every failure. Never prints secret values."""

from __future__ import annotations

import os
import shutil
import stat
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime

from codesift.config import ConfigError, load_credentials, load_user_config, model_overrides
from codesift.envfile import load_env_file
from codesift.llm import BifrostClient, ClientSettings, LLMError
from codesift.lockfile import LockError, active_lock_path, load_lock
from codesift.paths import Paths
from codesift.pyreqs import installed_versions as installed_py
from codesift.redact import Redactor
from codesift.rules import rules_dir, verify_rules
from codesift.state import load_state, parse_iso
from codesift.tools import ToolError, resolve_tool

OK, WARN, FAIL, TODO = "ok", "warn", "FAIL", "todo"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    fix: str = ""


def _credentials_checks(paths: Paths, env: Mapping[str, str], allow_http: bool) -> list[Check]:
    checks: list[Check] = []
    path = paths.credentials_file
    if path.is_file():
        try:
            keys = load_env_file(path)
            summary = ", ".join(f"{k} (len {len(v)})" for k, v in sorted(keys.items()))
            checks.append(Check("credentials file", OK, f"{path}: {summary or 'no keys'}"))
        except (OSError, UnicodeDecodeError) as exc:
            checks.append(Check("credentials file", FAIL, f"{path}: unreadable ({type(exc).__name__})"))
        if os.name != "nt":
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                checks.append(
                    Check("credentials permissions", WARN, f"mode {mode:o}", fix=f"chmod 600 {path}")
                )
    else:
        checks.append(
            Check(
                "credentials file",
                WARN,
                f"{path} not found",
                fix="run `sift install` or create it with BIFROST_BASE_URL and BIFROST_API_KEY",
            )
        )
    try:
        creds = load_credentials(paths, env, allow_http_localhost=allow_http)
        if creds is None:
            checks.append(
                Check(
                    "bifrost credentials",
                    WARN,
                    "not configured - scans will run without LLM triage",
                    fix=f"set BIFROST_BASE_URL and BIFROST_API_KEY in {path}",
                )
            )
        else:
            checks.append(
                Check(
                    "bifrost credentials",
                    OK,
                    f"host {creds.host}, key len {len(creds.api_key)}, source {creds.source}",
                )
            )
    except ConfigError as exc:
        checks.append(Check("bifrost credentials", FAIL, str(exc), fix=f"edit {path}"))
    return checks


def run_checks(paths: Paths, env: Mapping[str, str] | None = None, llm: bool = False) -> list[Check]:
    env = os.environ if env is None else env
    checks: list[Check] = []
    py = sys.version_info
    if py >= (3, 11):
        checks.append(Check("python", OK, f"{py.major}.{py.minor}.{py.micro} ({sys.executable})"))
    else:
        checks.append(Check("python", FAIL, f"{py.major}.{py.minor}", fix="install Python 3.11 or newer"))

    allow_http = False
    try:
        cfg = load_user_config(paths)
        allow_http = cfg.allow_http_localhost
        where = str(paths.config_file) if paths.config_file.is_file() else "defaults (no config.toml)"
        detail = f"{where}; model {cfg.llm.model}; threshold {cfg.threshold.label}; jobs {cfg.jobs}"
        checks.append(Check("user config", WARN if cfg.warnings else OK, detail, fix="; ".join(cfg.warnings)))
    except ConfigError as exc:
        checks.append(Check("user config", FAIL, str(exc), fix=f"fix or delete {paths.config_file}"))

    checks.extend(_credentials_checks(paths, env, allow_http))

    git = shutil.which("git")
    checks.append(
        Check("git", OK, git) if git else Check("git", WARN, "not on PATH", fix="install git (history scans)")
    )

    checks.extend(_tool_checks(paths))
    if llm:
        checks.extend(_llm_checks(paths, env, allow_http))
    return checks


def _llm_checks(paths: Paths, env: Mapping[str, str], allow_http: bool) -> list[Check]:
    """GET /models, model availability, and a warm-up call without reasoning (one request, no retries)."""
    try:
        creds = load_credentials(paths, env, allow_http_localhost=allow_http)
    except ConfigError:
        return []  # already reported by the credentials check
    if creds is None:
        return []
    cfg = load_user_config(paths).llm
    for key, value in model_overrides(paths, env).items():
        setattr(cfg, key, value)
    client = BifrostClient(creds, ClientSettings(timeout_s=cfg.warmup_timeout_s, retries=0, backoff_s=(0,)))
    redactor = Redactor([creds.api_key])
    out: list[Check] = []
    try:
        start = time.monotonic()
        models = client.models()
        out.append(
            Check(
                "bifrost /models",
                OK,
                f"HTTPS {creds.host}, {len(models)} models, {time.monotonic() - start:.1f}s",
            )
        )
    except LLMError as exc:
        fix = "check BIFROST_BASE_URL / the gateway is up / the VPN or network path"
        return [Check("bifrost /models", FAIL, redactor.scrub(str(exc)), fix=fix)]
    for label, model in (("primary model", cfg.model), ("fallback model", cfg.fallback_model)):
        if model in models:
            out.append(Check(label, OK, model))
        else:
            out.append(
                Check(
                    label,
                    FAIL if label == "primary model" else WARN,
                    f"{model} not offered by Bifrost",
                    fix="set BIFROST_MODEL / BIFROST_FALLBACK_MODEL or pull the model on the LLM VM",
                )
            )
    if cfg.model in models:
        try:
            result = client.chat(
                cfg.model,
                [{"role": "user", "content": 'Reply with JSON only: {"ok": true}'}],
                max_tokens=256,
                timeout=cfg.warmup_timeout_s,
                think=False,
            )
            note = " (cold start - the model was loading)" if result.latency_s > 20 else ""
            out.append(Check("warm-up call", OK, f"{result.latency_s:.1f}s{note}"))
        except LLMError as exc:
            out.append(
                Check(
                    "warm-up call",
                    FAIL,
                    redactor.scrub(str(exc)),
                    fix="if this is a model-load error, update Ollama on the LLM VM and retry",
                )
            )
    return out


def _tool_checks(paths: Paths) -> list[Check]:
    checks: list[Check] = []
    lock_path = active_lock_path(paths)
    try:
        lock = load_lock(lock_path)
    except LockError as exc:
        return [Check("tools.lock.json", FAIL, str(exc), fix="run `sift install` from the CodeSift checkout")]
    checks.append(Check("tools.lock.json", OK, f"{lock_path} (updated {lock.updated})"))
    today = datetime.now(UTC).date()
    for name, tool in sorted(lock.tools.items()):
        try:
            binary = resolve_tool(name, lock, paths.tools)
            age = (today - date.fromisoformat(tool.published)).days
            checks.append(Check(name, OK, f"{tool.version}, sha256 verified, released {age}d ago ({binary})"))
        except ToolError as exc:
            checks.append(Check(name, FAIL, str(exc), fix="run `sift install`"))
        except ValueError:
            checks.append(Check(name, WARN, f"{tool.version}: bad release date in lock"))

    installed = installed_py(paths.venv)
    if not installed:
        checks.append(Check("python scanners", FAIL, f"venv {paths.venv} missing", fix="run `sift install`"))
    else:
        wrong = [
            f"{k} {installed.get(k, 'missing')} != {v}"
            for k, v in sorted(lock.python.items())
            if installed.get(k) != v
        ]
        if wrong:
            checks.append(Check("python scanners", FAIL, "; ".join(wrong), fix="run `sift install`"))
        else:
            checks.append(
                Check("python scanners", OK, ", ".join(f"{k} {v}" for k, v in sorted(lock.python.items())))
            )

    if lock.rules is None:
        checks.append(Check("opengrep rules", WARN, "no rules pinned"))
    else:
        rdir = rules_dir(paths, lock.rules)
        if rdir is None:
            checks.append(Check("opengrep rules", FAIL, "not installed", fix="run `sift install`"))
        elif not verify_rules(rdir, lock.rules):
            checks.append(
                Check("opengrep rules", FAIL, f"{rdir}: tree hash mismatch", fix="run `sift install`")
            )
        else:
            checks.append(
                Check("opengrep rules", OK, f"commit {lock.rules.commit[:12]}, hash verified ({rdir})")
            )

    last = parse_iso(load_state(paths).get("last_update_check"))
    if last is None:
        checks.append(Check("update check", WARN, "never run", fix="run `sift update`"))
    else:
        days = (datetime.now(UTC) - last).days
        status = WARN if days > 30 else OK
        checks.append(Check("update check", status, f"last checked {days}d ago", fix="run `sift update`"))
    return checks


def format_checks(checks: list[Check]) -> str:
    width = max(len(c.name) for c in checks)
    lines = []
    for c in checks:
        lines.append(f"[{c.status:>4}] {c.name:<{width}}  {c.detail}")
        if c.fix and c.status in (WARN, FAIL):
            lines.append(f"       {'':<{width}}  fix: {c.fix}")
    return "\n".join(lines)


def has_failures(checks: list[Check]) -> bool:
    return any(c.status == FAIL for c in checks)
