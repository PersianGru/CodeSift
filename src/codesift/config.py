"""User config, Bifrost credentials and per-project config.

- User config:   <config dir>/config.toml       (LLM settings, threshold, parallelism, offline)
- Credentials:   <config dir>/bifrost.env       (BIFROST_BASE_URL, BIFROST_API_KEY, ...)
                 environment variables of the same name override the file.
- Project:       <project>/.codesift.toml       (optional, committed in the scanned repo)
"""

from __future__ import annotations

import ipaddress
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from codesift.envfile import load_env_file
from codesift.models import Severity
from codesift.paths import Paths

PROJECT_CONFIG_NAME = ".codesift.toml"
BASELINE_NAME = ".codesift-baseline.json"

CRED_KEYS = ("BIFROST_BASE_URL", "BIFROST_API_KEY", "BIFROST_MODEL", "BIFROST_FALLBACK_MODEL")
DEFAULT_MODEL = "ollama/qwen3.8:27b-mtp-q4_K_M"
DEFAULT_FALLBACK_MODEL = "ollama/qwen3-coder:30b"
THINK_MODES = ("auto", "on", "off")


class ConfigError(Exception):
    """Invalid configuration. Messages never contain secret values."""


@dataclass
class LLMSettings:
    model: str = DEFAULT_MODEL
    fallback_model: str = DEFAULT_FALLBACK_MODEL
    think: str = "auto"  # auto = decided per call type (see docs/model-eval.md)
    max_tokens: int = 2048
    warmup_timeout_s: int = 120
    call_timeout_s: int = 180
    total_budget_s: int = 1200
    max_findings: int = 60
    retries: int = 2
    context_lines: int = 30
    # --review: reasoning stays on (ADR-0010); a 400-line request takes minutes on the current VM
    review_max_tokens: int = 32768
    review_timeout_s: int = 1200
    review_budget_s: int = 2700


@dataclass
class UserConfig:
    llm: LLMSettings = field(default_factory=LLMSettings)
    threshold: Severity = Severity.HIGH
    jobs: int = 2
    offline: bool = False
    allow_http_localhost: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class Credentials:
    base_url: str
    api_key: str = field(repr=False)
    source: str = ""  # "file", "env" or "file+env" - for doctor output only

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""


@dataclass
class ProjectConfig:
    exclude: list[str] = field(default_factory=list)
    rules_dirs: list[str] = field(default_factory=list)
    threshold: Severity | None = None
    enable: list[str] = field(default_factory=list)
    disable: list[str] = field(default_factory=list)
    critical_paths: list[str] = field(default_factory=list)
    checklist: str | None = None
    path: Path | None = None


# ---------------------------------------------------------------- helpers


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from None
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read: {exc.strerror}") from None


def _expect(value: Any, typ: type, where: str) -> Any:
    if typ is int and isinstance(value, bool):
        raise ConfigError(f"{where}: expected int, got bool")
    if not isinstance(value, typ):
        raise ConfigError(f"{where}: expected {typ.__name__}, got {type(value).__name__}")
    return value


def _str_list(value: Any, where: str) -> list[str]:
    _expect(value, list, where)
    for i, item in enumerate(value):
        _expect(item, str, f"{where}[{i}]")
    return list(value)


def _severity(value: Any, where: str) -> Severity:
    try:
        return Severity.parse(_expect(value, str, where))
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None


# ---------------------------------------------------------------- user config


def parse_user_config(data: Mapping[str, Any], where: str = "config.toml") -> UserConfig:
    cfg = UserConfig()
    known_top = {"llm", "threshold", "jobs", "offline", "allow_http_localhost"}
    for key in data:
        if key not in known_top:
            cfg.warnings.append(f"{where}: unknown key {key!r} ignored")
    if "threshold" in data:
        cfg.threshold = _severity(data["threshold"], f"{where}: threshold")
    if "jobs" in data:
        cfg.jobs = _expect(data["jobs"], int, f"{where}: jobs")
        if not 1 <= cfg.jobs <= 8:
            raise ConfigError(f"{where}: jobs must be between 1 and 8")
    if "offline" in data:
        cfg.offline = _expect(data["offline"], bool, f"{where}: offline")
    if "allow_http_localhost" in data:
        cfg.allow_http_localhost = _expect(
            data["allow_http_localhost"], bool, f"{where}: allow_http_localhost"
        )

    llm = data.get("llm", {})
    _expect(llm, dict, f"{where}: [llm]")
    defaults = LLMSettings()
    for key, value in llm.items():
        if not hasattr(defaults, key):
            cfg.warnings.append(f"{where}: unknown key llm.{key!r} ignored")
            continue
        expected = type(getattr(defaults, key))
        setattr(cfg.llm, key, _expect(value, expected, f"{where}: llm.{key}"))
    if cfg.llm.think not in THINK_MODES:
        raise ConfigError(f"{where}: llm.think must be one of {', '.join(THINK_MODES)}")
    for key in (
        "max_tokens",
        "warmup_timeout_s",
        "call_timeout_s",
        "total_budget_s",
        "context_lines",
        "review_max_tokens",
        "review_timeout_s",
        "review_budget_s",
    ):
        if getattr(cfg.llm, key) <= 0:
            raise ConfigError(f"{where}: llm.{key} must be > 0")
    if cfg.llm.max_findings < 0 or cfg.llm.retries < 0:
        raise ConfigError(f"{where}: llm.max_findings and llm.retries must be >= 0")
    return cfg


def load_user_config(paths: Paths) -> UserConfig:
    path = paths.config_file
    if not path.is_file():
        return UserConfig()
    return parse_user_config(_read_toml(path), str(path))


# ---------------------------------------------------------------- credentials


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_base_url(url: str, allow_http_localhost: bool = False) -> str:
    """Return the normalized URL or raise ConfigError. Only HTTPS is accepted; plain HTTP only for
    loopback hosts with an explicit opt-in. Credentials, query strings and fragments are refused."""
    url = url.strip()
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        _ = parts.port  # raises on a bad port
    except ValueError:
        raise ConfigError("BIFROST_BASE_URL is not a valid URL") from None
    if not host:
        raise ConfigError("BIFROST_BASE_URL has no host")
    if parts.username or parts.password:
        raise ConfigError("BIFROST_BASE_URL must not contain credentials (put the key in BIFROST_API_KEY)")
    if parts.query or parts.fragment:
        raise ConfigError("BIFROST_BASE_URL must not contain a query string or fragment")
    if parts.scheme == "https":
        pass
    elif parts.scheme == "http" and _is_loopback(host):
        if not allow_http_localhost:
            raise ConfigError(
                "BIFROST_BASE_URL uses http:// - allowed only for localhost with allow_http_localhost = true"
            )
    else:
        raise ConfigError(f"BIFROST_BASE_URL must use https:// (got {parts.scheme or 'no'} scheme)")
    return url.rstrip("/")


def load_credentials(
    paths: Paths, env: Mapping[str, str] | None = None, allow_http_localhost: bool = False
) -> Credentials | None:
    """Load Bifrost credentials. Returns None when no base URL / key is configured at all."""
    env = os.environ if env is None else env
    file_values: dict[str, str] = {}
    if paths.credentials_file.is_file():
        try:
            file_values = load_env_file(paths.credentials_file)
        except OSError as exc:
            raise ConfigError(f"{paths.credentials_file}: cannot read: {exc.strerror}") from None
        except UnicodeDecodeError:
            raise ConfigError(f"{paths.credentials_file}: not valid UTF-8") from None

    sources: set[str] = set()
    values: dict[str, str] = {}
    for key in ("BIFROST_BASE_URL", "BIFROST_API_KEY"):
        if env.get(key):
            values[key] = env[key]
            sources.add("env")
        elif file_values.get(key):
            values[key] = file_values[key]
            sources.add("file")

    if not values:
        return None
    if "BIFROST_BASE_URL" not in values:
        raise ConfigError("BIFROST_API_KEY is set but BIFROST_BASE_URL is missing")
    if "BIFROST_API_KEY" not in values:
        raise ConfigError("BIFROST_BASE_URL is set but BIFROST_API_KEY is missing")
    url = validate_base_url(values["BIFROST_BASE_URL"], allow_http_localhost)
    return Credentials(base_url=url, api_key=values["BIFROST_API_KEY"], source="+".join(sorted(sources)))


def model_overrides(paths: Paths, env: Mapping[str, str] | None = None) -> dict[str, str]:
    """BIFROST_MODEL / BIFROST_FALLBACK_MODEL from env or the credentials file (non-secret)."""
    env = os.environ if env is None else env
    file_values: dict[str, str] = {}
    if paths.credentials_file.is_file():
        try:
            file_values = load_env_file(paths.credentials_file)
        except (OSError, UnicodeDecodeError):
            file_values = {}
    result: dict[str, str] = {}
    for key, name in (("BIFROST_MODEL", "model"), ("BIFROST_FALLBACK_MODEL", "fallback_model")):
        value = env.get(key) or file_values.get(key)
        if value:
            result[name] = value
    return result


# ---------------------------------------------------------------- project config


def parse_project_config(data: Mapping[str, Any], where: str = PROJECT_CONFIG_NAME) -> ProjectConfig:
    cfg = ProjectConfig()
    scan = data.get("scan", {})
    _expect(scan, dict, f"{where}: [scan]")
    if "exclude" in scan:
        cfg.exclude = _str_list(scan["exclude"], f"{where}: scan.exclude")
    if "rules_dirs" in scan:
        cfg.rules_dirs = _str_list(scan["rules_dirs"], f"{where}: scan.rules_dirs")
    if "threshold" in scan:
        cfg.threshold = _severity(scan["threshold"], f"{where}: scan.threshold")
    if "enable" in scan:
        cfg.enable = _str_list(scan["enable"], f"{where}: scan.enable")
    if "disable" in scan:
        cfg.disable = _str_list(scan["disable"], f"{where}: scan.disable")

    review = data.get("review", {})
    _expect(review, dict, f"{where}: [review]")
    if "critical_paths" in review:
        cfg.critical_paths = _str_list(review["critical_paths"], f"{where}: review.critical_paths")
    if "checklist" in review:
        cfg.checklist = _expect(review["checklist"], str, f"{where}: review.checklist")
    return cfg


def load_project_config(root: Path) -> ProjectConfig:
    path = root / PROJECT_CONFIG_NAME
    if not path.is_file():
        return ProjectConfig()
    cfg = parse_project_config(_read_toml(path), str(path))
    cfg.path = path
    return cfg


PROJECT_TEMPLATE = """\
# CodeSift project config - safe to commit. All keys are optional.
# Docs: run `sift --help` or see the CodeSift README.

[scan]
# Glob patterns (relative to the project root) that are never scanned.
exclude = [
  # "vendor/**",
  # "tests/fixtures/**",
]

# Extra opengrep rule directories (relative paths).
rules_dirs = []

# Minimum severity that makes `sift scan` exit 1: critical | high | medium | low | info
# threshold = "high"

# Force scanners on/off regardless of auto-detection
# (gitleaks, osv-scanner, opengrep, trivy, ruff, bandit, pip-audit, zizmor, composer-audit, govulncheck).
enable = []
disable = []

[review]
# Code that gets an extra LLM logic review with `sift scan --review`.
critical_paths = [
  # "backend/app/licensing/**",
]

# Optional project checklist (Markdown) used in the logic review.
# checklist = "docs/SECURITY-CHECKLIST.md"
"""
