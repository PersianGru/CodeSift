"""User config, LLM gateway settings and per-project config.

- User config:   <config dir>/config.toml       (LLM settings, threshold, parallelism, offline)
- LLM gateway:   <config dir>/gateway.env       (CODESIFT_LLM_BASE_URL, CODESIFT_LLM_API_KEY, ...)
                 environment variables of the same name override the file (ADR-0014).
- Project:       <project>/.codesift.toml       (optional, committed in the scanned repo)
"""

from __future__ import annotations

import ipaddress
import os
import re
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
class ValidateSettings:
    """`[validate]` in .codesift.toml. Commands run only inside the sandbox VM."""

    test: str = ""  # project test command (optional)
    image: str = ""  # overrides the vm.toml image
    timeout_s: int = 300
    never_send: list[str] = field(default_factory=list)
    allowed_fix_paths: list[str] = field(default_factory=list)
    max_patch_lines: int = 80
    poc: dict[str, str] = field(default_factory=dict)  # CWE-89 = "python poc/sqli.py"
    entry: dict[str, str] = field(default_factory=dict)  # CWE-89 = "app.db:find_user" (canned probes)
    prepare: str = ""  # network "prepare" step: off unless also --allow-prepare-network


@dataclass
class ProjectConfig:
    exclude: list[str] = field(default_factory=list)
    rules_dirs: list[str] = field(default_factory=list)
    threshold: Severity | None = None
    enable: list[str] = field(default_factory=list)
    disable: list[str] = field(default_factory=list)
    critical_paths: list[str] = field(default_factory=list)
    checklist: str | None = None
    validate: ValidateSettings = field(default_factory=ValidateSettings)
    districts: dict[str, list[str]] = field(default_factory=dict)  # [ui.districts]
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

# gateway.env keys (ADR-0014). Environment variables of the same names override the file.
LLM_URL, LLM_KEY, LLM_MODEL, LLM_FALLBACK = (
    "CODESIFT_LLM_BASE_URL",
    "CODESIFT_LLM_API_KEY",
    "CODESIFT_LLM_MODEL",
    "CODESIFT_LLM_FALLBACK_MODEL",
)
LLM_ALLOW_HTTP = "CODESIFT_LLM_ALLOW_HTTP"  # the user's recorded "trusted network" answer
GATEWAY_KEYS = (LLM_URL, LLM_KEY, LLM_MODEL, LLM_FALLBACK, LLM_ALLOW_HTTP)
# 0.1.0 names, still read silently as a fallback and migrated by `sift setup`. Never shown to users.
LEGACY_KEYS = {
    LLM_URL: CRED_KEYS[0],
    LLM_KEY: CRED_KEYS[1],
    LLM_MODEL: CRED_KEYS[2],
    LLM_FALLBACK: CRED_KEYS[3],
}


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_private_lan(host: str) -> bool:
    """RFC 1918 / ULA / link-local literal addresses (names are not trusted: DNS can point anywhere)."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return ip.is_private and not ip.is_loopback and not ip.is_unspecified and not ip.is_multicast


def url_kind(url: str) -> str:
    """'https', 'http-loopback' or 'http-lan'. Raises ConfigError for anything else."""
    url = url.strip()
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        _ = parts.port  # raises on a bad port
    except ValueError:
        raise ConfigError("the LLM gateway base URL is not a valid URL") from None
    if not host:
        raise ConfigError("the LLM gateway base URL has no host")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ConfigError("the LLM gateway base URL must not contain credentials (enter the key separately)")
    if parts.query or parts.fragment:
        raise ConfigError("the LLM gateway base URL must not contain a query string or fragment")
    if any(c.isspace() or ord(c) < 32 for c in url):
        raise ConfigError("the LLM gateway base URL contains whitespace or control characters")
    if parts.scheme == "https":
        return "https"
    if parts.scheme == "http" and _is_loopback(host):
        return "http-loopback"
    if parts.scheme == "http" and is_private_lan(host):
        return "http-lan"
    if parts.scheme == "http":
        raise ConfigError(
            "the LLM gateway base URL must use https:// (plain http only for loopback or a private LAN "
            "address on a trusted network)"
        )
    raise ConfigError(f"the LLM gateway base URL must use https:// (got {parts.scheme or 'no'} scheme)")


def validate_base_url(url: str, allow_http_localhost: bool = False, allow_http_lan: bool = False) -> str:
    """Return the normalized URL or raise ConfigError. HTTPS always; plain HTTP only for loopback
    (`allow_http_localhost`, or the trusted-network answer) or a private LAN address (trusted-network
    answer only). Credentials, query strings and fragments are refused."""
    kind = url_kind(url)
    if kind == "http-loopback" and not (allow_http_localhost or allow_http_lan):
        raise ConfigError(
            "the LLM gateway base URL uses http:// - allowed for localhost only after confirming a trusted "
            "network in `sift setup --llm` (or allow_http_localhost = true)"
        )
    if kind == "http-lan" and not allow_http_lan:
        raise ConfigError(
            "the LLM gateway base URL uses http:// on the local network - allowed only after confirming a "
            "trusted network in `sift setup --llm`"
        )
    return url.strip().rstrip("/")


def _env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    try:
        return load_env_file(path)
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read: {exc.strerror}") from None
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not valid UTF-8") from None


def gateway_values(paths: Paths, env: Mapping[str, str] | None = None) -> tuple[dict[str, str], set[str]]:
    """Resolve the gateway settings: env > gateway.env > legacy env names > legacy file.
    Returns (values by new key name, sources used). Values are never logged."""
    env = os.environ if env is None else env
    current = _env_file(paths.gateway_file)
    legacy_file = _env_file(paths.credentials_file)
    values: dict[str, str] = {}
    sources: set[str] = set()
    for key in GATEWAY_KEYS:
        legacy = LEGACY_KEYS.get(key)
        for value, source in (
            (env.get(key), "env"),
            (current.get(key), "file"),
            (env.get(legacy) if legacy else None, "env"),
            (legacy_file.get(legacy) if legacy else None, "file"),
        ):
            if value is not None and (value != "" or (key == LLM_KEY and source == "file")):
                values[key] = value
                sources.add(source)
                break
    return values, sources


def has_legacy_credentials(paths: Paths, env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return paths.credentials_file.is_file() or any(env.get(k) for k in LEGACY_KEYS.values())


def load_credentials(
    paths: Paths, env: Mapping[str, str] | None = None, allow_http_localhost: bool = False
) -> Credentials | None:
    """Load the LLM gateway settings. Returns None when no base URL / key is configured at all.
    An empty API key is allowed (some local gateways need none)."""
    values, sources = gateway_values(paths, env)
    url, key = values.get(LLM_URL), values.get(LLM_KEY)
    if url is None and not key:
        return None
    if url is None:
        raise ConfigError(
            "an LLM gateway API key is set but the base URL is missing - run `sift setup --llm`"
        )
    allow_lan = values.get(LLM_ALLOW_HTTP, "").strip().lower() in ("1", "true", "yes")
    url = validate_base_url(url, allow_http_localhost, allow_lan)
    return Credentials(base_url=url, api_key=key or "", source="+".join(sorted(sources)))


def model_overrides(paths: Paths, env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Model ids from env or the gateway settings (non-secret)."""
    try:
        values, _ = gateway_values(paths, env)
    except ConfigError:
        return {}
    result: dict[str, str] = {}
    for key, name in ((LLM_MODEL, "model"), (LLM_FALLBACK, "fallback_model")):
        if values.get(key):
            result[name] = values[key]
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
    cfg.validate = _parse_validate(data.get("validate", {}), where)
    ui = data.get("ui", {})
    _expect(ui, dict, f"{where}: [ui]")
    districts = ui.get("districts", {})
    _expect(districts, dict, f"{where}: [ui.districts]")
    for name, prefixes in districts.items():
        cfg.districts[str(name)] = _str_list(prefixes, f"{where}: ui.districts.{name}")
    return cfg


_CWE_KEY = re.compile(r"^CWE-\d{1,5}$")
_ENTRY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,200}:[A-Za-z_][A-Za-z0-9_]{0,100}$")


def _single_line(value: str, where: str, limit: int = 2000) -> str:
    if any(c in value for c in "\n\r\x00") or len(value) > limit:
        raise ConfigError(f"{where}: must be a single line of at most {limit} characters")
    return value


def _parse_validate(section: Any, where: str) -> ValidateSettings:
    _expect(section, dict, f"{where}: [validate]")
    v = ValidateSettings()
    known = {
        "test",
        "image",
        "timeout_s",
        "never_send",
        "allowed_fix_paths",
        "max_patch_lines",
        "poc",
        "entry",
    }
    known.add("prepare")
    for key in section:
        if key not in known:
            raise ConfigError(f"{where}: unknown key validate.{key}")
    if "test" in section:
        v.test = _single_line(
            _expect(section["test"], str, f"{where}: validate.test"), f"{where}: validate.test"
        )
    if "image" in section:
        v.image = _single_line(
            _expect(section["image"], str, f"{where}: validate.image"), f"{where}: validate.image"
        )
    if "prepare" in section:
        v.prepare = _single_line(
            _expect(section["prepare"], str, f"{where}: validate.prepare"), f"{where}: validate.prepare"
        )
    if "timeout_s" in section:
        v.timeout_s = _expect(section["timeout_s"], int, f"{where}: validate.timeout_s")
        if not 5 <= v.timeout_s <= 3600:
            raise ConfigError(f"{where}: validate.timeout_s must be between 5 and 3600")
    if "max_patch_lines" in section:
        v.max_patch_lines = _expect(section["max_patch_lines"], int, f"{where}: validate.max_patch_lines")
        if not 1 <= v.max_patch_lines <= 400:
            raise ConfigError(f"{where}: validate.max_patch_lines must be between 1 and 400 (hard max)")
    for key in ("never_send", "allowed_fix_paths"):
        if key in section:
            setattr(v, key, _str_list(section[key], f"{where}: validate.{key}"))
    for p in v.allowed_fix_paths:
        if p.startswith(("/", "\\")) or ".." in p.replace("\\", "/").split("/") or ":" in p:
            raise ConfigError(f"{where}: validate.allowed_fix_paths must be project-relative ({p!r})")
    for key, pattern in (("poc", None), ("entry", _ENTRY)):
        table = section.get(key, {})
        _expect(table, dict, f"{where}: [validate.{key}]")
        for cwe, value in table.items():
            if not _CWE_KEY.match(str(cwe)):
                raise ConfigError(f'{where}: validate.{key} keys must look like "CWE-89" (got {cwe!r})')
            text = _single_line(
                _expect(value, str, f"{where}: validate.{key}.{cwe}"), f"{where}: validate.{key}"
            )
            if pattern is not None and not pattern.match(text):
                raise ConfigError(f'{where}: validate.entry.{cwe} must look like "package.module:function"')
            getattr(v, key)[str(cwe)] = text
    return v


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

[validate]
# Used by `sift validate` and `sift fix`. Commands run ONLY inside the sandbox VM (`sift setup --vm`),
# never on this machine, in a container without network. Nothing here is run implicitly.
# test = "python -m pytest -q"        # project tests (single line); compared before/after a patch
# image = ""                          # sandbox image for this project (overrides vm.toml)
# timeout_s = 300
# never_send = ["secrets/**", "*.pem"]  # never copied into the workspace or sent to any model
# allowed_fix_paths = []              # extra files a fix may touch (default: only the finding's file)
# max_patch_lines = 80                # changed lines per patch (hard max 400)

[validate.poc]
# Proof-of-concept commands per CWE, run before and after a patch in the sandbox.
# Exit 0 = the vulnerable behaviour was reproduced, non-zero = blocked.
# "CWE-89" = "python poc/sqli.py"

[validate.entry]
# Callable entry points for CodeSift's canned probes (Python projects), per CWE.
# "CWE-78" = "app.tools:ping"

[ui.districts]
# `sift ui` groups files into districts by path prefix; these override the defaults.
# db = ["db", "models", "sql", "migrations"]
"""
