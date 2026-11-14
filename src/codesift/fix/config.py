"""`fix.toml`: fixer backends, escalation and budgets. Written owner-only by `sift setup --fixers`."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from typing import Any

from codesift.models import Severity
from codesift.paths import Paths

BACKENDS = ("gateway", "claude-cli", "claude-api")
SUGGESTED_API_MODEL = "claude-sonnet-5-5"  # a suggestion in the wizard; the user's fix.toml decides


class FixConfigError(Exception):
    pass


@dataclass
class ClaudeCliSettings:
    path: str = ""
    model: str = ""
    max_turns: int = 8
    timeout_s: int = 600


@dataclass
class ClaudeApiSettings:
    model: str = ""
    max_tokens: int = 4096
    timeout_s: int = 180


@dataclass
class FixSettings:
    backends: list[str] = field(default_factory=lambda: ["gateway", "claude-cli"])
    max_attempts_per_backend: int = 2
    escalate_min_severity: str = "high"
    max_findings: int = 5
    token_budget: int = 200_000
    time_budget_s: int = 3600
    finding_time_budget_s: int = 900
    claude_cli: ClaudeCliSettings = field(default_factory=ClaudeCliSettings)
    claude_api: ClaudeApiSettings = field(default_factory=ClaudeApiSettings)

    def validate(self) -> FixSettings:
        unknown = [b for b in self.backends if b not in BACKENDS]
        if unknown or not self.backends or len(set(self.backends)) != len(self.backends):
            raise FixConfigError(f"fix.backends must be distinct values of {', '.join(BACKENDS)}")
        try:
            Severity.parse(self.escalate_min_severity)
        except ValueError as exc:
            raise FixConfigError(f"fix.escalate_min_severity: {exc}") from None
        for name, low, high in (
            ("max_attempts_per_backend", 1, 5),
            ("max_findings", 1, 50),
            ("token_budget", 1000, 5_000_000),
            ("time_budget_s", 60, 86_400),
            ("finding_time_budget_s", 30, 86_400),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not low <= value <= high:
                raise FixConfigError(f"fix.{name} must be between {low} and {high}")
        if not 1 <= self.claude_cli.max_turns <= 50 or not 30 <= self.claude_cli.timeout_s <= 3600:
            raise FixConfigError("claude_cli.max_turns 1-50 and timeout_s 30-3600")
        if not 256 <= self.claude_api.max_tokens <= 64000 or not 10 <= self.claude_api.timeout_s <= 1800:
            raise FixConfigError("claude_api.max_tokens 256-64000 and timeout_s 10-1800")
        return self


def _fill(obj: Any, section: dict[str, Any], where: str) -> None:
    for f in fields(obj):
        if f.name not in section or f.name in ("claude_cli", "claude_api"):
            continue
        value, default = section[f.name], getattr(obj, f.name)
        if isinstance(default, list):
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise FixConfigError(f"{where}.{f.name} must be a list of strings")
        elif type(value) is not type(default):
            raise FixConfigError(f"{where}.{f.name} has the wrong type")
        setattr(obj, f.name, value)


def load_fix_settings(paths: Paths) -> FixSettings:
    cfg = FixSettings()
    if not paths.fix_file.is_file():
        return cfg
    try:
        with paths.fix_file.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise FixConfigError(f"fix.toml cannot be read: {type(exc).__name__}") from None
    for key, target in (("fix", cfg), ("claude_cli", cfg.claude_cli), ("claude_api", cfg.claude_api)):
        section = data.get(key, {})
        if not isinstance(section, dict):
            raise FixConfigError(f"fix.toml: [{key}] must be a table")
        _fill(target, section, key)
    return cfg.validate()


def _value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int | float):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(_value(x) for x in v) + "]"
    text = str(v)
    if "'" in text or any(ord(c) < 32 for c in text):
        raise FixConfigError("fix.toml: a value contains characters that cannot be stored")
    return f"'{text}'"


def render(cfg: FixSettings) -> str:
    lines = ["# CodeSift fixer backends. Edit with `sift setup --fixers`.", "[fix]"]
    for f in fields(cfg):
        if f.name not in ("claude_cli", "claude_api"):
            lines.append(f"{f.name} = {_value(getattr(cfg, f.name))}")
    for name in ("claude_cli", "claude_api"):
        lines += ["", f"[{name}]"]
        sub = getattr(cfg, name)
        lines += [f"{f.name} = {_value(getattr(sub, f.name))}" for f in fields(sub)]
    return "\n".join(lines) + "\n"


def save_fix_settings(paths: Paths, cfg: FixSettings) -> str:
    from codesift.secrets_store import write_private

    cfg.validate()
    return write_private(paths.fix_file, render(cfg))
