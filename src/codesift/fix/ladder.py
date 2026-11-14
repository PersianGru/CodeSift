"""Build the fixer ladder from fix.toml, consent and the environment (ADR-0013).

Default: gateway first (max_attempts_per_backend), then the Claude backends; findings at or above
`escalate_min_severity` skip straight to Claude. A backend without recorded consent, credentials or
an installed CLI is left out (and said so in the dry-run plan)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from codesift.config import ConfigError, load_credentials, load_user_config, model_overrides
from codesift.finding import Finding
from codesift.fix.base import Fixer
from codesift.fix.claude_api import ClaudeApiClient, ClaudeApiFixer
from codesift.fix.claude_cli import ClaudeCliFixer, find_claude
from codesift.fix.config import FixSettings
from codesift.fix.consent import has_consent
from codesift.fix.gateway_fixer import GatewayFixer
from codesift.gateway import ClientSettings, GatewayClient
from codesift.models import Severity
from codesift.paths import Paths
from codesift.redact import Redactor
from codesift.validate.engine import LadderStep

DESTINATION = {
    "gateway": "redacted excerpt -> your LLM gateway",
    "claude-cli": "workspace copy without secret files -> Claude CLI (Anthropic)",
    "claude-api": "redacted excerpt -> api.anthropic.com",
}


@dataclass
class Backends:
    fixers: dict[str, Fixer] = field(default_factory=dict)
    unavailable: dict[str, str] = field(default_factory=dict)


def build_backends(
    paths: Paths, env: Mapping[str, str], settings: FixSettings, redactor: Redactor
) -> Backends:
    out = Backends()
    for name in settings.backends:
        if not has_consent(paths, name):
            out.unavailable[name] = "no recorded consent (sift setup --fixers)"
            continue
        if name == "gateway":
            try:
                user = load_user_config(paths)
                creds = load_credentials(paths, env, allow_http_localhost=user.allow_http_localhost)
            except ConfigError as exc:
                out.unavailable[name] = str(exc)
                continue
            if creds is None:
                out.unavailable[name] = "no LLM gateway configured (sift setup --llm)"
                continue
            redactor.add(creds.api_key)
            model = model_overrides(paths, env).get("model", user.llm.model)
            client = GatewayClient(creds, ClientSettings(timeout_s=300, retries=1, max_tokens=4096))
            out.fixers[name] = GatewayFixer(client, model, redactor)
        elif name == "claude-cli":
            path = find_claude(settings.claude_cli.path)
            if path is None:
                out.unavailable[name] = "the `claude` CLI was not found"
                continue
            c = settings.claude_cli
            out.fixers[name] = ClaudeCliFixer(path, c.model, c.max_turns, c.timeout_s, redactor)
        elif name == "claude-api":
            from codesift.secrets_store import StoreError, read_env

            try:
                key = env.get("CODESIFT_ANTHROPIC_API_KEY") or read_env(paths.anthropic_file).get(
                    "CODESIFT_ANTHROPIC_API_KEY", ""
                )
            except StoreError as exc:
                out.unavailable[name] = str(exc)
                continue
            if not key:
                out.unavailable[name] = "no Claude API key (sift setup --fixers)"
                continue
            if not settings.claude_api.model:
                out.unavailable[name] = "no Claude API model in fix.toml"
                continue
            redactor.add(key)
            client_api = ClaudeApiClient(key, timeout_s=settings.claude_api.timeout_s)
            out.fixers[name] = ClaudeApiFixer(
                client_api, settings.claude_api.model, redactor, settings.claude_api.max_tokens
            )
    return out


def make_ladder(
    settings: FixSettings, backends: Backends, only: str | None = None
) -> Callable[[Finding], list[LadderStep]]:
    escalate = Severity.parse(settings.escalate_min_severity)

    def ladder(finding: Finding) -> list[LadderStep]:
        names = [only] if only else list(settings.backends)
        if not only and finding.severity >= escalate:
            external = [n for n in names if n != "gateway" and n in backends.fixers]
            if external:  # serious findings go straight to Claude when it is enabled
                names = external
        return [
            LadderStep(n, backends.fixers[n], settings.max_attempts_per_backend, DESTINATION[n])
            for n in names
            if n in backends.fixers
        ]

    return ladder


def make_reviewer(backends: Backends) -> Callable[[Finding, str], str] | None:
    """A text-only critic for --review-patch (advice only). Uses the Claude API if available."""
    api = backends.fixers.get("claude-api")
    if isinstance(api, ClaudeApiFixer):
        return lambda _f, diff: api.review(diff)
    gw = backends.fixers.get("gateway")
    if isinstance(gw, GatewayFixer):
        from codesift.fix.prompts import REVIEW_PROMPT

        def review(_f: Finding, diff: str) -> str:
            msgs = [
                {"role": "system", "content": REVIEW_PROMPT},
                {"role": "user", "content": gw.redactor.scrub(diff)[:30000]},
            ]
            return gw.client.chat(gw.model, msgs, max_tokens=600, json_mode=False).content

        return review
    return None
