"""`sift setup`: a calm, one-question-at-a-time wizard for the LLM gateway, the sandbox VM and the
fixer backends. Re-runnable: current values are shown (secrets masked) and Enter keeps them.

Secrets are read with hidden input, held in a Redactor, never echoed, logged or passed on a command
line. Every file is written owner-only (secrets_store)."""

from __future__ import annotations

import getpass
import socket
import ssl
import time
import urllib.error
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from codesift.config import (
    LLM_ALLOW_HTTP,
    LLM_FALLBACK,
    LLM_KEY,
    LLM_MODEL,
    LLM_URL,
    ConfigError,
    Credentials,
    gateway_values,
    has_legacy_credentials,
    url_kind,
    validate_base_url,
)
from codesift.gateway import ClientSettings, GatewayClient, LLMError
from codesift.paths import Paths
from codesift.redact import Redactor
from codesift.secrets_store import StoreError, describe, migrate_legacy_gateway, save_gateway

KEEP_HINT = "Enter keeps it"


class SetupError(Exception):
    """Wizard cannot continue. Never contains a secret value."""


# ---------------------------------------------------------------- I/O


@dataclass
class WizardIO:
    """Console I/O with injectable functions (tests script them). Everything printed passes through
    the redactor, which learns every secret the wizard reads."""

    ask_fn: Callable[[str], str] = input
    secret_fn: Callable[[str], str] = getpass.getpass
    print_fn: Callable[[str], None] = print
    redactor: Redactor = field(default_factory=Redactor)

    def say(self, text: str = "") -> None:
        self.print_fn(self.redactor.scrub(text))

    def ask(self, question: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default else ""
        try:
            answer = self.ask_fn(self.redactor.scrub(f"{question}{suffix}: ")).strip()
        except EOFError:
            raise SetupError("input ended - setup cancelled, nothing changed for this step") from None
        return answer or (default or "")

    def secret(self, question: str) -> str:
        try:
            value = self.secret_fn(f"{question}: ")
        except EOFError:
            raise SetupError("input ended - setup cancelled, nothing changed for this step") from None
        value = value.strip()
        self.redactor.add(value)
        return value

    def yes(self, question: str, default: bool = False) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            answer = self.ask(f"{question} ({hint})").lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.say("  please answer y or n")

    def exactly_yes(self, question: str) -> bool:
        """For trust decisions: only the literal word `yes` counts."""
        return self.ask(f"{question} (type yes to confirm)").lower() == "yes"


# ---------------------------------------------------------------- gateway connection test


@dataclass
class GatewayProbe:
    reachable: bool
    status: int | None = None
    models: int | None = None
    latency_s: float | None = None
    chat_ok: bool | None = None
    error_kind: str = ""  # dns | connect | tls | timeout | auth | not_found | http | invalid
    fix: str = ""

    def lines(self) -> list[str]:
        out = [f"  reachable: {'yes' if self.reachable else 'no'}"]
        if self.status is not None:
            out.append(f"  HTTP status: {self.status}")
        if self.models is not None:
            out.append(f"  models offered: {self.models}")
        if self.latency_s is not None:
            out.append(f"  latency: {self.latency_s:.2f}s")
        if self.chat_ok is not None:
            out.append(f"  test completion: {'ok' if self.chat_ok else 'failed'}")
        if self.fix:
            out.append(f"  fix: {self.fix}")
        return out


FIXES = {
    "dns": "the host name does not resolve - check the spelling, VPN or DNS",
    "connect": "nothing answers on that host/port - check the gateway is running and the port is open",
    "tls": "TLS failed - the certificate is not trusted by this machine or the URL should use another port",
    "timeout": "no answer in time - check firewall/VPN, or that the gateway is not overloaded",
    "auth": "the gateway refused the key (401/403) - check the API key",
    "not_found": "404 - the base URL path is probably wrong (most gateways end in /v1)",
    "http": "the gateway answered with an error - check its logs",
    "invalid": "the answer was not an OpenAI-compatible /models list - check the base URL",
}


def _classify(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return "auth"
        return "not_found" if exc.code == 404 else "http"
    reason: Any = getattr(exc, "reason", exc)
    if isinstance(reason, socket.gaierror):
        return "dns"
    if isinstance(reason, ssl.SSLError | ssl.CertificateError):
        return "tls"
    if isinstance(reason, TimeoutError | socket.timeout) or "timed out" in str(reason).lower():
        return "timeout"
    if isinstance(reason, ConnectionError | OSError):
        return "connect"
    return "connect"


def probe_gateway(base_url: str, api_key: str, model: str, timeout: float = 15) -> GatewayProbe:
    """GET <base>/models, then a 1-token completion. Shows only reachability, status, model count and
    latency (never the key or answer text)."""
    client = GatewayClient(
        Credentials(base_url=base_url, api_key=api_key),
        ClientSettings(timeout_s=timeout, retries=0, backoff_s=(0,), max_tokens=1, stream=False),
        sleep=lambda _s: None,
    )
    start = time.monotonic()
    try:
        data = client._request("GET", "/models", None, timeout)
    except urllib.error.HTTPError as exc:
        kind = _classify(exc)
        return GatewayProbe(True, status=exc.code, error_kind=kind, fix=FIXES[kind])
    except (urllib.error.URLError, TimeoutError, OSError, LLMError) as exc:
        kind = _classify(exc) if not isinstance(exc, LLMError) else "invalid"
        return GatewayProbe(False, error_kind=kind, fix=FIXES[kind])
    latency = time.monotonic() - start
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        return GatewayProbe(True, status=200, latency_s=latency, error_kind="invalid", fix=FIXES["invalid"])
    probe = GatewayProbe(True, status=200, models=len(data["data"]), latency_s=latency)
    if model:
        try:
            client.chat(
                model,
                [{"role": "user", "content": "Reply with: ok"}],
                max_tokens=1,
                timeout=timeout,
                json_mode=False,
                think=False,
                retries=0,
            )
            probe.chat_ok = True
        except LLMError as exc:
            # A 1-token budget may be spent on reasoning: the model still answered.
            probe.chat_ok = "empty answer" in str(exc)
            if not probe.chat_ok:
                probe.fix = "the gateway is reachable but the test completion failed - check the model id"
    return probe


# ---------------------------------------------------------------- step 1: LLM gateway


@dataclass
class StepResult:
    name: str
    saved: bool
    lines: list[str] = field(default_factory=list)


def _ask_url(io: WizardIO, current: str | None) -> tuple[str, bool]:
    """Returns (normalized URL, trusted-network flag)."""
    while True:
        answer = io.ask(
            "Base URL of your OpenAI-compatible LLM gateway (for example https://llm.example.com/v1 "
            "or http://10.0.0.5:4000/v1)",
            current,
        )
        if not answer:
            io.say("  a base URL is needed (or press Ctrl-C to stop)")
            continue
        try:
            kind = url_kind(answer)
        except ConfigError as exc:
            io.say(f"  {exc}")
            continue
        trusted = False
        if kind != "https":
            where = "this machine" if kind == "http-loopback" else "your local network"
            io.say(f"  This URL uses plain http on {where}: the key and code excerpts travel unencrypted.")
            if not io.exactly_yes("  Is this a trusted network?"):
                io.say("  not saved - use an https:// URL, or confirm the network is trusted")
                continue
            trusted = True
        return validate_base_url(answer, allow_http_lan=trusted), trusted


def step_llm(
    io: WizardIO,
    paths: Paths,
    env: Mapping[str, str],
    probe: Callable[[str, str, str], GatewayProbe] = probe_gateway,
) -> StepResult:
    io.say("")
    io.say("Step 1 - LLM gateway")
    io.say("CodeSift asks a model through any OpenAI-compatible gateway to triage findings and propose")
    io.say("fixes. Only redacted code excerpts are sent; secrets never are.")
    if has_legacy_credentials(paths, env) and migrate_legacy_gateway(paths):
        io.say("  settings from an older CodeSift version were migrated into gateway.env")
    try:
        current, _ = gateway_values(paths, env)
    except ConfigError:
        current = {}
    io.redactor.add(current.get(LLM_KEY))

    url, trusted = _ask_url(io, current.get(LLM_URL))
    key_state = describe(current.get(LLM_KEY)) if LLM_KEY in current else "not set"
    hint = f"currently {key_state}; {KEEP_HINT}, '-' clears it" if LLM_KEY in current else "empty is allowed"
    key = io.secret(f"API key ({hint}, input hidden)")
    if key == "" and LLM_KEY in current:
        key = current[LLM_KEY]
    elif key == "-":
        key = ""
    io.redactor.add(key)
    io.say("Model ids are whatever your gateway offers (free text).")
    model = io.ask("Default model id", current.get(LLM_MODEL))
    while not model:
        model = io.ask("Default model id (required)")
    fallback = io.ask("Optional fallback model id (Enter for none)", current.get(LLM_FALLBACK))

    if io.yes("Test the connection now?", default=True):
        result = probe(url, key, model)
        for line in result.lines():
            io.say(line)
        failed = not result.reachable or bool(result.error_kind)
        if failed and not io.yes("Save these settings anyway?", default=False):
            return StepResult("llm", False, ["LLM gateway: not saved"])

    values = {LLM_URL: url, LLM_KEY: key, LLM_MODEL: model}
    if fallback:
        values[LLM_FALLBACK] = fallback
    if trusted:
        values[LLM_ALLOW_HTTP] = "1"
    note = save_gateway(paths, values)
    io.say(f"  saved {paths.gateway_file} ({note})")
    host = url.split("//", 1)[-1].split("/", 1)[0]
    return StepResult(
        "llm",
        True,
        [
            f"LLM gateway: {host} · key {describe(key)} · model {model}"
            + (f" (fallback {fallback})" if fallback else "")
        ],
    )


def show_llm(paths: Paths, env: Mapping[str, str]) -> list[str]:
    try:
        values, sources = gateway_values(paths, env)
    except ConfigError as exc:
        return [f"LLM gateway: invalid ({exc})"]
    if LLM_URL not in values:
        return ["LLM gateway: not configured (`sift setup --llm`)"]
    url = values[LLM_URL]
    host = url.split("//", 1)[-1].split("/", 1)[0]
    return [
        f"LLM gateway: {host} · key {describe(values.get(LLM_KEY))}"
        + f" · model {values.get(LLM_MODEL, '(default)')}"
        + (f" · fallback {values[LLM_FALLBACK]}" if values.get(LLM_FALLBACK) else "")
        + (" · plain http on a trusted network" if values.get(LLM_ALLOW_HTTP) else "")
        + (" · from an older version (run `sift setup --llm` to migrate)" if sources == {"legacy"} else "")
    ]


SAFETY_STATEMENT = """\
What runs where:
  - Scanners run on this machine, read-only. Project code, tests and PoCs run ONLY in disposable,
    network-less containers on the sandbox VM - never here.
What is sent where:
  - LLM gateway: redacted code excerpts. Claude API (if enabled): redacted excerpts.
    Claude CLI (if enabled): a copy of the project with secret files removed.
What is never done:
  - No patch is applied, merged or pushed automatically. No secret is printed, stored or sent.
    A model never decides "fixed": deterministic checks do."""


# ---------------------------------------------------------------- orchestration

PARTS = ("llm", "vm", "fixers")
PART_FILES: dict[str, Callable[[Paths], list[Any]]] = {
    "llm": lambda p: [p.gateway_file],
    "vm": lambda p: [p.vm_file, p.vm_known_hosts, p.keys_dir],
    "fixers": lambda p: [p.fix_file, p.consent_file, p.anthropic_file],
}


@dataclass
class SetupOptions:
    parts: list[str] = field(default_factory=lambda: list(PARTS))
    non_interactive: bool = False
    show: bool = False
    reset: str | None = None
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_fallback_model: str | None = None
    llm_trusted_network: bool = False
    vm_host: str | None = None
    vm_port: int = 22
    vm_user: str | None = None
    vm_key: str | None = None
    vm_pin_fingerprint: str | None = None
    vm_runtime: str = "docker"
    vm_image: str | None = None
    enable_fixer: list[str] = field(default_factory=list)
    consent: bool = False
    claude_api_model: str | None = None
    claude_cli_path: str | None = None
    test_connection: bool = False


def reset_part(paths: Paths, part: str) -> list[str]:
    import shutil

    if part not in PART_FILES:
        raise SetupError(f"unknown part {part!r} (one of: {', '.join(PARTS)})")
    removed = []
    for target in PART_FILES[part](paths):
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
            removed.append(str(target))
        elif target.exists():
            target.unlink()
            removed.append(str(target))
    return removed or ["nothing to remove"]


def show_state(paths: Paths, env: Mapping[str, str]) -> list[str]:
    lines = show_llm(paths, env)
    for name in ("show_vm", "show_fixers"):
        fn = globals().get(name)
        if callable(fn):
            lines += fn(paths, env)
    return lines


def noninteractive_llm(opts: SetupOptions, paths: Paths, env: Mapping[str, str]) -> StepResult:
    migrate_legacy_gateway(paths)
    try:
        current, _ = gateway_values(paths, env)
    except ConfigError:
        current = {}
    url = opts.llm_base_url or current.get(LLM_URL)
    if not url:
        raise SetupError("--llm-base-url is required (or an existing gateway.env)")
    kind = url_kind(url)
    trusted = opts.llm_trusted_network or current.get(LLM_ALLOW_HTTP) == "1"
    if kind != "https" and not trusted:
        raise SetupError(
            "plain http needs --llm-trusted-network (only for loopback or private LAN addresses)"
        )
    url = validate_base_url(url, allow_http_lan=trusted)
    key = env.get(LLM_KEY, current.get(LLM_KEY, ""))  # secrets only via the environment, never argv
    model = opts.llm_model or current.get(LLM_MODEL)
    if not model:
        raise SetupError("--llm-model is required (or an existing gateway.env)")
    values = {LLM_URL: url, LLM_KEY: key, LLM_MODEL: model}
    fallback = opts.llm_fallback_model or current.get(LLM_FALLBACK)
    if fallback:
        values[LLM_FALLBACK] = fallback
    if trusted and kind != "https":
        values[LLM_ALLOW_HTTP] = "1"
    note = save_gateway(paths, values)
    lines = [f"LLM gateway saved to {paths.gateway_file} ({note}); key {describe(key)}"]
    if opts.test_connection:
        lines += probe_gateway(url, key, model).lines()
    return StepResult("llm", True, lines)


def run_setup(
    opts: SetupOptions,
    paths: Paths,
    env: Mapping[str, str],
    io: WizardIO | None = None,
) -> int:
    """Entry point for `sift setup`. Returns an exit code (0 ok, 2 error)."""
    io = io or WizardIO()
    try:
        if opts.show:
            for line in show_state(paths, env):
                io.say(line)
            return 0
        if opts.reset:
            for line in reset_part(paths, opts.reset):
                io.say(f"removed: {line}" if line != "nothing to remove" else line)
            return 0
        paths.config.mkdir(parents=True, exist_ok=True)
        results: list[StepResult] = []
        for part in opts.parts:
            if opts.non_interactive:
                fn = globals().get(f"noninteractive_{part}")
            else:
                fn = globals().get(f"step_{part}")
            if not callable(fn):
                raise SetupError(f"setup part {part!r} is not available")
            if opts.non_interactive:
                results.append(fn(opts, paths, env))
            else:
                results.append(fn(io, paths, env))
        io.say("")
        io.say("Summary")
        for result in results:
            for line in result.lines:
                io.say(f"  {line}")
        io.say("")
        for line in SAFETY_STATEMENT.splitlines():
            io.say(line)
        return 0
    except (SetupError, ConfigError, StoreError) as exc:
        io.say(f"sift setup: {exc}")
        return 2
    except KeyboardInterrupt:
        io.say("\nsift setup: cancelled")
        return 2
