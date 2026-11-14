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
from pathlib import Path
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
from codesift.vm import SandboxError
from codesift.vm import keys as vm_keys
from codesift.vm.admin import authorized_keys_line
from codesift.vm.config import DEFAULT_IMAGE, VMConfig, load_vm_config, save_vm_config
from codesift.vm.sshargs import ArgError, validate_host, validate_key_path, validate_port, validate_user

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
    except (SetupError, ConfigError, StoreError, SandboxError) as exc:
        io.say(f"sift setup: {exc}")
        return 2
    except KeyboardInterrupt:
        io.say("\nsift setup: cancelled")
        return 2


# ---------------------------------------------------------------- step 2: sandbox VM

VM_INTRO = (
    "Step 2 - Sandbox VM",
    "Project tests, proofs of concept and patched code run ONLY on a separate Linux VM, inside",
    "disposable containers with no network. Nothing untrusted ever runs on this machine.",
    "Use a lab VM with Docker or Podman - not a production server.",
)


def _current_vm(paths: Paths) -> VMConfig | None:
    try:
        return load_vm_config(paths)
    except SandboxError:
        return None


def _ask_valid(io: WizardIO, question: str, default: str | None, check: Callable[[str], object]) -> str:
    while True:
        answer = io.ask(question, default)
        try:
            check(answer)
            return answer
        except (ArgError, ValueError) as exc:
            io.say(f"  {exc}")


def _ask_int(io: WizardIO, question: str, default: int, low: int, high: int) -> int:
    while True:
        answer = io.ask(question, str(default))
        if answer.isdigit() and low <= int(answer) <= high:
            return int(answer)
        io.say(f"  enter a whole number between {low} and {high}")


def _pin(io: WizardIO, paths: Paths, host: str, port: int) -> str:
    io.say(f"Fetching the VM's SSH host key from {host}:{port} ...")
    found = vm_keys.scan_host_keys(host, port)
    for key in found:
        io.say(f"  {key.key_type}  {key.fingerprint}")
    io.say("Compare it with the fingerprint on the VM (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub).")
    if not io.exactly_yes("Pin this host key? Connections will refuse any other key"):
        raise SetupError("host key not pinned - nothing saved for the VM")
    preferred = [k for k in found if k.key_type == "ssh-ed25519"] or found
    note = vm_keys.pin_host_key(paths.vm_known_hosts, host, port, preferred)
    io.say(f"  pinned in {paths.vm_known_hosts} ({note})")
    return preferred[0].fingerprint


def step_vm(io: WizardIO, paths: Paths, env: Mapping[str, str]) -> StepResult:
    io.say("")
    for line in VM_INTRO:
        io.say(line)
    cur = _current_vm(paths) or VMConfig()
    host = _ask_valid(io, "VM host name or IP address", cur.host or None, validate_host)
    port = int(_ask_valid(io, "SSH port", str(cur.port), validate_port))
    io.say("Use a dedicated unprivileged user on the VM (not an admin; `sift vm admin-script` creates one).")
    user = _ask_valid(io, "VM user name", cur.user or "codesift", validate_user)
    runtime = io.ask("Container runtime (docker or podman)", cur.runtime)
    while runtime not in ("docker", "podman"):
        runtime = io.ask("Container runtime - type docker or podman", "docker")
    image = io.ask("Sandbox image (needs sh, tar, timeout; add your test tools)", cur.image or DEFAULT_IMAGE)
    cfg = VMConfig(host=host, port=port, user=user, runtime=runtime, image=image)
    if image == cur.image:
        cfg.image_id = cur.image_id
    if io.yes("Use the safe default limits (512 MB memory, 1 CPU, 128 processes, 300 s per job)?", True):
        cfg.memory_mb, cfg.cpus, cfg.pids, cfg.job_timeout_s = 512, 1.0, 128, 300
    else:
        cfg.memory_mb = _ask_int(io, "Memory per job (MB)", cur.memory_mb, 64, 65536)
        cfg.cpus = float(_ask_int(io, "CPUs per job", max(1, int(cur.cpus)), 1, 64))
        cfg.pids = _ask_int(io, "Max processes per job", cur.pids, 16, 4096)
        cfg.job_timeout_s = _ask_int(io, "Max seconds per job", cur.job_timeout_s, 5, 3600)
    cfg.min_free_mem_mb = max(cfg.memory_mb + 256, 512)

    # Authentication: a dedicated key (recommended) or an existing key path. No passwords, ever.
    pubkey = ""
    existing = Path(cur.key_path) if cur.key_path else None
    if existing and existing.is_file() and io.yes(f"Keep the current SSH key ({existing.name})?", True):
        cfg.key_path, cfg.key_user_supplied = str(existing), cur.key_user_supplied
        if not cur.key_user_supplied:
            pubkey = vm_keys.public_key_of(existing)
    elif io.yes("Generate a dedicated SSH key for the sandbox (recommended)?", True):
        io.say("  The key has no passphrase: it is used only for this sandbox and the gate script on the")
        io.say("  VM restricts it to sandbox jobs. It is stored owner-only in CodeSift's config folder.")
        private, pubkey = vm_keys.generate_key(paths.keys_dir)
        cfg.key_path, cfg.key_user_supplied = str(private), False
    else:
        io.say("  The key file is never read or shown; only its path is stored. A key with a passphrase")
        io.say("  works only if it is loaded in your ssh-agent (connections run in batch mode).")
        while True:
            path = io.ask("Path of the existing private key")
            try:
                resolved = validate_key_path(path, user_supplied=True)
            except ArgError as exc:
                io.say(f"  {exc}")
                continue
            break
        cfg.key_path, cfg.key_user_supplied = str(resolved), True
        from codesift.secrets_store import owner_only

        if owner_only(resolved) is False:
            io.say(f"  warning: {resolved} is readable by other users - run: chmod 600 {resolved}")
    if pubkey:
        io.say("")
        io.say("Public key (safe to share) - the VM admin installs it for the user above:")
        io.say(f"  {pubkey}")
        io.say("Recommended authorized_keys line (restricted to the gate, see `sift vm admin-script`):")
        io.say(f"  {authorized_keys_line(pubkey)}")
        io.say(f"Or without the gate:  echo '{pubkey}' >> ~{user}/.ssh/authorized_keys")
        io.say("")

    known = vm_keys.pinned_fingerprints(paths.vm_known_hosts) if cur.host == host and cur.port == port else []
    if known and cur.host_key_fingerprint in known and io.yes("Keep the pinned host key?", True):
        cfg.host_key_fingerprint = cur.host_key_fingerprint
    else:
        cfg.host_key_fingerprint = _pin(io, paths, host, port)
    cfg.known_hosts_path = str(paths.vm_known_hosts)
    note = save_vm_config(paths, cfg)
    io.say(f"  saved {paths.vm_file} ({note})")
    lines = [
        f"Sandbox VM: {user}@{host}:{port} · {runtime} · image {image}"
        + (" (pinned)" if cfg.image_id else " (not pinned yet: `sift vm image pull`)"),
        f"Host key: {cfg.host_key_fingerprint}",
    ]
    if io.yes("Contact the VM now and run `sift vm doctor`?", False):
        from codesift.vm.commands import doctor_lines

        for line in doctor_lines(paths):
            io.say(f"  {line}")
    return StepResult("vm", True, lines)


def noninteractive_vm(opts: SetupOptions, paths: Paths, env: Mapping[str, str]) -> StepResult:
    if not opts.vm_host or not opts.vm_user:
        raise SetupError("--vm-host and --vm-user are required")
    if not opts.vm_pin_fingerprint:
        raise SetupError("--vm-pin-fingerprint SHA256:... is required (host keys are never trusted blindly)")
    try:
        host, user = validate_host(opts.vm_host), validate_user(opts.vm_user)
        port = validate_port(opts.vm_port)
    except ArgError as exc:
        raise SetupError(str(exc)) from None
    cur = _current_vm(paths) or VMConfig()
    cfg = VMConfig(host=host, port=port, user=user, runtime=opts.vm_runtime, image=opts.vm_image or cur.image)
    if cfg.image == cur.image:
        cfg.image_id = cur.image_id
    lines: list[str] = []
    if opts.vm_key:
        try:
            cfg.key_path = str(validate_key_path(opts.vm_key, user_supplied=True))
        except ArgError as exc:
            raise SetupError(f"--vm-key: {exc}") from None
        cfg.key_user_supplied = True
    elif cur.key_path and Path(cur.key_path).is_file():
        cfg.key_path, cfg.key_user_supplied = cur.key_path, cur.key_user_supplied
    else:
        private, pubkey = vm_keys.generate_key(paths.keys_dir)
        cfg.key_path = str(private)
        lines.append(f"public key (install on the VM): {pubkey}")
    found = vm_keys.scan_host_keys(host, port)
    match = [k for k in found if k.fingerprint == opts.vm_pin_fingerprint]
    if not match:
        raise SetupError("the VM's host key does not match --vm-pin-fingerprint - nothing pinned")
    vm_keys.pin_host_key(paths.vm_known_hosts, host, port, match)
    cfg.host_key_fingerprint = match[0].fingerprint
    cfg.known_hosts_path = str(paths.vm_known_hosts)
    note = save_vm_config(paths, cfg)
    lines.insert(0, f"Sandbox VM saved to {paths.vm_file} ({note}): {user}@{host}:{port}")
    return StepResult("vm", True, lines)


def show_vm(paths: Paths, env: Mapping[str, str]) -> list[str]:
    from codesift.vm.selftest import last_result

    if not paths.vm_file.exists():
        return ["Sandbox VM: not configured (`sift setup --vm`)"]
    try:
        cfg = load_vm_config(paths)
    except SandboxError as exc:
        return [f"Sandbox VM: invalid ({exc})"]
    key = "dedicated key" if not cfg.key_user_supplied else "your key file"
    last = last_result(paths.data)
    selftest = "never run" if not last else ("passed" if last.get("passed") else "FAILED")
    return [
        f"Sandbox VM: {cfg.user}@{cfg.host}:{cfg.port} · {cfg.runtime} · image {cfg.image}"
        + (" (pinned)" if cfg.image_id else " (not pinned)"),
        f"  {key} · host key {cfg.host_key_fingerprint or 'NOT pinned'} · last self-test {selftest}",
        f"  limits {cfg.memory_mb} MB, {cfg.cpus:g} CPU, {cfg.pids} pids, {cfg.job_timeout_s}s per job",
    ]
