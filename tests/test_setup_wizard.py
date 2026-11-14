from __future__ import annotations

import os
import subprocess
from collections import deque
from collections.abc import Callable
from pathlib import Path

import pytest

from codesift.config import ConfigError, load_credentials, url_kind, validate_base_url
from codesift.paths import Paths
from codesift.secrets_store import read_env
from codesift.setup_wizard import (
    SetupOptions,
    WizardIO,
    probe_gateway,
    run_setup,
    show_state,
)
from mock_gateway import mock_gateway

LEGACY_PREFIX = "BIF" + "ROST_"


class Script:
    """Scripted answers for ask/secret, recording everything printed."""

    def __init__(self, answers: list[str], secrets: list[str]) -> None:
        self.answers = deque(answers)
        self.secrets = deque(secrets)
        self.out: list[str] = []
        self.prompts: list[str] = []

    def ask(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.popleft()

    def secret(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.secrets.popleft()

    def io(self) -> WizardIO:
        return WizardIO(ask_fn=self.ask, secret_fn=self.secret, print_fn=self.out.append)

    @property
    def text(self) -> str:
        return "\n".join(self.out + self.prompts)


def owner_only(path: Path) -> bool:
    if os.name != "nt":
        return path.stat().st_mode & 0o077 == 0
    icacls = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "icacls.exe"
    out = subprocess.run([str(icacls), str(path)], capture_output=True, text=True, check=True).stdout
    aces = [line.replace(str(path), "").strip() for line in out.splitlines() if ":(" in line]
    return len(aces) == 1 and not any(w in aces[0] for w in ("BUILTIN", "Everyone", "Authenticated"))


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("https://llm.example.com/v1", "https"),
        ("https://llm.example.com:8443/v1/", "https"),
        ("http://127.0.0.1:4000/v1", "http-loopback"),
        ("http://localhost:4000/v1", "http-loopback"),
        ("http://10.0.0.5:4000/v1", "http-lan"),
        ("http://192.168.1.20/v1", "http-lan"),
        ("http://[fd00::1]:4000/v1", "http-lan"),
    ],
)
def test_url_kinds(url: str, kind: str) -> None:
    assert url_kind(url) == kind


@pytest.mark.parametrize(
    "url",
    [
        "http://llm.example.com/v1",  # public plain http
        "http://8.8.8.8/v1",
        "https://user:pw@llm.example.com/v1",  # credentials in URL
        "https://token@llm.example.com/v1",
        "ftp://llm.example.com",
        "llm.example.com/v1",
        "https://llm.example.com/v1?key=x",
        "https://llm.example.com/v1#frag",
        "https:///v1",
        "not a url",
        "https://llm.example.com:99999/v1",
        "https://llm.exa mple.com/v1",
    ],
)
def test_url_rejected(url: str) -> None:
    with pytest.raises(ConfigError):
        url_kind(url)


def test_http_needs_trust() -> None:
    with pytest.raises(ConfigError, match="trusted network"):
        validate_base_url("http://10.0.0.5:4000/v1")
    assert validate_base_url("http://10.0.0.5:4000/v1/", allow_http_lan=True) == "http://10.0.0.5:4000/v1"


def test_wizard_llm_step(paths: Paths, fake_secret: Callable[[str], str]) -> None:
    key = fake_secret("generic")
    with mock_gateway() as (url, _state):
        # url is http://127.0.0.1 -> must confirm trusted network
        script = Script([url, "yes", "primary-model", "", "y"], [key])
        code = run_setup(SetupOptions(parts=["llm"]), paths, {}, script.io())
    assert code == 0
    assert key not in script.text
    assert "reachable: yes" in script.text
    assert "models offered: 2" in script.text
    values = read_env(paths.gateway_file)
    assert values["CODESIFT_LLM_API_KEY"] == key
    assert values["CODESIFT_LLM_ALLOW_HTTP"] == "1"
    assert owner_only(paths.gateway_file)
    creds = load_credentials(paths, env={})
    assert creds is not None and creds.api_key == key


def test_wizard_refuses_untrusted_http(paths: Paths) -> None:
    script = Script(["http://10.0.0.5:4000/v1", "no"], [])
    assert run_setup(SetupOptions(parts=["llm"]), paths, {}, script.io()) == 2
    assert "not saved" in script.text
    assert not paths.gateway_file.exists()


def test_wizard_rerun_keeps_and_masks(paths: Paths, fake_secret: Callable[[str], str]) -> None:
    key = fake_secret("generic")
    first = Script(["https://llm.example.com/v1", "m1", "", "n"], [key])
    assert run_setup(SetupOptions(parts=["llm"]), paths, {}, first.io()) == 0
    second = Script(["", "", "", "n"], [""])  # Enter everywhere keeps the values
    assert run_setup(SetupOptions(parts=["llm"]), paths, {}, second.io()) == 0
    assert key not in second.text
    assert f"set (len {len(key)})" in second.text
    assert "[https://llm.example.com/v1]" in second.text
    assert read_env(paths.gateway_file)["CODESIFT_LLM_API_KEY"] == key
    third = Script(["", "", "", "n"], ["-"])  # '-' clears the key
    assert run_setup(SetupOptions(parts=["llm"]), paths, {}, third.io()) == 0
    assert read_env(paths.gateway_file)["CODESIFT_LLM_API_KEY"] == ""


def test_noninteractive(paths: Paths, fake_secret: Callable[[str], str]) -> None:
    key = fake_secret("generic")
    script = Script([], [])
    opts = SetupOptions(
        parts=["llm"], non_interactive=True, llm_base_url="https://llm.example.com/v1/", llm_model="m"
    )
    assert run_setup(opts, paths, {"CODESIFT_LLM_API_KEY": key}, script.io()) == 0
    assert key not in script.text
    values = read_env(paths.gateway_file)
    assert values["CODESIFT_LLM_BASE_URL"] == "https://llm.example.com/v1"
    assert values["CODESIFT_LLM_API_KEY"] == key
    # plain http without the trust flag is refused
    bad = SetupOptions(parts=["llm"], non_interactive=True, llm_base_url="http://10.1.1.1/v1", llm_model="m")
    assert run_setup(bad, paths, {}, Script([], []).io()) == 2


def test_legacy_migration_hides_names(paths: Paths, fake_secret: Callable[[str], str]) -> None:
    key = fake_secret("generic")
    paths.credentials_file.write_text(
        f"{LEGACY_PREFIX}BASE_URL=https://old.example.com/v1\n{LEGACY_PREFIX}API_KEY={key}\n"
        f"{LEGACY_PREFIX}MODEL=old-model\n",
        encoding="utf-8",
    )
    # legacy still works without migration
    creds = load_credentials(paths, env={})
    assert creds is not None and creds.host == "old.example.com"
    shown = "\n".join(show_state(paths, {}))
    assert LEGACY_PREFIX not in shown and key not in shown
    script = Script(["", "", "", "n"], [""])
    assert run_setup(SetupOptions(parts=["llm"]), paths, {}, script.io()) == 0
    assert LEGACY_PREFIX not in script.text and key not in script.text
    assert "migrated" in script.text
    values = read_env(paths.gateway_file)
    assert values["CODESIFT_LLM_BASE_URL"] == "https://old.example.com/v1"
    assert values["CODESIFT_LLM_API_KEY"] == key
    assert values["CODESIFT_LLM_MODEL"] == "old-model"


def test_env_overrides_gateway_file(paths: Paths) -> None:
    paths.gateway_file.write_text(
        "CODESIFT_LLM_BASE_URL=https://file.example.com/v1\nCODESIFT_LLM_API_KEY=filekey123\n",
        encoding="utf-8",
    )
    creds = load_credentials(paths, env={"CODESIFT_LLM_BASE_URL": "https://env.example.com/v1"})
    assert creds is not None and creds.host == "env.example.com" and creds.api_key == "filekey123"


def test_empty_key_sends_no_auth_header(paths: Paths) -> None:
    with mock_gateway() as (url, state):
        probe = probe_gateway(url, "", "primary-model")
    assert probe.reachable and probe.models == 2 and probe.chat_ok
    assert all("Authorization" not in h for h in state.headers)


def test_probe_classifies_errors() -> None:
    with mock_gateway() as (url, state):
        state.models = []
        orig = state.script
        assert probe_gateway(url, "k" * 10, "").models == 0
        assert orig is state.script
    # nothing listening: connect error, no exception escapes
    with mock_gateway() as (url, _state):
        dead = url
    result = probe_gateway(dead, "k" * 10, "m", timeout=2)
    assert not result.reachable and result.error_kind in ("connect", "timeout") and result.fix


def test_probe_401(monkeypatch: pytest.MonkeyPatch) -> None:
    from mock_gateway import Handler

    def get(self: Handler) -> None:
        self.send_json(401, {"error": "no"})

    monkeypatch.setattr(Handler, "do_GET", get)
    with mock_gateway() as (url, _state):
        result = probe_gateway(url, "k" * 10, "m")
    assert result.status == 401 and result.error_kind == "auth"


def test_reset_and_show(paths: Paths) -> None:
    script = Script(["https://llm.example.com/v1", "m", "", "n"], [""])
    assert run_setup(SetupOptions(parts=["llm"]), paths, {}, script.io()) == 0
    out = Script([], [])
    assert run_setup(SetupOptions(show=True), paths, {}, out.io()) == 0
    assert "llm.example.com" in out.text
    assert run_setup(SetupOptions(reset="llm"), paths, {}, Script([], []).io()) == 0
    assert not paths.gateway_file.exists()
