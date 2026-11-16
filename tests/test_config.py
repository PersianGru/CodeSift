from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from codesift.config import (
    PROJECT_TEMPLATE,
    ConfigError,
    load_credentials,
    load_project_config,
    load_user_config,
    model_overrides,
    parse_project_config,
    parse_user_config,
    validate_base_url,
)
from codesift.envfile import parse_env_text
from codesift.models import Severity
from codesift.paths import Paths, get_paths


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


# ---------------------------------------------------------------- env file


def test_env_parser_handles_comments_quotes_export() -> None:
    text = (
        "# c\nA=1\nexport B = two \nC='x # y'\nD=\"q\"\nE=val # note\nF=   # only comment\nbad line\n9X=no\n"
    )
    assert parse_env_text(text) == {"A": "1", "B": "two", "C": "x # y", "D": "q", "E": "val", "F": ""}


# ---------------------------------------------------------------- URL validation


@pytest.mark.parametrize(
    "url",
    ["https://gw.example.com/v1", "https://gw.example.com:8443/v1/", "https://10.0.0.5/v1"],
)
def test_https_urls_accepted(url: str) -> None:
    assert validate_base_url(url).startswith("https://")
    assert not validate_base_url(url).endswith("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://gw.example.com/v1",
        "ftp://gw.example.com",
        "gw.example.com/v1",
        "https://user:pw@gw.example.com/v1",
        "https://gw.example.com/v1?key=abc",
        "https://gw.example.com:99999/v1",
    ],
)
def test_bad_urls_rejected(url: str) -> None:
    with pytest.raises(ConfigError):
        validate_base_url(url)


def test_http_localhost_needs_opt_in() -> None:
    with pytest.raises(ConfigError):
        validate_base_url("http://localhost:8080/v1")
    assert validate_base_url("http://127.0.0.1:8080/v1", allow_http_localhost=True)
    with pytest.raises(ConfigError):
        validate_base_url("http://gw.example.com/v1", allow_http_localhost=True)


def test_url_error_never_contains_secret(fake_secret: Callable[[str], str]) -> None:
    secret = fake_secret("generic")
    with pytest.raises(ConfigError) as exc:
        validate_base_url(f"https://u:{secret}@gw.example.com/v1")
    assert secret not in str(exc.value)


# ---------------------------------------------------------------- credentials


def test_no_credentials_returns_none(paths: Paths) -> None:
    assert load_credentials(paths, env={}) is None


def test_credentials_from_file(paths: Paths, fake_secret: Callable[[str], str]) -> None:
    key = fake_secret("generic")
    _write(paths.credentials_file, f"BIFROST_BASE_URL=https://gw.example.com/v1\nBIFROST_API_KEY={key}\n")
    creds = load_credentials(paths, env={})
    assert creds is not None
    assert creds.host == "gw.example.com"
    assert creds.api_key == key
    assert creds.source == "file"
    assert key not in repr(creds)


def test_env_overrides_file(paths: Paths, fake_secret: Callable[[str], str]) -> None:
    _write(
        paths.credentials_file, "BIFROST_BASE_URL=https://file.example.com/v1\nBIFROST_API_KEY=filekey123\n"
    )
    key = fake_secret("generic")
    creds = load_credentials(paths, env={"BIFROST_API_KEY": key})
    assert creds is not None
    assert creds.api_key == key
    assert creds.host == "file.example.com"
    assert creds.source == "env+file"


def test_non_https_credentials_rejected(paths: Paths) -> None:
    _write(paths.credentials_file, "BIFROST_BASE_URL=http://gw.example.com/v1\nBIFROST_API_KEY=abcdef123\n")
    with pytest.raises(ConfigError, match="https"):
        load_credentials(paths, env={})


def test_half_configured_credentials_rejected(paths: Paths) -> None:
    with pytest.raises(ConfigError, match="base URL is missing"):
        load_credentials(paths, env={"BIFROST_API_KEY": "abcdef123"})


def test_model_overrides(paths: Paths) -> None:
    _write(paths.credentials_file, "BIFROST_MODEL=m1\n")
    assert model_overrides(paths, env={"BIFROST_FALLBACK_MODEL": "m2"}) == {
        "model": "m1",
        "fallback_model": "m2",
    }


# ---------------------------------------------------------------- user config


def test_user_config_defaults(paths: Paths) -> None:
    cfg = load_user_config(paths)
    assert cfg.threshold is Severity.HIGH
    assert cfg.jobs == 2
    assert cfg.llm.max_tokens >= 2048


def test_user_config_parsed(paths: Paths) -> None:
    _write(
        paths.config_file,
        'threshold = "medium"\njobs = 1\n[llm]\nmodel = "x"\nmax_findings = 10\nbogus = 1\n',
    )
    cfg = load_user_config(paths)
    assert cfg.threshold is Severity.MEDIUM
    assert cfg.llm.model == "x"
    assert cfg.llm.max_findings == 10
    assert any("bogus" in w for w in cfg.warnings)


@pytest.mark.parametrize(
    "data",
    [
        {"jobs": 0},
        {"jobs": True},
        {"threshold": "severe"},
        {"llm": {"max_tokens": "big"}},
        {"llm": {"think": "maybe"}},
        {"llm": {"call_timeout_s": 0}},
    ],
)
def test_user_config_invalid(data: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        parse_user_config(data)


def test_invalid_toml(paths: Paths) -> None:
    _write(paths.config_file, "jobs = = 2\n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_user_config(paths)


# ---------------------------------------------------------------- project config


def test_project_template_parses(tmp_path: Path) -> None:
    _write(tmp_path / ".codesift.toml", PROJECT_TEMPLATE)
    cfg = load_project_config(tmp_path)
    assert cfg.path is not None
    assert cfg.exclude == []


def test_project_config_values() -> None:
    cfg = parse_project_config(
        {
            "scan": {"exclude": ["vendor/**"], "threshold": "critical", "disable": ["trivy"]},
            "review": {"critical_paths": ["app/licensing/**"], "checklist": "docs/spec.md"},
        }
    )
    assert cfg.exclude == ["vendor/**"]
    assert cfg.threshold is Severity.CRITICAL
    assert cfg.critical_paths == ["app/licensing/**"]
    assert cfg.checklist == "docs/spec.md"


def test_project_config_type_errors() -> None:
    with pytest.raises(ConfigError):
        parse_project_config({"scan": {"exclude": "vendor/**"}})


# ---------------------------------------------------------------- paths


def test_paths_windows() -> None:
    env = {"LOCALAPPDATA": r"C:\U\L", "APPDATA": r"C:\U\R", "USERPROFILE": r"C:\U"}
    p = get_paths(env, platform="win32")
    # AppData is never used on Windows (MSIX write virtualization, ADR-0002).
    assert p.data == Path(r"C:\U") / ".codesift"
    assert p.credentials_file == Path(r"C:\U") / ".codesift" / "config" / "bifrost.env"
    assert p.runs == p.data / "runs"
    assert p.bin == p.data / "bin"
    assert p.skill_file == Path(r"C:\U") / ".claude" / "skills" / "sift" / "SKILL.md"


def test_paths_linux_defaults_and_xdg() -> None:
    p = get_paths({"HOME": "/home/u"}, platform="linux")
    assert p.data == Path("/home/u/.local/share/codesift")
    assert p.config == Path("/home/u/.config/codesift")
    assert p.runs == Path("/home/u/.cache/codesift/runs")
    assert p.bin == Path("/home/u/.local/bin")
    p2 = get_paths({"HOME": "/home/u", "XDG_CONFIG_HOME": "/cfg"}, platform="linux")
    assert p2.config == Path("/cfg/codesift")


def test_paths_overrides() -> None:
    p = get_paths({"HOME": "/h", "CODESIFT_HOME": "/sc", "CODESIFT_CONFIG": "/scc"}, platform="linux")
    assert p.data == Path("/sc")
    assert p.runs == Path("/sc/runs")
    assert p.config == Path("/scc")
    p3 = get_paths({"HOME": "/h", "CODESIFT_HOME": "/sc", "CODESIFT_RUNS": "/r"}, platform="linux")
    assert p3.runs == Path("/r") and p3.data == Path("/sc") and p3.bin == Path("/sc/bin")
