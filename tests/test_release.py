from __future__ import annotations

import re
import tomllib
from importlib import resources
from pathlib import Path

import pytest

from codesift import __version__
from codesift.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]
# Product names that user-facing text must not contain (RULES.md rule 20). Built from parts so this
# file does not itself trip the check.
PRODUCTS = ["bif" + "rost", "lite" + "llm", "olla" + "ma", "open" + "router", "v" + "llm"]
USER_FACING = [
    "README.md",
    "RULES.md",
    "SECURITY.md",
    "skill/SKILL.md",
    "docs/prompts.md",
    "docs/architecture.md",
    "docs/validate-and-fix.md",
    "docs/ui.md",
    "docs/vm-setup.md",
    "docs/events-schema.md",
    "docs/threat-model.md",
    "install.ps1",
    "install.sh",
]

COMMANDS = [
    ["scan"],
    ["report"],
    ["baseline", "list"],
    ["init"],
    ["hook", "status"],
    ["update"],
    ["doctor"],
    ["install"],
    ["uninstall"],
    ["setup"],
    ["validate"],
    ["fix"],
    ["ui"],
    ["vm", "doctor"],
    ["vm", "status"],
    ["vm", "reset"],
    ["vm", "setup"],
    ["vm", "image", "pull"],
    ["vm", "image", "build"],
    ["vm", "admin-script"],
]


@pytest.mark.parametrize("cmd", COMMANDS, ids=lambda c: " ".join(c))
def test_every_command_has_help(cmd: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main([*cmd, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out.lower()
    assert "usage: sift" in out
    assert not any(p in out for p in PRODUCTS)


def test_top_level_help_lists_new_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    out = capsys.readouterr().out
    for cmd in ("setup", "vm", "validate", "fix", "ui"):
        assert cmd in out
    assert "4 budget exhausted" in out


@pytest.mark.parametrize("name", USER_FACING)
def test_no_gateway_product_names(name: str) -> None:
    text = (ROOT / name).read_text(encoding="utf-8").lower()
    found = [p for p in PRODUCTS if re.search(rf"\b{p}\b", text)]
    assert not found, f"{name} names {found}"


def test_no_product_names_in_ui_and_help_strings() -> None:
    for path in (ROOT / "src" / "codesift" / "ui" / "static").glob("*.*"):
        text = path.read_text(encoding="utf-8").lower()
        assert not any(p in text for p in PRODUCTS), path
    parser_text = build_parser().format_help().lower()
    assert not any(p in parser_text for p in PRODUCTS)


def test_versions_agree() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == __version__ == "0.2.0"
    assert "## [0.2.0]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_package_data_present() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = data["tool"]["setuptools"]["package-data"]["codesift"]
    assert "vm/codesift-gate.sh" in patterns and any("ui/static/vendor" in p for p in patterns)
    pkg = resources.files("codesift")
    for rel in ("vm/codesift-gate.sh", "ui/static/index.html", "ui/static/vendor/three.min.js"):
        assert pkg.joinpath(rel).is_file(), rel


def test_no_ai_attribution_in_new_docs() -> None:
    for name in [*USER_FACING, "CHANGELOG.md", "docs/decisions/ADR-0011-scope-0.2.0.md"]:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "Co-Authored-By" not in text and "Generated with" not in text, name
