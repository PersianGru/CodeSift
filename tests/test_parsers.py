"""Parser tests with synthetic tool output (no binaries needed)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codesift.detect import Detection
from codesift.gitutil import GitInfo
from codesift.lockfile import Lock
from codesift.models import Severity
from codesift.paths import Paths
from codesift.redact import Redactor
from codesift.runners.base import Context
from codesift.runners.gitleaks import Gitleaks, _glob_to_regex
from codesift.runners.opengrep import Opengrep, clean_rule_id, opengrep_severity, rulesets_for
from codesift.runners.optional import ComposerAudit, Govulncheck
from codesift.runners.osv import OsvScanner, cvss_severity
from codesift.runners.python import Bandit, Ruff
from codesift.runners.trivy import Trivy
from codesift.runners.zizmor import Zizmor


@pytest.fixture
def ctx(tmp_path: Path, paths: Paths) -> Context:
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(
        "import os\n" + "".join(f"line{i} = {i}\n" for i in range(2, 30)), encoding="utf-8"
    )
    raw = tmp_path / "raw"
    raw.mkdir()
    return Context(
        root=root,
        detection=Detection(root=root, files=["src/app.py"]),
        git=GitInfo(False),
        paths=paths,
        lock=Lock(updated="x"),
        raw_dir=raw,
        work_dir=tmp_path,
        exclude_globs=[],
        redactor=Redactor(),
    )


def test_rel_paths(ctx: Context) -> None:
    abs_path = str(ctx.root / "src" / "App.py")
    assert ctx.rel(abs_path) == "src/App.py"
    assert ctx.rel(abs_path.replace("\\", "/")) == "src/App.py"
    assert ctx.rel("./src/app.py") == "src/app.py"
    assert ctx.rel("docker/Dockerfile") == "docker/Dockerfile"


def test_opengrep_parse(ctx: Context) -> None:
    out = {
        "results": [
            {
                "check_id": "cache.opengrep-rules.abc.python.flask.security.injection.subprocess-injection",
                "path": str(ctx.root / "src" / "app.py"),
                "start": {"line": 3},
                "end": {"line": 4},
                "extra": {
                    "severity": "ERROR",
                    "message": "user input   in subprocess",
                    "metadata": {"cwe": ["CWE-78: OS Command Injection"], "confidence": "HIGH"},
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": ["x"]},
    }
    [finding] = Opengrep().parse(ctx, json.dumps(out))
    assert finding.rule == "python.flask.security.injection.subprocess-injection"
    assert finding.severity is Severity.HIGH and finding.cwe == ["CWE-78"]
    assert finding.path == "src/app.py" and (finding.line, finding.end_line) == (3, 4)
    assert finding.snippet == "line3 = 3\nline4 = 4"
    assert finding.message == "user input in subprocess"


def test_opengrep_severity_rules() -> None:
    assert opengrep_severity("ERROR", {}) is Severity.HIGH
    assert opengrep_severity("ERROR", {"subcategory": ["audit"]}) is Severity.MEDIUM
    assert opengrep_severity("ERROR", {"subcategory": ["audit"], "confidence": "LOW"}) is Severity.LOW
    assert opengrep_severity("INFO", {"confidence": "LOW"}) is Severity.LOW
    assert clean_rule_id("rules.custom.my-rule") == "custom.my-rule"
    assert rulesets_for({"python", "js"}) == ["generic", "javascript", "python", "typescript"]


def test_osv_parse_groups_per_package(ctx: Context) -> None:
    out = {
        "results": [
            {
                "source": {"path": str(ctx.root / "requirements.txt")},
                "packages": [
                    {
                        "package": {"name": "pyyaml", "version": "5.3", "ecosystem": "PyPI"},
                        "groups": [
                            {"ids": ["PYSEC-1", "GHSA-aaaa"], "max_severity": "9.8"},
                            {"ids": ["GHSA-bbbb"], "max_severity": ""},
                        ],
                        "vulnerabilities": [
                            {
                                "id": "GHSA-aaaa",
                                "summary": "RCE",
                                "affected": [
                                    {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}
                                ],
                            }
                        ],
                    },
                    {"package": {"name": "ok", "version": "1"}, "groups": [], "vulnerabilities": []},
                ],
            }
        ]
    }
    [finding] = OsvScanner().parse(ctx, json.dumps(out))
    assert finding.severity is Severity.CRITICAL
    assert finding.extra["advisories"] == ["GHSA-aaaa", "GHSA-bbbb"]
    assert finding.extra["fixed_in"] == ["5.4"]
    assert finding.path == "requirements.txt" and finding.line == 0
    assert cvss_severity("bogus") is Severity.MEDIUM
    assert cvss_severity("7.0") is Severity.HIGH and cvss_severity("3.9") is Severity.LOW


def test_trivy_parse_and_override(ctx: Context) -> None:
    out = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {"ID": "DS-0002", "Title": "root", "Message": "m", "Severity": "HIGH", "Status": "FAIL"},
                    {"ID": "DS-0029", "Title": "apt", "Message": "m", "Severity": "HIGH", "Status": "FAIL"},
                    {"ID": "DS-0001", "Title": "ok", "Severity": "MEDIUM", "Status": "PASS"},
                ],
            }
        ]
    }
    found = Trivy().parse(ctx, json.dumps(out))
    assert [(x.rule, x.severity) for x in found] == [("DS-0002", Severity.HIGH), ("DS-0029", Severity.LOW)]


def test_ruff_and_bandit_share_alias(ctx: Context) -> None:
    ruff = [
        {
            "code": "S602",
            "message": "shell=True",
            "filename": str(ctx.root / "src" / "app.py"),
            "location": {"row": 5},
            "end_location": {"row": 5},
            "name": "subprocess-popen-with-shell-equals-true",
        },
        {"code": "E501", "filename": "x", "location": {"row": 1}},
    ]
    [r] = Ruff().parse(ctx, json.dumps(ruff))
    assert r.aliases == ["bandit:B602"] and r.severity is Severity.HIGH and "CWE-78" in r.cwe
    bandit = {
        "results": [
            {
                "test_id": "B602",
                "filename": str(ctx.root / "src" / "app.py"),
                "line_number": 5,
                "line_range": [5],
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 78},
                "issue_text": "shell",
                "test_name": "subprocess_popen_with_shell_equals_true",
            }
        ]
    }
    [b] = Bandit().parse(ctx, json.dumps(bandit))
    assert b.aliases == r.aliases and b.confidence == "high"


def test_zizmor_rows_are_zero_based(ctx: Context) -> None:
    out = [
        {
            "ident": "template-injection",
            "desc": "code injection",
            "determinations": {"severity": "High", "confidence": "Medium"},
            "locations": [
                {
                    "symbolic": {
                        "key": {"Local": {"given_path": str(ctx.root / ".github/workflows/ci.yml")}},
                        "annotation": "may expand",
                        "kind": "Primary",
                    },
                    "concrete": {
                        "location": {"start_point": {"row": 16}, "end_point": {"row": 17}},
                        "feature": "run",
                    },
                }
            ],
        }
    ]
    [z] = Zizmor().parse(ctx, json.dumps(out))
    assert (z.line, z.end_line) == (17, 18)
    assert z.path == ".github/workflows/ci.yml" and z.severity is Severity.HIGH


def test_gitleaks_parse_masks(ctx: Context, fake_secret: Callable[[str], str]) -> None:
    secret = fake_secret("github")
    report = ctx.raw_dir / "gl.json"
    report.write_text(
        json.dumps(
            [
                {
                    "RuleID": "github-pat",
                    "Description": "GitHub PAT",
                    "File": "src/app.py",
                    "StartLine": 3,
                    "EndLine": 3,
                    "Match": f"token = {secret}",
                    "Secret": secret,
                    "Commit": "abcdef1234567890",
                }
            ]
        ),
        encoding="utf-8",
    )
    [g] = Gitleaks().parse(ctx, report, "history")
    assert secret not in json.dumps(g.to_dict())
    assert g.severity is Severity.HIGH and "commit abcdef123456" in g.message


def test_glob_to_regex() -> None:
    import re

    rx = re.compile(_glob_to_regex("tests/fixtures/**"))
    assert rx.search("tests/fixtures/a/b.py") and not rx.search("src/tests.py")
    rx2 = re.compile(_glob_to_regex("**/*.min.js"))
    assert rx2.search("web/app.min.js") and rx2.search("app.min.js")


def test_optional_parsers(ctx: Context) -> None:
    composer = {
        "advisories": {
            "guzzlehttp/guzzle": [{"cve": "CVE-2022-1", "title": "t", "severity": "high"}],
        }
    }
    [c] = ComposerAudit().parse(ctx, json.dumps(composer))
    assert c.severity is Severity.HIGH
    assert ComposerAudit().parse(ctx, json.dumps({"advisories": []})) == []
    objects: list[Any] = [
        {"config": {}},
        {"osv": {"id": "GO-1", "summary": "bad"}},
        {"finding": {"osv": "GO-1", "trace": [{"module": "m"}]}},
        {
            "finding": {
                "osv": "GO-1",
                "trace": [
                    {"module": "m", "function": "F"},
                    {
                        "function": "main",
                        "position": {"filename": str(ctx.root / "src" / "app.py"), "line": 2},
                    },
                ],
            }
        },
    ]
    stream = "\n".join(json.dumps(o) for o in objects)
    [g] = Govulncheck().parse(ctx, stream)
    assert g.rule == "GO-1" and g.path == "src/app.py" and g.line == 2


def test_zizmor_github_owned_actions_are_medium(ctx: Context) -> None:
    def item(uses: str) -> dict[str, Any]:
        return {
            "ident": "unpinned-uses",
            "desc": "unpinned action reference",
            "determinations": {"severity": "High", "confidence": "High"},
            "locations": [
                {
                    "symbolic": {
                        "key": {"Local": {"given_path": "ci.yml"}},
                        "annotation": "a",
                        "kind": "Primary",
                    },
                    "concrete": {
                        "location": {"start_point": {"row": 1}, "end_point": {"row": 1}},
                        "feature": uses,
                    },
                }
            ],
        }

    found = Zizmor().parse(ctx, json.dumps([item("uses: actions/checkout@v4"), item("uses: some/thing@v2")]))
    assert [x.severity for x in found] == [Severity.MEDIUM, Severity.HIGH]
