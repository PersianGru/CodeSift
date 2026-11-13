from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from codesift import baseline
from codesift.finding import Finding, fingerprint, normalize_cwes
from codesift.models import Severity
from codesift.normalize import HIDDEN, dedupe, hide_secret_lines, mark_review, order_and_number


def f(
    tool: str,
    rule: str,
    sev: Severity,
    path: str = "app.py",
    line: int = 10,
    *,
    cwe: list[str] | None = None,
    aliases: list[str] | None = None,
    code: str = "x",
    end: int = 0,
    snippet: str = "",
    extra: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        tool=tool,
        rule=rule,
        severity=sev,
        path=path,
        line=line,
        end_line=end,
        message=f"{tool} {rule}",
        fingerprint=fingerprint(tool, rule, path, code),
        cwe=cwe or [],
        aliases=aliases or [],
        snippet=snippet,
        extra=dict(extra or {}),
    )


def test_fingerprint_ignores_whitespace_and_lines() -> None:
    a = fingerprint("bandit", "B602", "a.py", "subprocess.run(cmd,  shell=True)")
    b = fingerprint("bandit", "B602", "a.py", "subprocess.run(cmd,\n    shell=True)")
    assert a == b
    assert a != fingerprint("bandit", "B602", "b.py", "subprocess.run(cmd, shell=True)")


def test_normalize_cwes() -> None:
    assert normalize_cwes(["CWE-78: OS Command Injection", "cwe-78", 89, {"id": 22}]) == [
        "CWE-78",
        "CWE-89",
        "CWE-22",
    ]


def test_dedupe_merges_alias_cwe_and_family() -> None:
    items = [
        f("ruff", "S602", Severity.HIGH, aliases=["bandit:B602"], code="r"),
        f("bandit", "B602", Severity.HIGH, aliases=["bandit:B602"], cwe=["CWE-78"], code="b"),
        f("opengrep", "python.subprocess-injection", Severity.HIGH, cwe=["CWE-78"], code="o"),
        f("opengrep", "python.tainted-sql-string", Severity.HIGH, line=20, cwe=["CWE-704"], code="s"),
        f("bandit", "B999", Severity.LOW, line=20, cwe=["CWE-1"], code="v"),  # unrelated: stays separate
        f("bandit", "B608", Severity.MEDIUM, line=20, cwe=["CWE-89"], code="t"),  # merged by "sql" family
        f("bandit", "B101", Severity.LOW, line=30, code="u"),
    ]
    items[5].category = "hardcoded_sql_expressions"
    merged = dedupe(items)
    assert len(merged) == 4
    first = next(m for m in merged if m.line == 10)
    assert first.tool == "opengrep"  # preferred primary at equal severity
    assert set(first.tools) == {"ruff", "bandit", "opengrep"}
    assert len(first.all_fingerprints) == 3
    sql = next(m for m in merged if m.line == 20)
    assert sql.severity is Severity.HIGH and set(sql.tools) == {"opengrep", "bandit"}


def test_dedupe_keeps_distinct_issues() -> None:
    items = [
        f("bandit", "B602", Severity.HIGH, line=10, cwe=["CWE-78"], code="a"),
        f("bandit", "B602", Severity.HIGH, line=50, cwe=["CWE-78"], code="b"),
        f("bandit", "B602", Severity.HIGH, path="other.py", line=10, cwe=["CWE-78"], code="c"),
    ]
    assert len(dedupe(items)) == 3


def test_dedupe_collapses_identical_fingerprints() -> None:
    a = f("gitleaks", "aws-key", Severity.HIGH, code="AKIA…", extra={"source": "history", "commit": "1"})
    b = f(
        "gitleaks",
        "aws-key",
        Severity.HIGH,
        line=99,
        code="AKIA…",
        extra={"source": "history", "commit": "2"},
    )
    assert len(dedupe([a, b])) == 1


def test_hide_secret_lines() -> None:
    leak = f("gitleaks", "generic-api-key", Severity.HIGH, line=11, extra={"source": "working tree"})
    other = f("bandit", "B105", Severity.LOW, line=10, end=12, snippet="a = 1\ntoken = 'REAL'\nb = 2")
    hide_secret_lines([leak, other])
    assert other.snippet.split("\n") == ["a = 1", HIDDEN, "b = 2"]


def test_order_ids_and_review() -> None:
    items = [
        f("bandit", "B101", Severity.LOW, code="1"),
        f("osv-scanner", "x", Severity.CRITICAL, line=0, code="2"),
        f("bandit", "B602", Severity.HIGH, line=5, code="3"),
    ]
    items[2].baseline = True
    mark_review(items)
    ordered = order_and_number(items)
    assert [x.severity for x in ordered] == [Severity.CRITICAL, Severity.LOW, Severity.HIGH]
    assert [x.id for x in ordered] == ["F001", "F002", "F003"]
    assert ordered[0].needs_review and not ordered[2].needs_review


def test_finding_roundtrip() -> None:
    a = f("bandit", "B602", Severity.HIGH, cwe=["CWE-78"])
    a.id = "F001"
    b = Finding.from_dict(a.to_dict())
    assert b.to_dict() == a.to_dict()


# ---------------------------------------------------------------- baseline


def test_baseline_accept_apply_and_expiry(tmp_path: Path) -> None:
    a = f("bandit", "B602", Severity.HIGH, code="1")
    a.id = "F001"
    b = f("bandit", "B608", Severity.MEDIUM, code="2")
    b.id = "F002"
    with pytest.raises(baseline.BaselineError, match="reason"):
        baseline.accept(tmp_path, [a, b], ["F001"], "  ", None)
    with pytest.raises(baseline.BaselineError, match="unknown"):
        baseline.accept(tmp_path, [a, b], ["F009"], "ok", None)
    with pytest.raises(baseline.BaselineError, match="future"):
        baseline.accept(tmp_path, [a, b], ["F001"], "ok", "2000-01-01")

    added = baseline.accept(tmp_path, [a, b], ["f001"], "internal tool, input is constant", "2999-01-01")
    assert len(added) == 1
    assert b"\r\n" not in (tmp_path / ".codesift-baseline.json").read_bytes()
    assert baseline.accept(tmp_path, [a, b], ["F001"], "again", None) == []

    entries = baseline.load(tmp_path)
    fresh = [
        f("bandit", "B602", Severity.HIGH, line=77, code="1"),
        f("bandit", "B608", Severity.MEDIUM, code="2"),
    ]
    expired = baseline.apply(fresh, entries)
    assert fresh[0].baseline and not fresh[1].baseline and expired == []
    later = [f("bandit", "B602", Severity.HIGH, code="1")]
    expired = baseline.apply(later, entries, today=date(3000, 1, 1))
    assert not later[0].baseline and len(expired) == 1


def test_baseline_prune(tmp_path: Path) -> None:
    a = f("bandit", "B602", Severity.HIGH, code="1")
    a.id = "F001"
    baseline.accept(tmp_path, [a], ["F001"], "reason", None)
    assert baseline.prune(tmp_path, [a]) == []
    removed = baseline.prune(tmp_path, [])
    assert len(removed) == 1 and baseline.load(tmp_path) == []


def test_baseline_invalid_file(tmp_path: Path) -> None:
    (tmp_path / ".codesift-baseline.json").write_text('{"version": 9}', encoding="utf-8")
    with pytest.raises(baseline.BaselineError):
        baseline.load(tmp_path)


def test_group_policy_findings_per_file() -> None:
    from codesift.normalize import group_policy_findings

    items = [
        f("zizmor", "unpinned-uses", Severity.HIGH, path="ci.yml", line=n, code=str(n)) for n in (5, 9, 14)
    ]
    items.append(f("zizmor", "unpinned-uses", Severity.HIGH, path="other.yml", line=3, code="o"))
    items.append(f("zizmor", "unpinned-uses", Severity.HIGH, path="ci.yml", line=20, code="b"))
    items[-1].baseline = True
    grouped = group_policy_findings(items)
    assert len(grouped) == 3  # ci.yml group, other.yml, baselined one kept apart
    head = grouped[0]
    assert head.message.startswith("3 occurrences (lines 5, 9, 14)") and len(head.all_fingerprints) == 3


def test_dedupe_merges_whole_file_and_line_dockerfile_findings() -> None:
    trivy = f("trivy", "DS-0002", Severity.HIGH, path="Dockerfile", line=0, code="t")
    grep = f("opengrep", "dockerfile.security.missing-user", Severity.MEDIUM, path="Dockerfile", line=6)
    other = f("opengrep", "dockerfile.security.no-sudo", Severity.MEDIUM, path="Dockerfile", line=6, code="s")
    merged = dedupe([trivy, grep, other])
    assert len(merged) == 2
    head = next(m for m in merged if "trivy:DS-0002" in m.rules)
    assert "opengrep:dockerfile.security.missing-user" in head.rules and head.severity == Severity.HIGH
