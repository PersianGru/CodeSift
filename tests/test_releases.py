from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from codesift import releases, rules, update
from codesift.lockfile import RulesLock
from codesift.pyreqs import PyRelease
from codesift.releases import (
    Advisory,
    Release,
    ReleaseError,
    affecting,
    build_tool_lock,
    in_range,
    pick_release,
    version_key,
)
from codesift.tools import TOOL_SPECS
from helpers import lock_with, make_tgz, sha

NOW = datetime(2026, 11, 12, tzinfo=UTC)


def rel(tag: str, days_old: int, assets: dict[str, dict[str, Any]] | None = None) -> Release:
    return Release("o/r", tag, NOW - timedelta(days=days_old), assets or {}, f"https://github.com/o/r/{tag}")


def test_version_key_orders() -> None:
    assert version_key("v1.10.0") > version_key("v1.9.9")
    assert version_key("0.76.1") > version_key("0.76.0")
    assert version_key("2.0.0") > version_key("2.0.0-alpha.1")
    assert version_key("1.2") == version_key("1.2.0")


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("0.69.4", "= 0.69.4", True),
        ("0.69.3", "=0.69.4", False),
        ("1.29.0", ">= 1.5.0, < 1.30.2", True),
        ("1.33.1", ">= 1.5.0, < 1.30.2", False),
        ("0.76.1", "<0.71.0", False),
        ("0.50.0", "< 0.51.2", True),
        ("1.0.0", "", False),
    ],
)
def test_in_range(version: str, spec: str, expected: bool) -> None:
    assert in_range(version, spec) is expected


def test_pick_release_respects_cooldown() -> None:
    eligible, newest = pick_release([rel("v1.0.0", 30), rel("v1.1.0", 3), rel("v1.0.1", 10)], 7, NOW)
    assert eligible is not None and eligible.tag == "v1.0.1"
    assert newest is not None and newest.tag == "v1.1.0"
    none, _ = pick_release([rel("v2.0.0", 1)], 7, NOW)
    assert none is None


def test_affecting_filters_package_and_range() -> None:
    advisories: list[dict[str, Any]] = [
        {
            "ghsa_id": "GHSA-1",
            "severity": "critical",
            "summary": "bad",
            "vulnerabilities": [
                {
                    "package": {"name": "github.com/aquasecurity/trivy"},
                    "vulnerable_version_range": "= 0.69.4",
                },
                {"package": {"name": "aquasecurity/trivy-action"}, "vulnerable_version_range": "< 0.35.0"},
            ],
        },
        {"ghsa_id": "GHSA-2", "withdrawn_at": "2026-01-01", "vulnerabilities": []},
    ]
    found = affecting(advisories, "0.69.4", package_hint="trivy")
    assert [a.ghsa for a in found] == ["GHSA-1"]
    assert affecting(advisories, "0.76.1", package_hint="trivy") == []


def _release_for(spec_name: str, version: str, checksum_text: str | None, digests: bool) -> Release:
    spec = TOOL_SPECS[spec_name]
    assets: dict[str, dict[str, Any]] = {}
    for template in spec.assets.values():
        name = template.format(version=version)
        data = name.encode()
        assets[name] = {
            "url": f"https://github.com/{spec.repo}/releases/download/v{version}/{name}",
            "size": len(data),
            "digest": f"sha256:{sha(data)}" if digests else "",
        }
    if spec.checksums:
        cname = spec.checksums.format(version=version)
        assets[cname] = {"url": f"https://github.com/{spec.repo}/releases/download/v{version}/{cname}"}
    return Release(spec.repo, f"v{version}", NOW - timedelta(days=30), assets, "")


def _checksums(spec_name: str, version: str) -> str:
    spec = TOOL_SPECS[spec_name]
    return "".join(
        f"{sha(t.format(version=version).encode())}  {t.format(version=version)}\n"
        for t in spec.assets.values()
    )


def test_build_tool_lock_uses_checksum_file(monkeypatch: pytest.MonkeyPatch) -> None:
    text = _checksums("gitleaks", "8.30.1")
    monkeypatch.setattr(releases, "fetch", lambda url, **_: text.encode())
    entry = build_tool_lock(TOOL_SPECS["gitleaks"], _release_for("gitleaks", "8.30.1", text, digests=True))
    asset = entry.platforms["linux-x64"]
    assert asset.sha256 == sha(asset.asset.encode())
    assert entry.checksum_source == "gitleaks_8.30.1_checksums.txt"


def test_build_tool_lock_detects_disagreement(monkeypatch: pytest.MonkeyPatch) -> None:
    text = _checksums("gitleaks", "8.30.1").replace("0", "1", 1)
    monkeypatch.setattr(releases, "fetch", lambda url, **_: text.encode())
    with pytest.raises(ReleaseError, match="disagree"):
        build_tool_lock(TOOL_SPECS["gitleaks"], _release_for("gitleaks", "8.30.1", text, digests=True))


def test_build_tool_lock_digest_only_tool() -> None:
    entry = build_tool_lock(TOOL_SPECS["opengrep"], _release_for("opengrep", "1.33.1", None, digests=True))
    assert entry.checksum_source == "github-asset-digest"
    with pytest.raises(ReleaseError, match="no GitHub digest"):
        build_tool_lock(TOOL_SPECS["opengrep"], _release_for("opengrep", "1.33.1", None, digests=False))


# ---------------------------------------------------------------- update check


def _patch_world(monkeypatch: pytest.MonkeyPatch, advisories: dict[str, list[Advisory]]) -> None:
    monkeypatch.setattr(update, "list_releases", lambda repo: [rel("v9.0.0", 30), rel("v9.1.0", 2)])
    monkeypatch.setattr(
        update, "tool_advisories", lambda name, version: advisories.get(f"{name}@{version}", [])
    )
    monkeypatch.setattr(
        update,
        "pick_pypi",
        lambda pkg, cd, now: (PyRelease(pkg, "1.0.0", NOW - timedelta(days=20)),) * 2,
    )
    monkeypatch.setattr(update, "latest_commit", lambda repo: ("a" * 40, NOW - timedelta(days=400), True))


def test_check_reports_updates_and_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_world(monkeypatch, {})
    lock = lock_with("trivy", "aquasecurity/trivy", "8.0.0", "linux-x64", "t", b"x")
    plan = update.check(lock, NOW)
    row = next(r for r in plan.rows if r.component == "trivy")
    assert (row.current, row.latest, row.status) == ("8.0.0", "9.0.0", "update")
    assert "v9.1.0 is 2d old" in row.note
    assert plan.tool_updates["trivy"] == "v9.0.0"
    assert plan.rules_commit == "a" * 40
    text = update.format_plan(plan)
    assert "sift update --apply" in text


def test_check_skips_release_with_advisory(monkeypatch: pytest.MonkeyPatch) -> None:
    adv = Advisory("GHSA-x", "high", "bad", "= 9.0.0")
    _patch_world(monkeypatch, {"trivy@9.0.0": [adv]})
    lock = lock_with("trivy", "aquasecurity/trivy", "8.0.0", "linux-x64", "t", b"x")
    plan = update.check(lock, NOW)
    row = next(r for r in plan.rows if r.component == "trivy")
    assert row.status == "advisory"
    assert "trivy" not in plan.tool_updates


def test_check_flags_pinned_version_with_advisory(monkeypatch: pytest.MonkeyPatch) -> None:
    adv = Advisory("GHSA-y", "critical", "bad", "= 9.0.0")
    _patch_world(monkeypatch, {"trivy@9.0.0": [adv]})
    lock = lock_with("trivy", "aquasecurity/trivy", "9.0.0", "linux-x64", "t", b"x")
    row = next(r for r in update.check(lock, NOW).rows if r.component == "trivy")
    assert row.status == "advisory" and "GHSA-y" in row.note


# ---------------------------------------------------------------- rules vendoring


def test_vendor_rules_filters_and_hashes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prefix = "opengrep-opengrep-rules-abc/"
    rule = b"rules:\n  - id: x\n"
    tarball = make_tgz(
        {
            prefix + "python/lang/security/a.yaml": rule,
            prefix + "python/lang/security/a.py": b"print('target')",
            prefix + "python/lang/security/a.test.yaml": rule,
            prefix + "generic/secrets/s.yaml": rule,
            prefix + "java/x.yaml": rule,
            prefix + "../escape.yaml": rule,
            prefix + "README.md": b"x",
        }
    )
    monkeypatch.setattr(rules, "fetch", lambda url, **_: tarball)
    count, digest = rules.vendor("b" * 40, tmp_path)
    vendored = tmp_path / rules.VENDOR_DIR
    files = sorted(p.relative_to(vendored).as_posix() for p in vendored.rglob("*") if p.is_file())
    assert files == ["python/lang/security/a.yaml"]
    assert count == 1
    assert digest == rules.tree_sha256(vendored)
    lock = RulesLock("r", "b" * 40, "", "", True, [], digest)
    assert rules.verify_rules(vendored, lock)
    (vendored / "python/lang/security/a.yaml").write_bytes(b"rules: []\n")
    assert not rules.verify_rules(vendored, lock)


def test_vendor_rejects_short_commit(tmp_path: Path) -> None:
    with pytest.raises(rules.RulesError):
        rules.vendor("main", tmp_path)
