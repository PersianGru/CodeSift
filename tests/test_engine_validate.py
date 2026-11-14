from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codesift.paths import Paths
from codesift.validate.commands import cmd_validate
from codesift.validate.engine import EngineOptions, run_engine
from codesift.validate.events import read_events
from engine_helpers import (
    CONFIG_ALL,
    CONFIG_TESTS,
    FIXED,
    FakeRescanner,
    deps,
    healthy_vm,
    make_project,
    tree_digest,
)
from fake_vm import FakeVM, vm_config


def _change(root: Path, old: str = FIXED[0], new: str = FIXED[1]) -> None:
    p = root / "app" / "tools.py"
    p.write_text(p.read_text(encoding="utf-8").replace(old, new), encoding="utf-8", newline="\n")


def _run(paths: Paths, root: Path, d: object, **opts: object) -> tuple[int, Path, dict[str, Any]]:
    o = EngineOptions(mode="validate", max_findings=10)
    for k, v in opts.items():
        setattr(o, k, v)
    code, run_dir, _ = run_engine(paths, root, o, d)  # type: ignore[arg-type]  # helper passes EngineDeps
    data = json.loads((run_dir / "fix-report.json").read_text(encoding="utf-8"))
    return code, run_dir, data


def _outcome(data: dict[str, Any]) -> str:
    findings = data["findings"]
    assert isinstance(findings, list)
    return str(findings[0]["outcome"])


def test_fixed_verified_with_poc_and_tests(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj", CONFIG_ALL)
    _change(root)
    before = tree_digest(root)
    vm = healthy_vm()
    code, run_dir, data = _run(paths, root, deps(FakeRescanner(), vm))
    assert code == 0, data["notes"]
    assert _outcome(data) == "fixed_verified"
    gates = data["findings"][0]["gates"]
    assert {k: v["status"] for k, v in gates.items()} == {
        "policy": "pass",
        "poc": "pass",
        "tests": "pass",
        "rescan": "pass",
    }
    assert tree_digest(root) == before  # the project is never written
    assert "+    return SAFE_CALL" in (run_dir / "combined.patch").read_text(encoding="utf-8")
    assert not (run_dir / "work").exists()
    assert (run_dir / "fix-report.md").read_text(encoding="utf-8").count("\n") <= 150
    events, _ = read_events(run_dir / "events.jsonl")
    types = [e["type"] for e in events]
    assert types[0] == "run.start" and types[-1] == "run.end" and "selftest.result" in types
    assert vm.gate_violations == []
    # .env never reaches the sandbox
    assert all(".env" not in files for _, files in vm.jobs)


def test_unproven_without_tests_or_poc_never_contacts_vm(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj")
    _change(root)
    vm = healthy_vm()
    code, _, data = _run(paths, root, deps(FakeRescanner(), vm))
    assert code == 1 and _outcome(data) == "fixed_unproven"
    assert vm.jobs == [] and data["sandbox"]["state"] == "not used"
    assert any("suggestion (not run)" in n for n in data["notes"])


def test_fail_closed_without_vm(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj", CONFIG_TESTS)
    _change(root)
    code, _, data = _run(paths, root, deps(FakeRescanner(), None))
    assert code == 2 and "no sandbox VM configured" in json.dumps(data["notes"])


def test_fail_closed_on_selftest_failure(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj", CONFIG_TESTS)
    _change(root)
    vm = FakeVM(vm_config(), broken={"net"})
    code, _, data = _run(paths, root, deps(FakeRescanner(), vm))
    assert code == 2 and "self-test failed" in json.dumps(data["notes"])
    assert not any(cmd == "python -m pytest -q" for cmd, _ in vm.jobs)  # no project code ran


def test_rejected_policy_when_tests_edited(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj")
    _change(root)
    t = root / "tests" / "test_tools.py"
    t.write_text(t.read_text(encoding="utf-8").replace("assert health()", "assert True"), encoding="utf-8")
    code, _, data = _run(paths, root, deps(FakeRescanner(), None))
    assert code == 1 and _outcome(data) == "rejected_policy"
    assert "touches_tests" in json.dumps(data["findings"])


def test_rejected_tests(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj", CONFIG_TESTS)
    _change(root, FIXED[0], FIXED[1] + "  # BROKEN")
    code, _, data = _run(paths, root, deps(FakeRescanner(), healthy_vm()))
    assert code == 1 and _outcome(data) == "rejected_tests"


def test_rejected_rescan_when_finding_remains_or_new_appears(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj")
    _change(root, "def health():", "def health():\n    UNSAFE_CALL('x')")
    code, _, data = _run(paths, root, deps(FakeRescanner(), None))
    assert code == 1 and _outcome(data) == "rejected_rescan"
    root2 = make_project(tmp_path / "proj2")
    _change(root2, FIXED[0], "    return NEW_RISK(host)")
    code, _, data = _run(paths, root2, deps(FakeRescanner(extra_rule="NEW_RISK("), None))
    assert _outcome(data) == "rejected_rescan" and "new finding" in json.dumps(data["findings"])


def test_rescan_unavailable_is_never_a_pass(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj")
    _change(root)
    d = deps(FakeRescanner(), None)
    d.rescanner = FakeRescanner(unavailable=True)
    code, _, data = _run(paths, root, d)
    assert code == 1 and _outcome(data) == "rejected_rescan"
    assert data["findings"][0]["gates"]["rescan"]["status"] == "unavailable"


def test_poc_inconclusive_and_rejected(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj", CONFIG_ALL)
    _change(root)
    vm = healthy_vm()
    vm.handlers.insert(0, lambda cmd, files: (1, "no") if cmd == "python poc/check.py" else None)
    code, _, data = _run(paths, root, deps(FakeRescanner(), vm))
    assert code == 1 and _outcome(data) == "inconclusive"
    root2 = make_project(tmp_path / "proj2", CONFIG_ALL)
    _change(root2, "def health():", "def health():  # touched")  # leaves the vulnerable call in place
    vm2 = healthy_vm()
    vm2.handlers.insert(0, lambda cmd, files: (0, "still") if cmd == "python poc/check.py" else None)
    _, _, data = _run(paths, root2, deps(FakeRescanner(), vm2))
    assert _outcome(data) in ("rejected_rescan", "rejected_poc")


def test_regression_only_when_change_misses_findings(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj")
    (root / "app" / "extra.py").write_text("X = 1\n", encoding="utf-8")
    from engine_helpers import git

    git(root, "add", "app/extra.py")
    git(root, "commit", "-q", "-m", "extra")
    p = root / "app" / "extra.py"
    p.write_text("X = 2\n", encoding="utf-8")
    code, _, data = _run(paths, root, deps(FakeRescanner(), None))
    assert data["regression"]["result"]["status"] == "pass"
    assert _outcome(data) == "inconclusive" and code == 1


def test_dry_run_contacts_nothing(paths: Paths, tmp_path: Path) -> None:
    root = make_project(tmp_path / "proj", CONFIG_ALL)
    _change(root)
    vm = healthy_vm()
    rescanner = FakeRescanner()
    code, _, data = _run(paths, root, deps(rescanner, vm), dry_run=True)
    assert code == 0 and vm.jobs == [] and not vm.transport().calls and rescanner.calls == []
    assert any("no backend and no VM" in p for p in data["plan"])


def test_secrets_never_in_artifacts(paths: Paths, tmp_path: Path) -> None:
    secret = "gw-key-" + "Q" * 30
    root = make_project(tmp_path / "proj", CONFIG_TESTS)
    _change(root)
    vm = healthy_vm()
    vm.handlers.insert(0, lambda cmd, files: (0, f"1 passed, token {secret}\n") if "pytest" in cmd else None)
    d = deps(FakeRescanner(), vm)
    d.secrets = [secret]
    _, run_dir, _ = _run(paths, root, d)
    for p in run_dir.rglob("*"):
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            assert secret not in text, p
            assert "never-copy-this" not in text, p


def test_cli_validate_patch_file_and_json(
    paths: Paths, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_project(tmp_path / "proj")
    patch = tmp_path / "fix.patch"
    _change(root)
    from codesift.validate.workspace import project_diff

    patch.write_text(project_diff(root), encoding="utf-8")
    from engine_helpers import git

    git(root, "checkout", "--", ".")
    out: list[str] = []
    code = cmd_validate(
        paths,
        {},
        str(root),
        patch_file=str(patch),
        branch=None,
        finding_ids=[],
        as_json=True,
        out=out.append,
        deps=deps(FakeRescanner(), None),
    )
    data = json.loads(out[0])
    assert code == 1 and data["schema"] == 1 and data["findings"][0]["outcome"] == "fixed_unproven"
    bad: list[str] = []
    assert (
        cmd_validate(
            paths, {}, str(root), patch_file=None, branch="-x", finding_ids=[], as_json=False, out=bad.append
        )
        == 2
    )
    nothing: list[str] = []
    assert (
        cmd_validate(
            paths,
            {},
            str(root),
            patch_file=None,
            branch=None,
            finding_ids=[],
            as_json=False,
            out=nothing.append,
            deps=deps(FakeRescanner(), None),
        )
        == 2
    )
    assert any("no change to validate" in line for line in nothing)
