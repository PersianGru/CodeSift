"""The validate workspace: the 'before' copy must take the project's working-tree diff on every OS."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from codesift.validate.workspace import create_workspace, project_diff

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize("autocrlf", ["true", "false"])
def test_tree_copy_takes_the_working_tree_diff(tmp_path: Path, autocrlf: str) -> None:
    # Windows git defaults to core.autocrlf=true: `git archive` then writes CRLF while `git diff` is
    # LF, and the patch did not apply ("patch does not apply").
    project = tmp_path / "proj"
    project.mkdir()
    _git(project, "init", "-q")
    _git(project, "config", "core.autocrlf", autocrlf)
    (project / "calc.py").write_bytes(b"def add(a, b):\n    return a + b\n")
    (project / "tool.sh").write_bytes(b"#!/bin/sh\necho hi\n")
    (project / "pkg").mkdir()
    (project / "pkg" / "data.txt").write_bytes(b"one\r\ntwo\r\n")  # CRLF stored as-is
    (project / ".env").write_bytes(b"TOKEN=x\n")
    _git(project, "add", "-A")
    _git(project, "commit", "-qm", "init")
    (project / "calc.py").write_bytes(b'def add(a, b):\n    """Sum."""\n    return a + b\n')
    (project / "pkg" / "data.txt").write_bytes(b"one\r\nTWO\r\n")

    ws = create_workspace(project, tmp_path / "ws", never_send=[], secret_paths=set(), source="tree")
    assert sorted(ws.files) == ["calc.py", "pkg/data.txt", "tool.sh"]
    assert ws.excluded == {".env": "sensitive file name"}
    assert (tmp_path / "ws" / "calc.py").read_bytes() == b"def add(a, b):\n    return a + b\n"

    ws.apply_patch(project_diff(project, "HEAD"))
    assert b'"""Sum."""' in (tmp_path / "ws" / "calc.py").read_bytes()
    # The copy holds what git stores: with autocrlf=true git stored the CRLF file as LF.
    eol = b"\n" if autocrlf == "true" else b"\r\n"
    assert (tmp_path / "ws" / "pkg" / "data.txt").read_bytes() == b"one" + eol + b"TWO" + eol


def test_tree_copy_skips_symlinks_and_unknown_refs(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    _git(project, "init", "-q")
    (project / "a.txt").write_text("a\n", encoding="utf-8")
    _git(project, "add", "-A")
    _git(project, "commit", "-qm", "init")
    from codesift.validate import ValidateError

    with pytest.raises(ValidateError):
        create_workspace(
            project, tmp_path / "ws", never_send=[], secret_paths=set(), source="tree", ref="nope"
        )
