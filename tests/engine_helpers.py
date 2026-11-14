"""A tiny synthetic project and fakes for engine tests. The "vulnerability" is a marker call
(`UNSAFE_CALL(`) found by a fake scanner; nothing here is real vulnerable code and nothing runs."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from codesift.finding import Finding, fingerprint
from codesift.models import Severity
from codesift.validate.engine import EngineDeps
from codesift.vm.sandbox import Sandbox
from fake_vm import FakeVM, vm_config

TOOLS_PY = """def ping(host):
    return UNSAFE_CALL("ping " + host)


def health():
    return True
"""
TEST_PY = """from app.tools import health


def test_health():
    assert health()
"""
FIXED = ('    return UNSAFE_CALL("ping " + host)', '    return SAFE_CALL(["ping", host])')


def git(root: Path, *args: str) -> str:
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    out = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return out.stdout


def make_project(root: Path, config: str = "") -> Path:
    (root / "app").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "tools.py").write_text(TOOLS_PY, encoding="utf-8", newline="\n")
    (root / "tests" / "test_tools.py").write_text(TEST_PY, encoding="utf-8", newline="\n")
    (root / ".env").write_text("TOKEN=never-copy-this-0123456789\n", encoding="utf-8")
    (root / ".gitattributes").write_text("* -text\n", encoding="utf-8")
    if config:
        (root / ".codesift.toml").write_text(config, encoding="utf-8", newline="\n")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    return root


def tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if ".git" in p.parts or not p.is_file():
            continue
        h.update(p.relative_to(root).as_posix().encode())
        h.update(p.read_bytes())
    return h.hexdigest()


@dataclass
class FakeRescanner:
    calls: list[tuple[str, str | None]] = field(default_factory=list)
    unavailable: bool = False
    extra_rule: str = ""  # a marker that produces a NEW medium finding

    def scan(self, root: Path, since: str | None) -> list[Finding] | None:
        self.calls.append((root.name, since))
        if self.unavailable:
            return None
        out: list[Finding] = []
        for p in sorted(root.rglob("*.py")):
            if ".git" in p.parts:
                continue
            rel = p.relative_to(root).as_posix()
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
                for marker, rule, sev in (
                    ("UNSAFE_CALL(", "unsafe", Severity.HIGH),
                    (self.extra_rule, "new", Severity.MEDIUM),
                ):
                    if marker and marker in line:
                        f = Finding(
                            tool="fake",
                            rule=rule,
                            severity=sev,
                            path=rel,
                            line=n,
                            message="marker",
                            fingerprint=fingerprint("fake", rule, rel, line),
                            cwe=["CWE-78"],
                        )
                        f.id = f"F{len(out) + 1:03d}"
                        out.append(f)
        return out


def project_tests(cmd: str, files: dict[str, bytes]) -> tuple[int, str] | None:
    if cmd != "python -m pytest -q":
        return None
    tools = files.get("app/tools.py", b"").decode()
    if "def health" in tools and "BROKEN" not in tools:
        return 0, "1 passed\n"
    return 1, "FAILED tests/test_tools.py::test_health - AssertionError\n"


def project_poc(cmd: str, files: dict[str, bytes]) -> tuple[int, str] | None:
    if cmd != "python poc/check.py":
        return None
    return (0, "reproduced\n") if b"UNSAFE_CALL(" in files.get("app/tools.py", b"") else (1, "blocked\n")


def deps(rescanner: FakeRescanner, vm: FakeVM | None, **kw: object) -> EngineDeps:
    def load(root: Path) -> list[Finding]:
        """Like the latest scan report: findings of the committed (HEAD) state."""
        import io
        import tarfile
        import tempfile

        data = subprocess.run(
            ["git", "-C", str(root), "archive", "--format=tar", "HEAD"], capture_output=True, check=True
        )
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(fileobj=io.BytesIO(data.stdout)) as tf:
                tf.extractall(tmp, filter="data")
            found = rescanner.scan(Path(tmp), None) or []
        rescanner.calls.pop()
        return found

    d = EngineDeps(
        rescanner=rescanner,
        sandbox_factory=(lambda: Sandbox(vm.cfg, vm.transport())) if vm is not None else None,
        load_findings=load,
    )
    for k, v in kw.items():
        setattr(d, k, v)
    return d


def healthy_vm() -> FakeVM:
    vm = FakeVM(vm_config())
    vm.handlers += [project_tests, project_poc]
    return vm


CONFIG_TESTS = '[validate]\ntest = "python -m pytest -q"\n'
CONFIG_ALL = CONFIG_TESTS + '[validate.poc]\n"CWE-78" = "python poc/check.py"\n'
