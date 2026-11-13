"""Runner framework: one subclass per scanner. A runner decides whether it applies, builds its
command (absolute binary path, neutral working dir), and parses the raw output into Findings."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from codesift.detect import Detection, path_excluded
from codesift.finding import Finding
from codesift.gitutil import GitInfo, safe_git_env
from codesift.lockfile import Lock
from codesift.paths import Paths
from codesift.pyreqs import venv_script
from codesift.redact import Redactor
from codesift.tools import resolve_tool, tool_env

MAX_SNIPPET_LINES = 12
MAX_FILE_TARGETS = 300  # beyond this, scan the whole project instead of listing files


class RunnerError(Exception):
    pass


@dataclass
class Context:
    root: Path
    detection: Detection
    git: GitInfo
    paths: Paths
    lock: Lock
    raw_dir: Path
    work_dir: Path  # neutral cwd for tools (never inside the project)
    exclude_globs: list[str]
    offline: bool = False
    since: str | None = None
    changed: list[str] | None = None  # project-relative changed files (with --since)
    jobs: int = 2
    timeout: int = 900
    redactor: Redactor = field(default_factory=Redactor)
    rules_dir: Path | None = None
    extra_rules_dirs: list[Path] = field(default_factory=list)

    @property
    def incremental(self) -> bool:
        return self.changed is not None

    def rel(self, path: str) -> str:
        """Tool path (absolute or relative, any separator) -> project-relative posix path."""
        p = path.replace("\\", "/")
        if p.startswith("file://"):
            p = p[len("file://") :]
        candidate = Path(p)
        if candidate.is_absolute() or (len(p) > 2 and p[1] == ":"):
            abs_p = os.path.abspath(p)
            prefix = os.path.normcase(os.path.abspath(self.root)).rstrip("\\/") + os.sep
            if os.path.normcase(abs_p).startswith(prefix):
                return abs_p[len(prefix) :].replace("\\", "/")  # compare case-insensitively, keep case
            return p
        return PurePosixPath(p).as_posix().removeprefix("./")

    def changed_matching(self, exclude_tests: bool, exts: tuple[str, ...] | None = None) -> list[str]:
        if self.changed is None:
            return []
        out = []
        for rel in self.changed:
            if path_excluded(rel, self.exclude_globs, exclude_tests):
                continue
            if exts and not rel.lower().endswith(exts):
                continue
            if (self.root / rel).is_file():
                out.append(rel)
        return out


@dataclass
class RunResult:
    name: str
    version: str = ""
    status: str = "ok"  # ok | skipped | error
    reason: str = ""
    duration_s: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    raw_files: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status,
            "reason": self.reason,
            "duration_s": round(self.duration_s, 1),
            "findings": len(self.findings),
            "raw_files": self.raw_files,
        }


class Runner:
    name = ""
    binary_tool: str | None = None  # name in tools.lock.json
    venv_tool: str | None = None  # console script in CodeSift's venv
    opt_in = False  # only runs when enabled explicitly
    needs_network = False  # skipped with --offline
    excludes_tests = False  # code-pattern scanners: test dirs/files are dropped

    def applies(self, ctx: Context) -> str | None:
        """None if the runner should run, otherwise the reason it is skipped."""
        return None

    def version(self, ctx: Context) -> str:
        if self.binary_tool and self.binary_tool in ctx.lock.tools:
            return ctx.lock.tools[self.binary_tool].version
        if self.venv_tool:
            return ctx.lock.python.get(self.venv_tool, "")
        return ""

    def executable(self, ctx: Context) -> Path:
        if self.binary_tool:
            return resolve_tool(self.binary_tool, ctx.lock, ctx.paths.tools)
        if self.venv_tool:
            exe = venv_script(ctx.paths.venv, self.venv_tool)
            if not exe.is_file():
                raise RunnerError(f"{self.venv_tool} not installed in {ctx.paths.venv} (run `sift install`)")
            return exe
        raise RunnerError(f"{self.name}: no executable configured")

    def run(self, ctx: Context) -> list[Finding]:
        raise NotImplementedError

    # -- helpers ---------------------------------------------------------------------------------

    def exec(
        self,
        ctx: Context,
        argv: list[str],
        *,
        stdout_file: Path | None = None,
        ok_codes: tuple[int, ...] = (0,),
        env_extra: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = safe_git_env(tool_env())
        if env_extra:
            env.update(env_extra)
        out_handle = stdout_file.open("w", encoding="utf-8", errors="replace") if stdout_file else None
        try:
            proc = subprocess.run(  # noqa: S603
                argv,
                cwd=ctx.work_dir,
                env=env,
                stdout=out_handle if out_handle else subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or ctx.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise RunnerError(f"{self.name} timed out after {timeout or ctx.timeout}s") from None
        except OSError as exc:
            raise RunnerError(f"{self.name} could not start: {exc.strerror}") from None
        finally:
            if out_handle:
                out_handle.close()
        log = ctx.raw_dir / f"{self.name}.log"
        stderr = ctx.redactor.scrub(proc.stderr or "")
        if stderr.strip():
            with log.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(stderr[-20000:])
        if proc.returncode not in ok_codes:
            tail = stderr.strip().splitlines()[-3:] if stderr.strip() else []
            raise RunnerError(f"{self.name} exited {proc.returncode}: {' | '.join(tail)[:400]}")
        return proc

    def snippet(self, ctx: Context, rel: str, start: int, end: int) -> str:
        return read_snippet(ctx, rel, start, end)


def read_snippet(ctx: Context, rel: str, start: int, end: int) -> str:
    """Flagged lines from the working tree (max 12), secrets masked."""
    if start <= 0 or not rel:
        return ""
    path = ctx.root / rel
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ""
    end = max(start, min(end, start + MAX_SNIPPET_LINES - 1))
    chunk = lines[start - 1 : end]
    return ctx.redactor.scrub("\n".join(chunk))[:2000]


def scrub_file(ctx: Context, path: Path) -> None:
    """Rewrite a raw output file with secrets masked (raw/ must never hold secret values)."""
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    scrubbed = ctx.redactor.scrub(text)
    if scrubbed != text:
        path.write_text(scrubbed, encoding="utf-8", newline="\n")


def timed(fn: Any) -> tuple[Any, float]:
    start = time.monotonic()
    result = fn()
    return result, time.monotonic() - start
