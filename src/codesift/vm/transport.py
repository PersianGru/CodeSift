"""How CodeSift reaches the sandbox VM.

`SshTransport` runs the system `ssh` with an argument list (never a shell), streams stdout/stderr
with hard caps while reading (never buffers unbounded) and kills the process on timeout.
`FakeTransport` is scriptable and records every command; every test uses it.

Everything that comes back is untrusted data (RULES.md rule 17): callers only ever look at capped,
control-character-free text, and nothing returned is executed."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Protocol

from codesift.vm import SandboxError
from codesift.vm.config import VMConfig
from codesift.vm.sshargs import ArgError, build_ssh_argv, validate_key_path

MAX_STDERR = 64 * 1024
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x80-\x9f]")


def clean_text(data: bytes | str, limit: int | None = None) -> str:
    """Untrusted bytes -> displayable text: UTF-8 (replacing errors), ANSI/OSC escapes and control
    characters removed (newline and tab kept), optionally capped."""
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    text = _CONTROL.sub("", _ANSI.sub("", text.replace("\r\n", "\n").replace("\r", "\n")))
    if limit is not None and len(text) > limit:
        text = text[:limit] + "\n…(truncated)"
    return text


@dataclass
class ExecResult:
    returncode: int
    stdout: bytes = b""
    stderr: str = ""
    truncated: bool = False
    timed_out: bool = False
    duration_s: float = 0.0

    @property
    def text(self) -> str:
        return clean_text(self.stdout)


class Transport(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes | None = None,
        timeout: float = 60,
        max_output: int = 262144,
    ) -> ExecResult: ...


def _drain(stream: IO[bytes], limit: int, out: list[bytes], flags: dict[str, bool], key: str) -> None:
    size = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        if size < limit:
            keep = chunk[: limit - size]
            out.append(keep)
            size += len(keep)
            if len(keep) < len(chunk):
                flags[key] = True
        else:
            flags[key] = True  # keep reading (so the remote side never blocks) but discard


class SshTransport:
    """Runs one remote command per call over SSH with CodeSift's fixed, strict option set."""

    def __init__(self, cfg: VMConfig, keys_dir: Path, ssh: str | None = None) -> None:
        exe = ssh or shutil.which("ssh")
        if exe is None:
            raise SandboxError("the `ssh` client is not installed or not on PATH", fix="install OpenSSH")
        self.ssh = exe
        self.cfg = cfg
        try:
            self.key = validate_key_path(cfg.key_path, [keys_dir], user_supplied=cfg.key_user_supplied)
        except ArgError as exc:
            raise SandboxError(f"SSH key: {exc}", fix="run `sift setup --vm`") from None
        self.known_hosts = Path(cfg.known_hosts_path)
        if not self.known_hosts.is_file():
            raise SandboxError("the VM host key is not pinned", fix="run `sift setup --vm` to pin it")

    def argv(self, remote: Sequence[str]) -> list[str]:
        try:
            return build_ssh_argv(
                self.ssh,
                host=self.cfg.host,
                port=self.cfg.port,
                user=self.cfg.user,
                key_path=self.key,
                known_hosts=self.known_hosts,
                remote=remote,
            )
        except ArgError as exc:
            raise SandboxError(f"unsafe SSH argument: {exc}") from None

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes | None = None,
        timeout: float = 60,
        max_output: int = 262144,
    ) -> ExecResult:
        cmd = self.argv(argv)
        env = {k: v for k, v in os.environ.items() if k not in ("SSH_ASKPASS", "DISPLAY")}
        start = time.monotonic()
        try:
            proc = subprocess.Popen(  # noqa: S603 - argument list, no shell, validated values
                cmd,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                shell=False,
            )
        except OSError as exc:
            raise SandboxError(f"cannot start ssh: {exc.strerror}") from None
        out: list[bytes] = []
        err: list[bytes] = []
        flags: dict[str, bool] = {}
        if proc.stdout is None or proc.stderr is None:  # pragma: no cover - PIPE always set
            raise SandboxError("ssh started without pipes")
        readers = [
            threading.Thread(target=_drain, args=(proc.stdout, max_output, out, flags, "out"), daemon=True),
            threading.Thread(target=_drain, args=(proc.stderr, MAX_STDERR, err, flags, "err"), daemon=True),
        ]
        for t in readers:
            t.start()
        if stdin is not None and proc.stdin is not None:

            pipe = proc.stdin

            def feed() -> None:
                try:
                    pipe.write(stdin)
                    pipe.close()
                except (BrokenPipeError, OSError):
                    pass

            threading.Thread(target=feed, daemon=True).start()
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            proc.wait(timeout=10)
        for t in readers:
            t.join(timeout=5)
        return ExecResult(
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=b"".join(out),
            stderr=clean_text(b"".join(err), MAX_STDERR),
            truncated=flags.get("out", False),
            timed_out=timed_out,
            duration_s=time.monotonic() - start,
        )


# ---------------------------------------------------------------- fake


@dataclass
class Call:
    argv: list[str]
    stdin: bytes | None
    timeout: float
    max_output: int


Responder = Callable[[list[str], bytes | None], ExecResult | None]


@dataclass
class FakeTransport:
    """Scriptable transport: responders are tried in order; the first non-None result wins. Every
    call is recorded. Output caps are applied like the real transport."""

    responders: list[Responder] = field(default_factory=list)
    default: ExecResult = field(default_factory=lambda: ExecResult(127, b"", "fake: no responder"))
    calls: list[Call] = field(default_factory=list)

    def on(self, match: Callable[[list[str]], bool], result: ExecResult | Responder) -> FakeTransport:
        def responder(argv: list[str], stdin: bytes | None) -> ExecResult | None:
            if not match(argv):
                return None
            return result(argv, stdin) if callable(result) else result

        self.responders.append(responder)
        return self

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes | None = None,
        timeout: float = 60,
        max_output: int = 262144,
    ) -> ExecResult:
        args = list(argv)
        self.calls.append(Call(args, stdin, timeout, max_output))
        for responder in self.responders:
            result = responder(args, stdin)
            if result is not None:
                break
        else:
            result = self.default
        if len(result.stdout) > max_output:
            result = ExecResult(
                result.returncode,
                result.stdout[:max_output],
                result.stderr,
                True,
                result.timed_out,
                result.duration_s,
            )
        result.stderr = clean_text(result.stderr, MAX_STDERR)
        return result

    @property
    def commands(self) -> list[list[str]]:
        return [c.argv for c in self.calls]
