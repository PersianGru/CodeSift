"""A simulated sandbox VM behind FakeTransport. It understands exactly the commands CodeSift sends,
checks that every one of them passes the forced-command gate's allow-list, and runs nothing: job
commands are answered by a Python handler that sees the unpacked files."""

from __future__ import annotations

import io
import shlex
import tarfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from codesift.vm.admin import gate_allows
from codesift.vm.config import VMConfig
from codesift.vm.transport import ExecResult, FakeTransport

IMAGE_ID = "sha256:" + "ab" * 32
Handler = Callable[[str, dict[str, bytes]], tuple[int, str] | None]


def inner_command(wrapper: str) -> tuple[int, str]:
    """(timeout, command) from the wrapper script CodeSift generates."""
    marker = "( timeout -s KILL "
    start = wrapper.index(marker) + len(marker)
    rest = wrapper[start:]
    timeout_text, rest = rest.split(" ", 1)
    assert rest.startswith("sh -c ")
    words = shlex.split(rest[len("sh -c ") :].split("; echo $? > /tmp/.rc", 1)[0])
    return int(timeout_text), words[0]


def cap_of(wrapper: str) -> int:
    return int(wrapper.rsplit("| head -c ", 1)[1].split(";", 1)[0])


def untar(data: bytes) -> tuple[dict[str, bytes], str]:
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
        for m in tf.getmembers():
            p = PurePosixPath(m.name)
            if m.name.startswith("/") or ".." in p.parts:
                return {}, "unsafe path in input"
            if m.isfile():
                f = tf.extractfile(m)
                files[m.name] = f.read() if f else b""
    return files, ""


@dataclass
class FakeVM:
    cfg: VMConfig
    image_id: str = IMAGE_ID
    free_mb: int = 4096
    running: list[str] = field(default_factory=list)
    leftovers: list[str] = field(default_factory=list)
    broken: set[str] = field(default_factory=set)  # names of self-test properties to break
    handlers: list[Handler] = field(default_factory=list)
    ssh_down: bool = False
    jobs: list[tuple[str, dict[str, bytes]]] = field(default_factory=list)
    gate_violations: list[str] = field(default_factory=list)
    other_containers: tuple[str, ...] = ("0123456789ab0123456789ab", "deadbeefdeadbeefdeadbeef")

    def transport(self) -> FakeTransport:
        t = FakeTransport()
        t.on(lambda a: True, self.respond)
        return t

    def respond(self, argv: list[str], stdin: bytes | None) -> ExecResult:
        line = shlex.join(argv)
        if not gate_allows(line):
            self.gate_violations.append(line)
        if self.ssh_down:
            return ExecResult(255, b"", "ssh: connect to host vm port 22: Connection refused")
        rt = self.cfg.runtime
        if argv == ["cat", "/proc/meminfo"]:
            return ExecResult(0, f"MemTotal: 8000000 kB\nMemAvailable: {self.free_mb * 1024} kB\n".encode())
        if argv[:2] == [rt, "version"]:
            return ExecResult(0, b"29.5.3\n")
        if argv[:3] == [rt, "image", "inspect"]:
            return ExecResult(0, (self.image_id + "\n").encode())
        if argv[:3] == [rt, "image", "pull"]:
            return ExecResult(0, b"pulled\n")
        if argv[:2] == [rt, "build"]:
            return ExecResult(0, b"built\n")
        if argv[:3] == [rt, "ps", "-q"]:
            return ExecResult(0, "\n".join(self.running).encode())
        if argv[:3] == [rt, "ps", "-aq"]:
            ids = list(self.leftovers)
            return ExecResult(0, "\n".join(ids).encode())
        if argv[:3] == [rt, "rm", "-f"]:
            for i in argv[3:]:
                if i in self.leftovers:
                    self.leftovers.remove(i)
            return ExecResult(0, b"")
        if argv[:2] == [rt, "run"]:
            return self.run_job(argv, stdin or b"")
        return ExecResult(127, b"", "unknown command")

    def run_job(self, argv: list[str], stdin: bytes) -> ExecResult:
        wrapper = argv[-1]
        timeout, command = inner_command(wrapper)
        cap = cap_of(wrapper)
        files, rejected = untar(stdin)
        if rejected:
            return ExecResult(0, f"__CODESIFT_REJECT__ {rejected}\n\n__CODESIFT_RC__=125\n".encode())
        self.jobs.append((command, files))
        duration = 0.2
        result: tuple[int, str] | None = None
        for handler in self.handlers:
            result = handler(command, files)
            if result is not None:
                break
        if result is None:
            result = self.builtin(command, cap)
        rc, out = result
        if rc == 137 and command.startswith("sleep"):
            duration = float(timeout)
        body = out.encode()[:cap]
        return ExecResult(0, body + f"\n__CODESIFT_RC__={rc}\n".encode(), duration_s=duration)

    def builtin(self, command: str, cap: int) -> tuple[int, str]:
        b = self.broken
        if command == "echo codesift-ok":
            return (1, "") if "start" in b else (0, "codesift-ok\n")
        if command == "id -u":
            return 0, ("0\n" if "root" in b else "65534\n")
        if command.startswith("grep CapEff"):
            return 0, ("CapEff:\t00000000a80425fb\n" if "caps" in b else "CapEff:\t0000000000000000\n")
        if command.startswith("if touch /codesift-x"):
            return 0, ("WRITABLE\n" if "rofs" in b else "READONLY\n")
        if command.startswith("cat /proc/net/dev"):
            ifaces = "  lo: 0 0\n" + ("  eth0: 1 2\n" if "net" in b else "")
            return 0, "Inter-|   Receive\n face |bytes\n" + ifaces + (
                "NET_OPEN\n" if "net" in b else "NET_BLOCKED\n"
            )
        if command.startswith("cat /sys/fs/cgroup/memory.max"):
            return 0, ("max\n" if "memory" in b else f"{self.cfg.memory_mb * 1024 * 1024}\n")
        if command.startswith("cat /sys/fs/cgroup/pids.max"):
            return 0, ("max\n" if "pids" in b else f"{self.cfg.pids}\n")
        if command == "sleep 30":
            return (0, "") if "timeout" in b else (137, "")
        if command.startswith("yes x | head -c"):
            n = int(command.rsplit(" ", 1)[1])
            return 0, ("x" * 10 if "cap" in b else "x\n" * (n // 2))
        return 0, f"ran: {command}\n"


def vm_config(**overrides: object) -> VMConfig:
    cfg = VMConfig(
        host="vm.example.test",
        user="codesift",
        key_path="/nonexistent/key",
        known_hosts_path="/nonexistent/known_hosts",
        image="python:3.12-alpine",
        image_id=IMAGE_ID,
        host_key_fingerprint="",
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg
