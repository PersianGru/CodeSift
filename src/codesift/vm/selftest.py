"""Isolation self-test (`sift vm doctor`, and automatically before the first job of every run).

Each item is a tiny job; every item must pass or CodeSift refuses to run anything (fail closed).
A pass is cached for 10 minutes per VM configuration."""

from __future__ import annotations

import io
import json
import re
import tarfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from codesift.vm import SandboxError
from codesift.vm.sandbox import JobResult, Sandbox

CACHE_TTL_S = 600
CACHE_NAME = "vm-selftest.json"


@dataclass
class Item:
    name: str
    status: str  # pass | fail
    detail: str = ""
    fix: str = ""


@dataclass
class SelfTestReport:
    items: list[Item] = field(default_factory=list)
    cached: bool = False

    @property
    def passed(self) -> bool:
        return bool(self.items) and all(i.status == "pass" for i in self.items)

    def lines(self) -> list[str]:
        out = []
        for i in self.items:
            mark = "ok  " if i.status == "pass" else "FAIL"
            out.append(f"[{mark}] {i.name}: {i.detail}")
            if i.status != "pass" and i.fix:
                out.append(f"       fix: {i.fix}")
        return out


def empty_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT):
        pass
    return buf.getvalue()


def evil_tar() -> bytes:
    """A tar whose member escapes the root: the in-container check must refuse it."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo("../codesift-escape")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    return buf.getvalue()


Check = Callable[[JobResult], tuple[bool, str]]


@dataclass
class Probe:
    name: str
    command: str
    check: Check
    fix: str
    timeout_s: int = 20
    tar: bytes | None = None


def _first_line(text: str) -> str:
    return (text.strip().splitlines() or [""])[0].strip()[:120]


def probes(sandbox: Sandbox) -> list[Probe]:
    cfg = sandbox.cfg
    mem_bytes = cfg.memory_mb * 1024 * 1024
    cap = cfg.max_output_kb * 1024

    def starts(r: JobResult) -> tuple[bool, str]:
        ok = r.rc == 0 and "codesift-ok" in r.output
        said = _first_line(r.output)
        return ok, f"rc {r.rc}" + ("" if ok or not said else f" ({said})")

    def non_root(r: JobResult) -> tuple[bool, str]:
        uid = _first_line(r.output)
        return uid.isdigit() and uid != "0", f"uid {uid or '?'}"

    def no_caps(r: JobResult) -> tuple[bool, str]:
        m = re.search(r"CapEff:\s*([0-9a-fA-F]+)", r.output)
        return bool(m) and set(m.group(1) if m else "x") == {"0"}, (m.group(0) if m else "CapEff not found")

    def read_only(r: JobResult) -> tuple[bool, str]:
        line = _first_line(r.output)
        return line == "READONLY", line or "no answer"

    def network(r: JobResult) -> tuple[bool, str]:
        ifaces = sorted(
            {m.group(1) for m in re.finditer(r"^\s*([A-Za-z0-9_.@-]+):", r.output, re.MULTILINE)}
            - {"Inter-|", "face"}
        )
        blocked = "NET_BLOCKED" in r.output and "NET_OPEN" not in r.output
        return ifaces == ["lo"] and blocked, f"interfaces {', '.join(ifaces) or 'none'}; " + (
            "outbound blocked" if blocked else "outbound NOT blocked"
        )

    def memory(r: JobResult) -> tuple[bool, str]:
        value = _first_line(r.output)
        return value == str(mem_bytes), f"limit {value or '?'} (want {mem_bytes})"

    def pids(r: JobResult) -> tuple[bool, str]:
        value = _first_line(r.output)
        return value == str(cfg.pids), f"pids.max {value or '?'} (want {cfg.pids})"

    def timeout(r: JobResult) -> tuple[bool, str]:
        killed = r.timed_out or r.rc in (124, 137, 143)
        return killed and r.duration_s < 25, f"rc {r.rc} after {r.duration_s:.1f}s"

    def output_cap(r: JobResult) -> tuple[bool, str]:
        size = len(r.output.encode())
        return r.truncated and size <= cap + 64, f"{size} bytes returned (cap {cap})"

    def tar_reject(r: JobResult) -> tuple[bool, str]:
        return bool(r.rejected), r.rejected or "an escaping tar member was NOT refused"

    return [
        Probe("container starts", "echo codesift-ok", starts, "check the runtime and the image on the VM"),
        Probe("not root", "id -u", non_root, "the image or runtime overrides --user; use a different image"),
        Probe(
            "no capabilities", "grep CapEff /proc/self/status", no_caps, "the runtime ignores --cap-drop ALL"
        ),
        Probe(
            "read-only root",
            "if touch /codesift-x 2>/dev/null; then echo WRITABLE; else echo READONLY; fi",
            read_only,
            "the runtime ignores --read-only",
        ),
        Probe(
            "no network",
            "cat /proc/net/dev; ( wget -q -T 3 -O /dev/null http://1.1.1.1/"
            " || nc -w 3 1.1.1.1 80 </dev/null ) >/dev/null 2>&1 && echo NET_OPEN || echo NET_BLOCKED",
            network,
            "the runtime ignores --network none",
        ),
        Probe(
            "memory limit",
            "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes",
            memory,
            "enable the memory cgroup controller on the VM",
        ),
        Probe(
            "pids limit",
            "cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max",
            pids,
            "enable the pids cgroup controller on the VM",
        ),
        Probe("timeout kills", "sleep 30", timeout, "the image needs `timeout` (busybox or coreutils)", 2),
        Probe("output cap", f"yes x | head -c {cap * 2}", output_cap, "the image needs `head -c`"),
        Probe(
            "input path check",
            "echo should-not-run",
            tar_reject,
            "the image needs tar and grep -E",
            tar=evil_tar(),
        ),
    ]


def run_selftest(sandbox: Sandbox) -> SelfTestReport:
    report = SelfTestReport()
    try:
        sandbox.verify_image()
        sandbox.guard()
    except SandboxError as exc:
        report.items.append(Item("preflight", "fail", str(exc), exc.fix))
        return report
    report.items.append(Item("preflight", "pass", f"image pinned, {sandbox.free_memory_mb()} MB free"))
    tar = empty_tar()
    for probe in probes(sandbox):
        try:
            result = sandbox.run_job(probe.command, probe.tar or tar, probe.timeout_s, guard=False)
            ok, detail = probe.check(result)
        except SandboxError as exc:
            ok, detail = False, str(exc)
        report.items.append(Item(probe.name, "pass" if ok else "fail", detail, "" if ok else probe.fix))
    try:
        left = sandbox.running_jobs()
        report.items.append(
            Item(
                "cleanup",
                "pass" if not left else "fail",
                f"{len(left)} labelled container(s) left",
                "run `sift vm reset`",
            )
        )
    except SandboxError as exc:
        report.items.append(Item("cleanup", "fail", str(exc)))
    return report


def _cache_path(state_dir: Path) -> Path:
    return state_dir / CACHE_NAME


def cached_pass(state_dir: Path, digest: str, now: float | None = None) -> bool:
    try:
        data = json.loads(_cache_path(state_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    now = time.time() if now is None else now
    return (
        isinstance(data, dict)
        and data.get("digest") == digest
        and data.get("passed") is True
        and 0 <= now - float(data.get("at", 0)) < CACHE_TTL_S
    )


def record(state_dir: Path, digest: str, report: SelfTestReport, now: float | None = None) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "digest": digest,
        "passed": report.passed,
        "at": time.time() if now is None else now,
        "items": [{"name": i.name, "status": i.status} for i in report.items],
    }
    _cache_path(state_dir).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


def last_result(state_dir: Path) -> dict[str, object] | None:
    try:
        data = json.loads(_cache_path(state_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def ensure_selftest(sandbox: Sandbox, state_dir: Path, now: float | None = None) -> SelfTestReport:
    """Run the self-test unless a pass for this configuration is cached; raise if it fails."""
    digest = sandbox.cfg.digest()
    if cached_pass(state_dir, digest, now):
        return SelfTestReport(
            cached=True, items=[Item("self-test", "pass", "cached (less than 10 minutes old)")]
        )
    report = run_selftest(sandbox)
    record(state_dir, digest, report, now)
    if not report.passed:
        failed = [i.name for i in report.items if i.status != "pass"]
        raise SandboxError(
            f"sandbox self-test failed ({', '.join(failed)}) - refusing to run anything",
            fix="run `sift vm doctor` for details",
        )
    return report
