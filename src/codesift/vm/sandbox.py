"""One job = one `docker run` / `podman run` with a fixed, hardened flag set (ADR-0012).

The container argv is produced by exactly one function, `container_argv`, which has no parameter
through which a mount, a capability, host networking or privileged mode could enter; `assert_safe`
double-checks every argv before it is sent. Code goes in as a tar on stdin; the wrapper refuses
absolute and `..` paths, extracts, runs the command under `timeout`, caps the output, and prints a
final `__CODESIFT_RC__=<n>` line, the only line that is parsed.

Before every job: image id verified, resource guard (free memory, no other CodeSift job running).
After every job, whatever happens: containers carrying *this job's* label are removed."""

from __future__ import annotations

import re
import shlex
import uuid
from dataclasses import dataclass

from codesift.vm import SandboxError
from codesift.vm.config import IMAGE_ID_RE, IMAGE_RE, VMConfig
from codesift.vm.transport import ExecResult, Transport, clean_text

LABEL = "codesift.job"
NAME_PREFIX = "sift-"
RC_MARKER = "__CODESIFT_RC__="
REJECT_MARKER = "__CODESIFT_REJECT__"
NOWRITE = "codesift: the job user cannot write /work in the container"
MAX_COMMAND = 4096
TRANSPORT_SLACK_S = 60
PROBE_TIMEOUT_S = 30
_JOB_ID = re.compile(r"^[0-9a-f]{32}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_RC_LINE = re.compile(r"^__CODESIFT_RC__=(\d{1,3})$")

# Flags that must never appear in a container argv (tested). `container_argv` cannot produce them.
FORBIDDEN = (
    "--privileged",
    "--cap-add",
    "--device",
    "--volume",
    "-v",
    "--mount",
    "--volumes-from",
    "--pid",
    "--ipc",
    "--uts",
    "--userns",
    "--network=host",
    "--net",
    "--net=host",
    "--security-opt=seccomp=unconfined",
    "seccomp=unconfined",
    "apparmor=unconfined",
    "label=disable",
    "--group-add",
    "--add-host",
    "--publish",
    "-p",
    "--expose",
)


@dataclass
class JobResult:
    job_id: str
    rc: int
    output: str  # sanitised, capped; untrusted
    duration_s: float
    timed_out: bool = False
    truncated: bool = False
    rejected: str = ""  # the in-container tar check refused the input


def new_job_id() -> str:
    return uuid.uuid4().hex


def wrapper_script(command: str, timeout_s: int, cap_bytes: int) -> str:
    """The fixed in-container wrapper, one line (no newlines: the gate refuses multi-line commands)."""
    validate_command(command)
    cmd = shlex.quote(command)
    fail = f"echo; echo {RC_MARKER}125; exit 0"
    unsafe = "'^/|(^|/)[.][.](/|$)'"
    return (
        "umask 022; export HOME=/work; T=/work/.in.tar; L=/work/.list; E=/work/.err; "
        f'cat > "$T" || {{ echo "{NOWRITE}"; {fail}; }}; '
        f'tar -tf "$T" > "$L" 2> "$E" || {{ echo "{REJECT_MARKER} unreadable input"; {fail}; }}; '
        # busybox tar strips '../' while listing and only warns on stderr: any warning is a refusal.
        f'if [ -s "$E" ] || grep -Eq {unsafe} "$L"; then '
        f'echo "{REJECT_MARKER} unsafe path in input"; {fail}; fi; '
        'mkdir -p /work/src && tar -xf "$T" -C /work/src 2>/dev/null'
        f' || {{ echo "{REJECT_MARKER} extract failed"; {fail}; }}; '
        'rm -f "$T" "$L" "$E"; cd /work/src || exit 0; '
        f"( timeout -s KILL {int(timeout_s)} sh -c {cmd}; echo $? > /tmp/.rc ) 2>&1"
        f" | head -c {int(cap_bytes)}; "
        f'echo; echo "{RC_MARKER}$(cat /tmp/.rc 2>/dev/null || echo 137)"'
    )


def validate_command(command: str) -> str:
    if not command or not command.strip():
        raise SandboxError("empty sandbox command")
    if len(command) > MAX_COMMAND:
        raise SandboxError(f"sandbox command longer than {MAX_COMMAND} characters")
    if any(c in command for c in "\n\r\x00"):
        raise SandboxError("sandbox commands must be a single line (no newlines)")
    return command


def container_argv(cfg: VMConfig, job_id: str, script: str) -> list[str]:
    """The only place a container command is built. Every value is validated; nothing can add flags."""
    if not _JOB_ID.match(job_id):
        raise SandboxError("invalid job id")
    if not IMAGE_RE.match(cfg.image):
        raise SandboxError("invalid image reference")
    if cfg.runtime not in ("docker", "podman"):
        raise SandboxError("invalid runtime")
    if "\n" in script or "\r" in script:
        raise SandboxError("wrapper must be a single line")
    fsize = int(cfg.max_output_kb) * 1024 * 64  # files written by the job (tmpfs bounds the rest)
    argv = [
        cfg.runtime,
        "run",
        "--rm",
        "-i",
        "--pull=never",
        "--name",
        f"{NAME_PREFIX}{job_id}",
        "--label",
        f"{LABEL}={job_id}",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m,mode=1777",  # noqa: S108  # nosec B108 - tmpfs inside the container, not a host path
        "--tmpfs",
        "/work:rw,exec,nosuid,size=256m,uid=65534,gid=65534,mode=0700",
        "--pids-limit",
        str(int(cfg.pids)),
        "--memory",
        f"{int(cfg.memory_mb)}m",
        "--memory-swap",
        f"{int(cfg.memory_mb)}m",
        "--cpus",
        f"{float(cfg.cpus):g}",
        "--ulimit",
        "nofile=1024:1024",
        "--ulimit",
        f"fsize={fsize}",
        "--user",
        "65534:65534",
        "--workdir",
        "/work",
        cfg.image,
        "sh",
        "-c",
        script,
    ]
    assert_safe(argv)
    return argv


def assert_safe(argv: list[str]) -> None:
    """Defence in depth: refuse an argv that contains any forbidden flag before the image name."""
    try:
        image_at = argv.index("--workdir") + 2
    except ValueError:
        image_at = len(argv)
    for token in argv[:image_at]:
        low = token.lower()
        for bad in FORBIDDEN:
            if low == bad or (bad.startswith("--") and low.startswith(bad + "=")):
                raise SandboxError(f"refusing unsafe container flag {token!r}")
        if "host" in low and low.startswith("--"):
            raise SandboxError(f"refusing unsafe container flag {token!r}")


def parse_result(job_id: str, result: ExecResult, timeout_s: int, cap_bytes: int) -> JobResult:
    text = clean_text(result.stdout)
    lines = text.rstrip("\n").split("\n")
    last = lines[-1].strip() if lines else ""
    match = _RC_LINE.match(last)
    if match is None:
        detail = clean_text(result.stderr, 300).strip().splitlines()
        hint = detail[-1] if detail else "no output"
        if result.timed_out:
            raise SandboxError("the sandbox job did not finish (transport timeout)")
        raise SandboxError(f"the sandbox returned no result line (runtime said: {hint[:200]})")
    rc = int(match.group(1))
    body = "\n".join(lines[:-1]).rstrip("\n")
    rejected = ""
    first = body.lstrip("\n").split("\n", 1)[0]
    if first.startswith(REJECT_MARKER):
        rejected = first[len(REJECT_MARKER) :].strip()[:100]
    timed_out = rc in (124, 137, 143) and result.duration_s >= timeout_s * 0.9
    raw = result.stdout.rstrip(b"\n")
    raw_body = raw[: max(0, raw.rfind(b"\n"))]  # without the marker line and the wrapper's own `echo`
    truncated = len(raw_body) >= cap_bytes or result.truncated
    return JobResult(job_id, rc, body, result.duration_s, timed_out or result.timed_out, truncated, rejected)


class Sandbox:
    """Runs jobs on the VM through a Transport. Fails closed with SandboxError."""

    def __init__(self, cfg: VMConfig, transport: Transport) -> None:
        self.cfg = cfg
        self.transport = transport
        self.jobs_run = 0

    # -- probes (read-only) --------------------------------------------------------------------

    def _probe(self, argv: list[str], max_output: int = 65536) -> ExecResult:
        try:
            return self.transport.run(argv, timeout=PROBE_TIMEOUT_S, max_output=max_output)
        except SandboxError:
            raise
        except OSError as exc:
            raise SandboxError(f"cannot reach the VM: {exc.strerror}") from None

    def runtime_version(self) -> str:
        res = self._probe([self.cfg.runtime, "version", "--format", "{{.Client.Version}}"], 4096)
        if res.returncode == 255:
            raise SandboxError("SSH connection failed: " + _ssh_hint(res.stderr), fix=_ssh_fix(res.stderr))
        if res.returncode != 0:
            raise SandboxError(
                f"{self.cfg.runtime} is not usable on the VM", fix="install it / add the user to its group"
            )
        return clean_text(res.stdout, 64).strip()

    def image_id(self) -> str:
        res = self._probe([self.cfg.runtime, "image", "inspect", "--format", "{{.Id}}", self.cfg.image], 4096)
        if res.returncode == 255:
            raise SandboxError("SSH connection failed: " + _ssh_hint(res.stderr), fix=_ssh_fix(res.stderr))
        value = clean_text(res.stdout, 200).strip()
        if res.returncode != 0 or not IMAGE_ID_RE.match(value):
            raise SandboxError(
                f"image {self.cfg.image} is not present on the VM",
                fix=f"run `sift vm image pull {self.cfg.image}` (uses the network on the VM)",
            )
        return value

    def verify_image(self) -> None:
        if not self.cfg.image_id:
            raise SandboxError(
                "the sandbox image is not pinned yet", fix=f"run `sift vm image pull {self.cfg.image}`"
            )
        actual = self.image_id()
        if actual != self.cfg.image_id:
            raise SandboxError(
                "the sandbox image on the VM changed since it was pinned",
                fix="review the change, then re-pin with `sift vm image pull`",
            )

    def free_memory_mb(self) -> int:
        res = self._probe(["cat", "/proc/meminfo"], 16384)
        if res.returncode == 255:
            raise SandboxError("SSH connection failed: " + _ssh_hint(res.stderr), fix=_ssh_fix(res.stderr))
        for line in clean_text(res.stdout).splitlines():
            m = re.match(r"^MemAvailable:\s+(\d{1,12})\s+kB$", line.strip())
            if m:
                return int(m.group(1)) // 1024
        raise SandboxError("cannot read free memory on the VM")

    def running_jobs(self) -> list[str]:
        res = self._probe([self.cfg.runtime, "ps", "-q", "--filter", f"label={LABEL}"])
        if res.returncode != 0:
            raise SandboxError("cannot list containers on the VM")
        return [i for i in clean_text(res.stdout).split() if _CONTAINER_ID.match(i)]

    def guard(self) -> None:
        free = self.free_memory_mb()
        if free < self.cfg.min_free_mem_mb:
            raise SandboxError(
                f"the VM has {free} MB free memory, below the {self.cfg.min_free_mem_mb} MB minimum",
                fix="wait, or lower min_free_mem_mb in vm.toml",
            )
        running = self.running_jobs()
        if len(running) >= self.cfg.max_concurrent:
            raise SandboxError(
                "another CodeSift job is running on the VM (max 1 at a time)",
                fix="wait for it to finish, or run `sift vm reset` if it is stale",
            )

    # -- jobs ----------------------------------------------------------------------------------

    def run_job(
        self, command: str, tar: bytes, timeout_s: int | None = None, *, guard: bool = True
    ) -> JobResult:
        timeout = int(timeout_s or self.cfg.job_timeout_s)
        timeout = max(1, min(timeout, self.cfg.job_timeout_s))
        cap = self.cfg.max_output_kb * 1024
        if guard:
            self.verify_image()
            self.guard()
        job_id = new_job_id()
        argv = container_argv(self.cfg, job_id, wrapper_script(command, timeout, cap))
        try:
            result = self.transport.run(
                argv, stdin=tar, timeout=timeout + TRANSPORT_SLACK_S, max_output=cap + 4096
            )
            if result.returncode == 255 and RC_MARKER not in clean_text(result.stdout[-200:]):
                raise SandboxError(
                    "SSH connection failed: " + _ssh_hint(result.stderr), fix=_ssh_fix(result.stderr)
                )
            self.jobs_run += 1
            return parse_result(job_id, result, timeout, cap)
        finally:
            self.cleanup(job_id)

    def cleanup(self, job_id: str) -> int:
        """Remove containers carrying this job's label. Never anything else."""
        if not _JOB_ID.match(job_id):
            raise SandboxError("invalid job id")
        return self._remove_by_filter(f"label={LABEL}={job_id}")

    def reset(self) -> int:
        """Remove every container carrying the codesift.job label (any job). Nothing else."""
        return self._remove_by_filter(f"label={LABEL}")

    def _remove_by_filter(self, flt: str) -> int:
        try:
            res = self.transport.run(
                [self.cfg.runtime, "ps", "-aq", "--filter", flt], timeout=PROBE_TIMEOUT_S
            )
        except (SandboxError, OSError):
            return 0
        ids = [i for i in clean_text(res.stdout).split() if _CONTAINER_ID.match(i)][:50]
        if res.returncode != 0 or not ids:
            return 0
        self.transport.run([self.cfg.runtime, "rm", "-f", *ids], timeout=PROBE_TIMEOUT_S)
        return len(ids)


def _ssh_hint(stderr: str) -> str:
    text = " ".join(clean_text(stderr, 400).split())
    if "host key" in text.lower() and ("changed" in text.lower() or "verification failed" in text.lower()):
        return "the VM's host key does not match the pinned key"
    return text[:200] or "no details"


def _ssh_fix(stderr: str) -> str:
    low = stderr.lower()
    if "host key" in low:
        return (
            "the VM may have been reinstalled or someone is intercepting; verify, then re-pin with "
            "`sift setup --vm`"
        )
    if "permission denied" in low:
        return "the VM does not accept the key; install the public key (sift setup --vm prints it)"
    return "check the VM is up and reachable, then run `sift vm doctor`"
