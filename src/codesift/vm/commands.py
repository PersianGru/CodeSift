"""`sift vm …` command logic (cli.py stays thin). Every command that touches the VM goes through
`make_transport`, so tests swap in a FakeTransport."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from codesift.paths import Paths
from codesift.vm import SandboxError
from codesift.vm.admin import admin_script, render_gate
from codesift.vm.config import VMConfig, load_vm_config, save_vm_config
from codesift.vm.image import build, pull
from codesift.vm.keys import public_key_of
from codesift.vm.sandbox import Sandbox
from codesift.vm.selftest import last_result, record, run_selftest
from codesift.vm.transport import SshTransport, Transport


def _ssh_transport(cfg: VMConfig, paths: Paths) -> Transport:
    return SshTransport(cfg, paths.keys_dir)


make_transport: Callable[[VMConfig, Paths], Transport] = _ssh_transport


def make_sandbox(paths: Paths) -> Sandbox:
    cfg = load_vm_config(paths)
    return Sandbox(cfg, make_transport(cfg, paths))


def doctor_lines(paths: Paths) -> list[str]:
    """Live check: SSH + runtime + full isolation self-test. Result cached for the run gate."""
    try:
        sandbox = make_sandbox(paths)
        version = sandbox.runtime_version()
    except SandboxError as exc:
        return [f"[FAIL] connection: {exc}"] + ([f"       fix: {exc.fix}"] if exc.fix else [])
    lines = [f"[ok  ] connection: {sandbox.cfg.user}@{sandbox.cfg.host}, {sandbox.cfg.runtime} {version}"]
    report = run_selftest(sandbox)
    record(paths.data, sandbox.cfg.digest(), report)
    lines += report.lines()
    lines.append(
        "self-test PASSED" if report.passed else "self-test FAILED - CodeSift will refuse to run jobs"
    )
    return lines


def cmd_doctor(paths: Paths, out: Callable[[str], None]) -> int:
    lines = doctor_lines(paths)
    for line in lines:
        out(line)
    return 0 if lines and lines[-1] == "self-test PASSED" else 2


def cmd_status(paths: Paths, out: Callable[[str], None]) -> int:
    try:
        sandbox = make_sandbox(paths)
        free = sandbox.free_memory_mb()
        running = sandbox.running_jobs()
    except SandboxError as exc:
        out(f"sift vm status: {exc}")
        return 2
    cfg = sandbox.cfg
    last = last_result(paths.data)
    out(f"VM {cfg.user}@{cfg.host}:{cfg.port} ({cfg.runtime})")
    out(f"  free memory: {free} MB (minimum {cfg.min_free_mem_mb} MB)")
    out(f"  CodeSift jobs running: {len(running)}")
    out(f"  image: {cfg.image} {'pinned ' + cfg.image_id[:19] if cfg.image_id else '(not pinned)'}")
    out(f"  last self-test: {'never' if not last else ('passed' if last.get('passed') else 'FAILED')}")
    return 0


def cmd_reset(paths: Paths, out: Callable[[str], None]) -> int:
    try:
        removed = make_sandbox(paths).reset()
    except SandboxError as exc:
        out(f"sift vm reset: {exc}")
        return 2
    out(f"removed {removed} container(s) labelled codesift.job (nothing else is touched)")
    return 0


def cmd_image_pull(paths: Paths, ref: str | None, out: Callable[[str], None]) -> int:
    try:
        cfg = load_vm_config(paths)
        ref = ref or cfg.image
        out(f"pulling {ref} on the VM (this uses the network on the VM) ...")
        image_id = pull(make_transport(cfg, paths), cfg, ref)
        cfg.image, cfg.image_id = ref, image_id
        save_vm_config(paths, cfg)
    except SandboxError as exc:
        out(f"sift vm image pull: {exc}")
        return 2
    out(f"pinned {ref} = {image_id} in {paths.vm_file}")
    return 0


def cmd_image_build(paths: Paths, dockerfile: str, tag: str, out: Callable[[str], None]) -> int:
    path = Path(dockerfile)
    if not path.is_file():
        out(f"sift vm image build: {dockerfile} not found")
        return 2
    try:
        cfg = load_vm_config(paths)
        out(f"building {tag} on the VM - BUILDING USES THE NETWORK ON THE VM; review the Dockerfile first")
        image_id = build(make_transport(cfg, paths), cfg, path, tag)
        cfg.image, cfg.image_id = tag, image_id
        save_vm_config(paths, cfg)
    except SandboxError as exc:
        out(f"sift vm image build: {exc}")
        return 2
    out(f"pinned {tag} = {image_id} in {paths.vm_file}")
    return 0


def cmd_admin_script(paths: Paths, gate_only: bool, out: Callable[[str], None]) -> int:
    if gate_only:
        out(render_gate().rstrip("\n"))
        return 0
    try:
        cfg = load_vm_config(paths)
        text = admin_script(cfg, public_key_of(Path(cfg.key_path)))
    except SandboxError as exc:
        out(f"sift vm admin-script: {exc}")
        return 2
    out(text.rstrip("\n"))
    return 0
