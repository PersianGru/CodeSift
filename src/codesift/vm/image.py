"""Sandbox image management. Pull and build USE THE NETWORK ON THE VM and run only on explicit
command (`sift vm image pull|build`). The resulting image id is recorded in vm.toml and verified
before every job, so an image swapped behind CodeSift's back is refused."""

from __future__ import annotations

import io
import re
import tarfile
from pathlib import Path

from codesift.vm import SandboxError
from codesift.vm.config import IMAGE_ID_RE, IMAGE_RE, VMConfig
from codesift.vm.sandbox import Sandbox
from codesift.vm.transport import Transport, clean_text

PULL_TIMEOUT_S = 900
BUILD_TIMEOUT_S = 1800
MAX_DOCKERFILE = 256 * 1024
_TAG = re.compile(r"^sift-[a-z0-9._-]{1,64}(:[A-Za-z0-9._-]{1,64})?$")


def pull(transport: Transport, cfg: VMConfig, ref: str) -> str:
    """Pull `ref` on the VM and return its image id (sha256:…)."""
    if not IMAGE_RE.match(ref):
        raise SandboxError("not a valid image reference")
    res = transport.run([cfg.runtime, "image", "pull", ref], timeout=PULL_TIMEOUT_S, max_output=65536)
    if res.returncode != 0:
        last = (clean_text(res.stderr or res.stdout, 400).strip().splitlines() or ["no details"])[-1]
        raise SandboxError(f"image pull failed: {last[:200]}")
    probe = VMConfig(**{**cfg.__dict__, "image": ref})
    return Sandbox(probe, transport).image_id()


def build(transport: Transport, cfg: VMConfig, dockerfile: Path, tag: str) -> str:
    """Build an image from a Dockerfile (sent as the only file of the build context, via stdin)."""
    if not _TAG.match(tag):
        raise SandboxError("the tag must look like sift-<name>[:<tag>] (CodeSift only builds its own images)")
    data = dockerfile.read_bytes()
    if len(data) > MAX_DOCKERFILE:
        raise SandboxError("Dockerfile too large")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo("Dockerfile")
        info.size, info.mode, info.uname, info.gname = len(data), 0o644, "nobody", "nobody"
        tf.addfile(info, io.BytesIO(data))
    res = transport.run(
        [cfg.runtime, "build", "--tag", tag, "-"],
        stdin=buf.getvalue(),
        timeout=BUILD_TIMEOUT_S,
        max_output=262144,
    )
    if res.returncode != 0:
        last = (clean_text(res.stderr or res.stdout, 400).strip().splitlines() or ["no details"])[-1]
        raise SandboxError(f"image build failed: {last[:200]}")
    probe = VMConfig(**{**cfg.__dict__, "image": tag})
    image_id = Sandbox(probe, transport).image_id()
    if not IMAGE_ID_RE.match(image_id):
        raise SandboxError("the built image has no valid id")
    return image_id
