"""`vm.toml`: the sandbox VM settings. Loaded strictly, validated, written owner-only.
No password is ever stored (password authentication is not supported)."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from codesift.paths import Paths
from codesift.vm import SandboxError
from codesift.vm.sshargs import ArgError, validate_host, validate_port, validate_user

RUNTIMES = ("docker", "podman")
# Image references: registry/name[:tag][@sha256:digest]. Never starts with '-', no spaces or quotes.
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
DEFAULT_IMAGE = "python:3.12-alpine"  # recommendation only; the user chooses (docs/vm-setup.md)

LIMITS = {
    "memory_mb": (64, 65536),
    "cpus": (0.1, 64.0),
    "pids": (16, 4096),
    "job_timeout_s": (5, 3600),
    "max_output_kb": (4, 16384),
    "min_free_mem_mb": (0, 65536),
    "max_concurrent": (1, 1),
}


@dataclass
class VMConfig:
    host: str = ""
    port: int = 22
    user: str = ""
    key_path: str = ""
    key_user_supplied: bool = False
    known_hosts_path: str = ""
    host_key_fingerprint: str = ""
    runtime: str = "docker"
    image: str = DEFAULT_IMAGE
    image_id: str = ""  # recorded by `sift vm image pull/build`, verified before every job
    memory_mb: int = 512
    cpus: float = 1.0
    pids: int = 128
    job_timeout_s: int = 300
    max_output_kb: int = 256
    min_free_mem_mb: int = 768
    max_concurrent: int = 1

    def validate(self) -> VMConfig:
        try:
            validate_host(self.host)
            validate_user(self.user)
            self.port = validate_port(self.port)
        except ArgError as exc:
            raise SandboxError(f"vm.toml: {exc}", fix="run `sift setup --vm`") from None
        if self.runtime not in RUNTIMES:
            raise SandboxError(f"vm.toml: runtime must be one of {', '.join(RUNTIMES)}")
        if not IMAGE_RE.match(self.image):
            raise SandboxError("vm.toml: image is not a valid image reference")
        if self.image_id and not IMAGE_ID_RE.match(self.image_id):
            raise SandboxError("vm.toml: image_id must look like sha256:<64 hex>")
        if self.host_key_fingerprint and not FINGERPRINT_RE.match(self.host_key_fingerprint):
            raise SandboxError("vm.toml: host_key_fingerprint must look like SHA256:<43 chars>")
        if not self.key_path or not self.known_hosts_path:
            raise SandboxError(
                "vm.toml: key_path and known_hosts_path are required", fix="run `sift setup --vm`"
            )
        for name, (low, high) in LIMITS.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not low <= value <= high:
                raise SandboxError(f"vm.toml: {name} must be between {low} and {high}")
        self.cpus = round(float(self.cpus), 2)
        return self

    def digest(self) -> str:
        """Hash of the settings that a self-test result depends on (cache key)."""
        data = {k: v for k, v in asdict(self).items() if k != "image_id"} | {"image_id": self.image_id}
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    text = str(value)
    if "'" in text or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise SandboxError("vm.toml: a value contains characters that cannot be stored")
    return f"'{text}'"  # TOML literal string: backslashes (Windows paths) are kept as they are


def render(cfg: VMConfig) -> str:
    lines = [
        "# CodeSift sandbox VM. Written by `sift setup --vm`; values are validated on load.",
        "# No password is ever stored. Edit with `sift setup --vm`.",
        "[vm]",
    ]
    for f in fields(cfg):
        lines.append(f"{f.name} = {_toml_value(getattr(cfg, f.name))}")
    return "\n".join(lines) + "\n"


def load_vm_config(paths: Paths) -> VMConfig:
    path = paths.vm_file
    if not path.is_file():
        raise SandboxError("no sandbox VM configured", fix="run `sift setup --vm`")
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SandboxError(
            f"vm.toml cannot be read: {type(exc).__name__}", fix="run `sift setup --vm`"
        ) from None
    section = data.get("vm")
    if not isinstance(section, dict):
        raise SandboxError("vm.toml has no [vm] section", fix="run `sift setup --vm`")
    cfg = VMConfig()
    known = {f.name: f for f in fields(cfg)}
    for key, value in section.items():
        if key not in known:
            continue  # unknown keys are ignored
        default = getattr(cfg, key)
        if isinstance(default, float) and isinstance(value, int) and not isinstance(value, bool):
            value = float(value)
        if type(value) is not type(default):
            raise SandboxError(f"vm.toml: {key} has the wrong type")
        setattr(cfg, key, value)
    return cfg.validate()


def save_vm_config(paths: Paths, cfg: VMConfig) -> str:
    from codesift.secrets_store import write_private

    cfg.validate()
    return write_private(paths.vm_file, render(cfg))


def key_file(cfg: VMConfig) -> Path:
    return Path(cfg.key_path)
