"""Scanner binaries: specs, verified install, verified lookup.

Integrity chain:
  official checksums file / GitHub asset digest  ->  tools.lock.json (asset sha256)
  download  -> sha256 must equal the lock         -> extract only the named binary
  manifest  (.codesift-tool.json: asset + binary sha256) written after verification
  every run -> binary sha256 must equal the manifest, manifest asset sha256 must equal the lock
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from codesift.lockfile import Lock, PlatformAsset, ToolLock, current_platform
from codesift.net import download

MANIFEST = ".codesift-tool.json"
MAX_DOWNLOAD = 400_000_000


@dataclass(frozen=True)
class ToolSpec:
    name: str
    repo: str
    binary: str  # executable name without .exe
    assets: dict[str, str]  # platform -> asset name template ({version})
    checksums: str | None  # checksums asset template, None = GitHub asset digest
    version_args: tuple[str, ...]
    go_module: str | None = None  # for GitHub advisory lookups


TOOL_SPECS: dict[str, ToolSpec] = {
    "gitleaks": ToolSpec(
        name="gitleaks",
        repo="gitleaks/gitleaks",
        binary="gitleaks",
        assets={
            "windows-x64": "gitleaks_{version}_windows_x64.zip",
            "linux-x64": "gitleaks_{version}_linux_x64.tar.gz",
            "linux-arm64": "gitleaks_{version}_linux_arm64.tar.gz",
            "darwin-arm64": "gitleaks_{version}_darwin_arm64.tar.gz",
        },
        checksums="gitleaks_{version}_checksums.txt",
        version_args=("version",),
        go_module="github.com/zricethezav/gitleaks/v8",
    ),
    "osv-scanner": ToolSpec(
        name="osv-scanner",
        repo="google/osv-scanner",
        binary="osv-scanner",
        assets={
            "windows-x64": "osv-scanner_windows_amd64.exe",
            "linux-x64": "osv-scanner_linux_amd64",
            "linux-arm64": "osv-scanner_linux_arm64",
            "darwin-arm64": "osv-scanner_darwin_arm64",
        },
        checksums="osv-scanner_SHA256SUMS",
        version_args=("--version",),
        go_module="github.com/google/osv-scanner/v2",
    ),
    "trivy": ToolSpec(
        name="trivy",
        repo="aquasecurity/trivy",
        binary="trivy",
        assets={
            "windows-x64": "trivy_{version}_windows-64bit.zip",
            "linux-x64": "trivy_{version}_Linux-64bit.tar.gz",
            "linux-arm64": "trivy_{version}_Linux-ARM64.tar.gz",
            "darwin-arm64": "trivy_{version}_macOS-ARM64.tar.gz",
        },
        checksums="trivy_{version}_checksums.txt",
        version_args=("--version",),
        go_module="github.com/aquasecurity/trivy",
    ),
    "opengrep": ToolSpec(
        name="opengrep",
        repo="opengrep/opengrep",
        binary="opengrep",
        assets={
            "windows-x64": "opengrep_windows_x86.exe",
            "linux-x64": "opengrep_manylinux_x86",
            "linux-arm64": "opengrep_manylinux_aarch64",
            "darwin-arm64": "opengrep_osx_arm64",
        },
        checksums=None,
        version_args=("--version",),
    ),
}


class ToolError(Exception):
    pass


def exe_name(binary: str, plat: str) -> str:
    return binary + ".exe" if plat.startswith("windows") else binary


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_dir(tools_root: Path, name: str, version: str) -> Path:
    return tools_root / name / version


def _is_archive(asset: str) -> bool:
    return asset.endswith((".zip", ".tar.gz", ".tgz"))


def _extract_member(archive: Path, member_name: str) -> bytes:
    """Read exactly one regular file (by base name) from an archive. Nothing else is written,
    so archive paths (../, absolute, links) can never escape."""
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            matches = [i for i in zf.infolist() if not i.is_dir() and Path(i.filename).name == member_name]
            if len(matches) != 1:
                raise ToolError(f"{archive.name}: expected one {member_name}, found {len(matches)}")
            return zf.read(matches[0])
    with tarfile.open(archive, "r:gz") as tf:
        members = [m for m in tf.getmembers() if m.isreg() and Path(m.name).name == member_name]
        if len(members) != 1:
            raise ToolError(f"{archive.name}: expected one {member_name}, found {len(members)}")
        fh = tf.extractfile(members[0])
        if fh is None:
            raise ToolError(f"{archive.name}: cannot read {member_name}")
        with fh:
            return fh.read()


def _write_manifest(dest: Path, name: str, tool: ToolLock, asset: PlatformAsset, binary_sha: str) -> None:
    manifest = {
        "name": name,
        "version": tool.version,
        "asset": asset.asset,
        "asset_sha256": asset.sha256,
        "binary_sha256": binary_sha,
        "installed": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (dest / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")


def install_tool(name: str, lock: Lock, tools_root: Path, plat: str | None = None) -> Path:
    """Download, verify and install one tool. Returns the binary path. Idempotent."""
    plat = plat or current_platform()
    tool = lock.tools.get(name)
    if tool is None:
        raise ToolError(f"{name} is not in the lock file")
    asset = tool.platforms.get(plat)
    if asset is None:
        raise ToolError(f"{name} {tool.version} has no build for platform {plat}")
    spec = TOOL_SPECS[name]
    dest = tool_dir(tools_root, name, tool.version)
    binary = dest / exe_name(spec.binary, plat)
    try:
        return resolve_tool(name, lock, tools_root, plat)
    except ToolError:
        pass

    staging = tools_root / ".staging" / f"{name}-{tool.version}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    try:
        downloaded = staging / asset.asset
        download(asset.url, downloaded, sha256=asset.sha256, max_bytes=min(MAX_DOWNLOAD, asset.size + 1024))
        if _is_archive(asset.asset):
            data = _extract_member(downloaded, exe_name(spec.binary, plat))
            downloaded.unlink()
        else:
            data = downloaded.read_bytes()
            downloaded.unlink()
        binary_sha = hashlib.sha256(data).hexdigest()
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        with binary.open("xb") as fh:
            fh.write(data)
        if not plat.startswith("windows"):
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        _write_manifest(dest, name, tool, asset, binary_sha)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return resolve_tool(name, lock, tools_root, plat)


def resolve_tool(name: str, lock: Lock, tools_root: Path, plat: str | None = None) -> Path:
    """Return the verified binary path or raise ToolError. Never returns an unverified binary."""
    plat = plat or current_platform()
    tool = lock.tools.get(name)
    if tool is None:
        raise ToolError(f"{name} is not in the lock file")
    asset = tool.platforms.get(plat)
    if asset is None:
        raise ToolError(f"{name} has no build for {plat}")
    dest = tool_dir(tools_root, name, tool.version)
    binary = dest / exe_name(TOOL_SPECS[name].binary, plat)
    manifest_path = dest / MANIFEST
    if not binary.is_file() or not manifest_path.is_file():
        raise ToolError(f"{name} {tool.version} is not installed (run `sift install`)")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError:
        raise ToolError(f"{name}: corrupt install manifest - reinstall with `sift install`") from None
    if manifest.get("asset_sha256") != asset.sha256:
        raise ToolError(f"{name}: installed build does not match the lock - run `sift install`")
    if sha256_file(binary) != manifest.get("binary_sha256"):
        raise ToolError(
            f"{name}: binary checksum mismatch - refusing to run it; reinstall with `sift install`"
        )
    return binary


def installed_versions(tools_root: Path, name: str) -> list[str]:
    root = tools_root / name
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if (p / MANIFEST).is_file())


def prune_versions(tools_root: Path, name: str, keep: set[str]) -> list[str]:
    removed = []
    for version in installed_versions(tools_root, name):
        if version not in keep:
            shutil.rmtree(tools_root / name / version, ignore_errors=True)
            removed.append(version)
    return removed


def parse_checksums(text: str) -> dict[str, str]:
    """Parse `sha256  filename` (or `sha256 *filename`) lines."""
    result: dict[str, str] = {}
    for line in io.StringIO(text):
        parts = line.strip().split()
        if len(parts) >= 2 and len(parts[0]) == 64:
            result[parts[-1].lstrip("*")] = parts[0].lower()
    return result


def tool_env() -> dict[str, str]:
    """Environment for scanner subprocesses: no telemetry, no update checks."""
    env = dict(os.environ)
    env.update(
        {
            "SEMGREP_SEND_METRICS": "off",
            "OPENGREP_SEND_METRICS": "off",
            "TRIVY_DISABLE_VEX_NOTICE": "true",
            "TRIVY_SKIP_VERSION_CHECK": "true",
            "TRIVY_NO_PROGRESS": "true",
        }
    )
    return env
