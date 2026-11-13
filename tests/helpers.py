"""Builders for fake releases, archives and locks (no network, no real binaries)."""

from __future__ import annotations

import hashlib
import io
import shutil
import tarfile
import zipfile
from pathlib import Path

from codesift.lockfile import Lock, PlatformAsset, ToolLock


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_tgz(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def lock_with(name: str, repo: str, version: str, plat: str, asset: str, data: bytes) -> Lock:
    tag = f"v{version}"
    entry = ToolLock(repo=repo, tag=tag, version=version, published="2026-01-01", checksum_source="x")
    entry.platforms[plat] = PlatformAsset(
        asset=asset,
        url=f"https://github.com/{repo}/releases/download/{tag}/{asset}",
        sha256=sha(data),
        size=len(data),
    )
    lock = Lock(updated="2026-01-01")
    lock.tools[name] = entry
    return lock


class FakeDownloads:
    """Replacement for codesift.net.download serving bytes by URL, with real sha256 checking."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.calls: list[str] = []

    def __call__(self, url: str, dest: Path, *, sha256: str, max_bytes: int, timeout: float = 120) -> None:
        from codesift.net import NetworkError

        self.calls.append(url)
        data = self.files[url]
        if len(data) > max_bytes:
            raise NetworkError("too big")
        if sha(data) != sha256:
            raise NetworkError(f"checksum mismatch for {dest.name} - refusing it")
        tmp = dest.with_name(dest.name + ".part")
        tmp.write_bytes(data)
        shutil.move(str(tmp), dest)
