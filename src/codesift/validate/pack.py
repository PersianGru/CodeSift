"""Safe tar writing and reading.

Packing: regular files only, relative POSIX names (no `..`, no leading `/`, no drive letters, no
backslashes or control characters), normalised permissions (0644 / 0755), owner nobody, mtime 0,
total size / file count / per-file caps.

Unpacking (anything coming back from the VM, or `git archive` output): uncompressed tar only (no
decompression bombs), the same name checks, links / devices / FIFOs refused (or skipped when
`strict=False`), every path resolved inside the destination, sizes capped while copying."""

from __future__ import annotations

import io
import os
import re
import stat
import tarfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 20_000
MAX_FILE = 8 * 1024 * 1024
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f\\:]")


class PackError(Exception):
    pass


def safe_name(name: str) -> str:
    """Validate a relative archive member name; returns it normalised."""
    original = name
    if not name or name.startswith("/") or _BAD_CHARS.search(name):
        raise PackError(f"unsafe path in archive: {original[:80]!r}")
    while name.startswith("./"):
        name = name[2:]
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise PackError(f"unsafe path in archive: {original[:80]!r}")
    return str(PurePosixPath(*parts))


def _info(name: str, size: int, executable: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(safe_name(name))
    info.size = size
    info.mode = 0o755 if executable else 0o644
    info.uid = info.gid = 65534
    info.uname = info.gname = "nobody"
    info.mtime = 0
    info.type = tarfile.REGTYPE
    return info


def pack_files(files: dict[str, bytes], *, max_total: int = MAX_TOTAL, max_files: int = MAX_FILES) -> bytes:
    if len(files) > max_files:
        raise PackError(f"too many files ({len(files)} > {max_files})")
    total = 0
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name in sorted(files):
            data = files[name]
            total += len(data)
            if total > max_total:
                raise PackError("archive larger than the size cap")
            tf.addfile(_info(name, len(data), False), io.BytesIO(data))
    return buf.getvalue()


def pack_tree(
    root: Path,
    *,
    skip_dirs: tuple[str, ...] = (".git",),
    extra: dict[str, bytes] | None = None,
    max_total: int = MAX_TOTAL,
    max_files: int = MAX_FILES,
    max_file: int = MAX_FILE,
) -> bytes:
    """Pack every regular file under `root` (symlinks and special files refused)."""
    entries: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        keep = []
        for d in dirnames:
            if d in skip_dirs and base == root:
                continue
            if (base / d).is_symlink():
                raise PackError(f"symlink in workspace: {(base / d).relative_to(root).as_posix()}")
            keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            p = base / name
            st = p.lstat()
            if not stat.S_ISREG(st.st_mode):
                raise PackError(f"not a regular file: {p.relative_to(root).as_posix()}")
            if st.st_size > max_file:
                raise PackError(f"file larger than the cap: {p.relative_to(root).as_posix()}")
            entries.append((p.relative_to(root).as_posix(), p))
    if len(entries) + len(extra or {}) > max_files:
        raise PackError(f"too many files ({len(entries)} > {max_files})")
    total = 0
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for rel, p in sorted(entries):
            data = p.read_bytes()
            total += len(data)
            if total > max_total:
                raise PackError("workspace larger than the size cap")
            executable = bool(p.stat().st_mode & 0o111) and os.name != "nt"
            tf.addfile(_info(rel, len(data), executable), io.BytesIO(data))
        for rel, data in sorted((extra or {}).items()):
            total += len(data)
            if total > max_total:
                raise PackError("workspace larger than the size cap")
            tf.addfile(_info(rel, len(data), False), io.BytesIO(data))
    return buf.getvalue()


def safe_unpack(
    data: bytes,
    dest: Path,
    *,
    strict: bool = True,
    max_total: int = MAX_TOTAL,
    max_files: int = MAX_FILES,
    max_file: int = MAX_FILE,
    accept: Callable[[str], bool] | None = None,
    skipped: list[tuple[str, str]] | None = None,
) -> list[str]:
    """Extract an uncompressed tar into `dest`. Returns the written relative paths.

    strict=True: any link/device/FIFO is an error. strict=False: such members are skipped and
    recorded in `skipped`. Unsafe names are always an error. `accept(rel)` can veto regular files."""
    if len(data) > max_total * 2:
        raise PackError("archive larger than the size cap")
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    written: list[str] = []
    total = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")  # noqa: SIM115 - closed by the with below
    except tarfile.TarError:
        raise PackError("not an uncompressed tar archive") from None
    with tf:
        for count, member in enumerate(tf, start=1):
            if count > max_files:
                raise PackError(f"too many members (> {max_files})")
            rel = safe_name(member.name.rstrip("/")) if member.name.rstrip("/") not in ("", ".") else ""
            if not rel:
                continue
            if member.isdir():
                continue
            if not member.isfile():
                kind = "link" if (member.issym() or member.islnk()) else "special file"
                if strict:
                    raise PackError(f"{kind} in archive: {rel[:80]}")
                if skipped is not None:
                    skipped.append((rel, kind))
                continue
            if member.size > max_file:
                if strict:
                    raise PackError(f"member larger than the cap: {rel[:80]}")
                if skipped is not None:
                    skipped.append((rel, "too large"))
                continue
            if accept is not None and not accept(rel):
                continue
            target = (root / rel).resolve()
            if not target.is_relative_to(root) or target == root:
                raise PackError(f"path escapes the destination: {rel[:80]}")
            # refuse writing through a symlinked parent that might already exist
            for parent in target.parents:
                if parent == root:
                    break
                if parent.is_symlink():
                    raise PackError(f"path escapes the destination: {rel[:80]}")
            total += member.size
            if total > max_total:
                raise PackError("archive content larger than the size cap")
            src = tf.extractfile(member)
            if src is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with src, target.open("wb") as out:
                remaining = member.size
                while remaining > 0:
                    chunk = src.read(min(65536, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)
            if member.mode & 0o111 and os.name != "nt":
                target.chmod(0o755)
            written.append(rel)
    return written
