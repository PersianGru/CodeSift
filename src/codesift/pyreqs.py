"""Python scanners (ruff, bandit, pip-audit, zizmor): hashed lock generation and installation.

requirements.lock pins every package (top-level + transitive) with the sha256 of every published
wheel for that version, so the same lock installs on Windows, Linux and macOS with
`pip install --require-hashes --only-binary=:all:` (no source builds, so no build scripts run).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from codesift.net import fetch_json
from codesift.releases import version_key

PYPI = "https://pypi.org/pypi"
SCANNERS = ("ruff", "bandit", "pip-audit", "zizmor")
# pip is pinned too, so the venv's installer itself comes from the hashed lock.
BOOTSTRAP = ("pip",)


class PyLockError(Exception):
    pass


def _pip_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "PIP_NO_INPUT": "1"})
    return env


_RUN: dict[str, Any] = {
    "capture_output": True,
    "text": True,
    "encoding": "utf-8",
    "errors": "replace",
    "check": False,
    "env": _pip_env(),
}


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class PyRelease:
    name: str
    version: str
    uploaded: datetime


def pypi_releases(name: str) -> list[PyRelease]:
    data = fetch_json(f"{PYPI}/{name}/json")
    out = []
    for ver, files in (data.get("releases") or {}).items():
        if not files or all(f.get("yanked") for f in files):
            continue
        if version_key(ver)[1] == 0 or not re.fullmatch(r"\d+(\.\d+)*", ver):
            continue  # pre/dev/post releases
        uploaded = min(
            datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")) for f in files
        )
        out.append(PyRelease(name, ver, uploaded))
    return out


def pick_pypi(name: str, cooldown_days: int, now: datetime | None = None) -> tuple[PyRelease, PyRelease]:
    now = now or datetime.now(UTC)
    rel = sorted(pypi_releases(name), key=lambda r: version_key(r.version), reverse=True)
    if not rel:
        raise PyLockError(f"no releases found for {name}")
    cutoff = now - timedelta(days=cooldown_days)
    eligible = next((r for r in rel if r.uploaded <= cutoff), None)
    if eligible is None:
        raise PyLockError(f"{name}: no release older than {cooldown_days} days")
    return eligible, rel[0]


def wheel_hashes(name: str, version: str) -> list[str]:
    data = fetch_json(f"{PYPI}/{name}/{version}/json")
    hashes = sorted(
        f["digests"]["sha256"]
        for f in data.get("urls", [])
        if f.get("packagetype") == "bdist_wheel" and not f.get("yanked")
    )
    if not hashes:
        raise PyLockError(f"{name}=={version} has no wheels on PyPI (source builds are not allowed)")
    return hashes


def resolve(pins: dict[str, str], cutoff: datetime, python: str | None = None) -> dict[str, str]:
    """Resolve the full dependency set with pip's resolver (dry run, nothing is installed)."""
    python = python or sys.executable
    cmd = [
        python,
        "-m",
        "pip",
        "install",
        "--dry-run",
        "--ignore-installed",
        "--quiet",
        "--disable-pip-version-check",
        "--only-binary=:all:",
        "--uploaded-prior-to",
        cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "--report",
        "-",
        *[f"{k}=={v}" for k, v in sorted(pins.items())],
    ]
    proc = subprocess.run(cmd, timeout=600, **_RUN)  # noqa: S603
    if proc.returncode != 0:
        raise PyLockError(f"pip could not resolve the scanner set: {proc.stderr.strip()[-800:]}")
    report: dict[str, Any] = json.loads(proc.stdout)
    resolved = {canonical(i["metadata"]["name"]): i["metadata"]["version"] for i in report.get("install", [])}
    return resolved


def render_lock(resolved: dict[str, str], header: str) -> str:
    lines = [header.rstrip(), ""]
    for name in sorted(resolved):
        version = resolved[name]
        hashes = wheel_hashes(name, version)
        lines.append(f"{name}=={version} \\")
        lines.extend(
            f"    --hash=sha256:{h}" + (" \\" if i < len(hashes) - 1 else "") for i, h in enumerate(hashes)
        )
    return "\n".join(lines) + "\n"


def parse_lock_pins(text: str) -> dict[str, str]:
    pins = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)", line)
        if m:
            pins[canonical(m.group(1))] = m.group(2)
    return pins


def build_lock_file(pins: dict[str, str], cooldown_days: int, python: str | None = None) -> str:
    bad = [k for k, v in pins.items() if not re.fullmatch(r"\d+(\.\d+)*", v)]
    if bad:
        raise PyLockError(f"no valid version pinned for: {', '.join(sorted(bad))}")
    cutoff = datetime.now(UTC) - timedelta(days=cooldown_days)
    resolved = resolve(pins, cutoff, python)
    for name, version in pins.items():
        if resolved.get(canonical(name)) != version:
            raise PyLockError(f"resolver picked {name}=={resolved.get(canonical(name))}, expected {version}")
    header = (
        "# CodeSift Python scanners - generated by `sift update --apply`. Do not edit by hand.\n"
        f"# Top-level: {', '.join(f'{k}=={v}' for k, v in sorted(pins.items()))}\n"
        f"# Dependencies uploaded before {cutoff.strftime('%Y-%m-%d')} ({cooldown_days}-day cooldown).\n"
        "# Install: pip install --require-hashes --only-binary=:all: --no-deps -r requirements.lock"
    )
    return render_lock(resolved, header)


def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def venv_script(venv: Path, name: str) -> Path:
    return (
        venv
        / ("Scripts" if sys.platform == "win32" else "bin")
        / (name + (".exe" if sys.platform == "win32" else ""))
    )


def install_lock(venv: Path, lock_file: Path) -> None:
    python = venv_python(venv)
    cmd = [
        str(python),
        "-m",
        "pip",
        "install",
        "--quiet",
        "--disable-pip-version-check",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-deps",
        "-r",
        str(lock_file),
    ]
    proc = subprocess.run(cmd, timeout=900, **_RUN)  # noqa: S603
    if proc.returncode != 0:
        raise PyLockError(f"pip install from {lock_file.name} failed: {proc.stderr.strip()[-1200:]}")


def installed_versions(venv: Path) -> dict[str, str]:
    python = venv_python(venv)
    if not python.is_file():
        return {}
    proc = subprocess.run(  # noqa: S603
        [str(python), "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
        timeout=120,
        **_RUN,
    )
    if proc.returncode != 0:
        return {}
    return {canonical(p["name"]): p["version"] for p in json.loads(proc.stdout)}
