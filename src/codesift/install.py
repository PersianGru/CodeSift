"""`sift install` / `uninstall`: everything lives in user-level folders (ADR-0002).

install:  venv + hashed Python scanners, verified binaries, rules, package snapshot, command shims,
          Claude Code skill, default config.toml. Optional, only on explicit flags (the install
          scripts ask first): copy LLM gateway settings (user-only permissions) and add the shim
          folder to the user PATH (Windows).
uninstall: removes what install created; runs/ and config/ (gateway/Claude keys, VM key, vm.toml,
           fix.toml, consent) only with --purge.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from codesift.envfile import load_env_file
from codesift.fsutil import replace_dir
from codesift.lockfile import LOCK_NAME, PY_LOCK_NAME, Lock, load_lock, source_root
from codesift.paths import Paths
from codesift.pyreqs import install_lock, venv_python
from codesift.rules import VENDOR_DIR, tree_sha256
from codesift.tools import install_tool, prune_versions
from codesift.update import self_test

SKILL_MARKER = "name: sift"

DEFAULT_CONFIG = """\
# CodeSift user config. All keys optional; defaults shown. LLM gateway settings live in gateway.env
# next to it (`sift setup --llm`).
# threshold = "high"        # severity that makes `sift scan` exit 1
# jobs = 2                  # scanners in parallel
# offline = false           # true = no network except a loopback/LAN LLM gateway and the VM
# allow_http_localhost = false

[llm]
# model = "<model id offered by your gateway>"
# fallback_model = "<second model id>"
# think = "auto"            # auto | on | off  (auto = on, see docs/model-eval.md)
# max_findings = 60
# total_budget_s = 1200
# call_timeout_s = 180
# review_budget_s = 2700    # --review: total time for the logic review (requests that do not fit are listed)
# review_timeout_s = 1200   # --review: one request (reasoning on: minutes per 400 lines)
"""


class InstallError(Exception):
    pass


def _source() -> Path:
    src = source_root()
    if src is None:
        raise InstallError("run `sift install` from a CodeSift source checkout (install.ps1 / install.sh)")
    return src


def _site_packages(venv: Path) -> Path:
    python = venv_python(venv)
    out = subprocess.run(  # noqa: S603
        [str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return Path(out.stdout.strip())


def ensure_venv(paths: Paths, log: list[str]) -> None:
    python = venv_python(paths.venv)
    if python.is_file():
        return
    paths.venv.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "venv", str(paths.venv)], check=True, timeout=300)  # noqa: S603
    log.append(f"created venv {paths.venv}")


def install_package_snapshot(paths: Paths, src: Path, log: list[str]) -> None:
    """Copy the CodeSift package into the data dir and link it into the venv with a .pth file,
    so the install does not depend on the checkout and needs no build backend from PyPI."""
    lib = paths.data / "lib"
    staging = paths.data / "lib.staging"
    shutil.rmtree(staging, ignore_errors=True)
    shutil.copytree(
        src / "src" / "codesift", staging / "codesift", ignore=shutil.ignore_patterns("__pycache__")
    )
    replace_dir(staging, lib)
    pth = _site_packages(paths.venv) / "codesift.pth"
    pth.write_text(str(lib) + "\n", encoding="utf-8", newline="\n")
    log.append(f"CodeSift package -> {lib}")


def install_rules(paths: Paths, src: Path, lock: Lock, log: list[str]) -> None:
    if lock.rules is None:
        log.append("no rules pinned in the lock - skipped")
        return
    source = src / "rules" / VENDOR_DIR
    if tree_sha256(source) != lock.rules.tree_sha256:
        raise InstallError(f"vendored rules in {source} do not match the lock's tree hash")
    dest = paths.data / "rules" / lock.rules.commit / VENDOR_DIR
    if dest.is_dir() and tree_sha256(dest) == lock.rules.tree_sha256:
        log.append(f"rules {lock.rules.commit[:12]} already installed")
        return
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(source, dest)
    log.append(f"rules {lock.rules.commit[:12]} -> {dest}")


# ---------------------------------------------------------------- shims, skill, config


def install_shims(paths: Paths, log: list[str]) -> list[Path]:
    """`sift` command: .cmd for cmd/PowerShell and a POSIX script for Git Bash / Linux / macOS."""
    python = venv_python(paths.venv)
    paths.bin.mkdir(parents=True, exist_ok=True)
    written = []
    sh = paths.bin / "sift"
    sh.write_text(f'#!/bin/sh\nexec "{python.as_posix()}" -m codesift "$@"\n', encoding="utf-8", newline="\n")
    sh.chmod(0o755)
    written.append(sh)
    if os.name == "nt":
        cmd = paths.bin / "sift.cmd"
        cmd.write_text(f'@echo off\r\n"{python}" -m codesift %*\r\n', encoding="utf-8", newline="")
        written.append(cmd)
    log.append("command shim -> " + ", ".join(str(p) for p in written))
    return written


def install_skill(paths: Paths, src: Path, log: list[str]) -> None:
    source = src / "skill" / "SKILL.md"
    target = paths.skill_file
    if target.exists() and SKILL_MARKER not in target.read_text(encoding="utf-8", errors="replace"):
        log.append(f"skill NOT installed: {target} exists and is not CodeSift's")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    log.append(f"Claude Code skill /sift -> {target}")


def ensure_config(paths: Paths, log: list[str]) -> None:
    paths.config.mkdir(parents=True, exist_ok=True)
    if not paths.config_file.exists():
        paths.config_file.write_text(DEFAULT_CONFIG, encoding="utf-8", newline="\n")
        log.append(f"default config -> {paths.config_file}")


def _windows_account() -> str:
    """DOMAIN\\user of the process token (GetUserNameExW, NameSamCompatible) - not from environment
    variables, which any parent process can set."""
    if sys.platform != "win32":
        raise InstallError("Windows only")
    import ctypes

    size = ctypes.c_ulong(512)
    buf = ctypes.create_unicode_buffer(size.value)
    name_sam_compatible = 2
    if not ctypes.windll.secur32.GetUserNameExW(name_sam_compatible, buf, ctypes.byref(size)):
        raise InstallError("cannot determine the current Windows account for the ACL")
    if not buf.value or any(c in buf.value for c in ':"*?<>|'):
        raise InstallError("unexpected Windows account name; ACL not changed")
    return buf.value


def _system32() -> Path:
    """The real System32 folder from the OS (GetSystemDirectoryW), not from PATH/environment."""
    if sys.platform != "win32":
        raise InstallError("Windows only")
    import ctypes

    buf = ctypes.create_unicode_buffer(260)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260):
        raise InstallError("cannot locate the Windows system directory")
    return Path(buf.value)


def _windows_user_sid() -> str:
    """String SID of the process token's user (OpenProcessToken + GetTokenInformation(TokenUser))."""
    if sys.platform != "win32":
        raise InstallError("Windows only")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]

    token_query, token_user = 0x0008, 1
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), token_query, ctypes.byref(token)):
        raise InstallError("cannot open the process token for the ACL")
    try:
        size = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, token_user, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not size.value or not advapi32.GetTokenInformation(
            token, token_user, buf, size, ctypes.byref(size)
        ):
            raise InstallError("cannot read the current Windows account for the ACL")
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]  # TOKEN_USER.User.Sid
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(text)):
            raise InstallError("cannot format the current Windows account SID")
        try:
            sid = text.value or ""
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.CloseHandle(token)
    if not sid.startswith("S-1-") or any(not (c.isdigit() or c in "S-") for c in sid):
        raise InstallError("unexpected Windows account SID; ACL not changed")
    return sid


def _set_windows_dacl(path: Path, sddl: str) -> None:
    """Replace the whole DACL (protected: nothing inherited). Unlike icacls /inheritance:r, this also
    drops explicit entries a new file got from the token's default DACL (Administrators, SYSTEM) when
    its folder had nothing to inherit."""
    if sys.platform != "win32":
        raise InstallError("Windows only")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]

    sd = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
        raise InstallError(f"cannot build the ACL (error {ctypes.get_last_error()})")
    try:
        dacl_info = 0x00000004 | 0x80000000  # DACL_SECURITY_INFORMATION | PROTECTED_DACL_...
        if not advapi32.SetFileSecurityW(str(path), dacl_info, sd):
            raise InstallError(f"cannot set the ACL on {path} (error {ctypes.get_last_error()})")
    finally:
        kernel32.LocalFree(sd)


def restrict_to_user(path: Path) -> str:
    """Owner-only access: chmod 600, or on Windows a DACL with exactly one entry, the current user
    (inherited by files created later when `path` is a folder)."""
    if sys.platform != "win32":
        path.chmod(0o600)
        return "mode 600"
    principal = _windows_account()
    inherit = "OICI" if path.is_dir() else ""
    _set_windows_dacl(path, f"D:P(A;{inherit};FA;;;{_windows_user_sid()})")
    return f"ACL: only {principal}"


def copy_credentials(paths: Paths, source: Path, log: list[str]) -> None:
    """Copy the LLM gateway settings (only those, new or 0.1.0 names) from an env file into
    gateway.env. Values are never printed."""
    from codesift.config import GATEWAY_KEYS, LEGACY_KEYS, LLM_URL, validate_base_url
    from codesift.secrets_store import save_gateway

    values = load_env_file(source)
    picked: dict[str, str] = {}
    for key in GATEWAY_KEYS:
        value = values.get(key) or values.get(LEGACY_KEYS.get(key, ""), "")
        if value:
            picked[key] = value
    if LLM_URL not in picked:
        raise InstallError(f"{source} has no LLM gateway base URL")
    validate_base_url(picked[LLM_URL])
    note = save_gateway(paths, picked)
    log.append(f"LLM gateway settings -> {paths.gateway_file} ({len(picked)} keys; {note})")


# ---------------------------------------------------------------- user PATH (Windows)


def _broadcast_env_change() -> None:
    if sys.platform != "win32":
        return
    import ctypes

    hwnd_broadcast, wm_settingchange, smto_abortifhung = 0xFFFF, 0x001A, 0x0002
    result = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(
        hwnd_broadcast, wm_settingchange, 0, "Environment", smto_abortifhung, 5000, ctypes.byref(result)
    )


def user_path_entries() -> list[str]:
    if sys.platform != "win32":
        return os.environ.get("PATH", "").split(os.pathsep)
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
        try:
            value, _ = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            return []
    return [p for p in str(value).split(";") if p]


def _set_user_path(entries: list[str]) -> None:
    if sys.platform != "win32":
        return
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, ";".join(entries))
    _broadcast_env_change()


def _same(a: str, b: str) -> bool:
    return os.path.normcase(os.path.normpath(os.path.expandvars(a))) == os.path.normcase(os.path.normpath(b))


def add_to_user_path(directory: Path, log: list[str]) -> None:
    if os.name != "nt":
        if not any(_same(p, str(directory)) for p in user_path_entries()):
            log.append(f"add {directory} to PATH in your shell profile (e.g. ~/.profile)")
        return
    entries = user_path_entries()
    if any(_same(p, str(directory)) for p in entries):
        log.append(f"{directory} already on the user PATH")
        return
    _set_user_path([*entries, str(directory)])
    log.append(f"added {directory} to the user PATH (open a new terminal to use `sift`)")


def remove_from_user_path(directory: Path, log: list[str]) -> None:
    if os.name != "nt":
        return
    entries = user_path_entries()
    keep = [p for p in entries if not _same(p, str(directory))]
    if len(keep) != len(entries):
        _set_user_path(keep)
        log.append(f"removed {directory} from the user PATH")


# ---------------------------------------------------------------- entry points


def install(
    paths: Paths,
    *,
    add_to_path: bool = False,
    credentials_from: Path | None = None,
    skill: bool = True,
) -> list[str]:
    log: list[str] = []
    src = _source()
    lock = load_lock(src / LOCK_NAME)
    paths.data.mkdir(parents=True, exist_ok=True)

    shutil.copy2(src / LOCK_NAME, paths.data / LOCK_NAME)
    shutil.copy2(src / PY_LOCK_NAME, paths.data / PY_LOCK_NAME)

    ensure_venv(paths, log)
    install_lock(paths.venv, paths.data / PY_LOCK_NAME)
    log.append("python scanners: " + ", ".join(f"{k}=={v}" for k, v in sorted(lock.python.items())))
    install_package_snapshot(paths, src, log)

    for name, tool in lock.tools.items():
        install_tool(name, lock, paths.tools)
        prune_versions(paths.tools, name, {tool.version})  # fresh install: only the pinned version
        log.append(f"{name} {tool.version} verified")
    install_rules(paths, src, lock, log)

    errors = self_test(lock, paths.tools)
    if errors:
        raise InstallError("self-test failed: " + "; ".join(errors))
    log.append("self-test passed")

    install_shims(paths, log)
    ensure_config(paths, log)
    if skill:
        install_skill(paths, src, log)
    if credentials_from is not None:
        copy_credentials(paths, credentials_from, log)
    if add_to_path:
        add_to_user_path(paths.bin, log)
    elif not any(_same(p, str(paths.bin)) for p in user_path_entries()):
        log.append(f"note: {paths.bin} is not on PATH (re-run the installer with the PATH option, or add it)")
    return log


def uninstall(paths: Paths, *, purge: bool = False) -> list[str]:
    log: list[str] = []
    remove_from_user_path(paths.bin, log)
    if paths.skill_file.is_file() and SKILL_MARKER in paths.skill_file.read_text(
        encoding="utf-8", errors="replace"
    ):
        shutil.rmtree(paths.skill, ignore_errors=True)
        log.append(f"removed skill {paths.skill}")
    for shim in (paths.bin / "sift", paths.bin / "sift.cmd"):
        if shim.is_file():
            shim.unlink()
            log.append(f"removed {shim}")
    for name in (
        "venv",
        "tools",
        "lib",
        "rules",
        "cache",
        LOCK_NAME,
        PY_LOCK_NAME,
        "tools.lock.prev.json",
        "state.json",
        "vm-selftest.json",
    ):
        target = paths.data / name
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
            log.append(f"removed {target}")
        elif target.is_file():
            target.unlink()
            log.append(f"removed {target}")
    keep = [p for p in (paths.runs, paths.config) if p.exists()]
    if purge:
        for p in keep:
            shutil.rmtree(p, ignore_errors=True)
            log.append(f"removed {p}")
    elif keep:
        log.append("kept (use --purge to delete): " + ", ".join(str(p) for p in keep))
    if paths.bin.is_dir() and not any(paths.bin.iterdir()):
        paths.bin.rmdir()
    if paths.data.is_dir() and not any(paths.data.iterdir()):
        paths.data.rmdir()
    return log
