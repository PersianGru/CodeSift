"""The VM administrator's side: a reviewed setup script (printed, never executed by CodeSift) and the
forced-command gate `codesift-gate`.

The gate's allow-list is defined once here (`GATE_PATTERNS`, POSIX ERE that Python's `re` reads the
same way). `render_gate()` produces the shipped `codesift-gate.sh`; a test checks they are identical,
and `gate_allows()` is the Python mirror used to test the allow/deny table."""

from __future__ import annotations

import re
from importlib import resources

from codesift.vm import SandboxError
from codesift.vm.config import IMAGE_RE, VMConfig
from codesift.vm.sshargs import validate_user

GATE_PATH = "/usr/local/bin/codesift-gate"
GATE_IMAGES = "/etc/codesift-gate.images"
GATE_DENY_RC = 126
MAX_GATE_COMMAND = 16384
SCRIPT_FAILED_RC = 10  # admin_script: a step failed (sudo/doas refusing the password exits 1)

_RT = "(docker|podman)"
_ID = "[0-9a-f]{32}"
_IMG = "[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}"
_QWORD = "'[^']*'(\"'\"'[^']*')*"  # exactly one shlex.quote()d word

GATE_PATTERNS: tuple[str, ...] = (
    "^cat /proc/meminfo$",
    f"^{_RT} version --format '\\{{\\{{\\.Client\\.Version\\}}\\}}'$",
    f"^{_RT} ps -q --filter label=codesift\\.job$",
    f"^{_RT} ps -aq --filter label=codesift\\.job(={_ID})?$",
    f"^{_RT} rm -f [0-9a-f]{{12,64}}( [0-9a-f]{{12,64}}){{0,49}}$",
    f"^{_RT} image inspect --format '\\{{\\{{\\.Id\\}}\\}}' {_IMG}$",
    f"^{_RT} image pull {_IMG}$",
    f"^{_RT} build --tag sift-[a-z0-9._-]{{1,64}}(:[A-Za-z0-9._-]{{1,64}})? -$",
    (
        f"^{_RT} run --rm -i --pull=never --name sift-{_ID} --label codesift\\.job={_ID} --network none "
        "--cap-drop ALL --security-opt no-new-privileges --read-only "
        "--tmpfs /tmp:rw,noexec,nosuid,size=64m --tmpfs /work:rw,exec,nosuid,size=256m "
        "--pids-limit [0-9]{1,5} --memory [0-9]{1,6}m --memory-swap [0-9]{1,6}m "
        "--cpus [0-9]{1,2}(\\.[0-9]{1,2})? --ulimit nofile=1024:1024 --ulimit fsize=[0-9]{1,12} "
        f"--user 65534:65534 --workdir /work {_IMG} sh -c {_QWORD}$"
    ),
)

_COMPILED = tuple(re.compile(p) for p in GATE_PATTERNS)
_RUN_IMAGE = re.compile(r"^[^']* --workdir /work ([^ ]+) sh -c ")


def _image_of(command: str) -> str | None:
    m = _RUN_IMAGE.match(command)
    if m:
        return m.group(1)
    if " image inspect " in command or " image pull " in command:
        return command.rsplit(" ", 1)[-1]
    return None


def gate_allows(command: str, images: list[str] | None = None) -> bool:
    """Python mirror of codesift-gate. `images` = contents of the optional images file."""
    if not command or len(command) > MAX_GATE_COMMAND or any(c in command for c in "\n\r\x00"):
        return False
    if not any(p.search(command) for p in _COMPILED):
        return False
    if images is not None:
        image = _image_of(command)
        if image is not None and image not in images:
            return False
    return True


def render_gate() -> str:
    patterns = "\n".join(GATE_PATTERNS)
    return f"""#!/bin/sh
# codesift-gate: forced command for CodeSift's sandbox SSH key (authorized_keys: restrict,command=...).
# Allows only the exact job shape and read-only probes that CodeSift generates; everything else exits
# {GATE_DENY_RC}. Generated from codesift/vm/admin.py (GATE_PATTERNS) - do not edit by hand.
# Optional: {GATE_IMAGES} lists the only images (one per line) jobs may use.
set -u
cmd="${{SSH_ORIGINAL_COMMAND:-}}"
nl='
'
cr=$(printf '\\r')
deny() {{ echo "codesift-gate: command refused" >&2; exit {GATE_DENY_RC}; }}
[ -n "$cmd" ] || deny
[ "${{#cmd}}" -le {MAX_GATE_COMMAND} ] || deny
case "$cmd" in *"$nl"*|*"$cr"*) deny ;; esac
allowed=0
while IFS= read -r re; do
    [ -n "$re" ] || continue
    if printf '%s\\n' "$cmd" | grep -Eq -- "$re"; then allowed=1; break; fi
done <<'PATTERNS'
{patterns}
PATTERNS
[ "$allowed" -eq 1 ] || deny
if [ -f {GATE_IMAGES} ]; then
    img=$(printf '%s\\n' "$cmd" | sed -n "s/^[^']* --workdir \\/work \\([^ ]*\\) sh -c .*$/\\1/p")
    case "$cmd" in *" image inspect "*|*" image pull "*) img="${{cmd##* }}" ;; esac
    if [ -n "$img" ]; then grep -Fxq -- "$img" {GATE_IMAGES} || deny; fi
fi
exec /bin/sh -c "$cmd"
"""


def shipped_gate() -> str:
    return resources.files("codesift.vm").joinpath("codesift-gate.sh").read_text(encoding="utf-8")


_PUBKEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]{40,100}={0,2}( [A-Za-z0-9@._-]{1,64})?$")


def validate_public_key(pubkey: str) -> str:
    key = pubkey.strip()
    if not _PUBKEY.match(key):
        raise SandboxError("the public key must be one ssh-ed25519 line")
    return key


def authorized_keys_line(pubkey: str, gate: bool = True) -> str:
    key = validate_public_key(pubkey)
    if gate:
        return f'restrict,command="{GATE_PATH}" {key}'
    return f"restrict {key}"


def admin_script(cfg: VMConfig, pubkey: str) -> str:
    """The one-time VM setup, run as root: by `sift setup --vm` over the admin's own SSH login, or by
    hand from `sift vm admin-script`. Idempotent: re-running it changes nothing that is already right."""
    user = validate_user(cfg.user)
    if not IMAGE_RE.match(cfg.image):
        raise SandboxError("invalid image reference")
    line = authorized_keys_line(pubkey)
    runtime_block = DOCKER_BLOCK if cfg.runtime == "docker" else PODMAN_BLOCK
    # S608/B608 below: a shell script for the VM, not SQL ("update ... set" trips the SQL heuristic).
    return f"""#!/bin/sh
# CodeSift sandbox - one-time setup of the VM, run as root. Safe to run again.
# Creates the unprivileged user '{user}', makes sure the container runtime is installed and running,
# installs the forced-command gate and authorises CodeSift's key ONLY through that gate.
set -eu
#    Any failure below exits {SCRIPT_FAILED_RC} (4 and 5 are reported with their own message), so the
#    caller can tell it apart from sudo/doas refusing the password, which exits 1 before this runs.
trap 'rc=$?; case $rc in 0|4|5) ;; *) exit {SCRIPT_FAILED_RC} ;; esac' EXIT
U='{user}'
say() {{ printf 'codesift: %s\\n' "$*"; }}

# 0. Package manager (only used when something is missing).
PKG=
for p in apk apt-get dnf yum zypper pacman; do
    if command -v "$p" >/dev/null 2>&1; then PKG=$p; break; fi
done
install_pkg() {{
    say "installing $* with ${{PKG:-?}}"
    case "$PKG" in
        apk) apk add --no-cache "$@" ;;
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq && apt-get install -y -qq "$@" ;;
        dnf) dnf install -y -q "$@" ;;
        yum) yum install -y -q "$@" ;;
        zypper) zypper --non-interactive install "$@" ;;
        pacman) pacman -S --noconfirm --needed "$@" ;;
        *) say "no known package manager - install $* yourself and run this again"; exit 4 ;;
    esac
}}
start_service() {{
    if command -v rc-service >/dev/null 2>&1; then
        rc-update add "$1" default >/dev/null 2>&1 || true
        rc-service "$1" start >/dev/null 2>&1 || true
    elif command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now "$1" >/dev/null 2>&1 || true
    else
        service "$1" start >/dev/null 2>&1 || true
    fi
}}

# 1. Dedicated user: no sudo, no usable password, login only with CodeSift's key through the gate.
if id "$U" >/dev/null 2>&1; then
    say "user $U exists"
else
    adduser -D -s /bin/sh "$U" 2>/dev/null || useradd -m -s /bin/sh "$U"
    say "created user $U"
fi
#    '*' = no password can ever match. Not '!' (locked): sshd without PAM (Alpine) refuses key logins
#    for locked accounts.
printf '%s:*\\n' "$U" | chpasswd -e

# 2. Container runtime: installed, running, and usable by $U.
{runtime_block.rstrip()}

# 3. The gate (allow-list of exact commands; everything else exits {GATE_DENY_RC}).
cat > {GATE_PATH} <<'CODESIFT_GATE'
{render_gate().rstrip()}
CODESIFT_GATE
chown root:root {GATE_PATH}
chmod 0755 {GATE_PATH}
say "gate installed at {GATE_PATH}"

# 4. Pin the images jobs may use.
printf '%s\\n' '{cfg.image}' > {GATE_IMAGES}
chmod 0644 {GATE_IMAGES}

# 5. Authorise CodeSift's key through the gate only (no forwarding, no pty). Added once.
H=$(getent passwd "$U" | cut -d: -f6)
mkdir -p "$H/.ssh"
touch "$H/.ssh/authorized_keys"
KEYLINE='{line}'
if grep -qxF "$KEYLINE" "$H/.ssh/authorized_keys"; then
    say "key already authorised"
else
    printf '%s\\n' "$KEYLINE" >> "$H/.ssh/authorized_keys"
    say "key authorised"
fi
chown -R "$U" "$H/.ssh"
chmod 700 "$H/.ssh"
chmod 600 "$H/.ssh/authorized_keys"

# 6. sshd must let $U in. Only checked, never edited.
if command -v sshd >/dev/null 2>&1; then
    ALLOW=$(sshd -T 2>/dev/null | grep -iE '^allow(users|groups) ' || true)
    if [ -n "$ALLOW" ]; then
        say "WARNING: sshd has AllowUsers/AllowGroups set - add $U there, or CodeSift cannot log in:"
        say "  $ALLOW"
    fi
fi
say "done: user $U can now run only CodeSift sandbox jobs"
"""  # noqa: S608  # nosec B608 - a shell script for the VM, not SQL


DOCKER_BLOCK = """\
if ! command -v docker >/dev/null 2>&1; then
    case "$PKG" in
        apt-get) install_pkg docker.io ;;
        dnf|yum) install_pkg moby-engine 2>/dev/null || install_pkg docker ;;
        *) install_pkg docker ;;
    esac
fi
if ! docker info >/dev/null 2>&1; then
    say "starting the docker service"
    start_service docker
    i=0
    while ! docker info >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -gt 30 ]; then
            say "docker is installed but not running - start it and run this again"; exit 5
        fi
        sleep 1
    done
fi
say "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?') is running"
getent group docker >/dev/null 2>&1 || groupadd docker 2>/dev/null || addgroup docker
#    NOTE: membership in the docker group is root-equivalent on this VM. The gate below limits what
#    CodeSift's key can run to the fixed, network-less job shape. Use a lab VM, never production.
addgroup "$U" docker 2>/dev/null || usermod -aG docker "$U"
"""

PODMAN_BLOCK = """\
command -v podman >/dev/null 2>&1 || install_pkg podman
#    podman runs rootless as "$U": it needs subuid/subgid ranges (see docs/vm-setup.md).
grep -q "^$U:" /etc/subuid 2>/dev/null || printf '%s:200000:65536\\n' "$U" >> /etc/subuid
grep -q "^$U:" /etc/subgid 2>/dev/null || printf '%s:200000:65536\\n' "$U" >> /etc/subgid
say "podman $(podman --version 2>/dev/null || echo '?')"
"""
