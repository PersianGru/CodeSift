#!/bin/sh
# codesift-gate: forced command for CodeSift's sandbox SSH key (authorized_keys: restrict,command=...).
# Allows only the exact job shape and read-only probes that CodeSift generates; everything else exits
# 126. Generated from codesift/vm/admin.py (GATE_PATTERNS) - do not edit by hand.
# Optional: /etc/codesift-gate.images lists the only images (one per line) jobs may use.
set -u
cmd="${SSH_ORIGINAL_COMMAND:-}"
nl='
'
cr=$(printf '\r')
deny() { echo "codesift-gate: command refused" >&2; exit 126; }
[ -n "$cmd" ] || deny
[ "${#cmd}" -le 16384 ] || deny
case "$cmd" in *"$nl"*|*"$cr"*) deny ;; esac
allowed=0
while IFS= read -r re; do
    [ -n "$re" ] || continue
    if printf '%s\n' "$cmd" | grep -Eq -- "$re"; then allowed=1; break; fi
done <<'PATTERNS'
^cat /proc/meminfo$
^(docker|podman) version --format '\{\{\.Client\.Version\}\}'$
^(docker|podman) ps -q --filter label=codesift\.job$
^(docker|podman) ps -aq --filter label=codesift\.job(=[0-9a-f]{32})?$
^(docker|podman) rm -f [0-9a-f]{12,64}( [0-9a-f]{12,64}){0,49}$
^(docker|podman) image inspect --format '\{\{\.Id\}\}' [A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$
^(docker|podman) image pull [A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$
^(docker|podman) build --tag sift-[a-z0-9._-]{1,64}(:[A-Za-z0-9._-]{1,64})? -$
^(docker|podman) run --rm -i --pull=never --name sift-[0-9a-f]{32} --label codesift\.job=[0-9a-f]{32} --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --tmpfs /work:rw,exec,nosuid,size=256m --pids-limit [0-9]{1,5} --memory [0-9]{1,6}m --memory-swap [0-9]{1,6}m --cpus [0-9]{1,2}(\.[0-9]{1,2})? --ulimit nofile=1024:1024 --ulimit fsize=[0-9]{1,12} --user 65534:65534 --workdir /work [A-Za-z0-9][A-Za-z0-9._/:@-]{0,254} sh -c '[^']*'("'"'[^']*')*$
PATTERNS
[ "$allowed" -eq 1 ] || deny
if [ -f /etc/codesift-gate.images ]; then
    img=$(printf '%s\n' "$cmd" | sed -n "s/^[^']* --workdir \/work \([^ ]*\) sh -c .*$/\1/p")
    case "$cmd" in *" image inspect "*|*" image pull "*) img="${cmd##* }" ;; esac
    if [ -n "$img" ]; then grep -Fxq -- "$img" /etc/codesift-gate.images || deny; fi
fi
exec /bin/sh -c "$cmd"
