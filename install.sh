#!/bin/sh
# Install (or uninstall) CodeSift for the current user (Linux / macOS). No root needed.
#
#   ./install.sh                                  install (asks before copying credentials)
#   ./install.sh --credentials-from FILE          copy LLM gateway settings from FILE (mode 600)
#   ./install.sh --no-skill --yes                 non-interactive
#   ./install.sh --uninstall [--purge]            remove (--purge also deletes runs, settings, keys)
set -eu

ROOT=$(cd "$(dirname "$0")" && pwd)
CREDS=""
NO_SKILL=""
UNINSTALL=""
PURGE=""
YES=""
while [ $# -gt 0 ]; do
    case "$1" in
        --credentials-from) CREDS="$2"; shift 2 ;;
        --no-skill) NO_SKILL="--no-skill"; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --purge) PURGE="--purge"; shift ;;
        --yes|-y) YES=1; shift ;;
        -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

PY=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
        "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        PY=$(command -v "$candidate")
        break
    fi
done
if [ -z "$PY" ]; then
    echo "Python 3.11 or newer (with the venv module) is required." >&2
    exit 2
fi
export PYTHONPATH="$ROOT/src"

if [ -n "$UNINSTALL" ]; then
    exec "$PY" -m codesift uninstall $PURGE
fi

CONFIG_DIR="${CODESIFT_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/codesift}"
if [ -z "$CREDS" ] && [ -z "$YES" ] && [ ! -f "$CONFIG_DIR/gateway.env" ] && [ -t 0 ]; then
    echo "LLM triage needs an LLM gateway. Recommended: run 'sift setup' after the install."
    printf "Or the path of an env file to copy the gateway settings from (Enter to skip; values are never shown): "
    read -r CREDS || CREDS=""
fi

set -- -m codesift install
[ -n "$NO_SKILL" ] && set -- "$@" "$NO_SKILL"
[ -n "$CREDS" ] && set -- "$@" --credentials-from "$CREDS"
"$PY" "$@"

BIN="${CODESIFT_HOME:+$CODESIFT_HOME/bin}"
BIN="${BIN:-$HOME/.local/bin}"
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "Add $BIN to your PATH (e.g. in ~/.profile): export PATH=\"$BIN:\$PATH\"" ;;
esac
echo "Next: run 'sift setup' (LLM gateway, sandbox VM, fixers), then 'sift doctor', then 'sift scan'."
echo "In Claude Code: /sift"
