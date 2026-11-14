"""Recorded consent for the external fixer backends (RULES.md rule 15). Without a record whose text
matches the current wording, the Claude backends are unusable."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from codesift.paths import Paths

EXTERNAL = ("claude-cli", "claude-api")
CONSENT_TEXT = {
    "claude-cli": (
        "The Claude CLI runs in a copy of the project with secret files removed (.env, keys, certificates, "
        "files with a secret finding, never_send globs). The files it reads are sent to Anthropic."
    ),
    "claude-api": (
        "Redacted excerpts of the file with the finding, the finding metadata and mechanical failure "
        "messages are sent to api.anthropic.com. Secrets are masked; whole repositories are never sent."
    ),
}


class ConsentError(Exception):
    pass


def load(paths: Paths) -> dict[str, dict[str, object]]:
    try:
        data = json.loads(paths.consent_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}


def record(paths: Paths, backend: str, enabled: bool) -> None:
    from codesift.secrets_store import write_json

    if backend not in EXTERNAL:
        raise ConsentError(f"{backend} needs no consent")
    data = load(paths)
    data[backend] = {
        "enabled": enabled,
        "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "text": CONSENT_TEXT[backend],
    }
    write_json(paths.consent_file, data)


def has_consent(paths: Paths, backend: str) -> bool:
    if backend not in EXTERNAL:
        return True
    entry = load(paths).get(backend)
    return bool(entry and entry.get("enabled") is True and entry.get("text") == CONSENT_TEXT[backend])


def require(paths: Paths, backend: str) -> None:
    if not has_consent(paths, backend):
        raise ConsentError(f"{backend} has no recorded consent - run `sift setup --fixers` to enable it")
