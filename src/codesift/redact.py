"""Secret masking. Every string that leaves CodeSift (reports, raw outputs, logs, LLM prompts)
must pass through a Redactor first. A masked value looks like `abcd…(len 40)`."""

from __future__ import annotations

import re
from collections.abc import Iterable

ELLIPSIS = "…"
MIN_SECRET_LEN = 6

# Generic secret shapes. Each pattern's group "secret" is what gets masked.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Authorization headers / bearer tokens
    re.compile(r"(?i)\b(?:bearer|token|basic)\s+(?P<secret>[A-Za-z0-9._~+/=-]{12,})"),
    # Credentials embedded in URLs: scheme://user:pass@host
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]*:(?P<secret>[^@\s/]{3,})@"),
    # key=value / key: value with a secret-ish key name
    re.compile(
        r"(?i)\b[\w.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|private[_-]?key|access[_-]?key)"
        r"[\w.-]*\s*[=:]\s*[\"']?(?P<secret>[^\s\"',;&]{6,})"
    ),
    # Well-known token prefixes
    re.compile(
        r"\b(?P<secret>(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}"
        r"|xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}))"
    ),
)

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<kind>[A-Z0-9 ]*)PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)


def mask(value: str, keep: int = 4) -> str:
    """Return a safe stand-in for a secret: first `keep` chars + length.
    Short values (< 3*keep) reveal nothing but their length."""
    n = len(value)
    if n < keep * 3:
        return f"{ELLIPSIS}(len {n})"
    return f"{value[:keep]}{ELLIPSIS}(len {n})"


class Redactor:
    """Masks known secret values (exact match) and generic secret shapes in text."""

    def __init__(self, secrets: Iterable[str] = (), patterns: bool = True) -> None:
        self._secrets: set[str] = set()
        self._patterns = patterns
        for s in secrets:
            self.add(s)

    def add(self, secret: str | None) -> None:
        if secret and len(secret) >= MIN_SECRET_LEN:
            self._secrets.add(secret)

    def __len__(self) -> int:
        return len(self._secrets)

    def known(self) -> list[str]:
        """The exact values being masked (for handing on to another Redactor; never print them)."""
        return sorted(self._secrets)

    def scrub(self, text: str) -> str:
        if not text:
            return text
        # Longest first so a secret that contains another is masked whole.
        for secret in sorted(self._secrets, key=len, reverse=True):
            if secret in text:
                text = text.replace(secret, mask(secret))
        if not self._patterns:
            return text
        text = _PRIVATE_KEY_BLOCK.sub(lambda m: f"-----{m.group('kind')}PRIVATE KEY (redacted)-----", text)
        for pattern in _PATTERNS:
            text = pattern.sub(_mask_group, text)
        return text


def _mask_group(match: re.Match[str]) -> str:
    whole = match.group(0)
    secret = match.group("secret")
    if ELLIPSIS in secret:  # already masked
        return whole
    start = match.start("secret") - match.start(0)
    end = start + len(secret)
    return whole[:start] + mask(secret) + whole[end:]
