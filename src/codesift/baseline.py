"""Accepted findings: `.codesift-baseline.json` in the scanned project (committed by the user).

Entries match by fingerprint (no line numbers), carry a reason, who/when, and an optional expiry.
Writing the file only ever happens on an explicit `sift baseline accept/prune`."""

from __future__ import annotations

import getpass
import json
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Any

from codesift.config import BASELINE_NAME
from codesift.finding import Finding
from codesift.gitutil import git


class BaselineError(Exception):
    pass


@dataclass
class Entry:
    fingerprint: str
    tool: str
    rule: str
    path: str
    reason: str
    accepted_by: str
    accepted_at: str
    expires: str = ""  # YYYY-MM-DD or ""
    message: str = ""

    def expired(self, today: date | None = None) -> bool:
        if not self.expires:
            return False
        return date.fromisoformat(self.expires) < (today or date.today())


def baseline_path(root: Path) -> Path:
    return root / BASELINE_NAME


def load(root: Path) -> list[Entry]:
    path = baseline_path(root)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise BaselineError(f"{path}: invalid JSON ({exc})") from None
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("entries"), list):
        raise BaselineError(f"{path}: expected {{'version': 1, 'entries': [...]}}")
    entries = []
    for i, e in enumerate(data["entries"]):
        try:
            entry = Entry(**{k: e[k] for k in Entry.__dataclass_fields__ if k in e})
            if entry.expires:
                date.fromisoformat(entry.expires)
        except (TypeError, ValueError, KeyError) as exc:
            raise BaselineError(f"{path}: entry {i} is invalid ({exc})") from None
        entries.append(entry)
    return entries


def save(root: Path, entries: list[Entry]) -> Path:
    path = baseline_path(root)
    entries = sorted(entries, key=lambda e: (e.path, e.tool, e.rule, e.fingerprint))
    data: dict[str, Any] = {
        "version": 1,
        "about": "Accepted CodeSift findings. Edit only via `sift baseline accept/prune`.",
        "entries": [asdict(e) for e in entries],
    }
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def apply(findings: list[Finding], entries: list[Entry], today: date | None = None) -> list[Entry]:
    """Mark findings covered by a non-expired entry. Returns expired entries that matched a finding."""
    active = {e.fingerprint: e for e in entries if not e.expired(today)}
    expired = {e.fingerprint: e for e in entries if e.expired(today)}
    hit_expired: list[Entry] = []
    for f in findings:
        for fp in f.all_fingerprints:
            if fp in active:
                f.baseline = True
                f.baseline_reason = active[fp].reason
                break
            if fp in expired and expired[fp] not in hit_expired:
                hit_expired.append(expired[fp])
    return hit_expired


def who(root: Path) -> str:
    name = (git(root, "config", "user.name") or "").strip()
    if name:
        return name
    try:
        return getpass.getuser()
    except (OSError, KeyError):
        return "unknown"


def accept(
    root: Path, findings: list[Finding], ids: list[str], reason: str, expires: str | None
) -> list[Entry]:
    if not reason.strip():
        raise BaselineError("a non-empty --reason is required")
    if expires:
        try:
            if date.fromisoformat(expires) <= date.today():
                raise BaselineError("--expires must be a future date (YYYY-MM-DD)")
        except ValueError:
            raise BaselineError("--expires must be YYYY-MM-DD") from None
    by_id = {f.id.upper(): f for f in findings}
    missing = [i for i in ids if i.upper() not in by_id]
    if missing:
        raise BaselineError(f"unknown finding id(s) in the latest report: {', '.join(missing)}")
    entries = load(root)
    known = {e.fingerprint for e in entries}
    added: list[Entry] = []
    today = date.today().isoformat()
    user = who(root)
    for i in ids:
        f = by_id[i.upper()]
        if f.fingerprint in known:
            continue
        entry = Entry(
            fingerprint=f.fingerprint,
            tool=f.tool,
            rule=f.rule,
            path=f.path,
            reason=reason.strip(),
            accepted_by=user,
            accepted_at=today,
            expires=expires or "",
            message=f.message[:160],
        )
        entries.append(entry)
        known.add(f.fingerprint)
        added.append(entry)
    if added:
        save(root, entries)
    return added


def prune(root: Path, findings: list[Finding] | None) -> list[Entry]:
    """Remove expired entries, and (when a full-scan report is given) entries no finding matches."""
    entries = load(root)
    seen: set[str] = set()
    if findings is not None:
        for f in findings:
            seen.update(f.all_fingerprints)
    keep, removed = [], []
    for e in entries:
        if e.expired() or (findings is not None and e.fingerprint not in seen):
            removed.append(e)
        else:
            keep.append(e)
    if removed:
        save(root, keep)
    return removed
