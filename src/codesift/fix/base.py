"""Fixer protocol and the JSON search/replace edit protocol (ADR-0013).

Model output is untrusted: the edit protocol accepts one JSON object
`{"edits":[{"path","search","replace"}],"explanation"}`; `search` must occur exactly once; `path`
must be an allowed file inside the workspace (resolved, no traversal, no symlink escape). The patch
policy still checks the resulting diff, whatever the model claims."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codesift.finding import Finding

MAX_EDITS = 10
MAX_EDIT_TEXT = 20_000


class EditError(ValueError):
    """Malformed or unsafe edit. The message is mechanical (fed back to the next attempt)."""


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def add(self, other: Usage) -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens


@dataclass
class FixRequest:
    finding: Finding  # redacted
    path: str
    content: str  # redacted, capped
    allowed_paths: list[str]
    workspace: Path
    feedback: list[str] = field(default_factory=list)  # mechanical failure messages only
    attempt: int = 1


@dataclass
class FixResult:
    ok: bool
    explanation: str = ""
    error: str = ""
    model: str = ""
    usage: Usage = field(default_factory=Usage)
    applied: list[str] = field(default_factory=list)


class Fixer(Protocol):
    name: str

    def fix(self, request: FixRequest) -> FixResult: ...


@dataclass
class Edit:
    path: str
    search: str
    replace: str


def extract_json(text: str) -> Any:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except ValueError:
                pass
    raise EditError("the answer is not a JSON object")


def parse_edits(text: str) -> tuple[list[Edit], str]:
    data = extract_json(text)
    if not isinstance(data, dict):
        raise EditError("the answer is not a JSON object")
    raw = data.get("edits")
    if not isinstance(raw, list) or not raw:
        raise EditError('"edits" must be a non-empty list')
    if len(raw) > MAX_EDITS:
        raise EditError(f"at most {MAX_EDITS} edits")
    edits = []
    for i, e in enumerate(raw):
        if not isinstance(e, dict):
            raise EditError(f"edit {i} is not an object")
        values = [e.get(k) for k in ("path", "search", "replace")]
        if not all(isinstance(v, str) for v in values):
            raise EditError(f"edit {i} needs string path, search and replace")
        path, search, replace = (str(v) for v in values)
        if not search:
            raise EditError(f"edit {i}: search is empty")
        if len(search) > MAX_EDIT_TEXT or len(replace) > MAX_EDIT_TEXT:
            raise EditError(f"edit {i}: text too long")
        path = path.replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        edits.append(Edit(path, search, replace))
    return edits, " ".join(str(data.get("explanation", "")).split())[:500]


def resolve_allowed(workspace: Path, rel: str, allowed: list[str]) -> Path:
    if rel not in allowed:
        raise EditError(f"{rel} is not an allowed path ({', '.join(allowed)})")
    root = workspace.resolve()
    target = (workspace / rel).resolve()
    if not target.is_relative_to(root) or target == root:
        raise EditError(f"{rel} is outside the workspace")
    probe = workspace / rel
    for parent in [probe, *probe.parents]:
        if parent == workspace:
            break
        if parent.is_symlink():
            raise EditError(f"{rel} goes through a symlink")
    if not target.is_file():
        raise EditError(f"{rel} does not exist in the workspace")
    return target


def apply_edits(workspace: Path, edits: list[Edit], allowed: list[str]) -> list[str]:
    """Apply all edits or none. Each `search` must occur exactly once in its file."""
    staged: dict[Path, str] = {}
    for i, e in enumerate(edits):
        target = resolve_allowed(workspace, e.path, allowed)
        text = staged.get(target)
        if text is None:
            text = target.read_bytes().decode("utf-8")
        count = text.count(e.search)
        if count != 1:
            raise EditError(f"edit {i}: search text found {count} times in {e.path} (must be exactly once)")
        staged[target] = text.replace(e.search, e.replace, 1)
    for target, text in staged.items():
        target.write_bytes(text.encode("utf-8"))
    return sorted({e.path for e in edits})
