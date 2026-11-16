"""In-process activity signals for `sift ui`: real LLM calls and VM commands, as they happen.

The gateway client and the SSH transport call `signal()`; a run (`sift scan`, `sift fix`) that writes
an events.jsonl subscribes with `listening()` and turns each signal into an event. With no listener,
`signal()` does nothing. Signals carry only metadata (model ids, sizes, timings, exit codes) - never
prompts, answers, commands' arguments or output."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from typing import Any

Listener = Callable[[str, dict[str, Any]], None]

_lock = threading.Lock()
_listeners: list[Listener] = []
_context = threading.local()


def signal(kind: str, **data: Any) -> None:
    """Tell every listener that `kind` happened. Never raises: telemetry must not break a run."""
    with _lock:
        listeners = list(_listeners)
    if not listeners:
        return
    purpose = getattr(_context, "purpose", None)
    if purpose and "purpose" not in data:
        data["purpose"] = purpose
    finding = getattr(_context, "finding", None)
    if finding and "finding" not in data:
        data["finding"] = finding
    for listener in listeners:
        with suppress(Exception):  # a broken listener must never stop the work
            listener(kind, dict(data))


@contextmanager
def listening(listener: Listener) -> Iterator[None]:
    with _lock:
        _listeners.append(listener)
    try:
        yield
    finally:
        with _lock:
            if listener in _listeners:
                _listeners.remove(listener)


@contextmanager
def doing(purpose: str, finding: str | None = None) -> Iterator[None]:
    """Label the signals sent from this thread (e.g. 'triage' of F003) until the block ends."""
    old = (getattr(_context, "purpose", None), getattr(_context, "finding", None))
    _context.purpose, _context.finding = purpose, finding
    try:
        yield
    finally:
        _context.purpose, _context.finding = old
