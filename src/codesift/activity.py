"""What `sift ui` needs to draw a run as it really is: the topology (which scanners, which gateway
host and models, which VM) at the start, and every real LLM call / VM command while it runs.

Only metadata goes into events.jsonl: host names, model ids, sizes, timings, exit codes."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlsplit

from codesift import telemetry
from codesift.paths import Paths
from codesift.validate.events import EventLog

_FINDING = re.compile(r"^[A-Z]{1,8}[0-9]{1,6}$")


def topology(paths: Paths, scanners: list[str] | None = None) -> dict[str, Any]:
    """Who takes part in a run. Every part is optional: a missing setting is simply left out."""
    out: dict[str, Any] = {"scanners": list(scanners or [])}
    try:
        from codesift.config import load_credentials, load_user_config, model_overrides

        user = load_user_config(paths)
        creds = load_credentials(paths, allow_http_localhost=user.allow_http_localhost)
        if creds is not None:
            over = model_overrides(paths)
            out["llm"] = {
                "host": urlsplit(creds.base_url).hostname or "",
                "model": over.get("model", user.llm.model),
                "fallback": over.get("fallback_model", user.llm.fallback_model or ""),
            }
    except Exception:  # noqa: S110 - the picture is optional; the run must not fail on it
        pass
    try:
        from codesift.vm.config import load_vm_config

        vm = load_vm_config(paths)
        out["vm"] = {"host": vm.host, "user": vm.user, "runtime": vm.runtime, "image": vm.image}
    except Exception:  # noqa: S110 - no VM configured is normal for `sift scan`
        pass
    return out


def forwarder(log: EventLog) -> Callable[[str, dict[str, Any]], None]:
    def forward(kind: str, data: dict[str, Any]) -> None:
        finding = data.pop("finding", None)
        if not (isinstance(finding, str) and _FINDING.match(finding)):
            finding = None
        log.note(kind, finding, **data)

    return forward


@contextmanager
def recording(log: EventLog) -> Iterator[None]:
    """Write every real LLM call and VM command made inside the block into `log`."""
    with telemetry.listening(forwarder(log)):
        yield
