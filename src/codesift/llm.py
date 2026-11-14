"""Compatibility module: the LLM client moved to `codesift.gateway` (ADR-0014)."""

from __future__ import annotations

from codesift.gateway import (
    IDLE_TIMEOUT_S,
    MAX_RESPONSE_BYTES,
    MAX_RETRY_AFTER_S,
    MAX_STREAM_BYTES,
    BifrostClient,
    ChatResult,
    ClientSettings,
    GatewayClient,
    LLMError,
    ModelSession,
)

__all__ = [
    "IDLE_TIMEOUT_S",
    "MAX_RESPONSE_BYTES",
    "MAX_RETRY_AFTER_S",
    "MAX_STREAM_BYTES",
    "BifrostClient",
    "ChatResult",
    "ClientSettings",
    "GatewayClient",
    "LLMError",
    "ModelSession",
]
