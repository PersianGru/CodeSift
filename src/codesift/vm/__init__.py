"""Sandbox VM backend: untrusted work runs only in disposable, network-less containers on a remote
VM reached over SSH (ADR-0012). Nothing in this package executes project code on the host."""

from __future__ import annotations


class SandboxError(Exception):
    """The sandbox refused or failed. Commands fail closed on this error (RULES.md rule 11).
    Messages never contain secret values."""

    def __init__(self, message: str, fix: str = "") -> None:
        super().__init__(message)
        self.fix = fix
