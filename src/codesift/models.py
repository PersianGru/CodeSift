"""Shared constants: exit codes and severities."""

from __future__ import annotations

from enum import IntEnum

# Exit codes (README "Exit codes")
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_LLM_UNAVAILABLE = 3


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from None

    @property
    def label(self) -> str:
        return self.name.lower()
