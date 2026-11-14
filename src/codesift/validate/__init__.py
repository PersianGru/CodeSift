"""Validate/fix engine: workspace copies, safe packing, mechanical patch policy, deterministic gates,
event log and reports. The user's project is never written (RULES.md rule 2)."""

from __future__ import annotations


class ValidateError(Exception):
    """Configuration or tool error for validate/fix (exit 2). Never contains secret values."""
