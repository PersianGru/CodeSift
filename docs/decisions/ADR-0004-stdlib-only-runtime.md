# ADR-0004: Standard-library-only runtime

- Status: accepted
- Date: 2026-11-12

## Context

CodeSift is itself security tooling. Every runtime dependency is supply-chain surface and install
weight.

## Decision

The CodeSift package uses only the Python standard library at runtime (`urllib` for HTTPS, `json`,
`tomllib`, `subprocess`, `hashlib`). Python ≥ 3.11 is required for `tomllib`. The Python-based
scanners (ruff, bandit, pip-audit, zizmor) are installed into CodeSift's own venv from a hashed lock
file (`--require-hashes`); they are run as subprocesses, not imported. Dev tools (pytest, mypy, ruff,
black) are a `dev` extra only.

## Consequences

Adding a runtime dependency requires a new ADR that explains why it pays off.
