# ADR-0016: Project-supplied PoCs only in 0.2.0

- Status: accepted
- Date: 2026-11-14
- Amends: [ADR-0011](ADR-0011-scope-0.2.0.md) (PoC scope)

## Context

The original 0.2.0 plan included built-in "canned probes" per vulnerability class and LLM-drafted
PoCs behind `--poc llm`. Building them was deferred during implementation.

## Decision

0.2.0 supports only project-supplied PoC commands from `[validate.poc]`. `--poc` accepts `none`
and `project` (default). For findings without a configured PoC, the PoC gates are "unavailable",
and such a finding can at best be `fixed_unproven` unless project tests apply. `[validate.entry]`
is accepted in the config but not used.

## Consequences

- Fewer findings reach `fixed_verified` without project help; the report says so explicitly.
- Canned probes and drafted PoCs can be added later behind their own ADR.
