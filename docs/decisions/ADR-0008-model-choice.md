# ADR-0008: Triage model and thinking mode

- Status: accepted
- Date: 2026-11-12

## Context

ADR-0001 named qwen3.8:27b-mtp as primary and qwen3-coder:30b as fallback, to be confirmed by a
bake-off. The bake-off (docs/model-eval.md) ran 19 labelled cases (11 real, 8 false positives)
through the production prompt on both models, with thinking on and with `/no_think`.

## Decision

- Primary: `ollama/qwen3.8:27b-mtp-q4_K_M`, **thinking on** — 19/19 correct, median 13.7 s.
- `/no_think` is not used for triage: on the current Ollama it does not reduce latency for qwen3.8
  and cost one case. It is still used for the warm-up ping (harmless).
- Fallback: `ollama/qwen3-coder:30b`, only when the primary fails twice (one switch per run). It
  scored 63–68% and called two real injections false positives, so runs that used it are labelled
  "FALLBACK MODEL … treat verdicts as hints" in the summary.

## Consequences

Triage of the default 60 findings takes about 14 minutes when nothing is cached. Re-run
`scripts/bakeoff.py` whenever the prompt version, the models or Ollama change, and update
docs/model-eval.md.
