# Model evaluation (bake-off)

Run on 2026-11-12 with `scripts/bakeoff.py` (raw results: [bakeoff-results.json](bakeoff-results.json)).
Re-run it after changing the prompt (`PROMPT_VERSION` in `src/codesift/triage.py`) or the models.

## Method

- **Corpus**: `tests/bakeoff/corpus/` — 22 small files in Python, JS, PHP, Go and GitHub Actions,
  one case each, with **neutral file names and no hint comments** (the first real run showed that a
  fixture comment like "never runs" sways the model). Ground truth in `tests/bakeoff/labels.json`,
  never shown to the model.
- **Cases**: the medium-or-higher findings the real scanners report on the corpus: **19 labelled
  cases — 11 real issues, 8 typical false positives** (constant shell command ×2, `shlex.quote`d
  path, allow-listed table name, int-cast id, HTML-escaped output, echo of a database row, `eval` of
  a module constant). 3 `ListenAndServe`-without-TLS findings were excluded (deployment-dependent).
- **Exactly the production prompt and validation** (`build_excerpt`, `build_messages`, `validate`,
  one corrective retry). Correct = `likely_real` on real cases, `likely_false_positive` on false
  positives; `unsure` counts as wrong.
- **Gentle on the VM**: one model at a time, one request at a time, 76 answers in total.

## Results

| Config | Accuracy | Real found | FP recognised | Real called FP | Invalid JSON / invented quote | Median / p95 |
|---|---|---|---|---|---|---|
| **qwen3.8:27b-mtp, thinking on** | **19/19 (100%)** | 11/11 | 8/8 | 0 | 0 / 0 | 13.7 s / 29.9 s |
| qwen3.8:27b-mtp, `/no_think` | 18/19 (95%) | 11/11 | 7/8 | 0 | 0 / 0 | 14.4 s / 30.4 s |
| qwen3-coder:30b, thinking on | 12/19 (63%) | 9/11 | 3/8 | **2** | 0 / 0 | 2.2 s / 3.0 s |
| qwen3-coder:30b, `/no_think` | 13/19 (68%) | 9/11 | 4/8 | **2** | 0 / 0 | 2.3 s / 2.7 s |

Warm-up: qwen3.8 1.6 s (already loaded), qwen3-coder 19.5 s (model switch on the VM).

Observations:

- qwen3.8 judged every case correctly, including the subtle ones (`shlex.quote`, allow-listed table,
  int cast, constant `eval`).
- `/no_think` does **not** make qwen3.8 faster on this Ollama version — it still reasons — and it
  missed one false positive (`eval` of a constant). Thinking stays on.
- qwen3-coder is 6× faster but called both GitHub-Actions template injections "likely false
  positive" and flagged every constant/escaped case as real. As a primary model that would be
  harmful (a real high finding labelled "likely false positive"); RULES.md §5 keeps such findings in
  the report and "needs review", but the hint would mislead.
- Every config produced valid JSON with verified quotes on the first try: the JSON-only contract and
  `response_format: json_object` work for both models.

## Decisions (ADR-0008)

- Primary model **`ollama/qwen3.8:27b-mtp-q4_K_M` with thinking on** (`llm.think = "auto"` resolves
  to on).
- **`ollama/qwen3-coder:30b` stays the outage fallback only.** When a run switches to it, the summary
  says "FALLBACK MODEL: weaker in the bake-off, treat verdicts as hints".
- Budgets unchanged: 60 findings × ~14 s median ≈ 14 min, inside the 20-minute run budget; the
  180 s per-call timeout covers the 30 s p95 with a large margin (cold starts take 30–65 s).

## Update after the real-world run (ADR-0010)

- The `/no_think` rows above did not switch reasoning off: qwen3.8 ignores the tag on this Ollama
  version (the latencies match). Through Bifrost only `reasoning_effort: "none"` turns it off
  (0.6 s instead of 18 s for a one-line question). CodeSift now sends that field for `think = "off"`
  and for warm-up pings; triage keeps thinking on, so the measured accuracy above still applies.
- Logic review without reasoning (one 400-line licensing file, real project) produced unusable
  output: non-issues, and explanations that contradicted themselves. With reasoning the same chunk
  took 376 s and about 9k tokens. The review therefore keeps reasoning on, streams the answer and
  works within a time budget.

## Limits

19 cases is a small sample: it separates the two models clearly, but it is not a precision
estimate for real projects. The [real-world check](real-world-check.md) adds a data point from a production project.
