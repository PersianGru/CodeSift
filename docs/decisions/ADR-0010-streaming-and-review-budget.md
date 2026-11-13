# ADR-0010: Streamed LLM answers, reasoning switch, review budget

- Status: accepted
- Date: 2026-11-12

## Context

The real-world run on a production project (docs/real-world-check.md) showed:

- The gateway's proxy answers **HTTP 504 after 90 s** when a request sends no bytes back. A thinking
  model reviewing ~400 lines of code reasons for several minutes before the first answer token, so
  11 of 12 logic-review requests failed, each after three attempts (68-minute run, almost no review).
- Measured on the same 400-line chunk: **with `stream: true` the gateway sends an event at least
  every 6 s** (reasoning tokens arrive as `reasoning_content` deltas), so the proxy never times out.
- **`/no_think` in the prompt is ignored** by qwen3.8 on this Ollama version (already seen in the
  bake-off). Of the request fields Bifrost passes through, only **`reasoning_effort: "none"`**
  turns reasoning off (0.6 s instead of 18 s for a one-line question; `think: false`,
  `reasoning.enabled`, `chat_template_kwargs` and a system `/no_think` have no effect).
- With reasoning off, the review answer for that chunk was unusable: it listed non-issues and
  argued with itself inside the explanations. With reasoning on, an 8k-token budget was spent on
  reasoning alone (no answer after 5 minutes).

## Decision

- Every chat request is **streamed** (server-sent events) and assembled into the usual answer. The
  call keeps a hard whole-answer deadline (`timeout`) plus a 120 s idle limit; the answer text stays
  capped at 2 MB and the raw stream at 64 MB. A gateway that rejects `stream` gets plain requests
  (detected once per run from a 400 that names it); one that answers plain JSON anyway is accepted.
- Thinking off (warm-up pings, `llm.think = "off"`) is sent as **`reasoning_effort: "none"`**, not
  as a prompt tag. A gateway that rejects the field gets requests without it.
- **The logic review keeps reasoning on**, with a large token budget and a long per-request
  deadline (`review.py`: `REVIEW_MAX_TOKENS`, `REVIEW_TIMEOUT_S`) and a **total review budget**
  (`REVIEW_BUDGET_S`); chunks that do not fit in the budget are listed as not reviewed instead of
  stopping the scan. Review requests do not retry after a timeout (the same chunk would time out
  again); a transport error still retries.

## Consequences

- `--review` on a large critical area is slow by nature (minutes per 400 lines on the current VM).
  The summary says how many requests ran, failed or did not fit in the budget, so a partial review
  is never shown as complete.
- Triage answers (median 14–30 s) are unaffected in speed but no longer depend on the proxy timeout.
