# ADR-0013: Fixer backends, consent and data policy

- Status: accepted
- Date: 2026-11-14
- Related: [ADR-0007](ADR-0007-llm-triage.md) (prompt contract, code is data),
  [ADR-0010](ADR-0010-streaming-and-review-budget.md) (budgets)

## Context

A local model is free and private but weaker; Claude is stronger but a third party. The owner wants
both, with Claude taking over for serious findings or when the local model keeps failing, and no
data leaving the machine without an explicit, recorded yes.

## Decision

1. **One protocol.** `Fixer.fix(request) -> FixResult`. The request carries the finding (redacted),
   the file content (redacted, capped), the allowed paths, the previous *mechanical* failure
   messages, and the attempt number. All backends work on the workspace copy.
2. **Edit protocol** for the API-style backends: one JSON object
   `{"edits":[{"path","search","replace"}],"explanation"}`. `search` must occur exactly once; the path
   must be an allowed file inside the workspace (no traversal, no symlink escape). Malformed output
   gets one retry with the parse error as feedback.
3. **Backends.**
   - *Gateway model* — through the neutral client, one request at a time.
   - *Claude CLI* — `claude -p` with the prompt on stdin, `cwd` = the workspace, tools limited to
     read/search/edit, edits accepted inside the workspace only, `--max-turns`, timeout, a minimal
     environment. The workspace already has secret files removed. Its diff is checked by the same
     policy as any other.
   - *Claude API* — `urllib` to `https://api.anthropic.com/v1/messages`, key only in the `x-api-key`
     header, no redirects, response size cap, errors scrubbed. The model id comes from `fix.toml`
     (the wizard suggests one; nothing is hard-coded the user cannot change).
4. **Consent.** Claude CLI and Claude API are unusable until `sift setup --fixers` (or the
   non-interactive `--enable-fixer … --i-consent`) records `consent.json`: enabled flag, timestamp
   and the exact text of what is shared.
5. **Data policy.** API: redacted excerpts only. CLI: a workspace without `.git`, `.env*`, keys,
   certificates, credential-looking files, files with a secret finding, or `never_send` globs.
   Gateway: same excerpts as triage. No secret value is ever sent, logged or stored.
6. **Escalation ladder** from `fix.toml`: gateway first (2 attempts by default), Claude for
   severity ≥ `escalate_min_severity` (default high). Each failed attempt feeds the mechanical
   failure message (policy / tests / re-scan) to the next one — never raw text from elsewhere.
7. **Budgets.** Attempts per backend, tokens per run, wall-clock per finding and per run, number of
   findings. Exhaustion stops with `budget_exhausted` and still writes the report.
8. **Optional review** (`--review-patch`): a different backend critiques a passing diff; advice only,
   never changes an outcome.

## Consequences

- The deterministic gates (ADR-0012, `validate/policy.py`, `validate/verify.py`) decide; a backend
  claiming "fixed" changes nothing.
- The Claude CLI reads whatever is in the workspace and sends it to its service; the workspace
  filter is therefore a security boundary and is tested.
