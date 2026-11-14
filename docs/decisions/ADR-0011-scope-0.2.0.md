# ADR-0011: Scope of 0.2.0 and the rule changes

- Status: accepted
- Date: 2026-11-14
- Amends: [ADR-0001](ADR-0001-scope-and-fixed-decisions.md) (scope), [RULES.md](../../RULES.md) rules 1–3

## Context

0.1.0 finds problems and has a local model triage them; a person still has to fix every finding and
then convince themselves the fix works and breaks nothing. The owner wants CodeSift to propose fixes
and *prove* them, without giving up the properties that make 0.1.0 safe to run on any repository:
it never changes the project and never executes the project's code.

## Decision

0.2.0 adds five commands inside the existing package; `sift scan` is unchanged.

| Command | What it does |
|---|---|
| `sift setup` | wizard: LLM gateway, sandbox VM (SSH key + pinned host key), fixer backends + consent |
| `sift vm …` | sandbox management: doctor (isolation self-test), status, reset, image, admin script |
| `sift validate` | prove a change (working tree, patch file or branch) on a copy, inside the sandbox |
| `sift fix` | AI fixers propose patches, deterministic gates verify them, output is a patch |
| `sift ui` | local, token-protected web UI ("living city" + plain dashboard) |

Fixed by the owner (not re-opened without them):

- Local model through any OpenAI-compatible gateway (ADR-0014); three fixer backends: gateway model,
  Claude CLI, Claude API, the external ones opt-in with consent (ADR-0013).
- Untrusted work runs only in disposable containers on a remote lab VM reached over SSH (ADR-0012).
- Escalation: gateway model first; Claude for high/critical findings or after N failures.
- PoCs: project-supplied commands and canned probes; LLM-drafted PoCs only behind `--poc llm`.
- UI: top-down neon "living city" with a plain dashboard fallback (ADR-0015).
- Never auto-merge, auto-apply, push, or let an LLM decide "fixed".

Rule changes: rule 1 now covers only the scan commands; rule 2 says the new commands work on a copy
and output a patch; rule 3 adds the gateway URL, the VM (SSH) and `api.anthropic.com` (consented
API backend only). New rules 11–20 (sandbox only, deterministic verdicts, no auto-apply, no check
weakening, consent, no secrets, VM output untrusted, bounded, label-scoped VM cleanup, no gateway
product names).

## Consequences

- The tool now has an execution surface (the VM) and a third-party data path (Claude backends). The
  threat model ([threat-model.md](../threat-model.md)) covers both; residual risks are stated there.
- ADR-0004 (stdlib-only runtime) still holds: SSH is the system `ssh` binary, the UI server is
  `http.server`, the 3D library is a vendored static file served to the browser, not a Python
  dependency.
- Exit codes for the new commands: 0 all verified, 1 some not verified, 2 configuration/tool error
  (including sandbox refusal), 4 budget exhausted.
