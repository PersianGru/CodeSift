---
name: sift
description: Run a local security check (security scan / audit) of the current project with the sift CLI - free scanners plus local-LLM triage - and verify only the serious findings. Use when the user asks to security-check, scan, or audit this project or its changes, or to fix and prove fixes for its findings.
---

# CodeSift

`sift` is a command installed on this machine. It scans the current project with open-source
scanners, has a model behind the user's LLM gateway triage the findings, and writes a short
`summary.md`. `sift fix` / `sift validate` propose and *prove* fixes on a copy of the project. Untrusted
code runs only in a sandbox VM. Full rules: `sift --help` and the CodeSift repo's RULES.md.

## Workflow

1. If `sift doctor` reports the LLM gateway or the sandbox VM as not configured, ask the user to run
   `sift setup` themselves (it asks for credentials with hidden input). Never type or print credentials.
2. Run `sift scan` in the project root (add `--review` for a deeper check of critical code). It is
   slow: run it in the background or with a long timeout; `--no-llm` gives scanner results in about
   a minute.
3. Read **only** the `summary.md` whose path the scan prints. For each high/critical item and each
   "unsure" item, open only the flagged lines and decide yourself whether it is real. `LLM:` lines are
   hints, not verdicts.
4. To fix: first `sift fix --dry-run` and show the user the plan (findings, backends, what is sent
   where). Run `sift fix` only with the user's OK. Read the printed `fix-report.md`.
5. Report outcomes honestly: `fixed_verified` (proven by PoC/tests + re-scan), `fixed_unproven` (no
   PoC/tests - say so), `rejected_*`, `inconclusive` (never "safe"), `budget_exhausted`.
6. Patches live in the run folder. Show the diff; apply one **only** with the user's explicit OK
   (e.g. `git apply <file>`), then suggest re-running `sift validate`.

## Never

- Never apply, merge or push a patch without the user's explicit OK; never use `--no-verify`.
- Never run a PoC, exploit or the project's tests on this machine to "check" a fix - that is the
  sandbox's job (`sift validate`).
- Never edit `.codesift-baseline.json`, disable a scanner or lower a threshold without the user's OK.
  To accept a finding (with their OK): `sift baseline accept <ID> --reason "…"`.
- Never print credentials or secret values, and never pass them on a command line.
- Never enable a Claude backend or record consent on the user's behalf - that is `sift setup --fixers`.
