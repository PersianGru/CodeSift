---
name: sift
description: Run a local security check (security scan / audit) of the current project with the sift CLI - free scanners plus local-LLM triage - and verify only the serious findings. Use when the user asks to security-check, scan, or audit this project or its changes.
---

# CodeSift

`sift` is a command installed on this machine. It scans the current project with open-source
scanners, has a local LLM triage the findings, and writes a short `summary.md`. It is read-only on
the project and never scans the network. Full rules: `sift --help` and the CodeSift repo's RULES.md.

## Workflow

1. Run `sift scan` in the project root (add `--review` when the user asks for a deeper check or
   when security-critical code changed). Run `sift doctor` **only** if a command failed, and
   follow the fix it prints.
   **It is slow**: the scanners take about a minute, LLM triage up to 20 minutes on first run
   (re-runs use a cache), and `--review` about 3–6 minutes per 400 lines of critical code (it stops
   after `--review-budget` minutes, default 45). Run it in the background or with a long command
   timeout; never kill it after the default 2 minutes. `--no-llm` gives scanner results in about a
   minute when the user is in a hurry.
2. Read **only** the `summary.md` whose path the scan prints. Do not read raw outputs or the whole repo.
3. For each high/critical item and each LLM-"unsure" item, open only the flagged lines (± some
   context) and decide yourself whether it is real. The `LLM:` lines are a local model's opinion —
   a hint, not a verdict; "likely false positive" on a high item still needs your check. Items in
   "AI logic review — unverified" (from `--review`) need the same check before you report them.
4. Report to the user: confirmed issues with a proposed fix, false positives with a one-line reason,
   and what was not covered (skipped scanners, `⚠ not covered` warnings such as dependencies without a
   lockfile, not-triaged items, files the review did not reach, errors). Offer fixes; apply them only
   with the user's OK.
5. Never edit `.codesift-baseline.json`, disable a scanner or lower a threshold without the user's
   explicit OK. To accept a finding (with their OK):
   `sift baseline accept <ID> --reason "…"`.
6. Never print credentials or secret values. Never use `git push --no-verify`.
