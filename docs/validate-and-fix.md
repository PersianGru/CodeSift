# `sift validate` and `sift fix`: user guide

Both commands work on a **copy** of your project in CodeSift's runs folder. Untrusted work runs
**only** in the sandbox VM, and a person reviews every patch. CodeSift never applies, merges or
pushes anything.

## Before the first run

1. `sift setup`: configure the LLM gateway, the sandbox VM and the fixer backends.
2. `sift vm image pull <image>`: pin the sandbox image. Your test tools must be inside it. This step
   uses the network on the VM.
3. `sift vm doctor`: runs the isolation self-test. Every item must pass.
4. Optional, in `.codesift.toml` (`sift init` writes a commented template):

```toml
[validate]
test = "python -m pytest -q"     # single line, runs only in the sandbox
timeout_s = 300
never_send = ["secrets/**"]       # never copied, never sent to any model
allowed_fix_paths = []            # extra files a fix may touch
max_patch_lines = 80              # hard max 400

[validate.poc]                    # exit 0 = vulnerable behaviour reproduced
"CWE-89" = "python poc/sqli.py"
```

Auto-detected test commands are only *suggested* in the report and never run implicitly.

## `sift validate`

```bash
sift validate                    # working tree diff against HEAD
sift validate --patch fix.patch  # a patch file against HEAD
sift validate --branch my-fix    # REF's change since its merge-base with HEAD
sift validate --finding F003 --json
```

CodeSift copies the project at the base revision, applies the change, and runs the gates for each
selected finding the change touches. If the change touches no selected finding, it runs a
*regression check* instead (policy, tests and new findings).

## `sift fix`

```bash
sift fix --dry-run               # plan: findings, PoCs, ladder, what goes where; contacts nothing
sift fix                         # high/critical findings, at most 5 (fix.toml)
sift fix --finding F001,F004 --backend gateway --review-patch
sift fix --budget-tokens 50000 --budget-minutes 20
```

1. **Findings**: taken from the latest `report.json`, or from a fresh `--no-llm` scan. CodeSift
   selects findings at or above `--min-severity` (default high), skipping baselined ones and those
   the model triaged as false positives. `--max-findings` caps the count.
2. **Workspace**: tracked files only. Left out are `.git`, `.env*`, keys and certificates,
   credential-looking names, files with a secret finding, `never_send` globs, symlinks and oversized
   files. A private git baseline makes every diff exact. The workspace is deleted when the run ends.
3. **Sandbox**: needed only when tests or PoCs are configured. The isolation self-test runs first
   (cached for 10 minutes). Baseline tests and the baseline PoC per finding run before any fixing.
4. **Ladder**: the gateway model first (2 attempts by default), then Claude.
   - Findings at or above `escalate_min_severity` go straight to Claude when it is enabled.
   - Each failed attempt passes the *mechanical* failure message (policy, tests, re-scan) to the next
     attempt.
5. **Gates**: policy → re-scan → PoC after → tests after. The outcome is set by these gates only.
6. **Budgets**: attempts, tokens, run time, time per finding and the number of findings are all
   capped. When a budget runs out the finding gets `budget_exhausted`, the run exits with code 4,
   and the report is still written.

## Outcomes and exit codes

| Outcome | Meaning |
|---|---|
| `fixed_verified` | Policy and re-scan passed, and a PoC pair or the project tests proved it |
| `fixed_unproven` | Policy and re-scan passed, but there was no PoC and no tests (the report says so) |
| `rejected_policy` / `_tests` / `_rescan` / `_poc` | That gate failed. An unavailable re-scan also rejects |
| `inconclusive` | The PoC did not reproduce on the baseline. This is not "safe" |
| `fixer_failed` / `budget_exhausted` | No usable patch / a budget ran out |

| Exit code | Meaning |
|---|---|
| `0` | Everything `fixed_verified` (or the regression check passed) |
| `1` | Something not verified |
| `2` | Configuration, tool or sandbox error (fail closed) |
| `4` | Budget exhausted |

## Run artefacts (`<runs>/validate/<project>/<run id>/`)

| File | Contents |
|---|---|
| `fix-report.md` | Short summary (at most 150 lines). Read this first |
| `fix-report.json` | Full report, stable schema below |
| `<finding>.patch`, `combined.patch` | Patches for review. **Apply them yourself if you agree** |
| `events.jsonl` | Event log for the UI ([events-schema.md](events-schema.md)) |
| `audit.jsonl` | Command, backend, model, tokens, durations, verdicts. No code, no secrets |
| `sandbox/*.log` | Sanitised, size-capped job output |
| `decisions.json` | Approve / reject / retry records written by `sift ui` |

The last 20 runs per project are kept.

## `--json` summary (schema 1)

```json
{"schema": 1, "run_id": "20261114-100000", "run_dir": "…", "mode": "fix", "exit_code": 1,
 "dry_run": false, "report": "…/fix-report.md",
 "findings": [{"id": "F001", "severity": "high", "outcome": "fixed_unproven", "patch": "F001.patch"}],
 "regression": null, "notes": ["…"]}
```

## Data policy

| Backend | What it receives |
|---|---|
| Gateway | The finding metadata and the redacted file (capped) |
| Claude API | The same as the gateway, sent to `api.anthropic.com`. Only with consent |
| Claude CLI | The filtered workspace copy, read through its own read/search/edit tools. No shell, no web, a turn cap. Only with consent |

Every value the redactor knows (the gateway key, the Claude key) is masked in prompts, events,
audit, logs and reports.
