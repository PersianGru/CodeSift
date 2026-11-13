# Architecture

```
sift scan PATH
  │
  ├─ detect.py        which ecosystems are present → which scanners apply (--only/--skip override)
  ├─ tools.py         locate pinned binaries, verify sha256 against tools.lock.json, run them
  ├─ runners/*.py     one per scanner: build argv, run with timeout, parse SARIF/JSON
  ├─ normalize.py     → Finding (schema below), severity mapping table per tool, fingerprint, dedupe
  ├─ baseline.py      mark findings accepted in .codesift-baseline.json (with reason / expiry)
  ├─ triage.py+llm.py Bifrost (OpenAI-compatible), one request at a time, caps, retries, cache
  └─ report.py        summary.md (≤ ~150 lines), report.json, raw/ (masked) in the runs dir
```

Every string that leaves a runner passes through `redact.Redactor` (known secret values + generic
secret shapes) before it is written anywhere or sent to the LLM.

## Modules

| Module | Purpose |
|---|---|
| `cli.py` | argparse front end, exit codes |
| `paths.py` | user-level locations per OS, `CODESIFT_HOME` / `CODESIFT_CONFIG` |
| `config.py` | `config.toml`, `bifrost.env`, `.codesift.toml` loading + validation |
| `envfile.py` | safe KEY=VALUE parser (no expansion) |
| `redact.py` | masking |
| `doctor.py` | health checks with fixes |
| `models.py` | exit codes, `Severity` |
| `net.py` | HTTPS allow-listed fetch/download with sha256 verification |
| `lockfile.py` | `tools.lock.json` schema, platform detection, lock location |
| `tools.py` | tool specs, verified install, verify-before-run |
| `releases.py` | GitHub releases, cooldown, checksums, advisories |
| `pyreqs.py` | hashed `requirements.lock` generation and install |
| `rules.py` | vendoring opengrep rules, tree hash |
| `update.py`, `install.py`, `state.py` | update check/apply/rollback, install, state |
| `gitutil.py`, `detect.py` | safe read-only git, file listing, ecosystem detection, excludes |
| `runners/` | one module per scanner (+ opt-in pip-audit, composer audit, govulncheck) |
| `finding.py`, `normalize.py` | finding model, fingerprints, secret hiding, dedupe, IDs |
| `baseline.py`, `report.py`, `scan.py` | baseline, runs dir + reports, orchestration |
| `llm.py` | Bifrost client: retries, Retry-After, empty-answer retry, one-way model fallback |
| `triage.py` | excerpts, prompt contract, answer validation, caps, budget, cache |
| `review.py` | `--review` logic review of critical changed files |
| `hook.py`, `install.py` | pre-push hook, installer, skill |

## Normalized finding

```json
{"id": "F012", "fingerprint": "sha256…", "tool": "bandit", "rule": "B602",
 "severity": "high", "confidence": "medium", "category": "command-injection", "cwe": ["CWE-78"],
 "path": "backend/app/x.py", "line": 42, "end_line": 44, "message": "…", "snippet": "…(redacted)…",
 "baseline": false,
 "triage": {"verdict": "likely_real|likely_false_positive|unsure", "reason": "…", "quoted_line": "…",
            "fix": "…", "model": "…", "status": "done|skipped|failed"}}
```

- Fingerprint = sha256(tool + rule + path + whitespace-stripped flagged code) — no line number, so
  baselines survive edits elsewhere in the file.
- Duplicates (same path, overlapping lines, same CWE) from different tools merge into one finding.

## Configuration precedence

CLI flags > environment variables > project `.codesift.toml` > user `config.toml` > built-in defaults.
Credentials: `BIFROST_*` environment variables > `bifrost.env`.
