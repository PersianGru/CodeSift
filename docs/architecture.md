# Architecture

```
sift scan PATH
  │
  ├─ detect.py        which ecosystems are present → which scanners apply (--only/--skip override)
  ├─ tools.py         locate pinned binaries, verify sha256 against tools.lock.json, run them
  ├─ runners/*.py     one per scanner: build argv, run with timeout, parse SARIF/JSON
  ├─ normalize.py     → Finding (schema below), severity mapping table per tool, fingerprint, dedupe
  ├─ baseline.py      mark findings accepted in .codesift-baseline.json (with reason / expiry)
  ├─ triage.py+gateway.py any OpenAI-compatible LLM gateway, one request at a time, caps, retries, cache
  └─ report.py        summary.md (≤ ~150 lines), report.json, raw/ (masked) in the runs dir
```

Every string that leaves a runner passes through `redact.Redactor` (known secret values + generic
secret shapes) before it is written anywhere or sent to the LLM.

## Modules

| Module | Purpose |
|---|---|
| `cli.py` | argparse front end, exit codes |
| `paths.py` | user-level locations per OS, `CODESIFT_HOME` / `CODESIFT_CONFIG` / `CODESIFT_RUNS` |
| `config.py` | `config.toml`, `gateway.env` (+ 0.1.0 fallback), `.codesift.toml` (incl. `[validate]`, `[ui.districts]`) |
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
| `gateway.py` (`llm.py` = compatibility alias) | LLM gateway client: retries, Retry-After, empty-answer retry, one-way model fallback |
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
LLM gateway: `CODESIFT_LLM_*` environment variables > `gateway.env` > 0.1.0 names (silent fallback, migrated by `sift setup`).

## 0.2.0: validate, fix, sandbox, UI

```
sift fix / sift validate
  │
  ├─ validate/workspace.py  filtered copy (tracked files only, secrets/never_send out), private git baseline
  ├─ validate/engine.py     selection → sandbox self-test → baseline tests/PoCs → ladder → gates → report
  │    ├─ fix/ladder.py     gateway → Claude (consent, escalation, budgets)
  │    │    └─ fix/{gateway_fixer,claude_api,claude_cli}.py   edit protocol in fix/base.py
  │    ├─ validate/policy.py   mechanical patch policy (no LLM)
  │    ├─ validate/verify.py   tests before/after, PoC before/after, re-scan (scan pipeline, offline)
  │    └─ vm/sandbox.py        one hardened container per job over vm/transport.py (system ssh)
  ├─ validate/events.py     events.jsonl (schema v1) ─────────────► ui/server.py (SSE, replay, demo)
  └─ validate/report.py     fix-report.json/.md, patches, audit.jsonl, sandbox logs
```

| Module | Purpose |
|---|---|
| `setup_wizard.py`, `secrets_store.py` | `sift setup`; owner-only files, masking, legacy migration |
| `vm/config.py`, `vm/sshargs.py`, `vm/transport.py` | `vm.toml`; strict ssh argv; SSH + fake transports |
| `vm/sandbox.py`, `vm/selftest.py`, `vm/image.py`, `vm/keys.py` | job runner + guard + cleanup; isolation self-test; image pinning; key/host-key pinning |
| `vm/admin.py`, `vm/codesift-gate.sh`, `vm/commands.py` | admin script + forced-command gate; `sift vm …` |
| `validate/pack.py`, `workspace.py`, `policy.py`, `verify.py`, `poc.py` | safe tar, workspace, policy, gates, project PoCs |
| `validate/engine.py`, `events.py`, `report.py`, `commands.py` | orchestration, event log, artefacts, CLI glue |
| `fix/base.py`, `config.py`, `consent.py`, `prompts.py`, `ladder.py` | protocol + edits, `fix.toml`, consent, prompts, ladder |
| `fix/gateway_fixer.py`, `claude_api.py`, `claude_cli.py` | the three backends |
| `ui/server.py`, `ui/state.py`, `ui/static/` | loopback server, runs/demo/decisions, the 3D realm, the 2D map and the table |

Decisions: ADR-0011 (scope), 0012 (sandbox), 0013 (fixers/consent), 0014 (gateway), 0015 (UI),
0016 (project-supplied PoCs only). Threat model: [threat-model.md](threat-model.md).
