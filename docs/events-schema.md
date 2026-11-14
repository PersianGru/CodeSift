# `events.jsonl` schema (version 1)

`events.jsonl` is the contract between the engine (`codesift/validate/events.py`) and the UI. The
file holds one JSON object per line and is validated on write. Every string is redacted and capped
at 300 characters. No code and no secrets are written.

```json
{"v":1,"ts":"2026-11-14T10:00:00Z","run":"20261114-100000","seq":12,"type":"stage.enter",
 "finding":"F007","data":{"stage":"fix","backend":"gateway","attempt":1}}
```

## Fields

| Field | Rule |
|---|---|
| `v` | always `1` |
| `ts` | UTC timestamp, ISO 8601 |
| `run` | `[A-Za-z0-9._-]{1,80}` |
| `seq` | 0, 1, 2, … per run |
| `finding` | `F001`-style id. Required for finding events, omitted otherwise |
| `data` | object of scalars or lists (at most 50 items) |

## Event types

| Type | Required `data` | Notes |
|---|---|---|
| `run.start` | — | `mode`, `dry_run`, `project` |
| `run.end` | — | `exit_code` |
| `finding.selected` | — | finding id |
| `finding.detected` | `path`, `line`, `category`, `cwe`, `severity`, `bug_type`, `district` | `bug_type` is one of `sqli`, `xss`, `cmdi`, `traversal`, `secret`, `dependency`, `glitch` |
| `stage.enter` / `stage.exit` | `stage` | `stage` is one of `triage`, `fix`, `policy`, `sandbox`, `verify`, `judge` |
| `fix.attempt` | `backend`, `attempt` | |
| `fix.result` | `backend`, `attempt`, `ok` | |
| `policy.verdict` | `ok` | `codes` (machine codes) |
| `sandbox.start` | — | `label` |
| `sandbox.result` | `rc`, `duration_s` | never the raw output |
| `verify.result` | `gate`, `status` | `status` is one of `pass`, `fail`, `unavailable`, `skipped` |
| `finding.outcome` | `outcome` | one of the nine outcomes in [validate-and-fix.md](validate-and-fix.md) |
| `budget.update` | — | `tokens_used`, `tokens_limit`, `time_limit_s`, `exhausted` |
| `selftest.result` | — | `passed`, `cached` |
| `error` | — | `message` (redacted) |

## Reading the log

`read_events(path, offset)` returns only complete lines. It ignores a truncated last line, so a file
that is still being written can be tailed safely. The UI's `/api/stream/<run>` endpoint uses it to
send server-sent events.
