# `events.jsonl` schema (version 1)

`events.jsonl` is the contract between CodeSift and the UI (`codesift/validate/events.py`). `sift
scan` writes it next to `report.json`; `sift validate` / `sift fix` next to `fix-report.json`. The
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
| `data` | object of scalars, lists (at most 50 items) and objects (three levels deep) |

## Event types

| Type | Required `data` | Notes |
|---|---|---|
| `run.start` | — | `mode`, `kind` (`scan` or `fix`), `dry_run`, `project`, `topology` (`scanners`; `llm`: `host`, `model`, `fallback`; `vm`: `host`, `user`, `runtime`, `image`) |
| `run.end` | — | `exit_code`; scans add `findings` and `llm` |
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
| `scanner.start` | `name` | |
| `scanner.result` | `name`, `status`, `findings`, `duration_s` | `reason`, `version`; `status` is `ok`, `error` or `skipped` |
| `llm.request` | `model` | `prompt_chars`, `max_tokens`, `purpose` (`triage`, `fix`), finding id. Never the prompt |
| `llm.response` | `model`, `ok`, `latency_s` | `served_by`, `tokens_in`, `tokens_out`, `answer_chars`, `error` (`HTTP 503`, `timeout`…). Never the answer |
| `vm.command` | `op` | `job` (8 hex), `bytes_in`. `op` is a fixed label (`job`, `image check`, `free memory`…), never the command |
| `vm.result` | `op`, `rc`, `duration_s` | `job`, `bytes_out`, `timed_out`. Never the output |

The last six are *activity* events, written while the run talks to the model and the VM
(`codesift/telemetry.py` → `codesift/activity.py`). In a scan, writing them is best effort: a bad
event or a full disk drops the event, never the scan.

## Reading the log

`read_events(path, offset)` returns only complete lines. It ignores a truncated last line, so a file
that is still being written can be tailed safely. The UI's `/api/stream/<run>` endpoint uses it to
send server-sent events.
