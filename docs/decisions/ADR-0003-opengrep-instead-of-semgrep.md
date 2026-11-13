# ADR-0003: opengrep instead of semgrep, and which rules

- Status: accepted
- Date: 2026-11-12

## Context

CodeSift needs a multi-language pattern scanner (Python, JS/TS, PHP, Go, generic). semgrep's open
source engine does not ship native Windows binaries, and its rules moved to the restrictive
"Semgrep Rules License v1.0".

## Decision

**Engine**: opengrep, the open fork of the semgrep engine — same rule format, SARIF output, release
binaries for Windows, Linux and macOS.

**Rules**: vendored from `opengrep/opengrep-rules` at commit `f1d2b562b414783763fd02a6ed2736eaed622efa`
(2025-01-26). Checked on 2026-11-12:

| Option | Licence | State |
|---|---|---|
| `opengrep/opengrep-rules` | LGPL-2.1 + Commons Clause (pre-change semgrep-rules licence) | archived (last commit 2025-01-26), described as for "research, testing & benchmarking" |
| `semgrep/semgrep-rules` | Semgrep Rules License v1.0 (restricts redistribution and competing use) | active |

The opengrep fork is the one whose licence permits vendoring a copy into CodeSift's repository and
redistributing it with its licence file (`rules/LICENSE.opengrep-rules`); the Commons Clause only
forbids selling the rules. CodeSift's own code is MIT; the vendored rules keep their licence. The Semgrep-licensed
repository is not used. Because the fork is archived, its rules will not receive fixes; CodeSift adds
its own rules under `rules/custom/` where coverage is missing, and `sift update` reports when the
rules source changes.

Vendored subset: rule YAML only (no test targets) for python, javascript, typescript, php, go,
generic (without `generic/secrets`, which gitleaks covers), dockerfile, yaml, bash — 835 files.

## Consequences

One engine on all platforms. The rules are a frozen snapshot with an integrity hash in the lock.
Revisit if opengrep publishes a maintained rules set.
