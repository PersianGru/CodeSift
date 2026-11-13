# Severity mapping

sift reports `critical / high / medium / low / info`. Each tool's own rating is mapped as below.
High and critical findings are always marked **needs review** and can never be hidden by the LLM.

| Tool | Source of severity | Mapping |
|---|---|---|
| gitleaks | – | every secret is **high** (rotate it, even if only in history) |
| osv-scanner | CVSS `max_severity` per advisory group; one finding per package, worst group wins | ≥ 9.0 critical · ≥ 7.0 high · ≥ 4.0 medium · > 0 low · unknown → **medium** (never hidden as low) |
| opengrep | rule level + metadata | `ERROR` high · `WARNING` medium · `INFO` low; rules with subcategory `audit` capped at medium; `confidence: LOW` lowers one step (min low) |
| trivy | check severity | `CRITICAL/HIGH/MEDIUM/LOW` as is, `UNKNOWN` info; overrides: `DS-0029` (apt-get `--no-install-recommends`, image hygiene) → low |
| bandit | `issue_severity` | `HIGH/MEDIUM/LOW` as is; CWE from bandit plus extra CWEs other tools use for the same issue (for dedupe) |
| ruff `S###` | bandit's table for the matching `B###` (ruff has no severity) | see `BANDIT_TABLE` in `src/codesift/runners/python.py` |
| zizmor | `determinations.severity` | `High/Medium/Low` as is, `Informational` info |
| pip-audit (opt-in) | none given | medium (osv-scanner's CVSS grading wins when both report the package) |
| composer audit (opt-in) | advisory severity | as is, unknown → medium |
| govulncheck (opt-in) | reachability | reachable vulnerable symbol → high |

## Dedupe

Findings merge into one when they are in the same file, their line ranges overlap and they share
any of: a CWE, an alias (ruff `S602` = bandit `B602`), or an issue family (sql, command, eval,
deserialization, yaml, xss, tls, debug, weak-hash, redirect, path, secret — matched on rule ids and
categories). The merged finding keeps the highest severity, lists every tool and rule, and carries
every tool's fingerprint, so a baseline entry made from any of them still matches.

## Fingerprints

`sha256(tool | rule | path | flagged code with all whitespace removed)` — no line numbers, so a
baseline entry survives edits elsewhere in the file. Dependency findings use
`ecosystem:package@version`; secrets use gitleaks' redacted match.
