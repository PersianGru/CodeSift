# Changelog

All notable changes. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- `sift ui` shows a live 3D map of the real run instead of the "living city": this machine with the
  run's scanners, the LLM gateway with your models, and the sandbox VM with its containers. Every
  packet is a real event; nothing moves without one. Scans now appear too, and the page follows a
  new run as soon as it starts.
- `sift scan` writes `events.jsonl`: scanners starting and reporting, each finding, each LLM call
  (model, tokens, time). `sift validate` / `sift fix` also record each LLM call and VM command.
  Metadata only: never a prompt, an answer, a command or output. New `CODESIFT_RUNS` override.
- A failed sandbox self-test names the failing check and its detail.

### Fixed
- `sift setup --vm`: a refused sudo/doas password is reported as such, not as a script error.
- Sandbox jobs on Docker 29: `/work` is mounted writable for the job user.
- Sandbox input check: BusyBox `tar` hiding `../` member names no longer slips through.
- Tests no longer read or write the real `~/.codesift`.

## [0.2.0] - 2026-11-14

Prove fixes, not just find problems. The scan commands behave as before. Design: ADR-0011..0016,
[docs/threat-model.md](docs/threat-model.md).

### Added

- `sift setup`: a wizard for the LLM gateway (any OpenAI-compatible base URL, connection test), the
  sandbox VM and the fixer backends (with recorded consent). For the VM it asks only for the address,
  port, admin user and how the admin signs in (key or password), pins the host key after a typed
  `yes`, then sets the VM up by itself: its own key in your SSH folder, one admin login (passwords go
  only into ssh's or sudo's own prompt) that creates the `codesift` user, installs and starts Docker
  if needed and installs the gate, then the image pull and the isolation self-test. Also `--show`, `--reset` and a non-interactive mode where secrets come only from
  environment variables.
- Sandbox VM backend (`sift vm setup|doctor|status|reset|image|admin-script`):
  - one hardened, network-less, read-only, non-root container per job, reached over the system `ssh`;
  - a resource guard, label-only cleanup and an isolation self-test, with fail-closed behaviour;
  - image pinning and a forced-command gate on the VM.
- `sift validate`: proves a working-tree change, a patch or a branch on a copy of the project, using
  the patch policy, project tests, project PoCs and a re-scan. Exact outcomes and exit codes
  0/1/2/4.
- `sift fix`: fixer backends (the gateway model, the Claude CLI and the Claude API), with:
  - an escalation ladder, budgets and a JSON edit protocol;
  - mechanical feedback between attempts and an optional advisory `--review-patch`;
  - `--dry-run` and `--json`, an audit log and the event log.
- `sift ui`: a local token-protected web UI with a 3D "living city" (vendored three.js
  r128, 21cel palette, shadows and glow, animated traffic between scanners, LLM backends,
  sandbox and gates) and a plain dashboard. Decisions are recorded; nothing is applied. `--demo` and `--run DIR`
  replay runs.
- `.codesift.toml`: new `[validate]`, `[validate.poc]` and `[ui.districts]` sections.
- `sift doctor`: gateway, VM and fixer sections.

### Changed

- The LLM endpoint is now product-neutral: `gateway.env` with `CODESIFT_LLM_*` variables,
  `GatewayClient` (the old class name remains as an alias), and an empty API key is allowed. 0.1.0
  settings are still read and are migrated by `sift setup --llm`.
- RULES.md: rules 1–3 rewritten for the new commands; rules 11–20 added.
- Installers point to `sift setup`; `--purge` also removes the new settings, keys and consent.

### Not included

- Canned PoC probes and LLM-drafted PoCs (ADR-0016). Only project-supplied PoCs are supported.

## [0.1.0] - 2026-11-13

First public release. MIT licence (the vendored opengrep rules keep their own licence); see
`SECURITY.md` for private vulnerability reports and `CONTRIBUTING.md` for development.

### Docs

- README: "Built on" (every scanner and component, with links and licences), "How it was built and
  checked", "Known limits".
- `docs/prompts.md`: copy-paste prompts for any project, split into a scan chat (cheaper model:
  setup, scan, triage, `triage.md` hand-off) and a fix chat (stronger model: re-check, fix on its
  own branch, verify, close out). Notes stay in the run folder, outside the project.
- Ten decision records in `docs/decisions/`, the model bake-off (`docs/model-eval.md`) and a
  real-world check on a production project (`docs/real-world-check.md`).

### Scanning

- `sift scan [PATH]`: detects what the project contains and runs only the scanners that apply,
  in parallel (default 2 jobs): gitleaks (history, unstaged, staged), osv-scanner (`--no-resolve`),
  opengrep (security rules of the detected languages only), trivy config, ruff `S`, bandit, zizmor
  (offline), and opt-in pip-audit, composer audit, govulncheck.
- One finding schema for all tools, severity mapping per tool ([docs/severity.md](docs/severity.md)),
  dedupe across tools, fingerprints without line numbers, baseline filtering.
- Per-line policy findings (zizmor `unpinned-uses`) grouped per workflow file, capped at medium for
  GitHub's own actions, and merged with opengrep's equivalent rule. trivy's whole-file Dockerfile
  findings merge with opengrep's line findings.
- Findings on git-ignored files are dropped (except gitleaks history/staged findings).
- Warning when a `pyproject.toml`, `package.json` or `composer.json` that declares dependencies has
  no lockfile next to it (osv-scanner cannot check those).
- `summary.md` (≤ 150 lines), `report.json`, masked `raw/`, `latest` pointer, last 20 runs kept, all
  outside the project. `sift report` re-prints the latest summary.
- Flags: `--since <ref>`, `--fast`, `--only/--skip`, `--threshold`, `--offline`, `--json`,
  `--verbose`, `--no-llm`, `--require-llm`, `--max-llm`. Exit codes 0/1/2/3.
- `sift baseline accept/list/prune` (reason and optional expiry), `sift init`.
- Git hardening for untrusted repositories (fsmonitor, hooks, external diff, textconv disabled).

### LLM triage and review

- Client for any OpenAI-compatible gateway (stdlib `urllib`): HTTPS only, key in the header only,
  cross-host redirects refused, retries with backoff and `Retry-After`, errors scrubbed of the key.
- Answers are streamed (server-sent events) with a whole-answer deadline and a 120 s idle limit, so
  gateways that cut silent requests (HTTP 504) do not kill slow reasoning models. Plain requests are
  used if a gateway rejects `stream`, `response_format` or `reasoning_effort` (ADR-0010).
- Triage of medium+ findings: excerpts extended to the enclosing definition plus related
  definitions, whole file for workflow findings, secrets masked, JSON-only contract, quoted-line
  verification, one corrective retry. Verdicts are shown in `summary.md`; severity is never changed
  and high/critical are always "needs review". Secrets, dependency advisories and policy findings are
  never sent.
- One model per run with a single switch to the fallback, warm-up call without reasoning, per-run
  caps, triage cache keyed by prompt version, model, fingerprint and excerpt.
- `sift scan --review`: logic review of critical files (`review.critical_paths`, `--critical`),
  ~400-line requests, reasoning on, optional checklist (`--checklist`), `--review-all`, a time
  budget (`--review-budget`, default 45 minutes) and a list of files it did not reach. Results are a
  separate "AI logic review — unverified" section.
- Model bake-off script and labelled corpus (19 cases); defaults chosen from it
  ([docs/model-eval.md](docs/model-eval.md), ADR-0008).

### Tools and supply chain

- `tools.lock.json`: gitleaks 8.30.1, osv-scanner 2.7.0, trivy 0.76.2, opengrep 1.33.1 for
  windows-x64, linux-x64, linux-arm64, darwin-arm64 (sha256 from official checksum files,
  cross-checked with GitHub asset digests).
- `requirements.lock`: ruff 0.17.3, bandit 1.9.4, pip-audit 2.10.1, zizmor 1.32.0 with every wheel
  hash; installed with `--require-hashes --only-binary=:all:`.
- Vendored opengrep rules (835 files) from the archived `opengrep/opengrep-rules` at a pinned commit,
  with a tree hash in the lock.
- `sift update` (7-day cooldown, advisory checks), `--apply` (verify, self-test, restore on
  failure), `--rollback`, `--lock` for maintainers. Binaries are re-verified before every run.
- HTTPS host allow-list for install/update traffic.

### Install, hook and skill

- `install.ps1` / `install.sh`: venv, verified tools, command shims, default `config.toml`, the
  Claude Code skill `/sift`, optional credential copy (`BIFROST_*` keys only, user-only ACL /
  mode 600) and optional user PATH entry. No admin rights.
- Windows installs to `%USERPROFILE%\.codesift`, not AppData, because packaged desktop apps
  virtualize writes there (ADR-0002).
- `sift hook install | uninstall | status`: pre-push hook that blocks only on new high/critical
  findings, chains an existing hook, respects `core.hooksPath`, and lets the push through with a
  warning when CodeSift is missing or fails.
- `sift doctor`: install, tool checksums and age, rules hash, config, gateway, models and
  warm-up, each problem with a fix. `sift uninstall [--purge]`.
- Tested on Windows 11 and in a clean Linux container; macOS untested.

### Security

- Secret redaction everywhere a string can leave sift: exact known values plus generic secret
  shapes (bearer tokens, URL credentials, `key=value` secrets, well-known token prefixes, private
  key blocks), including secrets quoted in tool messages.
