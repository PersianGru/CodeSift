# CodeSift

CodeSift is one command that runs free, open-source security scanners (gitleaks, osv-scanner, trivy,
opengrep, ruff/bandit, pip-audit, zizmor, …) on any code project, has a **local LLM** behind an
OpenAI-compatible gateway (Bifrost in our setup) triage the findings, and writes a **short `summary.md`** that a person or an AI assistant can
read cheaply. The expensive reviewer then only checks the serious items and the logic a pattern scanner
cannot judge.

> **Status: v0.1.0** (2026-11-13) — see [CHANGELOG.md](CHANGELOG.md) and the
> [real-world check](docs/real-world-check.md). Known gaps: [below](#known-limits). MIT licence.

What it will never do is listed in [RULES.md](RULES.md): it is read-only on the scanned code, never
scans the network, and never prints a secret.

## Install

Requires Python ≥ 3.11 and git. One line, Windows (PowerShell):

```powershell
git clone --branch v0.1.0 https://github.com/PersianGru/CodeSift.git "$HOME\codesift-src"; & "$HOME\codesift-src\install.ps1"
```

Linux / macOS:

```bash
git clone --branch v0.1.0 https://github.com/PersianGru/CodeSift.git ~/codesift-src && ~/codesift-src/install.sh
```

Or, from a checkout of this repository:

```powershell
# Windows (PowerShell) - asks before changing your user PATH or copying credentials
./install.ps1
```

```bash
# Linux / macOS - asks for the credentials file; prints a hint if ~/.local/bin is not on PATH
./install.sh
```

Non-interactive: `./install.ps1 -AddToPath -CredentialsFrom path\to\bifrost.env -Yes` /
`./install.sh --credentials-from path/to/bifrost.env --yes`.

The installer creates the venv, installs the hashed Python scanners, downloads and checksum-verifies
the four binaries, installs the rules, writes the `sift` command shims, a default `config.toml`,
and the Claude Code skill `/sift` (`~/.claude/skills/sift/`, skipped if a different skill of
that name exists). Credentials are copied only on request — only the `BIFROST_*` keys — and the copy
is restricted to your account (Windows ACL / mode 600). No admin rights; nothing system-wide.

Tested on Windows 11 (PowerShell 7) and Linux (`python:3.12-slim` container, install → doctor →
scan → uninstall, peak memory ≈ 512 MB). macOS uses the same script but is untested.

Re-run the installer after `git pull` to update CodeSift itself. Uninstall:
`./install.ps1 -Uninstall` / `./install.sh --uninstall` (keeps runs and credentials; add
`-Purge` / `--purge` to remove them too). Development setup: see [CONTRIBUTING.md](CONTRIBUTING.md).

### Pre-push hook (optional, per repository)

```bash
sift hook install     # in the repository; status / uninstall likewise
```

Before each `git push` it runs `sift scan --fast --no-llm --since <remote commit>` (gitleaks on the
pushed commits, code scanners on changed files, osv-scanner only if a manifest changed) and blocks
the push only on **new high/critical** findings that are not in the baseline. An existing pre-push
hook is kept as `pre-push.local` and runs first; `core.hooksPath` is respected. If CodeSift is missing
or a scan fails, the hook warns and lets the push through. The owner's emergency escape hatch is
`git push --no-verify` (assistants never use it).

## Quick start

```bash
sift scan            # full run: scanners + LLM triage + summary.md
sift scan --no-llm   # scanners only
sift doctor          # what is installed / configured, with a fix for each problem
```

In Claude Code, in any project, a new chat needs one line: **"run `/sift`"** (or "run
`sift scan` and read the summary"). The skill tells the assistant the rest.
For a full round, use the copy-paste prompts in [docs/prompts.md](docs/prompts.md): a scan chat
(cheaper model) writes a `triage.md` hand-off, and a fix chat (stronger model) fixes on its own branch.

### What runs

CodeSift detects what the project contains and runs only the scanners that apply:

| Scanner | Runs when | Covers |
|---|---|---|
| gitleaks | always | secrets in files and git history (unstaged, staged, commits) |
| osv-scanner | lockfiles / manifests exist (skipped with `--offline`) | known-vulnerable dependencies (pip, npm/yarn/pnpm, composer, Go, …) |
| opengrep | always | code patterns — security rules for the detected languages only |
| trivy | Dockerfile / Kubernetes / Terraform / Helm files | misconfigurations |
| ruff (`S`) + bandit | Python files | Python security issues |
| zizmor | `.github/workflows/*.yml` | GitHub Actions security |
| pip-audit, composer audit, govulncheck | only if enabled in `.codesift.toml` | extra dependency checks |

Never scanned: `node_modules`, `vendor`, virtualenvs, build output and the project's `exclude` globs.
Code-pattern scanners (opengrep, ruff, bandit) also skip test directories and test files; secret,
dependency and config scanners still scan them. Severity mapping, dedupe and fingerprints:
[docs/severity.md](docs/severity.md).

### LLM triage

After the scanners, each medium-or-higher finding (highest first, max 60 per run) goes to the local
LLM through Bifrost, one request at a time. The model answers `likely_real`, `likely_false_positive`
or `unsure` with a two-sentence reason, a quoted line (checked against the code — invented quotes are
rejected) and a short fix. The verdict is shown in `summary.md`; it never changes a severity or hides
a finding, and high/critical findings are always marked **needs review**.

Sent to the LLM: the finding's metadata and the flagged lines with ±30 lines of context (secrets
masked). **Never sent:** secrets found by gitleaks, dependency advisories, whole files or
repositories. Answers are cached, so re-runs only ask about new or changed findings. Without
credentials, with `--no-llm` / `--fast`, or when the LLM is down, the report lists the findings
untriaged and says why.

`sift scan --review` additionally sends the diff of changed files matching
`review.critical_paths` (plus the optional `review.checklist`) and lists concrete issues in a
separate "AI logic review — unverified" section. Design: [ADR-0007](docs/decisions/ADR-0007-llm-triage.md).
The review is slow by nature: the model reasons for about 6 minutes per 400 lines on the current VM
(answers are streamed so the gateway does not time out, [ADR-0010](docs/decisions/ADR-0010-streaming-and-review-budget.md)).
It stops after `--review-budget` minutes (default 45) and lists the files it did not get to.
`--critical <glob>` (repeatable), `--checklist <file>` and `--review-all` (all critical files, not
only changed ones) override the project config for one run.

Real-world results and limits: [docs/real-world-check.md](docs/real-world-check.md).

Each run writes to the runs folder (never into the project): `summary.md` (≤ 150 lines, read this),
`report.json` (all findings), `raw/` (each tool's output, secrets masked). The last 20 runs per
project are kept. `sift report` re-prints the latest summary.

## Commands

| Command | What it does |
|---|---|
| `sift scan [PATH]` | detect → scanners → normalize/dedupe → baseline → LLM triage → report |
| `sift scan --fast` | scanners only, changed files, no LLM (used by the pre-push hook) |
| `sift scan --review` | plus an LLM logic review of the project's critical code |
| `sift report --last` | re-print the latest summary |
| `sift baseline accept <ID…> --reason "…" [--expires YYYY-MM-DD]` / `list` / `prune` | accepted findings |
| `sift init` | write a commented `.codesift.toml` |
| `sift hook install` / `uninstall` / `status` | git pre-push hook |
| `sift update [--apply] [--rollback]` | check / apply tool updates (7-day cooldown) |
| `sift doctor` | health check; never shows secret values |
| `sift install` / `uninstall` | manage the installation |

Scan flags: `--no-llm`, `--require-llm`, `--offline`, `--only/--skip <tools>`, `--threshold <sev>`,
`--since <git-ref>`, `--json`, `--max-llm <n>`, `--verbose`; for `--review`: `--critical <glob>`,
`--checklist <file>`, `--review-all`, `--review-budget <minutes>`.

Exit codes: `0` nothing at/above threshold · `1` findings at/above threshold · `2` tool/config error ·
`3` LLM unavailable (only with `--require-llm`).

## Where things live

| Item | Windows | Linux / macOS |
|---|---|---|
| venv + package | `%USERPROFILE%\.codesift\venv` | `~/.local/share/codesift/venv` |
| scanner binaries | `%USERPROFILE%\.codesift\tools\<name>\<version>\` | `~/.local/share/codesift/tools/…` |
| command shim | `%USERPROFILE%\.codesift\bin\sift.cmd` | `~/.local/bin/sift` |
| config | `%USERPROFILE%\.codesift\config\config.toml` | `~/.config/codesift/config.toml` |
| credentials | `%USERPROFILE%\.codesift\config\bifrost.env` | `~/.config/codesift/bifrost.env` (mode 600) |
| reports | `%USERPROFILE%\.codesift\runs\<project>\<timestamp>\` | `~/.cache/codesift/runs/…` |
| Claude skill | `%USERPROFILE%\.claude\skills\sift\SKILL.md` | `~/.claude/skills/sift/SKILL.md` |

`CODESIFT_HOME` overrides the data/runs/shim root, `CODESIFT_CONFIG` the config dir.
Windows deliberately avoids `AppData`: packaged (MSIX) desktop apps redirect writes there into a
private per-app folder that other terminals cannot see ([ADR-0002](docs/decisions/ADR-0002-user-level-locations.md)).

### Credentials — `bifrost.env`

```
BIFROST_BASE_URL=https://<gateway>/v1
BIFROST_API_KEY=<secret>
BIFROST_MODEL=ollama/qwen3.8:27b-mtp-q4_K_M        # optional
BIFROST_FALLBACK_MODEL=ollama/qwen3-coder:30b      # optional
```

Any OpenAI-compatible endpoint works (Bifrost, LiteLLM, Ollama's own `/v1`, …) as long as it is
served over HTTPS; the variable names just say `BIFROST`. Environment variables of the same name
override the file. Only `https://` URLs are accepted
(`http://localhost` only with `allow_http_localhost = true` in `config.toml`). Without credentials,
scans still run and the report says triage was skipped.

### Project config — `.codesift.toml` (optional, committed)

Created by `sift init`: exclude globs, extra rule dirs, threshold, scanners on/off, "critical code"
globs and a checklist file for `--review`. Accepted findings live in `.codesift-baseline.json`.

## Pinned tools and updates

| Tool | Pinned | Integrity source |
|---|---|---|
| gitleaks | 8.30.1 | official `checksums.txt` + GitHub asset digest |
| osv-scanner | 2.7.0 | official `SHA256SUMS` + GitHub asset digest |
| trivy | 0.76.2 | official `checksums.txt` + GitHub asset digest |
| opengrep | 1.33.1 | GitHub asset digest (no checksums file is published) |
| ruff / bandit / pip-audit / zizmor | 0.17.3 / 1.9.4 / 2.10.1 / 1.32.0 | `requirements.lock`, every wheel hash |
| opengrep rules | `opengrep/opengrep-rules@f1d2b562` (archived) | tree sha256 in the lock |

Exact versions, URLs and hashes: [`tools.lock.json`](tools.lock.json), [`requirements.lock`](requirements.lock).
New releases are only picked up after a **7-day cooldown** and only if no published advisory affects
them. `sift update` prints current → latest; `sift update --apply` downloads, verifies,
self-tests and switches (previous versions are kept); `sift update --rollback` switches back.
Binaries are checked against their recorded sha256 **every time before they run**.

Without a token GitHub allows 60 API requests per hour; `update` needs about 15. If you hit the limit,
wait, or export a read-only `GITHUB_TOKEN` (never stored by CodeSift).

## What goes over the network

Only: the Bifrost URL (triage), GitHub releases / `api.github.com` and PyPI (`install`, `update` only),
`api.osv.dev` (package names + versions, never code), trivy's check bundle. `--offline` leaves only
Bifrost; `--no-llm` removes Bifrost. Nothing is ever sent to the scanned project's own services.

## Troubleshooting

Run `sift doctor`. Every failing check prints a fix. Common cases:

- **"BIFROST_BASE_URL must use https://"** — fix the URL in `bifrost.env`.
- **`sift doctor`** checks Bifrost `/models`, both models and a warm-up call (`--no-llm` skips it).
- **Triage empty / slow first call** — the LLM VM is loading the model (30–65 s cold start). If calls
  fail with model-load errors, update Ollama on the LLM VM.

## Known limits

- **Speed**: LLM triage takes up to 20 minutes on a first run (later runs use a cache), and
  `--review` takes about 3–6 minutes per 400 lines of critical code on the current LLM VM.
  `--no-llm` / `--fast` give scanner results in about a minute.
- **Coverage**: osv-scanner needs exact versions. Python projects with only `pyproject.toml` ranges
  and no lockfile are not dependency-checked unless `pip-audit` is enabled (the summary warns). The
  opt-in scanners (pip-audit, composer audit, govulncheck) were not exercised on a real project.
- **Platforms**: tested on Windows 11 and a Linux container; macOS is untested.
- **LLM**: verdicts are hints. The fallback model scored 63–68 % in the bake-off and is labelled as
  weaker when used. The logic review found 1 real issue out of 5 on a real project, and it cannot
  see guards that live in other files.
- **Rules**: the vendored opengrep rules come from an archived repository and receive no further
  updates.

## Built on

CodeSift is glue: the detection work is done by these open-source projects, run as separate programs.
Binaries are downloaded from each project's official GitHub release and checksum-verified; Python
tools are installed from PyPI with every wheel hash pinned.

| Project | Role in CodeSift | Licence |
|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | secrets in files and git history | MIT |
| [osv-scanner](https://github.com/google/osv-scanner) + [OSV.dev](https://osv.dev) | known-vulnerable dependencies | Apache-2.0 |
| [trivy](https://github.com/aquasecurity/trivy) | Dockerfile / Kubernetes / Terraform / Helm misconfigurations | Apache-2.0 |
| [opengrep](https://github.com/opengrep/opengrep) | multi-language code patterns (open fork of the semgrep engine) | LGPL-2.1 |
| [opengrep-rules](https://github.com/opengrep/opengrep-rules) | the vendored rule set opengrep runs | LGPL-2.1 + Commons Clause |
| [ruff](https://github.com/astral-sh/ruff) (`S` rules) | Python security lint | MIT |
| [bandit](https://github.com/PyCQA/bandit) | Python security issues | Apache-2.0 |
| [zizmor](https://github.com/zizmorcore/zizmor) | GitHub Actions workflow security | MIT |
| [pip-audit](https://github.com/pypa/pip-audit) (opt-in) | Python dependency audit | Apache-2.0 |
| [composer audit](https://getcomposer.org/doc/03-cli.md#audit) (opt-in) | PHP dependency audit | MIT |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) (opt-in) | Go vulnerability check | BSD-3-Clause |
| [Ollama](https://github.com/ollama/ollama) + Qwen models | the local LLM for triage and review | MIT (Ollama); see each model's card |
| [Bifrost](https://github.com/maximhq/bifrost) | OpenAI-compatible gateway in front of Ollama (any compatible endpoint works) | Apache-2.0 |

CodeSift itself is Python with no runtime dependencies beyond the standard library.

## How it was built and checked

- **Design first**: ten short decision records in [docs/decisions/](docs/decisions/) — scope, install
  locations, opengrep instead of semgrep, stdlib-only runtime, pinning and integrity, the scan
  pipeline, LLM triage, model choice, hook and installer, streaming and the review budget.
- **Supply chain**: every tool version pinned with its sha256 for four platforms, a 7-day cooldown
  and an advisory check before any update, binaries re-verified before every run.
- **Tests**: offline tests (sockets blocked) for every module, including a mock OpenAI-compatible
  server that simulates slow, broken, streaming and hallucinating models; integration tests with the
  real scanners on fixtures for Python, JS/TS, PHP, Go, Docker and GitHub workflows; CodeSift scans
  itself clean as the last test. `mypy --strict`, ruff and black on everything.
- **Model bake-off**: the triage prompt and both models were scored on a labelled corpus of 19
  cases before the defaults were fixed ([docs/model-eval.md](docs/model-eval.md)).
- **Real-world check**: five full runs against a ~560-file production monorepo, every medium+
  finding checked by hand, and the fixes that came out of it
  ([docs/real-world-check.md](docs/real-world-check.md)).
- **Platforms**: Windows 11, and a clean Linux container (install → doctor → scan → uninstall).

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) (tests, lint, conventions) and
[docs/architecture.md](docs/architecture.md). Security problems: [SECURITY.md](SECURITY.md).

## Licence

[MIT](LICENSE). The vendored opengrep rules keep their own licence
([rules/LICENSE.opengrep-rules](rules/LICENSE.opengrep-rules)).
