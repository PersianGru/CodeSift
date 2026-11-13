# ADR-0006: Scan pipeline choices

- Status: accepted
- Date: 2026-11-12

## Decisions

1. **Read-only by construction.** Every tool runs with an absolute binary path from an empty work
   directory inside the run folder, never with the project as its working directory. ruff runs
   `--isolated --no-cache`; git runs with `GIT_OPTIONAL_LOCKS=0`. An integration test hashes every
   project file (including `.git`) before and after a scan.
2. **Untrusted repositories cannot run code through git.** All git processes (CodeSift's and the
   scanners') get `core.fsmonitor=false`, `diff.external=` and
   `protocol.allow=never` via `GIT_CONFIG_*` environment variables; diffs use `--no-ext-diff
   --no-textconv`; refs starting with `-` are refused.
3. **Tests are not scanned by code-pattern tools.** opengrep, ruff and bandit skip `test/`,
   `tests/`, `__tests__/`, `spec/`, `testdata/`, `fixtures/` and `*_test.go`, `*.test.ts`, … (they
   are full of deliberately unsafe code). gitleaks, osv-scanner and trivy still scan them. opengrep's
   own default ignore list is turned off (`--x-ignore-semgrepignore-files`) so CodeSift's exclude list
   is the single source of truth; every finding path is also post-filtered.
4. **opengrep loads only security rules of detected languages.** Rule parsing dominates opengrep's
   run time (≈ 0.25 s per rule at 2 threads on this PC). The ruleset is the `security` sub-tree of
   the vendored rules for the detected languages plus `generic`, copied once per (rules commit,
   language set) into the cache. opengrep gets half the CPU cores (max 6).
5. **osv-scanner without deps.dev.** `--no-resolve` keeps traffic to `api.osv.dev` only (allowed
   host); call analysis is off. One finding per vulnerable package (worst CVSS), advisories listed in
   `extra`, keeps the summary short.
6. **gitleaks**: in a git repo, history (or `<since>..HEAD`) plus unstaged and staged changes; a
   plain directory otherwise. Untracked-but-not-ignored files are not covered in git mode (known
   gap). CodeSift generates a gitleaks config that extends the defaults (or the project's
   `.gitleaks.toml`) with its exclude paths.
7. **Secrets never leave masked form.** gitleaks runs with `--redact`; every raw file is re-masked
   with the pattern redactor; every finding's text fields get a final masking pass (bandit, for
   example, quotes the matched string in its message); snippet lines on which gitleaks found a
   secret are replaced. The integration test plants a generated token and asserts it appears in no
   file of the run directory.
8. **Opt-in runners**: pip-audit (osv-scanner already covers pinned requirements; when enabled it
   runs `--no-deps --disable-pip` against the OSV service only, so nothing is installed or
   resolved), composer audit and govulncheck (they use tools from PATH and contact hosts outside the
   allow-list: packagist.org, vuln.go.dev; govulncheck runs with `GOPROXY=off GOFLAGS=-mod=readonly
   GOTOOLCHAIN=local`).
9. **Exit codes**: 1 if any non-baselined finding is at/above the threshold; otherwise 2 if a scanner
   or config failed; otherwise 3 with `--require-llm` when triage did not run; otherwise 0.
10. **Summary budget**: ≤ 150 lines; high/critical first, then medium; low/info only as counts unless
    `--verbose`; the rest is in `report.json`.
