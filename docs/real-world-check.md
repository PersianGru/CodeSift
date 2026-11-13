# Real-world check

On 2026-11-12, CodeSift ran read-only against a private production project: a ~560-file monorepo
with a Python/FastAPI backend, a TypeScript web app, a React Native app, a small storefront service,
Dockerfiles and GitHub Actions workflows. Its licensing code and storefront were marked critical, and
a 20-rule checklist was condensed from the project's own integration spec. Project-specific findings
went to the owner privately; this page has the aggregate numbers and what changed in CodeSift.

A fingerprint of the project (HEAD, status, every file, ignored-folder listing) was identical before
and after every run. CodeSift wrote nothing into the project.

## Runs

| Run | What changed before it | Wall time | Result |
|---|---|---|---|
| 1 | — | 17 min | opengrep failed (cache rename "Access denied" on Windows); 25 of 38 triage calls went to a per-line policy rule |
| 2 | opengrep cache built in place; policy rules grouped and not sent | 14 min | opengrep 138 raw findings; review stopped on its first request (HTTP 504) |
| 3 | 400-line review requests, 80-file cap, failed requests no longer stop the review | 68 min | 11 of 12 review requests HTTP 504 after 3 attempts each |
| 4 | streamed answers, reasoning-effort switch, review budget (ADR-0010) | 35 min | all 12 review requests answered (≈ 2.8 min each); scanners ≈ 1 min; triage from cache |
| 5 | whole-file excerpts for workflows, Dockerfile duplicates merged (prompt `t4`) | 12 min | 22 findings triaged, median 34 s per answer |

Scanner times in a full run: gitleaks 2 s (history included), osv-scanner 3 s, opengrep 34 s, trivy
17 s, bandit 6 s, ruff and zizmor < 1 s. The LLM dominates the wall time.

## Findings (run 5)

2 critical, 20 high, 24 medium, 137 low/info. Raw: 39 gitleaks hits (5 after dedupe of the same
strings across commits), 138 opengrep, 80 bandit, 42 ruff, 58 zizmor, 13 osv-scanner, 4 trivy.

Medium and above (46), checked by hand against the code:

| Kind | Count | Verdict |
|---|---|---|
| Dependency advisories (JS dev/build tooling) | 13 | real (developer/CI exposure) |
| CI workflow hardening (unpinned actions, write permissions, persisted checkout credentials) | 15 | real, low effort to fix |
| Secrets (gitleaks) | 5 | 1 real policy question (product key in a private repo's history), 4 false positives (character set, documented example key ×2, published test vector) |
| Containers running as root | 2 | real, minor (one dev-only) |
| Code patterns (subprocess, SQL, YAML, CSRF, crypto mode) | 11 | 2 real (one required by an external API, one hardening), 9 false positives |

Scanner false-positive rate at medium+: about **13 of 46 (28 %)**, almost all code patterns and
secret look-alikes; the dependency and workflow findings were all real.

**LLM triage** (22 code/config findings sent; secrets, advisories and deterministic policy rules
are never sent): in run 4 (prompt `t3`), 18 of 24 verdicts were right. 5 of the 6 wrong ones called
real workflow/Dockerfile hardening "likely false positive", because a ±30-line window showed one job
of a two-job workflow. After the fix (run 5) **all 22 verdicts were defensible**, including every
code-pattern false positive. One "likely real" (an unvalidated table name in a backup restore) turned
out to be blocked from SQL injection but still worth an allow-list. High/critical findings stay
"needs review" whatever the verdict (RULES.md §5).

**Lockfile coverage:** three Python packages declared only version ranges with no lockfile, so their
dependencies were not checked at all. CodeSift now warns about this in the summary.

**AI logic review** (35 critical files, 12 requests, reasoning on): 5 issues. 1 was real (a
check-then-insert race in webhook deduplication). 4 were false positives: 3 because the guard lives
in another file (startup config validation, a verifier module), and 1 because a token in a URL was
the documented API contract. The review is useful as a reading aid, and it stays labelled
"unverified".

## Changes made in CodeSift because of this check

- Answers are streamed, with reasoning switched off by `reasoning_effort: "none"`. The review has
  a time budget and reports exactly what it did not cover
  ([ADR-0010](decisions/ADR-0010-streaming-and-review-budget.md)).
- Review requests are about 400 lines, packed per file. A failed request no longer stops the review.
  Tests and assets are skipped. New flags: `--critical`, `--checklist`, `--review-all`,
  `--review-budget`.
- Per-line policy findings (unpinned actions) are grouped per file. GitHub's own actions are capped
  at medium. Policy findings are not sent to the LLM, and they merge with opengrep's equivalent rule.
- Triage excerpts show the whole workflow file for workflow findings, and up to three related
  definitions elsewhere in the file.
- trivy's whole-file Dockerfile findings merge with opengrep's line findings.
- Findings on git-ignored files are dropped. A warning appears for manifests without a lockfile.
  Proxy error pages are reduced to their title.
- opengrep's rule cache is built in place, and directory replacement retries before copying
  (Windows "Access denied").

## Not covered by this check

- One project, on Windows only. Linux was covered by a separate container test; macOS is untested.
- The precision figures are one project's numbers, not a benchmark.
- The opt-in scanners (pip-audit, composer audit, govulncheck) were not enabled.
