# ADR-0005: Pinning, 7-day cooldown and integrity checks

- Status: accepted
- Date: 2026-11-12

## Context

CodeSift downloads and runs third-party security tools. Several scanner projects have had supply-chain
incidents (for example trivy's GHSA-69fq-xp46-6x23, March 2026: a compromised `v0.69.4` release and
compromised GitHub Actions). A security tool must not become the attack path.

## Decision

1. **Pinned versions only.** `tools.lock.json` holds, per tool and platform, the release asset URL
   (must be `https://github.com/<repo>/releases/download/<tag>/…`), size and sha256. Python scanners
   are pinned in `requirements.lock` with the sha256 of every published wheel; installed with
   `--require-hashes --only-binary=:all: --no-deps` (no source builds → no build scripts run). pip
   itself is pinned in the same lock.
2. **Cooldown.** `update` picks the newest *stable* release older than 7 days (`cooldown_days` in the
   lock). Python dependencies are resolved with pip's `--uploaded-prior-to` so transitive packages
   respect the same cooldown.
3. **Advisories.** Before pinning, `update` queries the GitHub repository security advisories and, for
   Go-based tools, the GitHub advisory database for the module; a release inside a vulnerable range is
   skipped and reported. The pinned version is re-checked on every `update`.
4. **Two independent hash sources.** The official checksums file must list the asset and, where
   GitHub provides a server-side asset digest, both must agree. opengrep publishes no checksums file
   (only sigstore signatures), so its digest comes from GitHub's asset digest alone. Verifying the
   sigstore signature would need cosign; noted as a possible improvement.
5. **Verify on every run.** After the archive hash is verified, only the named binary is extracted
   (by base name — archive paths can never escape) and its own sha256 goes into an install manifest.
   Before any run the binary's sha256 must match the manifest and the manifest must match the lock;
   otherwise CodeSift refuses to run it.
6. **Neutral working directory.** Self-tests run tools from an empty temp dir; scans will run tools
   with an absolute path and never from inside the scanned repo when avoidable (mitigates the class of
   bugs in opengrep GHSA-p779-wpvx-j33f / GHSA-gr98-vh6p-jh9v, fixed in 1.30.2).
7. **Network allow-list.** Install/update traffic goes only to GitHub and PyPI hosts, HTTPS only,
   redirects re-checked; an optional `GITHUB_TOKEN` is sent only to `api.github.com` and stripped on
   cross-host redirects.

## What was checked for the first pins (2026-11-12)

| Tool | Pinned | Newer, skipped | Advisories checked |
|---|---|---|---|
| gitleaks | 8.30.1 (2026-03-21) | – | repo: none; Go DB: none affecting |
| osv-scanner | 2.7.0 (2026-10-12) | 2.7.1 (2 days old) | repo: none |
| trivy | 0.76.1 (2026-10-21) | 0.76.2 (6 days old) | 5 repo advisories, all fixed ≤ 0.72.0 (incl. the 0.69.4 compromise) |
| opengrep | 1.33.1 (2026-10-29) | – (2.0.0 alphas are pre-releases) | 3 advisories published 2026-11-10, all fixed in 1.30.2 |
| ruff | 0.17.3 | 0.17.4 (6 days old) | – |
| bandit / pip-audit / zizmor / pip | 1.9.4 / 2.10.1 / 1.32.0 / 26.3 | – | – |

## Consequences

Fresh releases arrive a week late. A compromised release that is caught within a week never reaches
CodeSift users. `update --apply` keeps the previous binaries and lock (`tools.lock.prev.json`) for
`--rollback`.
