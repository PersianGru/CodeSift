# CodeSift rules — what it must never do

These rules bind the tool, its contributors and any assistant that runs it for a user.
A change that breaks one of them is a bug, whatever the reason.

1. **Never modify the scanned project**, except on explicit command:
   `sift init` (writes `.codesift.toml`), `sift baseline accept` (writes
   `.codesift-baseline.json`) and `sift hook install` / `uninstall`.
2. **Never scan the network.** No port scans, crawling, DAST, fuzzing or requests to the project's
   services. Static analysis of files and git history only.
3. **Allowed outbound network — nothing else:**
   - the configured Bifrost URL (LLM triage);
   - `api.github.com` and GitHub release downloads (only `install` and `update`);
   - `pypi.org` / `files.pythonhosted.org` for the hashed Python scanner lock (only `install` and
     `update`);
   - `api.osv.dev` (dependency lookups — sends package names and versions, never code);
   - trivy's check bundle / registry download (misconfiguration checks).

   `--offline` disables everything except Bifrost; `--no-llm` disables Bifrost.
4. **Never print, log, store or send a secret value.** Gitleaks matches are masked (`abcd…(len N)`)
   before they reach reports or the LLM. Tokens never go in URLs, and are kept off command lines
   (use env vars / headers).
5. **Never let the LLM hide a finding.** It annotates and ranks; it cannot delete a finding or move a
   high/critical below "needs human review". If the LLM is down, findings are listed untriaged and the
   report says so.
6. **Never hammer the LLM VM or the network.** One LLM request at a time, timeouts, retries with
   backoff, per-run caps. Scanners run with bounded parallelism (default 2).
7. **Never download anything** that is not in `tools.lock.json`, and never run a binary whose sha256
   does not match the lock.
8. **Never auto-install or auto-update** tools during a scan. Updates happen only via
   `sift update --apply`.
9. **Never commit reports or raw outputs** into the scanned project; they live in the user cache dir.
10. **Never weaken a check to make a test or hook pass.** Accepting a finding is an explicit baseline
    entry with a reason (and optional expiry).

For assistants using CodeSift in another project, additionally:

- Never edit the baseline, disable a scanner or lower a threshold without the user's explicit OK.
- Never print credentials. Never use `git push --no-verify` — that is the user's escape hatch only.
