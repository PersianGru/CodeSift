# Security policy

## Reporting a vulnerability

Please report security problems in CodeSift **privately** through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Do not open a public issue for them.

Useful in a report: the CodeSift version (`sift --version`), the operating system, what you ran,
and what happened. Never include real secrets or credentials; a fake value of the same shape is
enough.

You can expect a first answer within a week. Fixes are released as a new version and listed in
[CHANGELOG.md](CHANGELOG.md).

## Scope

In scope: CodeSift's own code, installer, hook and skill, for example:

- a secret value reaching a report, log, raw output or LLM prompt unmasked;
- CodeSift writing into a scanned project without an explicit command;
- network traffic outside the hosts listed in [RULES.md](RULES.md);
- a downloaded tool running without its sha256 matching `tools.lock.json`;
- a scanned (untrusted) repository making CodeSift run code or read files outside the project.

Out of scope: vulnerabilities in the scanners themselves (gitleaks, osv-scanner, trivy, opengrep,
ruff, bandit, zizmor, pip-audit, …) — please report those to their projects — and findings that a
scanner misses or gets wrong, which are normal issues.

## Supported versions

Only the latest release gets fixes.
