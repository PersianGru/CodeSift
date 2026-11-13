# Vendored opengrep rules

`opengrep-rules/` is a filtered copy of <https://github.com/opengrep/opengrep-rules> at the commit
pinned in [`../tools.lock.json`](../tools.lock.json) (`rules.commit`), with its integrity hash in
`rules.tree_sha256`. Do not edit files in `opengrep-rules/` by hand — refresh them with
`sift update --apply --lock tools.lock.json` from the checkout.

- **Source**: opengrep's fork of the Semgrep community rules (forked before Semgrep's rules licence
  change). The repository is **archived** (last commit 2025-01-26), so no further updates arrive.
- **Licence**: LGPL-2.1 with the Commons Clause — see [`LICENSE.opengrep-rules`](LICENSE.opengrep-rules).
  CodeSift uses the rules internally and does not sell them.
- **Included**: rule YAML files only (no test targets, no `.test.yaml`) for `python`, `javascript`,
  `typescript`, `php`, `go`, `generic`, `dockerfile`, `yaml`, `bash`.
- **Excluded**: `generic/secrets/` (gitleaks owns secret detection) and all other languages.

Project-specific rules go in a project's own rules directory (`scan.rules_dirs` in `.codesift.toml`);
CodeSift's own extra rules will live in `rules/custom/`.
