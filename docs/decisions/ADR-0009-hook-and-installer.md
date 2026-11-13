# ADR-0009: Pre-push hook and installer

- Status: accepted
- Date: 2026-11-12

## Hook

- **Where**: the directory `git rev-parse --git-path hooks` returns, so `core.hooksPath` is
  respected. An existing `pre-push` is renamed to `pre-push.local` and run first with the same stdin;
  `uninstall` restores it and refuses to delete a hook CodeSift did not write (marker line).
- **What**: `sift scan . --fast --no-llm --threshold high --since <remote sha>` per pushed ref
  (full fast scan for a new branch). Blocking threshold is fixed at high: the hook stops new
  high/critical findings, not style debt.
- **Never brick a repo**: missing interpreter, unknown ref, tool error → warning, push allowed.
  `CODESIFT_SKIP_HOOK=1` and `git push --no-verify` are the owner's escape hatches; assistants never
  use them (RULES.md).
- The hook calls the venv interpreter by absolute path (written at install time) rather than the
  `sift` shim, because Git for Windows runs hooks in `sh`, which cannot run `.cmd` shims.

## Installer

- Thin `install.ps1` / `install.sh` wrappers run `python -m codesift install` from the checkout
  (`PYTHONPATH=src`), so no build backend or unhashed package is fetched.
- The package is copied into `<data>/lib` and linked into the venv with a `.pth` file: the install
  works after the checkout moves; re-running the installer after `git pull` updates it.
- Shims: `sift.cmd` (cmd/PowerShell) and a POSIX `sift` (Git Bash, Linux, macOS).
- **Asks first** (interactive prompts, or explicit flags): adding the shim folder to the Windows user
  PATH (`HKCU\Environment`, `WM_SETTINGCHANGE` broadcast; removed on uninstall) and copying Bifrost
  credentials. Only `BIFROST_*` keys are copied; the copy gets a user-only ACL (`icacls
  /inheritance:r /grant:r <account>:(F)`) where the account comes from the process token
  (`GetUserNameExW`) and `icacls` from `GetSystemDirectoryW` — never from environment variables.
- The Claude Code skill is copied to `~/.claude/skills/sift/SKILL.md` unless a different skill
  already uses that name.
- `uninstall` removes venv, tools, rules, cache, shims, skill and PATH entry; runs and config
  (credentials) only with `--purge`. On Windows it must run from the checkout (`install.ps1
  -Uninstall`) because the running interpreter cannot delete itself.
