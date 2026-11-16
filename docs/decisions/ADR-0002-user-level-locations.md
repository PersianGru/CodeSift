# ADR-0002: User-level install locations

- Status: accepted (revised 2026-11-12: Windows moved out of AppData)
- Date: 2026-11-12

## Context

CodeSift must work from any project without admin rights and must never write into the scanned
project (except on explicit commands). Reports must not end up committed by accident.

The first design used `%LOCALAPPDATA%\codesift` and `%APPDATA%\codesift` on Windows. Testing showed
that packaged (MSIX) desktop apps, such as apps that host a terminal or a coding assistant, are a
problem: Windows silently redirects their child processes' **writes** under `AppData` into a private
per-app folder (`AppData\Local\Packages\<app>\LocalCache\…`). An install or update made from such an
app would therefore be invisible to the user's own terminal and to every other app, and would
disappear if the app were reset.

## Decision

- **Windows**: one folder outside AppData — `%USERPROFILE%\.codesift`:
  `venv\`, `tools\`, `lib\`, `rules\`, `runs\`, `bin\` (command shim) and `config\` (`config.toml`,
  `bifrost.env`). Chosen by the owner on 2026-11-12.
- **Linux/macOS**: XDG — `$XDG_DATA_HOME/codesift`, `$XDG_CONFIG_HOME/codesift`,
  `$XDG_CACHE_HOME/codesift/runs`, shim in `~/.local/bin`. macOS uses the same layout rather than
  `~/Library/...`, to keep one code path and one set of docs for the two Unix platforms.
- `CODESIFT_HOME`, `CODESIFT_CONFIG` and `CODESIFT_RUNS` override (used by tests and portable setups).
- The Claude skill goes to `~/.claude/skills/sift/`.
- Credentials are a separate `bifrost.env` (mode 600 / user-only ACL), not part of `config.toml`, so
  the config can be shared or printed safely.
- Runs keep the last 20 per project.

## Consequences

Every terminal, app and Claude session on Windows sees the same install. Uninstall removes one folder
on Windows (three on Linux/macOS) plus the shim and skill. Adding the shim folder to the user PATH
(Windows) needs the user's consent at install time.
