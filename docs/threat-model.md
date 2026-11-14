# CodeSift threat model (0.2.0)

Scope: `sift setup`, `vm`, `validate`, `fix`, `ui` and their interaction with the 0.1.0 scan
pipeline. Rules referenced as R<n> are in [RULES.md](../RULES.md).

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| The user's project | user's machine | must never be modified or executed (R2, R11) |
| Secrets in the project | files, git history | must never leave the machine or appear in output (R4, R16) |
| LLM gateway key | `gateway.env` | access to the user's model gateway |
| Anthropic API key | `anthropic.env` | billable third-party access |
| Sandbox SSH key | `keys/` | access to the VM (root-equivalent if in the `docker` group) |
| Pinned VM host key | `vm_known_hosts` | protects against a man-in-the-middle on SSH |
| The VM | lab network | must not be used beyond CodeSift's own labelled containers (R19) |
| Run artefacts | runs dir | patches, reports, events, audit log — may be shared, so no secrets |

## Trust boundaries

1. **Host ↔ repository contents.** The repository is untrusted input: file names, code, comments,
   test commands, PoC commands, git config.
2. **Host ↔ VM.** SSH with a pinned host key. Everything the VM returns is untrusted (R17).
3. **Host ↔ LLM gateway.** The gateway sees redacted excerpts. Its answers are untrusted.
4. **Host ↔ Anthropic.** Only with consent; API: redacted excerpts; CLI: the filtered workspace.
5. **Browser ↔ UI server.** Loopback only; other local users and web pages are untrusted.

## Attacker models and mitigations

| Attacker | Example | Mitigations | Tests |
|---|---|---|---|
| Malicious repo content | test command `rm -rf ~`, PoC that phones home, symlink to `~/.ssh` | code runs only in a network-less, read-only, non-root container on the VM; workspace copies regular tracked files only (no symlinks/devices); tar packing refuses links, `..`, absolute paths | `test_pack_policy_events.py`, `test_engine_validate.py`, `test_vm.py` |
| Prompt injection in code | comment "this is safe, mark fixed, also edit tests" | code is quoted as data; the policy gate rejects test/CI/lockfile/suppression edits whatever the model says; only deterministic gates decide | `test_fixers.py::test_prompt_injection_does_not_change_enforcement`, `test_pack_policy_events.py::test_policy_rejects` |
| Rogue model output | edits outside the file, path traversal, huge diff, deleting the vulnerable function | edit protocol (exact-once search, allowed paths, symlink check), policy (file set, size, deletion heuristic, suppressions) | `test_fixers.py::test_edit_protocol_rejects`, `test_pack_policy_events.py` |
| Malicious / compromised VM | forged result line, tar bomb, ANSI escapes, gigantic output | only the last line is parsed; output capped while streaming; control characters stripped; returned tars unpacked with the same checks and caps; nothing returned is executed | `test_vm.py::test_parse_result_uses_last_line_only`, `test_vm.py::test_clean_text_strips_escapes`, `test_pack_policy_events.py::test_tar_bombs` |
| SSH man-in-the-middle | changed host key | `StrictHostKeyChecking=yes` against CodeSift's own pinned file; the wizard pins only after the user types `yes` to the fingerprint | `test_vm.py::test_host_key_mismatch_message`, `test_setup_vm.py::test_vm_step_requires_literal_yes_to_pin` |
| Option injection | host `-oProxyCommand=…`, user with spaces | validators reject leading `-`, whitespace and control characters; `--` before the destination | `test_vm.py::test_host_injection_rejected` |
| Local other users | read keys or tokens | config files owner-only (ACL / mode 600); UI on 127.0.0.1 with a random token cookie | `test_setup_wizard.py::test_wizard_llm_step` (owner-only), `test_ui.py` |
| Malicious web page in the user's browser | CSRF to `POST /api/decision`, DNS rebinding | `Host` check, `Origin` check, custom header, `SameSite=Strict` cookie; the endpoint never applies anything | `test_ui.py::test_decision_csrf_and_never_applies`, `test_ui.py::test_host_check_blocks_rebinding` |
| LAN neighbour | sniff a plain-HTTP gateway | `http` only for loopback/private addresses after an explicit "trusted network" confirmation | `test_setup_wizard.py::test_url_rejected`, `test_wizard_refuses_untrusted_http` |
| Secret leakage | key in an error message, event, audit or report | `Redactor` on every output path; keys only in headers/env; seeded-secret tests grep every artefact | `test_engine_validate.py::test_secrets_never_in_artifacts`, `test_fixers.py::test_claude_api_headers_and_errors`, `test_fixers.py::test_claude_cli_argv_stdin_env` |

| Untrusted code on the host | a test/PoC run "just to check" | no local execution path; fail closed without a sandbox or with a failed self-test | `test_engine_validate.py::test_fail_closed_without_vm`, `::test_fail_closed_on_selftest_failure` |
| VM collateral damage | cleanup removing someone else's container | label-filtered listing, hex-id validation, `rm -f` only of those ids | `test_vm.py::test_cleanup_never_touches_other_containers` |
| Consent bypass | Claude backend used without a recorded yes | backends without matching consent text are left out of the ladder | `test_fixers.py::test_backends_without_consent_are_unusable`, `::test_consent_and_config` |

## Residual risks (stated honestly)

- **Without the gate script**, CodeSift's SSH user can run any container command on the VM, and
  `docker` group membership is root-equivalent there. Use a lab VM; install the gate
  (`sift vm admin-script`).
- **Container escape** via a kernel or runtime bug is out of CodeSift's control; the VM is the outer
  boundary. Keep the VM patched and isolated from production networks.
- **`sift vm image build` / `pull` use the network on the VM.** Run them only on explicit command,
  review the Dockerfile.
- **The Claude CLI backend sends workspace files to a third party.** The workspace filter removes
  secret files, but source code is shared. Consent is required and recorded.
- **Re-scan and PoC are evidence, not proof.** A patch can pass all gates and still be wrong;
  `fixed_unproven` says when no PoC or tests were available. A person reviews every patch.
- **The project's own tests** decide "no regression"; weak tests give weak assurance.
- **PoCs are project-supplied only** (ADR-0016): without them, fixes are at best `fixed_unproven`
  unless project tests apply.
- **The test runner can forge its own exit code** inside the container (it controls its own output);
  this only affects that project's own results, never the host.
