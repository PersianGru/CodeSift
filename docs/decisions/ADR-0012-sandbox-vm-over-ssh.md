# ADR-0012: Sandbox VM over SSH

- Status: accepted
- Date: 2026-11-14
- Related: [ADR-0004](ADR-0004-stdlib-only-runtime.md) (no new runtime dependency: system `ssh`),
  [ADR-0006](ADR-0006-scan-pipeline.md) (the re-scan gate reuses the scan pipeline)

## Context

Validating a fix means running project tests and proofs of concept: untrusted code. Running it on
the developer's machine is exactly what CodeSift must not do. A local container runtime is not
available everywhere (Windows laptops), and a local VM is heavy. The owner has a lab Linux VM with
Docker.

## Decision

1. **Transport.** The system `ssh` client (`shutil.which`), argument list only, never a shell, with a
   fixed option set: `BatchMode=yes`, `StrictHostKeyChecking=yes` against CodeSift's own pinned
   `vm_known_hosts`, `IdentitiesOnly=yes` with a dedicated key, no agent/X11/port forwarding, no TTY,
   connect/keep-alive timeouts, `LogLevel=ERROR`, `--` before the destination. Host, user, port and
   key path are validated (no option injection); every remote word is `shlex.quote`d. Output is
   streamed with a hard cap and control characters are stripped.
2. **Stateless jobs.** One job = one `docker run` (or `podman run`): code goes in as a tar on stdin,
   output comes back on stdout, the container is removed. Fixed flags: `--rm -i --pull=never
   --network none --cap-drop ALL --security-opt no-new-privileges --read-only`, `noexec` `/tmp`
   tmpfs, `/work` tmpfs, pids/memory/swap/cpu/nofile/fsize limits, `--user 65534:65534`, a pinned
   image whose id is verified before every job. One function builds the argv and cannot emit
   `--privileged`, `--network host`, `-v`/`--mount`, `--pid host`, `--cap-add` or `--device`.
3. **Inside the container** a fixed POSIX `sh` wrapper lists the tar first and refuses absolute
   paths and `..`, extracts it, runs the command under `timeout`, caps the output with `head -c`,
   and prints a final `__CODESIFT_RC__=<n>` line; only the last line is parsed.
4. **Resource guard** before every job: free memory on the VM and the number of running
   `codesift.job` containers (max 1). Refuse with a clear message otherwise.
5. **Self-test** (`sift vm doctor`, and automatically before the first job of a run, cached for 10
   minutes): container starts, non-root, no effective capabilities, read-only root, only `lo` and no
   outbound connection, memory and pids limits as configured, timeout kills, output cap works,
   cleanup leaves nothing, tar extraction refuses `..`/absolute paths.
6. **Fail closed.** SSH failure, host-key mismatch, missing runtime or image, failed self-test or a
   guard refusal → exit 2 with the reason. There is no local execution path.
7. **Label-scoped cleanup.** Everything carries `codesift.job=<uuid>` and the name `sift-<uuid>`;
   `sift vm reset` removes only containers with that label.
8. **Forced-command gate (recommended, optional in v1).** `sift vm admin-script` prints a script for
   the VM admin that creates an unprivileged user whose key is restricted
   (`restrict,command="/usr/local/bin/codesift-gate"`). The gate accepts only the exact job pattern
   above (and the small read-only probes) and exits 126 for anything else. Its allow/deny table is
   tested through a Python mirror and by executing the shipped script with stub commands.
9. **Images.** `sift vm image pull` / `build` run only on explicit command (they use the network on
   the VM); the resulting image id is recorded in `vm.toml` and verified before each job.

## Consequences / trade-offs

- Membership in the `docker` group is root-equivalent on the VM. Without the gate, CodeSift's SSH
  key can run any container command; with it, only the fixed job shape. The VM must be a lab
  machine; this is stated in the wizard, the admin guide and the threat model.
- A job that needs packages from the network cannot get them; bake them into the image
  (`sift vm image build`). The separate network-enabled "prepare" phase is off by default.
- Live behaviour depends on the VM's kernel/runtime; the self-test is what proves it on each VM.
