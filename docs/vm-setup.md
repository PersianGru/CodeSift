# Sandbox VM: admin guide

CodeSift runs project tests, proofs of concept and patched code only on a separate Linux VM. Each
job runs in a disposable container. Read [ADR-0012](decisions/ADR-0012-sandbox-vm-over-ssh.md) and
the [threat model](threat-model.md) first.

## Requirements

- A **lab** Linux VM. Never a production host. Alpine, Debian and Ubuntu all work.
- Docker or Podman, and the cgroup v2 memory and pids controllers.
- An SSH server, reachable from the developer's machine.
- RAM: at least the job memory cap plus 256 MB free. One job runs at a time.

## 1. Developer: `sift setup --vm`

`sift setup --vm` collects the host, port, user, runtime, image and limits, then:

1. Generates a dedicated ed25519 key. It prints the public key and the `authorized_keys` line.
2. Fetches the VM's host key and shows its fingerprint. You compare it with
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the VM, then type `yes` to pin it.

From then on CodeSift connects only with `StrictHostKeyChecking=yes` against its own
`vm_known_hosts`. If the key changes, it refuses to connect.

## 2. VM admin: `sift vm admin-script`

The developer runs `sift vm admin-script` and gives the printed script to the VM admin. CodeSift never
runs this script itself. Review it, then run it as root. It does the following:

1. Creates the unprivileged user (no sudo, password locked).
2. Adds the user to the `docker` group (Podman: see below).
3. Installs `/usr/local/bin/codesift-gate`, the forced-command gate.
4. Writes `/etc/codesift-gate.images` with the allowed image.
5. Appends the key as `restrict,command="/usr/local/bin/codesift-gate" ssh-ed25519 …`, which means
   no port, agent or X11 forwarding and no pty.

**The gate** reads `SSH_ORIGINAL_COMMAND` and allows only these commands:
- the exact `docker|podman run` job shape: `--rm -i --pull=never --network none --cap-drop ALL
  --security-opt no-new-privileges --read-only`, the tmpfs mounts, the resource limits,
  `--user 65534:65534`, the pinned image, and a single quoted `sh -c` wrapper;
- `cat /proc/meminfo`, label-filtered `ps`, `rm -f <hex ids>`, `image inspect`, `version`;
- `image pull`, and `build --tag sift-…` for the image commands.

Everything else exits 126.

**Trade-off, stated honestly:**
- **With the gate**, the key can only start CodeSift's fixed job shape.
- **Without the gate**, the key can run any container command. Docker group membership is
  root-equivalent on the VM.

The gate is optional in 0.2.0 and strongly recommended. The shipped gate equals
`sift vm admin-script --gate-only`; its allow/deny table is tested.

## 3. Image

```bash
sift vm image pull python:3.12-alpine        # pins the image id in vm.toml
sift vm image build --dockerfile Dockerfile.sandbox --tag sift-myproject:1
```

Both commands **use the network on the VM** and run only when you invoke them. The image needs `sh`,
`tar`, `grep -E`, `timeout`, `head -c` (busybox or coreutils), plus your test tools and
dependencies. Bake dependencies into the image: jobs have no network. CodeSift verifies the image id
before every job, and a changed image is refused until you re-pin it.

The default recommendation is a small official image such as `python:3.12-alpine`, plus your
project's dependencies in a `sift-` image you build yourself.

## 4. Check: `sift vm doctor`

`sift vm doctor` connects, shows the runtime version, and runs the self-test:

| Check | Expected |
|---|---|
| Container | starts |
| User | not root |
| `CapEff` | zero |
| Root filesystem | read-only |
| Network | only `lo`, and an outbound connection fails |
| Limits | memory and pids limits equal the configured caps |
| Timeout | kills a sleeper |
| Output | cap works |
| Input check | a tar with `..` is refused |
| Cleanup | no labelled container is left |

Every failing item prints a fix. A pass is cached for 10 minutes; `sift fix` and `sift validate`
re-run the test automatically when needed.

## Other commands

| Command | What it does |
|---|---|
| `sift vm status` | free memory, running CodeSift jobs, pinned image, last self-test |
| `sift vm reset` | removes containers labelled `codesift.job`, **and nothing else** |

## Podman

Run Podman rootless as the dedicated user. That needs `/etc/subuid` and `/etc/subgid` entries and
`loginctl enable-linger <user>` if your distribution uses systemd. Set `runtime = "podman"` in
`sift setup --vm`. The gate accepts `podman` in place of `docker`.
