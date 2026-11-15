# Sandbox VM: admin guide

CodeSift runs project tests, proofs of concept and patched code only on a separate Linux VM. Each
job runs in a disposable container. Read [ADR-0012](decisions/ADR-0012-sandbox-vm-over-ssh.md) and
the [threat model](threat-model.md) first.

## Requirements

- A **lab** Linux VM. Never a production host. Alpine, Debian and Ubuntu all work.
- Docker or Podman, and the cgroup v2 memory and pids controllers.
- An SSH server, reachable from the developer's machine.
- RAM: at least the job memory cap plus 256 MB free. One job runs at a time.

## 1. `sift setup --vm` does the whole setup

You answer a few questions, and CodeSift does the rest:

| Question | Default |
|---|---|
| VM IP address or host name | - |
| SSH port | 22 |
| Pin the VM's host key? Type `yes` after comparing the fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the VM | - |
| Admin user name on the VM | `root` |
| Does the admin sign in with an SSH key or a password? | `key` if a usual key (`id_ed25519`, `id_ecdsa`, `id_rsa`) is in your SSH folder |
| Path of the admin's private key (key only) | the key that was found |
| Folder to keep CodeSift's own SSH key in | your SSH folder: `%USERPROFILE%\.ssh` on Windows, `~/.ssh` on macOS and Linux |

Then CodeSift:

1. **Creates its own key** (`codesift_sandbox_ed25519` and `.pub`) in the chosen folder, or reuses it
   if it is already there.
2. **Logs in once as the admin** and runs the setup script below as root. If the admin is not root,
   the script uses `sudo`, or `doas` on Alpine. A password, a key passphrase or the sudo password is
   typed into ssh's or sudo's own prompt: **CodeSift never sees or stores it**. The admin key is only
   passed to ssh as a path; it is never read. The login trusts only the host key you just pinned,
   ignores your ssh config and forwards nothing.
3. **Saves the settings** (`vm.toml`). From now on it uses only its own restricted key; the admin
   login is not used again.
4. **Pulls the sandbox image** and pins its id.
5. **Runs the isolation self-test** (`sift vm doctor`) and prints the result.

The dedicated user is `codesift`, with Docker, the image `python:3.12-alpine` and safe limits (512 MB,
1 CPU, 128 processes, 300 s per job). Running `sift setup --vm` again offers to only re-check the VM.
Every connection uses `StrictHostKeyChecking=yes` against CodeSift's own `vm_known_hosts`; if the
VM's host key changes, CodeSift refuses to connect.

## 2. What the setup script does on the VM

It is safe to run more than once; anything already in place is left as it is. To review it, or to
run it by hand instead, print it with `sift vm admin-script`.

1. Creates the unprivileged user `codesift`: no sudo, and no usable password (`*`, not a locked
   `!`, because sshd without PAM, as on Alpine, refuses key logins for locked accounts).
2. Makes sure Docker is installed and running, installing it with the VM's package manager (`apk`,
   `apt-get`, `dnf`, `yum`, `zypper` or `pacman`) only if it is missing, and adds `codesift` to the
   `docker` group. For Podman, see below.
3. Installs `/usr/local/bin/codesift-gate`, the forced-command gate.
4. Writes `/etc/codesift-gate.images` with the allowed image.
5. Adds CodeSift's key once, as `restrict,command="/usr/local/bin/codesift-gate" ssh-ed25519 …`:
   no port, agent or X11 forwarding and no pty.
6. Warns if `sshd` has `AllowUsers` or `AllowGroups` that would keep `codesift` out. It never edits
   the sshd configuration.

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

`sift setup --vm` always installs the gate. The shipped gate equals
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
