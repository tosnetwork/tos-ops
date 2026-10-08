# Self-hosted CI runners on the development host

Implements the design agreed in the memo repository,
`ci-self-hosted-runner/README.md` (v8). Each GitHub Actions job for
`tosnetwork/tos` that is routed here runs in a single-use QEMU VM, in one of
three fixed slots. A root-owned admission hook inside the VM, confirmed by the
host, admits only pull requests by the trusted logins and pushes to `main`.

## Layout

| Path in this directory | Installed to | Role |
|---|---|---|
| `host/systemd/` | `/etc/systemd/system/` | slot template and drop-ins, slice, supervisor, slot-control socket, network, store mount |
| `host/lib/` | `/usr/lib/tos-ci/` | root-owned slot scripts, slot-control helper, supervisor, image build |
| `host/nft/tos-ci.nft` | `/usr/lib/tos-ci/` | VM network isolation |
| `host/network/` | `/etc/systemd/network/` | bridge `tosci0`, 10.231.37.1/24 |
| `host/config.json`, `host/trusted-logins` | `/etc/tos-ci/` | supervisor configuration and the allowlist |
| `guest/` | baked into the VM image | admission hook, single-job runner unit, console and audit settings |
| `tests/` | — | unit tests (`python3 -m unittest discover -s tests`) |

Accounts: `tos-ci` (supervisor; holds the token, no systemd rights, not in
kvm/docker/lxd/sudo), `tos-ci-slot1..3` (one QEMU each, kvm only),
`tos-ci-build` (image builder, kvm only).

## Install and start

1. Save the fine-grained token as described in the memo's `token-setup.md`.
2. Run `sudo ./install.sh`. It moves the token to `/etc/tos-ci/token` (owned by
   `tos-ci`, mode 0600) and shreds the source.
3. Build an image with `sudo python3 -I /usr/lib/tos-ci/build-image.py`. Rebuild weekly.
4. Start the supervisor with `sudo systemctl enable --now tos-ci-supervisor`.

Nothing runs a real job until the repository variable `SELF_HOSTED_LINUX` is
`true` and jobs are routed with the agreed `runs-on` expression.

## Operating

- **Drain** with `sudo touch /etc/tos-ci/drain`: no new VMs start, idle VMs are
  removed, and running jobs finish. Remove the file to resume.
- **Stop** with `sudo systemctl stop tos-ci-supervisor`: drain, wait up to ten
  minutes, then stop every slot and deregister.
- **Change the allowlist** by editing `/etc/tos-ci/trusted-logins` (root). It
  takes effect on the next admission request. Every VM not yet admitted is
  stopped when the change is seen.
- **Return to GitHub-hosted runners**:
  1. drain;
  2. set `SELF_HOSTED_LINUX=false`;
  3. cancel and rerun the queued jobs (see the memo, §9 and §11).
- **Logs**:
  - supervisor: `journalctl -u tos-ci-supervisor`, one JSON object per line;
  - a slot's guest console: `journalctl -u tos-ci-vm@N`.

## Verification mode

With auditing on, every `execve` in a VM is recorded:
- auditd writes its own log, without rotation;
- `audit-forward` streams it, from its first byte, over a flow-controlled virtio-serial port;
- the host's `tos-ci-audit@N` writer archives it under `/var/lib/tos-ci/audit/slotN/`. The kernel caps each file at 1 GiB, and `audit-prune` keeps closed files within 5 GiB and 200 files.

The guest kernel boots with `audit=1`, so no record is dropped without being counted.

`tests/live/audit-check.py` judges each lifetime from its console and its archive:
- **Valid** needs one nonce-bound end marker, contiguous serials, `lost=0` and the hook's own execution.
- **Denied** passes only with no job-controlled execution.
- **Allowed** passes only if job-controlled execution is visible.

Every exec must match an explicit rule in its table. The live controls are `tests/live/*-controls.sh` and the rounds in the memo.

The archives hold each VM's one-time runner registration: its JIT config appears in the runner's argv. They are readable only by root and the slot account, and are never copied out of the host.

### Accepted exposure: actions are unpacked before admission

Before the job-started hook runs, the runner downloads every remotely referenced action and unpacks its tarball, as the `runner` account inside the VM: `tar -xzf …/_actions/_temp_<uuid>/<uuid>.tar.gz` in `…/_temp_<uuid>/_staging`, with `gzip -d`.

So a denied job can make the runner parse an archive it chose. No job code runs: verified on runner v2.338.0, a remote Dockerfile action is built and a JavaScript action is started only after the hook.

The checker explains exactly this unpack, only for the verified runner version, and reports the count in every verdict.

**When the image's runner version changes, rerun the pre-admission and `--as-denied` controls before raising `VERIFIED_RUNNER` in the checker.** Until then the unpack fails every denied lifetime.

## Activation checklist

- [ ] The owner decides whether to restrict the repository's Actions policy to "Allow select actions" (GitHub-owned, verified creators, `tosnetwork/*`). That narrows which archives can reach the pre-admission unpack. It is an owner decision, and nothing here changes it.
- [ ] `"audit": false` installed (verification mode off).
- [ ] Repository variables `SELF_HOSTED_LINUX` and `CI_TRUSTED_LOGINS` set.

## Deviations from the memo design

- The code lives under `local/ci-runner/` in this repository, rather than a
  top-level `ci-runner/`, because this repository is organised per network and
  the runner host is the local development host.
- Execution auditing is switched on only for verification runs (`"audit":
  true` in `config.json`, set through `install.sh` so the install manifest
  matches). A real build executes millions of processes. See "Verification
  mode" below.
- A job that shows as busy on GitHub without an admission record is stopped
  after `unadmitted_busy_seconds`. This is the host-side form of the
  "activity without admission" violation.
