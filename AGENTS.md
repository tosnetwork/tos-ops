# Agent entry point for tos-ops

Read this before proposing or running an operation. `CLAUDE.md` is a symlink to
this file. This repository contains deployment scripts and runbooks, **not node
source or operational keys**. Locate the separate tos checkout through `TOS_ROOT`
or the script's explicit path options. Do not infer the running network from a
directory name: compare its zero-state identity with the approved ceremony.

## Open the right document

| Task | Read first |
| --- | --- |
| Find tools, tests and environment boundaries | [README.md](README.md) |
| Operate an independent testnet validator | [testnet/OPERATOR.md](testnet/OPERATOR.md) |
| Genesis, staking pools, coordinator signing, onboarding, fee top-ups, recovery or reset | [testnet/CEREMONY.md](testnet/CEREMONY.md) |
| Cross-node checks, watching and alert relay | [testnet/README.md](testnet/README.md) |
| Disposable local chain / health stack | [local/README.md](local/README.md), then [local/OPERATIONS.md](local/OPERATIONS.md) |
| Production planning | [production/README.md](production/README.md); proposals, not a deployment approval |

## Standing testnet fee authority (owner, 2026-11-04)

The owner delegates necessary testnet fee decisions and top-ups to agents. For the
existing authorized public-testnet validators and ongoing authorized tests, choose
and execute justified operational fee payments without asking for another human
approval per payment. This supersedes older per-action fee-approval wording in
this file and the runbooks. The current four-validator top-up of 3 TOS each,
12 TOS total, is authorized.

Before execution, verify the approved genesis, recipients, existing operation
state, source funds and remaining reserve. Use the smallest justified amount from
existing testnet operational wallets, preserve earmarked allocations and staking
principal, and record operation IDs and public settlement receipts. This is not
authority to withdraw principal, use production funds or replay an unknown
transaction. Keep all signing, journal, network and custody guards intact.

## Hard safety rules

- Never print, inspect through a tool response, copy to another host, or include in
  logs/chat a seed, private key, mnemonic, vault master key or token. Human-only
  encrypted backup/transfer ceremonies require an approved method; an agent must
  not handle their plaintext. Public identities and sanitized hashes are enough
  for diagnosis. Do not enable shell tracing or dump service environments.
- Outside the standing testnet fee authority above, get the human operator's
  **explicit go for the named network, hosts and action**
  before value movement or a destructive/live deployment operation. This includes
  `retire-host.sh`, local `--clean`, live `install-node.sh activate`, signing,
  `fund`, `onboard`, `withdraw`, `resubmit`, and a journal `record`,
  `baseline` or `retry` that permits later spending. An earlier diagnostic request
  is not permission to send. Run and review `--dry-run` first where supported. `fund --dry-run`
  still signs and stores a private BOC, so signing itself also needs permission.
  **`onboard`, `activate` and `retire-host.sh` have no dry-run option**: present the
  command and read-only evidence for approval instead; do not invent a flag.
- On a refusal, mismatch, timeout or unknown transaction outcome, stop the affected
  value action and diagnose autonomously. Reconcile the original transaction
  read-only; do not ask for a routine technical decision already delegated by the
  owner. Never override a safety check, remove a journal/lock, accept a new
  baseline, re-sign or replay a payment merely to get past a refusal.
- Use `systemctl`, never `kill`, for service lifecycle work. Keep quorum and obtain
  permission before a restart. Do not edit installed host units by hand: change
  the reviewed template and use its installer after approval.
- Never run the same consensus identity on two hosts. Retain its keys and database
  until duties, held stakes and recovery have been verified. A database rollback
  or reset is not a routine restart.
- Keep local deterministic keys, faucet funding and development privacy parameters
  in the disposable local environment. Never deploy them on a public network.

## Environment facts

The public-testnet build procedure targets **Ubuntu 24.04 LTS or a later LTS release, x86_64 with
x86-64-v2 instructions**, clang-21 and a pinned full tos commit. The preflight
profile also admits aarch64, but the supplied build script sets x86-64-v2; do not
assume that is a supported ARM build procedure.

| Identity / path | Purpose |
| --- | --- |
| `root` | Installs packages/templates and controls services; reads private env files without displaying them |
| `tos` | Non-login node account; `/var/lib/tos/<role>` (0700), `/var/log/tos/<role>` (0750) |
| `tos-ctl` | Non-login elections account; `/var/lib/tos-ctl` (0700); every host `tosctl` invocation runs as this account |
| `tos-alert` | Non-login alert-peer account; `/var/lib/tos-alert` |
| `/opt/tos-testnet` | Root-owned, service-readable copy of `testnet/` |
| `/etc/tos` | Public global config and root-only `tosctl.env` (0600); never display the latter |
| `/usr/local/bin` | Installed binaries; `/var/lib/tos-build` holds pinned builds and receipts |

Profile defaults: validator/full-node ADNL **30001/udp**, QUIC **31001/udp**;
DHT **30300/udp**. JSON-RPC **8081/tcp** and exporter **9100/tcp** stay on
loopback. The console **30002/tcp** listens on every address (the engine binds its
control port by number only, as upstream does); the host firewall must not admit it,
and it needs its client key. Full-node lite server is **30003/tcp**; a validator
has no public lite server. Check [profile.json](testnet/network/profile.json)
and installed unit, rather than opening a port from memory.

## Changes, verification and reporting

Write English. Never commit keys, seeds, tokens, certificates, secret inventories,
personal home paths or personal data. Keep generated output outside the tree;
review the staged diff even for ignored-looking filenames. Paths belong in
arguments or `TOS_ROOT`, not embedded personal layouts.

Small changes may go directly to main when authorized; larger changes use a PR
and review. Never force-push or merge without owner instruction. Use the tests in
[README.md](README.md#layout); record the exact tos commit and commands/exit
statuses. Do not run a live rehearsal as a documentation check.

Report the network identity, pinned revision, role/host placeholders, requested
and authorized action, checks performed, sanitized results, and outstanding
refusals. For value operations report operation IDs and public transaction hashes,
never signed secret material. Separate observed facts from untested proposals.
