# tos-ops

Operations tools and runbooks for TOS networks: host preparation, installation,
activation and retirement; the genesis ceremony; staking pools, journaled
funding, validator onboarding and withdrawals; monitoring, alerting and
cross-node checks.

This repository holds no node source code or operational keys. Scripts that need
node code, binaries or Python modules locate a separate **tos** checkout through
`TOS_ROOT` or explicit path arguments. Keys and generated ceremony/runtime output
belong outside the repository.

**Agent entry point:** [AGENTS.md](AGENTS.md). **Validator operators:**
[testnet/OPERATOR.md](testnet/OPERATOR.md).

**Start here:** [network bring-up](testnet/CEREMONY.md) ·
[onboarding](testnet/CEREMONY.md#81-onboarding-a-genesis-validator-for-elections) ·
[fee top-ups](testnet/CEREMONY.md#topping-up-an-operator-wallet) ·
[reset](testnet/CEREMONY.md#9-resetting-the-testnet) ·
[alerts](testnet/README.md#alerts).

## Layout

### `local/` — disposable development network

One-host PQ validators, observers, DHT and lite client, with optional election
rotation and test traffic. Development keys, funding and privacy parameters must
never be used on a public network.

| Entry | Purpose |
| --- | --- |
| [README.md](local/README.md) | Setup, retention, service layout and health-stack rebinding. |
| [OPERATIONS.md](local/OPERATIONS.md) | Election, transfer and development shielded-pool traffic procedures. |
| [setup-testnet.sh](local/scripts/setup-testnet.sh) | Install/reset the local chain; `--clean` deletes the previous `/data` contents. |
| [testnet-ctl.sh](local/scripts/testnet-ctl.sh) | Start, stop, inspect and check the local services. |
| [local-pq-elections.py](local/scripts/local-pq-elections.py) | Drive local elections with retained submission and acceptance evidence. |
| [local-pq-transfers.py](local/scripts/local-pq-transfers.py) / [local-pq-privacy.py](local/scripts/local-pq-privacy.py) | Generate and verify ordinary transfers / development-key pool operations. |
| [health-deploy.py](local/scripts/health-deploy.py) | Configure and verify the local health-monitoring stack. |
| [health-observe.py](local/scripts/health-observe.py) | Collect MCP node snapshots using bounded observation grants. |
| [health-pki.py](local/scripts/health-pki.py) | Check, rotate and recover the development monitoring PKI. |
| [systemd/](local/systemd/) | Node and lite-client templates, plus the user PKI-rotation timer. |
| [health/](local/health/) | Local monitoring rule inventory. |
| [host-nic/](local/host-nic/README.md) | Host-specific NIC watchdog and offload units. |

Tests: [local/tests/](local/tests/). From the repository root, with a built tos
checkout and its Python environment/test bindings prepared:

```bash
TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" -m pytest -q local/tests
```

### `testnet/` — public testnet operations

Multi-host tooling with a public [network profile](testnet/network/profile.json),
[example inventory](testnet/network/inventory.example.json) and per-role services.
Real inventories and ceremony directories stay outside the tree.

| Entry | Purpose |
| --- | --- |
| [OPERATOR.md](testnet/OPERATOR.md) | Operator tasks, custody, maintenance and incident response. |
| [CEREMONY.md](testnet/CEREMONY.md) | Authoritative bring-up, onboarding, value-operation and reset procedures. |
| [README.md](testnet/README.md) | Roles, monitoring, alert setup and verification guidance. |
| [preflight.py](testnet/scripts/preflight.py) / [setup-time.sh](testnet/scripts/setup-time.sh) | Check host resources, UDP reachability and time synchronization. |
| [build-node-binaries.sh](testnet/scripts/build-node-binaries.sh) / [build-tosctl.sh](testnet/scripts/build-tosctl.sh) | Build pinned node/operator binaries on their destination hosts. |
| [fetch-release.py](testnet/scripts/fetch-release.py) | Production binary path: fetch a role's binaries from a tos GitHub release, verify them against `SHA256SUMS` and `release-provenance.json`, and write a release directory `install-node.sh` accepts. |
| [remove-old-builds.sh](testnet/scripts/remove-old-builds.sh) | After an upgrade: remove other revisions' build trees and releases and `/opt/tos-testnet.old`, keeping the running revision and every log. |
| [tok01-signer.py](testnet/scripts/tok01-signer.py) | Signer adapter for tos `scripts/tok01-lifecycle.py --sender-command`: wallet v1 senders, keys 0600, returns only after the sender's seqno moved. |
| [install-node.sh](testnet/scripts/install-node.sh) | Prepare, install binaries and activate validator, full-node, rpc (wallet index and public RPC beside a full node) or DHT roles. |
| [testnet-operator.py](testnet/scripts/testnet-operator.py) / [testnet-dht.py](testnet/scripts/testnet-dht.py) | Produce operator and signed DHT public records. |
| [testnet-coordinator.py](testnet/scripts/testnet-coordinator.py) | Validate records and generate the manifest, genesis and global config. |
| [testnet-governance.py](testnet/scripts/testnet-governance.py) | Change a ConfigParam by a validator vote: `propose`, `sign` (node consoles), `vote`, `status`, `adopted`; each send a journaled operation. |
| [testnet-elections.py](testnet/scripts/testnet-elections.py) / [testnet_ops.py](testnet/scripts/testnet_ops.py) | `pool` (staking pool before genesis), `fund`, `onboard`, `withdraw`, and manual `reconcile`, `record`, `resubmit`, `baseline`, `retry`; durable journals and two-validator settlement. |
| [check-testnet.py](testnet/scripts/check-testnet.py) | Compare independent nodes' network identity, fresh full block IDs and selected configuration. |
| [check-handover.py](testnet/scripts/check-handover.py) | `collect` (read-only, paced, journaled) and offline `verify` of a validator-set handover: every block's certificate against its header-selected set; extended terms reported. Needs `dilithium-py` for ML-DSA-44. |
| [watch-testnet.py](testnet/scripts/watch-testnet.py) / [check-host-disk.py](testnet/scripts/check-host-disk.py) | Retain host/node samples and report anomalies. |
| [alert-relay.py](testnet/scripts/alert-relay.py) | Telegram alerts, acknowledgements, silence windows and coordinator/peer heartbeats. |
| [retire-host.sh](testnet/scripts/retire-host.sh) | Archive evidence, then retire a host bound to the explicitly confirmed old zero state. |
| [systemd/](testnet/systemd/) / [firewall/](testnet/firewall/) | Node, elections and alert units, the rpc role's `tos-testnet-wallet-index` and `tos-testnet-rpc` units; inbound firewall example. |
| [rehearse-loopback.sh](testnet/scripts/rehearse-loopback.sh) | Rehearse genesis and node activation on an isolated loopback network. |

Tests: [testnet/tests/](testnet/tests/); operation mutation controls are in
[mutants.py](testnet/tests/mutants.py). From the repository root:

```bash
TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" -m pytest -q testnet/tests \
  --ignore testnet/tests/test_con01_history.py \
  --ignore testnet/tests/test_con01_observer_crypto.py
```

Some tests skip, and say why, unless their tool is present. Supply them for a run with no skips:
`dilithium-py` 1.1.0 and `shellcheck` on the interpreter's path (`shellcheck-py` provides the binary),
`TOS_BIN` pointing at a tos build's `build/utils` (for `generate-random-id`), and
`PROOF_VERIFY_LIBRARY` set to the built `libtosproofverify.so` (target `tos-proof-embedded`; see
[production/scripts](production/scripts/README.md)).

The two con01 certificate suites verify real ML-DSA signatures and refuse to skip. They need
the compiled signature verifier ([con01_history](testnet/acceptance/con01_history/README.md#build-and-reproduce))
and a CPython with `os.memfd_create`; the standalone Python in a uv `.venv` may lack it. Build
the verifier against an OpenSSL of 3.5 or newer (a tos build carries one under
`build/third-party/openssl`), then run them with the system interpreter:

```bash
cc -std=c11 -O2 -Wall -Wextra -Werror -I "$OPENSSL_PREFIX/include" \
  testnet/acceptance/con01_history/mldsa_verify.c "$OPENSSL_PREFIX/lib/libcrypto.a" -ldl -pthread \
  -o "$VERIFIER" && chmod 500 "$VERIFIER"
CON01_SIGNATURE_VERIFIER="$VERIFIER" \
CON01_SIGNATURE_VERIFIER_SHA256="$(sha256sum "$VERIFIER" | cut -d' ' -f1)" \
  /usr/bin/python3 -m pytest -q testnet/tests/test_con01_history.py testnet/tests/test_con01_observer_crypto.py
```

### `production/` — designs and templates

[Production-Node.md](production/Production-Node.md) covers roles, custody,
retention, joining, validator lifecycle and monitoring; its
[gap register](production/Production-Node.md#12-gaps-before-this-procedure-can-be-followed)
records the procedure's limits. This directory is **not an accepted production
deployment**.
Only production operator tooling, shaped like upstream TON's, belongs there; test
harnesses, experiments and acceptance evidence live in `testnet/` (BR1 and CON-01
under [testnet/acceptance](testnet/acceptance/)).

- [README.md](production/README.md): scope and prerequisites for using the templates.
- [Hardware-and-Hosting.md](production/Hardware-and-Hosting.md): proposed capacity and hosting-diversity requirements.
- [systemd/](production/systemd/): proposed validator and elections-task units.

The read-only [network checker](production/scripts/README.md) verifies explicit
network identity, held-anchor PQ finality and Elector results over HTTP. Follow
its [pinned verifier build](production/scripts/README.md#build-the-verifier) and
review the [evidence and availability limits](testnet/acceptance/evidence/README.md).
Its fixture and mutation tests are in `testnet/tests`; there is no production
deployment acceptance suite here.

Root files: [AGENTS.md](AGENTS.md) (`CLAUDE.md` links to it) and
[.gitignore](.gitignore) contain working guidance and output/secret exclusions.

## Workflows

### Bring up a network

1. Follow [CEREMONY.md steps 0–4](testnet/CEREMONY.md#0-before-anything-coordinator): pin the tos revision, preflight hosts, prepare validators/DHT, derive each validator's staking pool from its operator wallet and exchange public records.
2. Follow [steps 5–7](testnet/CEREMONY.md#5-coordinator-manifest-genesis-global-config): generate and publish genesis/config, activate, then compare nodes.
3. For a disposable local chain instead, use [local initialization](local/README.md#initialize).

### Onboard, top up or withdraw

1. Follow [onboarding §8.1](testnet/CEREMONY.md#81-onboarding-a-genesis-validator-for-elections), including both-validator checks and readiness before enabling elections.
2. For later fee money, follow [fee top-ups](testnet/CEREMONY.md#topping-up-an-operator-wallet): a journaled `top-up` from the pool owner to the recorded operator wallet (before the bootstrap [sweep](testnet/CEREMONY.md#sweeping-the-bootstrap-wallet) a `fund` out of its 50 TOS margin may still serve); the stake principal stays in the pool. The bootstrap wallet is swept to the ConfigParam 5 blackhole once two elected sets hold the four stakes, and is never a funding source after that.
3. Use the same [§8.1 operation procedures](testnet/CEREMONY.md#81-onboarding-a-genesis-validator-for-elections) for withdrawal or interrupted operations. Inspect `reconcile`; verify evidence with `record`, resubmit only the original message, or explicitly `retry` a terminal failure. A baseline is a deliberate history acknowledgement, not an automatic recovery.

### Retire and reset

1. Follow [§9](testnet/CEREMONY.md#9-resetting-the-testnet): confirm the ended epoch's zero state and archive evidence before retirement.
2. Preserve the previous ceremony records, then start a new ceremony with fresh identities and the documented previous-epoch checks. Local resets use the separate [local reset checklist](local/README.md#startup-checklist-after-a-reset).

### Check and observe

1. Use [live-chain checks](testnet/CEREMONY.md#7-coordinator-the-chain-is-live) with `check-testnet.py` against at least two independent endpoints; agreement is observation, not a consensus proof.
2. Follow [network watching](testnet/README.md#watching-the-network) for ongoing host samples, and [local health rebinding](local/README.md#rebinding-the-local-health-stack) after a development-chain reset.

### Relay alerts

1. Follow [alert setup](testnet/README.md#alerts) for the coordinator and peer units, private credentials and heartbeat monitoring.
2. Use its silence/unsilence and acknowledgement procedures; the peer watches the coordinator's heartbeat, not the chain itself.

## Working rules

- Write English. Never commit keys, seeds, tokens, certificates, inventories with secrets, personal data or personal home paths.
- Accept paths through arguments or `TOS_ROOT`; do not embed an operator's machine layout.
- Keep generated genesis, journals, receipts, logs, databases, backups and build output outside the tree. Review staged changes even when `.gitignore` covers a filename.
- Small changes land directly on `main`; larger changes use a PR and review. Record the tos revision used for verification. Test the relevant environment before pushing.
- Keep disposable keys, faucet funding and development drivers in `local/`; do not copy them into public-network deployments.
