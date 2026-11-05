# Local PQ network

**Disposable local development only.** Read [agent safety rules](../AGENTS.md)
before any reset, funding or service change. Facts below describe the scripts
with tos `85c679c3454f306eb867e25b1960ae3d757bd3dd`, not a live-host status.

`local/scripts/setup-testnet.sh` installs four PQ validators, two observers and
a separate DHT on one host. It then deploys the shielded pool compiled from the
tos checkout. Consensus uses ML-DSA-44, ConfigParam 8 is version 16, and
ConfigParam 34 contains exactly the four newly generated PQ identities. No
classical validator is installed.

## Prerequisites

- A tos checkout, built (`cmake --build build`) and with its uv environment
  synced. Point `TOS_ROOT` at it:

  ```bash
  export TOS_ROOT=/path/to/tos
  ```

  The scripts here import tos modules (`tostester`, `toslib`, `contract`,
  `x02_config34_proof`) and run tos binaries from `$TOS_ROOT/build`. Keep the
  checkout at the revision this directory was last verified against; the
  scripts are not versioned with tos.
- Run every command below from the root of this repository. `sudo` resets the
  environment, so `TOS_ROOT` is passed explicitly wherever a command runs as
  root.

| Path | Contents |
| --- | --- |
| `scripts/` | Installer (`setup-testnet.sh`), control (`testnet-ctl.sh`), network library (`local_pq_testnet.py`), election, transfer and privacy drivers, two-step broadcast relay checker, root-service snapshot installer |
| `systemd/` | Unit templates for the DHT, validators, observers and the lite-client |
| `tests/` | Unit tests for the drivers and the snapshot installer |
| `OPERATIONS.md` | Elections, random transfers and shielded-pool traffic |
| `PREPARATION.md` | Topology and port plan |

The root-run drivers do not run from this directory.
`scripts/install-root-services.sh` copies them, with the tos modules they
import, into a root-owned snapshot under `/usr/local/lib/tos-dev-services`.

## Tests

Prepare the separate tos environment once, using its pinned lockfile and schema:

```bash
(cd "$TOS_ROOT" && uv sync --locked && uv run python test/tostester/generate_tl.py)
```

This writes generated bindings into the tos checkout, not this repository. If
bindings are generated in an external directory instead, add their parent to
`PYTHONPATH`. Then run from the tos-ops root:

```bash
TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" -m pytest -q local/tests
```

## Initialize

```bash
sudo TOS_ROOT="$TOS_ROOT" local/scripts/setup-testnet.sh --build --clean
local/scripts/testnet-ctl.sh status
local/scripts/testnet-ctl.sh check
```

`--build` builds the native tools and pool generator. Without it, existing
build outputs must be present. `--clean` **deletes all contents of `/data`**,
including the previous keys, databases, wallets and pool state. Without
`--clean`, an existing network is refused before stopping its services.
The installer starts the services and verifies the actual deployment.

The Genesis is version 16, which commits to an AUTH network tag (ConfigParam 48):
the namespace that binds Quantum wallet authorization to this one network, so a
signature made for an earlier local chain cannot be replayed on the next. tos
assigns no tag. Each setup derives a new one as the SHA-256 of
`TOS-AUTH-NETWORK-TAG-v1;network=tos-local-dev;global_id=3;epoch=<setup Unix time>`
and records the value and its rule under `auth_network_tag` in
`/data/network.json`. To fix the tag instead, pass `TOS_AUTH_NETWORK_TAG=<64 hex
digits>` on the `sudo` command line; reserved values (one repeated byte, or bytes
0 to 31) are refused.

This is a local development chain with a funded development wallet and a
**development pool verifying key**. It is not a release Genesis or a pool for
real funds. The initial validator set lasts 30 days; reset the local chain
before expiry or use the explicit election rehearsal described below.

## Startup checklist after a reset

A full reset of the local development network, in order:

1. `sudo TOS_ROOT="$TOS_ROOT" local/scripts/setup-testnet.sh --clean --rotate` (add `--build` after source
   changes). With `--rotate` it starts `tos-pq-elections`, which deploys and
   funds each candidate's staking wallet itself; see the next section.
   Do not edit `local/scripts/setup-testnet.sh` while it runs: bash reads the script
   as it executes, and a changed file makes it run the wrong lines.
2. `local/scripts/testnet-ctl.sh status` and `local/scripts/testnet-ctl.sh check`: every
   service active, seven nodes on one full block ID.
3. Bootstrap random transfers in a quiet interval of the election service (see
   [OPERATIONS.md](OPERATIONS.md)), then
   `sudo systemctl enable --now tos-pq-transfers`.
4. Confirm the first election: four `stake_accepted` events in
   `sudo journalctl -u tos-pq-elections`, then a new
   `/data/elections/activation-*.json` after the set switches.
5. Rebind health monitoring to the new zero-state (see "Health MCP after a chain
   reset"). Restarting the old monitoring units is not enough; their network ID
   belongs to the previous chain.
6. Watch disk use for the first two hours (next section).

## Disk retention

Historical local measurements were about 1.4 GB/hour per validator and
0.4 GB/hour per observer. They are not capacity bounds. The pinned engine
enables retired consensus-database cleanup by default, but eligibility still
follows the durable state-GC floor. Default retention is unsuitable for a small
disposable disk; use the explicit template TTLs below and observe actual growth.
The session statistics file rotates to a single `.old` copy at 256 MiB.

The local unit templates therefore pass:

| Option | Effect |
| --- | --- |
| `--state-ttl 3600` | states may be garbage collected after one hour |
| `--archive-ttl 7200` | archived blocks are kept two hours beyond that |
| `--enable-validator-consensus-cleanup` | States the pinned engine's default explicitly: delete retired databases only once the durable GC floor proves them obsolete. It is not an acceptance-only option in this build. |

A local `ExecStart` override, such as a health-monitoring drop-in, replaces the
template's command line. It must carry the same three options. Verify with
`systemctl show tos-pq-validator@1 -p ExecStart`.

**State GC and this revision's consensus cleanup need key blocks.** The GC floor advances only while it
is behind the last key block, the last validator-set rotation and the
persistent-state serializer, and only for states older than `state-ttl`. The
serializer walks every masterchain block and normally keeps up. It pauses only
when a key block starts a new 2^17 s (about 36.4 h) period
(`ValidatorManager::is_persistent_state`). Then it waits a random 0–6 h before
writing that persistent state, and the floor cannot pass it in the meantime.

On this network, with a key block every ten-minute election, the floor runs
about `state-ttl` (one hour) behind the head. Usage levels off after the first
few hours: about 29 GB for the seven nodes, measured on 2026-10-06. Expect a
temporary rise of up to six hours of growth, about 7 GB/h, when a persistent
state falls due.

Elections and set changes produce the key blocks. A network whose elections
fail keeps only its Genesis key block and never collects anything, whatever the
TTLs are. The validator logs then show
`VALCLEANUP pass gc_seqno=0 … reserved=0` indefinitely. If `/data` keeps
growing:

- check that elections still complete;
- check that `last_known_key_block_ago` in the node log stays below a few
  election periods;
- check that `VALCLEANUP pass` reports a `gc_seqno` about one hour behind the
  head.

**Short retention removes the early key blocks.** A toslib client that starts
from the zero state proves its way forward through every key block since
Genesis. Once those blocks are collected, every newly started client fails
with `LITE_SERVER_NOTREADY: block handle not in db`. The local drivers
therefore load their lite-client configs through
`local_pq_testnet.lite_config()`, which starts the proof chain at the latest
key block read from a local node. A client started with an unmodified
`/data/configs/node-*-lite.json` fails in the same way. A production client
takes a recent `init_block` from its global config instead.

## Staking wallets and continuous elections

`--rotate` selects a ten-minute development election profile and adds candidate
node 7. The election driver alternates the four-member sets 1/2/3/7 and 1/2/3/4.
This is different from the default 30-day bootstrap profile above.

**Keep elections running on a persistent network.** Elections produce the key
blocks that garbage collection advances behind (see "Disk retention"). A
bounded rehearsal's shutdown is not the default, and leaving validators running
without elections lets `/data` grow without bound.

Each of the five candidates (nodes 1, 2, 3, 4 and 7) stakes directly from its
own masterchain wallet (WalletV1). Setup creates a disposable key for each in
`/data/elections/keys/wallet-<i>.pk` and binds the node to that wallet: the
wallet's account id is the node's validator id, recorded with the consensus key
and ADNL id in `/data/elections/candidate-<i>.json`. The node signs stake
authorizations only for that account, and the elector refuses a stake signed
for any other.

`local/scripts/local-pq-elections.py` (the `tos-pq-elections` service) owns the
Genesis wallet as its faucet. When an election opens it, for each member of the
round:

1. deploys the candidate's wallet from the faucet if it is not yet active, and
   refuses a wallet whose code or key does not match the recorded StateInit;
2. asks the node for an ML-DSA-44 stake authorization for the wallet and refuses
   one made for another account, key or ADNL address;
3. encodes the stake with tosctl's production builder, installed by setup as
   `/usr/local/bin/tos-pq-pool-stake-order`, and sends the elector its body
   without the amount;
4. tops the wallet up from the faucet by only the deficit to 11,000 TOS stake +
   1.2 TOS elector fees + 1 TOS reserve, then sends 11,001.2 TOS from the wallet
   to the elector, bounceable;
5. reads the elector's answer from the wallet's own transactions: acceptance,
   a returned stake with the elector's reason, or a bounce.

About once a minute it also asks the elector (`compute_returned_stake`) whether a
candidate has a stake to recover, sends `RECOVER_STAKE` with 0.2 TOS from that
wallet when it has, and records the elector's answer as a `stake_recovery` event.
It writes `/data/elections/wallet-<i>.json` (deployed, balance, returned stake,
check time) on every such check.

These are local development values, not production fee estimates. Read-only
checks do not need the election service stopped:

```bash
sudo env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" \
  local/scripts/check-local-pq-elections.py
```

It reports the driver heartbeat, an expired ConfigParam 34 without a newer
activation, and any candidate wallet that is undeployed or not observed for ten
minutes. Spending from the faucet needs exclusive use of it, which a file lock
enforces, so do not run setup or traffic bootstraps while the election service
runs. Follow any maintenance stop with a checked restart.

Every sender (the faucet and each candidate wallet, journals in
`faucet-journal/` and `wallet-journal-<i>/`) records its exact signed request
before broadcasting. A restart reuses the same wallet seqno and reconciles the
destination transaction, and per-node intent records prevent paying a partly
completed round twice. Do not delete the journals, `candidate-intent-*.json` or
`submitted.json` to force a retry: reconcile the saved request against chain
state first. Unknown outcomes and deterministic refusals need attention, not a
new payment.

The candidate wallet keys in `/data/elections/keys/` are disposable development
keys and must never control real funds.

### Updating the drivers on a running network

The root-run drivers execute a snapshot under `/usr/local/lib/tos-dev-services`,
not the checkout. To deploy changed driver code:

1. Stop `tos-pq-elections` right after a round's four `stake_accepted` events.
2. Stop `tos-pq-transfers` only while its status reads `confirmed`:
   `sudo jq -r .kind /data/transfers/status.json`. If it is stopped between
   `submitting` and `confirmed`, it refuses to start again with
   "previous transfer is unresolved". In that case, check the sender's last
   transaction and the recipient's credit for the submitted amount before
   recording any resolution. Do not clear the status to force a restart.
3. If `tos-pq-privacy` is active, stop it only after its pending operation is
   confirmed; an unresolved plan needs reconciliation first. The installer refuses
   any active election/transfer/privacy service. After approval, install the
   snapshot with all four required arguments:

   ```bash
   sudo env UV="$(command -v uv)" local/scripts/install-root-services.sh \
     /usr/local/lib/tos-dev-services "$TOS_ROOT" "$TOS_ROOT/build" \
     "$TOS_ROOT/tools/shielded-pool-circuit/crosscheck/target/release/local_pool_traffic"
   ```

4. Start only the previously enabled traffic services and elections again, then
   verify their status and first confirmed receipts. A snapshot validation failure
   leaves the previous publication in place; do not bypass it.

### Diagnose a missing stake confirmation

| Observation | Check and response |
| --- | --- |
| `node stake authorization differs from candidate` | The node signed for another account, key or ADNL address. Check its bound validator id (the post-quantum custody line in the node log) against the candidate's `wallet` in `candidate-<i>.json`. Nothing was sent. |
| Elector returns the stake (`elector_refused`) | The reply carries the elector's reason; reason 0 with no open election means the election had closed. The stake is back in the wallet. |
| The elector bounces the stake (`elector_bounced`) | The elector's transaction failed and the value came back with the bounce. Inspect that transaction before the next round. A bounce is not an acceptance. |
| Election driver reports a confirmation timeout | The signed intent remains unresolved. Inspect the complete transaction path and the retained journal; do not infer acceptance or send a new payment. |
| `LITE_SERVER_NOTREADY: liteserver admission limit exceeded` | A lite server allows at most 128 heavy proof queries per second (`validator/liteserver-admission.h`), and several drivers starting together exceed it. The drivers wait it out (`PatientClient`, up to seven attempts with backoff); a refused query was never executed. Persistent refusals mean something keeps querying one node too heavily. |
| A restart appears to repeat funding | Check that the installed snapshot contains the journal, and preserve it. Reconcile exact transaction identities and balances; do not delete records to bypass duplicate protection. |

Do not disable contract guards to make deployment succeed. Correct missing
initialization or insufficient capital first; investigate unexpected failures
against the exact deployed code hash.

### Verify an actual election, not just submission

- Match the deployed elector and candidate wallet code identities to the intended
  build and frozen artifacts.
- Check successful elector receipts for all intended query IDs and the actual
  participant list/accepted amounts.
- Wait for Config34 to activate the intended four-member set. Acceptance alone
  does not prove selection or activation.
- Run `local/scripts/testnet-ctl.sh check` and verify a common full block ID across
  validators and observers after activation.
- For the local rotation rehearsal, run:

  ```bash
  sudo env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" \
    local/scripts/check-local-pq-relays.py --output /data/elections/relay-verification.json
  ```

  This checks retained traces after the transition grace period, including the
  new member and exclusion of the retired member from current first-hop sets.
- Inspect restarts, compute/action failures, wallet balances and `stake_recovery`
  events for the recovered stakes.
  A reserved operating-budget debit is not necessarily the actual gas spent.
- On a persistent network keep the election service and its health check
  active. `local/scripts/check-local-pq-elections.py` reports a stale heartbeat,
  an expired Config34 and low operating runway. Only a deliberately bounded,
  disposable rehearsal may be stopped.

One successful election does not validate the later unfreeze/withdrawal cycle,
all failure recovery paths, or production costs. Validate those separately.

## Health MCP after a chain reset

A reset creates a new zero-state root and new node process identities. Rebind
monitoring to that root; do not reuse an old manager/query database or report
old retained evidence as current health.

- Start the nodes with their approved `--health-node-id` aliases,
  `--health-core-metrics`, `--health-native-core-v3`, and numeric-loopback
  `--exporter-address` listeners. The initial `/health-snapshot` may be
  unavailable until the scheduled metrics owner has populated its cache.
- Bind each health edge to the running node PID and the new network ID.
  Configure collectors, native pollers and manager/query inventories with
  that same ID. Create separate private control, evidence and query databases.
- Build `tos-observability` with the `mcp` feature. Use a private Unix MCP
  socket, separate operator/service credentials and bounded run grants.
  A listening socket alone is not verification: initialize MCP, discover the
  six tools, read fresh node snapshots, check their network/PID/time/evidence,
  and revoke each observation grant after use. Never print run tokens.
- Apply CPU/memory/storage limits to monitoring services, and validate mTLS
  certificate expiry before enabling continuous collection. See the
  health deployment guide (tos `tools/node-health-monitor/deploy/README.md`).
- Read `coverage.missing_fields`, per-component quality and incident details.
  `partial` means usable but incomplete coverage, not necessarily a node
  failure; `ok` is not a blanket health verdict. `CACHE_MISS` is missing
  evidence, not a healthy zero. In the current projection, process coverage
  can lack `host_pressure`, `cgroup_effective` and `fd_usage`; native-derived
  chain/consensus/storage responses can inherit `shard_consensus_progress`
  gaps. Storage durability limitations must be read separately.
- Compare samples across the election boundary: new validators should begin
  participating, retired validators should stop current duties, and all nodes
  should continue following the same chain. Short memory samples do not prove
  the absence of a leak or replace a complete trend window.

### Rebinding the local health stack

The local stack lives in `~/.local/state/tos-local-health/<first 12 hex of the
network ID>/`. It has 32 user units (`tos-local-health-*`, including the
witness comparer) and seven system units (`tos-local-health-edge-<i>`, bound to
the node's PID). `local/scripts/health-deploy.py` builds all of it from this
repository: every config and unit is generated, the manager's rule inventory
comes from `local/health/manager-inventory.json`, and certificate pins are
computed from the live PKI. After a reset, once `setup-testnet.sh` has
finished and the nodes run:

```bash
(cd "$TOS_ROOT/tools/node-health-monitor" && cargo build --release --locked --features tos-health-services/mcp)
TOS_ROOT="$TOS_ROOT" local/scripts/health-deploy.py configure --start
```

It refuses (exit 2, nothing changed) unless `network.json`, the zero state in
`/data/tos-global.json` and all seven node units agree, each unit running with
its `--health-node-id` and `--exporter-address`. A new network gets a new
directory with fresh databases and tokens; the previous directory is left as
it was. Tokens, the PKI and databases of an existing directory are kept, so
running it again only regenerates configs and units. With `--start` it
restarts the whole stack, waits until every edge's native sample reports the
expected alias and network ID, and until `health-observe.py` sees all seven
nodes, and only then records the directory in `~/.local/state/tos-local-health/active`
(exit 1 if that fails). Switching to a new network needs `--start`; until the
switch verifies, `activation-pending` there stops PKI rotation. Without
`--start` it rewrites the files of the active stack and restarts nothing.

`local/scripts/health-observe.py` takes one MCP snapshot of every node and saves
it under the state directory's `observe/`. Expected: all seven nodes answer,
observers `ok` and validators `partial` with the known gaps listed above;
`host` is supported when the host collector and query projection provide fresh
evidence. `CACHE_MISS` means missing/freshness evidence; investigate admission and
collector/query logs rather than treating it as a healthy result. The local
configuration requests process, consensus, storage, chain and host, not telemetry.

The validator restart in a reset stops the edges (`BindsTo=`). Start them again
after `setup-testnet.sh`, even when the network ID does not change.

Keep node health collection running independently of the bounded election
submission driver. Resetting the chain again requires repeating this binding
procedure, not merely restarting the previous monitoring units.

### Health monitoring certificates

The stack authenticates every hop with a private development CA in `pki/`: a
server certificate for the eight TLS ingress listeners (SAN `localhost`,
`127.0.0.1`) and two client identities, probe and reader. The eight ingress
configs pin the two client certificates by the SHA-256 of their DER encoding.
The CA key is not kept, so a renewal re-issues the whole set. A certificate that
expires stops monitoring without a clear error, as it did on 2026-10-06.

`local/scripts/health-pki.py` renews it:

```bash
local/scripts/health-pki.py check            # expiry of the four certificates
local/scripts/health-pki.py rotate           # renew now
```

A rotation issues the new set (30 days by default), moves the pins in the
eight ingress configs, restarts the ingress units and then the other stack
units (never the edges, timers or itself), and proves monitoring works: every
listener serves the new server certificate for both names, both new
identities pass their routes, the replaced identities and an unpinned
certificate from the new CA are refused, `health-observe.py` sees all seven nodes
healthy and the manager's evaluation sequence advances. Verification is never
disabled to rotate.

It is a journaled transaction (`pki-rotation.json`) under a lock. Each live
file is replaced atomically, so an interrupted run is finished or undone by the
next one. If verification fails and the old certificates are still valid, the
old set is restored and verified (exit 1). If that fails too, or the old set has
expired, the run ends in `recovery_failed` (exit 3), keeps every artifact, and
reports the same failure on each later run until an operator chooses:

```bash
local/scripts/health-pki.py rotate --resolve keep-new     # or restore-old
```

Backups of the replaced files are kept under `retired/` (newest two).

Install the daily timer once. It rotates when a certificate has seven days
left, so it has seven attempts before expiry:

```bash
cp local/systemd/user/tos-local-health-pki.* ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tos-local-health-pki.timer
systemctl --user list-timers tos-local-health-pki.timer
journalctl --user -u tos-local-health-pki.service
```

The tracked PKI user-unit template expects this checkout at `%h/tos-ops`.
Keep that layout when installing the template. A different checkout path
requires a reviewed template/install change, not a hand-edited installed unit.

## Services and configuration

| Service | Database | JSON-RPC |
| --- | --- | --- |
| `tos-pq-dht` | `/data/testnet/node0` | — |
| `tos-pq-validator@1` | `/data/testnet/node1` | `127.0.0.1:8011` |
| `tos-pq-validator@2` | `/data/testnet/node2` | `127.0.0.1:8012` |
| `tos-pq-validator@3` | `/data/testnet/node3` | `127.0.0.1:8013` |
| `tos-pq-validator@4` | `/data/testnet/node4` | `127.0.0.1:8014` |
| `tos-pq-observer@5` | `/data/testnet/node5` | `127.0.0.1:8015` |
| `tos-pq-observer@6` | `/data/testnet/node6` | `127.0.0.1:8016` |
| `tos-pq-validator@7` (`--rotate` only) | `/data/testnet/node7` | `127.0.0.1:8017` |

Installed node units are enabled to start automatically at boot. Each validator can be restarted
independently, for example `sudo systemctl restart tos-pq-validator@4`.
`testnet-ctl.sh` also supports `start`, `stop`, `restart` and `logs 1..4`.

The exported public configurations are `/data/configs/node-1.json` through
`node-6.json` (also node 7 with `--rotate`), the corresponding `node-N-lite.json` files, and `global.json`.
Exact ADNL, lite and console ports are in `/data/testnet-ports.json`.
PQ seeds, keyrings and the development wallet stay in protected directories;
exporting the configuration does not export private keys.

## Shielded pool

`/data/shielded-pool/pool.json` records the address and compiled code/data
identity. `deployment.json` records the observed active account, code hash
and initial getter results. The installer funds the pool with 100 test TOS;
the reserve floor is 50 TOS. It checks both empty roots, zero liability and
that the actual balance covers liability plus reserve.

`testnet-ctl.sh check` verifies increasing common full block IDs across the local
nodes, live version 16, the four provisioned PQ identities, and the pool's
reserve/backing getters. `deploy-pool` resumes an interrupted deployment;
it checks an existing account before sending another deployment.
Pool proofs and withdrawals use the matching development parameters from
`tools/shielded-pool-circuit`; deployment does not claim a withdrawal test.

### Installed privacy generator independence

The installed traffic generator (`local_pool_traffic`, built from the tos
crosscheck crate) embeds both the pool gas-ceiling source and the development
verifying-key fixture. `install-root-services.sh` validates the generator's
`resources` response under `ProtectHome=true`, with the tos source and build
roots inaccessible, before it publishes the new snapshot
(`check-local-pq-resources.py`). A failed check keeps the previous `current`
snapshot. The ELF, symlink and Python search-path checks remain mandatory.

Rebuild the generator after either embedded source changes. When installing
without `--build`, existing artifacts must still match the checkout's exact
resource bytes. A successful resource check or locally generated proof is not
on-chain privacy acceptance: confirm a deposit, a transfer and a withdrawal
through the installed service and its cross-node checks. See
[DEFECTS-20261006.md](DEFECTS-20261006.md) for the defect record and the
remaining acceptance gates.

## Election test send admission primitive

`local/scripts/election_send_gate.py` is a library for an isolated test's single
financial producer. It is **not an RPC proxy, native receipt verifier or a fix
for the production election runner**. It cannot yet be used to run the delayed
registration money scenario.

The library holds reads and sends closed until a trusted caller supplies a
context-bound verification result. It serializes a read through response
publication, fsyncs a global latch before one forwarding callback, and never
reopens on an acknowledgement, timeout or restart. Exact original-operation
settlement must be checked by a separately reviewed native verifier before the
caller authorizes another admission. A previously unused process admission is
not automatically restored. Process identity is checked before any mutex acquisition,
so a fork child cannot reuse its parent's admission or block on an inherited lock.
Storage uncertainty is sticky; corrupt, incomplete,
foreign-context, shared or oversized journals refuse. The metadata hash chain is
corruption detection, not protection against the owner rolling storage back.

The future adapter/controller must enforce one sole RPC endpoint, one financial
producer, bounded full HTTP exchanges and no stale in-flight response or task
reload bypass. Reads already delivered to another signer cannot be revoked by
this library. Holding Config15 reads also pauses registration renewal; the test
must prove enough installed horizon and cannot claim uninterrupted renewal while
an unknown send remains unresolved. The native-confirmation and sole-producer/controller integration requirements
remain unimplemented; the bounded transport adapter is described below.

The synthetic unit suite covers admission, lost replies, a real subprocess exit,
restart, file ownership, write/fsync failures, record limits and publication
serialization. It neither signs transactions nor contacts a node:

```sh
TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" -m pytest -q local/tests/test_election_send_gate.py
```

`local/scripts/election_rpc_gate.py` now supplies the serial loopback transport
adapter for that core. It forwards only the explicit read-method inventory and
puts `sendBoc` and `sendBocReturnHash` behind the same latch. There is no HTTP
reset/authorization route or backend retry/failover. Backend replies are bounded
and checked for the request ID; the core read lock covers backend exchange and
frontend publication. Malformed requests, protocol failures and deadlines hold
admission. Refusing an exhausted request budget may close the connection before
consuming another body; that is a failure, not evidence of settlement.

The adapter accepts only an explicit loopback backend and listener, with a
16 KiB header limit, 1 MiB request/response bodies, a 100,000-request budget,
saturating counters and a kernel listen backlog of eight. The normal frontend
exchange deadline is five seconds and the backend deadline is 2.5 seconds;
connect/header/body/chunks share those total network I/O deadlines, not per-byte
timeouts. These do not bound filesystem synchronization or waiting for the trusted
controller mutex; controller integration must bound those separately. Error holds
are scoped to the request admission generation so a late error cannot revoke a
newly confirmed admission. Read callback failures close admission while still
holding the gate mutex.
The server handles one request at a time. It neither establishes native network
identity nor prevents a different producer using already delivered data.

The native receipt verifier, sole-producer/reload topology and actual CLI
controller remain missing. This is not an executable financial-test launcher or
a production runner repair. The additional loopback suite uses synthetic JSON
only and never a real node, wallet key or signed transaction carrier:

```sh
TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" -m pytest -q local/tests/test_election_send_gate.py local/tests/test_election_rpc_gate.py
```

RPC requests also bind the request-start admission generation under the core
read/forward mutex. A request begun before fresh admission cannot consume that
new permit, including when its body arrives late. This does not revoke a response
already delivered to a producer; exclusive producer/controller remains required.
