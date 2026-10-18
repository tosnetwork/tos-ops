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
| `scripts/` | Installer (`setup-testnet.sh`), control (`testnet-ctl.sh`), network library (`local_pq_testnet.py`), election, transfer, privacy and funding drivers, relay checker, root-service snapshot installer |
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

This is a local development chain with a funded development wallet and a
**development pool verifying key**. It is not a release Genesis or a pool for
real funds. The initial validator set lasts 30 days; reset the local chain
before expiry or use the explicit election rehearsal described below.

## Startup checklist after a reset

A full reset of the local development network, in order:

1. `sudo TOS_ROOT="$TOS_ROOT" local/scripts/setup-testnet.sh --clean --rotate` (add `--build` after source
   changes). With `--rotate` it deploys and authorizes the candidate
   controllers and only then starts `tos-pq-elections`; see the next section.
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

## Controller funding and continuous elections

`--rotate` selects a ten-minute development election profile and adds candidate
node 7. The election driver alternates the four-member sets 1/2/3/7 and 1/2/3/4.
This is different from the default 30-day bootstrap profile above.

**Keep elections running on a persistent network.** Elections produce the key
blocks that garbage collection advances behind (see "Disk retention"). A
bounded rehearsal's shutdown is not the default, and leaving validators running
without elections lets `/data` grow without bound.

A controller forwards a stake to the Elector only within an explicit,
root-signed operating authorization (controller action kind 4). A new controller
has zero allowance and expiry, so every relay is refused. A plain balance
transfer does not authorize spending, and exit 180 is a shared guard code, not
a unique diagnosis.

`setup-testnet.sh --rotate` runs `local/scripts/local-pq-fund-controllers.py`
after deployment and before it starts the election service. Setup and the
election driver share the helper in `local_pq_funding.py`; the driver rechecks
the selected candidates before each new round. For each of the five candidate
controllers it:

1. verifies the disposable network and the controller's birth, code and
   authority identity, deploying the exact StateInit when needed;
2. reads the current authority, `operating_state` and the Config20/24 fee
   parameters;
3. computes the automatic grant per relay and a 30-day target, and renews at
   25 % remaining or when the policy is missing or differs;
4. deposits only the deficit, signs with `/usr/local/bin/tos-pq-controller`
   and the development root seed `/data/elections/keys/root-<i>.seed`, and
   confirms the actual controller transaction and the exact state transition;
5. separately tops up ordinary capital to funds plus floor plus margin.

The contract **adds** a deposit to the recorded funds and **replaces** every
other field, so a renewal may deposit zero. Defaults:

- funds and allowance target `4320 × current grant`, which is 30 days of one
  relay per ten-minute round (about 27,800 TOS at about 6.44 TOS per relay);
- 20 TOS per-request cap, 10 TOS floor, 20 TOS capital margin;
- 30-day sponsorship.

The authorization signature itself expires after 600 seconds, independently of
the sponsorship. Unsupported prices or caps fail visibly. These are local
development values, not production fee estimates.

Read-only checks do not need the election service stopped:

```bash
sudo env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" \
  local/scripts/local-pq-fund-controllers.py --check
sudo env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" \
  local/scripts/check-local-pq-elections.py
```

`--check` reports a needed renewal without signing or writing. The election
service normally renews automatically. A manual write needs exclusive use of
the faucet (Genesis wallet), which a file lock enforces, so do not run setup or
traffic bootstraps while the election service runs. Follow any maintenance stop
with a checked restart.

The sender records its exact signed request before broadcasting. A restart
reuses the same wallet seqno and reconciles the destination transaction, and
per-node intent records prevent funding a partly completed round twice. Do not
delete `faucet-journal/`, `candidate-intent-*.json` or `submitted.json` to force
a retry: reconcile the saved request against chain state first. Unknown
outcomes and deterministic refusals need attention, not a new payment.

The development root seeds in `/data/elections/keys/` are deterministic
fixtures and must never control real funds. This automation is not production
root custody.

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
| Controller has balance but refuses forwarding | Read the explicit operating authorization, expiry, allowance and per-request limit; ordinary transfers do not authorize spending. |
| `operating_state` reads all zero or expired | The controller has no operating authorization. Check with `local-pq-fund-controllers.py --check`; the election service renews it, or run the tool with the service stopped. |
| Controller rejects with exit 180 | This is a shared relay guard code, not a unique diagnosis. Inspect the request and exact transaction; check balance against recorded funds plus floor, as well as the other relay preconditions. |
| Pool receives a native bounce after forwarding | Decode the controller compute/action failure and pool bounce transaction. Confirm where principal returned before retrying. A bounce is not an elector acceptance. |
| Election driver reports a confirmation timeout | The signed intent remains unresolved. Inspect the complete transaction path and the retained journal; do not infer acceptance or send a new payment. |
| `LITE_SERVER_NOTREADY: liteserver admission limit exceeded` | A lite server allows at most 128 heavy proof queries per second (`validator/liteserver-admission.h`), and several drivers starting together exceed it. The drivers wait it out (`PatientClient`, up to seven attempts with backoff); a refused query was never executed. Persistent refusals mean something keeps querying one node too heavily. |
| A restart appears to repeat funding | Check that the installed snapshot contains the journal, and preserve it. Reconcile exact transaction identities and balances; do not delete records to bypass duplicate protection. |

Do not disable contract guards to make deployment succeed. Correct missing
initialization or insufficient capital first; investigate unexpected failures
against the exact deployed code hash.

### Verify an actual election, not just submission

- Match the deployed elector/controller/pool code identities to the intended
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
- Inspect restarts, compute/action failures and balance/allowance consumption.
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

The tracked PKI user-unit template still hard-codes `%h/network-settings`
(the legacy checkout basename); the GitHub rename alone does not relocate it.
Keep that layout for this template. A different checkout requires a reviewed
template/install change, not a hand-edited installed unit. Directory migration
is outside this documentation change.

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
