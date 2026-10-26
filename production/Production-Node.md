# Production node configuration (design)

**Design and templates, not an accepted mainnet deployment procedure.** The
executable multi-host procedure in this repository is testnet-only:
[OPERATOR.md](../testnet/OPERATOR.md), [CEREMONY.md](../testnet/CEREMONY.md).
Read [AGENTS.md](../AGENTS.md) before any operation. Do not apply the testnet
profile, identities, amounts, AUTH tag or short TTLs to production.

Code reference: tos `85c679c3454f306eb867e25b1960ae3d757bd3dd`; deployment scripts:
tos-ops main `8e64906`. These references describe available interfaces, not
release approval or a live-host observation. Recheck the approved release's
help, network configuration and review gates before deployment. Node source and
its `doc/validator-operator-guide.md` are in the separate `TOS_ROOT` checkout.

## 1. What differs from the local network

| Concern | Local | Production design |
| --- | --- | --- |
| Network | Disposable global id 3 | Approved ceremony; mainnet global id 1 |
| Keys and funds | Deterministic fixtures / test funding | Independent custody and operator funding |
| Genesis / AUTH | Development parameters | Authenticated artifacts and separately approved AUTH policy/tag |
| Elections | Optional 600-second local rotations | Release template and approved live ConfigParam 15 |
| Privacy | Development verifying key / traffic | No permission to deploy development parameters |
| Retention / hardware | Short TTLs on one host | Measured capacity and recovery plan, [hardware proposal](Hardware-and-Hosting.md) |
| Monitoring | Local health stack | Separate failure domains; deployment blockers must be satisfied |

Nothing in `local/` is a production installer. `testnet/` is likewise a distinct
network, not production defaults under another name.

## 2. Node roles

| Role | Public listeners | Key / purpose |
| --- | --- | --- |
| Validator | ADNL and QUIC | Consensus keys for one validator identity; signs set duties |
| Full node | ADNL and QUIC | No consensus seed; sync source |
| RPC / lite server | Per approved access policy | Separate query capacity; no validator key. Public wallet RPC is a full node plus `tos-wallet-index` and `tos-rpc` on one host ([section 10.1](#101-the-rpc-role)) |
| Archive | Per approved access policy | Retained history with measured capacity |
| DHT | ADNL UDP | Address discovery; independent bootstrap hosts |

Validator console, exporter and write-capable JSON-RPC stay on loopback.
The pinned engine refuses a write-capable public JSON-RPC bind even with a key.
A public listener must be read-only, or use an authenticated proxy in front of
loopback with an explicitly reviewed policy. Authentication alone is not
permission to expose the validator's control channel.

The engine holds `<DB>/config.json.lock`. Never run two engines on that DB or
copy its signing identity into a second active engine. Locks and ownership
refusals are evidence to investigate, not files to delete.

### 2.1 Query capacity

The node applies lite-server admission limits. A `notready`/admission refusal
is not a healthy empty answer. Read-only clients back off; ambiguous value-moving
requests require transaction reconciliation before retry. Keep public wallet and
explorer load off validators. Exact limits and classification are in the pinned
tos `validator/liteserver-admission.h`; this repository does not configure them.

## 3. Key custody

| Domain | Material |
| --- | --- |
| Offline signing domain | Pool-owner wallet key; incoming consensus key while it is moved for a rotation |
| Node account | Consensus seeds, transport keyring and console server key |
| Operator-tool account | Encrypted stake-ordering wallet vault and console client credential |
| Principal owner | Separate offline pool-owner wallet, as implemented by the testnet coordinator |

### 3.1 Consensus key

`tos-pq-consensus-key generate` creates an owner-only seed and refuses overwrite;
`show` prints only public identity. The node checks a regular, non-symlink seed,
owned by its effective user, exactly 32 bytes, with no group/other access and a
safe parent directory. Fix ownership through the approved procedure; never loosen
modes to bypass a refusal.

A human must retain an **encrypted offline backup** using an approved encryption
and recovery process. The tool's `export` writes secret bytes only to a pipe or
socket; `import` receives them. Agents must not invoke plaintext export, capture
it, display it or copy it to another host. The repository provides no encryption
or backup-verification program. Never run a restored copy alongside the old node.

### 3.2 Staking account

The validator is named by its staking account, the masterchain account that
sends its stake to the Elector: the operator wallet when it stakes directly, or
a single-nominator pool when the pool sends the stake. The testnet uses a pool
whose owner is the offline principal owner and whose validator role is the
operator wallet; the pool's address is the validator id genesis records. The
node is bound to that account (`bind-node`, section 5.1) and signs stake
authorizations only for it; the Elector refuses a stake signed for another
account, and refuses a stake whose consensus key another member already uses.

The operator wallet only orders stakes and recoveries and pays their fees; it
cannot withdraw the principal. The owner alone withdraws, and can replace the
pool's validator role without changing the pool. A compromised host can
therefore stake and recover but not take the principal. Choose the staking
account before genesis or before binding the node: changing it means a new
binding and a new account, not an in-place edit.

## 4. Host layout and service account

| Account / path | Purpose |
| --- | --- |
| `root` | Installs packages, reviewed templates and binaries; controls services |
| `tos` | Non-login node account; database `/var/lib/tos/<role>` (0700), logs `/var/log/tos/<role>` |
| `tos-ctl` | Non-login elections account; owns `/var/lib/tos-ctl` (0700) |
| `/etc/tos/global-config.json` | Public authenticated network config |
| `/etc/tos/tosctl.env` | Root-only (0600) vault environment; never display |
| `/usr/local/bin` | Verified executables |

Every host `tosctl` command runs as `tos-ctl`, including configuration writes.
Systemd reads the root-only environment before dropping privileges. It is not
safe to create root-owned vault/lock/config files inside the service state.
Testnet's [operator guide](../testnet/OPERATOR.md#6-onboard-for-elections) shows the
safe invocation wrapper. Production installation must preserve these boundaries.

## 5. First start and binding the validator

Production needs an approved role installer; none is supplied here. The testnet
installer demonstrates the two-phase pattern: prepare generates node config and
transport identity using a placeholder config, then activation verifies the
published digest, installs real genesis/config, binds custody while stopped,
installs the reviewed unit and starts it. A placeholder must never run as a chain.

### 5.1 `bind-node`

The native tool supports:

```text
tos-pq-consensus-key bind-node [--replace] DB_ROOT KEYFILE VALIDATOR_ID
```

Run as the node account with the engine stopped and an absolute key path. It
holds the config lock, checks the schema and seed, refuses a different binding
unless replacement was explicitly requested, and publishes durably. Exit 1 is a
refusal; exit 3 means written but directory flush unconfirmed. Do not assume a
nonzero result means nothing changed. An identical single-key binding is a no-op;
a multi-key node is refused, even with replacement. Observe the public
`post-quantum consensus custody` identity/window lines after startup.

## 6. Storage and retention

### 6.1 How data is retired

At the pinned revision **state GC and retired-session cleanup remain GC-anchored**.
GC is constrained by key blocks, rotation, serializer, shard-client progress,
minimum references, lag behind the head and state TTL. A key block permits
progress; it is not a deletion deadline. Failed elections can hold GC at genesis.
Do not describe a later consensus-cleanup checkpoint proposal as installed here.

Archive pruning uses the durable GC timestamp and archive TTL, with package
retention rules. Persistent-state serialization can add hours of lag. Short
retention also removes early key blocks needed by fresh proof clients, so a
recent authenticated init block and a verified sync/recovery path are necessary.

### 6.2 Retention choices

The proposed validator template below uses 86,400 s state and archive TTLs.
The testnet validator instead uses 3,600 / 86,400; the local environment uses
shorter development retention. Those are different disk/availability policies,
not interchangeable performance knobs. Long-retention/permanent CellDb requires
its own memory/disk sizing and an explicit irreversible-setting review.

### 6.3 Disk sizing

No production capacity acceptance is established by these documents. Measure
state/archive growth, consensus backlog, logs, write endurance and GC lag under
representative validator counts and load; reserve recovery space and alert on
both free capacity and growth. Short TTLs reduce retention, not SSD writes.
Use [Hardware-and-Hosting.md](Hardware-and-Hosting.md) for the requirements
proposal and record actual measurements outside the repository.

### 6.4 Retired consensus databases

Cleanup is **on by default**; `--enable-validator-consensus-cleanup` states it
explicitly. `--disable-validator-consensus-cleanup` retains data for forensics;
the two together refuse startup with exit 2. Deletion requires a durable
retirement record, a closed actor/DB, no live/pending session, verified retirement
ancestry under the same durable GC state, and a strictly newer shard catchain.

Inspect `validator consensus cleanup: enabled`, `VALCLEANUP` passes and deletion
acknowledgements, not directory count alone. INFO verbosity is needed for normal
progress evidence; a failed deletion is retried and reported. Never manually
remove live consensus databases to recover disk space. Historical testnet
cleanup observations do not certify production capacity or every restart path.

## 7. Service definitions

The file [systemd/tos-validator.service](systemd/tos-validator.service) is a
**proposal**. The exact tracked template follows (tests check it stays identical):

```ini
[Unit]
Description=TOS validator
After=network-online.target
Wants=network-online.target

[Service]
User=tos
Group=tos
UMask=0077
WorkingDirectory=/var/lib/tos/validator
# RocksDB caches capped at 1 GiB each (owner decision 2026-10-15; memo
# public-testnet E23-18). CellDb V2 otherwise raises its block cache to
# max(1 GiB, cell cache entries x 5000), about 4.66 GiB with the defaults, and
# it does so even when --celldb-cache-size is smaller unless
# --celldb-cache-min-size is set too, so both flags carry the cap. The shared
# block cache of the other databases defaults to 1 GiB; it is set here so the
# cap does not depend on an engine default.
Environment=TOS_ROCKSDB_BLOCK_CACHE_SIZE=1073741824
ExecStart=/usr/local/bin/validator-engine \
  -C /etc/tos/global-config.json \
  -D /var/lib/tos/validator \
  -l /var/log/tos/validator/node.log \
  --session-logs /var/log/tos/validator/session-stats \
  -t 16 \
  --state-ttl 86400 --archive-ttl 86400 \
  --celldb-cache-size 1073741824 --celldb-cache-min-size 1073741824 \
  --exporter-address 127.0.0.1:9100 \
  --json-rpc-address 127.0.0.1:8081 --json-rpc-without-wallet-index
Restart=on-failure
RestartSec=10
KillMode=control-group
TimeoutStopSec=120
LimitNOFILE=1572864
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/tos/validator /var/log/tos/validator
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

The companion [tos-elections.service](systemd/tos-elections.service) runs
`tosctl service` as `tos-ctl` with `Restart=always`: the program can exit 0 while
RPC is unavailable. Both templates need approved installation/acceptance.
No service runs as root. Maintain the cache/log/resource choices in reviewed
templates, never by editing installed units ad hoc.

### 7.1 Options a production node must not set casually

Do not use unsafe catchain restore/rotation, database truncation, fault-injection
flags, disabled serialization, unlimited flood-control/file-descriptor settings,
unfinalized/unsynced serving or public write-RPC to make a refusal disappear.
Permanent storage and cleanup disabling require an explicit retention/forensics
plan. Read the pinned engine's help; an option's existence is not approval.

## 8. Joining the network

Authenticate the global config and its full zero-state identity before download.
Compare full block IDs with an independent trusted node. This repository supplies
no accepted production signed-release/config-distribution channel. A URL or a
matching height alone is insufficient. Prepare a verified persistent-state and
archive sync path with the approved release before committing validator duties.
Install the node binaries from the tos GitHub release with `fetch-release.py`
([section 10](#10-releases-upgrades-and-restarts)), not from a host build.

### 8.1 Refreshing the global config's init block

The tos script (not in this repository) supports:

```bash
python3 "$TOS_ROOT/scripts/refresh-global-config-init-block.py" \
  --rpc http://127.0.0.1:PORT/jsonRPC --global-id 1 INPUT.json OUTPUT.json
```

It follows native persistent-state anchor selection, **not simply the latest key
block**: the key block starts a persistent-state period, is at least one hour old,
and has more than eight hours of lifetime remaining. It checks full identities
and never overwrites output. Selection does not prove a snapshot is available.
Authenticate the new file and independently compare the trusted RPC view before
publishing it. Consult that revision's help for refusal/fallback conditions.

### 8.2 Snapshot import

Use only the pinned node's verified import procedures, locked against a running
engine and bound to the intended network. No production snapshot import wrapper
or rollback approval is supplied here. Do not restore an older DB under the same
signing identity without a separately reviewed safety procedure.

### 8.3 Choosing the genesis time

The coordinator must allow enough time for independent builds, record checking,
authenticated publication and activation. Future-time validation can leave the
chain at height zero before the announced epoch. The release template's exact
rules, approved schedule and full artifacts take precedence over a copied date.
See [testnet ceremony](../testnet/CEREMONY.md) for its separate reusable procedure.

## 9. Validator lifecycle

The pinned tos checkout's `doc/validator-operator-guide.md` is the native interface
reference. Public-testnet value movement uses the stricter [journaled ceremony](../testnet/CEREMONY.md#81-onboarding-a-genesis-validator-for-elections):
coordinator-built/validated StateInit, separate offline principal owner, exact
message/transaction evidence on two validators, shared journal lock, original
message resubmission only and explicit retry after terminal failure.

tosctl's election task asks the node for a stake authorization for the binding's
staking account and refuses, before any wallet message, one the node made for
another account. Without a pool it sends the stake plus 1.2 TOS of fees from the
wallet to the Elector; with a pool it sends the pool the order with the fees
only, and the pool forwards the stake. Recovered stakes are credited to the
staking account. Keep the pool funded for the stakes and the operator wallet
funded for the fees; neither replaces the node's binding to the account.

Multi-key consensus custody **is available** in the reference build: up to eight
held keys, election-date scheduling, group-specific key selection and hard expiry.
The offline tool lists/adds/removes keys; the running console can change them
without restart; the staking account stays the same. A human must coordinate the
schedule and preserve old keys for
current/previous/next duties. Offline removal cannot see those sets. Never set a
hard expiry before all signing obligations finish. This repository supplies no
journaled rotation driver; consult the exact native guide and obtain review.

To leave: disable future staking in an approved window, continue current/pending
duties, wait for held stakes and receipts, recover funds, then withdraw as the
owner. Ended-epoch testnet retirement is destructive, not a production departure
command. See [operator incidents/leaving](../testnet/OPERATOR.md#9-incidents-leaving-and-retirement).

## 10. Releases, upgrades and restarts

Production takes its node binaries from the tos repository's GitHub release for
the approved tag, not from a build on each host (the testnet keeps its host
builds). [fetch-release.py](../testnet/scripts/fetch-release.py) is that path.

The release binaries are dynamically linked and need Ubuntu 24.04 (glibc 2.39
or newer) with these runtime packages. Install them before fetching; the fetch
tool installs nothing:

| Architecture | Packages |
| --- | --- |
| x86_64 | `libjemalloc2 libgsl27 libblas3 libreadline8t64` |
| arm64 | `libjemalloc2 libgsl27 libblas3 libreadline8t64 libatomic1` |

`libjemalloc.so.2` is linked into `validator-engine` and `dht-server`,
`libgsl.so.27` and `libblas.so.3` into `validator-engine`, `libreadline.so.8`
into `validator-engine-console` and `lite-client`, and `libatomic.so.1` on
arm64. The `needed` lines of the release's build record are the authority for
this list. The fetch also uses `ldd` (glibc) and `readelf` (binutils).

```bash
sudo apt-get install libjemalloc2 libgsl27 libblas3 libreadline8t64   # arm64: also libatomic1
sudo python3 /opt/tos-testnet/scripts/fetch-release.py --tag v<VERSION> \
  --rev <FULL_40_CHARACTER_COMMIT> --role validator --arch x86_64 \
  --out /var/lib/tos-build/release-<FULL_40_CHARACTER_COMMIT>
sudo /opt/tos-testnet/scripts/install-node.sh binaries --role validator \
  --release /var/lib/tos-build/release-<FULL_40_CHARACTER_COMMIT> --rev <FULL_40_CHARACTER_COMMIT>
```

It downloads over HTTPS, without a GitHub login, the role's
`<binary>-linux-<arch>` assets, `node-build-info-linux-<arch>.txt`,
`SHA256SUMS`, `release-provenance.json` and the node build artifact
`tos-node-linux-<arch>.zip`. It writes nothing unless:

- the provenance names the tos repository, the tag and a commit equal to
  `--rev`, and its `tos-node-<arch>-linux` record names workflow
  `build-tos-linux-node-binaries.yml`, `head_sha` equal to `--rev` and an
  artifact digest equal to the zip's SHA-256;
- every downloaded file matches `SHA256SUMS`;
- every binary and the build record are byte-identical to their members of
  that zip, and the build record names `--rev`, each binary's SHA-256 and,
  in its `needed` lines, exactly the libraries `readelf` finds in each binary;
- this host can run them: `ldd` finds every needed library (a refusal names
  the package of each missing library above, and still refuses an unknown
  one), glibc is at least 2.39, and each binary with a `-V` option reports
  `Commit: <rev>`.

The output directory is the layout `check-release.sh` accepts. Its `BUILD-INFO`
records the source, the provenance digest, the build recipe lines (compiler,
flags, jemalloc package, build OS) and the host's glibc. The tool refuses an
existing `--out` and a release that lacks one of the role's assets: a release
must publish the node build assets before this path works for it. These checks
bind binaries to one published release; they do not authenticate the release
itself. Compare the `provenance_sha256` line across hosts and with the
published release.

### 10.1 The rpc role

The rpc role is a full node host that also runs the standalone public-RPC
services: `tos-wallet-index` reads the co-hosted node's database read-only and
`tos-rpc` serves the wallet HTTP endpoint behind a TLS proxy, read-only unless a
submission backend is configured. It uses the same release path:
`fetch-release.py --role rpc` fetches the full node's binaries and both services
from one tag, with every check above, and `install-node.sh binaries --role rpc`
installs them together, so the index always matches the source node's version.
This requires the release to include `tos-rpc-linux-<arch>` and
`tos-wallet-index-linux-<arch>`, as members of `tos-node-linux-<arch>.zip` with
`sha256` and `needed` lines in its build record; the fetch refuses a release
without them. The unit templates and the operating procedure are the testnet's
([OPERATOR.md section 10](../testnet/OPERATOR.md#10-run-the-public-rpc-role)),
an implementation reference, not a production approval.

```bash
sudo python3 /opt/tos-testnet/scripts/fetch-release.py --tag v<VERSION> \
  --rev <FULL_40_CHARACTER_COMMIT> --role rpc --arch x86_64 \
  --out /var/lib/tos-build/release-<FULL_40_CHARACTER_COMMIT>
sudo /opt/tos-testnet/scripts/install-node.sh binaries --role rpc \
  --release /var/lib/tos-build/release-<FULL_40_CHARACTER_COMMIT> --rev <FULL_40_CHARACTER_COMMIT>
```

### 10.2 Upgrades

Verify revision, binary digests and authenticated release origin. Fetch before
stopping, upgrade one validator at a time and prove sync/custody before the next.
Stop the old process with systemctl; do not delete a held lock or kill it. An
incompatible DB/protocol downgrade is not fixed by reinstalling old executables.
There is no automatic rollback tool here. Testnet's [maintenance procedure](../testnet/OPERATOR.md#8-upgrade-rollback-and-key-rotation)
is an implementation reference, not authorization to use it on mainnet.

Protocol/configuration votes require separate reviewed commands and consensus
policy. The presence of native vote/proposal tools does not authorize sending a
configuration change. Keep public RPC consumers separate from authenticated
operator control reads; never weaken RPC limits to serve an internal consumer.

## 11. Monitoring

Production health-stack placement and its admission blockers live in the tos
checkout under `tools/node-health-monitor`. This repository has local-stack
automation and testnet host watching/Telegram alerting, not an accepted production
monitor deployment. The read-only [network checker](scripts/README.md) verifies
held-anchor proofs and Elector results over HTTP. Its [build and evidence notes](evidence/README.md)
state its trust inputs and historical-proof availability limit; it is not a
production monitor deployment.

Require independent fresh full-block identity, head/shard-client lag, election
outcomes, authorization runway/expiry, disk/growth, GC/cleanup progress,
memory/restarts and clock checks. Every unknown observation must remain unknown,
not zero. Alerts must reach a human and retain acknowledgements. The supplied
testnet peer watches only the coordinator's heartbeat; it is **not a second chain
observer**. Production needs independent chain observation and failure-domain
coverage before that design claim can be made.

## 12. Gaps before this procedure can be followed

| Area | What still requires explicit acceptance |
| --- | --- |
| Release/config distribution | Authenticated release and refresh channel, named revision and verification responsibility |
| Hardware | Measured CPU, memory, disk, endurance and recovery capacity under representative load |
| Units/install | Approved production installation and unit/resource policy; these are templates |
| Custody/rotation | Human backup/restore and multi-host rotation rehearsal through real duties |
| Recovery | Verified archive/snapshot availability, restart and incompatible-upgrade response |
| Monitoring | Independent chain observers, alert delivery/acknowledgement and watcher-failure drills |

No stale PR status in a document establishes that an item is closed. Retain
acceptance evidence outside the repository and link it through the release
process; do not include keys, secret inventories or personal infrastructure data.
