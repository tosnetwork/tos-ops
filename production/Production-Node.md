# Production node configuration (design)

Status: **design for review, not an accepted operating procedure.** This
document is the production counterpart of the local network settings in
[`../local/`](../local/README.md). That tooling builds a
disposable development chain with one script. This one describes how an
independent operator should configure and start a node on a shared network:

- which roles exist and how each is exposed;
- where each key lives;
- which options a production node sets and which it must never set;
- how disk use is bounded;
- how a validator joins, stays in and leaves the validator set;
- what is still missing before any of this can be followed for real.

Every statement about behaviour is taken from the tos code. The revisions it
was checked against:

| tos revision | What it provides |
| --- | --- |
| PR #148, `feat/production-operator-gaps` at `e9e81d04b` | Release packaging of the PQ tools, `bind-node`, controller deployment tools, `tosctl controller operations`, `wallet send --bounce`, `vote offer create`, init-block refresh, locked snapshot import, consensus-database cleanup on by default (section 6.4) |
| PR #149, `feat/pq-multi-consensus-key` at `23df53058` | Several consensus keys per validator, zero-downtime rotation (section 9, step 8); **open, not merged** |

Section 12 lists the gaps that remain. Until they are closed, the steps that
depend on them cannot be carried out with released artifacts alone.

The step-by-step operator procedure in the tos repository is
`doc/validator-operator-guide.md`. This document adds the production
choices (roles, placement, retention, custody domains, monitoring) and points
out where that guide and the code disagree.

## 1. What differs from the local network

| Concern | Local development network | Production |
| --- | --- | --- |
| Genesis | Generated per reset, global ID 3 | One ceremony (tos `doc/validator-genesis-bootstrap.md`), global ID 1 |
| Consensus keys | Deterministic fixture seeds | Generated once by each operator, never derived, never shared |
| Controller root key | Deterministic seed on the node host | Offline operator domain; never on the validator host |
| Funds | Genesis faucet wallet | Operator wallets; pool principal belongs to its owner |
| Elections (Config15) | 600 / 300 / 60 / 180 s | 65536 / 32768 / 8192 / 32768 s (`gen-zerostate.fif`) |
| Validator set | 4 members plus one standby | At most 21 (`config/pq-launch-limits.json`), enforced at four points |
| Hosts | Seven nodes on one machine, loopback | One validator per host; separate full, RPC, archive and DHT hosts |
| Retention | 1 h states, 2 h archive | Section 6 |
| Consensus-database cleanup | On | On (the default, section 6.4) |
| Monitoring | Local health stack on the same host | Health stack off the validator host (`production_off_validator`) |
| Install | `setup-testnet.sh --clean` wipes `/data` | Nothing is ever wiped; data moves only through verified snapshots |

Nothing marked as development-only in the local document may be used in
production. That includes:

- `deterministic_pq_initial_validator_seed`;
- the fixture root seeds `SHA256("tos-test-pq-election-controller-root-v1" ‖ index)`;
- `main-wallet.pk` as a funder;
- `local-pq-elections.py`, `local-pq-transfers.py`, `local-pq-privacy.py` and
  `local-pq-fund-controllers.py`;
- the development pool verifying key;
- `--test-consensus-cleanup-crash-before-erase` (fault injection, section 7.1).

## 2. Node roles

| Role | Holds consensus key | Public listeners | Purpose |
| --- | --- | --- | --- |
| **Validator** | yes | ADNL/QUIC only | Produces and signs blocks while it is in Config34 |
| **Full node** | no | ADNL/QUIC | Follows the chain; source of sync for others |
| **RPC / liteserver node** | no | ADNL/QUIC, liteserver; JSON-RPC behind a proxy | Serves wallets, explorers and services |
| **Archive node** | no | as RPC, usually private | Keeps all blocks and states |
| **DHT node** | no | ADNL (UDP) | Address resolution for the overlay network |

Rules that follow from the code:

- A validator runs no public liteserver and no JSON-RPC. Its console and
  exporter bind to loopback. Wallet and explorer traffic go to RPC nodes, so a
  query load can never starve consensus.
- A validator host holds the consensus key of exactly one validator. The node
  refuses to start a validator group unless it holds the exact key that
  Config34 records for its controller (`validator/manager.cpp`, group
  creation). Running a second copy of the same key elsewhere is never a
  failover mechanism; it is how a validator double-signs.
- One engine per database. The engine takes `<db>/config.json.lock` (a POSIX
  `fcntl` write lock) before it reads any configuration and holds it until it
  exits. A second engine on the same database, or an engine started while
  `tos-pq-consensus-key bind-node` edits the configuration, exits with status 2
  and names the lock (`validator-engine.cpp`). Under systemd,
  `Restart=on-failure` then retries every `RestartSec`; the log line says why.
- JSON-RPC with write methods (`sendBoc`, `sendQuery`) may only bind to
  loopback. The node exits with code 2 otherwise, whatever API key is set
  (`validator-engine.cpp`, `json-rpc-listen-policy.h`). A public RPC endpoint is
  therefore either `--json-rpc-readonly` on a public address, or a loopback
  write listener behind an authenticating reverse proxy.
- A validator should keep a trusted full node as its master
  (`--full-node-master-trusted`, see tos `doc/FullNode.md`), so that block
  data fetching does not depend only on public peers.
- RPC nodes that serve `tosctl vote offer create --wallet` must be built from
  PR #148 or later: that command needs the account's `storage_stat`, which
  older nodes do not serve (section 10.1).

### 2.1 Lite server capacity

Every node's lite server admits external queries through one per-node limit
(`validator/liteserver-admission.h`), counted in a sliding one-second window
across all clients together:

| Class | Examples | Limit per second |
| --- | --- | --- |
| Heavy | `getBlockProof`, `getTransactions`, `getState`, `lookupBlockWithProof`, `getConfigAll` | 128 |
| Medium | `getAccountState`, `runSmcMethod`, `sendMessage`, `getConfigParams`, `lookupBlock` | 512 |
| Small | `getMasterchainInfo`, `getTime`, `getVersion` | 1,024 |
| All heavy and medium together | | 2,048 |

A query cost grows by one per 16 KiB of request. A query above the limit is
refused with `LITE_SERVER_NOTREADY: liteserver admission limit exceeded` and
is never executed, and so is a query type outside these lists. At most 512
admitted queries execute at once.

What this means for production:

- A verifying client spends several heavy queries per account read, because
  each answer is proved. Ten clients starting together can exceed 128 heavy
  queries in one second. This was observed on the local network.
- Clients must treat the refusal as "retry later": back off and retry. It is
  safe, because a refused query did nothing. A client that treats it as fatal
  turns a burst into an outage.
- Plan RPC capacity by heavy queries, not by requests. Spread wallet,
  explorer and indexer traffic across several RPC nodes, and keep each
  validator's own tooling (`tosctl`) on a node that serves no public clients.
- The limit is per node and compiled in. A public RPC tier that needs more
  heavy throughput needs more nodes, not a configuration change.

## 3. Key custody

There are three custody domains. A key never moves to a less protected domain.

| Domain | Keys | Where |
| --- | --- | --- |
| **Offline operator domain** | Controller root seed (`tos-pq-key keygen`); next root seed during rotation; a new consensus seed while it is bound (kind 3) | Air-gapped machine or HSM-backed signer. The root signs controller actions (`tos-pq-controller`) and nothing else. |
| **Validator host** | PQ consensus seed (32-byte ML-DSA-44 seed); ADNL/DHT transport keys in the keyring; console server key | The node host, owner-only files |
| **Operator wallets** | Pool owner wallet; validator (stake-ordering) wallet; operating-authorization payer wallet | Wallet custody of the operator's choice; the owner wallet ideally offline |

### 3.1 Consensus key

- Generate it on the validator host, as the node's service account:
  ```bash
  umask 077
  install -d -m 700 /var/lib/tos/validator/keys
  tos-pq-consensus-key generate /var/lib/tos/validator/keys/pq-consensus.seed
  tos-pq-consensus-key show /var/lib/tos/validator/keys/pq-consensus.seed
  ```
  `generate` refuses to overwrite a key, writes through a temporary file and a
  rename, and fsyncs the file and its directory. Both commands print the
  algorithm, `key_id` and public key in hex, and never the seed.
- The node and every PQ tool load the seed with the same rules
  (`crypto/pq/seed-file.h`):
  - no symlink;
  - a regular file of exactly 32 bytes (a FIFO is refused);
  - owned by the effective user;
  - no group or other permission bits;
  - a parent directory that is not group- or world-writable.

  A permission error must be fixed, never worked around by loosening modes.
- Back up the seed **offline and encrypted**, never on the host. The only
  command that outputs the seed is `export`, and it writes only to a pipe or a
  socket, never to a terminal or a regular file:
  ```bash
  tos-pq-consensus-key export KEYFILE | ENCRYPT > BACKUP
  DECRYPT < BACKUP | tos-pq-consensus-key import KEYFILE   # restore: 64 hex digits on stdin
  ```
  `ENCRYPT`/`DECRYPT` stand for the encryption program the operator uses.
- A lost consensus seed is recoverable by binding a new key (kind 3,
  section 9, step 8). A leaked seed is a double-signing risk until it is rebound.

### 3.2 Controller root key

- Generate it with `tos-pq-key keygen ROOTSEED` in the offline domain
  (`tos-pq-key public ROOTSEED` prints the public key again). The root is
  deliberately not linked into the node: `tos-pq-key` is a separate CMake
  project (`crypto/pq/tools`), and `scripts/check-root-authority-off-the-node.sh`
  fails the build if root symbols reach the validator, overlay, ADNL or
  catchain code.
- Every root action is an internal message body produced offline and submitted
  from a wallet:

  ```bash
  tos-pq-controller send|bind|rotate-root|fund-operations|withdraw-operations \
    ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH NONCE VALID_UNTIL ...
  ```

  - `EPOCH` and `NONCE` come from the controller getter `controller_state`;
    `tosctl controller operations plan` prints them for a kind 4 action.
  - `VALID_UNTIL` must be in the future and at most 3,600 s ahead.
  - Each action spends one nonce. `rotate-root` increments the epoch and
    resets the nonce to 0, so bodies prepared earlier become invalid.
- **Binding the first consensus key at birth.** The controller is deployed
  already bound to the consensus `key_id` (`tos-pq-controller init-data`,
  section 9, step 2). Only the public `key_id` crosses domains; the consensus seed
  never leaves the validator host for the first deployment.
- **Binding a later key (kind 3).** `tos-pq-controller bind ... CONSENSUS_SEED`
  needs a cosignature by the incoming key, so the new consensus seed must be
  inside the offline ceremony and is then moved to the host with
  `export | ENCRYPT` / `DECRYPT | import` (section 9, step 8).

## 4. Host layout and service account

One system user per node role, for example `tos`, with no login shell. The
layout below replaces the development `/data/testnet/node<i>` tree.

```
/usr/local/bin/                         release binaries, verified by digest (section 10)
/etc/tos/global-config.json             network global config (section 8), root-owned 0644
/var/lib/tos/<role>/                    -D database root, owned by tos, 0700
/var/lib/tos/<role>/config.json         local config generated on first run (section 5)
/var/lib/tos/<role>/config.json.lock    engine lock file; created by the engine, never delete it while anything runs
/var/lib/tos/<role>/keyring/            transport and console keys, 0700
/var/lib/tos/<role>/keys/pq-consensus.seed   validator only, 0600, in a 0700 directory
/var/log/tos/<role>/                    -l log, --session-logs
```

- Keep the database on dedicated NVMe and the logs on a separate volume.
- `-f` (Fift directory) is accepted but never read (`validator-engine.hpp`),
  so it is omitted.
- Release archives for Linux x86_64 and arm64 ship `tos-pq-consensus-key`,
  `tos-pq-controller`, `tos-pq-key` and `tos-pq-vote` beside `validator-engine`
  (`scripts/release-artifacts.json`). Install `tos-pq-key` and
  `tos-pq-controller` only in the offline domain, not on the validator host.
  The key tools are not shipped for macOS or Windows.

## 5. First start and binding the validator

The node always runs from `<db>/config.json`. `-c` is read **only when that
file does not exist**. In that case the engine:

1. builds `<db>/config.json` from the given local config and `-I <ip:port>`;
2. creates ADNL, DHT and full-node transport keys;
3. logs "check it manually before continue";
4. exits 0.

A production install therefore has two phases:

1. **Generate.** Run the engine once, as the service account:

   ```bash
   validator-engine -C /etc/tos/global-config.json -D /var/lib/tos/<role> -I <public-ip>:<port>
   ```

   It creates `config.json` and exits. Review the file.
2. **Configure** before the first real start, with the node stopped:
   - Add console control keys. The Docker entrypoint does this with
     `generate-random-id` and a permissions template (`docker/init.sh`,
     `docker/control.template`).
   - On RPC nodes only, add liteserver keys.
   - **Validator only:** bind the node to its controller (section 5.1).

The Ed25519 keys created in step 1 are transport identities only (ADNL,
DHT). They have no part in consensus.

Never edit `config.json` while the engine runs: it rewrites the file whenever
its configuration changes, and a hand edit is lost or overwritten.

### 5.1 `bind-node`

```bash
systemctl stop tos-validator
sudo -u tos tos-pq-consensus-key bind-node /var/lib/tos/validator \
  /var/lib/tos/validator/keys/pq-consensus.seed VALIDATOR_ID
```

- `DB_ROOT` is the node's `-D` directory; the tool edits
  `DB_ROOT/config.json` and sets `extraconfig.pq_consensus
  {validator_id, consensus_key_file}`.
- `KEYFILE` must be an absolute path. The key is checked under the node's own
  rules (section 3.1), so run the tool as the node's service account.
- `VALIDATOR_ID` is the controller's account id, as 64 hex digits or
  `-1:<64 hex digits>`.
- A different existing binding is replaced only with `--replace`
  (`bind-node --replace DB_ROOT KEYFILE VALIDATOR_ID`); an identical binding is
  a no-op.
- The tool holds `DB_ROOT/config.json.lock` for the whole read-modify-write,
  and the cell database's RocksDB `LOCK` when it exists. A running node holds
  the same configuration lock, so `bind-node` refuses while the node runs and
  the node refuses to start (exit 2) while `bind-node` edits. **Never run
  `bind-node` beside a running node**; stop the unit first. The lock is a
  second line of defence, not a substitute for stopping it.
- It refuses a leftover `config.json.tmp` (decide which file is correct
  first), content the engine's configuration schema would drop, a symbolic
  link, and a file owned by another user. It keeps the file's mode and group
  and writes through a temporary file, `fsync` and rename.

| Exit status | Meaning | Action |
| --- | --- | --- |
| 0 | Bound, or already bound | Start the node |
| 1 | Refused; nothing was written | Read the message, fix the cause |
| 2 | Usage error | Fix the command line |
| 3 | Written, but the directory flush failed: durability unconfirmed | Run `sync` on `config.json` and on the database root (`sync /var/lib/tos/validator/config.json /var/lib/tos/validator`) before starting or relying on it |

Start the node and check the custody line it logs at start-up:

```
post-quantum consensus custody: validator_id <hex> key_id <hex>
```

Both values are in the same hex form `tos-pq-consensus-key show` prints
(`validator-engine.cpp`). The engine aborts at start if `validator_id` is zero
or the key fails to load, instead of starting as an observer.

`bind-node` has been tested on Linux only. It is not shipped for macOS and
has not been run there.

## 6. Storage and retention

### 6.1 How data is retired

| Data | Retired when | Code |
| --- | --- | --- |
| States (CellDb) | The GC floor passes them | `ValidatorManagerImpl::try_advance_gc_masterchain_block` |
| Archived blocks | At least `state-ttl + archive-ttl` after their time, per 20,000-seqno package | `ArchiveManager::run_gc`, `archive-gc-floor.h` |
| Session statistics | Self-rotating at 256 MiB, one `.old` copy | `max_session_stats_file_bytes_` |
| Text log (`-l`) | Rotates at 10 MiB, one `.old` copy | `TsFileLog` |
| Retired validator consensus databases | Once provably obsolete, trailing the GC floor (default on, section 6.4) | `validator/manager.cpp`, `VALCLEANUP` |

The GC floor advances only while **all** of the following hold:

- it is behind the last key block;
- it is behind the last validator-set rotation;
- it is behind the persistent-state serializer;
- it is at least 1,024 blocks behind the head;
- it is behind the shard client;
- the state at the floor is older than `--state-ttl`.

The serializer walks every masterchain block and normally keeps up. It pauses
only when a key block starts a new 2^17 s (about 36.4 h) period. Then it waits a
random 0–6 h before writing that persistent state, and the floor cannot pass
it meanwhile. On the local network, with a key block every ten minutes, the
floor ran about `state-ttl` behind the head, and usage levelled off within
hours.

On production elections (`elected_for` 65,536 s), key blocks come from set
rotations about every 18 h, plus configuration changes. The floor can
therefore stop for up to about 18 h behind the last key block, plus up to 6 h
at a persistent-state boundary. **Plan disk for the TTLs plus about one day**,
not for the TTLs alone.

**Short retention also removes old key blocks.** A lite client that proves its
way forward from the zero state needs every key block since Genesis. Once those
blocks are collected, a newly started client fails with
`LITE_SERVER_NOTREADY: block handle not in db`; this was observed on the local
network. Every client therefore needs a recent trusted `init_block`. Section
8.1 covers how the global config provides it.

### 6.2 Recommended retention per role

| Role | `--state-ttl` | `--archive-ttl` | Other |
| --- | --- | --- | --- |
| Validator | 86400 (default) | 86400 | `--max-archive-fd` default 512 |
| Full node / RPC | 86400 | 604800 (default) | enough history for wallet clients |
| Archive | ≥ 30 d | as policy requires | `--permanent-celldb` only on a dedicated archive host; it cannot be turned off. At `state-ttl` ≥ 30 d CellDb raises its cache to at least 16 GiB. Do not copy the 1 GiB cache flags of section 7 to it. |

### 6.3 Disk sizing

Measured on the local development network: 4 validators, about 2.5–2.8
masterchain blocks/s, ConfigParam 30 target rate 400 ms. Per hour, per
validator:

- consensus databases about 670 MB (before cleanup);
- block files about 330 MB;
- archive about 180 MB;
- state database about 73 MB until GC.

A non-validating node writes about 370 MB/h.

These are **lower bounds** for production. With up to 21 validators, every
block carries more ML-DSA-44 signatures, at 2,420 bytes each. Production
sizing must be measured on the N6 hardware profile with 21 validators before
launch (gap G8). Until then, provision at least:

- (archive + block-file growth) × (TTLs + 2 days of GC lag) × 1.5 safety factor;
- plus the consensus databases retained until cleanup reaches them: about one
  `--state-ttl` plus the GC lag of growth (section 6.4);
- with at least 25 % free space (tos `doc/Validator.md`).

### 6.4 Retired consensus databases

Every validator-set session creates a RocksDB directory under
`<db>/consensus/`. A new session starts roughly every 250 s per validated
shard (ConfigParam 28 catchain lifetimes) and on every key block, so these
directories add up to gigabytes per day.

When a session retires, the engine writes a durable cleanup record (in the
same synced write as the retirement), then stops the group and closes its
database. It deletes the directory later, once all of the following hold
against the durable GC masterchain block:

- the block at which the session retired is an ancestor of the GC block;
- the GC state shows the session's shard on a strictly newer catchain;
- no current or next validator group uses or can recreate the session;
- the retiring group has closed its database.

Deletion therefore trails the GC floor, that is `--state-ttl` plus the GC lag
of section 6.1. A crash at any point is recovered on the next start. The
backlog is scanned 256 records at a time with at most 16 deletions per pass,
so a large backlog drains gradually without memory growth. A fixed 10 s timer
drives the scan: each tick runs at most one pass, the cursor wraps at the end of
the store and the scan never pauses, so a failed read or deletion is simply
retried on a later tick. Enabling or disabling cleanup is decided at start-up.

**Cleanup is on by default.** No flag is needed. The options are:

| Option | Effect |
| --- | --- |
| *(none)* | Delete retired consensus databases (the default) |
| `--enable-validator-consensus-cleanup` | States the default explicitly |
| `--disable-validator-consensus-cleanup` | Keep them, for forensics only; the disk grows without bound. Records keep accumulating and are reclaimed after a restart without the flag |
| both | Refused: the engine exits with status 2 |

Evidence in the log (`-l`):

- at start-up, `validator consensus cleanup: enabled` (INFO) or
  `validator consensus cleanup: disabled; ...` (WARNING);
- per deletion, `VALCLEANUP reserve`, `VALCLEANUP delete_done ...
  confirmed_gone=1` and `VALCLEANUP erase_ack`.

The start-up `enabled` line and the per-deletion lines are logged at **INFO**.
The engine's default verbosity is INFO (`-v 3`); at `-v 2` or lower they are not
written, and their absence then proves nothing about whether cleanup runs. A
failed deletion is logged as `VALCLEANUP delete_done ... confirmed_gone=0` at
WARNING, at any verbosity, and is retried. A production validator therefore
keeps the default verbosity and does not set `-v` below 3.

**Code status.** The default-on behaviour, the `--disable-` option and the
mutual-exclusion check are in PR #148. Builds from tos `main` before #148 merges
still have only `--enable-validator-consensus-cleanup`, labelled acceptance-only
and off by default, and do **not** clean up. Do not deploy a validator build
unless its `validator-engine --help` lists `--disable-validator-consensus-cleanup`.
Its log must also show `validator consensus cleanup: enabled`.

**Evidence so far.** On the local seven-node development network (one host),
an engine built from PR #148 deleted retired directories on all five validators
within the first hour: the oldest retained catchain moved from 176 to about 200
while each validator's directory count stayed flat (40–82).

The production evidence still missing is a validator on a live, multi-host
network that has deleted directories through several set rotations and kept
`<db>/consensus/` bounded (gap G11).

## 7. Service definitions

The tos repository has no production unit; the `tos-pq-*.service` files in
`../local/systemd/` are development templates. The unit below is also kept as
[`systemd/tos-validator.service`](systemd/tos-validator.service). Proposed validator unit:

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
  --exporter-address 127.0.0.1:9100
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

Notes on each choice:

- **`LimitNOFILE`.** The engine raises its own open-file limit to 1,572,864
  but only logs a failure. The unit grants that limit explicitly.
- **No `MemoryMax`/`CPUQuota`.** No hard cap until steady-state memory has been
  measured on the production profile (tos `doc/Validator.md`). A cap set
  too low turns a load spike into a validator restart.
- **RocksDB caches: 1 GiB each.** The CellDb block cache and the shared
  block cache of the other databases are each capped at 1 GiB. Without
  `--celldb-cache-min-size`, CellDb V2 raises its cache to about 4.66 GiB
  whatever `--celldb-cache-size` says, so the unit sets both. This bounds the
  caches only: memtables, the cell cache and allocator retention still add to
  RSS. An archive host (`--state-ttl` ≥ 30 d) is sized separately; there the
  engine's own floor is 16 GiB, and these flags would lower it.
- **`TimeoutStopSec`.** Leaves RocksDB time to close cleanly. The engine holds
  `config.json.lock` until it has exited; a replacement started earlier exits
  with status 2.
- **Consensus cleanup.** No flag: cleanup is the default (section 6.4).
- **Verbosity.** No `-v`: the default INFO level is what records the cleanup
  evidence.
- **Further sandboxing.** Options such as `RestrictAddressFamilies` or
  `SystemCallFilter` are deliberately absent until a staging node has run with
  them. A filter that blocks something the network stack needs fails at
  runtime, not at start.
- **Defaults kept on purpose:**
  - `--initial-sync-delay` stays at its default 60 s. It is not an ADNL
    requirement.
  - `--quic-flood-control` stays at its default of 1,000 connections per IP.
    The `-1` used locally disables the protection.
- **Exporter.** The health exporter flags (`--health-node-id`,
  `--health-core-metrics`, `--health-native-core-v3`) require a performance
  acceptance per their help text. Enable them only with the monitoring design
  in section 11.
- **Full node, RPC or archive.** Same unit, plus as needed:
  - liteserver keys;
  - `--json-rpc-address <loopback>:<port>` behind a proxy, or
    `--json-rpc-readonly` on a public address;
  - `--json-rpc-trusted-proxy`;
  - the retention from section 6.2.
- **DHT node.** Uses `dht-server` with `-C -c -D -l -t -u` only. It has no TTL
  or rlimit options.

### 7.1 Options a production node must not set

| Option | Why |
| --- | --- |
| `--disable-validator-consensus-cleanup` on a validator, except time-boxed for forensics | Unbounded disk growth (section 6.4) |
| `--test-consensus-cleanup-crash-before-erase` | Fault injection; exits abruptly by design |
| `-U/--unsafe-catchain-restore`, `-F/--unsafe-catchain-rotate` | Labelled dangerous; PQ rejects a nonzero rotate tag |
| `-T/--truncate-db` | Rewrites the database head; recovery tool only |
| `--disable-state-serializer` | Stops persistent states, which stops GC |
| `--permanent-celldb` | Irreversible; archive hosts only |
| `--quic-flood-control -1`, `--max-archive-fd 0` | Remove protection limits |
| `--unsynced-liteserver`, `--nonfinal-ls` | Serve unsynced or non-final data |
| `--json-rpc-cors-origin "*"`, `--json-rpc-expose-consensus-status` on a non-loopback bind | Expose the node beyond its role |
| `-v` above the default on a validator | Log volume and latency; diagnostics only, time-boxed |
| `-v` below 3 on a validator | Hides the INFO-level cleanup evidence (section 6.4) |

## 8. Joining the network

1. **Global config.** It contains the zero-state, the init block and the DHT
   seeds. Obtain it from the network's signed release, not from an
   unauthenticated URL, and verify:
   - the zero-state root hash;
   - the file hash;
   - the global ID (1);
   - that `validator.init_block` is a recent key block (section 8.1).

   The Docker default `https://tos.network/global-config.json` is
   not authenticated by anything in the repository (gap G7).
2. **Initial sync.** By default the node downloads the last `--sync-before`
   (3,600 s) of blocks and selects the best persistent state from peers.
   Persistent-state import is bounded by the `--persistent-state-*` budgets.
   Their effective values are logged at start; size the spool volume (48 GiB
   per import, 96 GiB total by default) accordingly.
3. **Snapshots.** Only into a new database, through the digest-checked
   importer (section 8.2). A snapshot's zero-state check does not authenticate
   the global config.
4. Confirm sync before anything else depends on the node:
   - the head advances;
   - the node agrees with a second trusted node on the full block ID, not just
     the height;
   - `/readyz`, on RPC nodes, is within its threshold.

### 8.1 Refreshing the global config's init block

Whoever publishes the network's global config refreshes `validator.init_block`
to a recent key block, at least as often as the shortest archive retention
among the network's public lite servers:

```bash
python3 "$TOS_ROOT/scripts/refresh-global-config-init-block.py" \
  --rpc http://127.0.0.1:<rpc-port>/jsonRPC --global-id 1 \
  CURRENT-global.config.json NEW-global.config.json
```

- It reads `getMasterchainInfo`, `getBlockHeader` and `lookupBlock` from one
  node and writes a **new** file; it never overwrites one.
- The new init block is the latest key block. If the chain has no key block
  after the zero state yet, the init block is the zero state itself, checked
  against the input config's.
- It refuses, writing nothing, when the node's zero state differs from the
  config's, when the two answers for the key block disagree on its full id,
  when a header is not a key block or carries another global id, or when the
  new init block is older than the existing one, or at the same height but a
  different block.
- The node is trusted, not proven. Run it against a node the publisher
  operates, after comparing that node's last block, on the full block id, with
  a second trusted node. The refreshed file is authenticated by the release
  that carries it (digest and attestation), not by the script.

### 8.2 Snapshot import

`docker/import-snapshot.sh` also runs outside the container. It takes its
settings from the environment (`SNAPSHOT_IMPORT=1`, `DUMP_URL`,
`DUMP_SHA256`, `DUMP_ZEROSTATE_ROOT_HASH`, `SNAPSHOT_STAGING_DIR`,
`TOS_DB_DIR`, `TOS_GLOBAL_CONFIG`) and needs `curl`, `plzip`, `sha256sum`,
`perl` and `jq`.

1. **Stop the node** (`systemctl stop tos-<role>`) and every other process that
   might open the database. The import must be the database's only writer
   until it exits.
2. Obtain `DUMP_SHA256` independently of the snapshot download. It is the only
   trust anchor; a checksum served next to the archive proves nothing.
   `DUMP_ZEROSTATE_ROOT_HASH` must equal the global config's zero state, which
   is a consistency check between two operator settings, not authentication.
3. Run the import as the service account, with the staging directory outside
   the database but on the same filesystem.

What the script enforces:

- It takes the engine's own lock: a POSIX `fcntl` write lock on
  `<db>/config.json.lock`, from before it reads the database until it exits,
  and confirms through `/proc/locks` that it holds it. An engine started during
  the import exits with status 2. `flock(1)`/`flock(2)` is a different lock that
  the engine neither takes nor sees; holding the database with `flock` excludes
  nothing, so do not wrap the import in `flock` and assume the node is kept out.
- It refuses if any RocksDB `LOCK` file under the database is held.
- It imports only into a new database: besides `config.json`,
  `config.json.lock`, `keyring/`, `tos-global.config`, the engine's empty
  `error/` log and an empty `lost+found`, nothing may be there, both before
  the download and again immediately before installation.
- It checks the SHA-256 before unpacking, accepts only regular files and
  directories with safe relative names, and writes the `.snapshot-imported`
  marker last.

The lock catches a node that was not stopped; it does not replace stopping
it, and nothing recovers an installation interrupted by a crash: start again
from a new database.

### 8.3 Choosing the genesis time

The genesis time (the `--epoch` passed to genesis, written into the zero state
as its `utime`) is the earliest time the chain can produce a block. No option
says "wait until genesis". Two consensus rules produce that behaviour together:

1. **Block time never goes backwards.** The collator sets a new block's
   `gen_utime` to the later of the previous state's time plus one second and
   the local clock (tos `validator/impl/collator.cpp`, `Collator::init_utime`).
   The previous state of the first block is the zero state, so the first block
   is dated at least genesis + 1 s, even when it is collated hours early.
   Validators reject a block dated before the previous state
   (`validate-query.cpp`, "creation time is not monotonic").
2. **No block from the future.** Each validator refuses to vote for a candidate
   whose `gen_utime` is more than 30 s ahead of its own clock
   (`validate-query.cpp`, "gen_utime ... is too far in the future"). The cap
   stops a leader from parking unbounded future-dated candidates in waits.

Before genesis, every candidate is dated genesis + 1 s or later, so every
validator rejects it as being from the future. Blocks start when the validators'
clocks reach about genesis − 29 s. Nodes started earlier connect, exchange
overlay traffic and wait at height 0; that is the expected state, not a stall.

Consequences for the ceremony:

- **Start every genesis validator before the genesis time.** A validator whose
  last applied masterchain block is at least 300 s old when it starts enters
  startup archive catch-up (tos `validator/startup-catchup.h`,
  `kStaleValidatorAgeSeconds`). A validator that first starts well after
  genesis therefore takes a different path from the rest of the genesis set.
  Leave enough time between the genesis step and the genesis time to publish
  the global config, copy it to every host and activate every node; the
  testnet runbooks use at least 60 minutes.
- **Clocks decide the first block.** The 30 s cap is checked against each
  validator's own clock. Synchronise clocks before activation (the testnet
  preflight requires NTP synchronisation with a selected server, and the
  epoch-2 hosts measured offsets under 2 ms); a validator
  whose clock runs more than 30 s slow keeps rejecting fresh blocks as being
  from the future, and one that runs fast collates blocks the others reject.
- **The genesis time fixes the schedule.** The first election opens at
  genesis + (initial set lifetime − `elections_start_before`) and the initial
  set expires at genesis + its lifetime. Choose the genesis time so that this
  window falls in staffed hours, and so that every operator's onboarding can
  finish before the election opens.
- **Allowed range.** The testnet coordinator accepts a genesis time between
  1 h in the past and 14 days ahead (`MAX_EPOCH_BEHIND`, `MAX_EPOCH_AHEAD` in
  `testnet/scripts/testnet-coordinator.py`). A time in the past makes the
  chain start as soon as the validators run, but it also makes any validator
  started 300 s or more after genesis enter archive catch-up.
- **Mainnet template.** The canonical `gen-zerostate.fif` pins
  `SOURCE_DATE_EPOCH` 1789434000 (2026-09-15 01:00:00 UTC). That date is
  already in the past; tos `doc/validator-genesis-bootstrap.md` requires it to
  be reviewed and updated, with the initial-set lifetime rehearsed, before the
  mainnet ceremony.

## 9. Validator lifecycle

Prerequisites: a synced full node (section 8) on the validator host, and an
operator wallet with funds. The tos guide (`doc/validator-operator-guide.md`)
has the full command sequence; the production points are below.

1. **Keys.** Consensus seed on the host (3.1). Root seed offline (3.2).
2. **Controller.**
   - Build the code from the release source (`func` on
     `crypto/smartcont/validator-controller-v1.fc`, then `fift`) and check
     that its code hash is admitted in ConfigParam 47; the Elector refuses
     unadmitted code with reason 10.
   - Offline: `tos-pq-controller init-data ROOT_PUBLIC_HEX CONSENSUS_KEY_ID_HEX`
     prints the initial data (epoch 0, nonce 0, the consensus `key_id`, the
     root public key). It refuses a zero key id and a key id equal to the
     root's own.
   - `tos-pq-controller state-init CODE_BOC_B64 INITIAL_DATA_BOC_B64` prints the
     StateInit; the address and code hash go to standard error.
   - Deploy it from an operator wallet with a non-bouncing message and an empty
     body:
     `tosctl wallet send --from WALLET --to -1:CONTROLLER_HEX --amount TOS --state-init-boc STATE_INIT_BOC_B64`.
   - Keep the raw BOC of the deployment transaction, and register the birth
     with
     `tosctl config bind import-birth --node NODE --transaction-boc TX.boc --output /abs/path/controller-birth.boc`.
     `tos-pq-controller witness CODE_BOC_B64 INITIAL_DATA_BOC_B64` prints the
     birth witness for inspection.
3. **Bind the node** to the controller with `bind-node` (section 5.1).
4. **Pool.** Deploy a single-nominator pool with owner, validator wallet and
   controller: `tosctl deploy pool --node NODE --owner OWNER --controller CONTROLLER --amount TOS`,
   or by hand with `init.fif` (five arguments, see
   `crypto/smartcont/single-nominator-pool/HOWTO-deploy.md`). Register it with
   `tosctl config pool add --controller ...` and `tosctl config bind add --pool ...`.
5. **Operating authorization (kind 4).**
   - Check it:
     `tosctl controller operations status --controller -1:CONTROLLER_HEX`.
     It prints funds, allowance, per-request limit, storage floor, expiry,
     payer, balance, the live grant (ConfigParam 20/24), stakes remaining and
     the runway at the ConfigParam 15 interval. Every value is read at one
     pinned masterchain block, which it names. `--strict` exits non-zero on
     any warning; `--format json` is available; `--target-days`,
     `--warn-percent` and `--expiry-warn-days` default to 30, 25 and 7.
   - Warnings marked **[BLOCKING]** mean the next relay fails: no
     authorization, expired, per-request limit below the grant, funds or
     allowance below one grant, or balance below funds + floor.
   - Renew it:
     `tosctl controller operations plan --controller -1:CONTROLLER_HEX --payer PAYER_ADDRESS`.
     The plan renews by deficit (a deposit adds to the funds, every other field
     replaces the stored one), names the block it read, and signs and sends
     nothing. `--floor-nanotos` is required for a first authorization;
     `--expiry-only` renews only the expiry; `--allow-payer-change` is needed
     to move sponsorship; `--valid-for` (default 1800, at most 3600 s) sets
     `valid_until`. It refuses while a relay is pending or retry fees are held.
   - When a new floor is not covered by the balance, the plan prints a step 0:
     a **capital top-up**, sent to the controller as a separate plain transfer,
     because the deposit raises balance and funds alike. Without it every relay
     fails the capital check, and the plan shows the projected warning as
     `[BLOCKING] after renewal`.
   - The plan prints the exact offline
     `tos-pq-controller fund-operations ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH NONCE VALID_UNTIL PAYLOAD_BOC_B64`
     line and the payer's send:
     `tosctl wallet send --from PAYER_WALLET --to -1:CONTROLLER_HEX --amount-nanotos VALUE --body-boc SIGNED_BODY_B64 --bounce`.
     `--bounce` makes a refused request return its value. Send exactly the
     printed value before `valid_until`, then re-run `status` and check that
     the nonce advanced and the values are the planned ones. Re-run the plan
     if any relay or root action happened after its pinned block.
   - Sizing: one stake per election, about every 18.2 h. At the current fee
     configuration a grant is about 6.44 TOS, about 8.5 TOS per day; take the
     live grant from `status`, not from this number. The payer is a dedicated
     operator wallet; operating capital is not pool principal.
6. **Stake.** `tosctl config elections enable NODE`, then `tosctl service`
   with the elections task:
   - polls `active_election_id`;
   - asks the node to sign the PQ stake authorization with its consensus key
     (`engine.validator.createPqStakeAuthorization`), so the node must be bound
     and running;
   - builds the pool stake order from the birth artifact;
   - recovers returned stakes;
   - creates no temporary validator key: on the PQ chain the node is matched to
     its set entry only through the consensus key;
   - reads each controller's operating authorization every five minutes, logs
     missing, expired or low ones, and publishes them per node as
     `operating_authorization` in `/v1/validators`. It reports; it cannot
     renew. Thresholds are under `elections.operating_authorization` in the
     `tosctl` configuration.
7. **Verify each election.**
   - The Elector replies `sr::ok` for the query.
   - The controller's recorded result matches.
   - After the set switch, the validator appears in Config34 with its exact
     `key_id`.
   - Its node creates the validator group.

   Elector refusal reasons are listed in `elector-code.fc` (for example
   3 = wrong `stake_at`, 5 = below `min_stake`, 13 = witness mismatch).
8. **Rotation.**
   - **Consensus key, today (PR #148): one key per node.** Once the controller
     is bound to a new key B it refuses stakes signed with the old key A, and
     once the node restarts with B it no longer signs for a set that lists A.
     A rotation is safe only in a verified interval in which A has no signing
     obligation: ConfigParam 34, and ConfigParam 36 while a next set is
     pending, no longer list this controller with A, and the next stake is not
     due before the restart. Otherwise it costs downtime. Steps: generate B
     offline; `tos-pq-controller bind ... NEXT.seed` and send the body; move B
     with `export | ENCRYPT` / `DECRYPT | import`; with the node stopped,
     `tos-pq-consensus-key bind-node --replace DB_ROOT NEW_KEYFILE VALIDATOR_ID`;
     start and check the custody line shows B; confirm the next election
     accepts B; then delete A and the transfer copies.
   - **Consensus key, zero downtime: available once PR #149 merges.** The node
     then holds up to eight keys per validator, each with `valid_from` (first
     election date it signs stakes for) and `expire_at` (0: never). B is added
     beside A on a running node with the console command
     `add-pq-consensus-key KEYFILE VALID_FROM EXPIRE_AT`, or offline with
     `tos-pq-consensus-key add-node-key DB_ROOT KEYFILE VALID_FROM [EXPIRE_AT]`;
     `get-pq-consensus-keys` / `list-node-keys DB_ROOT` show the held keys;
     A is removed with `del-pq-consensus-key` (refused while a current,
     previous or next set lists A) or `remove-node-key DB_ROOT KEYFILE|KEY_ID`
     on a stopped node (which cannot see validator sets). `expire_at` is a hard
     deadline read from the wall clock: from then on the key signs nothing,
     even in a running group, and once seen expired it is retired for the life
     of the process. A restart with the clock rolled back would load it again,
     so run NTP. `bind-node` refuses a node holding more than one key. Until
     #149 is merged and released, none of these commands exists in a release.
   - **Root key:** `rotate-root` (kind 2). It changes the epoch, so signed
     bodies prepared earlier become invalid.
9. **Leaving and recovery.** Stop staking. Funds stay frozen until
   `utime_until + stake_held_for` (32,768 s), then return through
   `compute_returned_stake` and the receipt-based recover path. Withdraw
   operating funds with kind 5 (`withdraw-operations`), which needs no relay
   pending. Keep the node running until the set it belongs to has expired.

### 9.1 Masterchain addresses on the command line

From PR #148, every `tosctl` address flag (for example `wallet send --to`,
`controller operations --controller/--payer`, `config pool add
--address/--owner/--controller`, `deploy pool --owner/--controller`) accepts a
raw masterchain address as its own word, `--to -1:<hex>`, as well as
`--to=-1:<hex>`. Each value is parsed as an address at parse time, so a
missing value followed by another option (`--to --bounce`) is refused instead
of being taken as the address. The tos guide's statement that `-1:<hex>` must
be written in the `--flag=` form predates this change; both forms work.

## 10. Releases, upgrades and restarts

- Install binaries only from a tagged release, verified by digest and
  attestation (`gh attestation verify`), and container images only by digest.
- Roll a version one validator at a time:
  - only while the chain is live and every other validator is at the head;
  - stop the old process completely before starting the new one: while it
    holds `<db>/config.json.lock` the new engine exits with status 2;
  - wait until the restarted node is back at the head before the next one;
  - two validators replaying at once can halt a four-member set.

  See `tools/node-health-monitor/deploy/README.md`, "Rolling an engine".
- Read the release notes for changed defaults. The release that brings
  consensus cleanup on by default changes behaviour without any flag; a unit
  that still passes `--enable-validator-consensus-cleanup` keeps working, and
  one that adds `--disable-` as well is refused with status 2.
- Never restart a validator to change a performance setting; measure on a
  non-validator first.

### 10.1 Configuration proposals

Protocol changes ship binary first, then activate by a configuration vote.

- Create a proposal with `tosctl vote offer create --param N` and one of
  `--value-boc`, `--value-boc-file` or `--remove`. It prices the proposal from
  live ConfigParam 11 and refuses locally what the configuration contract would
  refuse: a ConfigParam 10 parameter without `--critical`, a ConfigParam 9
  parameter that does not name the value it replaces (`--bind-current` or
  `--if-hash-equal`), and a value that does not decode as the parameter's type
  (`--skip-value-check` overrides only the last).
- With `--wallet NAME` it sends from a configured **masterchain** wallet after
  confirmation (`--yes` for non-interactive use). It bounds the wallet's own
  fees, including storage owed, from the `storage_stat` the node serves with
  the account at one block. A node not built from PR #148 does not serve it,
  and `--wallet` then refuses. Without `--wallet` it prints the body and value
  for an external masterchain wallet; the contract ignores a proposal from any
  other workchain and keeps its value.
- The report says `registered` only when the configuration contract is then
  seen holding the proposal; that is observed state, not proof that this
  transaction caused it. A lost send answer is reported as an unconfirmed
  broadcast, not as a failure.
- List and inspect with `tosctl vote offer ls` and
  `tosctl vote offer diff --hash HASH`.

### 10.2 Votes

- Votes are signed with the consensus key, on the validator host, as the
  node's service account:
  ```bash
  tos-pq-vote config KEYFILE GLOBAL_ID SET_ID_HEX VALIDATOR_ID_HEX IDX PROPOSAL_HEX
  ```
  `SET_ID_HEX` is the hash of the current ConfigParam 34 cell, `IDX` this
  validator's index in it, `VALIDATOR_ID_HEX` the controller id. The output is
  a message body; send it from a wallet (`tosctl wallet send ... --body-boc`)
  to the configuration contract (ConfigParam 0) with at least the masterchain
  compute fee for 50,000 gas plus the message's own processing. The contract
  refuses a smaller value before it checks the signature.
- `tosctl vote offer cast` does not send PQ votes; it explains why and stops.
- A round is won when validators holding **strictly more than three quarters**
  of the set's total weight have voted for the proposal. Exactly three quarters
  does not win: the contract starts each round at `floor(3W/4)` remaining
  weight and requires it to go below zero (`config-code.fc`). The number of
  won rounds needed, and of lost rounds that kill it, come from ConfigParam 11,
  separately for critical parameters.

## 11. Monitoring

Place the health stack **off the validator host**:

- `placement: production_off_validator`, `remote_native_mode: cached_only`;
  see `tools/node-health-monitor/config/production.example.yaml`.
- Its `production_blockers()` refuse to run until the deployment fields are
  bound. That means `network_id`, binary, performance, mTLS, receiver and
  resource digests, and three distinct failure domains.
- On the validator, only `health-edge` runs, bound to the node PID, plus the
  loopback exporter.

Alert at least on:

| Signal | Why |
| --- | --- |
| Head age, agreement with a second node on the full block ID | Liveness and fork detection |
| Election outcome per round (`sr::ok` present, controller refusal or bounce) | A missed election is silent otherwise |
| `tosctl controller operations status --controller ... --strict` non-zero, or `operating_authorization` in `/v1/validators` | Any `[BLOCKING]` warning stops the next stake; early warnings at 25 % of a 30-day runway and 7 days before expiry |
| Time since last key block, GC floor progress (`VALCLEANUP pass gc_seqno`, INFO once the cleanup change is merged), consensus directory count | GC stalls show up hours before the disk does |
| `validator consensus cleanup: enabled` at each start; `VALCLEANUP delete_done ... confirmed_gone=0` | Cleanup off or failing means unbounded growth |
| Free disk below 25 %; growth rate above plan | Section 6 |
| Wallet balances of payer and validator wallets | Fees for stake orders and authorizations |
| Engine exit status 2 in the unit's journal | A second engine, a held lock, or a refused option |

## 12. Gaps before this procedure can be followed

| ID | Gap | Status |
| --- | --- | --- |
| G1 | Release artifacts and the Docker image lacked the PQ tools | **Closed by #148** for Linux x86_64/arm64 and the image. Not shipped for macOS or Windows |
| G2 | No tool checked or renewed the kind 4 operating authorization | **Closed by #148** (`tosctl controller operations status/plan`, `wallet send --bounce`, elections-task warnings). Renewal stays a manual offline signing plus send by design. Not yet exercised on a live multi-host network |
| G3 | No tool set `extraconfig.pq_consensus` | **Closed by #148** (`tos-pq-consensus-key bind-node`). Tested on Linux only; macOS untested |
| G4 | No tool built controller initial data or deployed a controller | **Closed by #148** (`tos-pq-controller init-data/state-init`, `wallet send --state-init-boc`, `config bind import-birth`) |
| G5 | No supported key transfer path for a kind 3 ceremony; rotation needs downtime | **Partly closed.** #148: `export`/`import` and a documented single-key rotation inside a verified interval. Zero-downtime rotation is available once PR #149 merges. Open: a multi-node rotation through a real election on a live network |
| G6 | `tosctl` elections created classical temporary keys | **Closed by #148**: no temporary key; the permanent-key entry stays only as the ADNL-address record |
| G7 | No authenticated distribution of the global config, and no init-block refresh | **Partly closed.** #148 adds `scripts/refresh-global-config-init-block.py`. Open: an authenticated, signed release channel for the global config and a refresh schedule. Docker still defaults to an unauthenticated URL |
| G8 | Hardware profile `OWNER_REVIEW_REQUIRED`; no 21-validator disk or memory measurement | **Open.** Section 6.3 sizing is a lower bound only. Proposed requirements and hosting-diversity rules: [Hardware-and-Hosting.md](Hardware-and-Hosting.md) |
| G9 | Stale operator docs in tos | **Closed by #148** (operator guide, Validator.md, FullNode.md, single-nominator HOWTO, docker/README.md, tos-upgrade-process.md; the custody log line and `-1:<hex>` address wording were corrected in `47e317b57`) |
| G10 | No tool created a configuration proposal | **Closed by #148** (`tosctl vote offer create`). `--wallet` needs RPC nodes built from #148 (`storage_stat`) |
| G11 | Retired validator consensus databases never deleted by default | **Closed in code by #148** (section 6.4; on by default, fixed-period scan). Verified deleting on the local single-host network. Open: deletion evidence from a live multi-host network across several set rotations |
| G12 | No production systemd unit in the tos repository | **Open.** Section 7 remains a proposal; the tos repository still ships only development and monitoring units |

The order that unblocks a first external validator is now:

1. G11: merge the cleanup change into #148 and gather live deletion evidence;
2. G7: publish the global config through an authenticated channel, with the
   init block refreshed on a schedule;
3. G8: sizing on the production hardware profile;
4. G5: a multi-node rotation through a real election, after PR #149;
5. G12: an accepted production unit.
