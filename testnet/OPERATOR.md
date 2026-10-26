# Testnet validator operator guide

This is the **operator-side** runbook for the supplied Ubuntu 24.04 x86_64
installation, not a mainnet procedure. [CEREMONY.md](CEREMONY.md) is the
coordinator's authoritative signing and genesis sequence; this guide adds host
checks, custody, maintenance and incident response without duplicating that
sequence. Read [agent safety rules](../AGENTS.md#hard-safety-rules) first.

Commands with `<PLACEHOLDERS>` need approved values; never paste them unchanged.
Run host commands on the validator host and coordinator commands on the
coordinator. Keep all real inventories, keys, receipts and ceremony directories
outside this checkout. Any refusal means stop, retain evidence and ask the
coordinator. Never loosen a check to continue.

## 1. Agree the network and responsibilities

**Prerequisites:** the coordinator supplies the full 40-character tos commit,
approved profile, epoch/zero-state identity, operator label, authenticated public
artifacts and contact/alert channel. Record these outside the repository.
The documented reference build is tos `85c679c3454f306eb867e25b1960ae3d757bd3dd`;
the ceremony's approved revision takes precedence and must match on every host.

- **Operator:** provides host and SSH public access details, prepares it, retains
  the consensus seed, supplies the authenticated public record, and keeps it live.
- **Coordinator / authorized offline signer:** derives each validator's staking
  pool, generates/publishes genesis, retains the bootstrap and offline pool-owner
  wallets, journals payments and onboards. The pool owner keys stay in the
  coordinator's signing domain, never on the validator host.
- Only public records cross to the coordinator. A request for a seed, vault key
  or mnemonic is not part of onboarding.

Verify commands against this installed bundle, not an older guide:

```bash
python3 /opt/tos-testnet/scripts/testnet-operator.py --help
python3 /opt/tos-testnet/scripts/check-testnet.py --help
python3 /opt/tos-testnet/scripts/testnet-elections.py --help
```

The shell installers have no `--help` handler; their usage is in their opening
comments. `onboard`, `activate` and retirement have no dry run. Obtain explicit
human approval after read-only checks; `fund` and `withdraw` support
`--dry-run` and need its review before the live command. `fund --dry-run` signs and saves a private BOC;
it is not a no-signing check and requires signing permission.

## 2. Host requirements, clock and preflight

**Operator prerequisites:** dedicated host, static public IPv4 or verified UDP
forwarding/hairpin NAT, provider console access, root administration and enough
NVMe endurance. The current validator preflight floors are **4 CPUs, 11 GiB
MemTotal, 60 GiB free** on Ubuntu 24.04. These are installation floors, not a
production capacity guarantee. See [profile](network/profile.json) and
[hardware proposal](../production/Hardware-and-Hosting.md).

1. Install the reviewed `testnet/` bundle at `/opt/tos-testnet`, owned by root,
   readable by service accounts. Do not put it in a private home directory.
2. With approval, set time on the host:

   ```bash
   sudo /opt/tos-testnet/scripts/setup-time.sh
   ntpq -pn
   ```

   Expected: ntpsec follows a selected reachable server (`*` in `ntpq`), using
   IPv4. `NTPSynchronized=yes` alone is insufficient. On failure fix clock/network
   reachability; do not prepare a node with an unproven clock.
3. The **coordinator** runs [preflight §0.5](CEREMONY.md#05-coordinator-preflight-every-host)
   over all hosts. It must report no FAIL. `--install-tools` changes packages;
   first-seen SSH keys require independent confirmation. A changed key is refused.
4. Open provider **and host** ingress UDP 30001/31001 for a validator. RPC 8081 and
   exporter 9100 listen on loopback; the console 30002 listens on every address, so
   the host firewall must not admit it (preflight's `ufw` check refuses an allow rule). DHT uses 30300/udp; lite 30003/tcp
   belongs to a separate full node, not this validator. Verify the actual bindings:

   ```bash
   sudo ss -lntup
   ```

   A missing UDP mesh probe is a firewall/routing issue, not permission to open
   console/RPC publicly. See [activation networking](CEREMONY.md#6-everyone-activate-before-the-epoch).

## 3. Build the pinned binaries and prepare

**Operator, after approval:** set the full ceremony commit, then build on this
host; no binaries copied from a different CPU. The testnet keeps these host
builds; only production installs from tos GitHub releases with `fetch-release.py`:

```bash
TOS_COMMIT=<FULL_40_CHARACTER_COMMIT>
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev "$TOS_COMMIT" --role validator
sudo /opt/tos-testnet/scripts/build-tosctl.sh --rev "$TOS_COMMIT"
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role validator \
  --public-ip <PUBLIC_IPV4> --release "/var/lib/tos-build/release-$TOS_COMMIT" --rev "$TOS_COMMIT"
```

`--rev` is refused unless the release's `BUILD-INFO` names that commit. The
build is reproducible for one commit and toolchain: compare the release's
`SHA256SUMS` with another host's built from the same commit.

Build outputs: `/var/lib/tos-build/release-<COMMIT>/{SHA256SUMS,BUILD-INFO}`,
`/etc/tos/TOSCTL-BUILD-INFO`, and build logs in `/var/lib/tos-build`.
Expected: digest verification succeeds; prepare creates the stopped node's
config and prints only consensus public identity. It refuses an existing config.
Do not delete it to rerun preparation. A failed build needs its log examined;
never substitute an unverified executable.

```bash
(cd "/var/lib/tos-build/release-$TOS_COMMIT" && sha256sum --check --strict SHA256SUMS)
cat /etc/tos/BUILD-INFO /etc/tos/TOSCTL-BUILD-INFO
sudo -u tos tos-pq-consensus-key show /var/lib/tos/validator/keys/pq-consensus.seed
```

The node runs as `tos`, database/keys under `/var/lib/tos/validator` (0700),
seed owner-only (0600), logs `/var/log/tos/validator` (0750). No pool-owner key
or operator-wallet secret belongs there. Confirm seed identity without displaying
its contents. Arrange the human-only encrypted offline backup; see
[custody](../production/Production-Node.md#31-consensus-key). Never run a second
node from a backup while the first can still sign.

## 4. Staking account and public record

The validator is named by its **staking account**: a single-nominator pool whose
owner is an offline wallet the coordinator keeps and whose validator role is
your operator wallet on this host. Genesis records the pool's address as the
validator id, the node is bound to it, and it signs stake authorizations only
for it. The pool is derived from the two wallets, so the operator wallet is made
before genesis.

**Operator on host**, after `build-tosctl.sh`, with approval:

```bash
sudo /opt/tos-testnet/scripts/init-operator.sh --name <NODE_NAME> --wallet-only
```

Expected: the last line is `op-<NODE_NAME> <ADDRESS>`. It creates `tos-ctl`, its
vault and the masterchain operator wallet and needs no running node; the wallet
key stays in the host's vault. Send the address to the coordinator through an
authenticated channel.

**Coordinator** runs [step 2](CEREMONY.md#2-coordinator-staking-pools) for it and
returns the pool's validator id. Confirm out of band that the operator wallet it
names is yours.

**Operator on host**, using that validator id:

```bash
sudo -u tos python3 /opt/tos-testnet/scripts/testnet-operator.py record \
  --db /var/lib/tos/validator --seed /var/lib/tos/validator/keys/pq-consensus.seed \
  --validator-id <VALIDATOR_ID> --operator <OPERATOR_LABEL> \
  --address <PUBLIC_IPV4>:30001 --out /tmp/record.json
```

Expected: a public JSON record matching the prepared config's transport address
and consensus identity. Send only this file to the coordinator and verify receipt
out of band. A mismatch is a preparation/identity incident; never edit the record
by hand. The coordinator validates it in the manifest, which refuses a validator
id that is not a recorded pool.

## 5. Activate and verify custody and synchronization

**Prerequisites:** coordinator published complete ceremony artifacts, authenticated
global-config SHA-256 and epoch, and verified your record. With explicit approval:

```bash
sudo /opt/tos-testnet/scripts/install-node.sh activate --role validator \
  --global-config <GLOBAL_CONFIG_JSON> --sha256 <PUBLISHED_SHA256> \
  --genesis <PUBLISHED_GENESIS_DIRECTORY> --validator-id <VALIDATOR_ID>
systemctl is-active tos-testnet-validator
sudo journalctl -u tos-testnet-validator -n 100 --no-pager
sudo sh -c 'grep "post-quantum consensus custody" /var/log/tos/validator/node.log*'
```

Expected: active unit; the custody line names your pool's validator id and the
exact key id/window.
The installer binds the seed while stopped, configures the console (30002/tcp, closed by the host firewall), installs
and verifies the template, and starts the node. It refuses different installed
config content or a mismatched digest. Investigate rather than replace it silently.
Before the announced epoch, height zero can be expected; afterward ask the
coordinator to run [the two-node live check](CEREMONY.md#7-coordinator-the-chain-is-live).
An active unit alone does not prove sync or correct custody.

## 6. Onboard for elections

**Operator supplies:** label, host/approved SSH access, the operator wallet made
in §4, matching node/tosctl revision and a live synced console and RPC. Never
send the consensus seed or the vault key to the host/coordinator agent.

**Coordinator**, with human approval, follows [§8.1](CEREMONY.md#81-onboarding-a-genesis-validator-for-elections).
There is no `onboard --dry-run`. Review the two-validator `reconcile` report,
funding amounts/profile, identities and public artifacts before authorizing it.
It completes `tos-ctl` (console key, node), refuses an operator wallet other than
the one the pool was derived from, funds the operator wallet with fee money, funds
the offline owner, deploys the pool, configures pool and binding, sends the
principal from the owner, checks that the pool holds two stakes and that the node
reports custody for the pool, and enables elections. Keep the ceremony journal and secret
backups; do not restart onboarding with a different ceremony after a timeout.

**Operator verifies** the host task:

```bash
systemctl is-active tos-testnet-elections
sudo journalctl -u tos-testnet-elections -n 60 --no-pager
```

Expected: the task opens its wallet and pool and reports an election or no active
election. In an election it asks the node for a stake authorization for the pool,
refuses one signed for another account, and sends the pool the order with the
fees only (1.2 TOS); the pool forwards the stake. After the term it recovers the
stake to the pool. The task runs as `tos-ctl` and owns only `/var/lib/tos-ctl`.
Root reads `/etc/tos/tosctl.env` (0600) for it; never display that file. Every
manual host `tosctl` read uses the same identity and working directory, for
example:

```bash
sudo bash -c 'set -a; . /etc/tos/tosctl.env; set +a; cd /var/lib/tos-ctl; runuser -u tos-ctl -- tosctl wallet ls'
```

Expected: `op-<NODE_NAME>` with its balance. A successful stake submission still
needs Elector acceptance **and** the next Config34 activation, checked by the
coordinator.

## 7. Daily checks and fee top-ups

**Operator daily and after every restart/rotation:**

```bash
sudo python3 /opt/tos-testnet/scripts/check-host-disk.py --min-free-gib 15 --cpu-sample 3
systemctl is-active tos-testnet-validator tos-testnet-elections
sudo journalctl -u tos-testnet-elections --since '-1 hour' --no-pager
sudo journalctl -u tos-testnet-validator --since '-1 hour' --no-pager
df -h /var/lib/tos
```

Check head and head age, process memory/restarts, disk and growth, net failures,
peer/transport timeout logs, accepted stakes and the operator wallet balance from §6.
The disk checker prints JSON with null for unavailable observations and exits 1
below a floor. It is not a full peer-count or transaction audit. Persistent peer
timeouts need coordinator cross-node/UDP checks; this bundle has no dedicated
peer-health command. Coordinator watching/alerts: [testnet README](README.md#watching-the-network).

The operator wallet pays only fees: 1.2 TOS with every stake order and 0.2 TOS
with every recovery, plus its own gas. Ask the coordinator for a journaled
bootstrap [`fund` top-up](CEREMONY.md#topping-up-an-operator-wallet) well before
it runs low; the principal stays in the pool.

The gate explains only fully matched election-task pool messages from their
transaction BOCs. New-stake also requires a genesis-unchanged ConfigParam 15 on
both validators; recovery and maintenance have their own body/value limits. See
[election task history](CEREMONY.md#election-task-history). Other unexplained
transfers still require human reconciliation. Never automatically baseline or
assume every small transfer to the pool is the election task's.

## 8. Upgrade, rollback and key rotation

**Prerequisites:** owner-approved revision/window, healthy quorum, no pending
ambiguous transaction, current custody and backups, release notes reviewed.
Build new binaries before stopping anything. Upgrade one validator at a time:

```bash
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev <NEW_COMMIT> --role validator
sudo systemctl stop tos-testnet-elections tos-testnet-validator
sudo /opt/tos-testnet/scripts/install-node.sh binaries --role validator \
  --release /var/lib/tos-build/release-<NEW_COMMIT> --rev <NEW_COMMIT>
sudo /opt/tos-testnet/scripts/build-tosctl.sh --rev <NEW_COMMIT>
sudo systemctl start tos-testnet-validator
# Verify custody, sync and two-node identity before starting elections.
sudo systemctl start tos-testnet-elections
```

The binary installer refuses if **any** testnet node role on the host is active;
include co-hosted DHT/full-node maintenance in the approved plan. Do not proceed
to the next validator until the coordinator verifies convergence. Preserve build
receipts and the previous release. Stop on exit 2; do not delete a lock or edit
an installed unit to make it start. Template changes require a reviewed installer
rollout, not a hand-edited `ExecStart`.

**Rollback:** no automatic safe downgrade/DB rollback is supplied. Ask the
coordinator to verify protocol and database compatibility before reinstalling a
previous verified release. Never restore an older DB or truncate it under the
same signing identity as a routine rollback; retain forensic evidence first.

**Rotation:** the pinned node supports multiple consensus keys, but this bundle
has no journaled rotation command. A human coordinates the key schedule, the
retained current/previous/next signing duties and the election proof; the staking
account does not change. Use the exact tos checkout's
`doc/validator-operator-guide.md` ("Rotate the consensus key") and
`tos-pq-consensus-key` usage, with an independently reviewed command plan; never
rerun `activate` over a multi-key node.

### External-message pool option migration

Builds containing the external-admission release port remove `-m` and
`--mempool-num`. The supplied local and testnet unit templates do not pass
these options. Before activating such a build, check site-specific service
overrides and launch wrappers privately and remove either spelling from
validator-engine arguments if present.
Keep historical build receipts and approved bundles unchanged.

Pool limits now use the persisted `extraconfig.ext_message_pool_config` settings
or the native console command `set-ext-message-pool-options-json <filename>`.
The console command validates and persists the supplied configuration; use the
reviewed operator access and change procedure. Do not replace the retired flag
with a silently ignored argument.

The release defaults remain 24 regular checkers, zero reserved priority checkers
and local submission priority zero. This migration does not reserve a priority
checker or change the deployed admission settings; those require a separate
configuration decision. It also leaves HTTP and liteserver ingress limits in
place.

## 9. Incidents, leaving and retirement

| Symptom | Verify / response |
| --- | --- |
| Node down | Inspect `systemctl status` and journal; exit 2 is a refusal, not a retry instruction. Check clock, disk, config identity and custody. Ask before a restart. |
| Head stuck / peers timing out | Compare fresh full block IDs on two validators; check UDP mesh, head versus shard-client lag and memory. Keep logs. Do not reset to cure lag. |
| Disk filling | Inspect GC progress, key-block/election progress, consensus deletion logs and growth. Escalate before exhaustion; never delete live DB/consensus directories. |
| Wrong network / zero state | Stop and ask; preserve DB/config. Never overwrite config and reuse keys as a shortcut to another genesis. |
| Stake refused or not confirmed | Retain the query/transaction evidence; inspect the Elector result, the pool balance, the operator wallet's fee balance and the node's custody line (validator id = the pool). Do not resend or clear journals to force acceptance. |
| Open operation | Coordinator runs read-only `reconcile`; human chooses verified `record`, original-message `resubmit`, or terminal-failure `retry`. See [recovery](CEREMONY.md#81-onboarding-a-genesis-validator-for-elections). |

**Leaving:** coordinate disabling new stakes, keep the node signing through all
current and pending duties, wait for held funds to unfreeze and be recovered,
then have the offline owner withdraw in a quiet window. Removing a host while
its key remains in a set can halt the network. Permanent departure is not itself
permission to run the ended-epoch reset script.

**Ended-epoch retirement/reset**, only on explicit approval: follow
[CEREMONY §9](CEREMONY.md#9-resetting-the-testnet). The coordinator confirms the
installed old zero-state root, arranges evidence archive collection and fresh
identities for the next epoch. `retire-host.sh` has no dry run: it archives first,
stops/deletes node and operator state, and retains the cross-epoch alert peer.
A nonzero exit means stop and investigate; never remove data by hand.

Report sanitized UTC times, revision, public identity, service state, operation
IDs/transaction hashes, checks and refusals to the coordinator. No seed, token,
wallet secret or environment dump belongs in an incident report.
