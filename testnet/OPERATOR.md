# Testnet validator operator guide

[2026-12-05 public testnet genesis and validator invitation](ANNOUNCEMENT-20261205.md)

Use this guide to run your own validator in a coordinated public testnet
ceremony. You need a dedicated host you administer, running Ubuntu 24.04 LTS (recommended) or a later LTS release such as 26.04 after confirming it with the coordinator, and a registered
seat: on December 5, 2026 the genesis validator set is the team's two
validators, and an external validator registers its public record and pool
before genesis (registration closes on November 30), is written to the
ceremony's `genesis-records.json` but not to the zero state, and stands from the
first election (open from T + 12 h to T + 22 h; the elected set takes office at
T + 24 h). Each elected set then serves 24 h, and each election is open for 10 h
ending 2 h before its term (all times UTC). Your
pool stakes one unit (`elections.stake_tos`, 10,002 TOS), funded by the
coordinator. The two team pools stake (E+1)/2 units each for E external
validators, so the team holds a little over half of the weight and the external
validators together never two thirds. A block is final with at least two thirds
of the weight, so with both team validators up the chain needs about a third of
the external validators online (7 of 19 at E = 19), and with one team validator
down most of them (16 of 19); see [Liveness](CEREMONY.md#liveness-what-keeps-blocks-final). The coordinator handles genesis, staking
funds and its side of election onboarding. You administer the host alone, run
every step on it yourself, and hold its consensus key and operator wallet. The
coordinator never logs in to your host.

## Start here

1. **Ask for the onboarding packet.** Get the epoch and launch time in UTC,
   the full `tos` and `tos-ops` commits, the approved hardware and build path,
   your node name and operator label, the staking and fee funding arrangement,
   and a coordinator contact. Before activation, get the public genesis files
   and global config, its SHA-256 over a separate authenticated channel, and
   the expected zero-state root and file hashes.
2. **Confirm your route.** For a new genesis, reserve a seat with the
   coordinator and follow sections 1–7 in order. For an epoch already running,
   ask whether your pool is in its genesis records (`genesis-records.json`; an
   external validator is there but not in `genesis-set.json`). The supplied
   `testnet-elections.py onboard` requires that entry. If you are a new
   participant in a running epoch, you can [run an observer](#a-new-full-node-from-a-published-snapshot)
   with the coordinator's full-node instructions while waiting for a genesis
   seat or a reviewed procedure for live admission.
3. **Check each milestone.** A prepared node has a public identity. An
   activated node runs and synchronizes. An accepted stake is recorded by the
   Elector. A validator has duties once its pool appears in the active set
   during that set's term. Use the checks below to tell which step you reached.

Run commands on your validator host unless the guide assigns them to the
coordinator. Replace angle-bracket placeholders with values from your packet.
Commands give a masterchain address as `--option=-1:<hex>`, with the `=`: a
value starting with `-` is otherwise read as another option. The scripts also
accept `--option -1:<hex>`, but tools outside them may not.
Keep inventories, keys and generated records outside the source checkout.
If a command refuses or a transaction times out, retain the error and
coordinate read-only diagnosis before retrying. See [custody and operation
rules](../AGENTS.md#hard-safety-rules).

## 1. Agree the network and responsibilities

**Prerequisites:** the coordinator supplies the full 40-character tos commit,
approved profile, epoch/zero-state identity, operator label, authenticated public
artifacts and contact/alert channel. Record these outside the repository.
Use the revisions from the packet on every host.

- **Operator:** administers the host alone. You build and configure the node
  yourself, by hand or with the tos-ops scripts in this guide: preflight (§2),
  build and prepare (§3), the operator wallet and public record (§4),
  activation (§5) and the host-side onboarding steps (§6). You retain the
  consensus seed and the operator wallet's vault, supply the authenticated
  public records, and keep the node live.
- **Coordinator / authorized offline signer:** derives each validator's staking
  pool, generates/publishes genesis, retains the bootstrap and offline pool-owner
  wallets, and sends and journals every onboarding payment (fee money for your
  operator wallet, the pool deployment, the stake principal). The coordinator
  checks your host-side results only from chain state read through its own
  nodes. The pool owner keys stay in the coordinator's signing domain, never on
  the validator host.
- **The coordinator never touches your machine.** No SSH access, no remote
  commands, no SSH tunnel to it, no account on it. Do not create one for the
  coordinator, and treat any request for one as outside this procedure. Hosts the
  team itself operates (for example the DHT hosts) are the only ones the
  coordinator logs in to.
- Only public records cross to the coordinator: the preflight report, the
  operator wallet address, the genesis record and the onboarding summary. A
  request for a seed, vault key or mnemonic is not part of onboarding.

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
MemTotal, 160 GiB free** on Ubuntu 24.04 LTS or a later LTS release, on a recommended **250 GB SSD or
NVMe** (200 GB at least): a full 21-validator set is estimated to hold up to
about 128 GB on disk at once, about 116 GB of it consensus, state and archive data (consensus and states
about 30 h, the archive about 54 h; CEREMONY.md section 8 has the
arithmetic), and the load guard and the stall rules stop at 20 GiB free. Free
space is checked before you build: remove the build tree under
`/var/lib/tos-build` once the coordinator has compared your checksums. These are installation floors, not a
production capacity guarantee. See [profile](network/profile.json) and
[hardware proposal](../production/Hardware-and-Hosting.md).

1. On a fresh host, install the pinned operations bundle. Ask the coordinator
   to review any existing installation before replacing it.

   ```bash
   sudo apt-get update
   sudo apt-get install -y git ca-certificates
   git clone https://github.com/tosnetwork/tos-ops.git "$HOME/tos-ops"
   OPS_COMMIT='<APPROVED_TOS_OPS_COMMIT>'
   git -C "$HOME/tos-ops" checkout --detach "$OPS_COMMIT"
   git -C "$HOME/tos-ops" rev-parse HEAD
   sudo install -d -m 0755 /opt/tos-testnet
   sudo cp -a "$HOME/tos-ops/testnet/." /opt/tos-testnet/
   sudo chown -R root:root /opt/tos-testnet
   ```

   Compare the printed commit with your packet before using the bundle. Run the commands in order and stop on any error.
2. With approval, set time on the host:

   ```bash
   sudo /opt/tos-testnet/scripts/setup-time.sh
   ntpq -pn
   ```

   Expected: ntpsec follows a selected reachable server (`*` in `ntpq`), using
   IPv4. `NTPSynchronized=yes` alone is insufficient. On failure fix clock/network
   reachability; do not prepare a node with an unproven clock. `setup-time.sh`
   adds `ntp.nict.jp` beside the Ubuntu pool; on another continent pass a
   nearby server instead, for example `setup-time.sh time.cloudflare.com`.

   **Keep the clock disciplined by NTP at all times, not only now.** Consensus
   reads the local clock: a validator validates a candidate no earlier than 300 ms after its
   parent's generation time by its own clock, so a clock behind NTP delays its
   votes by the offset; as leader, a clock ahead of NTP gives its candidates
   future timestamps that the other validators hold until their own clocks
   reach them, slowing the chain (beyond 30 s they refuse them). Keep ntpsec, which
   `setup-time.sh` installs and configures (`install-node.sh prepare` runs it),
   running with a selected source, within **100 ms** of NTP time. ntpsec is the
   supported path: `setup-time.sh` disables chrony and systemd-timesyncd, and
   the checks accept only ntpd. The first `install-node.sh activate --role
   validator` and every `enable-elections.sh` refuse to start on a clock that
   fails this check; a service restart or a reboot is deliberately not gated (it
   must not wait on NTP), so the daily check and the alarm below cover the
   clock from then on.

   **All testnet times are UTC**, whatever your local time zone: launch,
   election windows, handovers and the times in your reports. Your host may keep
   any time zone setting; the kernel clock and NTP are UTC either way. Convert
   published times yourself (`date -u` prints UTC now).

   **Daily check**, and after every reboot:

   ```bash
   python3 /opt/tos-testnet/scripts/check-clock.py
   ```

   Expected, exit status 0:

   ```text
   clock ok: ntpd with 1 selected source, offset -0.412 ms (local minus NTP, limit 100 ms), NTPSynchronized=yes
   ```

   The offset is ntpd's system offset (`ntpq -c "rv 0 offset"`, not one
   peer's last sample), written as local clock minus NTP time: positive means
   your clock is ahead. Any `clock NOT OK: ...` line (exit status 1) names what
   is wrong: no `NTPSynchronized=yes`, ntpd not answering, no selected source,
   or an offset beyond 100 ms. Rerun `setup-time.sh` (with a nearby server), check
   outbound UDP 123, and tell the coordinator if it does not recover.

   **Alarm.** Run the same check every 10 minutes from cron so a lapse reaches
   you, not only the daily look; for example `/etc/cron.d/tos-clock`, with a
   15-minute grace after a boot while ntpd selects a source:

   ```text
   */10 * * * * root python3 /opt/tos-testnet/scripts/check-clock.py --quiet --boot-grace 900 || logger -p user.err -t tos-clock "clock not NTP-disciplined"
   ```

   and watch for `tos-clock` in `journalctl -p err`, or forward it to your own
   alerting. The coordinator's monitor raises the same condition for the team's
   hosts.
3. **Run the preflight on this host yourself.** It reads the same facts and
   applies the same floors as the coordinator's preflight of team hosts
   ([§0.5](CEREMONY.md#05-preflight-every-host)), locally, and changes nothing:

   ```bash
   sudo python3 /opt/tos-testnet/scripts/preflight.py --local --name <NODE_NAME> \
     --role validator --public-ip <PUBLIC_IPV4> --out /tmp/preflight-<NODE_NAME>.json
   ```

   It checks for Ubuntu 24.04 LTS or a later LTS release, the architecture and x86-64-v2 instructions, CPUs,
   memory and free disk against the validator floors, whether the public address
   is on an interface (a WARN behind NAT), NTP (ntpsec's ntpd with a selected
   server, within 100 ms of NTP time; this check cannot be waived), ufw rules
   for UDP 30001/31001 with console 30002 closed, and whether another program
   holds those ports. Expected: no FAIL. Fix every FAIL and rerun with a new
   `--out` file. Send the JSON report to the coordinator. If the coordinator
   recorded a floor waiver for this host, pass it exactly as given:
   `--waive memory="<REASON>"`. A waiver in your report is only your claim: the
   coordinator compares the report's `waive` entries with its own recorded
   decision and rejects a report with any other. `passed` in the report means
   no FAIL among the checks that were not waived.

   The `udp` line is a WARN until provider ingress is proven, because a host
   cannot prove it from the inside. Prove it before activation if you can:
   install tcpdump (`sudo apt-get install -y tcpdump`), start a listener here,
   and send probes **from a different machine**: one you control, or the
   coordinator's own machine (it needs only your public address, never
   access). Probes sent from this host itself never count: the listener
   captures on the default-route interface and ignores loopback and this
   host's own addresses. Name the sender's public address with
   `--expect-from <SENDER_NAME>@<SENDER_IPV4>` to count only its probes:

   ```bash
   # On this host (captures for 120 s):
   sudo python3 /opt/tos-testnet/scripts/preflight.py --local --name <NODE_NAME> \
     --role validator --public-ip <PUBLIC_IPV4> --listen-seconds 120 \
     --expect-from <SENDER_NAME>@<SENDER_IPV4> --out /tmp/preflight-udp-<NODE_NAME>.json
   # On the different machine, from a tos-ops checkout at the same commit, within those 120 s:
   python3 testnet/scripts/preflight.py --send-probes --name <SENDER_NAME> \
     --to <PUBLIC_IPV4> --role validator
   ```

   Expected: `udp:30001` and `udp:31001` PASS. A FAIL means the probes were
   dropped before the host: open the provider security group or ACL, not the
   console or RPC ports. Do this test: without it, ingress stays unproven until
   the node validates. Sync after activation (§5) shows that your node reaches
   the network, not that the network reaches it; a provider group that admits
   only replies lets a node sync and still miss its validator duties.
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
host. Use this recipe on the documented x86_64 build path. For arm64, get the
approved revision and hardware-SHA-capable artifact instructions from the
coordinator before preparing the host. See [CPU requirements](https://github.com/tosnetwork/tos/blob/main/doc/Validator.md#cpu-instruction-set).

```bash
TOS_COMMIT='<FULL_40_CHARACTER_COMMIT>'
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev "$TOS_COMMIT" --role validator
sudo /opt/tos-testnet/scripts/build-tosctl.sh --rev "$TOS_COMMIT"
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role validator \
  --public-ip <PUBLIC_IPV4> --release "/var/lib/tos-build/release-$TOS_COMMIT" --rev "$TOS_COMMIT"
```

`--rev` is refused unless the release's `BUILD-INFO` names that commit. The
build is reproducible for one commit, toolchain and Ubuntu release: compare
the release's `SHA256SUMS` with another host's built from the same commit on
the same Ubuntu release (the `build_os` line of `BUILD-INFO`). Hosts on
different Ubuntu releases build different bytes; that is expected, not a fault.

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
your operator wallet on this host. The genesis records (`genesis-records.json`)
name the pool's address as the validator id, the node is bound to it, and it signs stake authorizations only
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
  --validator-id=<VALIDATOR_ID> --operator <OPERATOR_LABEL> \
  --address <PUBLIC_IPV4>:30001 --out /tmp/record.json
```

Expected: a public JSON record matching the prepared config's transport address
and consensus identity. Send only this file to the coordinator and verify receipt
out of band. A mismatch is a preparation/identity incident; never edit the record
by hand. The coordinator validates it in the manifest, which refuses a validator
id that is not a recorded pool.

## 5. Activate and verify custody and synchronization

**Prerequisites:** coordinator published complete ceremony artifacts, authenticated
global-config SHA-256 and epoch, and verified your record. Use the directory
containing `genesis.json`, `zerostate.boc`, `basestate0.boc` and their published
file hashes. For a fresh genesis identity whose key has never signed, verify
the config digest and activate with explicit approval:

```bash
GLOBAL_CONFIG='<GLOBAL_CONFIG_JSON>'
CONFIG_SHA256='<PUBLISHED_SHA256>'
GENESIS_DIR='<PUBLISHED_GENESIS_DIRECTORY>'
VALIDATOR_ID='<VALIDATOR_ID>'
printf '%s  %s\n' "$CONFIG_SHA256" "$GLOBAL_CONFIG" | sha256sum --check
sudo /opt/tos-testnet/scripts/install-node.sh activate --role validator \
  --global-config "$GLOBAL_CONFIG" --sha256 "$CONFIG_SHA256" \
  --genesis "$GENESIS_DIR" --genesis-ceremony --validator-id "$VALIDATOR_ID"
systemctl is-active tos-testnet-validator
sudo journalctl -u tos-testnet-validator -n 100 --no-pager
sudo sh -c 'grep "post-quantum consensus custody" /var/log/tos/validator/node.log*'
```

Expected: active unit; the custody line names your pool's validator id and the
exact key id/window.
The installer binds the seed while stopped, configures the console (30002/tcp, closed by the host firewall), installs
and verifies the template, and starts the node. It refuses different installed
config content or a mismatched digest. Investigate rather than replace it silently.
Before the announced epoch, height zero can be expected. Follow the local
head check in section 7 and compare your node's zero state and a recent block
ID with the ones the coordinator's [two-node live
check](CEREMONY.md#7-coordinator-the-chain-is-live) of its own nodes publishes;
the coordinator does not connect to your node to do it. Require agreement on
zero state, a common recent block ID and AUTH policy before elections. Use `--genesis-ceremony` only when the
coordinator's instructions call for initializing a fresh genesis signing
ledger.

### A new full node from a published snapshot

A new full node can start from a signed snapshot generation instead of syncing
from genesis. Activate it with `--no-start`, then install the generation with
`tosctl node sync bootstrap` (tos repository, `doc/node-data-sync.md`, section
"Bootstrap a new node"):

```bash
sudo /opt/tos-testnet/scripts/install-node.sh activate --role fullnode \
  --global-config <GLOBAL_CONFIG_JSON> --sha256 <PUBLISHED_SHA256> \
  --genesis <PUBLISHED_GENESIS_DIRECTORY> --no-start
systemctl is-active tos-testnet-fullnode   # inactive: the database has never run
```

`--no-start` does everything `activate` does and enables the unit, but does not
start it. Bootstrap refuses a database that has ever run, so do not start the
unit before bootstrap; bootstrap starts it once the verified data is installed.
If the node starts first, it syncs from genesis as usual. `--no-start` is
refused for every other role: a validator never joins from a snapshot.

## 6. Onboard for elections

**Prerequisites:** the node is activated and synchronized (§5), its custody line
names your pool, and the operator wallet from §4 is unchanged. Nobody but you
logs in to the host, and nothing secret leaves it.

Onboarding is one hand-off in each direction. Every payment is sent and
journaled by the coordinator; your operator wallet sends nothing but its own
deployment.

| # | Who | Runs | Waits for | The other side checks |
|---|-----|------|-----------|-----------------------|
| 1 | Coordinator | `testnet-elections.py onboard --no-host` ([§8.1](CEREMONY.md#81-onboarding-a-genesis-validator-for-elections)): fee money to your operator wallet, the pool owner's funding and activation, the pool's deployment from the owner, the stake principal | each step's prerequisite on chain on two of its own nodes | — |
| 2 | Coordinator | stops with exit status 3 and sends you your exact command, pool and owner | the pool deployed with two stakes | you check the pool on your own node (step 3) |
| 3 | Operator | `testnet-operator.py onboard` on your host (below) | the pool active with the pinned code, its owner and validator roles as given, two stakes in it, fee money in your wallet | — |
| 4 | Operator | sends the printed JSON summary | — | the coordinator reads the chain, not the summary |
| 5 | Coordinator | the same `onboard --no-host` again | your operator wallet active with fee money, the pool unchanged | its own steps are done; your node's binding and election task stay **unverified** until the pool's stake appears in the Elector at the next election |

**Operator, on your host**, after the coordinator's hand-off (step 3):

```bash
sudo python3 /opt/tos-testnet/scripts/testnet-operator.py onboard --name <NODE_NAME> \
  --pool=<POOL_ADDRESS> --owner=<POOL_OWNER_ADDRESS> --out /tmp/onboard-<NODE_NAME>.json
```

`<POOL_ADDRESS>` is `-1:<VALIDATOR_ID>`. In order, each step skipped when its
result is already there, so a rerun changes nothing:

1. `init-operator.sh --name <NODE_NAME>` completes `tos-ctl` (console key, node
   registration, tosctl's master wallet) and prints the operator wallet;
2. it reads the pool from your own node and refuses unless it is active, runs
   the pinned single-nominator code (the hash of
   `crypto/smartcont/single-nominator-pool/single-nominator-code.hex` in the
   tos checkout `build-tosctl.sh` used, `/var/lib/tos-build/tos`, or
   `--tos-root`; the same file the coordinator pins), its validator role is
   your operator wallet, its owner is `--owner` (required), and it holds two
   stakes above its reserve. Before the coordinator's step 2 this refuses with
   "has not deployed it yet" or "has not sent the principal yet"; past step 1
   nothing is changed, rerun it later;
3. it activates the operator wallet (`tosctl wallet activate`: the wallet
   deploys itself from the fee money; nothing else is sent), refusing while the
   wallet holds no fee money;
4. `tosctl config pool add` and `config bind add` for `pool-<NODE_NAME>`;
5. the node's latest `post-quantum consensus custody` line must name the pool;
6. `enable-elections.sh --name <NODE_NAME>` installs and starts the election
   task with a fixed stake of `elections.stake_tos` and tosctl's default max factor
   (`elections.external_max_factor`, 3.0), unless it is already running (a rerun never restarts it); it refuses
   unless `tos-testnet-elections` is active at the end.

A refusal names what is missing. A pool whose validator role is not your wallet
means the pool was derived from another wallet: tell the coordinator; do not
create another wallet. Send `/tmp/onboard-<NODE_NAME>.json` (public facts only)
to the coordinator. You may do the same steps by hand instead, in the same order
and with the same checks (`testnet-operator.py --help` lists them); the
coordinator's check in step 5 is the same either way.

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

Read your local chain head twice, several seconds apart:

```bash
curl -fsS --max-time 5 http://127.0.0.1:8081/ \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getMasterchainInfo","params":{}}' \
  | python3 -m json.tool
systemctl show tos-testnet-validator -p NRestarts -p MemoryCurrent
```

Look for `result.last.seqno` advancing and `result.init` matching the packet's
zero state. A JSON-RPC `error`, missing result, or a head that stays behind the
coordinator's reference calls for investigation. For an actively advancing
but delayed node, ask the coordinator for the head age from the cross-node
check. Keep RPC on loopback. Use this table at each election and handover:

| Step | Evidence to check |
| --- | --- |
| Election task healthy | The service is active and its journal has recent activity. Investigate repeated errors or low wallet balance before the next window. |
| Stake accepted | The coordinator confirms your pool and stake in the Elector for the intended election ID. |
| Duty started | The coordinator confirms your pool in current ConfigParam 34 with the expected term and an expiry in the future. ConfigParam 36 describes the next set when published. |
| Duty ended or renewed | Confirm the new term and the old stake's recovery when due. Report a stale term even if blocks keep advancing. |

Agree with the coordinator who watches head freshness, set expiry, missed
stakes, balance, disk and service failures between your manual checks.
Confirm the alert channel reaches a person. To follow both services while
diagnosing a problem, run the command below and press Ctrl+C to exit the log
viewer.

```bash
sudo journalctl -f -u tos-testnet-validator -u tos-testnet-elections
```
When reporting a fault, provide
UTC time, epoch, host label, public pool ID, last head, service status and
relevant sanitized log lines.

Check head and head age, process memory/restarts, disk and growth, net failures,
peer/transport timeout logs, accepted stakes and the operator wallet balance from §6.
The disk checker prints JSON with null for unavailable observations and exits 1
below a floor. It is not a full peer-count or transaction audit. Persistent peer
timeouts need coordinator cross-node/UDP checks; this bundle has no dedicated
peer-health command. Coordinator watching/alerts: [testnet README](README.md#watching-the-network).

The operator wallet pays only fees: 1.2 TOS with every stake order and 0.2 TOS
with every recovery, plus its own gas. Onboarding gives it 10 TOS, about two
elections past the first returned stake, and staking rewards never reach it (they
go to the pool and its owner). Ask the coordinator for a journaled
[top-up](CEREMONY.md#topping-up-an-operator-wallet) well before it runs low: from
your pool's owner (`top-up`, after the owner withdrew rewards), or before the
bootstrap wallet is swept a `fund` out of its margin. The principal stays in the
pool.

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

`binaries` and `prepare` refuse, before they write anything, if **any** node or
rpc service on the host is active (validator, full node, DHT, wallet index, public RPC);
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

### Submission priority on full nodes (owner decision, 2026-11-09)

A full node that serves clients sets local submission priority **1**; validators keep **0**.
A full node checks the externals its own lite server receives and every external the network
relays to it with the same checkers. At priority 0 the relayed re-checks fill the admission
queue under load, and the node refuses its own clients' new messages with
`too many pending external message checks`. At priority 1 its clients' messages take a checker
slot ahead of relayed ones. Relayed externals are still checked; they only wait behind the
node's own clients.

Evidence (local bench, 4 validators and 4 ingress full nodes on one host, 600/s for 180 s,
builds with the overlay and liteserver admission alignment): at priority 0, 59,448 of 108,000
transfers settled, with 18,635 backpressure refusals at the ingress nodes. At priority 1,
84,017 settled, with no backpressure refusals. The remaining loss there is client timeouts and
the nonce gaps they leave. A shared host cannot tell whether that loss is the chain or the host;
the bench result is not a capacity claim.

`install-node.sh activate --role fullnode` applies it after starting the node. After
`--no-start` and `tosctl node sync bootstrap`, and on a full node already running, apply it as
`tos` once the node is up:

```sh
runuser -u tos -- python3 /opt/tos-testnet/scripts/testnet-operator.py submission-priority \
  --db /var/lib/tos/fullnode
```

It changes only `local_ls_message_priority` through the node's console, which persists it in
`config.json`. It is not a consensus setting, and the node keeps running.

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

## 10. Run the public RPC role

The `rpc` role serves the public wallet JSON-RPC from the standalone services
`tos-wallet-index` and `tos-rpc`, outside every validator process. It is a
**full node host**: the index reads the full node's database on the same host
and `tos-rpc` reaches the index only over loopback, so all three processes run
there. See the pinned tos checkout's `doc/standalone-wallet-services.md` and
`doc/FullNode.md` for what the services do.

| Unit | Account | Listens | Reads | Writes |
| --- | --- | --- | --- | --- |
| `tos-testnet-fullnode` | `tos` | ADNL/QUIC, lite server 30003/tcp, operator JSON-RPC `127.0.0.1:8081` | | `/var/lib/tos/fullnode` |
| `tos-testnet-wallet-index` | `tos` | `127.0.0.1:8083` (tos-rpc only) | `/var/lib/tos/fullnode`, read-only in its mount namespace | `/var/lib/tos-wallet-index` only |
| `tos-testnet-rpc` | `tos-rpc` | `127.0.0.1:8080` (the operator's TLS proxy only) | `/etc/tos/rpc-liteservers.json` | nothing |

The index runs as `tos` because the node database is owner-only; its unit
mounts that database read-only (`ReadOnlyPaths=`) and gives it a separate
`StateDirectory=` that does not overlap it, as the tos document requires. It
listens on 8083, not its default 8081, which the full node's operator JSON-RPC
holds. `tos-rpc` runs as its own non-login account, cannot see
`/var/lib/tos` or the index data, and trusts one liteserver: the full node's own
lite server on `127.0.0.1:30003` (`rpc-liteservers.json` is the published global
config with that entry, written by `install-node.sh activate --role rpc`).
The services follow explicit maintenance stop/start/restart of the full node
(and `tos-rpc` of the index): `PartOf=` carries a stop or restart of the node to
the index and of the index to `tos-rpc`, and `activate --role rpc` enables the
index as wanted by the node and `tos-rpc` as wanted by the index, so starting the
node starts the index and then `tos-rpc` (`After=` orders them). These
directives do not propagate a crash, and `After=` does not require a backend to
have started successfully: after a node crash the index pauses at its cursor and
`tos-rpc` reports backend errors per request. A start of the index while the
node is not active, or of `tos-rpc` while the index is not active, is skipped
(`ExecCondition=`): the unit stays inactive, not failed, and is not retried;
nothing in these units starts a node stopped for maintenance. The lifecycle was
checked with a real systemd 249 user manager
([check-rpc-units-lifecycle.sh](tests/check-rpc-units-lifecycle.sh));
**outstanding:** repeat that check on a systemd 255 / Ubuntu 24.04 host before
rollout.

**Prerequisites:** a tos commit that has the `services/` targets (`tos-rpc` and
`tos-wallet-index`); full-node preflight floors plus the index's memory and disk
(it holds its own RocksDB index; monitor resident memory, cursor lag and disk).
The index replays from masterchain block 1, so the full node must hold the
complete block archive from block 1: activate it with `--genesis` before or at
the epoch start. The supplied full-node template keeps the archive for 30 days
(`--archive-ttl 2592000`, as upstream mytonctrl's liteserver mode): an index started, or rebuilt, after the oldest blocks
were pruned pauses at its cursor and never catches up. Start the index while the
whole archive is still on the host; a longer retention is a reviewed template
change, not a host edit.

With approval, on the rpc host, in this order. Both preparations come before
the full node's activation: `prepare` (like `binaries`) refuses while the full
node, or any other node or rpc service on the host, is active. Both activations
come after them, the full node's first.

<!-- testnet/tests/test_rpc_role.py runs this block's install-node.sh lines, in
     this order, on a fake host; keep them runnable. -->
```bash
TOS_COMMIT='<FULL_40_CHARACTER_COMMIT>'
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev "$TOS_COMMIT" --role rpc
REL=/var/lib/tos-build/release-$TOS_COMMIT
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role fullnode \
  --public-ip <PUBLIC_IPV4> --release "$REL" --rev "$TOS_COMMIT"
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role rpc
sudo /opt/tos-testnet/scripts/install-node.sh activate --role fullnode \
  --global-config <GLOBAL_CONFIG_JSON> --sha256 <PUBLISHED_SHA256> --genesis <PUBLISHED_GENESIS_DIRECTORY>
sudo /opt/tos-testnet/scripts/install-node.sh activate --role rpc \
  --global-config <GLOBAL_CONFIG_JSON> --sha256 <PUBLISHED_SHA256>
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8083/readyz   # 200 once replay caught up
```

To add the rpc role to a full node that already runs, build `--role rpc` at the
node's commit, `systemctl stop tos-testnet-fullnode`, run
`prepare --role rpc --release "$REL" --rev "$TOS_COMMIT"`,
`systemctl start tos-testnet-fullnode`, then `activate --role rpc` as above.

An rpc release carries the full node's binaries and both services from one
build, so the index always runs the source node's version. `prepare` and
`binaries --role rpc` refuse a release that lacks either service, and
`activate --role rpc` refuses unless both services and the full node's binaries
are installed, the full node runs on the same global config and the tos-rpc
account exists. Production takes the same set from the tos GitHub release with
`fetch-release.py --role rpc`; that requires the release to include
`tos-rpc-linux-<arch>` and `tos-wallet-index-linux-<arch>` in its node build
artifact and build record.

**Exposure.** Only `tos-rpc` is published, through the operator's TLS reverse
proxy on this host, which forwards to `127.0.0.1:8080` and replaces any
client-supplied identity headers. The host firewall opens the proxy's port and
nothing for 8080, 8081 or 8083 (see the rpc block in
[tos-testnet.nft](firewall/tos-testnet.nft)). The index endpoint and the full
node's operator RPC are never proxy routes. For per-client attribution behind
the proxy, set in the root-owned `/etc/tos/tos-rpc.env`:

```
TOS_RPC_OPTIONS=--trust-proxy-headers --trusted-proxy 127.0.0.1
```

**Read-only by default.** The unit passes `--readonly` unless
`/etc/tos/tos-rpc.env` sets `TOS_RPC_MODE` explicitly. Submissions go to the
full node's operator RPC and require it to run with
`--json-rpc-trust-proxy-headers`, which the supplied full-node template does not
set: enabling writes needs that reviewed template change first, then
`TOS_RPC_MODE=--submission-address 127.0.0.1:8081` and a restart of
`tos-testnet-rpc`. `tos-rpc` refuses (exit 2) a write mode without a loopback
submission backend; do not work around it.

**Upgrade** with the [maintenance procedure](#8-upgrade-rollback-and-key-rotation):
build `--role rpc`, `systemctl stop tos-testnet-fullnode` (which stops the index
and `tos-rpc` with it; check all three are inactive, since `binaries` refuses
while any runs), install with `binaries --role rpc`, then
`systemctl start tos-testnet-fullnode`, which starts the index and `tos-rpc`
after it. **Rebuild the index** only with the index stopped
(`systemctl stop tos-testnet-wallet-index` stops `tos-rpc` too): move
`/var/lib/tos-wallet-index` aside (keep it until the new index is ready), start
the index (it starts `tos-rpc`) and wait for `/readyz`. Never delete or overwrite the node database
for an index problem. `retire-host.sh` stops both services and deletes the
index data and `rpc-liteservers.json` with the retired epoch.
