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
- **Coordinator / authorized offline signer:** generates/publishes genesis,
  retains bootstrap and offline pool-owner wallets, obtains root signatures,
  journals payments, onboards and renews. The controller root seed stays in the
  approved offline/coordinator signing domain, never on the validator host.
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
human approval after read-only checks; `fund`, `refund` and `withdraw` support
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
4. Open provider **and host** ingress UDP 30001/31001 for a validator. Keep console
   30002, RPC 8081 and exporter 9100 on loopback. DHT uses 30300/udp; lite 30003/tcp
   belongs to a separate full node, not this validator. Verify the actual bindings:

   ```bash
   sudo ss -lntup
   ```

   A missing UDP mesh probe is a firewall/routing issue, not permission to open
   console/RPC publicly. See [activation networking](CEREMONY.md#6-everyone-activate-before-the-epoch).

## 3. Build the pinned binaries and prepare

**Operator, after approval:** set the full ceremony commit, then build on this
host; no binaries copied from a different CPU:

```bash
TOS_COMMIT=<FULL_40_CHARACTER_COMMIT>
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev "$TOS_COMMIT" --role validator
sudo /opt/tos-testnet/scripts/build-tosctl.sh --rev "$TOS_COMMIT"
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role validator \
  --public-ip <PUBLIC_IPV4> --release "/var/lib/tos-build/release-$TOS_COMMIT"
```

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
seed owner-only (0600), logs `/var/log/tos/validator` (0750). No root seed or
operator-wallet secret belongs there. Confirm seed identity without displaying
its contents. Arrange the human-only encrypted offline backup; see
[custody](../production/Production-Node.md#31-consensus-key). Never run a second
node from a backup while the first can still sign.

## 4. Offline controller root and public record

**Human offline signer:** use the separately built `tos-pq-key` from the same tos
source (`crypto/pq/tools`, not linked into the node). Generate `ROOTSEED` under
umask 077 in a private offline directory, encrypt its backup using the approved
backup procedure, and verify recovery offline. The repository supplies no backup
encryption tool. Agents must not read/copy plaintext or log the signing session.
Only the public key and controller artifacts are shared. On the offline build
machine, the separate tool is built without installing anything on a validator:

```bash
cmake -S "$TOS_ROOT/crypto/pq/tools" -B <OFFLINE_BUILD_DIRECTORY>
cmake --build <OFFLINE_BUILD_DIRECTORY> --target tos-pq-key
```

Use that build's `tos-pq-key` for ceremony step 2. The human chooses encryption
and backup verification; no agent-visible plaintext command is needed.

[Step 2](CEREMONY.md#2-operator-controller-id-offline-root-key) gives key generation
and the controller derivation command. Confirm the controller's code hash and
consensus key id in `controller.json`; send that public file through an
authenticated channel. Retain it for later deployment/renewal.

**Operator on host**, using that controller id:

```bash
sudo -u tos python3 /opt/tos-testnet/scripts/testnet-operator.py record \
  --db /var/lib/tos/validator --seed /var/lib/tos/validator/keys/pq-consensus.seed \
  --controller-id <CONTROLLER_ID> --operator <OPERATOR_LABEL> \
  --address <PUBLIC_IPV4>:30001 --out /tmp/record.json
```

Expected: a public JSON record matching the prepared config's transport address
and consensus identity. Send only this file to the coordinator and verify receipt
out of band. A mismatch is a preparation/identity incident; never edit the record
by hand. The coordinator validates it in the manifest.

## 5. Activate and verify custody and synchronization

**Prerequisites:** coordinator published complete ceremony artifacts, authenticated
global-config SHA-256 and epoch, and verified your record. With explicit approval:

```bash
sudo /opt/tos-testnet/scripts/install-node.sh activate --role validator \
  --global-config <GLOBAL_CONFIG_JSON> --sha256 <PUBLISHED_SHA256> \
  --genesis <PUBLISHED_GENESIS_DIRECTORY> --validator-id <CONTROLLER_ID>
systemctl is-active tos-testnet-validator
sudo journalctl -u tos-testnet-validator -n 100 --no-pager
sudo grep 'post-quantum consensus custody' /var/log/tos/validator/node.log*
```

Expected: active unit; custody line names your controller and exact key id/window.
The installer binds the seed while stopped, configures a loopback console, installs
and verifies the template, and starts the node. It refuses different installed
config content or a mismatched digest. Investigate rather than replace it silently.
Before the announced epoch, height zero can be expected; afterward ask the
coordinator to run [the two-node live check](CEREMONY.md#7-coordinator-the-chain-is-live).
An active unit alone does not prove sync or correct custody.

## 6. Onboard for elections

**Operator supplies:** label, host/approved SSH access, public controller artifact,
matching node/tosctl revision, live synced console and RPC, and offline root-signing
availability. Never send the root or consensus seed to the host/coordinator agent.

**Coordinator**, with human approval, follows [§8.1](CEREMONY.md#81-onboarding-a-genesis-validator-for-elections).
There is no `onboard --dry-run`. Review the two-validator `reconcile` report,
funding amounts/profile, identities and public artifacts before authorizing it.
It initializes `tos-ctl`, funds/deploys/configures, signs the authorization offline,
checks readiness and enables elections. Keep the ceremony journal and secret
backups; do not restart onboarding with a different ceremony after a timeout.

**Operator verifies** the host task:

```bash
systemctl is-active tos-testnet-elections
sudo journalctl -u tos-testnet-elections -n 60 --no-pager
```

Expected: task opens its wallet/pool and reports an election or no active election,
with no blocking readiness failure. The task runs as `tos-ctl`, owns only
`/var/lib/tos-ctl`, and cannot renew root authorization itself. Root reads
`/etc/tos/tosctl.env` (0600) for it; never display that file. Every manual host
`tosctl` read uses the same identity and working directory, for example:

```bash
sudo bash -c 'set -a; . /etc/tos/tosctl.env; set +a; cd /var/lib/tos-ctl; runuser -u tos-ctl -- tosctl controller operations status --controller=-1:CONTROLLER_HEX --strict'
```

Expected: pinned block, funds/allowance, limit/floor, stakes remaining and expiry;
`--strict` returns nonzero for warnings. A successful stake submission still needs
Elector acceptance **and** the next Config34 activation, checked by the coordinator.

## 7. Daily checks and renewal

**Operator daily and after every restart/rotation:**

```bash
python3 /opt/tos-testnet/scripts/check-host-disk.py --min-free-gib 15 --cpu-sample 3
systemctl is-active tos-testnet-validator tos-testnet-elections
sudo journalctl -u tos-testnet-elections --since '-1 hour' --no-pager
sudo journalctl -u tos-testnet-validator --since '-1 hour' --no-pager
df -h /var/lib/tos
```

Check head and head age, process memory/restarts, disk and growth, net failures,
peer/transport timeout logs, accepted stakes and operating status from §6.
The disk checker prints JSON with null for unavailable observations and exits 1
below a floor. It is not a full peer-count or transaction audit. Persistent peer
timeouts need coordinator cross-node/UDP checks; this bundle has no dedicated
peer-health command. Coordinator watching/alerts: [testnet README](README.md#watching-the-network).

Run the strict operating-status read before remaining stakes run out or the
expiry window approaches. A balance alone does not authorize stakes.
**Coordinator renewal:** [renewal runbook](CEREMONY.md#renewing-operating-authorization),
first a journaled bootstrap `fund` top-up, then a separate `refund` root grant;
review dry runs, do one node, verify, then the rest. Both validators must agree
on the quiet election window and funds/fees. Operator confirms the election
service is active afterward and the exact new authorization is visible.

Current main does not automatically explain election-task stake relays in the
operation journal. A refusal for unexplained operator history requires human
reconciliation on both validators and, only after verification, an explicit
baseline. Do not automatically baseline or assume every 20 TOS transfer is a relay.

## 8. Upgrade, rollback and key rotation

**Prerequisites:** owner-approved revision/window, healthy quorum, no pending
ambiguous transaction, current custody and backups, release notes reviewed.
Build new binaries before stopping anything. Upgrade one validator at a time:

```bash
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev <NEW_COMMIT> --role validator
sudo systemctl stop tos-testnet-elections tos-testnet-validator
sudo /opt/tos-testnet/scripts/install-node.sh binaries --role validator \
  --release /var/lib/tos-build/release-<NEW_COMMIT>
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
has no journaled rotation command. A human coordinates the offline kind-3 bind,
key schedule, retained current/previous/next signing duties and election proof.
Use the exact tos checkout's `doc/validator-operator-guide.md` §10 and
`tos-pq-consensus-key` usage, with an independently reviewed command plan; never
rerun `activate` over a multi-key node. Root rotation changes epoch/nonce and
invalidates earlier signed requests. Do not treat it as an automated renewal.

## 9. Incidents, leaving and retirement

| Symptom | Verify / response |
| --- | --- |
| Node down | Inspect `systemctl status` and journal; exit 2 is a refusal, not a retry instruction. Check clock, disk, config identity and custody. Ask before a restart. |
| Head stuck / peers timing out | Compare fresh full block IDs on two validators; check UDP mesh, head versus shard-client lag and memory. Keep logs. Do not reset to cure lag. |
| Disk filling | Inspect GC progress, key-block/election progress, consensus deletion logs and growth. Escalate before exhaustion; never delete live DB/consensus directories. |
| Wrong network / zero state | Stop and ask; preserve DB/config. Never overwrite config and reuse keys as a shortcut to another genesis. |
| Stake refused or not confirmed | Retain the query/transaction evidence; inspect Elector result and controller readiness, pool balance and authorization expiry. Do not resend or clear journals to force acceptance. |
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
