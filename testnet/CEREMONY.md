# Genesis ceremony and validator bring-up

The order of work for the four genesis operators (O1–O4), the DHT hosts and
the coordinator (C). Every artifact that crosses between parties is public;
each party keeps its own secrets on its own machines.

```
O: prepare host -> O: operator wallet -> C: pool -> O: record --\
D: prepare DHT  -> D: dht-node -----------------------------------+-> C: manifest -> genesis -> global-config -> publish
                                                                                                                 |
O, D: activate (verify SHA-256, start before the epoch)  <-------------------------------------------------------/
C: check-testnet.py across independent nodes
```

Each validator is named by its staking account: a single-nominator pool whose
owner is an offline wallet the coordinator keeps and whose validator role is the
operator's wallet on the host. The pool's address is the validator id genesis
records, the node is bound to it, and the node signs stake authorizations only
for it. The pool derives from the two wallets, so both exist before genesis.

For host tasks and failure handling, use [OPERATOR.md](OPERATOR.md). All live
changes and signing require explicit human approval under [AGENTS.md](../AGENTS.md).
Commands here are templates, not permission to execute. The reference tos build
is `85c679c3454f306eb867e25b1960ae3d757bd3dd`; pin the approved ceremony commit.

Paths below assume `testnet/` is installed at `/opt/tos-testnet` (root-owned,
world-readable) and release binaries in `/usr/local/bin`.

## 0. Before anything (coordinator)

- Decision D03: the global id is 2, confirmed 2026-10-12 (`network/profile.json`,
  status `CONFIRMED`; `genesis` refuses any other status). Freeze the genesis
  epoch, and announce both.
- Name the tos commit (full 40-character id). Every host compiles its own
  binaries from that commit (step 1). The coordinator builds `create-state`,
  `fift` and `gen_fif` from the same commit
  (`cmake --build build --target create-state gen_fif fift`).
- Confirm the four operators' identities out of band. The ceremony checks that
  each record is self-consistent; it cannot prove who sent it.

## 0.4 Every host: set the clock first

On every host, before anything else:

```bash
sudo /opt/tos-testnet/scripts/setup-time.sh
```

The script:

- installs ntpsec and disables systemd-timesyncd and chrony;
- runs ntpd on IPv4 only, with a nearby stratum-1 server beside the pool;
- exits non-zero unless ntpd has selected a reachable server.

`install-node.sh prepare` runs it again before anything else, so a host
whose clock is not following NTP never gets a node.

The kernel flag `NTPSynchronized=yes` is not proof that time is followed. On
the first testnet hosts that flag said yes while ntpsec had no server at all.
The VMs had IPv6 addresses but no working IPv6 path, so ntpd chose IPv6
servers, dropped them, and kept nothing.

## 0.5 Coordinator: preflight every host

Before anything is installed, run the preflight from the coordinator's
machine against an inventory of every host (format:
`network/inventory.example.json`; keep the real one outside the repository):

```bash
python3 /opt/tos-testnet/scripts/preflight.py --inventory hosts.json --accept-new-host-keys --install-tools
```

It checks, per host:

- SSH, Ubuntu 24.04, and x86-64-v2 on x86_64;
- CPUs, memory and free disk against the role floors in `network/profile.json`;
- whether the public address is on an interface;
- NTP;
- ufw rules for the role's UDP ports, and that the console port is closed;
- whether another program already holds those ports.

It then has every host send UDP probes to every other host's role ports, while
each target captures with tcpdump. A probe that never arrives was dropped
outside the VM. Fix every FAIL before step 1. It is safe to rerun on live
nodes; a port held by `validator-engine` or `dht-server` passes.
`--accept-new-host-keys` accepts only a first-seen host key; a changed key
still stops SSH, and must be checked against the provider console first.

## 1. Operator: build and prepare the validator host

Compile the binaries and the operator tool on this host from the ceremony
commit, then prepare:

```bash
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev <COMMIT> --role validator
sudo /opt/tos-testnet/scripts/build-tosctl.sh --rev <COMMIT>
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role validator \
  --public-ip <PUBLIC_IPV4> --release /var/lib/tos-build/release-<COMMIT> --rev <COMMIT>
```

Never copy binaries from another machine. RocksDB compiles for the build
machine's CPU unless told otherwise, and a binary built on a newer Xeon
stopped with SIGILL (illegal instruction) on these hosts.
`build-node-binaries.sh` builds for `x86-64-v2`, as tos CI does, so a VM
migrated to an older CPU keeps working. It needs about 2.5 GiB of memory per
compile job and takes tens of minutes on a 6-core VM. To replace the binaries
of a prepared node later, stop it and run
`install-node.sh binaries --role <role> --release <dir> --rev <COMMIT>`.
`--rev` refuses a release whose `BUILD-INFO` names another commit. The four
validators' `SHA256SUMS` for one commit are identical (build timestamps take
the commit time); compare them after building, before installing.

This creates `/var/lib/tos/validator` and `/var/log/tos/validator` owned by
`tos`. It runs the first start with `-I <PUBLIC_IPV4>:30001` on a placeholder
global config (`/etc/tos/pregenesis-global-config.json`, never used to run a
node), and generates `/var/lib/tos/validator/keys/pq-consensus.seed`. It prints
the consensus `key_id` and public key. `<PUBLIC_IPV4>` is the address the
node announces; it must be static. The engine binds ADNL and QUIC by port on
all interfaces, so a host behind NAT works if the router forwards UDP 30001
and UDP 31001 to it. Two nodes behind the same NAT reach each other through
the announced public address, so the router must also support NAT hairpinning.

Have the human operator back up the seed encrypted and offline using the
approved backup procedure; see [consensus custody](../production/Production-Node.md#31-consensus-key).
The agent must not read, copy or display its plaintext. Do not use an unencrypted
file or log as an intermediate backup.

## 2. Coordinator: staking pools

On each validator host the operator first makes the operator wallet:

```bash
sudo /opt/tos-testnet/scripts/init-operator.sh --name <node-name> --wallet-only
```

It creates the user `tos-ctl`, its vault (`/etc/tos/tosctl.env`, 0600) and the
masterchain operator wallet `op-<node-name>`, and prints `op-<node-name>
<ADDRESS>` on its last line. It needs no running node. The operator sends the
address to the coordinator by a channel that authenticates them.

The coordinator then derives that validator's pool, once per validator, in the
directory that becomes the ceremony directory:

```bash
python3 /opt/tos-testnet/scripts/testnet-elections.py pool --name <node-name> \
  --operator <ADDRESS> --ceremony ./ceremony --tos-root "$TOS_ROOT" \
  --fift "$TOS_ROOT/build/crypto/fift" \
  --previous-ceremony ../epoch-1/ceremony   # after a reset: once per earlier epoch
```

It records the operator wallet as `op-<node-name>` in `ceremony/wallets.json`
and refuses one an earlier epoch recorded. It makes the pool's **owner**, a
wallet v3 in the masterchain (subwallet `0x504F4F4C`), with `new-wallet-v3.fif`
on the coordinator: its key is `ceremony/secret/pool-owner-<node-name>.pk`
(0600) and never leaves the coordinator; its address and self-deploy message are
in `ceremony/pool-owners/` and `wallets.json`. It derives the pool from the
pinned `single-nominator-code.hex`, the owner and the operator wallet (the same
StateInit as the pool's `init.fif`), records pool, owner and operator in
`ceremony/pools.json`, and prints the pool's `validator_id`. Nothing moves value
and no node is asked. Return the validator id to the operator.

## 3. Operator: the public record

```bash
sudo -u tos python3 /opt/tos-testnet/scripts/testnet-operator.py record \
  --db /var/lib/tos/validator --seed /var/lib/tos/validator/keys/pq-consensus.seed \
  --validator-id <VALIDATOR_ID> --operator <short-name> \
  --address <PUBLIC_IPV4>:30001 --out /tmp/record.json
```

`<VALIDATOR_ID>` is the pool's id from step 2. It refuses an address the node
does not announce, and a key id that does not match the public key. Send
`record.json` to the coordinator by a channel that authenticates you.

## 4. DHT host (at least two, run by the team)

```bash
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev <COMMIT> --role dht --jobs 2
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role dht \
  --public-ip <PUBLIC_IPV4> --release /var/lib/tos-build/release-<COMMIT> --rev <COMMIT>
```

A validator host that also serves DHT builds both with
`build-node-binaries.sh --role validator --with-dht`.

Send `/var/lib/tos/dht/dht-node.json` (a signed, public `dht.node`) to the
coordinator.

## 5. Coordinator: manifest, genesis, global config

The record order is the validator index order; fix it before you start. The
ceremony directory holds only what step 2 wrote; `manifest` refuses anything
else in it, and a record whose validator id is not one of the pools recorded in
`ceremony/pools.json`.

```bash
S=/opt/tos-testnet/scripts
python3 $S/testnet-coordinator.py manifest --ceremony ./ceremony --tos-root "$TOS_ROOT" \
  record-o1.json record-o2.json record-o3.json record-o4.json
export TOS_AUTH_NETWORK_TAG="$(python3 -c 'import json; print(json.load(open("/opt/tos-testnet/network/profile.json"))["genesis"]["auth_network_tag"]["value"])')"
python3 $S/testnet-coordinator.py genesis --ceremony ./ceremony --tos-root "$TOS_ROOT" \
  --tos-build "$TOS_ROOT/build" --epoch <EPOCH>
python3 $S/testnet-coordinator.py global-config --ceremony ./ceremony dht-1.json dht-2.json
```

After a reset, add the earlier epochs to both steps, once per earlier epoch
(section 9): `manifest --previous <old>/genesis-records.json` and
`genesis --previous-ceremony <old>`.

Global version 16 makes ConfigParam 48, the AUTH policy, mandatory and
critical: the collator, the validator and state admission refuse a version-16
configuration without it, and the template refuses to run without a public
AUTH network tag (tos `doc/auth-policy-v1.md`; tos assigns none). The tag is
`genesis.auth_network_tag` in `network/profile.json`: SHA-256 of the ASCII rule
`TOS-AUTH-NETWORK-TAG-v1;network=tos-public-testnet;global_id=2;epoch=<N>`, a
new one every epoch, because every epoch shares global id 2 and Quantum wallet
keys and signatures bind the tag. Before the next reset, set `campaign_epoch`,
`rule` and `value` to the next epoch's (`testnet_lib.derive_auth_network_tag`).
`genesis` takes the tag from `TOS_AUTH_NETWORK_TAG` (64 hexadecimal digits, the
form tos tooling takes) and refuses unless it equals the profile's value, is no
tos test namespace or the mainnet candidate's `0x42…`, and no earlier epoch
named with `--previous-ceremony` recorded it. It defines the tag on the line
after the template's first, as tos expects of a wrapper.

`genesis` refuses a dirty tos checkout and a template whose mainnet lines
changed. It generates the zero state twice and compares the outputs. Then it
reads the zero state back (its cell parser checked against create-state's root
hash first) and refuses unless ConfigParam 8 is version 16, ConfigParam 48 is
the initial policy for this tag (sequence 0, nothing retired, no deadline, the
v1 policy identity `5e4380ae…`) and 48 is in both ConfigParam 9 and 10. It
also refuses a zero state that still defines ConfigParam 47, or lists it in
ConfigParam 9 or 10: that parameter named the validator controller codes and
left tos with the controller, so its presence means the tos tree predates
staking from the operator's own account.
It refuses a genesis that is not the decided supply (CFG-01, memo STATUS 13.254):
ConfigParam 5 must name the blackhole `-1:ff…ff`, burn no fees (0/1) and be
critical (ConfigParam 10); the bootstrap wallet `-1:111…1` must hold exactly
`elections.bootstrap_wallet_tos` (80,151 TOS) and the state exactly
`genesis.total_supply_tos` (81,151 TOS: the wallet plus the Elector's and the
Config contract's 500 each), each account's balance, the accounts dictionary and
`total_balance` agreeing; and ConfigParam 15 read back from the state must be the
profile's schedule. These values come from the canonical template, so `--tos-root`
must be at a tos commit that carries them. `genesis.json` records the result as
`bootstrap` (the ConfigParam 5 cell hash, the blackhole, the balances and the
read-back schedule).
create-state itself runs the node's configuration check (`valid_config_data`,
which includes `validate_auth_policy_config`) before it writes a zero state,
and every node checks it again when it starts. `genesis.json` records the
result as `auth_policy`: the tag, its rule and the ConfigParam 48 cell hash.
Between
the two runs it derives the bootstrap wallet's public key from the new
`main-wallet.pk` and refuses one that an earlier epoch named with
`--previous-ceremony` used. It records the key as `main_wallet_public_key` in
`genesis.json`, in `main-wallet.pub` and as `bootstrap` in `wallets.json`. It
moves `main-wallet.pk`, the only secret output, to `ceremony/secret/`. Take that key
offline: it funds the four operator wallets and pool owners for the first
elections (tos `doc/validator-genesis-bootstrap.md`, "First ordinary elections")
and nothing else; once two elected sets hold the four stakes, the
[sweep](#sweeping-the-bootstrap-wallet) burns what is left and deletes the wallet.

AUTH validation and the complete summary are checked in `run-a` before any
key or output is published. Existing outputs are never overwritten. If genesis
fails, do not publish its partial outputs: a rerun refuses the retained scratch
runs or publication artifacts. Preserve any keys already created and start a
new ceremony directory; repeat the manifest step there. `genesis.json` is the
last published artifact and marks completion.

Publish, together and signed or attested by the release process:

- `global-config.json` and `global-config.json.sha256`
- `genesis.json`, `genesis-records.json`, `validator-pq.pub`
- `main-wallet.pub`, `wallets.json` and `pools.json` (public keys and addresses
  only; `wallets.json` grows as `load` adds its wallets, and the next reset
  reads it)
- `zerostate.boc`, `basestate0.boc` and their `.fhash`/`.rhash`
- `gen-zerostate-testnet.fif`, the exact template that ran

Anyone can regenerate the zero state from these and the named tos commit.

The epoch is the earliest time a block can be produced: until the validators'
clocks reach about epoch − 29 s, every candidate is rejected as being from the
future, and the nodes wait at height 0. Choose it at least 60 minutes after
this step, so that every node is activated before it. See
`production/Production-Node.md` section 8.3 for the rules behind this.

## 6. Everyone: activate before the epoch

Validator (operator), with the pool's validator id from step 2:

```bash
sudo /opt/tos-testnet/scripts/install-node.sh activate --role validator \
  --global-config global-config.json --sha256 <PUBLISHED_SHA256> \
  --genesis ./published --validator-id <VALIDATOR_ID>
```

This installs `/etc/tos/global-config.json` only on a matching digest. It
places the zero state in `/var/lib/tos/validator/static/` and runs
`tos-pq-consensus-key bind-node` with the node stopped. It adds a console on
30002/tcp, with its client keys in `/var/lib/tos/validator/console-client/`,
and then starts `tos-testnet-validator`. Check the custody line; its
`validator_id` must be the pool's:

```bash
sudo journalctl -u tos-testnet-validator | grep 'post-quantum consensus custody'
sudo sh -c 'grep "post-quantum consensus custody" /var/log/tos/validator/node.log*'
```

DHT host: `install-node.sh activate --role dht --global-config ... --sha256 ...`.

Full node: `install-node.sh prepare --role fullnode ...` and then `activate`.
A full node started at genesis passes `--genesis`; a later one syncs from the
network instead.

Apply the firewall: `firewall/tos-testnet.nft`, with the role block uncommented.

The host firewall is not the only one. Most VPS providers also filter traffic
outside the VM, with a stateful security group that by default admits only
SSH. Add **inbound** IPv4 UDP rules there too: 30001 and 31001 on validators
and full nodes, and 30300 on DHT hosts. Outbound is usually open already, and
IPv6 is not needed, because nodes announce IPv4 addresses only. Without these
rules the first deployment ran, but every validator stayed at height 0 with
`get_peer_node: timeout`. DHT nodes that both send to each other can still
talk, because each packet looks like a reply to the other side's state; that
hides the problem. To prove reachability, capture on each target with
`tcpdump -n -i eth0 'udp and dst port 30001'` while another host sends to it.
tcpdump sees a packet before the host firewall, so if it never appears, the
packet was dropped outside the VM.

## 7. Coordinator: the chain is live

```bash
TOS_ROOT=$TOS_ROOT "$TOS_ROOT/.venv/bin/python" /opt/tos-testnet/scripts/check-testnet.py \
  --genesis ceremony/genesis.json --genesis-set ceremony/genesis-records.json \
  --rpc http://127.0.0.1:18081 --rpc http://127.0.0.1:28081    # SSH tunnels to two nodes
```

It passes only when the nodes share the ceremony's zero state and one full
block id at the common head, that block carries the testnet global id and is
fresh, ConfigParam 34 is the four genesis identities, and (for a genesis.json
with `auth_policy`) live ConfigParam 48 carries the genesis tag and is
mandatory and critical, with ConfigParam 8 at version 16 or later. Run it from two
places that do not share infrastructure (plan G0: two independent observers).
After the first ordinary election, drop `--genesis-set`.

## 8. After genesis

The schedule is `genesis` in `network/profile.json`, and `genesis.json` prints
its times. Epoch 6 carries the 2 h ConfigParam 15 epoch 5 adopted by its live
vote (7,200 / 3,600 / 900 / 3,600). The bootstrap set is valid for 21,600 s after
the epoch T, and each elected set for 7,200 s. The four validators must be
onboarded (operator wallets and pool owners funded, pools deployed and holding the
principal) and stake through two overlapping elections (Production-Node.md
section 9). The first election opens at T + 5 h and closes at T + 5 h 45 min; the
elected set takes office at T + 6 h. The next election opens at T + 7 h, its set
takes office at T + 8 h, and the set rotates every 2 h after that, each rotation a
key block. Everything has to be ready before the first window opens. A rehearsal
of the bootstrap flow at production timing uses
`network/profile-production-timing.json` (the canonical template's schedule;
`rehearse-loopback.sh` takes it as `REHEARSAL_PROFILE`).

The first epoch used the canonical template's schedule unchanged: a 131,072 s
bootstrap set and 65,536 s terms. Its first key block after genesis would have
come at T + 34 h. Until then the GC checkpoint could not move, so no state and
no consensus database was deleted, and at about 145 GB a day the 99 GB disks
would have filled in 15 hours. That is why this testnet runs a shorter
schedule and a 3,600 s validator `state_ttl`.

### 8.1 Onboarding a genesis validator for elections

From the coordinator's machine, with SSH tunnels to **two** validators'
loopback JSON-RPC (`ssh -L 18081:127.0.0.1:8081 root@<validator>` and another
on 28081 to a second validator), once per validator whose pool step 2 recorded:

```bash
python3 /opt/tos-testnet/scripts/testnet-elections.py onboard \
  --name node-1 --host <HOST> --ssh-key <KEY> --ceremony ./ceremony \
  --tos-root "$TOS_ROOT" --fift "$TOS_ROOT/build/crypto/fift" \
  --rpc http://127.0.0.1:18081/jsonRPC --confirm-rpc http://127.0.0.1:28081/jsonRPC \
  --previous-ceremony ../epoch-1/ceremony   # after a reset: once per earlier epoch
```

It refuses unless `ceremony/pools.json` records the validator's pool, the pool
derives from its recorded owner and operator wallet, and the genesis records
name it as a validator id. It runs `init-operator.sh` on the host (vault,
console key, node registration, tosctl's master wallet, operator wallet) and refuses unless the host's
operator wallet is the one the pool was derived from (a host that kept
`/var/lib/tos-ctl` over a reset still has the old wallet key). Then it runs these
steps, in order:

1. it funds the operator wallet from the bootstrap wallet with fee money only
   (`operator_funding_tos`, 10: the measured epoch-5 operator spend through the
   first returned stake plus one failed submission) and activates it;
2. it funds the pool's **owner** with the principal and a reserve (`pool_tos` +
   `pool_owner_reserve_tos`) and activates it; the owner's key stays on the
   coordinator (below);
3. it deploys the pool with 2 TOS from the operator wallet;
4. it configures the pool and the binding in tosctl on the host
   (`config pool add --address --owner`, `config bind add --pool`);
5. the owner sends the stake principal (`pool_tos`) to the pool;
6. it checks readiness: the pool holds at least two stakes (`stake_tos`) above
   its storage reserve, and the node's latest `post-quantum consensus custody`
   line names the pool as its validator id (the Elector refuses a stake signed
   for another account);
7. it runs `enable-elections.sh`, which installs
   `systemd/tos-testnet-elections.service` (`Restart=always`).

The election task (`tosctl service`) refuses to start without a master wallet
(`service failed: initialize runtime config store: master wallet not
configured`), and `tosctl config generate` no longer writes one. So
`init-operator.sh`, in both modes, configures exactly the record the generated
configuration used to carry and epoch 5 ran with: vault key
`master-wallet-secret`, V3R2, subwallet 42, workchain 0 (`tosctl config
master-wallet set --secret-name master-wallet-secret --version V3R2`; the
record is `MASTER_WALLET` in `testnet-operator.py`). The service creates that
key in the host's vault on its first start, as it did on epoch 5; no step here
creates or reads it, and the testnet sends it no value. A rerun keeps it; a
different master wallet already configured is refused, never replaced.

The amounts are `elections` in the profile. `ceremony/secret/main-wallet.pk`
and the pool owners' keys never leave the coordinator.

**Every step that moves value is an operation** (`testnet_ops.py`):

- `fund-op-<name>`
- `fund-owner-<name>`
- `activate-owner-<name>`
- `deploy-pool-<name>`
- `principal-<name>`

Each has a record in `ceremony/operations/<id>.jsonl`. The lines are append-only
and each is fsynced with its directory. The signed message is durable there
before it is broadcast, and the shared ceremony journal lock is held across reread, validation,
signing and broadcast. It serializes operations across wallets and processes.

The operator wallet's messages are built and signed by tosctl on the host, but
**never broadcast there**: `wallet send --build-only` hands the message to the
coordinator. The coordinator decodes it and refuses anything but the intended
one, checking:

- the signing wallet;
- global id 2;
- the wallet's current seqno on both validators;
- the subwallet and an expiry within 120 s plus 30 s clock skew;
- send mode 3;
- the exact destination, value, bounce flag, StateInit and body.

Only then is the message journaled and broadcast from the coordinator. The pool is
deployed with the StateInit derived on the coordinator from the pinned
`single-nominator-code.hex` and its two roles.

Before signing anything, the coordinator reads the signing wallet's complete
history on both validators. It refuses when:

- any transaction sent value away and no settled or failed operation explains
  it;
- another operation of that wallet is still open;
- the two validators do not agree;
- the history cannot be read completely.

An operation settles only from the chain, matched by hashes: the wallet's
transaction for the exact external message, the one message it emitted, and the
destination's transaction for that message, on both validators. Configuration
steps (pool, binding) resume from what the host's tosctl
configuration already holds.

**A rerun never resends value.** When an operation is open, because a run was
interrupted or its message has not settled yet, the next run refuses and names
it. A person then resolves it:

```bash
S=/opt/tos-testnet/scripts/testnet-elections.py
C=(--ceremony ./ceremony --tos-root "$TOS_ROOT" --fift "$TOS_ROOT/build/crypto/fift"
   --rpc http://127.0.0.1:18081/jsonRPC --confirm-rpc http://127.0.0.1:28081/jsonRPC)
python3 "$S" reconcile "${C[@]}"                       # read only: every record against the chain
python3 "$S" record "${C[@]}" --id ID --settled --hint TXHASH
# Choose ONE evidence form a, b, c or d; hint is required where the form needs it.
python3 "$S" record "${C[@]}" --id ID --failed b --hint TXHASH
python3 "$S" resubmit "${C[@]}" --id ID                # the original message, never re-signed
python3 "$S" baseline "${C[@]}" --wallet ADDR --reason TEXT
```

What each command does:

- **`reconcile`** prints each operation's state against the chain, and every
  unexplained transfer of the journal's wallets.
- **`record --settled`** verifies the whole chain of evidence again, on both
  validators. The hint only locates the transaction.
- **`record --failed`** needs one of four terminal evidence forms:
  - (a) the wallet accepted the message but emitted not exactly the required
    message;
  - (b) the destination refused it, bounced it, or paid nothing;
  - (c) the message expired and was never accepted: complete history on both
    validators, and block time 120 s past its `valid_until`. This never applies
    to an activation;
  - (d) another transaction took its seqno while the wallet's identity stayed the
    same. The competing transaction then still needs accounting.

  A transaction counts as taking effect only when its compute succeeded and it
  did not abort. A run that aborts in the action phase still pays its fees, so the
  balance and the account's last transaction change, but its computed data and its
  out messages are not applied: the seqno stays where it was, nothing is sent, and
  the same message can run again. That run is neither
  settlement nor failure (a) of the operation, and it is never the consumer in (d).
  The operation stays open (`reconcile` lists the aborted runs) until it is
  resubmitted, expires (c), or another message takes the seqno (d).
- **`resubmit`** sends the journaled message once more. It is allowed only while
  that message can still execute (not accepted, same seqno, not expired) and the
  pool checks still hold.
- **`baseline`** accepts a wallet's history from before the journal, with a reason
  (never needed on a fresh epoch).

A failed operation is final under its id. It does not block its wallet: its
evidence accounts for its own outgoing messages.

The single-nominator pool keeps two roles apart, and is itself the staking
account the Elector names:

- the **owner** holds the principal and is the only role that can withdraw it;
- the **validator** is the operator wallet on the host, `op-<name>`. It can only
  order the pool to stake with the Elector (sending the fees, 1.2 TOS) and to
  recover the stake back into the pool.

The owner is not the operator wallet. Step 2 created `pool-owner-<name>` on the
coordinator:

- its key is `ceremony/secret/pool-owner-<name>.pk` (0600);
- its address and self-deploy message are in `ceremony/pool-owners/`;
- its address is in `wallets.json`;
- the pool, owner and operator are in `ceremony/pools.json`.

The bootstrap wallet funds the owner with `pool_tos` + 5 TOS. Before the
principal is signed, the coordinator checks four things: the owner's funding and
activation are settled operations; the pool is the derived address; the pool runs
the pinned code; and its `get_roles` is exactly the offline owner and the
operator wallet.

A compromised validator host can therefore stake and recover, but it can neither
take the principal nor have it sent elsewhere. The owner can also replace the
validator address (`CHANGE_VALIDATOR_ADDRESS`); the pool, and with it the
validator id, stays the same:

```bash
python3 "$S" change-validator "${C[@]}" --name node-1 --id change-node-1-1 --new --to "$NEW" --dry-run
# After approval, repeat without --dry-run. Restoring the operator wallet is
# another id with --to set to it.
```

The command builds op `0x1001` with the pool's own `change-validator.fif` and
signs a bounceable 0.1 TOS transfer from the owner wallet, which the pool keeps.
It refuses while an election is open, when `--to` is not a masterchain wallet
or already holds the role, and unless the pool's address, code and owner role
are the recorded ones. It settles when `get_roles` on both validators shows the
new validator. While another wallet holds the role, the host's election task
cannot stake or recover through the pool: restore it before the next election.

To take principal out, between elections (a stake at the Elector comes back
to the pool only when the election task recovers it, `stake_held_for` after
its term), name the withdrawal's operation id:

```bash
python3 "$S" withdraw "${C[@]}" --name node-1 --id withdraw-node-1-1 --new --all --dry-run
# After approval, repeat with --new --all but without --dry-run.
# To report the settled outcome later, omit --new and keep the same amount selection:
python3 "$S" withdraw "${C[@]}" --name node-1 --id withdraw-node-1-1 --all
```

`--new` creates the id. Without it, only an existing id is accepted, and its
parameters can never change. The command works in five steps:

1. It builds the pool's WITHDRAW body (op `0x1000`) with the pool's own
   `crypto/smartcont/single-nominator-pool/withdraw.fif`.
2. It signs, on the coordinator with the offline key, a bounceable 1 TOS transfer
   from the owner wallet carrying that body. The pool sends the amount and the
   unspent value back to the owner.
3. It refuses while an election is open, including on resubmission.
4. It checks the pool's address, the pinned code and its **owner** role. The
   validator role is not checked, because the owner may have replaced it.
5. It settles only when both validators show the pool's payment and the owner
   wallet's transaction that **retained** it: credit equal to the payment, compute
   success, no message sent on. For `--amount`, the payment must be at least the
   requested amount. A smaller retained payment is a terminal failure recording
   what was paid; a person may request a new operation. `--all` accepts the variable
   payment. A settled result is appended to `ceremony/withdrawals.jsonl`.

`check-testnet.py` refuses a version-16 `genesis.json` without `auth_policy`.
Do not use an older checker to bypass it: use the matching approved ceremony
artifacts or ask the coordinator to resolve the identity mismatch.

The election task runs as the non-login system user `tos-ctl`, never root.
Every `tosctl` call on the host, from these scripts and from
`testnet-elections.py` over SSH, runs as `tos-ctl` too (`runuser -u tos-ctl`,
with root only reading `/etc/tos/tosctl.env`, root-owned 0600): tosctl refuses
a vault, lock or key file its caller does not own, so one
root-owned file there stops the task. A host onboarded while the task ran as
root moves over once with `migrate-nonroot-services.sh --role validator`
(testnet/README.md), outside an open election.

`testnet-elections.py fund --id ID --label LABEL` sends from the bootstrap wallet
on its own as operation ID. **Its `--dry-run` still signs and saves a private BOC
under `sent/`, but does not journal or broadcast**; obtain signing permission
first. After the [sweep](#sweeping-the-bootstrap-wallet) `fund` refuses before it
signs anything, `--dry-run` included. `load` never spends the bootstrap wallet: it
takes `--funding-owner NAME` and makes each transfer from that pool owner its own
`owner-fund` operation; give it rewards withdrawn after the first returned stake
(about 13,550 TOS a day network-wide at the current ConfigParam 14), and start
per-type load after day 1.

A step whose operation failed terminally is never retried under its id and never
reset. A person starts another attempt, `ID.attempt-N`, which names the failed
one and keeps the step's parameters; all checks run again:

```bash
python3 "$S" retry "${C[@]}" --step ID --reason TEXT
```

#### Topping up an operator wallet

The operator wallet pays only fees: tosctl's election task attaches 1.2 TOS
(`ELECTOR_STAKE_FEE` + `NPOOL_COMPUTE_FEE`) to every stake order and 0.2 TOS to
every recovery, and pays its own gas; the stake itself comes from the pool. The
10 TOS of onboarding cover the first two stakes, the first recovery and one
failed submission with about 2.6 TOS spare, about two more election cycles.
Single-nominator rewards go to the pool and its owner, never to the operator, so
fee money after that comes from the owner.

**Before the sweep** a top-up may still come from the bootstrap wallet, out of its
50 TOS margin only, as an ordinary `fund` operation with its own fixed id:

```bash
# C is the common ceremony / tools / --rpc / --confirm-rpc arguments above.
python3 "$S" fund "${C[@]}" --id top-up-node-1-1 --label top-up-node-1-1 \
  --to <RECORDED_OPERATOR_WALLET> --amount 5 --dry-run
python3 "$S" fund "${C[@]}" --id top-up-node-1-1 --label top-up-node-1-1 \
  --to <RECORDED_OPERATOR_WALLET> --amount 5
```

**After the sweep** (and whenever it is the better source) the pool owner pays:
withdraw rewards from the pool to the owner between elections (`withdraw`, above),
then send the operator its fee money with `top-up`, an `owner-fund` operation
signed with the owner's offline key, non-bounce:

```bash
python3 "$S" top-up "${C[@]}" --name node-1 --id top-up-node-1-2 --new --amount 5 --dry-run
# After approval, repeat without --dry-run; omit --new to report a settled id later.
python3 "$S" top-up "${C[@]}" --name node-1 --id top-up-node-1-2 --new --amount 5
```

It refuses unless the operator wallet is the pool's recorded one and active, and
the owner keeps a withdrawal message (1 TOS) and its fee after the transfer. Both
kinds settle by message and transaction hashes on both validators (the operator's
credit equals the value), and repeating the same id reports it and does not fund
twice. `--dry-run` of `top-up` signs nothing. These commands move value; do not
run them as part of deployment verification.

#### Sweeping the bootstrap wallet

The bootstrap wallet is one-time (memo STATUS 13.155/13.254). Once the second
elected set is installed and holds all four stakes, its remaining balance (the
margin less what top-ups used, and the rounding) is sent with wallet-v3 send mode
160 (128: the whole remaining balance; 32: delete the account once empty), value
0, non-bounce, to the ConfigParam 5 blackhole `-1:ff…ff`, where the credit phase
destroys it and the block counts it in `ValueFlow.burned`. Nothing can be signed
from `-1:111…1` again: the account is gone and its address is no StateInit's.

`sweep` refuses unless, read on both validators: live ConfigParam 5 names the
blackhole and burns 0/1 (without it the transfer would create an ordinary account
holding the funds); the four `fund-op-`, `fund-owner-` and `principal-` operations
are settled; ConfigParam 34 and 32 are both elected sets of exactly the four pools,
each matched by an Elector result (the genesis set has none) and the previous one
older; each pool holds a frozen, unbanned stake in both results; each operator
wallet holds at least the measured first-recovery cash (0.203224039 TOS) plus the
1 TOS fee allowance; and no other bootstrap operation is open. Then it reads the
wallet's history like every bootstrap operation.

```bash
python3 "$S" sweep "${C[@]}" --dry-run
```

The dry run makes all those reads and prints the exact transfer it would sign
(mode, seqno, destination, value, bounce flag), the balance it would burn at most
and the history check; **it signs and writes nothing**. Review it, then with
explicit approval:

```bash
python3 "$S" sweep "${C[@]}"
```

The signed message is decoded and refused unless it is exactly that transfer;
every other kind is still refused anything but send mode 3. The run journals the
signed message and the masterchain head before signing (the search boundary:
the deleted account has no head to read history back from), broadcasts once, and
waits. It settles only when both validators show the wallet's transaction for
that message with end status `nonexist` and one non-bounced message to the
blackhole carrying a value, the wallet reading deleted, and the blackhole's
transaction for that message crediting nothing; then it stops **pending**, naming
the block of the blackhole transaction. Fetch that block's file with the
lite-client (`-D DIR`, `getblock <block-id-ext>`: the file is saved under its file
hash) and record it:

```bash
python3 "$S" record "${C[@]}" --id sweep-bootstrap --settled --hint <WALLET_TX> \
  --block-boc <BLOCK_FILE>
```

The file must hash to the block id both validators reported. In it the burn must
reconcile: a masterchain block of this network and seqno whose lt range holds the
transaction; the blackhole transaction itself (by hash) and every other blackhole
transaction of the block crediting nothing; a balancing `ValueFlow` whose `burned`
equals what those transactions burned (ConfigParam 5 at 0/1, read again on both
validators, burns no fees). The total supply does not simply fall by the swept
amount, because block rewards and fees keep flowing; the block's own flow is what
is checked. A mismatch refuses and leaves the operation open. The settled record
keeps the wallet transaction, the message, the blackhole transaction, the block id,
its file hash and its whole value flow, and its terminal checkpoint certifies the
deleted wallet up to the sweep's counter. `reconcile` then reports the wallet as
retired.

Publish the wallet transaction, the blackhole transaction, the block id and its
`ValueFlow.burned`. An interrupted sweep is resolved like any open operation
(`reconcile`, `resubmit` while it can still run, `record`): settlement finds the
transaction from the signed boundary also after the account is gone. Record it
within about a day, before validators prune that history. Under memo STATUS
13.156 any accepted failure of the sweep (a `failed` record of form a or b) stops
the ceremony for review; it retires the bootstrap wallet all the same.

If the first election cannot be conducted, the Elector cancels it at
`elect_at` and refunds the stakes. The chain does not stop: the genesis set
keeps validating past its `utime_until`. But no key block is produced and state
GC stops behind the last one, so disks grow until a later election succeeds.
Treat it as an incident.

### 8.2 Changing a configuration parameter by a validator vote

`testnet-governance.py` changes a ConfigParam on the live chain through the Config
contract (`-1:55…55`). The steps, and why each is shaped as it is:

1. **Value.** Write the new parameter cell to a BOC file and reproduce its hash
   independently (for example in Fift) before anything is sent.
2. **Propose** (`propose ... --dry-run` first). The proposal binds the current
   value's hash, so it can only replace the value it was made against. A
   parameter that ConfigParam 10 lists is registered as critical (the contract
   refuses it otherwise). The price follows ConfigParam 11: at least
   `min_store_sec` of storage (5,000,000 s for a critical parameter on the
   testnet, about 21.5 TOS for a 128-bit cell), and the contract wants 2^30
   nanotos beyond it, which it returns. The payer is a wallet v3 in the
   masterchain (the contract ignores other senders); the transfer is a journaled
   operation and settles only when `get_proposal` lists the proposal. The payer's
   earlier outgoing activity must be explained (journal or `baseline`).
3. **Sign** under the current validator set. Each validator's console signs
   `create-proposal-vote` on its host; only the vote body leaves the host. A
   vote commits to the set's hash, so votes are signed again after every
   rotation.
4. **Vote.** The votes go to the Config contract one at a time, each a journaled
   operation with 0.6 TOS attached (the verification is paid from it and the
   rest returned). The command refuses votes signed under another set and skips
   a validator that already voted in the round.
5. **Rounds.** A round is won when votes of more than 3/4 of the set's weight
   arrive; the proposal is adopted after ConfigParam 11's `min_wins` won rounds
   (2 ordinary, 3 critical), each under a different set. With four equal
   validators every round needs all four votes.
6. **Adopted.** `adopted` exits 0 only when both validators serve the new cell.

```bash
G=/opt/tos-testnet/scripts/testnet-governance.py
P=(--ceremony "$CEREMONY" --tos-root "$TOS_ROOT" --fift "$FIFT" --rpc "$RPC1" --confirm-rpc "$RPC2"
   --payer-key PAYER.pk --payer-addr PAYER.addr --payer-subwallet PAYER_SUBWALLET)
python3 "$G" propose "${P[@]}" --param 15 --value-boc new-cp15.boc --dry-run
python3 "$G" propose "${P[@]}" --param 15 --value-boc new-cp15.boc
# every round, after the rotation:
python3 "$G" sign --ceremony "$CEREMONY" --inventory inventory.json --rpc "$RPC1" --proposal HASH
python3 "$G" vote "${P[@]}" --proposal HASH
python3 "$G" status --rpc "$RPC1" --proposal HASH
python3 "$G" adopted --rpc "$RPC1" --confirm-rpc "$RPC2" --param 15 --value-boc new-cp15.boc
```

An exception after a broadcast is an unknown outcome: read the chain (`status`,
the journal) before running anything again.

## 9. Resetting the testnet

A reset is a new genesis with the same global id 2, so it shares the old
epoch's replay domain. Every operator generates a new operator wallet and a new
consensus seed, and the coordinator a new pool owner, so every pool and validator
id is new; never carry them over. The coordinator passes every
earlier epoch's `genesis-records.json` to `manifest --previous`, which refuses
any reused validator id, consensus key id or ADNL id. Validators that joined
an earlier epoch after genesis are not in those files. Keep their records and
pass them too.

Wallet keys are checked the same way. Keep every epoch's ceremony directory
(its `wallets.json`, `genesis.json` and `secret/`), and pass each one with
`--previous-ceremony` to `testnet-coordinator.py genesis` (the bootstrap
wallet: always at -1:111...1, so only its key differs between epochs),
`testnet-elections.py pool` and `onboard` (operator wallets and pool owners)
and `testnet-elections.py load` (the high-volume wallet and its relayers; start every epoch with a new
`--state` directory). Each refuses a wallet key or address the earlier epoch
recorded. A ceremony from before `wallets.json` existed gives its bootstrap
key through `secret/main-wallet.pk`, whose public key fift derives in place; a
previous ceremony that yields no wallet at all is refused rather than counted
as checked. Every operator must also let `retire-host.sh` delete the operator
tool's vault, so `init-operator.sh` creates a new wallet key.

On every host of the ended epoch, with that epoch's published zero state root
hash (`validator.zero_state.root_hash` in its `global-config.json`):

```bash
sudo /opt/tos-testnet/scripts/retire-host.sh --confirm-zerostate <ROOT_HASH_BASE64>
```

It refuses unless the installed global config names that zero state. It first
writes an evidence archive to `/var/lib/tos-retired/<epoch>/`: logs, unit
journals, kernel logs of this and the previous boot, and a live snapshot taken
before the units stop. It holds no database and no key, and if the archive
cannot be written, nothing is deleted. Then it stops and disables every
testnet unit and deletes the node databases, logs, the global config, the
operator tool's vault and its user `tos-ctl` (`init-operator.sh` creates it
again). It keeps the user `tos`, and on the DHT host the alert peer and its
user `tos-alert`, which watch across the reset. It keeps the binaries, so a reset on the same tos
commit starts again at step 0.4 without a rebuild.

The coordinator copies every host's archive, with its `.sha256`, into the
retired epoch's record before the next ceremony starts. An incident that was
not yet analysed must not lose its logs to a reset; the first reset did
exactly that (memo `public-testnet/EPOCH-1-FINDINGS.md`, E1-10).


### Election task history

The gate recognizes election-task pool messages only from their verified
transaction BOC: one outbound internal message to the recorded operator's own
pool, no StateInit or extra currencies, and no other outbound effect. Each body
must carry the expected opcode and query id. A new-stake order must have the
pool order layout tosctl builds (`nominator::new_stake`): stake, ML-DSA-44
algorithm 1, public-key reference, election id, max factor, ADNL address and
signature reference, and nothing after them. Recovery and maintenance bodies
must end after their documented fields.

| Kind (`explained_by: election-<kind>`) | Opcode | Maximum attached value | Other fields |
| --- | --- | --- | --- |
| `new-stake` | `0x4e73744b` | `stake_order_nanotos` (1.2 TOS) | Positive stake, algorithm 1, election id |
| `recover-stake` | `0x47657424` | 0.2 TOS recovery fee allowance | None |
| `update-validator-set` | `0x06` | 0.2 TOS maintenance gas | None |
| `validator-deposit` | `0x04` | 10 TOS per-tick rent top-up ceiling | None |
| `process-withdraw-requests` | `0x02` | 0.2 TOS maintenance gas | Batch limit exactly 8 (uint8) |

All values must be positive. The last three are the multi-nominator pool client's
maintenance actions; the single-nominator pool used here has no maintenance
actions. These are the runner's message shapes and ceilings, not permission to
send arbitrary value to a pool.

Only new-stake carries an election id. Its transaction `utime` must be in
`[election_id - elections_start_before, election_id - elections_end_before)`.
Both validators must return current ConfigParam 15 equal to the parameters saved
in `genesis.json`. If they changed, are unavailable or disagree, that window is
unknown and the gate refuses. Recovery and maintenance carry no election id and
are not limited to an open-election window. No historical getter or config read
is needed, so state TTL does not erase recognition. `reconcile` retains the
kind, transaction hash/time, query id and outputs, plus election/stake/window
fields for new-stake. Other outgoing effects remain unexplained.

### Abandoning an unsigned funding plan

If a coordinator funding run stopped with a `planned` record and no signed
message, use the supported recovery path rather than editing the journal:

```bash
python3 $S/testnet-elections.py record --ceremony ./ceremony \
  --rpc <VALIDATOR_1_RPC> --confirm-rpc <VALIDATOR_2_RPC> \
  --id <OPERATION_ID> --abandoned --dry-run
# Review the two-validator evidence, then repeat without --dry-run.
```

This applies only to unsigned planned `fund` operations. Any signing evidence,
a matching transfer or external funding intent since the plan's creation time,
unavailable/incomplete history, or disagreement refuses the operation. The
check reads signing-wallet history back through a decoded transaction older
than the plan (or account creation), ignoring baselines, on both
validators of the ceremony network; the real command repeats the absence check
before appending a terminal `failed` record. Dry-run appends nothing. It neither
explains nor changes any other wallet's transactions or journal records.

The coordinator's funding signer returns bytes from a temporary directory that
is removed before returning. The signed BOC is journaled and fsynced before
`sendBoc`; a crash before that journal write cannot have broadcast through this
path. Signed/broadcast records still require the existing reconciliation rules.
A refused gate is checked before a new funding plan is created, so repeatedly
starting the load cannot accumulate new plans behind an existing open one.

A node a block or two behind the network answers a read at a block it has not
applied with `UPSTREAM_UNAVAILABLE` (retryable) and error 651 "... is not
applied". Every read made by the operations and by `load` (refill and top-up
preflight, balances, seqnos) waits for that node, backing off from 0.5 s up to
4 s, for at most 30 s; it then fails with the node's answer and the same safety
stop as before. No other error is retried, `sendBoc` is never repeated, and the
two validators' answers must still agree.

### Destination settlement on busy accounts

Delivery is located by the outgoing message's hash and decoded `created_lt`,
starting with `lookupBlock` for the destination prefix and walking shard blocks
with `getBlockHeader` / `getBlockTransactionsExt`. It does not page the recipient's
whole account history. Full block identities, page progress and transaction BOC
hash/account/LT binding are checked, and both validators must agree on the result.
The same search confirms a withdrawal's retained owner receipt.

The operational envelope is 512 destination-shard blocks from message creation,
up to 128 pages of 256 transactions per block. Exhaustion or unavailable archive
blocks is an explicit unknown result, never a settled or failed payment. A missing
delivery stays pending. Signing-wallet history gates and expiry/consumed proofs
still require complete history; this change does not weaken those checks or
change any journal state automatically.

### Bootstrap wallet checkpoints

The coordinator bootstrap wallet has a pinned wallet-v3 code hash, genesis public
key and subwallet zero. Its gate audits from the latest verified checkpoint,
not from an increasingly old baseline. Other signing wallets are audited from
the newer of their manual baseline and their newest settled operation's own
transaction. That operation's gate read the wallet's history complete before it
signed, its settlement proved the transaction consumed exactly its seqno, and a
wallet v3 runs its externals in seqno order, so nothing the wallet sent can lie
between them. Validators prune transactions after about a day; without this an
owner wallet could not sign again a day after its last operation. A wallet with
no settled operation is still read in full. Checkpointing the election task's
messages is a separate follow-up, required before an operator wallet's history
grows past what the gate can read in full.

**Trust assumption:** the bootstrap signing key is custodied only by the
coordinator, and the local append-only journal is honest. The dry-run prints
this assumption. For an explicitly pruned interval, each consumed seqno must
have exactly one terminal operation whose wallet transaction hash was verified
on both validators when recorded. Its stored signed message must bind that
seqno, wallet, network, subwallet and transfer. The current active identity and
counter must agree on both validators. A matching counter alone, an unsigned
abandonment, an expired attempt, a broadcast or a manual baseline cannot explain
an outgoing effect. Incoming credits do not consume counters or send payments.
Timeout, empty history, disagreement and an unknown consumer still refuse.

To migrate an existing terminal bootstrap operation, use the same common
network arguments as `record`, first with no write:

```sh
python3 testnet/scripts/testnet-elections.py record \
  --ceremony "$CEREMONY" --tos-root "$TOS_ROOT" --fift "$FIFT" \
  --rpc "$RPC" --confirm-rpc "$CONFIRM_RPC" \
  --id "$TERMINAL_OPERATION" --checkpoint --dry-run
```

Review the origin, anchor, counter interval, both observations, receipt list and
custody assumption. On success and with authorization, repeat without
`--dry-run`. This cannot sign or broadcast; it appends a certificate to that
existing terminal operation without replacing its evidence. Repetition is
idempotent. No baseline or unrelated operation is changed.

Subsequent settlements append their certificate in the same synced terminal
journal line. Certificates bind the network, wallet incarnation, previous
digest, decoded transaction receipts and terminal consumer receipts. A fork or
regression refuses. If a payment settles but its prefix cannot be certified,
its true terminal result is retained with `checkpoint_refusal`; subsequent
spending remains blocked. `reconcile` checks the same prefix without writing.
