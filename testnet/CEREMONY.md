# Genesis ceremony and validator bring-up

The order of work for the four genesis operators (O1–O4), the DHT hosts and
the coordinator (C). Every artifact that crosses between parties is public;
each party keeps its own secrets on its own machines.

```
O: prepare host  ->  O: record  ----\
D: prepare DHT   ->  D: dht-node ----+->  C: manifest -> genesis -> global-config -> publish
                                                                                  |
O, D: activate (verify SHA-256, start before the epoch)  <-------------------------/
C: check-testnet.py across independent nodes
```

Paths below assume `testnet/` is installed at `/opt/tos-testnet` (root-owned,
world-readable) and release binaries in `/usr/local/bin`.

## 0. Before anything (coordinator)

- Decision D03: the global id is 2, confirmed 2026-10-12 (`network/profile.json`,
  status `CONFIRMED`; `genesis` refuses any other status). Freeze the genesis
  epoch, and announce both.
- Name the tos commit (full 40-character id). Every host compiles its own
  binaries from that commit (step 1). The coordinator builds `create-state`,
  `fift` and `gen_fif` from the same commit
  (`cmake --build build --target create-state gen_fif fift tos-pq-controller`).
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

Compile the binaries on this host from the ceremony commit, then prepare:

```bash
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev <COMMIT> --role validator
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role validator \
  --public-ip <PUBLIC_IPV4> --release /var/lib/tos-build/release-<COMMIT>
```

Never copy binaries from another machine. RocksDB compiles for the build
machine's CPU unless told otherwise, and a binary built on a newer Xeon
stopped with SIGILL (illegal instruction) on these hosts.
`build-node-binaries.sh` builds for `x86-64-v2`, as tos CI does, so a VM
migrated to an older CPU keeps working. It needs about 2.5 GiB of memory per
compile job and takes tens of minutes on a 6-core VM. To replace the binaries
of a prepared node later, stop it and run
`install-node.sh binaries --role <role> --release <dir>`.

This creates `/var/lib/tos/validator` and `/var/log/tos/validator` owned by
`tos`. It runs the first start with `-I <PUBLIC_IPV4>:30001` on a placeholder
global config (`/etc/tos/pregenesis-global-config.json`, never used to run a
node), and generates `/var/lib/tos/validator/keys/pq-consensus.seed`. It prints
the consensus `key_id` and public key. `<PUBLIC_IPV4>` is the address the
node announces; it must be static. The engine binds ADNL and QUIC by port on
all interfaces, so a host behind NAT works if the router forwards UDP 30001
and UDP 31001 to it. Two nodes behind the same NAT reach each other through
the announced public address, so the router must also support NAT hairpinning.

Back up the seed now, encrypted and offline (Production-Node.md section 3.1):

```bash
sudo -u tos tos-pq-consensus-key export /var/lib/tos/validator/keys/pq-consensus.seed | ENCRYPT > BACKUP
```

## 2. Operator: controller id (offline root key)

On the offline machine, create the controller root key and print its public
key (`tos-pq-key` is built from `crypto/pq/tools` in tos and installed only
offline):

```bash
tos-pq-key keygen ROOTSEED
tos-pq-key public ROOTSEED            # 1312-byte public key, hex
```

On any machine with the tos checkout and build of the ceremony commit:

```bash
python3 /opt/tos-testnet/scripts/testnet-operator.py controller \
  --tos-root "$TOS_ROOT" --tos-build "$TOS_ROOT/build" \
  --root-public <ROOT_PUBLIC_HEX> --key-id <CONSENSUS_KEY_ID> --out controller.json
```

`controller.json` holds the controller id, the code hash genesis admits in
ConfigParam 47, and the code, data and StateInit BOCs you will deploy with
after genesis. Keep it; it is public.

## 3. Operator: the public record

```bash
sudo -u tos python3 /opt/tos-testnet/scripts/testnet-operator.py record \
  --db /var/lib/tos/validator --seed /var/lib/tos/validator/keys/pq-consensus.seed \
  --controller-id <CONTROLLER_ID> --operator <short-name> \
  --address <PUBLIC_IPV4>:30001 --out /tmp/record.json
```

It refuses an address the node does not announce, and a key id that does not
match the public key. Send `record.json` to the coordinator by a channel that
authenticates you.

## 4. DHT host (at least two, run by the team)

```bash
sudo /opt/tos-testnet/scripts/build-node-binaries.sh --rev <COMMIT> --role dht --jobs 2
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role dht \
  --public-ip <PUBLIC_IPV4> --release /var/lib/tos-build/release-<COMMIT>
```

A validator host that also serves DHT builds both with
`build-node-binaries.sh --role validator --with-dht`.

Send `/var/lib/tos/dht/dht-node.json` (a signed, public `dht.node`) to the
coordinator.

## 5. Coordinator: manifest, genesis, global config

The record order is the validator index order; fix it before you start.

```bash
S=/opt/tos-testnet/scripts
python3 $S/testnet-coordinator.py manifest --ceremony ./ceremony --tos-root "$TOS_ROOT" \
  record-o1.json record-o2.json record-o3.json record-o4.json
export TOS_AUTH_NETWORK_TAG=<genesis.auth_network_tag.value in network/profile.json>
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
v1 policy identity `5e4380ae…`) and 48 is in both ConfigParam 9 and 10.
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
offline: it funds the four controllers for the first elections (genesis
bootstrap document, "First ordinary elections") and nothing else.

Publish, together and signed or attested by the release process:

- `global-config.json` and `global-config.json.sha256`
- `genesis.json`, `genesis-records.json`, `validator-pq.pub`
- `main-wallet.pub` and `wallets.json` (public keys and addresses only;
  `wallets.json` grows as `onboard` and `load` add their wallets, and the next
  reset reads it)
- `zerostate.boc`, `basestate0.boc` and their `.fhash`/`.rhash`
- `gen-zerostate-testnet.fif`, the exact template that ran

Anyone can regenerate the zero state from these and the named tos commit.

The epoch is the earliest time a block can be produced: until the validators'
clocks reach about epoch − 29 s, every candidate is rejected as being from the
future, and the nodes wait at height 0. Choose it at least 60 minutes after
this step, so that every node is activated before it. See
`production/Production-Node.md` section 8.3 for the rules behind this.

## 6. Everyone: activate before the epoch

Validator (operator), with the controller id from step 2:

```bash
sudo /opt/tos-testnet/scripts/install-node.sh activate --role validator \
  --global-config global-config.json --sha256 <PUBLISHED_SHA256> \
  --genesis ./published --validator-id <CONTROLLER_ID>
```

This installs `/etc/tos/global-config.json` only on a matching digest. It
places the zero state in `/var/lib/tos/validator/static/` and runs
`tos-pq-consensus-key bind-node` with the node stopped. It adds a console on
30002/tcp, with its client keys in `/var/lib/tos/validator/console-client/`,
and then starts `tos-testnet-validator`. Check the custody line:

```bash
journalctl -u tos-testnet-validator | grep 'post-quantum consensus custody'
grep 'post-quantum consensus custody' /var/log/tos/validator/node.log*
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
its times. The bootstrap set is valid for 21,600 s after the epoch T, and each
elected set for 14,400 s. The four operators must deploy their controllers,
authorize operations and stake through two overlapping elections
(Production-Node.md section 9). The first election opens at T + 4 h and closes
at T + 5.5 h; the elected set takes office at T + 6 h. The next election opens
at T + 8 h, and the set rotates every 4 h after that, each rotation a key
block. Everything has to be ready before the first window opens: the first
epoch's controllers were ready about 1.75 h after T.

The first epoch used the canonical template's schedule unchanged: a 131,072 s
bootstrap set and 65,536 s terms. Its first key block after genesis would have
come at T + 34 h. Until then the GC checkpoint could not move, so no state and
no consensus database was deleted, and at about 145 GB a day the 99 GB disks
would have filled in 15 hours. That is why this testnet runs a shorter
schedule and a 3,600 s validator `state_ttl`.

### 8.1 Onboarding a genesis validator for elections

On each validator host, once (after `build-node-binaries.sh`, same commit):

```bash
sudo /opt/tos-testnet/scripts/build-tosctl.sh --rev <TOS_COMMIT>
```

Then, from the coordinator's machine, with SSH tunnels to **two** validators'
loopback JSON-RPC (`ssh -L 18081:127.0.0.1:8081 root@<validator>` and another
on 28081 to a second validator), once per validator:

```bash
python3 /opt/tos-testnet/scripts/testnet-elections.py onboard \
  --name node-1 --host <HOST> --ssh-key <KEY> \
  --ceremony ./ceremony --controller controllers/node-1.json \
  --root-seed offline/root-node-1.seed --controller-tool "$TOS_ROOT/build/crypto/tos-pq-controller" \
  --tos-root "$TOS_ROOT" --fift "$TOS_ROOT/build/crypto/fift" \
  --rpc http://127.0.0.1:18081/jsonRPC --confirm-rpc http://127.0.0.1:28081/jsonRPC \
  --previous-ceremony ../epoch-1/ceremony   # after a reset: once per earlier epoch
```

It runs `init-operator.sh` on the host (vault, console key, operator wallet),
records the operator wallet's address as `op-<name>` in
`ceremony/wallets.json` and refuses an address an earlier epoch recorded (a
host that kept `/var/lib/tos-ctl` over a reset still has the old wallet key).
Then it runs these steps, in order:

1. it funds the wallet from the bootstrap wallet with fee and operating money
   only (`operator_funding_tos`, 150) and activates it;
2. it deploys the controller;
3. it creates the pool's **owner** on the coordinator (below), funds it and
   activates it;
4. it deploys the pool with 2 TOS from the operator wallet;
5. it configures the pool, the binding and the controller's birth in tosctl on
   the host;
6. the owner sends the stake principal (`pool_tos`) to the pool;
7. it plans the operating authorization on the host, signs it here with the root
   seed and sends it;
8. it checks readiness, which is tosctl's full assessment: no `[BLOCKING]` (capital
   reserve, a usable grant);
9. it runs `enable-elections.sh`, which installs
   `systemd/tos-testnet-elections.service` (`Restart=always`).

The amounts are `elections` in the profile. The root seed,
`ceremony/secret/main-wallet.pk` and the pool owners' keys never leave the
coordinator.

**Every step that moves value is an operation** (`testnet_ops.py`):

- `fund-op-<name>`
- `deploy-controller-<name>`
- `fund-owner-<name>`
- `activate-owner-<name>`
- `deploy-pool-<name>`
- `principal-<name>`
- `authorize-operations-<name>`

Each has a record in `ceremony/operations/<id>.jsonl`. The lines are append-only
and each is fsynced with its directory. The signed message is durable there
before it is broadcast, and a per-wallet lock is held until it is.

The operator wallet's messages are built and signed by tosctl on the host, but
**never broadcast there**: `wallet send --build-only` hands the message to the
coordinator. The coordinator decodes it and refuses anything but the intended
one, checking:

- the signing wallet;
- global id 2;
- the wallet's current seqno on both validators;
- an expiry within 120 s;
- send mode 3;
- the exact destination, value, bounce flag, StateInit and body.

Only then is the message journaled and broadcast from the coordinator. The pool is
deployed with the StateInit derived on the coordinator from the pinned
`single-nominator-code.hex` and the three roles.

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
steps (pool, binding, birth import) resume from what the host's tosctl
configuration already holds.

**A rerun never resends value.** When an operation is open, because a run was
interrupted or its message has not settled yet, the next run refuses and names
it. A person then resolves it:

```bash
S=/opt/tos-testnet/scripts/testnet-elections.py
C="--ceremony ./ceremony --tos-root $TOS_ROOT --fift $TOS_ROOT/build/crypto/fift \
   --rpc http://127.0.0.1:18081/jsonRPC --confirm-rpc http://127.0.0.1:28081/jsonRPC"
python3 $S reconcile $C                       # read only: every record against the chain
python3 $S record $C --id ID --settled --hint TXHASH
python3 $S record $C --id ID --failed a|b|c|d [--hint TXHASH]
python3 $S resubmit $C --id ID                # the original message, never re-signed
python3 $S baseline $C --wallet ADDR --reason TEXT
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

The single-nominator pool keeps three roles apart:

- the **owner** holds the principal and is the only role that can withdraw it;
- the **validator** is the operator wallet on the host, `op-<name>`. It can only
  send the principal to the Elector through the controller and recover it;
- the **controller** stands in the election.

Since epoch 4 the owner is not the operator wallet. `onboard` creates
`pool-owner-<name>`, a wallet v3 in the masterchain (subwallet `0x504F4F4C`), with
`new-wallet-v3.fif` on the coordinator:

- its key is `ceremony/secret/pool-owner-<name>.pk` (0600);
- its address and self-deploy message are in `ceremony/pool-owners/`;
- its address is in `wallets.json`;
- the pool, owner, operator and controller are in `ceremony/pools.json`.

The bootstrap wallet funds the owner with `pool_tos` + 5 TOS. Before the
principal is signed, the coordinator checks four things: the owner's funding and
activation are settled operations; the pool is the derived address; the pool runs
the pinned code; and its `get_roles` is exactly the offline owner, the operator
wallet and the controller.

A compromised validator host can therefore stake and recover, but it can neither
take the principal nor have it sent elsewhere. The owner can also replace the
validator address (`CHANGE_VALIDATOR_ADDRESS`).

To take principal out, between elections (a stake at the Elector comes back
to the pool only when the election task recovers it, `stake_held_for` after
its term), name the withdrawal's operation id:

```bash
python3 $S withdraw $C --name node-1 --id withdraw-node-1-1 --new (--amount <TOS> | --all)
python3 $S withdraw $C --name node-1 --id withdraw-node-1-1      # its outcome again, nothing sent
```

`--new` creates the id. Without it, only an existing id is accepted, and its
parameters can never change. The command works in five steps:

1. It builds the pool's WITHDRAW body (op `0x1000`) with the pool's own
   `crypto/smartcont/single-nominator-pool/withdraw.fif`.
2. It signs, on the coordinator with the offline key, a bounceable 1 TOS transfer
   from the owner wallet carrying that body. The pool sends the amount and the
   unspent value back to the owner.
3. It refuses while an election is open (`--during-election` overrides).
4. It checks the pool's address, the pinned code and its **owner** role. The
   validator role is not checked, because the owner may have replaced it.
5. It settles only when both validators show the pool's payment and the owner
   wallet's transaction that **retained** it: credit equal to the payment, compute
   success, no message sent on. The result is appended to
   `ceremony/withdrawals.jsonl`.

`check-testnet.py` refuses a `genesis.json` of version 16 or later that records no
`auth_policy`, so this branch's checker does not accept epoch 3's genesis (version
16, written before ConfigParam 48 existed); check epoch 3 with the main branch's
until it is retired.

The election task runs as the non-login system user `tos-ctl`, never root.
Every `tosctl` call on the host, from these scripts and from
`testnet-elections.py` over SSH, runs as `tos-ctl` too (`runuser -u tos-ctl`,
with root only reading `/etc/tos/tosctl.env`, root-owned 0600), and the
controller's birth transaction is written into `/var/lib/tos-ctl` as `tos-ctl`:
tosctl refuses a vault, lock or key file its caller does not own, so one
root-owned file there stops the task. A host onboarded while the task ran as
root moves over once with `migrate-nonroot-services.sh --role validator`
(testnet/README.md), outside an open election.

`testnet-elections.py fund --id ID --label LABEL` sends from the bootstrap wallet
on its own as operation ID (with `--dry-run` it only signs). `load` makes each
bootstrap transfer its own operation.

A step whose operation failed terminally is never retried under its id and never
reset. A person starts another attempt, `ID.attempt-N`, which names the failed
one and keeps the step's parameters (an operating authorization is planned
anew); all checks run again:

```bash
python3 $S retry $C --step ID --reason TEXT
```

**`refund` is disabled for the epoch-4 launch**: it sends from the operator wallet
over tosctl on the host, outside the journal, and refuses before it reads, signs
or stops anything. It becomes an operation in a follow-up due before the fifth
election (T + 19 h), when the 20 TOS of the first authorization (about four
stakes) run out. A settled authorization cannot be renewed with `retry` (that is
for failed attempts only); until the follow-up there is no supported renewal.

The operating authorization funds relays for a limited time (the first epoch's
gave about three days of runway). `tosctl controller operations status
--controller <C>` on the host shows the runway; renew it before it ends, once
per validator, with the same arguments as `onboard`:

```bash
python3 /opt/tos-testnet/scripts/testnet-elections.py refund \
  --name node-1 --host <HOST> --ssh-key <KEY> \
  --ceremony ./ceremony --controller controllers/node-1.json \
  --root-seed offline/root-node-1.seed --controller-tool "$TOS_ROOT/build/crypto/tos-pq-controller" \
  --tos-root "$TOS_ROOT" --fift "$TOS_ROOT/build/crypto/fift" \
  --rpc http://127.0.0.1:18081/jsonRPC \
  [--target-nanotos N] [--dry-run]
```

It plans the renewal on the host (funds target
`elections.authorization.refund_target_nanotos`, 260 TOS or ten days of
stakes, or `--target-nanotos`), signs
it locally with the root seed, stops `tos-testnet-elections` (it holds the
tosctl vault lock) only around the send from the operator wallet (as
`tos-ctl`, like every tosctl call) and always starts it again, then checks that the root authority nonce advanced, the
stakes remaining grew and no `[BLOCKING]` warning remains. Each sent refund is
appended to `ceremony/refunds.jsonl`. `--dry-run` plans, checks and signs, and
sends nothing.

Two refusals guard the next election:

- The operator wallet pays both the refund and every stake: the election task
  sends 20 TOS with each stake and will not stake below 20.2 TOS. A refund that
  left 17.77 TOS once kept all four validators out of an election. `refund`
  therefore refuses, before signing, when the wallet would keep less than
  `elections.authorization.operator_reserve_nanotos` (30 TOS) after the
  message value and a 1 TOS fee allowance, and names the top-up to send first
  with `testnet-elections.py fund`.
- It runs only in the quiet part of a term: not while the Elector has an
  election open (or finished but not yet installed), and not within 10 minutes
  after the current set took office or before the next election opens
  (ConfigParam 34 `utime_until` minus `elections_start_before`). The times come
  from the chain, not from `genesis.json`, because a failed election moves
  every later rotation; while an election keeps failing, `refund` keeps
  refusing. `--i-checked-the-window` overrides this after a manual check, for
  example when a controller's exhausted funds are what blocks the stakes.

If the first election cannot be conducted, the Elector cancels it at
`elect_at` and refunds the stakes. The chain does not stop: the genesis set
keeps validating past its `utime_until`. But no key block is produced and state
GC stops behind the last one, so disks grow until a later election succeeds.
Treat it as an incident.

## 9. Resetting the testnet

A reset is a new genesis with the same global id 2, so it shares the old
epoch's replay domain. Every operator generates a new controller root key and
a new consensus seed; never carry them over. The coordinator passes every
earlier epoch's `genesis-records.json` to `manifest --previous`, which refuses
any reused controller id, consensus key id or ADNL id. Validators that joined
an earlier epoch after genesis are not in those files. Keep their records and
pass them too.

Wallet keys are checked the same way. Keep every epoch's ceremony directory
(its `wallets.json`, `genesis.json` and `secret/`), and pass each one with
`--previous-ceremony` to `testnet-coordinator.py genesis` (the bootstrap
wallet: always at -1:111...1, so only its key differs between epochs),
`testnet-elections.py onboard` (operator wallets) and `testnet-elections.py
load` (the high-volume wallet and its relayers; start every epoch with a new
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
