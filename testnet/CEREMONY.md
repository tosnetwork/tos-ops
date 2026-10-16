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
python3 $S/testnet-coordinator.py genesis --ceremony ./ceremony --tos-root "$TOS_ROOT" \
  --tos-build "$TOS_ROOT/build" --epoch <EPOCH>
python3 $S/testnet-coordinator.py global-config --ceremony ./ceremony dht-1.json dht-2.json
```

After a reset, add the earlier epochs to both steps, once per earlier epoch
(section 9): `manifest --previous <old>/genesis-records.json` and
`genesis --previous-ceremony <old>`.

`genesis` refuses a dirty tos checkout and a template whose mainnet lines
changed. It generates the zero state twice and compares the outputs. Between
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
fresh, and ConfigParam 34 is the four genesis identities. Run it from two
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

Then, from the coordinator's machine, with an SSH tunnel to one validator's
loopback JSON-RPC (`ssh -L 18081:127.0.0.1:8081 root@<validator>`), once per
validator:

```bash
python3 /opt/tos-testnet/scripts/testnet-elections.py onboard \
  --name node-1 --host <HOST> --ssh-key <KEY> \
  --ceremony ./ceremony --controller controllers/node-1.json \
  --root-seed offline/root-node-1.seed --controller-tool "$TOS_ROOT/build/crypto/tos-pq-controller" \
  --tos-root "$TOS_ROOT" --fift "$TOS_ROOT/build/crypto/fift" \
  --rpc http://127.0.0.1:18081/jsonRPC \
  --previous-ceremony ../epoch-1/ceremony   # after a reset: once per earlier epoch
```

It runs `init-operator.sh` on the host (vault, console key, operator wallet),
records the operator wallet's address as `op-<name>` in
`ceremony/wallets.json` and refuses an address an earlier epoch recorded (a
host that kept `/var/lib/tos-ctl` over a reset still has the old wallet key),
funds the wallet from the bootstrap wallet, activates it, deploys the
controller and the pool, binds them, imports the controller's birth, plans the
operating authorization on the host, signs it locally with the root seed and
sends it, and runs `enable-elections.sh`, which installs
`systemd/tos-testnet-elections.service` (`Restart=always`). The amounts are
`elections` in the profile. A rerun continues where a failed run stopped. The
root seed and `ceremony/secret/main-wallet.pk` never leave the coordinator;
every signed bootstrap transfer is kept in `ceremony/sent/`.

The election task runs as the non-login system user `tos-ctl`, never root.
Every `tosctl` call on the host, from these scripts and from
`testnet-elections.py` over SSH, runs as `tos-ctl` too (`runuser -u tos-ctl`,
with root only reading `/etc/tos/tosctl.env`, root-owned 0600), and the
controller's birth transaction is written into `/var/lib/tos-ctl` as `tos-ctl`:
tosctl refuses a vault, lock or key file its caller does not own, so one
root-owned file there stops the task. A host onboarded while the task ran as
root moves over once with `migrate-nonroot-services.sh --role validator`
(testnet/README.md), outside an open election.

`testnet-elections.py fund` sends from the bootstrap wallet on its own (with
`--dry-run` it only signs).

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
