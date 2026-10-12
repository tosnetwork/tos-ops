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

`genesis` refuses a dirty tos checkout and a template whose mainnet lines
changed. It generates the zero state twice and compares the outputs. It moves
`main-wallet.pk`, the only secret output, to `ceremony/secret/`. Take that key
offline: it funds the four controllers for the first elections (genesis
bootstrap document, "First ordinary elections") and nothing else.

Publish, together and signed or attested by the release process:

- `global-config.json` and `global-config.json.sha256`
- `genesis.json`, `genesis-records.json`, `validator-pq.pub`
- `zerostate.boc`, `basestate0.boc` and their `.fhash`/`.rhash`
- `gen-zerostate-testnet.fif`, the exact template that ran

Anyone can regenerate the zero state from these and the named tos commit.

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

The bootstrap set is valid for 131,072 s after the epoch T. The four operators
must deploy their controllers, authorize operations and stake through two
overlapping elections (Production-Node.md section 9). The first election opens
at T + 27.3 h and closes at T + 34.1 h; the elected set takes office at
T + 36.4 h. Everything has to be ready before the window opens. The timeline is
in the memo plan, `public-testnet/README.md` section 5.4.

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
