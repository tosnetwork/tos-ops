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
- Name the tos release tag and its `SHA256SUMS`. Every party installs that
  release; the coordinator builds `create-state`, `fift` and `gen_fif` from the
  same commit (`cmake --build build --target create-state gen_fif fift tos-pq-controller`).
- Confirm the four operators' identities out of band. The ceremony checks that
  each record is self-consistent; it cannot prove who sent it.

## 1. Operator: prepare the validator host

```bash
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role validator \
  --public-ip <PUBLIC_IPV4> --release /path/to/verified/release
```

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
sudo /opt/tos-testnet/scripts/install-node.sh prepare --role dht \
  --public-ip <PUBLIC_IPV4> --release /path/to/verified/release
```

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
