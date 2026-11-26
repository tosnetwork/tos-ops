# Genesis ceremony and validator bring-up

The order of work for the genesis operators, the external validator operators,
the DHT hosts and the coordinator (C). Every artifact that crosses between
parties is public; each party keeps its own secrets on its own machines.

The December 5, 2026 network has two kinds of registered validator:

- **The genesis set** (`genesis.validators` = 2): the team's two validator
  hosts (O1, O2). They are the zero state's validator set (ConfigParam 34) and
  validate alone until the first election's set takes office at T + 24 h.
- **External validators** (E of them, at most `elections.max_external_validators`
  = 19): operators who register a record and a pool before genesis
  (registration closes on November 30) exactly like O1 and O2, but are not in
  the zero state. They are onboarded after genesis by
  `testnet-elections.py onboard --no-host` and `testnet-operator.py onboard`
  ([Onboarding an operator-run host](#onboarding-an-operator-run-host)) and stand
  from the first election (opens at T + 12 h, closes at T + 22 h).

`manifest` writes both: `genesis-set.json` (the zero state's set) and
`genesis-records.json` (every registered record, the genesis set first).
Onboarding accepts any pool `genesis-records.json` names; a pool in
`genesis-set.json` is a team pool and stakes the team multiple (below).

### Stake, weight and funding: set after registration closes

Each external pool stakes one unit (`elections.stake_tos`, 10,002 TOS). The
Elector records a pool's stake as the stake plus what is left of the 1.2 TOS
stake order (`stake_order_nanotos`) after the pool's fees
(`pool_new_stake_cost_nanotos`) and the Elector's own 1 TOS: measured in the
rehearsal as stake + 0.1788215 TOS, so a unit stands as 10,002.1788215. Each
team pool stakes `elections.team_stake_multiple` = (E+1)/2 units, at least one:
its order is multiple x (10,002 - 1) + 1 TOS, rounded down, which keeps its
credit at most multiple x a unit's credit whatever the Elector adds. TOS finalizes
with **at least** two thirds of the weight (tos `quorum.h` `has_quorum`:
signed x 3 >= total x 2). With both team pools elected the team holds E+1 units
against E, just above half; with one team pool absent from an election the
external validators hold 2E/(3E+1) of the weight, strictly below two thirds. So
the external validators can never finalize without the team (the hard
invariant), and with every pool elected neither side finalizes alone. E is known only when registration closes, so the profile ships
with `elections.external_validators`, `elections.team_stake_multiple`,
`elections.bootstrap_wallet_tos` and `genesis.total_supply_tos` set to `null`,
and `manifest`, `genesis` and team onboarding refuse until they are set. After
November 30 the coordinator runs

```bash
python3 $S/testnet-coordinator.py plan --external-validators <E>
```

and copies the four values it prints under `set_in_profile` into
`network/profile.json` (reviewed and committed like any profile change).

In the same change, set the validator disk floor (`host_requirements` validator
`min_disk_free_gib`) for the real set size N = 2 + E, using the arithmetic in
section 8:
- the consensus and state rate scales with the ceil(2N/3) signatures each
  certificate carries;
- the archive rate scales the same way;
- add the load-window allowance, the base, 15 % headroom and the 20 GiB stop
  level.

The 160 GiB default is the value for N = 21. Never set the floor below what this
arithmetic gives, and publish the final floor in the December 1–4 packet. The
invitation tells participants that the packet's floor is the binding one.

The
plan is `testnet_lib.election_plan`: it simulates the Elector's choice
(`elector-code.fc` `try_elect`) and refuses unless an election of the two team
pools alone concludes and elects both (E = 0 included), all 2 + E pools are
elected with no team stake cut by a max factor, the external validators hold
less than two thirds of the weight with every pool elected and with either team
pool absent, and from E = 3 the team's share is in [50 % (`team_weight_percent`),
two thirds). The team holding two thirds is the safe direction and is allowed:
the plan reports it as `team_finalizes_alone` (at E = 0 and 1), and under
`partial_sets` it reports every set of k standing external validators (for which
k the team finalizes alone) and the set with one team pool absent.
Every load of a profile with E set repeats the check, so a wrong bootstrap total
or multiple refuses. The bootstrap wallet is every pool's operator funding and
owner funding (principal + `pool_owner_reserve_tos` + `pool_deploy_tos`), a
margin of `bootstrap_margin_tos_per_pool` (13 TOS, epoch 6's 50 TOS for four
pools rounded up) for every pool, since what it covers, a retried funding
transfer or a fee rise, happens per pool and the sweep burns what is left, and
`bootstrap_transfer_fee_nanotos` for each of its 2 x (2 + E) + 1 transfers,
rounded up.

| E | team multiple | team stake order (TOS) | bootstrap wallet (TOS) | team weight | team finalizes alone | externals' weight, one team pool absent |
|---|---|---|---|---|---|---|
| 0 | 1 | 10,002 | 40,081 | 100.0 % | yes | — |
| 1 | 1 | 10,002 | 60,121 | 66.7 % | yes | 50.0 % |
| 2 | 1.5 | 15,002 | 100,161 | 60.0 % | no | 57.1 % |
| 3 | 2 | 20,003 | 140,205 | 57.1 % | no | 60.0 % |
| 4 | 2.5 | 25,003 | 180,245 | 55.6 % | no | 61.5 % |
| 5 | 3 | 30,004 | 220,289 | 54.5 % | no | 62.5 % |
| 10 | 5.5 | 55,006 | 420,497 | 52.4 % | no | 64.5 % |
| 19 | 10 | 100,011 | 780,877 | 51.3 % | no | 65.5 % |

At E = 0 and E = 1 the team holds two thirds or more and finalizes alone; that
is accepted degradation, the network then runs on the team. The same holds in
any election in which few external validators stand: at E = 19 the team
finalizes alone with up to 9 standing external validators.

A team pool's stake orders carry max factor 10.0 (`elections.max_factor`), so a
team stake of up to 10 units (E = 19: an order of 100,011 TOS, credited as
100,011.1788215, under the cap of 10 x 10,002.1788215) counts in full against
the one-unit external stakes;
ConfigParam 17 allows 10. This needs a tosctl that accepts a max
factor from 1.0 to 100.0 (the bound of upstream's `validator-elect-req.fif`);
releases before that change stop at 3.0. Team onboarding probes the host's
tosctl on a throwaway copy of its configuration before any value moves, and
refuses one that rejects 10.0 or does not read it back, and
`enable-elections.sh` refuses again when it sets the factor, so an old tosctl
fails loudly instead of capping the team's weight. External pools keep
tosctl's default 3.0 (`elections.external_max_factor`): their stakes are the
smallest in the set and are never capped.

The election limits are genesis values (`genesis.validator_num`,
`genesis.stake_limits`): ConfigParam 16 is 21 / 21 / 2 (an election the team
alone stands in concludes), and ConfigParam 17 is 10,000 / 10,000,000 /
**20,000** / 10. The template's `min_total_stake` of 40,000 TOS would postpone a
team-only election, whose two unit stakes are 20,004.357643 TOS in the Elector;
20,000 is the floor at which two minimum stakes still elect.

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

For host tasks and failure handling, use [OPERATOR.md](OPERATOR.md). Follow the
standing testnet fee authority and other live-operation approval boundaries in
[AGENTS.md](../AGENTS.md); delegated operational fee top-ups need no per-payment approval.
Commands here are templates, not permission to execute. The reference tos build
is `85c679c3454f306eb867e25b1960ae3d757bd3dd`; pin the approved ceremony commit.

Paths below assume `testnet/` is installed at `/opt/tos-testnet` (root-owned,
world-readable) and release binaries in `/usr/local/bin`.

## 0. Before anything (coordinator)

- **The team's two validator hosts need at least 200 GB disks (250 GB
  recommended), and the preflight must pass them at the 160 GiB floor with no
  disk waiver. Owner action: budget.** The epoch-6 to 8 team VPSs had about 70
  GiB free on about 98 GiB disks. The two team validators hold more than half of
  the weight: a full disk on both halts the chain, and on either one leaves the
  chain needing most of the external validators online (16 of 19 at E = 19).
  Do not waive the floor for them.

- Decision D03: the global id is 2, confirmed 2026-10-12 (`network/profile.json`,
  status `CONFIRMED`; `genesis` refuses any other status). Freeze the genesis
  epoch, and announce both.
- Name the tos commit (full 40-character id). Every host compiles its own
  binaries from that commit (step 1). The coordinator builds `create-state`,
  `fift` and `gen_fif` from the same commit
  (`cmake --build build --target create-state gen_fif fift`).
- Confirm every registered operator's identity out of band, the team's and
  each external one's. The ceremony checks that each record is self-consistent;
  it cannot prove who sent it.
- **Coordinator Python environment.** `testnet-elections.py` imports
  `pytosiq_core` (through `load_finality_window` and `load_finality`) for every
  subcommand, `pool` included, so run it, and `check-testnet.py`, with the tos
  checkout's own virtualenv: `"$TOS_ROOT/.venv/bin/python"`, where `$TOS_ROOT`
  is the tos checkout at the ceremony commit and its `.venv` has the tos test
  package installed editable (`"$TOS_ROOT/.venv/bin/pip" install -e
  "$TOS_ROOT/test/tostester"`, which provides `pytosiq_core`). A system
  `python3` fails with `ModuleNotFoundError: pytosiq_core`. Operator hosts need
  none of this: `testnet-operator.py` and the host scripts use the standard
  library only.
- **The whole tos-ops checkout, not `testnet/` alone.** `check-testnet.py` and
  `testnet-elections.py` load `production/network_check.py` from the directory
  beside `testnet/` (`<tos-ops>/production`). Run them from a full tos-ops
  checkout at the ceremony commit, or install `production/` next to
  `/opt/tos-testnet` as `/opt/production`.

### Rehearsed

The operator-run onboarding and the first elections of this configuration were
rehearsed on 2026-11-24 with tos-ops 5268121 and tosctl 6be232ff8, at E = 2 on
four isolated hosts of one machine with a shortened election schedule: genesis
with the two-validator set, `onboard --no-host` and
`testnet-operator.py onboard` for both external pools, team pools staking
15,002 TOS with max factor 10.0 and external pools 10,002 TOS with 3.0, two
elections electing all four pools, and stake recovery. Every item passed. The
measured team share was 59.99826 %, which `election_plan` now reproduces
exactly; the one defect found, a `-1:` address given as a separate argument, is
fixed in 8257324. The record is the memo's
`public-testnet/DEC5-REHEARSAL-20261124.md`.

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

**Continuously, on every validator, team or external.** The validators come
from many time zones, and every one keeps its clock disciplined by NTP for the
whole test: ntpsec (installed by `setup-time.sh`, the supported path) running
with a selected source,
within 100 ms of NTP time. The limit follows consensus timing: a candidate is
validated no earlier than 300 ms (`min_block_interval`) after its parent by the
local clock, and slots target 400 ms, so 100 ms is a third of the minimum
interval; a disciplined VPS clock stays within a few milliseconds.

- **All times are UTC**, whatever an operator's local time zone; hosts may
  keep any time zone setting, since the kernel clock and NTP are UTC either way.
- **Refused at start:** `preflight.py --local` fails the `time` check (not
  waivable) on an unsynchronised clock, on a clock ntpsec does not discipline
  (chrony and systemd-timesyncd are not the supported path), with no selected source
  or beyond 100 ms; `install-node.sh activate --role validator` and
  `enable-elections.sh` refuse to start on a clock `check-clock.py` rejects.
  They gate the first activation and every enabling of elections, not a
  service restart or a reboot, which must not wait on NTP; the daily check,
  the operators' cron alarm (`--boot-grace 900`) and the watch below cover
  the clock from then on.
- **Daily check** on every validator host: `python3
  /opt/tos-testnet/scripts/check-clock.py`, expected `clock ok: ntpd with 1
  selected source, offset ... ms (limit 100 ms), NTPSynchronized=yes`, exit 0
  ([OPERATOR.md §2](OPERATOR.md#2-host-requirements-clock-and-preflight) gives the
  operators a cron alarm that runs it every 10 minutes).
- **Monitoring, team hosts:** `watch-testnet.py` reads the clock in every
  round (`check-host-disk.py` reports `clock_synced`, `clock_daemon`,
  `clock_sources`, `clock_offset_ms`) and raises `<host>:clock_unsynced`
  (NTPSynchronized not yes, no ntpd, or no selected source, for
  `--clock-samples` rounds in a row, 3 by default, so a reboot's few minutes
  before ntpd selects a source do not alarm) or
  `<host>:clock_offset=<ms>ms` beyond `--max-clock-offset-ms` (default 100), which
  the alert relay forwards like every anomaly. Treat either as an incident: the
  host's votes lag by its offset (a clock behind) or its candidates are held
  until the other clocks reach their timestamps (a clock ahead, refused beyond
  30 s) until it is fixed. The offset is ntpd's system offset as local clock
  minus NTP time: positive = ahead.

## 0.5 Preflight every host

Every host is checked against the same floors before anything is installed,
but who runs the check depends on who runs the host. The coordinator never logs
in to a host an external operator runs: no SSH, no remote command, no tunnel.

**External operators, on their own hosts** ([OPERATOR.md §2](OPERATOR.md#2-host-requirements-clock-and-preflight)):

```bash
sudo python3 /opt/tos-testnet/scripts/preflight.py --local --name <NODE_NAME> \
  --role validator --public-ip <PUBLIC_IPV4> --out /tmp/preflight-<NODE_NAME>.json
```

The same facts script and the same checks (below, without SSH) run locally,
judged against the same profile floors; the operator sends the JSON report
(`tos-testnet.preflight-local.v1`, public facts only) to the coordinator, who
reviews it before step 1: `passed` true, no FAIL, and the expected name,
address and floors. A waiver the coordinator records for such a host is passed
by the operator as `--waive CHECK=REASON` and shows in the report's `waive`
entries. Those entries are self-attested: the coordinator compares them with its
own recorded decision and rejects a report carrying any other waiver or reason.
`passed` means no FAIL among the checks that were not waived.

The UDP mesh cannot be run without logging in to both ends, so for an external
host ingress is proven by a listener and a sender instead: the operator
captures with `--local --listen-seconds N --expect-from SENDER@<SENDER_IPV4>`,
and a different machine (one the operator controls, or the coordinator's own)
runs `preflight.py --send-probes --name SENDER --to <PUBLIC_IPV4> --role
validator`. Sending probes to a public port needs no access to the host. The
listener captures on the interface of the host's IPv4 default route (not `any`)
and does not count a probe whose source is a loopback address, an address of the
host itself, or, with `@<SENDER_IPV4>`, any other address, so a host cannot pass
by probing itself. Each role port must PASS for each expected sender. Without that test the report's `udp` line is
a WARN: syncing later shows only that the node reaches the network, not that
the network reaches it, so ingress stays unproven until the node validates.

**Team-operated hosts** (the DHT hosts, the coordinator's own validators), from
the coordinator's machine against an inventory of those hosts only (format:
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

It then has every inventory host send UDP probes to every other inventory
host's role ports, while each target captures with tcpdump. A probe that never arrives was dropped
outside the VM. Fix every FAIL before step 1. It is safe to rerun on live
nodes; a port held by `validator-engine` or `dht-server` passes.
`--accept-new-host-keys` accepts only a first-seen host key; a changed key
still stops SSH, and must be checked against the provider console first.

A host below a role floor needs a recorded decision, not a lower profile floor:
give it a per-host `"waive"` entry in the inventory for the `memory`, `cpu` or
`disk` check, each with the reason and where it was decided. The check then
reports `WAIVED` with the measured value and the reason, and does not fail the
run. Nothing else can be waived; a cpu waiver covers the CPU count, never
missing x86-64-v2 instructions. A validator under a memory waiver is activated
with lower caches and cgroup limits (section 6).

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
`--rev` refuses a release whose `BUILD-INFO` names another commit. All
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
  --operator=<ADDRESS> --ceremony ./ceremony --tos-root "$TOS_ROOT" \
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
  --validator-id=<VALIDATOR_ID> --operator <short-name> \
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

The positional records are the genesis set, exactly `genesis.validators` of them,
in validator index order; fix it before you start. Each external validator's
record is an `--external` record, exactly `elections.external_validators` of
them. The ceremony directory holds only what step 2 wrote; `manifest` refuses
anything else in it, a record whose validator id is not one of the pools
recorded in `ceremony/pools.json`, a recorded pool no record names, and two
records that share an identity or a host. The tos packer
(`scripts/prepare-pq-genesis-manifest.py`) takes exactly four records, so a
two-validator `validator-pq.pub` is packed by the coordinator alone; `genesis`
then reads the validator set back from the zero state and refuses unless it is
exactly `genesis-set.json` (a known limit; see [Known limits](#known-limits)).

```bash
S=/opt/tos-testnet/scripts
python3 $S/testnet-coordinator.py manifest --ceremony ./ceremony --tos-root "$TOS_ROOT" \
  record-o1.json record-o2.json \
  --external record-x1.json --external record-x2.json   # one per external validator
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
changed. Besides the mainnet pins and the schedule it replaces the genesis set
size (the manifest loader's length check and loop), ConfigParam 16, ConfigParam
17 and the bootstrap balance (`testnet_lib.patch_genesis_set`), and it reads
ConfigParam 16 and 17 and the validator set back from the zero state: the
profile's limits, and exactly the genesis set in order, all main validators of
equal weight (`genesis.json` `genesis_set`, with the plan as `election_plan`). It generates the zero state twice and compares the outputs. Then it
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
`elections.bootstrap_wallet_tos` (the plan's, set after registration) and the
state exactly `genesis.total_supply_tos` (the wallet plus the Elector's and the
Config contract's 500 each), each account's balance, the accounts dictionary and
`total_balance` agreeing; and ConfigParam 15 read back from the state must be the
profile's schedule. ConfigParam 5 comes from the canonical template, so
`--tos-root` must be at a tos commit that carries it. `genesis.json` records the result as
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
offline: it funds every registered validator's operator wallet and pool owner
for the first elections (tos `doc/validator-genesis-bootstrap.md`, "First
ordinary elections") and nothing else; once two elected sets hold every
registered pool's stake, the
[sweep](#sweeping-the-bootstrap-wallet) burns what is left and deletes the wallet.

AUTH validation and the complete summary are checked in `run-a` before any
key or output is published. Existing outputs are never overwritten. If genesis
fails, do not publish its partial outputs: a rerun refuses the retained scratch
runs or publication artifacts. Preserve any keys already created and start a
new ceremony directory; repeat the manifest step there. `genesis.json` is the
last published artifact and marks completion.

Publish, together and signed or attested by the release process:

- `global-config.json` and `global-config.json.sha256`
- `genesis.json`, `genesis-set.json`, `genesis-records.json`, `validator-pq.pub`
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
  --genesis ./published --genesis-ceremony --validator-id <VALIDATOR_ID>
```

On a host under a memory waiver (section 0.5), add the reviewed limits, for
example `--cache-bytes 268435456 --memory-max 2400M --memory-high 2200M`.
`--cache-bytes` lowers both RocksDB caches from the unit's 1 GiB (64 MiB at
least, never above 1 GiB); `--memory-max` and `--memory-high` become the unit's
cgroup limits, each leaving at least 1 GiB beside the two caches. activate
writes them as `/etc/systemd/system/tos-testnet-validator.service.d/50-resources.conf`
and records them in `/etc/tos/validator-resources.json`. It refuses the options
for any other role or step, refuses values out of range, and refuses an
existing drop-in that the options do not reproduce. Never edit the drop-in by
hand. The caches bound only part of the engine's memory: consensus candidates,
memtables and allocator retention are not cache-bounded, so watch such a node
for memory pressure and cgroup OOM kills under load.

This installs `/etc/tos/global-config.json` only on a matching digest. It
places the zero state in `/var/lib/tos/validator/static/` and runs
`tos-pq-consensus-key bind-node` with the node stopped. `--genesis-ceremony`
then runs `tos-pq-consensus-key init-signing-ledger --genesis-ceremony` for
the same validator id and this zero state: the node's signing ledger records
that the identity has never signed. **This step is required for every genesis
validator.** A validator without a signing ledger treats its earlier signing as
unknown and signs nothing until a masterchain block generated at least 91 s
after it took custody of its key; if every genesis validator waits, no block is
ever produced and the chain does not start. The node then logs, at the
zerostate, `no signing ledger at genesis`. Pass `--genesis-ceremony` only for a
consensus key generated for this epoch in step 2 that has never signed. A
validator that joins after genesis never runs it. It adds a console on
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
  --genesis ceremony/genesis.json --genesis-set ceremony/genesis-set.json \
  --rpc http://127.0.0.1:18081 --rpc http://127.0.0.1:28081    # SSH tunnels to two nodes
```

It passes only when the nodes share the ceremony's zero state and one full
block id at the common head, that block carries the testnet global id and is
fresh, ConfigParam 34 is the genesis set's identities, and (for a genesis.json
with `auth_policy`) live ConfigParam 48 carries the genesis tag and is
mandatory and critical, with ConfigParam 8 at version 16 or later. Run it from two
places that do not share infrastructure (plan G0: two independent observers).
After the first ordinary election, drop `--genesis-set`.

## 8. After genesis

### Liveness: what keeps blocks final

A block is final with at least two thirds of the elected set's weight. The plan
reports, under `liveness`, how many external validators must be online:

- **Before the first elected set (T to T + 24 h)** the set is the two team
  validators: both must be up.
- **Both team validators up:** the team holds just over half, so the chain
  needs about a third of the external weight online. At E = 19 that is
  7 of the 19 external validators.
- **One team validator down:** the remaining team validator holds about a
  quarter, so the chain needs most of the external weight. At E = 19 that is
  16 of the 19.
- **The first election elects every external that staked**, synchronized or
  not: a pool whose node is not in sync stands with its weight and does not
  sign, and counts as offline in the numbers above until it is.
- **A validator that fails stays elected for up to about 36 h.** Its election
  task stakes when the window opens, 12 h before the next term, so a validator
  that fails after that is in the next set too: offline weight for the rest of
  the current term and the whole next one, up to 12 h + 24 h. Bring a failed
  validator back fast; it leaves the set only at the first term whose election
  it did not stake in.

**Both team pools absent from an election** is the one case the stakes do not
cover. The hard invariant holds with either team pool absent, but if both team
pools miss an election at E >= 2, the external validators elect themselves and
hold all of the weight (the plan reports it as
`partial_sets.both_team_pools_absent`). It is plausible: both team hosts run the
same tosctl release and the same election configuration, so one fault can stop
both stake orders. Runbook check, every election: once its window opens and
before it closes (the window is `elections_start_before` to
`elections_end_before` before the next term, T + 12 h to T + 22 h for the
first), confirm that the Elector holds both team pools' stakes for that
election, from a node the coordinator reads:

```bash
lite-client -C global-config.json -c 'runmethod -1:3333333333333333333333333333333333333333333333333333333333333333 participant_list'
```

Each entry is `[validator id, stake]`, the id printed as a decimal integer and
the stake in nanotos (`python3 -c 'print(int("<hex id>", 16))'` converts a
`genesis-set.json` id). Both team validator ids must be in the list, each with
the team stake as the Elector credits it (the plan's `team_credit_nanotos`,
`team_stake_tos` + 0.1788215 TOS). A missing team stake is an incident:
check `journalctl -u tos-testnet-elections` on that team host, fix the election
task and let it resubmit while the window is open; if the window closes without
both, announce it and decide before the set takes office whether to continue.
No monitor raises this today (see [Known limits](#known-limits)).

**An election that does not conclude is a stall at its close, not at the
handover.** If no ConfigParam 36 (the next set) appears when the window closes,
at H + 22 h for a handover due at H + 24 h, the election failed (too few stakes,
or `min_total_stake` not met), and the current set will keep validating past
its term with no key block, so GC stops and the disks fill. Check it at every
close, 15 minutes after:

```bash
lite-client -C global-config.json -c 'getconfig 36'
```

`ConfigParam(36) = (null)` (no next set) at close + 15 min starts the stall
procedure at once: the
coordinator announces it in the official channel, then decides and announces
within 12 hours of that close whether the network continues (the Elector
retries the election when new stakes arrive), restarts from a new genesis or
ends. No watch raises this today ([Known limits](#known-limits)).

A halt shows first as head age. `watch-testnet.py` (`--max-head-age`, default
120 s) reports `ANOMALY <host>:head_age=...` and, with `--stuck-samples`, a head
seqno that stops moving, and the alert relay forwards it; `check-testnet.py`
across independent nodes refuses with the lag of each node. An election that
does not conclude keeps blocks going but makes no key block: the next set's
`utime_since` does not arrive and the database grows. The recovery plan is the
announcement's [stall section](ANNOUNCEMENT-20261205.md#if-elections-or-block-production-stall):
operators keep their nodes and election services running and report free disk,
and the coordinator announces whether the network continues, restarts from a new
genesis or ends: within 12 hours of a halt, or of an election close with no
ConfigParam 36 (above). Bring a downed team
validator back first: with both team validators up the chain needs the fewest
external validators.

### Schedule: 24 h terms

The schedule is `genesis` in `network/profile.json`, and `genesis.json` prints
its times. ConfigParam 15 is 86,400 / 43,200 / 7,200 / 21,600: each elected set
serves 24 h, its election opens 12 h before the term and closes 2 h before it,
and a stake is held 6 h after its term ends. The genesis set is valid for
86,400 s after the epoch T.

| When (UTC, from the epoch T) | What |
|---|---|
| T | genesis; the two team validators produce blocks |
| T + 12 h to T + 22 h | first election: a 10 h window, longer than a night, so every time zone has waking hours in it |
| about T + 22 h | election result installed (ConfigParam 36): a key block |
| T + 24 h | first elected set takes office: a key block |
| T + 36 h to T + 46 h | second election, for the set of T + 48 h |
| T + 24 h + 24 h k | every later set; a 14-day test has about 13 elected terms |

Every registered validator, the two team ones and each external one, must be
onboarded (operator wallets and pool owners funded, pools deployed and holding
the principal) before its first window closes, and stakes through overlapping
elections (Production-Node.md section 9). A pool holds two stakes: the one
frozen for the current term (until the term ends plus 6 h) and the one in the
next election. The stake placed for a term starting at S returns at S + 30 h,
before the election after next opens at S + 36 h, so two are enough;
`testnet_lib.validator_schedule` refuses any schedule where
`stake_held_for + elections_start_before` exceeds `elected_for`. A rehearsal of
the bootstrap flow at production timing uses
`network/profile-production-timing.json` (the canonical template's schedule;
`rehearse-loopback.sh` takes it as `REHEARSAL_PROFILE`).

**Why 2 h terms were adopted, and why 24 h is fine now.** The first epoch used
the canonical template's schedule unchanged: a 131,072 s bootstrap set and
65,536 s terms, with a 3,600 s validator `state_ttl`. Its first key block after
genesis would have come at T + 34 h. The GC point never passes the last key
block (tos `validator/manager.cpp` `try_advance_gc_masterchain_block`: also not
now minus `state_ttl`, the last rotation block or the persistent-state
serializer), so until then no state and no consensus database was deleted, and
at about 145 GB a day (16 basechain shards then) the 99 GB disks would have
filled in 15 hours. Epochs 5 to 8 therefore ran 2 h terms. Since then the
retention was aligned with upstream TON (`state_ttl` 86,400 s) and the
basechain starts as one shard. Every election result and every term start is a
key block, so with 24 h terms key blocks come at most 22 h apart, shorter than
`state_ttl`: the GC point trails the head by `state_ttl`, as it did with 2 h
terms, and a validator holds the same about 24-30 h of states and consensus
data. The longest gap is max(`elected_for` - `elections_end_before`,
`elections_end_before`), so longer terms cost no extra disk as long as that
stays within `state_ttl`.

**The 48 h alternative (owner-selectable).** 172,800 / 122,400 / 86,400 /
43,200, with an initial set of at least 126,000 s (for example 129,600 s: first
election T + 2 h to T + 12 h, first elected set at T + 36 h). Its election
closes 24 h before the term, so key blocks come every 24 h and the disk need
is the same as with 24 h terms; `validator_schedule` accepts it. Its costs: the
set is fixed 24 h before it takes office, a validator that fails after staking
stays elected for up to about 72-82 h instead of about 36 h, and a 14-day test
has about 7 terms instead of 13. Liveness matters more for this external test,
so December runs 24 h terms.

**Before December 5, rehearse the rotation scaled down** on the local net, at
1/12 of the December schedule: 7,200 / 3,600 / 600 / 1,800 with an initial set
of 7,200 s (`validator_schedule` accepts it: the first election opens 1 h after
genesis, and two stakes per pool still suffice). Run it through at least three
rotations, so the first stake is recovered and staked again, and confirm the
key blocks at each close and each term start and the GC point following them.

### Disk: measure in the first 48 h

The validator floor is 160 GiB free (`host_requirements`), on a recommended
250 GB SSD or NVMe (200 GB at least). It is an estimate for a full 21-validator
set at its worst point (`network/profile.json` `retention` and
`host_requirements`):

| Part | Held | Rate at N = 21 | Size |
|---|---|---|---|
| consensus data and states (GC point: `state_ttl` + serializer) | 30 h | 2.8 GB/h | 84 GB |
| archive (GC point's time minus `archive_ttl`) | 54 h | 0.45 GB/h | 24 GB |
| archive, two 4 h load windows at 200 transfers/s | | +1 GB/h | 8 GB |
| base database, logs, binaries | | | 12 GB |
| total, with 15 % headroom for the estimate | | | 128 GB, 147 GB (137 GiB) |
| plus the 20 GiB at which operators and the load guard stop | | | 157 GiB, floor 160 GiB |

The rates scale the measured 4-validator ones (0.56-0.62 GB/h of consensus
data, about 0.25 GB/h of archive) by the signatures they carry: a certificate
or a masterchain block proof holds ceil(2N/3) ML-DSA-44 signatures of 2,420
bytes, 14 at N = 21 against 3 at N = 4. **In the first 48 h of the test, with
the elected set, measure each team host's growth by part**: `consensus/`,
`archive/` and the states (`celldb/`) separately, `du -s` of each under
`/var/lib/tos/validator` every hour across at least one key block and one
archive cut, beside `watch-testnet.py`'s `free_gib` and `consensus_mb`, and ask
the operators for `df -h /var/lib/tos` at the same UTC times. If any part grows
faster than its rate above, raise the floor and tell the operators before free
space falls under 20 GiB anywhere.

### 8.1 Onboarding a genesis validator for elections

Onboarding has two forms, chosen by who runs the host. Both move value through
the same journaled operations and read the chain on **two** validators: the
coordinator's own or team-operated nodes, through their loopback JSON-RPC
(`ssh -L 18081:127.0.0.1:8081 root@<team validator>` and another on 28081 to a
second team validator). A tunnel is never opened to an external operator's host.

**A host an external operator runs: `onboard --no-host`.** The coordinator does
only its own steps and checks the operator's from chain state; it opens no SSH
and runs nothing on the host. The operator runs the host-side steps
([OPERATOR.md §6](OPERATOR.md#6-onboard-for-elections)). The hand-offs:

| # | Who | Runs | Proceeds only when (read on chain unless noted) |
|---|-----|------|-------------------------------------------------|
| 1 | Coordinator | `onboard --no-host` (below) | the pool is recorded, derives from its owner and operator wallet, and genesis names it |
| 1a | | `fund-op-<name>`: `operator_funding_tos` to the operator wallet (it may be undeployed) | the bootstrap wallet's history gate |
| 1b | | `fund-owner-<name>`, `activate-owner-<name>` | the owner's credit settled |
| 1c | | `deploy-pool-<name>` (kind `owner-deploy-pool`): `pool_deploy_tos` with the pool's StateInit, from the owner | the owner active on both validators, and keeping the principal, both fees and a withdrawal message |
| 1d | | `principal-<name>`: `pool_tos` from the owner | the pool active with the pinned code and the two roles |
| 2 | Coordinator | exits with status 3 and prints the operator's command; sends it, the pool and the owner through the agreed channel | the pool holds two stakes above its reserve |
| 3 | Operator | `sudo python3 /opt/tos-testnet/scripts/testnet-operator.py onboard --name <name> --pool <pool> --owner <owner>` on their host | on their own node: the pool active with the pinned code, its owner `--owner` and its validator role their wallet, two stakes in it, fee money in the wallet; then the custody line names the pool (host log), and the election unit is active at the end |
| 4 | Operator | sends the printed JSON summary | (informational: the coordinator decides from the chain) |
| 5 | Coordinator | `onboard --no-host` again: all operations settled, nothing is sent | the pool's code, roles and two stakes unchanged, and the operator wallet active holding at least a stake order (`stake_order_nanotos`) and its fee. It reports the host's binding and election task as UNVERIFIED: they are verified only when the pool's stake appears in the Elector |

```bash
python3 /opt/tos-testnet/scripts/testnet-elections.py onboard \
  --name node-1 --no-host --ceremony ./ceremony \
  --tos-root "$TOS_ROOT" --fift "$TOS_ROOT/build/crypto/fift" \
  --rpc http://127.0.0.1:18081/jsonRPC --confirm-rpc http://127.0.0.1:28081/jsonRPC \
  --previous-ceremony ../epoch-1/ceremony   # after a reset: once per earlier epoch
```

The owner deploys the pool, not the operator wallet. The pool's address is the
hash of its StateInit (the pinned code and a data cell of the two roles), so any
sender carrying that StateInit creates exactly this pool, and the contract
accepts an empty-body message from anyone. Deploying from the owner keeps every
onboarding payment signed and journaled here, needs no message from the
operator wallet before the principal, and leaves the operator a single step
after a single hand-off. Every owner is funded with `pool_deploy_tos` on top of
the principal and its reserve (`pool_owner_reserve_tos`), so the 2 TOS do not
come out of the reserve: after an owner deployment the owner still keeps the
whole reserve less its transfer fees, which covers a later withdrawal message.
The deployment is refused unless the owner keeps the principal, its fee and a
withdrawal message afterwards. The operator wallet's fee money is unchanged, so
it has 2 TOS more headroom than on a team host. This form takes only an external
pool (one `genesis-records.json` names outside `genesis-set.json`): a team pool
stakes the team multiple, which only the SSH form gives `enable-elections.sh`.

Whether the node is bound to the pool and the election task runs cannot be read
on chain before an election. They show at the first election as the pool's
stake in the Elector and then in ConfigParam 34, which `sweep`'s prerequisites
and the live checks read. A wrong binding loses nothing: the pool keeps the
principal and only its owner can withdraw it.

The operator's script first runs `init-operator.sh` (idempotent: it completes
`tos-ctl` on the host and creates nothing that already exists), then refuses, and
moves no value and configures no pool or election task, until the coordinator's
steps are visible on the operator's own node; a pool whose validator role is not
the host's wallet is refused there (the operator reports it; `change-validator`
is the coordinator's remedy). A host that kept `/var/lib/tos-ctl` over a reset
is caught the same way.

**A host the team operates: `onboard --host --ssh-key`.** From the coordinator's
machine, once per such validator whose pool step 2 recorded:

```bash
python3 /opt/tos-testnet/scripts/testnet-elections.py onboard \
  --name node-1 --host <HOST> --ssh-key <KEY> --ceremony ./ceremony \
  --tos-root "$TOS_ROOT" --fift "$TOS_ROOT/build/crypto/fift" \
  --rpc http://127.0.0.1:18081/jsonRPC --confirm-rpc http://127.0.0.1:28081/jsonRPC \
  --previous-ceremony ../epoch-1/ceremony   # after a reset: once per earlier epoch
```

It refuses unless `ceremony/pools.json` records the validator's pool, the pool
derives from its recorded owner and operator wallet, and `genesis-records.json`
names it as a validator id. A pool in `genesis-set.json` (a team pool) needs the
ceremony's plan and stakes `team_stake_multiple` x `stake_tos`; any other pool
stakes `stake_tos`. It runs `init-operator.sh` on the host (vault,
console key, node registration, tosctl's master wallet, operator wallet) and refuses unless the host's
operator wallet is the one the pool was derived from (a host that kept
`/var/lib/tos-ctl` over a reset still has the old wallet key). Then it runs these
steps, in order:

1. it funds the operator wallet from the bootstrap wallet with fee money only
   (`operator_funding_tos`, 10: the measured epoch-5 operator spend through the
   first returned stake plus one failed submission) and activates it;
2. it funds the pool's **owner** with the principal, a reserve and the deployment
   (the pool's principal + `pool_owner_reserve_tos` + `pool_deploy_tos`) and
   activates it; the owner's key stays on the coordinator (below). The principal
   is two stakes and the pool's headroom: `pool_tos` for one unit, and for a team
   pool `pool_tos` + 2 x (team stake - `stake_tos`);
3. it deploys the pool with 2 TOS from the operator wallet;
4. it configures the pool and the binding in tosctl on the host
   (`config pool add --address --owner`, `config bind add --pool`);
5. the owner sends the stake principal to the pool;
6. it checks readiness: the pool holds at least two of its stakes above
   its storage reserve, and the node's latest `post-quantum consensus custody`
   line names the pool as its validator id (the Elector refuses a stake signed
   for another account);
7. it runs `enable-elections.sh --stake-tos <the pool's stake> --max-factor <F>`
   (10.0 for a team pool, after probing the host's tosctl for it before step 1;
   3.0 for an external one), which installs
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
- `deploy-pool-<name>` (kind `deploy-pool` from the operator wallet on a team
  host, `owner-deploy-pool` from the owner with `--no-host`; a step settled one
  way is never redone the other way)
- `principal-<name>`

Each has a record in `ceremony/operations/<id>.jsonl`. The lines are append-only
and each is fsynced with its directory. The signed message is durable there
before it is broadcast, and the shared ceremony journal lock is held across reread, validation,
signing and broadcast. It serializes operations across wallets and processes.

On a team host, the operator wallet's messages are built and signed by tosctl on
the host, but **never broadcast there**: `wallet send --build-only` hands the message to the
coordinator. The coordinator decodes it and refuses anything but the intended
one, checking:

- the signing wallet;
- global id 2;
- the wallet's current seqno on both validators;
- the subwallet and an expiry within 120 s plus 30 s clock skew;
- the envelope's schema `tosctl.wallet-prepared-send.v2` and its `valid_until`,
  which must equal the expiry in the signed bytes;
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
python3 "$S" baseline "${C[@]}" --wallet=ADDR --reason TEXT
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
python3 "$S" change-validator "${C[@]}" --name node-1 --id change-node-1-1 --new --to="$NEW" --dry-run
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
margin only, as an ordinary `fund` operation with its own fixed id:

```bash
# C is the common ceremony / tools / --rpc / --confirm-rpc arguments above.
python3 "$S" fund "${C[@]}" --id top-up-node-1-1 --label top-up-node-1-1 \
  --to=<RECORDED_OPERATOR_WALLET> --amount 5 --dry-run
python3 "$S" fund "${C[@]}" --id top-up-node-1-1 --label top-up-node-1-1 \
  --to=<RECORDED_OPERATOR_WALLET> --amount 5
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
elected set is installed and holds the stake of both team pools and of every
funded external pool, its remaining balance (the margin less what top-ups used,
the rounding, and the allocation of every registered external validator that was
never onboarded, since funding moves only at onboarding) is sent with wallet-v3 send mode
160 (128: the whole remaining balance; 32: delete the account once empty), value
0, non-bounce, to the ConfigParam 5 blackhole `-1:ff…ff`, where the credit phase
destroys it and the block counts it in `ValueFlow.burned`. Nothing can be signed
from `-1:111…1` again: the account is gone and its address is no StateInit's.

`sweep` refuses unless, read on both validators: live ConfigParam 5 names the
blackhole and burns 0/1 (without it the transfer would create an ordinary account
holding the funds); every pool in `pools.json` is registered in
`genesis-records.json` and both team pools are recorded; the team pools'
`fund-op-`, `fund-owner-` and `principal-` operations are settled, and each
external pool's are either all settled (it was funded and must stand) or none
exists (it was never funded); ConfigParam 34 and 32 are both elected sets
holding every team pool and every funded external pool and no validator outside
the registered pools, each matched by an Elector result (the genesis set has
none) and the previous one older; each of those pools holds a frozen, unbanned
stake in both results; each of their operator
wallet holds at least the measured first-recovery cash (0.203224039 TOS) plus the
1 TOS fee allowance; and no other bootstrap operation is open. Then it reads the
wallet's history like every bootstrap operation.

```bash
python3 "$S" sweep "${C[@]}" --dry-run
```

The report lists the pools that stood (`stood`), the registered external
validators that were never onboarded (`not_onboarded`: their allocations are
burned with the rest), and the excluded ones (`excluded`).

An external validator that was funded (any of its onboarding operations exists)
but never stood in both elected sets refuses the sweep, as does one whose
onboarding stopped part way. Decide that it will not stand, then exclude it by
name, with the reason:

```bash
python3 "$S" sweep "${C[@]}" --exclude node-7 --reason "host never synchronized" --dry-run
python3 "$S" sweep "${C[@]}" --exclude node-7 --reason "host never synchronized"
```

The dry run checks the exclusion and records nothing. The real run records a
settled `sweep-exclusion` operation, `sweep-exclude-node-7`, in the journal (the
pool, the reason) only once every other prerequisite holds, and every later
sweep check honors it. Its principal stays in its pool, whose owner key is
offline on the coordinator: `withdraw --name node-7 --id <ID> --new --all` takes it
out later, outside an election window. A
team pool cannot be excluded, and a never-funded one needs no exclusion.

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
   (2 ordinary, 3 critical), each under a different set. With the team holding
   a little over half of the weight, every round needs both team validators and
   about half of the external weight; before the first election the two genesis
   validators both vote.
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

**ConfigParam 84 (recognized settlement assets) and the token bridge parameters.**
`propose` refuses, before anything is signed or sent:

- a ConfigParam 84 value when ConfigParam 10 does not list 84 (it must be critical);
- a value that does not decode exactly by the TL-B: tag, status 1-3, origin kind 1-2,
  a non-zero minimal `Coins` cap, a 456-bit origin cell, no trailing data, and every
  dictionary node consumed exactly (`hm_edge` with a label no longer than the key
  left; `hmn_fork` exactly its label and two references, so a trailing bit or a
  third reference is refused). Also a value with more than 16 entries, or needing
  more than 1,024 cells of validation (counted as the node counts them, every
  reference a visit). The node would refuse such a configuration when installing
  it and the masterchain would halt;
- a change that adds, removes or changes more or fewer than one entry of the
  current value; a proposal while another ConfigParam 84 proposal is pending; and a
  proposal while a bridge address change (79, 81, 82 or 83) is pending;
- any ConfigParam 84 proposal without `--node-release-evidence FILE`:

  ```json
  {"validators": [{"name": "...", "public_key": "<64 hex>", "commit": "<40 hex>",
                   "version_output": "<tos-validator-engine -V output>", "observed_at": 1795600000}]}
  ```

  Exactly one row per member of the current set (ConfigParam 34), keyed by its
  consensus public key: the Ed25519 key, or for a PQ validator its `key_id`. No
  extra, duplicate or non-member row is accepted. Each row was observed after the
  current set took office (`utime_since`) and at most 24 hours ago, as whole Unix
  seconds (an integer: a float, NaN, an infinity, a bool or a string is refused); its
  `version_output` names its commit; and the commit is in `--tos-root` and defines
  `= ConfigParam 84;` in its `crypto/block/block.tlb`. A node without that schema
  halts on any ConfigParam 84 value, well-formed or not. **Limitation:** a row is
  the operator's attested `-V` output. The script cannot prove which binary a remote
  host runs; it binds the attestation to the current set and to a commit with the
  schema;
- a ConfigParam 79, 81, 82 or 83 value that changes the bridge address while
  ConfigParam 84 still lists an active (status 1) asset of the old bridge for that
  chain (adopt that record's status 2 or 3 first, by its own proposal), or while a
  ConfigParam 84 proposal is pending.

The ordering rules (no ConfigParam 84 proposal beside a pending bridge address
change, and the reverse, and the migration rule) are checked again by `sign` and
`vote` before a round's votes are signed or sent, since other proposals may be
registered in between. For a ConfigParam 84 proposal `sign` and `vote` also read
ConfigParam 34 again and check the release evidence against the set of that round:
after a rotation, new members without evidence are refused by name. Pass the new
set's evidence with `--node-release-evidence` (and `--tos-root` to `sign`); without
it, the file kept with the proposal at registration is used. A parameter that is absent is proposed with the Config
contract's absent-value hash (zero) as its precondition, so two first installations
cannot overwrite each other. Proposing a value that is already registered (same
value and precondition, so the same proposal hash) resumes it.

`adopted --also-rpc URL` (repeatable) checks more nodes than the two validators;
use it to show the value on every validator.

### 8.3 Test USDC through the token bridge (USDC settlement T5)

Test USDC is a six-decimal test token locked in a test `Bridge.sol` on an EVM chain
and minted on TOS by a test token bridge, configured by ConfigParam 79 and
recognized by ConfigParam 84. The relayer has no live path yet, so a **stand-in
oracle** signs: three Ed25519 keys own the TOS oracle multisig (quorum 2) and three
secp256k1 keys are the EVM bridge's oracle set. It signs v5 votes in the formats of
tos `crosschain/token-bridge/SETTLEMENT-PROTOCOL.md` (sections 7.1 and 11). Every
key is generated at run time, stays on the host that runs the step, and is test-only.

#### Local network: executed 2026-11-25

`local/scripts/local-pq-usdc.py` runs every step on the local PQ network
([local/OPERATIONS.md](../local/OPERATIONS.md#test-usdc-through-the-token-bridge)).
It was run on tos `b9a5a0406` (the node, `tosctl`, the token bridge and
`Bridge.sol`), after `setup-testnet.sh --clean --rotate` with that build. Each step
records its evidence under `/data/usdc/evidence/`; the keys under
`/data/usdc/keys/` (0700) are private.

| # | Step | Expected output (from the 2026-11-25 run) |
|---|------|--------------------------------------------|
| 0 | Genesis | ConfigParam 10 lists 84; 79 and 84 are absent; every validator's `tos-validator-engine -V` reports `b9a5a0406193d3577022b5c856bab9f77836f58b` |
| 1 | `evm-deploy`: the test token (`TestFeeToken`, 6 decimals, fee 0) and `Bridge.sol` with the three stand-in oracles; `voteForSwitchLock(true, 1)` | `allowLock() = true` |
| 2 | `fund`, with elections stopped in a quiet interval and started again | deployer 120, submitter 20, buyer 30 and the governance payer (a wallet v3) 150 TOS, each deployed |
| 3 | `tvm-deploy`: the token bridge compiled with the ConfigParam 79 parameters; `new-multisig.fif` (2 of 3, the bridge as its only allowed destination) and `new-bridge.fif` (chain 1, the EVM bridge); a plain top-up fixes the bridge's life | the bridge account's code hash equals the compiled `token-bridge` hash, and its minter and wallet codes equal the compiled ones; the multisig allows only the bridge and holds no pending query |
| 4 | `config79`: `build-config79.fif` (mint fee 5 TOS, above `get_mint_fee_floor`), then `testnet-governance.py propose`, `sign --local-network` and `vote` in each round | `adopted` prints `ConfigParam 79 = f0f4ed98…a7dd on all 5 nodes` (validators 1, 2, 3, 4 and 7) after 2 won rounds |
| 5 | `generation`: `voteForNewGeneration(1, bridge, life, 1)` on the EVM side, then `activate_generation` (vote op 8) through the multisig | the TOS bridge's `get_bridge_state` shows generation 1, start 0, active |
| 6 | `lock`: a lock of the token before any cap; `voteForLockCap(token, 100000e6, 10000e6, 20000e6, 50000e6, 1)`; a lock above the per-lock cap; a 25 tUSDC lock to the buyer | the uncapped lock reverts with `lock: token has no lock cap`, mined with status 0 and no lock number taken; so does a second, never-capped probe token after the first is capped; the over-cap lock reverts with `lock: over the per-lock cap`; lock `n = 0` is open in generation 1 |
| 7 | `mint`: `pay_swap(1, 0)` with exactly the mint fee from the buyer, then the v5 swap vote (op 0: generation, n, chain 1, EVM bridge, recipient, amount, token data) through the multisig | the buyer's token wallet holds `25000000` (25 tUSDC); the minter's supply is 25000000; the swap is consumed and folded under the watermark (`swap_watermark = 1`) |
| 8 | `config84`: `tosctl vote offer settlement-assets build` from the deployed bridge's minter and wallet code hashes; propose with `--node-release-evidence` (each validator's running binary and its `-V` commit); sign and vote each round (the local ConfigParam 11 asks 4 won rounds for a critical change; the public testnet's asks 3) | `adopted` prints `ConfigParam 84 = 3fe75614…f761 on all 5 nodes` after 4 won rounds; `tosctl vote offer settlement-assets verify --pin <master>` re-derives the master from the bridge's codes at one block and prints `"listed": true, "verified": true, "status": "active", "decimals": 6, "bridge_param": 79` |

To re-run, from the tos-ops root, with the tos build the network runs and a
loopback EVM chain of chain id 1 (the chain ConfigParam 79 serves):

```bash
anvil --host 127.0.0.1 --port 18545 --chain-id 1 --silent &
(cd "$TOS_ROOT/crosschain/token-bridge/evm" && npm ci &&
  PRIVATE_KEY=0x0000000000000000000000000000000000000000000000000000000000000001 npx hardhat compile)
U=(sudo env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" local/scripts/local-pq-usdc.py)
"${U[@]}" keys && "${U[@]}" evm-deploy
sudo systemctl stop tos-pq-elections     # quiet interval: after the round's stakes are accepted
"${U[@]}" fund; sudo systemctl start tos-pq-elections
"${U[@]}" tvm-deploy && "${U[@]}" config79 && "${U[@]}" generation
"${U[@]}" lock && "${U[@]}" mint && "${U[@]}" config84
"${U[@]}" status
```

Every step is idempotent: what is already done is checked against the chain and
skipped. Every value-moving send (each funding payment, deployment top-up, mint
fee, oracle query, EVM deployment, transfer, approval, lock and oracle vote) is
journaled in `/data/usdc/state.json` before it is made; the journal is written to a
temporary file, fsynced, renamed and its directory fsynced before any broadcast. A
TOS send records its signed external message, bound to the wallet's seqno; an EVM
send records its sender, nonce, destination and exact calldata and goes out at
exactly that nonce. A sender with an unresolved send starts no other, so two
intents never claim one seqno or nonce. After an interruption the rerun reconciles
each journaled send from the chain: an unused seqno or nonce is sent again with
the same signed message or arguments; a used one counts only if it was this send:
the wallet's history must hold a transaction that took the journaled external
message (by its hash), and the EVM transaction at the nonce must carry the
journaled destination, calldata and no value. Anything else stops with an error and
is not marked done. A TOS send counts as delivered only if that transaction took
effect and its out-messages include the intended one (destination, value and body
hash). The wallets send with mode 3, which ignores errors: a wallet whose balance
dropped takes the message, advances its seqno and sends nothing. That case, and an
aborted action phase, is recorded as `accepted_not_sent`. It stops with an error,
is never signed again automatically, and blocks the wallet's later sends until a
person decides. Nothing is ever paid, locked or voted twice. A rerun after adoption writes
`config79-recheck.json` / `config84-recheck.json` and keeps the adoption's evidence.
The 2026-11-25 local net's `config79.json` and `config84.json` were rebuilt from
`state.json` and the run's output after a rerun of an earlier driver overwrote them.

The `config84` step collects the release evidence from each current validator's
running binary (`-V`) on this host, keyed by its PQ `key_id`, at the proposal and
again before every round's signing and votes. A rerun of an
interrupted `config84` resumes the registered proposal and keeps its won rounds.

A restarted EVM chain loses the EVM bridge the TOS bridge is pinned to: reset the
local network too, which also clears `/data/usdc`.

#### Public testnet: plan, NOT EXECUTED

The coordinator's decision: test USDC goes onto the December 5 public testnet only
later, by governance vote, never at genesis. **The tos commit that network pins must
include ConfigParam 84 support (tos #513, in `b9a5a0406` and later):** the schema,
the ConfigParam 10 entry and the `tosctl` builder. A validator without the schema
halts on any ConfigParam 84 value, so a network started from an older commit must
first be upgraded on every validator.

1. **Release.** Confirm every current validator runs a node built from a commit with
   the ConfigParam 84 schema. Collect from each operator, after the current set took
   office and within 24 hours of the proposal, an attested `tos-validator-engine -V`
   output and the time it was read, keyed by the validator's ConfigParam 34 key, into
   the release evidence file. The tool binds those attestations to the set; it cannot
   verify the binary on a host it does not run. Confirm ConfigParam 10 lists 84; if it does not,
   adding it is its own critical proposal, first.
2. **EVM side.** A public EVM test network whose chain id matches the ConfigParam 79
   bridge build (`MY_CHAIN_ID` in tos `crosschain/token-bridge/tvm/params`), or a
   test bridge compiled for another slot. Deploy the test token and `Bridge.sol` with
   a test oracle set of at least three keys, and open locking by vote.
3. **TOS side.** Deploy the oracle multisig and the bridge with `new-multisig.fif` and
   `new-bridge.fif`, checked as in step 3 above, from a coordinator wallet.
4. **ConfigParam 79** through `testnet-governance.py` (ordinary, 2 won rounds), signed
   on each validator host (`sign --inventory`); `adopted --also-rpc` on every team
   validator.
5. **Generation**, then **`voteForLockCap` for the test token before its first lock**,
   with caps sized for the test; show an uncapped lock refused first.
6. **A capped lock and its mint** to a test buyer wallet, voted by the stand-in oracle
   until the relayer implements settlement v5.
7. **ConfigParam 84** (critical, 3 won rounds under different sets), built with
   `tosctl vote offer settlement-assets build` from the deployed bridge's codes and
   proposed with `--node-release-evidence`; then `tosctl ... verify --pin`.

None of these steps has been run on the public testnet.

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

This applies only to unsigned planned `fund` operations (bootstrap wallet) and
`owner-fund` operations (a pool owner's `top-up` or `load` funding); never to a
sweep. Such a plan is what a real run refused before signing leaves behind, for
example a `load` whose `--deploy-amount` the owner cannot pay (its dry run does
not check that): while the plan is open the gate refuses every other operation
of that wallet, so close it before the owner's next `top-up` or `withdraw`. A
signed copy of the plan's message outside the journal (`ceremony/sent/`, found by
its name or by its wallet, destination, value and body; a fund dry run writes one)
refuses abandonment until its `valid_until` has passed on both validators: before
that it could still be accepted. The operator copy of an owner transfer is written
only after the signed journal line is durable, so a crash while signing leaves no
such copy next to a planned record. Any signing evidence,
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

## Known limits

- **The tos genesis manifest packer takes four records.** tos
  `scripts/prepare-pq-genesis-manifest.py` refuses any other count. The
  coordinator runs it and compares its bytes only for a four-record genesis
  set; the two-record December 5 set is packed by `testnet_lib.pack_manifest`
  alone, and the cross-check is the zero state's validator set, which `genesis`
  reads back and compares with `genesis-set.json`.
- **No monitor checks the team stakes in an open election.** `watch-testnet.py`
  samples the hosts (head age, units, disk), not the Elector, and no existing
  watch reads an election's participants. The check that both team pools have
  staked before each election closes is a manual runbook step
  ([Liveness](#liveness-what-keeps-blocks-final)).
- **No monitor raises "election closed with no ConfigParam 36".** The host
  probe reads the hosts, not configuration: telling a failed election from one
  still open would mean decoding ConfigParam 34 and 15 on each host as well. The
  check at every close is the manual `getconfig 36` above
  ([Liveness](#liveness-what-keeps-blocks-final)).
- **The CON-01 history observer assumes 7,200 s terms by default.**
  `acceptance/con01_history/observer.py` (the epoch-6 CON-01 record) checks each
  incoming term's length against its configuration's `term_lengths`, which
  defaults to `[7200]`. It is pinned evidence and is left as it is; a December
  run passes `"term_lengths": [86400]` in its configuration.
- **`scripts/check-validator-keys.py` is the epoch-6 gate.** It pins epoch 6's
  zero state and checks for four signers; it does not apply to a two-validator
  genesis set and has not been generalized. Use `check-testnet.py
  --genesis-set ceremony/genesis-set.json` and, after the first election,
  `--elected-set`.
