# Production hardware and hosting

How to choose machines and where to host them for the production network.
This is a **requirements proposal, not an accepted profile**. The hardware
profile is still open as gap G8 in [Production-Node.md](Production-Node.md)
section 12. The tos N6 release-hardware proposal it builds on has status
`PROVISIONING_REQUIRED`.

The hosting rules come mostly from Solana, whose validator set has twice lost
a large share of its stake at once because too much of it sat with one hosting
provider. Section 3 records what happened and section 4 turns it into rules.

## 1. Physical configuration

### 1.1 Validator

| Item | Requirement | Why |
| --- | --- | --- |
| Machine | Bare metal, one validator per host | A guest cannot observe or pin its host's frequency policy, and a noisy neighbour changes consensus timing. One host holds one consensus key (Production-Node.md section 2). |
| CPU | At least 8 physical cores; record the exact model | N6 release-hardware proposal. Count physical cores, not hyper-threads or vCPUs. |
| Frequency policy | Governor `performance`; turbo/boost **disabled** | Thermal throttling and boost make block and signature timing vary from host to host and from hour to hour. Disabling boost keeps measurements comparable. |
| Memory | At least 16 GiB; ECC recommended | A validator process measured about 6.0 GB RSS (6.1 GB peak) on the local network. 16 GiB leaves room for the page cache RocksDB relies on. ECC is a recommendation; the proposal does not require it. |
| Storage | NVMe SSD, database on its own device, logs on another volume | Production-Node.md section 4. Size the capacity by section 6.3 of the design, and choose models by write endurance (section 1.3 below). |
| Network | At least 1 Gbit/s; a static public IPv4, preferably on the interface | The engine announces the configured address but binds ADNL and QUIC by port on all interfaces (tos `adnl/adnl-network-manager.cpp` `add_self_addr`, `quic/quic-sender.cpp`). Behind NAT it works only with UDP forwarding for the ADNL port and the QUIC port (ADNL + 1000), and that adds a router to the failure path. Open UDP for both. |
| Time | NTP synchronised | Multi-key consensus validity (`valid_from`/`expire_at`) reads the wall clock (Production-Node.md section 9). |
| Architecture | Linux x86-64 or arm64 | The only platforms tos builds and releases for. |

These are minimums for a 21-validator network, not the measured production
sizing. G8 stays open until memory, disk and CPU are measured on this profile
with 21 validators.

For comparison only, TON's current validator guide asks for 8 cores / 16
threads, 128 GB RAM, 2 × 1.92 TB NVMe and 5 Gbit/s [T1]. TON carries far more
traffic and history than a new network; its numbers are not our target, but
they show where a busy network ends up.

### 1.2 Other roles

| Role | Machine | Notes |
| --- | --- | --- |
| Full node / RPC / lite server | Bare metal or a dedicated-CPU VM | Same memory as a validator (a non-validating node measured about 5.8 GB RSS). It keeps 7 days of archive (Production-Node.md section 6.2), so it needs more disk than a validator. |
| Archive | Bare metal | Size it by retention policy. At `--state-ttl` ≥ 30 days, CellDb raises its cache to at least 16 GiB. |
| DHT bootstrap | Small VM is enough | The local DHT server measured about 120 MB RSS and about 1 % of a core. Run at least two, with different providers (section 4). |
| Monitoring / observers | Any | Never with the same provider or in the same data center as the validators it watches (section 4.4). |

### 1.3 Disk endurance

Capacity is not the only constraint. On the local development network, under
continuous transfer and shielded-pool traffic at about 2.4 masterchain blocks
per second, one validator wrote about 352 GB in 45 hours, roughly **190 GB per
day**. Short retention cleans data up; it does not stop it being written.

- Choose drives whose rated endurance (TBW, or DWPD × capacity × warranty
  days) covers the planned service life at the measured write rate, with a
  factor of two in reserve. Consumer QLC drives are not suitable.
- Measure the write rate on the production profile with 21 validators (G8),
  and set alerts on the drive's own wear indicator (SMART / NVMe
  `percentage_used`).
- On rented hardware, confirm that the provider replaces worn drives and
  states the drive model.

## 2. Bare metal or VM

- **Validators: bare metal.** The release measurements behind G8 refuse
  virtualised hosts, and a validator must not share CPU or disk with
  unknown tenants.
- **Full, RPC and archive nodes:** bare metal preferred. A VM is acceptable if
  its CPU and disk are dedicated and it passes the same sync and load checks.
- **DHT, monitoring and tooling:** VMs are fine.
- The public testnet decided differently (decision D13 in the memo plan):
  testnet validators may run on VMs, because testnet capacity numbers are not
  release evidence. Do not carry that permission over to production.

## 3. What Solana's hosting concentration taught

Solana is the closest large precedent. Its validators are run by independent
operators who each chose a host, and the same few providers ended up with a
large share of the stake. Figures below are from public reports and differ
between sources; they are kept as the sources state them.

**Hetzner, November 2022 — a terms-of-service ban.** Hetzner's terms forbid
cryptocurrency activity, and it enforced them against Solana nodes. About 1,000
validators and about 20 % of active stake went offline within hours; before
the ban, about 40 % of validators (20 % of stake) were on Hetzner. The network
stayed up because the lost stake was below one third. Most operators were back
at other providers within days [S1, S2].

Lessons:

- A provider's terms of service are a single point of failure. A provider
  that allows nodes today may enforce a ban tomorrow, and it acts on every
  customer at once.
- Validator count and stake share are different measures. Losing 40 % of the
  validators but 20 % of the stake was survivable; the reverse would not have
  been.
- Recovery depended on operators being able to move quickly to another host.

**TeraSwitch, 12 August 2026 — a routing failure in one autonomous system.**
A routing misconfiguration at one hosting provider took about 90 validators
offline together. At the peak, 28.83 % of staked SOL was delinquent; the
affected TeraSwitch network, AS20326, hosted about 27–31 % of Solana's stake
[S3, S4]. The network came close to halting.

Lessons:

- Count concentration by **autonomous system (ASN)**, not by brand or by city.
  On validators.app, AS20326 appears separately in Frankfurt, Amsterdam and
  Tokyo, with about 9.5 %, 7.2 % and 2.9 % of stake [S5]. A table by data
  center hides that they fail together.
- Geographic spread inside one provider is not provider diversity: one
  routing error reaches every site of that network.
- TeraSwitch hosted far fewer validators than Hetzner did in 2022 (about 90
  against about 1,000) but more stake, so it came much closer to halting the
  chain. Stake share, not node count, decides.

**Solana's response.** Since 1 May 2026, validators in the Solana Foundation
Delegation Program must run on an ASN holding less than 25 % of network stake,
and a data center provider may hold at most 15 % of staked validators [S6].
Solana's "hosting Nakamoto coefficient" (the number of providers that together
hold one third of stake) has been reported as about 6 [S6].

**TON.** No current public breakdown of TON validators by provider was found.
A TON Research forum post from around 2023 estimated about 30 % of TON
validators on Hetzner when Hetzner moved to end contracts with customers from
Russia [S7]. That is an estimate from a discussion, not a measured dataset. It
shows the same exposure, and that legal jurisdiction is a failure domain too.

## 4. Hosting rules for TOS

### 4.1 The limit the protocol sets

A certificate needs `quorum_threshold(W) = ceil(2W / 3)` of the total
effective weight `W` (tos `tos/quorum.h`). If one provider fails, the weight
`L` it hosted goes offline. The rest can still finalize only if
`W − L ≥ ceil(2W / 3)`, that is, `L ≤ floor(W / 3)`.

- **Genesis:** four validators of weight 17 each. W = 68, the threshold is 46
  and the most that may go offline is 22, which is one validator. **The four
  genesis validators must therefore be on four different providers and four
  different ASNs.** Two genesis validators sharing a provider means one outage
  halts the chain.
- **21 equal validators:** at most 7 may go offline together.
- After the first election, weights follow stake and are no longer equal.
  Recompute from the live ConfigParam 34 after every election.

`L ≤ floor(W/3)` is the point at which the chain halts. It is not a target.

### 4.2 Operating targets

Stricter than the protocol limit, matching Solana's program:

| Failure domain | Maximum share of effective weight | At 21 equal validators |
| --- | --- | --- |
| One ASN (all its sites together) | less than 25 % | at most 5 |
| One hosting company (all its ASNs) | less than 25 % | at most 5 |
| One data center (one building or campus) | at most 15 % | at most 3 |
| One country / legal jurisdiction | less than 33 % | at most 6 |
| One upstream transit network shared by several providers | report it | — |

At genesis, with four validators, every one of these domains holds at most
one validator.

### 4.3 Choosing a provider

Before renting, for every provider:

- **Terms of service.** Get written confirmation that running blockchain
  validator and full nodes is permitted. Read the acceptable-use policy for
  "cryptocurrency", "mining" and "blockchain". Hetzner forbids cryptocurrency
  activity; its rule was applied to proof-of-stake validators. Record the
  date and the text you relied on.
- **ASN.** Look up the ASN that announces the server's IP address; do not
  rely on the provider's brand. Resellers and white-label hosts often sit
  on a larger provider's network. Record ASN, data center and city.
- **Jurisdiction.** Record the operating company's country. Sanctions,
  court orders and contract terminations act on a whole jurisdiction at once.
- **Hardware disclosure.** The provider must state the CPU model, physical
  core count, drive model and whether CPU and disk are dedicated.
- **Network.** A static public IPv4 (on the interface, or forwarded without
  rewriting the UDP ports), unfiltered UDP
  (no "DDoS protection" that drops UDP), and a stated bandwidth or traffic
  allowance large enough for the validator's sustained traffic.
- **Exit.** Know how quickly you can get an equivalent machine elsewhere.

### 4.4 Spread the rest of the network too

- **DHT bootstrap nodes:** at least two, on different providers, and not on
  the same provider as most validators. If every DHT seed shares a provider,
  one outage stops new nodes from joining.
- **RPC and lite servers:** at least two providers, so wallets keep working
  through one outage.
- **Monitoring and alerting:** on a provider that hosts none of the
  validators it watches. An outage must not also silence its own alarm.
- **Archive and snapshot sources:** at least two providers, or recovery
  depends on the provider that just failed.

### 4.5 Keep an inventory

For every production node, keep in the operations inventory (not in this
repository if it names customer accounts):

- role, operator, provider, ASN, data center, city, country;
- CPU model and physical cores, memory, drive models;
- the date the provider's terms were last checked.

After every election, compute each ASN's, provider's, data center's and
country's share of effective weight from ConfigParam 34. Compare the shares
with section 4.2, and alert when a target is exceeded.

### 4.6 Be ready to move

Solana operators recovered from the Hetzner ban by moving. For TOS:

- A validator moves to a new host by bringing up a synced node there and
  transferring or rebinding its consensus key (Production-Node.md sections 3.1
  and 9).
- **Never run the old and the new host with the same key at the same time.**
  That is double signing. Fence the old host first: stop it, and make sure it
  cannot restart.
- Rehearse a host move once per operator before mainnet, and keep the
  procedure next to the inventory.

## 5. Open items

- G8: measure memory, CPU, disk capacity and write rate on this profile with
  21 validators, then freeze the numbers in section 1.
- Accept or change the N6 release-hardware proposal (tos
  `scripts/check-n6-threshold-proposal.py`), which this document follows.
- Build the inventory and the weight-share check of section 4.5.

## Sources

Accessed 2026-10-12. Public reports disagree on exact stake shares; numbers
are quoted as each source gives them.

- [S1] [What Happened When Hetzner Banned Solana Validators (HackerNoon)](https://hackernoon.com/what-happened-when-hetzner-banned-solana-validators-1000-nodes-taken-offline-overnight)
- [S2] [Is Solana Decentralized? Cloud Provider Hetzner Ban Raises Questions (Decrypt)](https://decrypt.co/113429/is-solana-decentralized-cloud-provider-hetzner-ban-raises-questions)
- [S3] [Solana Validator Concentration Risk After the Near-Halt (hubra)](https://hubra.app/blog/solana-validator-concentration-risk-2026)
- [S4] [Solana Outage 2026 (Bitcoin Foundation)](https://bitcoinfoundation.org/news/analysis/solana-outage-2026-what-the-validator-failure-means-for-sols-next-rally/)
- [S5] [validators.app — Solana mainnet data centers](https://www.validators.app/data-centers?locale=en&network=mainnet)
- [S6] [Solana Validator Requirements 2026 (The Good Shell)](https://thegoodshell.com/solana-validator-requirements/); earlier concentration figures in [Measuring Solana's Decentralization (Helius)](https://www.helius.dev/blog/solana-decentralization-facts-and-figures)
- [S7] [Assessing the Impact of Hetzner's Service Termination on TON Validators (TON Research)](https://tonresear.ch/t/assessing-the-impact-of-hetzners-service-termination-on-ton-validators-a-comprehensive-analysis/49) — the page did not load on 2026-10-12; the figure is from the search summary
- [T1] [TON Docs — Run a validator](https://docs.ton.org/nodes/cpp/run-validator)
- Local measurements: the single-host development network (`../local/`), 2026-10-10 to 2026-10-12.
