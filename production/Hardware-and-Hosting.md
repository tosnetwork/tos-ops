# Production hardware and hosting (proposal)

**Requirements proposal, not an accepted or measured production profile.**
Use [Production-Node.md](Production-Node.md) for the design and acceptance gaps.
Public-testnet admission uses [profile.json](../testnet/network/profile.json),
not this proposal. [OPERATOR.md](../testnet/OPERATOR.md#2-host-requirements-clock-and-preflight)
is the implemented testnet host procedure.

## 1. Physical configuration

### 1.1 Validator

Proposed starting profile, subject to representative-load measurements:

| Resource | Proposal / verification |
| --- | --- |
| Host | Dedicated bare metal, one validator identity per host; no unknown CPU/disk tenants |
| CPU | At least 8 physical cores; record model, instruction baseline and frequency policy |
| Frequency | For comparable release measurements: performance governor, boost disabled; not an instruction to retune a live validator |
| RAM | At least 16 GiB, ECC preferred; measure node RSS, caches, page cache and peak recovery needs |
| Storage | NVMe, enough capacity for TTLs plus GC/serializer lag and recovery reserve; isolate logs where practical |
| Endurance | Measure sustained writes and rated TBW/DWPD; keep replacement headroom |
| Network | Static public IPv4, at least 1 Gbit/s; ADNL and QUIC UDP reachable without filtering |
| Time | Selected reachable NTP source; a synchronization flag alone is insufficient |
| Build | Linux release and CPU-compatible verified binaries; current testnet scripts target Ubuntu 24.04 x86_64/x86-64-v2 |

These are candidate floors, not a promise that 16 GiB or a particular disk size
supports every validator count/load. The original 21-validator sizing exercise
remains a measurement requirement, not completed evidence. Testnet VMs are
permitted for testnet; their timing/capacity observations are not release evidence.

### 1.2 Other roles

- Full/RPC nodes need their own query-throughput, sync and retention capacity.
  Keep public client load away from validators.
- Archive nodes need storage and cache sizing for their actual retention. Permanent
  CellDb and long-retention cache behavior must be reviewed before enabling them.
- DHT bootstrap, monitoring and tooling can use smaller VMs after measurement;
  keep independent failure domains rather than placing every service together.

### 1.3 Disk endurance

Historical single-host development measurements recorded about 190 GB/day of
writes per validator under transfer/privacy load. This is a workload observation,
not a production upper bound. Short retention removes old data; it does not reduce
all writes. Check drive model, wear indicators, replacement policy and growth at
representative load. Alert on remaining capacity and write rate separately.

## 2. Bare metal or VM

Choose dedicated hardware for reproducible production qualification. A VM's
reported resources do not prove isolated CPU/storage or host frequency policy.
Record virtualization and label testnet measurements accordingly. Never restart a
validator to explore tuning: qualify it on a non-validator first.

## 3. Shared failure domains

Count provider, ASN, building/region, jurisdiction and upstream transit exposure,
not only hostnames or validator count. Historical incidents on other networks
motivated the original proposal; their old stake-share figures are not a current
TOS inventory or a deployment check. This repository contains no automatic ASN
weight/concentration auditor.

## 4. Hosting rules for TOS

### 4.1 The limit the protocol sets

Read the pinned tos `tos/quorum.h` and actual ConfigParam 34 weights before a
maintenance plan. If the quorum is `ceil(2W/3)`, the maximum unavailable weight
that still leaves quorum is `floor(W/3)`; **more** than that prevents progress.
Keep operational reserve below the boundary. On a four-member equal-weight set,
two offline validators can halt progress. Upgrade one at a time and prove it
healthy before the next.

### 4.2 Operating targets

The earlier concentration targets remain proposals: less than 25% effective
weight at one ASN/provider, at most 15% at one data center, less than 33% in one
jurisdiction. A small four-validator network cannot meet every percentage target;
place its validators in independent domains and record the exception. Recompute
exposure from live stake weights after each election; equal counts do not imply
equal weight. No script here enforces these targets.

### 4.3 Choosing a provider

Before renting, verify current terms permit validators, declared CPU/drive models,
NVMe endurance/replacement, dedicated resources, unfiltered UDP and actual route
reachability. Confirm both provider security groups and host firewall. NAT needs
correct ADNL/QUIC forwarding and, where applicable, hairpin routing. Keep console
access for recovery. Do not commit real provider accounts, addresses or credentials.

### 4.4 Spread the rest of the network too

Use independent DHT bootstraps, RPC/snapshot sources and chain observers. A
provider outage must not silence every alert path. Testnet's alert peer checks a
heartbeat only, so it does not satisfy independent chain-observer coverage.

### 4.5 Keep an inventory

Keep the approved private inventory outside this repository: roles, public
identities, provider/ASN/site, resource model, jurisdiction and verification date.
Use the testnet preflight only for its actual checks, after review. Supplying
`--profile` can change floors but cannot turn the x86 build installer or testnet
network assumptions into an accepted production procedure.

### 4.6 Be ready to move

Rehearse a human-approved host migration with authenticated network state,
verified binaries and a safe custody transfer. Fence the old host so it cannot
restart before activating the same identity elsewhere. Never clone a live
signer's database/key onto another active node. Preserve duties and held-stake
recovery through the move.

## 5. Open items

- Measure capacity/endurance and recovery at the intended validator count and load.
- Approve hardware, resource limits and release-test conditions.
- Maintain a verified private inventory and a concentration-check procedure.
- Rehearse loss of a provider, a disk and a signing host without losing custody
  or the chain's quorum.

No production host is approved by this document alone. Stop on a failed check;
retain sanitized evidence and obtain an explicit decision before deployment.
