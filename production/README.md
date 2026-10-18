# Production network: planning only

This directory holds **designs and service templates, not an accepted production
deployment**. For an independent public-testnet operator use
[OPERATOR.md](../testnet/OPERATOR.md); for any operation read
[AGENTS.md](../AGENTS.md). Do not copy the local/testnet profile into mainnet.

| File | Use |
| --- | --- |
| [Production-Node.md](Production-Node.md) | Roles, custody, layout, retention, lifecycle, maintenance and [acceptance gaps](Production-Node.md#12-gaps-before-this-procedure-can-be-followed) |
| [Hardware-and-Hosting.md](Hardware-and-Hosting.md) | Proposed capacity, endurance and failure-domain requirements |
| [tos-validator.service](systemd/tos-validator.service) | Proposed non-root validator unit |
| [tos-elections.service](systemd/tos-elections.service) | Proposed non-root operator/elections unit |

There is no production installer or deployment acceptance suite here.
The templates assume `/usr/local/bin`,
`/etc/tos`, `/var/lib/tos/<role>` and `/var/log/tos/<role>`; installation, network
artifacts, release provenance and live acceptance need separate approval.

Node interfaces were checked against tos `85c679c3454f306eb867e25b1960ae3d757bd3dd`.
Available tooling does not establish mainnet readiness. Keep generated state,
keys and private inventory outside the repository.

## Network correctness checks

The read-only [HTTP checker](scripts/README.md) takes an explicit network identity,
compares independent nodes, checks the active and previous Elector results and
reuses the consensus proof verifier from a held anchor. It needs no validator
keys or SSH. Follow its [pinned proof-library build instructions](scripts/README.md#build-the-verifier)
before running it. Its [recorded evidence](evidence/README.md) identifies the
verifier build and the historical Config32 proof availability limitation.
Fixture tests and mutation controls live in `testnet/tests`; this tooling does
not establish mainnet readiness or replace deployment acceptance.
