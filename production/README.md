# Production network

Settings for nodes on the production network. This is a **design and template
set, not an accepted deployment**. The design every file here follows is
[Production-Node.md](Production-Node.md). Its section 12 tracks twelve gaps
(G1–G12) and what tos PR #148 closes. The global config's authenticated
distribution, production sizing, cleanup evidence from a live multi-host network,
a live multi-node key rotation and an accepted production unit are still open.

| Path | Contents |
| --- | --- |
| `Production-Node.md` | Design: node roles, key custody, options, retention, joining, validator lifecycle, monitoring, gaps |
| `Hardware-and-Hosting.md` | Physical requirements per role, disk endurance, bare metal vs VM, and hosting-provider diversity rules drawn from Solana's outages (proposal; gap G8) |
| `systemd/tos-validator.service` | Proposed hardened validator unit (design section 7) |
| `systemd/tos-elections.service` | The validator host's elections task, `tosctl service` as the user `tos-ctl` (design sections 4 and 7) |

The unit assumes the layout from design section 4:

- `/usr/local/bin` for release binaries;
- `/etc/tos/global-config.json`;
- `/var/lib/tos/<role>` for the database;
- `/var/log/tos/<role>` for logs.

Before using it:

- install binaries only from a tagged release, verified by digest;
- generate `<db>/config.json` with the two-phase first start (design section 5);
- on a validator, bind the consensus key with `tos-pq-consensus-key bind-node`
  while the node is stopped (design section 5.1);
- review the retention options against the disk plan (design section 6);
- check that the build cleans up retired consensus databases by default
  (`validator-engine --help` lists `--disable-validator-consensus-cleanup`,
  design section 6.4).

Do not copy anything from `local/` here. Deterministic seeds, the faucet wallet,
the development drivers and `--test-consensus-cleanup-crash-before-erase` are
development-only.

Node keys (consensus seed, keyring, console keys) and the controller root key
are never stored in this repository. See design section 3 for where each one
lives.

## Network correctness checks

The read-only [HTTP checker](scripts/README.md) takes an explicit network identity,
compares independent nodes, checks Elector results and reuses the consensus proof
verifier from a held anchor. It needs no validator keys or SSH.
