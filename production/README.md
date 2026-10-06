# Production network

Settings for nodes on the production network. This is a **template set, not an
accepted deployment**. The design every file here follows is
`doc/Production-Node.md` in the tos repository. That design lists twelve gaps
(G1–G12) that must be closed before an external validator can follow it.

| Path | Contents |
| --- | --- |
| `systemd/tos-validator.service` | Proposed hardened validator unit (design section 7) |

The unit assumes the layout from design section 4:

- `/usr/local/bin` for release binaries;
- `/etc/tos/global-config.json`;
- `/var/lib/tos/<role>` for the database;
- `/var/log/tos/<role>` for logs.

Before using it:

- install binaries only from a tagged release, verified by digest;
- generate `<db>/config.json` with the two-phase first start (design section 5);
- review the retention options against the disk plan (design section 6).

Do not copy anything from `local/` here. Deterministic seeds, the faucet wallet,
the development drivers and `--enable-validator-consensus-cleanup` are
development-only.

Node keys (consensus seed, keyring, console keys) and the controller root key
are never stored in this repository. See design section 3 for where each one
lives.
