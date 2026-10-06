# Network settings

Node service settings, operating documents and scripts for the TOS networks the
team runs. Each network has its own subdirectory. The tos repository holds the
node software; this repository holds how we configure, deploy and operate it.

## Directory layout

```
.
├── README.md                    this file
├── AGENTS.md                    working rules for agents and people (CLAUDE.md links here)
├── .gitignore                   keeps keys, seeds, tokens and certificates out
├── local/                       single-host local PQ development network
│   ├── README.md                guide: setup, controller funding, retention, health rebinding
│   ├── OPERATIONS.md            elections, random transfers, shielded-pool traffic
│   ├── PREPARATION.md           topology and port plan
│   ├── DEFECTS-20261006.md      record of the election-authorization and snapshot defects
│   ├── scripts/                 installer, control, drivers, snapshot installer
│   │   ├── setup-testnet.sh
│   │   ├── testnet-ctl.sh
│   │   ├── local_pq_testnet.py
│   │   ├── local-pq-elections.py
│   │   ├── local-pq-election-absence-drill.py
│   │   ├── local-pq-fund-controllers.py
│   │   ├── local_pq_funding.py           operating-authorization renewal (deficit, readback)
│   │   ├── local_pq_funding_policy.py    30-day sizing, renew at 25 %
│   │   ├── local_pq_transactions.py      faucet lock and crash-safe send journal
│   │   ├── local_pq_election_evidence.py
│   │   ├── local_pq_test_wire.py
│   │   ├── check-local-pq-elections.py   election health check (testnet-ctl.sh check)
│   │   ├── check-local-pq-resources.py   snapshot admission: run the generator protected
│   │   ├── check-local-pq-protected-resources.py
│   │   ├── local-pq-transfers.py
│   │   ├── local-pq-privacy.py
│   │   ├── check-local-pq-relays.py
│   │   ├── run-local-lite-client.py
│   │   ├── install-root-services.sh
│   │   └── install-root-services-check.py
│   ├── systemd/                 unit templates
│   │   ├── tos-pq-dht.service
│   │   ├── tos-pq-validator@.service
│   │   ├── tos-pq-observer@.service
│   │   └── tos-pq-lite-client.service
│   └── tests/                   driver and installer tests (pytest)
├── development/                 shared multi-host development network (empty)
│   └── README.md
└── production/                  production network design and templates
    ├── README.md
    ├── Production-Node.md       design: roles, keys, options, retention, validator lifecycle, gaps
    └── systemd/
        └── tos-validator.service
```

## Conventions

- **No secrets.** Never commit SSH keys, private keys, consensus or root seeds,
  wallet keys, console or edge tokens, or TLS private keys. `.gitignore` blocks
  the usual file names, but check every change before committing.
  Development-only fixture seeds are generated at setup time under `/data` and
  stay there.
- **English** for all files.
- **Scripts depend on a tos checkout.** Scripts that use tos code or binaries
  find them through the `TOS_ROOT` environment variable. Record the tos
  revision a change was verified against in its commit message.
- **One network per directory.** Do not copy development-only material
  (deterministic seeds, faucet wallets, the local drivers) into `production/`.
