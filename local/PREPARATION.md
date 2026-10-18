# Local PQ deployment preparation

This is a **local-only topology and preparation reference**, not a statement
that a host is stopped, reset or ready. Inspect `/data/network.json`, actual
service state and [the initialization runbook](README.md#initialize) first.
All resets require explicit human approval; never reuse this procedure on testnet.

Topology: one DHT, four PQ validators, two non-validator full nodes and one
standalone lite-client process. Only the four validators belong to Config34.

| Role | Data directory | ADNL UDP | LiteServer | Console | JSON-RPC |
| --- | --- | --- | --- | --- | --- |
| DHT | `/data/testnet/node0` | 2001 | — | — | — |
| Validator 1–4 | `/data/testnet/node1` … `node4` | 2002/2005/2008/2011 | 2003/2006/2009/2012 | 2004/2007/2010/2013 | 8011–8014 |
| Observer 5 | `/data/testnet/node5` | 2014 | 2015 | 2016 | 8015 |
| Observer 6 | `/data/testnet/node6` | 2017 | 2018 | 2019 | 8016 |
| Lite-client | `/data/lite-client` | No listener | Queries 2015/2018 | — | — |

`local_pq_testnet.py plan` only writes a topology and service templates into
`/data/preparation`. `prepare-observers` creates independent observer identities
and configs against the retained Genesis without invoking native tools,
starting services, changing validator membership or sending transactions.
Observers have no PQ consensus seed or validator configuration. During a protocol review, keep the services stopped until the human approves
activation. Inspect actual service state rather than assuming planning stopped them.

A historical preparation retained keys/configs/genesis while removing runtime
data. Do not assume that condition on a current host. `plan` and
`prepare-observers` do not authorize deleting or starting an existing chain;
inspect the retained plan and network identity before a human approves deployment.

After protocol review, use the reviewed binaries for all nodes together. Planning does not install the service templates or lite-client wrapper and
does not start them; that requires the approved installation step. Check resources and free ports,
start the DHT/validators/observers, then verify a common full block ID and the
four-member PQ Config34. Re-deploy and verify the pool before starting the
standalone lite-client service.

For a completely new Genesis, `setup-testnet.sh --clean` creates all six full
nodes and the pool through the normal installation path. It is a deployment
command, not a preparation command. `setup-testnet.sh --plan-only` cannot build,
clean data or start a service.
