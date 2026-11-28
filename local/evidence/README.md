# Local token-rail evidence

The original [lifecycle record](service-token-usdc-20261126.json) is retained
unchanged. Its buyer-driven continuation is
[the buyer record](service-token-buyer-usdc-20261126.json), followed by
[the isolated returned-case record](service-token-returned-local-20261126.json).
The records describe historical observations, not a new live verification.

[Saved public verifier outputs and transaction BOCs](service-token-public-20261126/INDEX.json)
are indexed by SHA-256. Verifier outputs omit local tool/input paths; transaction
BOCs are unmodified public chain data. The saved returned receipt chain includes
the source send, genuine refusal at the recipient, bounce to the source wallet,
and the actor's returned-entry transaction for both requests. It does not include
the later claim transaction BOC.

The bundle is **incomplete**: original lifecycle and buyer transaction BOCs were
not captured before history pruning. Their saved verifier outputs remain useful
historical evidence but cannot replace those transaction cells for offline
reconstruction. Do not treat the missing receipts as passed archival checks.
The original resolver used sending references for the first lifecycle runs;
the buyer and returned runs used nodes 4–6. New driver verification requires
nodes 4–6, disjoint from its sending endpoints, and writes a provenance sidecar.
This is the same production resolver in a separate process, consistent with the
native-rail verification model; it is not an independently implemented parser.

The [committed-build monitor replay status](service-token-public-20261126/monitor-replay-status.json)
records the exact historical refusal text and request/slot identifiers, clearly
separated from the current build's read-only preflight. That historical attempt stopped before injection because registry and actor
history had been pruned; it remains unchanged. It is superseded for the fresh-run
requirement by the [new monitor-injection record](service-token-monitor-local-20261127.json).
Neither a unit test nor an old log is relabelled as a live rerun.

## Fresh monitor-injection run

The [complete fresh bundle](service-token-monitor-public-20261127/INDEX.json)
retains 35 transaction BOCs and 21 verifier outputs for 15 captured steps. The
fresh actor and registry identities avoid the old pruned registry history. The
buyer paid 100,000 atomic test units, both monitor faults refused execution in
the same admitted slot, and clearing the report allowed one execution and a
response. Nodes 4–6 independently reconstructed pending and responded states.
All captured checkpoints satisfy the token invariant and reconcile the original
25,000,000-unit supply. Validator CPU caps remained at 55%; no validator service
or chain configuration changed.

Both bundles have a `SANITIZATION.json`: each output names the original SHA-256
cited by its record and every removed JSON pointer. The checker verifies the
original bytes, the citation, and the exact removal transform. All transaction
cells remain byte-for-byte public chain data. The earlier pruning gap stays an
accepted, explicit limitation; the new run does not fill it with invented cells.

## Refusal namespace identity

The local refusal entry uses source-chain id `56`, as required by the slot-81
bridge compiled with `params/bsc.fc` (`MY_CHAIN_ID = 56`). Its distinct
`LOCAL_ONLY_TEST_REFU` source-token bytes and pinned refusing wallet code mark
it as a test asset. The wallet requires `GLOBALID == 3`; the driver also binds
every endpoint to the approved local genesis. An arbitrary larger chain id
would not fit ConfigParam 84 or the bridge's uint32 field and would fail its
vote check. The retained returned-case evidence already used this valid id.

## Stablecoin final acceptance

The [local stablecoin acceptance](stablecoin-acceptance/README.md) covers:

- the canary under the decided caps and the cap raise;
- the LocalUSDT freeze drill, with incident resolution and resume;
- the fee-on-transfer and no-`bool` cases;
- the bridge lock-switch drill.

It replaces the public-testnet stage (memo decision 32).
