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
separated from the current build's read-only preflight. The requested new live
alarm/staleness injections remain blocked before injection by pruned registry and
actor history. Neither a unit test nor a saved historical log is relabelled as a
live rerun. A fresh accepted run with immediate receipt capture is still needed.
