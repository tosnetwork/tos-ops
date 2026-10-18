# Epoch-4 read-only checker evidence

`epoch4-live.json` is the complete production check report from the four
coordinator HTTP forwards, on public testnet source `85c679c34`, global id 2.
It uses the independently held ceremony global config and AUTH tag. Each
endpoint is limited to one request per 450 ms. No SSH, keys, broadcasts or
configuration changes were used.

Reproduction, substituting the coordinator's paths and a verified library:

```sh
python3 production/scripts/check-network.py \
  --global-id 2 --global-config "$CEREMONY/global-config.json" \
  --rpc http://127.0.0.1:18381/jsonRPC \
  --rpc http://127.0.0.1:18382/jsonRPC \
  --rpc http://127.0.0.1:18383/jsonRPC \
  --rpc http://127.0.0.1:18384/jsonRPC \
  --expected-auth-tag e36440a2e7704d9e26c79c5d9ba462507783b18404e876da9a232d38722e28fd \
  --proof-library "$PROOF_VERIFY_LIBRARY"
```

The run proves the common head from the held zero state, including the key-block
chain and exact head PQ finality, then proves its configuration and Elector state.
Config34 matches the Elector's exact elected-set commitment and frozen member
weights. All four nodes agree on the full block identity and public state.

The **overall exit is 1**, intentionally. Config32's frozen record has already
been removed. The checker attempts the historical state at the previous term's
last active time; every named source returns `Proof response unavailable`.
Thus Config32 cannot be checked against its historical Elector result from
these endpoints. The report preserves the current-set PASS and names the
previous-set FAIL. It does not declare the election wrong, downgrade unavailable
historical material to successful equality, or claim a completely verified run.
An archival HTTP source retaining that state is needed for a green live gate.

`run-metadata.json` records the source revision, library digest, input digests,
report digest and the tested gate results. The raw RPC evidence in the report
records selectors and response digests; it contains no private key, token or
personal path. The current snapshot's public cells and Elector data are also
retained as test fixtures under `testnet/tests/data/network-check-epoch4.json`.
That fixture's exact block is recorded separately; the live run advances its
head rather than pretending it is the same snapshot.
