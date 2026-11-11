# Epoch-4 read-only checker evidence

## Clean-build rerun

The verifier is built from the independently held tos commit
`85c679c3454f306eb867e25b1960ae3d757bd3dd`, using a new `build-network-check`
directory, Release, clang-21/clang++-21 and Ninja. Follow
[the complete build instructions](../../../production/scripts/README.md#build-the-verifier),
including the source check, dependency prerequisites, C ABI export checks and
checksum manifest. The exact target is `tos-proof-embedded`; it is excluded from
the default node build. Its output is
`$TOS_ROOT/build-network-check/lite-client/proof-verify/libtosproofverify.so`.
Both `tos_proof_acquire` and `tos_proof_verify_embedded` must be exported.
The measured clean-build SHA-256 is
`9ca8beeeba42dd700c8694f0c0dd308068395e5003dcf345df193c3787aeb08d`.

`clean-build-live.json` contains the read-only rerun with that newly built
library; `clean-build-metadata.json` records the source commit, commands,
compiler, digest and report/input digests. The rerun verifies held-anchor PQ
finality and the active Config34 result; it still exits 1 because all four
sources lack the historical proof needed for Config32. Record your own independently built
library's checksum and compare any installed copy with that trusted manifest.
Never obtain the verifier, source checkout, manifest or anchor from a checked
endpoint. The recorded digest identifies this build; different compiler versions,
paths or flags can produce different bytes.

## Original artifact provenance

The original verifier digest was
`5cac3277f25dd7d97bc95f652b64dcba4718987fa2d379a78e9ce44ce4f9900d`.
It was a pre-existing `tos-proof-embedded` shared-library artifact from a local
Release/clang-21/Ninja signature-parser build, reused without rebuilding for this
check. It was not produced by the coordinator's epoch-4 node build. Its link
output is dated 2026-10-17; no clean source-tree manifest was retained for that
artifact, so an exact clean commit cannot be attested retrospectively. The
original report's `source_revision` names the live node/fixture source, not a
proven source pin for that library. Treat that build provenance as unverified;
the clean-build rerun above supersedes it.

`epoch4-live.json` is the original production check report from the four
coordinator HTTP forwards, on public testnet source `85c679c34`, global id 2.
It uses the independently held ceremony global config and AUTH tag. Each
endpoint is limited to one request per 450 ms. No SSH, keys, broadcasts or
configuration changes were used.

Read-only reproduction after completing the clean build above, substituting
only the independently held ceremony directory and tos checkout:

```sh
python3 production/scripts/check-network.py \
  --global-id 2 --global-config "$CEREMONY/global-config.json" \
  --rpc http://127.0.0.1:18381/jsonRPC \
  --rpc http://127.0.0.1:18382/jsonRPC \
  --rpc http://127.0.0.1:18383/jsonRPC \
  --rpc http://127.0.0.1:18384/jsonRPC \
  --expected-auth-tag e36440a2e7704d9e26c79c5d9ba462507783b18404e876da9a232d38722e28fd \
  --proof-library "$TOS_ROOT/build-network-check/lite-client/proof-verify/libtosproofverify.so"
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

The original `run-metadata.json` records the node/fixture source revision, library digest, input digests,
report digest and the tested gate results. The raw RPC evidence in the report
records selectors and response digests; it contains no private key, token or
personal path. The current snapshot's public cells and Elector data are also
retained as test fixtures under `testnet/tests/data/network-check-epoch4.json`.
That fixture's exact block is recorded separately; the live run advances its
head rather than pretending it is the same snapshot.
