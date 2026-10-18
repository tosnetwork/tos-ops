# Read-only network checker

`check-network.py` runs from any HTTP client machine. It needs no validator
keys, SSH, console connection or local node database. Network identity is
explicit; no testnet profile or global-id default is used.

```sh
python3 production/scripts/check-network.py \
  --global-id 1 --global-config /etc/tos/global-config.json \
  --rpc https://node-a.example/jsonRPC --rpc https://node-b.example/jsonRPC \
  --min-version 16 --expected-auth-tag <64-hex-tag> \
  --proof-library /opt/tos/lib/libtosproofverify.so
```

Global id 2 uses the same command with `--global-id 2` and that network's
independently held global config and AUTH tag. The global config supplies
`validator.zero_state` and, when present, `validator.init_block`. Never obtain
that file, the expected tag, or the verifier library from an endpoint being
checked. An init block is an explicitly trusted key-block anchor, not a claim
that the checker authenticated its earlier ancestry.

Python uses only the standard library. Cell/RPC primitives already used by the
existing testnet checker are reused from `testnet_lib`; no parallel codecs were
added. Full proof verification uses the existing consensus verification library
through its C ABI, with HTTP callbacks to `getProofQuery`. It is not a new
Python signature implementation. A verified library can be installed on a
non-validator machine; `TOS_ROOT` is optional and only supplies its default path.
To build the library from an authenticated source checkout:

```sh
cmake --build "$TOS_ROOT/build" --target tos-proof-embedded
```

The default path is
`$TOS_ROOT/build/lite-client/proof-verify/libtosproofverify.so`. The HTTP transport
is read-only, limits each response to 96 MiB, and starts at most one request per
450 ms per endpoint. Native proof acquisition has a 64 MiB material budget and
an acquisition deadline. No transaction, configuration or local node state is
written. Pick independently operated endpoints; multiple URL aliases do not
establish operational independence.

## Checks and evidence

The JSON report contains a named status and evidence for each completed check:

- every endpoint's zero state equals the held identity;
- full masterchain block identity at the common head, not just equal height;
- freshness of each node's head, explicit global id, Config19, Config8 minimum
  version, and mandatory/critical Config48 (from version 16 or when Config9 requires it) with the expected
  AUTH tag or exact hash;
- key-block chain from the held anchor and PQ finality for the exact common
  head, verified by the consensus core; authenticated timestamps must also match
  the reported header and satisfy freshness;
- Config1 selects the Elector address; its configuration and account proofs at that same block, compared with
  the public replies from every endpoint;
- Config34's exact cell hash equals the Elector's retained `vset_hash`, and
  elected identities and weights equal its frozen records;
- Config32 similarly equals the previous election's result and is really an
  earlier term. If that frozen record has been removed, historical proof
  acquisition checks it at its last active block.

Frozen records contain identity, owner, weight and stake, **not public keys**.
The full elected-set cell hash is therefore essential: it commits to the keys,
ADNL, term and ordering as well as the fields reconstructed from frozen records.
A member/weight-only comparison is insufficient. Genesis was not elected: a
`NOT_APPLICABLE` initial-set result requires equality with Config34 authenticated
at block 1 from the zero-state anchor, not merely an empty election history.

An exact Config48 hash can additionally be pinned with
`--expected-cp48-hash <64-hex>`. Unlike a tag pin, that refuses a governance
replacement of the policy cell. At version 16 the checker refuses to proceed
without an independently expected tag or hash.

`PASS` and `ok: true` with `strength: anchor_verified` mean anchored verification
was actually performed. Only when **every** endpoint reports `getProofQuery`
as an unknown method does the checker fall back to `WEAKER` and
`strength: node_equality_only`. This is explicitly weaker detection, not a proof.
A served route with malformed, forged or unavailable material fails closed.
A missing verifier library also fails; it does not turn a node's verification
claim into client verification. Exit 0 means all available requirements passed;
exit 1 includes the first unverified/failed requirement and all prior evidence.

Historical state availability matters. A live chain may have removed the
previous frozen record and already collected the historical state needed to
prove it. In that case the current-set check can pass while Config32 is `FAIL`
with an evidence-unavailable reason. Use an archival HTTP endpoint retaining the
required states. The checker does not call mere agreement a verified election
result and does not report unavailable historical evidence as a wrong election.

The testnet CLI retains its arguments and summary shape. It calls the same
agreement implementation, then adds its explicit global-id-2 profile policy,
genesis/elected-record checks and ceremony AUTH rule. Its existing operator
record check is not relabeled as an Elector proof; use this production entry
point for that stronger check.

## Tests

```sh
TOS_ROOT=<source-checkout> \
PROOF_VERIFY_LIBRARY=<verified-library> \
  python3 -m pytest -q testnet/tests
TOS_ROOT=<source-checkout> \
PROOF_VERIFY_LIBRARY=<verified-library> \
  python3 testnet/tests/mutants.py NC1 NC2 NC3 NC4 NC5 NC6 NC7 NC8 NC9 NC10 NC11 NC12 NC13 NC14 NC15 NC16 NC17 NC18 NC19
```

The recorded proof tests need that library; without it they explicitly skip.
An acceptance run must supply it and must execute both the valid proof and the
signature/link negative controls. The ordinary unit suite needs only pytest.
