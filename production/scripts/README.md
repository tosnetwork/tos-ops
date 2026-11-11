# Read-only network checker

`check-network.py` runs from any HTTP client machine. It needs no validator
keys, SSH, console connection or local node database. Network identity is
explicit; no testnet profile or global-id default is used.

```sh
python3 production/scripts/check-network.py \
  --global-id 1 --global-config /etc/tos/global-config.json \
  --rpc https://node-a.example/jsonRPC --rpc https://node-b.example/jsonRPC \
  --min-version 16 --expected-auth-tag <64-hex-tag> \
  --proof-library "$TOS_ROOT/build-network-check/lite-client/proof-verify/libtosproofverify.so"
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
The explicit example above uses the clean build below; the optional automatic
lookup still uses `$TOS_ROOT/build/lite-client/proof-verify/libtosproofverify.so`.
It does not build or install the library for you.

## Build the verifier

Use an independently held, authenticated tos checkout at
`85c679c3454f306eb867e25b1960ae3d757bd3dd`, with its vendored dependencies intact.
Install the prerequisites described in that commit's `BUILD.md`. The tested
profile is Linux x86-64, Release, clang-21/clang++-21 and Ninja. Run from this
settings repository, with `TOS_ROOT` naming that checkout:

```sh
set -eu
TOS_COMMIT=85c679c3454f306eb867e25b1960ae3d757bd3dd
test "$(git -C "$TOS_ROOT" rev-parse HEAD)" = "$TOS_COMMIT"
test -z "$(git -C "$TOS_ROOT" status --porcelain --untracked-files=no)"
# Use a new directory, not an existing node build.
test ! -e "$TOS_ROOT/build-network-check"
cmake -S "$TOS_ROOT" -B "$TOS_ROOT/build-network-check" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21
cmake --build "$TOS_ROOT/build-network-check" --target tos-proof-embedded -j8
export PROOF_VERIFY_LIBRARY="$TOS_ROOT/build-network-check/lite-client/proof-verify/libtosproofverify.so"
for symbol in tos_proof_acquire tos_proof_verify_embedded; do
  nm -D --defined-only "$PROOF_VERIFY_LIBRARY" | awk '{print $3}' | grep -Fx "$symbol" || exit 1
done
(cd "$TOS_ROOT/build-network-check/lite-client/proof-verify" &&
  sha256sum libtosproofverify.so > libtosproofverify.so.sha256 &&
  sha256sum -c libtosproofverify.so.sha256)
```

Use a fresh directory; change `build-network-check` consistently if that name
is already in use. Reduce `-j8` on machines with less build memory. `tos-proof-embedded` is a
shared-library target marked `EXCLUDE_FROM_ALL`: building the node or the default
target does not produce it. It emits the `.so` at the exact path above, with the
two C ABI exports `tos_proof_acquire` and `tos_proof_verify_embedded`; either
missing symbol or a load failure is refused with a pointer to this section.
Record the source commit, compiler version, build flags and resulting digest
alongside the check report. Keep the checksum manifest independently; after
copying the library, compare it with that trusted manifest before use. For later
runs, repeat `sha256sum -c libtosproofverify.so.sha256` from the library directory
using that saved manifest; do not regenerate it from a replacement binary. A digest
recorded by an endpoint being checked is not an independent reference.

Never fetch the checkout, verifier binary, manifest or trusted network anchor
from a checked endpoint. The digest in the evidence identifies one local build,
not a promise of bit-identical binaries across compilers, build paths or flags.
See [the clean-build evidence](../../testnet/acceptance/evidence/README.md) for the measured digest and
live rerun. Python packages or a running validator are not needed to build or
load this C ABI.

## HTTP resource bounds

The HTTP transport is read-only, limits each response to 96 MiB, and starts at most one request per
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
- Config34's exact cell hash equals the Elector's active result, identified by
  both `active_hash` and `active_id`, and elected identities and weights equal
  that election's frozen records;
- Config32 is really an earlier term and equals the active election result
  authenticated at its last active block. A retained record alone cannot
  establish that an election was previously active.

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
TOS_ROOT="$TOS_ROOT" \
PROOF_VERIFY_LIBRARY="$TOS_ROOT/build-network-check/lite-client/proof-verify/libtosproofverify.so" \
  python3 -m pytest -q testnet/tests
TOS_ROOT="$TOS_ROOT" \
PROOF_VERIFY_LIBRARY="$TOS_ROOT/build-network-check/lite-client/proof-verify/libtosproofverify.so" \
  python3 testnet/tests/mutants.py
```

The recorded proof tests need that library; without it they explicitly skip.
An acceptance run must supply it and must execute both the valid proof and the
signature/link negative controls. The ordinary unit suite needs only pytest.
