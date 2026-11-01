# Frozen Epoch-6 PRI recovery candidate

The reviewed public PRI driver cannot rebuild a recovery mint. This patch adds
bounce replay, reservation consumption, recovered-note import/spending, an explicit
raw withdrawal destination, and a deploy entry for the existing frozen refuser.
It changes test tooling only; it does not change pool or consensus code.

`materialize.py` checks SHA-256 of all six reviewed driver source inputs, the
original transport and the frozen recipient StateInit, then writes a **new**
candidate directory. Rust sources are normalized first with the pinned rustfmt
1.8.0-stable (e408947bfd 2026-03-25), keeping the behavioral patch reviewable;
pass `--rustfmt` if it is not on PATH. It never copies any run, seed or private journal, never
signs, and never sends. Existing source/output is not overwritten. Dependencies
remain on the separately retained source export of tos
`c1cb3b8d699daf037106fd5f000c53d79c40f295`, used for the deployed Epoch-6 pool.
Use that export for `--tos-source`; newer node sources are not a replacement for
this frozen contract/circuit profile.

```sh
python3 materialize.py --driver-source "$REVIEWED_DRIVER" \
  --transport-source "$REVIEWED_TRANSPORT" --tos-source "$FROZEN_TOS" \
  --recipient "$FROZEN_RECIPIENT" --output "$NEW_CANDIDATE"
cargo test --manifest-path "$NEW_CANDIDATE/Cargo.toml" --release --locked \
  --offline --test recovery
PRI_E6_RECIPIENT="$FROZEN_RECIPIENT" python3 \
  "$NEW_CANDIDATE/tests/test_recovery_transport.py"
cargo build --manifest-path "$NEW_CANDIDATE/Cargo.toml" --release --locked --offline
```

Use the same production ceremony, VK and transcript pins as the reviewed driver.
The sibling adapter is hash-pinned to the materialized driver. Binaries have
separate names (`pri-e6-core`, `pri-e6-sandbox`); the old public binary is retained.
The local `pri-e6-sandbox recovery ROOT CEREMONY NEW_PRIVATE OUT GLOBAL_ID`
command refuses public global ID 2 and runs global version 16. It deploys the
frozen refuser, obtains a protocol-generated bounce, spends its recovered note,
and replays the pool transactions to check getters, ownership and the ledger.
Never use its local seeds or accounts on the public chain.

## Recovery boundaries

A successful rich bounce must match the exact body hash and recipient of an
already authenticated outbound payout, be unconsumed, and return no more value
than that payout. The model consumes the reservation once and mints only
`returned - recovery_charge`; dust consumes the reservation without minting.
It replaces the unspendable recovery template with the minted note so the same
index is not incorrectly counted twice. The reconstructed state must match all
six getters on both peers, including `reserved_recovery_leaves`.

The quoted charge uses current ConfigParam 21 and the frozen contract's gas
ceiling. Historical gas-price changes are not replayed: a changed historical
charge leads to getter disagreement and a refusal. This candidate is intended
for the fixed-price Epoch-6 interval, not arbitrary historical networks.

Raw `--recipient 0:<64 lowercase hex>` is withdrawal-only and exclusive with
`--recipient-wallet`. A withdrawal followed by a bounce is accepted only when
its own exact transaction is followed by that successful bounce, the recovery
record belongs to this destination, and all commitment/index/liability/
reservation/nullifier deltas match. Unknown or delayed outcomes stop; no retry,
resign or automatic progression is added.

`recipient-deploy --recipient-artifact DIR --value NANOTONS` pins the existing
StateInit SHA-256 and address, requires absence on both peers, requires explicit
funding capped at 5 TOS, and uses the existing journal-first, single-send path.
A dry run does not sign or send. Confirm the deployed code and data hashes on
both peers before any withdrawal. This command is not a pool deployment.

## Public execution

Building or merging these tools is not a public execution PASS. Apply the
existing network/zero-state identity, budget, quiet-window, dry-run and review
requirements. Do not send while a journal entry is unresolved. On an unknown
outcome use only read-only reconciliation; rebroadcast requires the existing
specific same-BOC decision. Do not repeat a completed command.

The public sequence is: reconcile/scan; recipient deploy dry/live and two-peer
code/data read-back; raw withdrawal dry/live; scan and recover the minted leaf;
transfer dry/live explicitly selecting that recovered leaf; final rescan,
ledger/backing/owner checks, and captured-surface leakage scan. A late bounce
requires a new scan; a successful withdrawal alone is not E6 acceptance.

## Upstream

Fetched upstream ton-c `857b8a57a178e6ae0fe7fa86e7d81c5233de8560` has no shielded
pool/PRI-driver counterpart. This is TOS-specific test tooling. The frozen
contract is unchanged; the difference between its handler and tos main
`d5114fea3afe231e5b7df5cc4dec4bbac3d8edcf` is comments. Wallet API additions in
main are outside the frozen driver profile.
