# Issuer precheck and unsigned redemption

`testnet/scripts/prepare-token-redemption.py` builds the bridge token wallet's
burn body only after a fresh issuer check. It never signs, reserves a wallet
sequence number or broadcasts. There was no bridge-redemption CLI in tosctl or
ai when this path was added. The generic JS token wallet's `sendBurn` is not a
bridge redemption builder: it has no source receiver payload. It is unchanged.
The bridge wallet and settlement protocol are TOS-specific; no inherited
implementation or upstream fix is being modified.

The operator-owned binding has exactly these fields:

- `schema`: `tos-settlement-issuer/1`;
- `chain_id`: the source chain id;
- `token`: its canonical `0x` issuer token address;
- `code_sha256`: SHA-256 of the expected deployed runtime code;
- `profile`: `standard` for `isBlacklisted`/`paused`, or `legacy_usdt` for
  `isBlackListed`/`paused`/`deprecated` and the fee getters;
- `master`, `wallet`: canonical workchain-0 TOS token accounts.

The binding is policy, not endpoint-supplied state. Before approving it, verify
the wallet's master and the pinned route to that exact issuer token. This tool
does not prove a TOS wallet's route, submit a burn or promise an unlock.

```
python3 testnet/scripts/prepare-token-redemption.py \
  --rpc https://RPC_ENDPOINT --binding issuer-binding.json \
  --receiver 0xRECEIVER --amount ATOMIC_AMOUNT --query-id QUERY_ID
```

The read-only RPC implementation is shared with `collect-settlement-evm.py`.
It selects `finalized`, pins all code/getter reads by block hash with
`requireCanonical`, validates the chain and runtime code, checks receiver
blacklist and pause, and refuses a deprecated legacy issuer. It checks the
number/hash again after the reads. Failed or malformed calls never imply
`false`. Finalized block age must be at most 1,800 seconds (allowing normal
finalization lag); future skew is bounded to 30 seconds, checked again before
building. A refusal emits no burn BOC and exits nonzero.

The document shows the burned amount, issuer fee and received amount, using
integer arithmetic: `min(amount * basisPointsRate / 10000, maximumFee)`. Source
locks mint that received delta; redemptions receive that delta. TOS wallet
transfers have no such issuer fee and still obey the actor's exact-amount rule.

**A recorded burn is final.** An issuer may change restrictions after the
finalized read; an unlock that then reverts can remain unredeemable to the
chosen receiver. A preview is not a durable authorization or a promise of
execution. Re-run the precheck immediately before any later manual signing;
never reuse an old prepared body merely because it exists.

The explicit isolated fixture lane is `testnet/tests/anvil_redemption.py`.
It starts its own loopback node, requires its dependencies, exercises both
issuer ABIs, and compares fee previews with a real received-balance delta.
No live TOS value is moved.
