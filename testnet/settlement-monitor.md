# Settlement monitoring

`scripts/check-settlement.py` is the T14 per-actor, per-asset alarm checker.
It does not hold keys, build signed messages, vote, change recognition, or pause
an actor. It accepts only complete observations of pinned actors and assets.
USDC and USDT have independent identities, thresholds and alarm scopes even
when their bridge and shared windows coincide.

## Run

```
python3 scripts/check-settlement.py --policy policy.json --snapshot observation.json \
  --state-dir monitor-state --initialize-baseline
python3 scripts/check-settlement.py --policy policy.json --snapshot observation.json \
  --state-dir monitor-state
```

Run the second command on each freshly collected finalized checkpoint (for
example from an operator timer). Exit 0 means clear, 1 means alarms or latched
incidents, and 2 means incomplete/invalid evidence or a newly initialized
baseline. Never treat exit 2 as healthy. Send the JSON alarm records to the
existing operator alert sink; include `asset`, `actor` and `code` in its key.
Duplicate-key JSON, missing actors/assets, old checkpoints, incomplete inventories,
foreign wallets, non-integer amounts and rollback refuse the entire sample.
An advancing checkpoint must be observed within `max_age_seconds`; a frozen
checkpoint is not healthy. Keep the operator timer active even after alarms.

`--collect PROGRAM ARG...` optionally invokes an explicitly configured read-only
collector, with a 60-second timeout. It must atomically write `--snapshot`.
No collector or sender is selected implicitly. These adapters are deployment
dependencies, not supplied proof verifiers: this checker does not turn an RPC
answer or a `complete` flag into cryptographic proof. T7's finalized resolver
must authenticate the state before constructing the observation. An untrusted
collector can falsify the report. Never connect an unreviewed collector to a
funded sender.

Initial balance acceptance requires `--initialize-baseline`. It still returns 2:
there is no prior interval to reconcile. Do not use initialization to replace a
lost baseline after an incident. Preserve state and reconcile that gap first.
The state directory belongs to the operator, is private, and must not be writable
by a service actor or by a collector running with less trust. One flock covers
the complete sequence: read and check, latch incidents, reconcile the outbox
(no sends), publish `report.json`, bounded dispatch, republish the report with
the dispatch outcome, then install the baseline. Alarms, incidents and the
asset-scoped `provider_pause_assets` hook are therefore durable and published
**before** any send, so one asset's refusal recovery never delays another
asset's emergency. Each file is replaced atomically with file and
parent-directory fsync.
Inputs and state files are limited to 8 MiB; oversized writes refuse before
replacing the readable previous file. Schedule reviewed archival before outbox
growth reaches this bound; preserve unknown operations and deduplication history.

## Collector contract (version 1)

The fully executable two-asset example is `tests/test_check_settlement.py::fixture`.
It is also the boundary test for collectors. No production addresses or keys are
embedded. Policy schema is `tos-settlement-policy/1`:

- `network`: approved zerostate root hash (64 lowercase hex digits).
- `max_age_seconds`: positive, at most 3,600.
- `thresholds`: positive `payout_blocks`, `returned_seconds`, `returned_count`,
  `refusals_count` (at most 32), and the re-report clearance bounds
  `rereport_clear_blocks` (TOS blocks) and `rereport_clear_seconds` (chain seconds).
- `assets`: unique operator labels `id`, `symbol` (USDC or USDT), pinned `master`
  and `source_token`, pinned `implementation`, `min_lock_headroom` in atomic
  token units, and `occupancy_percent` (1 through 100).
- Each asset's `actors`: unique `id`, pinned `own_wallet`, `tos_floor` (operating
  reserve, at least 1 TOS applied by the checker), `wallet_tos_floor` in nanoTOS.

Observation schema is `tos-settlement-observation/1`, with `network`, `complete`,
`checkpoint` and `source_checkpoint` (each `height`, `hash`, `utime`),
`bridge_address` from ConfigParam 79, `recognition` (the **whole** ConfigParam 84
dictionary, each `master`, `status`, `bridge`, `bridge_config_param`), and `assets`.
The collector derives the parameter from the authenticated origin; the migration
alarm compares only parameter 79 records, not records of another bridge route.
Every configured
asset and actor must appear exactly once. Amounts are nonnegative integers or
canonical decimal strings, never floating-point values; no decimal scaling.

Read each actor and its wallet at the **same authenticated TOS checkpoint**:

| Observation | Getter / history source |
| --- | --- |
| `native_ledger.locked_storage_fees`, `locked_outcome_fees`, `returned_count`, `returns_in_flight` | `get_native_ledger` tuple positions 1, 2, 6, 7 (zero-based) |
| `token_ledger.pending`, `refundable`, `returned`, `in_flight`, `revenue` | `get_token_ledger`, all five positions |
| `own_wallet`, `accepting_tokens`, `rereport_funding` | `get_own_wallet`, `get_accepting_tokens`, `get_rereport_funding` |
| `tos_balance`, `wallet_tos_balance` | finalized account balances, not incoming-message values |
| `payouts`: `id`, `amount`, `created_height` | `get_payout` plus authenticated creation transaction's masterchain reference |
| `returned`: `id`, `amount`, `paying`, `created_utime`, `kind` | `get_returned` plus the authenticated outcome/creation history |
| `mismatch_events` | SAO1 outcome 4 since the preceding checkpoint |
| `refusals_count`, `refusals`: `query_id`, `amount` | wallet `get_refusals_count`, each entry confirmed by `get_refusal` |

Enumerate IDs from the actor's `next_payout_id`, payouts and complete outcome
history, plus the wallet's refusal transactions, including stale wallet records
whose actor payout has already disappeared. Do not scan only currently paying
payouts. Refusal entries must equal the getter count. Returned count and total,
and payout amount total, must match their getter aggregates. Returned liability
counts only entries with `paying == 0`; an in-flight claim still holds its entry
but its amount belongs to `in_flight`, not `returned`. Its `paying` id must name
the matching payout. A `get_returned`
answer alone does **not** contain kind or creation time; do not fabricate these
from the first monitor observation. Creation times are chain times. TVM true
(-1) must be normalized to JSON true by the collector.

For each source token, at one finalized source checkpoint, collect:

- `bridge_balance`, `wrapped_supply` (the minter's total supply on TOS), and
  `lock_cap`: `total`, `available`, `hourly`, `daily`, `hour_used`, `day_used`.
  Use `getLockCapState`, including its returned **minimum** available amount;
  total headroom alone misses per-lock and fixed-bucket limits.
- `swap_used`, `swap_limit`, `channels_used`, `channels_limit`: complete bridge
  window/channel occupancy; these are shared resources, not separate asset caps.
- `balance_from_hash`: exactly the previous source checkpoint hash;
  `balance_events`: unique canonical event IDs, `kind` (`Lock`, `Unlock`,
  `LockRefunded`), and `amount`. Locks use received delta, not requested amount.
  Refund amounts come from the recorded lock. Only successful finalized events
  of this exact token and bridge count. Reject incomplete log pagination,
  duplicate logs, changed block hashes, or a missing interval; set
  `events_complete` only after this verification.
- `bridge_blacklisted`, `paused`, `pause_events`, `destroy_events`, and pending
  `redemptions` (`id`, `blacklisted`). Event counts cover the entire interval,
  so pause followed by unpause still alarms. For USDT also collect
  `fee_basis_points`, `maximum_fee`, `deprecated`, `implementation`; the latter
  is a pinned identity including code/forwarding target, not merely a display
  version. A proxy target/code change must change this identity.

These source reads are monitoring evidence, not atomic cross-domain solvency
proofs. Supply and backing can temporarily differ during settlement. Alarm and
reconcile against open locks and burns; never mint or compensate from the alarm.
Balance reconciliation detects a net unexplained increase (including a donation
filling the cap) or decrease (including a burn). Equal opposite unexplained
changes within an interval can cancel: collect at every finalized source block
and retain token transfer/issuer events for investigation. This checker does
not claim transaction-level detection of perfectly offsetting changes.

## Funded refusal recovery

Every confirmed refusal produces a request in private `rereports.json` with the
actor, wallet, query ID, exact `rereport_refusal` opcode `52545131`, funding in
nanoTOS and checkpoint. Funding comes from the actor's `get_rereport_funding`:
the release computes twice the current compute/forward prices for wallet
re-report, absent-payout actor handling and wallet clear. A pending payout with
a different refusal total alarms `refusal_mismatch` and is **not** automatically
cleared. SAO1 mismatch events also alarm.

Enable `--rereport-adapter PROGRAM ARG...` only after approval of its operational
wallet, fee reserve, approved genesis and transaction verification. The monitor
passes one JSON object on stdin, adding a stable `operation_id`. The adapter
must perform wallet-scoped locking and reconcile-before-sign, pin the destination
and query ID, refresh prices at its current verified checkpoint (refuse if the
quoted funding is no longer enough), preserve allocated principal, durably
journal the exact signed bytes **before** broadcast, and never retry an unknown
submission. It must confirm the specific transaction, compute/action phases and
the emitted message, not merely a wallet nonce increase.

Its sole stdout result is JSON: `operation_id`, `status: confirmed`,
`transaction_hash` (64 lowercase hex), `compute_success: true`,
`action_success: true`, and `request_sha256` (SHA-256 of sorted-key JSON of the
full input). These are trusted adapter attestations, not proofs checked here.
No adapter stderr or raw error body is printed. Unknown is fsynced **before**
invocation; timeout, crash or malformed answer leaves it unknown, never
automatically resubmitted. Query IDs are never reused by this actor release.

Every run revalidates the whole outbox against the current observation before
anything is sent. Each entry is keyed by network, asset, actor, wallet and query
ID, and has one state:

| State | Meaning | Next |
| --- | --- | --- |
| `prepared` | eligible in this observation, never sent | refreshed each run; sent when dispatch reaches it |
| `withdrawn` | prepared but no longer eligible; `withdrawn.reason` is `refusal_absent` (record gone) or `ineligible` (for example a `refusal_mismatch`), with `observed_amount` and checkpoint | prepared again only if a later observation makes it eligible (kept as `last_withdrawn`); never sent while withdrawn |
| `unknown` | a send may have happened | alarms `rereport_unknown` every run, never sent again; becomes `cleared` only when a later observation shows the S-side record absent |
| `submitted` | the adapter confirmed the send | becomes `cleared` when a later observation shows `get_refusal(query_id)` absent; alarms `rereport_overdue` while the record remains more than `rereport_clear_blocks` blocks or `rereport_clear_seconds` chain seconds after the send checkpoint |
| `cleared` | record absent after a send | terminal; the record reappearing alarms `refusal_reappeared` |

A submitted receipt means dispatch, not clearance. An overdue or unknown
operation is never replayed automatically: the operator reconciles it read-only
(the adapter's journal, the wallet's transactions) and decides any new send.
Never edit an outbox entry simply to retry it.

Dispatch is bounded per run: at most `--rereport-max-per-run` sends (default 4,
at most 32), each with `--rereport-timeout-seconds` (default 20, at most 60), and
a send starts only while its timeout still fits in `--rereport-budget-seconds`
(default 60, at most 600). Assets alternate, so one asset's backlog never
starves another's sends. Remaining requests stay prepared and are listed in
`rereport_dispatch.deferred`; size the timer interval to the budget.
Without a sender, pending requests alarm `rereport_sender_missing`; this is an
observer-only installation, not an enabled refusal-recovery service.

## Alarm response

The checker reports payout age in **blocks**, returned age in chain seconds,
returned count, refused funding returns (kind 4), actor backing/operating floor,
wallet floor, refusal count against 32, returns headroom at **448** and full at
**512**, admission disabled, mismatches, aggregate monitored-actor token
liability and total wrapped supply against the per-asset bridge cap, lock
headroom, fixed hourly/daily usage, swap/channel occupancy, recognition overflow
(more than 16), and an active old-bridge recognition record. USDT adds fee and
upgrade alarms; freeze, pause, destroy and receiver-blacklist checks are explicit.

On **freeze, pause or destroy** (also unexplained backing decrease or shortfall):

1. Page the operator/oracles immediately, with asset identity and checkpoints.
   Oracles vote `voteForDisableToken` for that token or `voteForSwitchLock` at
   once; the latter stops locks for both assets. Do not wait for recognition.
2. Publish the asset-scoped `provider_pause_assets` hook. T8's provider runtime
   must clear `active` on its own actors using its signed `update_policy`;
   integration and signing in that runtime are outside T14. Buyer policy also
   refuses the affected asset. Do not pause the other asset merely because
   the two share a bridge.
3. Propose ConfigParam 84 **status 2** for the affected entry through the reviewed
   critical governance ceremony. It is a slow admission stop, not immediate
   redemption recovery. Existing TOS payouts/refunds still settle in the same
   token; never misrepresent them as redeemable backing.
4. Retain observations, source logs and receipts. Freeze/pause/destroy/backing
   incidents latch durably in `incidents.json`; later healthy samples do not
   clear the provider pause hook. Only an explicit reviewed incident resolution
   may archive those latches. No automatic unpause, cap increase or compensation.

For a wallet/actor floor, fund only the smallest justified TOS top-up through the
normal approved value-moving procedure. For refusal pressure, enable/reconcile
the funded outbox first. For old-bridge status 1, stop the migration: suspend or
retire the old record before changing ConfigParam 79. Do not raise caps to hide
an unexplained balance change. Never discard a baseline, journal or incident to
make an alarm disappear.

## Evidence

Run under the operator's thermal guard:

```
python3 -m pytest -q testnet/tests/test_check_settlement.py
python3 testnet/tests/settlement_monitor_mutants.py
uv run ruff check testnet/scripts/check-settlement.py testnet/tests/test_check_settlement.py testnet/tests/settlement_monitor_mutants.py
uv run ruff format --check testnet/scripts/check-settlement.py testnet/tests/test_check_settlement.py testnet/tests/settlement_monitor_mutants.py
```

The threshold tests exercise each alarm below and at/above its boundary for
both assets, plus malformed/incomplete observations and unknown dispatch. The
mutation controls remove the guards in an isolated temporary source and require
the tests to fail. No test contacts a node, sends value or builds node code.
The checker is TOS-specific operational tooling; no inherited consensus or
bridge algorithm is changed.

Source audit: bridge/wallet reads at TOS `b9a5a0406193d3577022b5c856bab9f77836f58b`;
actor getter and accounting layout at `12cf5522801a30806eeb7cda9ee85fbd051ecbca`.
The upstream default branch at `99143587e6babb2e577eadea0fc741cb1b413fab`
has neither this actor nor this operational checker; there is no corresponding
upstream repair to port.
