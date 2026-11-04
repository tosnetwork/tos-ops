# Native-head transaction history decoding

`load_finality.py` decodes a bounded segment of public transaction BOCs beneath
an account's **native-verified** `last_trans_lt` / `last_trans_hash`. It checks
every predecessor hash and logical time back to the previous verified head,
including intermediate transactions that the load generator did not submit.
Missing tails, gaps and reordered responses fail without returning partial
progress. Query IDs themselves can execute out of order with multiple relayers.

This is an observer building block, not a runnable acceptance service. Its caller
must invoke the pinned native verifier against the approved genesis anchor,
validate the expected network, account and immutable highload code identity, and
obtain both heads from verified snapshots of that same account. Supplying RPC
account JSON to `Head` does not authenticate it. This module does not verify a
consensus certificate or independently establish that a checkpoint is finalized.

For a highload submission the decoder checks its signed global ID, wallet and
subwallet, then ordinary transaction, compute and action outcomes. The explicit
skip profile requires 255 actions, 254 skipped actions and one created refund
message, with its source, destination, excesses opcode and relayer correlation
decoded from the unique output. This proves emission, not receipt at the relayer.
Those skipped actions are deliberate computational load; they are not
delivered payments. General-profile receipts expose action counts and do not
establish downstream delivery. Authenticating transaction history is stronger
than observing a `processed?` marker alone, but remains separate from matching
every offered query and measuring its finality latency.

Each call accepts at most 8,192 transactions and 16 MiB of encoded history, with
a 1 MiB decoded/encoded-derived limit per transaction enforced before decoding.
Only one BOC is decoded at a time; returned receipts retain scalar metadata and
hashes, not BOCs. There is no persistent cache, thread, socket, subprocess, key,
signing path or automatic retry. The caller must bound its RPC paging and queue
before assembling this sequence. Overflow requires stopping/reconciling the
observation, never skipping unverified history.

The 17 KiB fixture contains two already-public transactions from global-2/V16
MC 1188922 and exercises the real BOC and submission decoders. The fixture's
head is test data, not a trusted consensus anchor. The full native proof is
retained with the acceptance artifacts. Run:

```sh
python -m pytest -q testnet/tests/test_load_finality.py
```

Before a 72-hour acceptance run this building block still needs the live native
proof/RPC collector, durable event wiring, proof retention and a fail-closed
connection to load admission. Passing these tests does not start or complete
that acceptance.

## Offered-request and latency window

`load_finality_window.FinalityWindow` correlates the decoded receipts with the
exact signed request digests already produced by the request builder. It does
not hash or read private outbox carriers. The caller must durably journal those
digests before broadcast and retain its unfinished-run fence across any exit.
The window is in memory; it does not authorize a restart, resume or new signature.

Admission requires a native baseline first. The caller must check `healthy`
before every offer and every funding action, and stop new work on any error.
The window has at most 8,192 pending entries, a fixed 1 MiB seen-query bitmap and
fixed latency histogram counters. It refuses query reuse even after completion.
`advance` checks all query/digest bindings before removing pending entries; the
caller must first authenticate the complete transaction segment and persist its
proof artifacts. No caller may substitute an RPC account head for a verified one.

The client supplies same-boot monotonic completion times. A boot change, clock
regression, stale observation, overdue query or checkpoint discontinuity latches
a failure that cannot be reset for admission. Default observation-age/query-age guards are
10/30 seconds. Refreshing a checkpoint cannot erase an observation gap.
Re-verifying the same masterchain checkpoint does not refresh this progress
clock; only a larger authenticated checkpoint sequence does. The caller must
also request live native proofs with authenticated age no larger than the
configured observation-age guard; replaying old historical proofs cannot satisfy
that prerequisite. An unchanged account head at a newer checkpoint is valid.
Default latency criteria are conservative histogram upper bounds p95 <= 5 seconds and
p99 <= 10 seconds; no inclusion or chain timestamp is substituted for completion
of proof and history verification. Authentic slow receipts still settle the
pending entries, while their latency makes the qualification fail. Summary
overflow buckets use the JSON string `infinity`, never a non-finite JSON number.
After a latency/observation-age failure, `advance` may continue strictly read-only
reconciliation of the original requests with fresh, complete same-boot native
evidence. Admission remains halted and the original failure remains recorded.
An identity, boot, clock, binding or checkpoint-integrity failure prevents that
automatic drain and requires external read-only investigation of the original
run; it never permits new signatures or a new baseline.

This class does not acquire proofs, persist events, stop the sender or execute
the caller's funding gate itself. Those live integration gates remain open.
