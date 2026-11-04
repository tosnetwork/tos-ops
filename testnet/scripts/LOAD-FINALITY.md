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
message. Those skipped actions are deliberate computational load; they are not
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
proof/RPC collector, same-boot monotonic offered-query correlation, durable
bounded pending state, latency criteria, proof retention and a fail-closed
connection to load admission. Passing these decoder tests does not start or
complete that acceptance.
