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

## Native acquisition and retained captures

`load_finality_collector.NativeCollector` acquires a live native proof using
explicit verifier and anchor SHA-256 pins. It snapshots bounded public anchor
and lite-server configuration files, copies the exact verified ELF into a
kernel-sealed memfd once, and executes that descriptor. The strategy reuses the
reviewed sealed-provider approach; replacing the original executable path cannot
change the bytes subsequently executed. Linux, installed curl/prlimit and their
trusted system libraries are prerequisites. Call `close()` when finished.

Each capture validates the expected account, active code hash, global ID and
version before following public RPC transaction BOCs back to the previous
verified head. A first capture establishes a baseline and does not collect old,
unbound offers. Subsequent default captures use the last successful head;
explicit mismatched previous heads are refused before acquisition. A failed
capture never advances that cursor. Subsequent captures return receipts only
for a complete verified segment. An unchanged account at a newer checkpoint is supported. This remains
the explicitly computational skip/refund profile, not delivered-payment proof.

The run directory must be new; existing collector runs cannot be resumed or
silently rebaselined. Live proof cache state is copied only from the previous
successful capture into the next capture, so failed writes and temporary files
remain inside the capture budget. Native output, public RPC responses, material
and directories are synced before returning a completed capture. No keys or
private outbox carriers are read. The caller must separately persist offered
digests and preserve its unfinished-run fence.

Per-file subprocess output has an 8 MiB kernel limit; stderr is additionally
checked against 1 MiB before acceptance. Each capture has monitored and final
limits of 64 MiB and 512 files, checked before returning progress. Aggregate
monitoring is not a filesystem quota: a write burst can overshoot before the
next check, and that rejected capture is retained. Oversized rejected evidence
exhausts the collector's retention budget and prevents further captures. Defaults
are at most 200,000 captures, a 256 GiB retained-capture budget, at least 20 GiB
plus capture headroom free, and an inode reserve. Count and byte limits also
apply to RPC pages/history. Snapshots and the sealed executable have separate
fixed input-size bounds. No proof artifacts are automatically deleted.

The default 8-second acquisition deadline fits within the configured 10-second
native-age limit; the same absolute deadline covers subprocesses, paging,
decoding and persistence. A failed capture returns no progress. It must stop
new admission in the caller; this module never retries signatures or payments.
Thirty-second age/deadline settings are available for explicitly separate
post-run diagnostics and must not be substituted for a 10-second SLO run.

The opt-in `load --qualify-load --native-finality` path now runs a continuous
worker, journals signed request digests before broadcast, and checks observer
health before new build/sign/send and funding reservations. It requires an
already deployed wallet, the skip/254-action profile, explicit verifier and
anchor paths plus SHA256 pins, a lite-server config and the expected wallet code
hash (`--native-verifier`, `--native-verifier-sha256`, `--native-anchor`,
`--native-anchor-sha256`, `--native-liteserver`, `--native-wallet-code-hash`).
The wallet's global version must be 16. Native mode requires existing
`highload.key` and `highload.addr`; it establishes its native baseline before
relayer preparation, and checks admission before Fift may sign a new relayer
activation carrier. It does not create a new highload wallet. Cold bootstrap is unscored and permits
30 seconds; admission starts only after a strict 10-second-age/8-second-deadline
capture. Each worker capture uses those strict settings. A worker failure
permanently stops admission; authenticated receipts may still drain read-only
where the window permits it. The worker joins before the durable journal closes.
If thread startup itself fails, the owned verifier is closed, the original
startup error is preserved, and the failed observer cannot be started again.
An unfinished native pending set preserves the original run fence, even when
the application journal never completed its offered event.

Admission is checked again after the offered event is fsynced and immediately
before broadcast, including relayer activation. Funding also rechecks after
wallet-lock waits and balance RPCs, at the actual owner signature call, and after
the signed message export before broadcast. Failure after signing retains the
original signed operation and unknown-funding fence; it never signs a replacement.

`--native-poll-seconds` explicitly selects capture start spacing (0.1..10 seconds,
default2). The worker remains serial; a slow capture consumes its interval and
does not spawn overlapping work. The capture-count allowance is
`ceil((duration + 600) / interval) + 100`, capped at the collector's supported
one million by **rejecting** an unsupported horizon before signing, not clamping
it. A72hour run at0.5seconds therefore allows519700captures. Count allowance
does not establish disk capacity or prove throughput; existing byte/inode/free
space guards remain active.

Native offered events now include `native_boot_id` and
`native_offered_monotonic_seconds`, sampled from the actual window offer call.
Baseline/checkpoint events include `boot_id` and
`verified_observation_monotonic_seconds`, the same value passed to the window
after persisted native capture and while holding its guard. Event/journal timing
remains separate; delayed callbacks cannot rewrite native observation latency.
These are additive fields; older runs do not retroactively gain exact timestamps.

The retained120second diagnostic fromNov4 stopped early with16/16bound native
receipts settled and one query beyond5seconds (p95bucket10), preservingFAIL.
Twenty-seven captures and all16exact request digests replay independently
offline. Historical probes show slowquery2639 already present atMC1228752,
while its original observation wasMC1228756. The explicit shorter interval is
a measured follow-up option; no p95/p99 limit is relaxed or new performancePASS
claimed. Fullrun replay/continuous key-boundary/live SLO/72hour gates stay open.

`verification_mode` distinguishes native signed-request completion from legacy
two-RPC processed checks. RPC seqno acceptance remains a separate metric; the
native histogram measures offered digests through verified, persisted capture
completion. Native mode avoids serial per-query processed RPC calls. This
integration has deterministic tests but no new paid live qualification result;
it does not establish improved throughput or authorize a 72-hour pass.

Sample the window's monotonic time while
holding its serialization lock, after capture persistence; do not submit an
older precomputed timestamp after a concurrent offer has advanced that clock.
The caller must enforce collector age <= window age and retain failure status
even during permitted read-only reconciliation. Unit acquisition tests stub the
proof execution boundary; only tests using the actual pinned native verifier
are evidence of native proof verification.

Persisted live material is not, by itself, a claim of standalone historical
offline replay: the existing verifier rejects a live-material bundle supplied
as historical material. Independent historical replay currently needs a
separately acquired historical request/material bundle at the exact target.
Continuous retained-proof replay coverage therefore remains an acceptance gate.

### Bounded history RPC failover

The native collector receives the load command's existing `--confirm-rpc` as an
optional history fallback. For each page it tries that distinct endpoint once
only when the primary returns a JSON-RPC internal error (`-32603`, without a
result). A shard client can temporarily lag an already native-proven head. Both
reads use the exact same account/LT/hash cursor and the original capture deadline;
there is no new age allowance, infinite retry, signing or admission bypass.
Primary error bytes/stderr and both public endpoint URLs remain under the
capture's `rpc-failover/`; the successful page retains its original canonical
`rpc-N.json` filename for offline replay. Malformed pages, empty lists and other
error codes still fail immediately. Two internal errors stop the capture.

Fallback rows remain untrusted: the unchanged capture path checks each BOC hash,
logical time, predecessor chain, transaction semantics and exact signed-request
digests against the native account head. A fallback with the wrong chain is
refused without promoting the collector head/state. Existing count/byte/file
and persistence bounds apply to failed attempts too. Added files can cause the
existing guard to refuse a pathological capture; its limits are not increased.

Upstream comparison: the underlying transaction-block lookup error remains in
upstream `validator/impl/liteserver.cpp:1763` at
857b8a57a178e6ae0fe7fa86e7d81c5233de8560 and TOS
`validator/impl/liteserver.cpp:1731` at
f58402109959aac7af8c3d7e93ec66d7468cd9b4. Upstream issue1105 remains open;
current source/search/release review did not identify a fix for this observation.
Inherited lookup behavior is unchanged. This operations collector has no upstream
counterpart; its previously single-endpoint acquisition is the scope of this fix.

### Atomic live-state rename during resource sampling

While the pinned native verifier is still running, its `commit_state` writes
`native-state.json.tmp` and atomically renames it to `native-state.json`. A
resource scan can enumerate the temporary pathname immediately before that
rename; lstat then returns ENOENT. The running-native scan tolerates precisely
that vanished pathname. It does not ignore other missing artifacts, permission
errors, existing symlinks or special files. RPC subprocess scans remain strict.
All scans after subprocess completion, capture synchronization and retained-byte
accounting remain strict, with the same file/byte limits and kernel file-size
bound. This fixes a sampler false failure without changing proof acceptance or
native state persistence. Deterministic tests perform the real rename exactly
between enumeration and lstat and test the strict boundaries separately.

Upstream comparison: both this operations collector and the native proof helper
are TOS-specific paths absent at upstream857b8a57a178e6ae0fe7fa86e7d81c5233de8560.
The unchanged helper performs the intended atomic rename in TOS proof-verify
main.cpp:167-191 atf58402109959aac7af8c3d7e93ec66d7468cd9b4. No inherited or
native proof code changes. Checklist: TE-8 (existed, not applied to the directory
scanner racing the helper's atomic state commit).

### Simultaneous RPC shard-index lag

Both configured RPCs can briefly lag the native-proven transaction head. Internal
error reads now use at most four rounds of the existing distinct endpoints,
with0.25/0.5/1-second backoff between rounds. This is at most eight reads with two
endpoints, or four with one endpoint, all inside the original capture deadline.
An exhausted deadline stops before sleeping or issuing another read. Other RPC
errors, malformed/empty pages and transport failures retain immediate refusal.

Every unsuccessful internal-error response/stderr/source URL is retained under a
unique attempt name. The first retains its original page-N filename for existing
diagnostics. Successful canonical page filenames and the exact cursor/request
remain unchanged. All native/head/BOC/request-digest validation and count/byte/file
budgets remain unchanged; extra diagnostics may exhaust the existing limit and
must then stop. This is read-only acquisition retry, never a payment retry.

Measured trigger: R3trial2-500k captures248/249/250 saw both sources return
-32603 block-not-found at the same shard-client height; later readonly acquisition
proved all141queries. One immediate fallback was insufficient. No inherited
lookup change: the same error remains upstream857b8a57a178e6ae0fe7fa86e7d81c5233de8560
liteserver.cpp1763 / TOSf584021:1731, and upstream issue1105 is open. This TOS-only
collector path has no upstream counterpart. Original failed-stage and unresolved
RPC bookkeeping remain failed until separate original-run reconciliation.

### Submission timing diagnostics

Qualified sends append one public `broadcast_timing` event after the original
single `sendBoc` call finishes or raises. It binds the query IDs and public relayer
address to monotonic timestamps around the durable offer call, the following
admission check and the HTTP call. The native `offered` timestamp remains the
original latency origin. The timing event adds no journal write before dispatch;
its own write time is excluded from the measured HTTP duration. `returned` means
only that the call returned; it is neither relayer acceptance nor native execution.

No endpoint URL, payload, private carrier, signature or exception body is copied
into this event. Failure to write it stops admission and retains the original
unresolved-query fence; it never repeats the send. An exception before dispatch
retains the existing refusal path and need not emit a timing event. Finality,
funding, native proof-age and p95/p99 gates are unchanged. Timings help distinguish
local offer/admission delays from HTTP/ingress delays, but cannot by themselves
separate remote queueing from consensus or establish a network latency cause.
