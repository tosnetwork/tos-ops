# Closed-run proof, history and timing replay

`load_run_replay.py` verifies one closed qualified **compute/skip** run. It streams
bounded public events into SQLite, recomposes retained forward proofs through the
reviewed prefix library, runs the pinned native historical verifier for every
capture, follows each public transaction BOC back to the preceding native account
head, binds every query to its exact offered signed-request hash and recomputes
the histogram from the original same-boot window clocks. Offered clocks must
not regress in serialized offer order, and checkpoint clocks must not regress
in capture order, including empty checkpoints. Callback record order across
these two kinds is deliberately not used as window order.

It does not sign, send, read keys/private carriers/outboxes/financial journals,
clear a spending fence, or turn coverage into load acceptance. A failed source
SLO remains failed. The entry point currently requires completed captures and a
closed reconciled source; interrupted/partial or live-follow recovery is a
separate unfinished path. Delivered/privacy/service/mixed profiles also remain
outside this compute decoder's scope. No 72-hour acceptance follows from a short
corpus or unit-test count.

## Inputs and command

Supply explicit absolute `--run` pointing to the public qualification run, the
original full `--summary` (wallet/transfers_mode/qualification fields),
`--producer-packet`, `--anchor`, `--schema`, `--verifier`, and their `--*-sha256`
pins. `--events-sha256` pins the public `events.jsonl`. Supply `--wallet` and
`--wallet-code-hash`; defaults are global ID2, version16, subwallet4269, and can
be selected explicitly. The producer packet must bind this state directory,
full genesis root/file, native verifier/anchor and wallet-code identities.

Use a new `--output` directory. Optional `--max-unique-bytes` defaults128GiB;
`--max-captures` defaults1million. The default public archive unique-payload
budget is not a bound on SQLite metadata/overhead. At least20GiB plus one64MiB
capture must remain free before each capture; disk failures propagate. The
caller must preserve the original public source through its acceptance retention
period and run the operational resource/contact monitors separately.

No network endpoint or signer is supplied to the replay. The helper is copied
into a sealed executable descriptor after checking its byte hash. Pinned anchor
and schema bytes are copied into the output and are the exact files passed to
the native verifier/TL decoder. Helper output is file-size limited, bounded and
subject to a30-second subprocess deadline. SIGTERM becomes an interruption so
owned native children are killed/reaped and no completion result is published.

## Bounds and durability

Events are streamed, at most1MiB/line,16GiB total and12million lines; query IDs
are bounded to the existing2^23 space. Offered-query and checkpoint indexes live
on disk, not in an all-run Python dictionary. Each capture retains the existing
bounded native proof/history limits. Chain file enumeration stops at1024parts
before loading them; cumulative raw chain/history bytes are checked while read.
Only one bounded capture and decoded history segment are resident at a time.
Next archive capture lookup uses the integer primary key; it does not count all
blobs on every capture. Archive statistics are collected only at completion.

The public context directory and its parent are fsynced before verification.
The output contains a pinned context/public-input snapshot, a per-attempt event
copy and derived SQLite index, the shared `proofs.sqlite`, advisory progress and
a durable `RESULT.json` only after complete coverage checks. Publication links
a fsynced temporary file atomically to an exclusive final name, then syncs the
directory; an interrupted result fsync cannot leave a partial final marker
that blocks resume. This single publication link is unrelated to proof-bundle
sharing and cannot exhaust per-inode link counts. Public TL responses,
historical request JSON and selected public RPC page JSON/transaction BOCs are
archived in exact order. Known masterchain-info/descent auxiliary TL files are
retained too; they are not substituted for the composed forward proof used by
the historical verifier. Original proof/result/request hashes are retained per
capture. Original state caches, locks and failure/stderr transcripts remain in
the original source and are not claimed as archived by this coverage artifact.

`--resume` requires the identical context and limits, an unfinished result, and
an exclusive replay lock. It builds a new derived index and **reverifies every
capture natively from the anchor**, comparing already committed archive entries
byte-for-byte before adding later captures. It does not trust a cached success
or skip native validation. Prior per-attempt evidence is retained. This is public
proof-index recovery, not wallet recovery, financial-journal abandonment or a
permission to replay any payment. Managed output/database files are trusted
filesystem state; this is not a hostile-SQLite parser.

## Evidence and upstream comparison

Control tests use a fake native boundary and a real retained public transaction
segment. They test failure/interruption/resume, wrong account/genesis/BOC/digest,
event/boot/clock/capture gaps, corrupted archives, pins and budgets. A separate
real317-capture/168-query corpus must run the exact source with the pinned native
verifier and offline network tracing; fake-boundary tests do not prove consensus.

These operations modules are absent at upstream
857b8a57a178e6ae0fe7fa86e7d81c5233de8560. Existing native verifier and node code
remain unchanged. Resource/latency measurements must be reported from the exact
replayed source and host, not extrapolated into completed long-run acceptance.


At initial4485c46, real-corpus validation completed317captures/168queries with identical
original same-boot histogram, no AF_INET/connect in the outer network trace,
75.30seconds elapsed under tracing and35,124KiB maximum RSS on the test host.
These are short-corpus measurements, not a72h resource or live-follow result.
The stricter material enumeration first exposed expected masterchain-info and
descent auxiliary files; both failed setup attempts are retained externally,
and the final run explicitly retains these known public file types.
