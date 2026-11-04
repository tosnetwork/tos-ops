# Public proof archive

`PublicProofArchive` stores explicit public TL proof responses once by SHA-256,
with ordered capture manifests in SQLite. It does not inspect directories or
accept keys, private journals, signed carriers or outboxes. Archive hashes prove
storage integrity only. Native historical verification, network identity and
complete offered-query/history reconciliation remain required outside this API.

Create an archive with a canonical caller-supplied identity (anchor/source/schema
pins), a unique-byte budget and a capture limit. Append contiguous captures from
zero. Each capture accepts at most 1024 parts, 8 MiB per part, 64 MiB in total,
and 1 MiB canonical JSON metadata. Unique bytes are bounded to the explicit
budget (at most 1 TiB); captures are bounded to at most one million. These are
payload bounds, not a bound on SQLite overhead or total manifest space. Callers
must monitor filesystem free space independently. Any disk failure propagates.

Each append is one FULL-synchronous transaction. A failed iterable, budget error,
interruption or process death leaves no partially accepted capture. Reopening
requires the same identity and limits. One writer is supported; SQLite serializes
transactions. Reading returns one capture, verifies every content hash and
requires exact part count/order. Materialize only one bounded capture for native
replay and remove that temporary material after verification. No hardlinks are
used, so a repeated prefix does not exhaust per-inode link counts.

This is a storage API, not a live collector replacement or a full-run replay CLI.
The latter must check gaps, source changes, native signatures, account history,
exact signed-request digests, boot identity and the original monotonic SLO inputs.

## Evidence

A same-host R2 corpus measurement stored 317 full public proof bundles, originally
466,574,356 bytes, as 8,203,652 unique payload bytes in a 9,416,704-byte SQLite
file. All reconstructed bytes and 317 offline native results matched the source
exactly. These measurements apply to this short corpus, not future 72-hour growth.
The first measurement attempt compared differently serialized request JSON and
correctly failed request-hash equality; the successful run preserves exact
original request text. Both attempts remain in the external evidence directory.

Upstream comparison: this TOS operations archive path is absent at upstream
857b8a57a178e6ae0fe7fa86e7d81c5233de8560. No inherited node path changes.
