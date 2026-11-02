# Missing certificate replies and bounded verifier timeouts

The full frozen replay's original qualification remains INCONCLUSIVE: 2,969
recorded signature-RPC BLOCK_UNAVAILABLE replies and three local signature-helper
5-second timeouts were counted as rejected certificates. Exact original packets
for all three timeouts subsequently passed the pinned native verifier in about
0.02 seconds each. This is a verifier/collection distinction, not a consensus fix.

An absent `result` with the exact canonical BLOCK_UNAVAILABLE envelope now yields
an explicit unsupported/unavailable certificate record. It is never `ok`, never
enters the accepted set or trust chain, retains its claimed header identity and
source/sequence, and cannot satisfy a handover certificate threshold. Unknown or
malformed RPC errors and result-plus-error responses retain rejection behavior.
The retained public consensus fixture at sequence300950 reproduces the category.
Its raw-line hash and cleaned-fixture hash/size are pinned in the manifests.

The sealed verifier retries only subprocess timeouts, at most three invocations
of the same pinned executable and identical public input, each with a5-second
subprocess timeout. A completed nonzero verification result refuses immediately;
no invalid signature is retried or cached. Resource pressure can still exhaust
this finite budget, in which case verification refuses. The thermal guard and
whole-worker runtime/memory bounds remain independent.

The judge, handover thresholds, seals and result loader have identical ASTs to
merged ops41. In particular, every actual cryptographic rejection is permanent,
required source counts/live observations/shard inclusion remain unchanged, and
history outside qualifying windows is claimed only for continuously verified
runs. Missing observations are not reconstructed or claimed live.

Validation:69tests and47runtime guard-removal controls, baseline and restoration
pass. Seven new controls remove missing-data classification, canonical/unknown
error boundaries, result/error separation, finite timeout retry/exhaustion and
cryptographic rejection. Every removal fails a named runtime assertion; parse,
setup or compilation errors do not count. The first targeted regression run
failed before the implementation. Receipts are retained on toserver under
`/tos/build/con01-rejudge-20261102/availability-controls-r1/` through2027-02-01.
`AVAILABILITY-EVIDENCE.json` binds source/fixture/report hashes. These test results
are not a new historical PASS: rerun the frozen source from zero with the new
pinned worker, preserve the original verdict, then qualify separately using the
matching47-control receipt.

Upstream comparison: this observer and TOS signature-RPC tooling are absent from
ton master857b8a57a178e6ae0fe7fa86e7d81c5233de8560 (fetched2026-11-02).
No inherited consensus code changed. Checklist TE-8 (existed / not applied): an
RPC reply without a certificate was incorrectly reported as a certificate
verification rejection; the raw retained failure now exercises that distinction.
