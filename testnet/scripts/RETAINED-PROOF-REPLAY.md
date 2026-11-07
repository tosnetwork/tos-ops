# Retained forward-proof prefix recomposition

`load_finality_replay.RetainedPrefix` composes retained live proof segments into
historical material accepted by the existing native verifier. Live cached-state
material cannot simply be passed as historical material: its starting key block
must first be authenticated from the original anchor, and the live-only latest
head/descent responses are not historical inputs.

The caller supplies the pinned protocol schemas and the explicit anchor. On each
`advance(responses, start=..., target=..., verify=...)`, the module decodes bounded
canonical forward responses, locates the already authenticated prefix ending at
the exact starting key block, appends the new segment, and repacks responses with
correct endpoint/completion fields. Original signed links and proof cells remain
unchanged. The callback must run the pinned native historical verifier with those
responses and the capture's original account/config proof material, validate its
expected account/code/network identity, and return that actual result. A mocked
callback is only a composition test and provides no cryptographic evidence.

The module checks the native result's historical mode and exact anchor/start/
target, then commits its key-block prefix. Refusals, exceptions and identity
mismatches leave the prior cache unchanged. Non-key target links are not cached
as future starting points. Capture targets may repeat identically but cannot
regress or change block hashes at the same height. Previously retained key-block
paths must remain consistent; an alternative path requires separate diagnosis,
not silently replacing authenticated cache state.

Limits are 1024 input/output responses, 8 MiB per response, 64 MiB total encoded
proof and 16384 links. Responses are repacked in groups of at most16 links with
an additional per-byte bound. No keys, private carriers, RPC client, signing,
live-state mutation, wall-clock override or payment retry enter this module.

Author runtime evidence is retained under
`/tos/build/e7-retained-proof-replay-20261104/`: twelve public captures from three
retained diagnostic runs verified offline through the actual sealed SHA-pinned
native helper, including prefix growth from92 to94 authenticated key blocks.
Each native target and account head/code/data matched its original capture;
network tracing showed no AF_INET/connect calls. Unit tests use a fake codec and
verifier and are explicitly separate from this native corpus evidence.

This library does not yet implement a complete run CLI, durable replay manifest,
capture-gap accounting, transaction-history replay, offered-digest correlation,
live SLO verification or continuous72-hour acceptance. The selected corpus spans
key-block proofs from separate retained runs; it is not evidence of uninterrupted
live capture through a key-block boundary. Keep those acceptance gates open.

Upstream comparison: this TOS ops integration has no counterpart in fetched
ton-c857b8a57a178e6ae0fe7fa86e7d81c5233de8560. It reuses the unmodified native
verifier's historical proof strategy; no inherited core rule is changed.
