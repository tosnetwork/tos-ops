# Frozen historical rejudgment

The historical observer incorrectly treated the scheduled end of an installed validator set as a finality cutoff when no successor set had been authenticated. The independent certificate verifier already corrects that observer-only defect. This adapter applies it to original immutable streams while preserving the original verdict and all missing-observation limits. No node/checker code is imported; no consensus rule changes.

`observer.py` preserves the original Stage A/B parser, integrity/parent/coverage/handover policy and live thresholds. It uses the independent verifier, compares the trusted validator cell and binds both source key-block root/file hashes to a previously certified key. The real retained block264347 verifies through this exact adapter after its scheduled end; a changed cached file hash refuses it. No missing observation is invented.

Run from this checkout with ordinary non-optimized Python3.10+ (the parser's assertions are verification checks). A private pinned OpenSSL verifier must be supplied; build/use the helper as described in README.md. The runner self-throttles to0.5 CPU including children; run it under the host thermal guard and a2GiB user-service ceiling. Cache entries are positive-only over exact key/signature/message bytes and backend digest, input-width checked before lookup, at most512MiB. No failed verification is cached. Stage A streams bounded records, retains at most200pending routed records and at most bounded cell-decoder caches; Stage B retains the frozen result history, so memory-limit failure is incomplete acceptance, never PASS.

```sh
PYTHONPATH="$PWD/production" python3 -m con01_history.rejudge \
  --source /retained/original-streams --config /retained/approved-config.json \
  --out /new/frozen-replay --verifier /pinned/mldsa-verifier \
  --verifier-sha256 EXACT_SHA256
# To resume that exact frozen run, use the same command plus --resume.
CON01_SIGNATURE_VERIFIER=/pinned/mldsa-verifier \
CON01_SIGNATURE_VERIFIER_SHA256=EXACT_SHA256 \
  python3 testnet/tests/con01_rejudge_controls.py --out /new/control-receipts
PYTHONPATH="$PWD/production" python3 -m con01_history.qualify \
  --replay /new/frozen-replay --controls /new/control-receipts/REPORT.json \
  --out /new/QUALIFICATION.json
```

The public rejudge entry uses the safe launcher: freeze original streams, preserve approved config, pin worker modules/helper digest and config/snapshot/seal bytes before invoking the internal worker. Resume refuses changed config, source, helper, worker code or frozen inputs before loading persisted state or overwriting the worker config. Use this entry, not the internal `_replay` module. Control/frozen/source inventories must be complete, and qualification requires every exact guard/test pair once; empty, partial or duplicated manifests refuse.

The worker code was moved byte-for-byte from the original rejudge module to `_replay.py`; the already-running old module continues in memory unchanged. A narrow explicit filename alias validates old `rejudge.py` provenance against exactly those identical `_replay.py` bytes; no source digest or decision change is waived, and the alias is reported in qualification. Positive alias controls and digest-refusal controls cover this compatibility path. The retained running run's input manifest was captured during execution, not claimed to predate it: its existing worker config was byte-for-byte reconstructed from the retained original approved config/path/0.5CPU setting before pinning. Original source provenance/snapshot/seals remain unchanged.

Original evidence remains untouched: sealed segments are hardlinked read-only by convention, final complete-line prefixes copied and results written only in the derivative output. Do not edit hardlinked segments; preserve originals and frozen derivatives on the authorized host.

The replay verdict is deliberately provisional INCONCLUSIVE. After the worker finishes, qualification checks complete input offsets, frozen sizes, three original source inventories, source/control revision digests and31 completed runtime guard removals, recomputes the unmodified production judge and seals, and writes a separate new verdict. It does not overwrite either old verdict. Default policy requires three qualifying handover windows,600seconds on either side,2certifying sources for every window block and all3certificates at the boundary, full IDs from3sources, trusted key history, shard inclusion, live head/freshness/rate checks and no unresolved rejected certificates/conflicts/parent/integrity/seal issues. The final report explicitly limits continuous history claims to its verified runs; explained gaps remain gaps. A replay still running, an incomplete offset, a changed source or missing controls cannot qualify.

The current full frozen replay is running; this change does not claim completed historical acceptance or authorize public Relayer enablement. Targeted raw receipts/provenance are indexed in REJUDGE-EVIDENCE.json and the retained output location. The original14crypto sensitivity controls remain independently available in con01_history_controls.py.

Upstream comparison: observer, deployment evidence and Rust/Python operator paths are absent at upstream857b8a57a178e6ae0fe7fa86e7d81c5233de8560; base d674fe81047eb4123b46a1f0a71a714de433c8b1. Native validator-set fallback is inherited and unchanged. This fixes the TOS observer, not an inherited core defect.
