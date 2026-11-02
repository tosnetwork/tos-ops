# Frozen historical rejudgment

The historical observer incorrectly treated the scheduled end of an installed validator set as a finality cutoff when no successor set had been authenticated. The independent certificate verifier already corrects that observer-only defect. This adapter applies it to original immutable streams while preserving the original verdict and all missing-observation limits. No node/checker code is imported; no consensus rule changes.

`observer.py` preserves the original Stage A/B parser, integrity/parent/coverage/handover policy and live thresholds. It uses the independent verifier, compares the trusted validator cell and binds both source key-block root/file hashes to a previously certified key. The real retained block264347 verifies through this exact adapter after its scheduled end; a changed cached file hash refuses it. No missing observation is invented.

Run from this checkout with ordinary non-optimized Python3.10+ (the parser's assertions are verification checks). A private pinned OpenSSL verifier must be supplied; build/use the helper as described in README.md. The runner self-throttles to0.5 CPU including children; run it under the host thermal guard and a2GiB user-service ceiling. Cache entries are positive-only over exact key/signature/message bytes and backend digest, input-width checked before lookup, at most512MiB. No failed verification is cached. Stage A streams bounded records, retains at most200pending routed records and at most bounded cell-decoder caches; Stage B retains the frozen result history, so memory-limit failure is incomplete acceptance, never PASS.

```sh
# Freeze inputs and source provenance before starting the worker.
PYTHONPATH="$PWD/production" python3 - /retained/original-streams /new/frozen-replay <<'PYCODE'
import hashlib, json, sys
from pathlib import Path
from con01_history import rejudge
source, output = map(Path, sys.argv[1:])
rejudge.snapshot(source, output)
package = Path(rejudge.__file__).parent
provenance = {"source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
    for p in package.glob("*.py")}, "positive_crypto_cache_entries": 0}
(output / "REPLAY-PROVENANCE.json").write_text(json.dumps(provenance, indent=2)+"\n")
PYCODE
PYTHONPATH="$PWD/production" python3 -m con01_history.rejudge --resume \
  --source /retained/original-streams --config /retained/config.json \
  --out /new/frozen-replay --verifier /pinned/mldsa-verifier \
  --verifier-sha256 EXACT_SHA256
CON01_SIGNATURE_VERIFIER=/pinned/mldsa-verifier \
CON01_SIGNATURE_VERIFIER_SHA256=EXACT_SHA256 \
  python3 testnet/tests/con01_rejudge_controls.py --out /new/control-receipts
PYTHONPATH="$PWD/production" python3 -m con01_history.qualify \
  --replay /new/frozen-replay --controls /new/control-receipts/REPORT.json \
  --out /new/QUALIFICATION.json
```

The frozen replay needs `REPLAY-PROVENANCE.json` binding all loaded worker module digests; retain this before execution. The current retained run has that index, snapshot/config/seals and successful-cache provenance. `--resume` continues only that frozen snapshot/state, never a different stream or decision revision. Provenance/control/source mismatches refuse final qualification. Originals remain untouched: sealed segments are hardlinked read-only by convention, the final complete-line prefix copied, results written only in the derivative output. Do not edit a hardlinked segment. Retain originals and frozen derivatives on the authorized host.

The replay verdict is deliberately provisional INCONCLUSIVE. After the worker finishes, qualification checks complete input offsets, frozen sizes, three original source inventories, source/control revision digests and18 completed runtime guard removals, recomputes the unmodified production judge and seals, and writes a separate new verdict. It does not overwrite either old verdict. Default policy requires three qualifying handover windows,600seconds on either side,2certifying sources for every window block and all3certificates at the boundary, full IDs from3sources, trusted key history, shard inclusion, live head/freshness/rate checks and no unresolved rejected certificates/conflicts/parent/integrity/seal issues. The final report explicitly limits continuous history claims to its verified runs; explained gaps remain gaps. A replay still running, an incomplete offset, a changed source or missing controls cannot qualify.

The current full frozen replay is running; this change does not claim completed historical acceptance or authorize public Relayer enablement. Targeted raw receipts/provenance are indexed in REJUDGE-EVIDENCE.json and the retained output location. The original14crypto sensitivity controls remain independently available in con01_history_controls.py.

Upstream comparison: observer, deployment evidence and Rust/Python operator paths are absent at upstream857b8a57a178e6ae0fe7fa86e7d81c5233de8560; base d674fe81047eb4123b46a1f0a71a714de433c8b1. Native validator-set fallback is inherited and unchanged. This fixes the TOS observer, not an inherited core defect.
