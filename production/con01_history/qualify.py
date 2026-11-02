"""Produce a separate qualification after a frozen replay and revision-bound controls.

Never overwrite the original observer verdict or the replay's provisional verdict.
This is a technical evidence gate, not approval to enable a public service.
"""

import argparse
import json
from pathlib import Path

from . import observer
from .certificate import require
from .frozen import sha, validate_segments


WORKER_MODULES = {
    "__init__.py",
    "observer.py",
    "_replay.py",
    "certificate.py",
    "audit.py",
    "formats.py",
}
CONTROL_GUARDS = 40
CONTROL_TESTS = {
    "source-key-file-binding": "test_cached_key_file_hash_is_bound_before_verification",
    "expired-term-regression": "test_expired_schedule_passes_full_observer",
    "rejected": "test_rejection_is_not_overwritten_by_later_success",
    "stream-integrity": "test_integrity_break",
    "uncertified-key": "test_uncertified_source_key_cannot_enter_trust_chain",
    "third-boundary-certificate": "test_boundary_requires_three_certificates",
    "two-window-certificates": "test_window_requires_two_sources",
    "three-full-ids": "test_full_ids_require_three_sources",
    "shard-inclusion": "test_shard_inclusion_requires_two_sources",
    "live-observation": "test_missing_live_heads",
    "outgoing-boundary-set": "test_outgoing_boundary_set_must_match",
    "incoming-next-set": "test_incoming_set_must_certify_following_block",
    "incomplete-replay": "test_incomplete_replay_cannot_qualify",
    "replay-revision": "test_changed_source_cannot_qualify",
    "control-revision": "test_changed_control_revision_cannot_qualify",
    "all-controls-required": "test_missing_controls_cannot_qualify",
    "snapshot-size": "test_frozen_size_change_cannot_qualify",
    "three-source-inventory": "test_missing_third_source_cannot_qualify",
    "complete-control-inventory": "test_incomplete_control_inventory_cannot_qualify",
    "complete-worker-inventory": "test_incomplete_replay_inventory_cannot_qualify",
    "unique-guard-identities": "test_duplicate_guard_identities_cannot_qualify",
    "frozen-input-identities": "test_changed_frozen_inputs_cannot_qualify",
    "launch-approved-config": "test_changed_approved_config_refuses_before_worker",
    "launch-frozen-inputs": "test_changed_frozen_input_refuses_before_worker",
    "launch-verifier": "test_changed_verifier_refuses_before_worker",
    "launch-source": "test_changed_source_refuses_before_worker",
    "launch-input-inventory": "test_incomplete_input_inventory_refuses_before_worker",
    "launch-worker-inventory": "test_incomplete_worker_inventory_refuses_before_worker",
    "launch-worker-revision": "test_changed_worker_revision_refuses_before_worker",
    "legacy-worker-alias": "test_historical_worker_name_is_exact_byte_alias",
    "launch-legacy-worker-alias": "test_historical_worker_name_resumes_exact_same_bytes",
    "launch-worker-config-bytes": "test_relative_output_alias_refuses_before_worker",
    "frozen-segment-content": "test_same_length_frozen_segment_change_cannot_qualify",
    "complete-segment-digests": "test_extra_segment_digest_cannot_qualify",
    "launch-frozen-segment-content": "test_same_length_frozen_segment_change_refuses_before_worker",
    "launch-segment-manifest-pin": "test_unchanged_frozen_inputs_resume",
    "qualification-extra-worker-segment": "test_unlisted_worker_segment_cannot_qualify",
    "qualification-extra-source-directory": "test_extra_source_directory_cannot_qualify",
    "launch-extra-worker-segment": "test_unlisted_worker_segment_refuses_before_worker",
    "launch-extra-source-directory": "test_extra_source_directory_refuses_before_worker",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--controls", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), "new qualification output required")
    root = Path(__file__).resolve().parents[2]
    control = json.loads(args.controls.read_bytes())
    require(control["result"] == "PASS", "completed controls required")
    rows = control["rows"]
    require(
        len(rows) == CONTROL_GUARDS + 2,
        "complete guard controls plus baseline/restoration required",
    )
    require(
        rows[0]["name"] == "baseline"
        and rows[0]["exit"] == 0
        and rows[-1]["name"] == "restored"
        and rows[-1]["exit"] == 0,
        "green baseline and restoration required",
    )
    require(
        all(row["exit"] == 1 and row["test"] for row in rows[1:-1]),
        "runtime guard removals required",
    )
    require(
        len({(row["name"], row["test"]) for row in rows[1:-1]}) == CONTROL_GUARDS
        and {(row["name"], row["test"]) for row in rows[1:-1]}
        == set(CONTROL_TESTS.items()),
        "exact unique guard identities required",
    )
    expected_files = {
        str(path.relative_to(root)) for path in Path(__file__).parent.glob("*.py")
    }
    tests = root / "testnet/tests"
    expected_files.update(
        str(path.relative_to(root)) for path in tests.glob("test_con01*.py")
    )
    expected_files.update(
        str(path.relative_to(root))
        for path in (tests / "data/con01-history").glob("*")
        if path.is_file()
    )
    expected_files.add("testnet/tests/con01_rejudge_controls.py")
    require(
        set(control["files"]) == expected_files,
        "complete control revision inventory required",
    )
    for name, digest in control["files"].items():
        path = root / name
        require(
            path.resolve().is_relative_to(root.resolve()),
            "control file outside checkout",
        )
        require(sha(path) == digest, "control revision changed: " + name)
    provenance = json.loads((args.replay / "REPLAY-PROVENANCE.json").read_bytes())
    # The already-running frozen worker was named rejudge.py before the safe
    # frontend was introduced. _replay.py preserves those exact source bytes.
    worker_files = {
        name: ("_replay.py" if name == "rejudge.py" else name)
        for name in provenance["source_sha256"]
    }
    require(
        len(worker_files) == len(WORKER_MODULES)
        and set(worker_files.values()) == WORKER_MODULES,
        "complete worker revision inventory required",
    )
    for name, digest in provenance["source_sha256"].items():
        require(
            sha(Path(__file__).with_name(worker_files[name])) == digest,
            "replay source revision changed: " + name,
        )
    require(
        (args.replay / "VERDICT.json").exists(),
        "replay must finish before qualification",
    )
    snapshot = json.loads((args.replay / "SNAPSHOT.json").read_bytes())
    state = json.loads((args.replay / "verified/state.json").read_bytes())
    require(
        {Path(segment["path"]).parts[0] for segment in snapshot["segments"]}
        == {"src-node1", "src-node3", "src-node5"},
        "three frozen original source inventories required",
    )
    for segment in snapshot["segments"]:
        path = args.replay / segment["path"]
        require(
            path.resolve().is_relative_to(args.replay.resolve()),
            "snapshot path outside replay",
        )
        require(path.stat().st_size == segment["bytes"], "frozen segment size changed")
        require(
            state["offsets"].get(segment["path"]) == segment["bytes"],
            "incomplete frozen replay: " + segment["path"],
        )
    pins = json.loads((args.replay / "REPLAY-INPUTS.json").read_bytes())
    require(
        set(pins["files"])
        == {
            "APPROVED-CONFIG.json",
            "REPLAY-CONFIG.json",
            "SNAPSHOT.json",
            "SEALS.jsonl",
            "SEGMENT-HASHES.json",
        },
        "complete frozen input inventory required",
    )
    require(
        all(
            sha(args.replay / name) == digest for name, digest in pins["files"].items()
        ),
        "frozen replay input identity changed",
    )
    validate_segments(args.replay)
    cfg = json.loads((args.replay / "REPLAY-CONFIG.json").read_bytes())
    cfg["_genesis_set"] = state.get("genesis_set")
    verdict = observer.judge(observer.load_results(args.replay), cfg)
    verdict["seals"] = observer.seals_check(args.replay)
    if verdict["seals"]["mismatches"]:
        verdict["inconclusive"].append("sealed segment hash mismatch")
        verdict["verdict"] = "INCONCLUSIVE" if verdict["verdict"] != "FAIL" else "FAIL"
    verdict["worker_source_files"] = worker_files
    verdict["frozen_inputs_sha256"] = sha(args.replay / "REPLAY-INPUTS.json")
    verdict["controls_sha256"] = sha(args.controls)
    verdict["replay_provenance_sha256"] = sha(args.replay / "REPLAY-PROVENANCE.json")
    verdict["verified_result_files"] = {
        path.name: sha(path)
        for path in sorted((args.replay / "verified").glob("results-*.jsonl"))
    }
    verdict["scope"] = (
        "Historical evidence qualification only; no deployment approval or repair of missing observations."
    )
    with args.out.open("x") as destination:
        json.dump(verdict, destination, indent=2)
        destination.write("\n")
    print(
        json.dumps(
            {key: verdict[key] for key in ("verdict", "rejected_count", "trust_chain")}
        )
    )


if __name__ == "__main__":
    main()
