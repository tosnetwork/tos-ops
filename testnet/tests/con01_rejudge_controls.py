"""Mutation controls in a private copy; never modify a running observer checkout."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MUTATIONS = [
    (
        "source-key-file-binding",
        'certified is not None and ids(link["src"]) == certified',
        "True",
        "test_cached_key_file_hash_is_bound_before_verification",
    ),
    (
        "expired-term-regression",
        "return verify_certificate(link, SIGNATURE_BACKEND)",
        'assert block_header(link["dest"])["gen_utime"] < validators(params[34].c.slice().ref())["until"], "term outside validity interval"\n        return verify_certificate(link, SIGNATURE_BACKEND)',
        "test_expired_schedule_passes_full_observer",
    ),
    ("rejected", "if rejected:", "if False:", "test_rejection_is_not_overwritten_by_later_success"),
    ("stream-integrity", "if breaks:", "if False:", "test_integrity_break"),
    (
        "uncertified-key",
        "if chain_issues:",
        "if False:",
        "test_uncertified_source_key_cannot_enter_trust_chain",
    ),
    (
        "third-boundary-certificate",
        "if edge:",
        "if False:",
        "test_boundary_requires_three_certificates",
    ),
    ("two-window-certificates", "if weak:", "if False:", "test_window_requires_two_sources"),
    ("three-full-ids", "if noid:", "if False:", "test_full_ids_require_three_sources"),
    (
        "shard-inclusion",
        'if len(okp) < bounds["min_sources_cert"]:',
        "if False:",
        "test_shard_inclusion_requires_two_sources",
    ),
    (
        "live-observation",
        'if len(live_ok_sources) < bounds["min_sources_cert"]:',
        "if False:",
        "test_missing_live_heads",
    ),
    (
        "outgoing-boundary-set",
        'if rb["set"] != outgoing["hash"]:',
        "if False:",
        "test_outgoing_boundary_set_must_match",
    ),
    (
        "incoming-next-set",
        'if nxt and any(r["set"] != inc["hash"] or r["prevkey"] != b for r in nxt.values()):',
        "if False:",
        "test_incoming_set_must_certify_following_block",
    ),
]


QUALIFICATION_MUTATIONS = [
    (
        "incomplete-replay",
        'state["offsets"].get(segment["path"]) == segment["bytes"]',
        "True",
        "test_incomplete_replay_cannot_qualify",
    ),
    (
        "replay-revision",
        "sha(Path(__file__).with_name(worker_files[name])) == digest",
        "True",
        "test_changed_source_cannot_qualify",
    ),
    (
        "control-revision",
        "sha(path) == digest",
        "True",
        "test_changed_control_revision_cannot_qualify",
    ),
    (
        "all-controls-required",
        "len(rows) == CONTROL_GUARDS + 2",
        "True",
        "test_missing_controls_cannot_qualify",
    ),
    (
        "snapshot-size",
        'path.stat().st_size == segment["bytes"]',
        "True",
        "test_frozen_size_change_cannot_qualify",
    ),
    (
        "three-source-inventory",
        '{Path(segment["path"]).parts[0] for segment in snapshot["segments"]}\n        == {"src-node1", "src-node3", "src-node5"}',
        "True",
        "test_missing_third_source_cannot_qualify",
    ),
]

QUALIFICATION_MUTATIONS.extend(
    [
        (
            "complete-control-inventory",
            'set(control["files"]) == expected_files',
            "True",
            "test_incomplete_control_inventory_cannot_qualify",
        ),
        (
            "complete-worker-inventory",
            "len(worker_files) == len(WORKER_MODULES)\n        and set(worker_files.values()) == WORKER_MODULES",
            "True",
            "test_incomplete_replay_inventory_cannot_qualify",
        ),
        (
            "unique-guard-identities",
            'len({(row["name"], row["test"]) for row in rows[1:-1]}) == CONTROL_GUARDS\n        and {(row["name"], row["test"]) for row in rows[1:-1]}\n        == set(CONTROL_TESTS.items())',
            "True",
            "test_duplicate_guard_identities_cannot_qualify",
        ),
        (
            "frozen-input-identities",
            "sha(args.replay / name) == digest",
            "True",
            "test_changed_frozen_inputs_cannot_qualify",
        ),
    ]
)


LAUNCH_MUTATIONS = [
    (
        "launch-approved-config",
        "sha(approved) == sha(args.config)",
        "True",
        "test_changed_approved_config_refuses_before_worker",
    ),
    (
        "launch-frozen-inputs",
        "sha(args.out / name) == digest",
        "True",
        "test_changed_frozen_input_refuses_before_worker",
    ),
    (
        "launch-verifier",
        'pins["verifier_sha256"] == args.verifier_sha256',
        "True",
        "test_changed_verifier_refuses_before_worker",
    ),
    (
        "launch-source",
        'Path(inventory["original"]).resolve() == args.source.resolve()',
        "True",
        "test_changed_source_refuses_before_worker",
    ),
    (
        "launch-input-inventory",
        'set(pins["files"]) == INPUT_FILES',
        "True",
        "test_incomplete_input_inventory_refuses_before_worker",
    ),
    (
        "launch-worker-inventory",
        "len(worker_files) == len(WORKER_MODULES)\n        and set(worker_files.values()) == WORKER_MODULES",
        "True",
        "test_incomplete_worker_inventory_refuses_before_worker",
    ),
    (
        "launch-worker-revision",
        "sha(package / worker_files[name]) == digest",
        "True",
        "test_changed_worker_revision_refuses_before_worker",
    ),
]

QUALIFICATION_MUTATIONS.append(
    (
        "legacy-worker-alias",
        '("_replay.py" if name == "rejudge.py" else name)',
        "name",
        "test_historical_worker_name_is_exact_byte_alias",
    )
)
LAUNCH_MUTATIONS.append(
    (
        "launch-legacy-worker-alias",
        '("_replay.py" if name == "rejudge.py" else name)',
        "name",
        "test_historical_worker_name_resumes_exact_same_bytes",
    )
)

LAUNCH_MUTATIONS.append(
    (
        "launch-worker-config-bytes",
        'expected_worker_config == (args.out / "REPLAY-CONFIG.json").read_bytes()',
        "True",
        "test_relative_output_alias_refuses_before_worker",
    )
)

QUALIFICATION_MUTATIONS.append(
    (
        "frozen-segment-content",
        "validate_segments(args.replay)",
        "pass",
        "test_same_length_frozen_segment_change_cannot_qualify",
    )
)
LAUNCH_MUTATIONS.extend(
    [
        (
            "launch-frozen-segment-content",
            "validate_segments(args.out)",
            "pass",
            "test_same_length_frozen_segment_change_refuses_before_worker",
        ),
        (
            "launch-segment-manifest-pin",
            '    "SEGMENT-HASHES.json",\n',
            "",
            "test_unchanged_frozen_inputs_resume",
        ),
    ]
)
MUTATIONS.extend(
    [
        (
            "missing-certificate-classification",
            'raise CertificateUnavailable("BLOCK_UNAVAILABLE")',
            'raise AssertionError("BLOCK_UNAVAILABLE")',
            "test_known_missing_certificate_remains_unaccepted_and_explicit",
        ),
        (
            "unknown-rpc-remains-rejected",
            "error == MISSING_CERTIFICATE",
            "True",
            "test_unknown_rpc_errors_are_not_reclassified",
        ),
        (
            "result-not-hidden-by-error",
            '"result" not in r',
            "True",
            "test_result_plus_error_cannot_hide_a_malformed_certificate",
        ),
        (
            "missing-envelope-canonical",
            'and type(error["data"]["schema_version"]) is int',
            "",
            "test_incomplete_unavailability_envelope_is_not_reclassified",
        ),
    ]
)
MUTATIONS.extend(
    [
        (
            "missing-envelope-code-type",
            'and type(error["code"]) is int',
            "",
            "test_float_error_code_is_not_canonical_missing_data",
        ),
        (
            "missing-envelope-retryable-type",
            'and error["data"]["retryable"] is False',
            "",
            "test_numeric_retryable_is_not_canonical_missing_data",
        ),
        (
            "missing-data-target-binding",
            'assert identity(dst) == identity(h["id"]), (\n                    "routed proof target differs from header id"\n                )',
            "pass",
            "test_wrong_routed_target_is_rejected_before_missing_certificate",
        ),
    ]
)
CERTIFICATE_MUTATIONS = [
    (
        "bounded-timeout-retry",
        "continue",
        "return",
        "test_timeout_then_success_reverifies_exact_bytes",
    ),
    (
        "timeout-exhaustion-bound",
        "attempt < 2",
        "attempt < 1",
        "test_timeout_exhaustion_is_refused_after_three_attempts",
    ),
    (
        "crypto-rejection-no-retry",
        'require(result.returncode == 0, "ML-DSA-44 verification rejected")',
        "pass",
        "test_cryptographic_rejection_is_never_retried",
    ),
]

FROZEN_MUTATIONS = [
    (
        "complete-segment-digests",
        "set(pinned) == set(paths)",
        "True",
        "test_extra_segment_digest_cannot_qualify",
    )
]

FROZEN_MUTATIONS.extend(
    [
        (
            "qualification-extra-worker-segment",
            'actual == {row["path"] for row in inventory}',
            "True",
            "test_unlisted_worker_segment_cannot_qualify",
        ),
        (
            "launch-extra-worker-segment",
            'actual == {row["path"] for row in inventory}',
            "True",
            "test_unlisted_worker_segment_refuses_before_worker",
        ),
        (
            "qualification-extra-source-directory",
            'set(source_dirs) == {"src-node1", "src-node3", "src-node5"}',
            "True",
            "test_extra_source_directory_cannot_qualify",
        ),
        (
            "launch-extra-source-directory",
            'set(source_dirs) == {"src-node1", "src-node3", "src-node5"}',
            "True",
            "test_extra_source_directory_refuses_before_worker",
        ),
    ]
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    package = root / "testnet/acceptance/con01_history"
    test = Path(__file__).with_name("test_con01_rejudge.py")
    rows = []
    with tempfile.TemporaryDirectory() as temporary:
        private = Path(temporary)
        shutil.copytree(
            package,
            private / "testnet/acceptance/con01_history",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        tests = private / "testnet/tests"
        tests.mkdir(parents=True)
        for source in test.parent.glob("test_con01*.py"):
            shutil.copyfile(source, tests / source.name)
        shutil.copytree(test.parent / "data", tests / "data")
        shutil.copyfile(Path(__file__), tests / Path(__file__).name)
        observer = private / "testnet/acceptance/con01_history/observer.py"
        original = observer.read_text()

        def run(name, selected=None, red=False):
            command = [
                sys.executable,
                "-B",
                "-m",
                "unittest",
                "discover",
                "-s",
                str(tests),
                "-p",
                "test_con01*.py",
            ]
            if selected:
                command += ["-k", selected]
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=30,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            raw = result.stdout + result.stderr
            (args.out / f"{name}.log").write_bytes(raw)
            if red:
                if (
                    not result.returncode
                    or b"AssertionError" not in raw
                    or not re.search(rb"FAILED \(failures=[1-9][0-9]*\)", raw)
                    or b"ERROR" in raw
                ):
                    raise RuntimeError(f"{name}: intended runtime assertion did not fail")
            elif result.returncode:
                raise RuntimeError(f"{name}: baseline/restored suite failed")
            rows.append(
                dict(
                    name=name,
                    test=selected,
                    exit=result.returncode,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    bytes=len(raw),
                )
            )

        run("baseline")
        for name, before, after, selected in MUTATIONS:
            if original.count(before) != 1:
                raise RuntimeError(f"{name}: guard anchor changed")
            observer.write_text(original.replace(before, after))
            run(name, selected, red=True)
            observer.write_text(original)
        qualification = private / "testnet/acceptance/con01_history/qualify.py"
        original_qualification = qualification.read_text()
        for name, before, after, selected in QUALIFICATION_MUTATIONS:
            if original_qualification.count(before) != 1:
                raise RuntimeError(f"{name}: qualification anchor changed")
            qualification.write_text(original_qualification.replace(before, after))
            run(name, selected, red=True)
            qualification.write_text(original_qualification)
        launcher = private / "testnet/acceptance/con01_history/launch.py"
        original_launcher = launcher.read_text()
        for name, before, after, selected in LAUNCH_MUTATIONS:
            if original_launcher.count(before) != 1:
                raise RuntimeError(f"{name}: launch anchor changed")
            launcher.write_text(original_launcher.replace(before, after))
            run(name, selected, red=True)
            launcher.write_text(original_launcher)
        frozen = private / "testnet/acceptance/con01_history/frozen.py"
        original_frozen = frozen.read_text()
        for name, before, after, selected in FROZEN_MUTATIONS:
            if original_frozen.count(before) != 1:
                raise RuntimeError(f"{name}: frozen anchor changed")
            frozen.write_text(original_frozen.replace(before, after))
            run(name, selected, red=True)
            frozen.write_text(original_frozen)
        certificate = private / "testnet/acceptance/con01_history/certificate.py"
        original_certificate = certificate.read_text()
        for name, before, after, selected in CERTIFICATE_MUTATIONS:
            if original_certificate.count(before) != 1:
                raise RuntimeError(f"{name}: certificate anchor changed")
            certificate.write_text(original_certificate.replace(before, after))
            run(name, selected, red=True)
            certificate.write_text(original_certificate)
        run("restored")
    files = {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(package.glob("*.py"))
    }
    for source in test.parent.glob("test_con01*.py"):
        files[str(source.relative_to(root))] = hashlib.sha256(source.read_bytes()).hexdigest()
    for source in sorted((test.parent / "data/con01-history").glob("*")):
        if source.is_file():
            files[str(source.relative_to(root))] = hashlib.sha256(source.read_bytes()).hexdigest()
    files[str(Path(__file__).relative_to(root))] = hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
    (args.out / "REPORT.json").write_text(
        json.dumps(dict(result="PASS", files=files, rows=rows), indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
