"""Mutation controls in a private copy; never modify a running observer checkout."""

import argparse
import hashlib
import json
import os
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
        "sha(Path(__file__).with_name(name)) == digest",
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    package = root / "production/con01_history"
    test = Path(__file__).with_name("test_con01_rejudge.py")
    rows = []
    with tempfile.TemporaryDirectory() as temporary:
        private = Path(temporary)
        shutil.copytree(
            package,
            private / "production/con01_history",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        tests = private / "testnet/tests"
        tests.mkdir(parents=True)
        for source in test.parent.glob("test_con01*.py"):
            shutil.copyfile(source, tests / source.name)
        shutil.copytree(test.parent / "data", tests / "data")
        observer = private / "production/con01_history/observer.py"
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
                    or b"FAILED (failures=1)" not in raw
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
        qualification = private / "production/con01_history/qualify.py"
        original_qualification = qualification.read_text()
        for name, before, after, selected in QUALIFICATION_MUTATIONS:
            if original_qualification.count(before) != 1:
                raise RuntimeError(f"{name}: qualification anchor changed")
            qualification.write_text(original_qualification.replace(before, after))
            run(name, selected, red=True)
            qualification.write_text(original_qualification)
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
