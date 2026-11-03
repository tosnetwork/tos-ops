"""Run window assertions with individual guards removed in a private copy."""

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
        "election-row-shape",
        "len(stack[0]) == 2",
        "True",
        "test_extra_or_malformed_getter_fields_refuse",
    ),
    (
        "legacy-fixed-since",
        'since, until = current["since"], current["until"]',
        'since, until = current["since"], current["until"]\n    require(since == 1793541840, "legacy pinned term")',
        "test_dynamic_term_and_expiring_nonapproval",
    ),
    ("settlement", "SETTLE_SECONDS = 905", "SETTLE_SECONDS = 0", "test_settlement_boundary"),
    ("handover", "MIN_REMAINING = 1800", "MIN_REMAINING = 0", "test_handover_boundary"),
    ("freshness", "MAX_AGE = 30", "MAX_AGE = 300", "test_stale_or_future_signed_target_refuses"),
    ("election", "if any(elections):", "if False:", "test_active_election_blocks"),
    (
        "election-type",
        "type(value) is int and value >= 0",
        "True",
        "test_malformed_election_is_not_inactive",
    ),
    ("config-peers", "configs[1] == current", "True", "test_config_peer_disagreement_refuses"),
    (
        "governing-set",
        'row["set_hash"]',
        'current["set_hash"]',
        "test_config_must_match_certified_governing_set",
    ),
    (
        "network-version",
        'current["global_id"] == 2 and current["version"] == 16',
        "True",
        "test_network_and_version_are_not_interchangeable",
    ),
    (
        "validator-count",
        'current["total"] == 4',
        "True",
        "test_network_and_version_are_not_interchangeable",
    ),
    (
        "source-population",
        'len(chain["sources"]) == 3',
        "True",
        "test_source_population_and_full_target_are_required",
    ),
    (
        "target-full-id",
        'identity(row["id"]) == identity(chain["target"])',
        "True",
        "test_source_population_and_full_target_are_required",
    ),
    (
        "governing-schedule",
        'row["term_schedule"] == "within_schedule"',
        "True",
        "test_expired_governing_set_refuses",
    ),
    (
        "config-full-id",
        "identity(block) == identity(key)",
        "True",
        "test_real_config_requires_certified_full_key_identity",
    ),
    (
        "proof-status",
        'chain["status"] == "VERIFIED_GENESIS_CHAIN_AND_THREE_SOURCE_SUFFIX"',
        "True",
        "test_unknown_proof_status_never_qualifies",
    ),
    (
        "header-expiry",
        'min(row["header"]["gen_utime"] for row in rows) + MAX_AGE,',
        "",
        "test_validity_never_outlives_oldest_proved_header",
    ),
    (
        "refresh-genesis-prefix",
        'archive["from_genesis"] is True',
        "True",
        "test_non_genesis_prefix_refused",
    ),
    (
        "refresh-genesis",
        'identity(info["init"]) == identity(prefix["anchor"])',
        "True",
        "test_substituted_genesis_refused",
    ),
    (
        "refresh-monotonic",
        'seqno >= identity(prefix["target"])[2]',
        "True",
        "test_backward_target_refused",
    ),
    (
        "refresh-full-target",
        'target is None or identity(header["id"]) == identity(target)',
        "True",
        "test_full_target_mismatch_refused",
    ),
    (
        "refresh-keys",
        'all(row["keys"] == reference["keys"] for row in reports.values())',
        "True",
        "test_key_chain_disagreement_refused",
    ),
    ("refresh-network", 'header["global_id"] == 2', "True", "test_wrong_network_refused"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    args.out.mkdir(mode=0o700, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    rows = []
    with tempfile.TemporaryDirectory() as folder:
        private = Path(folder)
        (private / "production").mkdir()
        shutil.copytree(
            root / "production/con01_history",
            private / "production/con01_history",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        target = private / "production/br1_window.py"
        shutil.copyfile(root / "production/br1_window.py", target)
        tests = private / "testnet/tests"
        tests.mkdir(parents=True)
        shutil.copyfile(root / "testnet/tests/test_br1_window.py", tests / "test_br1_window.py")
        shutil.copytree(root / "testnet/tests/data/br1-window", tests / "data/br1-window")
        shutil.copyfile(
            root / "testnet/tests/test_br1_window_refresh.py", tests / "test_br1_window_refresh.py"
        )
        original = target.read_text()

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
                "test_br1_window*.py",
            ]
            if selected:
                command += ["-k", selected]
            result = subprocess.run(command, capture_output=True, timeout=30)
            raw = result.stdout + result.stderr
            (args.out / (name + ".log")).write_bytes(raw)
            if red:
                if (
                    result.returncode != 1
                    or b"AssertionError" not in raw
                    or not re.search(rb"FAILED \(failures=[1-9][0-9]*\)", raw)
                    or b"ERROR" in raw
                ):
                    raise RuntimeError("intended runtime assertion did not fail: " + name)
            elif result.returncode != 0 or b"Ran 24 tests" not in raw or b"\nOK\n" not in raw:
                raise RuntimeError("complete baseline/restoration failed: " + name)
            rows.append(
                {
                    "name": name,
                    "test": selected,
                    "exit": result.returncode,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                }
            )

        run("baseline")
        for name, before, after, selected in MUTATIONS:
            if original.count(before) != 1:
                raise RuntimeError("guard anchor drift: " + name)
            target.write_text(original.replace(before, after))
            run(name, selected, True)
            target.write_text(original)
        run("restored")
    paths = [
        root / "production/br1_window.py",
        root / "testnet/tests/test_br1_window.py",
        root / "testnet/tests/test_br1_window_refresh.py",
        Path(__file__),
    ]
    paths += list((root / "production/con01_history").glob("*.py"))
    paths += list((root / "testnet/tests/data/br1-window").glob("*"))
    files = {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in paths
        if p.is_file()
    }
    (args.out / "REPORT.json").write_text(
        json.dumps({"result": "PASS", "sources": files, "rows": rows}, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
