#!/usr/bin/env python3
"""Isolated assertion-red controls for the read-only source collector.

Requires the explicit Anvil suite's dependencies.
A missing pattern, syntax error, collection/setup error, timeout or survivor is
INVALID, never a kill. The production checkout is never mutated.
"""

import argparse
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "testnet/scripts/collect-settlement-evm.py"
UNIT = "testnet/tests/test_settlement_evm.py"
ANVIL = "testnet/tests/anvil_settlement_observer.py"
CASES = (
    (
        "chain-id",
        'quantity(rpc.call("eth_chainId")) == binding["chain_id"]',
        "True",
        "testnet/tests/test_settlement_evm.py",
        "test_wrong_chain_refuses",
        "DID NOT RAISE",
    ),
    (
        "final-reorg",
        'block(rpc, target["number"])["hash"] == target["hash"]',
        "True",
        "testnet/tests/test_settlement_evm.py",
        "test_final_checkpoint_reorg_refuses",
        "DID NOT RAISE",
    ),
    (
        "contiguity",
        'quantity(current["number"]) == height and current["parentHash"] == parent',
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_block_log_refusals",
        "DID NOT RAISE",
    ),
    (
        "destroy-scope",
        "destroyed == int(bridge, 16)",
        "True",
        "testnet/tests/test_settlement_evm.py",
        "test_unrelated_destroy_is_not_bridge_destroy",
        "unrelated destroy paused bridge",
    ),
    (
        "hex-letter-case",
        'topics = [topic.lower() for topic in log["topics"]]',
        'topics = log["topics"]',
        "testnet/tests/test_settlement_evm_topic_case.py",
        "test_valid_uppercase_event_topic_is_not_ignored",
        "valid uppercase event topic ignored",
    ),
    (
        "log-byte-bound",
        "total_bytes <= MAX_LOG_BYTES",
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_each_log_budget_refuses",
        "DID NOT RAISE",
    ),
    (
        "pre-rpc-stale",
        "    stale_report(args.report)\n    try:",
        "    try:",
        "testnet/tests/test_settlement_evm.py",
        "test_report_is_stale_before_any_rpc_can_block",
        "healthy report survived until blocking RPC",
    ),
    (
        "readonly",
        "method in READ_METHODS",
        "True",
        "testnet/tests/test_settlement_evm.py",
        "test_signing_rpc_never_reaches_transport",
        "signing method reached network",
    ),
    (
        "stale",
        'hash="0" * 64, utime=0',
        'hash="0" * 64, utime=int(time.time())',
        "testnet/tests/test_settlement_evm.py",
        "test_rpc_failure_stales_report_before_reuse",
        "old healthy monitor survived source failure",
    ),
    (
        "interval-bound",
        "and stop - start <= MAX_BLOCKS",
        "and True",
        "testnet/tests/test_settlement_evm.py",
        "test_interval_bound_is_checked_before_rpc",
        "oversized interval reached RPC",
    ),
    (
        "blacklist",
        "read_bool(rpc, token, blacklist, point, bridge)",
        "False",
        "testnet/tests/anvil_settlement_observer.py",
        "test_legacy_sender_only_freeze_is_asset_scoped",
        "blacklist alarm missing",
    ),
    (
        "pause-interval",
        "pauses += 1",
        "pauses += 0",
        "testnet/tests/anvil_settlement_observer.py",
        "test_pause_then_unpause_is_not_lost",
        "pause interval event missing",
    ),
    (
        "destroy-event",
        "destroys += 1",
        "destroys += 0",
        "testnet/tests/anvil_settlement_observer.py",
        "test_destroy_without_transfer_has_its_own_alarm",
        "destruction/backing alarm missing",
    ),
    (
        "fees",
        'read_uint(rpc, token, "fee", point) if profile == "legacy_usdt" else 0',
        '0 if profile == "legacy_usdt" else 0',
        "testnet/tests/anvil_settlement_observer.py",
        "test_fee_and_legacy_upgrade_are_observed",
        "assert 0 == 19",
    ),
    (
        "deprecation",
        'read_bool(rpc, token, "deprecated", point) if profile == "legacy_usdt" else False',
        'False if profile == "legacy_usdt" else False',
        "testnet/tests/anvil_settlement_observer.py",
        "test_fee_and_legacy_upgrade_are_observed",
        "deprecation flag lost",
    ),
    (
        "bridge-events",
        "amount=values[amount_position]",
        "amount=0",
        "testnet/tests/anvil_settlement_observer.py",
        "test_complete_receipts_reconcile_lock_unlock_and_refund",
        "bridge event inventory wrong",
    ),
    (
        "receiver",
        "read_bool(rpc, token, blacklist, point, receiver)",
        "False",
        "testnet/tests/anvil_settlement_observer.py",
        "test_blacklisted_receiver_is_reported",
        "assert False is True",
    ),
    (
        "code-pin",
        'runtime == cfg["code_sha256"]',
        "True",
        "testnet/tests/anvil_settlement_observer.py",
        "test_contract_code_pin_refuses",
        "DID NOT RAISE",
    ),
    (
        "baseline",
        'prior["hash"][2:] == previous["hash"]',
        "True",
        "testnet/tests/anvil_settlement_observer.py",
        "test_baseline_hash_mismatch_refuses",
        "DID NOT RAISE",
    ),
    (
        "log-query-hash",
        "dict(blockHash=parent, address=addresses)",
        "dict(blockNumber=hex(height), address=addresses)",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_six_thousand_transactions_use_one_log_query_not_receipts",
        "log query lost hash filter",
    ),
    (
        "baseline-number",
        'quantity(prior["number"]) == start',
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_baseline_number_and_target_hash_refuse",
        "DID NOT RAISE",
    ),
    (
        "target-hash",
        'parent == target["hash"]',
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_baseline_number_and_target_hash_refuse",
        "DID NOT RAISE",
    ),
    (
        "log-block-hash",
        'and log["blockHash"] == parent',
        "and True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_block_log_refusals",
        "DID NOT RAISE",
    ),
    (
        "log-height",
        'and quantity(log["blockNumber"]) == height',
        "and True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_block_log_refusals",
        "DID NOT RAISE",
    ),
    (
        "removed",
        'and log.get("removed") is False',
        "and True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_block_log_refusals",
        "DID NOT RAISE",
    ),
    (
        "transaction-index",
        'tx_index < len(current["transactions"])',
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_block_log_refusals",
        "IndexError",
    ),
    (
        "transaction-hash",
        'log["transactionHash"] == current["transactions"][tx_index]',
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_block_log_refusals",
        "DID NOT RAISE",
    ),
    (
        "log-order",
        "index > previous_index and tx_index >= previous_tx",
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_block_log_refusals",
        "DID NOT RAISE",
    ),
    (
        "address-filter",
        'address(log["address"]) in addresses',
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_block_log_refusals",
        "DID NOT RAISE",
    ),
    (
        "topic-limit",
        'len(log["topics"]) <= 4,\n                "source log topic bound"',
        'True,\n                "source log topic bound"',
        "testnet/tests/test_settlement_evm_scale.py",
        "test_block_log_refusals",
        "DID NOT RAISE",
    ),
    (
        "block-count",
        "len(logs) <= MAX_BLOCK_LOGS",
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_each_log_budget_refuses",
        "DID NOT RAISE",
    ),
    (
        "block-bytes",
        "block_bytes <= MAX_BLOCK_LOG_BYTES",
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_each_log_budget_refuses",
        "DID NOT RAISE",
    ),
    (
        "total-count",
        "len(all_logs) <= MAX_LOGS",
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_each_log_budget_refuses",
        "DID NOT RAISE",
    ),
    (
        "gap-origin",
        'and batch["origin"] == origin',
        "and True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_archive_cannot_skip_or_substitute_a_batch",
        "DID NOT RAISE",
    ),
    (
        "gap-binding",
        'and batch["binding"] == binding_hash(binding)',
        "and True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_archive_cannot_skip_or_substitute_a_batch",
        "DID NOT RAISE",
    ),
    (
        "gap-chain",
        'and batch["from"] == cursor',
        "and True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_archive_cannot_skip_or_substitute_a_batch",
        "DID NOT RAISE",
    ),
    (
        "gap-digest",
        'and batch["previous_sha256"] == prior_hash',
        "and True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_archive_cannot_skip_or_substitute_a_batch",
        "DID NOT RAISE",
    ),
    (
        "gap-events",
        "    logs += block_logs(",
        "    logs = block_logs(",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_batches_catch_up_without_changing_the_baseline",
        "gap events were dropped",
    ),
    (
        "gap-prev",
        "gap_dir is None or previous is not None",
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_requires_original_previous_and_refuses_missing_batch",
        "gap archive",
    ),
    (
        "gap-height",
        '0 < end["height"] - cursor["height"] <= GAP_BATCH_BLOCKS',
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_height_and_count_and_bytes_are_bounded",
        "DID NOT RAISE",
    ),
    (
        "gap-count",
        "len(paths) <= MAX_GAP_BATCHES",
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_height_and_count_and_bytes_are_bounded",
        "DID NOT RAISE",
    ),
    (
        "gap-file",
        "len(data) <= monitor.MAX_BYTES",
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_height_and_count_and_bytes_are_bounded",
        "JSONDecodeError",
    ),
    (
        "gap-log-count",
        'len(logs) <= MAX_LOGS, "gap archive log bound"',
        'True, "gap archive log bound"',
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_height_and_count_and_bytes_are_bounded",
        "DID NOT RAISE",
    ),
)
CASES += (
    (
        "gap-inventory",
        'path.name == f"{index:06d}.json" and not path.is_symlink()',
        "True",
        "testnet/tests/test_settlement_evm_scale.py",
        "test_gap_requires_original_previous_and_refuses_missing_batch",
        "DID NOT RAISE",
    ),
)


def run(selection, path, log):
    result_path = log.with_suffix(".xml")
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--tb=short",
        "--junitxml=" + str(result_path),
        *selection,
    ]
    with log.open("w") as out:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env={**os.environ, "TOS_SETTLEMENT_COLLECTOR": str(path)},
            stdout=out,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
    return result.returncode, result_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    original = SOURCE.read_text()
    labels = [case[0] for case in CASES]
    patterns = [(case[1], case[2]) for case in CASES]
    if len(set(labels)) != len(labels) or len(set(patterns)) != len(patterns):
        raise RuntimeError("duplicate mutation control")
    for label, before, after, *_ in CASES:
        if original.count(before) != 1:
            raise RuntimeError("pattern must occur exactly once: " + label)
        ast.parse(original.replace(before, after))
    code, result = run(
        [
            UNIT,
            "testnet/tests/test_settlement_evm_scale.py",
            "testnet/tests/test_settlement_evm_topic_case.py",
            ANVIL,
        ],
        SOURCE,
        args.log_dir / "baseline.log",
    )
    if code != 0 or not list(ET.parse(result).getroot().iter("testcase")):
        raise RuntimeError("positive baseline invalid")
    for label, before, after, file, test, expected in CASES:
        if original.count(before) != 1:
            raise RuntimeError("pattern must occur exactly once: " + label)
        changed = original.replace(before, after)
        ast.parse(changed)
        with tempfile.TemporaryDirectory(prefix="source-observer-mutant-") as temporary:
            path = Path(temporary) / SOURCE.name
            path.write_text(changed)
            shutil.copy2(
                SOURCE.with_name("check-settlement.py"), path.with_name("check-settlement.py")
            )
            log = args.log_dir / (label + ".log")
            code, result = run([file, "-k", test], path, log)
            tree = ET.parse(result).getroot()
            failures = [
                c
                for c in tree.iter("testcase")
                if test in c.attrib["name"] and c.find("failure") is not None
            ]
            if (
                code != 1
                or not failures
                or list(tree.iter("error"))
                or expected not in log.read_text()
            ):
                raise RuntimeError("survived or invalid: " + label)
        print(label + ": assertion-red", flush=True)
    print(f"{len(CASES)}/{len(CASES)} assertion-red")


if __name__ == "__main__":
    main()
