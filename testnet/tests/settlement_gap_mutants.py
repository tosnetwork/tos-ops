#!/usr/bin/env python3
"""Assertion-red controls for the operator gap command; no source checkout edits."""

import argparse
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "testnet/scripts/reconcile-settlement-gap.py"
TEST = "testnet/tests/test_settlement_evm_scale.py"
CASES = (
    (
        "network",
        'previous["network"] == binding["network"]',
        "True",
        "test_gap_own_guards_refuse_without_writing",
        "DID NOT RAISE",
    ),
    (
        "chain",
        'collector.quantity(rpc.call("eth_chainId")) == binding["chain_id"]',
        "True",
        "test_gap_own_guards_refuse_without_writing",
        "DID NOT RAISE",
    ),
    (
        "minimum-batch",
        "1 <= blocks <= collector.GAP_BATCH_BLOCKS",
        "0 <= blocks <= collector.GAP_BATCH_BLOCKS",
        "test_gap_own_guards_refuse_without_writing",
        "DID NOT RAISE",
    ),
    (
        "checkpoint",
        'collector.block(rpc, hex(stop))["hash"] == target["hash"]',
        "True",
        "test_gap_own_guards_refuse_without_writing",
        "DID NOT RAISE",
    ),
    (
        "finalized",
        'collector.block(rpc, final["number"])["hash"] == final["hash"]',
        "True",
        "test_gap_own_guards_refuse_without_writing",
        "DID NOT RAISE",
    ),
    (
        "stale-before-rpc",
        '            collector.stale_report(args.state_dir / "report.json")',
        "            pass",
        "test_gap_cli_never_publishes_health_or_changes_previous",
        "HEALTHY",
    ),
    (
        "monitor-lock",
        "            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)",
        "            pass",
        "test_recovery_obeys_monitor_lock",
        "lock conflict reached RPC",
    ),
)


def run(source, selection, log):
    result_path = log.with_suffix(".xml")
    with tempfile.TemporaryDirectory(prefix="gap-mutant-") as directory:
        target = Path(directory) / SOURCE.name
        target.write_text(source)
        for name in ("collect-settlement-evm.py", "check-settlement.py"):
            shutil.copy2(SOURCE.with_name(name), target.with_name(name))
        with log.open("w") as output:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "--tb=short",
                    "--junitxml=" + str(result_path),
                    TEST,
                    "-k",
                    selection,
                ],
                cwd=ROOT,
                env={**os.environ, "TOS_SETTLEMENT_GAP": str(target)},
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=60,
                check=False,
            )
    return result.returncode, ET.parse(result_path).getroot()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    original = SOURCE.read_text()
    code, tree = run(original, "gap or recovery", args.log_dir / "baseline.log")
    if code or not list(tree.iter("testcase")):
        raise RuntimeError("invalid positive baseline")
    for label, before, after, test, expected in CASES:
        if original.count(before) != 1:
            raise RuntimeError("non-unique anchor: " + label)
        changed = original.replace(before, after)
        ast.parse(changed)
        log = args.log_dir / (label + ".log")
        code, tree = run(changed, test, log)
        failures = [
            t
            for t in tree.iter("testcase")
            if test in t.attrib["name"] and t.find("failure") is not None
        ]
        if code != 1 or not failures or list(tree.iter("error")) or expected not in log.read_text():
            raise RuntimeError("survived or invalid: " + label)
        print(label + ": assertion-red", flush=True)
    print(f"{len(CASES)}/{len(CASES)} assertion-red")


if __name__ == "__main__":
    main()
