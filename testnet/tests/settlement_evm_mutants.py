#!/usr/bin/env python3
"""Isolated assertion-red controls for the read-only source collector.

Requires the explicit Anvil suite's dependencies. Run under the thermal guard.
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
        "readonly",
        "method in READ_METHODS",
        "True",
        UNIT,
        "test_signing_rpc_never_reaches_transport",
        "signing method reached network",
    ),
    (
        "stale",
        'hash="0" * 64, utime=0',
        'hash="0" * 64, utime=int(time.time())',
        UNIT,
        "test_rpc_failure_stales_report_before_reuse",
        "old healthy monitor survived source failure",
    ),
    (
        "interval-bound",
        "and stop - start <= MAX_BLOCKS",
        "and True",
        UNIT,
        "test_interval_bound_is_checked_before_rpc",
        "oversized interval reached RPC",
    ),
    (
        "blacklist",
        "read_bool(rpc, token, blacklist, point, bridge)",
        "False",
        ANVIL,
        "test_blacklisted_bridge_accepts_lock_but_observation_stops_it",
        "blacklist alarm missing",
    ),
    (
        "pause-interval",
        "pauses += 1",
        "pauses += 0",
        ANVIL,
        "test_pause_then_unpause_is_not_lost",
        "pause interval event missing",
    ),
    (
        "destroy-event",
        "destroys += 1",
        "destroys += 0",
        ANVIL,
        "test_destroy_without_transfer_has_its_own_alarm",
        "destruction/backing alarm missing",
    ),
    (
        "fees",
        'read_uint(rpc, token, "fee", point) if profile == "legacy_usdt" else 0',
        '0 if profile == "legacy_usdt" else 0',
        ANVIL,
        "test_fee_and_legacy_upgrade_are_observed",
        "assert 0 == 19",
    ),
    (
        "deprecation",
        'read_bool(rpc, token, "deprecated", point) if profile == "legacy_usdt" else False',
        'False if profile == "legacy_usdt" else False',
        ANVIL,
        "test_fee_and_legacy_upgrade_are_observed",
        "deprecation flag lost",
    ),
    (
        "bridge-events",
        "amount=values[amount_position]",
        "amount=0",
        ANVIL,
        "test_complete_receipts_reconcile_lock_unlock_and_refund",
        "bridge event inventory wrong",
    ),
    (
        "receiver",
        "read_bool(rpc, token, blacklist, point, receiver)",
        "False",
        ANVIL,
        "test_blacklisted_receiver_is_reported",
        "assert False is True",
    ),
    (
        "code-pin",
        'runtime == cfg["code_sha256"]',
        "True",
        ANVIL,
        "test_contract_code_pin_refuses",
        "DID NOT RAISE",
    ),
    (
        "baseline",
        'prior["hash"][2:] == previous["hash"]',
        "True",
        ANVIL,
        "test_baseline_hash_mismatch_refuses",
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
    code, result = run([UNIT, ANVIL], SOURCE, args.log_dir / "baseline.log")
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
