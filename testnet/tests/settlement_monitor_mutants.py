#!/usr/bin/env python3
"""Run guard-removal controls in a disposable copy; no node access or source mutation."""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "testnet/scripts/check-settlement.py"
TEST = ROOT / "testnet/tests/test_check_settlement.py"
MUTANTS = {
    "payout_age": ('height - created > limits["payout_blocks"]', "False"),
    "returned_count": ('len(returned) >= limits["returned_count"]', "False"),
    "returned_age": ('seconds > limits["returned_seconds"]', "False"),
    "funding_return": ("if kind == 4:", "if False:"),
    "returns_headroom": ("if count >= 448:", "if False:"),
    "returns_full": ("if count >= 512:", "if False:"),
    "refusals": ('rc >= limits["refusals_count"]', "False"),
    "refusal_inventory": ("if rc != len(refusals):", "if False:"),
    "wallet_binding": ('actor["own_wallet"] != ap["own_wallet"]', "False"),
    "actor_floor": ('number(actor["tos_balance"], "tos_balance") < floor', "False"),
    "wallet_floor": (
        'number(actor["wallet_tos_balance"], "wallet_tos_balance") < number(',
        "False and number(",
    ),
    "liability": ("if liability >= total:", "if False:"),
    "recognition": ("if len(recognition) > 16:", "if False:"),
    "migration": ('parameter == 79 and record["bridge"] != bridge and status == 1', "False"),
    "donation_burn": ("if actual != expected_delta:", "if False:"),
    "freeze": ('if flag(asset, "bridge_blacklisted"):', "if False:"),
    "pause": ('if flag(asset, "paused"):', "if False:"),
    "destroy": ('if number(asset["destroy_events"], "destroy_events"):', "if False:"),
    "fee": ('number(asset["fee_basis_points"], "fee_basis_points")', "0"),
    "upgrade": ('asset["implementation"] != pin["implementation"]', "False"),
    "headroom": ('available <= number(pin["min_lock_headroom"], "min_lock_headroom")', "False"),
    "inventory": ('unique(actors, "id") != unique(expected, "id")', "False"),
    "unknown_retry": ('if entry["state"] != "prepared":', "if False:"),
    "journal_before_send": ('entry["state"] = "unknown"', 'entry["state"] = "prepared"'),
    "prepared_revalidation": ('state="withdrawn",', 'state="prepared",'),
    "dispatch_eligibility": (
        'if key not in eligible or eligible[key] != entry["request"]:',
        "if False:",
    ),
    "unknown_reprepared": (
        'if state in ("prepared", "withdrawn"):',
        'if state in ("prepared", "withdrawn", "unknown"):',
    ),
    "unknown_alarm": ('if state == "unknown":', "if False:"),
    "clearance": ("if record is None and later:", "if False:"),
    "overdue_blocks": ("blocks > clear_blocks", "False"),
    "overdue_seconds": ("seconds > clear_seconds", "False"),
    "reappeared": ("if record is not None:", "if False:"),
    "publish_before_dispatch": (
        "atomic(report_path, report)  # published before any dispatch",
        "pass",
    ),
    "dispatch_count": ("if len(attempted) >= limit:", "if False:"),
    "dispatch_budget": ("if monotonic() - started + timeout > budget:", "if False:"),
    "fair_order": ("ranked.append((index, asset, key))", "ranked.append((0, asset, key))"),
}


def run(source):
    with tempfile.TemporaryDirectory(prefix="settlement-control-") as folder:
        root = Path(folder)
        (root / "scripts").mkdir()
        (root / "tests").mkdir()
        (root / "scripts/check-settlement.py").write_text(source)
        test = root / "tests/test_check_settlement.py"
        test.write_bytes(TEST.read_bytes())
        return subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(test)],
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True,
            text=True,
            timeout=60,
        )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()
    source = SOURCE.read_text()
    base = run(source)
    if base.returncode:
        print("BASE_FAILED", base.stdout[-3000:])
        return 1
    failed = []
    for label, (old, new) in MUTANTS.items():
        if source.count(old) != 1:
            print("ANCHOR_DRIFT", label)
            failed.append(label)
            continue
        result = run(source.replace(old, new))
        # A syntax/import error is not a behavioral red control.
        killed = (
            result.returncode == 1
            and " failed" in result.stdout
            and "ERROR collecting" not in result.stdout
        )
        print(label, "RED" if killed else "NOT_KILLED")
        if not killed:
            failed.append(label)
    print(f"{len(MUTANTS) - len(failed)}/{len(MUTANTS)} controls killed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
