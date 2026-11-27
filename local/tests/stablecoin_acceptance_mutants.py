#!/usr/bin/env python3
"""Assertion-red controls for the stablecoin acceptance additions.

Each control removes one guard in a disposable copy of the scripts and requires
the named test to fail with the named message. Never accesses a running network.
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
DRIVER = "local/scripts/local-pq-stablecoin-acceptance.py"
SERVICE = "local/scripts/local-pq-service-token.py"
UNIT = "local/tests/test_local_pq_stablecoin_acceptance.py"
SERVICE_UNIT = "local/tests/test_local_pq_service_token.py"
CASES = [
    (
        "shared-minter",
        DRIVER,
        'require(out["usdc"]["minter"] != out["usdt"]["minter"], "the two assets share a minter")',
        "pass",
        UNIT,
        "test_assets_bind_each_run_and_refuse_a_shared_identity",
        "DID NOT RAISE",
    ),
    (
        "cap-order",
        DRIVER,
        'require(per_lock <= hourly <= daily, "caps must satisfy per-lock <= hourly <= daily")',
        "pass",
        UNIT,
        "test_cap_votes_are_checked_before_signing",
        "DID NOT RAISE",
    ),
    (
        "burn-layout",
        DRIVER,
        'require(len(bits) == 704 and not body.refs, "LOG_BURN body has another layout")',
        "pass",
        UNIT,
        "test_other_externals_are_not_burns_and_a_short_body_refuses",
        "DID NOT RAISE",
    ),
    (
        "burn-topic",
        DRIVER,
        "if length != 256 or topic != LOG_BURN:",
        "if length != 256:",
        UNIT,
        "test_other_externals_are_not_burns_and_a_short_body_refuses",
        "assert [{",
    ),
    (
        "v3-expiry",
        DRIVER,
        "time.time() < record[\"valid_until\"],",
        "True,",
        UNIT,
        "test_wallet_v3_never_resends_an_expired_message",
        "expired unsent",
    ),
    (
        "v3-subwallet",
        DRIVER,
        'require(subwallet == self.subwallet, "the payer\'s subwallet differs")',
        "pass",
        UNIT,
        "test_wallet_v3_refuses_another_subwallet",
        "DID NOT RAISE",
    ),
    (
        "probe-reason",
        DRIVER,
        'require(reason in output, f"the lock was refused for another reason: {output[-400:]}")',
        "pass",
        UNIT,
        "test_probe_refuses_another_reason",
        "DID NOT RAISE",
    ),
    (
        "probe-admitted",
        DRIVER,
        'require(not ok, f"a lock of {amount} was admitted at block {block[\'number\']}: {facts}")',
        "pass",
        UNIT,
        "test_probe_refuses_an_admitted_lock",
        "another reason",
    ),
    (
        "approval-clear",
        DRIVER,
        'allowance and state.intent(label + "-approve") is None',
        "False",
        UNIT,
        "test_approval_is_cleared_before_an_exact_one",
        "assert ['lock-approve'] ==",
    ),
    (
        "lock-preflight",
        DRIVER,
        'require(ok, f"the lock would be refused; nothing is sent: {output[-400:]}")',
        "pass",
        UNIT,
        "test_lock_refused_in_simulation_sends_nothing",
        "DID NOT RAISE",
    ),
    (
        "lock-supply",
        DRIVER,
        "supply == progress[\"supply_before\"] + received,",
        "True,",
        UNIT,
        "test_lock_supply_that_does_not_match_refuses",
        "DID NOT RAISE",
    ),
    (
        "lock-relabel",
        DRIVER,
        'progress["asset"] == asset_name and progress["amount"] == amount,',
        "True,",
        UNIT,
        "test_lock_label_cannot_be_reused_for_another_amount",
        "DID NOT RAISE",
    ),
    (
        "unlock-receiver-fee",
        DRIVER,
        'after["receiver"] - before["receiver"] == log["amount"] - fee,',
        "True,",
        UNIT,
        "test_unlock_receiver_short_of_the_preview_refuses",
        "DID NOT RAISE",
    ),
    (
        "unlock-preview",
        DRIVER,
        'int(burn["preview"]["received_atomic"]) == log["amount"] - fee,',
        "True,",
        UNIT,
        "test_unlock_preview_that_differs_refuses",
        "DID NOT RAISE",
    ),
    (
        "unlock-receiver",
        DRIVER,
        'require(burn["receiver"] == receiver, "the unlock names another receiver than the burn")',
        "pass",
        UNIT,
        "test_unlock_to_another_receiver_than_the_burn_refuses",
        "Expected regex: 'another receiver'",
    ),
    (
        "observe-latches",
        DRIVER,
        "and not incidents,",
        "and True,",
        UNIT,
        "test_a_latch_on_disk_is_not_clean_even_if_the_report_omits_it",
        "DID NOT RAISE",
    ),
    (
        "observe-stale",
        DRIVER,
        'and result["report_age_seconds"] <= 120,',
        "and True,",
        UNIT,
        "test_clean_observation_refuses_alarms_latches_and_staleness",
        "DID NOT RAISE",
    ),
    (
        "reconcile",
        DRIVER,
        'require(item["reconciled"], f"{name} supply',
        'require(True, f"{name} supply',
        UNIT,
        "test_reconcile_refuses_unbacked_supply",
        "DID NOT RAISE",
    ),
    (
        "fee-bounds",
        DRIVER,
        'require(0 <= args.basis_points < 20 and 0 <= args.max_fee < 50, "fee bounds")',
        "pass",
        UNIT,
        "test_issuer_fee_outside_the_fixture_bounds_refuses_before_sending",
        "Expected regex: 'fee bounds'",
    ),
    (
        "loopback",
        DRIVER,
        'require(args.evm_rpc.startswith("http://127.0.0.1:"), "local source endpoint required")',
        "pass",
        UNIT,
        "test_source_endpoint_must_be_loopback",
        "local source endpoint required",
    ),
    (
        "custom-case-name",
        SERVICE,
        "not custom or label not in FIXED_CASES,",
        "True,",
        SERVICE_UNIT,
        "test_explicit_funding_cannot_reuse_a_fixed_case",
        "DID NOT RAISE",
    ),
    (
        "custom-amount",
        SERVICE,
        'str(args.funding_atomic) if custom else "1000000"',
        '"1000000"',
        SERVICE_UNIT,
        "test_explicit_funding_uses_the_real_terms_and_the_given_amount",
        "1001001",
    ),
    (
        "custom-bounds",
        SERVICE,
        "type(args.funding_atomic) is int and 0 < args.funding_atomic < 2**120,",
        "True,",
        SERVICE_UNIT,
        "test_explicit_funding_amount_is_bounded",
        "DID NOT RAISE",
    ),
    (
        "verify-expected-state",
        SERVICE,
        "    elif expect_state:\n        expected = expect_state\n",
        "",
        SERVICE_UNIT,
        "test_verify_requires_the_expected_state",
        "DID NOT RAISE",
    ),
    (
        "resolve-condition",
        DRIVER,
        'require(CLEARED[code](facts), f"{args.incident} still holds at source block {point[\'number\']}")',
        "pass",
        UNIT,
        "test_resolution_refuses_while_its_condition_holds",
        "DID NOT RAISE",
    ),
    (
        "resolve-reenabled",
        DRIVER,
        'require(not facts["disabled"] and facts["allow_lock"], "re-enable the token before resolving")',
        "pass",
        UNIT,
        "test_resolution_refuses_while_its_condition_holds",
        "DID NOT RAISE",
    ),
    (
        "resolve-only-named",
        DRIVER,
        "remaining = {k: v for k, v in incidents.items() if k != args.incident}",
        "remaining = {}",
        UNIT,
        "test_resolution_removes_only_the_named_latch_and_keeps_copies",
        "usdc:token_paused",
    ),
    (
        "resolve-lock",
        DRIVER,
        "fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)\n        original",
        "original",
        UNIT,
        "test_resolution_refuses_while_the_checker_holds_its_lock",
        "DID NOT RAISE",
    ),
    (
        "resolve-fresh-after",
        DRIVER,
        'require(time.monotonic() < deadline, "no fresh report after the resolution")',
        "break",
        UNIT,
        "test_resolution_requires_a_fresh_report_afterwards",
        "DID NOT RAISE",
    ),
]


def run(root, selection, log):
    result_path = log.with_suffix(".xml")
    env = {
        **os.environ,
        "TOS_STABLECOIN_DRIVER": str(root / DRIVER),
        "TOS_SERVICE_TOKEN_DRIVER": str(root / SERVICE),
    }
    with log.open("w") as stream:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=short",
             "--junitxml=" + str(result_path), *selection],
            cwd=ROOT,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
    return result.returncode, ET.parse(result_path).getroot()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    code, report = run(ROOT, [UNIT, SERVICE_UNIT], args.log_dir / "baseline.log")
    if code or not list(report.iter("testcase")):
        raise RuntimeError("invalid positive baseline")
    for label, relative, before, after, file, test, expected in CASES:
        with tempfile.TemporaryDirectory(prefix="stablecoin-control-") as temp:
            root = Path(temp)
            for folder in ("local/scripts", "testnet/scripts", "local/contracts/test-usdt"):
                shutil.copytree(ROOT / folder, root / folder,
                                ignore=shutil.ignore_patterns("__pycache__"))
            path = root / relative
            original = path.read_text()
            if original.count(before) != 1:
                raise RuntimeError("ambiguous mutation: " + label)
            changed = original.replace(before, after)
            ast.parse(changed)
            path.write_text(changed)
            log = args.log_dir / (label + ".log")
            code, report = run(root, [file, "-k", test], log)
            failures = [
                c for c in report.iter("testcase")
                if test in c.attrib["name"] and c.find("failure") is not None
            ]
            if code != 1 or not failures or list(report.iter("error")) or expected not in log.read_text():
                raise RuntimeError("survived or invalid control: " + label)
        print(label + ": assertion-red", flush=True)
    print(f"{len(CASES)}/{len(CASES)} assertion-red")


if __name__ == "__main__":
    main()
