#!/usr/bin/env python3
"""Assertion-red issuer controls, always against the isolated source fixture."""

import ast
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "testnet/scripts"
CASES = (
    (
        "finalized-tag",
        "settlement_issuer.py",
        'source.block(rpc, "finalized")',
        'source.block(rpc, "latest")',
        "test_all_issuer_reads_use_the_finalized_hash",
        "issuer finality tag lost",
    ),
    (
        "canonical-point",
        "settlement_issuer.py",
        'dict(blockHash=target["hash"], requireCanonical=True)',
        'dict(blockHash=target["hash"], requireCanonical=False)',
        "test_all_issuer_reads_use_the_finalized_hash",
        "issuer canonical hash pin lost",
    ),
    (
        "fee-math",
        "settlement_issuer.py",
        'fee = min(amount * observation["fee_basis_points"] // 10000, int(observation["maximum_fee"]))',
        "fee = 0",
        "test_fee_preview_matches_actual_received_delta_and_cap",
        "issuer fee preview mismatch",
    ),
    (
        "fee-cap",
        "settlement_issuer.py",
        'fee = min(amount * observation["fee_basis_points"] // 10000, int(observation["maximum_fee"]))',
        'fee = amount * observation["fee_basis_points"] // 10000',
        "test_fee_preview_matches_actual_received_delta_and_cap",
        "issuer fee cap ignored",
    ),
    (
        "bridge-blacklist",
        "settlement_issuer.py",
        'not bridge_blocked, "redemption source bridge is blacklisted"',
        'True, "redemption source bridge is blacklisted"',
        "test_blacklisted_bridge_refuses_before_body",
    ),
    (
        "blacklist",
        "settlement_issuer.py",
        'not blacklisted, "redemption receiver is blacklisted"',
        'True, "redemption receiver is blacklisted"',
        "test_blacklisted_receiver_refuses_before_body",
    ),
    (
        "pause",
        "settlement_issuer.py",
        'not paused, "issuer token is paused"',
        'True, "issuer token is paused"',
        "test_paused_issuer_refuses_before_body",
    ),
    (
        "deprecated",
        "settlement_issuer.py",
        'not deprecated, "issuer token is deprecated"',
        'True, "issuer token is deprecated"',
        "test_deprecated_issuer_refuses_before_body",
    ),
    (
        "stale",
        "settlement_issuer.py",
        "-MAX_FUTURE_SKEW <= age <= MAX_FINALIZED_AGE",
        "True",
        "test_stale_finalized_read_refuses",
    ),
    (
        "code",
        "settlement_issuer.py",
        'source.code_hash(rpc, token, point) == binding["code_sha256"]',
        "True",
        "test_changed_issuer_code_refuses",
    ),
    (
        "chain",
        "settlement_issuer.py",
        'source.quantity(rpc.call("eth_chainId")) == binding["chain_id"]',
        "True",
        "test_wrong_source_chain_refuses",
    ),
    (
        "reorg",
        "settlement_issuer.py",
        'source.block(rpc, target["number"])["hash"] == target["hash"]',
        "True",
        "test_finalized_hash_change_refuses",
    ),
    (
        "failed-rpc",
        "collect-settlement-evm.py",
        'and "error" not in answer',
        "and True",
        "test_rpc_error_even_with_a_result_refuses",
    ),
)
CASES += (
    (
        "fee-ceil",
        "settlement_issuer.py",
        'amount * observation["fee_basis_points"] // 10000',
        '(amount * observation["fee_basis_points"] + 9999) // 10000',
        "test_nondivisible_fee_and_cap_boundaries_match_real_locks",
        "floor/cap preview differs",
    ),
    (
        "cap-one-low",
        "settlement_issuer.py",
        'int(observation["maximum_fee"])',
        'int(observation["maximum_fee"]) - 1',
        "test_nondivisible_fee_and_cap_boundaries_match_real_locks",
        "floor/cap preview differs",
    ),
    (
        "cap-one-high",
        "settlement_issuer.py",
        'int(observation["maximum_fee"])',
        'int(observation["maximum_fee"]) + 1',
        "test_nondivisible_fee_and_cap_boundaries_match_real_locks",
        "floor/cap preview differs",
    ),
    (
        "late-freshness",
        "settlement_issuer.py",
        "    fresh(target, now)\n    return dict(",
        "    return dict(",
        "test_issuer_read_rechecks_time_after_rpc",
    ),
    (
        "truncated-rpc",
        "prepare-token-redemption.py",
        "        http.client.HTTPException,\n",
        "",
        "test_truncated_rpc_cli_refuses_without_a_body",
        "IncompleteRead",
    ),
)
CASES += (
    (
        "truncated-details",
        "prepare-token-redemption.py",
        "detail = str(error) if isinstance(error, issuer.Invalid) else type(error).__name__",
        "detail = str(error)",
        "test_truncated_rpc_cli_refuses_without_a_body",
        "fixed refusal line changed",
    ),
)


def main():
    for name, filename, old, new, test, *markers in CASES:
        expected = markers[0] if markers else "DID NOT RAISE"
        original = (SCRIPTS / filename).read_text()
        if original.count(old) != 1:
            raise RuntimeError("non-unique mutation: " + name)
        changed = original.replace(old, new)
        ast.parse(changed)
        with tempfile.TemporaryDirectory(prefix="redemption-mutant-") as directory:
            root = Path(directory)
            for sibling in (
                "settlement_issuer.py",
                "prepare-token-redemption.py",
                "collect-settlement-evm.py",
                "check-settlement.py",
            ):
                shutil.copy2(SCRIPTS / sibling, root / sibling)
            (root / filename).write_text(changed)
            report = root / "result.xml"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "testnet/tests/anvil_redemption.py",
                    "-k",
                    test,
                    "--junitxml=" + str(report),
                ],
                cwd=ROOT,
                env={
                    **os.environ,
                    "T19_ISSUER_SOURCE": str(root / "settlement_issuer.py"),
                    "T19_REDEMPTION_SOURCE": str(root / "prepare-token-redemption.py"),
                },
                text=True,
                capture_output=True,
                timeout=180,
                check=False,
            )
            tree = ET.parse(report).getroot()
            cases = list(tree.iter("testcase"))
            failures = [c for c in cases if c.find("failure") is not None]
            if (
                result.returncode != 1
                or not failures
                or list(tree.iter("error"))
                or expected not in result.stdout
            ):
                raise RuntimeError(
                    "survivor or invalid control: " + name + "\n" + result.stdout + result.stderr
                )
        print("RED " + name + ": " + test, flush=True)
    print(f"REDEMPTION_MUTANTS_OK: {len(CASES)} assertion-red controls")


if __name__ == "__main__":
    main()
