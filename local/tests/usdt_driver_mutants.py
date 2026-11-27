#!/usr/bin/env python3
"""Assertion-red controls on disposable copies; never access a running network."""

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
DRIVER = "local/scripts/local-pq-usdt.py"
FIXTURE = "local/contracts/test-usdt/LocalUSDT.sol"
GOVERNANCE = "testnet/scripts/testnet-governance.py"
COLLECTOR = "testnet/scripts/collect-settlement-evm.py"
UNIT = "local/tests/test_local_pq_usdt.py"
ANVIL = "testnet/tests/anvil_settlement_observer.py"
CASES = [
    (
        "unsigned-recovery-excludes-prior-signatures",
        "local/scripts/local-pq-service-token.py",
        'and all(\n                record.get("state") == "done" for record in state.intents().values()\n            )',
        "and True",
        "local/tests/test_local_pq_service_token.py",
        "test_recover_without_finished_action_keeps_uncertain_steps_fenced",
        "DID NOT RAISE",
    ),
    (
        "unsigned-recovery-available",
        "local/scripts/local-pq-service-token.py",
        "and before == current",
        "and False",
        "local/tests/test_local_pq_service_token.py",
        "test_recover_unsigned_topup_does_not_block_a_new_step",
        "resume its original",
    ),
    (
        "unsigned-recovery-checks-intents",
        "local/scripts/local-pq-service-token.py",
        "and before == current",
        "and True",
        "local/tests/test_local_pq_service_token.py",
        "test_recover_without_finished_action_keeps_uncertain_steps_fenced",
        "DID NOT RAISE",
    ),
    (
        "unsigned-recovery-excludes-external-runners",
        "local/scripts/local-pq-service-token.py",
        'pending["label"].startswith(("topup-", "send-", "call-"))',
        "True",
        "local/tests/test_local_pq_service_token.py",
        "test_recover_without_finished_action_keeps_uncertain_steps_fenced",
        "DID NOT RAISE",
    ),
    (
        "monitor-namespace",
        DRIVER,
        'actual == expected and len(actual) == len(policy["assets"])',
        "True",
        UNIT,
        "test_monitor_gate_requires_this_namespace_not_just_freshness",
        "DID NOT RAISE",
    ),
    (
        "monitor-age",
        DRIVER,
        "-5 <= now - stamp <= 120",
        "True",
        UNIT,
        "test_governance_monitor_holds",
        "DID NOT RAISE",
    ),
    (
        "monitor-height",
        DRIVER,
        '0 <= height <= point["seqno"]',
        "True",
        UNIT,
        "test_governance_monitor_holds",
        "DID NOT RAISE",
    ),
    (
        "monitor-alarm",
        DRIVER,
        'not report["provider_pause_assets"] and not report["alarms"]',
        "True",
        UNIT,
        "test_governance_monitor_holds",
        "DID NOT RAISE",
    ),
    (
        "monitor-network",
        DRIVER,
        'policy["network"] == GENESIS["root"]',
        "True",
        UNIT,
        "test_governance_monitor_holds",
        "DID NOT RAISE",
    ),
    (
        "stack-order",
        DRIVER,
        'stack=list(reversed(v["stack"]))',
        'stack=v["stack"]',
        UNIT,
        "test_raw_rpc_stack_is_normalized_once_for_all_getters",
        "raw stack was not normalized",
    ),
    (
        "gov-per-send",
        GOVERNANCE,
        "        archive_governance_record(journal, urls, genesis, record)\n        return record",
        "        return record",
        UNIT,
        "test_each_governance_send_archives_before_return",
        "governance send returned before archival",
    ),
    (
        "gov-crash-recovery",
        GOVERNANCE,
        "    for record in records:\n        if legacy.get",
        "    for record in []:\n        if legacy.get",
        UNIT,
        "test_governance_archive_recovers_settled_record_before_next_action",
        "settled operation was skipped before next action",
    ),
    (
        "gov-raw-record",
        GOVERNANCE,
        "new.get(master) != payload",
        "False",
        UNIT,
        "test_governance_raw_preservation_refuses_a_changed_unselected_value",
        "DID NOT RAISE",
    ),
    (
        "reverted-source",
        DRIVER,
        'int(receipt["status"], 16) == 1',
        "True",
        UNIT,
        "test_reverted_source_is_archived_and_stops_the_next_send",
        "DID NOT RAISE",
    ),
    (
        "unfinalized-namespace",
        DRIVER,
        'state.get("namespace", {}).get("source_finalized") is True',
        "True",
        UNIT,
        "test_mint_requires_a_finalized_namespace_before_any_send",
        "unfinalized namespace reached source",
    ),
    (
        "preservation",
        DRIVER,
        "master in after and after[master] == payload",
        "True",
        UNIT,
        "test_existing_value_cannot_change",
        "DID NOT RAISE",
    ),
    (
        "archive-before-next",
        DRIVER,
        'super().put_intent(name, record)\n        if record.get("kind") == "evm" and record.get("state") == "done":\n            self.retain_source(name, record)',
        "super().put_intent(name, record)",
        UNIT,
        "test_source_archive_precedes_the_next_send",
        "evidence did not precede next send",
    ),
    (
        "nonce-identity",
        DRIVER,
        'and int(tx["nonce"], 16) == record["nonce"]',
        "and True",
        UNIT,
        "test_source_mismatch_never_counts_as_done_evidence",
        "DID NOT RAISE",
    ),
    (
        "build-provenance",
        DRIVER,
        'receipt["source_sha256"] == expected',
        "True",
        UNIT,
        "test_stale_build_log_cannot_authorize_deployment",
        "DID NOT RAISE",
    ),
    (
        "dry-run",
        DRIVER,
        'if not args.execute:\n        return {\n            "dry_run": True,\n            "sender": sender,',
        'if False:\n        return {\n            "dry_run": True,\n            "sender": sender,',
        UNIT,
        "test_namespace_dry_run_has_no_broadcast_or_record",
        "dry-run broadcast",
    ),
    (
        "blacklist-added-event",
        FIXTURE,
        "emit AddedBlackList(account);",
        "",
        ANVIL,
        "test_blacklist_events_and_destroy_deprecation_boundary",
        "blacklist event missing",
    ),
    (
        "blacklist-removed-event",
        FIXTURE,
        "emit RemovedBlackList(account);",
        "",
        ANVIL,
        "test_blacklist_events_and_destroy_deprecation_boundary",
        "blacklist event missing",
    ),
    (
        "destroy-deprecated",
        FIXTURE,
        'require(!deprecated, "destroy after deprecation is not a rehearsal");',
        "",
        ANVIL,
        "test_blacklist_events_and_destroy_deprecation_boundary",
        "DID NOT RAISE",
    ),
    (
        "blacklist-not-event-dependent",
        COLLECTOR,
        "read_bool(rpc, token, blacklist, point, bridge)",
        "False",
        ANVIL,
        "test_blacklist_without_an_event_is_still_detected",
        "silent blacklist not detected",
    ),
]


def run(root, selection, log):
    result_path = log.with_suffix(".xml")
    env = {
        **os.environ,
        "TOS_USDT_DRIVER": str(root / DRIVER),
        "TOS_USDT_FIXTURE": str(root / FIXTURE),
        "TOS_SETTLEMENT_COLLECTOR": str(root / COLLECTOR),
        "TOS_SERVICE_TOKEN_DRIVER": str(
            root / "local/scripts/local-pq-service-token.py"
        ),
    }
    with log.open("w") as stream:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "--tb=short",
                "--junitxml=" + str(result_path),
                *selection,
            ],
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
    code, report = run(
        ROOT,
        [UNIT, ANVIL, "local/tests/test_local_pq_service_token.py"],
        args.log_dir / "baseline.log",
    )
    if code or not list(report.iter("testcase")):
        raise RuntimeError("invalid positive baseline")
    for label, relative, before, after, file, test, expected in CASES:
        with tempfile.TemporaryDirectory(prefix="usdt-driver-control-") as temp:
            root = Path(temp)
            for folder in (
                "local/scripts",
                "testnet/scripts",
                "local/contracts/test-usdt",
            ):
                shutil.copytree(
                    ROOT / folder,
                    root / folder,
                    ignore=shutil.ignore_patterns("__pycache__"),
                )
            path = root / relative
            original = path.read_text()
            if original.count(before) != 1:
                raise RuntimeError("ambiguous mutation: " + label)
            changed = original.replace(before, after)
            if path.suffix == ".py":
                ast.parse(changed)
            path.write_text(changed)
            log = args.log_dir / (label + ".log")
            code, report = run(root, [file, "-k", test], log)
            failures = [
                c
                for c in report.iter("testcase")
                if test in c.attrib["name"] and c.find("failure") is not None
            ]
            if (
                code != 1
                or not failures
                or list(report.iter("error"))
                or expected not in log.read_text()
            ):
                raise RuntimeError("survived or invalid control: " + label)
        print(label + ": assertion-red", flush=True)
    print(str(len(CASES)) + "/" + str(len(CASES)) + " assertion-red")


if __name__ == "__main__":
    main()
