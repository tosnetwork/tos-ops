"""Run fixed funding assertions with individual guards removed in a private copy."""

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
    ("duration", "now >= EARLIEST", "True", "test_wall_clock_cannot_replace_resource_bound"),
    (
        "actual24h",
        'resource["observed_seconds"] >= 86400',
        "True",
        "test_short_nonfinite_or_boolean_soak_refuses",
    ),
    (
        "history-verdict",
        'history["verdict"] == "PASS"',
        "True",
        "test_inconclusive_history_refuses",
    ),
    (
        "handover-count",
        'for row in history["handovers"]) >= 3',
        'for row in history["handovers"]) >= 0',
        "test_insufficient_windows_refuse",
    ),
    (
        "input-sha",
        "expected is None or hashlib.sha256(raw).hexdigest() == expected",
        "True",
        "test_report_digest_is_checked",
    ),
    (
        "budget",
        "spent == 0",
        "True",
        "test_any_existing_signed_or_terminal_funding_fences_new_funding",
    ),
    ("nonce", "seqno == expected", "True", "test_changed_nonce_refuses_before_signing"),
    ("sign-window", "time.time() < deadline", "True", "test_expired_window_refuses_before_signing"),
    (
        "custody-public",
        "bytes(nacl.signing.SigningKey(seed).verify_key) == public",
        "True",
        "test_wrong_custody_key_or_mode_refuses",
    ),
    (
        "native-address",
        'config["funding_wallet"] == "0:" + cell.hash.hex()',
        "True",
        "test_target_address_is_not_an_arbitrary_destination",
    ),
    (
        "broadcast-window",
        'writes == 0 and time.time() < window["valid_until_utc"]',
        "writes == 0",
        "test_window_expiring_after_signing_has_zero_broadcast",
    ),
    (
        "client-ack",
        'getattr(args, "acknowledge_client_2_tos", False) is True',
        "True",
        "test_missing_new_allocation_ack_refuses_before_keys",
    ),
    ("client-network", 'manifest["global_id"] == 2', "True", "test_client_network_refused"),
    (
        "client-key",
        "data.load_bytes(32) == public",
        "len(data.load_bytes(32)) == 32",
        "test_client_public_key_refused",
    ),
    (
        "client-address",
        'manifest["wallet_address"] == "0:" + cell.hash.hex()',
        "True",
        "test_client_address_refused",
    ),
    (
        "client-private-check",
        "        client_vault_identity(client, manifest, drv)",
        "        None",
        "test_client_private_check_calls_vault_identity",
    ),
    (
        "fixed-role-pair",
        "(operation, amount) in ((OP, AMOUNT), (CLIENT_OP, CLIENT_AMOUNT))",
        "True",
        "test_arbitrary_amount_and_role_pairs_refused",
    ),
    (
        "client-vault-key-name",
        "line.split()[0] == key_name",
        "True",
        "test_offline_key_name_binding_refuses",
    ),
    (
        "client-vault-wallet-address",
        """drv.Address(matches[0]["address"]).to_str(is_user_friendly=False)
        == manifest["wallet_address"]""",
        "True",
        "test_offline_wrong_carrier_address_refuses",
    ),
    (
        "client-wallet-version",
        'configured["version"] == "V3R2"',
        "True",
        "test_offline_wrong_configured_version_refuses_before_cli",
    ),
    (
        "resume-attestation",
        'receipt["trusted_operator_attestation"] is True',
        "True",
        "test_unreviewed_attestation_refuses",
    ),
    (
        "resume-plan",
        'original["plan"] == plan',
        "True",
        "test_old_plan_cannot_change_destination_or_nonce",
    ),
    (
        "resume-log",
        'log.count("Traceback (most recent call last):") == 1\n        and frame in log\n        and log.rstrip().endswith(\n            "con01_history.certificate.Refused: window expired before signing"\n        )\n        and "COMPLETE client fund" not in log',
        "True",
        "test_wrong_guard_failure_is_not_an_unsent_attestation",
    ),
    (
        "resume-source-nonce",
        'all(\n            type(row.get("seqno")) is int and row["seqno"] != plan["seqno"]\n            for row in prior\n        )',
        "True",
        "test_old_nonce_conflict_in_other_operation_refuses",
    ),
    (
        "resume-signing-fence",
        'not (\n            marker.parent / "br1-public-client-presign-resume-v1.signing-started.json"\n        ).exists()',
        "True",
        "test_started_signature_is_irrevocable_fence",
    ),
    (
        "resume-dry-nosign",
        'dry_run=args.mode in {"dry-run", "resume-dry-run"}',
        'dry_run=args.mode == "dry-run"',
        "test_resume_dry_never_signs_or_consumes_original_marker",
    ),
    (
        "resume-before-crypto",
        "                    before_sign()",
        "                    pass",
        "test_signing_fence_exists_before_underlying_crypto",
    ),
    (
        "resume-post-fsync-deadline",
        "deadline > time.time()",
        "True",
        "test_slow_signing_fence_expiry_never_calls_crypto",
    ),
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
            root / "testnet/acceptance/con01_history",
            private / "testnet/acceptance/con01_history",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        target = private / "testnet/acceptance/br1_fund.py"
        shutil.copyfile(root / "testnet/acceptance/br1_fund.py", target)
        tests = private / "testnet/tests"
        tests.mkdir(parents=True)
        shutil.copyfile(root / "testnet/tests/test_br1_fund.py", tests / "test_br1_fund.py")
        shutil.copyfile(
            root / "testnet/tests/test_br1_fund_resume.py", tests / "test_br1_fund_resume.py"
        )
        shutil.copytree(root / "testnet/tests/data/br1-fund", tests / "data/br1-fund")
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
                "test_br1_fund*.py",
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
            elif result.returncode != 0 or b"Ran 68 tests" not in raw or b"\nOK\n" not in raw:
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
        root / "testnet/acceptance/br1_fund.py",
        root / "testnet/tests/test_br1_fund.py",
        root / "testnet/tests/test_br1_fund_resume.py",
        Path(__file__),
    ]
    paths += list((root / "testnet/acceptance/con01_history").glob("*.py"))
    paths += list((root / "testnet/tests/data/br1-fund").glob("*"))
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
