"""Disposable guard-removal controls. Requires the same real OpenSSL backend as tests."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MUTATIONS = [
    (
        "certificate.py",
        'fcntl.fcntl(copied, getattr(fcntl, "F_ADD_SEALS", 1033), 0x000F)',
        "pass  # mutant: omit executable sealing",
        "a_python_without_os_memfd_still_uses_a_sealed_executable",
    ),
    (
        "certificate.py",
        "    timing = (",
        '    require(v["since"] <= header["gen_utime"] <= v["until"], "term outside validity interval")\n    timing = (',
        "real_expired_schedule_certificate_has_valid_finality",
    ),
    (
        "certificate.py",
        '        verify_signature(member["pk"], f.D(sig["signature"]), message)',
        "        pass  # mutant: omit signature verification",
        "corrupted_real_signature_is_rejected",
    ),
    (
        "certificate.py",
        '    require(3 * weight > 2 * v["weight"], "insufficient quorum")',
        "    pass  # mutant: omit quorum",
        "quorum_is_not_inferred_from_validator_membership",
    ),
    (
        "certificate.py",
        '        require(vid not in seen, "duplicate signer")',
        "        pass  # mutant: omit uniqueness",
        "duplicate_signer_cannot_increase_weight",
    ),
    (
        "certificate.py",
        '        require(sig["algorithm_id"] == 1, "unsupported signature algorithm")',
        "        pass  # mutant: omit algorithm",
        "unknown_algorithm_is_not_accepted_as_mldsa",
    ),
    (
        "certificate.py",
        'f.D(cert["session_id"]) == f.session(params, v, header)',
        "True",
        "wrong_session_is_rejected_before_signature_backend",
    ),
    (
        "certificate.py",
        'link["config"].hash() == f.D(source["root_hash"])',
        "True",
        "source_root_must_match_authenticated_config",
    ),
    (
        "certificate.py",
        "identity(start) == identity(anchor)",
        "identity(start)[:3] == identity(anchor)[:3]",
        "trusted_full_anchor_includes_file_hash",
    ),
    (
        "certificate.py",
        'identity(link["src"]) == identity(expected_source)',
        "True",
        "retired_key_is_not_selected_after_authenticated_rollover",
    ),
    (
        "audit.py",
        '    require(packet["complete"], "last proof packet is incomplete")',
        "    pass  # mutant: accept truncated chain",
        "real_partial_genesis_packet_is_not_a_complete_target_proof",
    ),
    (
        "certificate.py",
        "0 < len(raw) <= 2 * 1024 * 1024",
        "len(raw) > 0",
        "packet_byte_limit_precedes_decoder",
    ),
    (
        "formats.py",
        "0 < count <= 65536",
        "0 < count",
        "oversized_cell_count_precedes_boc_allocation",
    ),
    (
        "formats.py",
        "if not __debug__:",
        "if False:",
        "optimized_python_refuses_assert_based_wire_decoder",
    ),
    (
        "certificate.py",
        "hashlib.sha256(raw).hexdigest() == digest",
        "True",
        "wrong_verifier_pin_fails_before_crypto",
    ),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    rows = []
    for filename, before, after, name in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="con01-control-") as temp:
            root = Path(temp)
            shutil.copytree(
                ROOT / "testnet/acceptance/con01_history",
                root / "testnet/acceptance/con01_history",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            target = root / "testnet/acceptance/con01_history" / filename
            text = target.read_text()
            if text.count(before) != 1:
                raise RuntimeError(f"mutation does not identify exactly one guard: {name}")
            target.write_text(text.replace(before, after))
            tests = root / "testnet/tests"
            tests.mkdir(parents=True)
            shutil.copyfile(
                ROOT / "testnet/tests/test_con01_history.py", tests / "test_con01_history.py"
            )
            shutil.copytree(ROOT / "testnet/tests/data/con01-history", tests / "data/con01-history")
            result = subprocess.run(
                [
                    sys.executable,
                    str(tests / "test_con01_history.py"),
                    "Certificates.test_" + name,
                    "-v",
                ],
                capture_output=True,
                timeout=30,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            )
            output = (result.stdout + result.stderr).decode(errors="replace")
            detected = (
                result.returncode == 1
                and any(x in output for x in ("FAIL: test_" + name, "ERROR: test_" + name))
                and "setUpClass" not in output
            )
            excerpt = "\n".join(output.splitlines()[-28:]) + "\n"
            (args.out / (name + ".txt")).write_text(excerpt)
            rows.append(
                dict(
                    test=name,
                    detected=detected,
                    returncode=result.returncode,
                    excerpt_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
                )
            )
    report = dict(status="PASS" if all(x["detected"] for x in rows) else "FAIL", controls=rows)
    (args.out / "REPORT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
