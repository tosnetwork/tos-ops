"""Disposable fee-alert guard removals; never query or send to a real chain."""

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
    ("election_fees.py", row["before"], row["after"], row["test"])
    for row in json.loads(Path(__file__).with_name("election-fee-controls.json").read_bytes())[
        "mutations"
    ]
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
                ROOT / "testnet/tests/test_election_fee_watch.py",
                tests / "test_election_fee_watch.py",
            )
            shutil.copytree(ROOT / "testnet/tests/data/con01-history", tests / "data/con01-history")
            result = subprocess.run(
                [
                    sys.executable,
                    str(tests / "test_election_fee_watch.py"),
                    "FeeWatch." + name,
                    "-v",
                ],
                capture_output=True,
                timeout=30,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            )
            output = (result.stdout + result.stderr).decode(errors="replace")
            detected = (
                result.returncode == 1
                and any(x in output for x in ("FAIL: " + name, "ERROR: " + name))
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
