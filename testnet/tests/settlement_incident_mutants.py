#!/usr/bin/env python3
"""Assertion-red controls for the incident resolution: each refusal guard is
removed in a disposable copy and its own refusal test must fail."""

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
SOURCE = ROOT / "testnet/scripts/resolve-settlement-incident.py"
TEST = "testnet/tests/test_resolve_settlement_incident.py"
REFUSAL = TEST + "::test_each_refusal_changes_nothing[{}]"
# label: (guard text, replacement); the label is also the refusal test's id.
CASES = {
    "reason-empty": ("value == value.strip() and value, ", "True, "),
    "reason-control": ("require(value.isprintable(),", "require(True,"),
    "not-private": ("\n            and not state.st_mode & 0o077", ""),
    "record-exists": ("not record.exists() and not record.is_symlink()", "True"),
    "record-in-state": ("a.state_dir.resolve() not in (parent, *parent.parents)", "True"),
    "lock-held": (
        "            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)",
        "            pass",
    ),
    "absent": ("require(incident in incidents,", "require(True,"),
    "key-mismatch": ('require(incident == asset + ":" + code,', "require(True,"),
    "not-emergency": ("require(code in monitor.EMERGENCIES,", "require(True,"),
    "stale": ('require("status" not in report,', "require(True,"),
    "baseline": ('require(report.get("baseline") is False,', "require(True,"),
    "inconsistent": (
        'require(report.get("latched_incidents") == sorted(incidents),',
        "require(True,",
    ),
    "too-old": ("stamp <= now + 5 and now - stamp <= max_age", "stamp <= now + 5"),
    "precedes": ('require(height > entry["checkpoint"]["height"],', "require(True,"),
    "still-alarmed": (
        'not any(a["asset"] == asset and a["code"] == code for a in alarms),',
        "True,",
    ),
}
EXPECTED = ("refusal did not refuse", "wrong refusal")


def run(source, selection, log):
    result_path = log.with_suffix(".xml")
    with tempfile.TemporaryDirectory(prefix="incident-mutant-") as directory:
        target = Path(directory) / SOURCE.name
        target.write_text(source)
        shutil.copy2(
            SOURCE.with_name("check-settlement.py"), target.with_name("check-settlement.py")
        )
        with log.open("w") as output:
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
                env={**os.environ, "TOS_SETTLEMENT_RESOLVE": str(target)},
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=120,
                check=False,
            )
    return result.returncode, ET.parse(result_path).getroot()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    original = SOURCE.read_text()
    code, tree = run(original, [TEST], args.log_dir / "baseline.log")
    cases = list(tree.iter("testcase"))
    if code or not cases or any(t.find("failure") is not None for t in cases):
        raise RuntimeError("invalid positive baseline")
    for label, (before, after) in CASES.items():
        if original.count(before) != 1:
            raise RuntimeError("non-unique anchor: " + label)
        changed = original.replace(before, after)
        ast.parse(changed)
        log = args.log_dir / (label + ".log")
        code, tree = run(changed, [REFUSAL.format(label)], log)
        failures = [t for t in tree.iter("testcase") if t.find("failure") is not None]
        text = log.read_text()
        if (
            code != 1
            or len(failures) != 1
            or list(tree.iter("error"))
            or not any(e in text for e in EXPECTED)
        ):
            raise RuntimeError("survived or invalid: " + label)
        print(label + ": assertion-red", flush=True)
    print(f"{len(CASES)}/{len(CASES)} assertion-red")


if __name__ == "__main__":
    main()
