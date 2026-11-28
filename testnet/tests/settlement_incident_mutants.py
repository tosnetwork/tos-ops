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
# Refusal guards, label: (guard text, replacement); the label is also the id of
# that refusal's own test, which must fail with one of REFUSED.
GUARDS = {
    "reason-empty": ("value == value.strip() and value, ", "True, "),
    "reason-control": ("require(value.isprintable(),", "require(True,"),
    "not-private": ("\n            and not state.st_mode & 0o077", ""),
    "record-exists": ("not record.exists() and not record.is_symlink()", "True"),
    "record-in-state": ("a.state_dir.resolve() not in (parent, *parent.parents)", "True"),
    "record-dir-missing": ("record.parent.is_dir() and os.access(record.parent, os.W_OK)", "True"),
    "record-dir-unwritable": (
        "record.parent.is_dir() and os.access(record.parent, os.W_OK)",
        "True",
    ),
    "record-race": ("os.O_CREAT | os.O_EXCL", "os.O_CREAT | os.O_TRUNC"),
    "lock-held": (
        "            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)",
        "            pass",
    ),
    "absent": ("require(incident in incidents,", "require(True,"),
    "incidents-not-object": ("require(isinstance(incidents, dict),", "require(True,"),
    "key-mismatch": ('require(incident == asset + ":" + code,', "require(True,"),
    "not-emergency": ("require(code in monitor.EMERGENCIES,", "require(True,"),
    "report-missing": ("require(report_path.is_file(),", "require(True,"),
    "report-schema": (
        'require(report.get("schema") == "tos-settlement-report/1",',
        "require(True,",
    ),
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
REFUSED = ("refusal did not refuse", "wrong refusal")
RECORD_CALL = "    create_record(record_path, encode(record))\n"
READ_BACK = "    current = current_hash(incidents_path)\n    if current != after:"
# Ordering and failure-path controls: label: (edits, test, expected assertion text).
FAULTS = {
    # The record is written after the replace, as before the fix.
    "record-after-replace": (
        [(RECORD_CALL, ""), (READ_BACK, RECORD_CALL + READ_BACK)],
        "test_a_failed_record_write_changes_nothing",
        ("incident removed first",),
    ),
    "partial-record-kept": (
        [("            os.unlink(path)\n", "            pass\n")],
        "test_a_failed_record_write_changes_nothing",
        ("partial record left behind",),
    ),
    "record-not-withdrawn": (
        [("                os.unlink(record_path)\n", "                pass\n")],
        "test_a_replace_that_fails_before_replacing_withdraws_the_record",
        ("record of an unapplied resolution was kept",),
    ),
    "partial-reported-refused": (
        [("        if current == before:", "        if True:")],
        "test_a_failure_after_the_replace_is_partial_not_refused",
        ("a change was reported as refused",),
    ),
    "read-back-unchecked": (
        [("    if current != after:", "    if False:")],
        "test_a_replace_that_does_not_read_back_is_partial",
        ("== 3",),
    ),
}
CASES = {
    **{k: ([v], REFUSAL.format(k), REFUSED) for k, v in GUARDS.items()},
    **{k: (edits, TEST + "::" + test, text) for k, (edits, test, text) in FAULTS.items()},
}


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
    for label, (edits, test, expected) in CASES.items():
        changed = original
        for before, after in edits:
            if changed.count(before) != 1:
                raise RuntimeError("non-unique anchor: " + label)
            changed = changed.replace(before, after)
        ast.parse(changed)
        log = args.log_dir / (label + ".log")
        code, tree = run(changed, [test], log)
        failures = [t for t in tree.iter("testcase") if t.find("failure") is not None]
        text = log.read_text()
        if (
            code != 1
            or len(failures) != 1
            or list(tree.iter("error"))
            or not any(e in text for e in expected)
        ):
            raise RuntimeError("survived or invalid: " + label)
        print(label + ": assertion-red", flush=True)
    print(f"{len(CASES)}/{len(CASES)} assertion-red")


if __name__ == "__main__":
    main()
