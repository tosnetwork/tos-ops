#!/usr/bin/env python3
"""Mutation guards for t1-sweep.py: each mutant weakens one safety rule; test_t1_sweep.py and
test_t1_sweep_emulator.py must go red.

    T1_SWEEP_EMULATOR=/path/to/libemulator.so python testnet/tests/t1_sweep_mutants.py [--jobs N]

Not collected by pytest. Each mutant runs in its own temporary copy of testnet/ (the working tree is never
touched). Refuses to run without the emulator, so that every mutant faces the real-execution tests too.
"""

import argparse
import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

W = Path(__file__).resolve().parents[1]
TARGET = "scripts/t1-sweep.py"
TESTS = ("tests/test_t1_sweep.py", "tests/test_t1_sweep_emulator.py")
FAILED = re.compile(r"\b[1-9]\d* failed\b")

MUTANTS = [
    ("S1 mode 130", "SEND_ALL = 130", "SEND_ALL = 128"),
    ("S2 journal before send", "    journal.append(record)  # fsynced before the send starts\n    try:\n        await chain.send(external)\n",
     "    try:\n        await chain.send(external)\n        journal.append(record)\n"),
    ("S3 a refused send stops", "    if state == \"refused\":\n        raise Stop(", "    if False:\n        raise Stop("),
    ("S4 only a settled sweep counts", '    if sent.state != "settled":\n        raise Stop(',
     '    if sent.state == "refused":\n        raise Stop('),
    ("S5 one message to the destination", "    if len(out) != 1 or out[0].destination != dest:", "    if not out:"),
    ("S6 not bounced, carries value", "    if msg.bounced or msg.value is None or msg.value <= 0:", "    if False:"),
    ("S7 fees reported", "    if fee is None:\n        problems.append", "    if False:\n        problems.append"),
    ("S8 accounting equation", "        if not 0 <= residual <= FWD_TOLERANCE_NANO:", "        if False:"),
    ("S9 the wallet emptied", "    if any(b != 0 for b in after):", "    if False:"),
    ("S10 recipient on every RPC", "        if len(found) != 1:\n            problems.append",
     "        if not found:\n            continue\n        if False:\n            problems.append"),
    ("S11 recipient credited as sent",
     "        if t.aborted or t.phase_failure is not None or t.in_msg.bounced or t.in_msg.value != msg.value \\\n"
     "                or t.account != dest:", "        if t.in_msg.value != msg.value:"),
    ("S12 recipient value", "or t.in_msg.bounced or t.in_msg.value != msg.value \\", "or t.in_msg.bounced \\"),
    ("S13 network pinned", "                (zero[\"root_hash\"], zero[\"file_hash\"], 0) or r[\"global_id\"] != GLOBAL_ID:",
     "                (zero[\"root_hash\"], zero[\"file_hash\"], 0) and False:"),
    ("S14 global id pinned", " or r[\"global_id\"] != GLOBAL_ID:", ":"),
    ("S15 RPCs agree", "        if {k: a.get(k) for k in keys} != first:", "        if False:"),
    ("S16 version, retired, epoch", "    if q[\"version\"] != 1 or q[\"retired\"] != 0 or q[\"epoch\"] != 0:", "    if False:"),
    ("S17 authority", "    if q[\"authority\"] != wallet.authority.hash.hex():", "    if False:"),
    ("S18 code hash", "    if live_code != code_hash:", "    if False:"),
    ("S19 source is not the destination", "    if dest in sources or dest == \"\":", "    if dest == \"\":"),
    ("S20 destination active", "    if d.get(\"state\") != \"active\":", "    if False:"),
    ("S21 skip below the fee bound", "        if st[\"balance\"] <= bound + MIN_LEFT_NANO:", "        if False:"),
    ("S22 dry run by default", "    if not a.go:", "    if False:"),
    ("S23 stop at the first inexact sweep", "            return 1\n        log(json.dumps", "            continue\n        log(json.dumps"),
    ("S25 unproved receipts block a run", "    if pending:\n        raise Refuse(", "    if False:\n        raise Refuse("),
    ("S26 an unprovable receipt stays pending", "            if proof[\"problems\"]:\n                pending.append(f\"{aid}: {proof['problems']}\")",
     "            if False:\n                pending.append(f\"{aid}: {proof['problems']}\")"),
    ("S27 problems at the sender are never counted", "            if obs.get(\"problems\") or obs.get(\"duplicates\"):",
     "            if obs.get(\"duplicates\"):"),
    ("S31 a second execution is never counted", "            if obs.get(\"problems\") or obs.get(\"duplicates\"):",
     "            if obs.get(\"problems\"):"),
    ("S32 an execution found by the reconcile needs its receipt", "    return resolution\n", "    return None\n"),
    ("S33 an undetermined sweep is never assumed unexecuted",
     "    if resolution is None or resolution.get(\"verdict\") == \"undetermined\":\n        return \"its",
     "    if resolution is None or resolution.get(\"verdict\") == \"undetermined\":\n        return None and \"its"),
    ("S34 a proven non-execution needs no receipt",
     "    if resolution.get(\"verdict\") == \"not_executed\":\n        return None",
     "    if resolution.get(\"verdict\") == \"not_executed\":\n        return \"x\""),
    ("S28 a proved sweep is not proved again", "            if attempt.get(\"role\") != \"sweep\" or \"delivered\" in kinds:",
     "            if attempt.get(\"role\") != \"sweep\":"),
    ("S29 run record readable by the ramp", '"to": dest, "mc_start": mc_start,', '"to": dest,'),
    ("S30 no made-up masterchain block", '"recipient_mc": None,', '"recipient_mc": 0,'),
    ("S24 delivery recorded", "    journal.event(\"delivered\", record[\"id\"],", "    (lambda *a, **k: None)(\"delivered\", record[\"id\"],"),
]


def suite(root: Path, fail_fast: bool) -> tuple[int, str]:
    args = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"] + (["-x"] if fail_fast else [])
    p = subprocess.run(args + [str(root / t) for t in TESTS], cwd=root / "tests", capture_output=True, text=True,
                       timeout=900)
    return p.returncode, p.stdout + p.stderr


def one(m):
    label, old, new = m
    with tempfile.TemporaryDirectory(prefix="t1-sweep-mutant-") as tmp:
        root = Path(tmp) / "testnet"
        shutil.copytree(W, root, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
        path = root / TARGET
        path.write_text(path.read_text().replace(old, new, 1))
        rc, out = suite(root, fail_fast=True)
    return ("killed" if rc == 1 and FAILED.search(out) else f"SURVIVED (pytest rc {rc})"), label


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=12)
    a = ap.parse_args()
    if not os.environ.get("T1_SWEEP_EMULATOR"):
        print("set T1_SWEEP_EMULATOR: every mutant must face the real-execution tests")
        return 2
    labels = [x[0] for x in MUTANTS]
    assert len(set(labels)) == len(labels), "duplicate mutant label"
    src = (W / TARGET).read_text()
    problems = []
    for label, old, new in MUTANTS:
        if src.count(old) != 1:
            problems.append(f"{label}: pattern occurs {src.count(old)} times")
            continue
        try:
            ast.parse(src.replace(old, new, 1))
        except SyntaxError as exc:
            problems.append(f"{label}: does not compile: {exc}")
    if problems:
        print("\n".join(problems))
        return 1
    rc, out = suite(W, fail_fast=False)
    if rc != 0 or "skipped" in out.splitlines()[-1]:
        print("unmutated suite is not green, or skipped tests:\n" + out[-2000:])
        return 1
    killed = 0
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:
        for verdict, label in pool.map(one, MUTANTS):
            print(f"{verdict:8} {label}", flush=True)
            killed += verdict == "killed"
            if verdict != "killed":
                problems.append(f"{label}: {verdict}")
    print(f"{killed}/{len(MUTANTS)} mutants killed")
    for p in problems:
        print("problem:", p)
    return 0 if killed == len(MUTANTS) and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
