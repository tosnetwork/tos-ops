#!/usr/bin/env python3
"""Mutation guards for t1-judge.py: each mutant weakens one criterion; test_t1_judge.py must go red.

    python testnet/tests/t1_judge_mutants.py

Not collected by pytest. Commit first: it rewrites the script in place and restores it from memory.
"""

import ast
import re
import subprocess
import sys
from pathlib import Path

W = Path(__file__).resolve().parents[1]
JUDGE = W / "scripts/t1-judge.py"
TEST = W / "tests/test_t1_judge.py"
FAILED = re.compile(r"\b[1-9]\d* failed\b")

MUTANTS = [
    ("R1 record hash", 'if hashlib.sha256(path.read_bytes()).hexdigest() != sha:', "if False:"),
    ("R2 thresholds required", 'if not finite(judge.get(key)) or judge[key] <= 0:', "if False:"),
    ("T1 torn tail only", "            if i == len(lines) - 1:\n                continue\n            raise", "            continue"),
    ("G1 stall limit", 'if gap > j["max_chain_gap_s"]:', "if False:"),
    ("G2 progress is a new maximum", 'if r["id"][2] > top:', "if True:"),
    ("B1 every boundary checked", 'if r is None or r["outcome"] in ("missed", "interrupted"):', "if r is None:"),
    ("B2 the key gate passed", 'and r.get("keys_exit") == 0', ""),
    ("B3 failed boundaries fail", "    if bad:\n        return result(FAIL, failed=bad, expected=len(expected))", "    if False:\n        return result(FAIL, failed=bad, expected=len(expected))"),
    ("S1 resource series complete", 'if max_gap([r["ts"] for r in complete], t0, t1) > j["resource_series_gap_s"]:', "if False:"),
    ("S2 identity constant", "if len(ids) > 1 or inactive:", "if inactive:"),
    ("S3 divergence", 'if changed or longest > j["divergence_s"]:', "if changed:"),
    ("M1 absolute RSS", 'if max(rss) > j["rss_anon_max_bytes"]:', "if False:"),
    ("M2 growth", 'if e2e > j["rss_growth_e2e_bytes"] or rolling > j["rss_growth_rolling_bytes"]:', "if False:"),
    ("D1 disk floor", 'if min(d["free_bytes"] for d in series) < j["disk_free_floor_bytes"] or \\', 'if False and min(d["free_bytes"] for d in series) < j["disk_free_floor_bytes"] or \\'),
    ("D2 per-block bound", 'if rate > j["disk_bytes_per_block_max"]:', "if False:"),
    ("F1 safety line", "    if hits:\n        return result(FAIL", "    if False:\n        return result(FAIL"),
    ("F2 coverage gap", "    if gaps:\n        return result(INCONCLUSIVE, coverage_gaps", "    if False:\n        return result(INCONCLUSIVE, coverage_gaps"),
    ("Q1 failed read window", "    if failed:\n        return result(FAIL, failed_windows", "    if False:\n        return result(FAIL, failed_windows"),
    ("W1 transfers only", 'if a.get("role") == "transfer"}', "}"),
    ("W2 bounce not delivered", 'if a is None or d.get("receipt_failure") is not None', "if a is None"),
    ("W3 hourly floor", "if short or fees > j[\"max_cost_nano\"]:", "if fees > j[\"max_cost_nano\"]:"),
    ("W4 hours of the signing window", "hours = int((last - first) // 3600)", "hours = int((t1 - first) // 3600)"),
    ("W5 unresolved", "    if undelivered:\n        return result(FAIL", "    if False:\n        return result(FAIL"),
    ("O1 operator floor", "    if low:\n        return result(FAIL", "    if False:\n        return result(FAIL"),
    ("V1 stops fail", '    if run["stops"]:\n', "    if False:\n"),
    ("V2 a clean end", 'elif run["end"] is None or not run["ramp_done"]:', "elif False:"),
    ("V3 FAIL dominates", "overall = FAIL if FAIL in statuses else INCONCLUSIVE if INCONCLUSIVE in statuses else PASS", "overall = INCONCLUSIVE if INCONCLUSIVE in statuses else FAIL if FAIL in statuses else PASS"),
]


def suite() -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", str(TEST)],
                       cwd=W / "tests", capture_output=True, text=True, timeout=900)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    original = JUDGE.read_text()
    labels = [m[0] for m in MUTANTS]
    assert len(set(labels)) == len(labels), "duplicate mutant label"
    rc, out = suite()
    if rc != 0:
        print("unmutated suite is not green:\n" + out[-2000:])
        return 1
    killed, problems = 0, []
    try:
        for label, old, new in MUTANTS:
            if original.count(old) != 1:
                problems.append(f"{label}: pattern occurs {original.count(old)} times")
                continue
            mutated = original.replace(old, new, 1)
            try:
                ast.parse(mutated)
            except SyntaxError as exc:
                problems.append(f"{label}: does not compile: {exc}")
                continue
            JUDGE.write_text(mutated)
            rc, out = suite()
            JUDGE.write_text(original)
            if rc == 1 and FAILED.search(out):
                killed += 1
                print(f"killed   {label}")
            else:
                problems.append(f"{label}: SURVIVED (pytest rc {rc})")
                print(f"SURVIVED {label}")
    finally:
        JUDGE.write_text(original)
    print(f"{killed}/{len(MUTANTS)} mutants killed")
    for p in problems:
        print("problem:", p)
    return 0 if killed == len(MUTANTS) and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
