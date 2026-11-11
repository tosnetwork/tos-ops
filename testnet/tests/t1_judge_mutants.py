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
    ("R1 record hash", "if hashlib.sha256(path.read_bytes()).hexdigest() != sha:", "if False:"),
    ("R2 thresholds required", "if not finite(judge.get(key)) or judge[key] <= 0:", "if False:"),
    ("R3 operators pinned", 'raise Refuse("acceptance record judge.operators must list every pinned operator")', "pass"),
    ("T1 torn tail only", "            if i == len(lines) - 1:\n                continue\n            raise", "            continue"),
    ("G1 stall limit", 'if gap > j["max_chain_gap_s"]:', "if False:"),
    ("G2 progress is a new maximum", 'if r["id"][2] > top:', "if True:"),
    ("G3 head series continuous", 'if any(g > j["head_series_gap_s"] for g in worst_series.values()):', "if False:"),
    ("B1 every boundary checked", 'if r is None or r["outcome"] in ("missed", "interrupted"):', "if r is None:"),
    ("B2 the key gate passed", 'and r.get("keys_exit") == 0', ""),
    ("S1 resource series complete", 'if max_gap([r["ts"] for r in complete], t0, t1) > j["resource_series_gap_s"]:', "if False:"),
    ("S2 identity constant", "if len(ids) > 1 or inactive:", "if inactive:"),
    ("S3 divergence", 'if changed or longest > j["divergence_s"]:', "if changed:"),
    ("S4 agreement recomputed", "agree = len(full) == len(HOSTS) and len(set(full)) == 1", 'agree = r.get("agree") is True'),
    ("S5 ids coverage", 'if max_gap(agreed, t0, t1) > j["ids_series_gap_s"]:', "if False:"),
    ("M1 absolute RSS", 'if max(rss) > j["rss_anon_max_bytes"]:', "if False:"),
    ("M2 growth", 'if e2e > j["rss_growth_e2e_bytes"] or rolling > j["rss_growth_rolling_bytes"]:', "if False:"),
    ("M3 phase coverage", "if len(terms) < 2 or missing:", "if len(terms) < 2:"),
    ("M4 phases, not terms", "e2e = max(med[(terms[-1], p)] - med[(terms[0], p)] for p in range(phases))", "e2e = 0"),
    ("D1 disk floor", 'if min(d["free_bytes"] for d in series) < j["disk_free_floor_bytes"] or \\', 'if False and min(d["free_bytes"] for d in series) < j["disk_free_floor_bytes"] or \\'),
    ("D2 per-block bound", 'if rate > j["disk_bytes_per_block_max"]:', "if False:"),
    ("F1 safety line", "    if hits:\n        return result(FAIL", "    if False:\n        return result(FAIL"),
    ("F2 coverage gap", "    if gaps or uncovered:", "    if uncovered:"),
    ("F3 positive coverage", "    if gaps or uncovered:", "    if gaps:"),
    ("C1 clock coverage", 'if any(max_gap(ts, t0, t1) > j["clock_series_gap_s"] for ts in ok.values()):', "if False:"),
    ("Q1 packet matches the record", ") != \\\n            (DURATION, width, READ_RATE) or not finite(started):", ") != (DURATION, width, READ_RATE) and False:"),
    ("Q2 completed fraction", 'if (w["ok"] < j["read_completed_fraction"] * scheduled', "if (False"),
    ("Q3 coverage", 'or len(w["endpoints"]) < READ_ENDPOINTS or not set(READ_METHODS) <= w["methods"]):', "):"),
    ("Q4 final status", "    if lag is None or lag or bad_rows or foreign:", "    if lag or bad_rows or foreign:"),
    ("W1 transfers only", 'if a.get("role") == "transfer"}', "}"),
    ("W2 receipt failure", 'if "receipt_failure" not in d or d["receipt_failure"] is not None:', "if False:"),
    ("W3 action index", "if type(i) is not int or not 0 <= i < n:", "if type(i) is not int:"),
    ("W4 recipient tx", "if not (isinstance(d.get(\"recipient_tx\"), str) and d[\"recipient_tx\"]) or not finite(d.get(\"recipient_utime\")):", "if not finite(d.get(\"recipient_utime\")):"),
    ("W5 hourly floor", "    if short or late_start", "    if late_start"),
    ("W6 schedule window", 'w0, w1 = t0 + j["write_start_max_s"], t1 - j["write_end_slack_s"]', "w0, w1 = min(signed), max(signed)"),
    ("W7 backlog", 'or peak > j["backlog_max_actions"]', ""),
    ("W8 unresolved", "            or unresolved or conflicts:", "            or conflicts:"),
    ("W9 conflicts", "            or unresolved or conflicts:", "            or unresolved:"),
    ("W10 late start", "    if short or late_start or early_end", "    if short or early_end"),
    ("O1 operator floor", "    if low:\n        return result(FAIL", "    if False:\n        return result(FAIL"),
    ("O2 every operator covered", "    if thin:", "    if False:"),
    ("V1 stops fail", "    if stops:\n        return result(FAIL", "    if False:\n        return result(FAIL"),
    ("V2 a clean end", 'if len(end) != 1 or end[0].get("result") != "cutoff" or kinds[-1] != "end":', 'if len(end) != 1:'),
    ("V3 termination confirmed", 'c.get("group_alive") is not False for c in term[0]["children"].values()):', "False for c in term[0][\"children\"].values()):"),
    ("V4 full duration", 'or cutoff[0]["ts"] < t1 - 60:', ":"),
    ("W11 early end", "    if short or late_start or early_end", "    if short or late_start"),
    ("F4 log lag bound", "return all(type(b) is int and 0 <= b <= LOG_LAG_BYTES for b in behind)", "return True"),
    ("F5 active log read", "    if not any(e.get(\"name\") == ACTIVE_LOG for e in read):\n        return False",
     "    if False:\n        return False"),
    ("F6 read rule applied", ' and log_read_covers(r.get("files"))] for h in HOSTS}', "] for h in HOSTS}"),
    ("W12 observed fields", 'if type(o.get("fee")) is not int or o["fee"] < 0 or "failure" not in o:',
     'if "failure" not in o:'),
    ("W13 malformed is inconclusive", "    if malformed:\n        return result(INCONCLUSIVE",
     "    if False:\n        return result(INCONCLUSIVE"),
    ("W14 receipt after execution", 'if not o["utime"] <= d["recipient_utime"] <= t1:',
     'if not d["recipient_utime"] <= t1:'),
    ("W15 receipt before the cutoff", 'if not o["utime"] <= d["recipient_utime"] <= t1:',
     'if not o["utime"] <= d["recipient_utime"]:'),
    ("W16 signing time required", 'malformed = [aid for aid, a in transfers.items() if not finite(a.get("signed_at"))]',
     "malformed = []"),
    ("Q5 foreign endpoint rows", '            if r.get("endpoint") not in T1_READ_ENDPOINTS:\n                foreign += 1\n'
     "                continue\n", ""),
    ("Q6 packet endpoints pinned", 'if sorted(packet.get("endpoints") or []) != sorted(T1_READ_ENDPOINTS):',
     "if False:"),
    ("V6 both children", 'or sorted(term[0]["children"]) != sorted(CHILDREN) or any(', "or any("),
    ("V7 lifecycle order", 'if order != ["start", "ramp_done", "cutoff", "terminated", "end"] or not all(',
     "if not all("),
    ("V8 lifecycle times", "or any(b < a for a, b in zip(times, times[1:])):", ":"),
    ("V5 FAIL dominates", "overall = FAIL if FAIL in statuses else INCONCLUSIVE if INCONCLUSIVE in statuses else PASS", "overall = INCONCLUSIVE if INCONCLUSIVE in statuses else FAIL if FAIL in statuses else PASS"),
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
