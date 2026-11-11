#!/usr/bin/env python3
"""Mutation guards for t1-judge.py and its evidence contract t1_evidence.py: each mutant weakens one rule;
test_t1_judge.py + test_t1_evidence.py must go red.

    python testnet/tests/t1_judge_mutants.py [--jobs N]

Not collected by pytest. Each mutant runs in its own temporary copy of testnet/ (the working tree is never
touched), with pytest -x, N at a time.
"""

import argparse
import ast
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

W = Path(__file__).resolve().parents[1]
TARGETS = {"judge": "scripts/t1-judge.py", "evidence": "scripts/t1_evidence.py"}
TESTS = ("tests/test_t1_judge.py", "tests/test_t1_evidence.py")
FAILED = re.compile(r"\b[1-9]\d* failed\b")

J, C = "judge", "evidence"
MUTANTS = [
    # the record
    (J, "R1 record hash", "if hashlib.sha256(path.read_bytes()).hexdigest() != sha:", "if False:"),
    (J, "R2 thresholds required", "if not finite(judge.get(key)) or judge[key] <= 0:", "if False:"),
    (J, "R3 operators pinned", 'raise Refuse("acceptance record judge.operators must list every pinned operator")',
     "pass"),
    (J, "R4 only a T1 run is judged", 'if s["mode"] != "t1" or s["cutoff_in_s"] != DURATION:', "if False:"),
    (J, "T1 torn tail only", "            if i == len(lines) - 1:\n                continue\n            raise",
     "            continue"),
    # the evidence contract
    (C, "K1 schemas applied", 'bad = [k for k, c in SCHEMAS[name].items() if k not in r or not c(r[k])]',
     "bad = []"),
    (C, "K2 unknown types refused",
     "        ev.violate(file, f\"{where}: unknown record type {r.get('kind', r.get('type', r.get('outcome')))!r}\")\n",
     ""),
    (J, "K3 violations cap a criterion", 'if c["status"] == PASS:\n                c["status"] = INCONCLUSIVE',
     'if False:\n                c["status"] = INCONCLUSIVE'),
    (C, "K4 required files", "            if required:\n                ev.missing.append(file)",
     "            if False:\n                ev.missing.append(file)"),
    (C, "K5 duplicate member names", "    if len(keys) != len(set(keys)):", "    if False:"),
    (C, "K6 torn interior line",
     "            if i == len(lines) - 1:\n                continue\n            ev.violate(file, f\"line {i + 1}: {exc}\")",
     "            continue"),
    (C, "K7 events need an attempt", '        elif t in ("sent", "delivered", "expired", "unknown"):\n'
     '            if r.get("id") not in roles:', '        elif t in ("sent", "delivered", "expired", "unknown"):\n'
     '            if False:'),
    (C, "K8 observed needs an attempt", 'role = roles.get(r.get("id"))\n            if role is None:',
     'role = roles.get(r.get("id"), "transfer")\n            if role is None:'),
    (C, "K9 only identical repeats collapse", "            if seen[key] == r:", "            if True:"),
    (C, "K10 receipt conflicts kept", "                ev.conflicts.append(key)", "                pass"),
    (C, "K11 distinct read offers", "        if off in offers:", "        if False:"),
    (C, "K12 read journal hash", 'if hashlib.sha256(data).hexdigest() != res["requests_sha256"]:', "if False:"),
    (C, "K13 read journal counts", 'if res["completed"] != len(rows) or', "if False and"),
    (C, "K14 observed schema by role",
     'name = f"journal/observed/{role}" if role in ("transfer", "funding") else None',
     'name = "journal/observed/transfer"'),
    (C, "K15 attempt roles", 'name = f"journal/attempt/{role}" if role in ("transfer", "funding") else None',
     'name = "journal/attempt/transfer"'),
    # §5.1
    (J, "G1 stall limit", 'if gap > j["max_chain_gap_s"]:', "if False:"),
    (J, "G2 progress is a new maximum", 'if r["id"][2] > top:', "if True:"),
    (J, "G3 head series continuous", 'if any(g > j["head_series_gap_s"] for g in worst_series.values()):',
     "if False:"),
    (J, "B1 every boundary checked", 'if r is None or r["outcome"] in ("missed", "interrupted"):', "if r is None:"),
    (J, "B2 the key gate passed", 'and r.get("keys_exit") == 0', ""),
    # §5.2
    (J, "S1 resource series complete", 'if max_gap([r["ts"] for r in rs], t0, t1) > j["resource_series_gap_s"]:',
     "if False:"),
    (J, "S2 identity constant", "if len(ids) > 1 or inactive:", "if inactive:"),
    (J, "S3 divergence", 'if changed or longest > j["divergence_s"]:', "if changed:"),
    (J, "S4 agreement recomputed", "agree = len(full) == len(HOSTS) and len(set(full)) == 1", 'agree = r["agree"]'),
    (J, "S5 ids coverage", 'if max_gap(agreed, t0, t1) > j["ids_series_gap_s"]:', "if False:"),
    # §5.3, §5.4
    (J, "M1 absolute RSS", 'if max(rss) > j["rss_anon_max_bytes"]:', "if False:"),
    (J, "M2 growth", 'if e2e > j["rss_growth_e2e_bytes"] or rolling > j["rss_growth_rolling_bytes"]:', "if False:"),
    (J, "M3 phase coverage", "if len(terms) < 2 or missing:", "if len(terms) < 2:"),
    (J, "M4 phases, not terms", "e2e = max(med[(terms[-1], p)] - med[(terms[0], p)] for p in range(phases))",
     "e2e = 0"),
    (J, "D1 disk floor", 'if min(d["free_bytes"] for d in series) < j["disk_free_floor_bytes"] or \\',
     'if False and min(d["free_bytes"] for d in series) < j["disk_free_floor_bytes"] or \\'),
    (J, "D2 per-block bound", 'if rate > j["disk_bytes_per_block_max"]:', "if False:"),
    # §5.5, clock
    (J, "F1 safety line", "    if hits:\n        return result(FAIL", "    if False:\n        return result(FAIL"),
    (J, "F2 coverage gap", "    if gaps or uncovered:", "    if uncovered:"),
    (J, "F3 positive coverage", "    if gaps or uncovered:", "    if gaps:"),
    (J, "F4 log lag bound", "return all(e.get(\"behind\", 0) <= LOG_LAG_BYTES for e in read)", "return True"),
    (J, "F5 active log read", "    if not any(e[\"name\"] == ACTIVE_LOG for e in read):\n        return False",
     "    if False:\n        return False"),
    (J, "F6 read rule applied", ' and log_read_covers(r["files"])] for h in HOSTS}', "] for h in HOSTS}"),
    (J, "C1 clock coverage", 'if any(max_gap(ts, t0, t1) > j["clock_series_gap_s"] for ts in ok.values()):',
     "if False:"),
    # §5.6
    (J, "Q1 packet matches the record", ') != \\\n            (DURATION, width, READ_RATE):', ") != (DURATION, width, READ_RATE) and False:"),
    (J, "Q2 completed fraction", 'if (w["ok"] < j["read_completed_fraction"] * scheduled', "if (False"),
    (J, "Q3 coverage", 'or len(w["endpoints"]) < READ_ENDPOINTS or not set(READ_METHODS) <= w["methods"]):', "):"),
    # (No mutant for `res is None` in judge_reads: a missing or invalid RESULT.json is always a contract violation
    # of reads/RESULT.json, which K3/K4 cover; the None test only keeps the code from indexing None.)
    (J, "Q5 foreign endpoint rows", '        if r["endpoint"] not in T1_READ_ENDPOINTS:\n            foreign += 1\n'
     "            continue\n", ""),
    (J, "Q6 packet endpoints pinned", 'if sorted(packet["endpoints"]) != sorted(T1_READ_ENDPOINTS):', "if False:"),
    (J, "Q7 no slot skipped", 'if res is None or res["not_offered_capacity"] or', "if res is None or"),
    # §5.7
    (J, "W1 transfers only", 'if a["role"] == "transfer"}', "}"),
    (J, "W2 receipt failure", 'if d["receipt_failure"] is not None or o["failure"][i] is not None \\',
     'if o["failure"][i] is not None \\'),
    # the schema already makes the index a natural number; the judge must bound it by the attempt's actions
    (J, "W3 action index", "if not 0 <= i < n or len(o[\"failure\"]) != n:", "if len(o[\"failure\"]) != n:"),
    (J, "W5 hourly floor", "    if short or late_start", "    if late_start"),
    (J, "W6 schedule window", 'w0, w1 = t0 + j["write_start_max_s"], t1 - j["write_end_slack_s"]',
     "w0, w1 = min(signed), max(signed)"),
    (J, "W7 backlog", 'or peak > j["backlog_max_actions"]', ""),
    (J, "W8 unresolved", "            or unresolved or ev.conflicts:", "            or ev.conflicts:"),
    (J, "W9 conflicts", "            or unresolved or ev.conflicts:", "            or unresolved:"),
    (J, "W10 late start", "    if short or late_start or early_end", "    if short or early_end"),
    (J, "W11 early end", "    if short or late_start or early_end", "    if short or late_start"),
    (J, "W12 unreported fee", "    if fee_unknown or bad_index:", "    if bad_index:"),
    (J, "W14 receipt after execution", 'or not o["utime"] <= d["recipient_utime"] <= t1:',
     'or not d["recipient_utime"] <= t1:'),
    (J, "W15 receipt before the cutoff", 'or not o["utime"] <= d["recipient_utime"] <= t1:',
     'or not o["utime"] <= d["recipient_utime"]:'),
    (J, "W17 fee cap", 'or fees > j["max_cost_nano"]', ""),
    # §5.8
    (J, "O1 operator floor", "    if low:\n        return result(FAIL", "    if False:\n        return result(FAIL"),
    (J, "O2 every operator covered", "    if thin:", "    if False:"),
    # run completed
    (J, "V1 stops fail", "    if stops:\n        return result(FAIL", "    if False:\n        return result(FAIL"),
    (J, "V2 a clean end", 'if len(end) != 1 or end[0]["result"] != "cutoff" or kinds[-1] != "end":',
     "if len(end) != 1:"),
    (J, "V3 termination confirmed", 'c["group_alive"] is not False for c in term[0]["children"].values()):',
     'False for c in term[0]["children"].values()):'),
    (J, "V4 full duration", 'or cutoff[0]["ts"] < t1 - 60:', ":"),
    (J, "V6 both children", 'or sorted(term[0]["children"]) != sorted(CHILDREN) or any(', "or any("),
    (J, "V7 lifecycle order", 'if order != ["start", "ramp_done", "cutoff", "terminated", "end"] \\\n'
     '            or any(', "if any("),
    (J, "V8 lifecycle times", "or any(b < a for a, b in zip(times, times[1:])):", ":"),
    (J, "V5 FAIL dominates",
     "overall = FAIL if FAIL in statuses else INCONCLUSIVE if INCONCLUSIVE in statuses else PASS",
     "overall = INCONCLUSIVE if INCONCLUSIVE in statuses else FAIL if FAIL in statuses else PASS"),
]


def suite(root: Path, fail_fast: bool) -> tuple[int, str]:
    args = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"] + (["-x"] if fail_fast else [])
    p = subprocess.run(args + [str(root / t) for t in TESTS], cwd=root / "tests", capture_output=True, text=True,
                       timeout=1800)
    return p.returncode, p.stdout + p.stderr


def one(m) -> tuple[str, str]:
    target, label, old, new = m
    with tempfile.TemporaryDirectory(prefix="t1-mutant-") as tmp:
        root = Path(tmp) / "testnet"
        shutil.copytree(W, root, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
        path = root / TARGETS[target]
        path.write_text(path.read_text().replace(old, new, 1))
        rc, out = suite(root, fail_fast=True)
    if rc == 1 and FAILED.search(out):
        return "killed", label
    return f"SURVIVED (pytest rc {rc})", label


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=12)
    a = ap.parse_args()
    labels = [m[1] for m in MUTANTS]
    assert len(set(labels)) == len(labels), "duplicate mutant label"
    problems = []
    for target, label, old, new in MUTANTS:
        src = (W / TARGETS[target]).read_text()
        if src.count(old) != 1:
            problems.append(f"{label}: pattern occurs {src.count(old)} times in {TARGETS[target]}")
            continue
        try:
            ast.parse(src.replace(old, new, 1))
        except SyntaxError as exc:
            problems.append(f"{label}: does not compile: {exc}")
    if problems:
        print("\n".join(problems))
        return 1
    rc, out = suite(W, fail_fast=False)
    if rc != 0:
        print("unmutated suite is not green:\n" + out[-2000:])
        return 1
    killed = 0
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:
        for verdict, label in pool.map(one, MUTANTS):
            print(f"{verdict:8} {label}", flush=True)
            if verdict == "killed":
                killed += 1
            else:
                problems.append(f"{label}: {verdict}")
    print(f"{killed}/{len(MUTANTS)} mutants killed")
    for p in problems:
        print("problem:", p)
    return 0 if killed == len(MUTANTS) and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
