#!/usr/bin/env python3
"""Mutation guards for t1_probe.py and t1-observe.py.

Each mutant replaces one exact snippet in one script, the way a guard would be removed or weakened, runs
test_t1_observe.py and restores the file. Every mutant must make a test fail: only pytest's exit 1 with a failed
test counts as killed. The run fails when a pattern does not occur exactly once, when a mutated file does not
compile, when the unmutated suite is not green, or when any mutant survives.

    python testnet/tests/t1_observe_mutants.py

Not collected by pytest.
"""

import ast
import re
import subprocess
import sys
from pathlib import Path

W = Path(__file__).resolve().parents[1]
PROBE = W / "scripts/t1_probe.py"
OBSERVE = W / "scripts/t1-observe.py"
TEST = W / "tests/test_t1_observe.py"
FAILED = re.compile(r"\b[1-9]\d* failed\b")

MUTANTS = [
    ("P1 since is exclusive", PROBE, "if ts <= since:", "if ts < since:"),
    ("P2 since filter", PROBE, "if ts <= since:\n                continue", "if False:\n                continue"),
    ("P3 old file skipped", PROBE, "if mtime < since:", "if False:"),
    ("P4 compressed file skipped", PROBE, 'if path.endswith(".gz"):', "if False:"),
    ("P5 tail only", PROBE, "fh.seek(max(0, size - TAIL_BYTES))", "fh.seek(0)"),
    ("P6 truncation reported", PROBE, '"truncated": size > TAIL_BYTES}', '"truncated": False}'),
    ("P7 diag kind", PROBE, "simplex-candidate-(?:payloads|resolver)", "simplex-candidate-(?:resolver)"),
    ("P8 oom_kill missing", PROBE, 'raise ValueError("/proc/vmstat has no oom_kill")', "return 0"),
    ("O1 no output", OBSERVE, "if not lines:\n        return None", "if False:\n        return None"),
    ("O2 unit section", OBSERVE, 'if not isinstance(report, dict) or not isinstance(report.get("unit"), dict):', "if not isinstance(report, dict):"),
    ("O3 timeout caught", OBSERVE, 'except subprocess.TimeoutExpired:\n        return None, "probe timeout"', 'except ZeroDivisionError:\n        return None, "probe timeout"'),
    ("O4 du cadence", OBSERVE, 'with_du = state["round"] % 10 == 1', 'with_du = state["round"] % 10 == 0'),
    ("O5 failed host continues", OBSERVE, 'sinks["cache"].write({"ts": now, "host": host.name, "error": error})\n            continue', 'sinks["cache"].write({"ts": now, "host": host.name, "error": error})\n            return'),
    ("O6 resources freshness", OBSERVE, 'fresh.good(f"resources:{host.name}")', "pass"),
    ("O7 cache needs payloads", OBSERVE, 'if any(d.get("kind") == "simplex-candidate-payloads" for d in new):', "if True:"),
    ("O8 diag list validated", OBSERVE, 'type(d.get("ts")) is int and', ""),
    ("O9 one-second overlap", OBSERVE, 'state["diag_since"][host.name] = max(d["ts"] for d in diag) - 1', 'state["diag_since"][host.name] = max(d["ts"] for d in diag)'),
    ("O10 dedupe", OBSERVE, "if key not in seen:\n            out.append(d)", "out.append(d)"),
    ("O11 seen bounded", OBSERVE, 'for d in lines if d["ts"] >= floor)', "for d in lines)"),
    ("O12 clock midpoint", OBSERVE, 'mid = (report["sent"] + report["received"]) / 2', 'mid = report["sent"]'),
    ("C1 head freshness", OBSERVE, 'fresh.good(f"chain:{host}")', "pass"),
    ("C2 head time", OBSERVE, '"root_hash": last["root_hash"], "gen_utime": hdr["gen_utime"]}', '"root_hash": last["root_hash"]}'),
    ("C3 all heads", OBSERVE, "if len(heads) < len(rpcs):", "if not heads:"),
    ("C4 common height", OBSERVE, "common = min(heads.values()) - 2", "common = max(heads.values()) - 2"),
    ("C5 all ids", OBSERVE, "agree = len(ids) == len(rpcs) and ", "agree = "),
    ("C6 ids agree", OBSERVE, "and len({json.dumps(v) for v in ids.values()}) == 1", ""),
    ("C7 allowlist", OBSERVE, 'if method not in {"getMasterchainInfo", "getBlockHeader"}:', "if False:"),
    ("H1 blind", OBSERVE, '"blind": bool(reasons)', '"blind": False'),
    ("H2 never seen is stale", OBSERVE, "if seen is None or now - seen > limit:", "if seen is not None and now - seen > limit:"),
    ("H3 ids watched", OBSERVE, ' + ["ids:all"]', ""),
    ("L1 failed round recorded", OBSERVE, 'sinks["health"].write({"ts": clock(), "collector": name,', 'print({"ts": clock(), "collector": name,'),
]


def suite() -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", str(TEST)],
                       cwd=W / "tests", capture_output=True, text=True, timeout=600)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    originals = {p: p.read_text() for p in (PROBE, OBSERVE)}
    labels = [m[0] for m in MUTANTS]
    assert len(set(labels)) == len(labels), "duplicate mutant label"
    rc, out = suite()
    if rc != 0:
        print("unmutated suite is not green:\n" + out[-2000:])
        return 1
    killed, problems = 0, []
    try:
        for label, path, old, new in MUTANTS:
            original = originals[path]
            if original.count(old) != 1:
                problems.append(f"{label}: pattern occurs {original.count(old)} times")
                continue
            mutated = original.replace(old, new, 1)
            try:
                ast.parse(mutated)
            except SyntaxError as exc:
                problems.append(f"{label}: does not compile: {exc}")
                continue
            path.write_text(mutated)
            rc, out = suite()
            path.write_text(original)
            if rc == 1 and FAILED.search(out):
                killed += 1
                print(f"killed   {label}")
            else:
                problems.append(f"{label}: SURVIVED (pytest rc {rc})")
                print(f"SURVIVED {label}")
    finally:
        for p, text in originals.items():
            p.write_text(text)
    print(f"{killed}/{len(MUTANTS)} mutants killed")
    for p in problems:
        print("problem:", p)
    return 0 if killed == len(MUTANTS) and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
