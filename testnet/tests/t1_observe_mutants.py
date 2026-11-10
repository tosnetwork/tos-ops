#!/usr/bin/env python3
"""Mutation guards for t1_probe.py and t1-observe.py.

Each mutant replaces one exact snippet in one script, the way a guard would be removed or weakened, runs
test_t1_observe.py and restores the file. Every mutant must make a test fail: only pytest's exit 1 with a failed
test counts as killed. The run fails when a pattern does not occur exactly once, when a mutated file does not
compile, when the unmutated suite is not green, or when any mutant survives.

    python testnet/tests/t1_observe_mutants.py

Not collected by pytest. Commit first: it rewrites the scripts in place and restores them from memory.
"""

import ast
import re
import subprocess
import sys
from pathlib import Path

W = Path(__file__).resolve().parents[1]
PROBE = W / "scripts/t1_probe.py"
OBSERVE = W / "scripts/t1-observe.py"
BOUND = W / "scripts/t1-boundaries.py"
TESTS = [W / "tests/test_t1_observe.py", W / "tests/test_t1_boundaries.py"]
FAILED = re.compile(r"\b[1-9]\d* failed\b")

MUTANTS = [
    ("S1 safety scan wired", PROBE, "if safety is not None:\n                        scan_safety(text, name, safety)", "if False:\n                        scan_safety(text, name, safety)"),
    ("S2 safety pattern", PROBE, "if any(p in line for p in SAFETY):", "if False:"),
    ("S3 safety report validated", OBSERVE, 'and all(isinstance(s, dict) and isinstance(s.get("file"), str) and isinstance(s.get("line"), str)', 'and all(isinstance(s, dict)'),
    ("S4 safety hits counted", OBSERVE, 'self.counts["safety_hits"] += len(safety)', 'self.counts["safety_hits"] += 0'),
    ("S5 gaps counted", OBSERVE, 'self.counts["coverage_gaps"] += len(gaps)', 'self.counts["coverage_gaps"] += 0'),
    ("L1 logs fresh only after the baseline", OBSERVE, "if cur is not None and behind <= LOG_LAG_BYTES:", "if behind <= LOG_LAG_BYTES:"),
    ("L2 logs watched without the cache series", OBSERVE, '            "resources", "logs", "du", "clock", "chain")', '            "resources", "du", "clock", "chain")'),
    ("L3 cache switch honoured", OBSERVE, '"chain") if self.cache_series else (', '"chain") if True else ('),
    ("F1 operator floor", OBSERVE, 'if v["balance_nano"] < OPERATOR_FLOOR_NANO)', "if False)"),
    ("F2 balance validated", OBSERVE, "if not (isinstance(balance, (str, int)) and str(balance).isdigit()):", "if balance is None:"),
    ("F3 two sources needed", OBSERVE, "if len(answers) < BALANCE_QUORUM:", "if not answers:"),
    ("F5 minimum of the sources", OBSERVE, "nano = min(answers.values())", "nano = max(answers.values())"),
    ("A1 safety count restored", OBSERVE, '"safety_hits": self.count_rows("safety", "safety_line")', '"safety_hits": 0'),
    ("A2 gap count restored", OBSERVE, '"coverage_gaps": self.count_rows("cache", "coverage_gap")', '"coverage_gaps": 0'),
    ("A3 backlog keeps logs stale", OBSERVE, "if cur is not None and behind <= LOG_LAG_BYTES:", "if cur is not None:"),
    ("B9 missed boundary row", BOUND, "if now() > boundary + LATE:", "if False:"),
    ("B10 interrupted boundary", BOUND, "if out_dir.exists():", "if False:"),
    ("B11 restart resumes", BOUND, "outcome = prior_outcomes(rows)", "outcome = {}"),
    ("B12 schedule confirmed", BOUND, "if term is not None and not on_grid(boundary, term, a.period):", "if False:"),
    ("B13 grid alignment", BOUND, 'and (boundary - term["since"]) % period == 0)', "and True)"),
    ("F4 operators in blind", OBSERVE, ' + [f"fees:{o}" for o in self.operators]', ""),
    ("B1 handover on four sources", BOUND, 'for host in HOSTS:\n        collect += ["--rpc", urls[host]]', 'for host in HOSTS[:2]:\n        collect += ["--rpc", urls[host]]'),
    ("B2 key gate on four sources", BOUND, 'for host in HOSTS:\n        argv += ["--source", host]', 'for host in HOSTS[:3]:\n        argv += ["--source", host]'),
    ("B3 term agreement", BOUND, "if len(set(seen.values())) != 1 or len(seen) != len(HOSTS):", "if False:"),
    ("B4 collection lead", BOUND, "wait = boundary - LEAD - now()", "wait = boundary - now()"),
    ("B5 no boundary after the end", BOUND, "while boundary <= a.end:", "while boundary <= a.end + a.period:"),
    ("B7 key gate after the switch", BOUND, '["--since", str(boundary)', '["--since", str(boundary - 3600)'),
    ("B8 checks time out", BOUND, 'row[f"{name}_exit"] = "timeout"', 'raise'),
    ("P1 baseline reads nothing", PROBE, 'entry.update(start=size, offset=size, status="baseline"', 'entry.update(start=0, offset=0, status="baseline"'),
    ("P2 shrink detected", PROBE, "elif size < start:", "elif False:"),
    ("P3 fingerprint checked", PROBE, "elif fingerprint(fh, start) != fp:", "elif False:"),
    ("P4 closed inode reuse", PROBE, "if changed and closed:", "if False:"),
    ("P5 only closed reuse waived", PROBE, "if changed and closed:", "if changed:"),
    ("P6 partial line kept", PROBE, 'cut = data.rfind(b"\\n") + 1', "cut = len(data)"),
    ("P7 over cap consumed", PROBE, "if cut == 0 and len(data) >= cap:", "if False:"),
    ("P8 read capped", PROBE, "data = fh.read(min(size - start, cap))", "data = fh.read(size - start)"),
    ("P9 duplicate once", PROBE, "if fid in seen:", "if False:"),
    ("P10 missing reported", PROBE, "missing = sorted(set(cursors or {}) - seen)", "missing = []"),
    ("P11 du exit code", PROBE, "if r.returncode != 0 or len(fields) != 2", "if len(fields) != 2"),
    ("P12 oom_kill missing", PROBE, 'raise ValueError("/proc/vmstat has no oom_kill")', "return 0"),
    ("P13 fingerprint at the new offset", PROBE, "fp=fingerprint(fh, start + cut))", "fp=fingerprint(fh, start))"),
    ("P14 diag kind", PROBE, "simplex-candidate-(?:payloads|resolver)", "simplex-candidate-(?:resolver)"),
    ("R1 resources fresh only when complete", OBSERVE, 'if not missing:\n            self.fresh.good(f"resources:{host.name}")', 'if True:\n            self.fresh.good(f"resources:{host.name}")'),
    ("R2 sample inside the call", OBSERVE, 'if finite(report.get("sample_clock")) and not sent - SKEW', "if False and not sent - SKEW"),
    ("R3 count refuses bool", OBSERVE, "return type(v) is int and v >= 0", "return isinstance(v, int) and v >= 0"),
    ("R4 count refuses negative", OBSERVE, "return type(v) is int and v >= 0", "return type(v) is int"),
    ("R5 boot id format", OBSERVE, 'if not (isinstance(r.get("boot_id"), str) and UUID.match(r["boot_id"])):', 'if not isinstance(r.get("boot_id"), str):'),
    ("R6 every data path", OBSERVE, "    for path in DATA_PATHS:\n        e = d.get(path)", "    for path in DATA_PATHS[:1]:\n        e = d.get(path)"),
    ("R7 active needs a pid", OBSERVE, 'if active and u["main_pid"] == 0:', "if False:"),
    ("R8 active needs proc", OBSERVE, "if active and not (isinstance(p, dict)", "if False and not (isinstance(p, dict)"),
    ("R9 strict json", OBSERVE, "return json.loads(text, parse_constant=refuse)", "return json.loads(text)"),
    ("K1 gap statuses", OBSERVE, 'if e["status"] in GAP_STATUSES or e["status"].startswith("error"):', 'if e["status"].startswith("error"):'),
    ("K2 vanished is a gap", OBSERVE, "if not (prev is not None and closed(prev)):", "if False:"),
    ("K3 closed needs a rotated name", OBSERVE, 'return ".old" in cursor["name"] and cursor["offset"] >= cursor["size"]', 'return cursor["offset"] >= cursor["size"]'),
    ("K4 closed needs drained", OBSERVE, 'return ".old" in cursor["name"] and cursor["offset"] >= cursor["size"]', 'return ".old" in cursor["name"]'),
    ("K5 gap judged once", OBSERVE, "if fid in buried and fid not in known:\n                continue", "if False:\n                continue"),
    ("K6 no gap for freshness", OBSERVE, "if cur is not None and not gaps and any(", "if cur is not None and any("),
    ("K7 baseline not fresh", OBSERVE, "if cur is not None and not gaps and any(", "if not gaps and any("),
    ("K8 required counters", OBSERVE, 'and all(count(d["fields"].get(k)) for k in CACHE_FIELDS)', ""),
    ("K9 stamp not too old", OBSERVE, 'and received - FRESHNESS["cache"] <= d["ts"] <= received + SKEW)', 'and d["ts"] <= received + SKEW)'),
    ("K10 stamp not in the future", OBSERVE, 'and received - FRESHNESS["cache"] <= d["ts"] <= received + SKEW)', 'and received - FRESHNESS["cache"] <= d["ts"])'),
    ("K11 payloads kind", OBSERVE, 'return (d.get("kind") == "simplex-candidate-payloads"', "return (True"),
    ("K12 refuse re-baseline", OBSERVE, "if cache.exists() and any(", "if False and any("),
    ("K13 grave expires", OBSERVE, 'if fid in new_files or grave[fid]["rounds"] <= 0:', "if fid in new_files:"),
    ("K14 file offsets ordered", OBSERVE, 'and e["start"] <= e["offset"] <= e["size"] and isinstance(e.get("fp"), str)\n', 'and isinstance(e.get("fp"), str)\n'),
    ("K15 diag stamp typed", OBSERVE, 'isinstance(d, dict) and type(d.get("ts")) is int and', "isinstance(d, dict) and"),
    ("K16 grave cursors sent", OBSERVE, 'offs = {k: [v["offset"], v["fp"], closed(v)] for k, v in cur.get("grave", {}).items()}', "offs = {}"),
    ("D1 du complete", OBSERVE, "complete = all(count(du.get(p)) for p in DU_PATHS)", "complete = True"),
    ("T1 clock interval inside the limit", OBSERVE, 'elif -CLOCK_LIMIT <= best["offset"] - best["bound"] and best["offset"] + best["bound"] <= CLOCK_LIMIT:', 'elif abs(best["offset"]) <= CLOCK_LIMIT:'),
    ("T2 clock step refused", OBSERVE, "if abs((w1 - w0) - (m1 - m0)) >= 0.01:", "if False:"),
    ("T3 narrowest try", OBSERVE, 'if best is None or t["bound"] < best["bound"]:', "if best is None:"),
    ("T4 bad verdict blind at once", OBSERVE, "reasons += [f\"clock:{h} latest verdict {v['verdict']}\" for h, v in clock.items() if v[\"verdict\"] != \"ok\"]", "reasons += []"),
    ("C1 head is masterchain", OBSERVE, "if want is None or not (want[0] == -1 and want[1] == SHARD):", "if want is None:"),
    ("C2 head bound to header", OBSERVE, "if header_id(hdr) != want:", "if False:"),
    ("C3 header gen_utime", OBSERVE, 'if not count(hdr.get("gen_utime")):', "if False:"),
    ("C4 advance only upward", OBSERVE, 'if prev is None or seq > prev["max_seqno"]:', "if True:"),
    ("C4b advance past the maximum, not the last", OBSERVE, 'if prev is None or seq > prev["max_seqno"]:', 'if prev is None or seq > prev["id"][2]:'),
    ("C12 hashes are 32 bytes", OBSERVE, "return len(base64.b64decode(v, validate=True)) == 32", "return True"),
    ("C13 id hashes required", OBSERVE, 'and count(i.get("seqno")) and hash32(i.get("root_hash")) and hash32(i.get("file_hash"))):', 'and count(i.get("seqno"))):'),
    ("C5 regression row", OBSERVE, 'if seq < prev["id"][2]:', "if False:"),
    ("C6 cadence miss", OBSERVE, 'if now_m - started > INTERVALS["chain"]:', "if False:"),
    ("C7 ids need fresh heads", OBSERVE, 'if now_m - v["seen_mono"] <= FRESHNESS["chain"]}', "if True}"),
    ("C8 ids bound to the request", OBSERVE, "if got is None or got[:3] != (-1, SHARD, common):", "if got is None:"),
    ("C9 ids from all four", OBSERVE, "agree = len(ids) == len(self.rpcs) and ", "agree = "),
    ("C10 ids agree", OBSERVE, "and len({json.dumps(v) for v in ids.values()}) == 1", ""),
    ("C11 allowlist", OBSERVE, 'if method not in {"getMasterchainInfo", "getBlockHeader", "getAddressInformation"}:', "if False:"),
    ("H1 blind", OBSERVE, '"blind": bool(reasons)', '"blind": False'),
    ("H2 never seen is stale", OBSERVE, "if seen is None or now - seen > limit:", "if seen is not None and now - seen > limit:"),
    ("H3 stalled hosts", OBSERVE, 'stalled = sorted(h for h, v in chain.items() if v["head_age_s"] > STALL)', "stalled = []"),
    ("H4 monotonic freshness", OBSERVE, "self.fresh = Freshness(mono)", "self.fresh = Freshness(wall)"),
    ("L1 failed round recorded", OBSERVE, 'obs.sinks["health"].write({"ts": obs.wall(), "collector": name,', 'print({"ts": obs.wall(), "collector": name,'),
]


def suite() -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *map(str, TESTS)],
                       cwd=W / "tests", capture_output=True, text=True, timeout=600)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    originals = {p: p.read_text() for p in (PROBE, OBSERVE, BOUND)}
    labels = [m[0] for m in MUTANTS]
    assert len(set(labels)) == len(labels), "duplicate mutant label"
    assert len({(m[1], m[2], m[3]) for m in MUTANTS}) == len(MUTANTS), "duplicate mutant"
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
