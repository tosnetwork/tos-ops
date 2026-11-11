#!/usr/bin/env python3
"""Mutation guards for t1-load.py and the T1 read profile.

Each mutant replaces one exact snippet, runs test_t1_load.py and test_read_load_t1.py, and restores the file.
Only pytest's exit 1 with a failed test counts as killed. The run fails when a pattern does not occur exactly
once, when a mutated file does not compile, when the unmutated suite is not green, or when any mutant survives.

    python testnet/tests/t1_load_mutants.py

Not collected by pytest. Commit first: it rewrites the scripts in place and restores them from memory.
"""

import ast
import re
import subprocess
import sys
from pathlib import Path

W = Path(__file__).resolve().parents[1]
LOAD = W / "scripts/t1-load.py"
READS = W / "scripts/sustained_read_load.py"
CLIENT = W / "scripts/read_client.py"
TESTS = [W / "tests/test_t1_load.py", W / "tests/test_read_load_t1.py"]
FAILED = re.compile(r"\b[1-9]\d* failed\b")

MUTANTS = [
    ("R1 record hash", LOAD, "if sha256_file(path) != expected_sha:", "if False:"),
    ("R2 record keys", LOAD, 'raise Refuse(f"acceptance record lacks a valid {key}")', "pass"),
    ("R3 section keys", LOAD, 'raise Refuse(f"acceptance record lacks {section}.{k}")', "pass"),
    ("R4 four ramp sources", LOAD, 'and len(rec["ramp"]["rpc"]) == 4)', ")"),
    ("R5 tos revision", LOAD, 'if head != rec["tos_rev"]:', "if False:"),
    ("R6 signer hash", LOAD, 'if sha256_file(Path(rec["signer"])) != rec["signer_sha256"]:', "if False:"),
    ("R7 key custody", LOAD, "if key.stat().st_mode & 0o077 or key.parent.stat().st_mode & 0o077:", "if key.stat().st_mode & 0o077:"),
    ("A1 layout repeats zero", LOAD, '"--layout-repeats", "0",', '"--layout-repeats", "1",'),
    ("A2 fixed rate", LOAD, '"--factor", "1",', '"--factor", "2",'),
    ("S1 missing field", LOAD, 'out.append(f"status lacks {key}")', "pass"),
    ("S2 other boot", LOAD, 'if st["coordinator_boot_id"] != boot_id:', "if False:"),
    ("S3 stale", LOAD, 'if not finite(st["updated_mono"]) or now_mono - st["updated_mono"] > rec["status_stale_s"]:', 'if now_mono - st["updated_mono"] > 10**9:'),
    ("S3b stale NaN", LOAD, 'if not finite(st["updated_mono"]) or now_mono - st["updated_mono"] > rec["status_stale_s"]:', 'if now_mono - st["updated_mono"] > rec["status_stale_s"]:'),
    ("S4 blind", LOAD, 'if st["blind"] is not False:', "if False:"),
    ("S5 stall of three", LOAD, 'or len(st["stalled_hosts"]) >= 3:', 'or len(st["stalled_hosts"]) >= 4:'),
    ("S6 stall threshold low", LOAD, 'or len(st["stalled_hosts"]) >= 3:', 'or len(st["stalled_hosts"]) >= 2:'),
    ("S7 safety", LOAD, 'if st["safety_hits"] != 0 or type(st["safety_hits"]) is not int:', "if False:"),
    ("S8 gaps", LOAD, 'if st["coverage_gaps"] != 0 or type(st["coverage_gaps"]) is not int:', "if False:"),
    ("S9 operators", LOAD, 'if st["operators_low"] != []:', "if False:"),
    ("H1 host row present", LOAD, 'return [f"{h}: no resource row"]', "return []"),
    ("H2 incomplete row", LOAD, '    if row.get("complete") is not True:\n        return', '    if False:\n        return'),
    ("H3 row age", LOAD, 'if not finite(row.get("received_mono")) or now_mono - row["received_mono"] > ROW_MAX_AGE:', 'if now_mono - row["received_mono"] > 10**9:'),
    ("H4 inactive", LOAD, 'if not isinstance(unit, dict) or unit.get("active_state") != "active":', "if not isinstance(unit, dict):"),
    ("H5 snapshot", LOAD, "if now_id != snapshot[h]:", "if False:"),
    ("H6 memory floor", LOAD, 'mem["MemAvailable"] < floors["mem_available_bytes"]:', 'mem["MemAvailable"] < 0:'),
    ("H6b memory finite", LOAD, 'if not (isinstance(mem, dict) and finite(mem.get("MemAvailable"))) or \\', 'if not isinstance(mem, dict) or \\'),
    ("H7 disk bytes", LOAD, 'elif d["free_bytes"] < floors["disk_free_bytes"] or d["free_inodes"] < floors["disk_free_inodes"]:', 'elif d["free_inodes"] < floors["disk_free_inodes"]:'),
    ("H8 disk inodes", LOAD, 'elif d["free_bytes"] < floors["disk_free_bytes"] or d["free_inodes"] < floors["disk_free_inodes"]:', 'elif d["free_bytes"] < floors["disk_free_bytes"]:'),
    ("H9 snapshot needs complete rows", LOAD, 'raise Refuse(f"{h}: no complete resource row to snapshot")', "continue"),
    ("H10 every data path", LOAD, "    for path in DATA_PATHS:\n        d = disks.get(path)", "    for path in (disks if isinstance(disks, dict) else {}):\n        d = disks.get(path)"),
    ("H11 disk values finite", LOAD, 'if not (isinstance(d, dict) and finite(d.get("free_bytes")) and finite(d.get("free_inodes"))):', "if not isinstance(d, dict):"),
    ("N1 record thresholds positive", LOAD, "        if not positive(v):", "        if False:"),
    ("I1 ramp on the inventory", LOAD, 'if rec["ramp"]["rpc"] != want:', "if False:"),
    ("I2 reads on the inventory", LOAD, "if read_endpoints != want:", "if False:"),
    ("I3 distinct tunnels", LOAD, "if None in want or len(set(want)) != len(HOSTS):", "if None in want:"),
    ("K1 inside the unit", LOAD, 'if not any(line.rstrip().endswith("/" + UNIT_NAME) for line in cgroup.splitlines()):', "if False:"),
    ("K2 kill mode", LOAD, 'if props.get("KillMode") != "control-group" or props.get("Restart") != "no":', 'if props.get("Restart") != "no":'),
    ("K3 no restart", LOAD, 'if props.get("KillMode") != "control-group" or props.get("Restart") != "no":', 'if props.get("KillMode") != "control-group":'),
    ("W1 held wallet lock", LOAD, 'raise Refuse(f"{lock} is held by a running process") from exc', "pass"),
    ("E1 ramp finishes its schedule", LOAD, 'if name == "ramp" and p.returncode == 0 and now - start >= ramp_finish:', 'if name == "ramp" and p.returncode == 0:'),
    ("E2 unfinished ramp at the cutoff", LOAD, 'if kind == "cutoff" and not ramp_done:', "if False:"),
    ("X1 sibling by path", LOAD, 'read_client = sibling("read_client")  # the endpoint pins live there', "import read_client"),
    ("J1 torn line kept", LOAD, "self.partial = lines.pop()", "self.partial = b''"),
    ("J2 per-action failure", LOAD, "elif i >= len(per) or per[i] is None:", "elif True:"),
    ("J6 early delivery", LOAD, "if key in self.early:\n                        self.early.discard(key)", "if False:\n                        self.early.discard(key)"),
    ("J3 delivery clears", LOAD, "if self.pending.pop(key, None) is None and aid in self.actions:", "if aid in self.actions:"),
    ("J4 count limit", LOAD, 'if len(self.pending) > limits["max_count"]:', "if False:"),
    ("J5 age limit", LOAD, 'if oldest is not None and now - oldest > limits["max_age_s"]:', "if False:"),
    ("C1 own process group", LOAD, "        os.setpgrp()\n", "        pass\n"),
    ("C2 death signal", LOAD, "if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:", "if False:"),
    ("C3 kill after grace", LOAD, "            os.killpg(p.pid, signal.SIGKILL)", "            pass"),
    ("L1 child exit stops", LOAD, 'reasons.append(f"{name} exited on its own with rc {p.returncode}")', "pass"),
    ("L2 status checked", LOAD, "reasons += status_reasons(read_status(status_path), snapshot, rec, now, me)", "pass"),
    ("L3 journal checked", LOAD, 'reasons += tail.reasons(now, rec["unresolved"])', "pass"),
    ("L4 refuse an unhealthy start", LOAD, "    if first:\n", "    if False:\n"),
    ("L5 failed launch cleans up", LOAD, 'append(log, {"ts": wall(), "kind": "terminated", "children": terminate(children, sleep)})', "pass"),
    ("L6 cutoff", LOAD, "        if now >= cutoff:\n            break", "        if False:\n            break"),
    ("P1 T1 topology", READS, "if endpoints != list(T1_ENDPOINTS):", "if False:"),
    ("P2 T1 address", READS, "if type(address) is not str or not RAW_ADDRESS.match(address):", "if False:"),
    ("P3 T1 deadline", READS, "if not (type(deadline) in (int, float) and DEADLINE_BOUNDS[0] <= deadline <= DEADLINE_BOUNDS[1]):\n            raise RuntimeError(\"T1 network deadline bound\")", "if False:\n            raise RuntimeError(\"T1 network deadline bound\")"),
    ("P4 rotation", READS, "endpoint = endpoints[slot % len(endpoints)]", "endpoint = endpoints[slot % 2]"),
    ("P5 deadline passed", READS, "result = request(endpoint, method, address, deadline)", "result = request(endpoint, method, address, 2.5)"),
    ("P6 worker bound", READS, '    maximum = math.ceil(rate * (deadline + 0.5))\n    if not 1 <= maximum <= 48:', '    maximum = math.ceil(rate * (deadline + 0.5))\n    if not 1 <= maximum <= 480:'),
    ("P7 unknown profile", READS, 'raise RuntimeError(f"Unknown read profile {profile!r}")', "maximum_pending, deadline = None, NETWORK_DEADLINE_SECONDS"),
    ("Q1 request deadline bound", CLIENT, 'raise ProtocolError("deadline bound")', "pass"),
]


def suite() -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *map(str, TESTS)],
                       cwd=W / "tests", capture_output=True, text=True, timeout=600)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    originals = {p: p.read_text() for p in (LOAD, READS, CLIENT)}
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
