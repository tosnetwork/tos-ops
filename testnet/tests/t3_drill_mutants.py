#!/usr/bin/env python3
"""Red controls for the T3 drill scripts (testnet/drills/t3) and test_t3_drills.py.

Each mutant replaces one exact snippet, runs test_t3_drills.py with a fresh
PYTHONPYCACHEPREFIX and restores the file. Only pytest's exit 1 with a failed test counts
as killed. The run fails when a pattern does not occur exactly once, when the unmutated
suite is not green or when any mutant survives. Commit before running: the file is
restored from memory, not from git.

    python testnet/tests/t3_drill_mutants.py [LABEL ...]

Not collected by pytest.
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

W = Path(__file__).resolve().parents[1]
D = W / "drills/t3"
LIB, NODE, RUN, SH = D / "t3_lib.py", D / "t3-node.py", D / "t3_run.py", D / "t3-run.sh"
TEST = W / "tests/test_t3_drills.py"
FAILED = re.compile(r"\b[1-9]\d* failed\b")

M = [
    # verdict
    ("V1 stall with 3 up not judged", LIB, "if stall >= 30:", "if stall >= 3000:"),
    ("V2 progress after settling not judged", LIB, "elif a > 0:", "elif a > 10**9:"),
    ("V3 rate band 0.50-0.70 not judged", LIB, "elif ratio < 0.70:", "elif ratio < 0.0:"),
    ("V4 double-sign kind not a safety failure", LIB, "if m[1] in DOUBLE_SIGN_KINDS:", "if False:"),
    (
        "V5 unconfirmed partition not INCONCLUSIVE",
        LIB,
        "if partitioned and confirmed is not True:",
        "if False:",
    ),
    ("V6 drop counters not required", LIB, "        if cp:\n", "        if False:\n"),
    (
        "V7 settling interval ignored",
        LIB,
        "a = advance(samples, port, hf + settle, ht)",
        "a = advance(samples, port, hf, ht)",
    ),
    (
        "V8 stale heads count as progress",
        LIB,
        'if len(fresh) < 0.9 * len(rows) or rows[-1]["seqno"]',
        'if rows[-1]["seqno"]',
    ),
    (
        "V9 safety failure reported as FAIL",
        LIB,
        'verdict = "SAFETY_FAIL" if safety else',
        'verdict = "FAIL" if safety else',
    ),
    # gates
    (
        "G1 abort budget not held before the recovery deadline",
        LIB,
        "if abort_end > recovery_deadline(term):",
        "if abort_end > until - 3600:",
    ),
    (
        "G2 clock skew not judged",
        LIB,
        "if abs(off) - half > MAX_CLOCK_SKEW or half > 2.0:",
        "if False:",
    ),
    ("G3 frozen heads pass", LIB, 'if b["seqno"] <= a["seqno"]:', "if False:"),
    (
        "G4 self-heal deadline not checked",
        LIB,
        "if not want_left - tolerance <= left <= want_left + 5:",
        "if False:",
    ),
    (
        "G5 per-unit rc not judged",
        LIB,
        '    if got != want:\n        p.append(f"units',
        '    if False:\n        p.append(f"units',
    ),
    (
        "G6 socket addresses kept",
        LIB,
        "out += [json.dumps(s) for s in socket_summary(lines)]",
        "out += lines",
    ),
    (
        "G7 alleged validator not mapped to its host",
        LIB,
        'elif e.get("validator") in by_vid:',
        "elif False:",
    ),
    # node script
    (
        "K1 workchain-0 signature accepted as masterchain",
        NODE,
        ' and "(-1,8000000000000000)" in line\n',
        "\n",
    ),
    (
        "K2 markers before the start counted",
        NODE,
        "if t is not None and t >= t0:",
        "if t is not None:",
    ),
    (
        "K3 untrusted not recognised",
        NODE,
        'UNTRUSTED = re.compile(r"unknown history|untrusted|cannot.*decision log", re.I)',
        'UNTRUSTED = re.compile(r"$^")',
    ),
    (
        "K4 start-engine also starts elections",
        NODE,
        '    run(["systemctl", "start", VALIDATOR])\n    return dict(result="ENGINE-STARTED"',
        '    run(["systemctl", "start", VALIDATOR])\n    run(["systemctl", "start", ELECTIONS])\n'
        '    return dict(result="ENGINE-STARTED"',
    ),
    ("K5 quarantine marker ignored", NODE, "if starts and quarantined():", "if False:"),
    (
        "K6 restore timer not verified",
        NODE,
        '        quiet(["systemctl", "stop", unit + ".timer"])\n'
        '        raise Refused(2, "RESTORE-TIMER-NOT-VERIFIED", left=left, exec=execs[:200])',
        "        pass",
    ),
    (
        "K7 unsafe marker does not quarantine",
        NODE,
        'q = do_quarantine(node, run_name, "unsafe ledger marker")',
        "q = None",
    ),
    # runner
    ("D1 execute is the default", SH, "MODE=${2:---dry-run}", "MODE=${2:---execute}"),
    (
        "D2 dry run executes",
        RUN,
        "execute=False, printer=printer)",
        "execute=True, printer=printer)",
    ),
    (
        "D3 open quarantine not refused",
        SH,
        'python3 -I "$HERE/t3_lib.py" quarantines "$EVIDENCE" ||',
        "true ||",
    ),
    ("P1 rules loaded without a verified self-heal", RUN, "if not self.arm_heal():", "if False:"),
    (
        "P2 ladder does not heal",
        RUN,
        'if self.sc["partition"]:\n            self.say("ladder 1',
        'if False:\n            self.say("ladder 1',
    ),
    (
        "P3 partial install not healed everywhere",
        RUN,
        'no rule loaded")\n            self.heal()\n            return False',
        'no rule loaded")\n            return False',
    ),
    (
        "P4 node-4 start skipped after a node-3 failure",
        RUN,
        "            self.say(f\"  node-3: {a3.get('result')}; node-4 starts now, not at t0+11 min\")",
        "            return",
    ),
    (
        "P5 no host-local restore timer in S3",
        RUN,
        'self.stop("node-4", restore_after=int(',
        'self.stop("node-4", restore_after=0 and int(',
    ),
    ("P6 implicated host not quarantined", RUN, "        for h in hosts:", "        for h in []:"),
    (
        "P7 rejoin ignores the block hash",
        RUN,
        "return len({block_hash(p, common) for p in ports}) == 1",
        "return True",
    ),
]


def pytest(prefix: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPYCACHEPREFIX=prefix)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", str(TEST)],
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def main(labels: list[str]) -> int:
    base = pytest(tempfile.mkdtemp(prefix="t3-mut-base-"))
    if base.returncode != 0:
        print("unmutated suite not green:\n" + base.stdout[-2000:])
        return 1
    bad = 0
    for label, path, old, new in M:
        if labels and label.split()[0] not in labels:
            continue
        text = path.read_text()
        if text.count(old) != 1:
            print(f"PATTERN {label}: occurs {text.count(old)} times")
            bad += 1
            continue
        try:
            path.write_text(text.replace(old, new))
            r = pytest(tempfile.mkdtemp(prefix=f"t3-mut-{label.split()[0]}-"))
        finally:
            path.write_text(text)
        killed = r.returncode == 1 and FAILED.search(r.stdout)
        first = next((x for x in r.stdout.splitlines() if x.startswith("FAILED")), "")
        print(f"{'KILLED  ' if killed else 'SURVIVED'} {label}: {first[:150]}")
        bad += not killed
    print(f"{len(M)} mutants, {bad} not killed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
