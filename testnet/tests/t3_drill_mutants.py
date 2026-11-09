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
    ("V1 stall with 3 up not judged", LIB, "if stall >= 30:", "if stall >= 3000:"),
    ("V2 blocks during a 2-down halt not judged", LIB, "elif a > 1:", "elif a > 10**9:"),
    ("V3 rate band 0.50-0.70 not judged", LIB, "elif ratio < 0.70:", "elif ratio < 0.0:"),
    ("V4 double-sign kind not a FAIL", LIB, "if m[1] in DOUBLE_SIGN_KINDS:", "if False:"),
    (
        "V5 unconfirmed partition not INCONCLUSIVE",
        LIB,
        "if partitioned and confirmed is not True:",
        "if False:",
    ),
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
        "K4 elections started before the markers",
        NODE,
        '    run(["systemctl", "start", VALIDATOR])\n    out = finish_markers(',
        '    run(["systemctl", "start", VALIDATOR])\n    run(["systemctl", "start", ELECTIONS])\n'
        "    out = finish_markers(",
    ),
    ("D1 execute is the default", SH, "MODE=${2:---dry-run}", "MODE=${2:---execute}"),
    (
        "D2 dry run executes",
        RUN,
        "execute=False, printer=printer)",
        "execute=True, printer=printer)",
    ),
    (
        "P1 no self-heal armed",
        LIB,
        'f"systemd-run --unit=t3-heal-{run} --on-active={SELF_HEAL} "\n'
        "        f\"/usr/sbin/nft delete table inet {TABLE} && nft -f - <<'T3EOF'\\n\"",
        "f\"nft -f - <<'T3EOF'\\n\"",
    ),
    (
        "P2 ladder does not heal",
        RUN,
        'if self.sc["partition"]:\n            self.say("ladder 1',
        'if False:\n            self.say("ladder 1',
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
