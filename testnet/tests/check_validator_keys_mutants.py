#!/usr/bin/env python3
"""Mutation guards for check-validator-keys.py.

Each mutant replaces one exact snippet, the way a guard would be removed or weakened, runs
test_check_validator_keys.py and restores the file. Every mutant must make a test fail: only pytest's exit 1
with a failed test counts as killed. The run fails when a pattern does not occur exactly once, when a mutated
file does not compile, when the unmutated suite is not green, or when any mutant survives.

    python testnet/tests/check_validator_keys_mutants.py

Not collected by pytest.
"""

import ast
import re
import subprocess
import sys
from pathlib import Path

W = Path(__file__).resolve().parents[1]
SCRIPT = W / "scripts/check-validator-keys.py"
TEST = W / "tests/test_check_validator_keys.py"
FAILED = re.compile(r"\b[1-9]\d* failed\b")

MUTANTS = [
    ("P1 zero-state record pin", 'need(\n        {k: zs.get(k) for k in EPOCH6_ZERO_STATE} == EPOCH6_ZERO_STATE,', 'need(\n        True,'),
    ("P2 zerostate file hash pin", 'hashlib.sha256(zerostate).digest() == base64.b64decode(EPOCH6_ZERO_STATE["file_hash"]),', 'True,'),
    ("P3 global id", 'need(global_id == EPOCH6_GLOBAL_ID,', 'need(True,'),
    ("P4 member count", 'need(len(members) == MEMBERS, f"genesis set has', 'need(True, f"genesis set has'),
    ("S1 tunnel inventory address", 'need(addr in by_address, f"{unit}: {addr} is not an inventory host")\n        host = by_address[addr]', 'host = by_address.get(addr, f"unknown-{addr}")'),
    ("S2 one tunnel per host", 'need(host not in out, f"{unit}: {host} has more than one tunnel")', 'pass'),
    ("S3 duplicate source", 'need(len(requested) == len(set(requested)), "duplicate source host")', 'pass'),
    ("S4 three sources", 'need(len(requested) >= 3, "at least three source hosts required")', 'pass'),
    ("S5 approved source", 'need(host in approved, f"{host} has no approved tunnel")', 'pass'),
    ("S6 excluded host", 'need(host != exclude, f"{host} is the host under test and cannot be a source")', 'pass'),
    ("E1 consecutive window", 'need(len(seqnos) >= 1 and seqnos == list(range(seqnos[0], seqnos[0] + len(seqnos))), "window is not consecutive")', 'pass'),
    ("E2 source agreement", 'need(len(ids) == 1, f"sources disagree on block {seqno}\'s full id")', 'pass'),
    ("E4 proof end binds the verified link", 'identity(end) == identity(jh["id"]) == identity(link["dst"]),', 'identity(end) == identity(jh["id"]),'),
    ("E4b proof end", 'identity(end) == identity(jh["id"]) == identity(link["dst"]),', 'True,'),
    ("E6 proof start", 'identity(start) == identity(c["key_header"]["id"]) == identity(link["src"]),', 'True,'),
    ("T1 term half-open", 'result["validator_since"] <= gen < result["validator_until"],', 'result["validator_since"] <= gen <= result["validator_until"],'),
    ("T2 term lower bound", 'result["validator_since"] <= gen < result["validator_until"],', 'gen < result["validator_until"],'),
    ("E5 verify_link", 'result = verify_link(link, verify_signature, expected_source=c["key_header"]["id"])', 'result = verify_link(link, lambda pk, sig, msg: None, expected_source=None)'),
    ("K1 pinned keys", 'need(members == pinned, f"{host}: block {seqno}: governing set is not the four pinned genesis keys")', 'pass'),
    ("K2 equal weights", 'need(len(weights) == 1, f"{host}: governing set weights are not equal")', 'pass'),
    ("H1 proven header agreement", '== (jh["gen_utime"], jh["prev_key_block_seqno"], jh["catchain_seqno"], jh["validator_list_hash_short"]),', '== (header["gen_utime"], header["prevkey"], header["cc"], header["vhash"]),'),
    ("F1 future", 'need(gen <= now + future, f"{host}: block {seqno} gen_utime {gen} is in the future")', 'pass'),
    ("F2 max age", 'need(now - gen <= max_age, f"{host}: block {seqno} is {int(now - gen)} s old (max {max_age})")', 'pass'),
    ("F3 since", 'if gen < since:\n                retry.append', 'if False:\n                retry.append'),
    ("G1 four signers", 'if signers != set(pinned):\n            retry.append', 'if False:\n            retry.append'),
    ("W1 terminal not retried", 'except Retry as exc:\n                attempts.append', 'except (Retry, Fail) as exc:\n                attempts.append'),
    ("W2 wait deadline", 'if time.monotonic() >= deadline:', 'if False:'),
]


def suite() -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", str(TEST)], cwd=W / "tests",
                       capture_output=True, text=True, timeout=600)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    original = SCRIPT.read_text()
    labels = [m[0] for m in MUTANTS]
    assert len(set(labels)) == len(labels), "duplicate mutant label"
    assert len({(m[1], m[2]) for m in MUTANTS}) == len(MUTANTS), "duplicate mutant"
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
            SCRIPT.write_text(mutated)
            rc, out = suite()
            SCRIPT.write_text(original)
            if rc == 1 and FAILED.search(out):
                killed += 1
                print(f"killed   {label}")
            else:
                problems.append(f"{label}: SURVIVED (pytest rc {rc})")
                print(f"SURVIVED {label}")
    finally:
        SCRIPT.write_text(original)
    print(f"{killed}/{len(MUTANTS)} mutants killed")
    for p in problems:
        print("problem:", p)
    return 0 if killed == len(MUTANTS) and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
