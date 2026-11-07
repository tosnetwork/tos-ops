#!/usr/bin/env python3
"""Guard-removal mutants for load_fence_reconcile.py; every one must turn the suite red.

Each mutant is applied to a fresh copy of testnet/ in a temporary directory, so
the checkout is never modified. Only pytest's exit 1 with a failed test counts
as RED; a pattern that does not occur exactly once, a mutant that does not
parse, a green baseline failure, a survivor or an invalid run fails the whole run.

    unshare -rn python testnet/tests/load_fence_reconcile_mutants.py [LABEL ...]

Not collected by pytest.
"""

import ast
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

W = Path(__file__).resolve().parents[1]
TARGET = "scripts/load_fence_reconcile.py"
TEST = "tests/test_load_fence_reconcile.py"
FAILED = re.compile(r"\b[1-9]\d* failed\b")
ERRORS = re.compile(r"\b[1-9]\d* errors?\b")

M = [
    (
        "R1 json.loads before the projection boundary",
        "    try:\n        spans = []\n",
        "    json.loads(bytes(buf[start:end]))\n    try:\n        spans = []\n",
    ),
    (
        "R2 boc span not nulled",
        '            buf[value_start : value_start + 4] = b"null"\n'
        "            _wipe(buf, value_start + 4, value_end)\n",
        "            pass\n",
    ),
    (
        "R3 opens a key file",
        "    names = reader.listing(st)\n",
        '    names = reader.listing(st)\n    os.close(os.open("highload.key", os.O_RDONLY, dir_fd=st))\n',
    ),
    (
        "R4 opens a signed .boc file",
        "    names = reader.listing(st)\n",
        "    names = reader.listing(st)\n"
        '    os.close(os.open("highload.init.boc", os.O_RDONLY, dir_fd=st))\n',
    ),
    (
        "R5 reader denylist removed",
        '        if denied(name, 0):\n            raise Refused(input_id, 0, "denied_name")\n',
        "",
    ),
    (
        "R6 audit hook veto removed",
        '        raise PermissionError("refused by the reconcile allowlist")\n',
        "        pass\n",
    ),
    (
        "R7 pending check removed",
        '    ok = not pending and result.get("pending") == 0\n',
        "    ok = True\n",
    ),
    (
        "R8 events hash check removed",
        '        and digests.get("run:events") == audit_id.get("events_sha256")\n',
        "",
    ),
    (
        "R9 funding sequence check removed",
        "    ok = (\n        not broken\n",
        "    ok = True or (\n        not broken\n",
    ),
    (
        "R10 open operations ignored",
        'r.get("wallet") in wallets and r.get("state") in OPEN_STATES',
        'r.get("wallet") in wallets and r.get("state") in ()',
    ),
    (
        "R11 held lock reported free",
        "    return LOCK_HELD if key in held else LOCK_FREE\n",
        "    return LOCK_FREE\n",
    ),
    (
        "R12 fence eligibility ignores the marker",
        '    if not (body["closed"] and body["safe"]):\n',
        "    if False:\n",
    ),
    (
        "R13 allocated-unlogged ids escape",
        "            q = next_query_id(q)\n        counter_verdict = UNKNOWN\n",
        "            q = next_query_id(q)\n        counter_verdict = RECONCILED\n",
    ),
    (
        "R14 core dumps left enabled",
        "    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))\n",
        "    pass\n",
    ),
    (
        "R15 read buffer not wiped",
        "    buf[0 : len(buf)] = bytes(len(buf))\n",
        "    pass\n",
    ),
    (
        "R16 refused line not wiped",
        "        _wipe(buf, start, end)\n"
        '        raise Refused(input_id, start, "line_not_tokenizable") from None\n',
        '        raise Refused(input_id, start, "line_not_tokenizable") from None\n',
    ),
    (
        "R17 excepthook prints content",
        "    text = str(value) if isinstance(value, Refused) else kind.__name__\n",
        "    text = str(value)\n",
    ),
    (
        "R18 secret scan bypassed",
        "    if scan(document):\n",
        "    if False:\n",
    ),
    (
        "R19 stability ignores identities",
        "        stable = (\n            first.idents == reader.idents\n",
        "        stable = (\n            True\n",
    ),
    (
        "R20 existing output not refused",
        "    if os.path.lexists(args.out):\n",
        "    if False:\n",
    ),
    (
        "R21 symlinks followed",
        "    FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC\n",
        "    FILE = os.O_RDONLY | os.O_CLOEXEC\n",
    ),
    (
        "R22 archived-not-offered counted as success",
        "        verdict = UNKNOWN  # archived but not offered: never counted as success\n",
        "        verdict = RECONCILED\n",
    ),
    (
        "R23 source disagreement ignored",
        "        if None in seen or len(set(seen)) != 1:\n",
        "        if None in seen:\n",
    ),
    (
        "R24 escaped boc key accepted",
        "                if key_end < 0 or 0x5C in buf[i:key_end]:\n",
        "                if key_end < 0:\n",
    ),
    (
        "R25 second boc member accepted",
        "        if _skip_ws(buf, i, end) != end or len(spans) > 1:\n",
        "        if _skip_ws(buf, i, end) != end:\n",
    ),
]


def suite(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", TEST],
        capture_output=True,
        text=True,
        cwd=root,
        timeout=600,
    )


def classify(result: subprocess.CompletedProcess) -> str:
    if result.returncode == 0:
        return "SURVIVED"
    out = result.stdout.strip().splitlines()
    summary = out[-1] if out else ""
    if result.returncode == 1 and FAILED.search(summary) and not ERRORS.search(summary):
        return "RED"
    return "INVALID"


def copy(scratch: Path, name: str) -> Path:
    root = scratch / name
    shutil.copytree(W, root, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return root


def main(only: list[str]) -> int:
    source = (W / TARGET).read_text()
    chosen = [m for m in M if not only or m[0].split()[0] in only]
    for label, old, new in chosen:
        if source.count(old) != 1:
            print(f"FAIL: {label}: pattern occurs {source.count(old)} times")
            return 1
        ast.parse(source.replace(old, new))
    with tempfile.TemporaryDirectory(prefix="lfr-mutants-") as scratch:
        scratch = Path(scratch)
        baseline = suite(copy(scratch, "baseline"))
        if baseline.returncode != 0:
            print("FAIL: the unmutated suite is not green")
            return 1
        bad = []
        for n, (label, old, new) in enumerate(chosen):
            root = copy(scratch, f"m{n}")
            (root / TARGET).write_text(source.replace(old, new))
            try:
                result = suite(root)
                verdict = classify(result)
                tail = (result.stdout.strip().splitlines() or [""])[-1]
            except subprocess.TimeoutExpired:
                verdict, tail = "INVALID", "timeout"
            shutil.rmtree(root)
            if verdict != "RED":
                bad.append(label)
            print(f"{label}: {verdict} -- {tail}", flush=True)
    print(f"{len(chosen) - len(bad)} of {len(chosen)} red; not red: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
