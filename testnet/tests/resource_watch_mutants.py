#!/usr/bin/env python3
"""Missing-row and alert mutants for the two resource monitors; every one must go red.

Each mutant is applied to a fresh copy of testnet/ in a temporary directory, so
the checkout is never modified. Only pytest's exit 1 with a failed test counts
as RED; a pattern that does not occur exactly once, a mutant that does not
parse, a green baseline failure, a survivor or an invalid run fails the whole run.

    unshare -rn python testnet/tests/resource_watch_mutants.py [LABEL ...]

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
EXTRA = "scripts/watch_extra_resources.py"
PRIMARY = "scripts/watch-testnet.py"
TESTS = {
    EXTRA: ["tests/test_watch_extra_resources.py"],
    PRIMARY: ["tests/test_watch_testnet.py", "tests/test_watch_testnet_missing.py"],
}
FAILED = re.compile(r"\b[1-9]\d* failed\b")
ERRORS = re.compile(r"\b[1-9]\d* errors?\b")

M = [
    (
        "E1 extra: raise on a failed host read restored",
        EXTRA,
        "    return host.name, None, reason\n",
        '    raise RuntimeError("Host resource observation unavailable: " + host.name)\n',
    ),
    (
        "E2 extra: a timeout ends the watch again",
        EXTRA,
        "    except subprocess.TimeoutExpired:\n        return None, PROBE_TIMEOUT_REASON\n",
        "",
    ),
    (
        "E3 extra: missing row dropped",
        EXTRA,
        "                append(stream, record)\n                if alert:\n",
        "                if alert:\n",
    ),
    (
        "E4 extra: alerts on every cycle",
        EXTRA,
        "        if host not in self.alerted and monotonic - first >= self.alert_after:\n",
        "        if True:\n",
    ),
    (
        "E5 extra: alerts every cycle after ten minutes",
        EXTRA,
        "        if host not in self.alerted and monotonic - first >= self.alert_after:\n",
        "        if monotonic - first >= self.alert_after:\n",
    ),
    (
        "E6 extra: never alerts",
        EXTRA,
        "            return first_unix, True\n",
        "            return first_unix, False\n",
    ),
    (
        "E7 extra: alert never re-armed after recovery",
        EXTRA,
        "        self.alerted.discard(host)\n",
        "        pass\n",
    ),
    (
        "E8 extra: partial cycle published as LATEST",
        EXTRA,
        "            if missing:\n                append(\n",
        "            if False:\n                append(\n",
    ),
    (
        "E9 extra: stale clock tolerated",
        EXTRA,
        '                raise RuntimeError("Host observation clock stale")\n',
        "                pass\n",
    ),
    (
        "E10 extra: baseline not checked while a host is missing",
        EXTRA,
        "            if baseline is not None:\n                for name in current:\n",
        "            if baseline is not None and not missing:\n                for name in current:\n",
    ),
    (
        "E11 extra: child output written as the reason",
        EXTRA,
        "        return None, SSH_FAILED if child.returncode == 255 else PROBE_FAILED\n",
        "        return None, str(child.stderr)\n",
    ),
    (
        "P1 primary: a missing host ends the watch",
        PRIMARY,
        "            report, reason = probe(h, args.cpu_sample)\n",
        "            report, reason = probe(h, args.cpu_sample)\n"
        "            if report is None:\n"
        '                raise lib.TestnetError("host unavailable")\n',
    ),
    (
        "P2 primary: malformed probe output passed to row()",
        PRIMARY,
        "    if not valid_report(report):\n        return None, OUTPUT_INVALID\n",
        "",
    ),
    (
        "P3 primary: missing row dropped",
        PRIMARY,
        "            rows.append(row(now(), h.name, report, reason))\n",
        "            if report is not None:\n"
        "                rows.append(row(now(), h.name, report, reason))\n",
    ),
    (
        "P4 primary: missing reason not written",
        PRIMARY,
        '        out["missing_reason"] = reason if reason in MISSING_REASONS else NO_OUTPUT\n',
        "",
    ),
    (
        "P5 primary: alerts on every round",
        PRIMARY,
        "        if name in self.alerted or at - first < self.after:\n",
        "        if False:\n",
    ),
    (
        "P6 primary: alerts every round after ten minutes",
        PRIMARY,
        "        if name in self.alerted or at - first < self.after:\n",
        "        if at - first < self.after:\n",
    ),
    (
        "P7 primary: never alerts",
        PRIMARY,
        "        return f\"{name}:missing_for={int(at - first)}s reason={current['missing_reason']}\"\n",
        "        return None\n",
    ),
    (
        "P8 primary: alert never re-armed after recovery",
        PRIMARY,
        "            self.alerted.discard(name)\n",
        "            pass\n",
    ),
    (
        "P9 primary: missing samples no longer latch the anomaly",
        PRIMARY,
        '                getattr(args, "require_load_metrics", False)\n'
        "                or self.unreachable[name] >= args.unreachable_samples\n",
        "                self.unreachable[name] >= args.unreachable_samples\n",
    ),
]


def suite(root: Path, tests: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests],
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
    sources = {target: (W / target).read_text() for target in TESTS}
    chosen = [m for m in M if not only or m[0].split()[0] in only]
    for label, target, old, new in chosen:
        source = sources[target]
        if source.count(old) != 1:
            print(f"FAIL: {label}: pattern occurs {source.count(old)} times")
            return 1
        ast.parse(source.replace(old, new))
    with tempfile.TemporaryDirectory(prefix="resource-watch-mutants-") as scratch:
        scratch = Path(scratch)
        baseline = suite(copy(scratch, "baseline"), [t for ts in TESTS.values() for t in ts])
        if baseline.returncode != 0:
            print("FAIL: the unmutated suite is not green")
            return 1
        bad = []
        for n, (label, target, old, new) in enumerate(chosen):
            root = copy(scratch, f"m{n}")
            (root / target).write_text(sources[target].replace(old, new))
            try:
                result = suite(root, TESTS[target])
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
