#!/usr/bin/env python3
"""Red controls for the monitor loop's stale-tick handling, on disposable copies.

Each control removes one guard and requires the named test to fail the stated
way: without TestnetError in the caught set, a rate-limited read escapes the
loop (the crash of 2026-11-27 23:57 UTC); with TypeError caught, a programming
error is swallowed as STALE; without the back-off bound, the delay grows past
MAX_BACKOFF_SECONDS. Never accesses a running network.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = "local/scripts/local-settlement-monitor.py"
TEST = "local/tests/test_local_settlement_monitor.py"
CASES = [
    (
        "testnet-error-crashes",
        "    u.lib.TestnetError,\n",
        "",
        "test_a_refused_read_is_a_stale_tick_not_a_crash",
        "RpcError",
    ),
    (
        "type-error-swallowed",
        "    u.lib.TestnetError,\n",
        "    u.lib.TestnetError,\n    TypeError,\n",
        "test_a_programming_error_ends_the_loop",
        "DID NOT RAISE",
    ),
    (
        "unbounded-back-off",
        "return min(MAX_BACKOFF_SECONDS, interval * 2 ** min(failures - 1, 6))",
        "return interval * 2 ** (failures - 1)",
        "test_stale_back_off_is_bounded_and_resets_on_success",
        "assert ",
    ),
]


def run(root, selection, log):
    with log.open("w") as stream:
        return subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=short", *selection],
            cwd=root,
            env=os.environ,
            stdout=stream,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        ).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    if run(ROOT, [TEST], args.log_dir / "baseline.log"):
        raise RuntimeError("invalid positive baseline")
    for label, before, after, test, expected in CASES:
        with tempfile.TemporaryDirectory(prefix="monitor-loop-control-") as temp:
            root = Path(temp)
            for item in ("local", "testnet", "conftest.py", "pyproject.toml"):
                source = ROOT / item
                if source.is_dir():
                    shutil.copytree(
                        source,
                        root / item,
                        ignore=shutil.ignore_patterns("__pycache__"),
                    )
                elif source.exists():
                    shutil.copy2(source, root / item)
            path = root / SCRIPT
            text = path.read_text()
            if text.count(before) != 1:
                raise RuntimeError("ambiguous control: " + label)
            path.write_text(text.replace(before, after))
            log = args.log_dir / (label + ".log")
            code = run(root, [TEST, "-k", test], log)
            output = log.read_text()
            if code != 1 or "failed" not in output or expected not in output:
                raise RuntimeError("survived or invalid control: " + label)
        print(label + ": assertion-red", flush=True)
    print(f"{len(CASES)}/{len(CASES)} assertion-red")


if __name__ == "__main__":
    main()
