#!/usr/bin/env python3
"""Host-resource stop guard for testnet load runs (T2, T4): the T1 stop rules, without a workload.

  load-guard.py --status STATUS.json --snapshot SNAP.json --stop-file PATH [--once]

The rules are t1-load.py's, imported from it unchanged (status_reasons): the observer status is fresh, not
blind, from this boot, with no safety line, no coverage gap, no operator under its floor and no stall on three
or more hosts; and every validator is active, with MainPID, NRestarts, boot id and OOM count as in the
snapshot, MemAvailable >= 2 GiB, and every data path at >= 20 GiB and >= 1M inodes free.

- The first run writes the snapshot from the current status; later runs compare with it. A run after a
  deliberate restart needs a new snapshot path.
- Without --once it checks every --interval seconds. On the first reason it writes the stop file (the T4 ramp
  stops new submissions when it appears, bench/t4/ramp.py --stop-file) with the reasons, and exits 1.
- With --once it checks once and exits 0 when the load may continue (a T2 burst may start) or 1 when it may
  not; it also writes the stop file then.

Exit status: 0 green (--once), 1 stop, 2 refused (no complete status to snapshot, or bad arguments).
"""

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GiB = 1 << 30
RULES = {"floors": {"mem_available_bytes": 2 * GiB, "disk_free_bytes": 20 * GiB, "disk_free_inodes": 1_000_000},
         "status_stale_s": 90}


def t1_load():
    spec = importlib.util.spec_from_file_location("t1_load", HERE / "t1-load.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_snapshot(tl, path: Path, status: Path) -> dict:
    if path.exists():
        return {h: tuple(v) for h, v in json.loads(path.read_text()).items()}
    st = tl.read_status(status)
    snap = tl.host_snapshot(st if isinstance(st, dict) else {})
    path.write_text(json.dumps(snap))
    return snap


def check(tl, status: Path, snap: dict, boot: str, now_mono: float) -> list[str]:
    return tl.status_reasons(tl.read_status(status), snap, RULES, now_mono, boot)


def stop(path: Path, reasons: list[str]) -> None:
    path.write_text(json.dumps({"time": time.time(), "reasons": reasons}) + "\n")


def main(argv=None, mono=time.monotonic, sleep=time.sleep) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                 allow_abbrev=False)
    ap.add_argument("--status", type=Path, required=True, help="the observer's status.json")
    ap.add_argument("--snapshot", type=Path, required=True, help="identity snapshot; written on the first run")
    ap.add_argument("--stop-file", type=Path, required=True)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=float, default=10.0)
    a = ap.parse_args(argv)
    tl = t1_load()
    try:
        snap = load_snapshot(tl, a.snapshot, a.status)
    except (tl.Refuse, OSError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    boot = tl.boot_id()
    while True:
        reasons = check(tl, a.status, snap, boot, mono())
        if reasons:
            stop(a.stop_file, reasons)
            print("STOP: " + "; ".join(reasons), flush=True)
            return 1
        if a.once:
            print("GREEN", flush=True)
            return 0
        sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
