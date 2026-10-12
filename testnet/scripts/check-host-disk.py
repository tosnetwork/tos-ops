#!/usr/bin/env python3
"""Report a testnet host's validator disk use and refuse when free space is low.

  check-host-disk.py [--db /var/lib/tos/validator] [--min-free-gib 15]

Runs on the host. Prints one JSON line:

  * free and total bytes of the filesystem holding the database;
  * the size of the database's consensus/ directory and its number of session
    directories.

Until retired consensus sessions are deleted before the first key block, the
consensus directory grows by about 100 MB a minute (17 groups per rotation,
about 18 MB each). The testnet schedule bounds that to about 10 h, which is
about 60 GB. Exits 1 when free space is below --min-free-gib, so the operator
acts before the disk fills.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

GIB = 1 << 30


def tree_bytes(root: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total


def check(db: Path, min_free_gib: float) -> dict:
    if not db.is_dir():
        raise OSError(f"{db} is not a directory")
    fs = os.statvfs(db)
    free = fs.f_bavail * fs.f_frsize
    total = fs.f_blocks * fs.f_frsize
    consensus = db / "consensus"
    sessions = sum(1 for p in consensus.iterdir() if p.is_dir()) if consensus.is_dir() else 0
    report = {
        "db": str(db),
        "free_bytes": free,
        "total_bytes": total,
        "consensus_bytes": tree_bytes(consensus) if consensus.is_dir() else 0,
        "consensus_sessions": sessions,
        "min_free_bytes": int(min_free_gib * GIB),
    }
    report["ok"] = free >= report["min_free_bytes"]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--db", type=Path, default=Path("/var/lib/tos/validator"))
    parser.add_argument("--min-free-gib", type=float, default=15.0)
    args = parser.parse_args(argv)
    if args.min_free_gib < 0:
        parser.error("--min-free-gib must not be negative")
    try:
        report = check(args.db, args.min_free_gib)
    except OSError as exc:
        print(json.dumps({"ok": False, "refused": str(exc)}))
        return 1
    print(json.dumps(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
