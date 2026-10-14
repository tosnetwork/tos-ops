#!/usr/bin/env python3
"""Report a testnet host's validator disk and process health; refuse when free space is low.

  check-host-disk.py [--db /var/lib/tos/validator] [--min-free-gib 15]
                     [--unit tos-testnet-validator]
                     [--rpc http://127.0.0.1:8081/jsonRPC]
                     [--metrics http://127.0.0.1:9100/metrics]
                     [--cpu-sample 0]

Runs on the host (standard library only, so the coordinator can also pipe it
over SSH: `ssh host python3 - [args] < check-host-disk.py`). Prints one JSON
line:

  * free and total bytes of the filesystem holding the database;
  * the size of the database's consensus/ directory and its number of session
    directories;
  * the validator unit's state, restart count and resident memory;
  * the node's masterchain head seqno from its loopback JSON-RPC;
  * from its loopback exporter: masterchain head age, shard client age, block
    download net failures and refused-answer counts;
  * with --cpu-sample N, host CPU busy and iowait percentages over N seconds.

A value that could not be observed is null, never 0: zero means an observed
zero.

Retired consensus sessions are deleted at each key block: on the public
testnet's 4 h terms `consensus/` grows about 10 MB a minute idle (about 31 MB
a minute under a ~6.4M gas per block load) and shrinks after every election.
Exits 1 when free space is below --min-free-gib, so the operator acts before
the disk fills. The other fields are reported, not judged; watch-testnet.py
judges them across samples.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

GIB = 1 << 30

# Exporter series reported as-is, keyed by the field name in the report.
METRICS = {
    "head_age_seconds": "tos_masterchain_head_age_seconds",
    "shard_client_age_seconds": "tos_shard_client_age_seconds",
    "net_failures_total": "tos_wait_block_data_net_failures_total",
    "refusal_answers_total": "tos_full_node_refusal_answers_total",
}


def tree_bytes(root: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total


def parse_metrics(text: str) -> dict:
    """The METRICS series from Prometheus text; an absent series is None."""
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, rest = line.partition(" ")
        base = name.partition("{")[0]
        if base in values:
            continue
        try:
            values[base] = float(rest.split()[0])
        except (IndexError, ValueError):
            continue
    return {field: values.get(series) for field, series in METRICS.items()}


def read_metrics(url: str | None) -> dict:
    if not url:
        return dict.fromkeys(METRICS)
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return parse_metrics(response.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return dict.fromkeys(METRICS)


def read_head_seqno(url: str | None) -> int | None:
    if not url:
        return None
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "getMasterchainInfo", "params": {}}
    ).encode()
    request = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return int(json.load(response)["result"]["last"]["seqno"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def unit_status(unit: str | None) -> dict:
    """systemd state, restart count and the main process's resident bytes."""
    status = {"unit_active": None, "unit_restarts": None, "rss_bytes": None}
    if not unit:
        return status
    try:
        shown = subprocess.run(
            ["systemctl", "show", unit, "-p", "ActiveState", "-p", "NRestarts", "-p", "MainPID"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return status
    props = dict(line.partition("=")[::2] for line in shown.splitlines() if "=" in line)
    status["unit_active"] = props.get("ActiveState") or None
    if props.get("NRestarts", "").isdigit():
        status["unit_restarts"] = int(props["NRestarts"])
    pid = props.get("MainPID", "")
    if pid.isdigit() and int(pid) > 0:
        try:
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    status["rss_bytes"] = int(line.split()[1]) * 1024
                    break
        except (OSError, ValueError, IndexError):
            pass
    return status


def cpu_times() -> list[int]:
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:8]
    return [int(v) for v in fields]


def cpu_usage(seconds: float, sleep=time.sleep, read=cpu_times) -> dict:
    """Busy and iowait percentages of all CPUs over `seconds`."""
    if seconds <= 0:
        return {"cpu_busy_pct": None, "cpu_iowait_pct": None}
    try:
        first = read()
        sleep(seconds)
        second = read()
    except (OSError, ValueError, IndexError):
        return {"cpu_busy_pct": None, "cpu_iowait_pct": None}
    delta = [b - a for a, b in zip(first, second)]
    total = sum(delta)
    if total <= 0:
        return {"cpu_busy_pct": None, "cpu_iowait_pct": None}
    idle, iowait = delta[3], delta[4]
    return {
        "cpu_busy_pct": round(100 * (total - idle - iowait) / total, 1),
        "cpu_iowait_pct": round(100 * iowait / total, 1),
    }


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
    parser.add_argument("--unit", default="tos-testnet-validator", help="'' to skip")
    parser.add_argument("--rpc", default="http://127.0.0.1:8081/jsonRPC", help="'' to skip")
    parser.add_argument("--metrics", default="http://127.0.0.1:9100/metrics", help="'' to skip")
    parser.add_argument("--cpu-sample", type=float, default=0.0)
    args = parser.parse_args(argv)
    if args.min_free_gib < 0:
        parser.error("--min-free-gib must not be negative")
    if args.cpu_sample < 0 or args.cpu_sample > 60:
        parser.error("--cpu-sample must be between 0 and 60 seconds")
    try:
        report = check(args.db, args.min_free_gib)
    except OSError as exc:
        print(json.dumps({"ok": False, "refused": str(exc)}))
        return 1
    report.update(unit_status(args.unit))
    report["head_seqno"] = read_head_seqno(args.rpc)
    report.update(read_metrics(args.metrics))
    report.update(cpu_usage(args.cpu_sample))
    print(json.dumps(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
