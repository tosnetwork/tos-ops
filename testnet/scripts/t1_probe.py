#!/usr/bin/env python3
"""T1 resource and cache-diagnostics probe, read-only. It runs on a validator host as `python3 - [args]` over SSH.

It prints one JSON object:
  unit   - tos-testnet-validator MainPID, NRestarts, ActiveState and ExecMainStartTimestampMonotonic
  proc   - RssAnon, VmRSS, RssFile, VmSwap and Threads of the MainPID, plus its open fd count
  mem    - MemTotal, MemAvailable, SwapTotal and SwapFree (bytes)
  oom_kill - the host's OOM-kill count since boot
  boot_id
  disks  - free bytes, size and free/total inodes of each --path (statvfs)
  du     - apparent size of each --du path, only when --du is given (an expensive walk)
  diag   - "MEMORY_DIAGNOSTICS simplex-candidate-*" lines in the validator logs dated after --diag-since,
           parsed into key=integer fields (UTC timestamps, per file)
  diag_files - each log file read: name, mtime, bytes read and status, so that missing coverage is visible
  clock  - this host's time.time(), for the coordinator's clock check

It writes nothing and changes nothing. Every section that cannot be read is reported as an error string in its
place, never omitted.
"""

import argparse
import calendar
import glob
import json
import os
import re
import subprocess
import sys
import time

UNIT = "tos-testnet-validator"
LOG_GLOB = "/var/log/tos/validator/node.log*"
TAIL_BYTES = 4 * 1024 * 1024
DIAG = re.compile(r"MEMORY_DIAGNOSTICS (simplex-candidate-(?:payloads|resolver))((?: [a-z_]+=-?\d+)+)")
STAMP = re.compile(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")
FIELD = re.compile(r"([a-z_]+)=(-?\d+)")


def unit() -> dict:
    out = subprocess.run(
        ["systemctl", "show", "-p", "MainPID", "-p", "NRestarts", "-p", "ActiveState",
         "-p", "ExecMainStartTimestampMonotonic", UNIT],
        capture_output=True, text=True, timeout=20, check=False,
    ).stdout
    v = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return {
        "main_pid": int(v.get("MainPID", "0") or 0),
        "n_restarts": int(v.get("NRestarts", "0") or 0),
        "active_state": v.get("ActiveState", ""),
        "exec_main_start_monotonic_us": int(v.get("ExecMainStartTimestampMonotonic", "0") or 0),
    }


def proc(pid: int):
    if pid <= 0:
        return "no main pid"
    status = {}
    with open(f"/proc/{pid}/status") as fh:
        for line in fh:
            key, _, rest = line.partition(":")
            if key in ("RssAnon", "VmRSS", "RssFile", "VmSwap"):
                status[key] = int(rest.split()[0]) * 1024
            elif key == "Threads":
                status[key] = int(rest.split()[0])
    status["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    return status


def meminfo() -> dict:
    out = {}
    with open("/proc/meminfo") as fh:
        for line in fh:
            key, _, rest = line.partition(":")
            if key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
                out[key] = int(rest.split()[0]) * 1024
    return out


def oom_kills() -> int:
    """The host's cumulative OOM-kill count since boot (/proc/vmstat oom_kill)."""
    with open("/proc/vmstat") as fh:
        for line in fh:
            key, _, value = line.partition(" ")
            if key == "oom_kill":
                return int(value)
    raise ValueError("/proc/vmstat has no oom_kill")


def disks(paths: list) -> dict:
    out = {}
    for p in paths:
        try:
            st = os.statvfs(p)
            out[p] = {
                "free_bytes": st.f_bavail * st.f_frsize,
                "size_bytes": st.f_blocks * st.f_frsize,
                "free_inodes": st.f_favail,
                "total_inodes": st.f_files,
            }
        except OSError as exc:
            out[p] = f"error: {exc}"
    return out


def du(paths: list) -> dict:
    out = {}
    for p in paths:
        r = subprocess.run(["du", "-sb", p], capture_output=True, text=True, timeout=600, check=False)
        try:
            out[p] = int(r.stdout.split()[0])
        except (IndexError, ValueError):
            out[p] = f"error: rc={r.returncode} {r.stderr.strip()[:200]}"
    return out


def diag(since: float, files_glob: str = LOG_GLOB) -> tuple:
    """Diagnostics lines dated after `since`, from every log file modified within the window."""
    lines, files = [], []
    for path in sorted(glob.glob(files_glob)):
        try:
            mtime = os.path.getmtime(path)
        except OSError as exc:
            files.append({"file": path, "status": f"error: {exc}"})
            continue
        if mtime < since:
            files.append({"file": path, "mtime": mtime, "status": "skipped: not modified in the window"})
            continue
        if path.endswith(".gz"):
            files.append({"file": path, "mtime": mtime, "status": "skipped: compressed (rotated before the window)"})
            continue
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as fh:
                fh.seek(max(0, size - TAIL_BYTES))
                data = fh.read().decode("utf-8", "replace")
        except OSError as exc:
            files.append({"file": path, "mtime": mtime, "status": f"error: {exc}"})
            continue
        files.append({"file": path, "mtime": mtime, "status": "read",
                      "bytes_read": min(size, TAIL_BYTES), "truncated": size > TAIL_BYTES})
        for line in data.splitlines():
            m = DIAG.search(line)
            if not m:
                continue
            s = STAMP.search(line)
            if not s:
                continue
            ts = calendar.timegm(time.strptime(s.group(1), "%Y-%m-%d %H:%M:%S"))
            if ts <= since:
                continue
            lines.append({"ts": ts, "kind": m.group(1), "fields": {k: int(v) for k, v in FIELD.findall(m.group(2))},
                          "file": os.path.basename(path)})
    lines.sort(key=lambda d: (d["ts"], d["kind"], d["file"]))
    return lines, files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", action="append", default=[])
    ap.add_argument("--du", action="append", default=[])
    ap.add_argument("--diag-since", type=float, default=None)
    a = ap.parse_args(argv)
    report = {}
    for name, fn in (("unit", unit), ("mem", meminfo), ("oom_kill", oom_kills)):
        try:
            report[name] = fn()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            report[name] = f"error: {exc}"
    pid = report["unit"].get("main_pid", 0) if isinstance(report["unit"], dict) else 0
    try:
        report["proc"] = proc(pid)
    except (OSError, ValueError) as exc:
        report["proc"] = f"error: {exc}"
    try:
        with open("/proc/sys/kernel/random/boot_id") as fh:
            report["boot_id"] = fh.read().strip()
    except OSError as exc:
        report["boot_id"] = f"error: {exc}"
    report["disks"] = disks(a.path)
    if a.du:
        report["du"] = du(a.du)
    if a.diag_since is not None:
        report["diag"], report["diag_files"] = diag(a.diag_since)
    report["clock"] = time.time()
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
