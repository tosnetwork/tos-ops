#!/usr/bin/env python3
"""T1 resource and cache-diagnostics probe, read-only. It runs on a validator host as `python3 - [args]` over SSH.

  python3 - --path P [--path P ...] (--baseline | --cursors JSON) [--cap BYTES]   resources and diagnostics
  python3 - --du P [--du P ...]                                                   apparent sizes only

It prints one JSON object. Resources come first and carry `sample_clock`, the host time when they were read:
  unit   - tos-testnet-validator MainPID, NRestarts, ActiveState and ExecMainStartTimestampMonotonic
  proc   - RssAnon, VmRSS, RssFile, VmSwap and Threads of the MainPID, plus its open fd count
  mem    - MemTotal, MemAvailable, SwapTotal and SwapFree (bytes)
  oom_kill - the host's OOM-kill count since boot
  boot_id
  disks  - free bytes, size and free/total inodes of each --path (statvfs)
Then the validator logs are read from per-file cursors:
  files  - one entry per log file, keyed by "dev:ino" from fstat on the open descriptor (a rename keeps it): name,
           size, the offset read from (`start`), the offset consumed to (`offset`), the fingerprint of the bytes
           before it (`fp`) and a status (see read_logs).
  diag   - the "MEMORY_DIAGNOSTICS simplex-candidate-*" lines in the consumed bytes, parsed into key=integer fields.
  safety - every consumed line holding a SAFETY pattern (the T3 safety scan), on the same gap-checked coverage.
  missing - cursor ids no file has any more (the coordinator decides whether that lost data).
  clock  - this host's time.time() at the end.

It writes nothing and changes nothing. Every section that cannot be read is reported as an error string in its
place, never omitted.
"""

import argparse
import calendar
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import time

UNIT = "tos-testnet-validator"
LOG_GLOB = "/var/log/tos/validator/node.log*"
CAP = 32 * 1024 * 1024
DIAG = re.compile(r"MEMORY_DIAGNOSTICS (simplex-candidate-(?:payloads|resolver))((?: [a-z_]+=-?\d+)+)")
STAMP = re.compile(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")
FIELD = re.compile(r"([a-z_]+)=(-?\d+)")
# The safety lines of the T3 scan: a consensus misbehaviour report, or a vote against a decision already logged.
SAFETY = ("MISBEHAVIOR DETECTED kind=", "conflicts with a decision already recorded")


def unit() -> dict:
    out = subprocess.run(
        ["systemctl", "show", "-p", "MainPID", "-p", "NRestarts", "-p", "ActiveState",
         "-p", "ExecMainStartTimestampMonotonic", UNIT],
        capture_output=True, text=True, timeout=20, check=True,
    ).stdout
    v = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return {
        "main_pid": int(v["MainPID"]),
        "n_restarts": int(v["NRestarts"]),
        "active_state": v["ActiveState"],
        "exec_main_start_monotonic_us": int(v["ExecMainStartTimestampMonotonic"]),
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
    """Apparent sizes; a walk that does not exit 0 is an error, never a partial size."""
    out = {}
    for p in paths:
        try:
            r = subprocess.run(["du", "-sb", p], capture_output=True, text=True, timeout=500, check=False)
        except subprocess.TimeoutExpired:
            out[p] = "error: du timed out"
            continue
        fields = r.stdout.split()
        if r.returncode != 0 or len(fields) != 2 or not fields[0].isdigit():
            out[p] = f"error: rc={r.returncode} {r.stderr.strip()[:200]}"
        else:
            out[p] = int(fields[0])
    return out


def parse_diag(text: str, name: str) -> list:
    lines = []
    for line in text.splitlines():
        m = DIAG.search(line)
        s = STAMP.search(line) if m else None
        if not s:
            continue
        lines.append({"ts": calendar.timegm(time.strptime(s.group(1), "%Y-%m-%d %H:%M:%S")), "kind": m.group(1),
                      "fields": {k: int(v) for k, v in FIELD.findall(m.group(2))}, "file": name})
    return lines


FP_BYTES = 64


def fingerprint(fh, offset: int) -> str:
    """Hash of the bytes just before `offset`: a cursor is valid only while these bytes are unchanged."""
    fh.seek(max(0, offset - FP_BYTES))
    return hashlib.sha256(fh.read(min(offset, FP_BYTES))).hexdigest()[:32]


def scan_safety(text: str, name: str, out: list) -> None:
    for line in text.splitlines():
        if any(p in line for p in SAFETY):
            out.append({"file": name, "line": line[:600]})


def read_logs(cursors, files_glob: str = LOG_GLOB, cap: int = CAP, safety: list | None = None) -> tuple:
    """Read every log file from its cursor. `cursors` is {"dev:ino": [offset, fingerprint, closed]}, or None for a
    baseline; `closed` says the coordinator saw that file under a rotated name and read it to its end, so a change
    under the cursor means a new file reused the inode, not lost bytes.

    Each file entry reports `fp`, the fingerprint at its new offset, for the next call. Status of each file:
      baseline   - first observation: the cursor is set to the current size, nothing is read
      read       - bytes [start, offset) consumed; a trailing partial line is left for the next read
      new        - a file the cursors do not know, read from 0
      shrunk     - size below the cursor: the file was truncated or replaced in place, read from 0 (a gap)
      rewritten  - the bytes before the cursor changed (truncated and regrown, or a reused inode), read from 0
                   (a gap)
      over_cap   - `cap` bytes without a newline: consumed as a gap so that the cursor cannot stall
      duplicate  - another name for a file already read this time
      error: ... - could not be opened or read
    `behind` is the size not yet consumed; it is lag, read on the next call, not a gap.
    """
    files, lines, seen = {}, [], set()
    for path in sorted(glob.glob(files_glob)):
        name = os.path.basename(path)
        try:
            fh = open(path, "rb")
        except OSError as exc:
            files[f"name:{name}"] = {"name": name, "status": f"error: {exc}"}
            continue
        with fh:
            try:
                st = os.fstat(fh.fileno())
            except OSError as exc:
                files[f"name:{name}"] = {"name": name, "status": f"error: {exc}"}
                continue
            fid, size = f"{st.st_dev}:{st.st_ino}", st.st_size
            if fid in seen:
                files[f"dup:{name}"] = {"name": name, "id": fid, "status": "duplicate"}
                continue
            seen.add(fid)
            entry = {"name": name, "size": size}
            try:
                if cursors is None:
                    entry.update(start=size, offset=size, status="baseline", fp=fingerprint(fh, size))
                    files[fid] = entry
                    continue
                cursor, status = cursors.get(fid), "read"
                if cursor is None:
                    start, status = 0, "new"
                else:
                    start, fp, closed = cursor
                    changed = size < start or fingerprint(fh, start) != fp
                    if changed and closed:
                        # The old file was closed and fully read; this inode now belongs to a new file.
                        start, status = 0, "new"
                    elif size < start:
                        entry["gap_bytes"] = start
                        start, status = 0, "shrunk"
                    elif fingerprint(fh, start) != fp:
                        entry["gap_bytes"] = start
                        start, status = 0, "rewritten"
                fh.seek(start)
                data = fh.read(min(size - start, cap))
                cut = data.rfind(b"\n") + 1
                if cut == 0 and len(data) >= cap:
                    entry["gap_bytes"] = entry.get("gap_bytes", 0) + len(data)
                    cut, status = len(data), "over_cap"
                else:
                    text = data[:cut].decode("utf-8", "replace")
                    lines.extend(parse_diag(text, name))
                    if safety is not None:
                        scan_safety(text, name, safety)
                entry.update(start=start, offset=start + cut, status=status, behind=size - (start + cut),
                             fp=fingerprint(fh, start + cut))
            except OSError as exc:
                entry.update(status=f"error: {exc}")
            files[fid] = entry
    missing = sorted(set(cursors or {}) - seen)
    lines.sort(key=lambda d: (d["ts"], d["kind"], d["file"]))
    return files, lines, missing


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", action="append", default=[])
    ap.add_argument("--du", action="append", default=[])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--baseline", action="store_true")
    mode.add_argument("--cursors", default=None)
    ap.add_argument("--cap", type=int, default=CAP)
    a = ap.parse_args(argv)
    if a.du:
        print(json.dumps({"du": du(a.du), "clock": time.time()}))
        return 0
    report = {}
    for name, fn in (("unit", unit), ("mem", meminfo), ("oom_kill", oom_kills)):
        try:
            report[name] = fn()
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            report[name] = f"error: {type(exc).__name__}: {exc}"
    pid = report["unit"].get("main_pid", 0) if isinstance(report["unit"], dict) else 0
    try:
        report["proc"] = proc(pid)
    except (OSError, ValueError, IndexError) as exc:
        report["proc"] = f"error: {exc}"
    try:
        with open("/proc/sys/kernel/random/boot_id") as fh:
            report["boot_id"] = fh.read().strip()
    except OSError as exc:
        report["boot_id"] = f"error: {exc}"
    report["disks"] = disks(a.path)
    report["sample_clock"] = time.time()
    if a.baseline or a.cursors is not None:
        cursors = None if a.baseline else {
            k: (int(v[0]), str(v[1]), v[2] is True) for k, v in json.loads(a.cursors).items()}
        report["safety"] = []
        report["files"], report["diag"], report["missing"] = read_logs(cursors, cap=a.cap, safety=report["safety"])
    report["clock"] = time.time()
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
