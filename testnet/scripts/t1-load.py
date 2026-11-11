#!/usr/bin/env python3
"""T1 load supervisor (memo public-testnet/T1-PRB-DESIGN-20261110 v3.1).

  t1-load.py --record RECORD.json --record-sha256 HEX --status STATUS.json --out NEW_DIR

Runs, as children, the tos T4 ramp sender (writes) and sustained_read_load.py in its T1 profile (reads), both
configured only from the frozen acceptance record (whose sha256 must match), and stops both on the first T1 stop
condition (T1-PLAN §6), at the T+72 h signing cutoff, or when either exits on its own. It never restarts or
adopts a submitter: after any stop, monitoring continues elsewhere and the stopped interval stays visible.

Containment: each child runs in its own process group with PR_SET_PDEATHSIG = SIGKILL, so it dies with this
process; run this under a systemd unit with KillMode=control-group and Restart=no for the window before the
signal is armed. Children write stdout/stderr to files, never to a pipe.

Every decision is a line in OUT/load.jsonl: start, each stop reason, the termination check and the end.
Exit status: 0 when the run ended at the cutoff with no stop condition, 1 when it was stopped, 2 when it refused
to start.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
HOSTS = ("node-1", "node-2", "node-3", "node-4")
PR_SET_PDEATHSIG = 1
TICK = 5.0
TERM_GRACE = 10.0
DURATION = 259_200  # T1-PLAN: 72 h of signing
ROW_MAX_AGE = 180.0  # a host's latest resource row older than this stops the run
REQUIRED = {
    "tos_checkout": str, "tos_rev": str, "signer": str, "signer_sha256": str, "key_file": str, "auth_tag": str,
    "ramp": dict, "reads": dict, "floors": dict, "unresolved": dict, "status_stale_s": (int, float),
}
RAMP_REQUIRED = ("batch", "wallets", "wallet_funding", "max_cost", "max_transfers", "rpc")
READS_REQUIRED = ("address", "network_deadline_seconds", "window_seconds")
FLOORS_REQUIRED = ("mem_available_bytes", "disk_free_bytes", "disk_free_inodes")
UNRESOLVED_REQUIRED = ("max_age_s", "max_count")


class Refuse(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- the record


def load_record(path: Path, expected_sha: str) -> dict:
    if not path.is_file():
        raise Refuse(f"no acceptance record at {path}")
    if sha256_file(path) != expected_sha:
        raise Refuse("acceptance record sha256 does not match --record-sha256")
    rec = json.loads(path.read_text())
    if not isinstance(rec, dict):
        raise Refuse("acceptance record is not an object")
    for key, kind in REQUIRED.items():
        if not isinstance(rec.get(key), kind) or isinstance(rec.get(key), bool):
            raise Refuse(f"acceptance record lacks a valid {key}")
    for section, keys in (("ramp", RAMP_REQUIRED), ("reads", READS_REQUIRED), ("floors", FLOORS_REQUIRED),
                          ("unresolved", UNRESOLVED_REQUIRED)):
        for k in keys:
            if rec[section].get(k) in (None, "", []):
                raise Refuse(f"acceptance record lacks {section}.{k}")
    if not (isinstance(rec["ramp"]["rpc"], list) and len(rec["ramp"]["rpc"]) == 4):
        raise Refuse("ramp.rpc must name the four validator tunnels")
    return rec


def check_inputs(rec: dict, run=subprocess.run) -> None:
    head = run(["git", "-C", rec["tos_checkout"], "rev-parse", "HEAD"], capture_output=True, text=True,
               timeout=30, check=False).stdout.strip()
    if head != rec["tos_rev"]:
        raise Refuse(f"tos checkout is at {head or 'nothing'}, not {rec['tos_rev']}")
    if sha256_file(Path(rec["signer"])) != rec["signer_sha256"]:
        raise Refuse("signer sha256 does not match the record")
    key = Path(rec["key_file"])
    if key.stat().st_mode & 0o077 or key.parent.stat().st_mode & 0o077:
        raise Refuse("the bench key file or its directory is readable by others")


def ramp_argv(rec: dict, out: Path) -> list[str]:
    r = rec["ramp"]
    argv = [sys.executable, str(Path(rec["tos_checkout"]) / "bench" / "run_t4_ramp.py"),
            "--out", str(out / "ramp"), "--key-file", rec["key_file"], "--signer", rec["signer"],
            "--auth-tag", rec["auth_tag"], "--build", str(Path(rec["tos_checkout"]) / "build"),
            "--wallets", str(r["wallets"]), "--batch", str(r["batch"]),
            "--start-rate", "2", "--factor", "1", "--steps", "3", "--step-seconds", "86400",
            "--layout-repeats", "0", "--tolerance", "0.5", "--p95-limit", "600",
            "--wallet-funding", str(r["wallet_funding"]), "--max-cost", str(r["max_cost"]),
            "--max-transfers", str(r["max_transfers"]), "--rpc-share", "0.25"]
    for url in r["rpc"]:
        argv += ["--rpc", url]
    return argv


def read_packet(rec: dict, out: Path) -> dict:
    import read_client  # the endpoint pins live there
    r = rec["reads"]
    return {"profile": "t1", "duration_seconds": DURATION, "requests_per_second": 8,
            "window_seconds": r["window_seconds"], "endpoints": list(read_client.T1_ENDPOINTS),
            "address": r["address"], "network_deadline_seconds": r["network_deadline_seconds"],
            "output": str(out / "reads")}


# ---------------------------------------------------------------- stop rules from the observer's status


def host_snapshot(st: dict) -> dict:
    snap = {}
    for h in HOSTS:
        row = (st.get("hosts") or {}).get(h)
        if not (isinstance(row, dict) and row.get("complete") is True and isinstance(row.get("unit"), dict)):
            raise Refuse(f"{h}: no complete resource row to snapshot")
        snap[h] = (row["unit"].get("main_pid"), row["unit"].get("n_restarts"), row.get("boot_id"), row.get("oom_kill"))
    return snap


def status_reasons(st, snapshot: dict, rec: dict, now_mono: float, boot_id: str) -> list[str]:
    """Every T1 §6 stop condition the observer's status shows; empty means keep going."""
    if not isinstance(st, dict):
        return ["status unreadable"]
    out = []
    for key in ("blind", "updated_mono", "coordinator_boot_id", "stalled_hosts", "safety_hits", "coverage_gaps",
                "operators_low", "hosts"):
        if key not in st:
            out.append(f"status lacks {key}")
    if out:
        return out
    if st["coordinator_boot_id"] != boot_id:
        return ["status comes from another boot"]
    if type(st["updated_mono"]) not in (int, float) or now_mono - st["updated_mono"] > rec["status_stale_s"]:
        out.append("status is stale")
    if st["blind"] is not False:
        out.append(f"blind: {st.get('reasons')}")
    if len(st["stalled_hosts"]) >= 3:
        out.append(f"stall on {st['stalled_hosts']}")
    if st["safety_hits"] != 0:
        out.append(f"safety lines: {st['safety_hits']}")
    if st["coverage_gaps"] != 0:
        out.append(f"log coverage gaps: {st['coverage_gaps']}")
    if st["operators_low"]:
        out.append(f"operators below the floor: {st['operators_low']}")
    floors = rec["floors"]
    for h in HOSTS:
        row = st["hosts"].get(h)
        if not isinstance(row, dict):
            out.append(f"{h}: no resource row")
            continue
        if row.get("complete") is not True:
            out.append(f"{h}: latest resource row incomplete: {row.get('missing') or row.get('error')}")
            continue
        if type(row.get("received_mono")) not in (int, float) or now_mono - row["received_mono"] > ROW_MAX_AGE:
            out.append(f"{h}: latest resource row too old")
        unit = row["unit"]
        if unit.get("active_state") != "active":
            out.append(f"{h}: validator {unit.get('active_state')}")
        if (unit.get("main_pid"), unit.get("n_restarts"), row.get("boot_id"), row.get("oom_kill")) != snapshot[h]:
            out.append(f"{h}: restart, reboot or OOM since the start")
        if row["mem"]["MemAvailable"] < floors["mem_available_bytes"]:
            out.append(f"{h}: MemAvailable below the floor")
        for path, d in row["disks"].items():
            if d["free_bytes"] < floors["disk_free_bytes"] or d["free_inodes"] < floors["disk_free_inodes"]:
                out.append(f"{h}: {path} below the disk floor")
    return out


# ---------------------------------------------------------------- unresolved deliveries from the ramp journal


class JournalTail:
    """Follows the ramp's journal.jsonl and keeps every action of an executed external without a delivery."""

    def __init__(self, path: Path):
        self.path, self.offset, self.partial = path, 0, b""
        self.actions: dict[str, int] = {}  # attempt id -> number of actions
        self.pending: dict[tuple[str, int], float] = {}  # (attempt id, action) -> when its sender was observed

    def poll(self, now: float) -> None:
        if not self.path.exists():
            return
        with self.path.open("rb") as fh:
            fh.seek(self.offset)
            data = fh.read()
        self.offset += len(data)
        data = self.partial + data
        lines = data.split(b"\n")
        self.partial = lines.pop()  # a torn or unfinished last line waits for its end
        for raw in lines:
            if not raw.strip():
                continue
            rec = json.loads(raw)
            kind, aid = rec.get("type"), rec.get("id")
            if kind == "attempt":
                self.actions[aid] = len(rec.get("actions") or [])
            elif kind == "observed" and not rec.get("failure"):
                for i in range(self.actions.get(aid, 0)):
                    self.pending.setdefault((aid, i), now)
            elif kind == "delivered":
                self.pending.pop((aid, rec.get("action")), None)

    def reasons(self, now: float, limits: dict) -> list[str]:
        out = []
        if len(self.pending) > limits["max_count"]:
            out.append(f"{len(self.pending)} undelivered actions (limit {limits['max_count']})")
        oldest = min(self.pending.values(), default=None)
        if oldest is not None and now - oldest > limits["max_age_s"]:
            out.append(f"an action undelivered for {now - oldest:.0f} s (limit {limits['max_age_s']} s)")
        return out


# ---------------------------------------------------------------- children


def contained(parent: int) -> Callable[[], None]:
    """preexec_fn: own process group, and SIGKILL when the supervisor dies."""
    def setup() -> None:
        os.setpgrp()
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            os._exit(127)
        if os.getppid() != parent:  # the supervisor died before the signal was armed
            os._exit(127)
    return setup


def spawn(argv: list[str], log: Path, cwd: str | None = None, env: dict | None = None) -> subprocess.Popen:
    fh = log.open("ab")
    try:
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT, cwd=cwd,
                                env=env, preexec_fn=contained(os.getpid()))
    finally:
        fh.close()


def group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def terminate(children: dict[str, subprocess.Popen], sleep=time.sleep) -> dict:
    """SIGTERM every child's group, SIGKILL after the grace, and confirm that nothing is left."""
    for p in children.values():
        if group_alive(p.pid):
            os.killpg(p.pid, signal.SIGTERM)
    deadline = time.monotonic() + TERM_GRACE
    while time.monotonic() < deadline and any(group_alive(p.pid) for p in children.values()):
        for p in children.values():
            p.poll()
        sleep(0.2)
    for p in children.values():
        if group_alive(p.pid):
            os.killpg(p.pid, signal.SIGKILL)
    for p in children.values():
        try:
            p.wait(timeout=TERM_GRACE)
        except subprocess.TimeoutExpired:
            pass
    return {name: {"rc": p.returncode, "group_alive": group_alive(p.pid)} for name, p in children.items()}


# ---------------------------------------------------------------- the run


def append(path: Path, row: dict) -> None:
    with path.open("a") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def read_status(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def supervise(rec: dict, status_path: Path, out: Path, launch: Callable[[str], subprocess.Popen],
              mono=time.monotonic, wall=time.time, sleep=time.sleep, boot=boot_id, duration=DURATION) -> int:
    log = out / "load.jsonl"
    st = read_status(status_path)
    me = boot()
    try:
        snapshot = host_snapshot(st if isinstance(st, dict) else {})
        first = status_reasons(st, snapshot, rec, mono(), me)
    except Refuse as exc:
        first = [str(exc)]
    if first:
        append(log, {"ts": wall(), "kind": "refused", "reasons": first})
        return 2
    start = mono()
    cutoff = start + duration
    append(log, {"ts": wall(), "kind": "start", "cutoff_in_s": duration, "snapshot": snapshot})
    children: dict[str, subprocess.Popen] = {}
    try:
        for name in ("ramp", "reads"):
            children[name] = launch(name)
    except Exception as exc:  # a child that started must not outlive a failed launch of the other
        append(log, {"ts": wall(), "kind": "stop", "reasons": [f"launch of {name} failed: {exc}"]})
        append(log, {"ts": wall(), "kind": "terminated", "children": terminate(children, sleep)})
        append(log, {"ts": wall(), "kind": "end", "result": "stop"})
        return 1
    tail = JournalTail(out / "ramp" / "journal.jsonl")
    reasons: list[str] = []
    while True:
        now = mono()
        if now >= cutoff:
            break
        for name, p in children.items():
            if p.poll() is not None:
                reasons.append(f"{name} exited on its own with rc {p.returncode}")
        try:
            tail.poll(now)
        except ValueError as exc:
            reasons.append(f"ramp journal unreadable: {exc}")
        reasons += status_reasons(read_status(status_path), snapshot, rec, now, me)
        reasons += tail.reasons(now, rec["unresolved"])
        if reasons:
            break
        sleep(TICK)
    kind = "stop" if reasons else "cutoff"
    append(log, {"ts": wall(), "kind": kind, "reasons": reasons, "elapsed_s": mono() - start,
                 "undelivered": len(tail.pending)})
    result = terminate(children, sleep)
    append(log, {"ts": wall(), "kind": "terminated", "children": result})
    left = [n for n, r in result.items() if r["group_alive"]]
    if left:
        append(log, {"ts": wall(), "kind": "alarm", "reason": f"process groups still alive: {left}"})
    append(log, {"ts": wall(), "kind": "end", "result": kind})
    return 0 if kind == "cutoff" and not left else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--record", type=Path, required=True)
    ap.add_argument("--record-sha256", required=True)
    ap.add_argument("--status", type=Path, required=True, help="the observer's status.json (t1-observe.py)")
    ap.add_argument("--out", type=Path, required=True, help="a new directory")
    a = ap.parse_args(argv)
    try:
        rec = load_record(a.record, a.record_sha256)
        check_inputs(rec)
        a.out.mkdir(parents=True, exist_ok=False)
    except (Refuse, OSError, ValueError) as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 2
    packet = a.out / "read-packet.json"
    packet.write_text(json.dumps(read_packet(rec, a.out)))

    def launch(name: str) -> subprocess.Popen:
        if name == "ramp":
            return spawn(ramp_argv(rec, a.out), a.out / "ramp.log", cwd=rec["tos_checkout"])
        return spawn([sys.executable, str(HERE / "sustained_read_load.py"), "--packet", str(packet),
                      "--output", str(a.out / "reads")], a.out / "reads.log", cwd=str(HERE))
    return supervise(rec, a.status, a.out, launch)


if __name__ == "__main__":
    sys.exit(main())
