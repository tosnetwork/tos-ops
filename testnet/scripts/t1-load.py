#!/usr/bin/env python3
"""T1 load supervisor (memo public-testnet/T1-PRB-DESIGN-20261110 v3.1).

  t1-load.py --record RECORD.json --record-sha256 HEX --status STATUS.json --out NEW_DIR

Runs, as children, the tos T4 ramp sender (writes) and sustained_read_load.py in its T1 profile (reads), both
configured only from the frozen acceptance record (whose sha256 must match), and stops both on the first T1 stop
condition (T1-PLAN §6), at the T+72 h signing cutoff, or when either exits on its own. It never restarts or
adopts a submitter: after any stop, monitoring continues elsewhere and the stopped interval stays visible.

Containment: each child runs in its own process group with PR_SET_PDEATHSIG = SIGKILL, so it dies with this
process; run this under a systemd unit with KillMode=control-group and Restart=no for the window before the
signal is armed. Children write stdout/stderr to files, never to a pipe. The launch is:

  systemd-run --user --unit=t1-load -p KillMode=control-group -p Restart=no -p StandardOutput=file:OUT.log \
      -p StandardError=file:OUT.log /usr/bin/python3 -I t1-load.py --record R --record-sha256 H --status S \
      --inventory INVENTORY --out O

It refuses to start outside that unit (its cgroup and KillMode/Restart are checked), and while any ramp wallet
lock is held. Within the unit, systemd kills grandchildren (the ramp's signer) with the cgroup; a stop's
SIGTERM/SIGKILL reaches them through the process group.

--calibrate runs the same machinery for the T1 start checklist's calibration: one ramp step in a one-hour run
instead of three steps in 72 h, with the same record, refusals, stop rules and OUT layout. The start row
names the mode ("calibration" or "t1").

Every decision is a line in OUT/load.jsonl: start, each stop reason, the termination check and the end.
Exit status: 0 when the run ended at the cutoff with no stop condition, 1 when it was stopped, 2 when it refused
to start.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import math
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
# The ramp's timing, pinned on its command line so that the budget below is the one it runs with. Its own fee
# horizon (bench/t4/ramp.py fee_horizon) bounds a run by: funding = (funding externals + 1) × deploy_wait; each
# step = step_seconds + 2 × drain + finality_wait; the end = drain + 2 × lifetime + deadline_grace + finality_wait.
RAMP_TIMING = {"deploy_wait": 120, "drain": 120, "finality_wait": 120, "lifetime": 60, "deadline_grace": 30}
STEPS = 3
MARGIN = 600  # scheduling slack before the cutoff
ROW_MAX_AGE = 180.0  # a host's latest resource row older than this stops the run
DATA_PATHS = ("/var/lib/tos/validator", "/var/log/tos")  # every one must be reported, as in t1-observe.py
UNIT_NAME = "t1-load.service"


def finite(v) -> bool:
    return type(v) in (int, float) and math.isfinite(v)


def positive(v) -> bool:
    return finite(v) and v > 0


def run_plan(calibrate: bool = False) -> dict:
    """The run's mode, signing duration and ramp step count: T1 is DURATION in STEPS steps; the calibration
    (T1 start checklist row 8) is one step in one hour, through the same schedule and supervisor."""
    if calibrate:
        return {"mode": "calibration", "duration": 3600, "steps": 1}
    return {"mode": "t1", "duration": DURATION, "steps": STEPS}


def schedule(funding_externals: int, duration: int = DURATION, steps: int = STEPS) -> dict:
    """The step length that lets the ramp fund, run its steps, drain and finish before the cutoff.

    T1-PLAN §5.7 needs zero unresolved transfers after the declared drain, so the ramp must end by itself, never
    be cut off: preparation + steps × (step + transition) + the final tail + MARGIN ≤ duration."""
    t = RAMP_TIMING
    prep = (funding_externals + 1) * t["deploy_wait"]
    transition = 2 * t["drain"] + t["finality_wait"]
    tail = t["drain"] + 2 * t["lifetime"] + t["deadline_grace"] + t["finality_wait"]
    step = (duration - prep - tail - MARGIN) // steps - transition
    if step <= 0 or step > 86_400:
        raise Refuse(f"no step length fits: {step}")
    total = prep + steps * (step + transition) + tail
    return {"step_seconds": int(step), "prep": prep, "transition": transition, "tail": tail,
            "ramp_budget": total, "slack": duration - total}


REQUIRED = {
    "tos_checkout": str, "tos_rev": str, "signer": str, "signer_sha256": str, "key_file": str, "auth_tag": str,
    "ramp": dict, "reads": dict, "floors": dict, "unresolved": dict, "status_stale_s": (int, float),
}
RAMP_REQUIRED = ("batch", "wallets", "wallet_funding", "max_cost", "max_transfers", "funding_externals", "rpc")
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
    fx = rec["ramp"]["funding_externals"]
    if type(fx) is not int or not 1 <= fx <= 8:
        raise Refuse(f"ramp.funding_externals must be an integer in [1, 8], not {fx!r}")
    for key in ("tos_checkout", "signer", "key_file"):
        if not Path(rec[key]).is_absolute():  # the children run in other working directories
            raise Refuse(f"acceptance record {key} must be an absolute path, not {rec[key]!r}")
    if not (isinstance(rec["ramp"]["rpc"], list) and len(rec["ramp"]["rpc"]) == 4):
        raise Refuse("ramp.rpc must name the four validator tunnels")
    numbers = [("status_stale_s", rec["status_stale_s"])]
    numbers += [(f"floors.{k}", rec["floors"][k]) for k in FLOORS_REQUIRED]
    numbers += [(f"unresolved.{k}", rec["unresolved"][k]) for k in UNRESOLVED_REQUIRED]
    numbers += [(f"ramp.{k}", rec["ramp"][k]) for k in RAMP_REQUIRED if k != "rpc"]
    numbers += [("reads.network_deadline_seconds", rec["reads"]["network_deadline_seconds"]),
                ("reads.window_seconds", rec["reads"]["window_seconds"])]
    for name, v in numbers:
        if not positive(v):
            raise Refuse(f"acceptance record {name} must be a finite number > 0, not {v!r}")
    return rec


def check_inventory(rec: dict, urls: dict[str, str], read_endpoints: list[str]) -> None:
    """Writes and reads must both go to the four inventory-bound validator tunnels, one per host."""
    want = [urls.get(h) for h in HOSTS]
    if None in want or len(set(want)) != len(HOSTS):
        raise Refuse(f"the tunnel inventory does not give one distinct tunnel per validator: {urls}")
    if rec["ramp"]["rpc"] != want:
        raise Refuse(f"ramp.rpc {rec['ramp']['rpc']} is not the inventory's tunnels {want}")
    if read_endpoints != want:
        raise Refuse(f"the read profile's endpoints {read_endpoints} are not the inventory's tunnels {want}")


def check_containment(cgroup: str, props: dict[str, str]) -> None:
    """The supervisor must run in its own systemd unit, which kills the whole cgroup (grandchildren too) when the
    supervisor dies and never restarts it."""
    if not any(line.rstrip().endswith("/" + UNIT_NAME) for line in cgroup.splitlines()):
        raise Refuse(f"not running inside {UNIT_NAME} (see the launch line in the docstring)")
    if props.get("KillMode") != "control-group" or props.get("Restart") != "no":
        raise Refuse(f"{UNIT_NAME} must have KillMode=control-group and Restart=no, not {props}")


def check_wallet_locks(state_dir: Path) -> None:
    """Refuse while any wallet lock under the ramp's state dir is held: an earlier submitter is still alive."""
    if not state_dir.exists():
        return
    for lock in sorted(state_dir.glob("*/lock")):
        fd = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        except BlockingIOError as exc:
            raise Refuse(f"{lock} is held by a running process") from exc
        finally:
            os.close(fd)


def unit_props(run=subprocess.run) -> dict[str, str]:
    out = run(["systemctl", "--user", "show", "-p", "KillMode", "-p", "Restart", UNIT_NAME], capture_output=True,
              text=True, timeout=30, check=False).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def sibling(name: str):
    """Load a sibling script by path: `python3 -I` leaves the script directory off sys.path."""
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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


def ramp_argv(rec: dict, out: Path, plan: dict | None = None) -> list[str]:
    plan = plan or run_plan()
    r = rec["ramp"]
    s = schedule(r["funding_externals"], plan["duration"], plan["steps"])
    t = RAMP_TIMING
    argv = [sys.executable, str(Path(rec["tos_checkout"]) / "bench" / "run_t4_ramp.py"),
            "--out", str(out / "ramp"), "--key-file", rec["key_file"], "--signer", rec["signer"],
            "--auth-tag", rec["auth_tag"], "--build", str(Path(rec["tos_checkout"]) / "build"),
            "--wallets", str(r["wallets"]), "--batch", str(r["batch"]),
            "--start-rate", "2", "--factor", "1", "--steps", str(plan["steps"]), "--step-seconds", str(s["step_seconds"]),
            "--deploy-wait", str(t["deploy_wait"]), "--drain", str(t["drain"]),
            "--finality-wait", str(t["finality_wait"]), "--lifetime", str(t["lifetime"]),
            "--deadline-grace", str(t["deadline_grace"]),
            "--layout-repeats", "0", "--tolerance", "0.5", "--p95-limit", "600",
            "--wallet-funding", str(r["wallet_funding"]), "--max-cost", str(r["max_cost"]),
            "--max-transfers", str(r["max_transfers"]), "--rpc-share", "0.25"]
    for url in r["rpc"]:
        argv += ["--rpc", url]
    return argv


def read_packet(rec: dict, out: Path, plan: dict | None = None) -> dict:
    plan = plan or run_plan()
    read_client = sibling("read_client")  # the endpoint pins live there
    r = rec["reads"]
    return {"profile": "t1", "duration_seconds": plan["duration"], "requests_per_second": 8,
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
        ident = identity(row)
        if ident is None:
            raise Refuse(f"{h}: the resource row has no valid MainPID, NRestarts, boot id and OOM count")
        snap[h] = ident
    return snap


def count(v) -> bool:
    return type(v) is int and v >= 0


def identity(row: dict):
    """(MainPID, NRestarts, boot id, OOM count) when every field is valid, else None: a missing field can never
    compare equal to an earlier missing field (codex r2)."""
    unit = row.get("unit") if isinstance(row.get("unit"), dict) else {}
    pid, restarts, boot, oom = unit.get("main_pid"), unit.get("n_restarts"), row.get("boot_id"), row.get("oom_kill")
    if count(pid) and pid > 0 and count(restarts) and isinstance(boot, str) and boot and count(oom):
        return (pid, restarts, boot, oom)
    return None


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
    if not finite(st["updated_mono"]) or now_mono - st["updated_mono"] > rec["status_stale_s"]:
        out.append("status is stale")
    if st["blind"] is not False:
        out.append(f"blind: {st.get('reasons')}")
    if not isinstance(st["stalled_hosts"], list) or len(st["stalled_hosts"]) >= 3:
        out.append(f"stall on {st['stalled_hosts']}")
    if st["safety_hits"] != 0 or type(st["safety_hits"]) is not int:
        out.append(f"safety lines: {st['safety_hits']}")
    if st["coverage_gaps"] != 0 or type(st["coverage_gaps"]) is not int:
        out.append(f"log coverage gaps: {st['coverage_gaps']}")
    if st["operators_low"] != []:
        out.append(f"operators below the floor: {st['operators_low']}")
    hosts = st["hosts"] if isinstance(st["hosts"], dict) else {}
    for h in HOSTS:
        out += host_reasons(h, hosts.get(h), snapshot, rec["floors"], now_mono)
    return out


def host_reasons(h: str, row, snapshot: dict, floors: dict, now_mono: float) -> list[str]:
    """Every field is validated on its own: a NaN, a missing key or a missing data path is a stop, never a pass."""
    if not isinstance(row, dict):
        return [f"{h}: no resource row"]
    if row.get("complete") is not True:
        return [f"{h}: latest resource row incomplete: {row.get('missing') or row.get('error')}"]
    out = []
    if not finite(row.get("received_mono")) or now_mono - row["received_mono"] > ROW_MAX_AGE:
        out.append(f"{h}: latest resource row too old")
    unit, mem, disks = row.get("unit"), row.get("mem"), row.get("disks")
    if not isinstance(unit, dict) or unit.get("active_state") != "active":
        out.append(f"{h}: validator {unit.get('active_state') if isinstance(unit, dict) else 'unit unreadable'}")
    else:
        now_id = identity(row)
        if now_id is None:
            out.append(f"{h}: MainPID, NRestarts, boot id or OOM count unreadable")
        elif now_id != snapshot[h]:
            out.append(f"{h}: restart, reboot or OOM since the start")
    if not (isinstance(mem, dict) and finite(mem.get("MemAvailable"))) or \
            mem["MemAvailable"] < floors["mem_available_bytes"]:
        out.append(f"{h}: MemAvailable below the floor or unreadable")
    for path in DATA_PATHS:
        d = disks.get(path) if isinstance(disks, dict) else None
        if not (isinstance(d, dict) and finite(d.get("free_bytes")) and finite(d.get("free_inodes"))):
            out.append(f"{h}: {path} unreadable")
        elif d["free_bytes"] < floors["disk_free_bytes"] or d["free_inodes"] < floors["disk_free_inodes"]:
            out.append(f"{h}: {path} below the disk floor")
    return out


# ---------------------------------------------------------------- unresolved deliveries from the ramp journal


class JournalTail:
    """Follows the ramp's journal.jsonl and keeps every action of an executed transfer external without a delivery.

    Only transfers are tracked: the ramp journals `delivered` for load-wallet transfers alone (ramp.py:837-847), so
    the bench wallet's funding externals (role "funding") never get a delivery and must not count as backlog."""

    def __init__(self, path: Path):
        self.path, self.offset, self.partial = path, 0, b""
        self.actions: dict[str, int] = {}  # attempt id -> number of actions, until its external is observed
        self.pending: dict[tuple[str, int], float] = {}  # (attempt id, action) -> when its sender was observed
        # A delivery the follower journaled before its external's `observed` record (it can, ramp.py:757–759):
        # kept until that record arrives, so the action is not counted as pending afterwards.
        self.early: set[tuple[str, int]] = set()

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
            if kind == "attempt" and rec.get("role") == "transfer":
                self.actions[aid] = len(rec.get("actions") or [])
            elif kind == "observed":
                n = self.actions.pop(aid, 0)
                # `failure` is per action (ledger.External.failure: None where the action was sent); a scalar
                # failure, if any, applies to every action.
                fail = rec.get("failure")
                per = fail if isinstance(fail, list) else [fail] * n
                for i in range(n):
                    key = (aid, i)
                    if key in self.early:
                        self.early.discard(key)
                    elif i >= len(per) or per[i] is None:
                        self.pending.setdefault(key, now)
            elif kind == "delivered":
                key = (aid, rec.get("action"))
                if self.pending.pop(key, None) is None and aid in self.actions:
                    self.early.add(key)
            elif kind in ("expired", "unknown"):
                self.actions.pop(aid, None)

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
              mono=time.monotonic, wall=time.time, sleep=time.sleep, boot=boot_id, duration=None,
              plan: dict | None = None) -> int:
    """`plan` is the run (run_plan); `duration` is its cutoff in seconds, the plan's own duration unless a test
    compresses time, in which case the ramp's finish point is compressed by the same factor."""
    plan = plan or run_plan()
    if duration is None:
        duration = plan["duration"]
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
    append(log, {"ts": wall(), "kind": "start", "mode": plan["mode"], "cutoff_in_s": duration, "snapshot": snapshot})
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
    ramp_done = False
    # The ramp finishing its whole schedule (exit 0, no earlier than its last step's end) is the normal end of
    # writing: it has drained its last transfers itself. Monitoring and the reads continue until the cutoff.
    planned = schedule(rec["ramp"]["funding_externals"], plan["duration"], plan["steps"])
    ramp_finish = plan["steps"] * planned["step_seconds"] * duration / plan["duration"]
    while True:
        now = mono()
        if now >= cutoff:
            break
        for name, p in children.items():
            if name == "ramp" and ramp_done:
                continue
            if p.poll() is not None:
                if name == "ramp" and p.returncode == 0 and now - start >= ramp_finish:
                    ramp_done = True
                    append(log, {"ts": wall(), "kind": "ramp_done", "elapsed_s": now - start})
                else:
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
    if kind == "cutoff" and not ramp_done:
        reasons = ["the ramp had not finished its schedule at the cutoff"]
        kind = "stop"
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
    ap.add_argument("--inventory", type=Path, required=True, help="the host inventory (as for t1-observe.py)")
    ap.add_argument("--unit-dir", type=Path, default=Path.home() / ".config/systemd/user")
    ap.add_argument("--calibrate", action="store_true",
                    help="the one-hour, one-step calibration run instead of the 72 h T1 run")
    a = ap.parse_args(argv)
    plan = run_plan(a.calibrate)
    # Children run with other working directories (the ramp in the tos checkout, the reads in this directory), so
    # every path handed to them, and the journal path the tail watches, must be absolute (bot review on #82).
    a.out, a.status, a.record, a.inventory = (p.resolve() for p in (a.out, a.status, a.record, a.inventory))
    try:
        rec = load_record(a.record, a.record_sha256)
        check_inputs(rec)
        urls = sibling("check-validator-keys").tunnel_inventory(a.unit_dir, json.loads(a.inventory.read_text()))
        check_inventory(rec, urls, list(sibling("read_client").T1_ENDPOINTS))
        check_containment(Path("/proc/self/cgroup").read_text(), unit_props())
        key = Path(rec["key_file"])
        check_wallet_locks(key.parent / (key.name + ".state"))  # the ramp's default state dir
        a.out.mkdir(parents=True, exist_ok=False)
    except Exception as exc:  # any failed precondition refuses the start; nothing has been launched yet
        print(f"refusing to start: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    packet = a.out / "read-packet.json"
    packet.write_text(json.dumps(read_packet(rec, a.out, plan)))

    def launch(name: str) -> subprocess.Popen:
        if name == "ramp":
            return spawn(ramp_argv(rec, a.out, plan), a.out / "ramp.log", cwd=rec["tos_checkout"])
        return spawn([sys.executable, str(HERE / "sustained_read_load.py"), "--packet", str(packet),
                      "--output", str(a.out / "reads")], a.out / "reads.log", cwd=str(HERE))
    return supervise(rec, a.status, a.out, launch, plan=plan)


if __name__ == "__main__":
    sys.exit(main())
