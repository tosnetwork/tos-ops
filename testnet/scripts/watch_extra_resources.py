#!/usr/bin/env python3
"""Read-only sustained OOM/process/inode guard; no node lifecycle or value actions.

  watch_extra_resources.py --inventory hosts.json --out DIR
  watch_extra_resources.py --summarize DIR/series.jsonl

Runs on the coordinator. Every cycle it pipes resource_extra_probe.py (pinned by
its SHA-256 below) to node-1 .. node-4 over SSH, in parallel, and appends to
DIR/series.jsonl (DIR must not exist; it is created with mode 0700):

  HEALTHY_EXTRA_RESOURCE_OBSERVATION   all four hosts observed; also published
                                       atomically as DIR/LATEST.json
  PARTIAL_EXTRA_RESOURCE_OBSERVATION   the hosts that were observed this cycle,
                                       with the names of the missing and the
                                       violating ones; LATEST.json is not
                                       replaced
  VIOLATION_EXTRA_RESOURCE_OBSERVATION one row per host observed in violation
                                       (VIOLATION_REASONS: validator_inactive);
                                       a criteria failure, never missing data
  MISSING_EXTRA_RESOURCE_OBSERVATION   one row per host that could not be
                                       observed: host, time, a fixed reason code
                                       (REASONS) and when the outage began
  ALERT_EXTRA_RESOURCE_HOST_MISSING    once per outage, when a host has been
                                       missing for ALERT_AFTER seconds; the same
                                       record is appended to DIR/ALERTS.jsonl and
                                       an `ALERT` line is printed on stdout

A host read is tried twice, RETRY_AFTER seconds apart. A host that cannot be read
never ends the watch: it is recorded as missing and the next cycle tries again.
An observation that was more than 60 s old when the cycle was published (another
host's read was slow) is checked like any other, then recorded as missing with
reason expired_at_publication; it is never fresh. Missing and violation rows
never carry command output. Whether missing data fails an acceptance window is
decided downstream (the stale LATEST.json and the missing rows), not here; the
outage alert is timed on the monotonic clock and decides nothing. A host is
alerted again only after it was observed and then went missing again.

An observed inactive validator (unit not active or no main PID) is written as a
violation row with reason validator_inactive and the watch keeps running, so the
rest of the series stays available; `VIOLATION <utc> <host>:validator_inactive`
is printed once per episode. --summarize reads a series and prints, as JSON,
the violations apart from the missing data (summarize()), for the outcome
review: a violation is a criteria failure, missing data is judged by the
unchanged missing-data criterion.

The integrity refusals end the watch (exit 1 with a traceback, as before):
probe source not matching the pin; an expected host absent from the inventory;
DIR already existing; a host clock more than 60 s off when its answer arrives;
an observation dated in the future at publication; coordinator free space below
20 GiB or series.jsonl above 256 MiB; in any active observation, fresh or
expired, missing cgroup OOM counters or filesystems or a disk/inode reserve
below its floor; and, against the first complete cycle's BASELINE.json, a
changed main PID, process start time, boot id, restart count, host OOM-kill
counter or cgroup OOM counter. At the end of the horizon it writes
MONITOR-COMPLETE.json, which is not an acceptance verdict.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import preflight  # noqa: E402

SOURCE = Path(__file__).resolve().parent / "resource_extra_probe.py"
PIN = "1203afe4bacbc6b70813ba4cb2782d0c4abe7bbead68373d570d5a364497c7a5"
HOSTS = ("node-1", "node-2", "node-3", "node-4")
DURATION = 345600
PAUSE = 60
RETRY_AFTER = 5
PROBE_TIMEOUT = 30
MAX_AGE = 60
ALERT_AFTER = 600
MIN_FREE = 20 << 30
MAX_LOG = 256 << 20
SCOPE = "Continuous counters/process/reserves only; not a leak or full72h verdict"

SSH_FAILED = "ssh_failed"
PROBE_FAILED = "probe_failed"
PROBE_TIMEOUT_REASON = "probe_timeout"
LAUNCH_FAILED = "probe_launch_failed"
OUTPUT_INVALID = "probe_output_invalid"
EXPIRED = "expired_at_publication"
REASONS = frozenset(
    (SSH_FAILED, PROBE_FAILED, PROBE_TIMEOUT_REASON, LAUNCH_FAILED, OUTPUT_INVALID, EXPIRED)
)
VALIDATOR_INACTIVE = "validator_inactive"
VIOLATION_REASONS = frozenset((VALIDATOR_INACTIVE,))
# systemd's ActiveState vocabulary; anything else is written as "unknown".
UNIT_STATES = frozenset(
    ("active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance")
)
HEALTHY = "HEALTHY_EXTRA_RESOURCE_OBSERVATION"
PARTIAL = "PARTIAL_EXTRA_RESOURCE_OBSERVATION"
MISSING = "MISSING_EXTRA_RESOURCE_OBSERVATION"
VIOLATION = "VIOLATION_EXTRA_RESOURCE_OBSERVATION"
ALERT = "ALERT_EXTRA_RESOURCE_HOST_MISSING"


def iso(stamp: float) -> str:
    return datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat()


def fresh(hosts: dict, names: set, now=time.time) -> None:
    stamp = now()
    if set(hosts) != names or any(
        not 0 <= stamp - value["utc_unix"] <= MAX_AGE for value in hosts.values()
    ):
        raise RuntimeError("Completed host observation expired before publication")


def atomic(path: Path, value, before_publish=None) -> None:
    temporary = path.with_suffix(".tmp")
    created = False
    try:
        with temporary.open("x") as stream:
            created = True
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        if before_publish is not None:
            before_publish()
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if created:
            temporary.unlink(missing_ok=True)


def inactive(value: dict) -> bool:
    pid = value.get("main_pid")
    return (
        value.get("unit_active") != "active"
        or isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 0
    )


def check_reserves(current: dict) -> None:
    """The refusals that need no baseline; check() repeats them against one."""
    if len(current["filesystems"]) != 3:
        raise RuntimeError("Filesystem observations incomplete")
    for key in ("oom", "oom_kill"):
        if key not in current["cgroup_memory_events"]:
            raise RuntimeError("CgroupOOM counters missing")
    for filesystem in current["filesystems"].values():
        if filesystem["free_bytes"] < MIN_FREE or filesystem["free_inodes"] < 100000:
            raise RuntimeError("Disk or inode reserve exhausted")


def check(current: dict, baseline: dict) -> None:
    if (
        set(current["filesystems"]) != set(baseline["filesystems"])
        or len(current["filesystems"]) != 3
    ):
        raise RuntimeError("Filesystem observations incomplete")
    for key in ("oom", "oom_kill"):
        if (
            key not in current["cgroup_memory_events"]
            or key not in baseline["cgroup_memory_events"]
        ):
            raise RuntimeError("CgroupOOM counters missing")
    for name in ("main_pid", "start_ticks", "boot_id", "unit_restarts", "host_oom_kill"):
        if current[name] != baseline[name]:
            raise RuntimeError("Process/boot/restart/hostOOM changed: " + name)
    if current["unit_active"] != "active" or current["cgroup_memory_events"].get(
        "oom_kill"
    ) != baseline["cgroup_memory_events"].get("oom_kill"):
        raise RuntimeError("Validator inactive or cgroupOOMkill changed")
    if current["cgroup_memory_events"].get("oom") != baseline["cgroup_memory_events"].get("oom"):
        raise RuntimeError("CgroupOOM event changed")
    for filesystem in current["filesystems"].values():
        if filesystem["free_bytes"] < MIN_FREE or filesystem["free_inodes"] < 100000:
            raise RuntimeError("Disk or inode reserve exhausted")


def probe_once(host: preflight.Host, source: str, run=subprocess.run) -> tuple[dict | None, str]:
    """(observation, "") or (None, reason code); never returns the child's output."""
    try:
        child = run(
            preflight.ssh_argv(host, accept_new=False) + ["python3 -"],
            input=source,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return None, PROBE_TIMEOUT_REASON
    except OSError:
        return None, LAUNCH_FAILED
    if child.returncode != 0:
        return None, SSH_FAILED if child.returncode == 255 else PROBE_FAILED
    try:
        value = json.loads(child.stdout)
    except ValueError:
        return None, OUTPUT_INVALID
    stamp = value.get("utc_unix") if isinstance(value, dict) else None
    if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
        return None, OUTPUT_INVALID
    return value, ""


def probe(
    host: preflight.Host, source: str, run=subprocess.run, sleep=time.sleep, now=time.time
) -> tuple[str, dict | None, str]:
    """(host, observation, "") or (host, None, reason) after two attempts.

    A stale host clock is an integrity refusal, not a missing sample.
    """
    reason = ""
    for attempt in range(2):
        value, reason = probe_once(host, source, run)
        if value is not None:
            if abs(now() - value["utc_unix"]) > MAX_AGE:
                raise RuntimeError("Host observation clock stale")
            return host.name, value, ""
        if attempt == 0:
            sleep(RETRY_AFTER)
    return host.name, None, reason


class MissingTracker:
    """When each host went missing, and whether that outage was alerted."""

    def __init__(self, alert_after: float = ALERT_AFTER):
        self.alert_after = alert_after
        self.since: dict[str, tuple[float, float]] = {}
        self.alerted: set[str] = set()

    def missing(self, host: str, monotonic: float, stamp: float) -> tuple[float, bool, float]:
        """(outage start unix time, whether to alert now, monotonic seconds missing).

        The outage is timed on the monotonic clock; the unix time is only printed.
        """
        first, first_unix = self.since.setdefault(host, (monotonic, stamp))
        elapsed = monotonic - first
        if host not in self.alerted and elapsed >= self.alert_after:
            self.alerted.add(host)
            return first_unix, True, elapsed
        return first_unix, False, elapsed

    def observed(self, host: str) -> None:
        self.since.pop(host, None)
        self.alerted.discard(host)


def append(stream, value: dict) -> None:
    stream.write(json.dumps(value) + "\n")
    stream.flush()
    os.fsync(stream.fileno())


def watch(
    hosts: list[preflight.Host],
    output: Path,
    probe_host,
    monotonic=time.monotonic,
    now=time.time,
    sleep=time.sleep,
    disk_free=lambda path: shutil.disk_usage(path).free,
    duration: float = DURATION,
    emit=print,
) -> None:
    names = {host.name for host in hosts}
    output.mkdir(mode=0o700)
    baseline = None
    tracker = MissingTracker()
    inactive_hosts: set[str] = set()
    started = monotonic()
    with (output / "series.jsonl").open("x") as stream:
        while monotonic() - started < duration:
            if disk_free(output) < MIN_FREE or stream.tell() > MAX_LOG:
                raise RuntimeError("Coordinator disk or observation log bound")
            cycle = monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(hosts)) as pool:
                results = list(pool.map(probe_host, hosts))
            observed = {name: value for name, value, _ in results if value is not None}
            missing = {name: reason for name, value, reason in results if value is None}
            violations: dict[str, dict] = {}
            current = {}
            stamp = now()
            for name in sorted(observed):
                value = observed[name]
                age = stamp - value["utc_unix"]
                if age < 0:
                    raise RuntimeError("Completed host observation expired before publication")
                if inactive(value):
                    violations[name] = value
                    continue
                # Every observation is checked, however late it is published.
                check_reserves(value)
                if baseline is not None:
                    check(value, baseline[name])
                if age > MAX_AGE:
                    # Another host's slow read delayed publication past the
                    # freshness bound: missing data, never a fresh sample.
                    missing[name] = EXPIRED
                else:
                    current[name] = value
            if baseline is None and not missing and not violations:
                baseline = current
                atomic(output / "BASELINE.json", current)
            # Only a fresh accepted or a violating observation ends an outage;
            # one that expired at publication is still missing.
            for name in set(current) | set(violations):
                tracker.observed(name)
            for name in sorted(violations):
                state = violations[name].get("unit_active")
                append(
                    stream,
                    {
                        "status": VIOLATION,
                        "host": name,
                        "checked_unix": stamp,
                        "checked_utc": iso(stamp),
                        "reason": VALIDATOR_INACTIVE,
                        "observed_unix": violations[name]["utc_unix"],
                        "unit_active": state if state in UNIT_STATES else "unknown",
                    },
                )
                if name not in inactive_hosts:
                    inactive_hosts.add(name)
                    emit(f"VIOLATION {iso(stamp)} {name}:{VALIDATOR_INACTIVE}")
            inactive_hosts &= set(violations)
            for name, reason in sorted(missing.items()):
                since, alert, elapsed = tracker.missing(name, cycle, stamp)
                record = {
                    "status": MISSING,
                    "host": name,
                    "checked_unix": stamp,
                    "checked_utc": iso(stamp),
                    "reason": reason,
                    "missing_since_unix": since,
                }
                append(stream, record)
                if alert:
                    record = dict(
                        record,
                        status=ALERT,
                        missing_seconds=int(elapsed),
                    )
                    append(stream, record)
                    with (output / "ALERTS.jsonl").open("a") as alerts:
                        append(alerts, record)
                    emit(
                        f"ALERT {record['checked_utc']} {name}:missing_for="
                        f"{record['missing_seconds']}s reason={reason}"
                    )
            if missing or violations:
                append(
                    stream,
                    {
                        "status": PARTIAL,
                        "checked_unix": stamp,
                        "checked_utc": iso(stamp),
                        "hosts": current,
                        "missing": sorted(missing),
                        "violations": sorted(violations),
                        "scope": SCOPE,
                    },
                )
            else:
                value = {
                    "status": HEALTHY,
                    "checked_unix": stamp,
                    "checked_utc": iso(stamp),
                    "hosts": current,
                    "scope": SCOPE,
                }
                append(stream, value)
                atomic(
                    output / "LATEST.json",
                    value,
                    before_publish=lambda: fresh(current, names, now),
                )
            sleep(PAUSE)
    atomic(
        output / "MONITOR-COMPLETE.json",
        {"status": "MONITOR_HORIZON_REACHED_NOT_ACCEPTANCE", "finished_unix": now()},
    )


def summarize(path: Path) -> dict:
    """Violations apart from missing data, for the outcome review; it decides nothing.

    A row is classified by its reason code, and only when its status agrees with
    that code; anything else (and a line that is not a JSON object) is counted as
    unrecognized, which a review must not read as clean. An unterminated last
    line, from a watch still writing, is not read.
    """
    out = {
        "rows": 0,
        "healthy_cycles": 0,
        "partial_cycles": 0,
        "violation_rows": 0,
        "violations": [],
        "missing_rows": 0,
        "missing": {},
        "alerts": 0,
        "unrecognized_rows": 0,
    }
    with Path(path).open() as stream:
        for line in stream:
            if not line.endswith("\n"):
                break
            out["rows"] += 1
            try:
                row = json.loads(line)
            except ValueError:
                row = None
            if not isinstance(row, dict):
                out["unrecognized_rows"] += 1
                continue
            status, reason = row.get("status"), row.get("reason")
            if reason in VIOLATION_REASONS:
                kind = "violation"
            elif reason in REASONS:
                kind = "missing"
            else:
                kind = None
            if status == HEALTHY and reason is None:
                out["healthy_cycles"] += 1
            elif status == PARTIAL and reason is None:
                out["partial_cycles"] += 1
            elif kind == "violation" and status == VIOLATION:
                out["violation_rows"] += 1
                out["violations"].append(
                    {
                        "host": row.get("host"),
                        "checked_unix": row.get("checked_unix"),
                        "reason": reason,
                    }
                )
            elif kind == "missing" and status == MISSING:
                out["missing_rows"] += 1
                per_host = out["missing"].setdefault(str(row.get("host")), {})
                per_host[reason] = per_host.get(reason, 0) + 1
            elif kind == "missing" and status == ALERT:
                out["alerts"] += 1
            else:
                out["unrecognized_rows"] += 1
    out["criteria_violated"] = out["violation_rows"] > 0
    out["missing_data"] = out["missing_rows"] > 0
    return out


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--summarize", type=Path, metavar="SERIES")
    args = parser.parse_args(argv)
    if args.summarize is not None:
        if args.inventory or args.out:
            parser.error("--summarize takes no --inventory or --out")
        print(json.dumps(summarize(args.summarize), indent=2, sort_keys=True))
        return
    if args.inventory is None or args.out is None:
        parser.error("--inventory and --out are required")
    source = SOURCE.read_text()
    if hashlib.sha256(source.encode()).hexdigest() != PIN:
        raise RuntimeError("Probe source changed")
    hosts = [host for host in preflight.load_inventory(args.inventory) if host.name in HOSTS]
    if len(hosts) != len(HOSTS):
        raise RuntimeError("Expected four original hosts")

    def probe_host(host):
        return probe(host, source)

    watch(hosts, args.out, probe_host, emit=lambda line: print(line, flush=True))


if __name__ == "__main__":
    main()
