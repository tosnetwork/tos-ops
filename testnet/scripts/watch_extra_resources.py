#!/usr/bin/env python3
"""Read-only sustained OOM/process/inode guard; no node lifecycle or value actions.

  watch_extra_resources.py --inventory hosts.json --out DIR

Runs on the coordinator. Every cycle it pipes resource_extra_probe.py (pinned by
its SHA-256 below) to node-1 .. node-4 over SSH, in parallel, and appends to
DIR/series.jsonl (DIR must not exist; it is created with mode 0700):

  HEALTHY_EXTRA_RESOURCE_OBSERVATION   all four hosts observed; also published
                                       atomically as DIR/LATEST.json
  PARTIAL_EXTRA_RESOURCE_OBSERVATION   the hosts that were observed this cycle,
                                       with the names of the missing ones;
                                       LATEST.json is not replaced
  MISSING_EXTRA_RESOURCE_OBSERVATION   one row per host that could not be
                                       observed: host, time, a fixed reason code
                                       (REASONS) and when the outage began
  ALERT_EXTRA_RESOURCE_HOST_MISSING    once per outage, when a host has been
                                       missing for ALERT_AFTER seconds; the same
                                       record is appended to DIR/ALERTS.jsonl and
                                       an `ALERT` line is printed on stdout

A host read is tried twice, RETRY_AFTER seconds apart. A host that cannot be read
never ends the watch: it is recorded as missing and the next cycle tries again.
Missing rows never carry command output. Whether missing data fails an
acceptance window is decided downstream (the stale LATEST.json and the missing
rows), not here. A host is alerted again only after it was observed and then
went missing again.

The integrity refusals end the watch (exit 1 with a traceback, as before):
probe source not matching the pin; an expected host absent from the inventory;
DIR already existing; a host clock more than 60 s off when its answer arrives;
an observation dated in the future at publication; coordinator free space below
20 GiB or series.jsonl above 256 MiB; and, against the first complete cycle's
BASELINE.json, a changed main PID, process start time, boot id, restart count,
host OOM-kill counter or cgroup OOM counter, an inactive unit, missing cgroup OOM
counters or filesystems, or a disk/inode reserve below its floor. At the end of
the horizon it writes MONITOR-COMPLETE.json, which is not an acceptance verdict.
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
PIN = "fa798d7fda9dc5d7e52fd50d640b79cea8dae8811bf38bd39cfdc0ef47240bbe"
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
EXPIRED = "observation_expired"
REASONS = frozenset(
    (SSH_FAILED, PROBE_FAILED, PROBE_TIMEOUT_REASON, LAUNCH_FAILED, OUTPUT_INVALID, EXPIRED)
)


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

    def missing(self, host: str, monotonic: float, stamp: float) -> tuple[float, bool]:
        """(outage start unix time, whether to alert now)."""
        first, first_unix = self.since.setdefault(host, (monotonic, stamp))
        if host not in self.alerted and monotonic - first >= self.alert_after:
            self.alerted.add(host)
            return first_unix, True
        return first_unix, False

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
    started = monotonic()
    with (output / "series.jsonl").open("x") as stream:
        while monotonic() - started < duration:
            if disk_free(output) < MIN_FREE or stream.tell() > MAX_LOG:
                raise RuntimeError("Coordinator disk or observation log bound")
            cycle = monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(hosts)) as pool:
                results = list(pool.map(probe_host, hosts))
            current = {name: value for name, value, _ in results if value is not None}
            missing = {name: reason for name, value, reason in results if value is None}
            stamp = now()
            for name in sorted(current):
                age = stamp - current[name]["utc_unix"]
                if age < 0:
                    raise RuntimeError("Completed host observation expired before publication")
                if age > MAX_AGE:
                    # Another host's slow read delayed publication past the
                    # freshness bound: this observation is missing, not wrong.
                    del current[name]
                    missing[name] = EXPIRED
            if baseline is None and not missing:
                baseline = current
                atomic(output / "BASELINE.json", current)
            if baseline is not None:
                for name in current:
                    check(current[name], baseline[name])
            for name in current:
                tracker.observed(name)
            for name, reason in sorted(missing.items()):
                since, alert = tracker.missing(name, cycle, stamp)
                record = {
                    "status": "MISSING_EXTRA_RESOURCE_OBSERVATION",
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
                        status="ALERT_EXTRA_RESOURCE_HOST_MISSING",
                        missing_seconds=int(stamp - since),
                    )
                    append(stream, record)
                    with (output / "ALERTS.jsonl").open("a") as alerts:
                        append(alerts, record)
                    emit(
                        f"ALERT {record['checked_utc']} {name}:missing_for="
                        f"{record['missing_seconds']}s reason={reason}"
                    )
            if missing:
                append(
                    stream,
                    {
                        "status": "PARTIAL_EXTRA_RESOURCE_OBSERVATION",
                        "checked_unix": stamp,
                        "checked_utc": iso(stamp),
                        "hosts": current,
                        "missing": sorted(missing),
                        "scope": SCOPE,
                    },
                )
            else:
                value = {
                    "status": "HEALTHY_EXTRA_RESOURCE_OBSERVATION",
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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
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
