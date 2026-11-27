#!/usr/bin/env python3
"""Archive one latched settlement incident after a reviewed resolution.

Operator-only. Under the monitor lock it removes exactly the named incident from
incidents.json, and only when the checker's current report is fresh, consistent
with incidents.json and shows that incident's condition clear. It writes a
resolution record with the sha256 of incidents.json before and after. It never
sends, signs, votes or changes a baseline. See settlement-monitor.md.
Exit 0: resolved, 2: refused (nothing changed).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import stat
import sys
import time
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "incident_monitor", Path(__file__).with_name("check-settlement.py")
)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)

RECORD_SCHEMA = "tos-settlement-incident-resolution/1"
MAX_REASON = 2000


def require(condition, message):
    if not condition:
        raise monitor.Invalid(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reason_text(value):
    require(isinstance(value, str) and value == value.strip() and value, "reason is empty")
    require(len(value) <= MAX_REASON, "reason exceeds its bound")
    require(value.isprintable(), "reason has control characters")
    return value


def resolve(state_dir, incident, reason, record_path, max_age, now):
    """Remove one incident; return the resolution record. Raises Invalid on refusal."""
    incidents_path = state_dir / "incidents.json"
    report_path = state_dir / "report.json"
    require(incidents_path.is_file(), "no incidents.json in the monitor state")
    incidents = monitor.read_json(incidents_path)
    require(isinstance(incidents, dict), "incidents.json is not an object")
    require(incident in incidents, "named incident is not latched")
    entry = incidents[incident]
    asset, code = entry["alarm"]["asset"], entry["alarm"]["code"]
    require(incident == asset + ":" + code, "incident key does not match its alarm")
    require(code in monitor.EMERGENCIES, "incident is not an emergency latch")

    require(report_path.is_file(), "no current report")
    report = monitor.read_json(report_path)
    require(report.get("schema") == "tos-settlement-report/1", "report schema differs")
    require("status" not in report, "report is stale or incomplete")
    require(report.get("baseline") is False, "report checked no interval")
    require(report.get("latched_incidents") == sorted(incidents), "report predates incidents")
    checkpoint = report["checkpoint"]
    monitor.digest(checkpoint["hash"])
    height = monitor.number(checkpoint["height"], "height", (1 << 64) - 1)
    stamp = monitor.number(checkpoint["utime"], "utime", (1 << 64) - 1)
    require(stamp <= now + 5 and now - stamp <= max_age, "report is too old")
    require(height > entry["checkpoint"]["height"], "report does not follow the incident")
    alarms = report["alarms"]
    require(isinstance(alarms, list), "report alarms are not a list")
    require(
        not any(a["asset"] == asset and a["code"] == code for a in alarms),
        "condition is still alarmed in the current report",
    )

    before = sha256(incidents_path)
    remaining = {k: v for k, v in incidents.items() if k != incident}
    monitor.atomic(incidents_path, remaining)
    after = sha256(incidents_path)
    require(monitor.read_json(incidents_path) == remaining, "incidents.json did not read back")
    record = dict(
        schema=RECORD_SCHEMA,
        incident=incident,
        removed=entry,
        remaining_incidents=sorted(remaining),
        incidents_sha256_before=before,
        incidents_sha256_after=after,
        report_checkpoint=checkpoint,
        report_sha256=sha256(report_path),
        reason=reason,
        time_unix=int(now),
    )
    monitor.atomic(record_path, record)
    return record


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--state-dir", type=Path, required=True, help="checker state; locks it")
    ap.add_argument("--policy", type=Path, required=True, help="the checker's policy")
    ap.add_argument("--incident", required=True, help="latched key, ASSET:CODE")
    ap.add_argument("--reason", required=True, help="the reviewed resolution, one line")
    ap.add_argument("--record", type=Path, required=True, help="new resolution record path")
    a = ap.parse_args(argv)
    try:
        reason = reason_text(a.reason)
        state = a.state_dir.lstat()
        require(
            stat.S_ISDIR(state.st_mode)
            and state.st_uid == os.geteuid()
            and not state.st_mode & 0o077,
            "monitor state is not private and owned",
        )
        record = a.record.absolute()
        require(not record.exists() and not record.is_symlink(), "resolution record exists")
        require(
            record.parent.is_dir() and os.access(record.parent, os.W_OK),
            "resolution record directory is missing or not writable",
        )
        parent = record.parent.resolve()
        require(
            a.state_dir.resolve() not in (parent, *parent.parents),
            "resolution record must be kept outside the monitor state",
        )
        policy = monitor.read_json(a.policy)
        max_age = monitor.bounded(policy["max_age_seconds"], "max_age_seconds", 1, 3600)
        with open(a.state_dir / "monitor.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = resolve(a.state_dir, a.incident, reason, record, max_age, time.time())
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps(dict(result="refused", reason=str(error))))
        return 2


if __name__ == "__main__":
    sys.exit(main())
