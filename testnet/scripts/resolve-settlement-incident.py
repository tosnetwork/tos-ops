#!/usr/bin/env python3
"""Archive one latched settlement incident after a reviewed resolution.

Operator-only. Under the monitor lock it removes exactly the named incident from
incidents.json, and only when the checker's current report is fresh, consistent
with incidents.json and has no alarm of that incident's asset and code. It first
creates the resolution record (exclusively, fsynced) with the sha256 of
incidents.json before and after, then replaces incidents.json. It never sends,
signs, votes or changes a baseline. See settlement-monitor.md.

An absent alarm is only as strong as the code it tests. For a level code (a
frozen bridge, a token that is paused, deprecated or upgraded now, a backing
shortfall) it shows that the condition no longer holds. For an edge-triggered
code (destroyed_funds, unexplained_decrease, and token_paused raised by
pause_events) it shows only that no new event occurred in the last checked
interval, not that the cause is resolved; for those the human review is the
real guard.

Exit 0: resolved. 2: refused, nothing changed. 3: partial, a failure after the
record was written left a change; the JSON names exactly what happened.
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


class Partial(Exception):
    """A failure after the record was written; carries what changed."""

    def __init__(self, **facts):
        super().__init__(facts["what"])
        self.facts = facts


def require(condition, message):
    if not condition:
        raise monitor.Invalid(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode(value):
    """The checker's exact state encoding (monitor.atomic)."""
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def fsync_directory(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def create_record(path, data):
    """Create a new record or refuse; never replaces an existing file.

    On a failure the partial file this call created is removed, so a refusal
    leaves nothing behind; if that removal fails, the failure is partial.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)  # FileExistsError if it appeared meanwhile
    try:
        write_all(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = None
        fsync_directory(path.parent)
    except OSError as error:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            raise Partial(
                what="record write failed and its partial file was left; incidents unchanged",
                error=str(error),
                record=str(path),
            ) from error
        raise


def current_hash(path):
    try:
        return sha256(path)
    except OSError:
        return None


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
    after = hashlib.sha256(encode(remaining)).hexdigest()
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
    # The record exists, durably, before the incident is removed.
    create_record(record_path, encode(record))
    try:
        monitor.atomic(incidents_path, remaining)
    except (OSError, ValueError) as error:
        current = current_hash(incidents_path)
        if current == before:
            try:
                os.unlink(record_path)
                fsync_directory(record_path.parent)
            except OSError:
                raise Partial(
                    what="incidents.json was not replaced, but the record could not be withdrawn",
                    error=str(error),
                    record=str(record_path),
                    incidents_sha256_current=current,
                ) from error
            raise
        raise Partial(
            what="incidents.json was replaced, but the replace did not complete durably",
            error=str(error),
            record=str(record_path),
            incidents_sha256_current=current,
            incidents_sha256_after=after,
        ) from error
    current = current_hash(incidents_path)
    if current != after:
        raise Partial(
            what="incidents.json was replaced, but it does not read back as the record states",
            record=str(record_path),
            incidents_sha256_current=current,
            incidents_sha256_after=after,
        )
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
    except Partial as partial:
        print(json.dumps(dict(result="partial", **partial.facts), sort_keys=True))
        return 3
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps(dict(result="refused", reason=str(error))))
        return 2


if __name__ == "__main__":
    sys.exit(main())
