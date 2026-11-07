"""Derive fixed-window SLOs from an already fully native-verified closed run.

This is a derived report, not a cryptographic verifier. Pin the native replay
result independently. Its complete journal/summary hashes bind this calculation
back to the proof/history/digest/clock coverage that must already be accepted.
"""

import argparse
import hashlib
import json
import math
import os
import shutil
import stat
from pathlib import Path

from load_finality_window import BUCKETS
from load_run_replay import MIB, EventIndex, durable_json, require, snapshot

STATUS = "FULL_STREAMED_CLOSED_RUN_PROOF_HISTORY_DIGEST_CLOCK_COVERAGE_VERIFIED"


def quantile(histogram, fraction):
    rank = math.ceil(sum(histogram) * fraction)
    require(rank > 0, "empty window cannot meet latency criteria")
    count = 0
    for upper, value in zip((*BUCKETS, "infinity"), histogram, strict=True):
        count += value
        if count >= rank:
            return upper
    raise RuntimeError("invalid histogram")


def calculate(index, result, summary, window_seconds):
    require(type(window_seconds) is int and 1 <= window_seconds <= 3600, "invalid window")
    start = index.stage_started
    require(start is not None, "fixed stage required")
    duration = start["duration_seconds"]
    require(
        type(duration) in (int, float)
        and duration > 0
        and duration % window_seconds == 0
        and duration / window_seconds <= 10000,
        "complete bounded equal windows required",
    )
    begin = start["started_monotonic_seconds"]
    target = summary["target_batches_per_second"]
    require(
        type(target) in (int, float) and math.isfinite(target) and target > 0,
        "invalid declared rate",
    )
    count = int(duration / window_seconds)
    windows = [
        {
            "index": number,
            "start_monotonic_seconds": begin + number * window_seconds,
            "end_monotonic_seconds": begin + (number + 1) * window_seconds,
            "offered": 0,
            "histogram": [0] * (len(BUCKETS) + 1),
        }
        for number in range(count)
    ]
    total_histogram = [0] * (len(BUCKETS) + 1)
    observed_previous = index.baseline["verified_observation_monotonic_seconds"]
    boot = index.baseline["boot_id"]
    for (raw,) in index.db.execute("SELECT event FROM checkpoints ORDER BY number"):
        checkpoint = json.loads(raw)
        observed = checkpoint["verified_observation_monotonic_seconds"]
        require(
            checkpoint["boot_id"] == boot and observed >= observed_previous,
            "checkpoint clock or boot changed",
        )
        observed_previous = observed
        ids = checkpoint.get("query_ids", [])
        require(type(ids) is list and len(ids) == len(set(ids)), "duplicate checkpoint query")
        for query in ids:
            row = index.db.execute(
                "SELECT clock,boot,matched FROM offers WHERE q=?", (query,)
            ).fetchone()
            require(
                row is not None and row[2] == 0 and row[1] == boot,
                "missing or repeated native completion",
            )
            offered = row[0]
            require(
                begin <= offered < begin + duration and observed >= offered,
                "query outside stage or negative latency",
            )
            position = int((offered - begin) // window_seconds)
            latency = observed - offered
            bucket = next((i for i, upper in enumerate(BUCKETS) if latency <= upper), len(BUCKETS))
            windows[position]["offered"] += 1
            windows[position]["histogram"][bucket] += 1
            total_histogram[bucket] += 1
            index.db.execute("UPDATE offers SET matched=1 WHERE q=?", (query,))
    require(
        index.db.execute("SELECT count(*) FROM offers WHERE matched!=1").fetchone()[0] == 0,
        "incomplete native population",
    )
    require(
        index.offers == result["offered"] == summary["qualification"]["offered"]
        and total_histogram == result["recomputed_histogram"],
        "verified population differs",
    )
    for window in windows:
        window["offered_per_second"] = window["offered"] / window_seconds
        window["minimum_offering_fraction"] = 0.90
        window["offering_fraction"] = window["offered_per_second"] / target
        window["p95_upper_seconds"] = (
            quantile(window["histogram"], 0.95) if window["offered"] else None
        )
        window["p99_upper_seconds"] = (
            quantile(window["histogram"], 0.99) if window["offered"] else None
        )
        window["pass"] = (
            window["offered"] > 0
            and window["offering_fraction"] >= 0.90
            and window["p95_upper_seconds"] != "infinity"
            and window["p99_upper_seconds"] != "infinity"
            and window["p95_upper_seconds"] <= 5
            and window["p99_upper_seconds"] <= 10
        )
    return {
        "status": "DERIVED_WINDOWS_PASS"
        if all(w["pass"] for w in windows)
        else "DERIVED_WINDOWS_FAIL",
        "scope": "Derived fixed-window rate/native latency only; relies on separately trusted pinned full replay result; not resource/leak/72h or full acceptance",
        "window_seconds": window_seconds,
        "duration_seconds": duration,
        "offered": index.offers,
        "recomputed_histogram": total_histogram,
        "windows": windows,
    }


def audit(args):
    run = Path(args.run).resolve(strict=True)
    events = run / "events.jsonl"
    output = Path(args.output).absolute()
    require(
        output.parent.resolve(strict=True) == output.parent
        and output != run
        and run not in output.parents
        and output not in run.parents,
        "separate canonical output required",
    )
    result_raw = snapshot(args.replay_result, MIB)
    require(
        hashlib.sha256(result_raw).hexdigest() == args.replay_result_sha256, "replay result pin"
    )
    result = json.loads(result_raw)
    require(
        result["status"] == STATUS
        and result["identity"]["run"] == str(run)
        and result["source_native_latency_criteria_pass"] is True,
        "full native coverage required",
    )
    summary_raw = snapshot(args.summary, MIB)
    require(hashlib.sha256(summary_raw).hexdigest() == result["summary_sha256"], "summary pin")
    summary = json.loads(summary_raw)
    require(
        summary["qualification"]["safe_to_start_new_run"] is True
        and summary["qualification"]["run_directory"] == run.name,
        "safe original run required",
    )
    require(shutil.disk_usage(output.parent).free >= 20 << 30, "audit free disk reserve")
    output.mkdir(mode=0o700)
    index = EventIndex(output / "index.sqlite", run)
    try:
        digest = hashlib.sha256()
        with os.fdopen(os.open(events, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            before = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(before.st_mode) and before.st_size <= 16 << 30, "journal bound/type"
            )
            lines = 0
            while line := stream.readline(MIB + 1):
                lines += 1
                require(
                    lines <= 12_000_000 and len(line) <= MIB and line.endswith(b"\n"),
                    "journal line bound",
                )
                digest.update(line)
                index.add(json.loads(line))
                if lines % 4096 == 0:
                    require(shutil.disk_usage(output).free >= 20 << 30, "audit free disk reserve")
            after = os.fstat(stream.fileno())
            require(
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                "journal changed",
            )
        require(digest.hexdigest() == result["events_sha256"], "full verified journal hash differs")
        index.finish_index()
        report = calculate(index, result, summary, args.window_seconds)
        report.update(
            replay_result_sha256=args.replay_result_sha256,
            events_sha256=digest.hexdigest(),
            summary_sha256=result["summary_sha256"],
            run=str(run),
        )
        durable_json(output / "RESULT.json", report)
        return report
    finally:
        index.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--replay-result", required=True, type=Path)
    parser.add_argument("--replay-result-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--window-seconds", required=True, type=int)
    args = parser.parse_args()
    report = audit(args)
    print(json.dumps(report))
    raise SystemExit(0 if report["status"] == "DERIVED_WINDOWS_PASS" else 1)


if __name__ == "__main__":
    main()
