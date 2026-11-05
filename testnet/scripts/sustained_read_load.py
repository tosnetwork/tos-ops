"""Bounded streaming RPC read load; evidence only, no keys or value actions."""

import hashlib
import json
import math
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from read_client import NETWORK_DEADLINE_SECONDS, request

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5)
METHODS = (
    "getMasterchainInfo",
    "getAddressInformation",
    "getTransactions",
    "getAddressInformation",
)


def durable(path, value, before_publish=None):
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
        fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if created:
            temporary.unlink(missing_ok=True)


def percentile(histogram, fraction):
    threshold = math.ceil(sum(histogram) * fraction)
    if threshold == 0:
        return None
    count = 0
    for upper, number in zip((*BUCKETS, "infinity"), histogram, strict=True):
        count += number
        if count >= threshold:
            return upper


def verdict(window, seconds, rate):
    count = window["completed"]
    p95 = percentile(window["histogram"], 0.95)
    p99 = percentile(window["histogram"], 0.99)
    return {
        "pass": count > 0
        and count / seconds >= rate * 0.90
        and window["errors"] / count <= 0.01
        and p95 != "infinity"
        and p99 != "infinity"
        and p95 <= 2
        and p99 <= 5,
        "completed": count,
        "errors": window["errors"],
        "offered_fraction": count / seconds / rate,
        "p95_upper_seconds": p95,
        "p99_upper_seconds": p99,
        "histogram": window["histogram"],
        "duration_seconds": seconds,
    }


def worker_budget(rate):
    """Cover one network deadline plus 0.5s scheduling margin, at most48 workers.

    This is bounded admission capacity, not a relaxed SLO or a throughput claim.
    The same count bounds submitted futures, so there is no executor backlog.
    """
    if type(rate) is not int or not 1 <= rate <= 16:
        raise RuntimeError("Read worker rate bound")
    maximum = math.ceil(rate * (NETWORK_DEADLINE_SECONDS + 0.5))
    if not 1 <= maximum <= 48:
        raise RuntimeError("Read worker budget exceeds48")
    return maximum


def run(packet, output):
    duration, rate, width = (
        packet["duration_seconds"],
        packet["requests_per_second"],
        packet["window_seconds"],
    )
    endpoints, address = packet["endpoints"], packet["address"]
    if not (
        type(duration) is int
        and 1 <= duration <= 345600
        and type(rate) is int
        and 1 <= rate <= 16
        and type(width) is int
        and 1 <= width <= 600
        and math.ceil(duration / width) <= 1000
    ):
        raise RuntimeError("Read horizon/rate/window bound")
    if duration * rate * 512 > 1 << 30:
        raise RuntimeError("Read horizon exceeds bounded journal budget")
    if endpoints != [
        "http://127.0.0.1:48081/jsonRPC",
        "http://127.0.0.1:48083/jsonRPC",
    ]:
        raise RuntimeError("Exact approved two-source topology required")
    if address != "0:ce32c0cfd54873d65fdd4b8b1710605ae2176734a1015d2d2c1ea00d8025f15a":
        raise RuntimeError("Original public wallet required")
    if shutil.disk_usage(output.parent).free < 20 << 30:
        raise RuntimeError("Initial read disk reserve")
    output.mkdir(mode=0o700)
    started = time.monotonic()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    windows = [
        {"completed": 0, "errors": 0, "histogram": [0] * (len(BUCKETS) + 1)}
        for _ in range(math.ceil(duration / width))
    ]
    pending, completed_windows = {}, set()
    slot = completed = errors = missed = 0
    last_complete = last_publish = started
    journal_hash = hashlib.sha256()
    maximum_pending = worker_budget(rate)
    pool = ThreadPoolExecutor(max_workers=maximum_pending)

    def invoke(endpoint, method):
        began = time.monotonic()
        result = request(endpoint, method, address)
        result["offered_monotonic_seconds"] = began
        result["finished_monotonic_seconds"] = time.monotonic()
        return result

    def fresh_progress():
        if time.monotonic() - last_complete > 15:
            raise RuntimeError("Actual read response progress expired")

    try:
        durable(
            output / "CONTEXT.json",
            {
                "packet": packet,
                "maximum_inflight": maximum_pending,
                "network_deadline_seconds": NETWORK_DEADLINE_SECONDS,
                "boot_id": boot,
                "started_monotonic_seconds": started,
                "deadline_monotonic_seconds": started + duration,
                "scope": "Read-only RPC workload, not native authentication or full acceptance",
            },
        )
        with (output / "requests.jsonl").open("xb") as stream:
            while (
                time.monotonic() < started + duration
                or pending
                or len(completed_windows) < len(windows)
            ):
                now = time.monotonic()
                for future in [future for future in pending if future.done()]:
                    result = future.result()
                    del pending[future]
                    position = int((result["offered_monotonic_seconds"] - started) // width)
                    if (
                        not 0 <= position < len(windows)
                        or result["offered_monotonic_seconds"] >= started + duration
                    ):
                        raise RuntimeError("Actual request offered outside declared interval")
                    window = windows[position]
                    window["completed"] += 1
                    window["errors"] += int(result["error"] is not None)
                    bucket = next(
                        (
                            i
                            for i, upper in enumerate(BUCKETS)
                            if result["latency_seconds"] <= upper
                        ),
                        len(BUCKETS),
                    )
                    window["histogram"][bucket] += 1
                    line = (json.dumps(result) + "\n").encode()
                    if len(line) > 512:
                        raise RuntimeError("Read record exceeds declared line bound")
                    stream.write(line)
                    journal_hash.update(line)
                    completed += 1
                    errors += int(result["error"] is not None)
                    last_complete = max(last_complete, result["finished_monotonic_seconds"])
                    if result["error"] == "NamespaceError":
                        raise RuntimeError("Read source namespace changed")
                if now < started + duration and now >= started + slot / rate:
                    if len(pending) >= maximum_pending:
                        missed += 1
                    else:
                        endpoint = endpoints[slot % 2]
                        method = METHODS[(slot // 2) % len(METHODS)]
                        future = pool.submit(invoke, endpoint, method)
                        pending[future] = now
                    slot += 1
                if now - last_complete > 15:
                    raise RuntimeError("No bounded read response progress")
                for position in range(len(completed_windows), len(windows)):
                    end = started + min(duration, (position + 1) * width)
                    if now < end or any(offered < end for offered in pending.values()):
                        break
                    seconds = min(width, duration - position * width)
                    report = verdict(windows[position], seconds, rate)
                    durable(
                        output / f"WINDOW-{position:04d}.json",
                        {"index": position, **report},
                    )
                    completed_windows.add(position)
                    if not report["pass"]:
                        raise RuntimeError("Declared read-window criteria failed")
                if now - last_publish >= 5:
                    if stream.tell() > 1 << 30 or shutil.disk_usage(output).free < 20 << 30:
                        raise RuntimeError("Read log or free disk bound")
                    stream.flush()
                    os.fsync(stream.fileno())
                    durable(
                        output / "LATEST.json",
                        {
                            "status": "READ_LOAD_RUNNING_NOT_ACCEPTED",
                            "checked_unix": time.time(),
                            "started_monotonic_seconds": started,
                            "boot_id": boot,
                            "completed": completed,
                            "errors": errors,
                            "not_offered_capacity": missed,
                            "completed_windows": len(completed_windows),
                            "last_response_monotonic_seconds": last_complete,
                        },
                        before_publish=fresh_progress,
                    )
                    last_publish = now
                if now - started > duration + 30:
                    raise RuntimeError("Read completion drain deadline")
                time.sleep(0.01)
            stream.flush()
            os.fsync(stream.fileno())
        if len(completed_windows) != len(windows):
            raise RuntimeError("Missing complete read windows")
        result = {
            "status": "DECLARED_READ_LOAD_WINDOWS_COMPLETE",
            "boot_id": boot,
            "started_monotonic_seconds": started,
            "deadline_monotonic_seconds": started + duration,
            "completed": completed,
            "errors": errors,
            "not_offered_capacity": missed,
            "windows": len(windows),
            "maximum_inflight": maximum_pending,
            "requests_sha256": journal_hash.hexdigest(),
            "scope": "RPC read-load/rate/latency only. Requires independent original producer interval overlap, resource, proof and full acceptance audit.",
        }
        durable(output / "RESULT.json", result)
        durable(
            output / "LATEST.json",
            {
                **result,
                "status": "READ_LOAD_COMPLETE_PENDING_ACCEPTANCE",
                "checked_unix": time.time(),
                "last_response_monotonic_seconds": last_complete,
            },
        )
        return result
    except BaseException:
        durable(
            output / "LATEST.json",
            {
                "status": "READ_LOAD_FAILED",
                "checked_unix": time.time(),
                "completed": completed,
                "errors": errors,
                "scope": "Retain original evidence; no automatic restart",
            },
        )
        raise
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    frozen = Path("/opt/tos-acceptance/e7-read-load-72h-20261105-r2")
    packet = json.loads((frozen / "READ-LOAD-PACKET.json").read_text())
    print(json.dumps(run(packet, Path(packet["output"]))))
