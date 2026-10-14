#!/usr/bin/env python3
"""Sample every validator host on a schedule, keep the series, and report anomalies.

  watch-testnet.py --inventory hosts.json --out series.tsv
                   [--interval 60] [--hosts node-1,node-4] [--cpu-sample 0]
                   [--duration SECONDS | --once] [--summary-every 900]
                   [--max-head-age 120] [--stuck-samples 3] [--net-failure-burst 5]
                   [--min-free-gib 20] [--until-current HOST]

Runs on the coordinator. Each round it pipes check-host-disk.py to every
validator host in the inventory (or the named --hosts) over SSH, so the hosts
need nothing installed, and appends one TSV row per host to --out:

  utc  host  reachable  unit_active  unit_restarts  head_seqno  head_age_s
  shard_client_age_s  net_failures  refusal_answers  rss_mb  consensus_mb
  consensus_sessions  free_gib  cpu_busy_pct  cpu_iowait_pct

An unobserved value is written as `-`. On stdout it prints one line per event,
for a person or a monitor to read:

  ANOMALY <utc> <host>:<reason> ...   when the set of anomalies changes
  RECOVERED <utc> all clear           when it empties
  SUMMARY <utc> heights host=seqno .. every --summary-every seconds
  CURRENT <utc> <host> after <s> s    with --until-current, then exits

Anomalies: host unreachable; unit not active; unit restart count changed;
head age above --max-head-age; head seqno unchanged for --stuck-samples
rounds; net failures up by --net-failure-burst or more in one round (single
retried failures are normal); free space below --min-free-gib.

--until-current HOST records a restarted validator's catch-up: it exits 0
once HOST's shard client age falls below 60 s, printing the time since the
watch started (start it right after the restart), or exits 1 after
--duration.

Exit status: 0 when --once or --duration ends, 1 on a bad inventory.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import preflight  # noqa: E402
import testnet_lib as lib  # noqa: E402

PROBE = Path(__file__).resolve().parent / "check-host-disk.py"
MIB = 1 << 20
GIB = 1 << 30
CURRENT_SHARD_AGE = 60

COLUMNS = (
    "utc",
    "host",
    "reachable",
    "unit_active",
    "unit_restarts",
    "head_seqno",
    "head_age_s",
    "shard_client_age_s",
    "net_failures",
    "refusal_answers",
    "rss_mb",
    "consensus_mb",
    "consensus_sessions",
    "free_gib",
    "cpu_busy_pct",
    "cpu_iowait_pct",
)


def utc(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def probe(host: preflight.Host, cpu_sample: float, run=subprocess.run) -> dict | None:
    """One check-host-disk.py report from the host, or None when it cannot be read."""
    argv = preflight.ssh_argv(host, accept_new=False) + [
        f"python3 - --min-free-gib 0 --cpu-sample {cpu_sample:g}"
    ]
    try:
        result = run(
            argv,
            input=PROBE.read_text(),
            capture_output=True,
            text=True,
            timeout=60 + cpu_sample,
            check=False,
        )
        report = json.loads(result.stdout.strip().splitlines()[-1])
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return None
    if "refused" in report:
        return None
    return report


def row(now: float, name: str, report: dict | None) -> dict:
    out = dict.fromkeys(COLUMNS)
    out["utc"], out["host"], out["reachable"] = utc(now), name, report is not None
    if report is None:
        return out

    def scaled(key: str, unit: int):
        value = report.get(key)
        return None if value is None else round(value / unit, 1)

    def whole(key: str):
        value = report.get(key)
        return None if value is None else int(value)

    out.update(
        unit_active=report.get("unit_active"),
        unit_restarts=report.get("unit_restarts"),
        head_seqno=report.get("head_seqno"),
        head_age_s=whole("head_age_seconds"),
        shard_client_age_s=whole("shard_client_age_seconds"),
        net_failures=whole("net_failures_total"),
        refusal_answers=whole("refusal_answers_total"),
        rss_mb=scaled("rss_bytes", MIB),
        consensus_mb=scaled("consensus_bytes", MIB),
        consensus_sessions=report.get("consensus_sessions"),
        free_gib=scaled("free_bytes", GIB),
        cpu_busy_pct=report.get("cpu_busy_pct"),
        cpu_iowait_pct=report.get("cpu_iowait_pct"),
    )
    return out


class Judge:
    """Anomalies across rounds; keeps only the previous round's counters."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.previous: dict[str, dict] = {}
        self.stuck: dict[str, int] = {}

    def __call__(self, current: dict) -> list[str]:
        args, found = self.args, []
        name, before = current["host"], self.previous.get(current["host"])
        if not current["reachable"]:
            found.append(f"{name}:unreachable")
        else:
            if current["unit_active"] != "active":
                found.append(f"{name}:unit={current['unit_active']}")
            if (
                before
                and None not in (before["unit_restarts"], current["unit_restarts"])
                and current["unit_restarts"] != before["unit_restarts"]
            ):
                found.append(f"{name}:restarts={current['unit_restarts']}")
            if current["head_age_s"] is not None and current["head_age_s"] > args.max_head_age:
                found.append(f"{name}:head_age={current['head_age_s']}s")
            seqno = current["head_seqno"]
            if before and seqno is not None and seqno == before["head_seqno"]:
                self.stuck[name] = self.stuck.get(name, 0) + 1
            else:
                self.stuck[name] = 0
            if self.stuck[name] >= args.stuck_samples:
                found.append(f"{name}:head_stuck_at={seqno}")
            if (
                before
                and None not in (before["net_failures"], current["net_failures"])
                and current["net_failures"] - before["net_failures"] >= args.net_failure_burst
            ):
                found.append(f"{name}:net_failure_burst={current['net_failures']}")
            if current["free_gib"] is not None and current["free_gib"] < args.min_free_gib:
                found.append(f"{name}:free={current['free_gib']}GiB")
        self.previous[name] = current
        return found


def append_rows(path: Path, rows: list[dict]) -> None:
    new = not path.exists() or path.stat().st_size == 0
    with path.open("a") as out:
        if new:
            out.write("\t".join(COLUMNS) + "\n")
        for r in rows:
            out.write("\t".join("-" if r[c] is None else str(r[c]) for c in COLUMNS) + "\n")


def select_hosts(inventory: list[preflight.Host], names: str | None) -> list[preflight.Host]:
    validators = [h for h in inventory if "validator" in h.roles]
    if not names:
        if not validators:
            raise lib.TestnetError("the inventory names no validator host")
        return validators
    wanted = [n.strip() for n in names.split(",") if n.strip()]
    by_name = {h.name: h for h in validators}
    unknown = [n for n in wanted if n not in by_name]
    if unknown or not wanted:
        raise lib.TestnetError(f"not validator hosts in the inventory: {unknown or names}")
    return [by_name[n] for n in wanted]


def watch(
    args: argparse.Namespace, probe=probe, now=time.time, sleep=time.sleep, emit=print
) -> int:
    hosts = select_hosts(preflight.load_inventory(args.inventory), args.hosts)
    if args.until_current and args.until_current not in {h.name for h in hosts}:
        raise lib.TestnetError(f"--until-current {args.until_current} is not a watched host")
    judge = Judge(args)
    started = now()
    last_summary = None
    last_anomalies: list[str] = []
    while True:
        round_start = now()
        rows = [row(now(), h.name, probe(h, args.cpu_sample)) for h in hosts]
        append_rows(args.out, rows)
        anomalies = [a for r in rows for a in judge(r)]
        stamp = utc(round_start)
        if anomalies != last_anomalies:
            if anomalies:
                emit(f"ANOMALY {stamp} {' '.join(anomalies)}")
            else:
                emit(f"RECOVERED {stamp} all clear")
            last_anomalies = anomalies
        if last_summary is None or round_start - last_summary >= args.summary_every:
            heights = " ".join(f"{r['host']}={r['head_seqno'] or '-'}" for r in rows)
            emit(f"SUMMARY {stamp} heights {heights}")
            last_summary = round_start
        if args.until_current:
            target = next(r for r in rows if r["host"] == args.until_current)
            age = target["shard_client_age_s"]
            if age is not None and age < CURRENT_SHARD_AGE:
                emit(
                    f"CURRENT {stamp} {args.until_current} after {int(round_start - started)} s "
                    f"(shard client age {age} s)"
                )
                return 0
        if args.once:
            return 0
        if args.duration is not None and now() - started >= args.duration:
            if args.until_current:
                emit(f"NOT CURRENT {stamp} {args.until_current} after {args.duration} s")
                return 1
            return 0
        sleep(max(0.0, args.interval - (now() - round_start)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=60.0)
    parser.add_argument("--hosts")
    parser.add_argument("--cpu-sample", type=float, default=0.0)
    stop = parser.add_mutually_exclusive_group()
    stop.add_argument("--duration", type=float)
    stop.add_argument("--once", action="store_true")
    parser.add_argument("--summary-every", type=float, default=900.0)
    parser.add_argument("--max-head-age", type=int, default=120)
    parser.add_argument("--stuck-samples", type=int, default=3)
    parser.add_argument("--net-failure-burst", type=int, default=5)
    parser.add_argument("--min-free-gib", type=float, default=20.0)
    parser.add_argument("--until-current")
    args = parser.parse_args(argv)
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    if not 0 <= args.cpu_sample <= 60:
        parser.error("--cpu-sample must be between 0 and 60 seconds")
    if args.duration is not None and args.duration <= 0:
        parser.error("--duration must be positive")
    if args.stuck_samples < 1 or args.net_failure_burst < 1 or args.max_head_age < 1:
        parser.error("thresholds must be positive")
    try:
        return watch(args, emit=lambda line: print(line, flush=True))
    except (lib.TestnetError, OSError, KeyError, ValueError) as exc:
        print(f"REFUSED {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
