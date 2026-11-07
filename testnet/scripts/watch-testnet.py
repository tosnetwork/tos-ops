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
  mempool_eligible  mempool_postponed  mempool_oldest_age_s
  jsonrpc_active_requests  metrics_snapshot_age_s  metrics_generation
  missing_reason

An unobserved value is written as `-`. A host that cannot be read is still
written, every round, as a row with reachable False, every value `-` and a
fixed missing_reason code (MISSING_REASONS; never command output); the watch
never stops because one host or probe failed. On stdout it prints one line per event,
for a person or a monitor to read:

  ANOMALY <utc> <host>:<reason> ...   when the set of anomalies changes
  RECOVERED <utc> all clear           when it empties
  SUMMARY <utc> heights host=seqno .. every --summary-every seconds
  CURRENT <utc> <host> after <s> s    with --until-current, then exits
  ALERT <utc> <host>:missing_for=<s>s reason=<code>
                                      with --require-load-metrics, once per
                                      outage after --missing-alert-after
                                      seconds (default 600, monotonic clock)
                                      without a sample

Anomalies: host unreachable; unit not active; unit restart count changed;
head age above --max-head-age; head seqno unchanged for --stuck-samples
rounds; net failures up by --net-failure-burst or more in one round (single
retried failures are normal); free space below --min-free-gib.

--until-current HOST records a restarted validator's catch-up: it exits 0
once HOST's shard client age falls below 60 s, printing the time since the
watch started (start it right after the restart), or exits 1 after
--duration.

--require-load-metrics requires --cpu-sample > 0, reports every missing resource
sample and stale/over-limit queues, and exits 1 if any anomaly occurred during
the run. Without it, ordinary alert debounce and exit behavior are unchanged.
In that mode a host missing for --missing-alert-after seconds is alerted once;
it is alerted again only after it was observed and then went missing again.
Use a new TSV when its header differs; old files are never silently migrated
(the trailing missing_reason column was added this way: a series written before
it is refused, not extended).

Exit status: 0 when --once or --duration ends (except strict anomalies),
1 on a bad inventory or mismatched TSV header.
"""

from __future__ import annotations

import argparse
import json
import math
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
    "mempool_eligible",
    "mempool_postponed",
    "mempool_oldest_age_s",
    "jsonrpc_active_requests",
    "metrics_snapshot_age_s",
    "metrics_generation",
    "missing_reason",
)

SSH_FAILED = "ssh_failed"
PROBE_TIMEOUT = "probe_timeout"
LAUNCH_FAILED = "probe_launch_failed"
NO_OUTPUT = "probe_no_output"
OUTPUT_INVALID = "probe_output_invalid"
PROBE_REFUSED = "probe_refused"
MISSING_REASONS = frozenset(
    (SSH_FAILED, PROBE_TIMEOUT, LAUNCH_FAILED, NO_OUTPUT, OUTPUT_INVALID, PROBE_REFUSED)
)
NUMERIC_FIELDS = (
    "unit_restarts",
    "head_seqno",
    "head_age_seconds",
    "shard_client_age_seconds",
    "net_failures_total",
    "refusal_answers_total",
    "rss_bytes",
    "consensus_bytes",
    "consensus_sessions",
    "free_bytes",
    "cpu_busy_pct",
    "cpu_iowait_pct",
    "mempool_eligible",
    "mempool_postponed",
    "mempool_oldest_age_seconds",
    "jsonrpc_active_requests",
    "metrics_snapshot_timestamp",
    "metrics_generation",
)
# row() converts these with int(), which refuses an infinity or NaN.
WHOLE_FIELDS = (
    "head_age_seconds",
    "shard_client_age_seconds",
    "net_failures_total",
    "refusal_answers_total",
)

LOAD_FIELDS = (
    "unit_restarts",
    "head_seqno",
    "head_age_s",
    "shard_client_age_s",
    "rss_mb",
    "consensus_mb",
    "consensus_sessions",
    "free_gib",
    "cpu_busy_pct",
    "cpu_iowait_pct",
    "mempool_eligible",
    "mempool_postponed",
    "mempool_oldest_age_s",
    "jsonrpc_active_requests",
    "metrics_snapshot_age_s",
    "metrics_generation",
)


def utc(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def probe(
    host: preflight.Host,
    cpu_sample: float,
    run=subprocess.run,
    retry_after: float = 5.0,
    sleep=time.sleep,
) -> dict | None:
    """One check-host-disk.py report from the host, or None when it cannot be read."""
    return probe_report(host, cpu_sample, run, retry_after, sleep)[0]


def probe_report(
    host: preflight.Host,
    cpu_sample: float,
    run=subprocess.run,
    retry_after: float = 5.0,
    sleep=time.sleep,
) -> tuple[dict | None, str | None]:
    """(report, None), or (None, a MISSING_REASONS code) when it cannot be read.

    A failed read is tried once more after `retry_after` seconds: hosts on the
    public internet see constant SSH login scans, and sshd drops some new
    connections while many unauthenticated ones are pending (MaxStartups), which
    would otherwise show a healthy node as unreachable.
    """
    report, reason = probe_attempt(host, cpu_sample, run)
    if report is None and retry_after > 0:
        sleep(retry_after)
        report, reason = probe_attempt(host, cpu_sample, run)
    return report, reason


def valid_report(report) -> bool:
    """Whether row() and Judge can read every value without a type error."""
    if not isinstance(report, dict):
        return False
    active = report.get("unit_active")
    if active is not None and not isinstance(active, str):
        return False
    for key in NUMERIC_FIELDS:
        value = report.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))):
            return False
    return all(report.get(key) is None or math.isfinite(report[key]) for key in WHOLE_FIELDS)


def probe_once(host: preflight.Host, cpu_sample: float, run=subprocess.run) -> dict | None:
    return probe_attempt(host, cpu_sample, run)[0]


def probe_attempt(
    host: preflight.Host, cpu_sample: float, run=subprocess.run
) -> tuple[dict | None, str | None]:
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
    except subprocess.TimeoutExpired:
        return None, PROBE_TIMEOUT
    except OSError:
        return None, LAUNCH_FAILED
    lines = (result.stdout or "").strip().splitlines()
    if not lines:
        return None, SSH_FAILED if getattr(result, "returncode", None) == 255 else NO_OUTPUT
    try:
        report = json.loads(lines[-1])
    except ValueError:
        return None, OUTPUT_INVALID
    if isinstance(report, dict) and "refused" in report:
        return None, PROBE_REFUSED
    if not valid_report(report):
        return None, OUTPUT_INVALID
    return report, None


def row(now: float, name: str, report: dict | None, reason: str | None = None) -> dict:
    out = dict.fromkeys(COLUMNS)
    out["utc"], out["host"], out["reachable"] = utc(now), name, report is not None
    if report is None:
        out["missing_reason"] = reason if reason in MISSING_REASONS else NO_OUTPUT
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
        mempool_eligible=report.get("mempool_eligible"),
        mempool_postponed=report.get("mempool_postponed"),
        mempool_oldest_age_s=report.get("mempool_oldest_age_seconds"),
        jsonrpc_active_requests=report.get("jsonrpc_active_requests"),
        metrics_snapshot_age_s=(
            None
            if report.get("metrics_snapshot_timestamp") is None
            else now - report["metrics_snapshot_timestamp"]
        ),
        metrics_generation=report.get("metrics_generation"),
    )
    return out


class Judge:
    """Anomalies across rounds; keeps only the previous round's counters."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.previous: dict[str, dict] = {}
        self.stuck: dict[str, int] = {}
        self.unreachable: dict[str, int] = {}

    def __call__(self, current: dict) -> list[str]:
        args, found = self.args, []
        name, before = current["host"], self.previous.get(current["host"])
        if not current["reachable"]:
            # Ordinary alerts debounce SSH failures; strict load observation
            # records every missing sample, even if a later round recovers.
            self.unreachable[name] = self.unreachable.get(name, 0) + 1
            if (
                getattr(args, "require_load_metrics", False)
                or self.unreachable[name] >= args.unreachable_samples
            ):
                found.append(f"{name}:unreachable")
        else:
            self.unreachable[name] = 0
            if getattr(args, "require_load_metrics", False):
                for key in LOAD_FIELDS:
                    value = current[key]
                    if value is None or not math.isfinite(value) or value < 0:
                        found.append(f"{name}:unobserved={key}")
                age = current["metrics_snapshot_age_s"]
                if age is not None and age > args.max_metrics_age:
                    found.append(f"{name}:metrics_stale={age:.1f}s")
                oldest = current["mempool_oldest_age_s"]
                if oldest is not None and oldest > args.max_mempool_age:
                    found.append(f"{name}:mempool_age={oldest}s")
                eligible, postponed = current["mempool_eligible"], current["mempool_postponed"]
                if eligible is not None and postponed is not None:
                    if eligible + postponed > args.max_mempool_messages:
                        found.append(f"{name}:mempool_messages={eligible + postponed}")
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
    if not new:
        with path.open() as previous:
            if previous.readline().rstrip("\n") != "\t".join(COLUMNS):
                raise lib.TestnetError("TSV header differs; use a new observation file")
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


class MissingAlerts:
    """One alert per outage, after `after` seconds without a sample from the host.

    `at` is a monotonic reading, so a wall-clock step cannot shorten or stretch
    an outage; only the printed timestamps are UTC.
    """

    def __init__(self, after: float):
        self.after = after
        self.since: dict[str, float] = {}
        self.alerted: set[str] = set()

    def __call__(self, current: dict, at: float) -> str | None:
        name = current["host"]
        if current["reachable"]:
            self.since.pop(name, None)
            self.alerted.discard(name)
            return None
        first = self.since.setdefault(name, at)
        if name in self.alerted or at - first < self.after:
            return None
        self.alerted.add(name)
        return f"{name}:missing_for={int(at - first)}s reason={current['missing_reason']}"


def watch(
    args: argparse.Namespace,
    probe=probe_report,
    now=time.time,
    sleep=time.sleep,
    emit=print,
    monotonic=time.monotonic,
) -> int:
    hosts = select_hosts(preflight.load_inventory(args.inventory), args.hosts)
    if args.until_current and args.until_current not in {h.name for h in hosts}:
        raise lib.TestnetError(f"--until-current {args.until_current} is not a watched host")
    judge = Judge(args)
    strict = getattr(args, "require_load_metrics", False)
    missing_alerts = MissingAlerts(getattr(args, "missing_alert_after", 600.0))
    observed_anomaly = False
    # Durations (horizon, pacing, summaries, catch-up time) use the monotonic
    # clock; the wall clock only stamps rows and events.
    started = monotonic()
    last_summary = None
    last_anomalies: list[str] = []
    while True:
        round_start = now()
        round_clock = monotonic()
        rows = []
        for h in hosts:
            report, reason = probe(h, args.cpu_sample)
            rows.append(row(now(), h.name, report, reason))
        append_rows(args.out, rows)
        anomalies = [a for r in rows for a in judge(r)]
        observed_anomaly |= bool(anomalies)
        stamp = utc(round_start)
        if strict:
            for r in rows:
                alert = missing_alerts(r, round_clock)
                if alert:
                    emit(f"ALERT {stamp} {alert}")
        if anomalies != last_anomalies:
            if anomalies:
                emit(f"ANOMALY {stamp} {' '.join(anomalies)}")
            else:
                emit(f"RECOVERED {stamp} all clear")
            last_anomalies = anomalies
        if last_summary is None or round_clock - last_summary >= args.summary_every:
            heights = " ".join(f"{r['host']}={r['head_seqno'] or '-'}" for r in rows)
            emit(f"SUMMARY {stamp} heights {heights}")
            last_summary = round_clock
        if args.until_current:
            target = next(r for r in rows if r["host"] == args.until_current)
            age = target["shard_client_age_s"]
            if age is not None and age < CURRENT_SHARD_AGE:
                emit(
                    f"CURRENT {stamp} {args.until_current} after {int(round_clock - started)} s "
                    f"(shard client age {age} s)"
                )
                return 0
        if args.once:
            return int(getattr(args, "require_load_metrics", False) and observed_anomaly)
        if args.duration is not None and monotonic() - started >= args.duration:
            if args.until_current:
                emit(f"NOT CURRENT {stamp} {args.until_current} after {args.duration} s")
                return 1
            return int(getattr(args, "require_load_metrics", False) and observed_anomaly)
        sleep(max(0.0, args.interval - (monotonic() - round_clock)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=60.0)
    parser.add_argument("--hosts")
    parser.add_argument("--cpu-sample", type=float, default=0.0)
    parser.add_argument("--require-load-metrics", action="store_true")
    parser.add_argument("--max-metrics-age", type=float, default=120.0)
    parser.add_argument("--max-mempool-age", type=float, default=30.0)
    parser.add_argument("--max-mempool-messages", type=int, default=10000)
    parser.add_argument("--missing-alert-after", type=float, default=600.0)
    stop = parser.add_mutually_exclusive_group()
    stop.add_argument("--duration", type=float)
    stop.add_argument("--once", action="store_true")
    parser.add_argument("--summary-every", type=float, default=900.0)
    parser.add_argument("--max-head-age", type=int, default=120)
    parser.add_argument("--stuck-samples", type=int, default=3)
    parser.add_argument("--unreachable-samples", type=int, default=2)
    parser.add_argument("--net-failure-burst", type=int, default=5)
    parser.add_argument("--min-free-gib", type=float, default=20.0)
    parser.add_argument("--until-current")
    args = parser.parse_args(argv)
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    if not 0 <= args.cpu_sample <= 60:
        parser.error("--cpu-sample must be between 0 and 60 seconds")
    if args.require_load_metrics and (args.cpu_sample <= 0 or args.until_current):
        parser.error("load observation requires positive --cpu-sample and no --until-current")
    if any(
        not math.isfinite(v) or v <= 0
        for v in (
            args.max_metrics_age,
            args.max_mempool_age,
            args.max_mempool_messages,
            args.missing_alert_after,
        )
    ):
        parser.error("load observation thresholds must be finite and positive")
    if args.duration is not None and args.duration <= 0:
        parser.error("--duration must be positive")
    if (
        args.stuck_samples < 1
        or args.unreachable_samples < 1
        or args.net_failure_burst < 1
        or args.max_head_age < 1
    ):
        parser.error("thresholds must be positive")
    try:
        return watch(args, emit=lambda line: print(line, flush=True))
    except (lib.TestnetError, OSError, KeyError, ValueError) as exc:
        print(f"REFUSED {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
