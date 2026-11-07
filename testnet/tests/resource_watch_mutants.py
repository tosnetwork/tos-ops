#!/usr/bin/env python3
"""Missing-row and alert mutants for the two resource monitors; every one must go red.

Each mutant is applied to a fresh copy of testnet/ in a temporary directory, so
the checkout is never modified. Only pytest's exit 1 with a failed test counts
as RED; a pattern that does not occur exactly once, a mutant that does not
parse, a green baseline failure, a survivor or an invalid run fails the whole run.

    unshare -rn python testnet/tests/resource_watch_mutants.py [LABEL ...]

Not collected by pytest.
"""

import ast
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

W = Path(__file__).resolve().parents[1]
EXTRA = "scripts/watch_extra_resources.py"
PRIMARY = "scripts/watch-testnet.py"
TESTS = {
    EXTRA: ["tests/test_watch_extra_resources.py"],
    PRIMARY: ["tests/test_watch_testnet.py", "tests/test_watch_testnet_missing.py"],
}
FAILED = re.compile(r"\b[1-9]\d* failed\b")
ERRORS = re.compile(r"\b[1-9]\d* errors?\b")

M = [
    (
        "E1 extra: raise on a failed host read restored",
        EXTRA,
        "    return host.name, None, reason\n",
        '    raise RuntimeError("Host resource observation unavailable: " + host.name)\n',
    ),
    (
        "E2 extra: a timeout ends the watch again",
        EXTRA,
        "    except subprocess.TimeoutExpired:\n        return None, PROBE_TIMEOUT_REASON\n",
        "",
    ),
    (
        "E3 extra: missing row dropped",
        EXTRA,
        "                append(stream, record)\n                if alert:\n",
        "                if alert:\n",
    ),
    (
        "E4 extra: alerts on every cycle",
        EXTRA,
        "        if host not in self.alerted and elapsed >= self.alert_after:\n",
        "        if True:\n",
    ),
    (
        "E5 extra: alerts every cycle after ten minutes",
        EXTRA,
        "        if host not in self.alerted and elapsed >= self.alert_after:\n",
        "        if elapsed >= self.alert_after:\n",
    ),
    (
        "E6 extra: never alerts",
        EXTRA,
        "            return first_unix, True, elapsed\n",
        "            return first_unix, False, elapsed\n",
    ),
    (
        "E7 extra: alert never re-armed after recovery",
        EXTRA,
        "        self.alerted.discard(host)\n",
        "        pass\n",
    ),
    (
        "E8 extra: partial cycle published as LATEST",
        EXTRA,
        "            if missing or violations:\n                append(\n",
        "            if False:\n                append(\n",
    ),
    (
        "E9 extra: stale clock tolerated",
        EXTRA,
        '                raise RuntimeError("Host observation clock stale")\n',
        "                pass\n",
    ),
    (
        "E10 extra: baseline not checked while a host is missing",
        EXTRA,
        "                if name in baseline:\n                    check(value, baseline[name])\n",
        "                if name in baseline and not missing:\n                    check(value, baseline[name])\n",
    ),
    (
        "E11 extra: child output written as the reason",
        EXTRA,
        "        return None, SSH_FAILED if child.returncode == 255 else PROBE_FAILED\n",
        "        return None, str(child.stderr)\n",
    ),
    (
        "V1 extra: inactive validator recorded as probe_failed missing data",
        EXTRA,
        "                    violations[name] = value\n                    continue\n",
        "                    missing[name] = PROBE_FAILED\n                    continue\n",
    ),
    (
        "V2 extra: outcome summary ignores the reason",
        EXTRA,
        '            if reason in VIOLATION_REASONS:\n                kind = "violation"\n',
        '            if False:\n                kind = "violation"\n',
    ),
    (
        "V3 extra: late observation classified before the integrity checks",
        EXTRA,
        "                # Every observation is checked, however late it is published.\n",
        "                if age > MAX_AGE:\n"
        "                    missing[name] = EXPIRED\n"
        "                    continue\n",
    ),
    (
        "V4 extra: reserves unchecked before the baseline",
        EXTRA,
        "                check_reserves(value)\n",
        "                pass\n",
    ),
    (
        "V5 extra: expired observation counted as fresh",
        EXTRA,
        "                if age > MAX_AGE:\n",
        "                if False:\n",
    ),
    (
        "V6 extra: inactive violation not written",
        EXTRA,
        '                    "reason": VALIDATOR_INACTIVE,\n',
        '                    "reason": PROBE_FAILED,\n',
    ),
    (
        "T1 extra: outage timed on wall time",
        EXTRA,
        "tracker.missing(name, cycle, stamp)",
        "tracker.missing(name, stamp, stamp)",
    ),
    (
        "T2 extra: alert duration from wall time",
        EXTRA,
        "missing_seconds=int(elapsed),",
        "missing_seconds=int(stamp - since),",
    ),
    (
        "T3 primary: outage timed on wall time",
        PRIMARY,
        "                alert = missing_alerts(r, round_clock)\n",
        "                alert = missing_alerts(r, round_start)\n",
    ),
    (
        "T4 extra: an expired observation resets the outage timer",
        EXTRA,
        "            for name in set(current) | set(violations):\n",
        "            for name in observed:\n",
    ),
    (
        "T5 primary: horizon on wall time",
        PRIMARY,
        "        if args.duration is not None and monotonic() - started >= args.duration:\n",
        "        if args.duration is not None and now() - started >= args.duration:\n",
    ),
    (
        "T6 primary: pacing on wall time",
        PRIMARY,
        "        sleep(max(0.0, args.interval - (monotonic() - round_clock)))\n",
        "        sleep(max(0.0, args.interval - (now() - round_start)))\n",
    ),
    (
        "T7 primary: horizon and pacing both on wall time",
        PRIMARY,
        "    started = monotonic()\n",
        "    started = now()\n    monotonic = now  # noqa: F841\n",
    ),
    (
        "T8 primary: summaries paced on wall time",
        PRIMARY,
        "        if last_summary is None or round_clock - last_summary >= args.summary_every:\n",
        "        if last_summary is None or round_start - last_summary >= args.summary_every:\n",
    ),
    (
        "B1 extra: one shared baseline, taken only from a complete cycle",
        EXTRA,
        "            for name in sorted(current):\n                if name not in baseline:\n",
        "            for name in sorted(current) if not missing and not violations else ():\n"
        "                if name not in baseline:\n",
    ),
    (
        "B2 extra: inactive sample not checked against its baseline",
        EXTRA,
        "                    if name in baseline:\n"
        "                        check_inactive(value, baseline[name])\n",
        "",
    ),
    (
        "B3 extra: baseline taken from a late or inactive sample",
        EXTRA,
        "            for name in sorted(current):\n                if name not in baseline:\n"
        "                    baseline[name] = current[name]\n",
        "            for name in sorted(observed):\n                if name not in baseline:\n"
        "                    baseline[name] = observed[name]\n",
    ),
    (
        "B4 extra: summary treats an unfinished series as complete",
        EXTRA,
        '    out["criteria_violated"] = out["violation_rows"] > 0 or not out["complete"]\n',
        '    out["criteria_violated"] = out["violation_rows"] > 0\n',
    ),
    (
        "B5 extra: hosts without a baseline not reported",
        EXTRA,
        '            "hosts_without_baseline": sorted(names - set(baseline)),\n',
        '            "hosts_without_baseline": [],\n',
    ),
    (
        "B6 extra: malformed observation passed to the checks",
        EXTRA,
        "    if not valid_observation(value):\n        return None, OUTPUT_INVALID\n",
        "",
    ),
    (
        "B7 extra: undecodable answer ends the watch",
        EXTRA,
        "    except UnicodeError:\n        # text=True decodes stdout and stderr before returning.\n"
        "        return None, OUTPUT_INVALID\n    except OSError:\n        return None, LAUNCH_FAILED\n",
        "    except OSError:\n        return None, LAUNCH_FAILED\n",
    ),
    (
        "B8 extra: publication freshness judged at a later now()",
        EXTRA,
        "before_publish=lambda: fresh(current, names, lambda: stamp),",
        "before_publish=lambda: fresh(current, names, now),",
    ),
    (
        "B9 extra: huge or non-finite time accepted",
        EXTRA,
        "        return math.isfinite(float(value))\n",
        "        return True\n",
    ),
    (
        "X1 extra: future observation accepted (skew bound removed)",
        EXTRA,
        "    if -age > MAX_FUTURE_SKEW_SECONDS:\n        raise",
        "    if False:\n        raise",
    ),
    (
        "F1 extra: no future tolerance (the earlier behaviour)",
        EXTRA,
        "MAX_FUTURE_SKEW_SECONDS = 2.0\n",
        "MAX_FUTURE_SKEW_SECONDS = 0.0\n",
    ),
    (
        "F2 extra: future_skew_ms not recorded",
        EXTRA,
        "                if skew is not None:\n                    value = dict(value, future_skew_ms=skew)\n",
        "",
    ),
    (
        "F3 extra: fresh() ignores the tolerance",
        EXTRA,
        '        publication_age(stamp, value["utc_unix"])[0] > MAX_AGE for value in hosts.values()\n',
        '        not 0 <= stamp - value["utc_unix"] <= MAX_AGE for value in hosts.values()\n',
    ),
    (
        "F4 extra: future refusal keeps the old message",
        EXTRA,
        '        raise RuntimeError("Host observation dated in the future")\n',
        '        raise RuntimeError("Completed host observation expired before publication")\n',
    ),
    (
        "F5 extra: violation row drops future_skew_ms",
        EXTRA,
        '                    record["future_skew_ms"] = violations[name]["future_skew_ms"]\n',
        "                    pass\n",
    ),
    (
        "F6 primary: future snapshot bound removed",
        PRIMARY,
        "    if age is not None and 0 < -age <= MAX_FUTURE_SKEW_SECONDS:\n",
        "    if age is not None and 0 < -age:\n",
    ),
    (
        "F7 primary: no future tolerance (the earlier behaviour)",
        PRIMARY,
        "MAX_FUTURE_SKEW_SECONDS = 2.0\n",
        "MAX_FUTURE_SKEW_SECONDS = 0.0\n",
    ),
    (
        "F8 primary: future_skew_ms not recorded",
        PRIMARY,
        '        out["metrics_snapshot_age_s"], out["future_skew_ms"] = 0.0, int(round(-age * 1000))\n',
        '        out["metrics_snapshot_age_s"] = 0.0\n',
    ),
    ("X2 extra: bool pid accepted", EXTRA, "        or isinstance(pid, bool)\n", ""),
    (
        "X5 extra: bool utc_unix accepted",
        EXTRA,
        "    if isinstance(stamp, bool) or not isinstance",
        "    if not isinstance",
    ),
    (
        "X3 extra: violation does not end an outage",
        EXTRA,
        "for name in set(current) | set(violations):",
        "for name in set(current):",
    ),
    (
        "X6 extra: inode reserve unchecked before a baseline",
        EXTRA,
        '        if filesystem["free_bytes"] < MIN_FREE or filesystem["free_inodes"] < 100000:\n'
        '            raise RuntimeError("Disk or inode reserve exhausted")\n\n\ndef check(',
        '        if filesystem["free_bytes"] < MIN_FREE:\n'
        '            raise RuntimeError("Disk or inode reserve exhausted")\n\n\ndef check(',
    ),
    (
        "X8 extra: VIOLATION line never re-armed",
        EXTRA,
        "            inactive_hosts &= set(violations)\n",
        "",
    ),
    (
        "X9 extra: LATEST freshness guard removed",
        EXTRA,
        "                    before_publish=lambda: fresh(current, names, lambda: stamp),\n",
        "",
    ),
    (
        "X13 extra: four-host inventory check removed",
        EXTRA,
        '    if len(hosts) != len(HOSTS):\n        raise RuntimeError("Expected four original hosts")\n',
        "",
    ),
    ("X16 extra: MAX_LOG bound removed", EXTRA, " or stream.tell() > MAX_LOG", ""),
    (
        "Y8 primary: alert threshold validation removed",
        PRIMARY,
        "            args.missing_alert_after,\n        )",
        "        )",
    ),
    (
        "B10 primary: undecodable answer ends the watch",
        PRIMARY,
        "    except UnicodeError:\n        # text=True decodes stdout and stderr before returning.\n"
        "        return None, OUTPUT_INVALID\n",
        "",
    ),
    (
        "B11 primary: huge integer passed to row()",
        PRIMARY,
        "            float(0 if value is None else value)\n",
        "            pass\n",
    ),
    (
        "P1 primary: a missing host ends the watch",
        PRIMARY,
        "            report, reason = probe(h, args.cpu_sample)\n",
        "            report, reason = probe(h, args.cpu_sample)\n"
        "            if report is None:\n"
        '                raise lib.TestnetError("host unavailable")\n',
    ),
    (
        "P2 primary: malformed probe output passed to row()",
        PRIMARY,
        "    if not valid_report(report):\n        return None, OUTPUT_INVALID\n",
        "",
    ),
    (
        "P3 primary: missing row dropped",
        PRIMARY,
        "            rows.append(row(now(), h.name, report, reason))\n",
        "            if report is not None:\n"
        "                rows.append(row(now(), h.name, report, reason))\n",
    ),
    (
        "P4 primary: missing reason not written",
        PRIMARY,
        '        out["missing_reason"] = reason if reason in MISSING_REASONS else NO_OUTPUT\n',
        "",
    ),
    (
        "P5 primary: alerts on every round",
        PRIMARY,
        "        if name in self.alerted or at - first < self.after:\n",
        "        if False:\n",
    ),
    (
        "P6 primary: alerts every round after ten minutes",
        PRIMARY,
        "        if name in self.alerted or at - first < self.after:\n",
        "        if at - first < self.after:\n",
    ),
    (
        "P7 primary: never alerts",
        PRIMARY,
        "        return f\"{name}:missing_for={int(at - first)}s reason={current['missing_reason']}\"\n",
        "        return None\n",
    ),
    (
        "P8 primary: alert never re-armed after recovery",
        PRIMARY,
        "            self.alerted.discard(name)\n",
        "            pass\n",
    ),
    (
        "P9 primary: missing samples no longer latch the anomaly",
        PRIMARY,
        '                getattr(args, "require_load_metrics", False)\n'
        "                or self.unreachable[name] >= args.unreachable_samples\n",
        "                self.unreachable[name] >= args.unreachable_samples\n",
    ),
]


def suite(root: Path, tests: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests],
        capture_output=True,
        text=True,
        cwd=root,
        timeout=600,
    )


def classify(result: subprocess.CompletedProcess) -> str:
    if result.returncode == 0:
        return "SURVIVED"
    out = result.stdout.strip().splitlines()
    summary = out[-1] if out else ""
    if result.returncode == 1 and FAILED.search(summary) and not ERRORS.search(summary):
        return "RED"
    return "INVALID"


def copy(scratch: Path, name: str) -> Path:
    root = scratch / name
    shutil.copytree(W, root, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return root


def main(only: list[str]) -> int:
    sources = {target: (W / target).read_text() for target in TESTS}
    chosen = [m for m in M if not only or m[0].split()[0] in only]
    for label, target, old, new in chosen:
        source = sources[target]
        if source.count(old) != 1:
            print(f"FAIL: {label}: pattern occurs {source.count(old)} times")
            return 1
        ast.parse(source.replace(old, new))
    with tempfile.TemporaryDirectory(prefix="resource-watch-mutants-") as scratch:
        scratch = Path(scratch)
        baseline = suite(copy(scratch, "baseline"), [t for ts in TESTS.values() for t in ts])
        if baseline.returncode != 0:
            print("FAIL: the unmutated suite is not green")
            return 1
        bad = []
        for n, (label, target, old, new) in enumerate(chosen):
            root = copy(scratch, f"m{n}")
            (root / target).write_text(sources[target].replace(old, new))
            try:
                result = suite(root, TESTS[target])
                verdict = classify(result)
                tail = (result.stdout.strip().splitlines() or [""])[-1]
            except subprocess.TimeoutExpired:
                verdict, tail = "INVALID", "timeout"
            shutil.rmtree(root)
            if verdict != "RED":
                bad.append(label)
            print(f"{label}: {verdict} -- {tail}", flush=True)
    print(f"{len(chosen) - len(bad)} of {len(chosen)} red; not red: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
