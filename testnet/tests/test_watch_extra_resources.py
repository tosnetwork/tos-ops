"""watch_extra_resources.py: missing host reads are rows, integrity refusals stay fatal."""

import copy
import hashlib
import json
import subprocess

import preflight
import pytest
import watch_extra_resources as wer

SECRET = "SECRET-TOKEN-0123456789 /home/operator/.ssh/id_key"
NAMES = ("node-1", "node-2", "node-3", "node-4")
HOSTS = [
    preflight.Host(name=n, address=f"44.0.0.{i + 1}", roles=["validator"], ssh_key="/k")
    for i, n in enumerate(NAMES)
]
START = 1_800_000_000.0
GIB = 1 << 30


def observation(stamp, **changes):
    value = {
        "utc_unix": stamp,
        "unit": "tos-testnet-validator.service",
        "unit_active": "active",
        "main_pid": 4242,
        "unit_restarts": 0,
        "start_ticks": 777,
        "boot_id": "b0",
        "open_fd_count": 90,
        "cgroup_memory_events": {"low": 0, "high": 0, "max": 0, "oom": 0, "oom_kill": 0},
        "host_oom_kill": 0,
        "filesystems": {
            p: {"free_bytes": 100 * GIB, "free_inodes": 10**6, "total_inodes": 2 * 10**6}
            for p in ("/var/lib/tos", "/var/log/tos", "/tmp")
        },
    }
    value.update(changes)
    return value


class Answer:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class Clock:
    """Advances only on the watch's own pause, so parallel probes see one instant.

    `t` is steady (the monotonic clock is t - START); the wall clock is t moved
    by `step(cycle)` seconds.
    """

    def __init__(self, step=lambda _cycle: 0.0):
        self.t = START
        self.cycle = 0
        self.step = step

    def now(self):
        return self.t + self.step(self.cycle)

    def monotonic(self):
        return self.t - START

    def sleep(self, seconds):
        self.t += seconds
        self.cycle += 1


def fake_run(clock, schedule, attempts):
    """schedule(cycle, name, attempt) -> Answer | exception | None (healthy)."""

    def run(argv, **kwargs):
        assert argv[-1] == "python3 -" and kwargs["timeout"] == wer.PROBE_TIMEOUT
        name = next(h.name for h in HOSTS if any(h.address in a for a in argv))
        key = (clock.cycle, name)
        attempt = attempts.get(key, 0)
        attempts[key] = attempt + 1
        answer = schedule(clock.cycle, name, attempt)
        if answer is None:
            return Answer(json.dumps(observation(clock.now())))
        if isinstance(answer, BaseException):
            raise answer
        return answer

    return run


def run_watch(tmp_path, cycles, schedule, disk_free=lambda _p: 100 * GIB, step=lambda _cycle: 0.0):
    clock, events, attempts = Clock(step), [], {}
    run = fake_run(clock, schedule, attempts)

    def probe_host(host):
        return wer.probe(host, "probe source", run=run, sleep=lambda _s: None, now=clock.now)

    out = tmp_path / "extra"
    wer.watch(
        HOSTS,
        out,
        probe_host,
        monotonic=clock.monotonic,
        now=clock.now,
        sleep=clock.sleep,
        disk_free=disk_free,
        duration=wer.PAUSE * cycles - 1,
        emit=events.append,
    )
    rows = [json.loads(line) for line in (out / "series.jsonl").read_text().splitlines()]
    return out, rows, events


def statuses(rows, status, host=None):
    return [r for r in rows if r["status"] == status and (host is None or r["host"] == host)]


def down(host, cycles, answer=None):
    answer = answer or Answer("", 255, SECRET)
    return lambda cycle, name, attempt: answer if name == host and cycle in cycles else None


MISSING = "MISSING_EXTRA_RESOURCE_OBSERVATION"
ALERT = "ALERT_EXTRA_RESOURCE_HOST_MISSING"
HEALTHY = "HEALTHY_EXTRA_RESOURCE_OBSERVATION"
PARTIAL = "PARTIAL_EXTRA_RESOURCE_OBSERVATION"


def test_healthy_cycles_keep_the_original_row_and_files(tmp_path):
    out, rows, events = run_watch(tmp_path, 3, lambda *_: None)
    assert [r["status"] for r in rows] == [HEALTHY] * 3
    assert set(rows[0]) == {"status", "checked_unix", "checked_utc", "hosts", "scope"}
    assert set(rows[0]["hosts"]) == set(NAMES)
    assert json.loads((out / "LATEST.json").read_text()) == rows[-1]
    assert set(json.loads((out / "BASELINE.json").read_text())) == set(NAMES)
    complete = json.loads((out / "MONITOR-COMPLETE.json").read_text())
    assert complete["status"] == "MONITOR_HORIZON_REACHED_NOT_ACCEPTANCE"
    assert (out.stat().st_mode & 0o777) == 0o700
    assert not (out / "ALERTS.jsonl").exists() and events == []


def test_transient_failure_is_exactly_one_missing_row_then_recovery(tmp_path):
    out, rows, events = run_watch(tmp_path, 4, down("node-4", {1}))
    missing = statuses(rows, MISSING)
    assert len(missing) == 1
    assert set(missing[0]) == {
        "status",
        "host",
        "checked_unix",
        "checked_utc",
        "reason",
        "missing_since_unix",
    }
    assert missing[0]["host"] == "node-4" and missing[0]["reason"] == "ssh_failed"
    assert missing[0]["checked_unix"] == START + 60
    partial = statuses(rows, PARTIAL)
    assert len(partial) == 1 and partial[0]["missing"] == ["node-4"]
    assert set(partial[0]["hosts"]) == {"node-1", "node-2", "node-3"}
    assert [r["status"] for r in rows] == [HEALTHY, MISSING, PARTIAL, HEALTHY, HEALTHY]
    assert json.loads((out / "LATEST.json").read_text())["checked_unix"] == START + 180
    assert not statuses(rows, ALERT) and events == []
    assert (out / "MONITOR-COMPLETE.json").exists()


def test_a_failure_that_the_retry_absorbs_writes_no_missing_row(tmp_path):
    def schedule(cycle, name, attempt):
        return Answer("", 255) if name == "node-2" and attempt == 0 else None

    _out, rows, _events = run_watch(tmp_path, 3, schedule)
    assert [r["status"] for r in rows] == [HEALTHY] * 3


def test_a_missing_row_never_refreshes_latest(tmp_path):
    out, rows, _ = run_watch(tmp_path, 6, down("node-1", {2, 3, 4, 5}))
    latest = json.loads((out / "LATEST.json").read_text())
    assert latest["checked_unix"] == START + 60 and latest["status"] == HEALTHY
    assert len(statuses(rows, MISSING, "node-1")) == 4


def test_long_outage_writes_every_cycle_and_alerts_once_after_ten_minutes(tmp_path):
    out, rows, events = run_watch(tmp_path, 20, down("node-4", set(range(2, 20))))
    missing = statuses(rows, MISSING, "node-4")
    assert len(missing) == 18
    assert [r["checked_unix"] for r in missing] == [START + 60 * c for c in range(2, 20)]
    assert {r["missing_since_unix"] for r in missing} == {START + 120}
    alerts = statuses(rows, ALERT)
    assert len(alerts) == 1
    # First missing at cycle 2 (t=120); 600 s later is cycle 12.
    assert alerts[0]["checked_unix"] == START + 720 and alerts[0]["missing_seconds"] == 600
    marker = [json.loads(line) for line in (out / "ALERTS.jsonl").read_text().splitlines()]
    assert marker == alerts
    assert len(events) == 1 and events[0].startswith("ALERT ")
    assert "node-4:missing_for=600s reason=ssh_failed" in events[0]


def test_realerts_only_after_recovery_and_a_new_long_outage(tmp_path):
    # A: cycles 1..12 (alerted at 11); recover 13; B: 14..20 (360 s, no
    # alert); recover 21; C: 22..34 (alerted at 32).
    cycles = set(range(1, 13)) | set(range(14, 21)) | set(range(22, 35))
    out, rows, events = run_watch(tmp_path, 36, down("node-2", cycles))
    alerts = statuses(rows, ALERT)
    assert [a["checked_unix"] for a in alerts] == [START + 660, START + 1920]
    assert len(events) == 2
    assert len((out / "ALERTS.jsonl").read_text().splitlines()) == 2
    assert len(statuses(rows, MISSING, "node-2")) == len(cycles)


def test_two_hosts_alert_independently(tmp_path):
    def schedule(cycle, name, attempt):
        if (name == "node-1" and cycle >= 1) or (name == "node-3" and cycle >= 5):
            return Answer("", 255)
        return None

    _out, rows, _events = run_watch(tmp_path, 20, schedule)
    alerts = statuses(rows, ALERT)
    assert [(a["host"], a["checked_unix"]) for a in alerts] == [
        ("node-1", START + 660),
        ("node-3", START + 900),
    ]


@pytest.mark.parametrize(
    "answer,reason",
    [
        (Answer("", 255, SECRET), "ssh_failed"),
        (Answer(SECRET, 1, SECRET), "probe_failed"),
        (subprocess.TimeoutExpired(["ssh"], 30, output=SECRET), "probe_timeout"),
        (OSError(SECRET), "probe_launch_failed"),
        (Answer(SECRET), "probe_output_invalid"),
        (Answer("[1]"), "probe_output_invalid"),
        (Answer(json.dumps({"utc_unix": SECRET})), "probe_output_invalid"),
        (Answer(json.dumps({"utc_unix": True})), "probe_output_invalid"),
    ],
)
def test_every_failure_kind_is_a_fixed_reason_without_output(tmp_path, answer, reason):
    out, rows, _events = run_watch(tmp_path, 3, down("node-3", {1}, answer))
    missing = statuses(rows, MISSING)
    assert [(r["host"], r["reason"]) for r in missing] == [("node-3", reason)]
    assert reason in wer.REASONS
    text = "".join(p.read_text() for p in out.iterdir())
    assert "SECRET" not in text and "/home" not in text and "id_key" not in text


def test_an_initial_outage_defers_the_baseline_to_the_first_complete_cycle(tmp_path):
    out, rows, _ = run_watch(tmp_path, 4, down("node-2", {0, 1}))
    assert [r["status"] for r in rows[:4]] == [MISSING, PARTIAL, MISSING, PARTIAL]
    baseline = json.loads((out / "BASELINE.json").read_text())
    assert {v["utc_unix"] for v in baseline.values()} == {START + 120}


def test_observation_delayed_past_publication_bound_is_missing_not_fatal(tmp_path):
    clock = Clock()

    def probe_host(host):
        if host.name == "node-1" and clock.cycle == 1:
            return host.name, observation(clock.t - 61), ""
        return host.name, observation(clock.t), ""

    out = tmp_path / "extra"
    wer.watch(
        HOSTS,
        out,
        probe_host,
        monotonic=clock.monotonic,
        now=clock.now,
        sleep=clock.sleep,
        disk_free=lambda _p: 100 * GIB,
        duration=179,
        emit=lambda _l: None,
    )
    rows = [json.loads(line) for line in (out / "series.jsonl").read_text().splitlines()]
    assert [(r["host"], r["reason"]) for r in statuses(rows, MISSING)] == [
        ("node-1", "expired_at_publication")
    ]


# Integrity refusals stay fatal.


def test_stale_host_clock_is_fatal(tmp_path):
    def schedule(cycle, name, attempt):
        if name == "node-2" and cycle == 1:
            return Answer(json.dumps(observation(START + 60 - 61)))
        return None

    with pytest.raises(RuntimeError, match="clock stale"):
        run_watch(tmp_path, 3, schedule)


def test_future_observation_at_publication_is_fatal(tmp_path):
    clock = Clock()

    def probe_host(host):
        return host.name, observation(clock.t + 1), ""

    with pytest.raises(RuntimeError, match="expired before publication"):
        wer.watch(
            HOSTS,
            tmp_path / "extra",
            probe_host,
            monotonic=clock.monotonic,
            now=clock.now,
            sleep=clock.sleep,
            disk_free=lambda _p: 100 * GIB,
            duration=59,
        )


@pytest.mark.parametrize(
    "change,match",
    [
        ({"main_pid": 4243}, "changed: main_pid"),
        ({"start_ticks": 778}, "changed: start_ticks"),
        ({"boot_id": "b1"}, "changed: boot_id"),
        ({"unit_restarts": 1}, "changed: unit_restarts"),
        ({"host_oom_kill": 1}, "changed: host_oom_kill"),
        ({"cgroup_memory_events": {"oom": 0, "oom_kill": 1}}, "inactive or cgroupOOMkill"),
        ({"cgroup_memory_events": {"oom": 1, "oom_kill": 0}}, "CgroupOOM event changed"),
        ({"cgroup_memory_events": {"oom_kill": 0}}, "CgroupOOM counters missing"),
        ({"filesystems": {}}, "Filesystem observations incomplete"),
        (
            {
                "filesystems": {
                    p: {"free_bytes": 19 * GIB, "free_inodes": 10**6, "total_inodes": 1}
                    for p in ("/var/lib/tos", "/var/log/tos", "/tmp")
                }
            },
            "reserve exhausted",
        ),
    ],
)
def test_baseline_violations_stay_fatal_even_while_another_host_is_missing(tmp_path, change, match):
    def schedule(cycle, name, attempt):
        if name == "node-4" and cycle == 2:
            return Answer("", 255)
        if name == "node-1" and cycle == 2:
            return Answer(json.dumps(observation(START + 120, **copy.deepcopy(change))))
        return None

    with pytest.raises(RuntimeError, match=match):
        run_watch(tmp_path, 4, schedule)


def test_coordinator_disk_bound_is_fatal(tmp_path):
    with pytest.raises(RuntimeError, match="Coordinator disk"):
        run_watch(tmp_path, 3, lambda *_: None, disk_free=lambda _p: 19 * GIB)


def test_existing_output_directory_is_refused(tmp_path):
    (tmp_path / "extra").mkdir()
    with pytest.raises(FileExistsError):
        run_watch(tmp_path, 1, lambda *_: None)


def test_probe_retries_once_and_reports_the_last_reason():
    slept, calls = [], []

    def run(argv, **kwargs):
        calls.append(1)
        return Answer("", 255, SECRET)

    assert wer.probe(HOSTS[0], "s", run=run, sleep=slept.append) == ("node-1", None, "ssh_failed")
    assert len(calls) == 2 and slept == [wer.RETRY_AFTER]


def test_probe_source_is_pinned_and_the_main_refuses_a_bad_inventory(tmp_path):
    assert hashlib.sha256(wer.SOURCE.read_bytes()).hexdigest() == wer.PIN
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "hosts": [
                    {"name": h.name, "address": h.address, "roles": ["validator"], "ssh_key": "/k"}
                    for h in HOSTS[:3]
                ]
            }
        )
    )
    with pytest.raises(RuntimeError, match="Expected four original hosts"):
        wer.main(["--inventory", str(inventory), "--out", str(tmp_path / "o")])
    assert not (tmp_path / "o").exists()


def test_missing_tracker_alerts_once_per_outage():
    t = wer.MissingTracker(600)
    assert [t.missing("a", s, s)[1] for s in range(0, 1300, 60)].count(True) == 1
    t.observed("a")
    assert t.missing("a", 2000, 2000) == (2000, False, 0)
    assert t.missing("a", 2600, 9) == (2000, True, 600)


# An observed inactive validator is a violation row, not missing data.

VIOLATION = "VIOLATION_EXTRA_RESOURCE_OBSERVATION"


def inactive_answer(clock_now, state="failed"):
    return Answer(
        json.dumps(
            {
                "utc_unix": clock_now,
                "unit": "tos-testnet-validator.service",
                "unit_active": state,
                "main_pid": 0,
                "unit_restarts": 0,
            }
        )
    )


def inactive_schedule(host, cycles, state="failed"):
    def schedule(cycle, name, attempt):
        if name == host and cycle in cycles:
            return inactive_answer(START + 60 * cycle, state)
        return None

    return schedule


def test_inactive_validator_is_a_violation_row_and_the_watch_continues(tmp_path):
    out, rows, events = run_watch(tmp_path, 6, inactive_schedule("node-3", {2, 3}))
    violations = statuses(rows, VIOLATION)
    assert [(r["host"], r["reason"], r["checked_unix"]) for r in violations] == [
        ("node-3", "validator_inactive", START + 120),
        ("node-3", "validator_inactive", START + 180),
    ]
    assert set(violations[0]) == {
        "status",
        "host",
        "checked_unix",
        "checked_utc",
        "reason",
        "observed_unix",
        "unit_active",
    }
    assert violations[0]["unit_active"] == "failed"
    assert not statuses(rows, MISSING) and not statuses(rows, ALERT)
    partial = statuses(rows, PARTIAL)
    assert [p["violations"] for p in partial] == [["node-3"], ["node-3"]]
    assert all("node-3" not in p["hosts"] for p in partial)
    assert [e for e in events if e.startswith("VIOLATION")] == [
        f"VIOLATION {wer.iso(START + 120)} node-3:validator_inactive"
    ]
    # The run reached its horizon; LATEST was never an incomplete cycle.
    assert (out / "MONITOR-COMPLETE.json").exists()
    assert json.loads((out / "LATEST.json").read_text())["checked_unix"] == START + 300
    summary = wer.summarize(out / "series.jsonl")
    assert summary["violation_rows"] == 2 and summary["criteria_violated"] is True
    assert summary["missing_rows"] == 0 and summary["missing_data"] is False
    assert summary["unrecognized_rows"] == 0


def test_a_restart_after_inactivity_is_still_fatal(tmp_path):
    def schedule(cycle, name, attempt):
        if name == "node-2" and cycle == 2:
            return inactive_answer(START + 120, "activating")
        if name == "node-2" and cycle >= 3:
            return Answer(json.dumps(observation(START + 60 * cycle, main_pid=5000)))
        return None

    with pytest.raises(RuntimeError, match="changed: main_pid"):
        run_watch(tmp_path, 5, schedule)


def test_an_unknown_unit_state_is_not_copied_into_the_row(tmp_path):
    _out, rows, _ = run_watch(tmp_path, 2, inactive_schedule("node-1", {1}, SECRET))
    (violation,) = statuses(rows, VIOLATION)
    assert violation["unit_active"] == "unknown"
    assert "SECRET" not in json.dumps(rows)


def test_inactive_before_the_baseline_defers_it(tmp_path):
    out, rows, _ = run_watch(tmp_path, 3, inactive_schedule("node-4", {0}))
    assert rows[0]["status"] == VIOLATION
    baseline = json.loads((out / "BASELINE.json").read_text())
    assert {v["utc_unix"] for v in baseline.values()} == {START + 60}


def test_summary_separates_violations_missing_and_unrecognized(tmp_path):
    def schedule(cycle, name, attempt):
        if name == "node-1" and cycle in (1, 2):
            return inactive_answer(START + 60 * cycle)
        if name == "node-2" and 1 <= cycle <= 12:
            return Answer("", 255)
        return None

    out, rows, _ = run_watch(tmp_path, 14, schedule)
    series = out / "series.jsonl"
    summary = wer.summarize(series)
    assert summary["violation_rows"] == 2
    assert {v["reason"] for v in summary["violations"]} == {"validator_inactive"}
    assert summary["missing"] == {"node-2": {"ssh_failed": 12}}
    assert summary["missing_rows"] == 12 and summary["alerts"] == 1
    assert summary["healthy_cycles"] == 2 and summary["partial_cycles"] == 12
    assert summary["rows"] == len(rows) and summary["unrecognized_rows"] == 0
    # A status that disagrees with its reason, an unknown reason, a non-object
    # and an unterminated tail are never read as clean.
    with series.open("a") as stream:
        stream.write(json.dumps({"status": VIOLATION, "reason": "probe_failed"}) + "\n")
        stream.write(json.dumps({"status": MISSING, "reason": "validator_inactive"}) + "\n")
        stream.write(json.dumps({"status": MISSING, "reason": "something_else"}) + "\n")
        stream.write("[1]\n")
        stream.write('{"status": "VIOLATION_EXTRA')
    again = wer.summarize(series)
    assert again["unrecognized_rows"] == 4 and again["rows"] == len(rows) + 4
    assert again["violation_rows"] == 2 and again["missing_rows"] == 12


def test_summarize_cli_prints_the_summary(tmp_path, capsys):
    out, _rows, _ = run_watch(tmp_path, 3, inactive_schedule("node-1", {1}))
    wer.main(["--summarize", str(out / "series.jsonl")])
    printed = json.loads(capsys.readouterr().out)
    assert printed == wer.summarize(out / "series.jsonl")
    assert printed["criteria_violated"] is True
    with pytest.raises(SystemExit):
        wer.main(["--summarize", str(out / "series.jsonl"), "--out", str(tmp_path / "x")])
    with pytest.raises(SystemExit):
        wer.main(["--out", str(tmp_path / "x")])


# Late observations are checked before they are classified as missing.


def late_probe(clock, late_host, late_cycle, **changes):
    def probe_host(host):
        if host.name == late_host and clock.cycle == late_cycle:
            return host.name, observation(clock.now() - 61, **changes), ""
        return host.name, observation(clock.now()), ""

    return probe_host


def run_late(tmp_path, probe_host, clock, cycles=3):
    out = tmp_path / "extra"
    wer.watch(
        HOSTS,
        out,
        probe_host,
        monotonic=clock.monotonic,
        now=clock.now,
        sleep=clock.sleep,
        disk_free=lambda _p: 100 * GIB,
        duration=wer.PAUSE * cycles - 1,
        emit=lambda _l: None,
    )
    return [json.loads(line) for line in (out / "series.jsonl").read_text().splitlines()]


LOW_DISK = {
    "filesystems": {
        p: {"free_bytes": 19 * GIB, "free_inodes": 10**6, "total_inodes": 2 * 10**6}
        for p in ("/var/lib/tos", "/var/log/tos", "/tmp")
    }
}


@pytest.mark.parametrize("late_cycle", [0, 1])
def test_a_late_observation_below_the_disk_floor_is_fatal(tmp_path, late_cycle):
    # Cycle 0 has no baseline yet; cycle 1 has one. Both must refuse.
    clock = Clock()
    with pytest.raises(RuntimeError, match="reserve exhausted"):
        run_late(tmp_path, late_probe(clock, "node-2", late_cycle, **LOW_DISK), clock)


def test_a_late_observation_with_a_changed_pid_is_fatal(tmp_path):
    clock = Clock()
    with pytest.raises(RuntimeError, match="changed: main_pid"):
        run_late(tmp_path, late_probe(clock, "node-2", 1, main_pid=1), clock)


def test_a_late_inactive_observation_is_a_violation(tmp_path):
    clock = Clock()

    def probe_host(host):
        if host.name == "node-2" and clock.cycle == 1:
            return host.name, json.loads(inactive_answer(clock.now() - 61).stdout), ""
        return host.name, observation(clock.now()), ""

    rows = run_late(tmp_path, probe_host, clock)
    assert [(r["host"], r["reason"]) for r in statuses(rows, VIOLATION)] == [
        ("node-2", "validator_inactive")
    ]
    assert not statuses(rows, MISSING)


# The outage alert is timed on the monotonic clock.


def test_extra_outage_is_timed_on_the_monotonic_clock_across_wall_steps(tmp_path):
    # node-4 is down from cycle 2 (monotonic 120 s). The wall clock steps
    # 400 s forward for cycles 5..9 and 3000 s back from cycle 10.
    def step(cycle):
        return 400.0 if 5 <= cycle < 10 else (-3000.0 if cycle >= 10 else 0.0)

    out, rows, events = run_watch(tmp_path, 20, down("node-4", set(range(2, 20))), step=step)
    (alert,) = statuses(rows, ALERT)
    assert alert["missing_seconds"] == 600
    assert alert["checked_unix"] == START + 720 - 3000
    assert alert["missing_since_unix"] == START + 120
    assert len(events) == 1 and "node-4:missing_for=600s" in events[0]
    assert len(statuses(rows, MISSING, "node-4")) == 18
