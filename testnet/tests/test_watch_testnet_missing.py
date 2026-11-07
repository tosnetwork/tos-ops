"""watch-testnet.py --require-load-metrics: a probe failure is a missing row, never the end."""

import functools
import importlib.util
import json
import signal
import subprocess

import pytest
from conftest import SCRIPTS
from test_watch_testnet import inventory, load_report, make_args

spec = importlib.util.spec_from_file_location("watch_testnet", SCRIPTS / "watch-testnet.py")
watch_testnet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch_testnet)

SECRET = "SECRET-TOKEN-0123456789 /home/operator/.ssh/id_key"
HOST = watch_testnet.preflight.Host(name="n", address="44.0.0.1", roles=["validator"], ssh_key="/k")


@pytest.fixture(autouse=True)
def bounded():
    """No test here may block: a watch that never ends fails after 30 s."""

    def expire(_signum, _frame):
        raise TimeoutError("test exceeded 30 s")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.alarm(30)
    yield
    signal.alarm(0)
    signal.signal(signal.SIGALRM, previous)


def strict_args(tmp_path, rounds, interval=30.0, **changes):
    return make_args(
        tmp_path,
        interval=interval,
        cpu_sample=3.0,
        duration=interval * (rounds - 1),
        require_load_metrics=True,
        max_metrics_age=120.0,
        max_mempool_age=30.0,
        max_mempool_messages=10000,
        **changes,
    )


class Answer:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


def scripted_run(clock, schedule, interval, cost=0.0):
    """A fake SSH: schedule(round, host_address) -> Answer or an exception to raise.

    Each read takes `cost` monotonic seconds; a runaway watch fails the test.
    """

    def run(argv, **kwargs):
        address = next(a for a in argv if "44." in a).rpartition("@")[2]
        rnd = int(round(clock.mono / interval))
        clock.mono += cost
        assert rnd < 1000, "the watch did not stop"
        answer = schedule(rnd, address)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    return run


class SteppedClock:
    """A steady monotonic clock and a wall clock that `step(round)` and
    `jump(monotonic)` move by seconds."""

    def __init__(self, interval, step=lambda _round: 0.0, jump=lambda _mono: 0.0):
        self.start, self.mono, self.interval, self.step = 1_800_000_000.0, 0.0, interval, step
        self.jump, self.slept = jump, []

    @property
    def t(self):
        rnd = int(round(self.mono / self.interval))
        return self.start + self.mono + self.step(rnd) + self.jump(self.mono)

    def now(self):
        return self.t

    def monotonic(self):
        return self.mono

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.mono += seconds


def fresh_report(clock):
    return json.dumps(load_report(metrics_snapshot_timestamp=clock.t))


def run_watch(
    tmp_path,
    rounds,
    schedule,
    interval=30.0,
    step=lambda _round: 0.0,
    jump=lambda _mono: 0.0,
    cost=0.0,
    clock=None,
    **changes,
):
    args = strict_args(tmp_path, rounds, interval=interval, **changes)
    clock = clock or SteppedClock(interval, step, jump)
    events = []
    run = scripted_run(clock, lambda r, a: schedule(r, a, clock), interval, cost)
    probe = functools.partial(watch_testnet.probe_report, run=run, sleep=lambda _s: None)
    status = watch_testnet.watch(
        args,
        probe=probe,
        now=clock.now,
        sleep=clock.sleep,
        emit=events.append,
        monotonic=clock.monotonic,
    )
    lines = args.out.read_text().splitlines()
    rows = [dict(zip(watch_testnet.COLUMNS, line.split("\t"))) for line in lines[1:]]
    assert lines[0].split("\t") == list(watch_testnet.COLUMNS)
    return status, events, rows, lines


def host_rows(rows, name):
    return [r for r in rows if r["host"] == name]


NODE2 = "44.0.0.2"


def test_transient_failure_writes_exactly_one_missing_row_then_recovers(tmp_path):
    def schedule(rnd, address, clock):
        if address == NODE2 and rnd == 1:
            return Answer("", 255)
        return Answer(fresh_report(clock))

    status, events, rows, _ = run_watch(tmp_path, 4, schedule)
    node2 = host_rows(rows, "node-2")
    assert len(node2) == 4 and len(host_rows(rows, "node-1")) == 4
    assert [r["reachable"] for r in node2] == ["True", "False", "True", "True"]
    assert node2[1]["missing_reason"] == "ssh_failed"
    assert all(
        v == "-"
        for k, v in node2[1].items()
        if k not in ("utc", "host", "reachable", "missing_reason")
    )
    assert all(r["missing_reason"] == "-" for r in rows if r["reachable"] == "True")
    # The anomaly latch (the acceptance criterion) is unchanged: one missing
    # sample is reported at once and fails the strict run.
    assert status == 1
    assert any(e.startswith("ANOMALY") and "node-2:unreachable" in e for e in events)
    assert any(e.startswith("RECOVERED") for e in events)
    assert not any(e.startswith("ALERT") for e in events)


def outage_schedule(down):
    def schedule(rnd, address, clock):
        if address == NODE2 and rnd in down:
            return Answer("", 255)
        return Answer(fresh_report(clock))

    return schedule


def test_long_outage_keeps_sampling_and_alerts_once_after_ten_minutes(tmp_path):
    # Rounds every 30 s; node-2 is down from round 2 (t=60) through round 40.
    down = set(range(2, 41))
    status, events, rows, _ = run_watch(tmp_path, 45, outage_schedule(down))
    node2 = host_rows(rows, "node-2")
    assert len(node2) == 45
    assert [i for i, r in enumerate(node2) if r["reachable"] == "False"] == sorted(down)
    alerts = [e for e in events if e.startswith("ALERT")]
    assert len(alerts) == 1
    # 600 s after the first missing round (t=60): round 22, at t=660.
    assert "node-2:missing_for=600s reason=ssh_failed" in alerts[0]
    assert watch_testnet.utc(1_800_000_000.0 + 660) in alerts[0]
    assert status == 1


def test_realerts_only_after_recovery_and_a_new_outage(tmp_path):
    # Outage A: rounds 1..25 (alerted); recover round 26; short outage B
    # rounds 27..40 (420 s, no alert); recover 41; outage C rounds 42..70.
    down = set(range(1, 26)) | set(range(27, 41)) | set(range(42, 71))
    _status, events, rows, _ = run_watch(tmp_path, 72, outage_schedule(down))
    alerts = [e for e in events if e.startswith("ALERT")]
    assert len(alerts) == 2
    assert watch_testnet.utc(1_800_000_000.0 + 30 * 21) in alerts[0]
    assert watch_testnet.utc(1_800_000_000.0 + 30 * 62) in alerts[1]
    assert len(host_rows(rows, "node-2")) == 72


def test_outage_is_timed_on_the_monotonic_clock_across_wall_steps(tmp_path):
    # node-2 is down from round 2. The wall clock steps 500 s forward for
    # rounds 10..19 (a wall-time timer would alert at round 10) and then
    # 2000 s back from round 20 (a wall-time timer would see a negative outage).
    def step(rnd):
        return 500.0 if 10 <= rnd < 20 else (-2000.0 if rnd >= 20 else 0.0)

    _status, events, rows, _ = run_watch(
        tmp_path, 45, outage_schedule(set(range(2, 41))), step=step
    )
    alerts = [e for e in events if e.startswith("ALERT")]
    assert len(alerts) == 1
    # Round 22 on the monotonic clock, stamped with that round's (stepped) UTC.
    assert "node-2:missing_for=600s" in alerts[0]
    assert watch_testnet.utc(1_800_000_000.0 + 660 - 2000) in alerts[0]
    assert len(host_rows(rows, "node-2")) == len(host_rows(rows, "node-1")) == 45


def healthy(rnd, address, clock):
    return Answer(fresh_report(clock))


@pytest.mark.parametrize("jump", [100_000.0, -100_000.0])
def test_horizon_and_pacing_ignore_a_wall_jump_mid_round(tmp_path, jump):
    # Each read takes 1 s (2 per round); the wall clock jumps after the first
    # read of round 10. A forward jump must not end the run early, a backward
    # one must not extend it, and the pause stays interval minus the round.
    clock = SteppedClock(30.0, jump=lambda mono: jump if mono >= 301 else 0.0)
    _status, events, rows, _ = run_watch(tmp_path, 20, healthy, cost=1.0, clock=clock)
    assert len(host_rows(rows, "node-1")) == len(host_rows(rows, "node-2")) == 20
    assert clock.slept == [28.0] * 19
    # Summaries are paced on the monotonic clock too: one in a 570 s run.
    assert len([e for e in events if e.startswith("SUMMARY")]) == 1


def test_a_backward_wall_step_does_not_delay_the_alert(tmp_path):
    def step(rnd):
        return -5000.0 if rnd >= 5 else 0.0

    _status, events, _rows, _ = run_watch(
        tmp_path, 30, outage_schedule(set(range(1, 30))), step=step
    )
    alerts = [e for e in events if e.startswith("ALERT")]
    assert len(alerts) == 1 and "node-2:missing_for=600s" in alerts[0]
    assert watch_testnet.utc(1_800_000_000.0 + 630 - 5000) in alerts[0]


def test_a_host_that_never_answers_still_has_a_row_every_round(tmp_path):
    _status, events, rows, _ = run_watch(tmp_path, 30, outage_schedule(set(range(30))))
    assert [r["reachable"] for r in host_rows(rows, "node-2")] == ["False"] * 30
    assert len([e for e in events if e.startswith("ALERT")]) == 1


@pytest.mark.parametrize(
    "answer,reason",
    [
        (Answer("", 255, SECRET), "ssh_failed"),
        (Answer("", 1, SECRET), "probe_no_output"),
        (subprocess.TimeoutExpired(["ssh"], 63, output=SECRET), "probe_timeout"),
        (OSError(SECRET), "probe_launch_failed"),
        (Answer(SECRET + "\n" + "{not json " + SECRET), "probe_output_invalid"),
        (Answer("[1]"), "probe_output_invalid"),
        (Answer("7"), "probe_output_invalid"),
        (Answer('{"head_age_seconds": "' + SECRET + '"}'), "probe_output_invalid"),
        (Answer('{"head_age_seconds": Infinity}'), "probe_output_invalid"),
        (Answer('{"unit_restarts": "x"}'), "probe_output_invalid"),
        (Answer('{"unit_restarts": true}'), "probe_output_invalid"),
        (Answer('{"unit_active": 3}'), "probe_output_invalid"),
        (Answer(json.dumps({"ok": False, "refused": SECRET})), "probe_refused"),
        (UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"), "probe_output_invalid"),
        (Answer('{"rss_bytes": ' + "9" * 400 + "}"), "probe_output_invalid"),
        (Answer('{"metrics_snapshot_timestamp": ' + "9" * 400 + "}"), "probe_output_invalid"),
        (Answer('{"free_bytes": ' + "9" * 5000 + "}"), "probe_output_invalid"),
        (Answer("[" * 100_000 + "]" * 100_000), "probe_output_invalid"),
    ],
)
def test_every_probe_failure_is_a_fixed_reason_and_never_ends_the_watch(tmp_path, answer, reason):
    def schedule(rnd, address, clock):
        if address == NODE2 and rnd == 1:
            return answer
        return Answer(fresh_report(clock))

    status, _events, rows, lines = run_watch(tmp_path, 3, schedule)
    assert [r["reachable"] for r in host_rows(rows, "node-2")] == ["True", "False", "True"]
    assert host_rows(rows, "node-2")[1]["missing_reason"] == reason
    assert reason in watch_testnet.MISSING_REASONS
    text = "\n".join(lines)
    assert "SECRET" not in text and "/home" not in text and "id_key" not in text
    assert status == 1


def test_probe_report_reasons_and_retry():
    calls = []

    def flaky(argv, **kwargs):
        calls.append(1)
        return Answer("", 255) if len(calls) == 1 else Answer(json.dumps(load_report()))

    report, reason = watch_testnet.probe_report(HOST, 3, run=flaky, sleep=lambda _s: None)
    assert reason is None and report["head_seqno"] == 100 and len(calls) == 2

    def down(argv, **kwargs):
        return Answer("", 255, SECRET)

    assert watch_testnet.probe_report(HOST, 3, run=down, sleep=lambda _s: None) == (
        None,
        "ssh_failed",
    )


def test_row_never_writes_an_unknown_reason():
    r = watch_testnet.row(0, "n", None, SECRET)
    assert r["missing_reason"] == "probe_no_output" and r["reachable"] is False


def test_ordinary_mode_has_no_missing_alert(tmp_path):
    args = make_args(tmp_path, interval=30.0, duration=30.0 * 39, inventory=inventory(tmp_path))
    clock, events = SteppedClock(30.0), []

    def probe(host, _cpu):
        if host.name == "node-2":
            return None, watch_testnet.SSH_FAILED
        return load_report(metrics_snapshot_timestamp=clock.t), None

    status = watch_testnet.watch(
        args,
        probe=probe,
        now=clock.now,
        sleep=clock.sleep,
        emit=events.append,
        monotonic=clock.monotonic,
    )
    assert status == 0
    assert not any(e.startswith("ALERT") for e in events)
    assert any("node-2:unreachable" in e for e in events)


def test_header_mismatch_and_bad_inventory_still_refuse(tmp_path):
    old = tmp_path / "series.tsv"
    # A series written before missing_reason existed is refused, not extended.
    old.write_text("\t".join(watch_testnet.COLUMNS[:-1]) + "\n")
    with pytest.raises(watch_testnet.lib.TestnetError, match="TSV header differs"):
        watch_testnet.append_rows(old, [watch_testnet.row(0, "node-1", None, "ssh_failed")])
    assert old.read_text() == "\t".join(watch_testnet.COLUMNS[:-1]) + "\n"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hosts": []}))
    assert (
        watch_testnet.main(["--inventory", str(bad), "--out", str(tmp_path / "n.tsv"), "--once"])
        == 1
    )


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_missing_alert_after_must_be_finite_and_positive(tmp_path, value, capsys):
    def never(*_args, **_kwargs):
        raise AssertionError("an invalid threshold reached the watch")

    original, watch_testnet.watch = watch_testnet.watch, never
    try:
        with pytest.raises(SystemExit) as exit_info:
            watch_testnet.main(
                [
                    "--inventory",
                    str(inventory(tmp_path)),
                    "--out",
                    str(tmp_path / "s.tsv"),
                    "--cpu-sample",
                    "3",
                    "--require-load-metrics",
                    "--missing-alert-after",
                    value,
                ]
            )
    finally:
        watch_testnet.watch = original
    assert exit_info.value.code == 2
    assert "thresholds must be finite and positive" in capsys.readouterr().err


@pytest.mark.parametrize(
    "offset,age,skew", [(0.005, 0.0, 5), (2.0, 0.0, 2000), (2.5, -2.5, None), (-3.0, 3.0, None)]
)
def test_a_slightly_future_metrics_snapshot_counts_as_age_zero(offset, age, skew):
    now = 1_800_000_000.0
    r = watch_testnet.row(now, "n", load_report(metrics_snapshot_timestamp=now + offset))
    assert r["metrics_snapshot_age_s"] == pytest.approx(age) and r["future_skew_ms"] == skew


def test_future_skew_is_written_to_the_series(tmp_path):
    def schedule(rnd, address, clock):
        offset = 0.005 if address == NODE2 and rnd == 1 else 0.0
        return Answer(json.dumps(load_report(metrics_snapshot_timestamp=clock.t + offset)))

    status, events, rows, _ = run_watch(tmp_path, 3, schedule)
    assert [r["future_skew_ms"] for r in host_rows(rows, "node-2")] == ["-", "5", "-"]
    assert host_rows(rows, "node-2")[1]["metrics_snapshot_age_s"] == "0.0"
    assert status == 0 and not any(e.startswith("ANOMALY") for e in events)
