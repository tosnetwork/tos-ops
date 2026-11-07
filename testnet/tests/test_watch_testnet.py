import argparse
import importlib.util
import json

import pytest
import testnet_lib as lib
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("watch_testnet", SCRIPTS / "watch-testnet.py")
watch_testnet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch_testnet)

GIB = 1 << 30


def inventory(tmp_path, names=("node-1", "node-2"), extra=()):
    hosts = [
        {"name": n, "address": f"44.0.0.{i + 1}", "roles": ["validator"], "ssh_key": "/k"}
        for i, n in enumerate(names)
    ]
    hosts += [
        {"name": n, "address": f"44.0.1.{i + 1}", "roles": ["dht"], "ssh_key": "/k"}
        for i, n in enumerate(extra)
    ]
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"hosts": hosts}))
    return path


def report(seqno=100, head_age=1.0, shard_age=2.0, restarts=0, net=0, active="active", free=50):
    return {
        "free_bytes": free * GIB,
        "consensus_bytes": 800 * (1 << 20),
        "consensus_sessions": 3,
        "unit_active": active,
        "unit_restarts": restarts,
        "rss_bytes": 2048 * (1 << 20),
        "head_seqno": seqno,
        "head_age_seconds": head_age,
        "shard_client_age_seconds": shard_age,
        "net_failures_total": net,
        "refusal_answers_total": 0,
        "cpu_busy_pct": None,
        "cpu_iowait_pct": None,
    }


def make_args(tmp_path, **overrides):
    values = dict(
        inventory=inventory(tmp_path),
        out=tmp_path / "series.tsv",
        interval=60.0,
        hosts=None,
        cpu_sample=0.0,
        duration=None,
        once=False,
        summary_every=900.0,
        max_head_age=120,
        stuck_samples=3,
        unreachable_samples=2,
        net_failure_burst=5,
        min_free_gib=20.0,
        until_current=None,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


class Clock:
    def __init__(self, start=1_800_000_000.0):
        self.t = start

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += max(seconds, 1.0)


def run(tmp_path, rounds, **overrides):
    """`rounds` is a list of {host: report-or-None}; the watch runs one round per entry."""
    # The watch stops after the round that ends at or beyond `duration`: round k
    # ends 60 k seconds after the start, so this runs exactly len(rounds) rounds.
    a = make_args(tmp_path, duration=60.0 * (len(rounds) - 1), **overrides)
    clock, events, index = Clock(), [], {"round": -1, "hosts_seen": 0}
    hosts = len(json.loads(a.inventory.read_text())["hosts"])

    def probe(host, _cpu):
        if index["hosts_seen"] % hosts == 0:
            index["round"] += 1
        index["hosts_seen"] += 1
        report = rounds[min(index["round"], len(rounds) - 1)].get(host.name)
        return report, None if report is not None else watch_testnet.SSH_FAILED

    status = watch_testnet.watch(
        a, probe=probe, now=clock.now, sleep=clock.sleep, emit=events.append
    )
    return status, events, a.out.read_text().splitlines()


def test_healthy_rounds_write_rows_and_one_summary(tmp_path):
    healthy = [{"node-1": report(seqno=100 + i), "node-2": report(seqno=101 + i)} for i in range(3)]
    status, events, rows = run(tmp_path, healthy)
    assert status == 0
    assert rows[0].split("\t") == list(watch_testnet.COLUMNS)
    assert len(rows) == 1 + 2 * 3
    assert [e.split()[0] for e in events] == ["SUMMARY"]
    first = dict(zip(watch_testnet.COLUMNS, rows[1].split("\t")))
    assert first["rss_mb"] == "2048.0" and first["consensus_mb"] == "800.0"
    assert first["cpu_busy_pct"] == "-"


def load_report(**changes):
    r = report()
    r.update(
        cpu_busy_pct=20,
        cpu_iowait_pct=1,
        mempool_eligible=7,
        mempool_postponed=11,
        mempool_oldest_age_seconds=2,
        jsonrpc_active_requests=1,
        metrics_snapshot_timestamp=0,
        metrics_generation=3,
    )
    r.update(changes)
    return r


def load_args(tmp_path, **changes):
    return make_args(
        tmp_path,
        require_load_metrics=True,
        max_metrics_age=120,
        max_mempool_age=30,
        max_mempool_messages=10000,
        **changes,
    )


def test_strict_load_observation_accepts_zero_and_fresh_snapshot(tmp_path):
    judge = watch_testnet.Judge(load_args(tmp_path))
    row = watch_testnet.row(1, "node-1", load_report(mempool_eligible=0))
    assert judge(row) == []
    assert row["mempool_eligible"] == 0 and row["mempool_postponed"] == 11
    assert row["metrics_snapshot_age_s"] == 1


@pytest.mark.parametrize("key", watch_testnet.LOAD_FIELDS)
def test_strict_load_observation_refuses_each_missing_field(tmp_path, key):
    row = watch_testnet.row(1, "node-1", load_report())
    row[key] = None
    assert f"node-1:unobserved={key}" in watch_testnet.Judge(load_args(tmp_path))(row)


def test_strict_load_observation_reports_stale_future_and_queue_limits(tmp_path):
    judge = watch_testnet.Judge(load_args(tmp_path))
    row = watch_testnet.row(
        121,
        "node-1",
        load_report(mempool_eligible=10000, mempool_postponed=1, mempool_oldest_age_seconds=31),
    )
    reasons = judge(row)
    assert any("metrics_stale=" in s for s in reasons)
    assert any("mempool_age=" in s for s in reasons)
    assert any("mempool_messages=" in s for s in reasons)
    row = watch_testnet.row(1, "node-1", load_report(metrics_snapshot_timestamp=2))
    assert "node-1:unobserved=metrics_snapshot_age_s" in judge(row)


def test_strict_load_observation_remembers_anomaly_after_recovery(tmp_path):
    rounds = [
        {"node-1": None, "node-2": load_report(metrics_snapshot_timestamp=1_800_000_000)},
        {
            "node-1": load_report(metrics_snapshot_timestamp=1_800_000_060),
            "node-2": load_report(metrics_snapshot_timestamp=1_800_000_060),
        },
    ]
    status, events, _ = run(
        tmp_path,
        rounds,
        require_load_metrics=True,
        max_metrics_age=120,
        max_mempool_age=30,
        max_mempool_messages=10000,
    )
    assert status == 1
    assert any("node-1:unreachable" in e for e in events)
    assert any(e.startswith("RECOVERED") for e in events)


def test_tsv_schema_mismatch_does_not_append(tmp_path):
    p = tmp_path / "old.tsv"
    p.write_text("utc\thost\nold\tnode-1\n")
    original = p.read_bytes()
    with pytest.raises(lib.TestnetError, match="TSV header differs"):
        watch_testnet.append_rows(p, [watch_testnet.row(1, "node-1", load_report())])
    assert p.read_bytes() == original


def test_unreachable_host_is_an_anomaly_and_its_return_recovers(tmp_path):
    rounds = [
        {"node-1": report(100), "node-2": report(100)},
        {"node-1": report(101), "node-2": None},
        {"node-1": report(102), "node-2": None},
        {"node-1": report(103), "node-2": report(103)},
    ]
    _status, events, rows = run(tmp_path, rounds)
    assert any(e.startswith("ANOMALY") and "node-2:unreachable" in e for e in events)
    assert any(e.startswith("RECOVERED") for e in events)
    assert "\tnode-2\tFalse\t-" in "\n".join(rows)


def test_one_unreadable_sample_is_not_an_anomaly(tmp_path):
    # A single refused SSH handshake (sshd shedding connections under login
    # scans) must not report a healthy node as unreachable.
    rounds = [
        {"node-1": report(100), "node-2": report(100)},
        {"node-1": report(101), "node-2": None},
        {"node-1": report(102), "node-2": report(102)},
    ]
    _status, events, rows = run(tmp_path, rounds)
    assert not any("unreachable" in e for e in events)
    assert "\tnode-2\tFalse\t-" in "\n".join(rows)


def test_a_stuck_head_needs_the_configured_number_of_rounds(tmp_path):
    rounds = [{"node-1": report(100), "node-2": report(100 + i)} for i in range(4)]
    _status, events, _rows = run(tmp_path, rounds)
    stuck = [e for e in events if "node-1:head_stuck_at=100" in e]
    assert len(stuck) == 1
    # Three repeats after the first sighting: rounds 2, 3 and 4.
    rounds = [{"node-1": report(100), "node-2": report(100 + i)} for i in range(3)]
    _status, events, _rows = run(tmp_path, rounds)
    assert not any("head_stuck" in e for e in events)


def test_restart_count_change_and_inactive_unit(tmp_path):
    rounds = [
        {"node-1": report(100, restarts=0), "node-2": report(100)},
        {"node-1": report(101, restarts=1, active="activating"), "node-2": report(101)},
    ]
    _status, events, _rows = run(tmp_path, rounds)
    anomaly = next(e for e in events if e.startswith("ANOMALY"))
    assert "node-1:restarts=1" in anomaly and "node-1:unit=activating" in anomaly


def test_single_net_failures_are_normal_but_a_burst_is_not(tmp_path):
    rounds = [
        {"node-1": report(100, net=10), "node-2": report(100)},
        {"node-1": report(101, net=14), "node-2": report(101)},
        {"node-1": report(102, net=19), "node-2": report(102)},
    ]
    _status, events, _rows = run(tmp_path, rounds)
    bursts = [e for e in events if "net_failure_burst" in e]
    assert len(bursts) == 1 and "net_failure_burst=19" in bursts[0]


def test_old_head_and_low_disk(tmp_path):
    rounds = [{"node-1": report(100, head_age=300, free=10), "node-2": report(100)}]
    _status, events, _rows = run(tmp_path, rounds)
    anomaly = next(e for e in events if e.startswith("ANOMALY"))
    assert "node-1:head_age=300s" in anomaly and "node-1:free=10.0GiB" in anomaly


def test_unobserved_metrics_raise_no_anomaly(tmp_path):
    blind = report(None, head_age=None, shard_age=None, restarts=None, net=None)
    rounds = [{"node-1": blind, "node-2": report(100 + i)} for i in range(5)]
    _status, events, _rows = run(tmp_path, rounds)
    assert not any(e.startswith("ANOMALY") for e in events)


def test_until_current_reports_the_catch_up_time(tmp_path):
    rounds = [
        {"node-1": report(100), "node-2": report(50, shard_age=900)},
        {"node-1": report(101), "node-2": report(80, shard_age=400)},
        {"node-1": report(102), "node-2": report(102, shard_age=12)},
    ]
    status, events, _rows = run(tmp_path, rounds, until_current="node-2")
    assert status == 0
    assert events[-1].startswith("CURRENT") and "node-2 after 120 s" in events[-1]


def test_until_current_fails_when_the_host_never_catches_up(tmp_path):
    rounds = [{"node-1": report(100 + i), "node-2": report(50, shard_age=900)} for i in range(3)]
    status, events, _rows = run(tmp_path, rounds, until_current="node-2")
    assert status == 1 and events[-1].startswith("NOT CURRENT")


def test_only_validator_hosts_are_watched_and_unknown_names_are_refused(tmp_path):
    hosts = watch_testnet.select_hosts(
        watch_testnet.preflight.load_inventory(inventory(tmp_path, extra=("dht-1",))), None
    )
    assert [h.name for h in hosts] == ["node-1", "node-2"]
    with pytest.raises(lib.TestnetError, match="not validator hosts"):
        watch_testnet.select_hosts(
            watch_testnet.preflight.load_inventory(inventory(tmp_path, extra=("dht-1",))), "dht-1"
        )


def test_probe_pipes_the_host_check_over_ssh_and_reads_its_last_line():
    host = watch_testnet.preflight.Host(
        name="n", address="44.0.0.1", roles=["validator"], ssh_key="/k"
    )
    seen = {}

    def run(argv, **kwargs):
        seen["argv"], seen["input"] = argv, kwargs["input"]

        class Done:
            stdout = "noise\n" + json.dumps(report()) + "\n"

        return Done()

    got = watch_testnet.probe(host, 3, run=run)
    assert got["head_seqno"] == 100
    assert seen["argv"][-1] == "python3 - --min-free-gib 0 --cpu-sample 3"
    assert "def parse_metrics" in seen["input"]


def test_probe_refusal_or_garbage_is_unreachable():
    host = watch_testnet.preflight.Host(
        name="n", address="44.0.0.1", roles=["validator"], ssh_key="/k"
    )

    def answering(text):
        def run(argv, **kwargs):
            class Done:
                stdout = text

            return Done()

        return run

    for text in ('{"ok": false, "refused": "x"}', "", "not json"):
        assert watch_testnet.probe(host, 0, run=answering(text), sleep=lambda _s: None) is None


def test_probe_retries_once_after_a_failed_read():
    host = watch_testnet.preflight.Host(
        name="n", address="44.0.0.1", roles=["validator"], ssh_key="/k"
    )
    calls, slept = [], []

    def flaky(argv, **kwargs):
        calls.append(1)

        class Done:
            stdout = "" if len(calls) == 1 else json.dumps(report())

        return Done()

    got = watch_testnet.probe(host, 0, run=flaky, retry_after=5, sleep=slept.append)
    assert got["head_seqno"] == 100
    assert len(calls) == 2 and slept == [5]
