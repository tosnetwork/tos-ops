import importlib.util
import json

from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("check_host_disk", SCRIPTS / "check-host-disk.py")
check_host_disk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_host_disk)


def make_db(tmp_path, sessions=3, size=1000):
    db = tmp_path / "validator"
    for i in range(sessions):
        session = db / "consensus" / f"session-{i}"
        session.mkdir(parents=True)
        (session / "wal").write_bytes(b"x" * size)
    return db


def test_reports_consensus_size_and_sessions(tmp_path, capsys):
    db = make_db(tmp_path, sessions=3, size=1000)
    assert check_host_disk.main(["--db", str(db), "--min-free-gib", "0"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["consensus_sessions"] == 3
    assert report["consensus_bytes"] == 3000
    assert report["free_bytes"] > 0


def test_refuses_when_free_space_is_below_the_minimum(tmp_path, capsys):
    db = make_db(tmp_path)
    # No filesystem has an exabyte free: the threshold must trip.
    assert check_host_disk.main(["--db", str(db), "--min-free-gib", str(1 << 30)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["free_bytes"] < report["min_free_bytes"]


def test_missing_database_is_a_refusal_not_a_pass(tmp_path, capsys):
    assert check_host_disk.main(["--db", str(tmp_path / "absent"), "--min-free-gib", "0"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_database_without_consensus_directory(tmp_path, capsys):
    db = tmp_path / "validator"
    db.mkdir()
    assert check_host_disk.main(["--db", str(db), "--min-free-gib", "0"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["consensus_sessions"] == 0 and report["consensus_bytes"] == 0


def test_metrics_are_parsed_and_an_absent_series_is_none():
    text = "\n".join(
        [
            "# HELP tos_masterchain_head_age_seconds age",
            "tos_masterchain_head_age_seconds 0.42",
            'tos_shard_client_age_seconds{shard="0"} 3',
            "tos_wait_block_data_net_failures_total 17",
            "unrelated_metric 5",
        ]
    )
    parsed = check_host_disk.parse_metrics(text)
    assert parsed["head_age_seconds"] == 0.42
    assert parsed["shard_client_age_seconds"] == 3.0
    assert parsed["net_failures_total"] == 17.0
    assert parsed["refusal_answers_total"] is None


def test_cpu_usage_from_two_readings():
    readings = iter([[100, 0, 100, 700, 100, 0, 0], [200, 0, 200, 1300, 300, 0, 0]])
    usage = check_host_disk.cpu_usage(3, sleep=lambda _s: None, read=lambda: next(readings))
    # delta: user 100, system 100, idle 600, iowait 200 of 1000.
    assert usage == {"cpu_busy_pct": 20.0, "cpu_iowait_pct": 20.0}


def test_load_metrics_preserve_both_queue_labels_and_real_zero():
    parsed = check_host_disk.parse_metrics(
        'tos_mempool_ext_messages{state="eligible"} 7\n'
        'tos_mempool_ext_messages{state="postponed"} 11\n'
        "tos_mempool_oldest_ext_message_age_seconds 0\n"
        "tos_exporter_snapshot_completed_timestamp_seconds 12345.5\n"
        "tos_exporter_snapshot_generation 3\n"
        "tos_jsonrpc_active_requests 2\n"
    )
    assert parsed["mempool_eligible"] == 7
    assert parsed["mempool_postponed"] == 11
    assert parsed["mempool_oldest_age_seconds"] == 0
    assert parsed["metrics_snapshot_timestamp"] == 12345.5
    assert parsed["metrics_generation"] == 3
    assert parsed["jsonrpc_active_requests"] == 2


def test_invalid_load_metrics_are_missing():
    for value in ("NaN", "+Inf", "-Inf", "-1", "not-a-number"):
        parsed = check_host_disk.parse_metrics(
            f'tos_mempool_ext_messages{{state="eligible"}} {value}'
        )
        assert parsed["mempool_eligible"] is None


def test_cpu_usage_skipped_is_unobserved_not_zero():
    assert check_host_disk.cpu_usage(0) == {"cpu_busy_pct": None, "cpu_iowait_pct": None}


def test_unreachable_sources_are_null_not_zero(tmp_path, capsys):
    db = make_db(tmp_path)
    argv = ["--db", str(db), "--min-free-gib", "0", "--unit", "", "--rpc", "", "--metrics", ""]
    assert check_host_disk.main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    for key in ("unit_active", "rss_bytes", "head_seqno", "head_age_seconds", "cpu_busy_pct"):
        assert report[key] is None


def test_closed_endpoints_are_null_not_zero(tmp_path, capsys):
    db = make_db(tmp_path)
    closed = "http://127.0.0.1:9/x"
    argv = [
        "--db",
        str(db),
        "--min-free-gib",
        "0",
        "--unit",
        "",
        "--rpc",
        closed,
        "--metrics",
        closed,
    ]
    assert check_host_disk.main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["head_seqno"] is None and report["head_age_seconds"] is None
