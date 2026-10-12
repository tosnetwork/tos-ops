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
