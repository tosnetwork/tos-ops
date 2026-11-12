"""Tests for load-guard.py against a real status file; the rules themselves are t1-load.py's (test_t1_load.py)."""

import importlib.util
import json
from pathlib import Path

import pytest
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("load_guard", SCRIPTS / "load-guard.py")
lg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lg)
tl = lg.t1_load()

BOOT = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
GiB = 1 << 30
NOW = 1000.0


def host_row(**over):
    row = {"complete": True, "received_mono": NOW, "boot_id": "host-boot", "oom_kill": 0,
           "unit": {"main_pid": 10, "n_restarts": 0, "active_state": "active"},
           "mem": {"MemAvailable": 8 * GiB},
           "disks": {p: {"free_bytes": 60 * GiB, "free_inodes": 5_000_000} for p in tl.DATA_PATHS}}
    row.update(over)
    return row


def status(hosts=None, **over):
    st = {"blind": False, "reasons": [], "updated_mono": NOW, "coordinator_boot_id": BOOT, "stalled_hosts": [],
          "safety_hits": 0, "coverage_gaps": 0, "operators_low": [],
          "hosts": {h: host_row() for h in tl.HOSTS}}
    if hosts:
        st["hosts"].update(hosts)
    st.update(over)
    return st


def files(tmp_path, st):
    p = tmp_path / "status.json"
    p.write_text(json.dumps(st))
    return p, tmp_path / "snap.json", tmp_path / "STOP"


def run(status_path, snap, stop, *extra, now=NOW):
    def sleep(_):
        raise AssertionError("--once kept watching")

    return lg.main(["--status", str(status_path), "--snapshot", str(snap), "--stop-file", str(stop), *extra],
                   mono=lambda: now, sleep=sleep)


def test_a_healthy_network_is_green_and_writes_the_snapshot(tmp_path):
    st, snap, stop = files(tmp_path, status())
    assert run(st, snap, stop, "--once") == 0
    assert not stop.exists()
    assert json.loads(snap.read_text()) == {h: [10, 0, "host-boot", 0] for h in tl.HOSTS}


@pytest.mark.parametrize("over,expect", [
    ({"node-2": host_row(disks={p: {"free_bytes": 19 * GiB, "free_inodes": 5_000_000} for p in tl.DATA_PATHS})},
     "below the disk floor"),
    ({"node-3": host_row(disks={p: {"free_bytes": 60 * GiB, "free_inodes": 999_999} for p in tl.DATA_PATHS})},
     "below the disk floor"),
    ({"node-1": host_row(mem={"MemAvailable": 2 * GiB - 1})}, "MemAvailable below the floor"),
    ({"node-4": host_row(unit={"main_pid": 11, "n_restarts": 1, "active_state": "active"})}, "restart"),
    ({"node-4": host_row(oom_kill=1)}, "OOM"),
])
def test_each_host_condition_stops_the_load(tmp_path, over, expect):
    st, snap, stop = files(tmp_path, status())
    assert run(st, snap, stop, "--once") == 0          # the snapshot is taken while healthy
    st.write_text(json.dumps(status(over)))
    assert run(st, snap, stop, "--once") == 1
    assert any(expect in r for r in json.loads(stop.read_text())["reasons"])


@pytest.mark.parametrize("over,expect", [
    ({"updated_mono": NOW - 91}, "stale"),
    ({"blind": True}, "blind"),
    ({"safety_hits": 1}, "safety lines"),
    ({"stalled_hosts": ["node-1", "node-2", "node-3"]}, "stall"),
    ({"coordinator_boot_id": "another"}, "another boot"),
])
def test_each_observer_condition_stops_the_load(tmp_path, over, expect):
    st, snap, stop = files(tmp_path, status())
    assert run(st, snap, stop, "--once") == 0
    st.write_text(json.dumps(status(**over)))
    assert run(st, snap, stop, "--once") == 1
    assert any(expect in r for r in json.loads(stop.read_text())["reasons"])


def test_an_unreadable_status_stops_the_load(tmp_path):
    st, snap, stop = files(tmp_path, status())
    assert run(st, snap, stop, "--once") == 0
    st.write_text("{not json")
    assert run(st, snap, stop, "--once") == 1
    assert "status unreadable" in json.loads(stop.read_text())["reasons"]


def test_no_complete_status_refuses_to_snapshot(tmp_path):
    st, snap, stop = files(tmp_path, status({"node-2": host_row(complete=False)}))
    assert run(st, snap, stop, "--once") == 2
    assert not snap.exists() and not stop.exists()


def test_the_watch_stops_on_the_first_reason(tmp_path):
    st, snap, stop = files(tmp_path, status())
    seen = []
    bad = status({"node-1": host_row(mem={"MemAvailable": GiB})})

    def sleep(_):
        seen.append(1)
        if len(seen) == 3:
            st.write_text(json.dumps(bad))
        if len(seen) > 10:
            raise AssertionError("the guard kept watching after a stop condition")

    rc = lg.main(["--status", str(st), "--snapshot", str(snap), "--stop-file", str(stop)],
                 mono=lambda: NOW, sleep=sleep)
    assert rc == 1 and len(seen) == 3
    assert any("MemAvailable" in r for r in json.loads(stop.read_text())["reasons"])
