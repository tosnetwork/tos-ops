"""Tests for t1-load.py. Children are real `sleep` processes where containment matters; nothing reaches a host."""

import copy
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("t1_load", SCRIPTS / "t1-load.py")
tl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tl)

BOOT = "dd1d9f3a-edf0-4835-a97d-731798e7be90"
GiB = 1 << 30


def record(**over):
    r = {
        "tos_checkout": "/x/tos", "tos_rev": "4fb9ee70330e6247f2e0bc766a9ac5638b42ce58",
        "signer": "/x/signer", "signer_sha256": "00" * 32, "key_file": "/x/key.json", "auth_tag": "ab" * 32,
        "ramp": {"batch": 4, "wallets": 40, "wallet_funding": 5, "max_cost": 200, "max_transfers": 530000,
                 "funding_externals": 2,
                 "rpc": [f"http://127.0.0.1:{p}/jsonRPC" for p in (18081, 38081, 28081, 48084)]},
        "reads": {"address": "-1:" + "1e" * 32, "network_deadline_seconds": 3.0, "window_seconds": 600},
        "floors": {"mem_available_bytes": 2 * GiB, "disk_free_bytes": 20 * GiB, "disk_free_inodes": 100000},
        "unresolved": {"max_age_s": 300, "max_count": 1000},
        "status_stale_s": 90,
    }
    r.update(over)
    return r


def write_record(tmp_path, rec):
    p = tmp_path / "record.json"
    p.write_text(json.dumps(rec))
    return p, hashlib.sha256(p.read_bytes()).hexdigest()


def host_row(now, **over):
    row = {"complete": True, "received_mono": now, "boot_id": BOOT, "oom_kill": 0,
           "unit": {"main_pid": 10, "n_restarts": 0, "active_state": "active"},
           "mem": {"MemAvailable": 8 * GiB},
           "disks": disks()}
    row.update(over)
    return row


def disks(**over):
    d = {p: {"free_bytes": 60 * GiB, "free_inodes": 5000000} for p in tl.DATA_PATHS}
    for p, v in over.items():
        d[p] = v
    return d


def status(now, **over):
    st = {"blind": False, "reasons": [], "updated_mono": now, "coordinator_boot_id": BOOT, "stalled_hosts": [],
          "safety_hits": 0, "coverage_gaps": 0, "operators_low": [], "hosts": {h: host_row(now) for h in tl.HOSTS}}
    st.update(over)
    return st


SNAP = {h: (10, 0, BOOT, 0) for h in tl.HOSTS}


# ---------------------------------------------------------------- the record


def test_a_complete_record_loads(tmp_path):
    p, sha = write_record(tmp_path, record())
    assert tl.load_record(p, sha)["ramp"]["batch"] == 4


@pytest.mark.parametrize("mutate,message", [
    (lambda r: r.pop("floors"), "lacks a valid floors"),
    (lambda r: r.update(status_stale_s=True), "lacks a valid status_stale_s"),
    (lambda r: r["ramp"].pop("max_cost"), "lacks ramp.max_cost"),
    (lambda r: r["reads"].update(address=""), "lacks reads.address"),
    (lambda r: r["unresolved"].pop("max_age_s"), "lacks unresolved.max_age_s"),
    (lambda r: r["ramp"].update(rpc=["a", "b"]), "four validator tunnels"),
])
def test_an_incomplete_record_refuses_the_launch(tmp_path, mutate, message):
    rec = record()
    mutate(rec)
    p, sha = write_record(tmp_path, rec)
    with pytest.raises(tl.Refuse, match=message):
        tl.load_record(p, sha)


def test_a_record_with_another_hash_refuses(tmp_path):
    p, sha = write_record(tmp_path, record())
    with pytest.raises(tl.Refuse, match="sha256"):
        tl.load_record(p, "0" * 64)
    with pytest.raises(tl.Refuse, match="no acceptance record"):
        tl.load_record(tmp_path / "none.json", sha)


def test_inputs_are_checked_against_the_record(tmp_path):
    signer = tmp_path / "signer"
    signer.write_bytes(b"binary")
    keydir = tmp_path / "custody"
    keydir.mkdir(mode=0o700)
    key = keydir / "key.json"
    key.write_text("{}")
    key.chmod(0o600)
    rec = record(signer=str(signer), signer_sha256=hashlib.sha256(b"binary").hexdigest(), key_file=str(key))
    good = lambda *a, **k: subprocess.CompletedProcess(a, 0, rec["tos_rev"] + "\n", "")  # noqa: E731
    tl.check_inputs(rec, run=good)
    with pytest.raises(tl.Refuse, match="tos checkout"):
        tl.check_inputs(rec, run=lambda *a, **k: subprocess.CompletedProcess(a, 0, "deadbeef\n", ""))
    with pytest.raises(tl.Refuse, match="signer"):
        tl.check_inputs(dict(rec, signer_sha256="11" * 32), run=good)
    key.chmod(0o644)
    with pytest.raises(tl.Refuse, match="readable by others"):
        tl.check_inputs(rec, run=good)
    key.chmod(0o600)
    keydir.chmod(0o755)
    with pytest.raises(tl.Refuse, match="readable by others"):
        tl.check_inputs(rec, run=good)


def test_the_ramp_arguments_carry_the_t1_shape(tmp_path):
    argv = tl.ramp_argv(record(), tmp_path)
    s = " ".join(argv)
    for part in ("--start-rate 2", "--factor 1", "--steps 3", f"--step-seconds {tl.schedule(2)['step_seconds']}", "--layout-repeats 0",
                 "--max-cost 200", "--max-transfers 530000", "--batch 4", "--wallets 40"):
        assert part in s, part
    assert argv.count("--rpc") == 4 and str(tmp_path / "ramp") in argv


def test_the_read_packet_is_the_t1_profile(tmp_path):
    p = tl.read_packet(record(), tmp_path)
    assert p["profile"] == "t1" and p["duration_seconds"] == tl.DURATION and p["requests_per_second"] == 8
    assert p["network_deadline_seconds"] == 3.0 and len(p["endpoints"]) == 4


def test_the_read_packet_builds_under_isolated_mode():
    # codex r1 §5: `python3 -I` leaves the script dir off sys.path, so the sibling must be loaded by path.
    code = (f"import importlib.util, json; from pathlib import Path; "
            f"s = importlib.util.spec_from_file_location('t', {str(SCRIPTS / 't1-load.py')!r}); "
            f"m = importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            f"print(len(m.read_packet(json.loads({json.dumps(json.dumps(record()))}), Path('/o'))['endpoints']))")
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.strip() == "4", r.stderr


URLS = {h: f"http://127.0.0.1:{p}/jsonRPC" for h, p in zip(tl.HOSTS, (18081, 38081, 28081, 48084))}


def test_writes_and_reads_must_go_to_the_inventory_tunnels():
    want = [URLS[h] for h in tl.HOSTS]
    tl.check_inventory(record(), URLS, want)
    with pytest.raises(tl.Refuse, match="ramp.rpc"):
        tl.check_inventory(record(ramp=dict(record()["ramp"], rpc=[want[0]] * 4)), URLS, want)
    with pytest.raises(tl.Refuse, match="read profile"):
        tl.check_inventory(record(), URLS, list(reversed(want)))
    with pytest.raises(tl.Refuse, match="one distinct tunnel"):
        tl.check_inventory(record(), dict(URLS, **{"node-4": URLS["node-1"]}), want)
    with pytest.raises(tl.Refuse, match="one distinct tunnel"):
        tl.check_inventory(record(), {h: u for h, u in URLS.items() if h != "node-2"}, want)


def test_the_supervisor_must_run_in_its_contained_unit():
    good = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/t1-load.service\n"
    tl.check_containment(good, {"KillMode": "control-group", "Restart": "no"})
    with pytest.raises(tl.Refuse, match="not running inside"):
        tl.check_containment("0::/user.slice/user-1000.slice/session-3.scope\n",
                             {"KillMode": "control-group", "Restart": "no"})
    with pytest.raises(tl.Refuse, match="KillMode"):
        tl.check_containment(good, {"KillMode": "process", "Restart": "no"})
    with pytest.raises(tl.Refuse, match="KillMode"):
        tl.check_containment(good, {"KillMode": "control-group", "Restart": "on-failure"})


def test_a_held_wallet_lock_refuses_the_start(tmp_path):
    import fcntl
    state = tmp_path / "key.json.state"
    (state / "-1_ab").mkdir(parents=True)
    lock = state / "-1_ab" / "lock"
    lock.write_text("")
    tl.check_wallet_locks(state)  # free
    tl.check_wallet_locks(tmp_path / "absent")  # no state yet
    holder = subprocess.Popen([sys.executable, "-c", f"import fcntl, os, time; fd = os.open({str(lock)!r}, os.O_RDWR); "
                               "fcntl.flock(fd, fcntl.LOCK_EX); print('held', flush=True); time.sleep(60)"],
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(tl.Refuse, match="held by a running process"):
            tl.check_wallet_locks(state)
    finally:
        holder.kill()
        holder.wait(5)
    assert fcntl  # the lock is free again once its holder is gone
    tl.check_wallet_locks(state)


@pytest.mark.parametrize("path,value", [
    (("floors", "mem_available_bytes"), 0), (("floors", "disk_free_bytes"), float("nan")),
    (("unresolved", "max_age_s"), -1), (("ramp", "max_cost"), "200"), (("status_stale_s",), float("inf")),
    (("reads", "network_deadline_seconds"), 0),
])
def test_a_record_threshold_must_be_finite_and_positive(tmp_path, path, value):
    rec = copy.deepcopy(record())
    target = rec
    for k in path[:-1]:
        target = target[k]
    target[path[-1]] = value
    p, sha = write_record(tmp_path, rec)
    with pytest.raises(tl.Refuse):
        tl.load_record(p, sha)


# ---------------------------------------------------------------- stop rules


def test_a_healthy_status_has_no_reason():
    assert tl.status_reasons(status(100.0), SNAP, record(), 100.0, BOOT) == []


@pytest.mark.parametrize("st,now,expect", [
    (None, 100, "status unreadable"),
    ({"blind": False}, 100, "status lacks updated_mono"),
    (status(100, coordinator_boot_id="other"), 100, "another boot"),
    (status(0), 100, "stale"),
    (status(100, blind=True), 100, "blind"),
    (status(100, stalled_hosts=["node-1", "node-2", "node-3"]), 100, "stall"),
    (status(100, safety_hits=1), 100, "safety lines"),
    (status(100, coverage_gaps=1), 100, "coverage gaps"),
    (status(100, operators_low=["node-2"]), 100, "operators below"),
])
def test_each_global_stop_condition(st, now, expect):
    reasons = tl.status_reasons(st, SNAP, record(), now, BOOT)
    assert any(expect in r for r in reasons), reasons


def test_two_stalled_hosts_alone_do_not_stop():
    assert tl.status_reasons(status(100, stalled_hosts=["node-1", "node-2"]), SNAP, record(), 100, BOOT) == []


@pytest.mark.parametrize("over,expect", [
    ({"complete": False, "missing": ["mem"]}, "incomplete"),
    ({"received_mono": 100 - tl.ROW_MAX_AGE - 1}, "too old"),
    ({"unit": {"main_pid": 10, "n_restarts": 0, "active_state": "failed"}}, "validator failed"),
    ({"unit": {"main_pid": 11, "n_restarts": 0, "active_state": "active"}}, "restart"),
    ({"unit": {"main_pid": 10, "n_restarts": 1, "active_state": "active"}}, "restart"),
    ({"boot_id": "x"}, "reboot"),
    ({"oom_kill": 1}, "OOM"),
    ({"mem": {"MemAvailable": GiB}}, "MemAvailable"),
    ({"disks": disks(**{"/var/log/tos": {"free_bytes": GiB, "free_inodes": 5000000}})}, "disk floor"),
    ({"disks": disks(**{"/var/lib/tos/validator": {"free_bytes": 60 * GiB, "free_inodes": 5}})}, "disk floor"),
    # codex r1 §2: NaN, missing and empty values are stops, never passes
    ({"received_mono": float("nan")}, "too old"),
    ({"mem": {"MemAvailable": float("nan")}}, "MemAvailable"),
    ({"mem": {}}, "MemAvailable"),
    ({"disks": {}}, "unreadable"),
    ({"disks": disks(**{"/var/log/tos": {"free_bytes": float("nan"), "free_inodes": 5}})}, "unreadable"),
    ({"unit": "error: x"}, "unit unreadable"),
])
def test_each_host_stop_condition(over, expect):
    st = status(100)
    st["hosts"]["node-3"] = host_row(100, **over)
    reasons = tl.status_reasons(st, SNAP, record(), 100, BOOT)
    assert any(r.startswith("node-3") and expect in r for r in reasons), reasons


@pytest.mark.parametrize("over,expect", [
    ({"updated_mono": float("nan")}, "stale"),
    ({"safety_hits": "0"}, "safety"),
    ({"coverage_gaps": None}, "coverage"),
    ({"operators_low": None}, "operators"),
    ({"stalled_hosts": None}, "stall"),
])
def test_a_malformed_status_field_is_a_stop(over, expect):
    reasons = tl.status_reasons(status(100, **over), SNAP, record(), 100, BOOT)
    assert any(expect in r for r in reasons), reasons


def test_a_missing_host_row_stops():
    st = status(100)
    del st["hosts"]["node-4"]
    assert "node-4: no resource row" in tl.status_reasons(st, SNAP, record(), 100, BOOT)


def test_the_snapshot_needs_a_complete_row_per_host():
    st = status(100)
    assert tl.host_snapshot(st) == SNAP
    st["hosts"]["node-2"] = host_row(100, complete=False)
    with pytest.raises(tl.Refuse, match="node-2"):
        tl.host_snapshot(st)


@pytest.mark.parametrize("over", [
    {"boot_id": None}, {"boot_id": ""}, {"oom_kill": None}, {"oom_kill": True},
    {"unit": {"main_pid": None, "n_restarts": 0, "active_state": "active"}},
    {"unit": {"main_pid": 0, "n_restarts": 0, "active_state": "active"}},
    {"unit": {"main_pid": 10, "active_state": "active"}},
])
def test_missing_identity_fields_never_snapshot_or_compare_equal(over):
    # codex r2: missing fields snapshotted as None would match later missing fields and hide a restart.
    st = status(100)
    st["hosts"]["node-1"] = host_row(100, **over)
    with pytest.raises(tl.Refuse, match="no valid MainPID"):
        tl.host_snapshot(st)
    reasons = tl.status_reasons(st, SNAP, record(), 100, BOOT)
    assert any(r.startswith("node-1") and "unreadable" in r for r in reasons), reasons


# ---------------------------------------------------------------- the journal tail


def jline(**rec):
    return (json.dumps(rec) + "\n").encode()


def test_undelivered_actions_are_tracked_until_delivered(tmp_path):
    j = tmp_path / "journal.jsonl"
    j.write_bytes(jline(type="attempt", id="a1", actions=[{}, {}]) + jline(type="observed", id="a1"))
    t = tl.JournalTail(j)
    t.poll(10.0)
    assert set(t.pending) == {("a1", 0), ("a1", 1)}
    with j.open("ab") as fh:
        fh.write(jline(type="delivered", id="a1", action=0, receipt_failure=None))
    t.poll(11.0)
    assert set(t.pending) == {("a1", 1)}


def test_a_failed_external_has_no_pending_actions(tmp_path):
    j = tmp_path / "journal.jsonl"
    j.write_bytes(jline(type="attempt", id="a1", actions=[{}]) + jline(type="observed", id="a1", failure="exit 37"))
    t = tl.JournalTail(j)
    t.poll(1.0)
    assert t.pending == {}


def test_a_torn_last_line_waits_for_its_end(tmp_path):
    j = tmp_path / "journal.jsonl"
    full = jline(type="attempt", id="a1", actions=[{}]) + jline(type="observed", id="a1")
    j.write_bytes(full[:-5])
    t = tl.JournalTail(j)
    t.poll(1.0)
    assert t.pending == {}
    with j.open("ab") as fh:
        fh.write(full[-5:])
    t.poll(2.0)
    assert set(t.pending) == {("a1", 0)}


def test_producer_shaped_records_with_per_action_failures(tmp_path):
    # codex r1 §1: the ramp writes `failure` per action (ledger.External.failure), [None, ...] when all were sent.
    j = tmp_path / "journal.jsonl"
    j.write_bytes(jline(type="attempt", id="a1", actions=[{}, {}, {}])
                  + jline(type="observed", id="a1", tx="t", tx_mc=5, utime=7, fee=1,
                          failure=[None, "action skipped", None]))
    t = tl.JournalTail(j)
    t.poll(1.0)
    assert set(t.pending) == {("a1", 0), ("a1", 2)}


def test_a_whole_external_failure_has_no_pending_actions(tmp_path):
    j = tmp_path / "journal.jsonl"
    j.write_bytes(jline(type="attempt", id="a1", actions=[{}, {}])
                  + jline(type="observed", id="a1", failure=["exit 37", "exit 37"]))
    t = tl.JournalTail(j)
    t.poll(1.0)
    assert t.pending == {}


def test_a_delivery_journaled_before_its_observed_record_is_not_resurrected(tmp_path):
    # codex r1 §1: the follower can journal `delivered` before `observed` (ramp.py:757–759).
    j = tmp_path / "journal.jsonl"
    j.write_bytes(jline(type="attempt", id="a1", actions=[{}, {}])
                  + jline(type="delivered", id="a1", action=0, receipt_failure=None))
    t = tl.JournalTail(j)
    t.poll(1.0)
    with j.open("ab") as fh:
        fh.write(jline(type="observed", id="a1", failure=[None, None]))
    t.poll(2.0)
    assert set(t.pending) == {("a1", 1)} and t.early == set()


def test_tail_state_stays_bounded(tmp_path):
    j = tmp_path / "journal.jsonl"
    t = tl.JournalTail(j)
    for i in range(200):
        with j.open("ab") as fh:
            fh.write(jline(type="attempt", id=f"a{i}", actions=[{}]) + jline(type="observed", id=f"a{i}", failure=[None])
                     + jline(type="delivered", id=f"a{i}", action=0, receipt_failure=None))
    with j.open("ab") as fh:
        fh.write(jline(type="attempt", id="x", actions=[{}]) + jline(type="expired", id="x"))
    t.poll(1.0)
    assert t.pending == {} and t.actions == {} and t.early == set()


def test_repeated_sends_with_withheld_deliveries_hit_the_limits(tmp_path):
    # codex r3: a wallet is released at its sender transaction, so undelivered actions can pile up.
    j = tmp_path / "journal.jsonl"
    t = tl.JournalTail(j)
    lim = {"max_age_s": 300, "max_count": 5}
    for i in range(6):
        with j.open("ab") as fh:
            fh.write(jline(type="attempt", id=f"a{i}", actions=[{}]) + jline(type="observed", id=f"a{i}"))
        t.poll(float(i))
    assert any("undelivered actions" in r for r in t.reasons(6.0, lim))
    assert t.reasons(6.0, {"max_age_s": 300, "max_count": 10}) == []
    assert any("undelivered for" in r for r in t.reasons(301.0, {"max_age_s": 300, "max_count": 10}))


# ---------------------------------------------------------------- containment (real processes)


def test_a_child_dies_with_its_supervisor(tmp_path):
    """A supervisor process spawns a child through spawn() and is SIGKILLed: the child must not survive."""
    helper = tmp_path / "parent.py"
    helper.write_text(textwrap.dedent(f"""
        import importlib.util, sys, time
        spec = importlib.util.spec_from_file_location("t1_load", {str(SCRIPTS / 't1-load.py')!r})
        tl = importlib.util.module_from_spec(spec); spec.loader.exec_module(tl)
        from pathlib import Path
        p = tl.spawn(["sleep", "300"], Path({str(tmp_path / 'child.log')!r}))
        print(p.pid, flush=True)
        time.sleep(300)
    """))
    parent = subprocess.Popen([sys.executable, str(helper)], stdout=subprocess.PIPE, text=True)
    child = int(parent.stdout.readline())
    assert os.getpgid(child) == child  # its own process group
    parent.send_signal(signal.SIGKILL)
    parent.wait(5)
    for _ in range(50):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(child, signal.SIGKILL)
        pytest.fail("the child outlived its supervisor")


def test_a_stop_also_kills_the_childs_own_children(tmp_path):
    # codex r1 §4: the ramp spawns the signer; a stop must reach that grandchild through the process group.
    log = tmp_path / "c.log"
    child = tl.spawn(["sh", "-c", "sleep 300 & echo $! ; wait"], log)
    for _ in range(100):
        text = log.read_text().strip()
        if text:
            break
        time.sleep(0.05)
    grandchild = int(text)
    assert os.getpgid(grandchild) == child.pid
    result = tl.terminate({"c": child})
    assert result["c"]["group_alive"] is False
    for _ in range(50):
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(grandchild, signal.SIGKILL)
        pytest.fail("the grandchild survived the stop")


def test_terminate_confirms_that_every_group_is_gone(tmp_path):
    stubborn = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(300)"
    children = {"a": tl.spawn(["sleep", "300"], tmp_path / "a.log"),
                "b": tl.spawn([sys.executable, "-c", stubborn], tmp_path / "b.log")}
    for _ in range(100):  # wait until the SIGTERM handler is installed
        if "ready" in (tmp_path / "b.log").read_text():
            break
        time.sleep(0.05)
    result = tl.terminate(children)
    assert all(not r["group_alive"] for r in result.values())
    assert result["a"]["rc"] == -signal.SIGTERM and result["b"]["rc"] == -signal.SIGKILL


# ---------------------------------------------------------------- the supervision loop


class Clock:
    def __init__(self):
        self.t = 1000.0

    def mono(self):
        return self.t

    def sleep(self, s):
        self.t += s


def run_supervise(tmp_path, st_fn, launch=None, duration=60, clock=None):
    clock = clock or Clock()
    out = tmp_path / "run"
    (out / "ramp").mkdir(parents=True)
    status_path = tmp_path / "status.json"

    def mono():
        status_path.write_text(json.dumps(st_fn(clock.t)))
        return clock.t
    mono()  # the observer has published before the supervisor starts
    launch = launch or (lambda name: tl.spawn(["sleep", "300"], tmp_path / f"{name}.log"))
    rc = tl.supervise(record(), status_path, out, launch, mono=mono, wall=lambda: 0.0, sleep=clock.sleep,
                      boot=lambda: BOOT, duration=duration)
    rows = [json.loads(x) for x in (out / "load.jsonl").read_text().splitlines()]
    return rc, rows


class FinishingRamp:
    """A real sleeping process that reports exit 0 once the fake clock passes `at` (the ramp's own end)."""

    def __init__(self, tmp_path, clock, at, rc=0):
        self.proc = tl.spawn(["sleep", "300"], tmp_path / "ramp.log")
        self.pid, self.clock, self.at, self.rc = self.proc.pid, clock, at, rc
        self.returncode = None

    def poll(self):
        if self.returncode is None and self.clock.t >= self.at:
            self.returncode = self.rc
        return self.returncode

    def wait(self, timeout=None):
        self.proc.wait(timeout)
        return self.returncode


def launcher(tmp_path, clock, ramp_at, rc=0):
    def launch(name):
        if name == "ramp":
            return FinishingRamp(tmp_path, clock, ramp_at, rc)
        return tl.spawn(["sleep", "300"], tmp_path / f"{name}.log")
    return launch


def test_the_schedule_fits_exactly_in_72_hours():
    # codex r2: preparation, every transition, the final tail and a margin all fit before the cutoff.
    for fx in (1, 2, 8):
        s = tl.schedule(fx)
        # the ramp's own budget (bench/t4/ramp.py fee_horizon) with the pinned timing, computed independently
        prep, transition, tail = (fx + 1) * 120, 2 * 120 + 120, 120 + 2 * 60 + 30 + 120
        assert (s["prep"], s["transition"], s["tail"]) == (prep, transition, tail)
        assert prep + tl.STEPS * (s["step_seconds"] + transition) + tail <= tl.DURATION - 600
        assert s["slack"] >= tl.MARGIN and 0 < s["step_seconds"] <= 86_400
    s = tl.schedule(2)
    argv = " ".join(tl.ramp_argv(record(), tl.Path("/o")))
    assert f"--steps {tl.STEPS}" in argv and f"--step-seconds {s['step_seconds']}" in argv
    for k, v in tl.RAMP_TIMING.items():
        assert f"--{k.replace('_', '-')} {v}" in argv  # the budget's timing is the one the ramp runs with


def test_no_step_length_fits_a_too_short_run():
    with pytest.raises(tl.Refuse, match="no step length"):
        tl.schedule(1, duration=1000)


SCALED = 2400  # a fake run long enough that the ramp's scaled finish lies more than one tick before the cutoff
FINISH = 1000 + tl.STEPS * tl.schedule(2)["step_seconds"] * SCALED / tl.DURATION + 1


def test_a_clean_run_ends_when_the_ramp_finishes_its_schedule_then_at_the_cutoff(tmp_path):
    clock = Clock()
    rc, rows = run_supervise(tmp_path, lambda now: status(now), launch=launcher(tmp_path, clock, FINISH),
                             duration=SCALED, clock=clock)
    kinds = [r["kind"] for r in rows]
    assert rc == 0 and kinds == ["start", "ramp_done", "cutoff", "terminated", "end"]
    assert all(not c["group_alive"] for c in rows[3]["children"].values())


def test_a_ramp_that_exits_zero_before_its_schedule_ends_is_a_stop(tmp_path):
    clock = Clock()
    rc, rows = run_supervise(tmp_path, lambda now: status(now), launch=launcher(tmp_path, clock, 1010), clock=clock)
    assert rc == 1 and any("ramp exited on its own with rc 0" in r for r in rows[1]["reasons"])


def test_a_ramp_still_running_at_the_cutoff_is_a_stop(tmp_path):
    rc, rows = run_supervise(tmp_path, lambda now: status(now))
    assert rc == 1 and rows[1]["kind"] == "stop"
    assert rows[1]["reasons"] == ["the ramp had not finished its schedule at the cutoff"]


def test_a_ramp_failing_at_its_end_is_a_stop(tmp_path):
    clock = Clock()
    rc, rows = run_supervise(tmp_path, lambda now: status(now), launch=launcher(tmp_path, clock, FINISH, rc=1),
                             duration=SCALED, clock=clock)
    assert rc == 1 and any("rc 1" in r for r in rows[1]["reasons"])


def test_a_stop_condition_stops_the_run(tmp_path):
    rc, rows = run_supervise(tmp_path, lambda now: status(now, safety_hits=1 if now > 1010 else 0))
    assert rc == 1 and rows[1]["kind"] == "stop" and any("safety" in r for r in rows[1]["reasons"])


def test_a_child_that_exits_on_its_own_stops_the_run(tmp_path):
    def launch(name):
        return tl.spawn(["true"] if name == "reads" else ["sleep", "300"], tmp_path / f"{name}.log")
    clock = Clock()
    rc, rows = run_supervise(tmp_path, lambda now: status(now), launch=launch, clock=clock)
    assert rc == 1 and any("reads exited on its own" in r for r in rows[1]["reasons"])


def test_an_unhealthy_status_refuses_the_start_before_any_child(tmp_path):
    launched = []
    rc, rows = run_supervise(tmp_path, lambda now: status(now, blind=True),
                             launch=lambda name: launched.append(name))
    assert rc == 2 and launched == [] and rows[0]["kind"] == "refused"


def test_a_failed_second_launch_terminates_the_first_child(tmp_path):
    started = {}

    def launch(name):
        if name == "reads":
            raise OSError("no such file")
        started[name] = tl.spawn(["sleep", "300"], tmp_path / "ramp.log")
        return started[name]
    rc, rows = run_supervise(tmp_path, lambda now: status(now), launch=launch)
    assert rc == 1 and "launch of reads failed" in rows[1]["reasons"][0]
    assert started["ramp"].poll() is not None


def test_undelivered_actions_in_the_journal_stop_the_run(tmp_path):
    def st_fn(now):
        if now > 1010:
            j = tmp_path / "run" / "ramp" / "journal.jsonl"
            if not j.exists():
                j.write_bytes(jline(type="attempt", id="a1", actions=[{}]) + jline(type="observed", id="a1"))
        return status(now)
    rc, rows = run_supervise(tmp_path, st_fn, duration=600)
    assert rc == 1 and any("undelivered for" in r for r in rows[1]["reasons"])
