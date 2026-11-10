"""Tests for t1_probe.py (runs on a validator host) and t1-observe.py (the coordinator collectors).

The diagnostics line has the shape the validator logs (candidate-resolver.cpp, simplex-candidate-payloads). The
cache tests run the real t1_probe.read_logs on temporary log files behind a fake SSH, so cursor handling across
rotation, deletion, truncation and collector restart is exercised end to end. No test reaches a host or a tunnel.
"""

import base64
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import time
from types import SimpleNamespace

import pytest
import t1_probe
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("t1_observe", SCRIPTS / "t1-observe.py")
obs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(obs)

T0 = 1_762_800_000
BOOT = "dd1d9f3a-edf0-4835-a97d-731798e7be90"
ALL_FIELDS = {k: 1 for k in obs.CACHE_FIELDS}


def stamp(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))


def payload_line(t: float, **fields) -> str:
    f = dict(ALL_FIELDS, **fields)
    body = " ".join(f"{k}={v}" for k, v in f.items() if v is not None)
    return f"[ 2][t 4][{stamp(t)}.123456789][candidate-resolver.cpp:966][!simplex]\tMEMORY_DIAGNOSTICS simplex-candidate-payloads {body}\n"


def append(path, text):
    with open(path, "a") as fh:
        fh.write(text)


# ---------------------------------------------------------------- probe: log cursors


def ids(files):
    return {e["name"]: fid for fid, e in files.items()}


def cur(entry, closed=False):
    return (entry["offset"], entry["fp"], closed)


def test_baseline_sets_cursors_at_the_end_and_reads_nothing(tmp_path):
    append(tmp_path / "node.log", payload_line(T0))
    files, lines, missing = t1_probe.read_logs(None, str(tmp_path / "node.log*"))
    (e,) = files.values()
    assert e["status"] == "baseline" and e["offset"] == e["size"] == (tmp_path / "node.log").stat().st_size
    assert lines == [] and missing == []


def test_read_from_cursor_leaves_a_partial_line_for_later(tmp_path):
    log = tmp_path / "node.log"
    append(log, "old line\n")
    files, _, _ = t1_probe.read_logs(None, str(tmp_path / "node.log*"))
    fid, base = next(iter(files.items()))
    full = payload_line(T0 + 5, node_charged_bytes=77)
    append(log, full + full[:30])
    files, lines, _ = t1_probe.read_logs({fid: cur(base)}, str(tmp_path / "node.log*"))
    e = files[fid]
    assert e["status"] == "read" and e["offset"] == base["offset"] + len(full) and e["behind"] == 30
    assert [d["fields"]["node_charged_bytes"] for d in lines] == [77] and lines[0]["ts"] == T0 + 5
    append(log, full[30:])
    files, lines, _ = t1_probe.read_logs({fid: cur(e)}, str(tmp_path / "node.log*"))
    assert len(lines) == 1 and files[fid]["behind"] == 0


def test_a_rename_keeps_the_cursor_and_a_new_file_is_read_from_zero(tmp_path):
    log = tmp_path / "node.log"
    append(log, payload_line(T0 + 1))
    files, _, _ = t1_probe.read_logs(None, str(tmp_path / "node.log*"))
    fid = ids(files)["node.log"]
    c = cur(files[fid])
    append(log, payload_line(T0 + 2))
    os.rename(log, tmp_path / "node.log.old")
    append(log, payload_line(T0 + 3))
    files, lines, missing = t1_probe.read_logs({fid: c}, str(tmp_path / "node.log*"))
    assert ids(files)["node.log.old"] == fid and files[fid]["status"] == "read"
    assert files[ids(files)["node.log"]]["status"] == "new"
    assert sorted(d["ts"] for d in lines) == [T0 + 2, T0 + 3] and missing == []


@pytest.mark.parametrize("new_text,status", [
    ("short\n", "shrunk"),  # smaller than the cursor
    ("z" * 200 + "\n", "rewritten"),  # rewritten in place and already past the cursor
])
def test_a_file_changed_under_its_cursor_is_a_gap_and_is_read_from_zero(tmp_path, new_text, status):
    log = tmp_path / "node.log"
    append(log, "x" * 100 + "\n")
    files, _, _ = t1_probe.read_logs(None, str(tmp_path / "node.log*"))
    fid, base = next(iter(files.items()))
    with open(log, "w") as fh:
        fh.write(new_text)
    files, _, _ = t1_probe.read_logs({fid: cur(base)}, str(tmp_path / "node.log*"))
    e = files[fid]
    assert e["status"] == status and e["gap_bytes"] == 101 and e["start"] == 0 and e["offset"] == len(new_text)
    # The same change under a closed cursor is a new file that reused the inode: read from 0, no gap.
    files, _, _ = t1_probe.read_logs({fid: cur(base, closed=True)}, str(tmp_path / "node.log*"))
    assert files[fid]["status"] == "new" and "gap_bytes" not in files[fid] and files[fid]["start"] == 0


def test_an_unterminated_line_longer_than_the_cap_is_consumed_as_a_gap(tmp_path):
    log = tmp_path / "node.log"
    append(log, "")
    files, _, _ = t1_probe.read_logs(None, str(tmp_path / "node.log*"))
    fid, base = next(iter(files.items()))
    append(log, "y" * 500)
    files, _, _ = t1_probe.read_logs({fid: cur(base)}, str(tmp_path / "node.log*"), cap=200)
    e = files[fid]
    assert e["status"] == "over_cap" and e["gap_bytes"] == 200 and e["offset"] == 200


def test_more_than_the_cap_is_lag_not_loss(tmp_path):
    log = tmp_path / "node.log"
    append(log, "")
    fid, e = next(iter(t1_probe.read_logs(None, str(tmp_path / "node.log*"))[0].items()))
    for i in range(10):
        append(log, payload_line(T0 + i))
    c, got = cur(e), []
    for _ in range(20):
        files, lines, _ = t1_probe.read_logs({fid: c}, str(tmp_path / "node.log*"), cap=700)
        got += [d["ts"] for d in lines]
        assert files[fid]["status"] == "read"
        c = cur(files[fid])
        if files[fid]["behind"] == 0:
            break
    assert got == [T0 + i for i in range(10)]


def test_a_second_name_for_one_file_is_read_once(tmp_path):
    append(tmp_path / "node.log", payload_line(T0))
    os.link(tmp_path / "node.log", tmp_path / "node.log.link")
    files, lines, _ = t1_probe.read_logs({}, str(tmp_path / "node.log*"))
    assert sorted(e["status"] for e in files.values()) == ["duplicate", "new"] and len(lines) == 1


def test_cursor_ids_without_a_file_are_reported_missing(tmp_path):
    append(tmp_path / "node.log", "a\n")
    _, _, missing = t1_probe.read_logs({"1:2": (5, "fp")}, str(tmp_path / "node.log*"))
    assert missing == ["1:2"]


def test_du_rejects_a_walk_that_did_not_exit_zero(monkeypatch):
    replies = iter([subprocess.CompletedProcess([], 1, "123\t/x\n", "du: cannot read"),
                    subprocess.CompletedProcess([], 0, "456\t/y\n", "")])
    monkeypatch.setattr(t1_probe.subprocess, "run", lambda *a, **k: next(replies))
    out = t1_probe.du(["/x", "/y"])
    assert out["/x"].startswith("error: rc=1") and out["/y"] == 456


def test_oom_kills_reads_vmstat(monkeypatch, tmp_path):
    vm = tmp_path / "vmstat"
    vm.write_text("nr_free_pages 5\noom_kill 3\n")
    real_open = open
    monkeypatch.setattr("builtins.open", lambda p, *a, **k: real_open(vm if p == "/proc/vmstat" else p, *a, **k))
    assert t1_probe.oom_kills() == 3
    vm.write_text("nr_free_pages 5\n")
    with pytest.raises(ValueError):
        t1_probe.oom_kills()


# ---------------------------------------------------------------- fakes for the observer


class Clocks:
    def __init__(self):
        self.w, self.m = float(T0), 1000.0

    def wall(self):
        return self.w

    def mono(self):
        return self.m

    def tick(self, s):
        self.w += s
        self.m += s


HOSTS = [SimpleNamespace(name=n, address=f"192.0.2.{i}", ssh_user="root", ssh_key="", ssh_port=22)
         for i, n in enumerate(obs.HOSTS, 1)]
ADDR = {h.address: h.name for h in HOSTS}


def resources(clock, **over):
    r = {"unit": {"main_pid": 10, "n_restarts": 0, "active_state": "active", "exec_main_start_monotonic_us": 1},
         "proc": {"RssAnon": 1, "VmRSS": 2, "RssFile": 1, "VmSwap": 0, "Threads": 3, "fds": 4},
         "mem": {"MemTotal": 9, "MemAvailable": 8, "SwapTotal": 0, "SwapFree": 0}, "oom_kill": 0, "boot_id": BOOT,
         "disks": {p: {"free_bytes": 1, "size_bytes": 2, "free_inodes": 3, "total_inodes": 4} for p in obs.DATA_PATHS},
         "sample_clock": clock.w}
    r.update(over)
    return r


class FakeSsh:
    """Answers t1-observe's SSH calls: the probe runs the real read_logs on each host's tmp log dir."""

    def __init__(self, tmp_path, clocks):
        self.tmp, self.clocks, self.over, self.raw, self.calls = tmp_path, clocks, {}, {}, []
        self.du = {}
        self.clock_reply = {}
        for h in HOSTS:
            (tmp_path / h.name).mkdir(exist_ok=True)

    def log(self, host):
        return self.tmp / host / "node.log"

    def __call__(self, argv, **kw):
        host = ADDR[argv[-2].split("@")[1]]
        remote = argv[-1]
        self.calls.append((host, remote, kw))
        if host in self.raw:
            reply = self.raw[host]
            if isinstance(reply, BaseException):
                raise reply
            return subprocess.CompletedProcess(argv, 0, reply, "")
        if remote.startswith("python3 -c"):
            value = self.clock_reply.get(host, lambda: self.clocks.w)()
            return subprocess.CompletedProcess(argv, 0, json.dumps(value) + "\n", "")
        args = shlex.split(remote)
        if "--du" in args:
            du = self.du.get(host, {p: 100 for p in obs.DU_PATHS})
            return subprocess.CompletedProcess(argv, 0, json.dumps({"du": du}) + "\n", "")
        report = resources(self.clocks, **self.over.get(host, {}))
        cursors = None if "--baseline" in args else json.loads(args[args.index("--cursors") + 1])
        report["safety"] = []
        report["files"], report["diag"], report["missing"] = t1_probe.read_logs(
            cursors, str(self.tmp / host / "node.log*"), safety=report["safety"])
        return subprocess.CompletedProcess(argv, 0, json.dumps(report) + "\n", "")


def H(label: str) -> str:
    """A well-formed 32-byte base64 hash named by `label`."""
    return base64.b64encode(hashlib.sha256(label.encode()).digest()).decode()


class FakeRpc:
    def __init__(self, head=50, ids=None, fail=(), head_hdr=None, wrong_seq=None):
        self.head, self.ids, self.fail = head, ids or {}, set(fail)
        self.head_hdr, self.wrong_seq = head_hdr, wrong_seq
        self.file_hash = H("F")

    def ident(self, seq):
        return {"workchain": -1, "shard": obs.SHARD, "seqno": seq, "root_hash": H(self.ids.get(seq, f"R{seq}")),
                "file_hash": self.file_hash}

    def call(self, method, timeout=None, **p):
        if method in self.fail:
            raise ConnectionError("down")
        if method == "getMasterchainInfo":
            return {"last": self.ident(self.head)}
        seq = p["seqno"]
        if self.head_hdr is not None and seq == self.head:
            return self.head_hdr
        i = self.ident(self.wrong_seq if self.wrong_seq is not None else seq)
        return {"id": i, "gen_utime": 100 + seq}


def make(tmp_path, rpcs=None):
    clocks = Clocks()
    ssh = FakeSsh(tmp_path / "hosts", clocks) if (tmp_path / "hosts").exists() else None
    if ssh is None:
        (tmp_path / "hosts").mkdir()
        ssh = FakeSsh(tmp_path / "hosts", clocks)
    o = obs.Observer(HOSTS, rpcs or {h: FakeRpc() for h in obs.HOSTS}, tmp_path / "out",
                     wall=clocks.wall, mono=clocks.mono, run=ssh)
    return o, ssh, clocks


def rows(o, name):
    p = o.out / f"{name}.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def stale(o, keys):
    return o.fresh.stale(keys)


# ---------------------------------------------------------------- resources


def test_a_complete_resource_sample_is_fresh(tmp_path):
    o, ssh, clocks = make(tmp_path)
    o.resources_round(HOSTS[0])
    (r,) = rows(o, "resources")
    assert r["complete"] is True and r["missing"] == [] and r["unit"]["main_pid"] == 10
    assert stale(o, ["resources:node-1"]) == []


@pytest.mark.parametrize("over,missing", [
    ({"proc": "error: gone"}, "proc"),
    ({"mem": {"MemAvailable": 1}}, "mem"),
    ({"oom_kill": True}, "oom_kill"),
    ({"oom_kill": -1}, "oom_kill"),
    ({"boot_id": "error: x"}, "boot_id"),
    ({"disks": {"/var/lib/tos/validator": {"free_bytes": 1, "size_bytes": 2, "free_inodes": 3, "total_inodes": 4}}}, "disk /var/log/tos"),
    ({"unit": "error: x"}, "unit"),
    ({"unit": {"main_pid": 0, "n_restarts": 0, "active_state": "active"}}, "unit main_pid"),
    ({"unit": {"main_pid": 1, "n_restarts": 0, "active_state": "weird"}}, "unit"),
    ({"sample_clock": T0 - 3600}, "sample_clock outside the call"),
    ({"sample_clock": "x"}, "sample_clock"),
])
def test_a_partial_resource_sample_is_kept_but_never_fresh(tmp_path, over, missing):
    o, ssh, clocks = make(tmp_path)
    ssh.over["node-1"] = over
    o.resources_round(HOSTS[0])
    (r,) = rows(o, "resources")
    assert r["complete"] is False and missing in r["missing"]
    assert stale(o, ["resources:node-1"]) != []


def test_an_inactive_validator_is_a_complete_observation_without_proc(tmp_path):
    o, ssh, clocks = make(tmp_path)
    ssh.over["node-1"] = {"unit": {"main_pid": 0, "n_restarts": 1, "active_state": "failed"}, "proc": "no main pid"}
    o.resources_round(HOSTS[0])
    assert rows(o, "resources")[0]["complete"] is True


@pytest.mark.parametrize("raw,error", [
    ("", "no output (ssh rc 0)"), ("nope\n", "output is not JSON"),
    ('{"unit": {"main_pid": NaN}}\n', "output is not JSON"), ("[1]\n", "report is not an object"),
    (subprocess.TimeoutExpired("ssh", 45), "timeout"),
])
def test_an_unreadable_host_is_an_error_row_in_both_series(tmp_path, raw, error):
    o, ssh, clocks = make(tmp_path)
    ssh.raw["node-1"] = raw
    o.resources_round(HOSTS[0])
    assert rows(o, "resources")[0]["error"] == error and rows(o, "cache")[0]["error"] == error


def test_the_probe_call_is_bounded_on_the_host_and_locally(tmp_path):
    o, ssh, clocks = make(tmp_path)
    o.resources_round(HOSTS[0])
    host, remote, kw = ssh.calls[0]
    assert remote.startswith(f"timeout -k 5 {obs.PROBE_TIMEOUT - 5} python3 - ") and kw["timeout"] == obs.PROBE_TIMEOUT
    assert "--baseline" in remote and kw["input"] == obs.PROBE.read_text()


# ---------------------------------------------------------------- cache


def baselined(tmp_path):
    o, ssh, clocks = make(tmp_path)
    append(ssh.log("node-1"), "boot\n")
    o.resources_round(HOSTS[0])
    return o, ssh, clocks


def test_the_baseline_round_never_makes_the_cache_fresh(tmp_path):
    o, ssh, clocks = make(tmp_path)
    append(ssh.log("node-1"), payload_line(T0))
    o.resources_round(HOSTS[0])
    assert rows(o, "cache")[0]["baseline"] is True and stale(o, ["cache:node-1"]) != []
    assert o.cursors["node-1"]["baselined"] == T0


def test_a_baseline_report_never_makes_the_cache_fresh_even_with_lines(tmp_path):
    o, _, _ = make(tmp_path)
    line = {"ts": T0, "kind": "simplex-candidate-payloads", "fields": dict(ALL_FIELDS), "file": "node.log"}
    report = {"files": {"1:1": {"name": "node.log", "status": "baseline", "start": 5, "offset": 5, "size": 5, "fp": "x"}},
              "diag": [line], "missing": [], "safety": []}
    o.cache_part("node-1", None, report, {"ts": T0, "host": "node-1"}, T0)
    assert stale(o, ["cache:node-1"]) != [] and o.cursors["node-1"]["baselined"] == T0


def test_a_new_complete_payload_line_makes_the_cache_fresh(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    clocks.tick(60)
    append(ssh.log("node-1"), payload_line(clocks.w - 10, node_charged_bytes=5))
    o.resources_round(HOSTS[0])
    read = [r for r in rows(o, "cache") if r["kind"] == "read"][-1]
    assert [d["fields"]["node_charged_bytes"] for d in read["lines"]] == [5]
    assert stale(o, ["cache:node-1"]) == []


@pytest.mark.parametrize("line", [
    payload_line(T0 + 50, node_live_over_charge=None),
    payload_line(T0 + 50, nonfinalized_bytes=None),
    payload_line(T0 + 60 - 181),  # older than the freshness window
    payload_line(T0 + 60 + 6),  # from the future beyond the skew allowance
    payload_line(T0 + 50).replace("simplex-candidate-payloads", "simplex-candidate-resolver"),
])
def test_an_incomplete_or_mistimed_payload_line_is_not_fresh(tmp_path, line):
    o, ssh, clocks = baselined(tmp_path)
    clocks.tick(60)
    append(ssh.log("node-1"), line)
    o.resources_round(HOSTS[0])
    assert stale(o, ["cache:node-1"]) != []


def test_a_deleted_file_with_unread_appends_is_one_permanent_gap(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    append(ssh.log("node-1"), payload_line(T0 + 1))  # appended after the read, then the file is deleted
    os.unlink(ssh.log("node-1"))
    append(ssh.log("node-1"), payload_line(T0 + 2))
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    gaps = [r for r in rows(o, "cache") if r["kind"] == "coverage_gap"]
    # A new inode is "vanished"; a filesystem that reuses the inode shows the same loss as "rewritten".
    assert [(g["name"], g["reason"]) for g in gaps] in ([("node.log", "vanished")], [("node.log", "rewritten")])
    assert stale(o, ["cache:node-1"]) != []
    for _ in range(3):
        clocks.tick(60)
        o.resources_round(HOSTS[0])
    assert len([r for r in rows(o, "cache") if r["kind"] == "coverage_gap"]) == 1


def test_a_deleted_file_that_was_drained_at_its_end_but_not_rotated_is_still_a_gap(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    os.unlink(ssh.log("node-1"))
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert [r["reason"] for r in rows(o, "cache") if r["kind"] == "coverage_gap"] == ["vanished"]


def test_a_rotated_file_read_to_its_end_may_be_deleted_without_a_gap(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    os.rename(ssh.log("node-1"), ssh.tmp / "node-1" / "node.log.old.3")
    clocks.tick(60)
    o.resources_round(HOSTS[0])  # observed under its rotated name, drained
    os.unlink(ssh.tmp / "node-1" / "node.log.old.3")
    append(ssh.log("node-1"), payload_line(clocks.w + 59))
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert [r for r in rows(o, "cache") if r["kind"] == "coverage_gap"] == []
    assert stale(o, ["cache:node-1"]) == []


def test_a_rotated_file_deleted_with_unread_bytes_is_a_gap(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    rotated = ssh.tmp / "node-1" / "node.log.old"
    os.rename(ssh.log("node-1"), rotated)
    append(rotated, "partial line without newline")  # left unread: the cursor stops before it
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    os.unlink(rotated)
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert [r["reason"] for r in rows(o, "cache") if r["kind"] == "coverage_gap"] == ["vanished"]


def test_a_truncated_file_is_a_gap(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    with open(ssh.log("node-1"), "w") as fh:
        fh.write("")
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert [r["reason"] for r in rows(o, "cache") if r["kind"] == "coverage_gap"] == ["shrunk"]


def test_a_gap_round_does_not_refresh_the_cache_even_with_a_good_line(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    with open(ssh.log("node-1"), "w") as fh:
        fh.write(payload_line(T0 + 55))
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert stale(o, ["cache:node-1"]) != []


def test_cursors_survive_a_restart_and_nothing_is_read_twice(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    append(ssh.log("node-1"), payload_line(T0 + 10, node_charged_bytes=1))
    o.resources_round(HOSTS[0])
    o2 = obs.Observer(HOSTS, o.rpcs, o.out, wall=clocks.wall, mono=clocks.mono, run=ssh)
    append(ssh.log("node-1"), payload_line(T0 + 11, node_charged_bytes=2))
    o2.resources_round(HOSTS[0])
    reads = [r for r in rows(o2, "cache") if r["kind"] == "read"]
    assert [r["baseline"] for r in reads] == [True, False, False]
    assert [d["fields"]["node_charged_bytes"] for r in reads for d in r["lines"]] == [1, 2]


def test_a_missing_cursor_file_with_existing_cache_rows_refuses_to_start(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    (o.out / "cursors" / "node-1.json").unlink()
    with pytest.raises(obs.RefuseStart):
        obs.Observer(HOSTS, o.rpcs, o.out, wall=clocks.wall, mono=clocks.mono, run=ssh)


def test_cursors_are_written_only_after_the_cache_row(tmp_path, monkeypatch):
    o, ssh, clocks = baselined(tmp_path)
    append(ssh.log("node-1"), payload_line(T0 + 10))
    before = json.loads((o.out / "cursors" / "node-1.json").read_text())

    def boom(record):
        raise OSError("disk full")
    monkeypatch.setattr(o.sinks["cache"], "write", boom)
    with pytest.raises(OSError):
        o.resources_round(HOSTS[0])
    assert json.loads((o.out / "cursors" / "node-1.json").read_text()) == before


def test_a_vanished_cursor_is_remembered_then_forgotten(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    fid = next(iter(o.cursors["node-1"]["files"]))
    report = {"files": {}, "diag": [], "missing": [fid], "safety": []}
    base = {"ts": T0, "host": "node-1"}
    o.cache_part("node-1", o.cursors["node-1"], report, base, T0)
    assert fid in o.cursors["node-1"]["grave"] and fid in o.cursor_offsets("node-1")
    for _ in range(obs.GRAVE_ROUNDS):
        o.cache_part("node-1", o.cursors["node-1"], report, base, T0)
    assert o.cursors["node-1"]["grave"] == {}
    assert len([r for r in rows(o, "cache") if r["kind"] == "coverage_gap"]) == 1


def test_a_malformed_log_read_is_a_cache_error_and_keeps_the_cursors(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    before = dict(o.cursors["node-1"])
    for report in ({"files": {"1:1": {"name": "n", "status": "read", "start": 9, "offset": 3, "size": 9, "fp": "x"}}, "diag": [], "missing": [], "safety": []},
                   {"files": {}, "diag": [{"ts": "1", "kind": "k", "fields": {}}], "missing": [], "safety": []},
                   {"files": {}, "diag": [], "missing": None, "safety": []},
                   {"files": {}, "diag": [], "missing": []},
                   {"files": {}, "diag": [], "missing": [], "safety": [{"file": "n", "line": 7}]}):
        o.cache_part("node-1", o.cursors["node-1"], report, {"ts": T0, "host": "node-1"}, T0)
    assert [r["error"] for r in rows(o, "cache") if r["kind"] == "error"] == ["probe returned no valid log read"] * 5
    assert o.cursors["node-1"] == before


# ---------------------------------------------------------------- du


def test_du_is_fresh_only_when_every_path_has_a_size(tmp_path):
    o, ssh, clocks = make(tmp_path)
    o.du_round(HOSTS[0])
    assert stale(o, ["du:node-1"]) == []
    ssh.du["node-2"] = {obs.DU_PATHS[0]: 5, obs.DU_PATHS[1]: "error: rc=1"}
    o.du_round(HOSTS[1])
    assert rows(o, "du")[-1]["complete"] is False and stale(o, ["du:node-2"]) != []
    host, remote, kw = ssh.calls[-1]
    assert remote.startswith("timeout -k 10 ") and kw["timeout"] == obs.DU_TIMEOUT


# ---------------------------------------------------------------- clock


def test_clock_verdicts(tmp_path):
    o, ssh, clocks = make(tmp_path)
    assert o.clock_round(HOSTS[0])["verdict"] == "ok"
    ssh.clock_reply["node-2"] = lambda: clocks.w + 10
    assert o.clock_round(HOSTS[1])["verdict"] == "skewed"
    ssh.raw["node-3"] = ""
    assert o.clock_round(HOSTS[2])["verdict"] == "unmeasured"


def test_clock_uncertain_when_the_interval_crosses_the_limit(tmp_path):
    o, ssh, clocks = make(tmp_path)
    real = ssh.__call__

    def slow(argv, **kw):
        clocks.tick(1.0)  # each call takes 2 s: bound 1 s
        r = real(argv, **kw)
        clocks.tick(1.0)
        return r
    o.run = slow
    ssh.clock_reply["node-1"] = lambda: clocks.w + 1.5  # offset 1.5 ± 1 crosses the 2 s limit
    row = o.clock_round(HOSTS[0])
    assert row["verdict"] == "uncertain" and row["best"]["bound"] == 1.0


def test_a_coordinator_clock_step_during_the_call_is_not_a_measurement(tmp_path):
    o, ssh, clocks = make(tmp_path)
    real = ssh.__call__

    def stepping(argv, **kw):
        clocks.w -= 30  # wall steps back, monotonic does not
        return real(argv, **kw)
    o.run = stepping
    row = o.clock_round(HOSTS[0])
    assert row["verdict"] == "unmeasured" and all("stepped" in t["error"] for t in row["tries"])


def test_a_new_skewed_clock_makes_the_status_blind_at_once(tmp_path):
    o, ssh, clocks = make(tmp_path)
    o.clock_round(HOSTS[0])
    ssh.clock_reply["node-1"] = lambda: clocks.w + 10
    o.clock_round(HOSTS[0])
    st = o.status()
    assert "clock:node-1 latest verdict skewed" in st["reasons"]
    assert st["clock"]["node-1"]["verdict"] == "skewed" and st["clock"]["node-1"]["last_ok"] == T0


# ---------------------------------------------------------------- chain


def test_a_head_is_bound_to_its_header(tmp_path):
    o, _, _ = make(tmp_path)
    o.chain_round("node-1")
    head = rows(o, "chain")[-1]
    assert head["id"] == [-1, obs.SHARD, 50, H("R50"), H("F")] and head["gen_utime"] == 150
    assert stale(o, ["chain:node-1"]) == []


def hid(**over):
    i = {"workchain": -1, "shard": obs.SHARD, "seqno": 50, "root_hash": H("R50"), "file_hash": H("F")}
    i.update(over)
    return {k: v for k, v in i.items() if v != "DROP"}


@pytest.mark.parametrize("hdr", [
    {"id": hid(file_hash=H("other")), "gen_utime": 1},
    {"id": hid(seqno=49), "gen_utime": 1},
    {"id": hid(workchain=0), "gen_utime": 1},
    {"id": hid()},
])
def test_a_head_whose_header_does_not_match_is_an_error_and_not_fresh(tmp_path, hdr):
    o, _, _ = make(tmp_path, {h: FakeRpc(head_hdr=hdr) for h in obs.HOSTS})
    o.chain_round("node-1")
    assert "error" in rows(o, "chain")[-1] and stale(o, ["chain:node-1"]) != []


BAD_IDS = [hid(root_hash="DROP", file_hash="DROP"), hid(root_hash=None, file_hash=None), hid(file_hash="F"),
           hid(root_hash=base64.b64encode(b"short").decode()), hid(seqno="50"), hid(seqno=True), hid(workchain="-1")]


@pytest.mark.parametrize("bad", BAD_IDS)
def test_an_incomplete_head_id_is_never_fresh_even_when_the_header_repeats_it(tmp_path, bad):
    rpc = FakeRpc()
    rpc.ident = lambda seq: dict(bad)
    rpc.head_hdr = {"id": dict(bad), "gen_utime": 1}
    o, _, _ = make(tmp_path, {h: rpc for h in obs.HOSTS})
    o.chain_round("node-1")
    assert "error" in rows(o, "chain")[-1] and stale(o, ["chain:node-1"]) != []


@pytest.mark.parametrize("bad", [b for b in BAD_IDS if b.get("seqno") == 50 and b.get("workchain") == -1])
def test_incomplete_ids_at_the_common_height_never_agree(tmp_path, bad):
    rpcs = {h: FakeRpc(100) for h in obs.HOSTS}
    o, _, _ = make(tmp_path, rpcs)
    all_heads(o)
    for r in rpcs.values():
        r.head_hdr = None
        r.call = lambda method, timeout=None, b=bad, **p: {"id": dict(b, seqno=p["seqno"]), "gen_utime": 1}
    o.ids_round()
    last = rows(o, "chain")[-1]
    assert last["agree"] is False and last["ids"] == {} and stale(o, ["ids:all"]) != []


def test_returning_to_a_height_after_a_regression_is_not_progress(tmp_path):
    rpc = FakeRpc(head=50)
    o, _, clocks = make(tmp_path, {h: rpc for h in obs.HOSTS})
    o.chain_round("node-1")
    clocks.tick(130)
    rpc.head = 49
    o.chain_round("node-1")
    rpc.head = 50
    o.chain_round("node-1")
    st = o.status()
    assert st["chain"]["node-1"]["head_age_s"] == 130 and st["stalled_hosts"] == ["node-1"]
    rpc.head = 51
    o.chain_round("node-1")
    assert o.status()["chain"]["node-1"]["head_age_s"] == 0


def test_stall_regression_and_identity_change(tmp_path):
    rpc = FakeRpc(head=50)
    o, _, clocks = make(tmp_path, {h: rpc for h in obs.HOSTS})
    o.chain_round("node-1")
    clocks.tick(100)
    rpc.file_hash = H("G")  # same height, different block
    o.chain_round("node-1")
    clocks.tick(30)
    rpc.head = 49
    o.chain_round("node-1")
    kinds = [r["kind"] for r in rows(o, "chain")]
    assert kinds == ["head", "identity_change", "head", "regression", "head"]
    st = o.status()
    assert st["chain"]["node-1"]["head_age_s"] == 130 and st["stalled_hosts"] == ["node-1"]
    rpc.head = 51
    o.chain_round("node-1")
    assert o.status()["chain"]["node-1"]["head_age_s"] == 0


def test_a_slow_head_round_records_a_cadence_miss(tmp_path):
    o, _, clocks = make(tmp_path)

    class Slow(FakeRpc):
        def call(self, method, timeout=None, **p):
            clocks.tick(3)
            return super().call(method, **p)
    o.rpcs["node-1"] = Slow()
    o.chain_round("node-1")
    assert [r["kind"] for r in rows(o, "chain")] == ["cadence_miss", "head"]


def all_heads(o):
    for h in obs.HOSTS:
        o.chain_round(h)


def test_ids_agree_on_the_full_id_at_a_common_height(tmp_path):
    rpcs = {"node-1": FakeRpc(50), "node-2": FakeRpc(48), "node-3": FakeRpc(51), "node-4": FakeRpc(50)}
    o, _, _ = make(tmp_path, rpcs)
    all_heads(o)
    o.ids_round()
    row = rows(o, "chain")[-1]
    assert row["seqno"] == 46 and row["agree"] is True and stale(o, ["ids:all"]) == []


def test_ids_reply_for_another_block_is_rejected(tmp_path):
    rpcs = {h: FakeRpc(100) for h in obs.HOSTS}
    o, _, _ = make(tmp_path, rpcs)
    all_heads(o)
    for r in rpcs.values():
        r.wrong_seq = 1
    o.ids_round()
    last = rows(o, "chain")[-1]
    assert last["agree"] is False and last["ids"] == {} and stale(o, ["ids:all"]) != []


def test_ids_need_all_four_replies(tmp_path):
    rpcs = {h: FakeRpc(50) for h in obs.HOSTS}
    o, _, _ = make(tmp_path, rpcs)
    all_heads(o)
    rpcs["node-4"].fail = {"getBlockHeader"}
    o.ids_round()
    last = rows(o, "chain")[-1]
    assert last["agree"] is False and sorted(last["ids"]) == ["node-1", "node-2", "node-3"]


def test_a_head_that_is_not_a_masterchain_block_is_an_error(tmp_path):
    rpc = FakeRpc()
    rpc.ident = lambda seq: hid(workchain=0, seqno=seq)
    o, _, _ = make(tmp_path, {h: rpc for h in obs.HOSTS})
    o.chain_round("node-1")
    assert "not a complete masterchain block id" in rows(o, "chain")[-1]["error"]


def test_the_clock_keeps_the_narrowest_try(tmp_path):
    o, ssh, clocks = make(tmp_path)
    real, widths = ssh.__call__, iter([3.0, 0.2, 1.0])

    def varied(argv, **kw):
        half = next(widths) / 2
        clocks.tick(half)
        r = real(argv, **kw)
        clocks.tick(half)
        return r
    o.run = varied
    row = o.clock_round(HOSTS[0])
    assert abs(row["best"]["bound"] - 0.1) < 1e-6 and row["verdict"] == "ok"  # float wall clock near 1.76e9


def test_ids_divergence_and_missing_heads(tmp_path):
    rpcs = {h: FakeRpc(50) for h in obs.HOSTS}
    rpcs["node-3"] = FakeRpc(50, ids={48: "other"})
    o, _, clocks = make(tmp_path, rpcs)
    all_heads(o)
    o.ids_round()
    assert rows(o, "chain")[-1]["agree"] is False
    clocks.tick(31)
    o.chain_round("node-1")
    o.ids_round()
    assert rows(o, "chain")[-1]["error"] == "only 1 of 4 fresh heads"


def test_rpc_refuses_methods_outside_the_allowlist():
    with pytest.raises(ValueError):
        obs.Rpc("http://127.0.0.1:9").call("sendMessage", boc="x")


# ---------------------------------------------------------------- health


def everything(o):
    for h in HOSTS:
        o.resources_round(h)
        o.du_round(h)
        o.clock_round(h)
        o.chain_round(h.name)
    o.ids_round()


def test_status_blind_reasons_and_recovery(tmp_path):
    o, ssh, clocks = make(tmp_path)
    for h in HOSTS:
        append(ssh.log(h.name), "x\n")
    everything(o)
    st = o.health_round()
    # After the baseline read, neither the cache nor the log coverage is proven yet.
    assert st["blind"] is True and sorted(st["reasons"]) == sorted(
        [f"cache:{h} stale (never > 180 s)" for h in obs.HOSTS] + [f"logs:{h} stale (never > 180 s)" for h in obs.HOSTS])
    clocks.tick(30)
    for h in HOSTS:
        append(ssh.log(h.name), payload_line(clocks.w))
    everything(o)
    st = o.health_round()
    assert st["blind"] is False and st["stalled_hosts"] == [] and set(st["baselined"].values()) == {T0}
    assert json.loads((o.out / "status.json").read_text())["blind"] is False
    clocks.tick(31)
    assert all(r.startswith("chain:") for r in o.health_round()["reasons"])


def test_freshness_ignores_wall_clock_steps(tmp_path):
    o, _, clocks = make(tmp_path)
    o.chain_round("node-1")
    clocks.w -= 3600
    clocks.m += 31
    assert stale(o, ["chain:node-1"]) == ["chain:node-1 stale (31 s > 30 s)"]


def test_never_seen_is_stale(tmp_path):
    o, _, _ = make(tmp_path)
    st = o.status()
    assert st["blind"] is True and len([r for r in st["reasons"] if "never" in r]) == 25


# ---------------------------------------------------------------- safety scan and the cache switch


MISBEHAVIOR = "[ 1][t 3][2025-11-10 18:40:05.1][pool.cpp:9][!simplex]\tMISBEHAVIOR DETECTED kind=equivocation slot=7\n"
CONFLICT = "[ 1][t 3][2025-11-10 18:40:06.1][x.cpp:1]\tvote conflicts with a decision already recorded slot=9\n"


def test_safety_lines_are_found_in_the_gap_checked_read_and_counted(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    append(ssh.log("node-1"), "ordinary\n" + MISBEHAVIOR + CONFLICT + "MISBEHAVIOR without the marker\n")
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    hits = rows(o, "safety")
    assert [h["line"] for h in hits] == [MISBEHAVIOR.rstrip("\n"), CONFLICT.rstrip("\n")]
    assert all(h["host"] == "node-1" and h["file"] == "node.log" for h in hits)
    assert o.status()["safety_hits"] == 2


def test_a_safety_line_before_the_baseline_is_not_reported(tmp_path):
    o, ssh, clocks = make(tmp_path)
    append(ssh.log("node-1"), MISBEHAVIOR)
    o.resources_round(HOSTS[0])
    assert rows(o, "safety") == [] and o.status()["safety_hits"] == 0


def test_a_safety_line_in_a_rotated_file_is_found_once(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    append(ssh.log("node-1"), MISBEHAVIOR)
    os.rename(ssh.log("node-1"), ssh.tmp / "node-1" / "node.log.old")
    append(ssh.log("node-1"), "fresh\n")
    for _ in range(2):
        clocks.tick(60)
        o.resources_round(HOSTS[0])
    assert len(rows(o, "safety")) == 1 and rows(o, "safety")[0]["file"] == "node.log.old"


def test_coverage_gaps_are_counted_in_the_status(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    with open(ssh.log("node-1"), "w") as fh:
        fh.write("")
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert o.status()["coverage_gaps"] == 1


def test_a_host_without_its_active_log_never_has_fresh_coverage(tmp_path):
    # bot review on #81: no log files at all must not count as a scanned log.
    o, ssh, clocks = make(tmp_path)
    o.resources_round(HOSTS[0])  # baseline with no files
    for _ in range(2):
        clocks.tick(60)
        o.resources_round(HOSTS[0])
    assert stale(o, ["logs:node-1"]) != []
    append(ssh.tmp / "node-1" / "node.log.thread3.log", "x\n")  # only a thread log, not the active one
    for _ in range(2):
        clocks.tick(60)
        o.resources_round(HOSTS[0])
    assert stale(o, ["logs:node-1"]) != []
    append(ssh.log("node-1"), "y\n")
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert stale(o, ["logs:node-1"]) == []


def test_logs_are_fresh_after_a_valid_read_without_cache_lines(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    assert stale(o, ["logs:node-1"]) != []  # the baseline read is not coverage
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert stale(o, ["logs:node-1"]) == [] and stale(o, ["cache:node-1"]) != []


def test_without_the_cache_series_the_run_is_not_blind_for_lack_of_cache_lines(tmp_path):
    (tmp_path / "hosts").mkdir()
    clocks = Clocks()
    ssh = FakeSsh(tmp_path / "hosts", clocks)
    o = obs.Observer(HOSTS, {h: FakeRpc() for h in obs.HOSTS}, tmp_path / "out", wall=clocks.wall,
                     mono=clocks.mono, run=ssh, cache_series=False)
    for h in HOSTS:
        append(ssh.log(h.name), "x\n")
    everything(o)
    clocks.tick(30)
    everything(o)
    st = o.health_round()
    assert st["blind"] is False and st["cache_series"] is False
    clocks.tick(200)  # the log reads lapse too: still blind on logs, whatever the cache switch says
    for h in HOSTS:
        o.chain_round(h.name)
    assert any(r.startswith("logs:") for r in o.status()["reasons"])


# ---------------------------------------------------------------- loops


def test_run_loops_writes_every_series_and_survives_a_failing_round(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "INTERVALS", {k: 0.05 for k in obs.INTERVALS})
    (tmp_path / "hosts").mkdir()
    ssh = FakeSsh(tmp_path / "hosts", Clocks())
    ssh.clocks.wall = time.time
    for h in HOSTS:
        append(ssh.log(h.name), "x\n")
    o = obs.Observer(HOSTS, {h: FakeRpc() for h in obs.HOSTS}, tmp_path / "out", run=ssh)
    calls = {"n": 0}
    real = o.ids_round

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real()
    o.ids_round = flaky
    obs.run_loops(o, 0.5)
    for name in ("resources", "cache", "du", "clock", "chain", "health"):
        assert (o.out / f"{name}.jsonl").stat().st_size > 0, name
    health = rows(o, "health")
    assert any(r.get("collector") == "ids" and "boom" in r["error"] for r in health) and calls["n"] > 1
    assert "blind" in json.loads((o.out / "status.json").read_text())


# ---------------------------------------------------------------- operator balances


class BalanceRpc(FakeRpc):
    def __init__(self, balances, fail=False):
        super().__init__()
        self.balances, self.down = balances, fail

    def call(self, method, timeout=None, **p):
        if method == "getAddressInformation":
            if self.down:
                raise ConnectionError("down")
            return {"balance": self.balances[p["address"]], "state": "active"}
        return super().call(method, timeout=timeout, **p)


OPS = {"node-1": "-1:" + "1" * 64, "node-2": "-1:" + "2" * 64}


def with_operators(tmp_path, rpcs):
    (tmp_path / "hosts").mkdir()
    clocks = Clocks()
    return obs.Observer(HOSTS, rpcs, tmp_path / "out", wall=clocks.wall, mono=clocks.mono,
                        run=FakeSsh(tmp_path / "hosts", clocks), operators=OPS), clocks


def test_operator_balances_are_recorded_and_low_ones_flagged(tmp_path):
    bal = {OPS["node-1"]: str(25 * 10**9), OPS["node-2"]: str(19 * 10**9)}
    o, _ = with_operators(tmp_path, {h: BalanceRpc(bal) for h in obs.HOSTS})
    o.fees_round()
    st = o.status()
    assert st["operators"]["node-1"]["balance_nano"] == 25 * 10**9 and st["operators_low"] == ["node-2"]
    assert stale(o, ["fees:node-1", "fees:node-2"]) == []
    assert all(len(r["answers"]) == 4 and r["disagree"] is False for r in rows(o, "fees"))


def test_a_lagging_source_cannot_hide_a_low_balance(tmp_path):
    # codex r1 §4: one source still shows 25 TOS, the others the current 19 TOS.
    low = {OPS["node-1"]: str(19 * 10**9), OPS["node-2"]: str(30 * 10**9)}
    stale_view = {OPS["node-1"]: str(25 * 10**9), OPS["node-2"]: str(30 * 10**9)}
    rpcs = {h: BalanceRpc(low) for h in obs.HOSTS}
    rpcs["node-1"] = BalanceRpc(stale_view)
    o, _ = with_operators(tmp_path, rpcs)
    o.fees_round()
    st = o.status()
    assert st["operators_low"] == ["node-1"] and st["operators"]["node-1"]["disagree"] is True
    assert st["operators"]["node-1"]["balance_nano"] == 19 * 10**9


def test_a_balance_needs_two_sources_and_all_failing_is_an_error_row(tmp_path):
    bal = {OPS["node-1"]: "30000000000", OPS["node-2"]: "30000000000"}
    rpcs = {h: BalanceRpc(bal, fail=True) for h in obs.HOSTS}
    rpcs["node-4"] = BalanceRpc(bal)
    o, _ = with_operators(tmp_path, rpcs)
    o.fees_round()
    assert all(r.get("error") == "only 1 sources answered" for r in rows(o, "fees"))
    assert o.status()["operators"] == {} and stale(o, ["fees:node-1"]) != []
    rpcs["node-3"].down = False
    o.fees_round()
    assert o.status()["operators"]["node-1"]["balance_nano"] == 30 * 10**9
    for r in rpcs.values():
        r.down = True
    o.fees_round()
    last = rows(o, "fees")[-2:]
    assert all(r["error"] == "only 0 sources answered" and len(r["errors"]) == 4 for r in last)


def test_alarm_counts_survive_an_observer_restart(tmp_path):
    # codex r1 §1: the restored cursors never re-read a consumed safety line or gap.
    o, ssh, clocks = baselined(tmp_path)
    append(ssh.log("node-1"), MISBEHAVIOR)
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    with open(ssh.log("node-1"), "w") as fh:
        fh.write("")
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert (o.status()["safety_hits"], o.status()["coverage_gaps"]) == (1, 1)
    o2 = obs.Observer(HOSTS, o.rpcs, o.out, wall=clocks.wall, mono=clocks.mono, run=ssh)
    assert (o2.status()["safety_hits"], o2.status()["coverage_gaps"]) == (1, 1)


def test_an_unreadable_alarm_row_refuses_the_start(tmp_path):
    o, ssh, clocks = baselined(tmp_path)
    with open(o.out / "safety.jsonl", "a") as fh:
        fh.write("{not json\n")
    with pytest.raises(obs.RefuseStart):
        obs.Observer(HOSTS, o.rpcs, o.out, wall=clocks.wall, mono=clocks.mono, run=ssh)


def test_a_read_backlog_keeps_the_logs_series_stale_until_caught_up(tmp_path, monkeypatch):
    # codex r1 §2: reading some bytes is not proof that the safety scan is current.
    o, ssh, clocks = baselined(tmp_path)
    monkeypatch.setattr(obs, "LOG_LAG_BYTES", 100)
    real_read = t1_probe.read_logs
    monkeypatch.setattr(t1_probe, "read_logs", lambda c, g, cap=200, safety=None: real_read(c, g, 200, safety))
    append(ssh.log("node-1"), ("y" * 80 + "\n") * 10 + MISBEHAVIOR)
    clocks.tick(60)
    o.resources_round(HOSTS[0])
    assert stale(o, ["logs:node-1"]) != [] and o.status()["log_behind"]["node-1"] > 100
    assert o.status()["safety_hits"] == 0
    for _ in range(10):
        clocks.tick(60)
        o.resources_round(HOSTS[0])
    assert stale(o, ["logs:node-1"]) == [] and o.status()["safety_hits"] == 1


@pytest.mark.parametrize("bad", [None, "-5", "1e9", "abc", 3.5])
def test_a_malformed_balance_is_never_a_reading(tmp_path, bad):
    bal = {OPS["node-1"]: bad, OPS["node-2"]: bad}
    o, _ = with_operators(tmp_path, {h: BalanceRpc(bal) for h in obs.HOSTS})
    o.fees_round()
    assert all("error" in r for r in rows(o, "fees")) and o.status()["operators"] == {}
    assert stale(o, ["fees:node-1"]) != []


def test_operator_freshness_is_part_of_blind(tmp_path):
    bal = {OPS["node-1"]: "30000000000", OPS["node-2"]: "30000000000"}
    o, clocks = with_operators(tmp_path, {h: BalanceRpc(bal) for h in obs.HOSTS})
    assert any(r.startswith("fees:node-1") for r in o.status()["reasons"])
    o.fees_round()
    assert not any(r.startswith("fees:") for r in o.status()["reasons"])
    clocks.tick(obs.FRESHNESS["fees"] + 1)
    assert any(r.startswith("fees:") for r in o.status()["reasons"])
