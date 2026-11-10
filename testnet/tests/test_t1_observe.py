"""Tests for t1_probe.py (runs on a validator host) and t1-observe.py (the coordinator collectors).

The diagnostics line below has the shape the validator logs (candidate-resolver.cpp, simplex-candidate-payloads);
everything else is a fake: no test reaches a host or a tunnel.
"""

import gzip
import importlib.util
import json
import os
import subprocess
from types import SimpleNamespace

import pytest
import t1_probe
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("t1_observe", SCRIPTS / "t1-observe.py")
obs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(obs)

T0 = 1_762_800_000  # 2025-11-10 18:40:00 UTC
STAMP0 = "2025-11-10 18:40:00"


def payload_line(stamp: str, charged: int = 1000, errors: int = 0) -> str:
    return (f"[ 2][t 4][{stamp}.123456789][candidate-resolver.cpp:966][!simplex]\tMEMORY_DIAGNOSTICS "
            f"simplex-candidate-payloads node_limit=536870912 node_charged_bytes={charged} "
            f"node_charged_peak={charged + 5} node_accounting_errors={errors} pinned_bytes=7 nondurable_bytes=0")


def stamp(offset: int) -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(T0 + offset))


# ---------------------------------------------------------------- probe: diagnostics parsing


def write_log(path, lines, mtime):
    path.write_text("".join(line + "\n" for line in lines))
    os.utime(path, (mtime, mtime))


def test_diag_parses_lines_after_since_only(tmp_path):
    write_log(tmp_path / "node.log", [
        payload_line(stamp(-10)),
        payload_line(stamp(0)),                # exactly at since: excluded
        payload_line(stamp(5), charged=2000),
        "[ 2][t 4][" + stamp(6) + ".1][x.cpp:1]\tsomething else node_limit=1",
    ], T0 + 10)
    lines, files = t1_probe.diag(T0, str(tmp_path / "node.log*"))
    assert [d["ts"] for d in lines] == [T0 + 5]
    assert lines[0]["kind"] == "simplex-candidate-payloads"
    assert lines[0]["fields"]["node_charged_bytes"] == 2000
    assert lines[0]["fields"]["node_limit"] == 536870912
    assert files == [{"file": str(tmp_path / "node.log"), "mtime": T0 + 10, "status": "read",
                      "bytes_read": (tmp_path / "node.log").stat().st_size, "truncated": False}]


def test_diag_reports_every_file_and_why_it_was_not_read(tmp_path):
    write_log(tmp_path / "node.log", [payload_line(stamp(5))], T0 + 10)
    write_log(tmp_path / "node.log.old", [payload_line(stamp(-500))], T0 - 400)
    with gzip.open(tmp_path / "node.log.1.gz", "wt") as fh:
        fh.write(payload_line(stamp(5)) + "\n")
    os.utime(tmp_path / "node.log.1.gz", (T0 + 10, T0 + 10))
    lines, files = t1_probe.diag(T0, str(tmp_path / "node.log*"))
    status = {os.path.basename(f["file"]): f["status"] for f in files}
    assert status == {"node.log": "read", "node.log.old": "skipped: not modified in the window",
                      "node.log.1.gz": "skipped: compressed (rotated before the window)"}
    assert len(lines) == 1


def test_diag_reads_only_the_tail_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(t1_probe, "TAIL_BYTES", 300)
    write_log(tmp_path / "node.log", [payload_line(stamp(i)) for i in range(1, 6)], T0 + 10)
    lines, files = t1_probe.diag(T0, str(tmp_path / "node.log*"))
    assert files[0]["truncated"] is True and files[0]["bytes_read"] == 300
    assert lines and lines[-1]["ts"] == T0 + 5 and len(lines) < 5


def test_diag_with_no_log_files_reports_no_files(tmp_path):
    assert t1_probe.diag(T0, str(tmp_path / "node.log*")) == ([], [])


def test_oom_kills_reads_vmstat(monkeypatch, tmp_path):
    vm = tmp_path / "vmstat"
    vm.write_text("nr_free_pages 5\noom_kill 3\n")
    real_open = open
    monkeypatch.setattr("builtins.open", lambda p, *a, **k: real_open(vm if p == "/proc/vmstat" else p, *a, **k))
    assert t1_probe.oom_kills() == 3
    vm.write_text("nr_free_pages 5\n")
    with pytest.raises(ValueError):
        t1_probe.oom_kills()


# ---------------------------------------------------------------- collector: probe call and parsing


HOSTS = [SimpleNamespace(name=n, address=f"192.0.2.{i}", ssh_user="root", ssh_key="", ssh_port=22)
         for i, n in enumerate(obs.HOSTS, 1)]


def report(diag=(), **over):
    r = {"unit": {"main_pid": 10, "n_restarts": 0, "active_state": "active"}, "proc": {"RssAnon": 1},
         "mem": {"MemAvailable": 2}, "oom_kill": 0, "boot_id": "b", "disks": {},
         "diag": diag if isinstance(diag, str) else list(diag),
         "diag_files": [], "clock": T0 + 1}
    r.update(over)
    return r


def fake_run(replies):
    """replies: host address -> stdout string, or an exception to raise."""
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))
        reply = replies[argv[-2].split("@")[1]]
        if isinstance(reply, BaseException):
            raise reply
        return subprocess.CompletedProcess(argv, 0, reply, "")
    run.calls = calls
    return run


@pytest.mark.parametrize("stdout,error", [
    ("", "no output (ssh rc 0)"),
    ("not json\n", "output is not JSON"),
    ('{"unit": "error: x"}\n', "output has no unit section"),
])
def test_probe_host_rejects_bad_output(stdout, error):
    assert obs.probe_host(HOSTS[0], T0, False, fake_run({"192.0.2.1": stdout})) == (None, error)


def test_probe_host_timeout_and_launch_failure():
    run = fake_run({"192.0.2.1": subprocess.TimeoutExpired("ssh", 90)})
    assert obs.probe_host(HOSTS[0], T0, False, run) == (None, "probe timeout")
    run = fake_run({"192.0.2.1": OSError("no ssh")})
    assert obs.probe_host(HOSTS[0], T0, False, run)[1].startswith("probe launch failed")


def test_probe_host_sends_the_probe_and_asks_du_only_when_told():
    run = fake_run({"192.0.2.1": json.dumps(report()) + "\n"})
    obs.probe_host(HOSTS[0], T0, False, run)
    obs.probe_host(HOSTS[0], T0, True, run)
    (a0, k0), (a1, k1) = run.calls
    assert "--du" not in a0[-1] and a1[-1].count("--du") == 2
    assert f"--diag-since {T0}" in a0[-1] and "BatchMode=yes" in a0
    assert k0["input"] == obs.PROBE.read_text()
    assert k0["timeout"] < k1["timeout"]


# ---------------------------------------------------------------- collector: resources and cache rounds


class Mem:
    def __init__(self):
        self.rows = []

    def write(self, r):
        self.rows.append(r)


def sinks():
    return {k: Mem() for k in ("resources", "cache", "chain", "health")}


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def diag_entry(offset, charged=1000):
    return {"ts": T0 + offset, "kind": "simplex-candidate-payloads", "file": "node.log",
            "fields": {"node_charged_bytes": charged}}


def test_resources_round_records_a_failed_host_and_keeps_the_others():
    replies = {h.address: json.dumps(report([diag_entry(1)])) for h in HOSTS}
    replies["192.0.2.2"] = ""
    s, clock = sinks(), Clock()
    fresh, state = obs.Freshness(clock), {}
    obs.resources_round(HOSTS, s, fresh, state, T0, fake_run(replies))
    assert [r["host"] for r in s["resources"].rows] == list(obs.HOSTS)
    bad = [r for r in s["resources"].rows if "error" in r]
    assert [r["host"] for r in bad] == ["node-2"]
    assert [r["host"] for r in s["cache"].rows if "error" in r] == ["node-2"]
    clock.t = T0 + 1
    stale = fresh.stale(obs.FRESHNESS, [f"resources:{h}" for h in obs.HOSTS] + [f"cache:{h}" for h in obs.HOSTS])
    assert stale == ["resources:node-2 stale (never > 180 s)", "cache:node-2 stale (never > 180 s)"]
    ok = s["resources"].rows[0]
    assert ok["oom_kill"] == 0 and ok["unit"]["main_pid"] == 10 and ok["clock"] is not None


def test_clock_offset_is_taken_at_the_call_midpoint_not_the_round_start():
    ticks = iter([T0 + 10, T0 + 14])  # the call itself ran 10 s into the round and took 4 s
    run = fake_run({"192.0.2.1": json.dumps(report(clock=T0 + 13))})
    rep, err = obs.probe_host(HOSTS[0], T0, False, run, clock=lambda: next(ticks))
    assert err is None and (rep["sent"], rep["received"]) == (T0 + 10, T0 + 14)
    assert obs.clock_offset(rep) == {"offset": 1, "bound": 2}
    assert obs.clock_offset(dict(rep, clock="error: x")) is None


def test_absent_diagnostics_never_make_the_cache_fresh():
    replies = {h.address: json.dumps(report([])) for h in HOSTS}
    s, fresh = sinks(), obs.Freshness(Clock())
    obs.resources_round(HOSTS, s, fresh, {}, T0, fake_run(replies))
    assert all(r["lines"] == [] for r in s["cache"].rows)
    assert len(fresh.stale(obs.FRESHNESS, [f"cache:{h}" for h in obs.HOSTS])) == 4
    assert fresh.stale(obs.FRESHNESS, [f"resources:{h}" for h in obs.HOSTS]) == []


def test_a_resolver_line_alone_does_not_count_as_cache_diagnostics():
    entry = dict(diag_entry(1), kind="simplex-candidate-resolver")
    replies = {h.address: json.dumps(report([entry])) for h in HOSTS}
    fresh = obs.Freshness(Clock())
    obs.resources_round(HOSTS, sinks(), fresh, {}, T0, fake_run(replies))
    assert len(fresh.stale(obs.FRESHNESS, [f"cache:{h}" for h in obs.HOSTS])) == 4


@pytest.mark.parametrize("diag", ["error: x", [{"ts": "1", "kind": "k", "fields": {}}], [7], [{"ts": 1, "kind": "k"}]])
def test_a_report_without_a_valid_diag_list_is_a_cache_error_on_every_host(diag):
    replies = {h.address: json.dumps(report(diag=diag)) for h in HOSTS}
    s, fresh = sinks(), obs.Freshness(Clock())
    obs.resources_round(HOSTS, s, fresh, {}, T0, fake_run(replies))
    assert [r.get("error") for r in s["cache"].rows] == ["probe returned no valid diag list"] * 4
    assert len(s["resources"].rows) == 4


def test_overlapping_reads_keep_each_line_once_and_lose_none():
    s, fresh, state = sinks(), obs.Freshness(Clock()), {}
    # Round 1 sees two lines in second +5; round 2 re-reads second +4.. and sees a third line logged in +5.
    first = [diag_entry(5, 1), diag_entry(5, 2)]
    second = first + [diag_entry(5, 3), diag_entry(6, 4)]
    one = [HOSTS[0]]
    obs.resources_round(one, s, fresh, state, T0, fake_run({"192.0.2.1": json.dumps(report(first))}))
    assert state["diag_since"]["node-1"] == T0 + 4
    run = fake_run({"192.0.2.1": json.dumps(report(second))})
    obs.resources_round(one, s, fresh, state, T0 + 60, run)
    assert f"--diag-since {T0 + 4}" in run.calls[0][0][-1]
    kept = [d["fields"]["node_charged_bytes"] for r in s["cache"].rows for d in r["lines"]]
    assert kept == [1, 2, 3, 4]
    assert len(state["diag_seen"]["node-1"]) == 4  # seconds +5 and +6 only
    # A later read that still returns the old seconds keeps only the last two seconds' keys.
    third = second + [diag_entry(70, 5), diag_entry(71, 6)]
    obs.resources_round(one, s, fresh, state, T0 + 120, fake_run({"192.0.2.1": json.dumps(report(third))}))
    assert [d["fields"]["node_charged_bytes"] for d in s["cache"].rows[-1]["lines"]] == [5, 6]
    assert len(state["diag_seen"]["node-1"]) == 2


def test_du_runs_on_the_first_and_every_tenth_round():
    replies = {"192.0.2.1": json.dumps(report())}
    run, state = fake_run(replies), {}
    for i in range(21):
        obs.resources_round([HOSTS[0]], sinks(), obs.Freshness(Clock()), state, T0 + 60 * i, run)
    with_du = [i for i, (argv, _) in enumerate(run.calls) if "--du" in argv[-1]]
    assert with_du == [0, 10, 20]


# ---------------------------------------------------------------- collector: chain


class FakeRpc:
    def __init__(self, head, ids=None, fail=()):
        self.head, self.ids, self.fail = head, ids or {}, set(fail)

    def call(self, method, **p):
        if method in self.fail:
            raise ConnectionError("down")
        if method == "getMasterchainInfo":
            return {"last": {"seqno": self.head, "root_hash": "R"}}
        seq = p["seqno"]
        return {"id": {"seqno": seq, "root_hash": self.ids.get(seq, "r"), "file_hash": "f"}, "gen_utime": 100 + seq}


def test_chain_round_records_heads_with_time_and_unreachable_observers_apart():
    rpcs = {"node-1": FakeRpc(50), "node-2": FakeRpc(49, fail={"getMasterchainInfo"}),
            "node-3": FakeRpc(51), "node-4": FakeRpc(50, fail={"getBlockHeader"})}
    s, fresh = sinks(), obs.Freshness(Clock())
    heads = obs.chain_round(rpcs, s, fresh, T0)
    assert heads == {"node-1": 50, "node-3": 51}
    rows = {r["host"]: r for r in s["chain"].rows}
    assert rows["node-1"]["gen_utime"] == 150 and rows["node-1"]["seqno"] == 50
    assert "error" in rows["node-2"] and "error" in rows["node-4"] and "seqno" not in rows["node-2"]
    assert fresh.stale(obs.FRESHNESS, [f"chain:{h}" for h in obs.HOSTS]) == [
        "chain:node-2 stale (never > 30 s)", "chain:node-4 stale (never > 30 s)"]


def test_ids_round_compares_one_common_height():
    rpcs = {h: FakeRpc(0) for h in obs.HOSTS}
    s, fresh = sinks(), obs.Freshness(Clock())
    obs.ids_round(rpcs, {"node-1": 50, "node-2": 48, "node-3": 51, "node-4": 50}, s, fresh, T0)
    row = s["chain"].rows[-1]
    assert row["seqno"] == 46 and row["agree"] is True and {v[0] for v in row["ids"].values()} == {46}
    assert fresh.stale(obs.FRESHNESS, ["ids:all"]) == []


def test_ids_round_divergence_is_recorded_and_not_fresh():
    rpcs = {h: FakeRpc(0) for h in obs.HOSTS}
    rpcs["node-3"] = FakeRpc(0, ids={46: "other"})
    s, fresh = sinks(), obs.Freshness(Clock())
    obs.ids_round(rpcs, {h: 48 for h in obs.HOSTS}, s, fresh, T0)
    assert s["chain"].rows[-1]["agree"] is False
    assert fresh.stale(obs.FRESHNESS, ["ids:all"]) != []


def test_ids_round_needs_all_four_heads_and_all_four_ids():
    rpcs = {h: FakeRpc(0) for h in obs.HOSTS}
    s, fresh = sinks(), obs.Freshness(Clock())
    obs.ids_round(rpcs, {"node-1": 50, "node-2": 50, "node-3": 50}, s, fresh, T0)
    assert s["chain"].rows == [{"ts": T0, "kind": "ids", "error": "only 3 of 4 heads"}]
    rpcs["node-4"] = FakeRpc(0, fail={"getBlockHeader"})
    obs.ids_round(rpcs, {h: 50 for h in obs.HOSTS}, s, fresh, T0)
    assert s["chain"].rows[-1]["agree"] is False and "node-4" not in s["chain"].rows[-1]["ids"]
    assert fresh.stale(obs.FRESHNESS, ["ids:all"]) != []


def test_rpc_refuses_methods_outside_the_allowlist():
    with pytest.raises(ValueError):
        obs.Rpc("http://127.0.0.1:9").call("sendMessage", boc="x")


# ---------------------------------------------------------------- health and status


def test_health_goes_blind_when_any_series_lapses_and_recovers(tmp_path):
    clock = Clock()
    fresh = obs.Freshness(clock)
    names = list(obs.HOSTS)
    for h in names:
        for k in ("resources", "cache", "chain"):
            fresh.good(f"{k}:{h}")
    fresh.good("ids:all")
    s = sinks()
    st = obs.health_round(fresh, names, s, tmp_path / "status.json", clock())
    assert st["blind"] is False and json.loads((tmp_path / "status.json").read_text())["blind"] is False
    clock.t += 31  # chain limit is 30 s
    st = obs.health_round(fresh, names, s, tmp_path / "status.json", clock())
    assert st["blind"] is True and len(st["reasons"]) == 4 and all(r.startswith("chain:") for r in st["reasons"])
    for h in names:
        fresh.good(f"chain:{h}")
    assert obs.health_round(fresh, names, s, tmp_path / "status.json", clock())["blind"] is False
    assert [r["blind"] for r in s["health"].rows] == [False, True, False]
    assert not (tmp_path / "status.tmp").exists()


def test_health_is_blind_before_anything_was_seen(tmp_path):
    st = obs.health_round(obs.Freshness(Clock()), list(obs.HOSTS), sinks(), tmp_path / "status.json", T0)
    assert st["blind"] is True and len(st["reasons"]) == 13


# ---------------------------------------------------------------- the loops


def test_run_loops_writes_every_series_and_survives_a_failing_round(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "INTERVALS", {"resources": 0.2, "chain": 0.05, "ids": 0.2, "health": 0.05})
    replies = {h.address: json.dumps(report([diag_entry(1)])) for h in HOSTS}
    rpcs = {h: FakeRpc(50) for h in obs.HOSTS}
    calls = {"n": 0}
    real = obs.chain_round

    def flaky(*a):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real(*a)

    monkeypatch.setattr(obs, "chain_round", flaky)
    import time
    obs.run_loops(HOSTS, rpcs, tmp_path / "run", time.time() + 0.6, run=fake_run(replies))
    out = tmp_path / "run"
    for name in ("resources", "cache", "chain", "health"):
        assert (out / f"{name}.jsonl").stat().st_size > 0, name
    health = [json.loads(x) for x in (out / "health.jsonl").read_text().splitlines()]
    assert any(r.get("collector") == "chain" and "boom" in r["error"] for r in health)
    assert calls["n"] > 1
    assert "blind" in json.loads((out / "status.json").read_text())
