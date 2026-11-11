"""The T1 judge on synthetic evidence: one green 72 h run, and the red controls of T1-PLAN §8, each of which must
make the verdict FAIL or INCONCLUSIVE (or refuse) as specified. Nothing reaches a host."""

import hashlib
import importlib.util
import json
import shutil

import pytest
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("t1_judge", SCRIPTS / "t1-judge.py")
tj = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tj)

T0 = 1_800_000_000.0
FIRST = T0 + 600  # the first pinned boundary
PERIOD = 7200
RATE = 0.01  # the synthetic declared rate (transfers/s), small enough to write 72 h of journal quickly
GiB = 1 << 30
H = "0" * 64

JUDGE = {"max_chain_gap_s": 60, "head_series_gap_s": 45, "resource_series_gap_s": 180, "divergence_s": 300,
         "rss_anon_max_bytes": 6 * GiB, "rss_growth_e2e_bytes": GiB // 2, "rss_growth_rolling_bytes": GiB // 2,
         "rolling_terms": 6, "mem_available_floor_bytes": 2 * GiB, "disk_free_floor_bytes": 20 * GiB,
         "disk_free_floor_inodes": 100000, "disk_bytes_per_block_max": 4096, "write_hourly_floor_fraction": 0.85,
         "backlog_max_actions": 1000, "max_cost_nano": 200 * 10**9, "operator_floor_nano": 20 * 10**9,
         "first_boundary": FIRST, "period": PERIOD}


def jsonl(path, items):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for r in items:
            fh.write(json.dumps(r) + "\n")


def build(root):
    obs, load = root / "observe", root / "load"
    end = T0 + tj.DURATION
    heads, ids = [], []
    for k, t in enumerate(range(int(T0), int(end) + 1, 20)):
        for h in tj.HOSTS:
            heads.append({"ts": float(t), "kind": "head", "host": h, "id": [-1, "x", 1000 + k, H, H], "gen_utime": t})
        if k % 3 == 0:
            ids.append({"ts": float(t), "kind": "ids", "agree": True})
    jsonl(obs / "chain.jsonl", heads + ids)
    res = []
    for k, t in enumerate(range(int(T0), int(end) + 1, 60)):
        for h in tj.HOSTS:
            res.append({"ts": float(t), "host": h, "complete": True, "boot_id": "b", "oom_kill": 0,
                        "unit": {"main_pid": 10, "n_restarts": 0, "active_state": "active"},
                        "proc": {"RssAnon": 2 * GiB + (k % 120) * 1000},
                        "mem": {"MemAvailable": 8 * GiB},
                        "disks": {p: {"free_bytes": 60 * GiB - k * 1000, "free_inodes": 5_000_000}
                                  for p in tj.DATA_PATHS}})
    jsonl(obs / "resources.jsonl", res)
    b, bounds = FIRST, []
    while b <= end:
        bounds.append({"boundary": b, "outcome": "checked", "collect_exit": 0, "verify_exit": 0, "keys_exit": 0,
                       "handover_report": {"result": "PASS"},
                       "keys_verdict": {"verdict": "PASS-FOUR-SIGNER-COVERAGE-PINNED-KEYS"}})
        b += PERIOD
    jsonl(obs / "boundaries.jsonl", bounds)
    jsonl(obs / "safety.jsonl", [])
    jsonl(obs / "cache.jsonl", [{"ts": T0 + 60, "kind": "read"}])
    jsonl(obs / "fees.jsonl", [{"ts": T0 + 600 * i, "operator": h, "balance_nano": 90 * 10**9}
                               for i in range(1, 400) for h in tj.HOSTS])
    jsonl(load / "load.jsonl", [{"ts": T0, "kind": "start"}, {"ts": end - 1000, "kind": "ramp_done"},
                                {"ts": end, "kind": "cutoff"}, {"ts": end, "kind": "end", "result": "cutoff"}])
    journal, t, n = [], T0 + 30, 0
    while t < end - 900:
        aid = f"a{n}"
        journal += [{"type": "attempt", "id": aid, "role": "transfer", "signed_at": t, "actions": [{}]},
                    {"type": "observed", "id": aid, "fee": 10**6, "failure": [None]},
                    {"type": "delivered", "id": aid, "action": 0, "recipient_utime": t + 5, "receipt_failure": None}]
        t += 1 / RATE
        n += 1
    jsonl(load / "ramp" / "journal.jsonl", journal)
    reads = load / "reads"
    reads.mkdir(parents=True)
    (reads / "CONTEXT.json").write_text(json.dumps({"packet": {"duration_seconds": tj.DURATION,
                                                               "window_seconds": 600}}))
    for i in range(tj.DURATION // 600):
        (reads / f"WINDOW-{i:04d}.json").write_text(json.dumps({"index": i, "pass": True}))
    (reads / "LATEST.json").write_text(json.dumps({"not_offered_capacity": 0}))


@pytest.fixture(scope="module")
def green_dir(tmp_path_factory):
    root = tmp_path_factory.mktemp("green")
    build(root)
    return root


@pytest.fixture()
def run(green_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(tj, "DECLARED_RATE", RATE)
    root = tmp_path / "ev"
    shutil.copytree(green_dir, root)

    def judge():
        return tj.verdict(JUDGE, root / "observe", root / "load")
    judge.root = root
    return judge


def edit(path, fn):
    rows = [json.loads(x) for x in path.read_text().splitlines() if x]
    jsonl(path, fn(rows))


def bad(v):
    return {k: c["status"] for k, c in v["criteria"].items() if c["status"] != "PASS"}


def test_the_green_run_passes(run):
    v = run()
    assert v["verdict"] == "PASS", bad(v)


# ---------------------------------------------------------------- the red controls of T1-PLAN §8


def test_zero_successful_writes_fail(run):
    edit(run.root / "load/ramp/journal.jsonl", lambda rs: [r for r in rs if r["type"] != "delivered"])
    v = run()
    assert v["verdict"] == "FAIL" and v["criteria"]["5.7 writes"]["status"] == "FAIL"


def test_under_offered_reads_fail(run):
    (run.root / "load/reads/WINDOW-0100.json").write_text(json.dumps({"index": 100, "pass": False}))
    v = run()
    assert v["verdict"] == "FAIL" and v["criteria"]["5.6 reads"]["status"] == "FAIL"


def test_a_missing_collector_interval_is_inconclusive(run):
    lo, hi = T0 + 30_000, T0 + 30_000 + 3600
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [r for r in rs if not (r["host"] == "node-2" and lo <= r["ts"] <= hi)])
    v = run()
    assert v["verdict"] == "INCONCLUSIVE" and v["criteria"]["5.2 no restart, OOM or divergence"]["status"] == \
        "INCONCLUSIVE"


def test_a_stopped_write_hour_fails_even_when_monitoring_recovered(run):
    lo, hi = T0 + 10 * 3600, T0 + 11 * 3600
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [r for r in rs if not (r["type"] == "delivered" and lo <= r["recipient_utime"] < hi)])
    v = run()
    assert v["verdict"] == "FAIL" and v["criteria"]["5.7 writes"]["short_hours"]


def test_a_record_missing_a_threshold_refuses(tmp_path):
    rec = {"judge": {k: v for k, v in JUDGE.items() if k != "disk_bytes_per_block_max"}}
    p = tmp_path / "r.json"
    p.write_text(json.dumps(rec))
    with pytest.raises(tj.Refuse, match="disk_bytes_per_block_max"):
        tj.load_record(p, hashlib.sha256(p.read_bytes()).hexdigest())


def test_a_restart_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, unit=dict(r["unit"], n_restarts=1)) if r["host"] == "node-3" and r["ts"] > T0 + 50_000
                     else r for r in rs])
    assert run()["criteria"]["5.2 no restart, OOM or divergence"]["status"] == "FAIL"


def test_an_oom_kill_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, oom_kill=1) if r["host"] == "node-1" and r["ts"] > T0 + 90_000 else r for r in rs])
    assert run()["verdict"] == "FAIL"


def test_an_unknown_send_across_a_runner_restart_is_unresolved(run):
    edit(run.root / "load/ramp/journal.jsonl", lambda rs: rs + [
        {"type": "attempt", "id": "lost", "role": "transfer", "signed_at": T0 + 1000, "actions": [{}]},
        {"type": "unknown", "id": "lost", "reason": "runner restarted"}])
    v = run()
    assert v["verdict"] == "FAIL" and v["criteria"]["5.7 writes"]["unresolved_actions"] == 1


def test_a_stall_fails(run):
    lo, hi = T0 + 40_000, T0 + 40_090
    edit(run.root / "observe/chain.jsonl",
         lambda rs: [r for r in rs if not (r.get("kind") == "head" and lo < r["ts"] < hi)])
    v = run()
    assert v["criteria"]["5.1 no stall"]["status"] == "FAIL"


def test_memory_growth_over_the_bound_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, proc={"RssAnon": r["proc"]["RssAnon"] + int((r["ts"] - T0) * 4000)})
                     if r["host"] == "node-4" else r for r in rs])
    v = run()
    assert v["criteria"]["5.3 bounded memory"]["status"] == "FAIL"


def test_a_safety_line_fails(run):
    jsonl(run.root / "observe/safety.jsonl", [{"ts": T0 + 5000, "kind": "safety_line", "line": "MISBEHAVIOR"}])
    assert run()["criteria"]["5.5 no safety line"]["status"] == "FAIL"


# ---------------------------------------------------------------- further controls


def test_a_bounced_delivery_is_not_delivered(run):
    lo, hi = T0 + 20 * 3600, T0 + 21 * 3600
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [dict(r, receipt_failure="bounced") if r["type"] == "delivered" and lo <= r["recipient_utime"] < hi
                     else r for r in rs])
    assert run()["criteria"]["5.7 writes"]["status"] == "FAIL"


def test_funding_does_not_count_as_load(run):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [dict(r, role="fund") if r["type"] == "attempt" else r for r in rs])
    assert run()["criteria"]["5.7 writes"]["status"] == "FAIL"


def test_a_missed_boundary_is_inconclusive_and_a_failed_one_fails(run):
    edit(run.root / "observe/boundaries.jsonl",
         lambda rs: [dict(r, outcome="missed") if r["boundary"] == FIRST + 3 * PERIOD else r for r in rs])
    assert run()["criteria"]["5.1 handovers and key gate"]["status"] == "INCONCLUSIVE"
    edit(run.root / "observe/boundaries.jsonl",
         lambda rs: [dict(r, outcome="checked", keys_exit=1) if r["boundary"] == FIRST + 4 * PERIOD else r
                     for r in rs])
    assert run()["criteria"]["5.1 handovers and key gate"]["status"] == "FAIL"


def test_a_coverage_gap_makes_safety_inconclusive(run):
    jsonl(run.root / "observe/cache.jsonl", [{"ts": T0 + 100, "kind": "coverage_gap", "reason": "vanished"}])
    assert run()["criteria"]["5.5 no safety line"]["status"] == "INCONCLUSIVE"


def test_a_disk_below_its_floor_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, disks={**r["disks"], "/var/log/tos": {"free_bytes": GiB, "free_inodes": 5_000_000}})
                     if r["host"] == "node-2" and r["ts"] > T0 + 1000 else r for r in rs])
    assert run()["criteria"]["5.4 bounded disk"]["status"] == "FAIL"


def test_disk_growth_over_the_per_block_bound_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, disks={p: dict(d, free_bytes=d["free_bytes"] - int((r["ts"] - T0) * 1000))
                                    for p, d in r["disks"].items()}) for r in rs])
    assert run()["criteria"]["5.4 bounded disk"]["status"] == "FAIL"


def test_an_operator_below_the_floor_fails(run):
    edit(run.root / "observe/fees.jsonl", lambda rs: rs + [{"ts": T0 + 7000, "operator": "node-3",
                                                             "balance_nano": 5 * 10**9}])
    assert run()["criteria"]["5.8 operators"]["status"] == "FAIL"


def test_a_persistent_divergence_fails(run):
    edit(run.root / "observe/chain.jsonl",
         lambda rs: [dict(r, agree=False) if r.get("kind") == "ids" and T0 + 9000 <= r["ts"] <= T0 + 9400 else r
                     for r in rs])
    assert run()["criteria"]["5.2 no restart, OOM or divergence"]["status"] == "FAIL"


def test_a_stopped_run_fails(run):
    edit(run.root / "load/load.jsonl", lambda rs: [rs[0], {"ts": T0 + 100, "kind": "stop", "reasons": ["blind"]},
                                                   *rs[1:]])
    assert run()["criteria"]["run completed"]["status"] == "FAIL" and run()["verdict"] == "FAIL"


def test_a_run_without_a_clean_end_is_inconclusive(run):
    edit(run.root / "load/load.jsonl", lambda rs: [rs[0]])
    assert run()["criteria"]["run completed"]["status"] == "INCONCLUSIVE"


def test_a_run_that_never_started_refuses(run):
    (run.root / "load/load.jsonl").write_text("")
    with pytest.raises(tj.Refuse, match="never started"):
        run()


def test_a_torn_last_journal_line_is_dropped_and_other_bad_lines_are_errors(tmp_path):
    p = tmp_path / "j.jsonl"
    p.write_text('{"a": 1}\n{"b": 2')
    assert tj.rows(p) == [{"a": 1}]
    p.write_text('{"a": 1}\nnot json\n{"b": 2}\n')
    with pytest.raises(ValueError):
        tj.rows(p)
