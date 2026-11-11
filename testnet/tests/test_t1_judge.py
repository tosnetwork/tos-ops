"""The T1 judge on synthetic evidence: one green 72 h run, and the red controls of T1-PLAN §8 plus codex r1's
false-PASS reproductions, each of which must make the verdict FAIL or INCONCLUSIVE (or refuse). Nothing reaches a
host. Rates are scaled down (writes 0.01/s, reads 0.01/s) so that 72 h of evidence stays small."""

import hashlib
import importlib.util
import json
import shutil

import pytest
import t1_fixture
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("t1_judge", SCRIPTS / "t1-judge.py")
tj = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tj)

T0 = 1_800_000_000.0
FIRST = T0 + 600  # the first pinned boundary
PERIOD = 7200
RATE = 0.01  # synthetic declared write rate (transfers/s)
READ = 0.01  # synthetic scheduled read rate (requests/s): 6 per 10-min window
GiB = 1 << 30
H = "0" * 64
END = T0 + 259_200

JUDGE = {"max_chain_gap_s": 60, "head_series_gap_s": 45, "ids_series_gap_s": 180, "resource_series_gap_s": 180,
         "logs_series_gap_s": 180, "clock_series_gap_s": 7500, "fees_series_gap_s": 1800, "divergence_s": 300,
         "rss_anon_max_bytes": 6 * GiB, "rss_growth_e2e_bytes": GiB // 2, "rss_growth_rolling_bytes": GiB // 2,
         "rolling_terms": 6, "phases_per_term": 8, "mem_available_floor_bytes": 2 * GiB,
         "disk_free_floor_bytes": 20 * GiB, "disk_free_floor_inodes": 100000, "disk_bytes_per_block_max": 4096,
         "read_window_s": 600, "read_deadline_s": 3, "read_completed_fraction": 0.9, "read_error_fraction_max": 0.01,
         "write_start_max_s": 7200, "write_end_slack_s": 3600, "write_hourly_floor_fraction": 0.85,
         "backlog_max_actions": 50, "max_cost_nano": 200 * 10**9, "operator_floor_nano": 20 * 10**9,
         "first_boundary": FIRST, "period": PERIOD,
         "operators": {h: f"-1:{i:064x}" for i, h in enumerate(tj.HOSTS, 1)}}
ENDPOINTS = [f"http://127.0.0.1:{p}/jsonRPC" for p in (18081, 38081, 28081, 48084)]


def jsonl(path, items):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for r in items:
            fh.write(json.dumps(r) + "\n")


def full_id(seq, root="R" * 43 + "="):
    return t1_fixture.head_id(seq, root)


OPERATORS = JUDGE["operators"]


def build(root):
    return t1_fixture.build(root, t0=T0, duration=tj.DURATION, first_boundary=FIRST, period=PERIOD, write_rate=RATE,
                            read_rate=READ, endpoints=ENDPOINTS, operators=OPERATORS)


def reseal(root):
    """After a test edits requests.jsonl, make RESULT.json describe it again (as the producer would), so that the
    test exercises the read criterion itself rather than the integrity check."""
    reads = root / "load" / "reads"
    data = (reads / "requests.jsonl").read_bytes()
    rows = [json.loads(x) for x in data.splitlines() if x.strip()]
    res = json.loads((reads / "RESULT.json").read_text())
    res.update(requests_sha256=hashlib.sha256(data).hexdigest(), completed=len(rows),
               errors=sum(1 for r in rows if r.get("error") is not None))
    (reads / "RESULT.json").write_text(json.dumps(res))


@pytest.fixture(scope="module")
def green_dir(tmp_path_factory):
    root = tmp_path_factory.mktemp("green")
    build(root)
    return root


@pytest.fixture()
def run(green_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(tj, "DECLARED_RATE", RATE)
    monkeypatch.setattr(tj, "READ_RATE", READ)
    root = tmp_path / "ev"
    shutil.copytree(green_dir, root)

    def judge(judge_rec=None):
        return tj.verdict(judge_rec or JUDGE, root / "observe", root / "load")
    judge.root = root
    return judge


def edit(path, fn):
    rows = [json.loads(x) for x in path.read_text().splitlines() if x]
    jsonl(path, fn(rows))


def bad(v):
    return {k: c["status"] for k, c in v["criteria"].items() if c["status"] != "PASS"}


def status(run, name):
    return run()["criteria"][name]["status"]


def test_the_green_run_passes(run):
    v = run()
    assert v["verdict"] == "PASS", bad(v)


# ---------------------------------------------------------------- the red controls of T1-PLAN §8


def test_zero_successful_writes_fail(run):
    edit(run.root / "load/ramp/journal.jsonl", lambda rs: [r for r in rs if r["type"] != "delivered"])
    assert run()["verdict"] == "FAIL" and status(run, "5.7 writes") == "FAIL"


def test_under_offered_reads_fail(run):
    edit(run.root / "load/reads/requests.jsonl",
         lambda rs: [r for r in rs if not 100 * 600 <= r["offered_monotonic_seconds"] < 101 * 600 or
                     r["offered_monotonic_seconds"] % 600 < 100])
    assert status(run, "5.6 reads") == "FAIL"


def test_a_missing_collector_interval_is_inconclusive(run):
    lo, hi = T0 + 30_000, T0 + 30_000 + 3600
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [r for r in rs if not (r["host"] == "node-2" and lo <= r["ts"] <= hi)])
    v = run()
    assert v["verdict"] == "INCONCLUSIVE" and v["criteria"]["5.2 no restart, OOM or divergence"]["status"] == \
        "INCONCLUSIVE"


def test_a_stopped_write_hour_fails_even_when_monitoring_recovered(run):
    lo, hi = T0 + 10 * 3600, T0 + 11 * 3600
    gone = set()

    def drop(rs):
        for r in rs:
            if r["type"] == "attempt" and lo <= r["signed_at"] < hi:
                gone.add(r["id"])
        return [r for r in rs if r.get("id") not in gone]
    edit(run.root / "load/ramp/journal.jsonl", drop)
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "FAIL" and w["short_hours"] and w["unresolved_actions"] == 0


def test_a_record_missing_a_threshold_refuses(tmp_path):
    for missing in ("disk_bytes_per_block_max", "operators", "read_deadline_s"):
        rec = {"judge": {k: v for k, v in JUDGE.items() if k != missing}}
        p = tmp_path / "r.json"
        p.write_text(json.dumps(rec))
        with pytest.raises(tj.Refuse, match=missing):
            tj.load_record(p, hashlib.sha256(p.read_bytes()).hexdigest())


def test_a_restart_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, unit=dict(r["unit"], n_restarts=1)) if r["host"] == "node-3" and r["ts"] > T0 + 50_000
                     else r for r in rs])
    assert status(run, "5.2 no restart, OOM or divergence") == "FAIL"


def test_an_oom_kill_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, oom_kill=1) if r["host"] == "node-1" and r["ts"] > T0 + 90_000 else r for r in rs])
    assert run()["verdict"] == "FAIL"


def test_an_unknown_send_across_a_runner_restart_is_unresolved(run):
    # an attempt journaled and sent with an ambiguous reply, then never observed (the runner restarted)
    def lost(rs):
        a = dict(next(r for r in rs if r["type"] == "attempt" and r["role"] == "transfer"), id="transfer:7:99999")
        return rs + [a, {"type": "sent", "id": a["id"], "time": a["time"] + 1, "state": "ambiguous",
                         "reason": "no answer: TimeoutError"}]
    edit(run.root / "load/ramp/journal.jsonl", lost)
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "FAIL" and w["unresolved_actions"] == 1


def test_a_stall_fails(run):
    lo, hi = T0 + 40_000, T0 + 40_090
    edit(run.root / "observe/chain.jsonl",
         lambda rs: [r for r in rs if not (r.get("kind") == "head" and lo < r["ts"] < hi)])
    assert status(run, "5.1 no stall") == "FAIL"


def test_memory_growth_over_the_bound_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, proc=dict(r["proc"], RssAnon=r["proc"]["RssAnon"] + int((r["ts"] - T0) * 4000)))
                     if r["host"] == "node-4" else r for r in rs])
    assert status(run, "5.3 bounded memory") == "FAIL"


def test_a_safety_line_fails(run):
    jsonl(run.root / "observe/safety.jsonl", [{"ts": T0 + 5000, "host": "node-2", "sent": T0 + 4999,
                                                "received": T0 + 5000, "kind": "safety_line",
                                                "file": "node.log", "line": "MISBEHAVIOR"}])
    assert status(run, "5.5 no safety line") == "FAIL"


# ---------------------------------------------------------------- codex r1: each false PASS is now caught


def test_one_surviving_transfer_does_not_shrink_the_write_window(run):
    edit(run.root / "load/ramp/journal.jsonl", lambda rs: [r for r in rs if r.get("id") == "transfer:5:0"])
    assert status(run, "5.7 writes") == "FAIL"


def test_a_backlog_over_its_bound_fails_even_if_it_drains(run):
    # deliveries 5400 s late: about 54 undelivered actions are outstanding, over the bound of 50. The last two
    # hours are not delayed, so every receipt still lands before the cutoff and nothing stays unresolved.
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [dict(r, recipient_utime=r["recipient_utime"] + 5400)
                     if r["type"] == "delivered" and r["recipient_utime"] < END - 7200 else r for r in rs])
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "FAIL" and w["backlog_peak"] > 50 and not w["short_hours"] \
        and not w["unresolved_actions"] and not w["conflicting_receipts"]


def test_fabricated_read_windows_do_not_pass(run):
    reads = run.root / "load/reads"
    (reads / "requests.jsonl").write_text("")
    for p in reads.glob("WINDOW-*.json"):
        p.unlink()
    (reads / "WINDOW-0999.json").write_text(json.dumps({"index": 999, "pass": True, "completed": 0}))
    assert status(run, "5.6 reads") == "FAIL"


def test_a_read_packet_that_does_not_match_the_schedule_is_inconclusive(run):
    ctx = run.root / "load/reads/CONTEXT.json"
    c = json.loads(ctx.read_text())
    c["packet"]["duration_seconds"] = 600
    ctx.write_text(json.dumps(c))
    assert status(run, "5.6 reads") == "INCONCLUSIVE"


def test_read_coverage_needs_every_endpoint_and_method(run):
    edit(run.root / "load/reads/requests.jsonl",
         lambda rs: [dict(r, endpoint=ENDPOINTS[0]) if 50 * 600 <= r["offered_monotonic_seconds"] < 51 * 600 else r
                     for r in rs])
    assert status(run, "5.6 reads") == "FAIL"


def test_a_missing_final_read_status_is_inconclusive(run):
    (run.root / "load/reads/RESULT.json").unlink()
    assert status(run, "5.6 reads") == "INCONCLUSIVE"


def test_missing_safety_and_coverage_files_are_not_a_pass(run):
    (run.root / "observe/cache.jsonl").unlink()
    assert status(run, "5.5 no safety line") == "INCONCLUSIVE"


def test_missing_common_height_ids_are_not_a_pass(run):
    edit(run.root / "observe/chain.jsonl", lambda rs: [r for r in rs if r.get("kind") != "ids"])
    assert status(run, "5.2 no restart, OOM or divergence") == "INCONCLUSIVE"


def test_a_stored_agree_flag_is_not_trusted(run):
    edit(run.root / "observe/chain.jsonl",
         lambda rs: [dict(r, ids={**r["ids"], "node-3": full_id(r["seqno"], root="Q" * 43 + "=")})
                     if r.get("kind") == "ids" and T0 + 9000 <= r["ts"] <= T0 + 9400 else r for r in rs])
    assert status(run, "5.2 no restart, OOM or divergence") == "FAIL"


def test_missing_clock_verdicts_are_inconclusive(run):
    (run.root / "observe/clock.jsonl").unlink()
    assert status(run, "collector clock") == "INCONCLUSIVE"


def test_a_host_without_regular_ok_clock_verdicts_is_inconclusive(run):
    # valid rows, so only the coverage rule can catch it: node-3 has no ok verdict after the first day
    edit(run.root / "observe/clock.jsonl",
         lambda rs: [r for r in rs if not (r["host"] == "node-3" and r["ts"] > T0 + 86_400)])
    c = run()["criteria"]["collector clock"]
    assert c["status"] == "INCONCLUSIVE" and "contract_violations" not in c


def test_one_operator_reading_is_not_coverage(run):
    # valid producer rows for node-1 only: the other operators have no readings
    edit(run.root / "observe/fees.jsonl", lambda rs: [r for r in rs if r["operator"] == "node-1"][:1])
    c = run()["criteria"]["5.8 operators"]
    assert c["status"] == "INCONCLUSIVE" and "contract_violations" not in c


def test_growth_at_the_same_session_phase_fails_although_term_medians_barely_move(run):
    # codex r1: memory grows in the last quarter of every term, more each term; the term medians hardly change.
    def grow(r):
        off = r["ts"] - FIRST
        term, pos = int(off // PERIOD), (off % PERIOD) / PERIOD
        if r["host"] == "node-2" and pos >= 0.75 and term >= 0:
            return dict(r, proc=dict(r["proc"], RssAnon=r["proc"]["RssAnon"] + term * 60 * (1 << 20)))
        return r
    edit(run.root / "observe/resources.jsonl", lambda rs: [grow(r) for r in rs])
    assert status(run, "5.3 bounded memory") == "FAIL"


def test_an_unobserved_term_phase_is_inconclusive(run):
    lo = FIRST + 10 * PERIOD + 2 * 900
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [r for r in rs if not (r["host"] == "node-1" and lo <= r["ts"] < lo + 900)])
    assert status(run, "5.3 bounded memory") == "INCONCLUSIVE"


@pytest.mark.parametrize("change", [
    {"action": -1}, {"action": 1}, {"action": "0"}, {"receipt_failure": "bounced"}, {"recipient_tx": None},
    {"recipient_utime": None},
])
def test_an_invalid_delivery_does_not_count(run, change):
    edit(run.root / "load/ramp/journal.jsonl", lambda rs: [dict(r, **change) if r["type"] == "delivered" else r
                                                           for r in rs])
    # the backlog bound is lifted so that the delivery validation itself is what fails
    w = run(dict(JUDGE, backlog_max_actions=10**9))["criteria"]["5.7 writes"]
    assert w["status"] == "FAIL" and w["delivered"] == 0


def test_a_late_first_transfer_fails_with_no_hour_short(run):
    w0 = T0 + JUDGE["write_start_max_s"]
    gone = set()

    def drop(rs):
        for r in rs:
            if r["type"] == "attempt" and r["signed_at"] < w0 + 100:
                gone.add(r["id"])
        return [r for r in rs if r.get("id") not in gone]
    edit(run.root / "load/ramp/journal.jsonl", drop)
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "FAIL" and w["first_signed_late"] and not w["short_hours"]


def test_an_early_last_transfer_fails_with_no_hour_short(run):
    # Signing stops 100 s before the window's end: every hour still meets its floor, so only the end check
    # can fail this run.
    w1 = END - JUDGE["write_end_slack_s"]
    gone = set()

    def drop(rs):
        for r in rs:
            if r["type"] == "attempt" and r["signed_at"] >= w1 - 100:
                gone.add(r["id"])
        return [r for r in rs if r.get("id") not in gone]
    edit(run.root / "load/ramp/journal.jsonl", drop)
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "FAIL" and w["last_signed_early"] and not w["short_hours"] \
        and not w["first_signed_late"] and not w["unresolved_actions"]


def test_one_head_series_with_a_gap_is_inconclusive_while_the_chain_advances(run):
    lo, hi = T0 + 40_000, T0 + 40_050
    edit(run.root / "observe/chain.jsonl",
         lambda rs: [r for r in rs if not (r.get("kind") == "head" and r["host"] == "node-2" and lo < r["ts"] < hi)])
    assert status(run, "5.1 no stall") == "INCONCLUSIVE"


def test_a_window_one_request_short_fails_with_full_coverage(run):
    edit(run.root / "load/reads/requests.jsonl",
         lambda rs: [r for r in rs if r["offered_monotonic_seconds"] != 70 * 600 + 500])
    assert status(run, "5.6 reads") == "FAIL"


def test_a_delivery_without_a_receipt_failure_field_does_not_count(run):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [{k: v for k, v in r.items() if k != "receipt_failure"} if r["type"] == "delivered" else r
                     for r in rs])
    assert status(run, "5.7 writes") == "FAIL"


def test_conflicting_receipts_fail(run):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: rs + [dict(next(r for r in rs if r["type"] == "delivered" and r["id"] == "transfer:5:0"),
                               recipient_tx="ff" * 32)])
    assert status(run, "5.7 writes") == "FAIL"


def test_an_end_row_without_a_clean_cutoff_is_not_a_pass(run):
    edit(run.root / "load/load.jsonl", lambda rs: [dict(r, result="stop") if r["kind"] == "end" else r for r in rs])
    assert status(run, "run completed") == "INCONCLUSIVE"


def test_an_unconfirmed_termination_is_not_a_pass(run):
    edit(run.root / "load/load.jsonl",
         lambda rs: [dict(r, children={"ramp": {"rc": 0, "group_alive": True},
                                       "reads": {"rc": 0, "group_alive": False}})
                     if r["kind"] == "terminated" else r for r in rs])
    c = run()["criteria"]["run completed"]
    assert c["status"] == "INCONCLUSIVE" and c["problems"] == \
        ["termination of both children (ramp and reads) is not confirmed"]


def test_a_cutoff_before_the_full_duration_is_not_a_pass(run):
    # ramp_done moves earlier too, so the lifecycle stays in order and only the duration check can catch it
    edit(run.root / "load/load.jsonl",
         lambda rs: [dict(r, ts=END - 7200) if r["kind"] == "cutoff" else
                     dict(r, ts=END - 8000) if r["kind"] == "ramp_done" else r for r in rs])
    c = run()["criteria"]["run completed"]
    assert c["status"] == "INCONCLUSIVE" and c["problems"] == ["no single cutoff row at the full duration"]


# ---------------------------------------------------------------- further controls


def test_funding_does_not_count_as_load(run):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [dict(r, role="fund") if r["type"] == "attempt" else r for r in rs])
    assert status(run, "5.7 writes") == "FAIL"


def test_a_late_first_or_early_last_transfer_fails(run):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [r for r in rs if not (r["type"] == "attempt" and r["signed_at"] > END - 3 * 3600)])
    assert status(run, "5.7 writes") == "FAIL"


def test_a_missed_boundary_is_inconclusive_and_a_failed_one_fails(run):
    edit(run.root / "observe/boundaries.jsonl",
         lambda rs: [{"ts": r["ts"], "boundary": r["boundary"], "outcome": "missed", "reason": "no slot"}
                     if r["boundary"] == FIRST + 3 * PERIOD else r for r in rs])
    b = run()["criteria"]["5.1 handovers and key gate"]
    assert b["status"] == "INCONCLUSIVE" and b["unchecked"] == [FIRST + 3 * PERIOD] and "contract_violations" not in b
    edit(run.root / "observe/boundaries.jsonl",
         lambda rs: [dict(r, outcome="checked", keys_exit=1) if r["boundary"] == FIRST + 4 * PERIOD else r
                     for r in rs])
    assert status(run, "5.1 handovers and key gate") == "FAIL"


def test_a_coverage_gap_makes_safety_inconclusive(run):
    edit(run.root / "observe/cache.jsonl", lambda rs: rs + [{"ts": T0 + 100, "host": "node-1", "sent": T0 + 99,
                                                             "received": T0 + 100, "kind": "coverage_gap",
                                                             "id": "1:2", "name": "node.log", "reason": "shrunk",
                                                             "bytes": 4096}])
    assert status(run, "5.5 no safety line") == "INCONCLUSIVE"


def test_a_disk_constantly_below_its_floor_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, disks={p: dict(d, free_bytes=10 * GiB) for p, d in r["disks"].items()})
                     if r["host"] == "node-2" else r for r in rs])
    assert status(run, "5.4 bounded disk") == "FAIL"


def test_disk_growth_over_the_per_block_bound_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, disks={p: dict(d, free_bytes=d["free_bytes"] - int((r["ts"] - T0) * 1000))
                                    for p, d in r["disks"].items()}) for r in rs])
    assert status(run, "5.4 bounded disk") == "FAIL"


def test_an_operator_below_the_floor_fails(run):
    edit(run.root / "observe/fees.jsonl", lambda rs: rs + [dict(next(r for r in rs if r["operator"] == "node-3"),
                                                                  ts=T0 + 7000, balance_nano=5 * 10**9,
                                                                  answers={h: 5 * 10**9 for h in tj.HOSTS})])
    assert status(run, "5.8 operators") == "FAIL"


def test_a_constant_rss_above_the_absolute_bound_fails(run):
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, proc=dict(r["proc"], RssAnon=7 * GiB)) if r["host"] == "node-1" else r for r in rs])
    assert status(run, "5.3 bounded memory") == "FAIL"


def test_heads_that_keep_coming_without_a_new_seqno_are_a_stall(run):
    lo, hi = T0 + 40_000, T0 + 40_090
    edit(run.root / "observe/chain.jsonl",
         lambda rs: [dict(r, id=full_id(1)) if r.get("kind") == "head" and lo < r["ts"] < hi else r for r in rs])
    assert status(run, "5.1 no stall") == "FAIL"


def test_a_stopped_run_fails(run):
    edit(run.root / "load/load.jsonl", lambda rs: [rs[0], {"ts": T0 + 100, "kind": "stop", "reasons": ["blind"]},
                                                   *rs[1:]])
    assert status(run, "run completed") == "FAIL" and run()["verdict"] == "FAIL"


def test_a_fail_dominates_an_inconclusive(run):
    edit(run.root / "observe/cache.jsonl", lambda rs: rs + [{"ts": T0 + 100, "host": "node-1", "sent": T0 + 99,
                                                             "received": T0 + 100, "kind": "coverage_gap",
                                                             "id": "1:2", "name": "node.log", "reason": "shrunk",
                                                             "bytes": 4096}])
    edit(run.root / "observe/resources.jsonl",
         lambda rs: [dict(r, oom_kill=1) if r["host"] == "node-1" and r["ts"] > T0 + 90_000 else r for r in rs])
    v = run()
    assert {"FAIL", "INCONCLUSIVE"} <= {c["status"] for c in v["criteria"].values()} and v["verdict"] == "FAIL"


def test_a_run_that_never_started_refuses(run):
    (run.root / "load/load.jsonl").write_text("")
    with pytest.raises(tj.Refuse, match="never started"):
        run()


def test_a_record_with_another_hash_refuses(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"judge": JUDGE}))
    tj.load_record(p, hashlib.sha256(p.read_bytes()).hexdigest())
    with pytest.raises(tj.Refuse, match="sha256"):
        tj.load_record(p, "0" * 64)


def test_a_torn_last_journal_line_is_dropped_and_other_bad_lines_are_errors(tmp_path):
    p = tmp_path / "j.jsonl"
    p.write_text('{"a": 1}\n{"b": 2')
    assert tj.rows(p) == [{"a": 1}]
    p.write_text('{"a": 1}\nnot json\n{"b": 2}\n')
    with pytest.raises(ValueError):
        tj.rows(p)


# ---------------------------------------------------------------- codex r2: evidence that must not pass


def test_the_judge_pins_equal_the_observer_and_the_read_client():
    s = importlib.util.spec_from_file_location("t1_observe_pins", SCRIPTS / "t1-observe.py")
    obs = importlib.util.module_from_spec(s)
    s.loader.exec_module(obs)
    assert (tj.LOG_LAG_BYTES, tj.ACTIVE_LOG, tj.LOG_READ_STATUSES) == \
        (obs.LOG_LAG_BYTES, obs.ACTIVE_LOG, obs.READ_STATUSES)
    s = importlib.util.spec_from_file_location("read_client_pins", SCRIPTS / "read_client.py")
    rc = importlib.util.module_from_spec(s)
    s.loader.exec_module(rc)
    assert tuple(rc.T1_ENDPOINTS) == tj.T1_READ_ENDPOINTS == tuple(ENDPOINTS)


def test_backlogged_log_reads_are_no_safety_coverage(run):
    def lag(r):
        if r.get("kind") != "read" or r["host"] != "node-3":
            return r
        return dict(r, files={k: dict(e, behind=2 * 1024 * 1024) if e["name"] == "node.log" else e
                              for k, e in r["files"].items()})
    edit(run.root / "observe/cache.jsonl", lambda rs: [lag(r) for r in rs])
    s = run()["criteria"]["5.5 no safety line"]
    assert s["status"] == "INCONCLUSIVE" and s["uncovered_hosts"] == ["node-3"] and s["coverage_gaps"] == 0


def test_reads_that_skip_the_active_log_are_no_safety_coverage(run):
    def skip(r):
        if r.get("kind") != "read" or r["host"] != "node-2":
            return r
        return dict(r, files={k: e for k, e in r["files"].items() if e["name"] != "node.log"})
    edit(run.root / "observe/cache.jsonl", lambda rs: [skip(r) for r in rs])
    s = run()["criteria"]["5.5 no safety line"]
    assert s["status"] == "INCONCLUSIVE" and s["uncovered_hosts"] == ["node-2"]


def test_a_funding_record_without_its_fee_is_inconclusive_not_zero(run):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [{k: v for k, v in r.items() if k != "fee"} if r["type"] == "observed" and
                     r["id"].startswith("funding") else r for r in rs])
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "INCONCLUSIVE" and "journal" in w["contract_violations"] and not w["unresolved_actions"]


def test_a_transfer_without_its_signing_time_is_inconclusive(run):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [{k: v for k, v in r.items() if k != "signed_at"} if r.get("id") == "transfer:4:62" and
                     r["type"] == "attempt" else r for r in rs])
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "INCONCLUSIVE" and "journal" in w["contract_violations"]


@pytest.mark.parametrize("field", ["utime", "fee", "failure"])
def test_an_observed_transfer_missing_a_field_never_counts(run, field):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [{k: v for k, v in r.items() if k != field} if r["type"] == "observed" else r for r in rs])
    assert status(run, "5.7 writes") == "FAIL"


def test_a_receipt_after_the_cutoff_does_not_resolve_an_action(run):
    def late(rs):
        last = [r for r in rs if r["type"] == "delivered"][-1]
        return [dict(r, recipient_utime=int(END) + 11 * 86400) if r is last else r for r in rs]
    edit(run.root / "load/ramp/journal.jsonl", late)
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "FAIL" and w["unresolved_actions"] == 1 and not w["short_hours"]


def test_a_receipt_before_its_execution_does_not_resolve_an_action(run):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: [dict(r, recipient_utime=r["recipient_utime"] - 10) if r["type"] == "delivered" and
                     r["id"] == "transfer:4:87" else r for r in rs])
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "FAIL" and w["unresolved_actions"] == 1 and not w["short_hours"]


def test_a_read_from_a_foreign_endpoint_is_inconclusive(run):
    edit(run.root / "load/reads/requests.jsonl", lambda rs: rs + [dict(rs[0], endpoint="http://198.51.100.7/x")])
    r = run()["criteria"]["5.6 reads"]
    assert r["status"] == "INCONCLUSIVE" and r["foreign_endpoint_rows"] == 1


def test_reads_from_four_unrelated_endpoints_do_not_pass(run):
    edit(run.root / "load/reads/requests.jsonl",
         lambda rs: [dict(r, endpoint=f"http://other-{ENDPOINTS.index(r['endpoint'])}/") for r in rs])
    assert status(run, "5.6 reads") != "PASS"


def test_a_read_packet_with_other_endpoints_is_inconclusive(run):
    p = run.root / "load/reads/CONTEXT.json"
    c = json.loads(p.read_text())
    c["packet"]["endpoints"] = [f"http://other-{i}/" for i in range(4)]
    p.write_text(json.dumps(c))
    r = run()["criteria"]["5.6 reads"]
    assert r["status"] == "INCONCLUSIVE" and "pinned T1 inventory" in r["reason"]


def test_termination_without_the_ramp_is_inconclusive(run):
    edit(run.root / "load/load.jsonl",
         lambda rs: [dict(r, children={"reads": {"rc": 0, "group_alive": False}}) if r["kind"] == "terminated"
                     else r for r in rs])
    c = run()["criteria"]["run completed"]
    assert c["status"] == "INCONCLUSIVE" and any("both children" in p for p in c["problems"])


def test_a_lifecycle_out_of_order_is_inconclusive(run):
    # Terminated before the cutoff, with times that never go back: only the order check can catch it.
    def reorder(rs):
        k = {r["kind"]: r for r in rs}
        return [k["start"], k["ramp_done"], k["terminated"], k["cutoff"], k["end"]]
    edit(run.root / "load/load.jsonl", reorder)
    c = run()["criteria"]["run completed"]
    assert c["status"] == "INCONCLUSIVE" and c["problems"] == ["the lifecycle is out of order or its times go back"]


def test_a_lifecycle_whose_times_go_back_is_inconclusive(run):
    edit(run.root / "load/load.jsonl",
         lambda rs: [dict(r, ts=END - 5000) if r["kind"] == "terminated" else r for r in rs])
    c = run()["criteria"]["run completed"]
    assert c["status"] == "INCONCLUSIVE" and c["problems"] == ["the lifecycle is out of order or its times go back"]


# ---------------------------------------------------------------- isolated controls for the contract re-scope


def test_a_spend_over_the_cap_fails(run):
    w = run(dict(JUDGE, max_cost_nano=10**9))["criteria"]["5.7 writes"]
    assert w["status"] == "FAIL" and w["fees_nano"] > 10**9 and not w["unresolved_actions"] and not w["short_hours"]


def test_a_delivery_of_an_action_its_attempt_does_not_have_is_inconclusive(run):
    edit(run.root / "load/ramp/journal.jsonl",
         lambda rs: rs + [dict(next(r for r in rs if r["type"] == "delivered" and r["id"] == "transfer:3:40"),
                               action=3)])
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "INCONCLUSIVE" and w["bad_action_index"] == 1 and "contract_violations" not in w


def test_a_read_slot_not_offered_is_inconclusive(run):
    p = run.root / "load/reads/RESULT.json"
    p.write_text(json.dumps(dict(json.loads(p.read_text()), not_offered_capacity=5)))
    r = run()["criteria"]["5.6 reads"]
    assert r["status"] == "INCONCLUSIVE" and r["not_offered"] == 5 and "contract_violations" not in r
