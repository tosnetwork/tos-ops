"""Tests for t1-boundaries.py with a fake clock, a fake RPC and a fake runner; nothing reaches a host."""

import base64
import importlib.util
import json
import subprocess
from types import SimpleNamespace

import pytest
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("t1_boundaries", SCRIPTS / "t1-boundaries.py")
tb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tb)

URLS = {h: f"http://127.0.0.1:{18081 + i}/jsonRPC" for i, h in enumerate(tb.HOSTS)}
T0 = 1_762_800_000
B1 = T0 + 3000
P = 7200


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


@pytest.fixture()
def terms(monkeypatch):
    """ConfigParam 34 answers: a per-host callable returning (since, until)."""
    state = {"by_host": {}}
    monkeypatch.setattr(tb.network_check.lib, "parse_boc", lambda raw: raw.decode())
    monkeypatch.setattr(tb.network_check, "decode_set", lambda cell: dict(zip(("since", "until"), json.loads(cell))))

    def fetch(url, method, **p):
        assert method == "getConfigParam" and p == {"param": 34}
        host = next(h for h, u in URLS.items() if u == url)
        since, until = state["by_host"][host]()
        return {"config": {"bytes": base64.b64encode(json.dumps([since, until]).encode()).decode()}}
    state["fetch"] = fetch
    return state


def args(tmp_path, end, first=B1):
    return SimpleNamespace(out=tmp_path / "out", end=end, first_boundary=first, period=P,
                           global_config=tmp_path / "g.json", zerostate=tmp_path / "z",
                           inventory=tmp_path / "inv.json", unit_dir=tmp_path / "units")


class Runner:
    def __init__(self, clock, codes=None):
        self.clock, self.calls, self.codes = clock, [], codes or {}

    def __call__(self, argv, **kw):
        step = "keys" if "check-validator-keys.py" in argv[2] else argv[3]
        self.calls.append((self.clock.t, step, argv))
        self.clock.t += 30
        code = self.codes.get(step, 0)
        if isinstance(code, BaseException):
            raise code
        return subprocess.CompletedProcess(argv, code)


def schedule(clock, first=B1):
    """The chain: the set switches every P s at first + k*P; the current term ends at the next switch."""
    def answer():
        k = (clock.t - first) // P + 1 if clock.t >= first else 0
        until = first + k * P
        return (until - P, until)
    return answer


def rows(a):
    return [json.loads(x) for x in (a.out / "boundaries.jsonl").read_text().splitlines()]


def outcomes(a):
    return [(r["boundary"], r["outcome"]) for r in rows(a) if "outcome" in r]


def go(a, terms, clock, run=None):
    run = run or Runner(clock)
    tb.run_boundaries(a, URLS, terms["fetch"], run, clock.now, clock.sleep)
    return run


def test_every_pinned_boundary_runs_all_three_checks_on_four_sources(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, B1 + P + 100)
    run = go(a, terms, clock)
    assert outcomes(a) == [(B1, "checked"), (B1 + P, "checked")]
    done = [r for r in rows(a) if r.get("outcome") == "checked"]
    assert all(r["collect_exit"] == r["verify_exit"] == r["keys_exit"] == 0 for r in done)
    collects = [argv for _, step, argv in run.calls if step == "collect"]
    assert all(argv.count("--rpc") == 4 for argv in collects)
    keys = [argv for _, step, argv in run.calls if step == "keys"]
    assert all(argv.count("--source") == 4 and "--exclude" not in argv for argv in keys)
    assert [t for t, step, _ in run.calls if step == "collect"] == [B1 - tb.LEAD, B1 + P - tb.LEAD]
    assert keys[0][keys[0].index("--since") + 1] == str(B1)


def test_a_boundary_after_the_end_is_not_started(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, B1 - 1)
    run = go(a, terms, clock)
    assert run.calls == [] and not (a.out / "boundaries.jsonl").exists()


def test_an_unreadable_term_does_not_stop_the_pinned_checks(tmp_path, terms):
    # codex r2: the first read fails at B-10; the boundary must still be checked, not lost.
    clock = Clock(B1 - 10)

    def broken():
        raise ConnectionError("tunnel down")
    terms["by_host"] = {h: broken for h in tb.HOSTS}
    a = args(tmp_path, B1 + 100)
    run = go(a, terms, clock)
    assert outcomes(a) == [(B1, "checked")]
    assert any("term unreadable" in r.get("error", "") for r in rows(a))
    assert [step for _, step, _ in run.calls] == ["collect", "verify", "keys"]


def test_terms_unreadable_until_the_end_still_give_every_boundary_an_outcome(tmp_path, terms):
    clock = Clock()

    def broken():
        raise ConnectionError("tunnel down")
    terms["by_host"] = {h: broken for h in tb.HOSTS}
    a = args(tmp_path, B1 + 2 * P)
    go(a, terms, clock)
    assert [b for b, _ in outcomes(a)] == [B1, B1 + P, B1 + 2 * P]


def test_a_wrapper_that_was_down_reports_the_boundaries_it_missed(tmp_path, terms):
    clock = Clock(B1 + P + tb.LATE + 1)  # started after the first two switches were too far gone
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, B1 + 2 * P + 100)
    go(a, terms, clock)
    assert outcomes(a) == [(B1, "missed"), (B1 + P, "missed"), (B1 + 2 * P, "checked")]


def test_a_late_start_within_the_grace_still_checks(tmp_path, terms):
    clock = Clock(B1 + 600)
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, B1 + 100)
    go(a, terms, clock)
    assert outcomes(a) == [(B1, "checked")]


def test_a_planned_boundary_whose_run_crashed_is_interrupted_after_restart(tmp_path, terms):
    # codex r2: planned=B is written, the run crashes, the wrapper restarts after the switch.
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, B1 + P + 100)

    class Crash(Runner):
        def __call__(self, argv, **kw):
            raise KeyboardInterrupt  # the wrapper process dies mid-boundary
    with pytest.raises(KeyboardInterrupt):
        go(a, terms, clock, Crash(clock))
    clock.t = B1 + 300
    go(a, terms, clock)
    assert outcomes(a) == [(B1, "interrupted"), (B1 + P, "checked")]


def test_a_restart_resumes_from_the_recorded_outcomes(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, B1 + 100)
    go(a, terms, clock)
    clock.t = B1 + P + tb.LATE + 10
    a.end = B1 + 2 * P + 100
    run = go(a, terms, clock)
    assert outcomes(a) == [(B1, "checked"), (B1 + P, "missed"), (B1 + 2 * P, "checked")]
    assert len([c for c in run.calls if c[1] == "collect"]) == 1


def test_a_chain_schedule_that_disagrees_with_the_pin_fails_closed(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock, first=B1 + 900) for h in tb.HOSTS}
    a = args(tmp_path, B1 + 100)
    run = go(a, terms, clock)
    assert outcomes(a) == [(B1, "schedule_mismatch")] and run.calls == []


def test_sources_that_disagree_are_an_unreadable_term_row(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    terms["by_host"]["node-3"] = lambda: (0, 1)
    a = args(tmp_path, B1 + 100)
    go(a, terms, clock)
    assert any("disagree" in r.get("error", "") for r in rows(a)) and outcomes(a) == [(B1, "checked")]


def test_failed_and_hung_checks_are_recorded_not_hidden(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, B1 + 100)
    go(a, terms, clock, Runner(clock, {"verify": 1, "keys": subprocess.TimeoutExpired("x", 1)}))
    (done,) = [r for r in rows(a) if r.get("outcome") == "checked"]
    assert (done["collect_exit"], done["verify_exit"], done["keys_exit"]) == (0, 1, "timeout")
    assert done["handover_report"].startswith("unreadable") and done["keys_verdict"].startswith("unreadable")


def test_the_report_and_verdict_are_copied_into_the_row(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, B1 + 100)

    class Writing(Runner):
        def __call__(self, argv, **kw):
            out = a.out / f"boundary-{B1}"
            (out / "collect").mkdir(parents=True, exist_ok=True)
            (out / "keys").mkdir(exist_ok=True)
            (out / "collect" / "report.json").write_text('{"result": "PASS"}')
            (out / "keys" / "VERDICT.json").write_text('{"verdict": "PASS-FOUR-SIGNER-COVERAGE-PINNED-KEYS"}')
            return super().__call__(argv, **kw)
    go(a, terms, clock, Writing(clock))
    (done,) = [r for r in rows(a) if r.get("outcome") == "checked"]
    assert done["handover_report"] == {"result": "PASS"}
    assert done["keys_verdict"]["verdict"] == "PASS-FOUR-SIGNER-COVERAGE-PINNED-KEYS"
