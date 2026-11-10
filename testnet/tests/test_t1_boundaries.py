"""Tests for t1-boundaries.py with a fake clock, a fake RPC and a fake runner; nothing reaches a host."""

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


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


@pytest.fixture()
def terms(monkeypatch):
    """ConfigParam 34 answers: a per-host list of (since, until), consumed in order once the clock passes."""
    state = {"by_host": {}}
    monkeypatch.setattr(tb.network_check.lib, "parse_boc", lambda raw: raw.decode())
    monkeypatch.setattr(tb.network_check, "decode_set", lambda cell: dict(zip(("since", "until"), json.loads(cell))))

    def fetch(url, method, **p):
        assert method == "getConfigParam" and p == {"param": 34}
        host = next(h for h, u in URLS.items() if u == url)
        since, until = state["by_host"][host]()
        import base64
        return {"config": {"bytes": base64.b64encode(json.dumps([since, until]).encode()).decode()}}
    state["fetch"] = fetch
    return state


def args(tmp_path, end):
    return SimpleNamespace(out=tmp_path / "out", end=end, global_config=tmp_path / "g.json", zerostate=tmp_path / "z",
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


def schedule(clock, period=7200, first=T0 + 3000):
    """The set switches every `period` s from `first`: the current term ends at the next switch."""
    def answer():
        k = max(0, (clock.t - first) // period + 1) if clock.t >= first else 0
        until = first + k * period
        return (until - period, until)
    return answer


def rows(a):
    return [json.loads(x) for x in (a.out / "boundaries.jsonl").read_text().splitlines()]


def test_every_boundary_until_the_end_runs_all_three_checks_on_four_sources(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, T0 + 3000 + 7200 + 100)
    run = Runner(clock)
    assert tb.run_boundaries(a, URLS, terms["fetch"], run, clock.now, clock.sleep) == 0
    done = [r for r in rows(a) if "collect_exit" in r]
    assert [r["boundary"] for r in done] == [T0 + 3000, T0 + 10200]
    assert all(r["collect_exit"] == r["verify_exit"] == r["keys_exit"] == 0 for r in done)
    collects = [argv for _, step, argv in run.calls if step == "collect"]
    assert all(argv.count("--rpc") == 4 for argv in collects)
    keys = [argv for _, step, argv in run.calls if step == "keys"]
    assert all(argv.count("--source") == 4 and "--exclude" not in argv for argv in keys)
    starts = [t for t, step, _ in run.calls if step == "collect"]
    assert starts == [T0 + 3000 - tb.LEAD, T0 + 10200 - tb.LEAD]
    assert keys[0][keys[0].index("--since") + 1] == str(T0 + 3000)


def test_a_boundary_after_the_end_is_not_started(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, T0 + 2000)
    run = Runner(clock)
    tb.run_boundaries(a, URLS, terms["fetch"], run, clock.now, clock.sleep)
    assert run.calls == [] and not (a.out / "boundaries.jsonl").exists()


def test_sources_that_disagree_on_the_term_are_an_error_row_and_retried(tmp_path, terms):
    clock = Clock()
    good = schedule(clock)
    flips = {"n": 0}

    def bad():
        flips["n"] += 1
        return good() if flips["n"] > 2 else (0, 1)
    terms["by_host"] = {h: good for h in tb.HOSTS}
    terms["by_host"]["node-3"] = bad
    a = args(tmp_path, T0 + 3100)
    tb.run_boundaries(a, URLS, terms["fetch"], Runner(clock), clock.now, clock.sleep)
    r = rows(a)
    assert sum("disagree" in x.get("error", "") for x in r) == 2
    assert [x["boundary"] for x in r if "collect_exit" in x] == [T0 + 3000]


def test_failed_and_hung_checks_are_recorded_not_hidden(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, T0 + 3100)
    run = Runner(clock, {"verify": 1, "keys": subprocess.TimeoutExpired("x", 1)})
    tb.run_boundaries(a, URLS, terms["fetch"], run, clock.now, clock.sleep)
    (done,) = [r for r in rows(a) if "collect_exit" in r]
    assert (done["collect_exit"], done["verify_exit"], done["keys_exit"]) == (0, 1, "timeout")
    assert done["handover_report"].startswith("unreadable") and done["keys_verdict"].startswith("unreadable")


def test_the_report_and_verdict_are_copied_into_the_row(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, T0 + 3100)

    class Writing(Runner):
        def __call__(self, argv, **kw):
            out = a.out / f"boundary-{T0 + 3000}"
            (out / "collect").mkdir(parents=True, exist_ok=True)
            (out / "keys").mkdir(exist_ok=True)
            (out / "collect" / "report.json").write_text('{"result": "PASS"}')
            (out / "keys" / "VERDICT.json").write_text('{"verdict": "PASS-FOUR-SIGNER-COVERAGE-PINNED-KEYS"}')
            return super().__call__(argv, **kw)
    tb.run_boundaries(a, URLS, terms["fetch"], Writing(clock), clock.now, clock.sleep)
    (done,) = [r for r in rows(a) if "collect_exit" in r]
    assert done["handover_report"] == {"result": "PASS"}
    assert done["keys_verdict"]["verdict"] == "PASS-FOUR-SIGNER-COVERAGE-PINNED-KEYS"


def test_an_unreadable_term_is_an_error_row(tmp_path, terms):
    clock = Clock()

    def broken():
        raise ConnectionError("tunnel down")
    terms["by_host"] = {h: broken for h in tb.HOSTS}
    a = args(tmp_path, T0 + 200)
    tb.run_boundaries(a, URLS, terms["fetch"], Runner(clock), clock.now, clock.sleep)
    r = rows(a)
    assert len(r) == 4 and all("term unreadable" in x["error"] for x in r)


def test_a_boundary_directory_is_never_reused(tmp_path, terms):
    clock = Clock()
    terms["by_host"] = {h: schedule(clock) for h in tb.HOSTS}
    a = args(tmp_path, T0 + 3100)
    (a.out / f"boundary-{T0 + 3000}").mkdir(parents=True)
    with pytest.raises(FileExistsError):
        tb.run_boundaries(a, URLS, terms["fetch"], Runner(clock), clock.now, clock.sleep)
