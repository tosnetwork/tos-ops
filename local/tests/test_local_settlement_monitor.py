"""Replay exact public local-chain reads; no endpoint or signing access."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "local_monitor", ROOT / "local/scripts/local-settlement-monitor.py"
)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
DATA = Path(__file__).parent / "data/usdt-tos-observation.json"


def replay(tmp_path, monkeypatch, change=None):
    fixture = json.loads(DATA.read_text())
    for call in fixture["calls"]:
        result = fixture["responses"][call["response_sha256"]]
        assert (
            hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
            == call["response_sha256"]
        )
        call["result"] = copy.deepcopy(result)
    if change:
        change(fixture)
    by_key = {
        json.dumps([x["method"], x["params"]], sort_keys=True): x["result"]
        for x in fixture["calls"]
    }
    calls = []

    class Chain:
        urls = fixture["urls"]

        def call(self, method, /, **params):
            assert params.get("seqno") == fixture["point"]["seqno"], (
                "read escaped the checkpoint"
            )
            key = json.dumps([method, params], sort_keys=True)
            assert key in by_key, "unexpected read or a broadcast"
            calls.append(params["url"])
            return copy.deepcopy(by_key[key])

    class View(m.asset.View):
        def __init__(self, chain, directory):
            self.chain, self.urls, self.point = chain, chain.urls[3:6], fixture["point"]

    monkeypatch.setattr(m.asset, "View", View)
    result = m.tos_observation(
        Chain(), fixture["states"], fixture["artifact"], tmp_path
    )
    return fixture, result, calls


def test_both_asset_snapshots_match_the_captured_checkpoint(tmp_path, monkeypatch):
    fixture, (observation, binding, policy), calls = replay(tmp_path, monkeypatch)
    assert observation == fixture["expected"]["observation"]
    assert binding == fixture["expected"]["binding"]
    assert policy == fixture["expected"]["policy"]
    assert set(calls) == set(fixture["urls"][3:6])
    assert [x["wrapped_supply"] for x in observation["assets"]] == [
        25_000_000,
        25_000_000,
    ]
    assert all(not x["actors"] for x in observation["assets"])


def test_changed_master_code_is_refused_before_source_collection(tmp_path, monkeypatch):
    def change(fixture):
        master = fixture["expected"]["observation"]["assets"][1]["master"]
        other_code = next(
            x["result"]["code"]
            for x in fixture["calls"]
            if x["method"] == "getAddressInformation"
            and x["params"]["address"] != master
        )
        for entry in fixture["calls"]:
            if (
                entry["method"] == "getAddressInformation"
                and entry["params"]["address"] == master
            ):
                entry["result"]["code"] = other_code

    with pytest.raises(m.u.Refused, match="monitored master code differs"):
        replay(tmp_path, monkeypatch, change)


def test_disagreeing_supply_is_not_merged_into_a_clean_snapshot(tmp_path, monkeypatch):
    def change(fixture):
        master = fixture["expected"]["observation"]["assets"][1]["master"]
        for entry in fixture["calls"]:
            if (
                entry["method"] == "runGetMethod"
                and entry["params"]["address"] == master
                and entry["params"]["method"] == "get_token_data"
                and entry["params"]["url"] == fixture["urls"][5]
            ):
                entry["result"]["stack"][-1] = ["num", "1"]

    with pytest.raises(m.u.Refused, match="supply references disagree"):
        replay(tmp_path, monkeypatch, change)


def raises(error):
    def tick(args):
        raise error

    return tick


def stale_args():
    from types import SimpleNamespace

    return SimpleNamespace(once=False, interval=15)


@pytest.mark.parametrize(
    "error",
    [
        m.u.lib.RpcError(
            "http://127.0.0.1:8014",
            "getMasterchainInfo",
            -32005,
            "RATE_LIMITED",
            "Rate limit exceeded (per-IP)",
            True,
        ),
        m.asset.archive.ops.Unknown(
            "http://127.0.0.1:8014: getMasterchainInfo: RATE_LIMITED -32005"
        ),
        TimeoutError("timed out"),
        ConnectionRefusedError("refused"),
    ],
)
def test_a_refused_read_is_a_stale_tick_not_a_crash(tmp_path, monkeypatch, error):
    (tmp_path / "report.json").write_text(
        json.dumps(
            {
                "schema": "tos-settlement-report/1",
                "alarms": [],
                "checkpoint": {"height": 9, "hash": "aa" * 32, "utime": 1795800000},
                "provider_pause_assets": [],
            }
        )
    )
    monkeypatch.setattr(m, "tick", raises(error))
    waits = []
    code = m.run(stale_args(), tmp_path, sleep=waits.append, ticks=3)
    report = json.loads((tmp_path / "report.json").read_text())
    # Fail-closed: the formerly healthy report is replaced by a stale one.
    assert (
        code == 2 and report["status"] == "STALE" and report["checkpoint"]["utime"] == 0
    )
    assert len(waits) == 2 and waits[1] > waits[0] > 0


def test_stale_back_off_is_bounded_and_resets_on_success(tmp_path, monkeypatch):
    assert m.stale_delay(15, 1) == 15
    assert m.stale_delay(15, 2) == 30
    assert m.stale_delay(15, 3) == 60
    assert all(m.stale_delay(15, n) == m.MAX_BACKOFF_SECONDS for n in range(4, 50))
    outcomes = iter([m.u.lib.TestnetError("x"), m.u.lib.TestnetError("y"), 0, 0])

    def tick(args):
        value = next(outcomes)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(m, "tick", tick)
    monkeypatch.setattr(m.source, "stale_report", lambda path: None)
    waits = []
    assert m.run(stale_args(), tmp_path, sleep=waits.append, ticks=4) == 0
    assert waits[0] > 0 and waits[1] > waits[0] and waits[2] <= 15
