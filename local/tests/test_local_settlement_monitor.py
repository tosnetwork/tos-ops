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
