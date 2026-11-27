"""Explicit issuer acceptance lane; isolated source fixture, no live TOS sends."""

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

pytest_plugins = ("anvil_settlement_observer",)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "testnet/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "redemption", ROOT / "testnet/scripts/prepare-token-redemption.py"
)
redemption = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(redemption)
issuer = redemption.issuer
if os.environ.get("T19_ISSUER_SOURCE"):
    SPEC = importlib.util.spec_from_file_location("mutant_issuer", os.environ["T19_ISSUER_SOURCE"])
    issuer = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(issuer)
    redemption.issuer = issuer


@pytest.fixture
def world(source_net):
    url, accounts, send, deploy = source_net
    token = deploy("LocalUSDT")
    binding = dict(
        schema="tos-settlement-issuer/1",
        bridge=deploy("BridgeFixture"),
        chain_id=1,
        token=token,
        profile="legacy_usdt",
        code_sha256=issuer.source.code_hash(issuer.source.RPC(url), token, "latest"),
        master="0:" + "a" * 64,
        wallet="0:" + "b" * 64,
    )
    return url, accounts, send, deploy, token, binding


def build(world, now=time.time):
    url, accounts, _, _, _, binding = world
    return redemption.prepare(issuer.source.RPC(url), binding, accounts[1], 100_000_000, 7, now)


def test_clear_receiver_builds_only_the_bridge_burn(world):
    document = build(world)
    assert document["received_atomic"] == "100000000"
    assert "recorded burn is final" in document["warning"]
    import base64

    lib = redemption.lib
    body = lib.parse_boc(base64.b64decode(document["body_boc"]))
    s = lib.Slice(body)
    assert s.bits(32) == 0x595F07BC and s.bits(64) == 7
    assert lib.read_grams(s) == 100_000_000
    assert s.bits(2) == 0 and s.bits(1) == 1
    receiver = lib.Slice(s.take_ref())
    assert receiver.bits(160) == int(world[1][1], 16) and receiver.end() and s.end()


@pytest.mark.parametrize("profile", ["legacy_usdt", "standard"])
def test_blacklisted_receiver_refuses_before_body(world, profile):
    _, accounts, send, deploy, token, binding = world
    if profile == "standard":
        token = deploy("StandardIssuerFixture")
        binding.update(
            token=token,
            profile=profile,
            code_sha256=issuer.source.code_hash(issuer.source.RPC(world[0]), token, "latest"),
        )
    send(token, "addBlackList(address)", accounts[1])
    with pytest.raises(issuer.Invalid, match="receiver is blacklisted"):
        build(world)


@pytest.mark.parametrize("profile", ["legacy_usdt", "standard"])
def test_paused_issuer_refuses_before_body(world, profile):
    _, _, send, deploy, token, binding = world
    if profile == "standard":
        token = deploy("StandardIssuerFixture")
        binding.update(
            token=token,
            profile=profile,
            code_sha256=issuer.source.code_hash(issuer.source.RPC(world[0]), token, "latest"),
        )
    send(token, "pause()")
    with pytest.raises(issuer.Invalid, match="token is paused"):
        build(world)


def test_deprecated_issuer_refuses_before_body(world):
    _, accounts, send, _, token, _ = world
    send(token, "deprecate(address)", accounts[2])
    with pytest.raises(issuer.Invalid, match="token is deprecated"):
        build(world)


def test_fee_preview_matches_actual_received_delta_and_cap(world):
    url, accounts, send, _, token, binding = world
    assert build(world)["issuer_fee_atomic"] == "0"
    send(token, "setParams(uint256,uint256)", 19, 1)
    document = build(world)
    assert document["received_atomic"] == "99810000"
    assert document["issuer_fee_atomic"] == "190000"
    before = issuer.source.read_uint(
        issuer.source.RPC(url), token, "balance", "latest", accounts[1]
    )
    send(token, "transfer(address,uint256)", accounts[1], 100_000_000)
    after = issuer.source.read_uint(issuer.source.RPC(url), token, "balance", "latest", accounts[1])
    assert after - before == int(document["received_atomic"])
    observation = issuer.read_issuer(issuer.source.RPC(url), binding, accounts[1])
    assert issuer.received_amount(3_000_000_000, observation) == (2_999_000_000, 1_000_000)
    send(token, "setParams(uint256,uint256)", 0, 0)
    assert build(world)["issuer_fee_atomic"] == "0"


def test_stale_finalized_read_refuses(world):
    with pytest.raises(issuer.Invalid, match="stale"):
        build(world, now=lambda: time.time() + issuer.MAX_FINALIZED_AGE + 100)


def test_failed_rpc_never_builds_a_body(world, monkeypatch):
    def fail(*args):
        raise OSError("fixture unavailable")

    monkeypatch.setattr(issuer.source.RPC, "call", fail)
    with pytest.raises(OSError):
        build(world)


def test_changed_issuer_code_refuses(world):
    world[-1]["code_sha256"] = "0" * 64
    with pytest.raises(issuer.Invalid, match="issuer code differs"):
        build(world)


def test_standard_fixture_rejects_blacklisted_receiver_on_transfer(world):
    _, accounts, send, deploy, _, _ = world
    token = deploy("StandardIssuerFixture")
    send(token, "addBlackList(address)", accounts[1])
    with pytest.raises(AssertionError):
        send(token, "transfer(address,uint256)", accounts[1], 100)


def test_wrong_source_chain_refuses(world):
    world[-1]["chain_id"] = 2
    with pytest.raises(issuer.Invalid, match="issuer chain differs"):
        build(world)


def test_finalized_hash_change_refuses(world):
    class ChangedHash:
        def __init__(self):
            self.rpc = issuer.source.RPC(world[0])

        def call(self, method, *params):
            value = self.rpc.call(method, *params)
            if method == "eth_getBlockByNumber" and params[0] != "finalized":
                value["hash"] = "0x" + "f" * 64
            return value

    with pytest.raises(issuer.Invalid, match="checkpoint changed"):
        redemption.prepare(ChangedHash(), world[-1], world[1][1], 100000000, 7)


def test_rpc_error_even_with_a_result_refuses(world, monkeypatch):
    import io
    import json

    real = issuer.source.urllib.request.urlopen

    def ambiguous(*args, **kwargs):
        with real(*args, **kwargs) as response:
            answer = json.loads(response.read())
        answer["error"] = dict(code=-32000, message="fixture error")
        return io.BytesIO(json.dumps(answer).encode())

    monkeypatch.setattr(issuer.source.urllib.request, "urlopen", ambiguous)
    with pytest.raises(issuer.Invalid, match="source RPC refused"):
        build(world)


def test_blacklisted_bridge_refuses_before_body(world):
    _, _, send, _, token, binding = world
    send(token, "addBlackList(address)", binding["bridge"])
    with pytest.raises(issuer.Invalid, match="source bridge is blacklisted"):
        build(world)
