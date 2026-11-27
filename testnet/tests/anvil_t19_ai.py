"""Run the independent buyer-side reader against the real issuer fixtures.

Explicit lane: T19_AI_ISSUER_PROBE must name the probe built from the ai T19
branch. Missing dependencies fail, never skip. No live chain is touched.
"""

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

pytest_plugins = ("anvil_redemption",)


def probe(redemption_world, *, rpc=None, clock=None, amount="100000000"):
    url, accounts, _, _, token, binding = redemption_world
    binary = Path(os.environ["T19_AI_ISSUER_PROBE"])
    assert binary.is_file(), "build the T19 ai issuer fixture probe first"
    request = dict(
        policy=dict(
            rpc_url=rpc or url,
            chain_id=1,
            token=token,
            bridge=binding["bridge"],
            code_sha256=binding["code_sha256"],
            profile=binding["profile"],
        ),
        receiver=accounts[1],
        amount=amount,
    )
    if clock is not None:
        request["now_unix"] = clock
    return subprocess.run(
        [str(binary)],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


@pytest.mark.parametrize("profile", ["legacy_usdt", "standard"])
def test_go_reader_accepts_clear_receiver(redemption_world, profile):
    _, _, _, deploy, _, binding = redemption_world
    if profile == "standard":
        import anvil_redemption

        token = deploy("StandardIssuerFixture")
        binding.update(
            token=token,
            profile=profile,
            code_sha256=anvil_redemption.issuer.source.code_hash(
                anvil_redemption.issuer.source.RPC(redemption_world[0]), token, "latest"
            ),
        )
        redemption_world = (*redemption_world[:4], token, binding)
    result = probe(redemption_world)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["received"] == "100000000" and value["fee"] == "0"
    assert value["observation"]["token"] == redemption_world[4]


@pytest.mark.parametrize(
    "profile,flag,signature,args",
    [
        ("legacy_usdt", "blacklisted", "addBlackList(address)", "receiver"),
        ("standard", "blacklisted", "addBlackList(address)", "receiver"),
        ("legacy_usdt", "paused", "pause()", None),
        ("standard", "paused", "pause()", None),
        ("legacy_usdt", "deprecated", "deprecate(address)", "target"),
    ],
)
def test_go_reader_refuses_restrictions(redemption_world, profile, flag, signature, args):
    _, accounts, send, deploy, token, binding = redemption_world
    if profile == "standard":
        import anvil_redemption

        token = deploy("StandardIssuerFixture")
        binding.update(
            token=token,
            profile=profile,
            code_sha256=anvil_redemption.issuer.source.code_hash(
                anvil_redemption.issuer.source.RPC(redemption_world[0]), token, "latest"
            ),
        )
        redemption_world = (*redemption_world[:4], token, binding)
    parameters = [] if args is None else [accounts[1] if args == "receiver" else accounts[2]]
    send(token, signature, *parameters)
    result = probe(redemption_world)
    assert result.returncode == 2 and flag in result.stderr, result.stdout + result.stderr
    assert result.stdout == ""


def test_go_reader_prices_the_real_fee(redemption_world):
    _, _, send, _, token, _ = redemption_world
    send(token, "setParams(uint256,uint256)", 19, 1)
    result = probe(redemption_world)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["received"] == "99810000" and value["fee"] == "190000"


def test_go_reader_refuses_stale_or_failed_source(redemption_world):
    import anvil_redemption

    block = anvil_redemption.issuer.source.block(
        anvil_redemption.issuer.source.RPC(redemption_world[0]), "finalized"
    )
    stale = probe(redemption_world, clock=int(block["timestamp"], 16) + 1801)
    assert stale.returncode == 2 and "stale" in stale.stderr and stale.stdout == ""
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        port = unavailable.getsockname()[1]
        # Bound but not listening: the connection is refused deterministically.
        failed = probe(redemption_world, rpc=f"http://127.0.0.1:{port}")
    assert failed.returncode == 2 and "unavailable" in failed.stderr and failed.stdout == ""


@pytest.mark.parametrize(
    "amount,received,fee",
    [
        (100_000_001, 99_810_001, 190_000),
        (526_315_789, 525_315_790, 999_999),
        (526_315_790, 525_315_790, 1_000_000),
        (526_316_316, 525_316_316, 1_000_000),
    ],
)
def test_go_reader_floors_and_caps_fee(redemption_world, amount, received, fee):
    _, _, send, _, token, _ = redemption_world
    send(token, "setParams(uint256,uint256)", 19, 1)
    result = probe(redemption_world, amount=str(amount))
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["received"] == str(received) and value["fee"] == str(fee)
