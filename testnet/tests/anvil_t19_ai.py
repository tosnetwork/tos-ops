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


def probe(world, *, rpc=None, clock=None):
    url, accounts, _, _, token, binding = world
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
        amount="100000000",
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
def test_go_reader_accepts_clear_receiver(world, profile):
    _, _, _, deploy, _, binding = world
    if profile == "standard":
        import anvil_redemption

        token = deploy("StandardIssuerFixture")
        binding.update(
            token=token,
            profile=profile,
            code_sha256=anvil_redemption.issuer.source.code_hash(
                anvil_redemption.issuer.source.RPC(world[0]), token, "latest"
            ),
        )
        world = (*world[:4], token, binding)
    result = probe(world)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["received"] == "100000000" and value["fee"] == "0"
    assert value["observation"]["token"] == world[4]


@pytest.mark.parametrize(
    "flag,signature,args",
    [
        ("blacklisted", "addBlackList(address)", "receiver"),
        ("paused", "pause()", None),
        ("deprecated", "deprecate(address)", "target"),
    ],
)
def test_go_reader_refuses_restrictions(world, flag, signature, args):
    _, accounts, send, _, token, _ = world
    parameters = [] if args is None else [accounts[1] if args == "receiver" else accounts[2]]
    send(token, signature, *parameters)
    result = probe(world)
    assert result.returncode == 2 and flag in result.stderr, result.stdout + result.stderr
    assert result.stdout == ""


def test_go_reader_prices_the_real_fee(world):
    _, _, send, _, token, _ = world
    send(token, "setParams(uint256,uint256)", 19, 1)
    result = probe(world)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["received"] == "99810000" and value["fee"] == "190000"


def test_go_reader_refuses_stale_or_failed_source(world):
    import anvil_redemption

    block = anvil_redemption.issuer.source.block(
        anvil_redemption.issuer.source.RPC(world[0]), "finalized"
    )
    stale = probe(world, clock=int(block["timestamp"], 16) + 1801)
    assert stale.returncode == 2 and "stale" in stale.stderr and stale.stdout == ""
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        port = unavailable.getsockname()[1]
        # Bound but not listening: the connection is refused deterministically.
        failed = probe(world, rpc=f"http://127.0.0.1:{port}")
    assert failed.returncode == 2 and "unavailable" in failed.stderr and failed.stdout == ""
