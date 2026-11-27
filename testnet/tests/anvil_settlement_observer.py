"""Explicit Anvil acceptance suite; run under the shared thermal guard.

This starts a separate loopback source-only fixture, never the existing TOS net.
Dependencies are mandatory: anvil, cast, Node and TOS_EVM_SOLC_MODULE. No skips.
"""

import copy
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(
    os.environ.get("TOS_SETTLEMENT_COLLECTOR", ROOT / "testnet/scripts/collect-settlement-evm.py")
)
SPEC = importlib.util.spec_from_file_location("evm_observer", SOURCE)
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)
SPEC = importlib.util.spec_from_file_location(
    "checker_fixtures", Path(__file__).with_name("test_check_settlement.py")
)
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)


@pytest.fixture(scope="module")
def source_net(tmp_path_factory):
    anvil, cast = shutil.which("anvil"), shutil.which("cast")
    assert anvil and cast, "Anvil and cast are required"
    solc = os.environ.get("TOS_EVM_SOLC_MODULE")
    assert solc and Path(solc).is_dir(), "TOS_EVM_SOLC_MODULE is required"
    sources = {
        "LocalUSDT.sol": {
            "content": (ROOT / "local/contracts/test-usdt/LocalUSDT.sol").read_text()
        },
        "BridgeFixture.sol": {
            "content": (
                ROOT / "testnet/tests/fixtures/settlement-source/BridgeFixture.sol"
            ).read_text()
        },
    }
    sources["StandardObserverFixture.sol"] = {
        "content": (
            ROOT / "testnet/tests/fixtures/settlement-source/StandardObserverFixture.sol"
        ).read_text()
    }
    program = 'const fs=require("fs");const solc=require(process.argv[1]);process.stdout.write(solc.compile(fs.readFileSync(0,"utf8")));'
    request = dict(
        language="Solidity",
        sources=sources,
        settings=dict(
            optimizer=dict(enabled=True, runs=200),
            outputSelection={"*": {"*": ["evm.bytecode.object"]}},
        ),
    )
    output = subprocess.run(
        ["node", "-e", program, solc],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        check=True,
        timeout=60,
    )
    compiled = json.loads(output.stdout)
    assert not [e for e in compiled.get("errors", []) if e["severity"] == "error"], compiled.get(
        "errors"
    )
    codes = {
        name: compiled["contracts"][file][name]["evm"]["bytecode"]["object"]
        for name, file in (
            ("LocalUSDT", "LocalUSDT.sol"),
            ("BridgeFixture", "BridgeFixture.sol"),
            ("StandardObserverFixture", "StandardObserverFixture.sol"),
        )
    }
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    root = tmp_path_factory.mktemp("source-anvil")
    with (root / "node.log").open("w") as log:
        process = subprocess.Popen(
            [
                anvil,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--chain-id",
                "1",
                "--slots-in-an-epoch",
                "1",
                "--silent",
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            url = f"http://127.0.0.1:{port}"
            for _ in range(100):
                try:
                    rpc = observer.RPC(url)
                    rpc.call("eth_chainId")
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                pytest.fail("fixture source node did not start")
            # This is a test sender outside the read-only collector, never a key.
            accounts = json.loads(
                subprocess.check_output([cast, "rpc", "--rpc-url", url, "eth_accounts"], text=True)
            )

            def send(destination, signature=None, *args):
                command = [
                    cast,
                    "send",
                    "--rpc-url",
                    url,
                    "--from",
                    accounts[0],
                    "--unlocked",
                    "--json",
                ]
                command += (
                    [destination, signature, *map(str, args)]
                    if signature
                    else ["--create", destination]
                )
                result = subprocess.run(
                    command, text=True, capture_output=True, timeout=30, check=False
                )
                assert result.returncode == 0, result.stderr
                # Only the isolated test driver mines; the collector cannot.
                # Move this receipt behind this fixture's two-slot finality lag.
                subprocess.run(
                    [cast, "rpc", "--rpc-url", url, "anvil_mine", "0x2"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                return json.loads(result.stdout)

            def deploy(kind):
                code = codes[kind]
                if kind == "LocalUSDT":
                    code += (10**12).to_bytes(32, "big").hex()
                return send("0x" + code)["contractAddress"].lower()

            yield url, accounts, send, deploy
        finally:
            process.terminate()
            process.wait(timeout=10)


@pytest.fixture
def world(source_net):
    url, accounts, send, deploy = source_net
    bridge = deploy("BridgeFixture")
    tokens = [deploy("LocalUSDT"), deploy("LocalUSDT")]
    for token in tokens:
        send(token, "transfer(address,uint256)", bridge, 500_000_000)
    policy, base = fixtures.fixture()
    binding = dict(
        schema="tos-settlement-source/1",
        network=base["network"],
        chain_id=1,
        bridge=bridge,
        bridge_code_sha256=observer.code_hash(observer.RPC(url), bridge, "latest"),
        assets=[],
    )
    for index, token in enumerate(tokens):
        policy["assets"][index]["source_token"] = token
        base["assets"][index]["source_token"] = token
        base["assets"][index]["wrapped_supply"] = 100_000_000
        binding["assets"].append(
            dict(
                id=base["assets"][index]["id"],
                token=token,
                profile="legacy_usdt",
                code_sha256=observer.code_hash(observer.RPC(url), token, "latest"),
                redemptions=[],
            )
        )
    initial = observer.collect(observer.RPC(url), binding, base, None)
    for p, a in zip(policy["assets"], initial["assets"], strict=True):
        p["implementation"] = a["implementation"]
    initial["checkpoint"]["utime"] = initial["source_checkpoint"]["utime"]

    def observe():
        value = observer.collect(observer.RPC(url), binding, base, initial)
        value["checkpoint"].update(
            height=101, hash="d" * 64, utime=value["source_checkpoint"]["utime"]
        )
        report = observer.monitor.evaluate(
            policy, value, initial, now=value["source_checkpoint"]["utime"]
        )
        return value, report

    return dict(
        url=url,
        bridge=bridge,
        tokens=tokens,
        accounts=accounts,
        send=send,
        deploy=deploy,
        binding=binding,
        base=base,
        initial=initial,
        policy=policy,
        observe=observe,
    )


def codes(report, asset):
    return {a["code"] for a in report["alarms"] if a["asset"] == asset}


@pytest.mark.parametrize("index", [0, 1])
def test_legacy_sender_only_freeze_is_asset_scoped(world, index):
    # The issuer fixture is legacy-shaped under each policy label; this proves
    # alarm scoping, not a production standard-issuer blacklist implementation.
    w = world
    token = w["tokens"][index]
    w["send"](token, "addBlackList(address)", w["bridge"])
    w["send"](token, "approve(address,uint256)", w["bridge"], 1_000_000)
    w["send"](w["bridge"], "deposit(address,uint256)", token, 1_000_000)
    value, report = w["observe"]()
    assert value["assets"][index]["bridge_balance"] == 501_000_000
    assert "bridge_frozen" in codes(report, ("usdc", "usdt")[index]), "blacklist alarm missing"
    assert "unexplained_decrease" not in codes(report, ("usdc", "usdt")[index])
    assert report["provider_pause_assets"] == [("usdc", "usdt")[index]], (
        "cross-asset emergency pause"
    )
    assert not codes(report, ("usdt", "usdc")[index])


@pytest.mark.parametrize("index", [0, 1])
def test_pause_then_unpause_is_not_lost(world, index):
    w = world
    w["send"](w["tokens"][index], "pause()")
    w["send"](w["tokens"][index], "unpause()")
    value, report = w["observe"]()
    assert value["assets"][index]["paused"] is False
    assert "token_paused" in codes(report, ("usdc", "usdt")[index]), "pause interval event missing"
    assert report["provider_pause_assets"] == [("usdc", "usdt")[index]]


@pytest.mark.parametrize("index", [0, 1])
def test_destroy_without_transfer_has_its_own_alarm(world, index):
    w = world
    token = w["tokens"][index]
    w["send"](token, "addBlackList(address)", w["bridge"])
    receipt = w["send"](token, "destroyBlackFunds(address)", w["bridge"])
    assert len(receipt["logs"]) == 1
    assert receipt["logs"][0]["topics"][0] == observer.TOPICS["DestroyedBlackFunds"]
    _, report = w["observe"]()
    actual = codes(report, ("usdc", "usdt")[index])
    assert {"destroyed_funds", "unexplained_decrease", "backing_shortfall"} <= actual, (
        "destruction/backing alarm missing"
    )
    assert not codes(report, ("usdt", "usdc")[index])


def test_fee_and_legacy_upgrade_are_observed(world):
    w = world
    w["send"](w["tokens"][1], "setParams(uint256,uint256)", 19, 49)
    value, report = w["observe"]()
    assert value["assets"][1]["fee_basis_points"] == 19
    assert value["assets"][1]["maximum_fee"] == 49_000_000
    assert "transfer_fee" in codes(report, "usdt"), "fee alarm missing"
    assert not report["provider_pause_assets"]
    w["send"](w["tokens"][1], "deprecate(address)", w["tokens"][0])
    value, report = w["observe"]()
    assert value["assets"][1]["deprecated"] is True, "deprecation flag lost"
    assert value["assets"][1]["issuer_identity"]["target"] == w["tokens"][0]
    assert "token_upgrade" in codes(report, "usdt"), "legacy upgrade alarm missing"
    assert report["provider_pause_assets"] == ["usdt"], "deprecated asset not paused"


def test_complete_receipts_reconcile_lock_unlock_and_refund(world):
    w = world
    token = w["tokens"][1]
    w["send"](token, "approve(address,uint256)", w["bridge"], 1_000_000)
    w["send"](w["bridge"], "deposit(address,uint256)", token, 1_000_000)
    w["send"](w["bridge"], "payout(address,address,uint256)", token, w["accounts"][1], 100_000)
    w["send"](w["bridge"], "refund(address,address,uint256)", token, w["accounts"][1], 200_000)
    value, report = w["observe"]()
    assert [(e["kind"], e["amount"]) for e in value["assets"][1]["balance_events"]] == [
        ("Lock", 1_000_000),
        ("Unlock", 100_000),
        ("LockRefunded", 200_000),
    ], "bridge event inventory wrong"
    assert not codes(report, "usdt")
    assert value["assets"][1]["bridge_balance"] == 500_700_000


def test_signing_method_refused_before_network():
    rpc = observer.RPC("http://127.0.0.1:1")
    for method in ("eth_sendTransaction", "eth_sendRawTransaction", "eth_sign", "personal_sign"):
        with pytest.raises(observer.Invalid, match="signing or unapproved"):
            rpc.call(method)


def test_rpc_error_makes_existing_report_immediately_stale(tmp_path):
    report, output = tmp_path / "report.json", tmp_path / "snapshot.json"
    observer.monitor.atomic(
        report,
        dict(
            schema="tos-settlement-report/1",
            checkpoint=dict(height=100, hash="a" * 64, utime=int(time.time())),
            provider_pause_assets=[],
        ),
    )
    args = [
        "--rpc",
        "http://127.0.0.1:1",
        "--binding",
        str(tmp_path / "missing.json"),
        "--tos-snapshot",
        str(tmp_path / "tos.json"),
        "--initialize-baseline",
        "--out",
        str(output),
        "--report",
        str(report),
    ]
    assert observer.main(args) == 2
    stale = json.loads(report.read_text())
    assert stale["checkpoint"]["utime"] == 0 and stale["status"] == "STALE", (
        "old healthy monitor survived source failure"
    )
    assert json.loads(output.read_text())["complete"] is False


def test_baseline_hash_mismatch_refuses(world):
    w = world
    bad = copy.deepcopy(w["initial"])
    bad["source_checkpoint"]["hash"] = "f" * 64
    with pytest.raises(observer.Invalid, match="baseline reorg"):
        observer.collect(observer.RPC(w["url"]), w["binding"], w["base"], bad)


def test_contract_code_pin_refuses(world):
    w = world
    bad = copy.deepcopy(w["binding"])
    bad["assets"][1]["code_sha256"] = "0" * 64
    with pytest.raises(observer.Invalid, match="source token code differs"):
        observer.collect(observer.RPC(w["url"]), bad, w["base"], None)


def test_blacklisted_receiver_is_reported(world):
    w = world
    receiver = w["accounts"][1]
    w["binding"]["assets"][1]["redemptions"].append(dict(id="burn-1", receiver=receiver))
    w["base"]["assets"][1]["redemptions"].append(dict(id="burn-1", blacklisted=False))
    w["send"](w["tokens"][1], "addBlackList(address)", receiver)
    value, report = w["observe"]()
    assert value["assets"][1]["redemptions"][0]["blacklisted"] is True
    assert "redemption_blocked" in codes(report, "usdt"), "receiver alarm missing"


def test_fixture_has_capped_owner_paid_fees_and_no_return_approval(world):
    w = world
    token = w["tokens"][1]
    w["send"](token, "setParams(uint256,uint256)", 19, 1)
    w["send"](token, "transfer(address,uint256)", w["accounts"][1], 100_000_000)
    balance = observer.read_uint(
        observer.RPC(w["url"]), token, "balance", "latest", w["accounts"][1]
    )
    assert balance == 99_810_000
    for basis_points, max_fee in ((20, 0), (0, 50)):
        with pytest.raises(AssertionError, match="fee bounds"):
            w["send"](token, "setParams(uint256,uint256)", basis_points, max_fee)
    w["send"](token, "pause()")
    data = "0x095ea7b3" + w["bridge"][2:].rjust(64, "0") + (1).to_bytes(32, "big").hex()
    answer = observer.RPC(w["url"]).call(
        "eth_call", dict(to=token, **{"from": w["accounts"][0]}, data=data), "latest"
    )
    assert answer == "0x", "approval unexpectedly returns a bool or is paused"


def test_log_reply_missing_refuses_instead_of_claiming_complete(world):
    w = world
    w["send"](w["tokens"][1], "pause()")

    class MissingLogs:
        def __init__(self):
            self.inner = observer.RPC(w["url"])

        def call(self, method, *args):
            return None if method == "eth_getLogs" else self.inner.call(method, *args)

    with pytest.raises(observer.Invalid, match="logs missing"):
        observer.collect(MissingLogs(), w["binding"], w["base"], w["initial"])


def test_local_fixture_exception_cannot_hide_a_freezable_token(world):
    w = world
    bad = copy.deepcopy(w["binding"])
    bad["network"] = observer.LOCAL_GENESIS
    base = copy.deepcopy(w["base"])
    base["network"] = observer.LOCAL_GENESIS
    bad["assets"][0]["profile"] = "local_test"
    with pytest.raises(observer.Invalid, match="local fixture profile refused"):
        observer.collect(observer.RPC(w["url"]), bad, base, None)


@pytest.fixture
def standard_world(world):
    w = world
    token = w["deploy"]("StandardObserverFixture")
    w["send"](token, "transfer(address,uint256)", w["bridge"], 500_000_000)
    # Real EIP-1967 slot; the fixture records identity but does not delegate calls.
    w["send"](token, "setImplementation(address)", w["tokens"][0])
    w["tokens"][0] = token
    cfg = w["binding"]["assets"][0]
    cfg.update(
        token=token,
        profile="standard",
        code_sha256=observer.code_hash(observer.RPC(w["url"]), token, "latest"),
        implementation_slot="0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    )
    w["base"]["assets"][0]["source_token"] = token
    w["policy"]["assets"][0]["source_token"] = token
    initial = observer.collect(observer.RPC(w["url"]), w["binding"], w["base"], None)
    initial["checkpoint"]["utime"] = initial["source_checkpoint"]["utime"]
    for pin, entry in zip(w["policy"]["assets"], initial["assets"], strict=True):
        pin["implementation"] = entry["implementation"]
    w["initial"] = initial
    return w


def standard_report(w):
    value = observer.collect(observer.RPC(w["url"]), w["binding"], w["base"], w["initial"])
    value["checkpoint"].update(height=101, hash="d" * 64, utime=value["source_checkpoint"]["utime"])
    return value, observer.monitor.evaluate(
        w["policy"], value, w["initial"], now=value["source_checkpoint"]["utime"]
    )


def test_standard_blacklist_and_pause_are_real_getter_reads(standard_world):
    w = standard_world
    _, healthy = standard_report(w)
    assert not healthy["provider_pause_assets"]
    w["send"](w["tokens"][0], "addBlackList(address)", w["bridge"])
    value, report = standard_report(w)
    assert value["assets"][0]["bridge_blacklisted"] is True
    assert "bridge_frozen" in codes(report, "usdc")
    assert report["provider_pause_assets"] == ["usdc"]
    w["send"](w["tokens"][0], "pause()")
    value, report = standard_report(w)
    assert value["assets"][0]["paused"] is True
    assert "token_paused" in codes(report, "usdc")


def test_standard_implementation_change_is_an_emergency(standard_world):
    w = standard_world
    value, healthy = standard_report(w)
    assert not codes(healthy, "usdc")
    assert (
        value["assets"][0]["issuer_identity"]["target"]
        == w["initial"]["assets"][0]["issuer_identity"]["target"]
    )
    w["send"](w["tokens"][0], "setImplementation(address)", w["bridge"])
    value, report = standard_report(w)
    assert value["assets"][0]["issuer_identity"]["target"] == w["bridge"]
    assert "token_upgrade" in codes(report, "usdc"), "standard upgrade alarm missing"
    assert report["provider_pause_assets"] == ["usdc"], "standard upgrade did not pause"
