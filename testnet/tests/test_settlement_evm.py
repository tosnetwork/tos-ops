"""Read-only method boundary, stale-report publication and interval bounds."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

SCRIPT = Path(
    os.environ.get(
        "TOS_SETTLEMENT_COLLECTOR",
        Path(__file__).resolve().parents[1] / "scripts/collect-settlement-evm.py",
    )
)
SPEC = importlib.util.spec_from_file_location("source_collector_unit", SCRIPT)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def test_signing_rpc_never_reaches_transport(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("signing method reached network")

    monkeypatch.setattr(collector.urllib.request, "urlopen", forbidden)
    rpc = collector.RPC("http://127.0.0.1:1")
    for method in (
        "eth_sendTransaction",
        "eth_sendRawTransaction",
        "eth_sign",
        "personal_sign",
        "anvil_setStorageAt",
    ):
        with pytest.raises(collector.Invalid, match="signing or unapproved"):
            rpc.call(method)


def test_rpc_failure_stales_report_before_reuse(tmp_path, monkeypatch):
    report, output = tmp_path / "report.json", tmp_path / "snapshot.json"
    binding, tos = tmp_path / "binding.json", tmp_path / "tos.json"
    collector.monitor.atomic(
        report,
        dict(
            schema="tos-settlement-report/1",
            checkpoint=dict(height=100, hash="a" * 64, utime=2_000_000_000),
            provider_pause_assets=[],
        ),
    )
    collector.monitor.atomic(
        binding, dict(schema="tos-settlement-source/1", network="a" * 64, chain_id=1)
    )
    collector.monitor.atomic(tos, dict(complete=True, network="a" * 64))

    class BrokenRPC:
        def call(self, *args):
            raise OSError("unavailable")

    monkeypatch.setattr(collector, "RPC", lambda url: BrokenRPC())
    args = [
        "--rpc",
        "http://127.0.0.1:1",
        "--binding",
        str(binding),
        "--tos-snapshot",
        str(tos),
        "--initialize-baseline",
        "--out",
        str(output),
        "--report",
        str(report),
    ]
    assert collector.main(args) == 2
    stale = json.loads(report.read_text())
    assert stale["checkpoint"]["utime"] == 0 and stale["status"] == "STALE", (
        "old healthy monitor survived source failure"
    )
    assert json.loads(output.read_text())["complete"] is False


def test_interval_bound_is_checked_before_rpc():
    class NoRPC:
        def call(self, *args):
            pytest.fail("oversized interval reached RPC")

    with pytest.raises(collector.Invalid, match="block bound"):
        collector.receipts(
            NoRPC(), dict(height=0, hash="a" * 64), dict(number=hex(collector.MAX_BLOCKS + 1))
        )


@pytest.mark.parametrize("value", [True, -1, "0x00", "0x", "1", "0x" + "f" * 65])
def test_rpc_quantities_are_bounded_and_canonical(value):
    with pytest.raises(collector.Invalid, match="quantity"):
        collector.quantity(value)


class SourceRPC:
    """Complete small source response, with every finalized read recorded."""

    url = "http://127.0.0.1:1"
    token = "0x" + "11" * 20
    bridge = "0x" + "22" * 20
    point_hash = "0x" + "33" * 32

    def __init__(self, *, paused=0):
        self.calls = []
        self.paused = paused

    def call(self, method, *args):
        self.calls.append((method, args))
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_getBlockByNumber":
            return dict(
                number="0x1",
                hash=self.point_hash,
                parentHash="0x" + "00" * 32,
                timestamp="0x10",
                transactions=[],
            )
        if method == "eth_getCode":
            return "0x01"
        if method == "eth_getStorageAt":
            return "0x" + (1).to_bytes(32, "big").hex()
        if method == "eth_call":
            selector = args[0]["data"][2:10]
            values = {
                collector.SELECTORS["balance"]: [100],
                collector.SELECTORS["blacklist_standard"]: [1],
                collector.SELECTORS["paused"]: [self.paused],
                collector.SELECTORS["caps"]: [1000, 100, 200, 500, 0, 0, 100],
            }[selector]
            return "0x" + b"".join(value.to_bytes(32, "big") for value in values).hex()
        raise AssertionError("unexpected source method")


def standard_inputs():
    import hashlib

    rpc = SourceRPC()
    code = hashlib.sha256(b"\x01").hexdigest()
    binding = dict(
        schema="tos-settlement-source/1",
        network="a" * 64,
        chain_id=1,
        bridge=rpc.bridge,
        bridge_code_sha256=code,
        assets=[
            dict(
                id="usdc",
                token=rpc.token,
                code_sha256=code,
                profile="standard",
                implementation_slot="0x" + "00" * 32,
                redemptions=[],
            )
        ],
    )
    base = dict(
        complete=True,
        network="a" * 64,
        assets=[dict(id="usdc", source_token=rpc.token, redemptions=[])],
    )
    return binding, base


def test_standard_issuer_uses_blacklist_and_pinned_implementation_slot():
    rpc = SourceRPC()
    binding, base = standard_inputs()
    value = collector.collect(rpc, binding, base, None)
    entry = value["assets"][0]
    assert entry["bridge_blacklisted"] is True and entry["paused"] is False
    assert entry["issuer_identity"]["target"] == "0x" + "00" * 19 + "01"
    assert len(entry["implementation"]) == 71
    assert entry["lock_cap"]["available"] == 100
    for method, args in rpc.calls:
        if method in ("eth_call", "eth_getCode", "eth_getStorageAt"):
            assert args[-1] == dict(blockHash=rpc.point_hash, requireCanonical=True), (
                "source read escaped canonical checkpoint"
            )


def test_noncanonical_boolean_is_never_a_healthy_flag():
    binding, base = standard_inputs()
    with pytest.raises(collector.Invalid, match="noncanonical source boolean"):
        collector.collect(SourceRPC(paused=2), binding, base, None)


def test_invalid_output_alias_never_overwrites_inputs(tmp_path):
    source = tmp_path / "source.json"
    source.write_text('{"sentinel": true}\n')
    before = source.read_bytes()
    result = collector.main(
        [
            "--rpc",
            "http://127.0.0.1:1",
            "--binding",
            str(source),
            "--tos-snapshot",
            str(source),
            "--initialize-baseline",
            "--out",
            str(source),
            "--report",
            str(tmp_path / "report.json"),
        ]
    )
    assert result == 2 and source.read_bytes() == before


def test_report_is_stale_before_any_rpc_can_block(tmp_path, monkeypatch):
    report, output = tmp_path / "report.json", tmp_path / "out.json"
    binding, tos = tmp_path / "binding.json", tmp_path / "tos.json"
    collector.monitor.atomic(report, dict(checkpoint=dict(utime=2_000_000_000)))
    collector.monitor.atomic(
        binding, dict(schema="tos-settlement-source/1", network="a" * 64, chain_id=1)
    )
    collector.monitor.atomic(tos, dict(network="a" * 64, complete=True))

    class BlockingRPC:
        def call(self, *args):
            assert json.loads(report.read_text())["checkpoint"]["utime"] == 0, (
                "healthy report survived until blocking RPC"
            )
            raise OSError("network unavailable")

    monkeypatch.setattr(collector, "RPC", lambda url: BlockingRPC())
    assert (
        collector.main(
            [
                "--rpc",
                "http://127.0.0.1:1",
                "--binding",
                str(binding),
                "--tos-snapshot",
                str(tos),
                "--initialize-baseline",
                "--out",
                str(output),
                "--report",
                str(report),
            ]
        )
        == 2
    )


@pytest.mark.parametrize(
    "reply",
    [
        b"[]",
        b"true",
        b"{}",
        b'{"jsonrpc":"2.0","id":true,"result":"0x1"}',
        b'{"jsonrpc":"2.0","id":1,"error":null,"result":"0x1"}',
        b'{"jsonrpc":"2.0","id":1,"id":1,"result":"0x1"}',
    ],
)
def test_malformed_rpc_answers_refuse_without_healthy_defaults(monkeypatch, reply):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            return reply

    monkeypatch.setattr(collector.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    with pytest.raises(collector.Invalid):
        collector.RPC("http://127.0.0.1:1").call("eth_chainId")


def test_local_fixture_pin_is_copied_from_checkpoint_evidence():
    import hashlib

    pin = json.loads(
        (Path(__file__).parent / "data/settlement-source/local-usdc-code.json").read_text()
    )
    assert pin["scope"] == "local-development-only"
    assert pin["tos_zero_state_root"] == collector.LOCAL_GENESIS
    assert (
        hashlib.sha256(bytes.fromhex(pin["runtime_code"][2:])).hexdigest()
        == collector.LOCAL_TEST_CODE
        == pin["runtime_sha256"]
    )
    assert pin["source_chain_id"] == 1 and pin["source_file"].endswith("/TestFeeToken.sol")


def test_receipt_inventory_has_an_aggregate_byte_bound(monkeypatch):
    prior, target_hash, tx_hash = "0x" + "11" * 32, "0x" + "22" * 32, "0x" + "33" * 32
    target = dict(
        number="0x1", hash=target_hash, parentHash=prior, timestamp="0x1", transactions=[tx_hash]
    )

    class LogRPC:
        def call(self, method, *args):
            if method == "eth_getBlockByNumber":
                return (
                    target
                    if args[0] == "0x1"
                    else dict(
                        number="0x0",
                        hash=prior,
                        parentHash="0x" + "00" * 32,
                        timestamp="0x0",
                        transactions=[],
                    )
                )
            return dict(
                transactionHash=tx_hash,
                blockHash=target_hash,
                blockNumber="0x1",
                transactionIndex="0x0",
                status="0x1",
                logs=[
                    dict(
                        address="0x" + "44" * 20,
                        topics=[],
                        data="0x" + "00" * 32,
                        transactionHash=tx_hash,
                        blockHash=target_hash,
                        blockNumber="0x1",
                        transactionIndex="0x0",
                        logIndex="0x0",
                        removed=False,
                    )
                ],
            )

    monkeypatch.setattr(collector, "MAX_LOG_BYTES", 16)
    with pytest.raises(collector.Invalid, match="log byte budget"):
        collector.receipts(LogRPC(), dict(height=0, hash=prior[2:]), target)
