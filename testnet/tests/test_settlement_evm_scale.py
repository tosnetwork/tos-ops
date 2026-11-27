"""Scale and recovery are endpoint observations, not log completeness proofs."""

import copy
import importlib.util
import json
import os
from pathlib import Path

import pytest
from test_settlement_evm import SourceRPC, collector, standard_inputs

SPEC = importlib.util.spec_from_file_location(
    "gap_reconciler",
    Path(
        os.environ.get(
            "TOS_SETTLEMENT_GAP", Path(__file__).parents[1] / "scripts/reconcile-settlement-gap.py"
        )
    ),
)
gap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gap)
gap.collector = collector


class VolumeRPC(SourceRPC):
    def __init__(self, height=1, transactions=6001):
        super().__init__()
        self.height = height
        self.transactions = transactions
        self.fault = None
        self.events = False

    @staticmethod
    def hash(height):
        return "0x" + (height + 1).to_bytes(32, "big").hex()

    def call(self, method, *args):
        self.calls.append((method, args))
        if method == "eth_getBlockByNumber":
            height = self.height if args[0] == "finalized" else int(args[0], 16)
            value = dict(
                number=hex(height),
                hash=self.hash(height),
                parentHash=self.hash(max(0, height - 1)),
                timestamp="0x10",
                transactions=[self.hash(10000 + i) for i in range(self.transactions)],
            )
            if height == 2 and self.fault == "parent":
                value["parentHash"] = self.hash(500)
            return value
        if method == "eth_getLogs":
            assert set(args[0]) == {"blockHash", "address"}, "log query lost hash filter"
            height = int(args[0]["blockHash"], 16) - 1
            assert args[0] == dict(
                blockHash=self.hash(height), address=sorted([self.bridge, self.token])
            )
            if self.fault == "missing":
                return None
            value = dict(
                address=self.token,
                topics=[],
                data="0x",
                blockHash=self.hash(height),
                blockNumber=hex(height),
                transactionHash=self.hash(10000),
                transactionIndex="0x0",
                logIndex="0x2",
                removed=False,
            )
            if self.events and height in (1, 80):
                value.update(
                    address=self.bridge,
                    topics=[
                        collector.TOPICS["Lock"],
                        self.hash(5),
                        "0x" + self.token[2:].rjust(64, "0"),
                        self.hash(6),
                    ],
                    data="0x" + b"".join(v.to_bytes(32, "big") for v in (7, 0, 6, 1, 1)).hex(),
                )
            if self.fault in ("blockHash", "transactionHash", "address"):
                value[self.fault] = self.hash(900) if self.fault != "address" else "0x" + "99" * 20
            if self.fault == "blockNumber":
                value["blockNumber"] = "0x999"
            if self.fault == "transactionIndex":
                value["transactionIndex"] = hex(self.transactions)
            if self.fault == "removed":
                value["removed"] = True
            if self.fault == "topics":
                value["topics"] = [self.hash(1)] * 5
            if self.fault == "data":
                value["data"] = "0x0"
            if self.fault == "duplicate":
                return [value, value]
            return [value]
        # Don't double-count the recorded generic calls.
        self.calls.pop()
        return super().call(method, *args)


def scan(rpc, target=None):
    return collector.block_logs(
        rpc,
        dict(height=0, hash=rpc.hash(0)[2:]),
        target or rpc.call("eth_getBlockByNumber", hex(rpc.height), False),
        [rpc.bridge, rpc.token],
    )


def test_six_thousand_transactions_use_one_log_query_not_receipts():
    rpc = VolumeRPC()
    assert len(scan(rpc)) == 1
    assert sum(m == "eth_getLogs" for m, _ in rpc.calls) == 1
    assert not any(m == "eth_getTransactionReceipt" for m, _ in rpc.calls)


def test_filtered_block_global_indices_may_have_gaps():
    rpc = VolumeRPC()
    assert scan(rpc)[0]["logIndex"] == "0x2"


@pytest.mark.parametrize(
    "fault,reason",
    [
        ("parent", "not contiguous"),
        ("missing", "logs missing"),
        ("blockHash", "identity"),
        ("blockNumber", "identity"),
        ("removed", "identity"),
        ("transactionIndex", "transaction index"),
        ("transactionHash", "transaction differs"),
        ("address", "address filter"),
        ("duplicate", "order or duplicate"),
        ("topics", "topic bound"),
        ("data", "RPC bytes"),
    ],
)
def test_block_log_refusals(fault, reason):
    rpc = VolumeRPC(height=2)
    rpc.fault = fault
    with pytest.raises(collector.Invalid, match=reason):
        scan(rpc)


@pytest.mark.parametrize(
    "name,value,reason",
    [
        ("MAX_BLOCK_LOGS", 0, "per-block log bound"),
        ("MAX_BLOCK_LOG_BYTES", 0, "per-block log byte"),
        ("MAX_LOGS", 0, "aggregate bound"),
        ("MAX_LOG_BYTES", 0, "aggregate bound"),
    ],
)
def test_each_log_budget_refuses(monkeypatch, name, value, reason):
    monkeypatch.setattr(collector, name, value)
    with pytest.raises(collector.Invalid, match=reason):
        scan(VolumeRPC())


def test_gap_batches_catch_up_without_changing_the_baseline(tmp_path):
    tmp_path.chmod(0o700)
    rpc = VolumeRPC(height=130, transactions=1)
    binding, base = standard_inputs()
    previous = dict(network=base["network"], source_checkpoint=dict(height=0, hash=rpc.hash(0)[2:]))
    rpc.events = True
    untouched = copy.deepcopy(previous)
    with pytest.raises(collector.Invalid, match="block bound"):
        collector.collect(rpc, binding, base, previous)
    heights = []
    for _ in range(5):
        progress = gap.append_batch(rpc, binding, previous, tmp_path)
        heights.append(progress["checkpoint"]["height"])
    assert heights == [32, 64, 96, 128, 130]
    assert progress["caught_up"] is True
    assert previous == untouched
    result = collector.collect(rpc, binding, base, previous, tmp_path)
    assert result["source_checkpoint"]["height"] == 130
    assert result["assets"][0]["balance_from_hash"] == previous["source_checkpoint"]["hash"]
    assert [e["amount"] for e in result["assets"][0]["balance_events"]] == [7, 7], (
        "gap events were dropped"
    )
    assert len(list(tmp_path.iterdir())) == 5


def test_bad_block_in_gap_never_advances_archive(tmp_path):
    tmp_path.chmod(0o700)
    rpc = VolumeRPC(height=130, transactions=1)
    binding, base = standard_inputs()
    previous = dict(network=base["network"], source_checkpoint=dict(height=0, hash=rpc.hash(0)[2:]))
    rpc.fault = "parent"
    with pytest.raises(collector.Invalid, match="not contiguous"):
        gap.append_batch(rpc, binding, previous, tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("field", ["binding", "from", "previous_sha256", "origin"])
def test_gap_archive_cannot_skip_or_substitute_a_batch(tmp_path, field):
    tmp_path.chmod(0o700)
    rpc = VolumeRPC(height=65, transactions=1)
    binding, base = standard_inputs()
    previous = dict(network=base["network"], source_checkpoint=dict(height=0, hash=rpc.hash(0)[2:]))
    gap.append_batch(rpc, binding, previous, tmp_path)
    path = tmp_path / "000000.json"
    batch = json.loads(path.read_text())
    batch[field] = "bad"
    path.write_text(json.dumps(batch))
    with pytest.raises(collector.Invalid, match="binding or continuity"):
        gap.append_batch(rpc, binding, previous, tmp_path)


def test_gap_requires_original_previous_and_refuses_missing_batch(tmp_path):
    tmp_path.chmod(0o700)
    rpc = VolumeRPC(height=33, transactions=1)
    binding, base = standard_inputs()
    previous = dict(network=base["network"], source_checkpoint=dict(height=0, hash=rpc.hash(0)[2:]))
    gap.append_batch(rpc, binding, previous, tmp_path)
    (tmp_path / "000000.json").rename(tmp_path / "000001.json")
    with pytest.raises(collector.Invalid, match="inventory"):
        collector.collect(rpc, binding, base, previous, tmp_path)
    with pytest.raises(collector.Invalid, match="approved previous"):
        collector.collect(rpc, binding, base, None, tmp_path)


def test_baseline_number_and_target_hash_refuse():
    class WrongBaseline(VolumeRPC):
        def call(self, method, *args):
            value = super().call(method, *args)
            if method == "eth_getBlockByNumber" and args[0] == "0x0":
                value["number"] = "0x1"
            return value

    with pytest.raises(collector.Invalid, match="baseline number"):
        scan(WrongBaseline())
    rpc = VolumeRPC()
    target = rpc.call("eth_getBlockByNumber", "0x1", False)
    target["hash"] = rpc.hash(9)
    with pytest.raises(collector.Invalid, match="target changed"):
        scan(rpc, target)


def test_empty_filtered_blocks_are_checked_and_allowed():
    class Empty(VolumeRPC):
        def call(self, method, *args):
            if method == "eth_getLogs":
                self.calls.append((method, args))
                return []
            return super().call(method, *args)

    rpc = Empty(height=32)
    assert scan(rpc) == []
    assert sum(m == "eth_getLogs" for m, _ in rpc.calls) == 32


def test_one_step_of_32_busy_blocks_has_bounded_rpc_volume():
    rpc = VolumeRPC(height=32, transactions=6001)
    assert len(scan(rpc)) == 32
    assert len(rpc.calls) == 66


def test_gap_height_and_count_and_bytes_are_bounded(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    rpc = VolumeRPC(height=65, transactions=1)
    binding, base = standard_inputs()
    previous = dict(network=base["network"], source_checkpoint=dict(height=0, hash=rpc.hash(0)[2:]))
    gap.append_batch(rpc, binding, previous, tmp_path)
    path = tmp_path / "000000.json"
    original = path.read_bytes()
    batch = json.loads(original)
    batch["to"]["height"] = 33
    path.write_text(json.dumps(batch))
    with pytest.raises(collector.Invalid, match="height bound"):
        collector.gap_history(tmp_path, binding, previous["source_checkpoint"])
    path.write_bytes(original)
    with monkeypatch.context() as m:
        m.setattr(collector, "MAX_GAP_BATCHES", 0)
        with pytest.raises(collector.Invalid, match="batch bound"):
            collector.gap_history(tmp_path, binding, previous["source_checkpoint"])
    with monkeypatch.context() as m:
        m.setattr(collector.monitor, "MAX_BYTES", 1)
        with pytest.raises(collector.Invalid, match="file bound"):
            collector.gap_history(tmp_path, binding, previous["source_checkpoint"])
    with monkeypatch.context() as m:
        m.setattr(collector, "MAX_LOGS", 0)
        with pytest.raises(collector.Invalid, match="log bound"):
            collector.gap_history(tmp_path, binding, previous["source_checkpoint"])
    with monkeypatch.context() as m:
        m.setattr(collector, "MAX_LOG_BYTES", 1)
        with pytest.raises(collector.Invalid, match="retained log byte"):
            collector.gap_history(tmp_path, binding, previous["source_checkpoint"])


def test_gap_cli_never_publishes_health_or_changes_previous(tmp_path, monkeypatch):
    state, archive = tmp_path / "state", tmp_path / "gap"
    state.mkdir(mode=0o700)
    binding, base = standard_inputs()
    rpc = VolumeRPC(height=65, transactions=1)
    previous = dict(network=base["network"], source_checkpoint=dict(height=0, hash=rpc.hash(0)[2:]))
    binding_path = tmp_path / "binding"
    collector.monitor.atomic(binding_path, binding)
    collector.monitor.atomic(state / "previous.json", previous)
    collector.monitor.atomic(state / "report.json", dict(status="HEALTHY"))
    before = (state / "previous.json").read_bytes()
    monkeypatch.setattr(collector, "RPC", lambda url: rpc)
    args = [
        "--rpc",
        rpc.url,
        "--binding",
        str(binding_path),
        "--state-dir",
        str(state),
        "--gap-dir",
        str(archive),
    ]
    assert gap.main(args) == 0
    assert collector.monitor.read_json(state / "report.json")["status"] == "STALE"
    assert (state / "previous.json").read_bytes() == before
    assert len(list(archive.iterdir())) == 1
    rpc.fault = "missing"
    assert gap.main(args) == 2
    assert len(list(archive.iterdir())) == 1
    assert (state / "previous.json").read_bytes() == before
    assert collector.monitor.read_json(state / "report.json")["status"] == "STALE"


@pytest.mark.parametrize(
    "fault,reason",
    [
        ("network", "network differs"),
        ("chain", "chain differs"),
        ("checkpoint", "checkpoint reorg"),
        ("final", "finalized reorg"),
        ("size", "batch size bound"),
    ],
)
def test_gap_own_guards_refuse_without_writing(tmp_path, fault, reason):
    tmp_path.chmod(0o700)

    class Reorg(VolumeRPC):
        def __init__(self):
            super().__init__(height=65, transactions=1)
            self.reads = {}

        def call(self, method, *args):
            value = super().call(method, *args)
            if method == "eth_getBlockByNumber":
                key = args[0]
                self.reads[key] = self.reads.get(key, 0) + 1
                if (fault == "checkpoint" and key == "0x20" and self.reads[key] == 3) or (
                    fault == "final" and key == "0x41"
                ):
                    value["hash"] = self.hash(900)
            return value

    rpc = Reorg()
    binding, base = standard_inputs()
    previous = dict(network=base["network"], source_checkpoint=dict(height=0, hash=rpc.hash(0)[2:]))
    if fault == "network":
        previous["network"] = "b" * 64
    if fault == "chain":
        binding["chain_id"] = 2
    with pytest.raises(collector.Invalid, match=reason):
        gap.append_batch(rpc, binding, previous, tmp_path, blocks=0 if fault == "size" else 32)
    assert not list(tmp_path.iterdir())


def test_recovery_obeys_monitor_lock(tmp_path, monkeypatch):
    import fcntl

    state = tmp_path / "state"
    state.mkdir(mode=0o700)

    def forbidden(*args):
        pytest.fail("lock conflict reached RPC")

    monkeypatch.setattr(collector, "RPC", forbidden)
    with (state / "monitor.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert (
            gap.main(
                [
                    "--rpc",
                    SourceRPC.url,
                    "--binding",
                    str(tmp_path / "absent"),
                    "--state-dir",
                    str(state),
                    "--gap-dir",
                    str(tmp_path / "gap"),
                ]
            )
            == 2
        )
    assert not (tmp_path / "gap").exists()
