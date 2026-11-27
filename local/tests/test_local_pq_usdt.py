"""Second-asset namespace and byte-preserving recognition controls."""

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load(
    "local_usdt",
    Path(os.environ.get("TOS_USDT_DRIVER", ROOT / "local/scripts/local-pq-usdt.py")),
)
f = load("cp84_cases", ROOT / "testnet/tests/test_governance_settlement_assets.py")


def test_append_preserves_every_old_value_cell():
    old = f.value({1: f.record(), 2: f.record()})
    new = f.value({1: f.record(), 2: f.record(), 3: f.record(token="ee" * 20)})
    result = m.check_append(old, new)
    assert result["entries"] == 3 and len(result["preserved"]) == 2
    assert result["validation_visits"] <= 1024
    for key, payload in m.record_cells(old).items():
        assert m.record_cells(new)[key] == payload


@pytest.mark.parametrize("change", ["remove", "status", "origin"])
def test_existing_value_cannot_change(change):
    old = f.value({1: f.record(), 2: f.record()})
    entries = {1: f.record(), 2: f.record(), 3: f.record(token="ee" * 20)}
    if change == "remove":
        del entries[1]
    elif change == "status":
        entries[1] = f.record(status=2)
    else:
        entries[1] = f.record(token="ff" * 20)
    with pytest.raises(m.u.Refused, match="value cells changed"):
        m.check_preserved(old, f.value(entries))


def test_seventeenth_entry_is_refused():
    old = f.value({i: f.record() for i in range(16)})
    with pytest.raises(m.u.lib.TestnetError, match="16"):
        m.check_append(old, f.value({i: f.record() for i in range(17)}))


def test_stale_build_log_cannot_authorize_deployment(tmp_path):
    import hashlib

    source = hashlib.sha256(m.SOURCE.read_bytes()).hexdigest()
    artifact = {
        "contractName": "LocalUSDT",
        "source_sha256": source,
        "compiler": "pinned",
        "bytecode": "0x01",
        "deployedBytecode": "0x02",
    }
    path, log = tmp_path / "artifact", tmp_path / "log"
    path.write_text(json.dumps(artifact))
    log.write_text(
        json.dumps({"source_sha256": "00" * 32, "compiler": "pinned"}) + "\nEXIT 0\n"
    )
    with pytest.raises(m.u.Refused, match="build log"):
        m.artifact_at(path, log)


class Source:
    def __init__(self):
        self.hash = "0x" + "aa" * 32
        self.sender = "0x" + "bb" * 20
        self.tx = dict(
            hash=self.hash,
            **{"from": self.sender},
            nonce="0x0",
            to=None,
            input="0x1234",
            value="0x0",
            blockHash="0x" + "cc" * 32,
        )
        self.receipt = {
            "transactionHash": self.hash,
            "blockHash": self.tx["blockHash"],
            "blockNumber": "0x1",
            "status": "0x1",
        }
        self.header = {"hash": self.tx["blockHash"], "number": "0x1"}

    def rpc(self, method, *args):
        return {
            "eth_getTransactionByHash": self.tx,
            "eth_getTransactionReceipt": self.receipt,
            "eth_getBlockByNumber": self.header,
        }[method]


def test_source_archive_precedes_the_next_send(tmp_path, monkeypatch):
    source = Source()
    state = m.EvidenceState(tmp_path, source)
    record = dict(
        kind="evm",
        state="done",
        tx=source.hash,
        **{"from": source.sender},
        nonce=0,
        to=None,
        data="0x1234",
    )
    phases = []
    original = m.archive.document

    def write(path, value):
        original(path, value)
        phases.append(path.parent.name)

    monkeypatch.setattr(m.archive, "document", write)
    state.put_intent("deployment", record)
    phases.append("next-send")
    assert phases == ["source-transactions", "source-finality", "next-send"], (
        "evidence did not precede next send"
    )
    assert (tmp_path / "source-transactions/deployment.json").exists()
    assert (tmp_path / "source-finality/deployment.json").exists()


def test_source_mismatch_never_counts_as_done_evidence(tmp_path):
    source = Source()
    state = m.EvidenceState(tmp_path, source)
    record = dict(
        kind="evm",
        state="done",
        tx=source.hash,
        **{"from": source.sender},
        nonce=1,
        to=None,
        data="0x1234",
    )
    with pytest.raises(m.u.Refused, match="differs from intent"):
        state.put_intent("deployment", record)
    assert not (tmp_path / "source-finality/deployment.json").exists()


def test_namespace_dry_run_has_no_broadcast_or_record(tmp_path):
    class EVM:
        def chain_id(self):
            return 1

        def code(self, address):
            return "0x01"

        def abi_encode(self, *args):
            return "0x" + "00" * 32

        def nonce(self, sender):
            return 0

        def rpc(self, method, *args):
            assert method in ("eth_getTransactionCount", "eth_estimateGas"), (
                "dry-run broadcast"
            )
            return "0x0" if method == "eth_getTransactionCount" else "0x100"

    state = m.u.State(tmp_path)
    result = m.namespace(
        SimpleNamespace(execute=False),
        state,
        EVM(),
        {"evm": {"deployer": "0x" + "11" * 20, "bridge": "0x" + "22" * 20}},
        {"bytecode": "0x01", "source_sha256": "00" * 32},
    )
    assert result["dry_run"] and not state.path.exists()
