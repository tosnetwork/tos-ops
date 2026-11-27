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


def test_reverted_source_is_archived_and_stops_the_next_send(tmp_path):
    source = Source()
    source.receipt["status"] = "0x0"
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
    with pytest.raises(m.u.Refused, match="source transaction reverted"):
        state.put_intent("deployment", record)
    assert (tmp_path / "source-transactions/deployment.json").exists()
    assert (tmp_path / "source-finality/deployment.json").exists()


def test_mint_requires_a_finalized_namespace_before_any_send(tmp_path):
    state = m.EvidenceState(tmp_path, Source())
    state.set("namespace", {"source_finalized": False, "token": "0x" + "11" * 20})

    class NoSource:
        def code(self, token):
            pytest.fail("unfinalized namespace reached source")

    with pytest.raises(m.u.Refused, match="namespace must finalize first"):
        m.mint(SimpleNamespace(execute=True), state, NoSource(), {}, None, {})


def test_raw_rpc_stack_is_normalized_once_for_all_getters():
    import base64

    point = {
        "workchain": -1,
        "shard": str(-(2**63)),
        "seqno": 7,
        "root_hash": base64.b64encode(bytes(32)).decode(),
        "file_hash": base64.b64encode(bytes(32)).decode(),
    }

    class Chain:
        def call(self, rpc_method, **params):
            assert rpc_method == "runGetMethod" and params["seqno"] == 7
            return {
                "block_id": point,
                "exit_code": 0,
                "stack": [["num", "0"], ["num", "25000000"]],
            }

    view = m.View.__new__(m.View)
    view.chain, view.urls, view.point = Chain(), ["a", "b", "c"], point
    values = view.read("runGetMethod", address="actor", method="get_supply_state")
    assert all(v["stack"] == [["num", "25000000"], ["num", "0"]] for v in values), (
        "raw stack was not normalized"
    )


def test_governance_archive_recovers_settled_record_before_next_action(
    tmp_path, monkeypatch
):
    import contextlib

    gov = m.u.governance_module()
    records = []

    class Journal:
        def lock(self):
            return contextlib.nullcontext()

        def all(self):
            return list(records)

    operations = SimpleNamespace(journal=Journal())
    journal = m.archive.StepJournal(tmp_path / "archive")
    urls = ["node-4", "node-5", "node-6"]
    genesis = {"root": "11" * 32, "file": "22" * 32}
    gov.recover_governance_archive_locked(journal, urls, genesis, operations)
    r = {
        "id": "vote-a",
        "kind": "config-vote",
        "state": "settled",
        "wallet": "-1:" + "33" * 32,
        "evidence": {"wallet_tx": "44" * 32, "wallet_tx_lt": "1"},
    }
    records.append(r)
    phases = []

    class Capture:
        def checkpoint(self):
            return None

        def __init__(self, folder, references, identity):
            assert references == urls and identity == genesis
            self.folder = folder

        def capture_wait(self, roots):
            assert roots[0]["lt"] == 1
            phases.append("archive")
            m.archive.sync_write(self.folder / "tx.boc", b"public-cell")
            return {
                "files": [
                    {"file": "tx.boc", "sha256": m.archive.digest(b"public-cell")}
                ]
            }

    monkeypatch.setattr(gov.archive, "TransactionArchive", Capture)
    gov.recover_governance_archive_locked(journal, urls, genesis, operations)
    phases.append("next-action")
    assert phases == ["archive", "next-action"], (
        "settled operation was skipped before next action"
    )
    assert len(journal.read()["completed"]) == 1
    gov.recover_governance_archive_locked(journal, urls, genesis, operations)
    assert phases == ["archive", "next-action"]


def test_governance_existing_record_bytes_share_the_driver_decoder():
    gov = m.u.governance_module()
    old = f.value({1: f.record(), 2: f.record()})
    new = f.value({1: f.record(), 2: f.record(), 3: f.record(token="ee" * 20)})
    change = gov.settlement_assets_change(
        gov.decode_settlement_assets(old), gov.decode_settlement_assets(new)
    )
    assert gov.preserve_settlement_records(old, new, change) == m.check_preserved(
        old, new
    )


def test_governance_raw_preservation_refuses_a_changed_unselected_value():
    gov = m.u.governance_module()
    old = f.value({1: f.record(), 2: f.record()})
    changed = f.value(
        {1: f.record(status=2), 2: f.record(), 3: f.record(token="ee" * 20)}
    )
    with pytest.raises(m.u.lib.TestnetError, match="untouched settlement record"):
        gov.preserve_settlement_records(old, changed, {"master": f"{3:064x}"})


def test_each_governance_send_archives_before_return(tmp_path, monkeypatch):
    import contextlib

    gov = m.u.governance_module()
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir()
    (ceremony / "genesis.json").write_text(
        json.dumps(
            {
                "zero_state": {
                    "root_hash": "ERERERERERERERERERERERERERERERERERERERERERE=",
                    "file_hash": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=",
                }
            }
        )
    )
    args = SimpleNamespace(
        evidence_dir=tmp_path / "archive",
        archive_rpc=["node4", "node5", "node6"],
        ceremony=ceremony,
        payer_addr="unused",
        payer_subwallet=1,
    )
    records = []
    phases = []

    class Journal:
        def lock(self):
            return contextlib.nullcontext()

        def all(self):
            return list(records)

    class Operations:
        journal = Journal()

        def run(self, op_id, params, *rest):
            phases.append("send-" + op_id)
            r = dict(
                params,
                id=op_id,
                state="settled",
                evidence={
                    "wallet_tx": "44" * 32,
                    "wallet_tx_lt": str(len(records) + 1),
                },
            )
            records.append(r)
            return r

    class Capture:
        def checkpoint(self):
            return None

        def __init__(self, folder, *rest):
            self.folder = folder

        def capture_wait(self, roots):
            phases.append("archive-" + str(roots[0]["lt"]))
            m.archive.sync_write(self.folder / "tx.boc", b"public-cell")
            return {
                "files": [
                    {"file": "tx.boc", "sha256": m.archive.digest(b"public-cell")}
                ]
            }

    monkeypatch.setattr(gov.archive, "TransactionArchive", Capture)
    monkeypatch.setattr(
        gov.elections, "address_from_file", lambda path: "-1:" + "33" * 32
    )
    monkeypatch.setattr(gov, "payer_signer", lambda *args: None)
    operations = Operations()
    for label in ["a", "b"]:
        gov.send(
            args,
            operations,
            3,
            label,
            label,
            "config-vote",
            1,
            m.u.Builder().uint(1, 1).end(),
            None,
        )
    assert phases == ["send-a", "archive-1", "send-b", "archive-2"], (
        "governance send returned before archival"
    )


def monitor_case():
    expected = {"usdc": ("master-c", "token-c"), "usdt": ("master-t", "token-t")}
    policy = {
        "network": m.GENESIS["root"],
        "assets": [
            {"id": k, "master": v[0], "source_token": v[1]} for k, v in expected.items()
        ],
    }
    report = {
        "schema": "tos-settlement-report/1",
        "checkpoint": {"height": 7, "utime": 1000},
        "provider_pause_assets": [],
        "alarms": [],
    }
    return expected, policy, report


def test_monitor_gate_requires_this_namespace_not_just_freshness():
    expected, policy, report = monitor_case()
    m.monitor_gate(policy, report, expected, {"seqno": 7}, 1000)
    policy["assets"][1]["source_token"] = "foreign-token"
    with pytest.raises(m.u.Refused, match="monitor assets differ"):
        m.monitor_gate(policy, report, expected, {"seqno": 7}, 1000)


@pytest.mark.parametrize("mode", ["stale", "future-height", "alarm", "network"])
def test_governance_monitor_holds(mode):
    expected, policy, report = monitor_case()
    if mode == "stale":
        report["checkpoint"]["utime"] = 1
    elif mode == "future-height":
        report["checkpoint"]["height"] = 8
    elif mode == "alarm":
        report["provider_pause_assets"] = ["usdt"]
    else:
        policy["network"] = "ff" * 32
    with pytest.raises(m.u.Refused, match="monitor"):
        m.monitor_gate(policy, report, expected, {"seqno": 7}, 1000)
