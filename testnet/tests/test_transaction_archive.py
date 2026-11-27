"""A next operation is fenced by durable, independently checked evidence."""

import base64
import json
from pathlib import Path

import pytest
import transaction_archive as archive


def captured(directory):
    raw = b"public transaction fixture"
    archive.sync_write(directory / "transaction.boc", raw)
    output = {"schema": "fixture-verifier.v1", "result": "pass"}
    archive.document(directory / "verifier.json", output)
    return {
        "files": [
            {"file": "transaction.boc", "sha256": archive.digest(raw)},
            {
                "file": "verifier.json",
                "sha256": archive.digest((directory / "verifier.json").read_bytes()),
            },
        ]
    }


def test_evidence_is_durable_before_the_next_step_starts(tmp_path, monkeypatch):
    journal = archive.StepJournal(tmp_path / "archive")
    fsyncs = []
    real = archive.os.fsync

    def fsync(fd):
        real(fd)
        fsyncs.append(fd)

    monkeypatch.setattr(archive.os, "fsync", fsync)
    journal.run("fund", "11" * 32, lambda: None, captured)
    before = len(fsyncs)

    def next_action():
        first = journal.validate("fund", "11" * 32)
        assert len(first["files"]) == 2
        assert json.loads((tmp_path / "archive/fund/verifier.json").read_text())["result"] == "pass"
        assert (
            tmp_path / "archive/fund/transaction.boc"
        ).read_bytes() == b"public transaction fixture"
        assert before >= 10  # file and directory fsyncs, including the commit marker

    journal.run("respond", "22" * 32, next_action, captured)


def test_capture_failure_fences_next_action_and_resumes_without_rebroadcast(tmp_path):
    journal = archive.StepJournal(tmp_path / "archive")
    actions = []

    def interrupted(_):
        raise OSError("injected evidence storage failure")

    with pytest.raises(OSError, match="storage failure"):
        journal.run("fund", "11" * 32, lambda: actions.append("fund"), interrupted)
    with pytest.raises(archive.Refused, match="previous step"):
        journal.run("respond", "22" * 32, lambda: actions.append("respond"), captured)
    assert actions == ["fund"]
    journal.run(
        "fund", "11" * 32, lambda: pytest.fail("rebroadcast after evidence failure"), captured
    )
    journal.run("respond", "22" * 32, lambda: actions.append("respond"), captured)
    assert actions == ["fund", "respond"]


def test_changed_or_missing_evidence_blocks_every_later_action(tmp_path):
    journal = archive.StepJournal(tmp_path / "archive")
    journal.run("fund", "11" * 32, lambda: None, captured)
    (tmp_path / "archive/fund/transaction.boc").write_bytes(b"damaged")
    with pytest.raises(archive.Refused, match="missing or changed"):
        journal.run(
            "respond", "22" * 32, lambda: pytest.fail("started with lost evidence"), captured
        )


def test_reusing_a_completed_step_with_changed_inputs_refuses(tmp_path):
    journal = archive.StepJournal(tmp_path / "archive")
    journal.run("fund", "11" * 32, lambda: None, captured)
    with pytest.raises(archive.Refused, match="identity"):
        journal.run("fund", "22" * 32, lambda: pytest.fail("changed payment"), captured)


def block(seqno):
    return {
        "workchain": 0,
        "shard": str(-(2**63)),
        "seqno": seqno,
        "root_hash": base64.b64encode(bytes([seqno]) * 32).decode(),
        "file_hash": base64.b64encode(bytes([seqno + 1]) * 32).decode(),
    }


class ProofNode:
    url = "node-a"

    def call(self, method, **params):
        if method == "getShards":
            return {"shards": [block(5)]}
        assert method == "getBlockHeader"
        n = params["seqno"]
        return {"id": block(n), "prev_blocks": [block(n - 1)] if n else []}


def test_transaction_block_is_linked_to_the_finalized_shard_head(tmp_path):
    collector = archive.TransactionArchive(tmp_path, ["a", "b", "c"], {})
    collector.finalized(ProofNode(), "0:" + "11" * 32, block(3), {"seqno": 10})
    with pytest.raises(archive.Refused, match="not finalized"):
        collector.finalized(ProofNode(), "0:" + "11" * 32, block(6), {"seqno": 10})
    assert len(collector.headers) == 3


def test_a_header_or_ancestry_bound_failure_is_not_a_success(tmp_path, monkeypatch):
    collector = archive.TransactionArchive(tmp_path, ["a", "b", "c"], {})
    monkeypatch.setattr(archive, "MAX_ANCESTORS", 1)
    with pytest.raises(archive.Refused, match="bound exceeded"):
        collector.finalized(ProofNode(), "0:" + "11" * 32, block(1), {"seqno": 10})


def test_real_transaction_cell_is_bound_and_reference_disagreement_refuses(tmp_path):
    path = next(
        (
            Path(__file__).parents[2]
            / "local/evidence/service-token-public-20261126/returned/transactions"
        ).glob("*.boc")
    )
    data = path.read_bytes()
    cell = archive.ops.lib.parse_boc(data)
    sl = archive.ops.lib.Slice(cell)
    assert sl.bits(4) == 7
    address = "0:" + f"{sl.bits(256):064x}"
    lt = sl.bits(64)
    tx = {
        "lt": lt,
        "hash": cell.hash().hex(),
        "data": base64.b64encode(data).decode(),
        "block": block(3),
    }
    account, result = archive.TransactionArchive.agreed(address, [tx, tx, tx])
    assert account == address and result["hash"] == tx["hash"]
    other = dict(tx, block=block(4))
    with pytest.raises(archive.Refused, match="disagree"):
        archive.TransactionArchive.agreed(address, [tx, other, tx])
    with pytest.raises(archive.Refused, match="not available"):
        archive.TransactionArchive.agreed(address, [tx, None, tx])


def test_independent_verifier_is_durable_before_any_next_step(tmp_path):
    journal = archive.StepJournal(tmp_path / "archive")
    journal.retain_verifier("funded", {"result": "pass", "request": "request-a"})
    path = next((journal.directory / "verifiers").glob("*.json"))
    journal.run("respond", "11" * 32, lambda: None, captured)
    path.write_bytes(b"truncated")
    with pytest.raises(archive.Refused, match="retained verifier"):
        journal.run(
            "withdraw", "22" * 32, lambda: pytest.fail("lost verifier output ignored"), captured
        )


def test_sanitized_output_is_bound_to_original_bytes_and_exact_removed_fields():
    original = json.dumps(
        {
            "result": "pass",
            "tool": {"path": "/private/binary"},
            "inputs": ["/private/config"],
            "request": "public-request",
        }
    ).encode()
    sanitized = (
        json.dumps({"result": "pass", "request": "public-request"}, indent=2) + "\n"
    ).encode()
    entry = {
        "original_sha256": archive.digest(original),
        "sanitized_sha256": archive.digest(sanitized),
        "removed_json_pointers": ["/tool", "/inputs"],
    }
    archive.verify_sanitized(original, sanitized, entry)
    with pytest.raises(archive.Refused, match="original verifier"):
        archive.verify_sanitized(original + b" ", sanitized, entry)
    with pytest.raises(archive.Refused, match="beyond"):
        archive.verify_sanitized(original, sanitized, {**entry, "removed_json_pointers": ["/tool"]})


def test_every_public_verifier_has_exact_hash_citations_and_removal_provenance():
    root = Path(__file__).parents[2] / "local/evidence"
    folder = root / "service-token-public-20261126"
    index = json.loads((folder / "INDEX.json").read_text())
    provenance = json.loads((folder / "SANITIZATION.json").read_text())
    entries = {x["archive_file"]: x for x in provenance["entries"]}
    files = {x["file"] for x in index["files"] if x["kind"] == "saved-public-verifier-output"}
    assert set(entries) == files
    for name, entry in entries.items():
        assert archive.digest((folder / name).read_bytes()) == entry["sanitized_sha256"]
        assert entry["original_record_citations"]
        archive.verify_citations(root, entry)
        assert all(p.startswith("/") for p in entry["removed_json_pointers"])
        for citation in entry["original_record_citations"]:
            value = json.loads((root / citation["record"]).read_text())
            for part in citation["pointer"][1:].split("/"):
                value = value[int(part)] if isinstance(value, list) else value[part]
            assert value == entry["original_sha256"]


def test_archive_uses_finalized_consensus_not_a_head_offset(tmp_path):
    class Node:
        def __init__(self, url):
            self.url = url

        def call(self, method, **params):
            if method == "getMasterchainInfo":
                return {
                    "init": {
                        "root_hash": base64.b64encode(bytes.fromhex("11" * 32)).decode(),
                        "file_hash": base64.b64encode(bytes.fromhex("22" * 32)).decode(),
                    },
                    "last": {"seqno": 1000},
                }
            if method == "getConsensusBlock":
                return {
                    "@type": "ext.blocks.consensusBlock",
                    "consensus_block": {"a": 100, "b": 101, "c": 102}[self.url],
                }
            assert method == "lookupBlock"
            return block(params["seqno"])

    collector = archive.TransactionArchive(
        tmp_path, ["a", "b", "c"], {"root": "11" * 32, "file": "22" * 32}, node=Node
    )
    assert collector.checkpoint()["seqno"] == 100
