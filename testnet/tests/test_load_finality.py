"""Public BOC regressions for native-head anchored history decoding."""

import base64
import json
from pathlib import Path

import load_finality as finality
import pytest
from pytosiq_core import Cell, Transaction


@pytest.fixture
def public():
    return json.loads((Path(__file__).parent / "data/load-finality-public.json").read_text())


def decode(public, transactions=None, **changes):
    args = dict(
        verified_head=finality.Head(**public["head"]),
        previous_head=finality.Head(**public["previous"]),
        wallet=public["wallet"],
        global_id=2,
        subwallet_id=4269,
        skipped_profile=True,
    )
    args.update(changes)
    return finality.decode_history(
        public["transactions"] if transactions is None else transactions, **args
    )


def transaction(public):
    return Transaction.deserialize(
        Cell.one_from_boc(base64.b64decode(public["transactions"][0])).begin_parse()
    )


def test_actual_public_chain_and_skip_phases(public):
    receipts = decode(public)
    assert [r.query_id for r in receipts] == [1566, 1565]
    assert receipts[0].transaction == finality.Head(**public["head"])
    assert (
        receipts[0].request_hash
        == "6c2a8af04c77dfbb63d803153d79dfdee0598a6d404ffdd6acb691fe72bc0284"
    )
    assert all(r.compute_gas == 786788 for r in receipts)
    assert all(
        (r.total_actions, r.skipped_actions, r.messages_created) == (255, 254, 1) for r in receipts
    )


@pytest.mark.parametrize("part", ["first", "last", "order"])
def test_missing_or_reordered_transactions(public, part):
    rows = public["transactions"]
    bad = rows[1:] if part == "first" else rows[:1] if part == "last" else rows[::-1]
    expected = "incomplete transaction history" if part == "last" else "head hash mismatch"
    with pytest.raises(finality.HistoryError, match=expected):
        decode(public, bad)


def test_wrong_native_head_hash(public):
    with pytest.raises(finality.HistoryError, match="head hash mismatch"):
        decode(public, verified_head=finality.Head(public["head"]["lt"], "00" * 32))


def test_wrong_native_head_lt(public):
    with pytest.raises(finality.HistoryError, match="head lt mismatch"):
        decode(
            public, verified_head=finality.Head(public["head"]["lt"] + 1, public["head"]["hash"])
        )


def test_wrong_account(public):
    with pytest.raises(finality.HistoryError, match="account mismatch"):
        decode(public, wallet="0:" + "11" * 32)


@pytest.mark.parametrize(
    "changes,message",
    [({"global_id": 3}, "global id mismatch"), ({"subwallet_id": 0}, "subwallet mismatch")],
)
def test_request_identity_is_decoded(public, changes, message):
    with pytest.raises(finality.HistoryError, match=message):
        decode(public, **changes)


def test_empty_only_when_native_heads_equal(public):
    assert decode(public, [], previous_head=finality.Head(**public["head"])) == ()
    with pytest.raises(finality.HistoryError, match="incomplete transaction history"):
        decode(public, [])
    with pytest.raises(finality.HistoryError, match="extends past previous head"):
        decode(public, previous_head=finality.Head(**public["head"]))


def test_bound_count_before_decode(public):
    with pytest.raises(finality.HistoryError, match="history transaction limit"):
        decode(public, [""] * 8193)


def test_bound_transaction_bytes_before_decode(public):
    with pytest.raises(finality.HistoryError, match="transaction byte limit"):
        decode(public, ["A" * (4 * ((finality.MAX_TRANSACTION_BYTES + 2) // 3) + 1)])


def test_cumulative_encoded_byte_bound(public, monkeypatch):
    size = sum(map(len, public["transactions"]))
    monkeypatch.setattr(finality, "MAX_HISTORY_BYTES", size)
    assert len(decode(public)) == 2
    monkeypatch.setattr(finality, "MAX_HISTORY_BYTES", size - 1)
    with pytest.raises(finality.HistoryError, match="history byte limit"):
        decode(public)


@pytest.mark.parametrize("bad", ["!", "", "AAAA"])
def test_malformed_boc_is_not_success(public, bad):
    with pytest.raises(finality.HistoryError):
        decode(public, [bad])


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("aborted", True, "aborted or destroyed"),
        ("destroyed", True, "aborted or destroyed"),
        ("compute_ph.success", False, "compute failed"),
        ("compute_ph.exit_code", 1, "compute failed"),
        ("action.success", False, "action failed"),
        ("action.valid", False, "action failed"),
        ("action.no_funds", True, "action failed"),
        ("action.result_code", 37, "action failed"),
        ("action.spec_actions", 1, "action failed"),
        ("action.skipped_actions", 253, "skip profile mismatch"),
        ("action.msgs_created", 2, "skip profile mismatch"),
        ("action.tot_actions", 254, "skip profile mismatch"),
    ],
)
def test_decoded_public_phase_refusals(public, field, value, message):
    # Alter the decoded public fixture, not a purported authenticated proof.
    # This exercises each production phase predicate without a fake success RPC.
    tx = transaction(public)
    obj = tx.description
    parts = field.split(".")
    for part in parts[:-1]:
        obj = getattr(obj, part)
    setattr(obj, parts[-1], value)
    with pytest.raises(finality.HistoryError, match=message):
        finality.submit_receipt(tx, public["wallet"], 2, 4269, skipped_profile=True)


@pytest.mark.parametrize("lt,hash_", [(-1, "00" * 32), (True, "00" * 32), (1, "z" * 64)])
def test_invalid_heads_refused(lt, hash_):
    with pytest.raises(finality.HistoryError):
        finality.Head(lt, hash_)
