"""Synthetic TL-B parser tests, not native proof or real Elector execution."""

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from election_elector_acceptance import (
    StakeApproval,
    bounded_cell,
    verify_registered_stake,
)
from election_native_receipt import DeliveryEvidence, ReceiptError
from pytosiq_core import (
    Address,
    Builder,
    CurrencyCollection,
    InternalMsgInfo,
    MessageAny,
)
from pytosiq_core.boc import HashMap

SENDER = "-1:" + "3" * 64
ELECTOR = "-1:" + "4" * 64


def message(body, sender, dest, value, *, bounced=False, bounce=True):
    return MessageAny(
        InternalMsgInfo(
            True,
            bounce,
            bounced,
            Address(sender),
            Address(dest),
            CurrencyCollection(value),
            0,
            0,
            100,
            1000,
        ),
        None,
        body,
    ).serialize()


def transaction(
    request,
    replies,
    *,
    aborted=False,
    exit_code=0,
    skipped=0,
    action_success=True,
    destroyed=False,
    account="4" * 64,
):
    """Encode the documented transaction TL-B schema, including VM/action phases."""
    gas = (
        Builder()
        .store_var_uint(1, 3)
        .store_var_uint(100, 3)
        .store_bit(0)
        .store_int(0, 8)
        .store_int(exit_code, 32)
        .store_bit(0)
        .store_uint(1, 32)
        .store_bytes(bytes(64))
        .end_cell()
    )
    action = (
        Builder()
        .store_bool(action_success)
        .store_bool(True)
        .store_bool(False)
        .store_bit(0)
        .store_bit(0)
        .store_bit(0)
        .store_int(0, 32)
        .store_bit(0)
        .store_uint(len(replies), 16)
        .store_uint(0, 16)
        .store_uint(skipped, 16)
        .store_uint(len(replies), 16)
        .store_bytes(bytes(32))
        .store_var_uint(1, 3)
        .store_var_uint(100, 3)
        .end_cell()
    )
    description = (
        Builder()
        .store_uint(0, 4)
        .store_bool(False)
        .store_bit(0)
        .store_bit(0)
        .store_bit(1)
        .store_bool(True)
        .store_bool(False)
        .store_bool(False)
        .store_coins(1)
        .store_ref(gas)
        .store_bit(1)
        .store_ref(action)
        .store_bool(aborted)
        .store_bit(0)
        .store_bool(destroyed)
        .end_cell()
    )
    out = HashMap(
        15,
        map_=dict(enumerate(replies)),
        value_serializer=lambda value, builder: builder.store_ref(value),
    )
    messages = Builder().store_maybe_ref(request).store_dict(out.serialize()).end_cell()
    update = Builder().store_uint(0x72, 8).store_bytes(bytes(64)).end_cell()
    return (
        Builder()
        .store_uint(7, 4)
        .store_bytes(bytes.fromhex(account))
        .store_uint(100, 64)
        .store_bytes(bytes(32))
        .store_uint(0, 64)
        .store_uint(1000, 32)
        .store_uint(len(replies), 15)
        .store_uint(2, 2)
        .store_uint(2, 2)
        .store_ref(messages)
        .store_cell(CurrencyCollection(1).serialize())
        .store_ref(update)
        .store_ref(description)
        .end_cell()
    )


def case(
    *,
    opcode=0xF374484C,
    query=7,
    comment=0,
    reply_value=999000000,
    reply_bounced=False,
    reply_sender=ELECTOR,
    reply_dest=SENDER,
    request_query=7,
    request_opcode=0x4E73744B,
    algorithm=1,
    election=1234,
    factor=65536,
    adnl=5,
    extra_body=False,
    replies_count=1,
    **tx_options,
):
    key = Builder().store_uint(17, 8).end_cell()
    signature = Builder().store_uint(19, 8).end_cell()
    body = (
        Builder()
        .store_uint(request_opcode, 32)
        .store_uint(request_query, 64)
        .store_uint(algorithm, 16)
        .store_ref(key)
        .store_uint(election, 32)
        .store_uint(factor, 32)
        .store_uint(adnl, 256)
        .store_ref(signature)
    )
    if extra_body:
        body.store_bit(0)
    body = body.end_cell()
    request = message(body, SENDER, ELECTOR, 11 * 10**9)
    answer = (
        Builder()
        .store_uint(opcode, 32)
        .store_uint(query, 64)
        .store_uint(comment, 32)
        .end_cell()
    )
    reply = message(
        answer, reply_sender, reply_dest, reply_value, bounced=reply_bounced
    )
    tx = transaction(request, [reply] * replies_count, **tx_options)
    intent = dict(
        schema="tos.operation-delivery-intent/1",
        operation="synthetic-stake-1",
        genesis_root="1" * 64,
        genesis_file="2" * 64,
        sender=SENDER,
        sender_code_hash="6" * 64,
        recipient=ELECTOR,
        recipient_code_hash="7" * 64,
        external_message_hash="8" * 64,
        body_hash=body.hash.hex(),
        value_nanotos=11 * 10**9,
        credited_nanotos=11 * 10**9,
        bounce=True,
        rpc=["http://127.0.0.1:8081", "http://127.0.0.1:8082"],
        history_limit=10,
        max_age_seconds=60,
        timeout_seconds=10,
    )
    raw = json.dumps(intent).encode()
    sha = hashlib.sha256(raw).hexdigest()
    receipt = dict(
        schema="tos.operation-delivery-receipt/1",
        status="AUTHENTICATED_REQUEST_AND_DELIVERY",
        operation=intent["operation"],
        intent_sha256=sha,
        recipient_transaction=tx.hash.hex(),
        delivery_message=request.hash.hex(),
        business_acceptance=False,
        authorizes_send=False,
    )
    delivery = DeliveryEvidence(
        receipt,
        intent["external_message_hash"],
        sha,
        "9" * 64,
        "synthetic-no-proof-artifacts",
    )
    approval = StakeApproval(
        "7" * 64,
        7,
        1234,
        65536,
        key.hash.hex(),
        f"{5:064x}",
        ELECTOR,
        "1" * 64,
        "2" * 64,
    )
    return delivery, raw, tx.to_boc(), approval


def test_historical_registration_is_never_send_authority():
    result = verify_registered_stake(*case())
    assert result.historical_registration is True
    assert result.current_membership is False
    assert result.authorizes_send is False
    assert result.registered_increment_nanotos == 10 * 10**9


@pytest.mark.parametrize(
    "options",
    [
        {"opcode": 0xEE6F454C},
        {"query": 8},
        {"comment": 1},
        {"reply_value": 0},
        {"reply_value": 10**9 + 1},
        {"reply_bounced": True},
        {"reply_sender": "-1:" + "a" * 64},
        {"reply_dest": "-1:" + "b" * 64},
        {"request_query": 8},
        {"request_opcode": 0},
        {"algorithm": 2},
        {"election": 1235},
        {"factor": 65537},
        {"adnl": 6},
        {"extra_body": True},
        {"replies_count": 0},
        {"replies_count": 2},
        {"aborted": True},
        {"exit_code": 1},
        {"skipped": 1},
        {"action_success": False},
        {"destroyed": True},
        {"account": "a" * 64},
    ],
)
def test_semantic_refusals_even_when_synthetic_native_hash_matches(options):
    with pytest.raises(ReceiptError):
        verify_registered_stake(*case(**options))


@pytest.mark.parametrize(
    "field,value",
    [
        ("elector_code_hash", "a" * 64),
        ("query_id", 0),
        ("query_id", True),
        ("query_id", 8),
        ("election_id", 1235),
        ("max_factor", 65535),
        ("public_key_cell_hash", "b" * 64),
        ("adnl", "0" * 64),
        ("elector_address", "-1:" + "a" * 64),
        ("genesis_root", "a" * 64),
        ("genesis_file", "a" * 64),
    ],
)
def test_approved_policy_must_match(field, value):
    delivery, raw, tx, approval = case()
    with pytest.raises(ReceiptError):
        verify_registered_stake(delivery, raw, tx, replace(approval, **{field: value}))


@pytest.mark.parametrize("field", ["intent_sha256", "original_message_hash"])
def test_delivery_binding(field):
    delivery, raw, tx, approval = case()
    with pytest.raises(ReceiptError):
        verify_registered_stake(
            replace(delivery, **{field: "a" * 64}), raw, tx, approval
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("recipient_transaction", "a" * 64),
        ("delivery_message", "a" * 64),
        ("business_acceptance", True),
        ("authorizes_send", True),
    ],
)
def test_receipt_binding(field, value):
    delivery, raw, tx, approval = case()
    receipt = dict(delivery.receipt, **{field: value})
    with pytest.raises(ReceiptError):
        verify_registered_stake(replace(delivery, receipt=receipt), raw, tx, approval)


def test_changed_intent_and_arbitrary_json_are_not_native_evidence():
    delivery, raw, tx, approval = case()
    with pytest.raises(ReceiptError):
        verify_registered_stake(delivery, raw + b" ", tx, approval)
    with pytest.raises(ReceiptError):
        verify_registered_stake(delivery.receipt, raw, tx, approval)
    with pytest.raises(ReceiptError):
        verify_registered_stake(SimpleNamespace(**delivery.__dict__), raw, tx, approval)


def test_query_zero_can_never_produce_positive_witness():
    delivery, raw, tx, approval = case(request_query=0, query=0)
    with pytest.raises(ReceiptError):
        verify_registered_stake(delivery, raw, tx, replace(approval, query_id=0))


@pytest.mark.parametrize("raw", [b"", b"BOC", b"x" * ((1 << 20) + 1)])
def test_bad_transaction_bytes(raw):
    delivery, intent, _, approval = case()
    with pytest.raises(ReceiptError):
        verify_registered_stake(delivery, intent, raw, approval)


def test_deep_graph_refused_before_transaction_decode():
    cell = Builder().end_cell()
    for _ in range(65):
        cell = Builder().store_ref(cell).end_cell()
    with pytest.raises(ReceiptError, match="depth"):
        bounded_cell(cell.to_boc())


@pytest.mark.parametrize("cells,roots,absent", [(4097, 1, 0), (1, 2, 0), (1, 1, 1)])
def test_header_counts_refuse_before_codec_allocation(
    monkeypatch, cells, roots, absent
):
    from election_elector_acceptance import Boc

    def unexpected_decode(_raw):
        raise AssertionError("codec allocated before preflight")

    monkeypatch.setattr(Boc, "deserialize_boc_header", unexpected_decode)
    raw = bytes.fromhex("b5ee9c72") + bytes([2, 1])
    raw += b"".join(value.to_bytes(2, "big") for value in (cells, roots, absent))
    with pytest.raises(ReceiptError, match="cell bound"):
        bounded_cell(raw)
