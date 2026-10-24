"""Actual TL-B wire positives and controlled refusal-correlation mutations."""

import pytest
from local_pq_election_evidence import RECOVER_STAKE_OP, election_result, recovery_result
from local_pq_test_wire import address, message, transaction
from pytosiq_core import Builder
from tostester.pq_election_fixture import ELECTOR

QUERY = (1791257021 << 8) | 7
WALLET = address(1)
ACCEPTED, RETURNED, RECOVERED = 0xF374484C, 0xEE6F454C, 0xF96F7324


def stake_body(query=QUERY, op=0x4E73744B):
    # A NEW_STAKE prefix is all the correlation reads; the elector parses the rest.
    return Builder().store_uint(op, 32).store_uint(query, 64).store_uint(42, 160).end_cell()


def reply(op, query=QUERY, detail=0):
    value = Builder().store_uint(op, 32).store_uint(query, 64)
    if detail is not None:
        value.store_uint(detail, 32)
    return value.end_cell()


def history(*answers, body=None, sent=True, wallet_ok=True, wallet_exit=0):
    body = body if body is not None else stake_body()
    outputs = [message(WALLET, ELECTOR, body, amount=11_001_200_000_000, lt=11)] if sent else []
    order = transaction(WALLET, 10, None, outputs, success=wallet_ok, exit_code=wallet_exit)
    later = [transaction(WALLET, 20 + i, inbound) for i, inbound in enumerate(answers)]
    return list(reversed([order, *later])), body


def args(body, query=QUERY):
    return dict(wallet=WALLET, query=query, body_hash=body.hash.hex())


@pytest.mark.parametrize(
    "op,detail,kind", [(ACCEPTED, 0, "accepted"), (RETURNED, 0, "elector_refused")]
)
def test_elector_answer_decides_the_outcome(op, detail, kind):
    items, body = history(message(ELECTOR, WALLET, reply(op, detail=detail)))
    assert election_result(items, **args(body)) == dict(kind=kind, reply=[op, detail])


def test_a_returned_stake_keeps_the_elector_reason():
    items, body = history(message(ELECTOR, WALLET, reply(RETURNED, detail=6)))
    assert election_result(items, **args(body))["reply"] == [RETURNED, 6]


def test_no_answer_yet_is_not_an_outcome():
    items, body = history()
    assert election_result(items, **args(body)) is None


@pytest.mark.parametrize(
    "mutation",
    [
        dict(query=QUERY + 1),
        dict(sender=address(9)),
        dict(dest=address(9)),
        dict(bounced=True),
    ],
)
def test_an_unrelated_answer_is_not_correlated(mutation):
    answer = message(
        mutation.get("sender", ELECTOR),
        mutation.get("dest", WALLET),
        reply(ACCEPTED, query=mutation.get("query", QUERY)),
        bounced=mutation.get("bounced", False),
    )
    items, body = history(answer)
    assert election_result(items, **args(body)) is None


def test_an_answer_the_wallet_failed_to_process_is_not_acceptance():
    items, body = history()
    failed = transaction(
        WALLET, 30, message(ELECTOR, WALLET, reply(ACCEPTED)), success=False, exit_code=33
    )
    assert election_result([failed, *items], **args(body)) is None


def test_a_wrong_body_or_query_is_not_the_saved_stake():
    items, body = history(message(ELECTOR, WALLET, reply(ACCEPTED)))
    assert election_result(items, wallet=WALLET, query=QUERY, body_hash="ff" * 32) is None
    assert election_result(items, **args(body, query=QUERY + 1)) is None


def test_two_sends_of_the_saved_stake_are_refused():
    items, body = history()
    again = transaction(WALLET, 15, None, [message(WALLET, ELECTOR, body, lt=16)])
    with pytest.raises(ValueError, match="more than one"):
        election_result([again, *items], **args(body))


def bounce(body, *, applied=True, commitment=None, sender=ELECTOR, bounced=True):
    width = min(256, body.begin_parse().remaining_bits)
    prefix = body.begin_parse().load_uint(width) if commitment is None else commitment
    value = Builder().store_uint(0xFFFFFFFF, 32).store_uint(prefix, width).end_cell()
    return transaction(
        WALLET,
        40,
        message(sender, WALLET, value, amount=11_000_000_000_000, bounced=bounced),
        success=applied,
    )


def test_a_native_bounce_is_reported_with_the_returned_value():
    items, body = history()
    result = election_result([bounce(body), *items], **args(body))
    assert result == dict(
        kind="elector_bounced", returned_nano=11_000_000_000_000, wallet_bounce_applied=True
    )


@pytest.mark.parametrize(
    "mutation", [dict(commitment=1), dict(sender=address(9)), dict(bounced=False)]
)
def test_an_unrelated_bounce_is_not_a_refusal(mutation):
    items, body = history()
    assert election_result([bounce(body, **mutation), *items], **args(body)) is None


def test_a_bounce_the_wallet_failed_to_apply_is_not_hidden():
    items, body = history()
    result = election_result([bounce(body, applied=False), *items], **args(body))
    assert result["wallet_bounce_applied"] is False


def test_a_failed_wallet_transaction_is_reported_directly():
    items, body = history(wallet_ok=False, wallet_exit=35)
    assert election_result(items, **args(body)) == dict(
        kind="wallet_refused", exit_code=35, action_code=None
    )


def recover_body(query=QUERY):
    return Builder().store_uint(RECOVER_STAKE_OP, 32).store_uint(query, 64).end_cell()


def test_a_recovery_is_credited_from_the_elector_answer():
    body = recover_body()
    answer = message(ELECTOR, WALLET, reply(RECOVERED, detail=None), amount=11_000_500_000_000)
    items, _ = history(answer, body=body)
    assert recovery_result(items, **args(body)) == dict(
        kind="recovered", returned_nano=11_000_500_000_000
    )


def test_nothing_to_recover_is_reported_not_credited():
    body = recover_body()
    items, _ = history(
        message(ELECTOR, WALLET, reply(0xFFFFFFFE, detail=RECOVER_STAKE_OP)), body=body
    )
    assert recovery_result(items, **args(body))["kind"] == "nothing_to_recover"


def test_a_recovery_answer_with_trailing_data_is_not_a_credit():
    body = recover_body()
    items, _ = history(message(ELECTOR, WALLET, reply(RECOVERED, detail=1)), body=body)
    assert recovery_result(items, **args(body)) is None


def test_a_stake_answer_is_not_a_recovery():
    body = recover_body()
    items, _ = history(message(ELECTOR, WALLET, reply(RECOVERED, detail=None)))
    assert recovery_result(items, **args(body)) is None


def test_a_bounced_recovery_request_comes_back_whole():
    body = recover_body()
    items, _ = history(body=body)
    assert recovery_result([bounce(body), *items], **args(body))["kind"] == "elector_bounced"
