"""Correlate a candidate wallet's real stake and recovery wire, not a log substring.

A local candidate stakes directly from its own masterchain wallet: the wallet
sends the elector a NEW_STAKE body with the stake as the message value, and the
elector answers the wallet. Every result is read from decoded transaction BOCs.
"""

from types import SimpleNamespace

from local_pq_transactions import decoded, successful
from pytosiq_core import InternalMsgInfo
from tosapi import toslib_api
from tostester.pq_election_fixture import (
    ELECTOR,
    NEW_STAKE_OP,
    RECOVERED_OP,
    STAKE_ACCEPTED_OP,
    elector_reply,
)

RECOVER_STAKE_OP = 0x47657424
# The elector's answer to a recovery request that found nothing to return.
NOTHING_TO_RECOVER_OP = 0xFFFFFFFE
BOUNCE_PREFIX = 0xFFFFFFFF


def internal(message, sender, destination, *, bounced=False):
    return (
        message is not None
        and isinstance(message.info, InternalMsgInfo)
        and message.info.src == sender
        and message.info.dest == destination
        and message.info.bounced is bounced
    )


def failure(transaction, kind):
    compute = getattr(transaction.description, "compute_ph", None)
    action = getattr(transaction.description, "action", None)
    return dict(
        kind=kind,
        exit_code=getattr(compute, "exit_code", None),
        action_code=getattr(action, "result_code", None),
    )


def _request(transactions, wallet, opcode, query, body_hash):
    """The one wallet transaction that sent this exact request to the elector.

    Returns (transaction, message), (failed transaction, None) when the wallet
    ran an external for this body hash but sent nothing, or (None, None).
    """
    found = []
    for tx in transactions:
        for message in tx.out_msgs:
            if not internal(message, wallet, ELECTOR) or message.body.hash.hex() != body_hash:
                continue
            cs = message.body.begin_parse()
            if cs.remaining_bits >= 96 and cs.load_uint(32) == opcode and cs.load_uint(64) == query:
                found.append((tx, message))
    if len(found) > 1:
        raise ValueError("more than one elector request for the saved intent")
    return found[0] if found else (None, None)


def _answers(transactions, wallet, query):
    """Elector answers to the wallet that the wallet kept, as elector_reply envelopes."""
    envelopes = []
    for tx in transactions:
        message = tx.in_msg
        if not internal(message, ELECTOR, wallet) or not successful(tx):
            continue
        # Decode business fields from the same verified transaction BOC,
        # not independently supplied raw-RPC message metadata.
        envelopes.append(
            SimpleNamespace(
                in_msg=SimpleNamespace(
                    source=SimpleNamespace(
                        account_address=message.info.src.to_str(is_user_friendly=False)
                    ),
                    msg_data=toslib_api.Msg_dataRaw(body=message.body.to_boc(), init_state=b""),
                ),
                value=message.info.value.tomis,
            )
        )
    return envelopes


def _bounce(transactions, wallet, request):
    """A native bounce of `request` back to the wallet: its body's first 256 bits.

    A shorter body, such as a recovery request, comes back whole.
    """
    body = request.body.begin_parse()
    width = min(256, body.remaining_bits)
    prefix = body.load_uint(width)
    for tx in transactions:
        message = tx.in_msg
        if not internal(message, ELECTOR, wallet, bounced=True):
            continue
        cs = message.body.begin_parse()
        if cs.remaining_bits < 32 + width or cs.load_uint(32) != BOUNCE_PREFIX:
            continue
        if cs.load_uint(width) == prefix:
            return dict(
                kind="elector_bounced",
                returned_nano=message.info.value.tomis,
                wallet_bounce_applied=successful(tx),
            )
    return None


def election_result(history, *, wallet, query, body_hash):
    """The elector's outcome for one direct stake, or None while it is not visible.

    `history` is the wallet's history bounded to the cursor saved before the stake.
    Only the elector's acceptance answer is acceptance; a returned stake carries
    the elector's reason, and a bounce means the elector did not process it.
    """
    transactions = [decoded(item) for item in history]
    tx, request = _request(transactions, wallet, NEW_STAKE_OP, query, body_hash)
    if tx is None:
        return None
    if not successful(tx):
        return failure(tx, "wallet_refused")
    answer = elector_reply(_answers(transactions, wallet, query), query)
    if answer is not None:
        return dict(
            kind="accepted" if answer[0] == STAKE_ACCEPTED_OP else "elector_refused",
            reply=list(answer),
        )
    return _bounce(transactions, wallet, request)


def recovery_result(history, *, wallet, query, body_hash):
    """The elector's outcome for one RECOVER_STAKE request, or None while not visible.

    A recovery is credited by the elector's answer carrying the returned value;
    "nothing to recover" is reported, not treated as a failure of the chain.
    """
    transactions = [decoded(item) for item in history]
    tx, request = _request(transactions, wallet, RECOVER_STAKE_OP, query, body_hash)
    if tx is None:
        return None
    if not successful(tx):
        return failure(tx, "wallet_refused")
    for envelope in _answers(transactions, wallet, query):
        answer = elector_reply([envelope], query)
        if answer is None:
            continue
        if answer[0] == RECOVERED_OP:
            return dict(kind="recovered", returned_nano=envelope.value)
        if answer[0] == NOTHING_TO_RECOVER_OP:
            return dict(kind="nothing_to_recover", returned_nano=envelope.value)
    return _bounce(transactions, wallet, request)
