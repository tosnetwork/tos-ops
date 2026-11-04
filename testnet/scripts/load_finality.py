"""Bounded transaction-history decoding beneath a native-verified account head.

The caller MUST obtain the account head from the native verifier, using its pinned
anchor and code identity. This module does not authenticate RPC account JSON or
verify consensus proofs. It never signs, broadcasts, or controls load admission.
"""

import base64
from dataclasses import dataclass

from pytosiq_core import Cell, Transaction
from pytosiq_core.boc.cell import CellError
from pytosiq_core.boc.deserialize import BocError
from pytosiq_core.boc.slice import SliceError
from pytosiq_core.tlb.tlb import TlbError

MAX_TRANSACTIONS = 8192
MAX_TRANSACTION_BYTES = 1 << 20
MAX_HISTORY_BYTES = 16 << 20
SUBMIT = 0x50514857


class HistoryError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise HistoryError(reason)


@dataclass(frozen=True)
class Head:
    lt: int
    hash: str

    def __post_init__(self):
        require(type(self.lt) is int and 0 <= self.lt < 1 << 64, "invalid transaction lt")
        require(
            isinstance(self.hash, str)
            and len(self.hash) == 64
            and all(c in "0123456789abcdef" for c in self.hash),
            "invalid transaction hash",
        )


@dataclass(frozen=True)
class SubmitReceipt:
    query_id: int
    transaction: Head
    request_hash: str
    compute_gas: int
    total_actions: int
    skipped_actions: int
    messages_created: int


def submit_receipt(tx, wallet, global_id, subwallet_id, *, skipped_profile):
    """Decode a bound, successful highload submission; unrelated deposits return None."""
    if tx.in_msg is None:
        return None
    body = tx.in_msg.body.begin_parse()
    if body.remaining_bits < 32 or body.load_uint(32) != SUBMIT:
        return None
    require(tx.in_msg.is_internal, "submission must be internal")
    body.load_uint(64)  # Relayer refund correlation, not the signed replay query.
    request = body.load_ref()
    body.load_ref()  # Signature already checked by the authenticated transaction.
    require(body.remaining_bits == body.remaining_refs == 0, "submission trailing data")
    signed = request.begin_parse()
    require(signed.load_int(32) == global_id, "submission global id mismatch")
    require(
        signed.load_address().to_str(is_user_friendly=False) == wallet,
        "submission wallet mismatch",
    )
    require(signed.load_uint(32) == subwallet_id, "submission subwallet mismatch")
    query = signed.load_uint(23)
    require(query & 1023 != 1023, "reserved query id")
    signed.load_uint(64)  # created_at
    signed.load_uint(22)  # timeout
    signed.load_ref()  # actions
    require(signed.remaining_bits == signed.remaining_refs == 0, "request trailing data")
    desc = tx.description
    require(type(desc).__name__ == "TransactionOrdinary", "submission is not ordinary")
    require(not desc.aborted and not desc.destroyed, "submission aborted or destroyed")
    compute = desc.compute_ph
    require(
        compute.type_ == "vm" and compute.success and compute.exit_code == 0,
        "submission compute failed",
    )
    action = desc.action
    require(
        action is not None
        and action.success
        and action.valid
        and not action.no_funds
        and action.result_code == 0
        and action.spec_actions == 0,
        "submission action failed",
    )
    if skipped_profile:
        require(
            action.tot_actions == 255
            and action.skipped_actions == 254
            and action.msgs_created == 1,
            "submission skip profile mismatch",
        )
    return SubmitReceipt(
        query,
        Head(tx.lt, tx.cell.hash.hex()),
        request.hash.hex(),
        compute.gas_used,
        action.tot_actions,
        action.skipped_actions,
        action.msgs_created,
    )


def decode_history(
    encoded_transactions,
    *,
    verified_head,
    previous_head,
    wallet,
    global_id,
    subwallet_id,
    skipped_profile,
):
    """Verify a complete newest-first chain segment ending at the previous head.

    Both heads must come from native-verified snapshots of the SAME account and
    anchor. The previous head is excluded from the supplied segment. A missing
    intermediate transaction, tail, or reordered RPC response is an error. No
    progress is returned on a partial failure. Query ids need not be ordered.
    """
    require(type(encoded_transactions) in (list, tuple), "history must be bounded sequence")
    require(type(verified_head) is Head and type(previous_head) is Head, "validated heads required")
    require(len(encoded_transactions) <= MAX_TRANSACTIONS, "history transaction limit")
    require(type(skipped_profile) is bool, "explicit profile required")
    require(type(global_id) is int and type(subwallet_id) is int, "integer identity required")
    require(
        isinstance(wallet, str)
        and wallet.startswith("0:")
        and len(wallet) == 66
        and all(c in "0123456789abcdef" for c in wallet[2:]),
        "expected basechain wallet required",
    )
    expected = verified_head
    receipts = []
    seen = set()
    total = 0
    for encoded in encoded_transactions:
        require(expected != previous_head, "history extends past previous head")
        require(isinstance(encoded, str), "transaction must be base64 text")
        require(len(encoded) <= 4 * ((MAX_TRANSACTION_BYTES + 2) // 3), "transaction byte limit")
        total += len(encoded)
        require(total <= MAX_HISTORY_BYTES, "history byte limit")
        try:
            raw = base64.b64decode(encoded, validate=True)
            require(len(raw) <= MAX_TRANSACTION_BYTES, "transaction byte limit")
            cell = Cell.one_from_boc(raw)
            require(cell.hash.hex() == expected.hash, "transaction head hash mismatch")
            tx = Transaction.deserialize(cell.begin_parse())
            require(tx.account_addr_hex == wallet[2:], "transaction account mismatch")
            require(tx.lt == expected.lt, "transaction head lt mismatch")
            require(tx.prev_trans_lt < tx.lt, "nondecreasing previous transaction lt")
            receipt = submit_receipt(
                tx, wallet, global_id, subwallet_id, skipped_profile=skipped_profile
            )
        except HistoryError:
            raise
        except (
            ValueError,
            TypeError,
            AttributeError,
            IndexError,
            KeyError,
            BocError,
            CellError,
            SliceError,
            TlbError,
        ) as exc:
            raise HistoryError("malformed transaction or submission") from exc
        if receipt is not None:
            require(receipt.query_id not in seen, "duplicate query in transaction history")
            seen.add(receipt.query_id)
            receipts.append(receipt)
        expected = Head(tx.prev_trans_lt, tx.prev_trans_hash.hex())
    require(expected == previous_head, "incomplete transaction history")
    return tuple(receipts)
