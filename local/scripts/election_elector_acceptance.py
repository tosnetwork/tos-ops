"""Read-only historical Elector registration witness for a direct wallet stake.

The caller must supply a DeliveryEvidence returned by the pinned native worker,
and a reviewed Elector code hash whose new-stake semantics match elector-code.fc
(TOS 5439f98, lines 304-422). Caller-supplied JSON is NOT native evidence.
Code approval is a trust input, not inferred from an RPC response or this parser.
The positive acknowledgement strategy is inherited from upstream 857b8a5,
elector-code.fc:198-277. Missing acknowledgement remains UNKNOWN, never rejection.

This proves registration at ONE transaction, not current membership/election,
nominator-pool routing, or permission to send. No signer, network or journal I/O.
Provide the reviewed TOS Python codec on PYTHONPATH, as for other local drivers.
"""

import hashlib
from dataclasses import dataclass

from election_native_receipt import (
    DeliveryEvidence,
    ReceiptError,
    decode_json,
    digest,
    validate_intent,
)
from pytosiq_core import Cell, InternalMsgInfo, Transaction
from pytosiq_core.boc.deserialize import Boc

NANO = 10**9
MAX_BOC = 1 << 20
MAX_CELLS = 4096
MAX_DEPTH = 64


@dataclass(frozen=True)
class StakeApproval:
    """Trusted operator policy; code hash requires prior source/code review."""

    elector_code_hash: str
    query_id: int
    election_id: int
    max_factor: int
    public_key_cell_hash: str
    adnl: str
    elector_address: str
    genesis_root: str
    genesis_file: str


@dataclass(frozen=True)
class RegistrationEvidence:
    operation: str
    original_message_hash: str
    intent_sha256: str
    recipient_transaction: str
    delivery_message: str
    confirmation_message: str
    query_id: int
    election_id: int
    registered_increment_nanotos: int
    historical_registration: bool = True
    current_membership: bool = False
    authorizes_send: bool = False


def bounded_cell(raw):
    """Bound bytes/cells before decoding; reject exotic/deep transaction graphs."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BOC:
        raise ReceiptError("public transaction byte bound")
    # Preflight counts before the codec allocates root/index lists. This accepts
    # the generic BOC envelope emitted by TOS, not legacy indexed magic variants.
    if len(raw) < 6 or raw[:4] != bytes.fromhex("b5ee9c72") or raw[4] & 0x38:
        raise ReceiptError("generic TOS transaction BOC required")
    size, offset = raw[4] & 7, raw[5]
    if not 1 <= size <= 4 or not 1 <= offset <= 4 or len(raw) < 6 + 3 * size:
        raise ReceiptError("public transaction header bound")
    cells, roots, absent = (
        int.from_bytes(raw[6 + i * size : 6 + (i + 1) * size], "big") for i in range(3)
    )
    if not 0 < cells <= MAX_CELLS or roots != 1 or absent != 0:
        raise ReceiptError("public transaction cell bound")
    header = Boc.deserialize_boc_header(raw)
    if (
        not 0 < header["cells_num"] <= MAX_CELLS
        or header["roots_num"] != 1
        or header["absent_num"] != 0
    ):
        raise ReceiptError("public transaction cell bound")
    root = Cell.one_from_boc(raw)
    if root.get_depth() > MAX_DEPTH:
        raise ReceiptError("public transaction depth bound")
    pending, seen = [root], set()
    while pending:
        cell = pending.pop()
        if id(cell) in seen:
            continue
        seen.add(id(cell))
        if cell.is_exotic:
            raise ReceiptError("complete ordinary transaction graph required")
        pending.extend(cell.refs)
    return root


def internal(message, sender, recipient):
    info = message.info if message is not None else None
    return (
        isinstance(info, InternalMsgInfo)
        and info.src is not None
        and info.src.to_str(is_user_friendly=False) == sender
        and info.dest.to_str(is_user_friendly=False) == recipient
        and not info.bounced
        and info.ihr_disabled
        and not info.value.other.dict
        and message.init is None
    )


def verify_registered_stake(delivery, intent_raw, transaction_boc, approval):
    """Refuse anything short of a native-bound positive registration witness.

    All parsing errors fail closed. A refusal is insufficient to permit retry.
    Execute under the controller's finite CPU/memory/runtime service as well.
    """
    try:
        return _verify(delivery, intent_raw, transaction_boc, approval)
    except ReceiptError:
        raise
    # The reviewed codec's BocError/CellError/TlbError have no common parser base.
    # All ordinary decoder exceptions refuse; process termination still propagates.
    except Exception as error:
        raise ReceiptError("malformed public registration witness") from error


def _verify(delivery, intent_raw, transaction_boc, approval):
    if type(delivery) is not DeliveryEvidence or type(approval) is not StakeApproval:
        raise ReceiptError("trusted native delivery and code approval required")
    intent = decode_json(intent_raw)
    validate_intent(intent)
    receipt = delivery.receipt
    intent_sha = hashlib.sha256(intent_raw).hexdigest()
    if (
        delivery.intent_sha256 != intent_sha
        or receipt["intent_sha256"] != intent_sha
        or receipt["operation"] != intent["operation"]
        or delivery.original_message_hash != intent["external_message_hash"]
        or receipt["status"] != "AUTHENTICATED_REQUEST_AND_DELIVERY"
        or receipt["schema"] != "tos.operation-delivery-receipt/1"
        or receipt["business_acceptance"] is not False
        or receipt["authorizes_send"] is not False
        or delivery.business_acceptance is not False
        or delivery.authorizes_send is not False
    ):
        raise ReceiptError("native delivery intent binding mismatch")
    for value in (
        approval.elector_code_hash,
        approval.public_key_cell_hash,
        approval.adnl,
        approval.genesis_root,
        approval.genesis_file,
    ):
        digest(value)
    for value, low, high in (
        (approval.query_id, 1, (1 << 64) - 1),
        (approval.election_id, 1, (1 << 32) - 1),
        (approval.max_factor, 65536, (1 << 32) - 1),
    ):
        if type(value) is not int or not low <= value <= high:
            raise ReceiptError("approved stake field bound")
    if (
        intent["recipient_code_hash"] != approval.elector_code_hash
        or intent["recipient"] != approval.elector_address
        or intent["genesis_root"] != approval.genesis_root
        or intent["genesis_file"] != approval.genesis_file
        or not intent["sender"].startswith("-1:")
        or not intent["recipient"].startswith("-1:")
        or int(intent["sender"].split(":")[1], 16) == 0
        or int(approval.adnl, 16) == 0
        or intent["credited_nanotos"] <= NANO
    ):
        raise ReceiptError("approved Elector code or direct stake mismatch")
    root = bounded_cell(transaction_boc)
    if root.hash.hex() != digest(receipt["recipient_transaction"]):
        raise ReceiptError("native recipient transaction hash mismatch")
    tx = Transaction.deserialize(root.begin_parse())
    if tx.account_addr_hex != intent["recipient"].split(":")[1]:
        raise ReceiptError("Elector account mismatch")
    request = tx.in_msg
    if (
        not internal(request, intent["sender"], intent["recipient"])
        or request.cell is None
        or request.cell.hash.hex() != digest(receipt["delivery_message"])
        or request.body.hash.hex() != intent["body_hash"]
        or request.info.value.tomis != intent["credited_nanotos"]
        or request.info.bounce != intent["bounce"]
    ):
        raise ReceiptError("native original stake message mismatch")
    body = request.body.begin_parse()
    if (
        body.remaining_bits != 432
        or body.remaining_refs != 2
        or body.load_uint(32) != 0x4E73744B
        or body.load_uint(64) != approval.query_id
        or body.load_uint(16) != 1
        or body.load_ref().hash.hex() != approval.public_key_cell_hash
        or body.load_uint(32) != approval.election_id
        or body.load_uint(32) != approval.max_factor
        or body.load_uint(256) != int(approval.adnl, 16)
    ):
        raise ReceiptError("approved PQ stake body mismatch")
    descr = tx.description
    compute = getattr(descr, "compute_ph", None)
    action = getattr(descr, "action", None)
    if (
        descr.type_ != "ordinary"
        or descr.aborted
        or descr.destroyed
        or descr.bounce is not None
        or compute is None
        or compute.type_ != "vm"
        or compute.success is not True
        or compute.exit_code != 0
        or action is None
        or action.success is not True
        or action.valid is not True
        or action.no_funds
        or action.result_code != 0
        or action.skipped_actions != 0
        or action.msgs_created != 1
        or tx.outmsg_cnt != 1
        or len(tx.out_msgs) != 1
    ):
        raise ReceiptError("successful single-confirmation transaction required")
    reply = tx.out_msgs[0]
    if (
        not internal(reply, intent["recipient"], intent["sender"])
        or not reply.info.bounce
        or not 0 < reply.info.value.tomis <= NANO
        or reply.cell is None
        or len(reply.body.bits) != 128
        or reply.body.refs
    ):
        raise ReceiptError("Elector confirmation envelope mismatch")
    answer = reply.body.begin_parse()
    if (
        answer.load_uint(32) != 0xF374484C
        or answer.load_uint(64) != approval.query_id
        or answer.load_uint(32) != 0
    ):
        raise ReceiptError("positive Elector confirmation required")
    return RegistrationEvidence(
        intent["operation"],
        delivery.original_message_hash,
        intent_sha,
        root.hash.hex(),
        request.cell.hash.hex(),
        reply.cell.hash.hex(),
        approval.query_id,
        approval.election_id,
        intent["credited_nanotos"] - NANO,
    )
