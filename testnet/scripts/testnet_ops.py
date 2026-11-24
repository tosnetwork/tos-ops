"""Value-moving operations of the coordinator: journal, gate, settlement, manual paths.

A new module because onboard, withdraw, fund, load and the manual commands
(reconcile, record, resubmit, baseline) of testnet-elections.py all share it, and
its rules are tested on their own. Standard library only, like testnet_lib.

The rules (memo: epoch-4-fixplan-2.md, revision 4, agreed with the reviewer):

* Every message that moves value is an *operation* with a stable id and
  immutable parameters, recorded in ceremony/operations/<id>.jsonl: append-only
  lines, each written whole and fsynced with its directory, the signed message
  durable before it is broadcast. One lock over the whole journal is held for
  every decision and transition, each taken on a record re-read under it; a step
  is resolved to its newest attempt, and a new attempt after a terminal failure
  exists only by a person's `retry`.
* Every fact settlement uses is decoded from the transaction's own BOC, checked
  against the reported transaction hash, account and lt, on both validators.
* Nothing is ever resumed automatically. Before signing, the *gate* reads the
  signing wallet's history on two validators of the intended network, complete
  from the newer of its manual baseline and its newest settled operation's own
  transaction (validators prune older history after about a day; see
  history_start), and refuses when any transaction emitting a message is not explained by a
  settled or failed operation, when any operation of that wallet is open, or
  when the history is unknown (unavailable, incomplete, or the two disagree).
* An operation settles only from the chain, matched by hashes: the wallet's
  transaction for the exact external message, the exact internal message it
  emitted, and the destination's transaction for that message, on both
  validators; the per-kind outcome rules are in settle().
* An open operation is resolved only by a person: record (settled or failed,
  with verified evidence), resubmit (the original message, never re-signed),
  after reconcile has shown the state.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import testnet_lib as lib

NANO = 10**9
OPERATIONS_DIR = "operations"
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,80}$")
# What a wallet message may cost beyond its value (checked before signing).
FEE_ALLOWANCE_NANOTOS = NANO
# How long a broadcast is watched before the run stops with the operation open.
SETTLE_SECONDS = 150
POLL_SECONDS = 3
HISTORY_PAGE = 16
HISTORY_PAGES = 256
# Operational search envelope from the emitted message, independent of account history.
DELIVERY_BLOCKS = 512
DELIVERY_BLOCK_PAGES = 128
DELIVERY_PAGE = 256
# Clock and propagation margin before an expired message counts as dead.
EXPIRY_MARGIN = 120
# wallet-v3: tosctl builds with 120 s, wallet-v3.fif here with 300 s.
MAX_TTL = {"host": 120, "coordinator": 300}
TTL_SKEW = 30
ACTIVATION_VALID_UNTIL = 0xFFFFFFFF
# What a wallet v3 self-deployment needs on its account before it is sent.
ACTIVATION_FEE_NANOTOS = NANO // 10
WALLET_V3_MODE = 3
# The bootstrap wallet's final transfer: carry the whole remaining balance (128)
# and delete the account once it is empty (32), to the ConfigParam 5 blackhole.
SWEEP_MODE = 128 + 32
# The funding plans record_abandoned may close: signed on the coordinator through
# run(), so an unsigned plan was never broadcast.
ABANDONABLE_KINDS = ("fund", "owner-fund")
BLACKHOLE = lib.BLACKHOLE
EMPTY_BODY_HASH = lib.cell_from_bits("").hash().hex()
# Search envelope for the transaction that ran a sweep, from the masterchain head
# at signing: the message expires 300 s after signing, so it ran within that many
# seconds of blocks; the search stops at the first run that took effect.
SWEEP_SEARCH_BLOCKS = 4096
BOOTSTRAP_WALLET = "-1:" + "11" * 32
# Hash of WCode3 used by the independently held genesis artifact.
BOOTSTRAP_CODE_HASH = "5829bd66ea5884eef70788d0609acad76af5c418aed2fc17709def2224cf9164"
CUSTODY_ASSUMPTION = "The bootstrap signing key is custodied only by the coordinator."


def certificate_digest(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# config-propose and config-vote (testnet-governance.py) send to the Config contract,
# change-validator to a pool; they settle only when a getter shows the effect (the
# caller's expect check). owner-deploy-pool is the pool deployment of an
# operator-run host, sent with the pool's StateInit from the offline owner; like
# the host's deploy-pool it settles only when the pool reads deployed with its
# pinned code and roles.
COORDINATOR_KINDS = (
    "fund",
    "owner-fund",
    "sweep",
    "activate-owner",
    "owner-deploy-pool",
    "principal",
    "withdraw",
    "change-validator",
    "config-propose",
    "config-vote",
)
HOST_KINDS = ("deploy-pool",)
KINDS = COORDINATOR_KINDS + HOST_KINDS
STATES = ("planned", "signed", "broadcast", "settled", "failed")
# Test hook: TESTNET_OPS_CRASH_AT=<id>:<point> makes the process exit at that
# point, as a crash would, so the rehearsal can kill a run at each boundary.
CRASH_ENV = "TESTNET_OPS_CRASH_AT"
CRASH_POINTS = ("planned", "signed", "broadcast", "delivered")
# The stake authorization algorithm a pool order carries (ML-DSA-44).
MLDSA44_ALGORITHM_ID = 1


def burn_expect(block_boc: bytes):
    """A sweep's settlement extra: its burn verified in the block file `block_boc`
    (Operations.verify_burn). Without one a delivered sweep stays pending."""

    def expect(operations, record, delivery, evidence):
        return operations.verify_burn(record, delivery, evidence, block_boc)

    return expect


class OperationRefused(lib.TestnetError):
    """The gate or a manual path refuses; the message says what was found."""


class Unknown(OperationRefused):
    """History or state could not be established; never evidence of absence."""


def crash_point(op_id: str, point: str) -> None:
    if os.environ.get(CRASH_ENV) == f"{op_id}:{point}":
        print(f"crash hook: exiting at {op_id}:{point}", flush=True)
        os._exit(70)


# ---------------------------------------------------------------- message decoding


def b64hash(value: Any) -> bytes:
    if not isinstance(value, str):
        raise Unknown(f"not a base64 hash: {value!r}")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise Unknown(f"not a base64 hash: {value!r}") from exc
    if len(raw) != 32:
        raise Unknown(f"a hash of {len(raw)} bytes: {value!r}")
    return raw


def span_cell(cell: lib.Cell, bit_start: int, bit_end: int, ref_start: int, ref_end: int):
    s = lib.Slice(cell)
    s.bits(bit_start)
    bits = "".join(str(s.bits(1)) for _ in range(bit_end - bit_start))
    return lib.cell_from_bits(bits, cell.refs[ref_start:ref_end])


def read_address(s: lib.Slice) -> str | None:
    """MsgAddress: addr_none -> None, addr_std -> workchain:hex; others refused."""
    tag = s.bits(2)
    if tag == 0:
        return None
    if tag != 2:
        raise lib.TestnetError(f"unsupported address tag {tag:02b}")
    if s.bits(1):
        raise lib.TestnetError("anycast addresses are not used here")
    workchain = s.bits(8)
    workchain -= 256 if workchain > 127 else 0
    return f"{workchain}:{s.bytes(32).hex()}"


def read_coins(s: lib.Slice) -> int:
    return s.bits(8 * s.bits(4))


def read_currency(s: lib.Slice) -> int:
    value = read_coins(s)
    if s.bits(1):
        raise lib.TestnetError("extra currencies are not expected here")
    return value


def read_init_and_body(s: lib.Slice) -> tuple[bytes | None, bytes, lib.Cell]:
    """init:(Maybe (Either StateInit ^StateInit)) body:(Either X ^X) -> hashes and body cell."""
    init_hash = None
    if s.bits(1):
        if s.bits(1):
            init_hash = s.take_ref().hash()
        else:
            start, ref_start = s.pos, s.ref
            if s.bits(1):
                s.bits(5)
            if s.bits(1):
                s.bits(2)
            for _ in range(2):  # code, data
                if s.bits(1):
                    s.take_ref()
            if s.bits(1):  # library
                s.take_ref()
            init_hash = span_cell(s.cell, start, s.pos, ref_start, s.ref).hash()
    if s.bits(1):
        body = s.take_ref()
    else:
        body = span_cell(s.cell, s.pos, s.cell.bits, s.ref, len(s.cell.refs))
    return init_hash, body.hash(), body


def decode_internal(cell: lib.Cell) -> dict:
    s = lib.Slice(cell)
    if s.bits(1) != 0:
        raise lib.TestnetError("not an internal message")
    s.bits(1)  # ihr_disabled
    bounce = bool(s.bits(1))
    s.bits(1)  # bounced
    read_address(s)  # source, filled in by the wallet
    destination = read_address(s)
    value = read_currency(s)
    read_coins(s)  # ihr fee
    read_coins(s)  # forward fee
    s.bits(64 + 32)
    init_hash, body_hash, _ = read_init_and_body(s)
    return {
        "destination": destination,
        "value": value,
        "bounce": bounce,
        "init_hash": init_hash.hex() if init_hash else None,
        "body_hash": body_hash.hex(),
    }


def decode_signed_header(root: lib.Cell) -> dict:
    """The wallet v3 signed header of an external message (global id, subwallet,
    valid_until, seqno), whatever follows it. A wallet v3 accepts up to four
    transfers per message (wallet3-code.fc), so a competitor that consumed a seqno
    is identified by this header alone, not by decode_external's single-transfer
    shape."""
    s = lib.Slice(root)
    if s.bits(2) != 0b10:
        raise lib.TestnetError("not an external inbound message")
    read_any_address(s)
    destination = read_address(s)
    read_coins(s)
    _init_hash, _, body = read_init_and_body(s)
    b = lib.Slice(body)
    b.bits(512)
    global_id = b.bits(32)
    global_id -= (global_id >> 31) << 32
    return {
        "destination": destination,
        "global_id": global_id,
        "subwallet": b.bits(32),
        "valid_until": b.bits(32),
        "seqno": b.bits(32),
    }


def decode_external(boc: bytes) -> dict:
    """An external message to a wallet v3, as wallet-v3.fif, new-wallet-v3.fif and
    tosctl build it: the signature, then the signed part (global id, subwallet,
    valid_until, seqno, and for a transfer the mode and the internal message)."""
    root = lib.parse_boc(boc)
    s = lib.Slice(root)
    if s.bits(2) != 0b10:
        raise lib.TestnetError("not an external inbound message")
    if read_address(s) is not None:
        raise lib.TestnetError("an external message with a source address")
    destination = read_address(s)
    read_coins(s)  # import fee
    init_hash, _, body = read_init_and_body(s)
    b = lib.Slice(body)
    b.bits(512)
    global_id = b.bits(32)
    global_id -= (global_id >> 31) << 32
    out = {
        "external_hash": root.hash().hex(),
        "destination": destination,
        "init_hash": init_hash.hex() if init_hash else None,
        "global_id": global_id,
        "subwallet": b.bits(32),
        "valid_until": b.bits(32),
        "seqno": b.bits(32),
        "mode": None,
        "internal": None,
    }
    if b.remaining() or b.ref < len(body.refs):
        out["mode"] = b.bits(8)
        out["internal"] = decode_internal(b.take_ref())
    if not b.end():
        raise lib.TestnetError("trailing data in the signed part")
    return out


def credit_of(transaction_boc: bytes) -> int | None:
    """The credit phase's amount of an ordinary transaction, decoded from its BOC."""
    s = lib.Slice(lib.parse_boc(transaction_boc))
    if s.bits(4) != 0b0111:
        raise lib.TestnetError("not a transaction")
    s.bits(256 + 64 + 256 + 64 + 32 + 15 + 2 + 2)
    s.take_ref()  # in_msg and out_msgs
    read_currency_dict(s)  # total fees
    s.take_ref()  # state update
    d = lib.Slice(s.take_ref())
    if d.bits(4) != 0:
        return None  # not trans_ord
    d.bits(1)  # credit_first
    if d.bits(1):  # storage phase
        read_coins(d)
        if d.bits(1):
            read_coins(d)
        if d.bits(1):
            d.bits(1)
    if not d.bits(1):
        return None
    if d.bits(1):
        read_coins(d)  # due fees collected
    return read_currency(d)


def read_currency_dict(s: lib.Slice) -> int:
    value = read_coins(s)
    if s.bits(1):
        s.take_ref()
    return value


# ---------------------------------------------------------------- nodes


class Node:
    """One validator's JSON-RPC, as the operations read it."""

    def __init__(self, url: str, rpc=lib.rpc):
        self.url, self.rpc = url, rpc

    @property
    def rpc(self):
        return self._rpc

    @rpc.setter
    def rpc(self, rpc) -> None:
        # One node a block or two behind the others answers a read with "not
        # applied" for a few seconds; every read waits for it (lib.retrying_reads),
        # sendBoc never repeats. Agreement between nodes is checked on the answers.
        self._rpc = lib.retrying_reads(rpc)

    def call(self, rpc_method: str, /, **params: Any) -> Any:
        try:
            return self.rpc(self.url, rpc_method, **params)
        except lib.TestnetError as exc:
            raise Unknown(f"{self.url}: {exc}") from exc

    def account(self, address: str) -> dict:
        info = self.call("getAddressInformation", address=address)
        if not isinstance(info, dict) or "state" not in info or "balance" not in info:
            raise Unknown(f"{self.url}: malformed account answer for {address}")
        return info

    def seqno(self, address: str) -> int:
        if self.account(address)["state"] != "active":
            return 0
        result = self.call("runGetMethod", address=address, method="seqno", stack=[])
        stack = result.get("stack") if isinstance(result, dict) else None
        if result.get("exit_code") != 0 or not stack or not isinstance(stack[0], list):
            raise Unknown(f"{self.url}: seqno of {address}: {result}")
        try:
            return int(stack[0][1], 0)
        except (TypeError, ValueError) as exc:
            raise Unknown(f"{self.url}: seqno of {address}: {stack[0]!r}") from exc

    def utime(self) -> int:
        last = self.call("getMasterchainInfo")["last"]
        header = self.call(
            "getBlockHeader",
            workchain=lib.MASTERCHAIN,
            shard=str(lib.MASTERCHAIN_SHARD),
            seqno=int(last["seqno"]),
        )
        return int(header["gen_utime"])

    def history(self, address: str, boundary: dict | None, since: int | None = None) -> list[dict]:
        """Transactions newer than `boundary` (None: the whole account), newest first,
        each decoded from its own BOC (verify_transaction).

        getTransactionsStd pages backward through previous_transaction_id. The
        boundary must be reached exactly; anything else is Unknown. A since cutoff
        stops only after decoding an older transaction, without requesting older
        pages that may already have been collected."""
        info = self.account(address)
        last = info.get("last_transaction_id") or {}
        lt, hash_b64 = str(last.get("lt", "0")), last.get("hash", "")
        if lt == "0":
            if boundary:
                raise Unknown(f"{self.url}: {address} has no transactions, boundary {boundary}")
            return []
        if boundary and hash_b64 and b64hash(hash_b64).hex() == boundary["hash"]:
            # Nothing after the boundary; its block may already be pruned.
            return []
        out, seen = [], set()
        for _ in range(HISTORY_PAGES):
            page = self.call(
                "getTransactionsStd",
                address=address,
                lt=lt,
                hash=hash_b64,
                limit=1 if since is not None else HISTORY_PAGE,
            )
            txs = page.get("transactions") if isinstance(page, dict) else None
            if not isinstance(txs, list) or not txs:
                raise Unknown(f"{self.url}: empty history page for {address} at {lt}")
            progress = False
            for tx in txs:
                tid = tx.get("transaction_id") if isinstance(tx, dict) else None
                if not isinstance(tid, dict):
                    raise Unknown(f"{self.url}: a transaction without an id for {address}")
                tx_hash = b64hash(tid.get("hash")).hex()
                try:
                    tx_lt = int(tid.get("lt", -1))
                except (TypeError, ValueError) as exc:
                    raise Unknown(f"{self.url}: transaction lt {tid.get('lt')!r}") from exc
                if boundary and tx_hash == boundary["hash"]:
                    return out
                if boundary and tx_lt <= int(boundary["lt"]):
                    raise Unknown(f"{self.url}: {address} history passed its boundary {boundary}")
                if tx_hash in seen:
                    continue
                seen.add(tx_hash)
                progress = True
                out.append(verify_transaction(tx.get("data"), tx_hash, address, tx_lt))
                if since is not None and out[-1]["utime"] < since:
                    return out
            prev = page.get("previous_transaction_id") or {}
            if boundary and prev.get("hash") and b64hash(prev["hash"]).hex() == boundary["hash"]:
                return out  # the next one is the boundary; it may already be pruned
            if str(prev.get("lt", "")) == "0":
                if boundary:
                    raise Unknown(f"{self.url}: {address} boundary {boundary} not in its history")
                return out
            if not progress:
                raise Unknown(f"{self.url}: {address} history made no progress at {lt}")
            lt, hash_b64 = str(prev.get("lt")), prev.get("hash")
        raise Unknown(f"{self.url}: {address} history longer than {HISTORY_PAGES} pages")

    def delivery(self, destination: str, message_hash: str, created_lt: int) -> dict | None:
        """Find the emitted message in a bounded sequence of destination shard blocks.

        LT routing follows the destination prefix through topology changes. Every
        page/header is bound to the lookup's full block identity. No account-history
        cursor or current account state is involved.
        """
        for tx in self.shard_transactions(destination, created_lt):
            if tx["in_kind"] == "internal" and tx["in_hash"] == message_hash:
                if tx["lt"] <= created_lt:
                    raise Unknown(
                        f"{self.url}: unknown delivery block: delivery precedes message creation"
                    )
                return tx
        return None

    def external_runs(self, wallet: str, external_hash: str, from_lt: int) -> list[dict]:
        """Every transaction of `wallet` that ran the external message, oldest first,
        up to and including the first one that took effect, from the blocks after
        `from_lt`. This finds a run without the account's head, which a deleted
        account no longer has."""
        runs = []
        for tx in self.shard_transactions(wallet, from_lt, SWEEP_SEARCH_BLOCKS):
            if tx["in_kind"] == "external" and tx["in_hash"] == external_hash:
                runs.append({k: v for k, v in tx.items() if k != "block"})
                if took_effect(tx):
                    break
        return runs

    def shard_transactions(self, destination: str, created_lt: int, budget: int | None = None):
        """The destination's transactions in its shard's blocks from created_lt on, in
        block order, each decoded from its own BOC and carrying its block id."""
        budget = DELIVERY_BLOCKS if budget is None else budget
        wc, account = destination.split(":")
        prefix = int(account[:16], 16)
        shard = prefix | 1
        if shard >= 2**63:
            shard -= 2**64
        # Native masterchain lookup accepts only the full masterchain shard.
        if int(wc) == lib.MASTERCHAIN:
            shard = lib.MASTERCHAIN_SHARD
        cursor = created_lt
        last = self.call("getMasterchainInfo")["last"]
        head = self.call(
            "getBlockHeader", workchain=-1, shard=str(lib.MASTERCHAIN_SHARD), seqno=last["seqno"]
        )
        stop = int(head["end_lt"])
        seen = set()
        for _ in range(budget):
            if cursor >= stop:
                return
            block = self.call("lookupBlock", workchain=int(wc), shard=str(shard), lt=str(cursor))
            try:
                block_wc, block_shard = int(block["workchain"]), int(block["shard"])
                seqno = int(block["seqno"])
                b64hash(block["root_hash"])
                b64hash(block["file_hash"])
                unsigned = block_shard & (2**64 - 1)
                low = unsigned & -unsigned
                mask = (2**64 - 1) ^ (2 * low - 1)
                if (
                    block_wc != int(wc)
                    or not -(2**63) <= block_shard < 2**63
                    or not low
                    or not 0 <= seqno < 2**32
                    or prefix & mask != unsigned & mask
                ):
                    raise ValueError("lookup is not a block of the destination shard")
                key = (block_wc, block_shard, seqno, block["root_hash"], block["file_hash"])
                if key in seen:
                    raise ValueError("block search made no progress")
                seen.add(key)
                args = {"workchain": block_wc, "shard": str(block_shard), "seqno": seqno}
                header = self.call("getBlockHeader", **args)
                if header.get("id") != block or int(header["end_lt"]) < cursor:
                    raise ValueError("block header identity/range mismatch")
                after = {}
                previous = None
                for _ in range(DELIVERY_BLOCK_PAGES):
                    page = self.call(
                        "getBlockTransactionsExt", **args, count=DELIVERY_PAGE, **after
                    )
                    if page.get("id") != block or type(page.get("incomplete")) is not bool:
                        raise ValueError("transaction page block identity mismatch")
                    rows = page.get("transactions")
                    if not isinstance(rows, list) or len(rows) > DELIVERY_PAGE:
                        raise ValueError("invalid transaction page")
                    for row in rows:
                        row_account = row["account"].lower()
                        if len(row_account) != 64:
                            raise ValueError("invalid transaction account")
                        position = (int(row_account, 16), int(row["lt"]))
                        if previous is not None and position <= previous:
                            raise ValueError("transaction page made no progress")
                        previous = position
                        if row_account == account:
                            tx = verify_transaction(
                                row.get("data"),
                                b64hash(row["hash"]).hex(),
                                destination,
                                position[1],
                            )
                            yield dict(tx, block=block)
                    if not page["incomplete"]:
                        break
                    if not rows:
                        raise ValueError("empty incomplete transaction page")
                    after = {"after_account": rows[-1]["account"], "after_lt": str(rows[-1]["lt"])}
                else:
                    raise Unknown("delivery block exceeds transaction-page budget")
                cursor = int(header["end_lt"]) + 1
            except (KeyError, TypeError, ValueError, lib.TestnetError) as exc:
                raise Unknown(f"{self.url}: unknown delivery block: {exc}") from exc
        raise Unknown(f"delivery search exceeds {budget} shard blocks; remains unsettled")


# ---------------------------------------------------------------- transactions from their BOC


def read_any_address(s: lib.Slice) -> str | None:
    """MsgAddress including addr_extern (external messages' source or destination)."""
    if s.bits(2) == 0b01:
        s.bits(s.bits(9))
        return None
    s.pos -= 2
    return read_address(s)


def decode_message(cell: lib.Cell) -> dict:
    """The summary the rules read, from a Message cell."""
    s = lib.Slice(cell)
    if s.bits(1) == 0:
        s.bits(1)  # ihr_disabled
        s.bits(1)  # bounce
        bounced = bool(s.bits(1))
        source = read_address(s)
        destination = read_address(s)
        value = read_coins(s)
        if s.bits(1):
            s.take_ref()  # extra currencies
        read_coins(s)  # ihr_fee
        read_coins(s)  # fwd_fee
        created_lt = s.bits(64)
        return {
            "kind": "internal",
            "created_lt": created_lt,
            "hash": cell.hash().hex(),
            "source": source,
            "destination": destination,
            "value": value,
            "bounced": bounced,
        }
    if s.bits(1) == 0:
        read_any_address(s)
        destination = read_address(s)
        return {
            "kind": "external",
            "hash": cell.hash().hex(),
            "source": None,
            "destination": destination,
            "value": None,
            "bounced": False,
        }
    source = read_address(s)
    return {
        "kind": "external-out",
        "hash": cell.hash().hex(),
        "source": source,
        "destination": None,
        "value": None,
        "bounced": False,
    }


# AccountStatus: acc_state_uninit$00 frozen$01 active$10 nonexist$11.
ACCOUNT_STATUS = ("uninit", "frozen", "active", "nonexist")


def verify_transaction(data: Any, tx_hash: str, address: str, tx_lt: int) -> dict:
    """A transaction decoded from its BOC, bound to its reported id and account.

    The root's hash must be the reported transaction hash, the decoded account the
    queried one and the decoded lt the reported lt. Every fact the rules use (in and
    out messages and their hashes, compute success, aborted, the credit) comes from
    the decoded cells, never from the node's JSON summary. Anything else is Unknown."""
    if not isinstance(data, str) or not data:
        raise Unknown(f"transaction {tx_hash} has no data")
    try:
        root = lib.parse_boc(base64.b64decode(data, validate=True))
        if root.hash().hex() != tx_hash:
            raise Unknown(f"transaction {tx_hash}: its BOC hashes to {root.hash().hex()}")
        s = lib.Slice(root)
        if s.bits(4) != 0b0111:
            raise Unknown(f"transaction {tx_hash} is not a transaction")
        account = s.bytes(32).hex()
        lt = s.bits(64)
        previous_hash, previous_lt = s.bytes(32).hex(), s.bits(64)
        utime = s.bits(32)
        s.bits(15)
        orig_status, end_status = ACCOUNT_STATUS[s.bits(2)], ACCOUNT_STATUS[s.bits(2)]
        if f"{address.split(':')[0]}:{account}" != address or lt != tx_lt:
            raise Unknown(f"transaction {tx_hash} belongs to {account} at lt {lt}")
        m = lib.Slice(s.take_ref())
        incoming = decode_message(m.take_ref()) if m.bits(1) else None
        outgoing = []
        if m.bits(1):
            entries = lib.hashmap_items(m.take_ref(), 15)
            outgoing = [decode_message(entries[k].take_ref()) for k in sorted(entries)]
        read_currency_dict(s)
        s.take_ref()
        d = lib.Slice(s.take_ref())
        compute_success, aborted, credit = False, None, None
        if d.bits(4) == 0:  # trans_ord
            d.bits(1)
            if d.bits(1):
                read_coins(d)
                if d.bits(1):
                    read_coins(d)
                if d.bits(1):
                    d.bits(1)
            if d.bits(1):
                if d.bits(1):
                    read_coins(d)
                credit = read_currency_dict(d)
            if d.bits(1):  # tr_phase_compute_vm
                compute_success = bool(d.bits(1))
                d.bits(2)
                read_coins(d)
                d.take_ref()
            elif d.bits(2) == 0b11:  # skipped; cskip_suspended has a third bit
                d.bits(1)
            if d.bits(1):
                d.take_ref()
            aborted = bool(d.bits(1))
    except Unknown:
        raise
    except (lib.TestnetError, ValueError, IndexError) as exc:
        raise Unknown(f"transaction {tx_hash} cannot be decoded: {exc}") from exc
    return {
        "hash": tx_hash,
        "lt": tx_lt,
        "utime": utime,
        "previous": {"hash": previous_hash, "lt": str(previous_lt)},
        "data": data,
        "in_kind": incoming["kind"] if incoming else None,
        "in_hash": incoming["hash"] if incoming else None,
        "in_source": incoming["source"] if incoming else None,
        "in_value": incoming["value"] if incoming else None,
        "in_bounced": incoming["bounced"] if incoming else False,
        "aborted": aborted,
        "compute_success": compute_success,
        "credit": credit,
        "out": outgoing,
        "orig_status": orig_status,
        "end_status": end_status,
    }


def external_seqno(tx: dict) -> int | None:
    """The seqno an external message signed, decoded from the transaction's BOC."""
    try:
        root = lib.parse_boc(base64.b64decode(tx["data"]))
        messages = lib.Slice(root.refs[0])
        if not messages.bits(1):
            return None
        return decode_signed_header(messages.take_ref())["seqno"]
    except (lib.TestnetError, ValueError, IndexError, KeyError):
        return None


def took_effect(tx: dict) -> bool:
    """Whether a transaction installed its computed state and its actions. Compute
    can succeed and the action phase still abort (a mode 1 transfer above the
    balance, say). The transaction still charges its fees and updates the account's
    balance and last-transaction metadata, but the computed data (so a wallet's
    seqno) and the out messages are not applied, and the same external message can
    run again while it is valid."""
    return bool(tx["compute_success"]) and tx["aborted"] is False


def leaves(tx: dict, wallet: str) -> bool:
    """Whether a transaction sent value away from the wallet. A message to the
    wallet itself (tosctl's `wallet activate` deploys a wallet with one) moves
    nothing and needs no operation."""
    return any(m["destination"] != wallet for m in tx["out"])


def party(address: Any) -> str | None:
    if address is None:
        return None
    if not isinstance(address, str):
        raise Unknown(f"not an address: {address!r}")
    if ":" in address:
        return lib.check_raw_address(address)
    data = base64.urlsafe_b64decode(
        address.replace("+", "-").replace("/", "_") + "=" * (-len(address) % 4)
    )
    if len(data) != 36:
        raise Unknown(f"not a user-friendly address: {address!r}")
    return f"{int.from_bytes(data[1:2], 'big', signed=True)}:{data[2:34].hex()}"


# ---------------------------------------------------------------- the journal


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def append_line(path: Path, entry: dict) -> None:
    """One JSON line appended in full and fsynced with its directory, or a refusal."""
    data = (json.dumps(entry, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        written = 0
        while written < len(data):
            count = os.write(fd, data[written:])
            if count <= 0:
                raise OperationRefused(f"{path}: the journal write made no progress")
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(path.parent)


def publish_new(path: Path, entry: dict) -> None:
    """A new record file holding one complete line, or none at all.

    Written to a temporary file in the same directory, fsynced, then linked to its
    name (which refuses an existing one) and the directory fsynced: a crash leaves
    only a hidden temporary file, which nothing reads and the next attempt replaces.
    """
    data = (json.dumps(entry, sort_keys=True) + "\n").encode()
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        written = 0
        while written < len(data):
            count = os.write(fd, data[written:])
            if count <= 0:
                raise OperationRefused(f"{tmp}: the journal write made no progress")
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(tmp, path)
    except FileExistsError as exc:
        raise OperationRefused(f"{path} exists already") from exc
    finally:
        os.unlink(tmp)
    fsync_dir(path.parent)


ATTEMPT = re.compile(
    r"^(?P<step>[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]+)*?)(?:\.attempt-(?P<n>[2-9]|[1-9][0-9]+))?$"
)


def attempt_id(step: str, n: int) -> str:
    return step if n == 1 else f"{step}.attempt-{n}"


class Journal:
    """ceremony/operations/: one append-only record per operation, one lock for all.

    A single lock over the whole journal gives every transition the same order
    (no per-wallet locks to take in two orders), binds an id to its wallet and
    parameters atomically, and serializes attempts after failures."""

    def __init__(self, ceremony: Path):
        self.dir = Path(ceremony) / OPERATIONS_DIR

    def ensure(self) -> Path:
        lib.private_dir(self.dir)
        return self.dir

    def path(self, op_id: str) -> Path:
        if not SAFE_ID.match(op_id) or ".." in op_id:
            raise OperationRefused(f"not an operation id: {op_id!r}")
        return self.dir / f"{op_id}.jsonl"

    def lines(self, op_id: str) -> list[dict]:
        path = self.path(op_id)
        if not path.exists():
            return []
        text = path.read_text()
        if text and not text.endswith("\n"):
            raise OperationRefused(f"{path} ends in a torn line; reconcile it by hand")
        out = []
        for number, line in enumerate(text.splitlines(), 1):
            try:
                entry = json.loads(line)
            except ValueError as exc:
                raise OperationRefused(f"{path} line {number} is not JSON") from exc
            if entry.get("state") not in STATES:
                raise OperationRefused(f"{path} line {number} has no known state")
            out.append(entry)
        return out

    def record(self, op_id: str) -> dict | None:
        lines = self.lines(op_id)
        if not lines:
            return None
        merged: dict = {}
        for entry in lines:
            merged.update(entry)
        merged["id"] = op_id
        return merged

    def append(self, op_id: str, entry: dict) -> None:
        self.ensure()
        entry = dict(entry, utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        path = self.path(op_id)
        if path.exists():
            append_line(path, entry)
        else:
            publish_new(path, entry)

    def all(self) -> list[dict]:
        if not self.dir.is_dir():
            return []
        return [
            self.record(p.stem)
            for p in sorted(self.dir.glob("*.jsonl"))
            if not p.name.startswith("baseline-")
        ]

    def for_wallet(self, wallet: str) -> list[dict]:
        return [r for r in self.all() if r and r.get("wallet") == wallet]

    def attempts(self, step: str) -> list[tuple[int, str]]:
        """(n, id) of every recorded attempt of a step, oldest first."""
        if not SAFE_ID.match(step) or ".attempt-" in step:
            raise OperationRefused(f"not a step id: {step!r}")
        found = []
        if self.path(step).exists():
            found.append((1, step))
        if self.dir.is_dir():
            for p in self.dir.glob(f"{step}.attempt-*.jsonl"):
                match = ATTEMPT.match(p.stem)
                if match and match.group("step") == step and match.group("n"):
                    found.append((int(match.group("n")), p.stem))
        found.sort()
        numbers = [n for n, _ in found]
        if numbers != list(range(1, len(numbers) + 1)):
            raise OperationRefused(f"step {step} has attempts {numbers}; reconcile it by hand")
        return found

    def newest(self, step: str) -> str:
        attempts = self.attempts(step)
        return attempts[-1][1] if attempts else step

    @contextlib.contextmanager
    def lock(self, wallet: str | None = None):
        """The journal lock; `wallet` is only named in the refusal."""
        self.ensure()
        fd = os.open(self.dir / ".lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise OperationRefused(
                f"another run holds the operations journal lock ({wallet or 'journal'}); "
                "wait for it, then run again"
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def baseline(self, wallet: str) -> dict | None:
        entry = self.baseline_entry(wallet)
        return entry["boundary"] if entry else None

    def baseline_entry(self, wallet: str) -> dict | None:
        path = self.dir / f"baseline-{wallet.replace(':', '_')}.jsonl"
        if not path.is_file():
            return None
        lines = [json.loads(line) for line in path.read_text().splitlines() if line]
        return lines[-1] if lines else None

    def settled_boundary(self, wallet: str) -> tuple[dict, str] | None:
        """The wallet transaction of the wallet's newest settled operation, as a
        history boundary, with the record's last journal time.

        The operation's gate read the wallet's complete history before it signed,
        and its settlement proved that this transaction consumed exactly its
        message's seqno. A wallet v3 runs its externals in seqno order, so nothing
        else the wallet sent can lie between that check and this transaction. Its
        lt is the recorded one; a record from before lts were recorded gives "0",
        and the boundary is then reached by hash alone."""
        newest = None
        for record in self.for_wallet(wallet):
            evidence = record.get("evidence") or {}
            if state_of(record) != "settled" or not evidence.get("wallet_tx"):
                continue
            if not isinstance(record.get("seqno"), int):
                continue
            if newest is None or record["seqno"] > newest["seqno"]:
                newest = record
        if newest is None:
            return None
        evidence = newest["evidence"]
        boundary = {"hash": evidence["wallet_tx"], "lt": evidence.get("wallet_tx_lt", "0")}
        return boundary, newest.get("utc", "")

    def set_baseline(self, wallet: str, boundary: dict, reason: str) -> None:
        self.ensure()
        path = self.dir / f"baseline-{wallet.replace(':', '_')}.jsonl"
        entry = {
            "wallet": wallet,
            "boundary": boundary,
            "reason": reason,
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        append_line(path, entry)

    def explained(self) -> set[str]:
        out: set[str] = set()
        for record in self.all():
            if record and record.get("state") in ("settled", "failed"):
                out.update(record.get("evidence", {}).get("explains", []))
        return out


def state_of(record: dict | None) -> str | None:
    return record.get("state") if record else None


# ---------------------------------------------------------------- the operations context


class Operations:
    """The two validators, the journal and the network an operation runs against."""

    def __init__(
        self,
        ceremony: Path,
        nodes: list[Node],
        global_id: int,
        clock=time.time,
        sleep=time.sleep,
        *,
        profile_path: Path = lib.PROFILE_PATH,
    ):
        if len(nodes) != 2 or nodes[0].url == nodes[1].url:
            raise OperationRefused("value-moving steps need two different validators")
        self.ceremony = Path(ceremony)
        self.nodes, self.global_id = nodes, global_id
        self.journal = Journal(ceremony)
        self.clock, self.sleep = clock, sleep
        self.profile_path = profile_path

    # -- network

    def check_network(self) -> None:
        genesis = json.loads((self.ceremony / "genesis.json").read_text())
        zero = genesis["zero_state"]
        for node in self.nodes:
            info = node.call("getMasterchainInfo")
            init = info.get("init") or {}
            if (init.get("root_hash"), init.get("file_hash")) != (
                zero["root_hash"],
                zero["file_hash"],
            ):
                raise OperationRefused(f"{node.url} serves another network (zero state)")
            header = node.call(
                "getBlockHeader",
                workchain=lib.MASTERCHAIN,
                shard=str(lib.MASTERCHAIN_SHARD),
                seqno=int(info["last"]["seqno"]),
            )
            if int(header.get("global_id", 0)) != self.global_id:
                raise OperationRefused(f"{node.url} serves global id {header.get('global_id')}")

    # -- reading both

    def read_both(self, read) -> list:
        """Revalidate each endpoint before using either validator's chain facts."""
        self.check_network()
        return [read(node) for node in self.nodes]

    def both(self, read) -> Any:
        answers = self.read_both(read)
        if answers[0] != answers[1]:
            raise Unknown(f"the validators disagree or one lags: {answers[0]!r} / {answers[1]!r}")
        return answers[0]

    def history(self, wallet: str, boundary: dict | None) -> list[dict]:
        """Agreed history: the same transactions (each verified against its own BOC
        on each node, so the same hash means the same decoded facts)."""
        histories = self.read_both(lambda node: node.history(wallet, boundary))
        if histories[0] != histories[1]:
            raise Unknown(f"the validators' histories of {wallet} disagree or one lags")
        return histories[0]

    def seqno(self, wallet: str) -> int:
        return self.both(lambda n: n.seqno(wallet))

    def head(self, wallet: str) -> dict | None:
        def read(node):
            last = node.account(wallet).get("last_transaction_id") or {}
            if str(last.get("lt", "0")) == "0":
                return None
            return {"lt": str(last["lt"]), "hash": b64hash(last["hash"]).hex()}

        return self.both(read)

    def wallet_data(self, wallet: str) -> tuple[str, str, int] | None:
        """(code hash, public key, subwallet) of an active wallet v3, agreed by both."""

        def read(node):
            info = node.account(wallet)
            code, data = info.get("code") or "", info.get("data") or ""
            if info["state"] != "active" or not code or not data:
                return None
            try:
                data_slice = lib.Slice(lib.parse_boc(base64.b64decode(data)))
                data_slice.bits(32)
                subwallet = data_slice.bits(32)
                public_key = data_slice.bytes(32).hex()
                code_hash = lib.parse_boc(base64.b64decode(code)).hash().hex()
            except (lib.TestnetError, ValueError) as exc:
                raise Unknown(f"{node.url}: {wallet} is not a wallet v3: {exc}") from exc
            return code_hash, public_key, subwallet

        return self.both(read)

    def identity(self, wallet: str) -> tuple[str, str] | None:
        data = self.wallet_data(wallet)
        return (data[0], data[1]) if data else None

    def balance(self, address: str) -> int:
        return self.both(lambda n: int(n.account(address)["balance"]))

    def state(self, address: str) -> str:
        return self.both(lambda n: n.account(address)["state"])

    def utimes(self) -> list[int]:
        return self.read_both(lambda node: node.utime())

    def election_message(self, wallet: str, tx: dict) -> dict | None:
        """Recognize the election task's bounded pool messages from their verified transaction.

        Only new-stake carries an election id and needs a genesis-configured window.
        Recovery and maintenance bodies have exact layouts and native value ceilings.
        """
        path = self.ceremony / "pools.json"
        if not path.is_file() or not wallet.startswith("-1:"):
            return None
        pools = json.loads(path.read_text())
        matches = [
            entry["pool"]
            for entry in pools.values()
            if entry.get("operator") == wallet and entry.get("pool")
        ]
        if len(matches) != 1 or not took_effect(tx) or tx["in_kind"] != "external":
            return None
        if len(tx["out"]) != 1:
            return None
        message = tx["out"][0]
        if (
            message["kind"] != "internal"
            or message["destination"] != matches[0]
            or message["source"] != wallet
            or message["bounced"]
        ):
            return None
        # Decode the outgoing message, not the external's template or JSON summary.
        try:
            root = lib.parse_boc(base64.b64decode(tx["data"], validate=True))
            messages = lib.Slice(root.refs[0])
            if messages.bits(1):
                messages.take_ref()
            if not messages.bits(1):
                return None
            entries = lib.hashmap_items(messages.take_ref(), 15)
            outgoing = next(iter(entries.values())).take_ref()
            m = lib.Slice(outgoing)
            m.bits(4)
            read_address(m)
            read_address(m)
            read_currency(m)  # refuses extra currencies as an additional effect
            read_coins(m)
            read_coins(m)
            m.bits(64 + 32)
            init, _, body = read_init_and_body(m)
            b = lib.Slice(body)
            if init is not None:
                return None
            opcode = b.bits(32)
            query_id = b.bits(64)
            # runner.rs and the pool client's maintenance(): only these messages
            # can leave the election wallet, with one internal message per send.
            kinds = {
                0x4E73744B: ("new-stake", None),
                0x47657424: ("recover-stake", 200_000_000),
                0x06: ("update-validator-set", 200_000_000),
                0x04: ("validator-deposit", 10_000_000_000),
                0x02: ("process-withdraw-requests", 200_000_000),
            }
            if opcode not in kinds:
                return None
            kind, ceiling = kinds[opcode]
            if kind == "new-stake":
                # The pool order layout (tosctl nominator::new_stake): the stake the
                # pool forwards, then the ML-DSA-44 authorization fields the Elector
                # reads, and nothing after them.
                stake = read_coins(b)
                if stake <= 0 or b.bits(16) != MLDSA44_ALGORITHM_ID:
                    return None
                b.take_ref()  # public key
                stake_at = b.bits(32)
                b.bits(32 + 256)  # max factor, ADNL address
                b.take_ref()  # signature
                if not b.end():
                    return None
            else:
                if kind == "process-withdraw-requests" and b.bits(8) != 8:
                    return None
                if not b.end() or not 0 < message["value"] <= ceiling:
                    return None
        except (lib.TestnetError, ValueError, IndexError):
            return None

        explanation = {
            "wallet": wallet,
            "tx": tx["hash"],
            "lt": tx["lt"],
            "out": tx["out"],
            "explained_by": f"election-{kind}",
            "utime": tx["utime"],
            "query_id": query_id,
        }
        if kind != "new-stake":
            return explanation

        ceiling = lib.load_profile(self.profile_path)["elections"].get("stake_order_nanotos")
        if type(ceiling) is not int or not 0 < ceiling < 2**120:
            raise Unknown("invalid profile stake order value")
        if not 0 < message["value"] <= ceiling:
            return None

        genesis = json.loads((self.ceremony / "genesis.json").read_text())
        try:
            expected = tuple(genesis["election_params"][name] for name in lib.ELECTION_PARAM_NAMES)
            if any(type(n) is not int or not 0 < n < 2**32 for n in expected):
                raise ValueError("invalid genesis election parameters")
        except (KeyError, TypeError, ValueError) as exc:
            raise Unknown(f"unknown genesis election parameters: {exc}") from exc

        def window(node):
            config = node.call("getConfigParam", param=15)
            try:
                c = lib.Slice(
                    lib.parse_boc(base64.b64decode(config["config"]["bytes"], validate=True))
                )
                values = tuple(c.bits(32) for _ in range(4))
                if not c.end() or values != expected:
                    raise Unknown(
                        "ConfigParam 15 changed since genesis; election window is unknown"
                    )
                return values
            except (KeyError, TypeError, ValueError, lib.TestnetError) as exc:
                raise Unknown(f"unknown current election parameters: {exc}") from exc

        elected_for, start_before, end_before, _held = self.both(window)
        active = stake_at
        if (
            not 0 < end_before < start_before < elected_for
            or not active
            or not active - start_before <= tx["utime"] < active - end_before
        ):
            return None
        return dict(
            explanation,
            election_id=active,
            stake_nanotos=stake,
            election_params=list(expected),
        )

    def bootstrap_identity(self, wallet: str) -> list | None:
        genesis = json.loads((self.ceremony / "genesis.json").read_text())
        key = genesis.get("main_wallet_public_key")
        if wallet != BOOTSTRAP_WALLET or not key:
            return None
        return [BOOTSTRAP_CODE_HASH, key.lower(), 0]

    def bootstrap_snapshot(self, wallet: str) -> dict:
        expected = self.bootstrap_identity(wallet)
        if expected is None:
            raise OperationRefused("checkpoint adapter supports only the pinned bootstrap wallet")

        def read(node):
            info = node.account(wallet)
            if info.get("state") == "uninitialized":
                # Deleted: a node reports an account it does not hold this way.
                return {"head": None, "seqno": None, "identity": None, "deleted": True}
            if info.get("state") != "active":
                raise Unknown("checkpoint wallet must be active or deleted")
            try:
                code = lib.parse_boc(base64.b64decode(info["code"], validate=True))
                data = lib.Slice(lib.parse_boc(base64.b64decode(info["data"], validate=True)))
                seqno, subwallet, key = data.bits(32), data.bits(32), data.bytes(32).hex()
                identity = [code.hash().hex(), key, subwallet]
                if not data.end() or identity != expected or seqno == 0xFFFFFFFF:
                    raise Unknown("checkpoint wallet identity changed or counter exhausted")
                last = info.get("last_transaction_id") or {}
                head = (
                    None
                    if int(last.get("lt", 0)) == 0
                    else {"hash": b64hash(last["hash"]).hex(), "lt": str(last["lt"])}
                )
                return {"head": head, "seqno": seqno, "identity": identity, "deleted": False}
            except (KeyError, ValueError, lib.TestnetError) as exc:
                raise Unknown(f"checkpoint wallet snapshot refused: {exc}") from exc

        return self.both(read)

    def bootstrap_state(self, wallet: str) -> dict:
        """The bootstrap wallet's snapshot, also once its final sweep deleted it.

        A deleted account has no head on the node, so the head is the sweep's own
        transaction, found from the sweep's signed boundary: the journaled external
        message, searched in the blocks after the masterchain head at signing on
        both validators. It must be the one run of that message that took effect,
        and it must have ended the account (end status nonexist). Its counter is the
        sweep's seqno plus one; bootstrap_tail then walks back from it to the
        boundary like from any head. -1:111...1 is not a StateInit address, so a
        later credit can only make an account that never runs code again."""
        snapshot = self.bootstrap_snapshot(wallet)
        if not snapshot["deleted"]:
            return snapshot
        found = []
        for record in self.journal.for_wallet(wallet):
            if record.get("kind") != "sweep" or not isinstance(record.get("boc"), str):
                continue
            tx = self.sweep_transaction(record)
            if tx is not None:
                found.append((record, tx))
        if len(found) != 1:
            raise Unknown(
                f"{wallet} is not active and {len(found)} journaled sweeps took effect; "
                "exactly one must explain the deletion"
            )
        record, tx = found[0]
        if tx["end_status"] != "nonexist":
            raise Unknown(f"{wallet} is not active but sweep {tx['hash']} did not delete it")
        return {
            "head": {"hash": tx["hash"], "lt": str(tx["lt"])},
            "seqno": record["seqno"] + 1,
            "identity": self.bootstrap_identity(wallet),
            "deleted": True,
            "swept_by": record["id"],
        }

    def sweep_transaction(self, record: dict) -> dict | None:
        """The transaction in which a signed sweep took effect, agreed by both
        validators, or None when it has not run."""
        try:
            floor = int(record["search_lt"])
        except (KeyError, TypeError, ValueError) as exc:
            raise Unknown(f"sweep {record['id']} has no signed search boundary") from exc

        def read(node):
            runs = node.external_runs(record["wallet"], record["external_hash"], floor)
            return next((tx for tx in runs if took_effect(tx)), None)

        return self.both(read)

    def bootstrap_retired(self, wallet: str) -> str | None:
        """The sweep that retired the bootstrap wallet as a funding source: one that
        settled, or that took effect and failed a later check. None otherwise."""
        if wallet != BOOTSTRAP_WALLET:
            return None
        for record in self.journal.for_wallet(wallet):
            if record.get("kind") != "sweep":
                continue
            evidence = record.get("evidence") or {}
            if state_of(record) == "settled" or (
                state_of(record) == "failed" and evidence.get("wallet_tx")
            ):
                return record["id"]
        return None

    def search_floor(self) -> int:
        """The lower of the two validators' masterchain head end_lt: every block a
        message broadcast after this read lands in starts above it."""

        def read(node):
            last = node.call("getMasterchainInfo")["last"]
            header = node.call(
                "getBlockHeader",
                workchain=lib.MASTERCHAIN,
                shard=str(lib.MASTERCHAIN_SHARD),
                seqno=int(last["seqno"]),
            )
            return int(header["end_lt"])

        return min(self.read_both(read))

    def bootstrap_certificate(self, wallet: str) -> dict | None:
        genesis = json.loads((self.ceremony / "genesis.json").read_text())
        certificates = {}
        for record in self.journal.for_wallet(wallet):
            for line in self.journal.lines(record["id"]):
                cp = line.get("checkpoint")
                if cp is None:
                    continue
                body = {k: v for k, v in cp.items() if k != "digest"}
                if (
                    line.get("state") not in ("settled", "failed")
                    or cp.get("digest") != certificate_digest(body)
                    or cp.get("version") != 1
                    or cp.get("wallet") != wallet
                    or cp.get("zero_state") != genesis["zero_state"]
                    or cp.get("global_id") != self.global_id
                    or cp.get("identity") != self.bootstrap_identity(wallet)
                    or cp.get("source_operation") != record["id"]
                    or not isinstance(cp.get("head"), dict)
                    or type(cp.get("post_seqno")) is not int
                    or not 0 <= cp["post_seqno"] < 0xFFFFFFFF
                ):
                    raise Unknown("invalid checkpoint certificate binding or digest")
                certificates[cp["digest"]] = cp
        parent = None
        previous_seqno, previous_lt = -1, -1
        while certificates:
            children = [cp for cp in certificates.values() if cp.get("previous") == parent]
            if len(children) != 1:
                raise Unknown("checkpoint certificates fork or have a missing parent")
            cp = children[0]
            if cp["post_seqno"] < previous_seqno or int(cp["head"]["lt"]) <= previous_lt:
                raise Unknown("checkpoint certificates regress")
            parent = cp["digest"]
            previous_seqno, previous_lt = cp["post_seqno"], int(cp["head"]["lt"])
            del certificates[parent]
        return cp if parent else None

    def bootstrap_tail(self, wallet: str, snapshot: dict, boundary: dict | None) -> dict:
        """Follow decoded previous pointers; only explicit archive absence permits a gap."""

        def read(node):
            cursor = snapshot["head"]
            txs = []
            for _ in range(HISTORY_PAGES):
                if cursor == boundary or cursor is None or int(cursor["lt"]) == 0:
                    if boundary and cursor != boundary:
                        raise Unknown("wallet history ended before the checkpoint")
                    return {"transactions": txs, "pruned": False}
                try:
                    answer = node.call(
                        "getTransactionsStd",
                        address=wallet,
                        limit=1,
                        lt=cursor["lt"],
                        hash=base64.b64encode(bytes.fromhex(cursor["hash"])).decode(),
                    )
                except Unknown as exc:
                    cause = exc.__cause__
                    if (
                        isinstance(cause, lib.RpcError)
                        and cause.code == -32603
                        and "lt not in db" in cause.message
                    ):
                        return {"transactions": txs, "pruned": True}
                    raise
                rows = answer.get("transactions")
                if not isinstance(rows, list) or len(rows) != 1:
                    raise Unknown("checkpoint history is empty or malformed before its boundary")
                row = rows[0]
                tx = verify_transaction(row.get("data"), cursor["hash"], wallet, int(cursor["lt"]))
                txs.append(tx)
                previous = tx["previous"]
                if int(previous["lt"]) >= int(cursor["lt"]):
                    raise Unknown("wallet transaction previous pointer does not descend")
                cursor = previous
            raise Unknown("checkpoint history request budget exhausted")

        return self.both(read)

    def bootstrap_receipts(self, wallet: str, extra: dict | None = None) -> dict:
        """Terminal acknowledgements bind execution to one signed authorization per counter."""
        records = {r["id"]: r for r in self.journal.for_wallet(wallet)}
        if extra:
            records[extra["id"]] = extra
        receipts = {}
        for record in records.values():
            evidence = record.get("evidence") or {}
            if record["state"] not in ("settled", "failed") or not evidence.get("wallet_tx"):
                continue
            if record["state"] == "failed" and evidence.get("form") not in ("a", "b"):
                continue
            try:
                signed = [
                    line for line in self.journal.lines(record["id"]) if line["state"] == "signed"
                ]
                if not signed or not isinstance(record.get("boc"), str):
                    raise Unknown("terminal receipt has no durable signed record")
                decoded = decode_external(base64.b64decode(record["boc"], validate=True))
                seqno = record["seqno"]
                if (
                    type(seqno) is not int
                    or not 0 <= seqno < 0xFFFFFFFF
                    or decoded["seqno"] != seqno
                    or decoded["destination"] != wallet
                    or decoded["global_id"] != self.global_id
                    or decoded["subwallet"] != 0
                    or decoded["external_hash"] != record["external_hash"]
                    or record.get("identity") != self.bootstrap_identity(wallet)[:2]
                    or decoded["mode"]
                    != (SWEEP_MODE if record["kind"] == "sweep" else WALLET_V3_MODE)
                    or decoded["init_hash"] is not None
                    or decoded["internal"]
                    != {
                        "destination": record["destination"],
                        "value": record["value"],
                        "bounce": record["bounce"],
                        "init_hash": record.get("state_init_hash"),
                        "body_hash": record["body_hash"],
                    }
                    or not any(
                        line.get("external_hash") == record["external_hash"]
                        and line.get("seqno") == seqno
                        for line in signed
                    )
                    or evidence["wallet_tx"] not in evidence.get("explains", [])
                ):
                    raise Unknown("terminal receipt has no verified signed-counter binding")
                if seqno in receipts:
                    raise Unknown(f"duplicate terminal receipts for seqno {seqno}")
                receipts[seqno] = {
                    "id": record["id"],
                    "seqno": seqno,
                    "wallet_tx": evidence["wallet_tx"],
                    "external_hash": record["external_hash"],
                }
            except (KeyError, ValueError, lib.TestnetError) as exc:
                raise Unknown(f"checkpoint receipt {record['id']} refused: {exc}") from exc
        return receipts

    def verify_bootstrap_prefix(self, wallet: str, extra: dict | None = None) -> dict:
        """Certify a stable prefix using served transactions and previously verified receipts.

        Counter closure of a pruned gap assumes an honest local terminal journal and
        exclusive coordinator custody; it is not a proof against a compromised signer.
        """
        cp = self.bootstrap_certificate(wallet)
        if self.journal.baseline(wallet) is not None:
            raise Unknown("bootstrap checkpoint origin must be genesis, not a manual baseline")
        start = cp["post_seqno"] if cp else 0
        snapshot = self.bootstrap_state(wallet)
        if cp and (
            not snapshot["head"]
            or int(snapshot["head"]["lt"]) < int(cp["head"]["lt"])
            or (snapshot["head"]["lt"] == cp["head"]["lt"] and snapshot["head"] != cp["head"])
        ):
            raise Unknown("checkpoint wallet transaction head regressed or diverged")
        tail = self.bootstrap_tail(wallet, snapshot, cp["head"] if cp else None)
        receipts = self.bootstrap_receipts(wallet, extra)
        end = snapshot["seqno"]
        if end < start:
            raise Unknown("checkpoint wallet counter regressed")
        if end - start > len(receipts):
            raise Unknown("unexplained seqno interval: insufficient verified terminal receipts")
        for seqno in range(start, end):
            if seqno not in receipts:
                raise Unknown(f"unexplained seqno {seqno}: no verified terminal receipt")
        if any(q >= end for q in receipts):
            raise Unknown("journaled consumer was not executed in the current wallet incarnation")
        served = set()
        expected_tail = end
        for tx in tail["transactions"]:
            if tx["in_kind"] == "external" and took_effect(tx):
                seqno = external_seqno(tx)
                receipt = receipts.get(seqno)
                if (
                    receipt is None
                    or seqno != expected_tail - 1
                    or seqno in served
                    or not start <= seqno < end
                    or receipt["wallet_tx"] != tx["hash"]
                    or receipt["external_hash"] != tx["in_hash"]
                ):
                    raise Unknown(f"unexplained wallet transaction {tx['hash']} or counter")
                served.add(seqno)
                expected_tail -= 1
            elif leaves(tx, wallet):
                raise Unknown(f"unexplained outgoing transaction {tx['hash']}")
        if not tail["pruned"] and served != set(range(start, end)):
            raise Unknown("served wallet counter continuity disagrees with terminal receipts")
        if self.bootstrap_state(wallet) != snapshot:
            raise Unknown("wallet snapshot moved during checkpoint verification")
        return {
            "wallet": wallet,
            "global_id": self.global_id,
            "zero_state": json.loads((self.ceremony / "genesis.json").read_text())["zero_state"],
            "origin": cp["digest"] if cp else "genesis",
            "head": snapshot["head"],
            "post_seqno": end,
            "identity": snapshot["identity"],
            "deleted": snapshot["deleted"],
            "counter_interval": [start, end],
            "served_consumers": len(served),
            "pruned_gap": tail["pruned"],
            "transaction_receipts": tail["transactions"],
            "receipts": [receipts[q] for q in range(start, end)],
            "observations": [{"url": url, **snapshot} for url in self.read_both(lambda n: n.url)],
            "assumption": CUSTODY_ASSUMPTION,
            "legacy_receipt_trust": "Terminal wallet hashes were verified on both validators when recorded.",
        }

    def checkpoint_entry(self, record: dict, report: dict) -> dict | None:
        old = self.bootstrap_certificate(record["wallet"])
        if old and old["head"] == report["head"] and old["post_seqno"] == report["post_seqno"]:
            return None
        if not report["head"]:
            raise Unknown("cannot checkpoint a wallet with no transaction")
        genesis = json.loads((self.ceremony / "genesis.json").read_text())
        cp = dict(
            report,
            version=1,
            previous=old["digest"] if old else None,
            zero_state=genesis["zero_state"],
            global_id=self.global_id,
            source_operation=record["id"],
        )
        cp["digest"] = certificate_digest(cp)
        return cp

    def record_checkpoint(self, op_id: str, dry_run: bool = False) -> dict:
        with self.journal.lock():
            record = self.journal.record(op_id)
            if not record or record["state"] not in ("settled", "failed"):
                raise OperationRefused("checkpoint requires an existing terminal operation")
            wallet = record["wallet"]
            if self.bootstrap_identity(wallet) is None:
                raise OperationRefused("checkpoint supports only the pinned bootstrap wallet")
            if any(
                r["state"] in ("planned", "signed", "broadcast")
                for r in self.journal.for_wallet(wallet)
            ):
                raise OperationRefused("checkpoint refuses an open bootstrap operation")
            eligible = self.bootstrap_receipts(wallet)
            if not any(r["id"] == op_id for r in eligible.values()):
                raise OperationRefused("checkpoint needs a committed terminal wallet transaction")
            report = self.verify_bootstrap_prefix(wallet)
            cp = self.checkpoint_entry(record, report)
            if not dry_run and cp:
                self.journal.append(op_id, {"state": record["state"], "checkpoint": cp})
            public_report = {k: v for k, v in report.items() if k != "transaction_receipts"}
            return dict(
                public_report, dry_run=dry_run, certificate=cp["digest"] if cp else report["origin"]
            )

    def append_terminal(self, record: dict, outcome: str, evidence: dict, **fields) -> None:
        entry = dict(fields, state=outcome, evidence=evidence)
        if self.bootstrap_identity(record["wallet"]) and evidence.get("wallet_tx"):
            candidate = dict(record, state=outcome, evidence=evidence)
            try:
                report = self.verify_bootstrap_prefix(record["wallet"], candidate)
                cp = self.checkpoint_entry(record, report)
                if cp:
                    entry["checkpoint"] = cp
            except OperationRefused as exc:
                entry["checkpoint_refusal"] = str(exc)
        self.journal.append(record["id"], entry)

    def history_start(self, wallet: str) -> dict | None:
        """Where a wallet's history must be complete and explained from: the newer of
        its manual baseline and its newest settled operation's transaction (None:
        the whole account). Validators prune history after about a day, so a wallet
        that signed before then can only be checked from a verified point."""
        entry = self.journal.baseline_entry(wallet)
        settled = self.journal.settled_boundary(wallet)
        if settled is None:
            return entry["boundary"] if entry else None
        boundary, settled_utc = settled
        if entry is None:
            return boundary
        if boundary["lt"] != "0":
            newer = int(boundary["lt"]) > int(entry["boundary"]["lt"])
        else:
            newer = settled_utc >= entry.get("utc", "")
        return boundary if newer else entry["boundary"]

    def gate(self, wallet: str, op_id: str) -> dict | None:
        """Refuse unless the wallet's history is complete, agreed and explained, and
        no other operation of the wallet is open. Called with the journal lock held."""
        self.check_network()
        retired = self.bootstrap_retired(wallet)
        if retired:
            raise OperationRefused(
                f"the bootstrap wallet has been swept ({retired}); it is retired as a funding "
                "source: fund from a pool owner wallet (owner-fund, top-up)"
            )
        for record in self.journal.for_wallet(wallet):
            if record["id"] != op_id and state_of(record) in ("planned", "signed", "broadcast"):
                raise OperationRefused(
                    f"operation {record['id']} of {wallet} is open ({record['state']}, external "
                    f"{record.get('external_hash')}); run reconcile, then record or resubmit"
                )
        if self.bootstrap_identity(wallet):
            return self.verify_bootstrap_prefix(wallet)
        boundary = self.history_start(wallet)
        explained = self.journal.explained()
        for tx in self.history(wallet, boundary):
            if (
                leaves(tx, wallet)
                and tx["hash"] not in explained
                and self.election_message(wallet, tx) is None
            ):
                described = ", ".join(f"{m['value']} to {m['destination']}" for m in tx["out"])
                raise OperationRefused(
                    f"{wallet} transaction {tx['hash']} (lt {tx['lt']}) sent {described}, which no "
                    "settled or failed operation explains; reconcile it by hand"
                    + ("" if boundary else " (or record a baseline if it predates the journal)")
                )

    # -- running one step

    def begin(self, op_id: str, params: dict) -> dict:
        """The operation's record, created as planned if new, with the journal lock held.
        Recorded parameters never change."""
        record = self.journal.record(op_id)
        if record is None:
            self.journal.append(op_id, dict(params, state="planned"))
            crash_point(op_id, "planned")
            return self.journal.record(op_id)
        mismatch = {
            k: (record.get(k), v) for k, v in params.items() if k not in record or record[k] != v
        }
        if mismatch:
            raise OperationRefused(f"operation {op_id} exists with other parameters: {mismatch}")
        return record

    def run(
        self, step: str, params: dict, sign, validate, prerequisites=None, expect=None, export=None
    ) -> dict:
        """Gate, sign once, journal, broadcast once, watch for settlement, all decided
        with the journal lock held and the record re-read under it.

        `step` resolves to its newest attempt. `sign(seqno)` returns the external
        message BOC; `validate(decoded)` refuses a message that is not exactly the
        intended one; `prerequisites()` checks spending conditions right before
        signing. Returns the settled record."""
        if params["kind"] not in KINDS:
            raise OperationRefused(f"unknown operation kind {params['kind']}")
        wallet = params["wallet"]
        if params["kind"] == "sweep" and not self.bootstrap_identity(wallet):
            raise OperationRefused(
                "a sweep needs the pinned bootstrap wallet (genesis.json main_wallet_public_key)"
            )
        with self.journal.lock(wallet):
            op_id = self.journal.newest(step)
            record = self.journal.record(op_id)
            if state_of(record) in (None, "planned"):
                self.gate(wallet, op_id)
            record = self.begin(op_id, params)
            if state_of(record) == "settled":
                return record
            if state_of(record) == "failed":
                raise OperationRefused(
                    f"operation {op_id} failed ({record.get('evidence')}); a person may start "
                    f"another attempt with `retry --step {step}`"
                )
            if state_of(record) in ("signed", "broadcast"):
                raise OperationRefused(
                    f"operation {op_id} is open ({record['state']}); run reconcile, then record or resubmit"
                )
            if prerequisites:
                prerequisites()
            witness = self.gate(wallet, op_id) if self.bootstrap_identity(wallet) else None
            boundary = witness["head"] if witness else self.head(wallet)
            seqno = witness["post_seqno"] if witness else self.seqno(wallet)
            identity = tuple(witness["identity"][:2]) if witness else self.identity(wallet)
            # A sweep deletes its wallet, and with it the head settlement would page
            # back from; the masterchain head before signing bounds where it can run.
            extra = {"search_lt": str(self.search_floor())} if params["kind"] == "sweep" else {}
            boc = sign(seqno)
            decoded = decode_external(boc)
            self.check_message(decoded, record, seqno)
            validate(decoded)
            self.journal.append(
                op_id,
                {
                    "state": "signed",
                    "boc": base64.b64encode(boc).decode(),
                    "external_hash": decoded["external_hash"],
                    "seqno": decoded["seqno"],
                    "valid_until": decoded["valid_until"],
                    "boundary": boundary,
                    "identity": list(identity) if identity else None,
                    "gate_witness": witness,
                    **extra,
                },
            )
            crash_point(op_id, "signed")
            # A copy of the signed message for the operator (ceremony/sent/) is written
            # only now, after the signed journal line is durable: a crash before it
            # leaves no signed bytes outside the journal next to a planned record.
            if export is not None:
                export(boc, decoded["seqno"])
            self.nodes[0].call("sendBoc", boc=base64.b64encode(boc).decode())
            self.journal.append(op_id, {"state": "broadcast"})
            crash_point(op_id, "broadcast")
        return self.watch(op_id, expect)

    def check_message(self, decoded: dict, params: dict, seqno: int) -> None:
        """What every external message must be, whoever built it."""
        if decoded["destination"] != params["wallet"]:
            raise OperationRefused(
                f"the message is for {decoded['destination']}, not the signing wallet {params['wallet']}"
            )
        if decoded["global_id"] != self.global_id:
            raise OperationRefused(f"the message is signed for global id {decoded['global_id']}")
        if decoded["subwallet"] != params.get("subwallet"):
            raise OperationRefused(
                f"the message names subwallet {decoded['subwallet']}, the wallet's is "
                f"{params.get('subwallet')}"
            )
        if decoded["seqno"] != seqno:
            raise OperationRefused(
                f"the message carries seqno {decoded['seqno']}, the wallet is at {seqno}"
            )
        now = int(self.clock())
        if params["kind"] == "activate-owner":
            if decoded["valid_until"] != ACTIVATION_VALID_UNTIL or decoded["internal"]:
                raise OperationRefused("not a wallet self-deployment message")
            if decoded["init_hash"] != params.get("state_init_hash"):
                raise OperationRefused("the activation carries another StateInit")
            return
        ttl = MAX_TTL["host" if params["kind"] in HOST_KINDS else "coordinator"]
        if not now < decoded["valid_until"] <= now + ttl + TTL_SKEW:
            raise OperationRefused(
                f"the message expires at {decoded['valid_until']}, outside ({now}, {now + ttl + TTL_SKEW}]"
            )
        mode = SWEEP_MODE if params["kind"] == "sweep" else WALLET_V3_MODE
        if decoded["mode"] != mode or decoded["init_hash"]:
            raise OperationRefused(
                f"not a wallet v3 transfer with send mode {mode} and no StateInit"
            )
        if params["kind"] == "sweep" and (
            params["destination"] != BLACKHOLE
            or params["value"] != 0
            or params["bounce"] is not False
            or params.get("state_init_hash") is not None
            or params["body_hash"] != EMPTY_BODY_HASH
        ):
            raise OperationRefused(
                "a sweep is a non-bounce transfer of value 0, empty body and no StateInit, "
                f"to the blackhole {BLACKHOLE}"
            )
        internal = decoded["internal"] or {}
        expected = {
            "destination": params["destination"],
            "value": params["value"],
            "bounce": params["bounce"],
            "init_hash": params.get("state_init_hash"),
            "body_hash": params["body_hash"],
        }
        actual = {k: internal.get(k) for k in expected}
        if actual != expected:
            raise OperationRefused(
                f"the message is not the intended transfer: {actual} != {expected}"
            )

    def watch(self, op_id: str, expect=None) -> dict:
        """Poll for settlement; each decision is taken with the lock held and the
        record re-read, so a settlement recorded by another run is not repeated."""
        deadline = self.clock() + SETTLE_SECONDS
        while True:
            with self.journal.lock():
                record = self.journal.record(op_id)
                if state_of(record) == "settled":
                    return record
                if state_of(record) == "failed":
                    raise OperationRefused(f"operation {op_id} failed: {record.get('evidence')}")
                try:
                    outcome, evidence = self.settle(record, expect)
                except Unknown as exc:
                    outcome, evidence = "pending", {"reason": str(exc)}
                if outcome == "settled":
                    crash_point(op_id, "delivered")
                    self.append_terminal(record, "settled", evidence)
                    return self.journal.record(op_id)
                if outcome == "failed":
                    self.append_terminal(record, "failed", evidence)
                    raise OperationRefused(f"operation {op_id} failed: {evidence}")
            if self.clock() > deadline:
                raise OperationRefused(
                    f"operation {op_id} is broadcast but not settled after {SETTLE_SECONDS} s "
                    f"({evidence.get('reason', evidence)}); run reconcile"
                )
            self.sleep(POLL_SECONDS)

    # -- attempts

    def retry(self, step: str, reason: str) -> dict:
        """A new attempt of a step whose newest attempt failed, chosen by a person.

        Under the journal lock: refused unless the newest attempt is failed (an open,
        planned or settled one is never succeeded). The successor keeps the step's
        parameters, names its predecessor, and is created by one complete append, so a crash leaves either
        no successor or one planned successor, never two."""
        if not reason.strip():
            raise OperationRefused("a retry needs a reason")
        with self.journal.lock():
            attempts = self.journal.attempts(step)
            if not attempts:
                raise OperationRefused(f"step {step} has no attempt")
            n, newest = attempts[-1]
            record = self.journal.record(newest)
            if state_of(record) != "failed":
                raise OperationRefused(
                    f"the newest attempt {newest} is {state_of(record)}; only a failed one is retried"
                )
            keep = {
                k: v
                for k, v in record.items()
                if k
                not in {
                    "id",
                    "state",
                    "utc",
                    "boc",
                    "external_hash",
                    "seqno",
                    "valid_until",
                    "boundary",
                    "identity",
                    "evidence",
                    "by",
                    "resubmitted",
                    "predecessor",
                    "checkpoint",
                    "gate_witness",
                    "checkpoint_refusal",
                    "reason",
                    "search_lt",
                }
            }
            successor = attempt_id(step, n + 1)
            self.journal.append(
                successor,
                dict(
                    keep,
                    state="planned",
                    predecessor=newest,
                    reason=reason,
                ),
            )
            return self.journal.record(successor)

    # -- settlement

    def wallet_attempts(self, record: dict) -> list[dict]:
        """Every wallet transaction of the record's external message, newest first."""
        wallet = record["wallet"]
        if self.bootstrap_identity(wallet):
            snapshot = self.bootstrap_state(wallet)
            tail = self.bootstrap_tail(wallet, snapshot, record.get("boundary"))
            if tail["pruned"]:
                raise Unknown("settlement transaction history pruned before its signed boundary")
            history = tail["transactions"]
        else:
            history = self.history(wallet, record.get("boundary"))
        return [
            tx
            for tx in history
            if tx["in_kind"] == "external" and tx["in_hash"] == record["external_hash"]
        ]

    def find_wallet_tx(self, record: dict) -> dict | None:
        """The transaction in which the record's message took effect. One that ran
        and aborted paid its fees but took no seqno and sent nothing: the message is
        not consumed and may run again."""
        for tx in self.wallet_attempts(record):
            if took_effect(tx):
                return tx
        return None

    def find_delivery(self, destination: str, message_hash: str, created_lt: int) -> dict | None:
        found = self.read_both(lambda node: node.delivery(destination, message_hash, created_lt))
        if found[0] != found[1]:
            raise Unknown(f"the validators disagree or one lags on the delivery of {message_hash}")
        return found[0]

    def settle(self, record: dict, expect=None) -> tuple[str, dict]:
        """("pending" | "settled" | "failed", evidence) from the chain alone."""
        if state_of(record) not in ("signed", "broadcast"):
            raise OperationRefused(f"operation {record['id']} is {state_of(record)}")
        self.check_network()
        tx = self.find_wallet_tx(record)
        if tx is None:
            aborted = [t["hash"] for t in self.wallet_attempts(record)]
            if aborted:
                return "pending", {
                    "reason": (
                        f"the message ran and aborted in {', '.join(aborted)} (fees paid, no "
                        "seqno taken, nothing sent) and may run again; resubmit it, or prove "
                        "(c) or (d)"
                    ),
                    "aborted_attempts": aborted,
                }
            return "pending", {"reason": "no transaction for the external message yet"}
        evidence = {
            "wallet_tx": tx["hash"],
            "wallet_tx_lt": str(tx["lt"]),
            "explains": [tx["hash"]],
        }
        if record["kind"] == "sweep":
            return self.settle_sweep(record, tx, evidence, expect)
        if record["kind"] == "activate-owner":
            if tx["out"]:
                return "failed", dict(evidence, form="a", reason="a self-deployment that sent")
            return self.check_activated(record, evidence)
        wanted = [
            m
            for m in tx["out"]
            if m["kind"] == "internal"
            and m["destination"] == record["destination"]
            and m["value"] == record["value"]
            and not m["bounced"]
        ]
        if len(tx["out"]) != 1 or len(wanted) != 1:
            return "failed", dict(
                evidence, form="a", reason="the wallet emitted not exactly the required message"
            )
        message = wanted[0]
        evidence["message"] = message["hash"]
        delivery = self.find_delivery(record["destination"], message["hash"], message["created_lt"])
        if delivery is None:
            return "pending", dict(evidence, reason="the message is not delivered yet")
        evidence["destination_tx"] = delivery["hash"]
        kind = record["kind"]
        if kind in ("fund", "owner-fund"):
            # Mode 3 charges forwarding separately: the destination is credited the
            # full message value. A credit to an undeployed wallet has a skipped
            # compute and may be aborted; it keeps the credit unless it bounced.
            if any(m["bounced"] for m in delivery["out"]):
                return "failed", dict(evidence, form="b", reason="the credit bounced")
            if delivery["credit"] != message["value"] or message["value"] != record["value"]:
                return "failed", dict(
                    evidence,
                    form="b",
                    reason=f"credited {delivery['credit']}, sent {record['value']}",
                )
            return "settled", evidence
        if not took_effect(delivery):
            return "failed", dict(evidence, form="b", reason="the destination refused it")
        if any(m["bounced"] for m in delivery["out"]):
            return "failed", dict(evidence, form="b", reason="the destination bounced it")
        if kind == "withdraw":
            return self.check_receipt(record, delivery, evidence)
        if expect:
            return expect(self, record, delivery, evidence)
        return "settled", evidence

    def settle_sweep(self, record: dict, tx: dict, evidence: dict, expect) -> tuple[str, dict]:
        """A sweep settles from its own transaction (one non-bounced internal message
        to the blackhole carrying a value, the wallet deleted), the wallet reading
        not active on both validators, the blackhole's transaction for that message
        crediting nothing, and the burn verified in that block's ValueFlow (expect,
        verify_burn). Without a block to verify it stays pending."""
        evidence["wallet_end_status"] = tx["end_status"]
        out = tx["out"]
        if (
            len(out) != 1
            or out[0]["kind"] != "internal"
            or out[0]["destination"] != record["destination"]
            or out[0]["bounced"]
        ):
            return "failed", dict(
                evidence,
                form="a",
                reason="the sweep emitted not exactly one message to the blackhole",
            )
        message = out[0]
        evidence["message"] = message["hash"]
        if tx["end_status"] != "nonexist":
            return "failed", dict(
                evidence,
                form="a",
                reason=f"the sweep left the wallet {tx['end_status']}, not deleted",
            )
        if message["value"] <= 0:
            return "failed", dict(evidence, form="a", reason="the sweep carried no value")
        evidence["burned_nanotos"] = message["value"]
        accounts = self.read_both(lambda node: node.account(record["wallet"]))
        if any(a["state"] != "uninitialized" for a in accounts):
            return "pending", dict(
                evidence, reason="the swept wallet still reads active on a validator"
            )
        evidence["wallet_after"] = [
            {"state": a["state"], "balance": int(a["balance"])} for a in accounts
        ]
        delivery = self.find_delivery(record["destination"], message["hash"], message["created_lt"])
        if delivery is None:
            return "pending", dict(
                evidence, reason="the sweep is not delivered to the blackhole yet"
            )
        evidence["destination_tx"] = delivery["hash"]
        evidence["destination_block"] = delivery["block"]
        evidence["blackhole_end_status"] = delivery["end_status"]
        if delivery["in_value"] != message["value"] or delivery["credit"] != 0 or delivery["out"]:
            return "failed", dict(
                evidence,
                form="b",
                reason=f"the blackhole was credited {delivery['credit']} of {message['value']}: "
                "not burned (is ConfigParam 5 in force?)",
            )
        if expect is None:
            block = delivery["block"]
            return "pending", dict(
                evidence,
                reason=(
                    "burned at the blackhole; verify the burn in its block: fetch block "
                    f"({block['workchain']},{int(block['shard']) & (2**64 - 1):016x},{block['seqno']})"
                    f":{b64hash(block['root_hash']).hex().upper()}"
                    f":{b64hash(block['file_hash']).hex().upper()} "
                    f"and run record --id {record['id']} --settled --hint {evidence['wallet_tx']} "
                    "--block-boc FILE"
                ),
            )
        return expect(self, record, delivery, evidence)

    def verify_burn(
        self, record: dict, delivery: dict, evidence: dict, boc: bytes
    ) -> tuple[str, dict]:
        """The sweep's burn in its block, from the block's own bytes.

        The file must hash to the file hash of the block both validators found the
        blackhole transaction in. In it: the network's global id, a masterchain block
        of that seqno whose lt range holds the transaction; the blackhole
        transaction itself (by hash) with every other blackhole transaction of the
        block, each crediting nothing; a balancing ValueFlow whose burned equals
        what those transactions burned, which ConfigParam 5 at 0/1 (read again on
        both validators) makes all the block burns. A mismatch refuses and leaves
        the operation open: stop and investigate."""
        block_id = delivery["block"]
        if hashlib.sha256(boc).digest() != b64hash(block_id["file_hash"]):
            raise OperationRefused(
                f"the block file is not block {block_id['seqno']} (file hash "
                f"{b64hash(block_id['file_hash']).hex()}), where the blackhole transaction is"
            )
        try:
            block = lib.read_block(boc)
        except lib.TestnetError as exc:
            raise OperationRefused(f"the block file cannot be read: {exc}") from exc
        if (
            block["global_id"] != self.global_id
            or not block["masterchain"]
            or block["workchain"] != lib.MASTERCHAIN
            or block["seqno"] != int(block_id["seqno"])
            or not block["start_lt"] <= delivery["lt"] <= block["end_lt"]
        ):
            raise OperationRefused("the block file is not the masterchain block of the burn")
        self.both(lambda node: lib.check_burning_config(self.config_cell(node, 5))["fee_burn"])
        account = BLACKHOLE.split(":")[1]
        burns = []
        for lt, cell in sorted(block["transactions"].get(account, {}).items()):
            data = base64.b64encode(lib.serialize_boc(cell)).decode()
            tx = verify_transaction(data, cell.hash().hex(), BLACKHOLE, lt)
            if tx["in_kind"] != "internal" or tx["credit"] != 0 or tx["out"]:
                raise OperationRefused(
                    f"blackhole transaction {tx['hash']} in the block is not a burn"
                )
            burns.append({"tx": tx["hash"], "lt": lt, "nanotos": tx["in_value"]})
        if delivery["hash"] not in {b["tx"] for b in burns}:
            raise OperationRefused("the block holds no transaction of the blackhole for this sweep")
        flow = block["value_flow"]
        burned = sum(b["nanotos"] for b in burns)
        if flow["burned"] != burned:
            raise OperationRefused(
                f"the block's ValueFlow.burned is {flow['burned']}, its blackhole transactions "
                f"burned {burned}: the burn does not reconcile; stop and investigate"
            )
        wallet = record["wallet"].split(":")[1]
        wallet_in_block = any(
            cell.hash().hex() == evidence["wallet_tx"]
            for cell in block["transactions"].get(wallet, {}).values()
        )
        return "settled", dict(
            evidence,
            burn={
                "block": block_id,
                "block_file_sha256": hashlib.sha256(boc).hexdigest(),
                "value_flow": flow,
                "blackhole_transactions": burns,
                "sweep_message": evidence["message"],
                "sweep_burned_nanotos": evidence["burned_nanotos"],
                "wallet_tx_in_block": wallet_in_block,
            },
        )

    def config_cell(self, node: Node, number: int) -> lib.Cell:
        try:
            answer = node.call("getConfigParam", param=number)
        except Unknown as exc:
            raise Unknown(f"ConfigParam {number} is unavailable: {exc}") from exc
        try:
            return lib.parse_boc(base64.b64decode(answer["config"]["bytes"], validate=True))
        except (KeyError, TypeError, ValueError, lib.TestnetError) as exc:
            raise Unknown(f"{node.url}: ConfigParam {number} is unavailable: {exc}") from exc

    def check_activated(self, record: dict, evidence: dict) -> tuple[str, dict]:
        state = self.identity(record["wallet"])
        if state is None:
            return "pending", dict(evidence, reason="the wallet is not active yet")
        if list(state) != [record["code_hash"], record["public_key"]]:
            return "failed", dict(evidence, form="a", reason=f"the wallet is not ours: {state}")
        return "settled", evidence

    def check_receipt(self, record: dict, pool_tx: dict, evidence: dict) -> tuple[str, dict]:
        """A withdrawal settles only when the owner retained the payment; an owner
        transaction that did not keep it is a terminal failure that accounts for it."""
        payments = [
            m
            for m in pool_tx["out"]
            if m["destination"] == record["wallet"] and not m["bounced"] and m["kind"] == "internal"
        ]
        if len(payments) != 1:
            return "failed", dict(evidence, form="b", reason="the pool paid the owner nothing")
        payment = payments[0]
        evidence["payment"] = payment["hash"]
        receipt = self.find_delivery(record["wallet"], payment["hash"], payment["created_lt"])
        if receipt is None:
            return "pending", dict(evidence, reason="payment emitted, not yet received")
        evidence["owner_tx"] = receipt["hash"]
        retained = (
            not receipt["in_bounced"]
            and receipt["aborted"] is False
            and receipt["compute_success"]
            and not receipt["out"]
            and receipt["credit"] == payment["value"]
        )
        if not retained:
            failed = dict(evidence, form="b", reason="the owner did not retain the payment")
            failed["explains"] = evidence["explains"] + [receipt["hash"]]
            failed["receipt_out"] = [m["hash"] for m in receipt["out"]]
            return "failed", failed
        evidence["paid_nanotos"] = payment["value"]
        requested = record["requested_nanotos"]
        if requested is not None and payment["value"] < requested:
            return "failed", dict(
                evidence,
                form="b",
                reason=f"the pool paid {payment['value']} nanotos, less than requested {requested}",
                explains=evidence["explains"] + [receipt["hash"]],
            )
        return "settled", evidence

    # -- manual paths (each under the journal lock, the record re-read under it)

    def open_record(self, op_id: str) -> dict:
        record = self.journal.record(op_id)
        if state_of(record) not in ("signed", "broadcast"):
            raise OperationRefused(
                f"operation {op_id} is {state_of(record) or 'unknown'}, not open"
            )
        return record

    def record_settled(self, op_id: str, hint: str, expect=None) -> dict:
        with self.journal.lock():
            record = self.open_record(op_id)
            self.check_network()
            outcome, evidence = self.settle(record, expect)
            if outcome != "settled":
                raise OperationRefused(f"operation {op_id} is not settled: {outcome} {evidence}")
            if hint not in (evidence.get("wallet_tx"), evidence.get("destination_tx")):
                raise OperationRefused(
                    f"{hint} is not this operation's transaction ({evidence.get('wallet_tx')})"
                )
            self.append_terminal(record, "settled", evidence, by="record")
            return self.journal.record(op_id)

    def record_abandoned(self, op_id: str, dry_run: bool = False) -> dict:
        """Close only an unsigned coordinator funding plan, after two-node absence checks.

        A funding plan is a `fund` from the bootstrap wallet or an `owner-fund` from
        a pool owner (top-up, load funding): both are signed here, on the
        coordinator, through run(). The signer returns bytes from a removed
        temporary directory, and run() fsyncs those bytes as signed before sendBoc;
        no planned funding can broadcast through that path, including a crash
        between signing and the journal write. A run refused before signing (a
        prerequisite such as the owner's balance) leaves such a plan, and while it
        is open the gate refuses every other operation of its wallet; this closes
        it. A sweep is never abandoned here.
        """
        with self.journal.lock():
            lines = self.journal.lines(op_id)
            record = self.journal.record(op_id)
            if state_of(record) != "planned" or record.get("kind") not in ABANDONABLE_KINDS:
                raise OperationRefused(
                    "abandonment requires an unsigned planned fund or owner-fund"
                )
            signed_fields = ("boc", "external_hash", "seqno", "valid_until", "boundary", "identity")
            if any(
                line["state"] != "planned"
                or any(line.get(key) is not None for key in signed_fields)
                for line in lines
            ):
                raise OperationRefused(
                    "the plan contains signing evidence; use normal reconciliation"
                )
            try:
                since = int(
                    datetime.strptime(lines[0]["utc"], "%Y-%m-%dT%H:%M:%SZ")
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                )
            except (ValueError, KeyError) as exc:
                raise OperationRefused("the plan has no valid creation time") from exc
            artifacts = self.signed_artifacts(record, op_id)
            evidence = self.fund_plan_absence(record, since)
            evidence["signed_artifacts"] = artifacts
            if dry_run:
                return {"id": op_id, "state": "planned", "dry_run": True, "evidence": evidence}
            # Recheck both validators immediately before the terminal append.
            artifacts = self.signed_artifacts(record, op_id)
            evidence = self.fund_plan_absence(record, since)
            evidence["signed_artifacts"] = artifacts
            self.append_terminal(record, "failed", evidence, by="record")
            return self.journal.record(op_id)

    def signed_artifacts(self, record: dict, op_id: str) -> list[dict]:
        """Signed messages for this plan outside the journal (ceremony/sent/: the
        operator copies, a fund dry run's), found by name or by content: an external
        to the plan's wallet whose transfer has the plan's destination, value and
        body. The plan is abandoned only if each has expired on both validators
        (valid_until in the past), so none can still be accepted; whether one was
        accepted before is what the absence check then decides. Unreadable files
        refuse."""
        sent = self.ceremony / "sent"
        if not sent.is_dir():
            return []
        found = []
        for path in sorted(sent.iterdir()):
            if not path.is_file():
                continue
            try:
                decoded = decode_external(path.read_bytes())
            except (OSError, lib.TestnetError, ValueError, IndexError) as exc:
                if op_id in path.name:
                    raise OperationRefused(
                        f"cannot read signed artifact {path.name}: {exc}"
                    ) from exc
                continue
            internal = decoded.get("internal") or {}
            matches = decoded.get("destination") == record["wallet"] and (
                op_id in path.name
                or (
                    internal.get("destination") == record["destination"]
                    and internal.get("value") == record["value"]
                    and internal.get("body_hash") == record["body_hash"]
                )
            )
            if matches:
                found.append(
                    {
                        "file": path.name,
                        "external_hash": decoded["external_hash"],
                        "seqno": decoded["seqno"],
                        "valid_until": decoded["valid_until"],
                    }
                )
        if found:
            times = self.utimes()
            for artifact in found:
                if not all(now > artifact["valid_until"] for now in times):
                    raise OperationRefused(
                        f"a signed message for this plan exists ({artifact['file']}, seqno "
                        f"{artifact['seqno']}, valid until {artifact['valid_until']}); it may "
                        "still be accepted, so the plan is not abandoned before it has expired "
                        "on both validators"
                    )
        return found

    def fund_plan_absence(self, record: dict, since: int) -> dict:
        chain_times = self.utimes()
        if any(now < since for now in chain_times):
            raise Unknown("both validators must have reached the plan's creation time")
        observations = self.read_both(
            lambda node: {"node": node.url, "history": node.history(record["wallet"], None, since)}
        )
        if observations[0]["history"] != observations[1]["history"]:
            raise Unknown("the validators disagree on the planned fund's wallet history")
        summaries = []
        for observation in observations:
            history = observation["history"]
            relevant = [tx for tx in history if tx["utime"] >= since]
            for tx in relevant:
                messages = list(tx["out"])
                if tx["in_kind"] == "external":
                    try:
                        root = lib.parse_boc(base64.b64decode(tx["data"], validate=True))
                        incoming = lib.Slice(root.refs[0])
                        if not incoming.bits(1):
                            raise Unknown("external transaction has no inbound message")
                        decoded = decode_external(lib.serialize_boc(incoming.take_ref()))
                        if decoded["internal"]:
                            messages.append(decoded["internal"])
                    except (lib.TestnetError, ValueError, IndexError) as exc:
                        raise Unknown(
                            f"cannot inspect funding intent in {tx['hash']}: {exc}"
                        ) from exc
                if any(
                    message.get("destination") == record["destination"]
                    and message.get("value") == record["value"]
                    and message.get("body_hash") == record["body_hash"]
                    for message in messages
                ):
                    raise OperationRefused(
                        f"transaction {tx['hash']} matches the planned fund; reconcile it, do not abandon"
                    )
            summaries.append(
                {
                    "node": observation["node"],
                    "transactions_checked": len(history),
                    "transactions_since_plan": len(relevant),
                    "head": {key: history[0][key] for key in ("hash", "lt", "utime")}
                    if history
                    else None,
                    "matching_transactions": [],
                }
            )
        return {
            "form": "unsigned-fund-plan-abandoned",
            "wallet": record["wallet"],
            "destination": record["destination"],
            "value": record["value"],
            "body_hash": record["body_hash"],
            "planned_since": since,
            "checked_chain_times": chain_times,
            "observations": summaries,
            "explains": [],
        }

    def record_failed(self, op_id: str, form: str, hint: str | None = None, expect=None) -> dict:
        with self.journal.lock():
            record = self.open_record(op_id)
            self.check_network()
            if form in ("a", "b"):
                outcome, evidence = self.settle(record, expect)
                if outcome != "failed" or evidence.get("form") != form:
                    raise OperationRefused(
                        f"no terminal failure of form {form}: {outcome} {evidence}"
                    )
                if hint not in (
                    evidence.get("wallet_tx"),
                    evidence.get("destination_tx"),
                    evidence.get("owner_tx"),
                ):
                    raise OperationRefused(f"{hint} is not this operation's transaction")
            elif form == "c":
                evidence = self.prove_expired(record)
            elif form == "d":
                evidence = self.prove_consumed(record)
            else:
                raise OperationRefused(f"unknown failure form {form}")
            # (c) and (d) say the message never took effect; one last read of both
            # validators, right before the immutable record, must still agree.
            if form in ("c", "d") and self.find_wallet_tx(record) is not None:
                raise OperationRefused(
                    "the message took effect after all; settle it (record --settled)"
                )
            self.append_terminal(record, "failed", evidence, by="record")
            return self.journal.record(op_id)

    def prove_expired(self, record: dict) -> dict:
        if record["kind"] == "activate-owner" or record["valid_until"] == ACTIVATION_VALID_UNTIL:
            raise OperationRefused("an activation never expires; resubmit it, or prove (d)")
        # Expiry first, on both validators: once it is past, the message can no
        # longer execute, so the absence read after it is final.
        times = self.utimes()
        if any(t < record["valid_until"] + EXPIRY_MARGIN for t in times):
            raise OperationRefused(
                f"block times {times} are not all past valid_until {record['valid_until']} + "
                f"{EXPIRY_MARGIN} s; the message can still execute"
            )
        if self.find_wallet_tx(record) is not None:
            raise OperationRefused("the message was accepted; this is not expiry")
        if self.seqno(record["wallet"]) != record["seqno"]:
            raise OperationRefused("the wallet's seqno moved; prove (d) instead")
        return {
            "form": "c",
            "valid_until": record["valid_until"],
            "block_times": times,
            "explains": [],
        }

    def prove_consumed(self, record: dict) -> dict:
        if self.find_wallet_tx(record) is not None:
            raise OperationRefused("the message itself was accepted; this is not (d)")
        # The identity the message was signed against: the activation's expected one,
        # or the wallet's own as read when the message was signed.
        if record["kind"] == "activate-owner":
            identity = [record["code_hash"], record["public_key"]]
        else:
            identity = record.get("identity")
        current = self.identity(record["wallet"])
        if not identity or current is None or list(current) != list(identity):
            raise OperationRefused(
                "the wallet's identity is unknown or changed; (d) cannot be proven"
            )
        if self.seqno(record["wallet"]) <= record["seqno"]:
            raise OperationRefused("the record's seqno is not consumed yet")
        # Read after the seqno: the message itself may have taken effect since the
        # first check, and is then the consumer. A run of it that aborted took no
        # seqno, so whatever took effect at the seqno is another message.
        history = self.history(record["wallet"], record.get("boundary"))
        if any(
            t["in_kind"] == "external"
            and t["in_hash"] == record["external_hash"]
            and took_effect(t)
            for t in history
        ):
            raise OperationRefused(
                "the message itself took effect; this is not (d): settle it (record --settled)"
            )
        externals = [
            t
            for t in reversed(history)
            if t["in_kind"] == "external"
            and took_effect(t)
            and external_seqno(t) == record["seqno"]
        ]
        if len(externals) != 1:
            raise Unknown(
                f"{len(externals)} transactions in the history took seqno {record['seqno']}"
            )
        competitor = externals[0]
        return {"form": "d", "consumed_by": competitor["hash"], "explains": []}

    def resubmit(self, op_id: str, prerequisites=None, expect=None) -> dict:
        """The record's original message once more, while it can still execute."""
        with self.journal.lock():
            record = self.open_record(op_id)
            if record["kind"] not in KINDS:
                raise OperationRefused(f"operation {op_id} cannot be resubmitted")
            self.check_network()
            wallet = record["wallet"]
            if self.find_wallet_tx(record) is not None:
                raise OperationRefused("the message was accepted; record it instead")
            if record["kind"] == "activate-owner":
                # Not yet deployed: the address must be the StateInit's, and the
                # account only funded, never active or frozen.
                if wallet != f"-1:{record['state_init_hash']}":
                    raise OperationRefused("the activation's address is not its StateInit's")
                if self.balance(wallet) < ACTIVATION_FEE_NANOTOS:
                    raise OperationRefused(
                        f"{wallet} holds less than the activation's fee budget "
                        f"({ACTIVATION_FEE_NANOTOS} nanotos); fund it first"
                    )
                state = self.state(wallet)
                if state != "uninitialized":
                    raise OperationRefused(
                        f"the owner wallet is {state}; the activation cannot run"
                    )
            else:
                if self.seqno(wallet) != record["seqno"]:
                    raise OperationRefused("the wallet's seqno moved; the message cannot execute")
                current = self.identity(wallet)
                if (
                    not record.get("identity")
                    or current is None
                    or list(current) != record["identity"]
                ):
                    raise OperationRefused(
                        "the wallet's identity changed; the message is not resubmitted"
                    )
                times = self.utimes()
                if any(t >= record["valid_until"] for t in times):
                    raise OperationRefused(f"the message has expired at {times}; prove (c) instead")
                if self.balance(wallet) < record["value"] + FEE_ALLOWANCE_NANOTOS:
                    raise OperationRefused(f"{wallet} cannot pay the message and its fee any more")
            if prerequisites:
                prerequisites()
            if self.bootstrap_identity(wallet):
                self.gate(wallet, op_id)
            self.nodes[0].call("sendBoc", boc=record["boc"])
            self.journal.append(op_id, {"state": "broadcast", "resubmitted": True})
        return self.watch(op_id, expect)

    def reconcile(self, wallets: list[str]) -> dict:
        """Read only: every record against the chain, and unexplained activity."""
        report: dict = {"operations": [], "unexplained": [], "explained": []}
        for record in self.journal.all():
            if not record:
                continue
            row = {
                k: record.get(k)
                for k in ("id", "kind", "wallet", "state", "external_hash", "predecessor")
            }
            if state_of(record) in ("signed", "broadcast"):
                try:
                    row["chain"] = self.settle(record)
                except Unknown as exc:
                    row["chain"] = ("unknown", str(exc))
            report["operations"].append(row)
        explained = self.journal.explained()
        for wallet in wallets:
            try:
                retired = self.bootstrap_retired(wallet)
                if retired:
                    report.setdefault("retired", []).append(self.retired_report(wallet, retired))
                    continue
                if self.bootstrap_identity(wallet):
                    prefix = self.verify_bootstrap_prefix(wallet)
                    report.setdefault("checkpoints", []).append(
                        {k: v for k, v in prefix.items() if k != "transaction_receipts"}
                    )
                    continue
                for tx in self.history(wallet, self.history_start(wallet)):
                    if leaves(tx, wallet) and tx["hash"] not in explained:
                        election = self.election_message(wallet, tx)
                        if election is not None:
                            report["explained"].append(election)
                        else:
                            report["unexplained"].append(
                                {
                                    "wallet": wallet,
                                    "tx": tx["hash"],
                                    "lt": tx["lt"],
                                    "out": tx["out"],
                                }
                            )
            except Unknown as exc:
                report["unexplained"].append({"wallet": wallet, "unknown": str(exc)})
        return report

    def retired_report(self, wallet: str, sweep_id: str) -> dict:
        """A swept bootstrap wallet: its sweep's evidence, and the account still not
        active on both validators. No history is needed: the account is gone and its
        address is no StateInit's, so nothing can ever run code there again."""
        accounts = self.read_both(lambda node: node.account(wallet))
        if any(a["state"] != "uninitialized" for a in accounts):
            raise Unknown(f"the swept bootstrap wallet {wallet} reads {accounts[0]['state']}")
        record = self.journal.record(sweep_id) or {}
        evidence = record.get("evidence") or {}
        return {
            "wallet": wallet,
            "swept_by": sweep_id,
            "state": record.get("state"),
            "wallet_tx": evidence.get("wallet_tx"),
            "destination_tx": evidence.get("destination_tx"),
            "burned_nanotos": evidence.get("burned_nanotos"),
            "now": [{"state": a["state"], "balance": int(a["balance"])} for a in accounts],
        }

    def set_baseline(self, wallet: str, reason: str) -> dict:
        with self.journal.lock(wallet):
            self.check_network()
            for record in self.journal.for_wallet(wallet):
                if state_of(record) in ("planned", "signed", "broadcast"):
                    raise OperationRefused(f"operation {record['id']} is open")
            history = self.history(wallet, self.history_start(wallet))
            head = self.head(wallet)
            if head is None:
                raise OperationRefused(f"{wallet} has no transactions; no baseline is needed")
            self.journal.set_baseline(wallet, head, reason)
        return {"wallet": wallet, "boundary": head, "transactions_before": len(history)}
