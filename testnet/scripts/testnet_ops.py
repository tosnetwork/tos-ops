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
  signing wallet's complete history on two validators of the intended network
  and refuses when any transaction emitting a message is not explained by a
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
import json
import os
import re
import time
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
# Clock and propagation margin before an expired message counts as dead.
EXPIRY_MARGIN = 120
# wallet-v3: tosctl builds with 120 s, wallet-v3.fif here with 300 s.
MAX_TTL = {"host": 120, "coordinator": 300}
TTL_SKEW = 30
ACTIVATION_VALID_UNTIL = 0xFFFFFFFF
# What a wallet v3 self-deployment needs on its account before it is sent.
ACTIVATION_FEE_NANOTOS = NANO // 10
WALLET_V3_MODE = 3

COORDINATOR_KINDS = ("fund", "activate-owner", "principal", "withdraw")
HOST_KINDS = ("deploy-controller", "deploy-pool", "authorize-operations")
KINDS = COORDINATOR_KINDS + HOST_KINDS
STATES = ("planned", "signed", "broadcast", "settled", "failed")
# Test hook: TESTNET_OPS_CRASH_AT=<id>:<point> makes the process exit at that
# point, as a crash would, so the rehearsal can kill a run at each boundary.
CRASH_ENV = "TESTNET_OPS_CRASH_AT"
CRASH_POINTS = ("planned", "signed", "broadcast", "delivered")


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

    def history(self, address: str, boundary: dict | None) -> list[dict]:
        """Transactions newer than `boundary` (None: the whole account), newest first,
        each decoded from its own BOC (verify_transaction).

        getTransactionsStd pages backward through previous_transaction_id. The
        boundary must be reached exactly; anything else is Unknown."""
        info = self.account(address)
        last = info.get("last_transaction_id") or {}
        lt, hash_b64 = str(last.get("lt", "0")), last.get("hash", "")
        if lt == "0":
            if boundary:
                raise Unknown(f"{self.url}: {address} has no transactions, boundary {boundary}")
            return []
        out, seen = [], set()
        for _ in range(HISTORY_PAGES):
            page = self.call(
                "getTransactionsStd", address=address, lt=lt, hash=hash_b64, limit=HISTORY_PAGE
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
            prev = page.get("previous_transaction_id") or {}
            if str(prev.get("lt", "")) == "0":
                if boundary:
                    raise Unknown(f"{self.url}: {address} boundary {boundary} not in its history")
                return out
            if not progress:
                raise Unknown(f"{self.url}: {address} history made no progress at {lt}")
            lt, hash_b64 = str(prev.get("lt")), prev.get("hash")
        raise Unknown(f"{self.url}: {address} history longer than {HISTORY_PAGES} pages")


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
        return {
            "kind": "internal",
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
        s.bits(256 + 64 + 32 + 15 + 2 + 2)
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


# Parameters an attempt after a failure fixes anew (the failed one's are stale):
# an operating authorization is a new root-signed request with its own value.
ATTEMPT_PARAMS = {"authorize-operations": ("value", "body_hash", "plan", "body_b64")}
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
        path = self.dir / f"baseline-{wallet.replace(':', '_')}.jsonl"
        if not path.is_file():
            return None
        lines = [json.loads(line) for line in path.read_text().splitlines() if line]
        return lines[-1]["boundary"] if lines else None

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
        self, ceremony: Path, nodes: list[Node], global_id: int, clock=time.time, sleep=time.sleep
    ):
        if len(nodes) != 2 or nodes[0].url == nodes[1].url:
            raise OperationRefused("value-moving steps need two different validators")
        self.ceremony = Path(ceremony)
        self.nodes, self.global_id = nodes, global_id
        self.journal = Journal(ceremony)
        self.clock, self.sleep = clock, sleep
        self._network_checked = False

    # -- network

    def check_network(self) -> None:
        if self._network_checked:
            return
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
        self._network_checked = True

    # -- reading both

    def both(self, read) -> Any:
        answers = [read(node) for node in self.nodes]
        if answers[0] != answers[1]:
            raise Unknown(f"the validators disagree or one lags: {answers[0]!r} / {answers[1]!r}")
        return answers[0]

    def history(self, wallet: str, boundary: dict | None) -> list[dict]:
        """Agreed history: the same transactions (each verified against its own BOC
        on each node, so the same hash means the same decoded facts)."""
        histories = [node.history(wallet, boundary) for node in self.nodes]
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
        return [node.utime() for node in self.nodes]

    # -- the gate

    def gate(self, wallet: str, op_id: str) -> None:
        """Refuse unless the wallet's history is complete, agreed and explained, and
        no other operation of the wallet is open. Called with the journal lock held."""
        self.check_network()
        for record in self.journal.for_wallet(wallet):
            if record["id"] != op_id and state_of(record) in ("signed", "broadcast"):
                raise OperationRefused(
                    f"operation {record['id']} of {wallet} is open ({record['state']}, external "
                    f"{record.get('external_hash')}); run reconcile, then record or resubmit"
                )
        boundary = self.journal.baseline(wallet)
        explained = self.journal.explained()
        for tx in self.history(wallet, boundary):
            if leaves(tx, wallet) and tx["hash"] not in explained:
                described = ", ".join(f"{m['value']} to {m['destination']}" for m in tx["out"])
                raise OperationRefused(
                    f"{wallet} transaction {tx['hash']} (lt {tx['lt']}) sent {described}, which no "
                    "settled or failed operation explains; reconcile it by hand"
                    + ("" if boundary else " (or record a baseline if it predates the journal)")
                )

    # -- running one step

    def begin(self, op_id: str, params: dict) -> dict:
        """The operation's record, created as planned if new, with the journal lock held.
        Recorded parameters never change; a new attempt fixes its open ones once."""
        record = self.journal.record(op_id)
        if record is None:
            self.journal.append(op_id, dict(params, state="planned"))
            crash_point(op_id, "planned")
            return self.journal.record(op_id)
        open_keys = set(record.get("open_params") or []) if state_of(record) == "planned" else set()
        mismatch = {
            k: (record.get(k), v)
            for k, v in params.items()
            if k in record and record.get(k) != v and k not in open_keys
        }
        mismatch.update(
            {k: (None, v) for k, v in params.items() if k not in record and k not in open_keys}
        )
        if mismatch:
            raise OperationRefused(f"operation {op_id} exists with other parameters: {mismatch}")
        fill = {k: params[k] for k in open_keys if k in params}
        if fill:
            self.journal.append(op_id, dict(fill, state="planned", open_params=[]))
            record = self.journal.record(op_id)
        return record

    def run(self, step: str, params: dict, sign, validate, prerequisites=None, expect=None) -> dict:
        """Gate, sign once, journal, broadcast once, watch for settlement, all decided
        with the journal lock held and the record re-read under it.

        `step` resolves to its newest attempt. `sign(seqno)` returns the external
        message BOC; `validate(decoded)` refuses a message that is not exactly the
        intended one; `prerequisites()` checks spending conditions right before
        signing. Returns the settled record."""
        if params["kind"] not in KINDS:
            raise OperationRefused(f"unknown operation kind {params['kind']}")
        wallet = params["wallet"]
        with self.journal.lock(wallet):
            op_id = self.journal.newest(step)
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
            self.gate(wallet, op_id)
            if prerequisites:
                prerequisites()
            boundary = self.head(wallet)
            seqno = self.seqno(wallet)
            identity = self.identity(wallet)
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
                },
            )
            crash_point(op_id, "signed")
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
        if decoded["mode"] != WALLET_V3_MODE or decoded["init_hash"]:
            raise OperationRefused("not a wallet v3 transfer with send mode 3 and no StateInit")
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
                    self.journal.append(op_id, {"state": "settled", "evidence": evidence})
                    return self.journal.record(op_id)
                if outcome == "failed":
                    self.journal.append(op_id, {"state": "failed", "evidence": evidence})
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
        parameters (only the kind's ATTEMPT_PARAMS are fixed anew, once), names its
        predecessor, and is created by one complete append, so a crash leaves either
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
            open_keys = ATTEMPT_PARAMS.get(record["kind"], ())
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
                    "open_params",
                    "predecessor",
                    "reason",
                }
                and k not in open_keys
            }
            successor = attempt_id(step, n + 1)
            self.journal.append(
                successor,
                dict(
                    keep,
                    state="planned",
                    predecessor=newest,
                    reason=reason,
                    open_params=list(open_keys),
                ),
            )
            return self.journal.record(successor)

    # -- settlement

    def wallet_attempts(self, record: dict) -> list[dict]:
        """Every wallet transaction of the record's external message, newest first."""
        return [
            tx
            for tx in self.history(record["wallet"], record.get("boundary"))
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

    def find_delivery(self, destination: str, message_hash: str, after_lt: int) -> dict | None:
        def read(node):
            for tx in node.history(destination, None):
                if tx["lt"] <= after_lt:
                    return None
                if tx["in_hash"] == message_hash and tx["in_kind"] == "internal":
                    return tx
            return None

        found = [read(node) for node in self.nodes]
        if found[0] != found[1]:
            raise Unknown(f"the validators disagree or one lags on the delivery of {message_hash}")
        return found[0]

    def settle(self, record: dict, expect=None) -> tuple[str, dict]:
        """("pending" | "settled" | "failed", evidence) from the chain alone."""
        if state_of(record) not in ("signed", "broadcast"):
            raise OperationRefused(f"operation {record['id']} is {state_of(record)}")
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
        evidence = {"wallet_tx": tx["hash"], "explains": [tx["hash"]]}
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
        delivery = self.find_delivery(record["destination"], message["hash"], tx["lt"])
        if delivery is None:
            return "pending", dict(evidence, reason="the message is not delivered yet")
        evidence["destination_tx"] = delivery["hash"]
        kind = record["kind"]
        if kind == "fund":
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
        receipt = self.find_delivery(record["wallet"], payment["hash"], pool_tx["lt"])
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
            self.journal.append(op_id, {"state": "settled", "evidence": evidence, "by": "record"})
            return self.journal.record(op_id)

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
            self.journal.append(op_id, {"state": "failed", "evidence": evidence, "by": "record"})
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
            self.nodes[0].call("sendBoc", boc=record["boc"])
            self.journal.append(op_id, {"state": "broadcast", "resubmitted": True})
        return self.watch(op_id, expect)

    def reconcile(self, wallets: list[str]) -> dict:
        """Read only: every record against the chain, and unexplained activity."""
        report: dict = {"operations": [], "unexplained": []}
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
                for tx in self.history(wallet, self.journal.baseline(wallet)):
                    if leaves(tx, wallet) and tx["hash"] not in explained:
                        report["unexplained"].append(
                            {"wallet": wallet, "tx": tx["hash"], "lt": tx["lt"], "out": tx["out"]}
                        )
            except Unknown as exc:
                report["unexplained"].append({"wallet": wallet, "unknown": str(exc)})
        return report

    def set_baseline(self, wallet: str, reason: str) -> dict:
        with self.journal.lock(wallet):
            self.check_network()
            for record in self.journal.for_wallet(wallet):
                if state_of(record) in ("signed", "broadcast"):
                    raise OperationRefused(f"operation {record['id']} is open")
            history = self.history(wallet, self.journal.baseline(wallet))
            head = self.head(wallet)
            if head is None:
                raise OperationRefused(f"{wallet} has no transactions; no baseline is needed")
            self.journal.set_baseline(wallet, head, reason)
        return {"wallet": wallet, "boundary": head, "transactions_before": len(history)}
