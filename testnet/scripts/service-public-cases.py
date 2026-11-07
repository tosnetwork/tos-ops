#!/usr/bin/env python3
"""Once-only public runner for the bounded service-contract acceptance cases (SC-02..SC-08).

The runner drives the pinned `tosctl` against the public testnet from a private directory
on the coordinator and records exact public receipts. It never signs the funding (pool-owner)
wallet: funding stays in `testnet-elections.py owner-fund`, and this tool only plans the
amounts, verifies the credits and keeps the cumulative total under a hard ceiling.

Guarantees the tests pin:
  * every value step has a stable label and an `O_EXCL` attempt marker written before the CLI
    is invoked; a label whose marker exists is refused, so a crash or lost reply can never lead
    to a second send of the same step (reconciliation is read-only); a step that ended in any
    verdict other than settled / refused-as-intended / cli-refused-before-broadcast is never
    replayed or re-sent;
  * a settlement claim is the exact transaction (same hash) seen on the broadcast source and on
    every confirmation source, found through the payer's own outgoing message, with the compute
    exit code, the aborted flag and the action result recorded; a refusal control must abort
    with the pinned exit code and leave the protected contract state unchanged;
  * a CLI refusal is only recorded as "nothing was sent" after a bounded observation window on
    the payer, and such a control carries no on-chain receipt, which the case result says;
  * preflight refuses a wrong CLI binary, a different genesis on any source, a global version
    other than the pinned one, the window around a validator-set rotation (ConfigParam 34
    bounds), an over-temperature package, a group-readable private directory and a cumulative
    funding total above the ceiling; the rotation and thermal guards run again before every
    value step;
  * `plan <case>` lists the exact CLI argument vectors a case will use; `case` checks them
    against the pinned CLI's own `--help` before the first send;
  * CLI stdout/stderr land in the private directory; the evidence directory only receives
    sanitized records (labels, argv with the private path redacted, addresses, hashes, codes).

Commands: preflight | setup | plan-funding | record-funding | activate | plan <case> |
case <case> | return-funds | status.  See `--help`.
"""

from __future__ import annotations

import argparse
import base64
import calendar
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

NANO = 10**9
QUIET_S = 600
TEMP_LIMIT_C = 82.0
CLI_TIMEOUT_S = 180
SETTLE_TIMEOUT_S = 150
REFUSAL_OBSERVE_S = 45
# A record that ended `unknown` after a refused CLI is settled as "nothing sent" only this long
# after it was written: the live window already watched 45 s after the CLI exit, and a message
# still in flight at that point lands within the next few blocks or never; well beyond that is
# the margin for a slow source, not a different quantity than the live window.
NOTHING_SENT_SETTLE_S = 120
POLL_S = 2.0
CP8_VERSION = 16
WALLETS = ("sc-owner", "sc-client", "sc-verifier", "sc-respondent", "sc-outsider")
KEYS = ("sc-attestor-key", "sc-rotated-attestor-key", "sc-wrong-key")
FUNDING_PLAN_TOS = {
    "sc-owner": "7.5",
    "sc-client": "3.0",
    "sc-verifier": "2.0",
    "sc-respondent": "1.5",
    "sc-outsider": "2.0",
}
AMOUNT_RE = re.compile(r"^(\d+)(?:\.(\d{1,9}))?$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HASH = {
    "subject": "11" * 32,
    "attested_1": "22" * 32,
    "attested_2": "33" * 32,
    "metadata": "44" * 32,
    "proof_scheme": "55" * 32,
    "task_categories": "66" * 32,
    "pricing": "77" * 32,
    "verification_method": "88" * 32,
    "new_metadata": "99" * 32,
    "policy": "aa" * 32,
    "result": "bb" * 32,
    "evidence": "cc" * 32,
    "dispute": "dd" * 32,
    "claimant_evidence": "ee" * 32,
    "respondent_evidence": "ff" * 32,
    "ruling": "12" * 32,
    "response": "34" * 32,
    "request_1": "56" * 32,
    "request_2": "78" * 32,
}

# Contract exit codes (crypto/smartcont/*.fc at the pinned CLI commit) and limits.
SERVICE_NOT_OWNER = 1900
SERVICE_NOT_AUTHORIZED = 1923
TASK_ACCEPT_NOT_AGENT = 101
TASK_SETTLE_NOT_SUBMITTED = 104  # settle in any status other than result_submitted
TASK_SETTLE_AUTHORITY = 105
TASK_RESOLVE_AUTHORITY = 124
# Agent-account refusals that happen before accept_message(): the node rejects the external
# message at admission ("exitcode=N" in the sendBoc error) and no transaction can exist.
AGENT_BAD_SIGNATURE = 1704
AGENT_BAD_SEQNO = 1705
AGENT_STALE_CONTROLLER = 1710
AGENT_EXPIRED = 1706
# Native Registry (tos c17d3fca5, crypto/smartcont/native-registry-code.fc).
NR_BAD_PREDECESSOR = 2204
NR_TOMBSTONED = 2206
NR_BAD_SIGNATURE = 2208
NR_LABEL = "tos:global-id:2"  # owner-frozen identity domain (queue report section 7.1)
NR_GLOBAL_CONFIG_SHA256 = "28a764e73f4f0f69e34dfdde6748d67b78afa242b211282f81d25721d860e039"
NR_CODE_HASH = "d3bb66d0011a1f362dd0be8408ed688f4e740d096a0e2dc2a79fc0ffc628b28a"
NR_ACTOR = "sc-registry"
NR_CONTROLLERS = ("nr-a1", "nr-a2", "nr-b1")
NR_VALUE_NANOTOS = 300_000_000  # per registry message (section 7.3)
NR_CAP_NANOTOS = 5_000_000_000  # hard cap for the whole registry batch (section 7.3)
NR_GLOBAL_ID = 2
AGENT_TASK_SEND_OP = "0x41475003"
# SC-03e: a prepared request expires this far ahead; the chain must be this far past it.
EXPIRY_LEAD_S = 90
EXPIRY_MARGIN_S = 20
AGENT_EXTERNAL_SIGNATURE_BITS = 512
# An executed controller request of the public testnet (SC-03, 2026-11-06), as carried by its
# transaction: a public message whose hash the chain reports as the transaction's in_msg hash.
# The planner and the tests parse it; nothing in it is secret.
SAMPLE_AGENT_REQUEST_BOC = (
    "te6ccgEBAwEAqQABRYgB6ubp2LaRkBGjiQlZ49/saG+jkMHkowybfYb1ogT0qzIMAQH7o4rs/u4hNchj5X08Ofe0"
    "AdTgB+ecmMTdZhHGXpCnZAkHAQDz5QAhK6ol3XKmO8PdUsrNVlysuJ2wCr80lbtACUFHUAMAAAACAAAAAAAAAAEA"
    "AAACau1dqYAZXuPXhP2BFCZdA/CFiK9Zkt3ZtaoQKi77N5NdCuDwXGgL68IBAgAA"
)
SAMPLE_AGENT_REQUEST_HASH = "UEOm2JO876SysgF7jRy/uOepTot+liQBx+X81h55EeA="
DISPUTE_NOT_RESPONDENT = 2000
DISPUTE_NOT_REVIEWER = 2001
DISPUTE_ALREADY_RESOLVED = 2002
ATTEST_BAD_SIGNATURE = 2101
ATTEST_NOT_OWNER = 2102
REGISTRY_NOT_OWNER = 1800
REGISTRY_NOT_VERIFIER = 1801
REGISTRY_INSUFFICIENT_BOND = 1805
TASK_MIN_REVIEW_PERIOD_S = 3600
TASK_HORIZON_S = 7200
SERVICE_MIN_DEPLOY_TOS = "1.5"  # >= 1 TOS operating reserve + 0.2 TOS fee margin
SERVICE_WITHDRAW_CAP = 50_000_000  # 0.05 TOS, at most the price of the one answered call
REPLAYABLE = ("settled", "refused-as-intended", "cli-refused-before-broadcast")
RECONCILABLE = ("unknown", "unknown-not-observed", "unexpected-abort")
FLAG_FIXTURE = (
    Path(__file__).resolve().parents[1] / "tests" / "data" / "service-public-cases-cli-flags.json"
)


class Refusal(Exception):
    """A guard refused to continue; nothing was sent after it."""


def now() -> int:
    return int(time.time())


def utc(ts: int | float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def from_utc(text) -> int:
    """The epoch second of a journal timestamp written by `utc`."""
    try:
        return calendar.timegm(time.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ"))
    except (TypeError, ValueError) as exc:
        raise Refusal(f"record timestamp unreadable: {text!r}") from exc


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def norm_addr(address: str) -> str:
    """Canonical `wc:hex` form of a raw or user-friendly (base64url, checksummed) address."""
    if not isinstance(address, str) or not address:
        raise Refusal(f"bad address {address!r}")
    if ":" in address:
        wc, _, acc = address.partition(":")
        if not re.fullmatch(r"-?\d+", wc) or not HEX64_RE.fullmatch(acc.lower()):
            raise Refusal(f"bad raw address {address!r}")
        return f"{int(wc)}:{acc.lower()}"
    try:
        raw = base64.urlsafe_b64decode(address.replace("+", "-").replace("/", "_") + "==")
    except (ValueError, TypeError) as exc:
        raise Refusal(f"bad address {address!r}") from exc
    if len(raw) != 36 or crc16_xmodem(raw[:34]) != int.from_bytes(raw[34:], "big"):
        raise Refusal(f"bad address checksum {address!r}")
    wc = int.from_bytes(raw[1:2], "big", signed=True)
    return f"{wc}:{raw[2:34].hex()}"


def same_addr(a: str | None, b: str | None) -> bool:
    try:
        return bool(a) and bool(b) and norm_addr(a) == norm_addr(b)
    except Refusal:
        return False


def tos_to_nanotos(text: str) -> int:
    m = AMOUNT_RE.fullmatch(str(text).strip())
    if not m:
        raise Refusal(f"bad TOS amount {text!r}")
    whole, frac = m.group(1), m.group(2) or ""
    return int(whole) * NANO + int((frac + "0" * 9)[:9])


def nanotos_text(value: int) -> str:
    if value < 0:
        raise Refusal("negative amount")
    return f"{value // NANO}.{value % NANO:09d}"


def state_nanotos(value) -> int:
    """A contract view amount, which the CLI prints either as nanotos or as a TOS string."""
    if isinstance(value, bool) or value is None:
        raise Refusal(f"amount field missing: {value!r}")
    if isinstance(value, int):
        return value
    text = str(value)
    return tos_to_nanotos(text) if "." in text else int(text)


def boc_root_data(raw: bytes) -> bytes:
    """Data bytes of the root cell of a serialized bag of cells (no cell parsing beyond that)."""
    try:
        if raw[:4] != bytes.fromhex("b5ee9c72"):
            raise Refusal("not a BOC")
        flags = raw[4]
        size = flags & 7
        has_index = bool(flags & 0x80)
        off = raw[5]
        p = 6
        count = int.from_bytes(raw[p : p + size], "big")
        p += size * 3  # cells, roots, absent
        p += off  # total size
        root = int.from_bytes(raw[p : p + size], "big")
        p += size
        if has_index:
            p += count * off
        for i in range(count):
            d1, d2 = raw[p], raw[p + 1]
            refs = d1 & 7
            stored = bool(d1 & 16)
            p += 2
            if stored:
                hashes = bin(d1 >> 5).count("1") + 1
                p += hashes * 34
            ln = (d2 + 1) // 2
            data = raw[p : p + ln]
            if len(data) != ln:
                raise Refusal("BOC truncated")
            p += ln + refs * size
            if i == root:
                return data
    except IndexError as exc:
        raise Refusal("BOC truncated") from exc
    raise Refusal("BOC root missing")


class Cell:
    """An ordinary TVM cell: a bit string and up to four child cells."""

    __slots__ = ("bits", "refs")

    def __init__(self, bits: str, refs: list):
        if len(bits) > 1023 or len(refs) > 4 or set(bits) - {"0", "1"}:
            raise Refusal("cell out of bounds")
        self.bits = bits
        self.refs = list(refs)


BOC_MAGIC = bytes.fromhex("b5ee9c72")
MAX_CELL_DEPTH = 1024
MAX_BOC_CELLS = 255


def _cell_bits(data: bytes, d2: int) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    if d2 % 2 == 1:
        # Completion tag: the last set bit and everything after it is padding.
        if "1" not in bits:
            raise Refusal("cell padding without a completion tag")
        bits = bits[: bits.rindex("1")]
    if _d2(bits) != d2:
        raise Refusal("cell completion tag does not match its length descriptor")
    return bits


def _d2(bits: str) -> int:
    return (len(bits) + 7) // 8 + len(bits) // 8


def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def _cell_data(bits: str) -> bytes:
    if len(bits) % 8:
        bits = bits + "1" + "0" * (7 - len(bits) % 8)
    return int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b""


def _descriptors(c: Cell) -> bytes:
    return bytes([len(c.refs), _d2(c.bits)])


def boc_decode(raw: bytes) -> Cell:
    """The single root of a serialized bag of ordinary cells. Fails closed: every header field,
    cell descriptor and completion tag must be exactly what a tree of ordinary level-0 cells
    serializes to; indexed bags and cache bits are refused; a CRC, when present, must verify."""
    try:
        if raw[:4] != BOC_MAGIC:
            raise Refusal("not a BOC")
        flags = raw[4]
        size, off = flags & 7, raw[5]
        has_index, has_crc = bool(flags & 0x80), bool(flags & 0x40)
        if flags & 0x38:
            raise Refusal("BOC header uses cache bits or reserved flags")
        if has_index:
            raise Refusal("indexed BOC not supported")
        if not 1 <= size <= 4 or not 1 <= off <= 8:
            raise Refusal("BOC header sizes out of range")
        p = 6
        count = int.from_bytes(raw[p : p + size], "big")
        roots = int.from_bytes(raw[p + size : p + 2 * size], "big")
        absent = int.from_bytes(raw[p + 2 * size : p + 3 * size], "big")
        total = int.from_bytes(raw[p + 3 * size : p + 3 * size + off], "big")
        p += 3 * size + off
        if roots != 1 or absent != 0 or count == 0:
            raise Refusal(f"BOC with {roots} roots, {absent} absent cells, {count} cells")
        root_idx = int.from_bytes(raw[p : p + size], "big")
        if root_idx >= count:
            raise Refusal("BOC root index out of range")
        p += size
        cells_start = p
        raw_cells = []
        for i in range(count):
            d1, d2 = raw[p], raw[p + 1]
            if d1 >= 8:
                raise Refusal("not an ordinary level-0 cell without stored hashes")
            refs = d1
            ln = (d2 + 1) // 2
            data = raw[p + 2 : p + 2 + ln]
            if len(data) != ln:
                raise Refusal("BOC truncated")
            p += 2 + ln
            ref_idx = [
                int.from_bytes(raw[p + j * size : p + (j + 1) * size], "big") for j in range(refs)
            ]
            if any(r <= i or r >= count for r in ref_idx):
                raise Refusal("BOC reference order")
            p += refs * size
            raw_cells.append((_cell_bits(data, d2), ref_idx))
        if p - cells_start != total:
            raise Refusal("BOC cell data size does not match its header")
        if has_crc:
            if raw[p : p + 4] != _crc32c(raw[:p]).to_bytes(4, "little") or len(raw) < p + 4:
                raise Refusal("BOC CRC mismatch")
            p += 4
        if p != len(raw):
            raise Refusal("BOC has trailing bytes")
    except IndexError as exc:
        raise Refusal("BOC truncated") from exc
    cells: list = [None] * count
    for i in range(count - 1, -1, -1):
        bits, ref_idx = raw_cells[i]
        cells[i] = Cell(bits, [cells[r] for r in ref_idx])
    return cells[root_idx]


def _tree(root: Cell) -> list[Cell]:
    """Cells of a tree, parents before children, found iteratively; a shared cell, a cycle, an
    excess depth or an excess cell count is refused before its descendants are expanded."""
    order: list[Cell] = []
    seen: set[int] = set()
    stack = [(root, 0)]
    while stack:
        c, depth = stack.pop()
        if id(c) in seen:
            raise Refusal("shared cells are not supported")
        if depth > MAX_CELL_DEPTH:
            raise Refusal("cell tree too deep")
        seen.add(id(c))
        order.append(c)
        if len(order) > MAX_BOC_CELLS:
            raise Refusal("BOC too large for this encoder")
        for r in reversed(c.refs):
            stack.append((r, depth + 1))
    return order


def boc_encode(root: Cell) -> bytes:
    """Serialize a tree of ordinary cells (no index, no CRC); children follow their parent."""
    order = _tree(root)
    index = {id(c): i for i, c in enumerate(order)}
    body = b"".join(
        _descriptors(c) + _cell_data(c.bits) + b"".join(bytes([index[id(r)]]) for r in c.refs)
        for c in order
    )
    off = max(1, (len(body).bit_length() + 7) // 8)
    return (
        bytes.fromhex("b5ee9c72")
        + bytes([1, off, len(order), 1, 0])
        + len(body).to_bytes(off, "big")
        + b"\x00"
        + body
    )


def _depths_and_hashes(root: Cell) -> tuple[dict[int, int], dict[int, bytes]]:
    depth: dict[int, int] = {}
    hashes: dict[int, bytes] = {}
    for c in reversed(_tree(root)):
        rep = _descriptors(c) + _cell_data(c.bits)
        rep += b"".join(depth[id(r)].to_bytes(2, "big") for r in c.refs)
        rep += b"".join(hashes[id(r)] for r in c.refs)
        depth[id(c)] = 0 if not c.refs else 1 + max(depth[id(r)] for r in c.refs)
        hashes[id(c)] = hashlib.sha256(rep).digest()
    return depth, hashes


MAX_DAG_CELLS = 4096
# A positively established absence of a registry object (JSON-safe; survives a journal reload).
NR_ABSENT = {"registered": False, "absent": True}
NR_FEE_ALLOWANCE_NANOTOS = 10_000_000  # the payer's own transfer fee, on top of the value
NR_PAYER_RESERVE_NANOTOS = 50_000_000  # kept in the payer after each send
WALLET_ACTIVATE_MIN_NANOTOS = 100_000_000  # tosctl `wallet activate` MIN_BALANCE (0.1 TOS)


def dag_cell_hash_b64(root: Cell) -> str:
    return base64.b64encode(dag_cell_hash(root)).decode()


def dag_cell_hash(root: Cell) -> bytes:
    """Representation hash of a cell DAG whose subtrees may be shared (a contract's code inside a
    StateInit), as the chain computes it. Iterative and memoized per distinct cell; refuses more
    than MAX_DAG_CELLS distinct cells, a depth beyond MAX_CELL_DEPTH, and cycles. Used only to
    bind decoded payloads; the runner never re-encodes a DAG, it sends saved bytes as they are."""
    hashes: dict[int, bytes] = {}
    depths: dict[int, int] = {}
    on_path: set[int] = set()
    stack: list[tuple[Cell, int, bool]] = [(root, 0, False)]
    while stack:
        c, level, expanded = stack.pop()
        key = id(c)
        if expanded:
            on_path.discard(key)
            rep = _descriptors(c) + _cell_data(c.bits)
            rep += b"".join(depths[id(r)].to_bytes(2, "big") for r in c.refs)
            rep += b"".join(hashes[id(r)] for r in c.refs)
            depths[key] = 0 if not c.refs else 1 + max(depths[id(r)] for r in c.refs)
            if depths[key] > MAX_CELL_DEPTH:
                raise Refusal("cell DAG too deep")
            hashes[key] = hashlib.sha256(rep).digest()
            continue
        if key in hashes:
            continue
        if key in on_path:
            raise Refusal("cell DAG has a cycle")
        if level > MAX_CELL_DEPTH:
            raise Refusal("cell DAG too deep")
        on_path.add(key)
        if len(on_path) + len(hashes) > MAX_DAG_CELLS:
            raise Refusal("cell DAG too large")
        stack.append((c, level, True))
        for r in reversed(c.refs):
            if id(r) not in hashes:
                stack.append((r, level + 1, False))
    return hashes[id(root)]


def cell_depth(c: Cell) -> int:
    return _depths_and_hashes(c)[0][id(c)]


def cell_hash(c: Cell) -> bytes:
    """Representation hash of an ordinary level-0 cell, as the chain reports it."""
    return _depths_and_hashes(c)[1][id(c)]


def admission_exit_code(message: str) -> int | None:
    """The exit code the node names when it rejects an external message at admission."""
    m = re.search(r"\bexitcode=(-?\d+)\b", message)
    return int(m.group(1)) if m else None


def cell_hash_b64(c: Cell) -> str:
    return base64.b64encode(cell_hash(c)).decode()


def transaction_in_message(tx: Cell) -> Cell:
    """The inbound message of a serialized transaction (its first reference holds
    `in_msg:(Maybe ^Message)` followed by the outbound queue)."""
    if not tx.refs or not tx.refs[0].bits or tx.refs[0].bits[0] != "1" or not tx.refs[0].refs:
        raise Refusal("transaction has no inbound message")
    return tx.refs[0].refs[0]


def external_message_parts(msg: Cell) -> dict:
    """Destination and body of an inbound external message (`ext_in_msg_info`, no StateInit,
    body in a reference)."""
    b = msg.bits
    if len(b) < 276 or b[:2] != "10" or b[2:4] != "00" or b[4:6] != "10" or b[6] != "0":
        raise Refusal("not an ext_in_msg_info to a standard address")
    wc = int(b[7:15], 2)
    wc = wc - 256 if wc >= 128 else wc
    addr = f"{wc}:{int(b[15:271], 2):064x}"
    fee_len = int(b[271:275], 2)
    p = 275 + fee_len * 8
    if len(b) < p + 2 or b[p] != "0":
        raise Refusal("external message carries a StateInit")
    if b[p + 1] != "1" or len(b) != p + 2 or not msg.refs:
        raise Refusal("external message body is not a reference")
    return {"destination": addr, "body": msg.refs[0]}


def agent_external_header(body: Cell) -> dict:
    """Signature-covered header of an agent-account controller request."""
    b = body.bits
    s = AGENT_EXTERNAL_SIGNATURE_BITS
    if len(b) < s + 32 + 32 + 64 + 32 + 32:
        raise Refusal("agent request body too short")
    gid = int(b[s + 32 : s + 64], 2)
    return {
        "op": f"0x{int(b[s : s + 32], 2):08x}",
        "global_id": gid - (1 << 32) if gid >= 1 << 31 else gid,
        "controller_epoch": int(b[s + 64 : s + 128], 2),
        "seqno": int(b[s + 128 : s + 160], 2),
        "valid_until": int(b[s + 160 : s + 192], 2),
    }


class _Bits:
    """A cursor over one cell's bits and refs that refuses to read past either."""

    def __init__(self, cell: Cell):
        self.cell, self.pos, self.ref = cell, 0, 0

    def take(self, n: int) -> str:
        if self.pos + n > len(self.cell.bits):
            raise Refusal("cell underflow")
        out = self.cell.bits[self.pos : self.pos + n]
        self.pos += n
        return out

    def uint(self, n: int) -> int:
        return int(self.take(n), 2) if n else 0

    def next_ref(self) -> Cell:
        if self.ref >= len(self.cell.refs):
            raise Refusal("cell has no further reference")
        self.ref += 1
        return self.cell.refs[self.ref - 1]

    def grams(self) -> int:
        return self.uint(self.uint(4) * 8)

    def std_address(self) -> str:
        if self.take(3) != "100":  # addr_std$10, no anycast
            raise Refusal("not a standard address without anycast")
        wc = self.uint(8)
        wc = wc - 256 if wc >= 128 else wc
        return f"{wc}:{self.uint(256):064x}"

    def at_end(self) -> bool:
        return self.pos == len(self.cell.bits) and self.ref == len(self.cell.refs)


def _inline_state_init(m: _Bits) -> Cell:
    """Read a StateInit stored inline in a message and return it as its own cell (the cell a
    reference would hold), so its hash can be compared with a separately built StateInit.
    Only code and data are accepted: split_depth, special and libraries are refused."""
    start, first_ref = m.pos, m.ref
    if m.take(1) != "0" or m.take(1) != "0":
        raise Refusal("StateInit with split_depth or special flags is not supported")
    refs = []
    for _ in ("code", "data"):
        if m.take(1) == "1":
            refs.append(m.next_ref())
    if m.take(1) != "0":
        raise Refusal("StateInit with libraries is not supported")
    if m.ref - first_ref != len(refs):
        raise Refusal("StateInit reference count mismatch")
    return Cell(m.cell.bits[start : m.pos], refs)


def decode_wallet_envelope(msg: Cell) -> dict:
    """The exact contents of a TOS V3R2 (wallet3) signed external message with one internal
    message: the wallet address, global id, subwallet, deadline and seqno it was signed for, and the internal
    message's bounce flag, destination, value, StateInit and body as cells. Anything outside
    that shape (extra currencies, a second message, an inline StateInit, a non-standard address,
    trailing data) is refused, so a binding check never compares a partially parsed message."""
    h = _Bits(msg)
    if h.take(2) != "10" or h.take(2) != "00":  # ext_in_msg_info$10, src addr_none$00
        raise Refusal("not an inbound external message without a source")
    out = {"wallet": h.std_address()}
    h.grams()  # import_fee
    if h.take(1) != "0":
        raise Refusal("a wallet's external message carries no StateInit")
    if h.take(1) == "1":
        body = h.next_ref()
        if not h.at_end():
            raise Refusal("external message has trailing data after its body reference")
    else:
        body = Cell(msg.bits[h.pos :], msg.refs[h.ref :])
    b = _Bits(body)
    b.take(AGENT_EXTERNAL_SIGNATURE_BITS)
    gid = b.uint(32)  # TOS wallet3: global_id anti-replay field (crypto/smartcont/wallet3-code.fc)
    out["global_id"] = gid - (1 << 32) if gid >= 1 << 31 else gid
    out["subwallet"], out["valid_until"], out["seqno"] = b.uint(32), b.uint(32), b.uint(32)
    out["mode"] = b.uint(8)
    inner = b.next_ref()
    if not b.at_end():
        raise Refusal("wallet message carries more than one internal message or trailing data")
    m = _Bits(inner)
    if m.take(1) != "0":
        raise Refusal("not an internal message")
    m.take(1)  # ihr_disabled
    out["bounce"] = m.take(1) == "1"
    if m.take(1) != "0":
        raise Refusal("a bounced message cannot be an outgoing wallet message")
    if m.take(2) != "00":
        raise Refusal("outgoing wallet message must name no source")
    out["destination"] = m.std_address()
    out["value_nanotos"] = m.grams()
    if m.take(1) != "0":
        raise Refusal("extra currencies are not supported")
    m.grams()  # ihr_fee
    m.grams()  # fwd_fee
    m.uint(64)  # created_lt
    m.uint(32)  # created_at
    out["state_init"] = None
    if m.take(1) == "1":
        if m.take(1) == "1":
            out["state_init"] = m.next_ref()
        else:
            out["state_init"] = _inline_state_init(m)
    if m.take(1) == "1":
        out["body"] = m.next_ref()
        if not m.at_end():
            raise Refusal("internal message has trailing data after its body reference")
    else:
        rest = m.cell.bits[m.pos :]
        out["body"] = Cell(rest, m.cell.refs[m.ref :])
    return out


MAX_EXTERNAL_MESSAGE_BYTES = 65535
PREPARED_SEND_VERSION = "tosctl.wallet-prepared-send.v1"


def bind_prepared_send(
    envelope: dict,
    built: dict,
    *,
    payer: str,
    value_nanotos: int,
    bounce: bool,
    global_id: int,
    seqno: int,
) -> tuple[bytes, Cell, dict]:
    """Bind a `wallet send --build-only` envelope to the registry message it must carry.

    The exact signed bytes are decoded (never trusted from the envelope's own summary fields)
    and every part is compared: the paying wallet, network, wallet seqno, the internal message's
    destination, value and bounce flag, and the body and StateInit hashes of the CLI's
    `register-agent`/`action` output. The external message must fit MAX_EXTERNAL_MESSAGE_BYTES.
    Returns the raw bytes, the decoded message and the decoded envelope; refuses on any mismatch.
    """
    if envelope.get("version") != PREPARED_SEND_VERSION:
        raise Refusal(f"unexpected prepared-send version {envelope.get('version')!r}")
    raw = base64.b64decode(str(envelope.get("message_boc_base64") or ""), validate=True)
    if not raw or len(raw) > MAX_EXTERNAL_MESSAGE_BYTES:
        raise Refusal(f"external message is {len(raw)} bytes; limit {MAX_EXTERNAL_MESSAGE_BYTES}")
    msg = boc_decode(raw)
    e = decode_wallet_envelope(msg)
    body = boc_decode(base64.b64decode(str(built.get("body_boc") or ""), validate=True))
    want_init = built.get("state_init_boc")
    checks = {
        "payer": same_addr(e["wallet"], payer) and same_addr(envelope.get("payer"), payer),
        "global_id": e["global_id"] == global_id,
        "seqno": e["seqno"] == seqno,
        "destination": same_addr(e["destination"], built.get("destination"))
        and same_addr(envelope.get("destination"), built.get("destination")),
        "value": e["value_nanotos"] == value_nanotos == envelope.get("amount_nanotos"),
        "bounce": e["bounce"] == bounce,
        "body": dag_cell_hash(e["body"]) == dag_cell_hash(body),
    }
    if want_init:
        init = boc_decode(base64.b64decode(str(want_init), validate=True))
        checks["state_init"] = e["state_init"] is not None and dag_cell_hash(
            e["state_init"]
        ) == dag_cell_hash(init)
        checks["address"] = same_addr(built.get("destination"), "0:" + dag_cell_hash(init).hex())
    else:
        checks["state_init"] = e["state_init"] is None
    failed = sorted(k for k, ok in checks.items() if not ok)
    if failed:
        raise Refusal(
            f"prepared wallet message does not carry the built registry message: {failed}"
        )
    return raw, msg, e


def boc_encode_dag(root: Cell) -> bytes:
    """Serialize a cell DAG (shared subtrees stored once), parents before children, no index and
    no CRC. Used only for a registry body the runner mutates on purpose (a signature-bit probe);
    every other message is sent as the exact bytes it was built with."""
    hashes: dict[int, bytes] = {}

    def h(c: Cell) -> bytes:
        if id(c) not in hashes:
            hashes[id(c)] = dag_cell_hash(c)
        return hashes[id(c)]

    unique: dict[bytes, Cell] = {}
    order: list[bytes] = []
    visiting: set[bytes] = set()
    stack: list[tuple[Cell, bool]] = [(root, False)]
    while stack:
        c, done = stack.pop()
        key = h(c)
        if done:
            visiting.discard(key)
            if key not in unique:
                unique[key] = c
                order.append(key)
            continue
        if key in unique or key in visiting:
            continue
        visiting.add(key)
        stack.append((c, True))
        for r in c.refs:
            stack.append((r, False))
        if len(visiting) + len(unique) > MAX_DAG_CELLS:
            raise Refusal("cell DAG too large to encode")
    order.reverse()  # post-order reversed: every parent precedes its children
    index = {key: i for i, key in enumerate(order)}
    size = max(1, (len(order).bit_length() + 7) // 8)
    body = b"".join(
        _descriptors(unique[k])
        + _cell_data(unique[k].bits)
        + b"".join(index[h(r)].to_bytes(size, "big") for r in unique[k].refs)
        for k in order
    )
    off = max(1, (len(body).bit_length() + 7) // 8)
    return (
        BOC_MAGIC
        + bytes([size, off])
        + len(order).to_bytes(size, "big")
        + (1).to_bytes(size, "big")
        + (0).to_bytes(size, "big")
        + len(body).to_bytes(off, "big")
        + index[h(root)].to_bytes(size, "big")
        + body
    )


def with_flipped_registry_signature(body: Cell) -> Cell:
    """A copy of a Native Registry submission body whose first authority signature has its first
    data bit inverted. The structure is checked on the way down (signature set count, key id,
    the 2,420-byte ML-DSA-44 length) so only signature data, never a length or a key id, is
    altered."""
    if len(body.refs) < 2:
        raise Refusal("registry body has no signature set")
    sigset = body.refs[1]
    if len(sigset.bits) != 8 or int(sigset.bits, 2) < 1 or not sigset.refs:
        raise Refusal("registry body has an empty signature set")
    entry = sigset.refs[0]
    if len(entry.bits) != 256 or not entry.refs:
        raise Refusal("signature entry is not a key id followed by its signature")
    length = entry.refs[0]
    if len(length.bits) != 32 or int(length.bits, 2) != 2420 or not length.refs:
        raise Refusal("signature is not a 2,420-byte ML-DSA-44 signature")
    data = length.refs[0]
    flipped = Cell(("1" if data.bits[0] == "0" else "0") + data.bits[1:], data.refs)
    new_length = Cell(length.bits, [flipped, *length.refs[1:]])
    new_entry = Cell(entry.bits, [new_length, *entry.refs[1:]])
    new_sigset = Cell(sigset.bits, [new_entry, *sigset.refs[1:]])
    return Cell(body.bits, [body.refs[0], new_sigset, *body.refs[2:]])


def with_flipped_signature_bit(msg: Cell) -> Cell:
    """A copy of an external message whose first signature bit is inverted: same destination,
    same payload, a signature that cannot verify."""
    parts = external_message_parts(msg)
    body = parts["body"]
    if len(body.bits) < AGENT_EXTERNAL_SIGNATURE_BITS:
        raise Refusal("body shorter than a signature")
    flipped = ("1" if body.bits[0] == "0" else "0") + body.bits[1:]
    return Cell(msg.bits, [Cell(flipped, body.refs)])


def quiet_window_distance(ts: int, since: int, until: int) -> int:
    """Seconds between `ts` and the nearest validator-set boundary; 0 once `until` has passed."""
    if ts >= until or ts < since:
        return 0
    return min(ts - since, until - ts)


def package_temperatures() -> list[float]:
    out: list[float] = []
    for hw in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        for label in hw.glob("temp*_label"):
            try:
                if not label.read_text().startswith("Package id"):
                    continue
                value = label.with_name(label.name.replace("_label", "_input")).read_text()
                out.append(int(value.strip()) / 1000.0)
            except (OSError, ValueError):
                continue
    return out


class Rpc:
    def __init__(self, primary: str, confirms: list[str]):
        self.primary = primary
        self.confirms = confirms

    @property
    def all_sources(self) -> list[str]:
        return [self.primary, *self.confirms]

    def call(self, method: str, url: str | None = None, **params):
        return self.call_with(method, params, url)

    def call_with(self, method: str, params: dict, url: str | None = None):
        """JSON-RPC call with an explicit parameter object (needed when a parameter is itself
        named `method`, as in runGetMethod)."""
        url = url or self.primary
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        req = urllib.request.Request(
            url, data=body.encode(), headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                answer = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise Refusal(f"rpc {method} on {url}: {exc}") from exc
        if "result" not in answer:
            raise Refusal(f"rpc {method} on {url}: {answer.get('error')}")
        return answer["result"]

    def genesis(self, url: str) -> dict:
        init = self.call("getMasterchainInfo", url)["init"]
        return {"root_hash": init["root_hash"], "file_hash": init["file_hash"]}

    def head(self, url: str | None = None) -> dict:
        return self.call("getMasterchainInfo", url)["last"]

    def account_shard_utime(self, account: str, url: str | None = None) -> int:
        """Generation time of the shard block that covers `account` in the source's latest
        masterchain view: admission judges an external message's deadline against that shard
        state's time, which can lag the masterchain."""
        last = self.head(url)
        wc, hexaddr = norm_addr(account).split(":")
        prefix = int(hexaddr[:16], 16)
        covering = []
        for top in self.call("shards", url, seqno=last["seqno"])["shards"]:
            if int(top["workchain"]) != int(wc):
                continue
            shard = int(top["shard"]) & ((1 << 64) - 1)
            if shard == 0:
                continue
            low = shard & -shard  # the shard's tag bit
            mask = ((1 << 64) - 1) ^ (low - 1) ^ low
            if (prefix & mask) == (shard & mask):
                covering.append(top)
        if len(covering) != 1:
            raise Refusal(f"{len(covering)} shard tips cover {account}; expected exactly one")
        top = covering[0]
        header = self.call(
            "getBlockHeader",
            url,
            workchain=top["workchain"],
            shard=top["shard"],
            seqno=top["seqno"],
            root_hash=top["root_hash"],
            file_hash=top["file_hash"],
        )
        return int(header["gen_utime"])

    def config_param(self, idx: int) -> bytes:
        res = self.call("getConfigParam", config_id=idx)
        return boc_root_data(base64.b64decode(res["config"]["bytes"]))

    def send_boc(self, boc_b64: str, url: str | None = None) -> dict:
        """Broadcast a serialized message; the node's refusal is an answer, not a transport
        failure, so it is returned (`{"error": ...}`) instead of raised."""
        url = url or self.primary
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "sendBoc", "params": {"boc": boc_b64}}
        )
        req = urllib.request.Request(
            url, data=body.encode(), headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                answer = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise Refusal(f"rpc sendBoc on {url}: {exc}") from exc
        if "result" in answer:
            return {"result": answer["result"]}
        err = answer.get("error")
        if not isinstance(err, dict):
            raise Refusal(f"rpc sendBoc on {url}: malformed answer")
        return {"error": {k: err.get(k) for k in ("code", "message", "data")}}

    def run_get_method(self, address: str, method: str, url: str | None = None) -> list:
        res = self.call_with(
            "runGetMethod", {"address": address, "method": method, "stack": []}, url
        )
        if res.get("exit_code") != 0:
            raise Refusal(f"{method} on {address}: exit {res.get('exit_code')}")
        return list(res.get("stack") or [])

    def transaction_by_hash(self, address: str, tx_hash: str, url: str | None = None) -> dict:
        rows = self.call("getTransactions", url, address=address, limit=10)
        hit = [r for r in rows if r["transaction_id"]["hash"] == tx_hash]
        if len(hit) != 1:
            raise Refusal(f"transaction {tx_hash} of {address} is not in the latest page")
        return hit[0]

    def global_version(self) -> int:
        data = self.config_param(8)
        if len(data) < 5 or data[0] != 0xC4:
            raise Refusal("ConfigParam 8 tag")
        return int.from_bytes(data[1:5], "big")

    def rotation_bounds(self) -> tuple[int, int]:
        """(utime_since, utime_until) of the installed validator set (ConfigParam 34)."""
        data = self.config_param(34)
        if len(data) < 9 or data[0] not in (0x11, 0x12):
            raise Refusal("ConfigParam 34 tag")
        return int.from_bytes(data[1:5], "big"), int.from_bytes(data[5:9], "big")

    def info(self, address: str, url: str | None = None) -> dict:
        return self.call("getAddressInformation", url, address=address)

    def balance(self, address: str) -> int:
        return int(self.info(address)["balance"])

    def state(self, address: str) -> str:
        return str(self.info(address)["state"])

    def last_lt(self, address: str, url: str | None = None) -> int:
        tid = self.info(address, url).get("last_transaction_id") or {}
        return int(tid.get("lt") or 0)

    def transactions_after(self, address: str, lt: int, url: str | None = None) -> list[dict]:
        rows = self.call("getTransactions", url, address=address, limit=10)
        if len(rows) == 10 and all(int(r["transaction_id"]["lt"]) > lt for r in rows):
            raise Refusal(f"transaction page for {address} does not reach the baseline lt")
        return [r for r in rows if int(r["transaction_id"]["lt"]) > lt]


class Journal:
    def __init__(self, evidence: Path):
        self.evidence = evidence
        self.steps = evidence / "steps"
        self.steps.mkdir(parents=True, exist_ok=True)
        self.events = evidence / "events.jsonl"

    def log(self, **event) -> None:
        event.setdefault("utc", utc(now()))
        with self.events.open("a") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")

    def attempt(self, label: str, record: dict) -> Path:
        path = self.steps / f"{label}.attempt.json"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise Refusal(
                f"step {label!r} was already attempted; reconcile read-only, never re-send"
            ) from None
        with os.fdopen(fd, "w") as fh:
            json.dump({"label": label, "utc": utc(now()), **record}, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        return path

    def attempt_record(self, label: str) -> dict | None:
        path = self.steps / f"{label}.attempt.json"
        return json.loads(path.read_text()) if path.exists() else None

    def done(self, label: str, record: dict) -> None:
        path = self.steps / f"{label}.done.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"label": label, "utc": utc(now()), **record}, sort_keys=True))
        os.replace(tmp, path)

    def result(self, label: str) -> dict | None:
        """The step's record: a read-only reconciliation, if one was made, else the original."""
        for suffix in ("reconciled", "done"):
            path = self.steps / f"{label}.{suffix}.json"
            if path.exists():
                return json.loads(path.read_text())
        return None

    def reconciled(self, label: str, record: dict) -> None:
        path = self.steps / f"{label}.reconciled.json"
        with path.open("x") as fh:
            json.dump({"label": label, "utc": utc(now()), **record}, fh, sort_keys=True)

    def attempted(self, label: str) -> bool:
        return (self.steps / f"{label}.attempt.json").exists()


class Cli:
    def __init__(self, path: Path, sha256: str, private_dir: Path, journal: Journal):
        self.path = path
        self.expected_sha = sha256
        self.private = private_dir
        self.config = private_dir / "tosctl-config.json"
        self.vault_env = private_dir / "vault.env"
        self.receipts = private_dir / "receipts"
        self.journal = journal
        self.calls = 0

    def check_binary(self) -> str:
        actual = sha256_file(self.path)
        if actual != self.expected_sha:
            raise Refusal(f"CLI sha256 {actual} != pinned {self.expected_sha}")
        return actual

    def env(self) -> dict:
        env = {k: v for k, v in os.environ.items() if k not in ("VAULT_URL",)}
        if self.vault_env.exists():
            for line in self.vault_env.read_text().splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "VAULT_URL":
                    env["VAULT_URL"] = value.strip()
        return env

    def redact(self, args: tuple[str, ...]) -> list[str]:
        private = str(self.private)
        return [a.replace(private, "<private>") if private in a else a for a in args]

    def run(
        self,
        label: str,
        *args: str,
        want_json: bool = False,
        format_flag: bool = True,
        config: Path | None = None,
    ):
        """Run tosctl once. Raw output stays private; the sanitized record is journaled.

        `want_json` parses stdout as JSON; `format_flag=False` does so without appending the
        global `--format json` (for commands that print JSON themselves and reject that flag).

        Returns (exit code or None on timeout, stdout text or parsed JSON)."""
        self.receipts.mkdir(mode=0o700, exist_ok=True)
        argv = [str(self.path), *args, "-c", str(config or self.config)]
        if want_json and format_flag:
            argv += ["--format", "json"]
        self.calls += 1
        started = utc(now())
        timed_out = False
        try:
            proc = subprocess.run(
                argv, env=self.env(), capture_output=True, timeout=CLI_TIMEOUT_S, check=False
            )
            rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc, stdout, stderr = None, exc.stdout or b"", exc.stderr or b""
        (self.receipts / f"{label}.stdout").write_bytes(stdout)
        (self.receipts / f"{label}.stderr").write_bytes(stderr)
        self.journal.log(
            kind="cli",
            label=label,
            argv=self.redact(args),
            exit_code=rc,
            timed_out=timed_out,
            started=started,
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        )
        text = stdout.decode("utf-8", "replace")
        if want_json and rc == 0:
            try:
                return rc, json.loads(text)
            except json.JSONDecodeError as exc:
                raise Refusal(f"{label}: CLI did not return JSON ({exc})") from exc
        return rc, text


def pinned_flags(path: Path) -> dict:
    return json.loads(path.read_text())


class Runner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.private = Path(args.private_dir).expanduser()
        self.evidence = Path(args.evidence_dir).expanduser()
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.journal = Journal(self.evidence)
        self.cli = Cli(Path(args.cli), args.cli_sha256, self.private, self.journal)
        self.rpc = Rpc(args.rpc, list(args.confirm_rpc or []))
        self.actors_path = self.evidence / "actors.json"
        self.ledger_path = self.evidence / "funding-ledger.jsonl"
        self.plan_path = self.evidence / "funding-plan.json"
        self.ceiling = tos_to_nanotos(args.stop_ceiling)

    # ----- state files ------------------------------------------------------------------
    def actors(self) -> dict:
        if not self.actors_path.exists():
            raise Refusal("actors.json missing; run setup first")
        return json.loads(self.actors_path.read_text())

    def actor_address(self, actor: str) -> str:
        wallets = self.actors()["wallets"]
        if actor not in wallets:
            raise Refusal(f"unknown actor {actor!r}; known: {sorted(wallets)}")
        return wallets[actor]

    def funded_total(self) -> int:
        total = 0
        if self.ledger_path.exists():
            for line in self.ledger_path.read_text().splitlines():
                total += int(json.loads(line)["amount_nanotos"])
        return total

    # ----- guards -------------------------------------------------------------------------
    def check_private_dir(self) -> None:
        if not self.private.exists():
            self.private.mkdir(mode=0o700, parents=True)
        mode = stat.S_IMODE(self.private.stat().st_mode)
        if mode & 0o077:
            raise Refusal(f"private dir {self.private} mode {oct(mode)} must be 0700")

    def check_genesis(self) -> dict:
        seen = {url: self.rpc.genesis(url) for url in self.rpc.all_sources}
        pinned = {"root_hash": self.args.genesis_root, "file_hash": self.args.genesis_file}
        for url, g in seen.items():
            if g != pinned:
                raise Refusal(f"genesis on {url} is {g}, pinned {pinned}")
        return pinned

    def check_quiet_window(self) -> dict:
        since, until = self.rpc.rotation_bounds()
        distance = quiet_window_distance(now(), since, until)
        if distance < QUIET_S:
            raise Refusal(
                f"within {distance}s of a validator-set boundary (since {utc(since)}, "
                f"until {utc(until)}); wait"
            )
        return {"utime_since": since, "utime_until": until, "seconds_to_boundary": distance}

    def check_thermal(self) -> list[float]:
        temps = package_temperatures()
        if self.args.skip_thermal:
            return temps
        if not temps:
            raise Refusal("no package temperature readable; use --skip-thermal only off-host")
        if max(temps) > TEMP_LIMIT_C:
            raise Refusal(f"package temperature {max(temps)} C above {TEMP_LIMIT_C}")
        return temps

    def guards(self) -> dict:
        """The two conditions that can change while a case runs; checked before every step."""
        return {
            "quiet_window": self.check_quiet_window(),
            "package_temperatures_c": self.check_thermal(),
        }

    def preflight(self, value_action: bool = True) -> dict:
        record = {
            "utc": utc(now()),
            "cli_sha256": self.cli.check_binary(),
            "genesis": self.check_genesis(),
            "global_version": self.rpc.global_version(),
            "head": self.rpc.head(),
            "funded_total_nanotos": self.funded_total(),
            "stop_ceiling_nanotos": self.ceiling,
        }
        if record["global_version"] != CP8_VERSION:
            raise Refusal(f"global version {record['global_version']} != {CP8_VERSION}")
        if value_action:
            record.update(self.guards())
        self.check_private_dir()
        self.journal.log(kind="preflight", **record)
        return record

    # ----- non-value CLI steps -----------------------------------------------------------------
    def local(
        self,
        label: str,
        *argv: str,
        want_json: bool = False,
        format_flag: bool = True,
        private_answer: bool = False,
    ):
        """A once-only CLI step that moves no value (profile, key or wallet bookkeeping).

        `private_answer` keeps the parsed answer in the private dir (0600) and only its sha256
        in the public journal: for a signed wallet message that must not be published before it
        is spent or expired."""
        previous = self.journal.result(label)
        if previous:
            if previous.get("exit_code") == 0:
                if previous.get("answer_private"):
                    return self.private_answer_read(label, previous["answer_sha256"])
                return previous.get("answer")
            raise Refusal(f"step {label!r} already failed with exit {previous.get('exit_code')}")
        if self.journal.attempted(label):
            raise Refusal(f"step {label!r} was attempted without a result; reconcile by hand")
        self.journal.attempt(label, {"kind": "local", "argv": self.cli.redact(argv)})
        rc, answer = self.cli.run(label, *argv, want_json=want_json, format_flag=format_flag)
        if private_answer and want_json and rc == 0:
            digest = self.private_answer_write(label, answer)
            self.journal.done(
                label, {"exit_code": rc, "answer_private": True, "answer_sha256": digest}
            )
        else:
            self.journal.done(
                label, {"exit_code": rc, "answer": answer if want_json and rc == 0 else None}
            )
        if rc != 0:
            raise Refusal(f"{label}: exit {rc}")
        return answer if want_json else None

    def private_answer_write(self, label: str, answer) -> str:
        directory = self.private / "answers"
        directory.mkdir(mode=0o700, exist_ok=True)
        data = json.dumps(answer, sort_keys=True).encode()
        fd = os.open(directory / f"{label}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return hashlib.sha256(data).hexdigest()

    def private_answer_read(self, label: str, digest: str):
        data = (self.private / "answers" / f"{label}.json").read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise Refusal(f"{label}: private answer does not match its journaled digest")
        return json.loads(data)

    def quorum_configs(self) -> list[str]:
        """Two single-endpoint copies of the CLI config, one per confirmation source, for the
        CLI's own three-view resolution of a broadcast controller action. Written once into
        the private dir (0600); only the RPC URL differs from the primary config."""
        paths = []
        base = json.loads(self.cli.config.read_text())
        for i, url in enumerate(self.rpc.confirms, start=1):
            path = self.private / f"tosctl-config-quorum-{i}.json"
            if not path.exists():
                derived = dict(base)
                derived["chain_rpc"] = {
                    **base.get("chain_rpc", {}),
                    "urls": [url.rsplit("/", 1)[0] + "/"],
                }
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    json.dump(derived, fh)
            paths.append(str(path.resolve()))
        if len(paths) != 2:
            raise Refusal("task-send resolution needs exactly two confirmation sources")
        return paths

    def retry_label(self, label: str) -> str:
        """The label to use for a step whose previous attempt the CLI refused client-side
        with nothing broadcast: the original record is kept and the retry is explicit."""
        previous = self.journal.result(label)
        if (
            previous
            and previous.get("verdict") == "cli-refused"
            and previous.get("payer_tx_after") == []
        ):
            return f"{label}-retry"
        return label

    # ----- setup --------------------------------------------------------------------------
    def setup(self) -> dict:
        self.preflight(value_action=False)
        if not self.cli.config.exists():
            rc, _ = self.cli.run(
                "setup-config", "config", "generate", "-o", str(self.cli.config), "--force"
            )
            if rc != 0:
                raise Refusal("config generate failed")
            cfg = json.loads(self.cli.config.read_text())
            cfg["chain_rpc"] = {
                "urls": [self.args.rpc.rsplit("/jsonRPC", 1)[0] + "/"],
                "api_key": None,
            }
            cfg["elections"] = None
            cfg["master_wallet"] = None
            cfg["indexer_enabled"] = False
            self.cli.config.write_text(json.dumps(cfg, indent=2) + "\n")
            os.chmod(self.cli.config, 0o600)
        if not self.cli.vault_env.exists():
            vault = self.private / "vault.json"
            master = secrets.token_hex(32)
            fd = os.open(self.cli.vault_env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(f"VAULT_URL=file://{vault}?master_key={master}\n")
            del master
        for key in KEYS:
            self.local(f"setup-key-{key}", "key", "add", "--name", key)
        for wallet in WALLETS:
            self.local(
                f"setup-wallet-{wallet}", "wallet", "create", "-n", wallet, "-v", "V3R2", "-w", "0"
            )
        rc, rows = self.cli.run(f"setup-wallet-ls-{self.cli.calls}", "wallet", "ls", want_json=True)
        if rc != 0 or not isinstance(rows, list):
            raise Refusal("wallet ls failed")
        addresses = {}
        for row in rows:
            if isinstance(row, dict) and row.get("name") in WALLETS and row.get("address"):
                addresses[row["name"]] = norm_addr(row["address"])
        missing = [w for w in WALLETS if w not in addresses]
        if missing:
            raise Refusal(f"wallets without address: {missing}")
        actors = {"wallets": addresses, "keys": list(KEYS), "created_utc": utc(now())}
        self.actors_path.write_text(json.dumps(actors, indent=2, sort_keys=True) + "\n")
        self.journal.log(kind="setup", wallets=addresses)
        return actors

    # ----- funding ------------------------------------------------------------------------
    def plan_funding(self, source: str) -> dict:
        actors = self.actors()
        source = norm_addr(source)
        plan = []
        total = 0
        for wallet, amount in FUNDING_PLAN_TOS.items():
            nanotos = tos_to_nanotos(amount)
            total += nanotos
            plan.append(
                {
                    "actor": wallet,
                    "to": actors["wallets"][wallet],
                    "amount_tos": amount,
                    "operation_id": f"sc-fund-{wallet.removeprefix('sc-')}-{self.args.date}",
                    "purpose": f"service contract public cases {wallet} {self.args.date}",
                }
            )
        if self.funded_total() + total > self.ceiling:
            raise Refusal("plan exceeds the stop ceiling")
        out = {
            "funding_source": source,
            "plan": plan,
            "total_nanotos": total,
            "stop_ceiling_nanotos": self.ceiling,
            "tool": "testnet-elections.py owner-fund --name node-4 --new --dry-run first",
        }
        self.plan_path.write_text(json.dumps(out, indent=2) + "\n")
        return out

    def funding_source(self) -> str:
        if not self.plan_path.exists():
            raise Refusal("funding-plan.json missing; run plan-funding first")
        return norm_addr(json.loads(self.plan_path.read_text())["funding_source"])

    def record_funding(self, actor: str, amount: str, operation_id: str) -> dict:
        address = self.actor_address(actor)
        nanotos = tos_to_nanotos(amount)
        if nanotos <= 0:
            raise Refusal("amount must be positive")
        if self.funded_total() + nanotos > self.ceiling:
            raise Refusal(
                f"recording {amount} TOS would exceed the stop ceiling "
                f"{nanotos_text(self.ceiling)} (funded {nanotos_text(self.funded_total())})"
            )
        if self.ledger_path.exists():
            for line in self.ledger_path.read_text().splitlines():
                if json.loads(line)["operation_id"] == operation_id:
                    raise Refusal(f"operation {operation_id} already recorded")
        balances = {
            url: int(self.rpc.info(address, url)["balance"]) for url in self.rpc.all_sources
        }
        if min(balances.values()) < nanotos:
            raise Refusal(f"credit not visible on every source yet: {balances}")
        row = {
            "utc": utc(now()),
            "actor": actor,
            "to": address,
            "amount_nanotos": nanotos,
            "operation_id": operation_id,
            "balances_nanotos": balances,
        }
        with self.ledger_path.open("a") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        self.journal.log(kind="funding-recorded", **row)
        return row

    def activate(self) -> dict:
        self.preflight()
        actors = self.actors()
        out = {}
        for wallet, address in actors["wallets"].items():
            state = self.rpc.state(address)
            if state == "active":
                out[wallet] = "already-active"
                continue
            if self.rpc.balance(address) < tos_to_nanotos("0.05"):
                out[wallet] = "unfunded"
                continue
            label = f"activate-{wallet}"
            if self.journal.attempted(label):
                raise Refusal(f"{label} was attempted before and the wallet is {state}")
            self.guards()
            self.journal.attempt(label, {"kind": "wallet-activate", "address": address})
            rc, _ = self.cli.run(label, "wallet", "activate", "-n", wallet)
            ok = rc == 0 and self.wait(lambda: self.rpc.state(address) == "active")
            self.journal.done(label, {"exit_code": rc, "active": ok})
            if not ok:
                raise Refusal(f"{label}: wallet did not become active")
            out[wallet] = "activated"
        return out

    # ----- generic value step -------------------------------------------------------------
    def wait(self, predicate, timeout: float | None = None) -> bool:
        deadline = time.monotonic() + (SETTLE_TIMEOUT_S if timeout is None else timeout)
        while True:
            try:
                if predicate():
                    return True
            except Refusal:
                pass
            if time.monotonic() >= deadline:
                return False
            time.sleep(POLL_S)

    def external_arrivals(self, observe: str, since_lt: int, url: str | None = None) -> list[dict]:
        """Transactions of `observe` after `since_lt` that were triggered by an external message
        (a command signed for the contract itself, not sent by another account)."""
        return [
            r
            for r in self.rpc.transactions_after(observe, since_lt, url)
            if (r.get("in_msg") or {}).get("kind") == "external"
        ]

    def messages_to(
        self, payer: str, since_lt: int, observe: str, url: str | None = None
    ) -> list[tuple[dict, str | None]]:
        """Every outbound message of `payer` to `observe` after `since_lt`, one entry per message
        (two messages inside one transaction are two entries), as (transaction, message hash)."""
        return [
            (r, m.get("hash"))
            for r in self.rpc.transactions_after(payer, since_lt, url)
            for m in r.get("out_msgs", [])
            if same_addr(m.get("destination"), observe)
        ]

    def sends_to(self, payer: str, since_lt: int, observe: str | None) -> list[dict]:
        """Payer transactions after `since_lt` that carry a message to `observe` (any, if None)."""
        rows = self.rpc.transactions_after(payer, since_lt)
        if observe is None:
            return [r for r in rows if r.get("out_msgs")]
        return [
            r
            for r in rows
            if any(same_addr(m.get("destination"), observe) for m in r.get("out_msgs", []))
        ]

    def step(
        self,
        label: str,
        argv: list[str],
        payer: str,
        observe: str | None,
        expect_exit: int = 0,
        want_json: bool = False,
        show=None,
        external: bool = False,
    ) -> dict:
        """One CLI action that sends exactly one message from `payer` (an actor wallet).

        `external=True` for a command the CLI signs for the contract itself: no wallet sends
        anything, the proof is the single new transaction of `observe` with an external
        in-message after the baseline (`payer` is then the contract, for its balance).

        `observe` is the contract address whose next transaction must be the message from
        `payer` (None for a deploy whose address is only known from the CLI answer).
        `expect_exit` 0 = must succeed; another code = must abort with exactly that compute exit
        code while the protected state read by `show` stays unchanged.
        """
        previous = self.journal.result(label)
        if previous:
            if previous.get("verdict") in REPLAYABLE:
                previous.setdefault("label", label)
                return previous
            raise Refusal(
                f"step {label!r} already ended with verdict {previous.get('verdict')!r}; "
                "it is never re-sent"
            )
        if self.journal.attempted(label):
            raise Refusal(f"step {label!r} was attempted without a result; reconcile read-only")
        self.guards()
        before = {
            "head": self.rpc.head(),
            "payer_lt": self.rpc.last_lt(payer),
            "payer_balance": self.rpc.balance(payer),
            "observe_lt": self.rpc.last_lt(observe) if observe else None,
            "observe_balance": self.rpc.balance(observe) if observe else None,
            "state": show() if show else None,
        }
        base = {
            "label": label,
            "argv": self.cli.redact(tuple(argv)),
            "payer": payer,
            "observe": observe,
            "external": external,
            "expect_exit": expect_exit,
            "before": before,
        }
        if os.environ.get("SC_DRILL_CRASH") == label:
            self.journal.attempt(label, {"kind": "drill", **base})
            raise SystemExit(f"drill: process lost after the attempt marker of {label}")
        after_send_drill = os.environ.get("SC_DRILL_CRASH_AFTER_SEND") == label
        self.journal.attempt(
            label, {"kind": "drill-after-send" if after_send_drill else "value", **base}
        )
        rc, answer = self.cli.run(label, *argv, want_json=want_json)
        if after_send_drill:
            # The message has left the wallet and the reply is lost before any record is written.
            self.journal.log(kind="drill-crash-after-send", label=label, exit_code=rc)
            raise SystemExit(f"drill: process lost after the CLI returned for {label}")
        record: dict = {"exit_code": rc, **base}
        if want_json and rc == 0 and isinstance(answer, dict):
            record["answer"] = {
                k: v for k, v in answer.items() if k in ("address", "request_id", "status")
            }
            answered = answer.get("address")
            observe = observe or (norm_addr(answered) if answered else None)
            record["observe"] = observe
        if rc != 0:
            # The CLI refused, timed out or crashed. Watch the payer for a bounded window: a
            # message that was broadcast anyway makes the outcome unknown. Never retry.
            sent: list[dict] = []

            observation_failed = False

            def broadcast() -> bool:
                nonlocal observation_failed
                try:
                    if external:
                        sent[:] = self.external_arrivals(observe, before["observe_lt"] or 0)
                    else:
                        sent[:] = self.sends_to(payer, before["payer_lt"], observe)
                except Refusal:
                    observation_failed = True
                    raise
                return bool(sent)

            self.wait(broadcast, REFUSAL_OBSERVE_S)
            record["payer_tx_after"] = [r["transaction_id"] for r in sent]
            record["broadcast_observation_failed"] = observation_failed
            if rc is not None and len(sent) == 1 and observe:
                # The CLI broadcast the message and then reported the contract's own failure
                # (or its own) with a non-zero exit. Exactly one message is on chain, so the
                # contract transaction decides exactly as for a clean exit.
                record["cli_reported_failure"] = True
            elif sent or rc is None or observation_failed:
                record["verdict"] = "unknown"
            elif expect_exit != 0:
                # A negative control the CLI already refuses client-side: nothing was sent, the
                # protected state is unchanged, but no on-chain refusal row exists for it.
                record["after"] = {"state": show() if show else None}
                record["verdict"] = (
                    "cli-refused-before-broadcast"
                    if record["after"]["state"] == before["state"]
                    else "refusal-control-failed"
                )
            else:
                record["verdict"] = "cli-refused"
            if "verdict" in record:
                self.journal.done(label, record)
                if record["verdict"] == "cli-refused-before-broadcast":
                    return record
                raise Refusal(f"{label}: CLI exit {rc}; {record['verdict']}; reconciled read-only")
        found: dict = {}

        def settled() -> bool:
            if external:
                arrivals = self.external_arrivals(observe, before["observe_lt"] or 0)
                if len(arrivals) > 1:
                    found["error"] = f"{len(arrivals)} external messages reached {observe}"
                    return True
                if not arrivals:
                    return False
                found["payer_tx"] = None
                found["tx"] = arrivals[0]
                return True
            sends = self.sends_to(payer, before["payer_lt"], observe)
            if len(sends) > 1:
                found["error"] = f"payer sent {len(sends)} messages to {observe}"
                return True
            if not sends or not observe:
                return False
            out_hash = [
                m["hash"] for m in sends[0]["out_msgs"] if same_addr(m.get("destination"), observe)
            ][0]
            rows = self.rpc.transactions_after(observe, before["observe_lt"] or 0)
            hit = [r for r in rows if (r.get("in_msg") or {}).get("hash") == out_hash]
            if not hit:
                return False
            found["payer_tx"] = sends[0]
            found["tx"] = hit[0]
            return True

        observed = self.wait(settled)
        if "error" in found:
            record["verdict"] = "multiple-sends-observed"
            record["error"] = found["error"]
            self.journal.done(label, record)
            raise Refusal(f"{label}: {found['error']}; stop and reconcile by hand")
        if not observed:
            record["verdict"] = "unknown-not-observed"
            self.journal.done(label, record)
            raise Refusal(f"{label}: the exact message was not observed in time; no retry")
        tx = found["tx"]
        compute = tx.get("compute") or {}
        action = tx.get("action")
        confirmations = {}
        for url in self.rpc.confirms:
            confirmations[url] = self.wait(
                lambda u=url: any(
                    r["transaction_id"]["hash"] == tx["transaction_id"]["hash"]
                    for r in self.rpc.transactions_after(observe, before["observe_lt"] or 0, u)
                )
            )
        after_state = show() if show else None
        record.update(
            {
                "payer_tx": (found["payer_tx"] or {}).get("transaction_id"),
                "tx": tx["transaction_id"],
                "block_id": tx.get("block_id"),
                "compute": compute,
                "aborted": tx.get("aborted"),
                "action": action,
                "in_msg_hash": (tx.get("in_msg") or {}).get("hash"),
                "out_msgs": [
                    {k: m.get(k) for k in ("destination", "value", "bounced", "hash")}
                    for m in tx.get("out_msgs", [])
                ],
                "confirmed_on": confirmations,
                "after": {
                    "head": self.rpc.head(),
                    "payer_balance": self.rpc.balance(payer),
                    "observe_balance": self.rpc.balance(observe),
                    "state": after_state,
                },
            }
        )
        if not all(confirmations.values()):
            record["verdict"] = "not-confirmed-on-all-sources"
            self.journal.done(label, record)
            raise Refusal(f"{label}: transaction not seen on every confirmation source")
        if expect_exit == 0:
            how = self.positive_outcome(
                tx, before["observe_balance"] or 0, record["after"]["observe_balance"]
            )
            ok = bool(how)
            record["settled_as"] = how or None
            record["verdict"] = "settled" if ok else "unexpected-abort"
        else:
            aborted = tx.get("aborted") is True and compute.get("success") is False
            code_ok = compute.get("exit_code") == expect_exit
            state_ok = show is None or before["state"] == after_state
            ok = aborted and code_ok and state_ok
            record["verdict"] = "refused-as-intended" if ok else "refusal-control-failed"
        self.journal.done(label, record)
        if not ok:
            raise Refusal(f"{label}: {record['verdict']} ({compute}, aborted={tx.get('aborted')})")
        return record

    def show(self, *argv: str):
        def read():
            rc, data = self.cli.run(f"show-{secrets.token_hex(4)}", *argv, want_json=True)
            if rc != 0 or not isinstance(data, dict):
                raise Refusal(f"show failed: {argv}")
            return data

        return read

    @staticmethod
    def transferred(record: dict, to: str, min_tos: str) -> bool:
        """Whether the step's contract transaction carried at least `min_tos` to `to` without a
        bounce; read from the record, so a replayed step gives the same answer."""
        floor = tos_to_nanotos(min_tos)
        return any(
            same_addr(m.get("destination"), to)
            and not m.get("bounced")
            and int(m.get("value") or 0) >= floor
            for m in record.get("out_msgs") or []
        )

    @staticmethod
    def argv_value(record: dict, flag: str) -> str:
        """The value that followed `flag` in the step's recorded argument vector."""
        argv = list(record.get("argv") or [])
        if flag not in argv or argv.index(flag) + 1 >= len(argv):
            raise Refusal(f"{record.get('label')}: {flag} missing from the recorded argv")
        return str(argv[argv.index(flag) + 1])

    @staticmethod
    def positive_outcome(tx: dict, before_balance: int | None, after_balance: int | None) -> str:
        """How a step that had to succeed settled: `executed`, `credited-without-compute`
        (a plain value transfer to an account without code: compute phase skipped, nothing
        bounced, the balance grew) or `` when neither holds."""
        compute = tx.get("compute") or {}
        action = tx.get("action")
        action_ok = action is None or action.get("success") is not False
        if (
            compute.get("success") is True
            and compute.get("exit_code") == 0
            and tx.get("aborted") is False
            and action_ok
        ):
            return "executed"
        if (
            compute.get("skipped") is True
            and not tx.get("out_msgs")
            and before_balance is not None
            and after_balance is not None
            and after_balance > before_balance
        ):
            return "credited-without-compute"
        return ""

    @staticmethod
    def verdict(final_ok: bool, controls: list[dict]) -> dict:
        """A control passes with an on-chain refusal, or with a client-side refusal only where
        the case declared that the protected property is enforced by the CLI (no contract row
        can exist); such controls are listed separately so the report stays explicit."""

        def passed(c: dict) -> bool:
            if c.get("verdict") == "refused-as-intended":
                return True
            return c.get("verdict") == "cli-refused-before-broadcast" and bool(
                c.get("client_side_refusal_accepted")
            )

        without = [c["label"] for c in controls if not passed(c)]
        client_side = [
            c["label"] for c in controls if passed(c) and c.get("verdict") != "refused-as-intended"
        ]
        return {
            "final_state_ok": final_ok,
            "controls": {c["label"]: c.get("verdict") for c in controls},
            "controls_refused_client_side": client_side,
            "controls_without_on_chain_receipt": without,
            "pass": bool(final_ok) and not without,
        }

    # ----- cases --------------------------------------------------------------------------
    CASES = (
        "sc02",
        "sc03",
        "sc04",
        "sc05",
        "sc06",
        "sc07",
        "sc08",
        "sc03x",
        "sc05x",
        "sc08x",
        "sc03e",
        "scnr",
    )

    def case_fn(self, name: str):
        fn = getattr(self, f"case_{name}", None)
        if name not in self.CASES or fn is None:
            raise Refusal(f"unknown case {name}; known: {self.CASES}")
        return fn

    def plan(self, name: str) -> list[dict]:
        """The CLI argument vectors a case will issue, produced by a dry pass without any send."""
        planner = PlanRunner(self.args, self.actors()["wallets"])
        planner.case_fn(name)(planner.wallets)
        return planner.recorded

    def check_flags(self, planned: list[dict], flags: dict) -> None:
        """Every `--flag` and `--operation` value of a plan exists in the pinned CLI's help."""
        if flags.get("cli_sha256") != self.args.cli_sha256:
            raise Refusal("flag fixture was recorded from a different CLI binary")
        for item in planned:
            argv = item["argv"]
            path = " ".join(argv[:3]) if argv[0] == "agent" else " ".join(argv[:2])
            known = flags["commands"].get(path)
            if not known:
                raise Refusal(f"{item['label']}: command {path!r} is not in the flag fixture")
            for i, token in enumerate(argv):
                if token.startswith("--") and token not in known["flags"]:
                    raise Refusal(f"{item['label']}: {path} does not accept {token}")
                if token == "--operation":
                    values = {
                        v.strip() for group in known["possible_values"] for v in group.split(",")
                    }
                    if values and argv[i + 1] not in values:
                        raise Refusal(f"{item['label']}: {path} has no operation {argv[i + 1]}")

    def case(self, name: str) -> dict:
        self.preflight()
        planned = self.plan(name)
        if not self.args.flag_fixture:
            raise Refusal("a case runs only against the pinned CLI flag fixture (--flag-fixture)")
        self.check_flags(planned, pinned_flags(Path(self.args.flag_fixture)))
        self.journal.log(kind="case-start", case=name, planned_steps=[p["label"] for p in planned])
        result = self.case_fn(name)(self.actors()["wallets"])
        (self.evidence / f"{name}-RESULT.json").write_text(
            json.dumps({"case": name, "utc": utc(now()), **result}, indent=2, sort_keys=True) + "\n"
        )
        return result

    def wait_active(self, address: str, what: str) -> None:
        if not self.wait(lambda: self.rpc.state(address) == "active"):
            raise Refusal(f"{what} at {address} is not active")

    def case_sc07(self, w: dict) -> dict:
        owner, outsider = w["sc-owner"], w["sc-outsider"]
        deploy = self.step(
            "sc07-deploy",
            [
                "agent",
                "attestation",
                "deploy",
                "--name",
                "sc07",
                "--owner",
                owner,
                "--signer-vault-key",
                "sc-attestor-key",
                "--subject-hash",
                HASH["subject"],
                "--from",
                "sc-owner",
                "--amount",
                "0.1",
                "-w",
                "0",
                "--yes",
            ],
            payer=owner,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "attestation", "show", "--name", "sc07")
        self.wait_active(address, "sc07 attestation")
        send = ["agent", "attestation", "send", "--name", "sc07", "--yes", "--amount", "0.1"]
        controls = []
        self.step(
            "sc07-attest-valid",
            send
            + [
                "--operation",
                "attest",
                "--from",
                "sc-outsider",
                "--attested-hash",
                HASH["attested_1"],
                "--signer-vault-key",
                "sc-attestor-key",
            ],
            payer=outsider,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc07-attest-wrong-key",
                send
                + [
                    "--operation",
                    "attest",
                    "--from",
                    "sc-outsider",
                    "--attested-hash",
                    HASH["attested_2"],
                    "--signer-vault-key",
                    "sc-wrong-key",
                ],
                payer=outsider,
                observe=address,
                expect_exit=ATTEST_BAD_SIGNATURE,
                show=show,
            )
        )
        controls.append(
            self.step(
                "sc07-rotate-outsider",
                send
                + [
                    "--operation",
                    "rotate-key",
                    "--from",
                    "sc-outsider",
                    "--new-signer-vault-key",
                    "sc-rotated-attestor-key",
                ],
                payer=outsider,
                observe=address,
                expect_exit=ATTEST_NOT_OWNER,
                show=show,
            )
        )
        self.step(
            "sc07-rotate-owner",
            send
            + [
                "--operation",
                "rotate-key",
                "--from",
                "sc-owner",
                "--new-signer-vault-key",
                "sc-rotated-attestor-key",
            ],
            payer=owner,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc07-revoke-outsider",
                send + ["--operation", "revoke", "--from", "sc-outsider"],
                payer=outsider,
                observe=address,
                expect_exit=ATTEST_NOT_OWNER,
                show=show,
            )
        )
        self.step(
            "sc07-revoke-owner",
            send + ["--operation", "revoke", "--from", "sc-owner"],
            payer=owner,
            observe=address,
            show=show,
        )
        final = show()
        final_ok = final.get("revoked") is True and final.get("has_attestation") is False
        return {"address": address, "final_state": final, **self.verdict(final_ok, controls)}

    def case_sc04(self, w: dict) -> dict:
        owner, client, outsider = w["sc-owner"], w["sc-client"], w["sc-outsider"]
        deploy = self.step(
            "sc04-deploy",
            [
                "agent",
                "service",
                "deploy",
                "--name",
                "sc04",
                "--owner",
                owner,
                "--price-per-call",
                "0.05",
                "--storage-fee",
                "0.2",
                "--cleanup-bounty",
                "0.1",
                "--response-sla",
                "3600",
                "--refund-claim-window",
                "3600",
                "--rate-limit-per-day",
                "0",
                "--metadata-hash",
                HASH["metadata"],
                "--proof-scheme-hash",
                HASH["proof_scheme"],
                "--authorized-caller",
                client,
                "--signer-vault-key",
                "sc-attestor-key",
                "--from",
                "sc-owner",
                "--amount",
                SERVICE_MIN_DEPLOY_TOS,
                "-w",
                "0",
                "--yes",
            ],
            payer=owner,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "service", "show", "--name", "sc04")
        self.wait_active(address, "sc04 service")
        # Message values are left to the CLI, which quotes them from the on-chain policy
        # (price + storage fee + admission allowance for a call, payout allowance otherwise).
        send = ["agent", "service", "send", "--name", "sc04", "--yes"]
        controls = []
        controls.append(
            self.step(
                "sc04-call-outsider",
                send
                + [
                    "--operation",
                    "call",
                    "--from",
                    "sc-outsider",
                    "--request-hash",
                    HASH["request_2"],
                ],
                payer=outsider,
                observe=address,
                expect_exit=SERVICE_NOT_AUTHORIZED,
                show=show,
            )
        )
        self.step(
            "sc04-call-client",
            send
            + ["--operation", "call", "--from", "sc-client", "--request-hash", HASH["request_1"]],
            payer=client,
            observe=address,
            show=show,
        )
        state = show()
        if "next_request_id" not in state:
            raise Refusal("service view has no next_request_id")
        request_id = str(int(state["next_request_id"]) - 1)
        controls.append(
            self.step(
                "sc04-respond-outsider",
                send
                + [
                    "--operation",
                    "respond",
                    "--from",
                    "sc-outsider",
                    "--request-id",
                    request_id,
                    "--response-hash",
                    HASH["response"],
                    "--signer-vault-key",
                    "sc-attestor-key",
                ],
                payer=outsider,
                observe=address,
                expect_exit=SERVICE_NOT_OWNER,
                show=show,
            )
        )
        self.step(
            "sc04-respond-owner",
            send
            + [
                "--operation",
                "respond",
                "--from",
                "sc-owner",
                "--request-id",
                request_id,
                "--response-hash",
                HASH["response"],
                "--signer-vault-key",
                "sc-attestor-key",
            ],
            payer=owner,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc04-withdraw-outsider",
                send
                + [
                    "--operation",
                    "withdraw-revenue",
                    "--from",
                    "sc-outsider",
                    "--withdraw-amount",
                    "0.01",
                ],
                payer=outsider,
                observe=address,
                expect_exit=SERVICE_NOT_OWNER,
                show=show,
            )
        )
        withdrawal = self.journal.result("sc04-withdraw-owner")
        if withdrawal is not None:
            if withdrawal.get("verdict") != "settled":
                raise Refusal("original service withdrawal is unresolved; reconcile read-only")
            if not same_addr(withdrawal.get("observe"), address):
                raise Refusal("recorded service withdrawal names a different service contract")
            before_state = (withdrawal.get("before") or {}).get("state") or {}
            # A record without a pre-withdrawal baseline is refused by state_nanotos itself.
            withdrawable = state_nanotos(before_state.get("withdrawable_revenue"))
            amount = self.argv_value(withdrawal, "--withdraw-amount")
            if not 0 < tos_to_nanotos(amount) <= min(withdrawable, SERVICE_WITHDRAW_CAP):
                raise Refusal("recorded service withdrawal exceeds its original baseline")
        else:
            withdrawable = state_nanotos(show().get("withdrawable_revenue"))
            if withdrawable <= 0:
                raise Refusal("no withdrawable revenue after the answered call")
            amount = nanotos_text(min(withdrawable, SERVICE_WITHDRAW_CAP))
        self.step(
            "sc04-withdraw-owner",
            send
            + [
                "--operation",
                "withdraw-revenue",
                "--from",
                "sc-owner",
                "--withdraw-amount",
                amount,
            ],
            payer=owner,
            observe=address,
            show=show,
        )
        final = show()
        final_ok = int(final.get("pending_count", -1)) == 0 and state_nanotos(
            final.get("withdrawable_revenue")
        ) == withdrawable - tos_to_nanotos(amount)
        return {
            "address": address,
            "request_id": request_id,
            "withdrawn_tos": amount,
            "final_state": final,
            **self.verdict(final_ok, controls),
        }

    def task_create_argv(self, name: str, w: dict) -> list[str]:
        return [
            "agent",
            "task",
            "create",
            "--name",
            name,
            "--creator",
            w["sc-owner"],
            "--agent",
            w["sc-client"],
            "--verifier",
            w["sc-verifier"],
            "--budget",
            "1",
            "--deadline",
            str(now() + TASK_HORIZON_S),
            "--review-period",
            str(TASK_MIN_REVIEW_PERIOD_S),
            "--policy-hash",
            HASH["policy"],
            "--from",
            "sc-owner",
            "--amount",
            "1.3",
            "-w",
            "0",
            "--yes",
        ]

    def case_sc05(self, w: dict) -> dict:
        creator, agent = w["sc-owner"], w["sc-client"]
        deploy = self.step(
            "sc05-create",
            self.task_create_argv("sc05", w),
            payer=creator,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "task", "show", "--name", "sc05")
        self.wait_active(address, "sc05 task")
        # Task message values are quoted by the CLI from the escrow's fee schedule.
        send = ["agent", "task", "send", "--name", "sc05", "--yes"]
        controls = []
        controls.append(
            self.step(
                "sc05-accept-creator",
                send + ["--operation", "accept", "--from", "sc-owner"],
                payer=creator,
                observe=address,
                expect_exit=TASK_ACCEPT_NOT_AGENT,
                show=show,
            )
        )
        self.step(
            "sc05-accept-agent",
            send + ["--operation", "accept", "--from", "sc-client"],
            payer=agent,
            observe=address,
            show=show,
        )
        self.step(
            "sc05-result-agent",
            send
            + [
                "--operation",
                "result",
                "--from",
                "sc-client",
                "--result-hash",
                HASH["result"],
                "--evidence-hash",
                HASH["evidence"],
            ],
            payer=agent,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc05-settle-agent",
                send + ["--operation", "settle", "--from", "sc-client", "--payout", "0.6"],
                payer=agent,
                observe=address,
                expect_exit=TASK_SETTLE_AUTHORITY,
                show=show,
            )
        )
        settlement = self.step(
            "sc05-settle-creator",
            send + ["--operation", "settle", "--from", "sc-owner", "--payout", "0.6"],
            payer=creator,
            observe=address,
            show=show,
        )
        # The payout is read from the settle transaction's own outgoing message, so a resumed
        # run judges the recorded settlement instead of waiting for a second payment.
        paid = self.transferred(settlement, agent, "0.59")
        final = show()
        final_ok = final.get("status") == "settled" and paid
        return {
            "address": address,
            "final_state": final,
            "agent_paid": paid,
            **self.verdict(final_ok, controls),
        }

    def case_sc06(self, w: dict) -> dict:
        claimant, respondent, reviewer, outsider = (
            w["sc-client"],
            w["sc-respondent"],
            w["sc-verifier"],
            w["sc-outsider"],
        )
        deploy = self.step(
            "sc06-deploy",
            [
                "agent",
                "dispute",
                "deploy",
                "--name",
                "sc06",
                "--claimant",
                claimant,
                "--respondent",
                respondent,
                "--reviewer",
                reviewer,
                "--deadline",
                str(now() + TASK_HORIZON_S),
                "--subject-hash",
                HASH["subject"],
                "--claimant-evidence-hash",
                HASH["claimant_evidence"],
                "--from",
                "sc-client",
                "--amount",
                "0.1",
                "-w",
                "0",
                "--yes",
            ],
            payer=claimant,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "dispute", "show", "--name", "sc06")
        self.wait_active(address, "sc06 dispute")
        send = ["agent", "dispute", "send", "--name", "sc06", "--yes", "--amount", "0.1"]
        controls = []
        controls.append(
            self.step(
                "sc06-evidence-outsider",
                send
                + [
                    "--operation",
                    "submit-respondent-evidence",
                    "--from",
                    "sc-outsider",
                    "--respondent-evidence-hash",
                    HASH["respondent_evidence"],
                ],
                payer=outsider,
                observe=address,
                expect_exit=DISPUTE_NOT_RESPONDENT,
                show=show,
            )
        )
        self.step(
            "sc06-evidence-respondent",
            send
            + [
                "--operation",
                "submit-respondent-evidence",
                "--from",
                "sc-respondent",
                "--respondent-evidence-hash",
                HASH["respondent_evidence"],
            ],
            payer=respondent,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc06-rule-outsider",
                send
                + [
                    "--operation",
                    "rule",
                    "--from",
                    "sc-outsider",
                    "--ruling",
                    "claimant",
                    "--ruling-hash",
                    HASH["ruling"],
                ],
                payer=outsider,
                observe=address,
                expect_exit=DISPUTE_NOT_REVIEWER,
                show=show,
            )
        )
        self.step(
            "sc06-rule-reviewer",
            send
            + [
                "--operation",
                "rule",
                "--from",
                "sc-verifier",
                "--ruling",
                "claimant",
                "--ruling-hash",
                HASH["ruling"],
            ],
            payer=reviewer,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc06-rule-again",
                send
                + [
                    "--operation",
                    "rule",
                    "--from",
                    "sc-verifier",
                    "--ruling",
                    "respondent",
                    "--ruling-hash",
                    HASH["ruling"],
                ],
                payer=reviewer,
                observe=address,
                expect_exit=DISPUTE_ALREADY_RESOLVED,
                show=show,
            )
        )
        final = show()
        final_ok = final.get("status") == "resolved" and final.get("ruling") == "claimant"
        return {"address": address, "final_state": final, **self.verdict(final_ok, controls)}

    def case_sc02(self, w: dict) -> dict:
        owner, verifier, outsider = w["sc-owner"], w["sc-verifier"], w["sc-outsider"]
        deploy = self.step(
            "sc02-deploy",
            [
                "agent",
                "registry",
                "deploy",
                "--name",
                "sc02",
                "--owner",
                owner,
                "--verifier",
                verifier,
                "--task-categories-hash",
                HASH["task_categories"],
                "--pricing-hash",
                HASH["pricing"],
                "--metadata-hash",
                HASH["metadata"],
                "--verification-method-hash",
                HASH["verification_method"],
                "--bond",
                "0.5",
                "--from",
                "sc-owner",
                "--amount",
                "0.7",
                "-w",
                "0",
                "--yes",
            ],
            payer=owner,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "registry", "show", "--name", "sc02")
        self.wait_active(address, "sc02 registry")
        send = ["agent", "registry", "send", "--name", "sc02", "--yes", "--amount", "0.1"]
        meta = [
            "--task-categories-hash",
            HASH["task_categories"],
            "--pricing-hash",
            HASH["pricing"],
            "--metadata-hash",
            HASH["new_metadata"],
            "--verification-method-hash",
            HASH["verification_method"],
        ]
        controls = []
        controls.append(
            self.step(
                "sc02-update-outsider",
                send + ["--operation", "update-metadata", "--from", "sc-outsider"] + meta,
                payer=outsider,
                observe=address,
                expect_exit=REGISTRY_NOT_OWNER,
                show=show,
            )
        )
        self.step(
            "sc02-update-owner",
            send + ["--operation", "update-metadata", "--from", "sc-owner"] + meta,
            payer=owner,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc02-reputation-outsider",
                send
                + ["--operation", "update-reputation", "--from", "sc-outsider", "--delta", "10"],
                payer=outsider,
                observe=address,
                expect_exit=REGISTRY_NOT_VERIFIER,
                show=show,
            )
        )
        self.step(
            "sc02-reputation-verifier",
            send + ["--operation", "update-reputation", "--from", "sc-verifier", "--delta", "10"],
            payer=verifier,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc02-overdraw-bond",
                send
                + [
                    "--operation",
                    "withdraw-bond",
                    "--from",
                    "sc-owner",
                    "--withdraw-amount",
                    "100",
                ],
                payer=owner,
                observe=address,
                expect_exit=REGISTRY_INSUFFICIENT_BOND,
                show=show,
            )
        )
        self.step(
            "sc02-withdraw-bond",
            send
            + ["--operation", "withdraw-bond", "--from", "sc-owner", "--withdraw-amount", "0.3"],
            payer=owner,
            observe=address,
            show=show,
        )
        self.step(
            "sc02-deactivate",
            send + ["--operation", "deactivate", "--from", "sc-owner"],
            payer=owner,
            observe=address,
            show=show,
        )
        final = show()
        final_ok = final.get("active") is False and int(final.get("reputation_score", -1)) == 10
        return {"address": address, "final_state": final, **self.verdict(final_ok, controls)}

    def case_sc03(self, w: dict) -> dict:
        owner, target = w["sc-owner"], w["sc-verifier"]
        self.local(
            "sc03-agent-wallet-create",
            "agent",
            "wallet",
            "create",
            "-n",
            "sc03-agent",
            "-v",
            "V5R1",
            "-w",
            "0",
            "--max-per-tx",
            "0.5",
            "--daily-limit",
            "2",
        )
        deploy = self.step(
            "sc03-account-deploy",
            [
                "agent",
                "account",
                "deploy",
                "--wallet",
                "sc03-agent",
                "--from",
                "sc-owner",
                "-w",
                "0",
                "--amount",
                "0.5",
                "--yes",
            ],
            payer=owner,
            observe=None,
            want_json=True,
        )
        account = deploy["observe"]
        profile = self.local(
            "sc03-agent-wallet-show", "agent", "wallet", "show", "-n", "sc03-agent", want_json=True
        )
        answered = (profile or {}).get("address") or ((profile or {}).get("result") or {}).get(
            "address"
        )
        agent_wallet = norm_addr(answered)
        self.step(
            "sc03-agent-wallet-fund",
            [
                "agent",
                "wallet",
                "fund",
                "--name",
                "sc03-agent",
                "--from",
                "sc-owner",
                "--amount",
                "0.5",
                "--yes",
            ],
            payer=owner,
            observe=agent_wallet,
        )
        if self.rpc.state(agent_wallet) != "active":
            self.local(
                "sc03-agent-wallet-activate", "agent", "wallet", "activate", "-n", "sc03-agent"
            )
            self.wait_active(agent_wallet, "sc03 agent wallet")
        first = self.step(
            "sc03-task-send-1",
            [
                "agent",
                "account",
                "task-send",
                "--wallet",
                "sc03-agent",
                "--target",
                target,
                "--value",
                "0.1",
                "--valid-until",
                str(now() + 300),
                "--action-id",
                secrets.token_hex(32),
                "--yes",
            ],
            payer=account,
            observe=account,
            external=True,
        )
        # Replay-safe: the delivery and the action id to replay come from the step's own record.
        delivered = self.transferred(first, target, "0.09")
        action_1 = self.argv_value(first, "--action-id")
        # The CLI's custody journal keeps a broadcast task-send unresolved until its exact
        # transaction is bound from three RPC views; a later controller action is refused
        # client-side until then. Resolution moves no value.
        quorum = self.quorum_configs()
        self.local(
            "sc03-task-send-1-resolve",
            "agent",
            "account",
            "task-send-resolve",
            "--wallet",
            "sc03-agent",
            "--action-id",
            action_1,
            "--quorum-config",
            *quorum,
        )
        # Replaying the same action id must not execute a second transfer. The CLI refuses it
        # client-side from its custody journal (the account contract stores no action id), so
        # no on-chain row is expected; a second successful transfer is the failure.
        duplicate = self.duplicate_control(
            "sc03-task-send-1-duplicate",
            [
                "agent",
                "account",
                "task-send",
                "--wallet",
                "sc03-agent",
                "--target",
                target,
                "--value",
                "0.1",
                "--valid-until",
                str(now() + 300),
                "--action-id",
                action_1,
                "--yes",
            ],
            account,
            account,
            target,
            external=True,
        )
        self.local(
            "sc03-policy-local",
            "agent",
            "wallet",
            "update-policy",
            "-n",
            "sc03-agent",
            "--max-per-tx",
            "0.2",
            "--daily-limit",
            "1",
        )
        self.step(
            "sc03-update-policy",
            [
                "agent",
                "account",
                "update-policy",
                "--wallet",
                "sc03-agent",
                "--amount",
                "0.05",
                "--yes",
            ],
            payer=agent_wallet,
            observe=account,
        )
        self.local("sc03-rotate-local", "agent", "wallet", "rotate-controller", "-n", "sc03-agent")
        self.step(
            "sc03-rotate-controller",
            [
                "agent",
                "account",
                "rotate-controller",
                "--wallet",
                "sc03-agent",
                "--amount",
                "0.05",
                "--yes",
            ],
            payer=agent_wallet,
            observe=account,
        )
        second = self.step(
            self.retry_label("sc03-task-send-2"),
            [
                "agent",
                "account",
                "task-send",
                "--wallet",
                "sc03-agent",
                "--target",
                target,
                "--value",
                "0.1",
                "--valid-until",
                str(now() + 300),
                "--action-id",
                secrets.token_hex(32),
                "--yes",
            ],
            payer=account,
            observe=account,
            external=True,
        )
        delivered_2 = self.transferred(second, target, "0.09")
        self.local(
            "sc03-task-send-2-resolve",
            "agent",
            "account",
            "task-send-resolve",
            "--wallet",
            "sc03-agent",
            "--action-id",
            self.argv_value(second, "--action-id"),
            "--quorum-config",
            *quorum,
        )
        status = self.local(
            "sc03-status", "agent", "account", "status", "--wallet", "sc03-agent", want_json=True
        )
        final_ok = bool(delivered and delivered_2 and duplicate["verdict"] != "DUPLICATE-EXECUTED")
        return {
            "account": account,
            "agent_wallet": agent_wallet,
            "status": status,
            "first_transfer_delivered": delivered,
            "transfer_after_rotation_delivered": delivered_2,
            **self.verdict(final_ok, [duplicate]),
        }

    def duplicate_control(
        self,
        label: str,
        argv: list[str],
        payer: str,
        account: str,
        target: str,
        external: bool = False,
    ) -> dict:
        """Replay of an already executed action id: it must not pay the target a second time.

        The proof is the exact on-chain row, as in `step()`: the agent wallet's message to the
        account and the account transaction it produced. An aborted account transaction is the
        intended refusal and its exit code is recorded; a CLI refusal with no send is recorded
        as client-side (no on-chain row); a second transfer is the failure. A missing row is an
        unknown that stops the case, never a pass.
        """
        duplicate = self.journal.result(label)
        if duplicate is not None:
            if duplicate.get("verdict") not in REPLAYABLE:
                raise Refusal(f"{label} ended {duplicate.get('verdict')!r}; reconcile read-only")
            duplicate.setdefault("label", label)
            return duplicate
        if self.journal.attempted(label):
            raise Refusal(f"{label} was attempted without a result; reconcile read-only")
        self.guards()
        before = {
            "head": self.rpc.head(),
            "payer_lt": self.rpc.last_lt(payer),
            "observe_lt": self.rpc.last_lt(account),
            "target_balance": self.rpc.balance(target),
        }
        record: dict = {
            "argv": self.cli.redact(tuple(argv)),
            "payer": payer,
            "observe": account,
            "external": external,
            "target": target,
            "before": before,
        }
        self.journal.attempt(label, {"kind": "value", **record})
        rc, _ = self.cli.run(label, *argv)
        record["exit_code"] = rc
        paid_at = before["target_balance"] + tos_to_nanotos("0.09")

        def finish(verdict: str) -> dict:
            record["target_paid_again"] = self.rpc.balance(target) >= paid_at
            if verdict == "cli-refused-before-broadcast":
                # Accepted by declaration only after a clean observation window proved that
                # nothing left the payer (the contract keeps no action id).
                record["client_side_refusal_accepted"] = True
            record["verdict"] = verdict
            self.journal.done(label, record)
            record["label"] = label
            return record

        if rc != 0:
            sent: list[dict] = []

            observation_failed = False

            def broadcast() -> bool:
                nonlocal observation_failed
                try:
                    if external:
                        sent[:] = self.external_arrivals(account, before["observe_lt"])
                    else:
                        sent[:] = self.sends_to(payer, before["payer_lt"], account)
                except Refusal:
                    observation_failed = True
                    raise
                return bool(sent)

            self.wait(broadcast, REFUSAL_OBSERVE_S)
            record["payer_tx_after"] = [r["transaction_id"] for r in sent]
            record["broadcast_observation_failed"] = observation_failed
            if sent or rc is None or observation_failed:
                finish("unknown")
                raise Refusal(
                    f"{label}: CLI exit {rc}; a message left the wallet or the observation "
                    "failed; reconcile read-only"
                )
            if self.rpc.balance(target) >= paid_at:
                return finish("DUPLICATE-EXECUTED")
            return finish("cli-refused-before-broadcast")
        found: dict = {}

        def settled() -> bool:
            if external:
                arrivals = self.external_arrivals(account, before["observe_lt"])
                if len(arrivals) > 1:
                    found["error"] = f"{len(arrivals)} external messages reached {account}"
                    return True
                if not arrivals:
                    return False
                found["payer_tx"] = None
                found["tx"] = arrivals[0]
                return True
            sends = self.sends_to(payer, before["payer_lt"], account)
            if len(sends) > 1:
                found["error"] = f"payer sent {len(sends)} messages to {account}"
                return True
            if not sends:
                return False
            out_hash = [
                m["hash"] for m in sends[0]["out_msgs"] if same_addr(m.get("destination"), account)
            ][0]
            rows = self.rpc.transactions_after(account, before["observe_lt"])
            hit = [r for r in rows if (r.get("in_msg") or {}).get("hash") == out_hash]
            if not hit:
                return False
            found["payer_tx"] = sends[0]
            found["tx"] = hit[0]
            return True

        observed = self.wait(settled)
        if "error" in found:
            record["error"] = found["error"]
            finish("multiple-sends-observed")
            raise Refusal(f"{label}: {found['error']}; stop and reconcile by hand")
        if not observed:
            finish("unknown-not-observed")
            raise Refusal(f"{label}: the exact message was not observed in time; no retry")
        tx = found["tx"]
        compute = tx.get("compute") or {}
        confirmations = {
            url: self.wait(
                lambda u=url: any(
                    r["transaction_id"]["hash"] == tx["transaction_id"]["hash"]
                    for r in self.rpc.transactions_after(account, before["observe_lt"], u)
                )
            )
            for url in self.rpc.confirms
        }
        transferred = [
            {k: m.get(k) for k in ("destination", "value", "bounced", "hash")}
            for m in tx.get("out_msgs", [])
            if same_addr(m.get("destination"), target)
        ]
        record.update(
            {
                "payer_tx": (found["payer_tx"] or {}).get("transaction_id"),
                "tx": tx["transaction_id"],
                "block_id": tx.get("block_id"),
                "compute": compute,
                "aborted": tx.get("aborted"),
                "action": tx.get("action"),
                "in_msg_hash": (tx.get("in_msg") or {}).get("hash"),
                "transfers_to_target": transferred,
                "confirmed_on": confirmations,
            }
        )
        if not all(confirmations.values()):
            finish("not-confirmed-on-all-sources")
            raise Refusal(f"{label}: transaction not seen on every confirmation source")
        if transferred or self.rpc.balance(target) >= paid_at:
            return finish("DUPLICATE-EXECUTED")
        if tx.get("aborted") is True and compute.get("success") is False:
            return finish("refused-as-intended")
        return finish("accepted-without-transfer")

    def case_sc08(self, w: dict) -> dict:
        """Integrated journey with a disputed task and the lost-reply drill.

        Run once with `SC_DRILL_CRASH=sc08-resolve-verifier`: the process exits after that
        step's attempt marker. The second run must refuse to re-send that label, prove nothing
        reached the chain after the marker, and only then issue the resolve under a new label.
        """
        creator, agent, verifier = w["sc-owner"], w["sc-client"], w["sc-verifier"]
        parts = {}
        for name in ("sc02", "sc03", "sc04", "sc05", "sc06", "sc07"):
            path = self.evidence / f"{name}-RESULT.json"
            if not path.exists():
                raise Refusal(f"sc08 needs {name} first")
            part = json.loads(path.read_text())
            if not isinstance(part, dict) or part.get("pass") is not True:
                raise Refusal(f"sc08 prerequisite {name} did not pass")
            parts[name] = part
        deploy = self.step(
            "sc08-task-create",
            self.task_create_argv("sc08", w),
            payer=creator,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "task", "show", "--name", "sc08")
        self.wait_active(address, "sc08 task")
        send = ["agent", "task", "send", "--name", "sc08", "--yes"]
        controls = []
        self.step(
            "sc08-accept",
            send + ["--operation", "accept", "--from", "sc-client"],
            payer=agent,
            observe=address,
            show=show,
        )
        self.step(
            "sc08-result",
            send
            + [
                "--operation",
                "result",
                "--from",
                "sc-client",
                "--result-hash",
                HASH["result"],
                "--evidence-hash",
                HASH["evidence"],
            ],
            payer=agent,
            observe=address,
            show=show,
        )
        self.step(
            "sc08-dispute",
            send
            + ["--operation", "dispute", "--from", "sc-owner", "--dispute-hash", HASH["dispute"]],
            payer=creator,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc08-resolve-agent",
                send + ["--operation", "resolve", "--from", "sc-client", "--payout", "0.4"],
                payer=agent,
                observe=address,
                expect_exit=TASK_RESOLVE_AUTHORITY,
                show=show,
            )
        )
        drill = "sc08-resolve-verifier"
        resolve = send + ["--operation", "resolve", "--from", "sc-verifier", "--payout", "0.4"]
        attempt = self.journal.attempt_record(drill)
        drill_state = "not-exercised"
        if attempt and not self.journal.result(drill):
            # A marker without a result: the first run was lost after writing it. Re-send only
            # when the marker says it was the drill and nothing reached the chain after it.
            before = attempt.get("before") or {}
            after_contract = self.rpc.transactions_after(address, before.get("observe_lt") or 0)
            after_payer = self.sends_to(verifier, before.get("payer_lt") or 0, address)
            record = {
                "verdict": "lost-reply-reconciled",
                "kind": attempt.get("kind"),
                "contract_tx_after_marker": len(after_contract),
                "payer_sends_after_marker": len(after_payer),
                "re_sent": False,
            }
            if attempt.get("kind") != "drill" or after_contract or after_payer:
                record["verdict"] = "lost-reply-unresolved"
                self.journal.done(drill, record)
                raise Refusal(
                    f"{drill}: marker without result and the chain is not provably "
                    "untouched; reconcile by hand, never re-send"
                )
            self.journal.done(drill, record)
            drill_state = "reconciled"
            self.step(
                "sc08-resolve-verifier-2", resolve, payer=verifier, observe=address, show=show
            )
        else:
            self.step(drill, resolve, payer=verifier, observe=address, show=show)
        final = show()
        final_ok = final.get("status") == "settled"
        return {
            "address": address,
            "final_state": final,
            "components": {
                k: {"address": v.get("address") or v.get("account"), "pass": v.get("pass")}
                for k, v in parts.items()
            },
            "lost_reply_drill": drill_state,
            **self.verdict(final_ok, controls),
        }

    # ----- follow-on cases on the already deployed components ------------------------------
    def component_result(self, name: str) -> dict:
        """A component case's RESULT file, accepted only as an object with a literal pass."""
        path = self.evidence / f"{name}-RESULT.json"
        if not path.exists():
            raise Refusal(f"{name}-RESULT.json missing; run {name} first")
        part = json.loads(path.read_text())
        if not isinstance(part, dict) or part.get("pass") is not True:
            raise Refusal(f"component {name} did not pass")
        return part

    def agent_account_state(self, account: str, url: str | None = None) -> dict:
        """seqno and controller epoch of an agent account, read with its own get method (the
        stack is reported top first: the last returned field comes first)."""
        stack = self.rpc.run_get_method(account, "get_agent_account_data", url)
        if len(stack) != 12 or any(stack[i][0] != "num" for i in (0, 2, 8)):
            raise Refusal(f"get_agent_account_data on {account}: unexpected stack shape")
        return {
            "seqno": int(stack[2][1]),
            "controller_epoch": int(stack[8][1]),
            "spent_today": int(stack[0][1]),
        }

    def sc03_original_message(self, account: str) -> tuple[dict, Cell]:
        """The executed SC-03 controller request, read back from its own transaction and bound
        to the chain by its message hash (the transaction's `in_msg.hash` and the step record)."""
        label = "sc03-task-send-2-retry"
        original = self.journal.result(label)
        if not original or original.get("verdict") != "settled" or not original.get("external"):
            raise Refusal(f"{label} is not a settled external step; nothing to replay")
        row = self.rpc.transaction_by_hash(account, original["tx"]["hash"])
        msg = transaction_in_message(boc_decode(base64.b64decode(row["data"])))
        msg_hash = cell_hash_b64(msg)
        if msg_hash != (row.get("in_msg") or {}).get("hash") or msg_hash != original.get(
            "in_msg_hash"
        ):
            raise Refusal("extracted message hash does not match the chain's in_msg hash")
        return {"label": label, "tx": original["tx"], "in_msg_hash": msg_hash}, msg

    def refusal_broadcast(
        self,
        label: str,
        msg: Cell,
        account: str,
        expect_exit: int,
        raw: bytes | None = None,
        licence: dict | None = None,
    ) -> dict:
        """Broadcast a message the account must refuse before accepting it.

        `raw` sends exactly those bytes (a message the CLI signed and saved) instead of the
        runner's own encoding of `msg`; they must decode to the same message hash. `licence`
        (the observation that justified sending) is written into the attempt marker itself, so
        it exists exactly when a broadcast may have happened.

        Nothing can be paid: a request refused before `accept_message()` never becomes a
        transaction, and the node reports the refusal itself when it admits the message
        ("exitcode=N" in the sendBoc error). The record keeps the node's answer verbatim, then
        proves on every source that no external message reached the account inside the
        observation window and that its seqno and controller epoch did not move.
        """
        done = self.journal.result(label)
        if done is not None:
            if done.get("verdict") != "refused-at-admission":
                raise Refusal(f"{label} ended {done.get('verdict')!r}; never re-broadcast")
            done.setdefault("label", label)
            return done
        if self.journal.attempted(label):
            raise Refusal(f"{label} was attempted without a result; reconcile read-only")
        self.guards()
        if raw is not None:
            if cell_hash_b64(boc_decode(raw)) != cell_hash_b64(msg):
                raise Refusal(f"{label}: the saved bytes are not the checked message")
            boc_b64 = base64.b64encode(raw).decode()
        else:
            boc_b64 = base64.b64encode(boc_encode(msg)).decode()
        before = {
            "head": self.rpc.head(),
            "observe_lt": self.rpc.last_lt(account),
            "state": {url: self.agent_account_state(account, url) for url in self.rpc.all_sources},
        }
        record: dict = {
            "kind": "refusal-broadcast",
            "observe": account,
            "expect_exit": expect_exit,
            "message_hash": cell_hash_b64(msg),
            "message_boc_sha256": hashlib.sha256(base64.b64decode(boc_b64)).hexdigest(),
            "before": before,
        }
        if licence is not None:
            record["licence"] = licence
        self.journal.attempt(label, record)
        answer = self.rpc.send_boc(boc_b64)
        record["rpc_answer"] = answer
        message = str((answer.get("error") or {}).get("message") or "")
        record["admission_exit_code"] = admission_exit_code(message)
        record["admission_refused_with_expected_exit"] = (
            record["admission_exit_code"] == expect_exit
        )

        def arrived() -> bool:
            return bool(self.external_arrivals(account, before["observe_lt"]))

        observed = self.wait(arrived, REFUSAL_OBSERVE_S)
        record["arrivals"] = {
            url: len(self.external_arrivals(account, before["observe_lt"], url))
            for url in self.rpc.all_sources
        }
        record["after"] = {
            "state": {url: self.agent_account_state(account, url) for url in self.rpc.all_sources}
        }
        unchanged = record["after"]["state"] == before["state"]
        if observed or any(record["arrivals"].values()) or not unchanged:
            record["verdict"] = "EXECUTED-OR-STATE-MOVED"
        elif record["admission_refused_with_expected_exit"]:
            record["verdict"] = "refused-at-admission"
        else:
            record["verdict"] = "refusal-control-failed"
        self.journal.done(label, record)
        self.journal.log(kind="refusal-broadcast", label=label, verdict=record["verdict"])
        record["label"] = label
        if record["verdict"] != "refused-at-admission":
            raise Refusal(f"{label}: {record['verdict']} ({message[:200]!r})")
        return record

    def case_sc03x(self, w: dict) -> dict:
        """Refusal coverage on the SC-03 agent account with the account's own public history.

        The executed controller request of SC-03 is read back from its transaction, bound to
        the chain by its message hash, and broadcast again unchanged (replay: bad seqno), with
        one signature bit inverted (wrong signer) and, after a real controller rotation by the
        owner wallet, unchanged once more (stale controller). Each refusal is the node's own
        admission verdict plus an unchanged account on every source. Expiry is recorded as not
        producible: the pinned CLI signs and broadcasts in one call and the contract checks the
        seqno before the deadline.
        """
        base = self.component_result("sc03")
        account = norm_addr(base["account"])
        agent_wallet = norm_addr(base["agent_wallet"])
        original, msg = self.sc03_original_message(account)
        parts = external_message_parts(msg)
        if not same_addr(parts["destination"], account):
            raise Refusal("original message is not addressed to the agent account")
        header = agent_external_header(parts["body"])
        state0 = self.agent_account_state(account)
        if (
            header["seqno"] >= state0["seqno"]
            or header["controller_epoch"] > state0["controller_epoch"]
        ):
            raise Refusal("original request is still current; a replay could execute")
        controls = [
            self.refusal_broadcast("sc03x-replay", msg, account, AGENT_BAD_SEQNO),
            self.refusal_broadcast(
                "sc03x-wrong-signer", with_flipped_signature_bit(msg), account, AGENT_BAD_SIGNATURE
            ),
        ]
        # The rotation is judged against the state recorded before it was first attempted, so a
        # resumed run (the live state already carries the new epoch) reaches the same verdict.
        pre = self.journal.result("sc03x-rotation-pre-state")
        pre_state = pre["state"] if pre else state0
        if pre is None:
            self.journal.attempt("sc03x-rotation-pre-state", {"kind": "local"})
            self.journal.done("sc03x-rotation-pre-state", {"exit_code": 0, "state": state0})
        self.local("sc03x-rotate-local", "agent", "wallet", "rotate-controller", "-n", "sc03-agent")
        rotation = self.step(
            "sc03x-rotate-controller",
            [
                "agent",
                "account",
                "rotate-controller",
                "--wallet",
                "sc03-agent",
                "--amount",
                "0.05",
                "--yes",
            ],
            payer=agent_wallet,
            observe=account,
        )
        state1 = self.agent_account_state(account)
        rotated = state1["controller_epoch"] == pre_state["controller_epoch"] + 1
        if not rotated:
            raise Refusal("controller epoch did not advance after the rotation")
        controls.append(
            self.refusal_broadcast(
                "sc03x-replay-stale-controller", msg, account, AGENT_STALE_CONTROLLER
            )
        )
        state2 = self.agent_account_state(account)
        final_ok = (
            all(c["verdict"] == "refused-at-admission" for c in controls)
            and rotation["verdict"] == "settled"
            and state2 == state1
        )
        return {
            "account": account,
            "original": {**original, "header": header},
            "state_before": state0,
            "state_after_rotation": state1,
            "state_final": state2,
            "rotation": {"label": "sc03x-rotate-controller", "verdict": rotation["verdict"]},
            "controls": {
                c["label"]: {
                    "verdict": c["verdict"],
                    "expect_exit": c["expect_exit"],
                    "node_answer": (c.get("rpc_answer") or {}).get("error"),
                    "arrivals": c.get("arrivals"),
                }
                for c in controls
            },
            "expiry_control": {
                "status": "not-run",
                "reason": "the pinned CLI signs and broadcasts in one call (no sign-only mode) "
                "and the contract checks the seqno before valid_until, so no public expiry "
                "refusal can be produced for this account without a new signing path",
            },
            "pass": final_ok,
        }

    def agreed_agent_state(self, account: str) -> dict:
        """The agent account state, required identical on every source."""
        states = {url: self.agent_account_state(account, url) for url in self.rpc.all_sources}
        first = next(iter(states.values()))
        for url, state in states.items():
            if (state["seqno"], state["controller_epoch"]) != (
                first["seqno"],
                first["controller_epoch"],
            ):
                raise Refusal(f"sources disagree on the agent account state ({url})")
        return first

    def expiry_probe_path(self) -> Path:
        """Where the CLI saves the signed SC-03e request: an owner-private export directory
        inside the private dir (the file is a valid spend authorization until it expires)."""
        exports = self.private / "exports"
        exports.mkdir(mode=0o700, exist_ok=True)
        if stat.S_IMODE(exports.stat().st_mode) & 0o077:
            raise Refusal("private export directory is not owner-private")
        return exports / "sc03e-expiry.boc"

    def check_prepared(
        self, answer, action_id: str, account: str, state: dict, valid_until: int
    ) -> dict:
        """The CLI's task-send-prepare answer must name exactly the request asked for, signed
        for the account's current sequence."""
        if not isinstance(answer, dict):
            raise Refusal("task-send-prepare returned no JSON object")
        expected = {
            "schema": "tosctl.agent-account.task-send-prepare.v1",
            # An exported request is held as possibly broadcast in custody (tos #424).
            "state": "broadcasting",
            "action_id": action_id,
            "seqno": state["seqno"],
            "controller_epoch": state["controller_epoch"],
            "valid_until": valid_until,
        }
        for key, value in expected.items():
            if answer.get(key) != value:
                raise Refusal(f"task-send-prepare answer {key}={answer.get(key)!r}, not {value!r}")
        if not same_addr(answer.get("account"), account):
            raise Refusal("task-send-prepare signed for another account")
        digest = str(answer.get("exact_signed_boc_digest") or "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise Refusal("task-send-prepare answer has no exact signed BOC digest")
        return answer

    def wait_chain_past(self, deadline: int, account: str) -> dict:
        """Wait until, on every source, the shard block covering `account` is EXPIRY_MARGIN_S
        past `deadline` (the clock admission uses), and return those times."""
        target = deadline + EXPIRY_MARGIN_S

        def times() -> dict:
            return {url: self.rpc.account_shard_utime(account, url) for url in self.rpc.all_sources}

        if not self.wait(
            lambda: all(t > target for t in times().values()), max(0.0, target - now()) + 300
        ):
            raise Refusal(f"shard time did not pass {target} on every source")
        observed = times()
        if not all(t > target for t in observed.values()):
            raise Refusal(f"shard time fell back below {target} on a source")
        return observed

    def read_expiry_probe(self, path: Path, prepared: dict, account: str) -> tuple[bytes, Cell]:
        """The saved request, bound to the CLI's printed digest and decoded back to the
        account, operation, sequence and deadline the answer named."""
        raw = path.read_bytes()
        if "sha256:" + hashlib.sha256(raw).hexdigest() != prepared["exact_signed_boc_digest"]:
            raise Refusal("saved request does not match the digest task-send-prepare printed")
        msg = boc_decode(raw)
        parts = external_message_parts(msg)
        if not same_addr(parts["destination"], account):
            raise Refusal("saved request is not addressed to the agent account")
        header = agent_external_header(parts["body"])
        if (
            header["op"] != AGENT_TASK_SEND_OP
            or header["seqno"] != prepared["seqno"]
            or header["controller_epoch"] != prepared["controller_epoch"]
            or header["valid_until"] != prepared["valid_until"]
        ):
            raise Refusal(f"saved request header {header} differs from the prepared request")
        return raw, msg

    def sc03e_prepare_label(self) -> str:
        """`sc03e-prepare`, or `sc03e-prepare-r2` when the first attempt ended with the CLI's
        argument-parse exit (2): clap refuses before any config, key or chain access, so nothing
        was signed and the first record stays as evidence. Any other failure is never retried."""
        first = self.journal.result("sc03e-prepare")
        if first is not None and first.get("exit_code") == 2 and first.get("answer") is None:
            return "sc03e-prepare-r2"
        return "sc03e-prepare"

    def case_sc03e(self, w: dict) -> dict:
        """Expiry refusal on the SC-03 agent account (exit 1706) with a request that is still
        current in every other respect.

        Expiry is judged against the time of the shard block that covers the account (the
        admission clock), on every source, not against the masterchain head.

        The CLI signs one controller task-send for the account's current sequence with a
        deadline EXPIRY_LEAD_S ahead and saves it without broadcasting (`task-send-prepare
        --signed-boc-out`). Once every source's shard block covering the account is past the deadline and the
        sequence is unchanged, those exact bytes are broadcast once: the node must refuse them
        at admission with 1706 and the account must stay unchanged on every source.

        The prepared custody record keeps this sequence reserved (no absence resolver for a
        plain task-send), so this is the last controller action of the SC-03 agent wallet.
        """
        self.component_result("sc03x")
        base = self.component_result("sc03")
        account = norm_addr(base["account"])
        agent_wallet = norm_addr(base["agent_wallet"])
        state0 = self.agreed_agent_state(account)
        action_id = hashlib.sha256(f"sc03e-expiry-{self.args.date}".encode()).hexdigest()
        label = self.sc03e_prepare_label()
        previous = self.journal.result(label)
        if previous and isinstance(previous.get("answer"), dict):
            valid_until = int(previous["answer"]["valid_until"])
        else:
            valid_until = int(now()) + EXPIRY_LEAD_S
        path = self.expiry_probe_path()
        answer = self.local(
            label,
            "agent",
            "account",
            "task-send-prepare",
            "--wallet",
            "sc03-agent",
            "--target",
            agent_wallet,
            "--value",
            "0.001",
            "--valid-until",
            str(valid_until),
            "--action-id",
            action_id,
            "--signed-boc-out",
            str(path),
            "--yes",
            want_json=True,
            # task-send-prepare prints its own JSON and rejects the global --format flag.
            format_flag=False,
        )
        control = self.journal.result("sc03e-expired")
        if control is None:
            prepared = self.check_prepared(answer, action_id, account, state0, valid_until)
        else:
            # Resumed after the broadcast: the account has the state the broadcast left.
            prepared = answer
        if control is not None:
            # Done: report the times recorded in the broadcast's own marker; nothing is re-sent.
            chain_times = (control.get("licence") or {}).get("shard_utime")
        else:
            # Not yet broadcast (or interrupted before the marker): re-judge from scratch.
            chain_times = self.wait_chain_past(valid_until, account)
        state1 = self.agreed_agent_state(account)
        if (state1["seqno"], state1["controller_epoch"]) != (
            prepared["seqno"],
            prepared["controller_epoch"],
        ):
            raise Refusal("the prepared sequence moved before expiry; not an expiry control")
        raw, msg = self.read_expiry_probe(path, prepared, account)
        control = self.refusal_broadcast(
            "sc03e-expired",
            msg,
            account,
            AGENT_EXPIRED,
            raw=raw,
            licence={"deadline": valid_until, "shard_utime": chain_times},
        )
        state2 = self.agreed_agent_state(account)
        return {
            "account": account,
            "action_id": action_id,
            "prepared": {
                k: prepared.get(k)
                for k in ("seqno", "controller_epoch", "valid_until", "exact_signed_boc_digest")
            },
            "shard_time_at_broadcast": chain_times,
            "message_hash": cell_hash_b64(msg),
            "control": {
                "verdict": control["verdict"],
                "expect_exit": control["expect_exit"],
                "node_answer": (control.get("rpc_answer") or {}).get("error"),
                "arrivals": control.get("arrivals"),
            },
            "state_before": state1,
            "state_after": state2,
            "custody_note": "the exported record is held as Broadcasting; sc03-agent takes no further "
            "controller action",
            "pass": control["verdict"] == "refused-at-admission" and state2 == state1,
        }

    # ----- Native Registry (SC-01 Agent identity, SC-02 Capability) --------------------------
    def nr_require_deploy_gate(self) -> Path:
        """The registry batch runs only with an explicit opt-in and the frozen domain's config:
        merging this code grants no execution authority (the owner's deployment ruling does)."""
        if not getattr(self.args, "allow_registry_deploy", False):
            raise Refusal("registry cases need --allow-registry-deploy (owner deployment ruling)")
        path = Path(str(getattr(self.args, "registry_global_config", "") or ""))
        if not path.is_file():
            raise Refusal("registry cases need --registry-global-config <testnet global config>")
        if hashlib.sha256(path.read_bytes()).hexdigest() != NR_GLOBAL_CONFIG_SHA256:
            raise Refusal("registry global config is not the published testnet config")
        return path

    def nr_actors(self) -> dict:
        path = self.evidence / "registry-actors.json"
        if not path.exists():
            raise Refusal("registry-actors.json missing; run setup-registry first")
        return json.loads(path.read_text())

    def setup_registry(self) -> dict:
        """Create the registry payer wallet and the ML-DSA-44 controllers through the CLI's own
        custody (vault secrets native-registry-<name>); record only public keys and key ids, and
        write the two Agent policies from them. No value moves; funding is a separate step."""
        self.preflight(value_action=False)
        self.local(
            f"setup-wallet-{NR_ACTOR}", "wallet", "create", "-n", NR_ACTOR, "-v", "V3R2", "-w", "0"
        )
        rc, rows = self.cli.run(
            f"setup-registry-ls-{self.cli.calls}", "wallet", "ls", want_json=True
        )
        if rc != 0 or not isinstance(rows, list):
            raise Refusal("wallet ls failed")
        wallet = [
            norm_addr(r["address"])
            for r in rows
            if isinstance(r, dict) and r.get("name") == NR_ACTOR and r.get("address")
        ]
        if len(wallet) != 1:
            raise Refusal(f"{NR_ACTOR} has no unique address")
        controllers = {}
        for name in NR_CONTROLLERS:
            self.local(
                f"setup-controller-{name}",
                "agent",
                "native-registry",
                "new-controller",
                "--name",
                name,
                want_json=True,
            )
            pub = self.local(
                f"setup-controller-pub-{name}",
                "agent",
                "native-registry",
                "controller",
                "--name",
                name,
                want_json=True,
            )
            if not isinstance(pub, dict) or pub.get("suite") != "ML-DSA-44":
                raise Refusal(f"controller {name}: unexpected answer")
            controllers[name] = {"key_id": pub["key_id"], "public_key": pub["public_key"]}
        policies = {
            "a": {
                "threshold": 1,
                "recovery_threshold": 1,
                "recovery_timelock": 86400,
                "controllers": [
                    {"public_key": controllers[n]["public_key"], "weight": 1, "purposes": 15}
                    for n in ("nr-a1", "nr-a2")
                ],
            },
            "b": {
                "threshold": 1,
                "recovery_threshold": 1,
                "recovery_timelock": 86400,
                "controllers": [
                    {"public_key": controllers["nr-b1"]["public_key"], "weight": 1, "purposes": 15}
                ],
            },
        }
        for name, policy in policies.items():
            target = self.evidence / f"registry-policy-{name}.json"
            if not target.exists():
                target.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
        actors = {"wallet": wallet[0], "controllers": controllers, "created_utc": utc(now())}
        path = self.evidence / "registry-actors.json"
        if not path.exists():
            path.write_text(json.dumps(actors, indent=2, sort_keys=True) + "\n")
        return json.loads(path.read_text())

    def nr_nonce(self, purpose: str) -> str:
        """A 32-byte hex nonce bound to this run's date and the step's purpose: the same step
        always builds the same object, so a rerun cannot mint a second one."""
        return hashlib.sha256(f"nr-{self.args.date}-{purpose}".encode()).hexdigest()

    def nr_build(self, label: str, *argv: str) -> dict:
        """One once-only CLI build of a signed registry message (never sent by the CLI)."""
        gc = self.nr_require_deploy_gate()
        built = self.local(
            label,
            "agent",
            "native-registry",
            *argv,
            "--global-config",
            str(gc),
            "--network-label",
            NR_LABEL,
            want_json=True,
        )
        if not isinstance(built, dict) or not built.get("body_boc") or not built.get("destination"):
            raise Refusal(f"{label}: unexpected build answer")
        return built

    def nr_show(self, address: str) -> dict:
        """The registry object at `address`, read on every source (chain_time excluded).

        Returns the decoded object, or NR_ABSENT only when every source positively reports no
        initialized account there. Any read failure, or sources that disagree, raises: a failed
        read is never mistaken for an unchanged or absent object."""
        gc = self.nr_require_deploy_gate()
        urls = [self.rpc.primary, *self.rpc.confirms]
        configs = [None, *[Path(p) for p in self.quorum_configs()]]
        views = []
        for url, config in zip(urls, configs, strict=True):
            state = (self.rpc.info(address, url) or {}).get("state")
            if state in ("uninitialized", "nonexist", "uninit"):
                views.append(dict(NR_ABSENT))
                continue
            rc, view = self.cli.run(
                f"nr-show-{self.cli.calls}",
                "agent",
                "native-registry",
                "show",
                "--global-config",
                str(gc),
                "--network-label",
                NR_LABEL,
                "--address",
                address,
                want_json=True,
                config=config,
            )
            if rc != 0 or not isinstance(view, dict) or view.get("registered") is not True:
                raise Refusal(f"registry object at {address} could not be read on {url}")
            views.append({k: v for k, v in view.items() if k != "chain_time"})
        if any(v != views[0] for v in views):
            raise Refusal(f"sources disagree on the registry object at {address}")
        return views[0]

    def nr_payer_ready(self, payer: str) -> None:
        """The payer is active on every source and holds the value, its own fee and the reserve."""
        need = NR_VALUE_NANOTOS + NR_FEE_ALLOWANCE_NANOTOS + NR_PAYER_RESERVE_NANOTOS
        for url in self.rpc.all_sources:
            info = self.rpc.info(payer, url) or {}
            if info.get("state") != "active":
                raise Refusal(f"{NR_ACTOR} is not active on {url}; run activate-registry")
            if int(info.get("balance") or 0) < need:
                raise Refusal(f"{NR_ACTOR} holds less than {need} nanoTOS on {url}")

    def activate_registry(self) -> dict:
        """Activate the registry payer once (it must be funded first). An existing attempt is
        never repeated: its outcome is judged read-only from the chain."""
        self.preflight()
        address = self.nr_actors()["wallet"]
        states = {
            url: (self.rpc.info(address, url) or {}).get("state") for url in self.rpc.all_sources
        }
        if all(v == "active" for v in states.values()):
            return {NR_ACTOR: "already-active", "states": states}
        label = f"activate-{NR_ACTOR}"
        if self.journal.attempted(label):
            raise Refusal(f"{label} was attempted before; wallet states {states}; judge by hand")
        # The CLI activates only from WALLET_ACTIVATE_MIN_NANOTOS (tos c17d3fca5 wallet_cmd.rs
        # MIN_BALANCE); below it the once-only marker would be spent on a skipped activation.
        if self.rpc.balance(address) < WALLET_ACTIVATE_MIN_NANOTOS:
            return {NR_ACTOR: "unfunded", "states": states}
        self.guards()
        self.journal.attempt(label, {"kind": "wallet-activate", "address": address})
        rc, _ = self.cli.run(label, "wallet", "activate", "-n", NR_ACTOR)
        ok = rc == 0 and self.wait(
            lambda: all(
                (self.rpc.info(address, url) or {}).get("state") == "active"
                for url in self.rpc.all_sources
            )
        )
        self.journal.done(label, {"exit_code": rc, "active": ok})
        if not ok:
            raise Refusal(f"{label}: wallet did not become active on every source")
        return {NR_ACTOR: "activated"}

    def wallet_seqno(self, address: str) -> int:
        seqnos = set()
        for url in self.rpc.all_sources:
            stack = self.rpc.run_get_method(address, "seqno", url)
            seqnos.add(int(stack[0][1]))
        if len(seqnos) != 1:
            raise Refusal(f"sources disagree on the wallet seqno of {address}: {seqnos}")
        return seqnos.pop()

    def registry_send(
        self,
        label: str,
        built: dict,
        *,
        bounce: bool,
        expect_exit: int = 0,
        body_boc: str | None = None,
    ) -> dict:
        """Send one built registry message from the registry payer, once.

        The CLI builds and signs the registry message; `wallet send --build-only` signs the exact
        wallet message (kept private until spent); bind_prepared_send decodes it and checks every
        part against the build; the attempt marker is written before the single sendBoc. A
        success needs the payer transaction for that external message, the first receiver's
        transaction for the payer's message, and the final target holding last_action ==
        action_hash with the CLI's predicted generation and sequence on every source. A refusal
        needs the first receiver's transaction aborted with exactly `expect_exit`, the final
        target unchanged on every source and, when bounceable, the refund bound by message hash.
        `body_boc` replaces the build's body (a replay or a mutated signature); the destination
        and StateInit stay the build's."""
        done = self.journal.result(label)
        if done is not None:
            if done.get("verdict") not in ("settled", "refused-as-intended"):
                raise Refusal(f"{label} ended {done.get('verdict')!r}; never re-sent")
            done.setdefault("label", label)
            return done
        if self.journal.attempted(label):
            raise Refusal(f"{label} was attempted without a result; reconcile read-only")
        self.guards()
        actors = self.nr_actors()
        payer = actors["wallet"]
        self.nr_payer_ready(payer)
        carried = {**built, "body_boc": body_boc or built["body_boc"]}
        if body_boc is not None:
            carried.pop("state_init_boc", None)
        destination = norm_addr(carried["destination"])
        final = norm_addr(carried.get("final_target") or destination)
        before = {
            "head": self.rpc.head(),
            "payer_lt": self.rpc.last_lt(payer),
            "destination_lt": self.rpc.last_lt(destination),
            "final_lt": self.rpc.last_lt(final),
            "final_state": self.nr_show(final),
        }
        registering = (
            body_boc is None
            and bool(carried.get("state_init_boc"))
            or (
                expect_exit == 0
                and final != destination
                and built.get("generation") == 1
                and built.get("sequence") == 1
            )
        )
        if expect_exit != 0 and before["final_state"].get("registered") is not True:
            raise Refusal(f"{label}: a refusal control needs an existing registry object")
        if registering and before["final_state"] != NR_ABSENT:
            raise Refusal(f"{label}: the object to register already exists or is unreadable")
        seqno = self.wallet_seqno(payer)
        argv = [
            "wallet",
            "send",
            "--from",
            NR_ACTOR,
            "--to",
            destination,
            "--amount-nanotos",
            str(NR_VALUE_NANOTOS),
            "--body-boc",
            carried["body_boc"],
        ]
        if carried.get("state_init_boc"):
            argv += ["--state-init-boc", carried["state_init_boc"]]
        if bounce:
            argv.append("--bounce")
        argv += ["--build-only", "--yes"]
        envelope = self.local(
            f"{label}-envelope", *argv, want_json=True, format_flag=False, private_answer=True
        )
        if self.wallet_seqno(payer) != seqno:
            raise Refusal(f"{label}: payer seqno moved while building; by hand")
        raw, msg, decoded = bind_prepared_send(
            envelope,
            carried,
            payer=payer,
            value_nanotos=NR_VALUE_NANOTOS,
            bounce=bounce,
            global_id=NR_GLOBAL_ID,
            seqno=seqno,
        )
        external_hash = dag_cell_hash_b64(msg)
        record: dict = {
            "kind": "registry-send",
            "payer": payer,
            "observe": destination,
            "final_target": final,
            "external": False,
            "external_hash": external_hash,
            "message_boc_sha256": hashlib.sha256(raw).hexdigest(),
            "wallet_seqno": seqno,
            "bounce": bounce,
            "expect_exit": expect_exit,
            "action_hash": built.get("action_hash"),
            "generation": built.get("generation"),
            "sequence": built.get("sequence"),
            "valid_until": decoded.get("valid_until"),
            "before": before,
        }
        self.journal.attempt(label, record)
        record["rpc_answer"] = self.rpc.send_boc(base64.b64encode(raw).decode())
        found: dict = {}

        def settled() -> bool:
            rows = self.rpc.transactions_after(payer, before["payer_lt"])
            hit = [r for r in rows if (r.get("in_msg") or {}).get("hash") == external_hash]
            if len(hit) != 1:
                return False
            outs = [
                m
                for m in hit[0].get("out_msgs", [])
                if same_addr(m.get("destination"), destination)
            ]
            if len(outs) != 1:
                found["error"] = f"payer transaction carries {len(outs)} messages to {destination}"
                return True
            first = [
                r
                for r in self.rpc.transactions_after(destination, before["destination_lt"])
                if (r.get("in_msg") or {}).get("hash") == outs[0]["hash"]
            ]
            if len(first) != 1:
                return False
            found["payer_tx"], found["tx"] = hit[0], first[0]
            return True

        if not self.wait(settled) or "error" in found:
            record["verdict"] = (
                "multiple-sends-observed" if "error" in found else "unknown-not-observed"
            )
            record["error"] = found.get("error")
            self.journal.done(label, record)
            raise Refusal(f"{label}: {record['verdict']}; reconcile read-only, no resend")
        return self._registry_finish(label, record, found["payer_tx"], found["tx"], built)

    def _registry_finish(
        self, label: str, record: dict, payer_tx: dict, tx: dict, built: dict
    ) -> dict:
        """Judge one registry send from its observed transactions (shared by the live send and
        its read-only reconciliation) and write the result."""
        before = record["before"]
        payer, destination, final = record["payer"], record["observe"], record["final_target"]
        bounce, expect_exit = record["bounce"], record["expect_exit"]
        found: dict = {"payer_tx": payer_tx, "tx": tx}
        compute = tx.get("compute") or {}
        record.update(
            {
                "payer_tx": found["payer_tx"]["transaction_id"],
                "tx": tx["transaction_id"],
                "compute": compute,
                "aborted": tx.get("aborted"),
                "out_msgs": [
                    {k: m.get(k) for k in ("destination", "value", "bounced", "hash")}
                    for m in tx.get("out_msgs", [])
                ],
            }
        )
        for url in self.rpc.confirms:
            seen = any(
                r["transaction_id"]["hash"] == tx["transaction_id"]["hash"]
                for r in self.rpc.transactions_after(destination, before["destination_lt"], url)
            )
            if not seen:
                record["verdict"] = "not-confirmed-on-all-sources"
                self.journal.done(label, record)
                raise Refusal(f"{label}: transaction not seen on {url}")
        if expect_exit == 0:
            ok_first = tx.get("aborted") is not True and compute.get("exit_code") in (0, 1)

            def landed() -> bool:
                view = self.nr_show(final)
                found["after"] = view
                return (
                    bool(view)
                    and view.get("last_action") == built.get("action_hash")
                    and (view.get("generation"), view.get("sequence"))
                    == (built.get("generation"), built.get("sequence"))
                )

            ok_final = self.wait(landed)
            record["after"] = {"final_state": found.get("after")}
            record["settlement_basis"] = "first-hop+final-state"
            record["verdict"] = "settled" if ok_first and ok_final else "unexpected-abort"
        else:
            aborted = tx.get("aborted") is True and compute.get("exit_code") == expect_exit
            after_state = self.nr_show(final)
            unchanged = after_state == before["final_state"]
            refund_ok, refund_pending = True, False
            if bounce:
                bounces = [
                    m for m in tx.get("out_msgs", []) if same_addr(m.get("destination"), payer)
                ]
                refund_ok = False
                if len(bounces) == 1:
                    refund = self.nr_refund(payer, before["payer_lt"], bounces[0]["hash"])
                    record["refund"] = refund
                    refund_ok = refund["bound"]
                    refund_pending = not refund_ok and refund["pending"]
            record["after"] = {"final_state": after_state}
            record["refund_bound"] = refund_ok
            ok = aborted and unchanged and refund_ok
            if aborted and unchanged and refund_pending:
                record["verdict"] = "refund-pending"
            else:
                record["verdict"] = "refused-as-intended" if ok else "refusal-control-failed"
        self.journal.done(label, record)
        self.journal.log(kind="registry-send", label=label, verdict=record["verdict"])
        record["label"] = label
        if record["verdict"] not in ("settled", "refused-as-intended"):
            raise Refusal(f"{label}: {record['verdict']} ({compute}, aborted={tx.get('aborted')})")
        return record

    def nr_refund(self, payer: str, since_lt: int, bounce_hash: str) -> dict:
        """The bounce credit of a refused message on every source: exactly one non-aborted payer
        transaction whose input is that bounced message with a positive value, and the same
        transaction on every source. `pending` when it is not yet visible everywhere."""
        seen: dict[str, str | None] = {}

        def everywhere() -> bool:
            for url in self.rpc.all_sources:
                hits = [
                    r
                    for r in self.rpc.transactions_after(payer, since_lt, url)
                    if (r.get("in_msg") or {}).get("hash") == bounce_hash
                ]
                ok = (
                    len(hits) == 1
                    and hits[0].get("aborted") is not True
                    and str((hits[0].get("in_msg") or {}).get("bounced")) == "True"
                    and int((hits[0].get("in_msg") or {}).get("value") or 0) > 0
                )
                seen[url] = hits[0]["transaction_id"]["hash"] if ok else None
            return all(seen.values()) and len(set(seen.values())) == 1

        bound = self.wait(everywhere, REFUSAL_OBSERVE_S)
        return {"bound": bound, "pending": not bound, "per_source": dict(seen)}

    def registry_reconcile(self, label: str) -> dict:
        """Read-only recovery of a registry send whose reply was lost. Nothing is sent. On every
        source exactly one payer transaction must carry the journaled external message hash, with
        exactly one message to the first receiver and exactly one first-receiver transaction for
        it, and every source must name the same transactions; the verdict then follows the live
        rules. A message that no source carries after the wallet deadline is recorded as
        expired-unsent: it can no longer apply, and the label is never re-sent."""
        self.preflight(value_action=False)
        record = self.journal.attempt_record(label)
        done = self.journal.result(label)
        if record is None or record.get("kind") != "registry-send":
            raise Refusal(f"{label} has no registry-send attempt marker")
        if done is not None and done.get("verdict") not in (
            "unknown-not-observed",
            "refund-pending",
        ):
            raise Refusal(f"{label} already ended {done.get('verdict')!r}")
        before = record["before"]
        payer, destination = record["payer"], record["observe"]
        picks: dict = {}
        for url in self.rpc.all_sources:
            hits = [
                r
                for r in self.rpc.transactions_after(payer, before["payer_lt"], url)
                if (r.get("in_msg") or {}).get("hash") == record["external_hash"]
            ]
            if not hits:
                picks[url] = None
                continue
            if len(hits) != 1:
                raise Refusal(f"{label}: {len(hits)} payer transactions carry it on {url}")
            outs = [
                m
                for m in hits[0].get("out_msgs", [])
                if same_addr(m.get("destination"), destination)
            ]
            if len(outs) != 1:
                raise Refusal(f"{label}: {len(outs)} messages to {destination} on {url}; by hand")
            first = [
                r
                for r in self.rpc.transactions_after(destination, before["destination_lt"], url)
                if (r.get("in_msg") or {}).get("hash") == outs[0]["hash"]
            ]
            if len(first) != 1:
                raise Refusal(f"{label}: first receiver transaction not unique on {url}; by hand")
            picks[url] = (hits[0], first[0])
        if all(v is None for v in picks.values()):
            deadline = int(record.get("valid_until") or 0)
            observed = {
                url: {
                    "wallet_shard_utime": self.rpc.account_shard_utime(payer, url),
                    "wallet_seqno": int(self.rpc.run_get_method(payer, "seqno", url)[0][1]),
                }
                for url in self.rpc.all_sources
            }
            past = deadline and all(
                o["wallet_shard_utime"] > deadline + EXPIRY_MARGIN_S for o in observed.values()
            )
            unspent = all(o["wallet_seqno"] == record["wallet_seqno"] for o in observed.values())
            if past and unspent:
                result = {
                    **record,
                    "verdict": "expired-unsent",
                    "reconciled_from": "attempt",
                    "expiry_observations": observed,
                }
                self.journal.done(label, result)
                return result
            if past and not unspent:
                raise Refusal(f"{label}: wallet seqno moved without the message; by hand")
            raise Refusal(f"{label}: no source carries the message yet; wait for its deadline")
        if any(v is None for v in picks.values()):
            raise Refusal(f"{label}: sources disagree on whether the message applied; by hand")
        ids = {
            (v[0]["transaction_id"]["hash"], v[1]["transaction_id"]["hash"]) for v in picks.values()
        }
        if len(ids) != 1:
            raise Refusal(f"{label}: sources name different transactions; by hand")
        payer_tx, tx = picks[self.rpc.primary]
        built = {
            "action_hash": record.get("action_hash"),
            "generation": record.get("generation"),
            "sequence": record.get("sequence"),
        }
        record = {**record, "reconciled_from": "attempt", "re_sent": False}
        return self._registry_finish(label, record, payer_tx, tx, built)

    def nr_flip_body(self, body_boc: str) -> str:
        """The base64 body with its first authority signature's first data bit inverted."""
        cell = with_flipped_registry_signature(boc_decode(base64.b64decode(body_boc)))
        return base64.b64encode(boc_encode_dag(cell)).decode()

    def case_scnr(self, w: dict) -> dict:
        """Public SC-01 (Agent identity) and SC-02 (Capability) on the ML-DSA-44 Native Registry,
        in one executable order so Agent A is revoked only after the Capability lifecycle:

        register A, register B, delegate on A (SC-01); register a Capability under A, add a
        version, transfer it to B with B's counter-signature, revoke it (SC-02); then three
        refusals around A's revocation: A's registration body replayed after A advanced (2204),
        a fresh A action with one signature bit flipped (2208), revoke A, and A's delegate body
        after the tombstone (2206). Eleven messages at 0.3 TOS, bounceable when the first
        receiver is an existing Agent."""
        self.nr_require_deploy_gate()
        policy_a = str(self.evidence / "registry-policy-a.json")
        policy_b = str(self.evidence / "registry-policy-b.json")
        steps: dict = {}
        reg_a = self.nr_build(
            "scnr-build-register-a",
            "register-agent",
            "--policy",
            policy_a,
            "--nonce",
            self.nr_nonce("agent-a"),
            "--signer",
            "nr-a1",
            "--signer",
            "nr-a2",
        )
        steps["register-a"] = self.registry_send("scnr-register-a", reg_a, bounce=False)
        agent_a = norm_addr(reg_a["destination"])
        reg_b = self.nr_build(
            "scnr-build-register-b",
            "register-agent",
            "--policy",
            policy_b,
            "--nonce",
            self.nr_nonce("agent-b"),
            "--signer",
            "nr-b1",
        )
        steps["register-b"] = self.registry_send("scnr-register-b", reg_b, bounce=False)
        agent_b = norm_addr(reg_b["destination"])
        delegate = self.nr_build(
            "scnr-build-delegate-a",
            "action",
            "--kind",
            "delegate",
            "--agent",
            agent_a,
            "--nonce",
            self.nr_nonce("delegate-a"),
            "--delegation",
            self.nr_nonce("delegation-1"),
            "--signer",
            "nr-a1",
        )
        steps["delegate-a"] = self.registry_send("scnr-delegate-a", delegate, bounce=True)
        cap = self.nr_build(
            "scnr-build-register-cap",
            "action",
            "--kind",
            "register-capability",
            "--agent",
            agent_a,
            "--nonce",
            self.nr_nonce("register-cap"),
            "--object-nonce",
            self.nr_nonce("cap-object"),
            "--version",
            "v1",
            "--manifest",
            self.nr_nonce("manifest-v1"),
            "--signer",
            "nr-a1",
        )
        steps["register-cap"] = self.registry_send("scnr-register-cap", cap, bounce=True)
        capability = norm_addr(cap["final_target"])
        add = self.nr_build(
            "scnr-build-add-version",
            "action",
            "--kind",
            "add-version",
            "--agent",
            agent_a,
            "--capability",
            capability,
            "--nonce",
            self.nr_nonce("add-version"),
            "--version",
            "v2",
            "--manifest",
            self.nr_nonce("manifest-v2"),
            "--signer",
            "nr-a1",
        )
        steps["add-version"] = self.registry_send("scnr-add-version", add, bounce=True)
        transfer = self.nr_build(
            "scnr-build-transfer-cap",
            "action",
            "--kind",
            "transfer-capability",
            "--agent",
            agent_a,
            "--capability",
            capability,
            "--new-owner",
            agent_b,
            "--nonce",
            self.nr_nonce("transfer-cap"),
            "--signer",
            "nr-a1",
            "--counter-signer",
            "nr-b1",
        )
        steps["transfer-cap"] = self.registry_send("scnr-transfer-cap", transfer, bounce=True)
        revoke_cap = self.nr_build(
            "scnr-build-revoke-cap",
            "action",
            "--kind",
            "revoke-capability",
            "--agent",
            agent_b,
            "--capability",
            capability,
            "--nonce",
            self.nr_nonce("revoke-cap"),
            "--signer",
            "nr-b1",
        )
        steps["revoke-cap"] = self.registry_send("scnr-revoke-cap", revoke_cap, bounce=True)
        # Refusals on A while it is still live: its own registration body (predecessor 0 against
        # a registered object) and a current action whose first signature bit is flipped.
        steps["refuse-stale"] = self.registry_send(
            "scnr-refuse-stale",
            {**reg_a, "final_target": agent_a},
            bounce=True,
            expect_exit=NR_BAD_PREDECESSOR,
            body_boc=reg_a["body_boc"],
        )
        fresh = self.nr_build(
            "scnr-build-signature-probe",
            "action",
            "--kind",
            "delegate",
            "--agent",
            agent_a,
            "--nonce",
            self.nr_nonce("signature-probe"),
            "--delegation",
            self.nr_nonce("delegation-2"),
            "--signer",
            "nr-a1",
        )
        flipped = self.nr_flip_body(fresh["body_boc"])
        steps["refuse-signature"] = self.registry_send(
            "scnr-refuse-signature",
            fresh,
            bounce=True,
            expect_exit=NR_BAD_SIGNATURE,
            body_boc=flipped,
        )
        revoke_a = self.nr_build(
            "scnr-build-revoke-a",
            "action",
            "--kind",
            "revoke-agent",
            "--agent",
            agent_a,
            "--nonce",
            self.nr_nonce("revoke-a"),
            "--signer",
            "nr-a1",
        )
        steps["revoke-a"] = self.registry_send("scnr-revoke-a", revoke_a, bounce=True)
        steps["refuse-tombstone"] = self.registry_send(
            "scnr-refuse-tombstone",
            {**delegate, "final_target": agent_a},
            bounce=True,
            expect_exit=NR_TOMBSTONED,
            body_boc=delegate["body_boc"],
        )
        final = {
            "agent_a": self.nr_show(agent_a),
            "agent_b": self.nr_show(agent_b),
            "capability": self.nr_show(capability),
        }
        refusals = [steps[k] for k in ("refuse-stale", "refuse-signature", "refuse-tombstone")]
        codes_executed = all(
            r.get("verdict") == "refused-as-intended"
            and (r.get("compute") or {}).get("exit_code") == r.get("expect_exit")
            for r in refusals
        )
        ok = all(v["verdict"] in ("settled", "refused-as-intended") for v in steps.values())
        ok = ok and bool(final["agent_a"]) and final["agent_a"].get("tombstone") is True
        return {
            "domain": {"label": NR_LABEL, "code_hash": NR_CODE_HASH},
            "agents": {"a": agent_a, "b": agent_b},
            "capability": capability,
            "steps": {
                k: {"verdict": v["verdict"], "tx": v.get("tx"), "expect_exit": v.get("expect_exit")}
                for k, v in steps.items()
            },
            "final": final,
            "expected_codes_executed": codes_executed,
            "settlement_basis": "first-hop+final-state",
            "pass": ok and codes_executed,
        }

    def case_sc05x(self, w: dict) -> dict:
        """Duplicate settlement of the already settled SC-05 task must be refused with no second
        payout: the escrow accepts settle only in `result_submitted`."""
        part = self.component_result("sc05")
        address = norm_addr(part["address"])
        creator, agent = w["sc-owner"], w["sc-client"]
        show = self.show("agent", "task", "show", "--name", "sc05")
        state0 = show()
        if state0.get("status") != "settled":
            raise Refusal(f"sc05 task is {state0.get('status')!r}, not settled; wrong premise")
        agent_before = self.rpc.balance(agent)
        settle_again = self.step(
            "sc05x-settle-again",
            [
                "agent",
                "task",
                "send",
                "--name",
                "sc05",
                "--yes",
                "--operation",
                "settle",
                "--from",
                "sc-owner",
                "--payout",
                "0.6",
            ],
            payer=creator,
            observe=address,
            expect_exit=TASK_SETTLE_NOT_SUBMITTED,
            show=show,
        )
        paid_again = self.transferred(settle_again, agent, "0.000000001")
        final = show()
        final_ok = final.get("status") == "settled" and not paid_again
        return {
            "address": address,
            "agent_paid_again": paid_again,
            "agent_balance_before": agent_before,
            "agent_balance_after": self.rpc.balance(agent),
            "final_state": final,
            **self.verdict(final_ok, [settle_again]),
        }

    def component_bindings(self, parts: dict) -> dict:
        """Hashes the SC-08x task commits to on chain, derived from every component contract's
        address and its latest transaction when the journey starts; recorded once in the journal
        so a resumed run commits to the same values, and recomputable by anyone from the chain."""
        stored = self.journal.result("sc08x-bindings")
        if stored is not None:
            return stored["bindings"]
        anchors = {}
        for name, part in sorted(parts.items()):
            address = norm_addr(part.get("address") or part.get("account"))
            last = self.rpc.info(address).get("last_transaction_id") or {}
            if not last.get("lt") or not last.get("hash"):
                raise Refusal(f"component {name} has no transaction to anchor")
            anchors[name] = {"address": address, "lt": str(last["lt"]), "hash": last["hash"]}
        preimage = "|".join(f"{n}:{a['address']}:{a['lt']}:{a['hash']}" for n, a in anchors.items())
        bindings = {
            "anchors": anchors,
            "preimage": preimage,
            "result_hash": hashlib.sha256(f"sc08x-result|{preimage}".encode()).hexdigest(),
            "evidence_hash": hashlib.sha256(f"sc08x-evidence|{preimage}".encode()).hexdigest(),
            "dispute_hash": hashlib.sha256(f"sc08x-dispute|{preimage}".encode()).hexdigest(),
        }
        self.journal.attempt("sc08x-bindings", {"kind": "local"})
        self.journal.done("sc08x-bindings", {"exit_code": 0, "bindings": bindings})
        return bindings

    def case_sc08x(self, w: dict) -> dict:
        """Integrated journey whose on-chain hashes bind the component contracts, with the
        lost reply AFTER forwarding.

        Run once with `SC_DRILL_CRASH_AFTER_SEND=sc08x-resolve-verifier`: the process exits
        right after the CLI returned for that step, so the message is on its way and no record
        exists. The second run must not re-send: it reconciles the attempt read-only from the
        exact message and continues from the recovered record.
        """
        creator, agent, verifier = w["sc-owner"], w["sc-client"], w["sc-verifier"]
        parts = {
            name: self.component_result(name)
            for name in ("sc02", "sc03", "sc04", "sc05", "sc06", "sc07")
        }
        bindings = self.component_bindings(parts)
        needed = tos_to_nanotos("1.31")
        if self.journal.result("sc08x-task-create") is None and self.rpc.balance(creator) < needed:
            raise Refusal(
                "sc-owner holds less than 1.31 TOS; fund it first (plan-funding/record-funding)"
            )
        deploy = self.step(
            "sc08x-task-create",
            self.task_create_argv("sc08x", w),
            payer=creator,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "task", "show", "--name", "sc08x")
        self.wait_active(address, "sc08x task")
        send = ["agent", "task", "send", "--name", "sc08x", "--yes"]
        controls = []
        self.step(
            "sc08x-accept",
            send + ["--operation", "accept", "--from", "sc-client"],
            payer=agent,
            observe=address,
            show=show,
        )
        self.step(
            "sc08x-result",
            send
            + [
                "--operation",
                "result",
                "--from",
                "sc-client",
                "--result-hash",
                bindings["result_hash"],
                "--evidence-hash",
                bindings["evidence_hash"],
            ],
            payer=agent,
            observe=address,
            show=show,
        )
        self.step(
            "sc08x-dispute",
            send
            + [
                "--operation",
                "dispute",
                "--from",
                "sc-owner",
                "--dispute-hash",
                bindings["dispute_hash"],
            ],
            payer=creator,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc08x-resolve-agent",
                send + ["--operation", "resolve", "--from", "sc-client", "--payout", "0.4"],
                payer=agent,
                observe=address,
                expect_exit=TASK_RESOLVE_AUTHORITY,
                show=show,
            )
        )
        drill = "sc08x-resolve-verifier"
        attempt = self.journal.attempt_record(drill)
        if attempt and not self.journal.result(drill):
            if attempt.get("kind") != "drill-after-send":
                raise Refusal(
                    f"{drill}: marker without result is not the after-send drill; by hand"
                )
            self.reconcile_attempt(drill)
        resolve = self.step(
            drill,
            send + ["--operation", "resolve", "--from", "sc-verifier", "--payout", "0.4"],
            payer=verifier,
            observe=address,
            show=show,
        )
        final = show()
        bound = all(
            str(final.get(k)) == bindings[k]
            for k in ("result_hash", "evidence_hash", "dispute_hash")
        )
        # The lost-reply coverage is read from the durable resolve record, never from this run's
        # control flow, so a rerun that replays the record reports the same.
        recovered = (
            resolve.get("reconciled_from") == "attempt-without-result"
            and resolve.get("re_sent") is False
        )
        drill_state = "reconciled-after-forward" if recovered else "not-exercised"
        final_ok = (
            final.get("status") == "settled"
            and bound
            and resolve["verdict"] == "settled"
            and recovered
        )
        return {
            "address": address,
            "final_state": final,
            "bindings": bindings,
            "bindings_on_chain": bound,
            "lost_reply_recovered_after_forward": recovered,
            "components": {
                k: norm_addr(v.get("address") or v.get("account")) for k, v in parts.items()
            },
            "lost_reply_drill": drill_state,
            "resolve": {
                "verdict": resolve["verdict"],
                "tx": resolve.get("tx"),
                "in_msg_hash": resolve.get("in_msg_hash"),
                "reconciled_from": resolve.get("reconciled_from"),
                "re_sent": resolve.get("re_sent"),
            },
            **self.verdict(final_ok, controls),
        }

    # ----- wrap-up ------------------------------------------------------------------------
    def return_funds(self, to: str, round_: int = 1) -> dict:
        """Send each actor's balance above its 0.05 TOS floor back to the recorded source (the
        Native Registry payer included once setup-registry recorded it). Each
        return round has its own once-only labels: round 1 keeps the original `return-<wallet>`
        labels, a later round (after further funding) uses `return-<wallet>-r<N>`, so a replay
        of round 1 can never stand in for a later return and a later round can never re-send
        round 1."""
        if round_ < 1:
            raise Refusal("return round must be 1 or higher")
        self.preflight()
        to = norm_addr(to)
        source = self.funding_source()
        if to != source:
            raise Refusal(f"return destination {to} is not the recorded funding source {source}")
        actors = dict(self.actors()["wallets"])
        if (self.evidence / "registry-actors.json").exists():
            # The Native Registry payer is funded from the same source and returns the same way.
            actors[NR_ACTOR] = norm_addr(self.nr_actors()["wallet"])
        out = {}
        keep = tos_to_nanotos("0.05")
        suffix = "" if round_ == 1 else f"-r{round_}"
        for wallet, address in actors.items():
            balance = self.rpc.balance(address)
            if balance <= keep * 2:
                out[wallet] = {"skipped": balance}
                continue
            amount = balance - keep
            rec = self.step(
                f"return-{wallet}{suffix}",
                [
                    "wallet",
                    "send",
                    "--from",
                    wallet,
                    "--to",
                    to,
                    "--amount-nanotos",
                    str(amount),
                    "--bounce",
                    "--yes",
                ],
                payer=address,
                observe=to,
            )
            # A replayed record reports the amount it actually sent, not today's recomputation.
            out[wallet] = {
                "returned_nanotos": int(self.argv_value(rec, "--amount-nanotos")),
                "tx": rec["tx"],
            }
        return out

    def reconcile(self, label: str, external: bool = False, sender: str | None = None) -> dict:
        """Read-only reconciliation of a step that ended `unknown` or `unexpected-abort`.

        Nothing is sent. The payer's single message to the observed contract after the step's
        baseline is located, the contract transaction it produced is read and confirmed on
        every source, and the verdict follows the same rules as a live step: a duplicate
        control (a record naming a `target`) is judged by the duplicate rules, every other
        record by its `expect_exit`. When no message at all left the payer after a CLI
        refusal, the refusal is settled by `reconcile_nothing_sent`. The original record is
        kept; the reconciliation is written beside it and replayed from then on.
        """
        self.preflight(value_action=False)
        done = self.journal.result(label)
        if done is None:
            raise Refusal(f"{label} has no record")
        if done.get("reconciled"):
            raise Refusal(f"{label} was already reconciled")
        if done.get("verdict") not in RECONCILABLE:
            raise Refusal(
                f"{label} ended {done.get('verdict')!r}; only {RECONCILABLE} are reconciled"
            )
        payer, observe = done.get("payer"), done.get("observe")
        before = done.get("before") or {}
        external = (bool(done.get("external")) or external) and sender is None
        duplicate = "target" in done
        if not payer or not observe or "payer_lt" not in before:
            raise Refusal(f"{label} lacks payer/observe/baseline; reconcile by hand")
        if duplicate and (not done.get("target") or "target_balance" not in before):
            raise Refusal(f"{label} is a duplicate control without a target baseline; by hand")
        if sender is not None:
            # The record named the wrong payer: find the contract's single new transaction
            # carrying an internal message from `sender` after the contract's own baseline.
            sender = norm_addr(sender)
            rows = self.rpc.transactions_after(observe, int(before.get("observe_lt") or 0))
            hit = [
                r
                for r in rows
                if (r.get("in_msg") or {}).get("kind") == "internal"
                and same_addr((r.get("in_msg") or {}).get("source"), sender)
            ]
            if len(hit) != 1:
                raise Refusal(f"{label}: {len(hit)} messages from {sender} reached {observe}")
            sends = [None]
            tx = hit[0]
            out_hash = (tx.get("in_msg") or {}).get("hash")
        elif external:
            arrivals = self.external_arrivals(observe, int(before.get("observe_lt") or 0))
            if not arrivals:
                return self.reconcile_nothing_sent(label, done, external=True)
            if len(arrivals) != 1:
                raise Refusal(f"{label}: {len(arrivals)} external messages reached {observe}")
            sends = [None]
            tx = arrivals[0]
            out_hash = (tx.get("in_msg") or {}).get("hash")
        else:
            sends = self.sends_to(payer, int(before["payer_lt"]), observe)
            if not sends:
                return self.reconcile_nothing_sent(label, done, external=False)
            if len(sends) != 1:
                raise Refusal(f"{label}: payer sent {len(sends)} messages to {observe}; by hand")
            out_hash = [
                m["hash"] for m in sends[0]["out_msgs"] if same_addr(m.get("destination"), observe)
            ][0]
            rows = self.rpc.transactions_after(observe, int(before.get("observe_lt") or 0))
            hit = [r for r in rows if (r.get("in_msg") or {}).get("hash") == out_hash]
            if len(hit) != 1:
                raise Refusal(f"{label}: {len(hit)} contract transactions carry the message")
            tx = hit[0]
        compute = tx.get("compute") or {}
        action = tx.get("action")
        confirmations = {
            url: any(
                r["transaction_id"]["hash"] == tx["transaction_id"]["hash"]
                for r in self.rpc.transactions_after(
                    observe, int(before.get("observe_lt") or 0), url
                )
            )
            for url in self.rpc.confirms
        }
        record = dict(done)
        record.update(
            {
                "reconciled": True,
                "reconciled_from_verdict": done.get("verdict"),
                "external": external,
                "sender": sender,
                "payer_tx": (sends[0] or {}).get("transaction_id"),
                "tx": tx["transaction_id"],
                "block_id": tx.get("block_id"),
                "compute": compute,
                "aborted": tx.get("aborted"),
                "action": action,
                "in_msg_hash": out_hash,
                "out_msgs": [
                    {k: m.get(k) for k in ("destination", "value", "bounced", "hash")}
                    for m in tx.get("out_msgs", [])
                ],
                "confirmed_on": confirmations,
                "state_check": "unavailable",
            }
        )
        if not all(confirmations.values()):
            raise Refusal(f"{label}: transaction not seen on every confirmation source")
        expect_exit = int(done.get("expect_exit") or 0)
        if duplicate:
            # Same rules as `duplicate_control`: any transfer to the target is the failure, an
            # aborted account transaction is the intended refusal.
            target = norm_addr(done["target"])
            paid_at = int(before["target_balance"]) + tos_to_nanotos("0.09")
            record["transfers_to_target"] = [
                m for m in record["out_msgs"] if same_addr(m.get("destination"), target)
            ]
            record["target_paid_again"] = self.rpc.balance(target) >= paid_at
            if record["transfers_to_target"] or record["target_paid_again"]:
                record["verdict"] = "DUPLICATE-EXECUTED"
            elif tx.get("aborted") is True and compute.get("success") is False:
                record["verdict"] = "refused-as-intended"
            else:
                record["verdict"] = "accepted-without-transfer"
        elif expect_exit == 0:
            after_balance = self.rpc.balance(observe)
            record["after"] = {**(done.get("after") or {}), "observe_balance": after_balance}
            how = self.positive_outcome(tx, before.get("observe_balance") or 0, after_balance)
            record["settled_as"] = how or None
            record["verdict"] = "settled" if how else "unexpected-abort"
        else:
            ok = (
                tx.get("aborted") is True
                and compute.get("success") is False
                and compute.get("exit_code") == expect_exit
            )
            record["verdict"] = "refused-as-intended" if ok else "refusal-control-failed"
        self.journal.reconciled(label, record)
        self.journal.log(kind="reconciled", label=label, verdict=record["verdict"])
        return record

    def reconcile_nothing_sent(self, label: str, done: dict, external: bool) -> dict:
        """Settle an `unknown` record whose CLI exited non-zero and after which no message is
        visible on any source once the observation window has elapsed.

        This is the read-only form of the live client-side verdicts: nothing left the payer, so
        a duplicate control is a client-side refusal, a negative control is
        `cli-refused-before-broadcast` only while the observed contract has no transaction after
        its baseline, and a positive step is `cli-refused`. Every source must have advanced past
        the record's baseline block, or its empty answer proves nothing. Two cases stay by hand
        on purpose: a successful CLI exit with nothing on chain, and a duplicate control whose
        target was paid although no message from the payer is visible (the live control would
        record DUPLICATE-EXECUTED; here the payment has no located cause, so nothing is written).
        """
        rc = done.get("exit_code")
        if rc in (None, 0):
            raise Refusal(f"{label}: CLI exit {rc!r} but no message is on chain; by hand")
        if now() - from_utc(done.get("utc")) < NOTHING_SENT_SETTLE_S:
            raise Refusal(f"{label}: observation window not elapsed since the record; wait")
        payer, observe = done["payer"], done["observe"]
        before = done.get("before") or {}
        baseline_head = (before.get("head") or {}).get("seqno")
        if baseline_head is None:
            raise Refusal(f"{label}: record has no baseline block; reconcile by hand")
        observe_lt = int(before.get("observe_lt") or 0)
        visible = {}
        for url in self.rpc.all_sources:
            if int(self.rpc.head(url)["seqno"]) <= int(baseline_head):
                raise Refusal(f"{label}: {url} has not advanced past the baseline block; wait")
            if external:
                rows = self.external_arrivals(observe, observe_lt, url)
            else:
                rows = [
                    r
                    for r in self.rpc.transactions_after(payer, int(before["payer_lt"]), url)
                    if any(same_addr(m.get("destination"), observe) for m in r.get("out_msgs", []))
                ]
            visible[url] = len(rows)
        if any(visible.values()):
            raise Refusal(
                f"{label}: a message is visible on some source {visible}; reconcile again"
            )
        record = dict(done)
        record.update(
            {
                "reconciled": True,
                "reconciled_from_verdict": done.get("verdict"),
                "external": external,
                "payer_tx_after": [],
                "nothing_sent_confirmed_on": {url: True for url in visible},
            }
        )
        if "target" in done:
            target = norm_addr(done["target"])
            paid_at = int(before["target_balance"]) + tos_to_nanotos("0.09")
            record["target_paid_again"] = self.rpc.balance(target) >= paid_at
            if record["target_paid_again"]:
                raise Refusal(f"{label}: target balance grew without a located message; by hand")
            record["client_side_refusal_accepted"] = True
            record["verdict"] = "cli-refused-before-broadcast"
        elif int(done.get("expect_exit") or 0) != 0:
            changed = {
                url: len(self.rpc.transactions_after(observe, observe_lt, url))
                for url in self.rpc.all_sources
            }
            if any(changed.values()):
                raise Refusal(f"{label}: {observe} has transactions after the baseline; by hand")
            record["verdict"] = "cli-refused-before-broadcast"
        else:
            record["verdict"] = "cli-refused"
        self.journal.reconciled(label, record)
        self.journal.log(kind="reconciled", label=label, verdict=record["verdict"])
        return record

    def reconcile_attempt(self, label: str) -> dict:
        """Read-only recovery of a step whose process was lost after the CLI returned: the
        attempt marker (argv, payer, baselines) is the durable identity, the exact message after
        the payer's baseline is located on chain and confirmed on every source, and the result
        is written as the step's record so the case replays it. Nothing is re-sent: no message,
        or more than one, stays by hand.
        """
        self.preflight(value_action=False)
        attempt = self.journal.attempt_record(label)
        if attempt is None:
            raise Refusal(f"{label} has no attempt marker")
        if attempt.get("kind") == "registry-send":
            return self.registry_reconcile(label)
        if self.journal.result(label) is not None:
            raise Refusal(f"{label} already has a result")
        payer, observe = attempt.get("payer"), attempt.get("observe")
        before = attempt.get("before") or {}
        if not payer or not observe or "payer_lt" not in before:
            raise Refusal(f"{label}: marker lacks payer/observe/baseline; by hand")
        # The message is located on EVERY source, and every source must name the same message
        # and the same contract transaction, before anything is recorded.
        sources = self.rpc.all_sources
        observe_lt = int(before.get("observe_lt") or 0)
        located: dict[str, int] = {}
        txs: dict[str, dict] = {}
        if attempt.get("external"):
            payer_tx = None
            in_hashes: dict[str, str | None] = {}
            for url in sources:
                arrivals = self.external_arrivals(observe, observe_lt, url)
                located[url] = len(arrivals)
                if len(arrivals) != 1:
                    continue
                txs[url] = arrivals[0]
                in_hashes[url] = (arrivals[0].get("in_msg") or {}).get("hash")
            if any(n != 1 for n in located.values()):
                raise Refusal(f"{label}: external arrivals per source {located}; by hand")
            if len(set(in_hashes.values())) != 1:
                raise Refusal(f"{label}: sources disagree on the inbound message; by hand")
            out_hash = in_hashes[self.rpc.primary]
        else:
            messages = {
                url: self.messages_to(payer, int(before["payer_lt"]), observe, url)
                for url in sources
            }
            located = {url: len(m) for url, m in messages.items()}
            if any(n != 1 for n in located.values()):
                raise Refusal(f"{label}: payer messages to {observe} per source {located}; by hand")
            hashes = {url: m[0][1] for url, m in messages.items()}
            if len(set(hashes.values())) != 1 or hashes[self.rpc.primary] is None:
                raise Refusal(f"{label}: sources disagree on the payer's message; by hand")
            out_hash = hashes[self.rpc.primary]
            payer_tx = messages[self.rpc.primary][0][0]
            for url in sources:
                hit = [
                    r
                    for r in self.rpc.transactions_after(observe, observe_lt, url)
                    if (r.get("in_msg") or {}).get("hash") == out_hash
                ]
                if len(hit) != 1:
                    raise Refusal(
                        f"{label}: {len(hit)} contract transactions carry the message on {url}"
                    )
                txs[url] = hit[0]
        tx_hashes = {url: t["transaction_id"]["hash"] for url, t in txs.items()}
        if len(set(tx_hashes.values())) != 1:
            raise Refusal(f"{label}: sources disagree on the contract transaction; by hand")
        tx = txs[self.rpc.primary]
        confirmations = {url: True for url in self.rpc.confirms}
        compute = tx.get("compute") or {}
        after_balance = self.rpc.balance(observe)
        record = {k: v for k, v in attempt.items() if k != "kind"}
        record.update(
            {
                "exit_code": None,
                "reconciled_from": "attempt-without-result",
                "re_sent": False,
                "payer_tx": (payer_tx or {}).get("transaction_id"),
                "tx": tx["transaction_id"],
                "block_id": tx.get("block_id"),
                "compute": compute,
                "aborted": tx.get("aborted"),
                "action": tx.get("action"),
                "in_msg_hash": out_hash,
                "out_msgs": [
                    {k: m.get(k) for k in ("destination", "value", "bounced", "hash")}
                    for m in tx.get("out_msgs", [])
                ],
                "confirmed_on": confirmations,
                "located_per_source": located,
                "after": {"observe_balance": after_balance},
            }
        )
        expect_exit = int(attempt.get("expect_exit") or 0)
        if expect_exit == 0:
            how = self.positive_outcome(tx, before.get("observe_balance") or 0, after_balance)
            record["settled_as"] = how or None
            record["verdict"] = "settled" if how else "unexpected-abort"
        else:
            ok = (
                tx.get("aborted") is True
                and compute.get("success") is False
                and compute.get("exit_code") == expect_exit
            )
            record["verdict"] = "refused-as-intended" if ok else "refusal-control-failed"
        self.journal.done(label, record)
        self.journal.log(kind="reconciled-attempt", label=label, verdict=record["verdict"])
        record["label"] = label
        return record

    def status(self) -> dict:
        actors = self.actors() if self.actors_path.exists() else {}
        balances = {n: self.rpc.balance(a) for n, a in actors.get("wallets", {}).items()}
        steps = sorted(p.name for p in self.journal.steps.glob("*.json"))
        return {"funded_total_nanotos": self.funded_total(), "balances": balances, "steps": steps}


class PlanRunner(Runner):
    """A dry pass over a case: records every CLI argument vector and sends nothing."""

    def __init__(self, args: argparse.Namespace, wallets: dict):
        self.args = args
        self.wallets = dict(wallets)
        self.recorded: list[dict] = []
        self.fake = "0:" + "0f" * 32

    def guards(self) -> dict:
        return {}

    def local(self, label, *argv, want_json=False, format_flag=True):
        # The flag check must see what the CLI receives, including the implicit --format json.
        implicit = ["--format", "json"] if want_json and format_flag else []
        self.recorded.append({"label": label, "argv": [*argv, *implicit], "value": False})
        return {"address": self.fake, "result": {"address": self.fake}} if want_json else None

    def step(
        self, label, argv, payer, observe, expect_exit=0, want_json=False, show=None, external=False
    ):
        implicit = ["--format", "json"] if want_json else []
        self.recorded.append(
            {
                "label": label,
                "argv": [*argv, *implicit],
                "value": True,
                "payer": payer,
                "external": external,
                "expect_exit": expect_exit,
            }
        )
        return {
            "label": label,
            "observe": observe or self.fake,
            "argv": list(argv),
            "verdict": "settled" if expect_exit == 0 else "refused-as-intended",
        }

    def show(self, *argv):
        return lambda: {
            "status": "settled",
            "ruling": "claimant",
            "revoked": True,
            "has_attestation": False,
            "active": False,
            "reputation_score": 10,
            "next_request_id": 1,
            "pending_count": 0,
            "withdrawable_revenue": 250_000_000,
        }

    def wait(self, predicate, timeout=None):
        return True

    def wait_active(self, address, what):
        return None

    def quorum_configs(self):
        return ["/plan/quorum-1.json", "/plan/quorum-2.json"]

    def retry_label(self, label):
        return label

    def sc03e_prepare_label(self):
        return "sc03e-prepare"

    def nr_require_deploy_gate(self):
        return Path("/plan/testnet-global.config.json")

    def nr_build(self, label, *argv):
        self.local(
            label,
            "agent",
            "native-registry",
            *argv,
            "--global-config",
            "/plan/testnet-global.config.json",
            "--network-label",
            NR_LABEL,
            want_json=True,
        )
        fake = self.fake
        return {
            "destination": fake,
            "final_target": fake,
            "body_boc": "plan",
            "action_hash": "00" * 32,
            "generation": 1,
            "sequence": 1,
        }

    def registry_send(self, label, built, *, bounce, expect_exit=0, body_boc=None):
        self.recorded.append(
            {
                "label": label,
                "argv": ["wallet", "send", "--build-only"],
                "value": True,
                "payer": NR_ACTOR,
                "expect_exit": expect_exit,
            }
        )
        return {
            "label": label,
            "verdict": "settled" if expect_exit == 0 else "refused-as-intended",
            "expect_exit": expect_exit,
        }

    def nr_show(self, address):
        return {"tombstone": True}

    def nr_flip_body(self, body_boc):
        return body_boc

    def duplicate_control(self, label, argv, payer, account, target, external=False):
        self.recorded.append(
            {"label": label, "argv": list(argv), "value": True, "payer": payer, "expect_exit": -1}
        )
        return {"label": label, "verdict": "refused-as-intended"}

    def refusal_broadcast(self, label, msg, account, expect_exit, raw=None, licence=None):
        return {"label": label, "verdict": "refused-at-admission", "expect_exit": expect_exit}

    def agreed_agent_state(self, account):
        return {"seqno": 3, "controller_epoch": 1, "spent_today": 0}

    def expiry_probe_path(self):
        return Path("/plan/exports/sc03e-expiry.boc")

    def check_prepared(self, answer, action_id, account, state, valid_until):
        return {
            "seqno": state["seqno"],
            "controller_epoch": state["controller_epoch"],
            "valid_until": valid_until,
            "exact_signed_boc_digest": "sha256:" + "00" * 32,
        }

    def wait_chain_past(self, deadline, account):
        return {}

    def read_expiry_probe(self, path, prepared, account):
        return b"", boc_decode(base64.b64decode(SAMPLE_AGENT_REQUEST_BOC))

    def sc03_original_message(self, account):
        msg = boc_decode(base64.b64decode(SAMPLE_AGENT_REQUEST_BOC))
        return {
            "label": "sc03-task-send-2-retry",
            "tx": None,
            "in_msg_hash": cell_hash_b64(msg),
        }, msg

    def agent_account_state(self, account, url=None):
        # Each read of the planner's stand-in account moves the controller epoch forward, so
        # the SC-03x plan passes its own rotation check without reaching the chain.
        self.plan_epoch = getattr(self, "plan_epoch", 0) + 1
        return {"seqno": 3, "controller_epoch": self.plan_epoch, "spent_today": 0}

    def component_bindings(self, parts):
        return {k: "00" * 32 for k in ("result_hash", "evidence_hash", "dispute_hash")}

    def reconcile_attempt(self, label):
        return {"label": label, "verdict": "settled"}

    @property
    def rpc(self):
        return _PlanRpc()

    @property
    def journal(self):
        return _PlanJournal()

    @property
    def evidence(self):
        return _PlanEvidence()


class _PlanRpc:
    def balance(self, address):
        return 10 * NANO

    def state(self, address):
        return "active"

    def last_lt(self, address, url=None):
        return 0

    def transactions_after(self, address, lt, url=None):
        return []


class _PlanJournal:
    def result(self, label):
        return None

    def attempted(self, label):
        return False

    def attempt_record(self, label):
        return None

    def attempt(self, label, record):
        return None

    def done(self, label, record):
        return None


class _PlanEvidence:
    def __truediv__(self, name):
        return _PlanPart(name)


class _PlanPart:
    def __init__(self, name):
        self.name = name

    def exists(self):
        return True

    def read_text(self):
        fake = "0:" + "0f" * 32
        # The stand-in SC-03 account is the destination of the sample request, so the plan
        # passes the same destination check as a live run.
        sample = boc_decode(base64.b64decode(SAMPLE_AGENT_REQUEST_BOC))
        account = external_message_parts(sample)["destination"]
        return json.dumps({"address": fake, "account": account, "agent_wallet": fake, "pass": True})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--private-dir", required=True)
    p.add_argument("--evidence-dir", required=True)
    p.add_argument("--cli", required=True)
    p.add_argument("--cli-sha256", required=True)
    p.add_argument("--rpc", required=True, help="broadcast + primary read JSON-RPC URL")
    p.add_argument("--confirm-rpc", action="append", default=[])
    p.add_argument("--genesis-root", required=True)
    p.add_argument("--genesis-file", required=True)
    p.add_argument("--stop-ceiling", default="20", help="hard cumulative funding ceiling, TOS")
    p.add_argument(
        "--flag-fixture",
        default=str(FLAG_FIXTURE),
        help="JSON of the pinned CLI's accepted flags per command; required for `case`",
    )
    p.add_argument("--skip-thermal", action="store_true")
    p.add_argument(
        "--registry-global-config",
        default=None,
        help="testnet global config for the Native Registry domain (sha256 pinned)",
    )
    p.add_argument(
        "--allow-registry-deploy",
        action="store_true",
        help="explicit opt-in for the registry case (needs the owner's deployment ruling)",
    )
    p.add_argument("--date", default=time.strftime("%Y%m%d", time.gmtime()))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    sub.add_parser("setup")
    pf = sub.add_parser("plan-funding")
    pf.add_argument("--funding-source", required=True, help="pool-owner address funds come from")
    rf = sub.add_parser("record-funding")
    rf.add_argument("--actor", required=True)
    rf.add_argument("--amount", required=True)
    rf.add_argument("--operation-id", required=True)
    sub.add_parser("activate")
    pl = sub.add_parser("plan")
    pl.add_argument("name")
    c = sub.add_parser("case")
    c.add_argument("name")
    r = sub.add_parser("return-funds")
    r.add_argument("--to", required=True)
    r.add_argument("--round", type=int, default=1, help="return round; 2+ after further funding")
    sub.add_parser("status")
    sub.add_parser("setup-registry")
    sub.add_parser("activate-registry")
    rc = sub.add_parser("reconcile")
    rc.add_argument("label")
    rc.add_argument(
        "--external",
        action="store_true",
        help="the step's command was signed for the contract itself (no wallet send)",
    )
    rc.add_argument(
        "--from",
        dest="sender",
        default=None,
        help="the wallet that actually sent the message, when the record named another",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = Runner(args)
    try:
        if args.command == "preflight":
            out = runner.preflight()
        elif args.command == "setup":
            out = runner.setup()
        elif args.command == "plan-funding":
            out = runner.plan_funding(args.funding_source)
        elif args.command == "record-funding":
            out = runner.record_funding(args.actor, args.amount, args.operation_id)
        elif args.command == "activate":
            out = runner.activate()
        elif args.command == "plan":
            out = runner.plan(args.name)
        elif args.command == "case":
            out = runner.case(args.name)
        elif args.command == "return-funds":
            out = runner.return_funds(args.to, args.round)
        elif args.command == "setup-registry":
            out = runner.setup_registry()
        elif args.command == "activate-registry":
            out = runner.activate_registry()
        elif args.command == "reconcile":
            out = runner.reconcile(args.label, external=args.external, sender=args.sender)
        else:
            out = runner.status()
    except Refusal as exc:
        reason = str(exc).replace(str(runner.private), "<private>")
        runner.journal.log(kind="refusal", command=args.command, reason=reason)
        print(json.dumps({"refused": reason}, indent=2))
        return 3
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - journaled, then surfaced as a distinct exit code
        error = repr(exc).replace(str(runner.private), "<private>")
        runner.journal.log(kind="error", command=args.command, error=error)
        print(json.dumps({"error": error}, indent=2))
        return 2
    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
