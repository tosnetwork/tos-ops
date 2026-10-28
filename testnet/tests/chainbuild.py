"""Builders of the chain structures the sweep checks read, in their TL-B layouts
(crypto/block/block.tlb): ConfigParam 5, a post-quantum validator set (ConfigParam
32/34), the Elector's data, and a block with its ValueFlow and account blocks.

The readers these feed are checked against real bytes elsewhere (a create-state
zero state and a real masterchain block in data/); these builders make the cases a
real capture does not have, such as a burn, a missing stake or an unbalanced flow.
"""

from __future__ import annotations

import base64
import hashlib
import os

import testnet_lib as lib
from fakechain import coins_bits


def bits(value: int, width: int) -> str:
    return format(value & ((1 << width) - 1), f"0{width}b")


def cc(nanotos: int) -> str:
    """A CurrencyCollection without extra currencies."""
    return coins_bits(nanotos) + "0"


def burning_config(blackhole: str | None = "ff" * 32, num: int = 0, denom: int = 1) -> lib.Cell:
    body = "1" + bits(int(blackhole, 16), 256) if blackhole is not None else "0"
    return lib.cell_from_bits(bits(0x01, 8) + body + bits(num, 32) + bits(denom, 32))


def _node(keys: dict[str, tuple[str, list]], m: int, fork_extra: str | None) -> tuple[str, list]:
    """(bits, refs) of a Hashmap(Aug) edge of key width m whose leaves are given as
    {key bits: (value bits, value refs)}; with fork_extra, a HashmapAug."""
    label = os.path.commonprefix(list(keys))
    width = m.bit_length()
    head = "10" + (format(len(label), f"0{width}b") if width else "") + label
    rest = m - len(label)
    if rest == 0:
        value_bits, value_refs = next(iter(keys.values()))
        return head + value_bits, list(value_refs)
    children = []
    for branch in "01":
        sub = {k[len(label) + 1 :]: v for k, v in keys.items() if k[len(label)] == branch}
        child_bits, child_refs = _node(sub, rest - 1, fork_extra)
        children.append(lib.cell_from_bits(child_bits, child_refs))
    return head + (fork_extra or ""), children


def hashmap(entries: dict[int, tuple[str, list]], n: int) -> lib.Cell:
    """A non-empty Hashmap n X with X inline: key -> (bits, refs)."""
    keys = {format(k, f"0{n}b"): v for k, v in entries.items()}
    return lib.cell_from_bits(*_node(keys, n, None))


def aug_parts(entries: dict[int, tuple[str, list]], n: int, fork_extra: str) -> tuple[str, list]:
    """A HashmapAug n X Y edge, inline: key -> (leaf extra + value bits, refs)."""
    keys = {format(k, f"0{n}b"): v for k, v in entries.items()}
    return _node(keys, n, fork_extra)


def pq_key(seed: bytes) -> bytes:
    return hashlib.shake_256(b"pq-key-" + seed).digest(lib.PQ_PUBLIC_KEY_BYTES)


def pq_key_root(raw: bytes) -> lib.Cell:
    chunks = [raw[i : i + 127] for i in range(0, len(raw), 127)]
    cell = None
    for chunk in reversed(chunks):
        cell = lib.cell_from_bits(
            "".join(bits(b, 8) for b in chunk), [cell] if cell is not None else []
        )
    return lib.cell_from_bits(bits(len(raw), 32), [cell])


def validator_set(validator_ids: list[str], since: int, until: int, weight: int = 1000) -> lib.Cell:
    """validators_ext#12 of post-quantum descriptors (0xB3) for these validator ids."""
    entries = {}
    for index, validator in enumerate(validator_ids):
        raw = pq_key(bytes.fromhex(validator))
        entry = bits(0xB3, 8) + bits(int(validator, 16), 256) + bits(1, 16)
        entry += bits(int(lib.pq_key_id(raw).hex(), 16), 256) + bits(weight, 64)
        entry += bits(int(hashlib.sha256(raw).hexdigest(), 16), 256)
        entries[index] = (entry, [pq_key_root(raw)])
    total = len(validator_ids)
    head = bits(0x12, 8) + bits(since, 32) + bits(until, 32) + bits(total, 16) + bits(total, 16)
    head += bits(weight * total, 64) + "1"
    return lib.cell_from_bits(head, [hashmap(entries, 16)])


def elector_data(past: list[dict]) -> lib.Cell:
    """The Elector's data as network_check.decode_elector reads it: no open election,
    no credits, and `past` elections, each {election_id, set (a validator_set cell),
    members: {validator id: (stake, banned)}}."""
    elections = {}
    for election in past:
        members = {
            int(validator, 16): (
                bits(0, 256) + bits(1000, 64) + coins_bits(stake) + ("1" if banned else "0"),
                [],
            )
            for validator, (stake, banned) in election["members"].items()
        }
        value = bits(election["election_id"] + 3600, 32) + bits(3600, 32)
        value += bits(int(election["set"].hash().hex(), 16), 256)
        refs = []
        if members:
            value += "1"
            refs.append(hashmap(members, 256))
        else:
            value += "0"
        value += coins_bits(sum(s for s, _ in election["members"].values())) + coins_bits(0) + "0"
        elections[election["election_id"]] = (value, refs)
    head = "0" + "0"
    refs = []
    if elections:
        head += "1"
        refs.append(hashmap(elections, 32))
    else:
        head += "0"
    head += coins_bits(0) + bits(0, 32) + bits(0, 256)
    return lib.cell_from_bits(head, refs)


def value_flow(flow: dict, v2: bool = True) -> lib.Cell:
    first = lib.cell_from_bits(
        "".join(cc(flow[k]) for k in ("from_prev_blk", "to_next_blk", "imported", "exported"))
    )
    second = lib.cell_from_bits(
        "".join(cc(flow[k]) for k in ("fees_imported", "recovered", "created", "minted"))
    )
    tag = lib.VALUE_FLOW_V2_TAG if v2 else lib.VALUE_FLOW_TAG
    body = bits(tag, 32) + cc(flow["fees_collected"]) + (cc(flow["burned"]) if v2 else "")
    return lib.cell_from_bits(body, [first, second])


def balanced_flow(burned: int, previous: int | None = None) -> dict:
    """A masterchain flow that balances with `burned` leaving the chain."""
    previous = burned + 81_151 * 10**9 if previous is None else previous
    created = 39_496_630
    return {
        "from_prev_blk": previous,
        "to_next_blk": previous + created - burned,
        "imported": 0,
        "exported": 0,
        "fees_collected": 0,
        "burned": burned,
        "fees_imported": 0,
        "recovered": 0,
        "created": created,
        "minted": 0,
    }


def block(
    global_id: int,
    seqno: int,
    start_lt: int,
    end_lt: int,
    flow: dict,
    transactions: dict[str, dict[int, lib.Cell]],
    v2: bool = True,
    workchain: int = lib.MASTERCHAIN,
) -> bytes:
    """A block's file: BlockInfo, ValueFlow, a stand-in state update and BlockExtra
    whose account blocks hold `transactions` (account hex -> {lt: transaction cell})."""
    info = bits(lib.BLOCK_INFO_TAG, 32) + bits(0, 32)
    info += ("1" if workchain != lib.MASTERCHAIN else "0") + "0" * 7 + bits(0, 8)
    info += bits(seqno, 32) + bits(0, 32)
    info += "00" + bits(0, 6) + bits(workchain, 32) + bits(0, 64)
    info += bits(1_800_000_000, 32) + bits(start_lt, 64) + bits(end_lt, 64)
    accounts = {}
    for account, txs in transactions.items():
        if not txs:
            continue  # an AccountBlock holds at least one transaction
        inner_bits, inner_refs = aug_parts(
            {lt: (cc(0), [cell]) for lt, cell in txs.items()}, 64, cc(0)
        )
        value_bits = cc(0) + bits(0x5, 4) + bits(int(account, 16), 256) + inner_bits
        accounts[int(account, 16)] = (value_bits, inner_refs + [lib.cell_from_bits("")])
    if accounts:
        root_bits, root_refs = aug_parts(accounts, 256, cc(0))
        account_blocks = lib.cell_from_bits("1" + cc(0), [lib.cell_from_bits(root_bits, root_refs)])
    else:
        account_blocks = lib.cell_from_bits("0" + cc(0))
    extra = lib.cell_from_bits(
        bits(lib.BLOCK_EXTRA_TAG, 32) + bits(0, 512) + "0",
        [lib.cell_from_bits("0"), lib.cell_from_bits("0"), account_blocks],
    )
    root = lib.cell_from_bits(
        bits(lib.BLOCK_TAG, 32) + bits(global_id, 32),
        [lib.cell_from_bits(info), value_flow(flow, v2), lib.cell_from_bits("1" * 8), extra],
    )
    return lib.serialize_boc(root)


def tx_cell(tx: dict) -> lib.Cell:
    """The transaction cell of a fake chain's transaction record."""
    return lib.parse_boc(base64.b64decode(tx["data"]))
