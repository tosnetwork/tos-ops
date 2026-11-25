#!/usr/bin/env python3
"""Change a configuration parameter by a vote of the validators (coordinator side).

  propose  --ceremony DIR --tos-root DIR --fift PATH --rpc URL --confirm-rpc URL
           --payer-key FILE --payer-addr FILE --payer-subwallet N
           --param N --value-boc FILE [--expire-seconds S] [--id ID] [--dry-run]
      Register a proposal with the Config contract (-1:55..55) to set ConfigParam N
      to the cell in FILE. The proposal binds the current value's hash, so it can
      only replace the value it was made against. A parameter that ConfigParam 10
      lists is registered as critical (the contract refuses it otherwise); the
      storage price follows ConfigParam 11 and is paid from the payer, a wallet v3 in
      the masterchain (only masterchain senders reach the Config contract). The
      transfer is an ordinary journaled operation (testnet_ops): one intent, one
      broadcast, settled on both validators; it then counts only if the Config
      contract lists the proposal.

      ConfigParam 84 (recognized settlement assets) is refused unless ConfigParam 10
      lists it, the value decodes strictly (tags, statuses, origin kinds, no
      trailing data), holds at most 16 entries and fits the node's 1,024-cell
      validation budget, changes exactly one entry of the current value, no other
      ConfigParam 84 proposal and no bridge address change is pending, and
      --node-release-evidence FILE has exactly one row per member of the current
      set (ConfigParam 34), keyed by its consensus public key (the Ed25519 key, or
      the PQ key_id), each observed after the set took office and within 24 hours,
      each naming a tos commit whose block.tlb defines ConfigParam 84 (a node
      without that schema halts on any ConfigParam 84). A row is the operator's
      attested `tos-validator-engine -V` output: this tool cannot prove which
      binary a remote host runs. A token bridge parameter (79, 81, 82, 83) whose
      bridge address changes is refused while ConfigParam 84 still lists an
      active asset of the old bridge, or while a ConfigParam 84 proposal is
      pending. These ordering rules are checked again before each round's votes
      are signed and sent. An absent parameter is proposed with the Config
      contract's absent-value hash (zero) as its precondition, so a first
      installation cannot overwrite a concurrent one. Proposing a value that is
      already registered resumes that proposal.

  sign     --ceremony DIR --inventory FILE --rpc URL --proposal HASH [--host NAME]...
      On each validator host, the node's console signs a vote for the proposal
      (`create-proposal-vote`) under the current validator set. Only the vote body
      leaves the host. The votes and the ConfigParam 34 they were signed under are
      written to DIR/governance/<proposal>/round-<set>.json.

  sign     --ceremony DIR --local-network FILE --rpc URL --proposal HASH
      The same on the local development network: each local validator's console
      (its port in testnet-ports.json, its client key under elections/) signs; a
      node outside the current set is skipped, and every member must sign.

  --local-network FILE (before the command) runs propose and vote against the
      local development network that FILE (its network.json) describes, instead
      of the testnet profile: the global id is the local one, and the ceremony
      directory's genesis.json is the local zero state.

  vote     --ceremony DIR --tos-root DIR --fift PATH --rpc URL --confirm-rpc URL
           --payer-key FILE --payer-addr FILE --payer-subwallet N --proposal HASH
      Deliver the current round's votes one at a time, each as its own journaled
      operation with 0.6 TOS attached (the contract pays the verification from it
      and returns the rest). Refused when the validator set changed since the votes
      were signed (a vote is bound to its set), and a validator that already voted
      in this round is skipped. Stops when the round is won.

  status   --rpc URL --proposal HASH
      The proposal as the Config contract stores it: critical flag, parameter,
      remaining weight, rounds left, wins and losses (or "absent").

  adopted  --rpc URL --confirm-rpc URL [--also-rpc URL]... --param N --value-boc FILE
      Exit 0 only if every named node (both validators and each --also-rpc)
      serves ConfigParam N equal to FILE.

A proposal needs ConfigParam 11's min_wins winning rounds (2 ordinary, 3 critical),
each under a different validator set, and a round is won when votes of more than
3/4 of the set's weight arrive. Votes must be signed again after every rotation.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import testnet_lib as lib  # noqa: E402
import testnet_ops as ops  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "testnet_elections_for_governance", HERE / "testnet-elections.py"
)
elections = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(elections)

CONFIG_ADDRESS = "-1:" + "55" * 32
REGISTER_OP = 0x6E565052
VOTE_OP = 0x5051766F
PROPOSAL_TAG = 0xF3
VOTE_VALUE = 600_000_000
# The contract keeps the price and requires at least 2^30 nanotos beyond it.
REGISTER_HEADROOM = (1 << 30) + 500_000_000
CONSOLE = (
    "validator-engine-console -a 127.0.0.1:30002 "
    "-k /var/lib/tos/validator/console-client/client "
    "-p /var/lib/tos/validator/console-client/server.pub"
)
LOCAL_CONSOLE = "/usr/local/bin/tos-validator-console"

# ConfigParam 84, the recognized settlement assets (tos crypto/block/block.tlb).
SETTLEMENT_ASSETS_PARAM = 84
SETTLEMENT_ASSETS_TAG = 0x01
SETTLEMENT_ASSET_TAG = 0x01
SETTLEMENT_ASSETS_MAX_ENTRIES = 16
# check_one_config_param validates each parameter against 1,024 cells; a value
# over it is refused when installed and the masterchain halts.
CONFIG_PARAM_VALIDATION_CELLS = 1024
ASSET_STATUSES = {1: "active", 2: "admission_suspended", 3: "retired"}
ORIGIN_KINDS = {1: "token_bridge", 2: "native_issuance"}
ORIGIN_BITS = 8 + 256 + 32 + 160
# Each token bridge parameter serves one source chain (tos crosschain/token-bridge/tvm/params).
TOKEN_BRIDGE_PARAMS = {79: 1, 81: 56, 82: 137, 83: 728126428}
# The schema line a node release must carry before any ConfigParam 84 value.
SETTLEMENT_ASSETS_SCHEMA_LINE = "= ConfigParam 84;"
# The hash the Config contract compares a precondition with when a parameter is absent.
ABSENT_VALUE_HASH = bytes(32)


# ---------------------------------------------------------------- cells


def uint_bits(value: int, width: int) -> str:
    if not 0 <= value < (1 << width):
        raise lib.TestnetError(f"{value} does not fit {width} bits")
    return format(value, f"0{width}b")


def int_bits(value: int, width: int) -> str:
    if not -(1 << (width - 1)) <= value < (1 << (width - 1)):
        raise lib.TestnetError(f"{value} does not fit a signed {width}-bit field")
    return uint_bits(value % (1 << width), width)


def proposal_cell(param: int, value: lib.Cell, current_hash: bytes | None) -> lib.Cell:
    """cfg_proposal#f3 param_id:int32 param_value:(Maybe ^Cell) if_hash_equal:(Maybe uint256)"""
    bits = uint_bits(PROPOSAL_TAG, 8) + int_bits(param, 32) + "1"
    if current_hash is None:
        bits += "0"
    else:
        if len(current_hash) != 32:
            raise lib.TestnetError("the current value hash is 32 bytes")
        bits += "1" + uint_bits(int.from_bytes(current_hash, "big"), 256)
    return lib.cell_from_bits(bits, [value])


def register_body(
    query_id: int, expire_seconds: int, proposal: lib.Cell, critical: bool
) -> lib.Cell:
    """new_voting_proposal: op, query_id, expire_at (relative while < 2^30), ^proposal, critical."""
    if not 0 < expire_seconds < (1 << 30):
        raise lib.TestnetError("expire_seconds is a positive relative time below 2^30")
    bits = (
        uint_bits(REGISTER_OP, 32)
        + uint_bits(query_id, 64)
        + uint_bits(expire_seconds, 32)
        + ("1" if critical else "0")
    )
    return lib.cell_from_bits(bits, [proposal])


def tree_size(root: lib.Cell) -> tuple[int, int]:
    """(bits, refs) over the distinct cells of a tree, as compute_data_size counts them."""
    seen: dict[bytes, lib.Cell] = {}
    stack = [root]
    while stack:
        cell = stack.pop()
        h = cell.hash()
        if h in seen:
            continue
        seen[h] = cell
        stack.extend(cell.refs)
    return sum(c.bits for c in seen.values()), sum(len(c.refs) for c in seen.values())


def parse_vote_setup(cp11: lib.Cell, critical: bool) -> dict[str, int]:
    """cfg_vote_setup#91 normal_params:^ConfigProposalSetup critical_params:^ConfigProposalSetup"""
    s = lib.Slice(cp11)
    if s.bits(8) != 0x91:
        raise lib.TestnetError("ConfigParam 11 is not cfg_vote_setup#91")
    setup = lib.Slice(cp11.refs[1] if critical else cp11.refs[0])
    if setup.bits(8) != 0x36:
        raise lib.TestnetError("ConfigProposalSetup is not cfg_vote_cfg#36")
    names = ("min_tot_rounds", "max_tot_rounds", "min_wins", "max_losses")
    out = {n: setup.bits(8) for n in names}
    for n in ("min_store_sec", "max_store_sec", "bit_price", "cell_price"):
        out[n] = setup.bits(32)
    return out


def proposal_price(value: lib.Cell, setup: dict[str, int], expire_seconds: int) -> int:
    """The price register_voting_proposal keeps (config-code.fc), in nanotos."""
    if expire_seconds < setup["min_store_sec"]:
        raise lib.TestnetError(
            f"the proposal must be kept at least {setup['min_store_sec']} s (ConfigParam 11)"
        )
    kept = min(expire_seconds, setup["max_store_sec"])
    bits, refs = tree_size(value)
    return (setup["bit_price"] * (bits + 1024) + setup["cell_price"] * (refs + 2)) * kept


def signed_keys(cell: lib.Cell | None, width: int = 32) -> set[int]:
    if cell is None:
        return set()
    keys = lib.hashmap_items(cell, width)
    return {k - (1 << width) if k >> (width - 1) else k for k in keys}


def parse_vote(boc: bytes, proposal: str) -> tuple[int, lib.Cell]:
    """The console's vote body: op, query_id, idx:uint16, proposal:uint256, ^signature."""
    cell = lib.parse_boc(boc)
    s = lib.Slice(cell)
    if s.bits(32) != VOTE_OP:
        raise lib.TestnetError("the console's answer is not a configuration vote")
    s.bits(64)
    idx = s.bits(16)
    if f"{s.bits(256):064x}" != proposal:
        raise lib.TestnetError("the vote is for another proposal")
    if len(cell.refs) != 1 or s.remaining() != 0:
        raise lib.TestnetError("the vote body has an unexpected shape")
    return idx, cell


# ---------------------------------------------------------------- ConfigParam 84


def validation_visits(root: lib.Cell, limit: int = CONFIG_PARAM_VALIDATION_CELLS) -> int:
    """The cells the node's validate_ref visits: every reference is a visit, so a
    cell reached twice counts twice. Refuses a value above `limit`."""
    visits, pending = 0, [root]
    while pending:
        cell = pending.pop()
        if cell.exotic:
            raise lib.TestnetError("a configuration value holds an exotic cell")
        visits += 1
        if visits > limit:
            raise lib.TestnetError(
                f"the value needs more than {limit} cells of validation; "
                "the node would refuse to install it and the masterchain would halt"
            )
        pending.extend(cell.refs)
    return visits


def read_coins(s: lib.Slice) -> int:
    """Coins with a minimal length, as the node's decoder requires."""
    length = s.bits(4)
    value = s.bits(8 * length)
    if length and value >> (8 * length - 8) == 0:
        raise lib.TestnetError("a Coins value has a non-minimal length")
    return value


def decode_settlement_asset(s: lib.Slice) -> dict:
    """settlement_asset_v1#01: decoded exactly, refusing anything the node or a reader
    would not reproduce."""
    if s.bits(8) != SETTLEMENT_ASSET_TAG:
        raise lib.TestnetError("ConfigParam 84: unknown settlement asset tag")
    status = s.bits(8)
    if status not in ASSET_STATUSES:
        raise lib.TestnetError(f"ConfigParam 84: undefined status {status}")
    decimals = s.bits(8)
    minter_code_hash = s.bytes(32).hex()
    wallet_code_hash = s.bytes(32).hex()
    cap = read_coins(s)
    if cap == 0:
        raise lib.TestnetError("ConfigParam 84: max_liability_per_actor must be non-zero")
    if s.remaining() != 0 or len(s.cell.refs) - s.ref != 1:
        raise lib.TestnetError("ConfigParam 84: a record carries trailing data")
    origin = s.take_ref()
    if origin.bits != ORIGIN_BITS or origin.refs:
        raise lib.TestnetError(f"ConfigParam 84: the origin cell is not exactly {ORIGIN_BITS} bits")
    o = lib.Slice(origin)
    kind = o.bits(8)
    if kind not in ORIGIN_KINDS:
        raise lib.TestnetError(f"ConfigParam 84: undefined origin kind {kind}")
    return {
        "status": ASSET_STATUSES[status],
        "decimals": decimals,
        "minter_code_hash": minter_code_hash,
        "wallet_code_hash": wallet_code_hash,
        "max_liability_per_actor": str(cap),
        "origin": {
            "kind": ORIGIN_KINDS[kind],
            "bridge_address": o.bytes(32).hex(),
            "source_chain_id": o.bits(32),
            "source_token": o.bytes(20).hex(),
        },
    }


def strict_hashmap_items(root: lib.Cell, key_bits: int) -> dict[int, lib.Slice]:
    """Every entry of a Hashmap key_bits X, decoded exactly (tos crypto/block/block.tlb):
    hm_edge is a label of at most the remaining key length, then a node; hmn_fork
    is exactly two references and nothing after the label; hmn_leaf is the value,
    handed back as a slice positioned after the label for the caller to consume
    exactly. Anything else, a trailing bit or a third reference at a fork
    included, is refused."""
    items: dict[int, lib.Slice] = {}
    pending = [(root, 0, key_bits)]
    while pending:
        node, prefix, left = pending.pop()
        if node.exotic:
            raise lib.TestnetError("a dictionary holds an exotic cell")
        s = lib.Slice(node)
        label, length = lib.hashmap_label(s, left)
        prefix, left = (prefix << length) | label, left - length
        if left == 0:
            items[prefix] = s
            continue
        if s.remaining() != 0 or len(node.refs) != 2:
            raise lib.TestnetError(
                "a dictionary fork must hold exactly its label and two references"
            )
        for branch in (0, 1):
            pending.append((node.refs[branch], (prefix << 1) | branch, left - 1))
    return items


def decode_settlement_assets(cell: lib.Cell) -> dict[str, dict]:
    """settlement_assets_v1#01 assets:(HashmapE 256 SettlementAssetV1): every entry,
    keyed by the master's account id. Refuses a malformed value, more than 16
    entries and a value over the validation budget, the checks proposal tooling
    owes the node (design 3.1)."""
    validation_visits(cell)
    s = lib.Slice(cell)
    if s.bits(8) != SETTLEMENT_ASSETS_TAG:
        raise lib.TestnetError("ConfigParam 84: not settlement_assets_v1#01")
    present = s.bits(1)
    if s.remaining() != 0 or len(cell.refs) != present:
        raise lib.TestnetError("ConfigParam 84: the value carries trailing data")
    if not present:
        return {}
    entries = strict_hashmap_items(cell.refs[0], 256)
    if len(entries) > SETTLEMENT_ASSETS_MAX_ENTRIES:
        raise lib.TestnetError(
            f"ConfigParam 84: {len(entries)} entries, more than {SETTLEMENT_ASSETS_MAX_ENTRIES}"
        )
    return {f"{key:064x}": decode_settlement_asset(value) for key, value in entries.items()}


def settlement_assets_change(current: dict[str, dict], new: dict[str, dict]) -> dict:
    """The one entry a proposal changes. ConfigParam 84 is one value, so two
    proposals made from the same old value would drop each other's entry: a
    change touching more or fewer than one entry is refused (design 3.1)."""
    touched = sorted(
        master for master in set(current) | set(new) if current.get(master) != new.get(master)
    )
    if len(touched) != 1:
        raise lib.TestnetError(
            f"a ConfigParam 84 proposal must change exactly one entry; this one changes {len(touched)}"
        )
    master = touched[0]
    action = "add" if master not in current else "remove" if master not in new else "change"
    return {
        "master": master,
        "action": action,
        "before": current.get(master),
        "after": new.get(master),
    }


def bridge_address_of(cell: lib.Cell | None) -> str | None:
    """The bridge_address of a TokenBridgeParams value (v0 #00 or v1 #01)."""
    if cell is None:
        return None
    s = lib.Slice(cell)
    if s.bits(8) not in (0x00, 0x01):
        raise lib.TestnetError("not a TokenBridgeParams value")
    return s.bytes(32).hex()


def check_bridge_migration(
    param: int, current: lib.Cell | None, new: lib.Cell, assets: dict[str, dict]
) -> None:
    """A bridge address change while ConfigParam 84 still lists an active asset of
    the old bridge is refused: that record would stop verifying (design 7.4). Its
    status 2 or 3 is adopted first, by its own proposal."""
    old, replacement = bridge_address_of(current), bridge_address_of(new)
    if old is None or old == replacement:
        return
    chain = TOKEN_BRIDGE_PARAMS[param]
    active = [
        master
        for master, asset in assets.items()
        if asset["status"] == "active"
        and asset["origin"]["kind"] == "token_bridge"
        and asset["origin"]["bridge_address"] == old
        and asset["origin"]["source_chain_id"] == chain
    ]
    if active:
        raise lib.TestnetError(
            f"ConfigParam {param} would replace bridge {old}, but ConfigParam 84 still lists "
            f"active assets of it ({', '.join(active)}); adopt their status 2 or 3 first"
        )


def validator_set(cp34: lib.Cell) -> dict:
    """ConfigParam 34 (validators#11 or validators_ext#12): utime_since, utime_until,
    total and each member's key. A member is keyed by its consensus public key:
    the Ed25519 key of validator#53 / validator_addr#73, or, for validator_pq#b3,
    its key_id, the frozen derivation over the algorithm and the ML-DSA public key
    that cannot fit a cell inline."""
    s = lib.Slice(cp34)
    tag = s.bits(8)
    if tag not in (0x11, 0x12):
        raise lib.TestnetError("ConfigParam 34 is not a validator set")
    since, until, total, main = s.bits(32), s.bits(32), s.bits(16), s.bits(16)
    if tag == 0x12:
        s.bits(64)  # total_weight
        root = s.take_ref() if s.bits(1) else None
    else:
        # validators#11 holds a Hashmap (not HashmapE) in place: the rest of the cell.
        rest = format(int.from_bytes(cp34.data, "big"), f"0{8 * len(cp34.data)}b")[: cp34.bits]
        root = lib.cell_from_bits(rest[s.pos :], cp34.refs[s.ref :])
    keys = []
    for _, entry in sorted((strict_hashmap_items(root, 16) if root is not None else {}).items()):
        kind = entry.bits(8)
        if kind in (0x53, 0x73):
            if entry.bits(32) != 0x8E81278A:
                raise lib.TestnetError("ConfigParam 34: a key that is not ed25519_pubkey")
            keys.append(entry.bytes(32).hex())
        elif kind == 0xB3:
            entry.bytes(32)  # validator_id
            entry.bits(16)  # algorithm_id
            keys.append(entry.bytes(32).hex())  # key_id
        else:
            raise lib.TestnetError(f"ConfigParam 34: unknown validator descriptor {kind:#x}")
    if len(keys) != total or len(set(keys)) != total:
        raise lib.TestnetError("ConfigParam 34: the list does not hold total distinct members")
    return {"utime_since": since, "utime_until": until, "total": total, "main": main, "keys": keys}


def validator_count(cp34: lib.Cell) -> int:
    return validator_set(cp34)["total"]


# Release evidence older than this, or from before the current set took office, is stale.
RELEASE_EVIDENCE_MAX_AGE = 24 * 3600
RELEASE_EVIDENCE_CLOCK_SKEW = 300


def check_node_releases(
    evidence_path: str | None, tos_root: str, current: dict, now: float | None = None
) -> list[dict]:
    """The rollout precondition of ConfigParam 84 (design 3.1): every current
    validator runs a node whose schema has ConfigParam 84.

    The evidence is one row per member of the current set (ConfigParam 34), keyed
    by the member's consensus public key ("public_key", as validator_set reads
    it), with the tos commit its operator attests the node runs ("commit", from
    `tos-validator-engine -V`, kept in "version_output") and when it was observed
    ("observed_at", Unix seconds). Every member has exactly one row, and no row
    names anyone else. Each observation is after the current set took office and
    at most 24 hours old, and each commit is in --tos-root and defines ConfigParam
    84 in its block.tlb.

    Limitation: this tool cannot prove which binary a remote host runs. A row is an
    operator's attestation; the check binds it to the current set and to a commit
    with the schema, nothing more."""
    if not evidence_path:
        raise lib.TestnetError(
            "ConfigParam 84 needs --node-release-evidence: a node without its schema halts on any "
            "ConfigParam 84 value, so every current validator's release must be shown first"
        )
    now = time.time() if now is None else now
    rows = json.loads(Path(evidence_path).read_text()).get("validators")
    if not isinstance(rows, list):
        raise lib.TestnetError("the release evidence has no validators list")
    members = set(current["keys"])
    seen: dict[str, dict] = {}
    for row in rows:
        key = str(row.get("public_key", "")).lower()
        if key not in members:
            raise lib.TestnetError(
                f"{row.get('name')}: {key or 'no key'} is not in the current set"
            )
        if key in seen:
            raise lib.TestnetError(f"{row.get('name')}: a second row for {key}")
        seen[key] = row
    missing = sorted(members - set(seen))
    if missing:
        raise lib.TestnetError(f"no release evidence for current validators {', '.join(missing)}")
    checked = []
    for key in current["keys"]:
        row = seen[key]
        observed = row.get("observed_at")
        if not isinstance(observed, (int, float)) or isinstance(observed, bool):
            raise lib.TestnetError(f"{row.get('name')}: no observation time")
        if observed <= current["utime_since"]:
            raise lib.TestnetError(
                f"{row.get('name')}: observed before the current set took office; observe again"
            )
        if (
            observed > now + RELEASE_EVIDENCE_CLOCK_SKEW
            or now - observed > RELEASE_EVIDENCE_MAX_AGE
        ):
            raise lib.TestnetError(
                f"{row.get('name')}: the observation is not from the last 24 hours"
            )
        commit = str(row.get("commit", ""))
        if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
            raise lib.TestnetError(f"{row.get('name')}: not a full commit id: {commit!r}")
        if commit not in str(row.get("version_output", "")):
            raise lib.TestnetError(
                f"{row.get('name')}: the attested -V output does not name {commit}"
            )
        shown = subprocess.run(
            ["git", "-C", tos_root, "show", f"{commit}:crypto/block/block.tlb"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if shown.returncode != 0:
            raise lib.TestnetError(f"{row.get('name')}: commit {commit} is not in {tos_root}")
        if SETTLEMENT_ASSETS_SCHEMA_LINE not in shown.stdout:
            raise lib.TestnetError(
                f"{row.get('name')}: commit {commit} has no ConfigParam 84 schema; upgrade first"
            )
        checked.append(
            {"name": row.get("name"), "public_key": key, "commit": commit, "observed_at": observed}
        )
    return checked


# ---------------------------------------------------------------- reads


def config_cell(url: str, param: int) -> lib.Cell | None:
    """The parameter's value, or None when the configuration holds none."""
    try:
        answer = lib.rpc(url, "getConfigParam", param=param)
    except lib.RpcError as error:
        if error.reason == "CONFIG_PARAM_ABSENT":
            return None
        raise
    data = (answer or {}).get("config", {}).get("bytes")
    return lib.parse_boc(base64.b64decode(data)) if data else None


def status(url: str, proposal: str) -> dict | None:
    """get_proposal: [expires, critical?, [param, value, hash], vset_id, voters, weight_remaining,
    rounds_remaining, losses, wins], or null."""
    answer = lib.rpc(
        url,
        "runGetMethod",
        address=CONFIG_ADDRESS,
        method="get_proposal",
        stack=[["num", str(int(proposal, 16))]],
    )
    if answer.get("exit_code") != 0:
        raise lib.TestnetError(f"get_proposal exited {answer.get('exit_code')}")
    stack = answer.get("stack") or []
    if not stack or stack[0][0] != "tuple":
        return None
    e = stack[0][1]["elements"]

    def num(x):
        return int(x[1], 0)

    voters: list[int] = []
    node = e[4]
    while node[0] == "tuple" and node[1]["elements"]:
        head, tail = node[1]["elements"]
        voters.append(num(head))
        node = tail
    if node[0] == "list":
        voters += [num(x) for x in node[1]["elements"]]
    return {
        "expires": num(e[0]),
        "critical": num(e[1]) != 0,
        "param": num(e[2][1]["elements"][0]),
        "vset_id": f"{num(e[3]):064x}",
        "voters": sorted(voters),
        "weight_remaining": num(e[5]),
        "rounds_remaining": num(e[6]),
        "losses": num(e[7]),
        "wins": num(e[8]),
    }


def stack_list(entry) -> list:
    """The elements of a TVM list as the node renders it: a "list", or nested
    two-element "tuple" cons cells ending in an empty tuple or null."""
    out: list = []
    while entry and entry[0] in ("tuple", "list"):
        elements = entry[1]["elements"]
        if entry[0] == "list":
            return out + list(elements)
        if not elements:
            break
        if len(elements) != 2:
            raise lib.TestnetError("a list cell is not a pair")
        out.append(elements[0])
        entry = elements[1]
    return out


def stack_cell_or_none(entry) -> lib.Cell | None:
    """A cell entry, or None for a TVM null (rendered as null or as an empty list)."""
    if entry and entry[0] in ("cell", "slice"):
        return lib.parse_boc(base64.b64decode(entry[1]["bytes"]))
    return None


def pending_proposals(url: str) -> dict[str, dict]:
    """Every registered proposal (list_proposals): the parameter it sets and its value."""
    answer = lib.rpc(url, "runGetMethod", address=CONFIG_ADDRESS, method="list_proposals", stack=[])
    if answer.get("exit_code") != 0:
        raise lib.TestnetError(f"list_proposals exited {answer.get('exit_code')}")
    stack = answer.get("stack") or []
    out = {}
    for item in stack_list(stack[0]) if stack else []:
        phash, body = item[1]["elements"]
        params = body[1]["elements"][2][1]["elements"]
        out[f"{int(phash[1], 0):064x}"] = {
            "param": int(params[0][1], 0),
            "value": stack_cell_or_none(params[1]),
        }
    return out


def pending_params(url: str) -> dict[str, int]:
    """Every registered proposal and the parameter it sets."""
    return {h: p["param"] for h, p in pending_proposals(url).items()}


def current_set_hash(url: str) -> str:
    cell = config_cell(url, 34)
    if cell is None:
        raise lib.TestnetError("no ConfigParam 34")
    return cell.hash().hex()


# ---------------------------------------------------------------- operations


def payer_signer(args: argparse.Namespace, global_id: int, value: int, body: lib.Cell):
    key = Path(args.payer_key)
    address_file = Path(args.payer_addr).read_bytes()

    def sign(seqno: int) -> bytes:
        with tempfile.TemporaryDirectory(prefix="governance-") as work:
            path = Path(work) / "body.boc"
            path.write_bytes(lib.serialize_boc(body))
            return elections.sign_wallet_v3(
                args,
                global_id,
                key,
                address_file,
                CONFIG_ADDRESS,
                args.payer_subwallet,
                seqno,
                elections.nanotos_text(value),
                bounce=True,
                body=path,
            )

    return sign


def send(
    args,
    operations,
    global_id: int,
    op_id: str,
    label: str,
    kind: str,
    value: int,
    body: lib.Cell,
    expect,
) -> dict:
    payer = elections.address_from_file(Path(args.payer_addr))
    params = {
        "kind": kind,
        "wallet": payer,
        "destination": CONFIG_ADDRESS,
        "value": value,
        "bounce": True,
        "body_hash": body.hash().hex(),
        "state_init_hash": None,
        "label": label,
        "subwallet": args.payer_subwallet,
    }

    def prerequisites() -> None:
        balance = operations.balance(payer)
        if balance < value + ops.FEE_ALLOWANCE_NANOTOS:
            raise lib.TestnetError(f"the payer holds {balance / 1e9:.9f} TOS")

    return operations.run(
        op_id,
        params,
        payer_signer(args, global_id, value, body),
        lambda decoded: None,
        prerequisites,
        expect,
    )


def network_global_id(args) -> int:
    """The global id value-moving steps sign for: the testnet profile's confirmed
    one, or, with --local-network, the local development network's. In the local
    case the ceremony's genesis.json (the zero state every operation checks the
    nodes against) is written from the network file, or must already agree."""
    if not getattr(args, "local_network", None):
        return lib.confirmed_global_id(lib.load_profile(Path(args.profile)))
    network = json.loads(Path(args.local_network).read_text())
    if (
        network.get("global_id") != lib.LOCAL_GLOBAL_ID
        or network.get("scope") != "local-development"
    ):
        raise lib.TestnetError(
            f"{args.local_network} does not describe the local development network"
        )
    genesis = {
        "zero_state": {
            "root_hash": base64.b64encode(bytes.fromhex(network["zerostate_root"])).decode(),
            "file_hash": base64.b64encode(bytes.fromhex(network["zerostate_file"])).decode(),
        },
        "scope": "local-development",
    }
    path = lib.private_dir(Path(args.ceremony)) / "genesis.json"
    if path.exists():
        if json.loads(path.read_text()).get("zero_state") != genesis["zero_state"]:
            raise lib.TestnetError(f"{path} names another zero state than {args.local_network}")
    else:
        path.write_text(json.dumps(genesis, indent=1) + "\n")
    return lib.LOCAL_GLOBAL_ID


def bridge_change(param: int, current: lib.Cell | None, value: lib.Cell | None) -> bool:
    """Whether a token bridge parameter value replaces the bridge the current one names."""
    old = bridge_address_of(current)
    return old is not None and (value is None or bridge_address_of(value) != old)


def check_rules(
    args, param: int, value: lib.Cell | None, phash: str, critical: bool
) -> dict | None:
    """The rules a proposal must pass against the chain as it is now: at propose,
    and again before each round's votes are signed, since other proposals may
    have been registered or adopted in between.

    ConfigParam 84 changes are serialized, and a bridge replacement never runs
    alongside one: while a ConfigParam 84 proposal is pending a bridge address
    change is refused, and while a bridge address change is pending a ConfigParam
    84 proposal is refused (design 7.4). The proposal `phash` itself, when it is
    already registered, is not counted against itself, so an interrupted
    proposal resumes."""
    pending = {h: p for h, p in pending_proposals(args.rpc).items() if h != phash}
    current = config_cell(args.rpc, param)
    if param == SETTLEMENT_ASSETS_PARAM:
        if not critical:
            raise lib.TestnetError("ConfigParam 84 must be listed in ConfigParam 10 (critical)")
        if value is None:
            raise lib.TestnetError("ConfigParam 84 is never removed by a proposal")
        new = decode_settlement_assets(value)
        old = decode_settlement_assets(current) if current is not None else {}
        change = settlement_assets_change(old, new)
        others = [h for h, p in pending.items() if p["param"] == SETTLEMENT_ASSETS_PARAM]
        if others:
            raise lib.TestnetError(
                f"another ConfigParam 84 proposal is pending ({', '.join(others)}); "
                "changes to ConfigParam 84 are serialized"
            )
        replacing = [
            h
            for h, p in pending.items()
            if p["param"] in TOKEN_BRIDGE_PARAMS
            and bridge_change(p["param"], config_cell(args.rpc, p["param"]), p["value"])
        ]
        if replacing:
            raise lib.TestnetError(
                f"a bridge address change is pending ({', '.join(replacing)}); "
                "ConfigParam 84 waits until it is adopted or expires"
            )
        return {"entries": len(new), "validation_cells": validation_visits(value), "change": change}
    if param in TOKEN_BRIDGE_PARAMS and bridge_change(param, current, value):
        recognized = config_cell(args.rpc, SETTLEMENT_ASSETS_PARAM)
        assets = decode_settlement_assets(recognized) if recognized is not None else {}
        if value is not None:
            check_bridge_migration(param, current, value, assets)
        listed = [h for h, p in pending.items() if p["param"] == SETTLEMENT_ASSETS_PARAM]
        if listed:
            raise lib.TestnetError(
                f"a ConfigParam 84 proposal is pending ({', '.join(listed)}); the bridge address "
                f"change waits until it is adopted or expires"
            )
    return None


def cmd_propose(args) -> int:
    value = lib.parse_boc(Path(args.value_boc).read_bytes())
    current = config_cell(args.rpc, args.param)
    if current is not None and current.hash() == value.hash():
        raise lib.TestnetError(f"ConfigParam {args.param} already has this value")
    critical = args.param in signed_keys(config_cell(args.rpc, 10))
    # The precondition is the current value's hash; for an absent parameter it is
    # the Config contract's absent-value hash, zero (config-code.fc accept_proposal),
    # so two concurrent first installations cannot overwrite each other.
    precondition = current.hash() if current is not None else ABSENT_VALUE_HASH
    proposal = proposal_cell(args.param, value, precondition)
    phash = proposal.hash().hex()
    checks = check_rules(args, args.param, value, phash, critical)
    if args.param == SETTLEMENT_ASSETS_PARAM:
        checks["node_releases"] = check_node_releases(
            args.node_release_evidence, args.tos_root, validator_set(config_cell(args.rpc, 34))
        )
    setup = parse_vote_setup(config_cell(args.rpc, 11), critical)
    expire = args.expire_seconds or setup["min_store_sec"]
    price = proposal_price(value, setup, expire)
    body = register_body(int(time.time()), expire, proposal, critical)
    plan = {
        "proposal": phash,
        "param": args.param,
        "critical": critical,
        "price_nanotos": price,
        "attached_nanotos": price + REGISTER_HEADROOM,
        "expire_seconds": expire,
        "current_hash": current.hash().hex() if current is not None else None,
        "if_hash_equal": precondition.hex(),
        "value_hash": value.hash().hex(),
        "min_wins": setup["min_wins"],
    }
    if checks is not None:
        plan["settlement_assets"] = checks
    folder = lib.private_dir(lib.private_dir(Path(args.ceremony) / "governance") / phash)
    (folder / "proposal.json").write_text(json.dumps(plan, indent=1) + "\n")
    (folder / "value.boc").write_bytes(lib.serialize_boc(value))
    print(json.dumps(plan, indent=1))
    if args.dry_run:
        print("dry run: nothing signed or sent")
        return 0
    if status(args.rpc, phash) is not None:
        print(f"proposal {phash} is already registered")
        return 0
    global_id = network_global_id(args)
    operations = elections.operations_for(args, global_id)

    def expect(_ops, record, delivery, evidence):
        if status(args.rpc, phash) is None:
            return "failed", dict(
                evidence, form="b", reason="the Config contract did not register it"
            )
        return "settled", evidence

    send(
        args,
        operations,
        global_id,
        args.id or f"config-propose-{phash[:12]}",
        f"propose-{args.param}",
        "config-propose",
        price + REGISTER_HEADROOM,
        body,
        expect,
    )
    print(json.dumps(status(args.rpc, phash), indent=1))
    return 0


def tl_key_file(path: Path, prefix: bytes, key_b64: str) -> None:
    key = base64.b64decode(key_b64, validate=True)
    if len(key) != 32:
        raise lib.TestnetError("a console key is 32 bytes")
    lib.write_new(path, prefix + key, 0o600)


def sign_local(args, proposal: str) -> dict:
    """Votes from the local network's consoles: one per member of the current set.
    A candidate outside the set has no key for it and is skipped."""
    data = Path(args.local_network).resolve().parent
    ports = json.loads((data / "testnet-ports.json").read_text())["nodes"]
    members = validator_count(config_cell(args.rpc, 34))
    votes: dict = {}
    skipped = []
    for node in ports:
        if node["role"] not in ("validator", "candidate"):
            continue
        name = f"node-{node['idx']}"
        console = data / "elections" / f"console-{node['idx']}.private.json"
        if not console.is_file():
            raise lib.TestnetError(
                f"{console} is missing; the local network was set up without --rotate"
            )
        config = json.loads(console.read_text())
        with tempfile.TemporaryDirectory(prefix="config-vote-") as work:
            w = Path(work)
            tl_key_file(
                w / "client", lib.ED25519_PRIVATE_TL_PREFIX, config["client_private_key"]["key"]
            )
            tl_key_file(
                w / "server.pub", lib.ED25519_PUBLIC_TL_PREFIX, config["server_public_key"]["key"]
            )
            out = subprocess.run(
                [
                    args.console,
                    "-a",
                    config["address"],
                    "-k",
                    str(w / "client"),
                    "-p",
                    str(w / "server.pub"),
                    "-t",
                    "30",
                    "-c",
                    f"create-proposal-vote 0x{proposal} {w / 'vote.boc'}",
                ],
                capture_output=True,
                text=True,
                timeout=90,
            )
            vote = w / "vote.boc"
            if out.returncode != 0 or not vote.is_file() or not vote.stat().st_size:
                skipped.append(name)
                print(f"{name}: no vote (not in the current set or the console refused)")
                continue
            raw = vote.read_bytes()
        idx, cell = parse_vote(raw, proposal)
        if str(idx) in votes:
            raise lib.TestnetError(
                f"{name}: index {idx} was already signed by {votes[str(idx)]['host']}"
            )
        votes[str(idx)] = {
            "host": name,
            "boc": base64.b64encode(raw).decode(),
            "hash": cell.hash().hex(),
        }
        print(f"{name}: idx {idx}")
    if len(votes) != members:
        raise lib.TestnetError(f"{len(votes)} votes for a set of {members}; skipped {skipped}")
    return votes


def revalidate(args, proposal: str) -> None:
    """The proposal's rules again, against the chain as it is now (check_rules)."""
    registered = pending_proposals(args.rpc).get(proposal)
    now = status(args.rpc, proposal)
    if registered is None or now is None:
        raise lib.TestnetError(f"proposal {proposal} is not registered")
    check_rules(args, registered["param"], registered["value"], proposal, now["critical"])


def cmd_sign(args) -> int:
    proposal = args.proposal.lower()
    revalidate(args, proposal)
    set_hash = current_set_hash(args.rpc)
    if args.local_network:
        votes = sign_local(args, proposal)
        return save_round(args, proposal, set_hash, votes)
    if not args.inventory:
        raise lib.TestnetError("sign needs --inventory (or --local-network for the local network)")
    inventory = {h["name"]: h for h in json.loads(Path(args.inventory).read_text())["hosts"]}
    hosts = args.host or ["node-1", "node-2", "node-3", "node-4"]
    script = (
        "set -eu\numask 077\n"
        "d=$(mktemp -d /var/lib/tos/validator/config-vote.XXXXXX)\n"
        'trap \'rm -rf "$d"\' EXIT\ncd "$d"\n'
        f"{CONSOLE} -c 'create-proposal-vote 0x{proposal} vote.boc' >/dev/null\n"
        "test -s vote.boc\nprintf 'CONFIG_VOTE '\nbase64 -w0 vote.boc\nprintf '\\n'\n"
    )
    votes = {}
    for name in hosts:
        h = inventory[name]
        host = elections.Host(h["address"], str(Path(h["ssh_key"]).expanduser()))
        out = subprocess.run(
            host.base + ["runuser -u tos -- bash -s"],
            input=script,
            text=True,
            capture_output=True,
            timeout=90,
        )
        if out.returncode != 0:
            raise lib.TestnetError(f"{name}: the console refused (exit {out.returncode}); no retry")
        lines = [x for x in out.stdout.splitlines() if x.startswith("CONFIG_VOTE ")]
        if len(lines) != 1:
            raise lib.TestnetError(f"{name}: expected one vote")
        raw = base64.b64decode(lines[0].split()[1], validate=True)
        idx, cell = parse_vote(raw, proposal)
        votes[str(idx)] = {
            "host": name,
            "boc": base64.b64encode(raw).decode(),
            "hash": cell.hash().hex(),
        }
        print(f"{name}: idx {idx}")
    return save_round(args, proposal, set_hash, votes)


def save_round(args, proposal: str, set_hash: str, votes: dict) -> int:
    if current_set_hash(args.rpc) != set_hash:
        raise lib.TestnetError("the validator set changed while signing; sign again")
    folder = lib.private_dir(lib.private_dir(Path(args.ceremony) / "governance") / proposal)
    path = folder / f"round-{set_hash[:16]}.json"
    path.write_text(json.dumps({"set": set_hash, "votes": votes}, indent=1) + "\n")
    print(f"{len(votes)} votes signed under ConfigParam 34 {set_hash[:16]}: {path}")
    return 0


def cmd_vote(args) -> int:
    proposal = args.proposal.lower()
    set_hash = current_set_hash(args.rpc)
    path = Path(args.ceremony) / "governance" / proposal / f"round-{set_hash[:16]}.json"
    if not path.is_file():
        raise lib.TestnetError(f"no votes signed under the current set {set_hash[:16]}; run sign")
    round_ = json.loads(path.read_text())
    if round_["set"] != set_hash:
        raise lib.TestnetError("the votes were signed under another validator set")
    global_id = network_global_id(args)
    operations = elections.operations_for(args, global_id)
    before = status(args.rpc, proposal)
    if before is None:
        raise lib.TestnetError(f"proposal {proposal} is not registered (or was already adopted)")
    revalidate(args, proposal)
    for idx in sorted(round_["votes"], key=int):
        now = status(args.rpc, proposal)
        if now is None:
            print("the proposal is gone: adopted or removed; check with `adopted`")
            return 0
        if now["wins"] > before["wins"]:
            print(f"round won: wins {now['wins']}")
            return 0
        if int(idx) in now["voters"]:
            print(f"idx {idx} already voted in this round")
            continue
        if current_set_hash(args.rpc) != set_hash:
            raise lib.TestnetError("the validator set changed; these votes no longer count")
        vote = lib.parse_boc(base64.b64decode(round_["votes"][idx]["boc"]))

        def expect(_ops, record, delivery, evidence, _idx=int(idx)):
            after = status(args.rpc, proposal)
            if after is None or _idx in after["voters"] or after["wins"] > before["wins"]:
                return "settled", evidence
            return "failed", dict(
                evidence, form="b", reason="the Config contract did not count the vote"
            )

        send(
            args,
            operations,
            global_id,
            f"config-vote-{proposal[:12]}-{set_hash[:8]}-{idx}",
            f"vote-{proposal[:12]}-{idx}",
            "config-vote",
            VOTE_VALUE,
            vote,
            expect,
        )
        print(f"idx {idx}: {json.dumps(status(args.rpc, proposal))}")
    final = status(args.rpc, proposal)
    print(json.dumps(final, indent=1) if final else "the proposal is gone: adopted or removed")
    return 0


def cmd_status(args) -> int:
    print(json.dumps(status(args.rpc, args.proposal.lower()), indent=1))
    return 0


def cmd_adopted(args) -> int:
    want = lib.parse_boc(Path(args.value_boc).read_bytes()).hash()
    urls = [args.rpc, args.confirm_rpc, *(args.also_rpc or [])]
    for url in urls:
        cell = config_cell(url, args.param)
        if cell is None or cell.hash() != want:
            print(f"{url}: ConfigParam {args.param} is not the proposed value")
            return 1
        print(f"{url}: ConfigParam {args.param} = {want.hex()}")
    print(f"ConfigParam {args.param} = {want.hex()} on all {len(urls)} nodes")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", default=str(lib.PROFILE_PATH))
    parser.add_argument(
        "--local-network",
        help="the local development network's network.json, used instead of --profile",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def chain(p, confirm=False):
        p.add_argument("--rpc", required=True)
        if confirm:
            p.add_argument("--confirm-rpc", required=True)

    def payer(p):
        p.add_argument("--ceremony", required=True)
        p.add_argument("--tos-root", required=True)
        p.add_argument("--fift", required=True)
        p.add_argument("--payer-key", required=True)
        p.add_argument("--payer-addr", required=True)
        p.add_argument("--payer-subwallet", type=int, required=True)

    p = sub.add_parser("propose")
    payer(p)
    chain(p, confirm=True)
    p.add_argument("--param", type=int, required=True)
    p.add_argument("--value-boc", required=True)
    p.add_argument("--expire-seconds", type=int)
    p.add_argument("--id")
    p.add_argument(
        "--node-release-evidence",
        help="ConfigParam 84: {validators: [{public_key, name, commit, version_output, "
        "observed_at}]}, one row per current validator; each row is the operator's attested "
        "tos-validator-engine -V output, which this tool cannot verify on the host",
    )
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_propose)

    p = sub.add_parser("sign")
    p.add_argument("--ceremony", required=True)
    p.add_argument("--inventory")
    chain(p)
    p.add_argument("--proposal", required=True)
    p.add_argument("--host", action="append")
    p.add_argument("--console", default=LOCAL_CONSOLE, help="the local validator console")
    p.set_defaults(fn=cmd_sign)

    p = sub.add_parser("vote")
    payer(p)
    chain(p, confirm=True)
    p.add_argument("--proposal", required=True)
    p.set_defaults(fn=cmd_vote)

    p = sub.add_parser("status")
    chain(p)
    p.add_argument("--proposal", required=True)
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("adopted")
    chain(p, confirm=True)
    p.add_argument("--also-rpc", action="append", help="another node that must serve the value")
    p.add_argument("--param", type=int, required=True)
    p.add_argument("--value-boc", required=True)
    p.set_defaults(fn=cmd_adopted)

    args = parser.parse_args(lib.cli_argv(argv))
    try:
        return args.fn(args)
    except (lib.TestnetError, ops.OperationRefused) as error:
        print(f"testnet-governance: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
