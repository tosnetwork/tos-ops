#!/usr/bin/env python3
"""Check that independent nodes agree on one live public testnet.

  check-testnet.py --genesis genesis.json --rpc URL --rpc URL [--rpc URL ...]
                   [--max-age 120] [--genesis-set genesis-records.json]

Each URL is a JSON-RPC endpoint of a node the checker trusts to answer for
itself (a validator's loopback listener through an SSH tunnel, or a full
node's read-only listener). At least two are required: one node agreeing with
itself proves nothing. The check refuses unless:

  * every node's zero state is the ceremony's (getMasterchainInfo.init);
  * at the lowest head among them, every node returns the same full block id
    (workchain, shard, seqno, root hash, file hash), not merely the same height;
  * that block carries the testnet global id;
  * every node's own head is younger than --max-age. When none is, the
    network has stalled; when only some are, those nodes are behind, and the
    refusal names them with their lag;
  * with --genesis-set (and TOS_ROOT naming a tos checkout to decode with),
    live ConfigParam 34 is exactly the four genesis identities. Use it only
    before the first ordinary election replaces the genesis set.

Agreement among observers is detection, not a consensus proof: the nodes are
trusted to report what they hold. Prints a JSON summary; exits 1 on refusal.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

SHARD = str(lib.MASTERCHAIN_SHARD)


def full_id(block: dict) -> tuple:
    return tuple(str(block[k]) for k in ("workchain", "shard", "seqno", "root_hash", "file_hash"))


def decode_config34(boc_b64: str) -> dict:
    tos_root = os.environ.get("TOS_ROOT")
    if not tos_root:
        raise lib.TestnetError("--genesis-set needs TOS_ROOT to decode ConfigParam 34")
    for sub in ("test/tostester/src", "scripts"):
        path = str(Path(tos_root) / sub)
        if path not in sys.path:
            sys.path.append(path)
    try:
        from pytosiq_core import Cell
        from x02_config34_proof import decode_validator_set
    except ImportError as exc:
        raise lib.TestnetError(
            f"cannot load the tos decoder ({exc}); run with the tos environment: $TOS_ROOT/.venv/bin/python"
        ) from exc

    return decode_validator_set(Cell.one_from_boc(base64.b64decode(boc_b64)))


def check(args: argparse.Namespace, rpc=lib.rpc, now=time.time) -> dict:
    if len(set(args.rpc)) < 2:
        raise lib.TestnetError("name at least two distinct nodes")
    genesis = json.loads(Path(args.genesis).read_text())
    global_id = lib.check_global_id(genesis["global_id"])
    zero = genesis["zero_state"]
    expected_zero = (str(lib.MASTERCHAIN), SHARD, "0", zero["root_hash"], zero["file_hash"])

    infos = {}
    for url in args.rpc:
        info = rpc(url, "getMasterchainInfo")
        if full_id(info["init"]) != expected_zero:
            raise lib.TestnetError(
                f"{url} runs a different zero state: it belongs to another network"
            )
        infos[url] = info
    height = min(int(info["last"]["seqno"]) for info in infos.values())
    if height < 1:
        raise lib.TestnetError("no masterchain block after the zero state yet")

    headers = {
        url: rpc(url, "getBlockHeader", workchain=lib.MASTERCHAIN, shard=SHARD, seqno=height)
        for url in args.rpc
    }
    ids = {url: full_id(h["id"]) for url, h in headers.items()}
    if len(set(ids.values())) != 1:
        raise lib.TestnetError(f"nodes disagree on masterchain block {height}: {ids}")
    header = next(iter(headers.values()))
    if int(header["global_id"]) != global_id:
        raise lib.TestnetError(
            f"block {height} carries global id {header['global_id']}, expected {global_id}"
        )
    age = int(now()) - int(header["gen_utime"])

    # Freshness is judged per node, at each node's own head: one node behind is
    # not the network stalled, and the two need different responses.
    nodes = {}
    for url, info in infos.items():
        head = int(info["last"]["seqno"])
        own = rpc(url, "getBlockHeader", workchain=lib.MASTERCHAIN, shard=SHARD, seqno=head)
        nodes[url] = {"head": head, "age_seconds": int(now()) - int(own["gen_utime"])}
    newest = max(node["head"] for node in nodes.values())
    newest_age = min(node["age_seconds"] for node in nodes.values())
    if newest_age > args.max_age:
        raise lib.TestnetError(
            f"no node has a head younger than {args.max_age} s; the newest, {newest}, "
            f"is {newest_age} s old: progress stalled"
        )
    behind = {url: node for url, node in nodes.items() if node["age_seconds"] > args.max_age}
    if behind:
        detail = "; ".join(
            f"{url} at {node['head']} ({newest - node['head']} blocks behind, "
            f"head {node['age_seconds']} s old)"
            for url, node in behind.items()
        )
        raise lib.TestnetError(f"the network is at {newest}, but a node is behind: {detail}")

    summary = {
        "height": height,
        "block": dict(
            zip(("workchain", "shard", "seqno", "root_hash", "file_hash"), ids[args.rpc[0]])
        ),
        "age_seconds": age,
        "global_id": global_id,
        "nodes": len(args.rpc),
        "heads": {url: node["head"] for url, node in nodes.items()},
        "head_ages": {url: node["age_seconds"] for url, node in nodes.items()},
    }
    if args.genesis_set:
        records = lib.check_operator_set(json.loads(Path(args.genesis_set).read_text()))
        param = rpc(args.rpc[0], "getConfigParam", param=34, seqno=height)
        decoded = decode_config34(param["config"]["bytes"])
        actual = {
            (v["controller_id_hex"], v["consensus_key_id_hex"]) for v in decoded["validators"]
        }
        expected = {(r["controller_id"], r["key_id"]) for r in records}
        if decoded["total"] != lib.GENESIS_VALIDATORS or actual != expected:
            raise lib.TestnetError("live ConfigParam 34 is not the four genesis identities")
        summary["config34"] = "the four genesis identities"
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--rpc", action="append", required=True)
    parser.add_argument("--max-age", type=int, default=120)
    parser.add_argument("--genesis-set", type=Path)
    args = parser.parse_args(argv)
    try:
        summary = check(args)
    except (lib.TestnetError, OSError, KeyError, ValueError) as exc:
        print(json.dumps({"ok": False, "refused": str(exc)}))
        return 1
    print(json.dumps({"ok": True, **summary}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
