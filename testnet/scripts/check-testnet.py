#!/usr/bin/env python3
"""Check that independent nodes agree on one live public testnet.

  check-testnet.py --genesis genesis.json --rpc URL --rpc URL [--rpc URL ...]
                   [--max-age 120]
                   [--genesis-set genesis-records.json | --elected-set genesis-records.json]

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
  * with --genesis-set,
    live ConfigParam 34 is exactly the four genesis identities. Use it only
    before the first ordinary election replaces the genesis set;
  * with --elected-set (same records file), after a rotation:
    live ConfigParam 34 has as many members as the records, all of them main
    validators, and its validator ids (staking accounts) are exactly the
    records'. The consensus keys are not compared: an election may register
    new ones. The
    summary reports the set's term (utime_since, utime_until) so a run record
    can tie it to an election;
  * when genesis.json records an auth_policy (version-16 genesis), live
    ConfigParam 48 at that block carries the genesis AUTH network tag and is
    in ConfigParam 9 and 10, and ConfigParam 8 is at least the genesis
    version. The summary says whether ConfigParam 48 is still the genesis
    cell (a governance replacement may legitimately move its sequence on). A
    genesis.json of version 16 or later without auth_policy is refused, not
    skipped.

Agreement among observers is detection, not a consensus proof: the nodes are
trusted to report what they hold. Prints a JSON summary; exits 1 on refusal.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

SHARD = str(lib.MASTERCHAIN_SHARD)


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
import network_check as shared  # noqa: E402

full_id = shared.full_id
decode_config34 = shared.decode_config34
config_cell = shared.config_cell
check_auth_policy = shared.check_auth_policy


def check(args: argparse.Namespace, rpc=lib.rpc, now=time.time, decode=decode_config34) -> dict:
    genesis = json.loads(Path(args.genesis).read_text())
    lib.check_global_id(genesis["global_id"])
    summary = shared.check_agreement(args, genesis, rpc=rpc, now=now)
    height = summary["height"]
    if "auth_policy" in genesis:
        summary["config48"] = check_auth_policy(rpc, args.rpc[0], height, genesis)
    elif int(genesis.get("global_version", 0)) >= 16:
        # Every version-16 genesis carries ConfigParam 48; a genesis.json that does
        # not record it is not one the ceremony wrote, so the check is not skipped.
        raise lib.TestnetError(
            f"genesis.json is version {genesis['global_version']} but records no auth_policy"
        )
    if args.genesis_set:
        records = lib.check_operator_set(json.loads(Path(args.genesis_set).read_text()))
        param = rpc(args.rpc[0], "getConfigParam", param=34, seqno=height)
        decoded = decode(param["config"]["bytes"])
        actual = {(v["validator_id_hex"], v["consensus_key_id_hex"]) for v in decoded["validators"]}
        expected = {(r["validator_id"], r["key_id"]) for r in records}
        if decoded["total"] != lib.GENESIS_VALIDATORS or actual != expected:
            raise lib.TestnetError("live ConfigParam 34 is not the four genesis identities")
        summary["config34"] = "the four genesis identities"
    if args.elected_set:
        records = lib.check_operator_set(json.loads(Path(args.elected_set).read_text()))
        param = rpc(args.rpc[0], "getConfigParam", param=34, seqno=height)
        decoded = decode(param["config"]["bytes"])
        actual = {v["validator_id_hex"] for v in decoded["validators"]}
        expected = {r["validator_id"] for r in records}
        if decoded["total"] != len(records) or decoded["main"] != decoded["total"]:
            raise lib.TestnetError(
                f"live ConfigParam 34 has {decoded['total']} members ({decoded['main']} main), "
                f"expected {len(records)}, all main"
            )
        if actual != expected:
            missing = sorted(c[:16] for c in expected - actual)
            foreign = sorted(c[:16] for c in actual - expected)
            raise lib.TestnetError(
                f"live ConfigParam 34 validator ids differ: missing {missing}, unexpected {foreign}"
            )
        summary["config34"] = {
            "utime_since": decoded["utime_since"],
            "utime_until": decoded["utime_until"],
            "total": decoded["total"],
            "main": decoded["main"],
            "validator_ids": "exactly the records' staking accounts",
        }
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--rpc", action="append", required=True)
    parser.add_argument("--max-age", type=int, default=120)
    sets = parser.add_mutually_exclusive_group()
    sets.add_argument("--genesis-set", type=Path)
    sets.add_argument("--elected-set", type=Path)
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
