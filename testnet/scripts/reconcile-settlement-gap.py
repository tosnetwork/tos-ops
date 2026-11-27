#!/usr/bin/env python3
"""Operator-only source gap walk, one bounded batch; never publishes health."""

import argparse
import fcntl
import importlib.util
import json
import os
import stat
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "gap_collector", Path(__file__).with_name("collect-settlement-evm.py")
)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def append_batch(rpc, binding, previous, directory, blocks=collector.GAP_BATCH_BLOCKS):
    collector.require(
        type(blocks) is int and 1 <= blocks <= collector.GAP_BATCH_BLOCKS, "gap batch size bound"
    )
    collector.require(previous["network"] == binding["network"], "gap network differs")
    collector.require(
        collector.quantity(rpc.call("eth_chainId")) == binding["chain_id"], "gap chain differs"
    )
    original = previous["source_checkpoint"]
    origin = dict(height=original["height"], hash=original["hash"])
    cursor, _, prior_hash, count = collector.gap_history(directory, binding, origin)
    final = collector.block(rpc, "finalized")
    final_height = collector.quantity(final["number"])
    collector.require(cursor["height"] <= final_height, "gap cursor beyond finalized")
    if cursor["height"] == final_height:
        collector.require(cursor["hash"] == final["hash"][2:], "gap finalized reorg")
        return dict(caught_up=True, checkpoint=cursor, batches=count)
    collector.require(count < collector.MAX_GAP_BATCHES, "gap archive batch bound")
    stop = min(final_height, cursor["height"] + blocks)
    target = collector.block(rpc, hex(stop))
    collector.require(collector.quantity(target["number"]) == stop, "gap target number differs")
    logs = collector.block_logs(
        rpc, cursor, target, [binding["bridge"]] + [a["token"] for a in binding["assets"]]
    )
    collector.require(
        collector.block(rpc, hex(stop))["hash"] == target["hash"], "gap checkpoint reorg"
    )
    collector.require(
        collector.block(rpc, final["number"])["hash"] == final["hash"], "gap finalized reorg"
    )
    batch = dict(
        schema="tos-source-gap/1",
        binding=collector.binding_hash(binding),
        origin=origin,
        **{"from": cursor, "to": dict(height=stop, hash=target["hash"][2:])},
        logs=logs,
        previous_sha256=prior_hash,
    )
    collector.require(
        len(json.dumps(batch).encode()) <= collector.monitor.MAX_BYTES, "gap archive file bound"
    )
    destination = directory / f"{count:06d}.json"
    collector.require(not destination.exists(), "gap batch already exists")
    collector.monitor.atomic(destination, batch)
    return dict(caught_up=stop == final_height, checkpoint=batch["to"], batches=count + 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument(
        "--state-dir", type=Path, required=True, help="existing checker state; locks monitor.lock"
    )
    parser.add_argument(
        "--gap-dir", type=Path, required=True, help="separate private archive retained as evidence"
    )
    parser.add_argument(
        "--blocks",
        type=int,
        default=collector.GAP_BATCH_BLOCKS,
        help="1-32 blocks per invocation; reduce for dense blocks",
    )
    args = parser.parse_args(argv)
    try:
        state = args.state_dir.lstat()
        collector.require(
            stat.S_ISDIR(state.st_mode)
            and state.st_uid == os.geteuid()
            and not state.st_mode & 0o077,
            "monitor state is not private and owned",
        )
        collector.require(
            args.gap_dir.resolve() != args.state_dir.resolve(), "gap archive must be separate"
        )
        with open(args.state_dir / "monitor.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            collector.stale_report(args.state_dir / "report.json")
            args.gap_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            result = append_batch(
                collector.RPC(args.rpc),
                collector.monitor.read_json(args.binding),
                collector.monitor.read_json(args.state_dir / "previous.json"),
                args.gap_dir,
                args.blocks,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        collector.http.client.HTTPException,
        RecursionError,
    ):
        print("gap reconciliation refused; no baseline advanced; report remains stale")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
