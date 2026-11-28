#!/usr/bin/env python3
"""Observe the two local bridge assets; actor inventories are explicitly empty.

This local bridge-scope adapter uses canonical account/config reads corroborated
by nodes 4-6. Provider custody checks inspect their actors separately. It does
not claim actor payout/refusal coverage or send any transaction.
"""

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


asset = load("local_usdt_monitor", HERE / "local-pq-usdt.py")
u = asset.u
source = load("local_source_monitor", u.TESTNET_SCRIPTS / "collect-settlement-evm.py")
a = asset.archive


def pinned_implementation(runtime):
    return (
        "sha256:"
        + hashlib.sha256(
            b"source-issuer-v1\0"
            + bytes.fromhex(runtime)
            + bytes(20)
            + hashlib.sha256(b"").digest()
        ).hexdigest()
    )


def tos_observation(chain, states, artifact, directory):
    view = asset.View(chain, directory / "references")
    bridge, minter_code, wallet_code = asset.bridge_codes(view, states[0])
    account = view.account(bridge)
    data = u.lib.parse_boc(base64.b64decode(account["data"]))
    cursor = u.lib.Slice(data.refs[2])
    cursor.bits(64)
    swap_count = (
        len(u.governance_module().strict_hashmap_items(cursor.take_ref(), 64))
        if cursor.bits(1)
        else 0
    )
    bridge_states = view.read(
        "runGetMethod", address=bridge, method="get_bridge_state", stack=[]
    )
    u.require(
        all(
            v["exit_code"] == 0 and v["stack"] == bridge_states[0]["stack"]
            for v in bridge_states
        ),
        "bridge state references disagree",
    )
    channels = u.num(bridge_states[0]["stack"][7])
    headers = [
        chain.call(
            "getBlockHeader",
            url=url,
            workchain=-1,
            shard=str(-(2**63)),
            seqno=view.point["seqno"],
        )
        for url in view.urls
    ]
    u.require(
        all(
            a.block_key(v["id"]) == a.block_key(view.point)
            and v["gen_utime"] == headers[0]["gen_utime"]
            for v in headers
        ),
        "checkpoint headers disagree",
    )
    checkpoint = {
        "height": view.point["seqno"],
        "hash": a.ops.b64hash(view.point["root_hash"]).hex(),
        "utime": headers[0]["gen_utime"],
    }
    recognition = []
    routes = {bridge.split(":")[1]: 79}
    test_bridge = u.governance_module().bridge_address_of(view.config(81))
    if test_bridge is not None:
        routes[test_bridge] = 81
    for master, record in (
        u.governance_module().decode_settlement_assets(view.config(84)).items()
    ):
        origin = record["origin"]
        if origin["kind"] == "token_bridge":
            recognition.append(
                {
                    "master": "0:" + master,
                    "status": {"active": 1, "admission_suspended": 2, "retired": 3}[
                        record["status"]
                    ],
                    "bridge": "-1:" + origin["bridge_address"],
                    "bridge_config_param": routes[origin["bridge_address"]],
                }
            )
        else:
            raise u.Refused("unknown local recognition origin")
    binding = {
        "schema": "tos-settlement-source/1",
        "network": asset.GENESIS["root"],
        "chain_id": 1,
        "bridge": states[0]["evm"]["bridge"],
        "bridge_code_sha256": states[0]["monitor_source_bridge_code_sha256"],
        "assets": [],
    }
    policy = {
        "schema": "tos-settlement-policy/1",
        "network": asset.GENESIS["root"],
        "max_age_seconds": 120,
        "thresholds": {
            "payout_blocks": 30,
            "returned_seconds": 120,
            "returned_count": 4,
            "refusals_count": 24,
            "rereport_clear_blocks": 30,
            "rereport_clear_seconds": 300,
        },
        "assets": [],
    }
    entries = []
    for i, state in enumerate(states):
        label = ("usdc", "usdt")[i]
        token = state["evm"]["token"] if i == 0 else state["namespace"]["token"]
        master = asset.derive_master(bridge, token, minter_code, wallet_code)
        u.require(
            view.minter(bridge, token) == master,
            "bridge-anchored minter derivation differs",
        )
        info = view.account(master)
        u.require(info["state"] == "active", "monitored master is not deployed")
        u.require(
            u.lib.parse_boc(base64.b64decode(info["code"])).hash().hex()
            == minter_code.hash().hex(),
            "monitored master code differs",
        )
        values = view.read(
            "runGetMethod", address=master, method="get_token_data", stack=[]
        )
        u.require(
            all(
                v["exit_code"] == 0 and v["stack"] == values[0]["stack"] for v in values
            ),
            "supply references disagree",
        )
        supply = u.num(values[0]["stack"][0])
        runtime = (
            source.LOCAL_TEST_CODE
            if i == 0
            else hashlib.sha256(
                bytes.fromhex(artifact["deployedBytecode"][2:])
            ).hexdigest()
        )
        implementation = pinned_implementation(runtime)
        policy["assets"].append(
            {
                "id": label,
                "symbol": label.upper(),
                "master": master,
                "source_token": token,
                "implementation": implementation,
                "min_lock_headroom": 1_000_000,
                "occupancy_percent": 90,
                "actors": [],
            }
        )
        binding["assets"].append(
            {
                "id": label,
                "token": token,
                "code_sha256": runtime,
                "profile": "local_test" if i == 0 else "legacy_usdt",
                "redemptions": [],
            }
        )
        entries.append(
            {
                "id": label,
                "master": master,
                "source_token": token,
                "implementation": implementation,
                "wrapped_supply": supply,
                "swap_used": swap_count,
                "swap_limit": 16,
                "channels_used": channels,
                "channels_limit": 8,
                "actors": [],
                "redemptions": [],
            }
        )
        a.sync_write(
            directory / (label + "-master-data.boc"), base64.b64decode(info["data"])
        )
    observation = {
        "schema": "tos-settlement-observation/1",
        "network": asset.GENESIS["root"],
        "complete": True,
        "checkpoint": checkpoint,
        "bridge_address": bridge,
        "recognition": recognition,
        "assets": entries,
    }
    a.document(directory / "tos-checkpoint.json", view.point)
    a.sync_write(directory / "config84.boc", u.lib.serialize_boc(view.config(84)))
    a.sync_write(directory / "bridge-data.boc", u.lib.serialize_boc(data))
    return observation, binding, policy


def tick(args):
    directory = u.private_dir(args.state)
    report = directory / "report.json"
    source.stale_report(report)
    states = [
        json.loads(args.source_state.read_text()),
        json.loads(args.asset_state.read_text()),
    ]
    pin = json.loads(args.source_pin.read_text())
    u.require(
        pin["genesis"] == asset.GENESIS["root"]
        and pin["source_bridge"] == states[0]["evm"]["bridge"],
        "source bridge pin differs",
    )
    states[0]["monitor_source_bridge_code_sha256"] = pin["source_bridge_runtime_sha256"]
    artifact = asset.artifact_at(args.artifact, args.build_log)
    tos, binding, policy = tos_observation(
        u.Chain(args.data), states, artifact, directory
    )
    for name, value in [("binding", binding), ("policy", policy)]:
        path = directory / (name + ".json")
        if path.exists():
            u.require(
                json.loads(path.read_text()) == value,
                "monitor " + name + " changed; review a new scope",
            )
        else:
            a.document(path, value)
    a.document(directory / "tos.json", tos)
    previous = directory / "previous.json"
    value = source.collect(
        source.RPC(args.evm_rpc),
        binding,
        tos,
        json.loads(previous.read_text()) if previous.exists() else None,
        **({"gap_dir": args.gap_dir} if getattr(args, "gap_dir", None) else {}),
    )
    a.document(directory / "snapshot.json", value)
    result = subprocess.run(
        [
            sys.executable,
            str(u.TESTNET_SCRIPTS / "check-settlement.py"),
            "--policy",
            str(directory / "policy.json"),
            "--snapshot",
            str(directory / "snapshot.json"),
            "--state-dir",
            str(directory),
            *([] if previous.exists() else ["--initialize-baseline"]),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    u.require(result.returncode in (0, 1, 2), "checker process failed")
    output = json.loads(report.read_text())
    u.require(
        output.get("checkpoint", {}).get("utime", 0) > 0,
        "checker did not publish fresh health",
    )
    print(
        json.dumps(
            {
                "exit": result.returncode,
                "checkpoint": output["checkpoint"],
                "provider_pause_assets": output["provider_pause_assets"],
                "alarms": [x["code"] for x in output["alarms"]],
                "scope": "bridge-and-masters-only",
            }
        ),
        flush=True,
    )
    return result.returncode


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, default=Path("/data"))
    p.add_argument("--source-state", type=Path, required=True)
    p.add_argument("--asset-state", type=Path, required=True)
    p.add_argument("--source-pin", type=Path, required=True)
    p.add_argument("--artifact", type=Path, required=True)
    p.add_argument("--build-log", type=Path, required=True)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--evm-rpc", default="http://127.0.0.1:18545")
    p.add_argument("--interval", type=int, default=15)
    p.add_argument("--once", action="store_true")
    p.add_argument(
        "--gap-dir",
        type=Path,
        help="a reconcile-settlement-gap.py archive for one --once tick (runbook step 4)",
    )
    args = p.parse_args()
    u.require(
        args.gap_dir is None or args.once,
        "--gap-dir is only for one explicit --once tick",
    )
    u.require(
        args.evm_rpc.startswith("http://127.0.0.1:") and 1 <= args.interval <= 30,
        "local endpoint and bounded interval required",
    )
    root = u.private_dir(args.state)
    with (root / "scope.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return run(args, root)


# Every failure of one read or one tick is a STALE tick: the report is marked
# stale (provider and buyer refuse paid work on it) and the loop keeps going.
# A node's RPC refusal (rate limit, timeout, connection) arrives as a
# testnet_lib.TestnetError subclass (RpcError, or testnet_ops.Unknown wrapping it).
STALE_ERRORS = (
    OSError,
    ValueError,
    KeyError,
    TypeError,
    u.Refused,
    u.lib.TestnetError,
    source.http.client.HTTPException,
    RecursionError,
    subprocess.TimeoutExpired,
)
MAX_BACKOFF_SECONDS = 60


def stale_delay(interval, failures):
    """The wait after `failures` consecutive stale ticks: the normal interval,
    doubled per further failure, never above MAX_BACKOFF_SECONDS."""
    if failures <= 1:
        return interval
    return min(MAX_BACKOFF_SECONDS, interval * 2 ** min(failures - 1, 6))


def run(args, root, *, sleep=time.sleep, ticks=None):
    failures = 0
    done = 0
    while True:
        started = time.monotonic()
        try:
            code = tick(args)
            failures = 0
        except STALE_ERRORS as error:
            source.stale_report(root / "report.json")
            failures += 1
            print(
                json.dumps(
                    {"status": "STALE", "reason": str(error), "consecutive": failures}
                ),
                flush=True,
            )
            code = 2
        done += 1
        if args.once or (ticks is not None and done >= ticks):
            return code
        wait = stale_delay(args.interval, failures) if failures else args.interval
        sleep(max(0, wait - (time.monotonic() - started)))


if __name__ == "__main__":
    raise SystemExit(main())
