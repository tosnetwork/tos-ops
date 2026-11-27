#!/usr/bin/env python3
"""Read-only source observations for the settlement checker.

Enrich an already authenticated TOS observation; never invent its actor state.
RPC answers are trusted endpoint observations, not cross-domain proofs. All
source reads use one block hash; every receipt in the bounded interval is read,
so truncated log-query pages cannot silently hide an issuer event. No keys or
signing RPC methods are accepted. See settlement-monitor.md.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

SPEC = importlib.util.spec_from_file_location(
    "settlement_monitor", Path(__file__).with_name("check-settlement.py")
)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)
Invalid = monitor.Invalid
MAX_BLOCKS = 64
MAX_TRANSACTIONS = 4096
MAX_LOGS = 16384
MAX_RESPONSE = 4 << 20
SELECTORS = {
    "balance": "70a08231",
    "blacklist_legacy": "e47d6060",
    "blacklist_standard": "fe575a87",
    "paused": "5c975abb",
    "fee": "dd644f72",
    "maximum": "35390714",
    "deprecated": "0e136b19",
    "upgraded": "26976e3f",
    "caps": "3cb72d57",
    "test_fee": "b8606eef",
}
TOPICS = {
    "Lock": "0x1af7c5c9fa10634a4d4a22e141ad33d6ccd5f1474cde819b57b75aa6762f01a5",
    "Unlock": "0x7288db6a9257374290bd46846c6c7a988c10fad7aeba335d3ed9b30da2bea91c",
    "LockRefunded": "0x7554de4b86cc59591f927a6e4d05830720815a64ac3d6a4102d95cca2ebd8b24",
    "DestroyedBlackFunds": "0x61e6e66b0d6339b2980aecc6ccc0039736791f0ccde9ed512e789a7fbdd698c6",
    "Pause": "0x6985a02210a168e66602d3235cb6db0e70f92b3ba4d376a33c0f3d9434bff625",
    "Paused": "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258",
}
# The original local source fixture has no blacklist, pause or upgrade path.
# This is an exact deployed-code exception, never a fallback for failed getters.
LOCAL_GENESIS = "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366"
LOCAL_TEST_CODE = "a2847a6069933a1e31b0864afaf6feaba7e1f117f8f88fe2cbb884bc30ca5a67"
READ_METHODS = frozenset(
    {
        "eth_chainId",
        "eth_getBlockByNumber",
        "eth_getTransactionReceipt",
        "eth_call",
        "eth_getCode",
        "eth_getStorageAt",
    }
)


def require(condition, message):
    if not condition:
        raise Invalid(message)


def address(value):
    require(
        isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", value),
        "invalid source address",
    )
    return value.lower()


def raw(value, size=None):
    require(
        isinstance(value, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value),
        "invalid RPC bytes",
    )
    data = bytes.fromhex(value[2:])
    require(
        len(data) <= MAX_RESPONSE and (size is None or len(data) == size), "invalid RPC byte length"
    )
    return data


def quantity(value):
    require(
        isinstance(value, str) and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})", value),
        "invalid RPC quantity",
    )
    return int(value, 16)


def words(value, count):
    data = raw(value, 32 * count)
    return [int.from_bytes(data[i : i + 32], "big") for i in range(0, len(data), 32)]


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, "duplicate RPC JSON field")
        result[key] = value
    return result


class RPC:
    def __init__(self, url, timeout=45):
        parsed = urlsplit(url)
        require(
            parsed.scheme in ("http", "https")
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.fragment,
            "invalid source endpoint",
        )
        require(
            parsed.scheme == "https" or parsed.hostname in ("localhost", "127.0.0.1", "::1"),
            "non-local RPC requires TLS",
        )
        self.url, self.deadline, self.counter = url, time.monotonic() + timeout, 0

    def call(self, method, *params):
        require(method in READ_METHODS, "signing or unapproved RPC method refused")
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "source collection deadline")
        self.counter += 1
        request = urllib.request.Request(
            self.url,
            json.dumps(
                dict(jsonrpc="2.0", id=self.counter, method=method, params=list(params))
            ).encode(),
            {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=min(remaining, 10)) as response:
            data = response.read(MAX_RESPONSE + 1)
        require(len(data) <= MAX_RESPONSE, "RPC response too large")
        answer = json.loads(data, object_pairs_hook=pairs)
        require(
            isinstance(answer, dict)
            and answer.get("jsonrpc") == "2.0"
            and type(answer.get("id")) is int
            and answer["id"] == self.counter
            and "error" not in answer
            and "result" in answer,
            "source RPC refused",
        )
        return answer["result"]


def block(rpc, number):
    value = rpc.call("eth_getBlockByNumber", number, False)
    require(isinstance(value, dict), "source block missing")
    raw(value["hash"], 32)
    raw(value["parentHash"], 32)
    quantity(value["number"])
    quantity(value["timestamp"])
    require(isinstance(value["transactions"], list), "missing source transaction inventory")
    return value


def read_uint(rpc, token, selector, checkpoint, arg=None):
    data = "0x" + SELECTORS[selector]
    if arg is not None:
        data += address(arg)[2:].rjust(64, "0")
    return words(rpc.call("eth_call", {"to": address(token), "data": data}, checkpoint), 1)[0]


def read_bool(rpc, token, selector, checkpoint, arg=None):
    value = read_uint(rpc, token, selector, checkpoint, arg)
    require(value in (0, 1), "noncanonical source boolean")
    return bool(value)


def code_hash(rpc, token, checkpoint):
    return hashlib.sha256(raw(rpc.call("eth_getCode", address(token), checkpoint))).hexdigest()


def receipts(rpc, previous, target):
    start, stop = previous["height"], quantity(target["number"])
    require(
        type(start) is int and 0 <= start <= stop and stop - start <= MAX_BLOCKS,
        "source interval exceeds block bound",
    )
    prior = block(rpc, hex(start))
    require(prior["hash"][2:] == previous["hash"], "source baseline reorg")
    all_logs, count, parent = [], 0, prior["hash"]
    seen = set()
    for height in range(start + 1, stop + 1):
        current = block(rpc, hex(height))
        require(
            quantity(current["number"]) == height and current["parentHash"] == parent,
            "source interval not contiguous",
        )
        parent = current["hash"]
        count += len(current["transactions"])
        require(count <= MAX_TRANSACTIONS, "source transaction bound")
        next_log_index = 0
        for index, tx in enumerate(current["transactions"]):
            raw(tx, 32)
            receipt = rpc.call("eth_getTransactionReceipt", tx)
            require(
                isinstance(receipt, dict)
                and receipt["transactionHash"] == tx
                and receipt["blockHash"] == parent
                and quantity(receipt["blockNumber"]) == height
                and quantity(receipt["transactionIndex"]) == index,
                "source receipt missing or mismatched",
            )
            status = quantity(receipt["status"])
            require(
                status in (0, 1)
                and isinstance(receipt["logs"], list)
                and (status == 1 or not receipt["logs"]),
                "invalid receipt status/logs",
            )
            for log in receipt["logs"]:
                require(
                    log["transactionHash"] == tx
                    and log["blockHash"] == parent
                    and quantity(log["blockNumber"]) == height
                    and quantity(log["transactionIndex"]) == index
                    and log.get("removed", False) is False,
                    "source log identity differs",
                )
                require(
                    quantity(log["logIndex"]) == next_log_index,
                    "source receipt log inventory has a gap",
                )
                next_log_index += 1
                key = (parent, quantity(log["logIndex"]))
                require(key not in seen, "duplicate source log")
                seen.add(key)
                require(len(seen) <= MAX_LOGS and len(log["topics"]) <= 4, "source log bound")
                address(log["address"])
                for topic in log["topics"]:
                    raw(topic, 32)
                raw(log["data"])
                all_logs.append(log)
    require(parent == target["hash"], "source target changed")
    return all_logs


def asset_events(logs, token, bridge):
    events, pauses, destroys = [], 0, 0
    for log in logs:
        topics = log["topics"]
        if not topics:
            continue
        sender = address(log["address"])
        if sender == token:
            if topics[0] == TOPICS["DestroyedBlackFunds"]:
                require(len(topics) == 1, "invalid destruction event")
                words(log["data"], 2)
                destroys += 1
            elif topics[0] in (TOPICS["Pause"], TOPICS["Paused"]):
                # Legacy Pause() has no arguments; standard Paused(address) is data.
                require(len(topics) == 1, "invalid pause event")
                words(log["data"], 0 if topics[0] == TOPICS["Pause"] else 1)
                pauses += 1
        if sender != bridge:
            continue
        for kind, topic_position, count, amount_position in (
            ("Lock", 2, 5, 0),
            ("Unlock", 1, 4, 2),
            ("LockRefunded", 3, 1, 0),
        ):
            if topics[0] == TOPICS[kind]:
                require(len(topics) == 4, "invalid bridge event topics")
                event_token = topics[topic_position]
                require(raw(event_token, 32)[:12] == bytes(12), "noncanonical event address")
                values = words(log["data"], count)
                if address("0x" + event_token[-40:]) == token:
                    events.append(
                        dict(
                            id=log["blockHash"][2:] + ":" + str(quantity(log["logIndex"])),
                            kind=kind,
                            amount=values[amount_position],
                        )
                    )
    return events, pauses, destroys


def collect(rpc, binding, base, previous):
    require(
        binding["schema"] == "tos-settlement-source/1"
        and base["complete"] is True
        and base["network"] == binding["network"],
        "source/TOS binding differs",
    )
    require(
        type(binding["chain_id"]) is int and 0 < binding["chain_id"] < 2**32,
        "invalid source chain id",
    )
    require(quantity(rpc.call("eth_chainId")) == binding["chain_id"], "source chain differs")
    bridge = address(binding["bridge"])
    target = block(rpc, "finalized")
    point = dict(blockHash=target["hash"], requireCanonical=True)
    if previous is None:
        # Explicitly approved initial baseline: no earlier event interval is claimed.
        previous_point = dict(height=quantity(target["number"]), hash=target["hash"][2:])
    else:
        require(previous["network"] == base["network"], "baseline network differs")
        previous_point = previous["source_checkpoint"]
    logs = receipts(rpc, previous_point, target)
    require(code_hash(rpc, bridge, point) == binding["bridge_code_sha256"], "bridge code differs")
    configs = {a["id"]: a for a in binding["assets"]}
    require(
        0 < len(configs) <= 16 and len(configs) == len(binding["assets"]), "invalid source assets"
    )
    result = copy.deepcopy(base)
    require(
        set(configs) == {a["id"] for a in result["assets"]}
        and len(result["assets"]) == len(configs),
        "source asset inventory differs",
    )
    for entry in result["assets"]:
        cfg = configs[entry["id"]]
        token = address(cfg["token"])
        require(token == address(entry["source_token"]), "source token identity differs")
        runtime = code_hash(rpc, token, point)
        require(runtime == cfg["code_sha256"], "source token code differs")
        profile = cfg["profile"]
        require(profile in ("legacy_usdt", "standard", "local_test"), "unknown issuer interface")
        if profile == "local_test":
            require(
                base["network"] == LOCAL_GENESIS
                and runtime == LOCAL_TEST_CODE
                and urlsplit(rpc.url).hostname in ("localhost", "127.0.0.1", "::1"),
                "local fixture profile refused",
            )
            require(
                read_uint(rpc, token, "test_fee", point) == 0, "local source fixture fee changed"
            )
        blacklist = "blacklist_legacy" if profile == "legacy_usdt" else "blacklist_standard"
        entry["bridge_balance"] = read_uint(rpc, token, "balance", point, bridge)
        entry["bridge_blacklisted"] = (
            False if profile == "local_test" else read_bool(rpc, token, blacklist, point, bridge)
        )
        entry["paused"] = (
            False if profile == "local_test" else read_bool(rpc, token, "paused", point)
        )
        entry["fee_basis_points"] = (
            read_uint(rpc, token, "fee", point) if profile == "legacy_usdt" else 0
        )
        entry["maximum_fee"] = (
            read_uint(rpc, token, "maximum", point) if profile == "legacy_usdt" else 0
        )
        entry["deprecated"] = (
            read_bool(rpc, token, "deprecated", point) if profile == "legacy_usdt" else False
        )
        if profile == "legacy_usdt":
            target_id = read_uint(rpc, token, "upgraded", point)
            require(target_id < 2**160, "invalid upgrade target")
            implementation = f"0x{target_id:040x}"
        elif profile == "local_test":
            implementation = "0x" + "0" * 40
        else:
            # The operator pins the implementation slot of this particular issuer.
            slot = cfg["implementation_slot"]
            raw(slot, 32)
            storage = raw(rpc.call("eth_getStorageAt", token, slot, point), 32)
            require(storage[:12] == bytes(12), "noncanonical implementation slot")
            implementation = "0x" + storage[12:].hex()
        target_code = code_hash(rpc, implementation, point)
        entry["issuer_identity"] = dict(
            runtime_sha256=runtime, target=implementation, target_code_sha256=target_code
        )
        identity = (
            b"source-issuer-v1\0"
            + bytes.fromhex(runtime)
            + bytes.fromhex(implementation[2:])
            + bytes.fromhex(target_code)
        )
        entry["implementation"] = "sha256:" + hashlib.sha256(identity).hexdigest()
        capdata = "0x" + SELECTORS["caps"] + token[2:].rjust(64, "0")
        total, per_lock, hourly, daily, hour_used, day_used, available = words(
            rpc.call("eth_call", {"to": bridge, "data": capdata}, point), 7
        )
        require(max(total, per_lock, hourly, daily) < 2**128, "invalid cap width")
        entry["lock_cap"] = dict(
            total=total,
            per_lock=per_lock,
            hourly=hourly,
            daily=daily,
            hour_used=hour_used,
            day_used=day_used,
            available=available,
        )
        entry["balance_events"], entry["pause_events"], entry["destroy_events"] = asset_events(
            logs, token, bridge
        )
        entry["balance_from_hash"] = previous_point["hash"]
        entry["events_complete"] = True
        targets = {r["id"]: address(r["receiver"]) for r in cfg["redemptions"]}
        require(
            len(targets) <= 256 and len(targets) == len(cfg["redemptions"]),
            "invalid redemption inventory",
        )
        require(
            len(entry["redemptions"]) == len(targets)
            and {r["id"] for r in entry["redemptions"]} == set(targets),
            "redemption receiver not pinned",
        )
        for redemption in entry["redemptions"]:
            receiver = targets[redemption["id"]]
            redemption["blacklisted"] = (
                False
                if profile == "local_test"
                else read_bool(rpc, token, blacklist, point, receiver)
            )
    require(block(rpc, target["number"])["hash"] == target["hash"], "source checkpoint reorg")
    result["source_checkpoint"] = dict(
        height=quantity(target["number"]),
        hash=target["hash"][2:],
        utime=quantity(target["timestamp"]),
    )
    result["source_binding"] = dict(
        bridge=bridge, chain_id=binding["chain_id"], transactions_checked=True
    )
    return result


def stale_report(path):
    # Publish before RPC: a timeout or terminated collector must not leave a
    # formerly healthy report usable. The checker publishes health only after
    # it validates the completed observation under the same monitor lock.
    monitor.atomic(
        path,
        dict(
            schema="tos-settlement-report/1",
            checkpoint=dict(height=0, hash="0" * 64, utime=0),
            provider_pause_assets=[],
            status="STALE",
        ),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--tos-snapshot", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--initialize-baseline", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--report",
        type=Path,
        required=True,
        help="checker report to invalidate on collection failure",
    )
    args = parser.parse_args(argv)
    inputs = {
        p.resolve() for p in (args.binding, args.tos_snapshot, args.previous) if p is not None
    }
    if (
        args.out.resolve() == args.report.resolve()
        or args.out.resolve() in inputs
        or args.report.resolve() in inputs
    ):
        print("source collector input/output paths overlap")
        return 2
    stale_report(args.report)
    try:
        require(
            args.previous is not None or args.initialize_baseline,
            "initial source baseline needs explicit approval",
        )
        value = collect(
            RPC(args.rpc),
            monitor.read_json(args.binding),
            monitor.read_json(args.tos_snapshot),
            monitor.read_json(args.previous) if args.previous else None,
        )
        monitor.atomic(args.out, value)
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        # Never leave a previously healthy report usable after an RPC failure.
        stale_report(args.report)
        monitor.atomic(args.out, dict(schema="tos-settlement-observation/1", complete=False))
        print("source collection refused; monitor report stale")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
