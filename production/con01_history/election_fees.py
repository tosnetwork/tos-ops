"""Read-only two-observer election fee alert. Never funds, signs or sends."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import time
import urllib.request
from pathlib import Path

from .audit import Rpc, read, wire
from .certificate import identity, require

MINIMUM = 1_400_000_000
WARNING = 5_200_000_000
MAX_REPLY = 2 * 1024 * 1024


class FeeRpc(Rpc):
    def call(self, method, params):
        require(
            method in {"getMasterchainInfo", "getBlockHeader", "getAddressInformation"},
            "read-only fee RPC allowlist",
        )
        request = urllib.request.Request(
            self.url,
            json.dumps(
                dict(jsonrpc="2.0", id=1, method=method, params=params)
            ).encode(),
            {"Content-Type": "application/json"},
        )
        with self.opener.open(request, timeout=10) as response:
            raw = response.read(MAX_REPLY + 1)
        require(len(raw) <= MAX_REPLY, "fee RPC response byte bound")
        answer = json.loads(raw)
        require(
            isinstance(answer, dict) and "result" in answer and "error" not in answer,
            "fee RPC unavailable",
        )
        time.sleep(0.6)
        return answer["result"]


def amount(value):
    require(
        isinstance(value, str)
        and value.isascii()
        and value.isdecimal()
        and len(value) <= 20,
        "invalid nanotOS balance",
    )
    result = int(value)
    require(result <= 2**64 - 1, "nanotOS balance exceeds u64")
    return result


def observe(sources, wallets, genesis, now):
    require(
        len(sources) == 2 and len({source.url for source in sources}) == 2,
        "two distinct RPC observers required",
    )
    require(identity(genesis)[2] == 0, "pinned genesis required")
    require(
        isinstance(wallets, dict)
        and 0 < len(wallets) <= 16
        and all(
            re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name)
            and re.fullmatch(r"-1:[0-9a-f]{64}", address)
            for name, address in wallets.items()
        ),
        "bounded masterchain fee wallet manifest required",
    )
    require(len(set(wallets.values())) == len(wallets), "duplicate fee wallet")
    heads = [source.call("getMasterchainInfo", {}) for source in sources]
    require(
        all(identity(head["init"]) == identity(genesis) for head in heads),
        "observer genesis differs from approved network",
    )
    height = min(identity(head["last"])[2] for head in heads) - 3
    require(height > 0, "common checkpoint unavailable")
    headers = [
        source.call(
            "getBlockHeader",
            dict(workchain=-1, shard="-9223372036854775808", seqno=height),
        )
        for source in sources
    ]
    require(
        all(
            header["global_id"] == 2 and header["id"]["seqno"] == height
            for header in headers
        ),
        "public checkpoint required",
    )
    require(
        identity(headers[0]["id"]) == identity(headers[1]["id"]),
        "checkpoint full-id disagreement",
    )
    require(
        all(
            type(header["gen_utime"]) is int and 0 <= now - header["gen_utime"] <= 60
            for header in headers
        ),
        "stale or future fee observation",
    )
    rows = {}
    for name, address in sorted(wallets.items()):
        answers = [
            source.call("getAddressInformation", dict(address=address, seqno=height))
            for source in sources
        ]
        require(
            all(
                identity(answer["block_id"]) == identity(headers[0]["id"])
                for answer in answers
            ),
            "account read not bound to common checkpoint",
        )
        balances = [amount(answer["balance"]) for answer in answers]
        require(balances[0] == balances[1], "fee balance disagreement")
        balance = balances[0]
        rows[name] = dict(
            balance_nanotos=balance,
            warning=balance < WARNING,
            cannot_afford_next_stake=balance < MINIMUM,
        )
    return dict(
        status="LOW_FEE_RUNWAY"
        if any(row["warning"] for row in rows.values())
        else "HEALTHY_FEE_RESERVE",
        checked_utc=now,
        valid_until_utc=now + 600,
        checkpoint=wire(headers[0]["id"]),
        wallets=rows,
        next_stake_fee_nanotos=MINIMUM,
        warning_threshold_nanotos=WARNING,
        scope="Two-source RPC observation, not a cryptographic spending authorization. Three nominal stake fees plus storage; maintenance/recovery and live pricing cost extra.",
        automatic_top_up=False,
    )


def write_status(path, report):
    require(path.parent.is_dir(), "existing private status directory required")
    fd, name = tempfile.mkstemp(prefix=".fee-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", action="append", required=True)
    parser.add_argument("--wallets", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        wallets = json.loads(read(args.wallets, 16384))
        genesis = json.loads(read(args.genesis, 16384))
        report = observe(
            [FeeRpc(url) for url in args.rpc], wallets, genesis, time.time()
        )
        code = 1 if report["status"] == "LOW_FEE_RUNWAY" else 0
    except Exception as error:
        report = dict(
            status="INDETERMINATE",
            checked_utc=time.time(),
            reason=(type(error).__name__ + ": " + str(error))[:300],
            automatic_top_up=False,
        )
        code = 2
    write_status(args.out, report)
    print(json.dumps(report), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
