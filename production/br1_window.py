"""Read-only, current-term window assessment; never an approval to spend."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import struct
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

from con01_history import audit, formats as f
from con01_history.certificate import Refused, SignatureVerifier, identity, require

MAX_AGE = 30
SETTLE_SECONDS = 905
MIN_REMAINING = 1800


def assess(chain, configs, elections, checked):
    """Assess freshly authenticated inputs, retaining separate window refusals."""
    require(
        chain["status"] == "VERIFIED_GENESIS_CHAIN_AND_THREE_SOURCE_SUFFIX",
        "proof status",
    )
    require(
        len(chain["sources"]) == 3 and len(configs) == 2 and len(elections) == 2,
        "source counts",
    )
    rows = [source["links"][-1] for source in chain["sources"].values()]
    for row in rows:
        require(
            identity(row["id"]) == identity(chain["target"]), "proved target differs"
        )
        require(
            row["term_schedule"] == "within_schedule", "governing set outside schedule"
        )
        stamp = row["header"]["gen_utime"]
        require(
            type(stamp) is int and -5 <= checked - stamp <= MAX_AGE,
            "stale/future target",
        )
    current = configs[0]
    require(configs[1] == current, "proved config disagreement")
    require(
        current["global_id"] == 2 and current["version"] == 16,
        "public global2/version16 required",
    )
    require(current["total"] == 4, "four validators required")
    since, until = current["since"], current["until"]
    require(
        type(since) is int and type(until) is int and 0 <= since < until, "term bounds"
    )
    require(since <= checked < until, "current term does not contain now")
    require(
        all(
            (row["validator_since"], row["validator_until"], row["set_hash"])
            == (since, until, current["set_hash"])
            for row in rows
        ),
        "config differs from governing certified set",
    )
    require(
        all(type(value) is int and value >= 0 for value in elections),
        "election result type",
    )
    reasons = []
    if checked < since + SETTLE_SECONDS:
        reasons.append("term_not_settled")
    if until - checked <= MIN_REMAINING:
        reasons.append("too_close_to_handover")
    if any(elections):
        reasons.append("active_election")
    return {
        "schema": "tos.br1.quiet-term.v1",
        "quiet": not reasons,
        "reasons": reasons,
        "checked_utc": checked,
        "valid_until_utc": min(
            checked + MAX_AGE,
            min(row["header"]["gen_utime"] for row in rows) + MAX_AGE,
            until - MIN_REMAINING,
        )
        if not reasons
        else checked,
        "term": current,
        "target": chain["target"],
        "settled_after_utc": since + SETTLE_SECONDS,
        "quiet_before_utc": until - MIN_REMAINING,
        "election_ids": elections,
        "election_observation": "Two loopback RPC getter replies; not an authenticated contract-state proof.",
        "public_activation_approved": False,
        "scope": "Current-term window only; resource/history/budget/custody gates remain separate.",
    }


def config(rpc, key, path):
    query = (
        f.T("config")
        + struct.pack("<I", 0x8000)
        + f.bid(key)[4:]
        + struct.pack("<I8i", 8, 8, 19, 28, 29, 30, 32, 34, 36)
    )
    reply = rpc.call("getProofQuery", {"query": f.B(query)}, path)
    block, params, _ = f.key_config_reply(f.D(reply["reply"]))
    require(identity(block) == identity(key), "config proof differs from certified key")
    cell = params[8].c.slice().ref().slice()
    require(cell.u(8) == 0xC4, "config8 constructor")
    version = cell.u(32)
    cell.u(64)
    cell.end()
    global_id = params[19].c.slice().ref().slice()
    network = global_id.u(32)
    global_id.end()
    current = f.validators(params[34].c.slice().ref())
    return {
        "global_id": network,
        "version": version,
        "since": current["since"],
        "until": current["until"],
        "total": current["total"],
        "set_hash": current["cell_hash"].hex(),
    }


def election(rpc, path):
    query = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "runGetMethod",
        "params": {
            "address": "-1:" + "3" * 64,
            "method": "active_election_id",
            "stack": [],
        },
    }
    request = urllib.request.Request(
        rpc.url, json.dumps(query).encode(), {"Content-Type": "application/json"}
    )
    with rpc.opener.open(request, timeout=10) as response:
        raw = response.read(8193)
    require(len(raw) <= 8192, "election reply bound")
    with path.open("xb") as output:
        output.write(raw)
    value = json.loads(raw)
    require("result" in value and "error" not in value, "election RPC unavailable")
    value = value["result"]
    require(
        type(value["exit_code"]) is int and value["exit_code"] == 0,
        "election getter failed",
    )
    stack = value["stack"]
    require(
        type(stack) is list
        and len(stack) == 1
        and type(stack[0]) is list
        and len(stack[0]) == 2
        and stack[0][0] == "num"
        and type(stack[0][1]) is str,
        "election stack",
    )
    return int(stack[0][1], 0)


def refresh_target(args, prefix, verifier):
    """Authenticate a new target after slow genesis acquisition, without a cache."""
    archive = prefix["sources"][args.archive]
    require(
        prefix["status"] == "VERIFIED_GENESIS_CHAIN_AND_THREE_SOURCE_SUFFIX"
        and archive["from_genesis"] is True
        and identity(archive["anchor"]) == identity(prefix["anchor"])
        and identity(archive["target"]) == identity(prefix["target"]),
        "refresh needs verified genesis prefix",
    )
    join = archive["keys"][str(max(map(int, archive["keys"])))]
    require(identity(join)[2] > 0, "refresh needs certified key")
    out = args.out / "fresh"
    out.mkdir(mode=0o700)
    sources = {
        name: audit.Rpc(url) for name, url in (item.split("=", 1) for item in args.rpc)
    }
    require(len(sources) == 3 and args.archive in sources, "refresh source population")
    heads = {}
    for name, rpc in sources.items():
        info = rpc.call("getMasterchainInfo", {}, out / f"head-{name}.json")
        require(
            identity(info["init"]) == identity(prefix["anchor"]),
            "refresh genesis mismatch",
        )
        heads[name] = info["last"]
    seqno = min(identity(head)[2] for head in heads.values())
    require(seqno >= identity(prefix["target"])[2], "refresh target went backwards")
    target = None
    for name, rpc in sources.items():
        header = rpc.call(
            "getBlockHeader",
            dict(workchain=-1, shard=str(-9223372036854775808), seqno=seqno),
            out / f"target-{name}.json",
        )
        require(header["global_id"] == 2, "refresh public network")
        require(identity(header["id"])[2] == seqno, "refresh header height differs")
        require(
            target is None or identity(header["id"]) == identity(target),
            "refresh full target disagreement",
        )
        target = header["id"]
    reports = {
        name: audit.acquire(rpc, join, target, out / f"suffix-{name}", verifier)
        for name, rpc in sources.items()
    }
    reference = reports[args.archive]
    require(
        all(row["keys"] == reference["keys"] for row in reports.values()),
        "refresh key chain disagreement",
    )
    result = dict(
        status="VERIFIED_GENESIS_CHAIN_AND_THREE_SOURCE_SUFFIX",
        anchor=prefix["anchor"],
        target=audit.wire(target),
        join_key=audit.wire(join),
        archive=args.archive,
        sources=reports,
        genesis_prefix=dict(
            path=str(args.out / "chain/REPORT.json"),
            sha256=hashlib.sha256(
                (args.out / "chain/REPORT.json").read_bytes()
            ).hexdigest(),
        ),
        claim="Same-run genesis prefix authenticates refresh join; three sources independently prove the new target; all freshness checks remain unchanged.",
    )
    audit.write_new(out / "REPORT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("anchor", "verifier", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--rpc", action="append", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--join-key", type=int, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, exist_ok=False)
    verifier = SignatureVerifier(args.verifier, args.verifier_sha256)
    try:
        options = SimpleNamespace(**{**vars(args), "out": args.out / "chain"})
        with contextlib.redirect_stdout(io.StringIO()):
            audit.collect(options, verifier)
        chain = json.loads((options.out / "REPORT.json").read_bytes())
        chain = refresh_target(args, chain, verifier)
        archive = chain["sources"][args.archive]
        key = archive["keys"][str(max(map(int, archive["keys"])))]
        configs, elections = [], []
        for index, named in enumerate(args.rpc[:2]):
            rpc = audit.Rpc(named.split("=", 1)[1])
            configs.append(config(rpc, key, args.out / f"config-{index}.json"))
            elections.append(election(rpc, args.out / f"election-{index}.json"))
        result = assess(chain, configs, elections, time.time())
        audit.write_new(args.out / "WINDOW.json", result)
        print(json.dumps(result))
        return 0 if result["quiet"] else 3
    finally:
        verifier.close()
        f.Cell.hd.cache_clear()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Refused, AssertionError, KeyError, ValueError, OSError) as error:
        raise SystemExit("WINDOW_REFUSED: " + str(error)) from None
