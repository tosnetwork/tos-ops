"""Read-only proof-chain collection and independent historical verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import time
import urllib.parse
import urllib.request
from pathlib import Path

from . import formats as f
from .certificate import Refused, SignatureVerifier, identity, require, verify_packet

MAX_PACKET = 2 * 1024 * 1024
MAX_PACKETS = 64
MAX_BYTES = 64 * 1024 * 1024


def wire(block):
    wc, shard, seq, root, file = identity(block)
    return dict(
        workchain=wc,
        shard=str(shard),
        seqno=seq,
        root_hash=f.B(root),
        file_hash=f.B(file),
    )


def read(path, limit=MAX_PACKET):
    with Path(path).open("rb") as handle:
        value = handle.read(limit + 1)
    require(len(value) <= limit, "artifact byte bound")
    return value


def write_new(path, value):
    with Path(path).open("x") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def verify_files(paths, anchor, target, verifier):
    require(0 < len(paths) <= MAX_PACKETS, "proof packet count")
    current = wire(anchor)
    keys = {current["seqno"]: current}
    links = []
    files = []
    total = 0
    for path in paths:
        raw = read(path)
        total += len(raw)
        require(total <= MAX_BYTES, "proof aggregate byte bound")
        packet = verify_packet(raw, current, verifier)
        require(len(links) + len(packet["links"]) <= 512, "proof link count")
        links.extend(packet["links"])
        current = packet["end"]
        for result in packet["links"]:
            if result["header"]["key"]:
                keys[result["id"]["seqno"]] = result["id"]
        files.append(
            dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        )
    require(
        identity(current) == identity(target),
        "proof chain misses exact requested target",
    )
    require(packet["complete"], "last proof packet is incomplete")
    return dict(
        status="VERIFIED_KEY_CHAIN",
        anchor=wire(anchor),
        target=wire(target),
        from_genesis=identity(anchor)[2] == 0,
        keys={str(k): v for k, v in keys.items()},
        links=links,
        files=files,
        claim="Authenticated key-block trust chain only; not complete per-block collection or live handover qualification.",
        term_schedule_incidents=[
            dict(
                seqno=r["id"]["seqno"],
                kind=r["term_schedule"],
                since=r["validator_since"],
                until=r["validator_until"],
                utime=r["header"]["gen_utime"],
            )
            for r in links
            if r["term_schedule"] != "within_schedule"
        ],
    )


class Rpc:
    """Loopback-only named SSH tunnels; bounded reads and no write method."""

    def __init__(self, url):
        endpoint = urllib.parse.urlsplit(url)
        require(
            endpoint.scheme == "http"
            and endpoint.hostname == "127.0.0.1"
            and endpoint.port
            and endpoint.path == "/jsonRPC"
            and not endpoint.username
            and not endpoint.password
            and not endpoint.query
            and not endpoint.fragment,
            "only explicit loopback RPC origin",
        )
        self.url = url
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method, params, path):
        require(
            method in {"getMasterchainInfo", "getBlockHeader", "getProofQuery"},
            "read-only RPC allowlist",
        )
        request = urllib.request.Request(
            self.url,
            json.dumps(
                dict(jsonrpc="2.0", id=1, method=method, params=params)
            ).encode(),
            {"Content-Type": "application/json"},
        )
        with self.opener.open(request, timeout=30) as reply:
            raw = reply.read(MAX_PACKET + 1)
        require(len(raw) <= MAX_PACKET, "RPC response byte bound")
        with path.open("xb") as handle:
            handle.write(raw)
        answer = json.loads(raw)
        require(
            isinstance(answer, dict) and "result" in answer and "error" not in answer,
            "RPC proof unavailable",
        )
        time.sleep(0.2)
        return answer["result"]


def acquire(rpc, anchor, target, out, verifier):
    out.mkdir(mode=0o700)
    current = wire(anchor)
    paths = []
    total = 0
    for number in range(MAX_PACKETS):
        query = (
            f.T("proof") + struct.pack("<I", 1) + f.bid(current)[4:] + f.bid(target)[4:]
        )
        answer = rpc.call(
            "getProofQuery", dict(query=f.B(query)), out / f"{number:04}.json"
        )
        raw = f.D(answer["reply"])
        total += len(raw)
        require(total <= MAX_BYTES, "proof acquisition byte bound")
        packet = verify_packet(raw, current, verifier)
        require(
            identity(packet["end"])[2] <= identity(target)[2],
            "proof overshoots requested target",
        )
        path = out / f"chain-{number:04}.tl"
        with path.open("xb") as handle:
            handle.write(raw)
        paths.append(path)
        current = packet["end"]
        if identity(current) == identity(target):
            require(packet["complete"], "incomplete terminal proof packet")
            return verify_files(paths, anchor, target, verifier)
    raise Refused("proof acquisition packet limit")


def collect(args, verifier):
    anchor = json.loads(read(args.anchor, 16384))
    require(identity(anchor)[2] == 0, "collection needs pinned genesis")
    require(len(args.rpc) == 3, "exactly three named observers required")
    sources = {}
    for item in args.rpc:
        name, url = item.split("=", 1)
        require(
            name
            and len(name) <= 32
            and name.replace("-", "").isalnum()
            and name not in sources,
            "source label",
        )
        require(url not in [r.url for r in sources.values()], "duplicate RPC source")
        sources[name] = Rpc(url)
    require(args.archive in sources, "archive must be one of the named observers")
    args.out.mkdir(mode=0o700)
    heads = {}
    for name, rpc in sources.items():
        info = rpc.call("getMasterchainInfo", {}, args.out / f"head-{name}.json")
        require(
            identity(info["init"]) == identity(anchor),
            "RPC genesis differs from pinned anchor",
        )
        heads[name] = info["last"]
    seq = min(identity(head)[2] for head in heads.values())
    target = None
    for name, rpc in sources.items():
        header = rpc.call(
            "getBlockHeader",
            dict(workchain=-1, shard=str(-9223372036854775808), seqno=seq),
            args.out / f"target-{name}.json",
        )
        require(header["global_id"] == 2, "public network required")
        require(
            target is None or identity(header["id"]) == identity(target),
            "common target full-id disagreement",
        )
        target = header["id"]
    archive = acquire(
        sources[args.archive], anchor, target, args.out / "archive-chain", verifier
    )
    require(
        str(args.join_key) in archive["keys"],
        "join point is not genesis-authenticated key block",
    )
    join = archive["keys"][str(args.join_key)]
    reports = {args.archive: archive}
    for name, rpc in sources.items():
        if name == args.archive:
            continue
        report = acquire(rpc, join, target, args.out / f"suffix-{name}", verifier)
        for seqno, key in report["keys"].items():
            require(
                seqno in archive["keys"]
                and identity(key) == identity(archive["keys"][seqno]),
                "observer key-chain disagreement",
            )
        reports[name] = report
    result = dict(
        status="VERIFIED_GENESIS_CHAIN_AND_THREE_SOURCE_SUFFIX",
        anchor=wire(anchor),
        target=wire(target),
        join_key=wire(join),
        archive=args.archive,
        sources=reports,
        original_qualification_unchanged=True,
        claim="Archive prefix is authenticated from genesis; all three sources independently prove the same suffix/target. This does not restore missing historical observer traffic or prove every historical certificate.",
    )
    write_new(args.out / "REPORT.json", result)
    print(
        json.dumps(
            dict(
                status=result["status"],
                target=seq,
                join_key=args.join_key,
                archive_packets=len(archive["files"]),
                term_incidents=len(archive["term_schedule_incidents"]),
            )
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    commands = parser.add_subparsers(dest="mode", required=True)
    check = commands.add_parser("verify")
    check.add_argument("--anchor", type=Path, required=True)
    check.add_argument("--target", type=Path, required=True)
    check.add_argument("--proof", type=Path, action="append", required=True)
    check.add_argument("--out", type=Path, required=True)
    network = commands.add_parser("collect")
    network.add_argument("--anchor", type=Path, required=True)
    network.add_argument("--rpc", action="append", required=True)
    network.add_argument("--archive", required=True)
    network.add_argument("--join-key", type=int, required=True)
    network.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    verifier = SignatureVerifier(args.verifier, args.verifier_sha256)
    try:
        if args.mode == "collect":
            collect(args, verifier)
        else:
            result = verify_files(
                args.proof,
                json.loads(read(args.anchor, 16384)),
                json.loads(read(args.target, 16384)),
                verifier,
            )
            write_new(args.out, result)
            print(json.dumps(dict(status=result["status"], links=len(result["links"]))))
    finally:
        verifier.close()


if __name__ == "__main__":
    main()
