#!/usr/bin/env python3
"""Check a validator-set handover: every masterchain block on both sides of it is
finalized by the set the chain itself selected for that block.

  check-handover.py collect --boundary UNIXTIME --rpc URL --rpc URL [--rpc URL ...]
                            --genesis-config global.config.json --out DIR
                            [--span 100] [--interval 0.6] [--max-wait 900] [--lock-dir DIR]
  check-handover.py verify --genesis-config global.config.json --out DIR

`--term-start` is another name for `--boundary`: the incoming set's
`utime_since`. Give one URL per validator (each node's own JSON-RPC listener,
for example through an SSH tunnel); at least two are required.

collect is read-only. It refuses any method outside a read-only allow-list,
starts requests to one node at least --interval seconds apart (never less than
0.6 s; with --lock-dir the spacing also holds across processes that share the
directory) and appends every request and the hash of its answer to
DIR/journal.jsonl. It waits until the wall clock passes the boundary, finds the
block at the boundary time on every node once every node's head is 5 blocks past
it (a node that has not received the blocks after the boundary yet answers with
an older block: that is lag and is retried, not a disagreement; nodes whose
heads are past the margin must agree), waits until every head is 5 blocks past
the range, and reads for each of the 2*span+1 blocks around
it, from every node: the finality certificate, lookupBlock, the header and the
shard tops; then ConfigParam 34 at every set-source key block the headers and
certificates name, and ConfigParam 32/34 at the end of the range. When a node
has garbage-collected a source key block's state, ConfigParam 34 is read at the
first collected non-key block whose header (agreed by every node) names that
source instead: ConfigParam 34 changes only at key blocks. The substitution and
the original answers are recorded. Everything lands in DIR/collection.json.

verify is offline and reads only DIR/collection.json. It needs the ML-DSA-44
verifier from the `dilithium-py` package (pure Python, tested with 1.1.0) and
refuses without it. It writes DIR/report.json and exits 0 only on PASS:

  * every node's zero state is the global config's, every header carries the
    profile's global id;
  * every node returns the same full id from lookupBlock, the header and the
    certificate for every block, the same header fields, the same shard tops and
    byte-identical ConfigParam 34 / 32 cells;
  * each block's set is bound by its header: prev_key_block_seqno names the key
    block whose ConfigParam 34 is that block's set. Every node's certificate is
    verified against that set (not against the set the node says it used):
    every ML-DSA-44 signature over the rebuilt signing preimage, unique signers
    of the set, signed weight at least ceil(2/3) of the total. The node's own
    set source must name the same bytes and the certificate's session
    commitment (cc_seqno, validator_set_hash) must equal the header's;
  * after the handover, ConfigParam 32 is the outgoing set and ConfigParam 34
    the incoming one; the blocks are outgoing then incoming, contiguously, and
    the last outgoing block is the key block that installs the incoming set;
  * the term rule: a block generated before its set's utime_since fails. A block
    generated after its set's utime_until is valid while no incoming set has
    been installed (the chain extends the term, for example after a postponed
    election); it is reported under `extended_term` with its block range and
    still has to pass every binding check above. One that does not fails;
  * controls that must be rejected: the outgoing certificate against the
    incoming set and the reverse, a pre-boundary signature spliced into a
    post-boundary certificate, every certificate against the other term's set,
    and certificate tampering (a flipped signature byte, another block's
    signature, another root hash, signatures below the threshold, a duplicate
    or foreign signer, another slot or session, keys rotated between members,
    a conflicting full id on one node).

Agreement among nodes is detection, not a proof chain from an authenticated
anchor: the nodes are trusted to report the headers and configuration they
hold. With identical keys in both terms, signatures alone do not tell the terms
apart; the header binding does (see `bare_verifier_wrong_set_probe`).
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime
import fcntl
import hashlib
import json
import os
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
import network_check as shared  # noqa: E402

SHARD = str(lib.MASTERCHAIN_SHARD)
SCHEMA = "tos-handover-collection/1"
REPORT_SCHEMA = "tos-handover-report/1"
CONTEXT = b"TOS-CONSENSUS-SIMPLEX-v1"
ALG_MLDSA44 = 1
MLDSA44_SIG_LEN = 2420
MIN_INTERVAL = 0.6
HEAD_MARGIN = 5
MAX_SPAN = 1000
MAX_RESPONSE = 32 << 20
READ_ONLY_METHODS = frozenset(
    {
        "getMasterchainInfo",
        "getMasterchainBlockSignatures",
        "lookupBlock",
        "getBlockHeader",
        "shards",
        "getConfigParam",
    }
)
HEADER_FIELDS = (
    "gen_utime",
    "prev_key_block_seqno",
    "catchain_seqno",
    "validator_list_hash_short",
    "is_key_block",
    "global_id",
)

VerifyFn = Callable[[bytes, bytes, bytes], bool]


class HandoverError(lib.TestnetError):
    """A refusal to collect or verify at all (bad input, missing verifier)."""


class Reject(Exception):
    """One certificate, set or answer does not pass a check."""


def utc(t: float) -> str:
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mc_params(seqno: int) -> dict[str, Any]:
    return {"workchain": -1, "shard": SHARD, "seqno": seqno}


def full_id(block: Any) -> tuple:
    if not isinstance(block, dict):
        raise Reject("not a block id")
    try:
        return shared.full_id(block)
    except KeyError as exc:
        raise Reject(f"block id lacks {exc}") from exc


# ---------------------------------------------------------------- collection


def post(url: str, method: str, params: dict[str, Any], timeout: float = 30) -> dict[str, Any]:
    """One JSON-RPC request. Returns what was observed, never raises for a node's
    answer: {"http": status, "answer": envelope} or {"http": status|None, "transport_error": text}."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": lib.RPC_REQUEST_ID, "method": method, "params": params}
    )
    request = urllib.request.Request(
        url, body.encode(), {"Content-Type": "application/json"}, method="POST"
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            status, raw = response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(MAX_RESPONSE + 1)
    except (OSError, ValueError) as exc:
        return {"http": None, "transport_error": f"{type(exc).__name__}: {exc}"}
    if len(raw) > MAX_RESPONSE:
        return {"http": status, "transport_error": "answer exceeds the byte budget"}
    try:
        return {"http": status, "answer": json.loads(raw)}
    except ValueError:
        return {"http": status, "transport_error": "answer is not JSON"}


class Pacer:
    """Request starts to one node at least `interval` seconds apart. With a lock
    file, the spacing is shared with every process that uses the same file."""

    def __init__(
        self, interval: float, clock=time.monotonic, sleep=time.sleep, lock: Path | None = None
    ):
        if interval < MIN_INTERVAL:
            raise HandoverError(f"--interval must be at least {MIN_INTERVAL} s")
        self.interval, self.clock, self.sleep, self.lock = interval, clock, sleep, lock
        self.last: float | None = None

    def wait(self) -> float:
        if self.lock is None:
            return self._space(self.last)
        with self.lock.open("a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            handle.seek(0)
            text = handle.read().strip()
            try:
                shared_last = float(text) if text else None
            except ValueError:
                shared_last = None
            known = [x for x in (shared_last, self.last) if x is not None]
            started = self._space(max(known) if known else None)
            handle.seek(0)
            handle.truncate()
            handle.write(repr(started))
            handle.flush()
            return started

    def _space(self, last: float | None) -> float:
        if last is not None:
            gap = self.interval - (self.clock() - last)
            if gap > 0:
                self.sleep(gap)
        self.last = self.clock()
        return self.last


class Journal:
    """Appends one JSON line per request, flushed before the answer is used."""

    def __init__(self, path: Path):
        self.path, self.mutex = path, threading.Lock()

    def write(self, entry: dict[str, Any]) -> None:
        line = json.dumps(entry, sort_keys=True) + "\n"
        with self.mutex, self.path.open("a") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())


class Node:
    def __init__(
        self, name: str, url: str, pacer: Pacer, journal: Journal, transport=post, now=time.time
    ):
        self.name, self.url, self.pacer, self.journal = name, url, pacer, journal
        self.transport, self.now, self.requests = transport, now, 0

    def call(self, method: str, **params: Any) -> dict[str, Any]:
        if method not in READ_ONLY_METHODS:
            raise HandoverError(f"refusing {method}: not a read-only method")
        self.pacer.wait()
        started = self.now()
        observed = self.transport(self.url, method, params)
        secs = self.now() - started
        self.requests += 1
        entry = {"method": method, "params": params, "t": round(started, 3), "secs": round(secs, 3)}
        entry.update(observed)
        raw = json.dumps(observed.get("answer"), sort_keys=True).encode()
        self.journal.write(
            {
                "utc": utc(started),
                "node": self.name,
                "method": method,
                "params": params,
                "http": observed.get("http"),
                "outcome": outcome(entry),
                "answer_sha256": hashlib.sha256(raw).hexdigest(),
                "secs": entry["secs"],
            }
        )
        return entry


def outcome(entry: dict[str, Any]) -> str:
    if "transport_error" in entry:
        return "transport_error"
    answer = entry.get("answer")
    if isinstance(answer, dict) and "result" in answer and "error" not in answer:
        return "result"
    return "error"


def result_of(entry: Any, what: str) -> Any:
    """The JSON-RPC result recorded in a collected entry, or Reject."""
    if not isinstance(entry, dict):
        raise Reject(f"{what}: not collected")
    if "transport_error" in entry:
        raise Reject(f"{what}: transport error {entry['transport_error']}")
    try:
        return lib.rpc_result(entry.get("answer"), "node", entry.get("method", "?"))
    except lib.TestnetError as exc:
        raise Reject(f"{what}: {exc}") from exc


def maybe(entry: Any) -> Any:
    try:
        return result_of(entry, "")
    except Reject:
        return None


def zero_state(config: dict[str, Any]) -> tuple:
    zero = (config.get("validator") or {}).get("zero_state")
    if not isinstance(zero, dict):
        raise HandoverError("the global config has no validator.zero_state")
    return shared.full_id(shared.normalize_id(zero))


def lowest_head(heads: dict[str, Any], zero: tuple) -> int:
    """The lowest masterchain head seqno among the nodes' getMasterchainInfo
    answers, or -1 when an answer is missing or malformed. A node whose zero
    state is not the global config's is refused."""
    try:
        info = {k: result_of(e, f"{k} getMasterchainInfo") for k, e in heads.items()}
        for k, r in info.items():
            if full_id(r["init"]) != zero:
                raise HandoverError(f"{k} has another zero state than the global config")
        return min(int(r["last"]["seqno"]) for r in info.values())
    except (Reject, KeyError, TypeError, ValueError):
        return -1


def boundary_block(
    nodes: list[Node], boundary: int, zero: tuple, clock, sleep, deadline: float
) -> tuple[dict[str, Any], int]:
    """lookupBlock at the boundary time on every node, repeated until every
    node's head is HEAD_MARGIN blocks past the block the lookups name.

    A node that has not yet received the blocks after the boundary answers the
    time lookup with its own, older head or with an error. That is lag, not a
    disagreement: the lookup is repeated until --max-wait. Only nodes whose heads
    are all past the margin and still name different blocks are refused."""
    while True:
        lookups = {
            n.name: n.call("lookupBlock", workchain=-1, shard=SHARD, unixtime=boundary)
            for n in nodes
        }
        lowest = lowest_head({n.name: n.call("getMasterchainInfo") for n in nodes}, zero)
        unavailable: Reject | None = None
        try:
            centers = {full_id(result_of(e, f"{k} lookupBlock")) for k, e in lookups.items()}
        except Reject as exc:
            centers, unavailable = set(), exc
        if centers and lowest >= max(int(c[2]) for c in centers) + HEAD_MARGIN:
            if len(centers) != 1:
                raise HandoverError("the nodes disagree on the block at the boundary time")
            return lookups, int(next(iter(centers))[2])
        if clock() > deadline:
            if unavailable is not None:
                raise HandoverError(
                    f"the block at the boundary time is unavailable: {unavailable}"
                ) from unavailable
            raise HandoverError(
                "the nodes' heads did not pass the block at the boundary time by "
                f"{HEAD_MARGIN} blocks within --max-wait"
            )
        sleep(5.0)


def collect(
    args: argparse.Namespace,
    transport=post,
    clock=time.monotonic,
    sleep=time.sleep,
    now=time.time,
    pacer_factory=None,
) -> dict[str, Any]:
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise HandoverError(f"{out} is not empty: collect into a new directory")
    if not 1 <= args.span <= MAX_SPAN:
        raise HandoverError(f"--span must be between 1 and {MAX_SPAN}")
    if len(args.rpc) < 2 or len(set(args.rpc)) != len(args.rpc):
        raise HandoverError("give at least two distinct --rpc URLs, one per validator")
    zero = zero_state(json.loads(Path(args.genesis_config).read_text()))
    out.mkdir(parents=True, exist_ok=True)
    journal = Journal(out / "journal.jsonl")
    lock_dir = Path(args.lock_dir) if args.lock_dir else None

    def make_pacer(index: int) -> Pacer:
        if pacer_factory is not None:
            return pacer_factory(index)
        lock = (
            lock_dir / f"rpc-{hashlib.sha256(args.rpc[index].encode()).hexdigest()[:16]}.lock"
            if lock_dir
            else None
        )
        return Pacer(args.interval, clock=clock, sleep=sleep, lock=lock)

    nodes = [
        Node(f"node-{i + 1}", url, make_pacer(i), journal, transport=transport, now=now)
        for i, url in enumerate(args.rpc)
    ]
    names = [n.name for n in nodes]
    deadline = clock() + args.max_wait
    while now() < args.boundary + 1:
        if clock() > deadline:
            raise HandoverError("the boundary time was not reached within --max-wait")
        sleep(min(20.0, args.boundary + 1 - now()))
    started = utc(now())

    lookups, center = boundary_block(nodes, args.boundary, zero, clock, sleep, deadline)
    lo, hi = center - args.span, center + args.span
    if lo < 1:
        raise HandoverError("the range reaches below block 1")

    while True:
        heads = {n.name: n.call("getMasterchainInfo") for n in nodes}
        lowest = lowest_head(heads, zero)
        if lowest >= hi + HEAD_MARGIN:
            break
        if clock() > deadline:
            raise HandoverError(
                f"the nodes' heads did not reach {hi + HEAD_MARGIN} within --max-wait"
            )
        sleep(5.0)

    blocks: dict[str, dict[str, Any]] = {}
    errors: list[str] = []

    def per_node(node: Node) -> None:
        mine: dict[str, Any] = {}
        blocks[node.name] = mine
        try:
            for s in range(lo, hi + 1):
                mine[str(s)] = {
                    "signatures": node.call("getMasterchainBlockSignatures", seqno=s),
                    "lookup": node.call("lookupBlock", **mc_params(s)),
                    "header": node.call("getBlockHeader", **mc_params(s)),
                    "shards": node.call("shards", seqno=s),
                }
        except Exception as exc:  # recorded and refused below; the thread must not die silently
            errors.append(f"{node.name}: {type(exc).__name__}: {exc}")

    run_parallel(nodes, per_node)
    if errors:
        raise HandoverError("block collection failed: " + "; ".join(errors))

    sources: set[int] = set()
    for name in names:
        for entry in blocks[name].values():
            header, cert = maybe(entry["header"]), maybe(entry["signatures"])
            if isinstance(header, dict) and isinstance(header.get("prev_key_block_seqno"), int):
                sources.add(header["prev_key_block_seqno"])
            source = cert_source(cert)
            if source is not None:
                sources.add(source)
    config34: dict[str, dict[str, Any]] = {}
    post_handover: dict[str, dict[str, Any]] = {}

    def per_node_config(node: Node) -> None:
        try:
            config34[node.name] = {
                str(k): node.call("getConfigParam", param=34, seqno=k) for k in sorted(sources)
            }
            post_handover[node.name] = {
                str(p): node.call("getConfigParam", param=p, seqno=hi) for p in (32, 34)
            }
        except Exception as exc:
            errors.append(f"{node.name}: {type(exc).__name__}: {exc}")

    run_parallel(nodes, per_node_config)
    if errors:
        raise HandoverError("configuration collection failed: " + "; ".join(errors))
    collection = {
        "schema": SCHEMA,
        "boundary": args.boundary,
        "span": args.span,
        "range": [lo, hi],
        "nodes": names,
        "rpc": {n.name: n.url for n in nodes},
        "started_utc": started,
        "heads": heads,
        "boundary_lookups": lookups,
        "blocks": blocks,
        "config34": config34,
        "post_handover": post_handover,
        "substitutions": [],
    }
    supplement(collection, {n.name: n for n in nodes})
    collection["finished_utc"] = utc(now())
    collection["requests"] = {n.name: n.requests for n in nodes}
    (out / "collection.json").write_text(json.dumps(collection) + "\n")
    return {
        "range": [lo, hi],
        "center": center,
        "requests": collection["requests"],
        "substitutions": [
            {"source": s["source"], "read_at": s["read_at"]} for s in collection["substitutions"]
        ],
    }


def run_parallel(nodes: list[Node], fn: Callable[[Node], None]) -> None:
    threads = [threading.Thread(target=fn, args=(n,)) for n in nodes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def cert_source(cert: Any) -> int | None:
    if not isinstance(cert, dict):
        return None
    source = ((cert.get("verification") or {}).get("validator_set_source") or {}).get("seqno")
    return source if isinstance(source, int) and not isinstance(source, bool) else None


def substitute_block(collection: dict[str, Any], source: int) -> int | None:
    """The first collected non-key block whose header, on every node, names `source`."""
    lo, hi = collection["range"]
    for s in range(lo, hi + 1):
        headers = [maybe(collection["blocks"][n][str(s)]["header"]) for n in collection["nodes"]]
        if any(not isinstance(h, dict) for h in headers):
            continue
        if len({(h.get("prev_key_block_seqno"), h.get("is_key_block")) for h in headers}) != 1:
            continue
        if (
            headers[0].get("prev_key_block_seqno") == source
            and headers[0].get("is_key_block") is False
        ):
            return s
    return None


def supplement(collection: dict[str, Any], nodes: dict[str, Node]) -> None:
    """Fill each set source whose ConfigParam 34 some node could not serve (its
    state was garbage-collected) from a later non-key block naming that source."""
    names = collection["nodes"]
    missing = sorted(
        {int(k) for n in names for k, e in collection["config34"][n].items() if maybe(e) is None}
    )
    for source in missing:
        chosen = substitute_block(collection, source)
        if chosen is None:
            continue  # verify reports the source as unavailable
        original = {n: collection["config34"][n][str(source)] for n in names}
        for n in names:
            entry = nodes[n].call("getConfigParam", param=34, seqno=chosen)
            entry["substituted_for"] = source
            collection["config34"][n][str(source)] = entry
        collection["substitutions"].append(
            {"source": source, "read_at": chosen, "original": original}
        )


# ---------------------------------------------------------------- certificates


def tl_id(schema_line: str) -> bytes:
    return struct.pack("<I", zlib.crc32(schema_line.encode()))


TL = {
    "dataToSign": tl_id("consensus.dataToSign session_id:int256 data:bytes = consensus.DataToSign"),
    "finalizeVote": tl_id(
        "consensus.simplex.finalizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote"
    ),
    "candidateId": tl_id("consensus.candidateId slot:int hash:int256 = consensus.CandidateId"),
    "ordinary": tl_id(
        "consensus.candidateHashDataOrdinary block:tosNode.blockIdExt collated_file_hash:int256 "
        "parent:consensus.CandidateParent = consensus.CandidateHashData"
    ),
    "empty": tl_id(
        "consensus.candidateHashDataEmpty block:tosNode.blockIdExt parent:consensus.candidateId "
        "= consensus.CandidateHashData"
    ),
    "parent": tl_id(
        "consensus.candidateParent id:consensus.CandidateId = consensus.CandidateParent"
    ),
    "noParent": tl_id("consensus.candidateWithoutParents = consensus.CandidateParent"),
}


def tl_bytes(data: bytes) -> bytes:
    head = (
        bytes([254]) + len(data).to_bytes(3, "little") if len(data) >= 254 else bytes([len(data)])
    )
    out = head + data
    return out + b"\x00" * (-len(out) % 4)


def b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise Reject("not a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise Reject(f"bad base64: {exc}") from exc


def parse_candidate(raw: bytes) -> dict[str, Any]:
    """Strict decode of a boxed consensus.CandidateHashData that consumes every byte."""

    def block_id(off: int) -> tuple[dict[str, Any], int]:
        if len(raw) < off + 80:
            raise Reject("candidate truncated in block id")
        wc, shard, seqno = struct.unpack_from("<iqi", raw, off)
        return (
            {
                "workchain": wc,
                "shard": str(shard),
                "seqno": seqno,
                "root_hash": raw[off + 16 : off + 48],
                "file_hash": raw[off + 48 : off + 80],
            },
            off + 80,
        )

    if len(raw) < 4:
        raise Reject("candidate too short")
    ctor = raw[:4]
    if ctor == TL["ordinary"]:
        blk, off = block_id(4)
        if len(raw) < off + 36:
            raise Reject("candidate truncated")
        off += 32
        parent = raw[off : off + 4]
        off += 4
        if parent == TL["parent"]:
            if raw[off : off + 4] != TL["candidateId"]:
                raise Reject("parent candidateId constructor")
            off += 4 + 36
        elif parent != TL["noParent"]:
            raise Reject("unknown parent constructor")
    elif ctor == TL["empty"]:
        blk, off = block_id(4)
        off += 36
    else:
        raise Reject(f"unknown candidate constructor {ctor.hex()}")
    if off != len(raw):
        raise Reject(f"candidate has {len(raw) - off} trailing or missing bytes")
    return blk


def build_payload(session_id: bytes, slot: int, candidate: bytes) -> bytes:
    vote = TL["finalizeVote"] + TL["candidateId"] + struct.pack("<i", slot)
    vote += hashlib.sha256(candidate).digest()
    return TL["dataToSign"] + session_id + tl_bytes(vote)


def threshold(total: int) -> int:
    """The native quorum threshold, ceil(2 * total / 3)."""
    return -(-2 * total // 3)


def decode_set(boc_b64: str) -> dict[str, Any]:
    """A ConfigParam 32/34 cell, decoded and checked by the shared strict decoder."""
    try:
        value = shared.decode_set(lib.parse_boc(b64(boc_b64)))
    except lib.TestnetError as exc:
        raise Reject(f"validator set does not decode: {exc}") from exc
    validators = {}
    for row in value["validators"]:
        if row["algorithm"] != ALG_MLDSA44:
            raise Reject(f"validator {row['index']} is not an ML-DSA-44 member")
        validators[bytes.fromhex(row["id"])] = {
            "index": row["index"],
            "pk": bytes.fromhex(row["public_key"]),
            "weight": row["weight"],
        }
    total = sum(v["weight"] for v in validators.values())
    return {
        "utime_since": value["since"],
        "utime_until": value["until"],
        "total": value["total"],
        "total_weight": total,
        "validators": validators,
    }


def verify_certificate(cert: Any, vset: dict[str, Any], seqno: int, verify_fn: VerifyFn) -> dict:
    """Facts about a valid certificate, or Reject. Uses nothing from cert['verification']."""
    if not isinstance(cert, dict) or cert.get("@type") != "blocks.blockSignatures.simplexPq":
        raise Reject("not a PQ simplex finality certificate")
    bid = cert.get("id") or {}
    if bid.get("workchain") != -1 or str(bid.get("shard")) != SHARD or bid.get("seqno") != seqno:
        raise Reject("certificate is for a different block slot")
    root, fil, session = (
        b64(bid.get("root_hash")),
        b64(bid.get("file_hash")),
        b64(cert.get("session_id")),
    )
    if len(session) != 32 or len(root) != 32 or len(fil) != 32:
        raise Reject("hash length")
    slot = cert.get("slot")
    if not isinstance(slot, int) or isinstance(slot, bool) or not 0 <= slot <= 0x7FFFFFFF:
        raise Reject("slot")
    candidate = b64(cert.get("candidate"))
    if len(candidate) > 1024:
        raise Reject("candidate oversize")
    blk = parse_candidate(candidate)
    claimed = (blk["workchain"], blk["shard"], blk["seqno"], blk["root_hash"], blk["file_hash"])
    if claimed != (-1, SHARD, seqno, root, fil):
        raise Reject("candidate does not commit to the claimed block id")
    payload = build_payload(session, slot, candidate)
    sigs = cert.get("signatures")
    if not isinstance(sigs, list) or not sigs or len(sigs) > 400:
        raise Reject("signature list empty or oversize")
    seen: set[bytes] = set()
    weight = 0
    signers = []
    for s in sigs:
        if not isinstance(s, dict):
            raise Reject("malformed signature entry")
        vid = b64(s.get("validator_id"))
        if vid in seen:
            raise Reject("duplicate signer")
        seen.add(vid)
        member = vset["validators"].get(vid)
        if member is None:
            raise Reject("signer not in the validator set")
        if s.get("algorithm_id") != ALG_MLDSA44:
            raise Reject("unsupported algorithm")
        sig = b64(s.get("signature"))
        if len(sig) != MLDSA44_SIG_LEN:
            raise Reject(f"signature length {len(sig)}")
        if not verify_fn(member["pk"], payload, sig):
            raise Reject(
                f"ML-DSA-44 signature of validator index {member['index']} does not verify"
            )
        weight += member["weight"]
        signers.append(member["index"])
    total = vset["total_weight"]
    if weight > total:
        raise Reject("signed weight exceeds total")
    if weight < threshold(total):
        raise Reject(f"signed weight {weight} below threshold {threshold(total)}")
    return {"signers": sorted(signers), "weight": weight, "slot": slot}


def mldsa44_verifier() -> VerifyFn:
    """ML-DSA-44 verification with the signature context the consensus uses."""
    try:
        from dilithium_py.ml_dsa import ML_DSA_44  # type: ignore[import-not-found]
    except ImportError as exc:
        raise HandoverError(
            "verify needs the ML-DSA-44 verifier from the dilithium-py package "
            "(pip install dilithium-py==1.1.0); the tos build has no standalone verifier"
        ) from exc

    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            return bool(ML_DSA_44.verify(pk, msg, sig, ctx=CONTEXT))
        except ValueError:
            return False

    return verify


# ---------------------------------------------------------------- verification


def ranges(seqnos: list[int]) -> list[list[int]]:
    out: list[list[int]] = []
    for s in sorted(seqnos):
        if out and out[-1][1] == s - 1:
            out[-1][1] = s
        else:
            out.append([s, s])
    return out


def verify(
    collection: dict[str, Any], genesis_config: dict[str, Any], verify_fn: VerifyFn, global_id: int
) -> dict:
    if collection.get("schema") != SCHEMA:
        raise HandoverError(f"not a {SCHEMA} collection")
    names = collection["nodes"]
    lo, hi = collection["range"]
    if len(names) < 2 or not isinstance(lo, int) or not isinstance(hi, int) or hi <= lo:
        raise HandoverError("the collection has fewer than two nodes or an empty range")
    seqnos = list(range(lo, hi + 1))
    failures: list[str] = []
    zero = zero_state(genesis_config)

    def node_result(entry: Any, what: str) -> Any:
        try:
            return result_of(entry, what)
        except Reject as exc:
            failures.append(str(exc))
            return None

    # Network identity.
    for n in names:
        info = node_result(collection["heads"].get(n), f"{n} getMasterchainInfo")
        if info is not None and full_id(info.get("init") or {}) != zero:
            failures.append(f"{n}: zero state differs from the global config")
    centers = set()
    for n in names:
        found = node_result(collection["boundary_lookups"].get(n), f"{n} boundary lookupBlock")
        if found is not None:
            centers.add(full_id(found))
    if len(centers) != 1:
        failures.append("nodes disagree on the block at the boundary time")
    elif not lo <= int(next(iter(centers))[2]) <= hi:
        failures.append("the range does not contain the block at the boundary time")

    # Headers, ids and shard tops, compared across every node.
    headers: dict[int, dict[str, Any]] = {}
    certs: dict[tuple[str, int], Any] = {}
    agreement = {"blocks": len(seqnos), "same_full_id_on_all_nodes": 0, "same_shard_tops": 0}
    for s in seqnos:
        ids, fields, tops = set(), set(), set()
        complete = True
        for n in names:
            entry = (collection["blocks"].get(n) or {}).get(str(s))
            if not isinstance(entry, dict):
                failures.append(f"{n}/{s}: block not collected")
                complete = False
                continue
            header = node_result(entry.get("header"), f"{n}/{s} getBlockHeader")
            look = node_result(entry.get("lookup"), f"{n}/{s} lookupBlock")
            cert = node_result(entry.get("signatures"), f"{n}/{s} getMasterchainBlockSignatures")
            shards = node_result(entry.get("shards"), f"{n}/{s} shards")
            if header is None or look is None or cert is None or shards is None:
                complete = False
                continue
            certs[(n, s)] = cert
            try:
                ids.update({full_id(header.get("id")), full_id(look), full_id(cert.get("id"))})
                tops.add(tuple(sorted(full_id(x) for x in shards.get("shards") or [])))
            except Reject as exc:
                failures.append(f"{n}/{s}: {exc}")
                complete = False
                continue
            fields.add(tuple(header.get(k) for k in HEADER_FIELDS))
            headers.setdefault(s, header)
            if header.get("global_id") != global_id:
                failures.append(
                    f"{n}/{s}: header global id {header.get('global_id')!r}, expected {global_id}"
                )
        if not complete:
            continue
        if len(ids) == 1 and next(iter(ids))[2] == str(s):
            agreement["same_full_id_on_all_nodes"] += 1
        else:
            failures.append(
                f"block {s}: full ids differ across nodes or between lookup, header and certificate"
            )
        if len(fields) != 1:
            failures.append(f"block {s}: header fields differ across nodes")
        if len(tops) == 1 and next(iter(tops)):
            agreement["same_shard_tops"] += 1
        else:
            failures.append(f"block {s}: shard tops differ across nodes or are missing")

    # Validator sets: byte-identical on every node, decoded here.
    substitutions = {
        int(x["source"]): int(x["read_at"]) for x in collection.get("substitutions", [])
    }
    sets: dict[int, dict[str, Any]] = {}
    set_report: dict[str, Any] = {}
    sources = {int(k) for n in names for k in (collection["config34"].get(n) or {})}
    for k in sorted(sources):
        cells = set()
        for n in names:
            entry = (collection["config34"].get(n) or {}).get(str(k))
            found = node_result(entry, f"{n} ConfigParam 34 at {k}")
            if found is None:
                continue
            read_at = (entry.get("params") or {}).get("seqno")
            if read_at != k:
                if entry.get("substituted_for") != k or substitutions.get(k) != read_at:
                    failures.append(
                        f"{n}: ConfigParam 34 for source {k} was read at {read_at}, not recorded as a substitution"
                    )
                elif substitute_block(collection, k) != read_at:
                    failures.append(
                        f"source {k}: substitute block {read_at} is not the first agreed non-key block naming it"
                    )
            cells.add(((found.get("config") or {}).get("bytes")))
        if len(cells) != 1 or None in cells:
            failures.append(f"ConfigParam 34 at source {k} differs or is missing across nodes")
            continue
        boc = next(iter(cells))
        try:
            sets[k] = {"boc": boc, **decode_set(boc)}
        except Reject as exc:
            failures.append(f"ConfigParam 34 at source {k}: {exc}")
            continue
        set_report[str(k)] = {
            "utime_since": sets[k]["utime_since"],
            "utime_until": sets[k]["utime_until"],
            "total": sets[k]["total"],
            "total_weight": str(sets[k]["total_weight"]),
            "threshold": str(threshold(sets[k]["total_weight"])),
            "boc_sha256": hashlib.sha256(b64(boc)).hexdigest(),
            "read_at": substitutions.get(k, k),
        }
    post_cells: dict[str, str | None] = {}
    for p in ("32", "34"):
        cells = set()
        for n in names:
            entry = (collection["post_handover"].get(n) or {}).get(p)
            found = node_result(entry, f"{n} post-handover ConfigParam {p}")
            if found is not None:
                if (entry.get("params") or {}).get("seqno", -1) < hi:
                    failures.append(f"{n}: post-handover ConfigParam {p} read before the range end")
                cells.add((found.get("config") or {}).get("bytes"))
        if len(cells) != 1 or None in cells:
            failures.append(f"post-handover ConfigParam {p} differs or is missing across nodes")
            post_cells[p] = None
        else:
            post_cells[p] = next(iter(cells))

    # Roles: each block's set is selected by its header.
    roles: dict[int, str] = {}
    selected: dict[int, int] = {}
    for s in seqnos:
        header = headers.get(s)
        if header is None:
            continue
        k = header.get("prev_key_block_seqno")
        if k not in sets:
            failures.append(f"block {s}: no agreed ConfigParam 34 for its set source {k}")
            continue
        selected[s] = k
        boc = sets[k]["boc"]
        roles[s] = (
            "outgoing"
            if boc == post_cells["32"]
            else "incoming"
            if boc == post_cells["34"]
            else "other"
        )
        if roles[s] == "other":
            failures.append(f"block {s}: its set is neither post-handover ConfigParam 32 nor 34")
    outgoing = [s for s in seqnos if roles.get(s) == "outgoing"]
    incoming = [s for s in seqnos if roles.get(s) == "incoming"]
    boundary: dict[str, Any] = {}
    if not outgoing or not incoming:
        failures.append("the range does not cross a handover")
    else:
        last_out, first_in = outgoing[-1], incoming[0]
        boundary = {"last_outgoing": last_out, "first_incoming": first_in}
        if (
            first_in != last_out + 1
            or outgoing != list(range(outgoing[0], last_out + 1))
            or incoming != list(range(first_in, incoming[-1] + 1))
        ):
            failures.append(
                "handover roles are not contiguous: outgoing blocks, then incoming blocks"
            )
        if not (
            headers[last_out].get("is_key_block") is True and selected.get(first_in) == last_out
        ):
            failures.append(
                "the last outgoing block is not the key block that installs the incoming set"
            )
        for name, s in (("last_outgoing_id", last_out), ("first_incoming_id", first_in)):
            boundary[name] = headers[s].get("id")

    # Every certificate against its header-selected set, plus the binding facts.
    bound_ok: dict[int, bool] = {}
    per_node = {n: {"verified": 0, "rejected": []} for n in names}
    sessions: dict[Any, set] = {}
    for s in seqnos:
        k = selected.get(s)
        bound_ok[s] = k is not None
        for n in names:
            cert = certs.get((n, s))
            if cert is None or k is None:
                bound_ok[s] = False
                continue
            try:
                verify_certificate(cert, sets[k], s, verify_fn)
                per_node[n]["verified"] += 1
            except Reject as exc:
                per_node[n]["rejected"].append([s, str(exc)])
                failures.append(f"{n}/{s}: certificate rejected: {exc}")
                bound_ok[s] = False
            source = cert_source(cert)
            if source not in sets or sets[source]["boc"] != sets[k]["boc"]:
                failures.append(
                    f"{n}/{s}: certificate set source {source} differs from the header-selected set {k}"
                )
                bound_ok[s] = False
            header = headers[s]
            if (cert.get("cc_seqno"), cert.get("validator_set_hash")) != (
                header.get("catchain_seqno"),
                header.get("validator_list_hash_short"),
            ):
                failures.append(f"{n}/{s}: certificate session commitment differs from the header")
                bound_ok[s] = False
            sessions.setdefault(cert.get("cc_seqno"), set()).add(cert.get("session_id"))
    for cc, ids in sessions.items():
        if len(ids) != 1:
            failures.append(f"catchain seqno {cc} has more than one session id")

    # The term rule, applied to every block.
    blocks_report = []
    extended: dict[int, list[int]] = {}
    for s in seqnos:
        k = selected.get(s)
        if k is None:
            continue
        t, since, until = (
            headers[s].get("gen_utime"),
            sets[k]["utime_since"],
            sets[k]["utime_until"],
        )
        if not isinstance(t, int) or isinstance(t, bool) or t < since:
            failures.append(f"block {s}: generated at {t}, before its set's term begins at {since}")
            term = "before_term"
        elif t <= until:
            term = "in_term"
        else:
            # The outgoing set keeps signing past utime_until until a key block
            # installs the next set; only the chain-selected set may do so.
            term = "extended_term"
            extended.setdefault(k, []).append(s)
            if not bound_ok[s]:
                failures.append(
                    f"block {s}: extended-term block is not signed by the chain-selected set"
                )
        blocks_report.append(
            {
                "seqno": s,
                "role": roles.get(s),
                "set_source": k,
                "gen_utime": t,
                "is_key_block": headers[s].get("is_key_block"),
                "term": term,
                "full_id": headers[s].get("id"),
            }
        )
    extended_report = []
    for k, blocks in sorted(extended.items()):
        for first, last in ranges(blocks):
            extended_report.append(
                {
                    "set_source": k,
                    "role": roles.get(first),
                    "utime_until": sets[k]["utime_until"],
                    "first": first,
                    "last": last,
                    "blocks": last - first + 1,
                    "first_gen_utime": headers[first]["gen_utime"],
                    "last_gen_utime": headers[last]["gen_utime"],
                    "seconds_past_until": headers[last]["gen_utime"] - sets[k]["utime_until"],
                }
            )

    controls, wrong_term, bare, cert_controls = [], {}, [], {}
    if (
        boundary
        and post_cells["32"]
        and post_cells["34"]
        and failures_allow_controls(certs, names, boundary)
    ):
        controls, wrong_term, bare = handover_controls(
            collection,
            names,
            certs,
            headers,
            sets,
            selected,
            roles,
            boundary,
            post_cells,
            verify_fn,
            failures,
        )
        cert_controls = certificate_controls(
            names, certs, sets, selected, seqnos, verify_fn, failures
        )
    else:
        failures.append("controls could not run: the range lacks a complete handover")

    report = {
        "schema": REPORT_SCHEMA,
        "result": "PASS" if not failures else "FAIL",
        "failures": failures,
        "range": [lo, hi],
        "boundary_time": collection.get("boundary"),
        "collected": [collection.get("started_utc"), collection.get("finished_utc")],
        "boundary": boundary,
        "extended_term": extended_report,
        "counts": {
            "outgoing_blocks": len(outgoing),
            "incoming_blocks": len(incoming),
            "certificates_expected": len(seqnos) * len(names),
            "certificates_verified": sum(v["verified"] for v in per_node.values()),
        },
        "agreement": agreement,
        "sets": set_report,
        "substitutions": [{"source": k, "read_at": v} for k, v in sorted(substitutions.items())],
        "sessions": {str(k): sorted(v) for k, v in sessions.items()},
        "nodes": per_node,
        "controls": controls,
        "wrong_term_coverage": wrong_term,
        "certificate_controls": cert_controls,
        "bare_verifier_wrong_set_probe": bare,
        "blocks": blocks_report,
        "set_binding": "header.prev_key_block_seqno -> ConfigParam 34; post-handover ConfigParam 32/34 "
        "equality; every node agrees",
        "trust_limit": "Cross-node header and configuration equality, not an authenticated proof chain. "
        "Signatures alone may accept the same keys in both terms; the header binding separates them.",
    }
    return report


def failures_allow_controls(certs, names, boundary) -> bool:
    return all(
        (n, boundary[k]) in certs for n in names for k in ("last_outgoing", "first_incoming")
    )


def handover_controls(
    collection,
    names,
    certs,
    headers,
    sets,
    selected,
    roles,
    boundary,
    post_cells,
    verify_fn,
    failures,
):
    last_out, first_in = boundary["last_outgoing"], boundary["first_incoming"]
    old, new = certs[(names[0], last_out)], certs[(names[0], first_in)]

    def bound_check(cert, boc, s):
        if boc != sets[selected[s]]["boc"]:
            raise Reject("supplied validator set differs from the chain-selected ConfigParam 34")
        return verify_certificate(cert, decode_set(boc), s, verify_fn)

    controls = []

    def control(name, fn):
        try:
            fn()
            rejected, why = False, "accepted"
        except Reject as exc:
            rejected, why = True, str(exc)
        controls.append({"control": name, "rejected": rejected, "reason": why})
        if not rejected:
            failures.append(f"control accepted: {name}")

    control(
        "outgoing certificate against the incoming set",
        lambda: bound_check(old, post_cells["34"], last_out),
    )
    control(
        "incoming certificate against the outgoing set",
        lambda: bound_check(new, post_cells["32"], first_in),
    )
    spliced = copy.deepcopy(new)
    donors = {x["validator_id"]: x for x in old.get("signatures") or []}
    recipient = next(
        (x for x in spliced.get("signatures") or [] if x["validator_id"] in donors), None
    )
    if recipient is None:
        failures.append("control could not run: no common signer across the boundary")
    else:
        recipient["signature"] = donors[recipient["validator_id"]]["signature"]
        control(
            "pre-boundary signature spliced into a post-boundary certificate",
            lambda: bound_check(spliced, post_cells["34"], first_in),
        )
    wrong_term = {"outgoing_rejected": 0, "incoming_rejected": 0, "accepted": []}
    for s, role in sorted(roles.items()):
        if role not in ("outgoing", "incoming"):
            continue
        wrong = post_cells["34"] if role == "outgoing" else post_cells["32"]
        for n in names:
            if (n, s) not in certs:
                continue
            try:
                bound_check(certs[(n, s)], wrong, s)
            except Reject:
                wrong_term[role + "_rejected"] += 1
            else:
                wrong_term["accepted"].append([n, s])
                failures.append(f"{n}/{s}: wrong-term set binding accepted")
    bare = []
    for name, cert, boc, s in (
        ("outgoing with incoming", old, post_cells["34"], last_out),
        ("incoming with outgoing", new, post_cells["32"], first_in),
    ):
        try:
            verify_certificate(cert, decode_set(boc), s, verify_fn)
            outcome_ = "accept"
        except Reject as exc:
            outcome_ = f"reject: {exc}"
        bare.append({"case": name, "membership_and_signature_only": outcome_})
    return controls, wrong_term, bare


def certificate_controls(names, certs, sets, selected, seqnos, verify_fn, failures):
    """Tampered certificates that must each be rejected, and one honest one accepted."""
    base_s = seqnos[len(seqnos) // 2]
    node = names[0]
    if (node, base_s) not in certs or (node, base_s - 1) not in certs or base_s not in selected:
        failures.append("certificate controls could not run: no base certificate")
        return {}
    base, other = certs[(node, base_s)], certs[(node, base_s - 1)]
    vs = sets[selected[base_s]]

    def flip_sig(c):
        raw = bytearray(b64(c["signatures"][0]["signature"]))
        raw[100] ^= 0x01
        c["signatures"][0]["signature"] = lib.b64(bytes(raw))

    def swap_sig(c):
        donors = {x["validator_id"]: x for x in other["signatures"]}
        target = next((x for x in c["signatures"] if x["validator_id"] in donors), None)
        if target is None:
            raise Reject("no common validator for the splice control")
        target["signature"] = donors[target["validator_id"]]["signature"]

    def root_id_only(c):
        raw = bytearray(b64(c["id"]["root_hash"]))
        raw[0] ^= 0xFF
        c["id"]["root_hash"] = lib.b64(bytes(raw))

    def root_consistent(c):
        root_id_only(c)
        cand = bytearray(b64(c["candidate"]))
        cand[4 + 16 : 4 + 48] = b64(c["id"]["root_hash"])
        c["candidate"] = lib.b64(bytes(cand))

    def drop_below(c):
        while c["signatures"]:
            w = sum(vs["validators"][b64(x["validator_id"])]["weight"] for x in c["signatures"])
            if w < threshold(vs["total_weight"]):
                break
            c["signatures"].pop()

    def duplicate(c):
        drop_below(c)
        c["signatures"].append(copy.deepcopy(c["signatures"][0]))

    def foreign(c):
        c["signatures"][0]["validator_id"] = lib.b64(hashlib.sha256(b"not-a-validator").digest())

    def other_slot(c):
        c["slot"] = c["slot"] + 1

    def other_session(c):
        raw = bytearray(b64(c["session_id"]))
        raw[0] ^= 1
        c["session_id"] = lib.b64(bytes(raw))

    cases = [
        ("honest certificate (positive control)", lambda c: None, True),
        ("flip one byte of a signature", flip_sig, False),
        ("the same validator's signature from block N-1", swap_sig, False),
        ("a different root hash, id only", root_id_only, False),
        ("a different root hash, candidate rewritten, original signatures", root_consistent, False),
        ("signatures dropped below 2/3 of the weight", drop_below, False),
        ("a below-threshold set padded with a duplicate signer", duplicate, False),
        ("a signer not in the set", foreign, False),
        ("a different slot, original signatures", other_slot, False),
        ("a different session id, original signatures", other_session, False),
    ]
    results = []
    for name, mutate, expect in cases:
        c = copy.deepcopy(base)
        try:
            mutate(c)
            verify_certificate(c, vs, base_s, verify_fn)
            accepted, why = True, "accepted"
        except Reject as exc:
            accepted, why = False, str(exc)
        results.append(
            {"control": name, "expected": "accept" if expect else "reject", "reason": why}
        )
        if accepted != expect:
            failures.append(f"certificate control failed: {name} ({why})")
    rotated = copy.deepcopy(vs)
    keys = list(rotated["validators"])
    pks = [rotated["validators"][k]["pk"] for k in keys]
    for k, pk in zip(keys, pks[1:] + pks[:1]):
        rotated["validators"][k]["pk"] = pk
    try:
        verify_certificate(base, rotated, base_s, verify_fn)
        why = "accepted"
        failures.append("certificate control failed: keys rotated between members accepted")
    except Reject as exc:
        why = str(exc)
    results.append({"control": "keys rotated between members", "expected": "reject", "reason": why})
    forged = copy.deepcopy(base)
    root_consistent(forged)
    ids = {n: full_id(certs[(n, base_s)]["id"]) for n in names if (n, base_s) in certs}
    ids[names[1]] = full_id(forged["id"])
    detected = len(set(ids.values())) != 1
    if not detected:
        failures.append(
            "certificate control failed: a conflicting full id on one node not detected"
        )
    results.append(
        {
            "control": "one node serves a conflicting full id",
            "expected": "reject",
            "reason": "full ids differ" if detected else "not detected",
        }
    )
    return {"base": {"node": node, "seqno": base_s}, "results": results}


def run_verify(args: argparse.Namespace, verify_fn: VerifyFn | None = None) -> dict:
    out = Path(args.out)
    collection = json.loads((out / "collection.json").read_text())
    genesis = json.loads(Path(args.genesis_config).read_text())
    global_id = lib.confirmed_global_id(lib.load_profile())
    report = verify(collection, genesis, verify_fn or mldsa44_verifier(), global_id)
    (out / "report.json").write_text(json.dumps(report, indent=1) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect", help="read-only capture around a boundary time")
    when = c.add_mutually_exclusive_group(required=True)
    when.add_argument("--boundary", type=int, dest="boundary", metavar="UNIXTIME")
    when.add_argument("--term-start", type=int, dest="boundary", metavar="UNIXTIME")
    c.add_argument("--rpc", action="append", required=True, metavar="URL")
    c.add_argument("--genesis-config", type=Path, required=True)
    c.add_argument("--span", type=int, default=100, help="blocks on each side (default 100)")
    c.add_argument("--out", type=Path, required=True)
    c.add_argument(
        "--interval",
        type=float,
        default=MIN_INTERVAL,
        help="seconds between request starts per node",
    )
    c.add_argument(
        "--max-wait", type=float, default=900, help="seconds to wait for the boundary and the heads"
    )
    c.add_argument("--lock-dir", type=Path, help="share the per-node spacing with other processes")
    v = sub.add_parser("verify", help="offline verification of a collection")
    v.add_argument("--genesis-config", type=Path, required=True)
    v.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            print(json.dumps({"ok": True, **collect(args)}, indent=2))
            return 0
        report = run_verify(args)
    except (lib.TestnetError, OSError, KeyError, ValueError, TypeError) as exc:
        print(json.dumps({"ok": False, "refused": str(exc)}))
        return 2
    summary = {
        k: report[k] for k in ("result", "failures", "range", "boundary", "extended_term", "counts")
    }
    summary["controls_rejected"] = all(x["rejected"] for x in report["controls"]) and bool(
        report["controls"]
    )
    print(json.dumps(summary, indent=2))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
