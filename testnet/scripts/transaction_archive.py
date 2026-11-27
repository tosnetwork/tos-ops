"""Durable, bounded transaction-cell capture at a trusted finalized checkpoint.

Callers supply approved RPC references and the operation's exact transaction ids.
This archives evidence; it does not authorize payments or infer settlement from
an archival success. Business-outcome verifier outputs are retained separately.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path

import testnet_ops as ops

MAX_TRANSACTIONS = 256
MAX_ANCESTORS = 1024
MAX_BOC_BYTES = 8 << 20
MAX_GRAPH_BYTES = 64 << 20
MAX_STEPS = 1024
LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,159}\Z")


class Refused(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def durable_directory(path):
    path = Path(path)
    if path.exists():
        require(path.is_dir() and not path.is_symlink(), "invalid archive directory")
        return
    durable_directory(path.parent)
    path.mkdir(mode=0o700)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_write(path, data):
    """Publish bytes only after file fsync, then fsync the containing directory."""
    path = Path(path)
    durable_directory(path.parent)
    temporary = path.with_suffix(path.suffix + ".pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            require(written > 0, "evidence write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def document(path, value):
    sync_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def block_key(block):
    require(isinstance(block, dict), "missing block identity")
    key = (
        int(block["workchain"]),
        int(block["shard"]),
        int(block["seqno"]),
        ops.b64hash(block["root_hash"]).hex(),
        ops.b64hash(block["file_hash"]).hex(),
    )
    require(
        key[0] in (-1, 0) and -(2**63) <= key[1] < 2**63 and 0 <= key[2] < 2**32,
        "invalid block identity",
    )
    return key


def contains(shard, account):
    unsigned = int(shard) & (2**64 - 1)
    low = unsigned & -unsigned
    require(low != 0, "invalid shard prefix")
    mask = (2**64 - 1) ^ (2 * low - 1)
    return (int(account[:16], 16) & mask) == (unsigned & mask)


class TransactionArchive:
    def __init__(self, directory, endpoints, genesis, *, node=ops.Node):
        require(
            len(endpoints) == 3 and len(set(endpoints)) == 3,
            "archive needs three distinct references",
        )
        self.directory = Path(directory)
        self.nodes = [node(url) for url in endpoints]
        self.endpoints = list(endpoints)
        self.genesis = genesis
        self.headers = {}

    def header(self, node, block):
        key = (node.url, block_key(block))
        if key not in self.headers:
            require(len(self.headers) < 3 * MAX_ANCESTORS, "archive block-proof bound exceeded")
            result = node.call(
                "getBlockHeader",
                workchain=int(block["workchain"]),
                shard=str(block["shard"]),
                seqno=int(block["seqno"]),
            )
            require(block_key(result["id"]) == key[1], "archive block header differs")
            self.headers[key] = result
        return self.headers[key]

    def checkpoint(self):
        for node in self.nodes:
            initial = node.call("getMasterchainInfo")["init"]
            require(
                ops.b64hash(initial["root_hash"]).hex() == self.genesis["root"],
                "archive reference genesis differs",
            )
            require(
                ops.b64hash(initial["file_hash"]).hex() == self.genesis["file"],
                "archive reference genesis file differs",
            )
        positions = []
        for node in self.nodes:
            position = node.call("getConsensusBlock")
            require(
                position.get("@type") == "ext.blocks.consensusBlock"
                and type(position.get("consensus_block")) is int
                and 0 < position["consensus_block"] < 2**32,
                "archive finalized checkpoint unavailable",
            )
            positions.append(position["consensus_block"])
        seqno = min(positions)
        blocks = [
            n.call("lookupBlock", workchain=-1, shard=str(-(2**63)), seqno=seqno)
            for n in self.nodes
        ]
        require(
            all(block_key(b) == block_key(blocks[0]) for b in blocks),
            "archive checkpoint references disagree",
        )
        return blocks[0]

    def source(self, root):
        require(set(root) == {"account", "lt", "hash"}, "invalid archive source id")
        require(
            re.fullmatch(r"(?:0|-1):[0-9a-f]{64}", root["account"])
            and re.fullmatch(r"[0-9a-f]{64}", root["hash"]),
            "invalid archive source identity",
        )
        require(type(root["lt"]) is int and 0 < root["lt"] < 2**64, "invalid archive source LT")
        answers = []
        for node in self.nodes:
            tx = next(
                (
                    tx
                    for tx in node.shard_transactions(root["account"], root["lt"] - 1, 2)
                    if tx["lt"] == root["lt"] and tx["hash"] == root["hash"]
                ),
                None,
            )
            require(tx is not None, "archive source not available yet")
            answers.append(tx)
        return self.agreed(root["account"], answers)

    @staticmethod
    def agreed(account, answers):
        require(all(a is not None for a in answers), "archive delivery not available yet")
        decoded = []
        for tx in answers:
            require(
                isinstance(tx["data"], str) and len(tx["data"]) <= 4 * ((MAX_BOC_BYTES + 2) // 3),
                "archive transaction cell exceeds its bound",
            )
            # Decode the cell ourselves; never archive RPC summary fields as facts.
            value = ops.verify_transaction(tx["data"], tx["hash"], account, int(tx["lt"]))
            decoded.append(dict(value, block=tx["block"]))
        first = decoded[0]
        require(
            all(
                x["data"] == first["data"] and block_key(x["block"]) == block_key(first["block"])
                for x in decoded
            ),
            "archive transaction references disagree",
        )
        return account, first

    def finalized(self, node, account, target, checkpoint):
        wc, address = account.split(":")
        if int(wc) == -1:
            frontier = [checkpoint]
        else:
            shards = node.call("getShards", seqno=int(checkpoint["seqno"]))["shards"]
            require(
                isinstance(shards, list) and len(shards) <= MAX_ANCESTORS,
                "archive shard-list bound exceeded",
            )
            frontier = [
                b
                for b in shards
                if int(b["workchain"]) == int(wc) and contains(b["shard"], address)
            ]
        seen = set()
        while frontier:
            require(len(seen) < MAX_ANCESTORS, "archive ancestry bound exceeded")
            block = frontier.pop()
            key = block_key(block)
            if key == block_key(target):
                self.header(node, block)
                return
            if key in seen or key[2] < int(target["seqno"]):
                continue
            seen.add(key)
            header = self.header(node, block)
            parents = header["prev_blocks"]
            require(
                isinstance(parents, list) and len(parents) <= 2, "invalid archive block parents"
            )
            for parent in parents:
                require(int(parent["seqno"]) < key[2], "archive ancestry made no progress")
                if int(parent["workchain"]) == int(wc) and (
                    int(wc) == -1 or contains(parent["shard"], address)
                ):
                    frontier.append(parent)
        raise Refused("transaction block is not finalized at the archive checkpoint yet")

    def capture(self, roots, reports=None):
        require(
            isinstance(roots, list) and 0 < len(roots) <= MAX_TRANSACTIONS,
            "archive needs bounded exact transaction roots",
        )
        pending = [self.source(root) for root in roots]
        found = {}
        total_bytes = 0
        while pending:
            account, tx = pending.pop(0)
            key = (account, tx["lt"], tx["hash"])
            if key in found:
                continue
            require(len(found) < MAX_TRANSACTIONS, "archive transaction graph exceeds its bound")
            raw = base64.b64decode(tx["data"], validate=True)
            total_bytes += len(raw)
            require(total_bytes <= MAX_GRAPH_BYTES, "archive graph bytes exceed their bound")
            path = self.directory / "transactions" / f"{tx['lt']}-{tx['hash']}.boc"
            sync_write(path, raw)
            found[key] = (account, tx, path, raw)
            for msg in tx["out"]:
                if msg["kind"] != "internal":
                    continue
                require(
                    len(pending) + len(found) < MAX_TRANSACTIONS,
                    "archive message fanout exceeds its bound",
                )
                answers = [
                    n.delivery(msg["destination"], msg["hash"], msg["created_lt"])
                    for n in self.nodes
                ]
                pending.append(self.agreed(msg["destination"], answers))
        checkpoint = self.checkpoint()
        for account, tx, _, _ in found.values():
            for node in self.nodes:
                self.finalized(node, account, tx["block"], checkpoint)
        files = []
        for account, tx, path, raw in found.values():
            files.append(
                {
                    "file": str(path.relative_to(self.directory)),
                    "sha256": digest(raw),
                    "account": account,
                    "lt": tx["lt"],
                    "transaction_hash": tx["hash"],
                    "block": tx["block"],
                }
            )
        report = {
            "schema": "transaction-archive-verification.v1",
            "result": "pass",
            "trust_model": "three approved trusted nodes; matching decoded transaction cells and block ancestry to one matching finalized checkpoint",
            "genesis": self.genesis,
            "checkpoint": checkpoint,
            "endpoints": self.endpoints,
            "roots": roots,
            "transactions": files,
        }
        require(
            isinstance(reports or {}, dict)
            and len(reports or {}) <= 64
            and "archival-verification" not in (reports or {}),
            "invalid archive verifier set",
        )
        outputs = {"archival-verification": report, **(reports or {})}
        for name, value in outputs.items():
            require(
                LABEL.fullmatch(name) and isinstance(value, dict), "invalid archive verifier output"
            )
            raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
            require(len(raw) <= 8 << 20, "archive verifier output exceeds its bound")
            path = self.directory / "verifiers" / f"{name}-{digest(raw)}.json"
            sync_write(path, raw)
            files.append({"file": str(path.relative_to(self.directory)), "sha256": digest(raw)})
        headers = [{"endpoint": url, "header": value} for (url, _), value in self.headers.items()]
        raw = (json.dumps(headers, indent=2, sort_keys=True) + "\n").encode()
        sync_write(self.directory / "block-headers.json", raw)
        files.append({"file": "block-headers.json", "sha256": digest(raw)})
        return {"checkpoint": checkpoint, "files": files, "roots": roots}

    def capture_wait(self, roots, reports=None, *, timeout=900, interval=2):
        require(0 < timeout <= 1800 and 0 < interval <= 10, "invalid archive wait bound")
        deadline = time.monotonic() + timeout
        while True:
            self.headers = {}
            try:
                return self.capture(roots, reports)
            except (ops.Unknown, Refused) as error:
                waiting = (
                    isinstance(error, ops.Unknown)
                    or "not available yet" in str(error)
                    or "not finalized" in str(error)
                )
                if not waiting or time.monotonic() >= deadline:
                    raise
                time.sleep(min(interval, max(0, deadline - time.monotonic())))


class StepJournal:
    """The caller holds its operation lock. No next action before evidence commit."""

    def __init__(self, directory):
        self.directory = Path(directory)
        durable_directory(self.directory)
        self.path = self.directory / "steps.json"

    def read(self):
        return (
            json.loads(self.path.read_text())
            if self.path.exists()
            else {"pending": None, "completed": {}}
        )

    def validate(self, label, identity):
        path = self.directory / label / "manifest.json"
        manifest = json.loads(path.read_text())
        require(
            manifest["complete"]
            and manifest["label"] == label
            and manifest["identity"] == identity,
            "archive step identity differs",
        )
        for item in manifest["files"]:
            target = self.directory / label / item["file"]
            require(
                target.resolve().is_relative_to((self.directory / label).resolve()),
                "archive path escapes its step",
            )
            require(
                digest(target.read_bytes()) == item["sha256"],
                "archive evidence is missing or changed",
            )
        return manifest

    def retain_verifier(self, name, value, raw=None):
        require(
            LABEL.fullmatch(name) and isinstance(value, dict), "invalid retained verifier output"
        )
        if raw is None:
            raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        else:
            require(
                isinstance(raw, bytes) and json.loads(raw) == value,
                "raw verifier output differs from its parsed result",
            )
        require(len(raw) <= 8 << 20, "retained verifier output exceeds its bound")
        relative = f"verifiers/{name}-{digest(raw)}.json"
        sync_write(self.directory / relative, raw)
        path = self.directory / "retained-verifiers.json"
        records = json.loads(path.read_text()) if path.exists() else {}
        require(
            relative in records or len(records) < MAX_STEPS,
            "retained verifier count exceeds its bound",
        )
        records[relative] = digest(raw)
        document(path, records)

    def validate_verifiers(self):
        path = self.directory / "retained-verifiers.json"
        if not path.exists():
            return
        for relative, expected in json.loads(path.read_text()).items():
            target = self.directory / relative
            require(
                target.resolve().is_relative_to(self.directory.resolve()),
                "retained verifier path escapes archive",
            )
            require(
                digest(target.read_bytes()) == expected,
                "retained verifier evidence is missing or changed",
            )

    def run(self, label, identity, action, capture):
        require(
            LABEL.fullmatch(label) and re.fullmatch(r"[0-9a-f]{64}", identity),
            "invalid archive step name or identity",
        )
        self.validate_verifiers()
        state = self.read()
        for previous, expected in state["completed"].items():
            self.validate(previous, expected)
        pending = state["pending"]
        require(
            pending is None or pending == {"label": label, "identity": identity},
            "previous step evidence is not archived; resume that step read-only first",
        )
        if label in state["completed"]:
            return self.validate(label, identity)
        require(len(state["completed"]) < MAX_STEPS, "archived step count exceeds its bound")
        state["pending"] = {"label": label, "identity": identity}
        document(self.path, state)
        finished = self.directory / label / "action-finished.json"
        if not finished.exists():
            action()
            document(finished, {"identity": identity})
        else:
            require(
                json.loads(finished.read_text()) == {"identity": identity},
                "archive finished-action identity differs",
            )
        result = capture(self.directory / label)
        require(
            isinstance(result, dict) and result.get("files"), "step produced no archived evidence"
        )
        manifest = {**result, "complete": True, "label": label, "identity": identity}
        document(self.directory / label / "manifest.json", manifest)
        self.validate(label, identity)
        state["completed"][label] = identity
        state["pending"] = None
        document(self.path, state)
        return manifest


def verify_sanitized(original, sanitized, entry):
    """Check a cited public output, deleting only named object fields."""
    require(
        len(original) <= 8 << 20 and len(sanitized) <= 8 << 20,
        "verifier document exceeds its bound",
    )
    require(
        digest(original) == entry["original_sha256"],
        "original verifier SHA-256 differs from its citation",
    )
    require(digest(sanitized) == entry["sanitized_sha256"], "sanitized verifier SHA-256 differs")
    value = json.loads(original)
    pointers = entry["removed_json_pointers"]
    require(
        isinstance(pointers, list) and len(pointers) <= 128 and len(set(pointers)) == len(pointers),
        "invalid sanitization field list",
    )
    for pointer in pointers:
        require(
            isinstance(pointer, str) and pointer.startswith("/") and len(pointer) <= 1024,
            "invalid sanitization pointer",
        )
        require(
            not any(other != pointer and pointer.startswith(other + "/") for other in pointers),
            "overlapping sanitization fields",
        )
        parts = pointer[1:].split("/")
        require(
            all(re.search(r"~(?![01])", p) is None for p in parts),
            "invalid sanitization pointer escape",
        )
        parts = [p.replace("~1", "/").replace("~0", "~") for p in parts]
        parent = value
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        require(isinstance(parent, dict) and parts[-1] in parent, "sanitization field is absent")
        del parent[parts[-1]]
    expected = (json.dumps(value, indent=2, ensure_ascii=True, sort_keys=False) + "\n").encode()
    require(sanitized == expected, "sanitized verifier differs beyond the removed fields")


def verify_citations(records_root, entry):
    root = Path(records_root).resolve()
    require(entry.get("original_record_citations"), "public verifier has no record citation")
    for citation in entry["original_record_citations"]:
        path = root / citation["record"]
        require(path.resolve().is_relative_to(root), "verifier citation escapes record directory")
        value = json.loads(path.read_text())
        pointer = citation["pointer"]
        require(
            isinstance(pointer, str) and pointer.startswith("/"),
            "invalid verifier citation pointer",
        )
        for part in pointer[1:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            value = value[int(part)] if isinstance(value, list) else value[part]
        require(
            value == entry["original_sha256"], "record does not cite this original verifier SHA-256"
        )
