#!/usr/bin/env python3
"""Local test archive transport, not a substitute for finalized state.

Only a node's explicit pruned-transaction error can use retained transaction
cells. Current state, genesis and finality responses are forwarded unchanged.
The production reader still checks every cell against its live account head,
account, logical time and predecessor chain. Source routes may explicitly
forward submissions once; reference routes are always read-only. This helper
holds no signing keys and never builds or retries a submitted message.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "testnet/scripts"))
import testnet_ops as ops

MAX_BODY = 2 << 20
MAX_REPLY = 16 << 20
MAX_CELL = 1 << 20
MAX_BYTES = 64 << 20
MAX_ENTRIES = 4096
READS = frozenset(
    (
        "getWalletInformation",
        "getMasterchainInfo",
        "getConsensusBlock",
        "getAddressInformation",
        "getConfigParam",
        "getConfigParamStd",
        "runGetMethod",
        "runGetMethodStd",
        "getTransactions",
        "getTransactionsStd",
        "getBlockHeader",
        "lookupBlock",
    )
)
SUBMISSIONS = frozenset(("sendBoc", "sendBocReturnHash"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Cells:
    def __init__(self):
        self.rows = {}
        self.bytes = 0

    def add(self, raw):
        require(0 < len(raw) <= MAX_CELL, "transaction cell exceeds bound")
        root = ops.lib.parse_boc(raw)
        s = ops.lib.Slice(root)
        require(s.bits(4) == 7, "not a transaction")
        account, lt = s.bytes(32).hex(), s.bits(64)
        previous_hash, previous_lt, utime = s.bytes(32), s.bits(64), s.bits(32)
        digest = root.hash()
        key = (account, lt, digest)
        row = {
            "@type": "raw.transaction",
            "account": account,
            "data": base64.b64encode(raw).decode(),
            "transaction_id": {
                "@type": "internal.transactionId",
                "lt": str(lt),
                "hash": base64.b64encode(digest).decode(),
            },
            "utime": utime,
        }
        if key in self.rows:
            require(self.rows[key][0] == row, "conflicting archive cell")
            return key
        require(len(self.rows) < MAX_ENTRIES, "archive entry bound reached")
        require(self.bytes + len(raw) <= MAX_BYTES, "archive byte bound reached")
        self.rows[key] = (row, previous_lt, previous_hash)
        self.bytes += len(raw)
        return key

    def load(self, roots):
        visited = 0
        for root in roots:
            for path in root.rglob("transactions/*.boc"):
                visited += 1
                require(visited <= 32768, "archive input-file bound reached")
                require(path.stat().st_size <= MAX_CELL, "archive input exceeds bound")
                self.add(path.read_bytes())
        require(self.rows, "archive is empty")

    def page(self, params):
        require(isinstance(params, dict), "missing transaction query")
        address, limit = params.get("address"), params.get("limit")
        require(
            isinstance(address, str) and address.startswith(("0:", "-1:")),
            "invalid account",
        )
        account = address.split(":", 1)[1]
        require(
            len(account) == 64 and bytes.fromhex(account).hex() == account,
            "invalid account id",
        )
        require(type(limit) is int and 0 < limit <= 1000, "invalid page bound")
        lt = int(params["lt"])
        require(0 < lt < 2**64, "invalid logical time")
        digest = base64.b64decode(params["hash"], validate=True)
        require(len(digest) == 32, "invalid transaction hash")
        page = []
        while lt and len(page) < limit:
            row = self.rows.get((account, lt, digest))
            if row is None:
                break
            value, lt, digest = row
            page.append(value)
        require(page, "requested transaction is absent from archive")
        # A missing predecessor does not become a fabricated zero predecessor:
        # it remains committed in the BOC and the reader must fetch it next.
        return page


def endpoint(value):
    url = urllib.parse.urlsplit(value)
    require(
        url.scheme == "http"
        and url.hostname == "127.0.0.1"
        and url.port is not None
        and url.username is None
        and url.password is None
        and url.path in ("", "/jsonRPC")
        and not url.query
        and not url.fragment,
        "only local RPC endpoints are allowed",
    )
    return value.rstrip("/") + ("" if url.path else "/jsonRPC")


def fetch(url, raw):
    request = urllib.request.Request(url, raw, {"Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(MAX_REPLY + 1)
        require(len(body) <= MAX_REPLY, "upstream response exceeds bound")
        return response.code, body


def answer(raw, upstream, cells, submit=False, transport=fetch):
    require(0 < len(raw) <= MAX_BODY, "request exceeds bound")
    request = json.loads(raw)
    require(
        isinstance(request, dict) and request.get("jsonrpc") == "2.0", "invalid request"
    )
    method = request.get("method")
    require(method in READS or submit and method in SUBMISSIONS, "method not permitted")
    status, body = transport(
        upstream, raw
    )  # Exactly one attempt, also for submissions.
    response = json.loads(body)
    require(isinstance(response, dict), "invalid upstream response")
    error = response.get("error")
    if (
        method == "getTransactions"
        and status in (200, 500)
        and isinstance(error, dict)
        and error.get("code") == -32603
        and "lt not in db" in error.get("message", "")
    ):
        page = cells.page(request.get("params"))
        body = json.dumps(
            {"jsonrpc": "2.0", "id": request.get("id"), "result": page}
        ).encode()
        return 200, body, True
    return status, body, False


def identity(upstream, root, file):
    node = ops.Node(upstream)
    info = node.call("getMasterchainInfo")
    require(
        ops.b64hash(info["init"]["root_hash"]).hex() == root
        and ops.b64hash(info["init"]["file_hash"]).hex() == file,
        "upstream genesis differs",
    )
    config = node.call("getConfigParam", param=19)
    cell = ops.lib.parse_boc(base64.b64decode(config["config"]["bytes"], validate=True))
    require(ops.lib.Slice(cell).bits(32) == 3, "local global id 3 required")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, upstream, cells, submit):
        super().__init__(("127.0.0.1", port), Handler)
        self.upstream, self.cells, self.submit = upstream, cells, submit
        self.slots = threading.BoundedSemaphore(16)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            self.connection.settimeout(35)
            size = int(self.headers.get("Content-Length", "0"))
            require(0 < size <= MAX_BODY, "request exceeds bound")
            status, body, cached = answer(
                self.rfile.read(size),
                self.server.upstream,
                self.server.cells,
                self.server.submit,
            )
            if cached:
                print(
                    json.dumps(
                        {
                            "upstream": self.server.upstream,
                            "retained_transaction_page": True,
                        }
                    ),
                    flush=True,
                )
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            RecursionError,
            ops.lib.TestnetError,
        ):
            status = 503
            body = b'{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"archive transport refused"}}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", action="append", required=True)
    parser.add_argument("--archive-root", type=Path, action="append", required=True)
    parser.add_argument("--genesis-root", required=True)
    parser.add_argument("--genesis-file", required=True)
    parser.add_argument("--listen-base", type=int, default=19010)
    parser.add_argument("--submission-sources", type=int, default=0)
    args = parser.parse_args()
    require(3 <= len(args.upstream) <= 6, "three to six independent upstreams required")
    upstreams = [endpoint(v) for v in args.upstream]
    require(len(set(upstreams)) == len(upstreams), "duplicate upstream")
    require(1024 <= args.listen_base <= 65535 - len(upstreams), "invalid listen ports")
    require(0 <= args.submission_sources <= 3, "at most three source submission routes")
    for upstream in upstreams:
        identity(upstream, args.genesis_root, args.genesis_file)
    cells = Cells()
    cells.load(args.archive_root)
    print(
        json.dumps(
            {
                "upstreams": upstreams,
                "retained_cells": len(cells.rows),
                "bytes": cells.bytes,
            }
        ),
        flush=True,
    )
    for index, upstream in enumerate(upstreams, 1):
        server = Server(
            args.listen_base + index, upstream, cells, index <= args.submission_sources
        )
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
