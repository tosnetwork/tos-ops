#!/usr/bin/env python3
"""Re-runnable client steps for the local token buyer agent.

This client never signs or confirms a payment. Use the custody account's
confirmer after inspecting the preview. The agent owns the value journal.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import socket
from pathlib import Path

MAX_BYTES = 16 << 20


class Refused(ValueError):
    pass


def call(path, method, params):
    request = {
        "schema": "tos.service.mcp-buyer.agent-api.v1",
        "method": method,
        "params": params,
    }
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(320)
        connection.connect(str(path))
        connection.sendall(json.dumps(request).encode() + b"\n")
        with connection.makefile("rb") as stream:
            raw = stream.readline(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES or not raw.endswith(b"\n"):
        raise Refused("agent response outside bounds")
    result = json.loads(raw)
    if result.get("schema") != request["schema"] or not result.get("ok"):
        raise Refused(json.dumps(result.get("error", "invalid agent response")))
    return result["result"]


def save(path, record):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as output:
        os.chmod(temporary, 0o600)
        json.dump(record, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_input(path):
    with path.open("rb") as source:
        data = source.read((1 << 20) + 1)
    if not 0 < len(data) <= 1 << 20:
        raise Refused("offer or archive outside bounds")
    return data


def prepare(args, path):
    offer_bytes = read_input(args.offer)
    archive = read_input(args.archive)
    if not 0 < len(offer_bytes) <= 1 << 20 or not 0 < len(archive) <= 1 << 20:
        raise Refused("offer or archive outside bounds")
    offer = json.loads(offer_bytes)
    identity = {
        "case": args.case,
        "offer_hash": hashlib.sha256(offer_bytes).hexdigest(),
        "archive_hash": hashlib.sha256(archive).hexdigest(),
        "socket": str(args.socket),
    }
    record = json.loads(path.read_text()) if path.exists() else {"identity": identity}
    if record["identity"] != identity:
        raise Refused("case reused with a different offer, archive or agent")
    save(path, record)
    if "quote" not in record:
        record["quote"] = call(
            args.socket,
            "quote",
            {
                "capability_id": offer["capability_id"],
                "capability_version": offer["version"],
                "source": "local",
                "offer_file_base64": base64.b64encode(offer_bytes).decode(),
            },
        )
        save(path, record)
    if "purchase" not in record:
        # A lost reply reuses the same quote, source and idempotency key.
        # No payment happens until the separate custody confirmation.
        record["purchase"] = call(
            args.socket,
            "prepare",
            {
                "quote_id": record["quote"]["quote_id"],
                "idempotency_key": "token-work-" + args.case,
                "archive_base64": base64.b64encode(archive).decode(),
            },
        )
        save(path, record)
    return record["purchase"]


def execute(args):
    if not re.fullmatch(r"[a-z0-9_-]{6,53}", args.case):
        raise Refused(
            "case must be 6-53 lowercase letters, digits, underscores or hyphens"
        )
    args.state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.state.is_symlink() or args.state.stat().st_mode & 0o077:
        raise Refused("client state must be private")
    path = args.state / (args.case + ".json")
    with (args.state / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.step == "prepare":
            if args.offer is None or args.archive is None:
                raise Refused("prepare needs --offer and --archive")
            return prepare(args, path)
        record = json.loads(path.read_text())
        if record["identity"]["socket"] != str(args.socket):
            raise Refused("another agent socket")
        params = {"request_hash": record["purchase"]["request_hash"]}
        method = args.step
        if method == "request-payment":
            method = "request_payment"
            params["wait_seconds"] = 0
        elif method == "refund":
            method = "refund_now"
        result = call(args.socket, method, params)
        record[args.step] = result
        save(path, record)
        return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "step", choices=("prepare", "request-payment", "status", "refund", "result")
    )
    p.add_argument("--socket", type=Path, required=True)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--offer", type=Path)
    p.add_argument("--archive", type=Path)
    args = p.parse_args()
    print(json.dumps(execute(args), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
