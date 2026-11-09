#!/usr/bin/env python3
"""Read-only T3 sampler: masterchain head and consensus block of each observation port.

  t3-sample.py --out samples.jsonl --duration SECONDS [--interval 2]
               [--port 18081 --port 38081 --port 28081 --port 48084]

Every interval it calls getMasterchainInfo and getConsensusBlock on each port's loopback
JSON-RPC tunnel and appends one JSON line per port: the UTC time, the port, the head
seqno, the consensus block, the last block's utime and any error. With the default four
ports and 2 s it sends 1 request per second to each node, far inside the 600 requests per
10 s per address budget. It stops after --duration (at most 3600 s) or on SIGTERM/SIGINT,
writes a final {"stop": ...} line and exits 0.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
import urllib.request

DEFAULT_PORTS = (18081, 38081, 28081, 48084)
MAX_DURATION = 3600
MIN_INTERVAL = 1.0
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def rpc(port: int, method: str, timeout: float = 3.0) -> dict:
    body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params={})).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/jsonRPC", body, {"Content-Type": "application/json"}
    )
    with OPENER.open(req, timeout=timeout) as r:
        d = json.load(r)
    if "error" in d:
        raise RuntimeError(str(d["error"])[:200])
    return d["result"]


def sample(port: int, call=rpc, now=time.time) -> dict:
    row: dict = dict(
        t=round(now(), 3),
        port=port,
        seqno=None,
        consensus_block=None,
        last_block_utime=None,
        error=None,
    )
    errors = []
    try:
        row["seqno"] = int(call(port, "getMasterchainInfo")["last"]["seqno"])
    except Exception as e:
        errors.append(f"getMasterchainInfo: {e!r}"[:200])
    try:
        c = call(port, "getConsensusBlock")
        row["consensus_block"] = int(c["consensus_block"])
        row["last_block_utime"] = int(c["last_block_utime"])
    except Exception as e:
        errors.append(f"getConsensusBlock: {e!r}"[:200])
    row["error"] = "; ".join(errors) or None
    return row


def main(argv: list[str], call=rpc, sleep=time.sleep, now=time.time) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--port", type=int, action="append")
    a = ap.parse_args(argv)
    if not 0 < a.duration <= MAX_DURATION:
        print(f"refused: --duration must be in (0, {MAX_DURATION}]", file=sys.stderr)
        return 2
    if a.interval < MIN_INTERVAL:
        print(f"refused: --interval must be at least {MIN_INTERVAL}", file=sys.stderr)
        return 2
    ports = a.port or list(DEFAULT_PORTS)
    stop = {"why": None}

    def on_signal(signum, _frame):
        stop["why"] = signal.Signals(signum).name

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    start = now()
    end = start + a.duration
    with open(a.out, "a", buffering=1) as f:
        f.write(
            json.dumps(dict(start=start, ports=ports, interval=a.interval, duration=a.duration))
            + "\n"
        )
        tick = start
        while stop["why"] is None and now() < end:
            for port in ports:
                f.write(json.dumps(sample(port, call, now)) + "\n")
            # Never catch up in a burst after slow answers: the budget is per second.
            tick = max(tick + a.interval, now())
            while stop["why"] is None and now() < min(tick, end):
                sleep(min(0.2, max(0.0, tick - now())))
        f.write(json.dumps(dict(stop=now(), reason=stop["why"] or "duration")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
