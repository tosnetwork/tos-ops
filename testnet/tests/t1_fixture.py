"""The T1 judge's green 72 h run, built by cloning producer samples (tests/data/t1-evidence/samples.json).

Only ids, timestamps and counters are varied; every other field is the sample's, so the fixture has exactly the
producers' shapes. The relationships the judge relies on are kept: each delivery belongs to its attempt and action,
each observed record follows its attempt's role, receipts follow execution, the lifecycle runs in order, and the
read result hashes the request journal it describes. Totals the tests assert are computed here from the schedule,
not with the judge's accounting.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data" / "t1-evidence" / "samples.json"
HOSTS = ("node-1", "node-2", "node-3", "node-4")
DATA_PATHS = ("/var/lib/tos/validator", "/var/log/tos")
GiB = 1 << 30


def samples() -> dict:
    return json.loads(DATA.read_text())["samples"]


def rec(s: dict, name: str, **over) -> dict:
    r = copy.deepcopy(s[name]["record"])
    r.update(over)
    return r


def write_jsonl(path: Path, items, journal_style: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for r in items:
            if journal_style:  # the ramp journal's own encoding (journal.py:125-128)
                fh.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
            else:
                fh.write(json.dumps(r, sort_keys=True) + "\n")


def head_id(seq: int, root: str) -> list:
    return [-1, "-9223372036854775808", seq, root, "XWiBwnMGrk+30a27i3JZRCgaThYa7viSxnaOVWouTj8="]


def build(root: Path, *, t0: float, duration: int, first_boundary: float, period: int, write_rate: float,
          read_rate: float, endpoints: list[str], operators: dict[str, str]) -> dict:
    """Write the green run under root/observe and root/load. Returns the schedule's own totals."""
    s = samples()
    obs, load = root / "observe", root / "load"
    end = t0 + duration
    # chain: a head per host every 20 s, ids every 60 s
    chain = []
    for k, t in enumerate(range(int(t0), int(end) + 1, 20)):
        for h in HOSTS:
            chain.append(rec(s, "chain/head", ts=float(t), host=h, id=head_id(1000 + k, "R" * 43 + "="),
                             gen_utime=t))
        if k % 3 == 0:
            ids = head_id(998 + k, "I" * 43 + "=")
            chain.append(rec(s, "chain/ids", ts=float(t), seqno=998 + k, ids={h: list(ids) for h in HOSTS},
                             agree=True))
    write_jsonl(obs / "chain.jsonl", chain)
    # resources and cache reads per host every 60 s
    res, cache = [], []
    base_read = s["cache/read"]["record"]
    for k, t in enumerate(range(int(t0), int(end) + 1, 60)):
        for h in HOSTS:
            r = rec(s, "resources/complete", ts=float(t), host=h, sent=t - 0.6, received=float(t),
                    sample_clock=t - 0.1)
            r["unit"].update(main_pid=4242, n_restarts=0, active_state="active")
            r["boot_id"] = f"boot-{h}"
            r["oom_kill"] = 0
            r["proc"]["RssAnon"] = 2 * GiB + (k % 120) * 1000
            r["mem"]["MemAvailable"] = 8 * GiB
            for p in DATA_PATHS:
                r["disks"][p].update(free_bytes=60 * GiB - k * 1000, free_inodes=5_000_000)
            res.append(r)
            c = rec(s, "cache/read", ts=float(t), host=h, sent=t - 0.6, received=float(t), baseline=k == 0)
            files = {"1:2": dict(name="node.log", size=1000 + k, start=1000 + k, offset=1000 + k, status="read",
                                 behind=0, fp="0" * 32)}
            # three of the live sample's other files, as captured (a real round reads about a hundred)
            files |= dict([(fid, e) for fid, e in base_read["files"].items() if e["name"] != "node.log"][:3])
            if k == 0:
                files = {fid: {kk: v for kk, v in dict(e, status="baseline").items() if kk != "behind"}
                         for fid, e in files.items() if e["status"] in ("read", "new")}
            c["files"] = files
            cache.append(c)
    write_jsonl(obs / "resources.jsonl", res)
    write_jsonl(obs / "cache.jsonl", cache)
    write_jsonl(obs / "clock.jsonl", [rec(s, "clock", ts=t0 + 3600 * i, host=h, verdict="ok")
                                      for i in range(duration // 3600 + 1) for h in HOSTS])
    b, bounds = first_boundary, []
    while b <= end:
        bounds.append(rec(s, "boundaries/checked", ts=b + 900, boundary=int(b), ended=b + 1200,
                          dir=f"/evidence/boundary-{int(b)}"))
        b += period
    write_jsonl(obs / "boundaries.jsonl", bounds)
    write_jsonl(obs / "fees.jsonl", [rec(s, "fees/reading", ts=t0 + 600 * i, operator=h, address=operators[h],
                                         answers={x: 90 * 10**9 for x in HOSTS}, balance_nano=90 * 10**9)
                                     for i in range(duration // 600 + 1) for h in HOSTS])
    # the supervisor's lifecycle
    write_jsonl(load / "load.jsonl", [
        rec(s, "load/start", ts=t0, cutoff_in_s=duration, mode="t1"),
        rec(s, "load/ramp_done", ts=end - 1000, elapsed_s=duration - 1000.0),
        rec(s, "load/cutoff", ts=end, reasons=[], elapsed_s=float(duration), undelivered=0),
        rec(s, "load/terminated", ts=end, children={"ramp": {"rc": 0, "group_alive": False},
                                                    "reads": {"rc": None, "group_alive": False}}),
        rec(s, "load/end", ts=end, result="cutoff")])
    # the ramp journal: run, one funding attempt, then transfers at the declared rate until the drain
    journal = [rec(s, "journal/run", time=t0 + 1)]
    fund = rec(s, "journal/attempt/funding", id="funding:bench:0", time=t0 + 5, signed_at=t0 + 5)
    journal += [fund, rec(s, "journal/sent", id=fund["id"], time=t0 + 6, state="accepted", reason=None),
                rec(s, "journal/observed/funding", id=fund["id"], time=t0 + 20, utime=int(t0 + 15))]
    t, n, transfers = t0 + 30, 0, 0
    while t < end - 900:
        aid = f"transfer:{n % 8}:{n // 8}"
        a = rec(s, "journal/attempt/transfer", id=aid, wallet=n % 8, seqno=n // 8, nonce=n // 8, signed_at=int(t),
                time=t, intended=t)
        a["actions"] = a["actions"][:1]
        journal += [a, rec(s, "journal/sent", id=aid, time=t + 0.5, state="accepted", reason=None),
                    rec(s, "journal/observed/transfer", id=aid, time=t + 3, utime=int(t) + 2, failure=[None]),
                    rec(s, "journal/delivered", id=aid, time=t + 6, action=0, recipient_tx=f"{n:064x}",
                        recipient_utime=int(t) + 5, receipt_failure=None)]
        transfers += 1
        t += 1 / write_rate
        n += 1
    journal.append(rec(s, "journal/end", time=end - 500))
    write_jsonl(load / "ramp" / "journal.jsonl", journal, journal_style=True)
    # the read client
    reads = load / "reads"
    reads.mkdir(parents=True)
    ctx = rec(s, "reads/context", started_monotonic_seconds=0.0, deadline_monotonic_seconds=float(duration))
    ctx["packet"].update(duration_seconds=duration, window_seconds=600, requests_per_second=read_rate,
                         endpoints=list(endpoints))
    (reads / "CONTEXT.json").write_text(json.dumps(ctx))
    per_window = int(read_rate * 600)
    methods = ("getMasterchainInfo", "getAddressInformation", "getTransactions", "getAddressInformation")
    lines = []
    for i in range(duration // 600):
        for k in range(per_window):
            off = i * 600 + k * (600 / per_window)
            r = rec(s, "reads/request", endpoint=endpoints[k % 4], method=methods[(k // 4) % 4] if per_window > 8
                    else methods[k % 3], latency_seconds=0.05, error=None, offered_monotonic_seconds=off,
                    finished_monotonic_seconds=off + 0.05)
            lines.append((json.dumps(r) + "\n").encode())
    data = b"".join(lines)
    (reads / "requests.jsonl").write_bytes(data)
    result = rec(s, "reads/result", completed=len(lines), errors=0, not_offered_capacity=0,
                 windows=duration // 600, requests_sha256=hashlib.sha256(data).hexdigest(),
                 started_monotonic_seconds=0.0)
    (reads / "RESULT.json").write_text(json.dumps(result))
    return {"transfers": transfers, "requests": len(lines), "boundaries": len(bounds)}
