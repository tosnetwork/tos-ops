#!/usr/bin/env python3
"""T1 observation collectors (read-only), for the 72 h stability run (memo public-testnet/T1-PLAN-20261110.md §4).

  t1-observe.py --inventory hosts.json --unit-dir ~/.config/systemd/user --out DIR [--duration SECONDS]

Collectors, each appending one JSON object per line to its own file under DIR:
  resources.jsonl  every 60 s per validator host, over SSH (t1_probe.py through `python3 -`):
                   MainPID, NRestarts, ActiveState, RssAnon/VmRSS/VmSwap, threads, fds, MemAvailable, swap,
                   boot id, free bytes and inodes of the data and log paths; every 10th sample the apparent size
                   of celldb and archive; the host clock.
  cache.jsonl      the "MEMORY_DIAGNOSTICS simplex-candidate-*" lines each host logged since the previous sample
                   (they exist only when the validator runs with TOS_MEMORY_DIAGNOSTICS=1), with each log file's
                   read status, so that missing coverage is recorded, never inferred.
  chain.jsonl      every 5 s, the masterchain head of each validator through its inventory-bound tunnel; every 60 s
                   the full block id of a common height on all four.
  health.jsonl     every 30 s, each collector's age since its last good record, against its freshness limit.
  status.json      rewritten every 30 s: {"blind": bool, "reasons": [...], "updated": unix}. The load runner stops
                   new submissions while it is blind, and also when "updated" is older than 90 s (the health
                   collector itself stopped).

Not covered here (separate wrappers): handovers and the key gate, the safety-line scan, and fees (§4.4-4.6).

A host or source that cannot be read is recorded every time as a row with its error. A collector never stops
because one host failed. Nothing here writes to a host.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import preflight  # noqa: E402

HOSTS = ("node-1", "node-2", "node-3", "node-4")
DATA_PATHS = ("/var/lib/tos/validator", "/var/log/tos")
DU_PATHS = ("/var/lib/tos/validator/celldb", "/var/lib/tos/validator/archive")
SHARD = "-9223372036854775808"
INTERVALS = {"resources": 60.0, "chain": 5.0, "ids": 60.0, "health": 30.0}
# A collector is stale when its last good record is older than this; then the run is blind.
FRESHNESS = {"resources": 180.0, "cache": 180.0, "chain": 30.0, "ids": 180.0}
PROBE = HERE / "t1_probe.py"


def load_keys_gate():
    spec = importlib.util.spec_from_file_location("check_validator_keys", HERE / "check-validator-keys.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Sink:
    """Append-only JSONL file; one lock per file."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True) + "\n"
        with self.lock, self.path.open("a") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())


class Freshness:
    """Last good-record time per collector, and per host where it matters."""

    def __init__(self, clock: Callable[[], float]):
        self.clock = clock
        self.lock = threading.Lock()
        self.last: dict[str, float] = {}

    def good(self, key: str) -> None:
        with self.lock:
            self.last[key] = self.clock()

    def stale(self, limits: dict[str, float], keys: list[str]) -> list[str]:
        now = self.clock()
        with self.lock:
            out = []
            for key in keys:
                limit = limits[key.split(":")[0]]
                seen = self.last.get(key)
                if seen is None or now - seen > limit:
                    out.append(f"{key} stale ({'never' if seen is None else f'{now - seen:.0f} s'} > {limit:.0f} s)")
            return out


# ---------------------------------------------------------------- resources and cache (SSH)


def probe_host(host, since: float, with_du: bool, run=subprocess.run, clock=time.time) -> tuple[dict | None, str | None]:
    """The probe's report, with "sent" and "received" (coordinator clock) around the SSH call, or an error."""
    sent = clock()
    report, error = _probe_host(host, since, with_du, run)
    if report is not None:
        report["sent"], report["received"] = sent, clock()
    return report, error


def clock_offset(report: dict) -> dict | None:
    """Host clock minus coordinator clock at the call's midpoint; `bound` is half the round trip."""
    if type(report.get("clock")) not in (int, float):
        return None
    mid = (report["sent"] + report["received"]) / 2
    return {"offset": report["clock"] - mid, "bound": (report["received"] - report["sent"]) / 2}


def _probe_host(host, since: float, with_du: bool, run) -> tuple[dict | None, str | None]:
    args = " ".join(f"--path {p}" for p in DATA_PATHS) + f" --diag-since {since:.0f}"
    if with_du:
        args += " " + " ".join(f"--du {p}" for p in DU_PATHS)
    argv = preflight.ssh_argv(host, accept_new=False) + [f"python3 - {args}"]
    try:
        r = run(argv, input=PROBE.read_text(), capture_output=True, text=True, timeout=660 if with_du else 90,
                check=False)
    except subprocess.TimeoutExpired:
        return None, "probe timeout"
    except OSError as exc:
        return None, f"probe launch failed: {exc}"
    lines = (r.stdout or "").strip().splitlines()
    if not lines:
        return None, f"no output (ssh rc {r.returncode})"
    try:
        report = json.loads(lines[-1])
    except ValueError:
        return None, "output is not JSON"
    if not isinstance(report, dict) or not isinstance(report.get("unit"), dict):
        return None, "output has no unit section"
    return report, None


def resources_round(hosts, sinks, fresh, state, now, run=subprocess.run) -> None:
    state["round"] = state.get("round", 0) + 1
    with_du = state["round"] % 10 == 1
    for host in hosts:
        since = state.setdefault("diag_since", {}).get(host.name, now - 120)
        report, error = probe_host(host, since, with_du, run)
        if report is None:
            sinks["resources"].write({"ts": now, "host": host.name, "error": error})
            sinks["cache"].write({"ts": now, "host": host.name, "error": error})
            continue
        sinks["resources"].write({
            "ts": now, "host": host.name,
            "unit": report.get("unit"), "proc": report.get("proc"), "mem": report.get("mem"),
            "oom_kill": report.get("oom_kill"), "boot_id": report.get("boot_id"),
            "disks": report.get("disks"), "du": report.get("du"),
            "probe_sent": report["sent"], "probe_received": report["received"], "clock": clock_offset(report),
        })
        fresh.good(f"resources:{host.name}")
        diag = report.get("diag")
        if not isinstance(diag, list) or not all(
                isinstance(d, dict) and type(d.get("ts")) is int and isinstance(d.get("kind"), str)
                and isinstance(d.get("fields"), dict) for d in diag):
            sinks["cache"].write({"ts": now, "host": host.name, "error": "probe returned no valid diag list"})
            continue
        new = fresh_diag_lines(state.setdefault("diag_seen", {}).setdefault(host.name, set()), diag)
        sinks["cache"].write({"ts": now, "host": host.name, "since": since, "lines": new,
                              "files": report.get("diag_files", [])})
        if any(d.get("kind") == "simplex-candidate-payloads" for d in new):
            fresh.good(f"cache:{host.name}")
        if diag:
            # Log stamps have one-second resolution: re-read the last second next time, drop what was already kept.
            state["diag_since"][host.name] = max(d["ts"] for d in diag) - 1


def fresh_diag_lines(seen: set, lines: list[dict]) -> list[dict]:
    """The lines not yet recorded; `seen` keeps only keys from the last two seconds read, so it stays bounded."""
    out = []
    for d in lines:
        key = json.dumps([d.get("ts"), d.get("kind"), d.get("file"), d.get("fields")], sort_keys=True)
        if key not in seen:
            out.append(d)
    if lines:
        floor = max(d["ts"] for d in lines) - 1
        seen.clear()
        seen.update(json.dumps([d.get("ts"), d.get("kind"), d.get("file"), d.get("fields")], sort_keys=True)
                    for d in lines if d["ts"] >= floor)
    return out


# ---------------------------------------------------------------- chain (RPC through the tunnels)


class Rpc:
    def __init__(self, url: str):
        self.url = url
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method: str, **params: Any) -> Any:
        if method not in {"getMasterchainInfo", "getBlockHeader"}:
            raise ValueError(f"{method} is not in the read-only allowlist")
        body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
        req = urllib.request.Request(self.url, body, {"Content-Type": "application/json"})
        with self.opener.open(req, timeout=10) as reply:
            answer = json.loads(reply.read(1024 * 1024 + 1))
        if not isinstance(answer, dict) or "result" not in answer:
            raise RuntimeError(str(answer.get("error"))[:200])
        return answer["result"]


def chain_round(rpcs: dict[str, Rpc], sinks, fresh, now) -> dict[str, int]:
    heads = {}
    for host, r in rpcs.items():
        try:
            last = r.call("getMasterchainInfo")["last"]
            hdr = r.call("getBlockHeader", workchain=-1, shard=SHARD, seqno=last["seqno"])
            heads[host] = last["seqno"]
            sinks["chain"].write({"ts": now, "kind": "head", "host": host, "seqno": last["seqno"],
                                  "root_hash": last["root_hash"], "gen_utime": hdr["gen_utime"]})
            fresh.good(f"chain:{host}")
        except Exception as exc:  # an unreachable observer is recorded, never a crash
            sinks["chain"].write({"ts": now, "kind": "head", "host": host, "error": f"{type(exc).__name__}: {exc}"[:240]})
    return heads


def ids_round(rpcs: dict[str, Rpc], heads: dict[str, int], sinks, fresh, now) -> None:
    if len(heads) < len(rpcs):
        sinks["chain"].write({"ts": now, "kind": "ids", "error": f"only {len(heads)} of {len(rpcs)} heads"})
        return
    common = min(heads.values()) - 2
    ids, gens = {}, {}
    for host, r in rpcs.items():
        try:
            h = r.call("getBlockHeader", workchain=-1, shard=SHARD, seqno=common)
            ids[host] = [h["id"]["seqno"], h["id"]["root_hash"], h["id"]["file_hash"]]
            gens[host] = h["gen_utime"]
        except Exception as exc:
            sinks["chain"].write({"ts": now, "kind": "ids", "host": host, "seqno": common,
                                  "error": f"{type(exc).__name__}: {exc}"[:240]})
    agree = len(ids) == len(rpcs) and len({json.dumps(v) for v in ids.values()}) == 1
    sinks["chain"].write({"ts": now, "kind": "ids", "seqno": common, "ids": ids, "gen_utime": gens, "agree": agree})
    if agree:
        fresh.good("ids:all")


# ---------------------------------------------------------------- health and status


def health_round(fresh, hosts: list[str], sinks, status_path: Path, now) -> dict:
    keys = [f"resources:{h}" for h in hosts] + [f"cache:{h}" for h in hosts] + [f"chain:{h}" for h in hosts] + ["ids:all"]
    reasons = fresh.stale(FRESHNESS, keys)
    status = {"blind": bool(reasons), "reasons": reasons, "updated": now}
    sinks["health"].write({"ts": now, **status})
    tmp = status_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(status) + "\n")
    os.replace(tmp, status_path)
    return status


# ---------------------------------------------------------------- main


def run_loops(hosts, rpcs, out: Path, until: float, clock=time.time, sleep=time.sleep, run=subprocess.run) -> None:
    out.mkdir(parents=True, exist_ok=True)
    sinks = {k: Sink(out / f"{k}.jsonl") for k in ("resources", "cache", "chain", "health")}
    fresh = Freshness(clock)
    state: dict[str, Any] = {}
    stop = threading.Event()

    def every(interval: float, fn: Callable[[float], None], name: str) -> None:
        nxt = clock()
        while not stop.is_set() and clock() < until:
            try:
                fn(clock())
            except Exception as exc:  # a failed round is recorded; its freshness then lapses and the run goes blind
                sinks["health"].write({"ts": clock(), "collector": name, "error": f"{type(exc).__name__}: {exc}"[:240]})
            nxt += interval
            delay = nxt - clock()
            if delay > 0:
                stop.wait(delay) if sleep is time.sleep else sleep(delay)
            else:
                nxt = clock()

    heads: dict[str, int] = {}

    def chain_tick(now):
        heads.clear()
        heads.update(chain_round(rpcs, sinks, fresh, now))
        if now - state.get("ids_at", float("-inf")) >= INTERVALS["ids"]:
            state["ids_at"] = now
            ids_round(rpcs, dict(heads), sinks, fresh, now)

    threads = [
        threading.Thread(target=every, args=(INTERVALS["resources"], lambda now: resources_round(hosts, sinks, fresh, state, now, run), "resources"), daemon=True),
        threading.Thread(target=every, args=(INTERVALS["chain"], chain_tick, "chain"), daemon=True),
        threading.Thread(target=every, args=(INTERVALS["health"], lambda now: health_round(fresh, [h.name for h in hosts], sinks, out / "status.json", now), "health"), daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        for t in threads:
            t.join()
    finally:
        stop.set()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inventory", type=Path, required=True)
    ap.add_argument("--unit-dir", type=Path, default=Path.home() / ".config/systemd/user")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--duration", type=float, default=80 * 3600)
    a = ap.parse_args(argv)
    inventory = json.loads(a.inventory.read_text())
    hosts = [h for h in preflight.load_inventory(a.inventory) if h.name in HOSTS]
    if sorted(h.name for h in hosts) != list(HOSTS):
        print(f"inventory must name {', '.join(HOSTS)}", file=sys.stderr)
        return 1
    urls = load_keys_gate().tunnel_inventory(a.unit_dir, inventory)
    rpcs = {h: Rpc(urls[h]) for h in HOSTS}
    run_loops(hosts, rpcs, a.out, time.time() + a.duration)
    return 0


if __name__ == "__main__":
    sys.exit(main())
