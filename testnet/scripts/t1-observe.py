#!/usr/bin/env python3
"""T1 observation collectors (read-only), for the 72 h stability run (memo public-testnet/T1-PLAN-20261110.md §4).

  t1-observe.py --inventory hosts.json --unit-dir ~/.config/systemd/user --out DIR [--duration SECONDS]

Runs on the coordinator. Each collector appends one JSON object per line to its own file under DIR; every row has
`ts` (UTC, for evidence). Freshness, pacing and the run deadline use the monotonic clock only.

  resources.jsonl  per host every 60 s (t1_probe.py over SSH): unit, process, memory, OOM count, boot id and
                   disks, read first on the host and stamped with the host's `sample_clock`. A row lists what is
                   `missing`; only a complete row whose sample time falls inside the call refreshes freshness.
  cache.jsonl      from the same call: the validator logs read from per-file (dev:ino, offset) cursors, the parsed
                   "MEMORY_DIAGNOSTICS simplex-candidate-*" lines, and `coverage_gap` rows for any byte that was
                   or may have been lost. Gaps are permanent evidence; the collector never repairs them.
  du.jsonl         per host every 10 min, in its own thread: apparent size of celldb and archive.
  clock.jsonl      per host every hour: a clock-only SSH call, three tries, the narrowest interval kept.
  chain.jsonl      per host every 5 s: the head (getMasterchainInfo) bound to its header (all five id fields);
                   head regressions and same-height identity changes as their own rows. Every 60 s the full ids
                   at a common height on all four.
  health.jsonl     every 30 s, the status below, plus any collector round that raised.
  status.json      rewritten every 30 s:
                     blind          - true when any series is stale or any host's latest clock verdict is not ok;
                                      `reasons` names each. blind=false means the observations are fresh, NOT
                                      that the chain progresses.
                     chain          - per host head seqno and head_age_s (time since the seqno last increased);
                     stalled_hosts  - hosts whose head_age_s > 120 (T1 §6 stops at 3 or more);
                     clock          - per host latest verdict and when it was last ok;
                     baselined      - per host, when its log cursors were first set;
                     updated, updated_mono, coordinator_boot_id - compare monotonic values only within one boot.
                   The load runner must also treat a status.json older than 90 s as blind.
  cursors/<host>.json  the log cursors, rewritten after the cache row that consumed them is on disk. On restart
                   they are restored; a host with cache rows but no cursor file refuses the start.

A host or source that cannot be read is recorded every time as a row with its error. One host never delays or
stops another. Nothing here writes to a host. Handovers, the key gate, the safety scan and fees are separate
wrappers (§4.4-4.6).
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import math
import os
import re
import shlex
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
INTERVALS = {"resources": 60.0, "du": 600.0, "clock": 3600.0, "chain": 5.0, "ids": 60.0, "health": 30.0,
             "fees": 600.0}
OPERATOR_FLOOR_NANO = 20 * 10**9  # T1-PLAN §6: an operator under 20 TOS stops new submissions
# A series is stale when its last good record is older than this (monotonic seconds); then the run is blind.
FRESHNESS = {"resources": 180.0, "cache": 180.0, "logs": 180.0, "du": 1800.0, "clock": 7500.0, "chain": 30.0,
             "ids": 180.0, "fees": 1800.0}
PROBE_TIMEOUT, DU_TIMEOUT, CLOCK_TIMEOUT, RPC_TIMEOUT = 45, 560, 15, 2.0
SKEW = 5.0  # host vs coordinator clock allowance when placing a host-stamped time inside a call
CLOCK_LIMIT = 2.0  # |host - coordinator| allowed; the whole uncertainty interval must lie inside it
STALL = 120.0
GRAVE_ROUNDS = 10  # rounds a vanished file's cursor is remembered, in case the file is readable again
CACHE_FIELDS = ("node_limit", "node_charged_bytes", "node_charged_peak", "node_accounting_errors",
                "node_live_over_charge", "pinned_bytes", "nondurable_bytes", "nonfinalized_bytes")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
UNIT_STATES = {"active", "activating", "deactivating", "inactive", "failed", "reloading"}
PROBE = HERE / "t1_probe.py"
READ_STATUSES = ("baseline", "read", "new", "shrunk", "rewritten", "over_cap")  # the probe moved the cursor
GAP_STATUSES = ("shrunk", "rewritten", "over_cap")  # bytes were lost or may have been
ID_FIELDS = ("workchain", "shard", "seqno", "root_hash", "file_hash")


class RefuseStart(Exception):
    pass


def load_keys_gate():
    spec = importlib.util.spec_from_file_location("check_validator_keys", HERE / "check-validator-keys.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def strict_json(text: str) -> Any:
    def refuse(name):
        raise ValueError(f"non-finite number {name}")
    return json.loads(text, parse_constant=refuse)


def count(v) -> bool:
    return type(v) is int and v >= 0


def finite(v) -> bool:
    return type(v) in (int, float) and math.isfinite(v)


class Sink:
    """Append-only JSONL file, fsynced per row; one lock per file."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True) + "\n"
        with self.lock, self.path.open("a") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())


def atomic_write(path: Path, data: Any) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w") as fh:
        json.dump(data, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class Freshness:
    """Last good-record time per series key, on the monotonic clock."""

    def __init__(self, mono: Callable[[], float]):
        self.mono = mono
        self.lock = threading.Lock()
        self.last: dict[str, float] = {}

    def good(self, key: str) -> None:
        with self.lock:
            self.last[key] = self.mono()

    def stale(self, keys: list[str]) -> list[str]:
        now = self.mono()
        with self.lock:
            out = []
            for key in keys:
                limit = FRESHNESS[key.split(":")[0]]
                seen = self.last.get(key)
                if seen is None or now - seen > limit:
                    out.append(f"{key} stale ({'never' if seen is None else f'{now - seen:.0f} s'} > {limit:.0f} s)")
            return out


# ---------------------------------------------------------------- validation


def resource_problems(r: dict) -> list[str]:
    """What a probe report lacks to count as one complete resource observation."""
    out = []
    u = r.get("unit")
    if not (isinstance(u, dict) and count(u.get("main_pid")) and count(u.get("n_restarts"))
            and u.get("active_state") in UNIT_STATES):
        return ["unit"]
    active = u["active_state"] == "active"
    if active and u["main_pid"] == 0:
        out.append("unit main_pid")
    p = r.get("proc")
    if active and not (isinstance(p, dict) and all(count(p.get(k)) for k in ("RssAnon", "VmRSS", "VmSwap", "Threads", "fds"))):
        out.append("proc")
    m = r.get("mem")
    if not (isinstance(m, dict) and all(count(m.get(k)) for k in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"))):
        out.append("mem")
    if not count(r.get("oom_kill")):
        out.append("oom_kill")
    if not (isinstance(r.get("boot_id"), str) and UUID.match(r["boot_id"])):
        out.append("boot_id")
    d = r.get("disks")
    for path in DATA_PATHS:
        e = d.get(path) if isinstance(d, dict) else None
        if not (isinstance(e, dict) and all(count(e.get(k)) for k in ("free_bytes", "size_bytes", "free_inodes", "total_inodes"))):
            out.append(f"disk {path}")
    if not finite(r.get("sample_clock")):
        out.append("sample_clock")
    return out


def payload_ok(d: dict, received: float) -> bool:
    """A payloads line with every required counter, stamped inside the freshness window of this call."""
    return (d.get("kind") == "simplex-candidate-payloads"
            and all(count(d["fields"].get(k)) for k in CACHE_FIELDS)
            and received - FRESHNESS["cache"] <= d["ts"] <= received + SKEW)


def diag_shape_ok(diag) -> bool:
    return isinstance(diag, list) and all(
        isinstance(d, dict) and type(d.get("ts")) is int and isinstance(d.get("kind"), str)
        and isinstance(d.get("fields"), dict) and all(type(v) is int for v in d["fields"].values()) for d in diag)


def files_shape_ok(files) -> bool:
    if not isinstance(files, dict):
        return False
    for fid, e in files.items():
        if not (isinstance(e, dict) and isinstance(e.get("status"), str) and isinstance(e.get("name"), str)):
            return False
        if e["status"] in READ_STATUSES and not (
                count(e.get("start")) and count(e.get("offset")) and count(e.get("size"))
                and e["start"] <= e["offset"] <= e["size"] and isinstance(e.get("fp"), str)):
            return False
    return True


def closed(cursor: dict) -> bool:
    """A file seen under a rotated name and read to its end is closed and drained: the validator writes only to
    the active names, so nothing can follow, and its later disappearance or inode reuse loses nothing."""
    return ".old" in cursor["name"] and cursor["offset"] >= cursor["size"]


def hash32(v) -> bool:
    if not isinstance(v, str):
        return False
    try:
        return len(base64.b64decode(v, validate=True)) == 32
    except ValueError:
        return False


def block_id(i) -> tuple | None:
    """A complete block id (workchain, shard, seqno, root_hash, file_hash), or None when the seqno is not a
    count or a hash is not 32 bytes of base64: two missing hashes must never compare equal. Workchain and shard
    are not typed here because every use compares them for equality with -1 and SHARD."""
    if not (isinstance(i, dict) and "workchain" in i and "shard" in i
            and count(i.get("seqno")) and hash32(i.get("root_hash")) and hash32(i.get("file_hash"))):
        return None
    return tuple(i[k] for k in ID_FIELDS)


def header_id(h) -> tuple | None:
    return block_id(h.get("id")) if isinstance(h, dict) else None


# ---------------------------------------------------------------- RPC


class Rpc:
    def __init__(self, url: str):
        self.url = url
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method: str, timeout: float = RPC_TIMEOUT, **params: Any) -> Any:
        if method not in {"getMasterchainInfo", "getBlockHeader", "getAddressInformation"}:
            raise ValueError(f"{method} is not in the read-only allowlist")
        body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
        req = urllib.request.Request(self.url, body, {"Content-Type": "application/json"})
        with self.opener.open(req, timeout=timeout) as reply:
            answer = strict_json(reply.read(1024 * 1024 + 1))
        if not isinstance(answer, dict) or "result" not in answer:
            raise RuntimeError(str(answer.get("error") if isinstance(answer, dict) else answer)[:200])
        return answer["result"]


# ---------------------------------------------------------------- the observer


class Observer:
    def __init__(self, hosts, rpcs: dict, out: Path, wall=time.time, mono=time.monotonic, run=subprocess.run,
                 cache_series: bool = True, operators: dict[str, str] | None = None):
        self.hosts, self.rpcs, self.out = list(hosts), rpcs, out
        self.wall, self.mono, self.run = wall, mono, run
        # Without TOS_MEMORY_DIAGNOSTICS there are no cache lines; the cache series is then not a freshness
        # requirement, while the log reads (coverage for the safety scan) still are.
        self.cache_series = cache_series
        out.mkdir(parents=True, exist_ok=True)
        (out / "cursors").mkdir(exist_ok=True)
        self.sinks = {k: Sink(out / f"{k}.jsonl")
                      for k in ("resources", "cache", "safety", "du", "clock", "chain", "health")}
        self.counts = {"safety_hits": 0, "coverage_gaps": 0}
        self.operators = dict(operators or {})  # name -> address of each operator wallet (public)
        self.balances: dict[str, dict] = {}
        self.sinks["fees"] = Sink(out / "fees.jsonl")
        self.fresh = Freshness(mono)
        self.lock = threading.Lock()
        self.cursors = {h.name: self.load_cursors(h.name) for h in self.hosts}
        self.heads: dict[str, dict] = {}
        self.clock_verdict: dict[str, dict] = {}

    # ---- cursors

    def load_cursors(self, host: str) -> dict | None:
        path = self.out / "cursors" / f"{host}.json"
        if path.exists():
            data = strict_json(path.read_text())
            if not (isinstance(data, dict) and isinstance(data.get("files"), dict)):
                raise RefuseStart(f"{path}: not a cursor file")
            return data
        cache = self.out / "cache.jsonl"
        if cache.exists() and any(strict_json(x).get("host") == host for x in cache.read_text().splitlines() if x):
            raise RefuseStart(f"{host}: cache rows exist but {path} is missing; refusing to re-baseline")
        return None

    def save_cursors(self, host: str) -> None:
        atomic_write(self.out / "cursors" / f"{host}.json", self.cursors[host])

    # ---- remote calls

    def ssh(self, host, remote: str, stdin: str | None, timeout: float):
        argv = preflight.ssh_argv(host, accept_new=False) + [remote]
        try:
            r = self.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except OSError as exc:
            return None, f"launch failed: {exc}"
        lines = (r.stdout or "").strip().splitlines()
        if not lines:
            return None, f"no output (ssh rc {r.returncode})"
        try:
            return strict_json(lines[-1]), None
        except ValueError:
            return None, "output is not JSON"

    # ---- resources and cache

    def resources_round(self, host) -> None:
        cur = self.cursors[host.name]
        args = [a for p in DATA_PATHS for a in ("--path", p)]
        args += ["--baseline"] if cur is None else ["--cursors", json.dumps(self.cursor_offsets(host.name))]
        remote = f"timeout -k 5 {PROBE_TIMEOUT - 5} python3 - " + " ".join(shlex.quote(a) for a in args)
        sent = self.wall()
        report, error = self.ssh(host, remote, PROBE.read_text(), PROBE_TIMEOUT)
        received = self.wall()
        base = {"ts": received, "host": host.name, "sent": sent, "received": received}
        if report is None or not isinstance(report, dict):
            error = error or "report is not an object"
            self.sinks["resources"].write({**base, "error": error})
            self.sinks["cache"].write({**base, "kind": "error", "error": error})
            return
        missing = resource_problems(report)
        if finite(report.get("sample_clock")) and not sent - SKEW <= report["sample_clock"] <= received + SKEW:
            missing.append("sample_clock outside the call")
        self.sinks["resources"].write({
            **base, "complete": not missing, "missing": missing, "sample_clock": report.get("sample_clock"),
            **{k: report.get(k) for k in ("unit", "proc", "mem", "oom_kill", "boot_id", "disks")}})
        if not missing:
            self.fresh.good(f"resources:{host.name}")
        self.cache_part(host.name, cur, report, base, received)

    def cache_part(self, host: str, cur: dict | None, report: dict, base: dict, received: float) -> None:
        files, diag, vanished = report.get("files"), report.get("diag"), report.get("missing")
        safety = report.get("safety")
        if not (files_shape_ok(files) and diag_shape_ok(diag) and isinstance(vanished, list)
                and all(isinstance(v, str) for v in vanished) and isinstance(safety, list)
                and all(isinstance(s, dict) and isinstance(s.get("file"), str) and isinstance(s.get("line"), str)
                        for s in safety)):
            self.sinks["cache"].write({**base, "kind": "error", "error": "probe returned no valid log read"})
            return
        known = {} if cur is None else cur["files"]
        buried = {} if cur is None else cur.get("grave", {})
        gaps = []
        for fid, e in files.items():
            if e["status"] in GAP_STATUSES or e["status"].startswith("error"):
                gaps.append({"id": fid, "name": e["name"], "reason": e["status"], "bytes": e.get("gap_bytes")})
        for fid in vanished:
            if fid in buried and fid not in known:
                continue  # its disappearance was already judged when it first vanished
            prev = known.get(fid)
            if not (prev is not None and closed(prev)):
                gaps.append({"id": fid, "name": prev and prev["name"], "reason": "vanished", "bytes": None})
        self.sinks["cache"].write({**base, "kind": "read", "baseline": cur is None, "files": files, "lines": diag,
                                   "vanished": vanished})
        for g in gaps:
            self.sinks["cache"].write({**base, "kind": "coverage_gap", **g})
        for s in safety:
            self.sinks["safety"].write({**base, "kind": "safety_line", **s})
        with self.lock:
            self.counts["coverage_gaps"] += len(gaps)
            self.counts["safety_hits"] += len(safety)
        # Advance the cursors only now that the evidence they consumed is on disk.
        grave = {k: dict(v) for k, v in buried.items()}
        new_files = {}
        for fid, e in files.items():
            if e["status"] in READ_STATUSES:
                new_files[fid] = {"offset": e["offset"], "fp": e["fp"], "size": e["size"], "name": e["name"]}
            elif fid in known:
                new_files[fid] = known[fid]
        # A vanished file's cursor is kept for GRAVE_ROUNDS rounds and still sent to the probe, so a file that
        # becomes readable again resumes from its offset instead of being re-read from 0.
        for fid in vanished:
            if fid in known:
                grave[fid] = dict(known[fid], rounds=GRAVE_ROUNDS + 1)
        for fid in list(grave):
            grave[fid]["rounds"] -= 1
            if fid in new_files or grave[fid]["rounds"] <= 0:
                del grave[fid]
        self.cursors[host] = {"files": new_files, "grave": grave,
                              "baselined": base["ts"] if cur is None else cur["baselined"]}
        self.save_cursors(host)
        if cur is not None:
            self.fresh.good(f"logs:{host}")  # a valid read after the baseline; any gap is its own permanent row
        if cur is not None and not gaps and any(payload_ok(d, received) for d in diag):
            self.fresh.good(f"cache:{host}")

    def cursor_offsets(self, host: str) -> dict:
        cur = self.cursors[host]
        offs = {k: [v["offset"], v["fp"], closed(v)] for k, v in cur.get("grave", {}).items()}
        offs.update({k: [v["offset"], v["fp"], closed(v)] for k, v in cur["files"].items()})
        return offs

    # ---- du

    def du_round(self, host) -> None:
        args = " ".join(f"--du {shlex.quote(p)}" for p in DU_PATHS)
        sent = self.wall()
        report, error = self.ssh(host, f"timeout -k 10 {DU_TIMEOUT - 20} python3 - {args}", PROBE.read_text(), DU_TIMEOUT)
        row = {"ts": self.wall(), "host": host.name, "sent": sent}
        du = report.get("du") if isinstance(report, dict) else None
        if not isinstance(du, dict):
            self.sinks["du"].write({**row, "error": error or "no du section"})
            return
        complete = all(count(du.get(p)) for p in DU_PATHS)
        self.sinks["du"].write({**row, "du": du, "complete": complete})
        if complete:
            self.fresh.good(f"du:{host.name}")

    # ---- clock

    def clock_round(self, host, attempts: int = 3) -> dict:
        best = None
        tries = []
        for _ in range(attempts):
            w0, m0 = self.wall(), self.mono()
            reply, error = self.ssh(host, "python3 -c 'import json,time; print(json.dumps(time.time()))'", None, CLOCK_TIMEOUT)
            w1, m1 = self.wall(), self.mono()
            if error or not finite(reply):
                tries.append({"error": error or "not a number"})
                continue
            if abs((w1 - w0) - (m1 - m0)) >= 0.01:
                tries.append({"error": "coordinator clock stepped during the call"})
                continue
            t = {"offset": reply - (w0 + w1) / 2, "bound": (w1 - w0) / 2}
            tries.append(t)
            if best is None or t["bound"] < best["bound"]:
                best = t
        if best is None:
            verdict = "unmeasured"
        elif -CLOCK_LIMIT <= best["offset"] - best["bound"] and best["offset"] + best["bound"] <= CLOCK_LIMIT:
            verdict = "ok"
        elif abs(best["offset"]) - best["bound"] > CLOCK_LIMIT:
            verdict = "skewed"
        else:
            verdict = "uncertain"
        now = self.wall()
        with self.lock:
            prev = self.clock_verdict.get(host.name, {})
            self.clock_verdict[host.name] = {"verdict": verdict, "at": now,
                                             "last_ok": now if verdict == "ok" else prev.get("last_ok")}
        if verdict == "ok":
            self.fresh.good(f"clock:{host.name}")
        row = {"ts": now, "host": host.name, "verdict": verdict, "best": best, "tries": tries, "limit": CLOCK_LIMIT}
        self.sinks["clock"].write(row)
        return row

    # ---- chain

    def chain_round(self, host: str) -> None:
        r = self.rpcs[host]
        started = self.mono()
        try:
            last = r.call("getMasterchainInfo")["last"]
            want = block_id(last)
            if want is None or not (want[0] == -1 and want[1] == SHARD):
                raise ValueError(f"head is not a complete masterchain block id: {str(last)[:160]}")
            hdr = r.call("getBlockHeader", workchain=-1, shard=SHARD, seqno=want[2])
            if header_id(hdr) != want:
                raise ValueError(f"header {header_id(hdr)} does not match the head {want}")
            if not count(hdr.get("gen_utime")):
                raise ValueError("header has no gen_utime")
        except Exception as exc:  # an unreachable or inconsistent observer is recorded, never a crash
            self.sinks["chain"].write({"ts": self.wall(), "kind": "head", "host": host,
                                       "error": f"{type(exc).__name__}: {exc}"[:240]})
            return
        now_m, now_w = self.mono(), self.wall()
        if now_m - started > INTERVALS["chain"]:
            self.sinks["chain"].write({"ts": now_w, "kind": "cadence_miss", "host": host,
                                       "elapsed": now_m - started})
        with self.lock:
            prev = self.heads.get(host)
            seq = want[2]
            # Progress is a new maximum: returning to a height after a regression is not progress.
            if prev is None or seq > prev["max_seqno"]:
                advanced, top = now_m, seq
            else:
                advanced, top = prev["advanced_mono"], prev["max_seqno"]
                if seq < prev["id"][2]:
                    self.sinks["chain"].write({"ts": now_w, "kind": "regression", "host": host,
                                               "from": prev["id"], "to": list(want)})
                elif tuple(prev["id"]) != want:
                    self.sinks["chain"].write({"ts": now_w, "kind": "identity_change", "host": host,
                                               "from": prev["id"], "to": list(want)})
            self.heads[host] = {"id": list(want), "gen_utime": hdr["gen_utime"], "seen_mono": now_m,
                                "advanced_mono": advanced, "max_seqno": top}
        self.sinks["chain"].write({"ts": now_w, "kind": "head", "host": host, "id": list(want),
                                   "gen_utime": hdr["gen_utime"]})
        self.fresh.good(f"chain:{host}")

    def ids_round(self) -> None:
        now_m = self.mono()
        with self.lock:
            heads = {h: dict(v) for h, v in self.heads.items()}
        fresh_heads = {h: v["id"][2] for h, v in heads.items() if now_m - v["seen_mono"] <= FRESHNESS["chain"]}
        if len(fresh_heads) < len(self.rpcs):
            self.sinks["chain"].write({"ts": self.wall(), "kind": "ids",
                                       "error": f"only {len(fresh_heads)} of {len(self.rpcs)} fresh heads"})
            return
        common = min(fresh_heads.values()) - 2
        ids = {}
        for host, r in self.rpcs.items():
            try:
                h = r.call("getBlockHeader", workchain=-1, shard=SHARD, seqno=common)
                got = header_id(h)
                if got is None or got[:3] != (-1, SHARD, common):
                    raise ValueError(f"reply id {got} is not the requested block {common}")
                ids[host] = list(got)
            except Exception as exc:
                self.sinks["chain"].write({"ts": self.wall(), "kind": "ids", "host": host, "seqno": common,
                                           "error": f"{type(exc).__name__}: {exc}"[:240]})
        agree = len(ids) == len(self.rpcs) and len({json.dumps(v) for v in ids.values()}) == 1
        self.sinks["chain"].write({"ts": self.wall(), "kind": "ids", "seqno": common, "ids": ids, "agree": agree})
        if agree:
            self.fresh.good("ids:all")

    # ---- operator balances

    def fees_round(self) -> None:
        """Each operator wallet's balance from the first source that answers, every 10 min."""
        for name, address in self.operators.items():
            errors = []
            for host, r in self.rpcs.items():
                try:
                    info = r.call("getAddressInformation", address=address)
                    balance = info.get("balance") if isinstance(info, dict) else None
                    if not (isinstance(balance, (str, int)) and str(balance).isdigit()):
                        raise ValueError(f"balance {balance!r} is not a non-negative integer")
                    nano = int(balance)
                    break
                except Exception as exc:  # one source failing tries the next; all failing is a row
                    errors.append(f"{host}: {type(exc).__name__}: {exc}"[:160])
            else:
                self.sinks["fees"].write({"ts": self.wall(), "operator": name, "address": address, "error": errors})
                continue
            now = self.wall()
            self.sinks["fees"].write({"ts": now, "operator": name, "address": address, "source": host,
                                      "balance_nano": nano})
            with self.lock:
                self.balances[name] = {"balance_nano": nano, "at": now}
            self.fresh.good(f"fees:{name}")

    # ---- health

    def status(self) -> dict:
        names = [h.name for h in self.hosts]
        series = ("resources", "cache", "logs", "du", "clock", "chain") if self.cache_series else (
            "resources", "logs", "du", "clock", "chain")
        keys = [f"{k}:{h}" for k in series for h in names] + ["ids:all"] + [f"fees:{o}" for o in self.operators]
        reasons = self.fresh.stale(keys)
        now_m = self.mono()
        with self.lock:
            counts = dict(self.counts)
            balances = {o: dict(v) for o, v in self.balances.items()}
            clock = {h: dict(self.clock_verdict.get(h, {"verdict": "unmeasured"})) for h in names}
            chain = {h: {"seqno": v["id"][2], "max_seqno": v["max_seqno"], "head_age_s": now_m - v["advanced_mono"]}
                     for h, v in self.heads.items()}
            baselined = {h: (c or {}).get("baselined") for h, c in self.cursors.items()}
        reasons += [f"clock:{h} latest verdict {v['verdict']}" for h, v in clock.items() if v["verdict"] != "ok"]
        stalled = sorted(h for h, v in chain.items() if v["head_age_s"] > STALL)
        return {"blind": bool(reasons), "reasons": reasons, "chain": chain, "stalled_hosts": stalled,
                "clock": clock, "baselined": baselined, "cache_series": self.cache_series, **counts,
                "operators": balances,
                "operators_low": sorted(o for o, v in balances.items() if v["balance_nano"] < OPERATOR_FLOOR_NANO),
                "updated": self.wall(), "updated_mono": now_m, "coordinator_boot_id": coordinator_boot_id()}

    def health_round(self) -> dict:
        st = self.status()
        self.sinks["health"].write({"ts": st["updated"], **st})
        atomic_write(self.out / "status.json", st)
        return st


def coordinator_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError as exc:
        return f"error: {exc}"


# ---------------------------------------------------------------- loops


def run_loops(obs: Observer, duration: float) -> None:
    deadline = obs.mono() + duration
    stop = threading.Event()

    def every(interval: float, fn: Callable[[], Any], name: str) -> None:
        nxt = obs.mono()
        while not stop.is_set() and obs.mono() < deadline:
            try:
                fn()
            except Exception as exc:  # a failed round is recorded; its freshness then lapses and the run goes blind
                obs.sinks["health"].write({"ts": obs.wall(), "collector": name,
                                           "error": f"{type(exc).__name__}: {exc}"[:240]})
            nxt += interval
            delay = nxt - obs.mono()
            if delay > 0:
                stop.wait(min(delay, max(0.0, deadline - obs.mono())))
            else:
                nxt = obs.mono()

    jobs = [(INTERVALS["ids"], obs.ids_round, "ids"), (INTERVALS["health"], obs.health_round, "health")]
    if obs.operators:
        jobs.append((INTERVALS["fees"], obs.fees_round, "fees"))
    for h in obs.hosts:
        jobs += [(INTERVALS["resources"], lambda h=h: obs.resources_round(h), f"resources:{h.name}"),
                 (INTERVALS["du"], lambda h=h: obs.du_round(h), f"du:{h.name}"),
                 (INTERVALS["clock"], lambda h=h: obs.clock_round(h), f"clock:{h.name}"),
                 (INTERVALS["chain"], lambda h=h: obs.chain_round(h.name), f"chain:{h.name}")]
    threads = [threading.Thread(target=every, args=j, daemon=True) for j in jobs]
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
    ap.add_argument("--operators", type=Path, default=None,
                    help="JSON {name: wallet address} of the operator wallets to watch (public addresses only)")
    ap.add_argument("--no-cache-series", action="store_true",
                    help="the validators run without TOS_MEMORY_DIAGNOSTICS: do not require cache lines for freshness")
    a = ap.parse_args(argv)
    inventory = json.loads(a.inventory.read_text())
    hosts = [h for h in preflight.load_inventory(a.inventory) if h.name in HOSTS]
    if sorted(h.name for h in hosts) != list(HOSTS):
        print(f"inventory must name {', '.join(HOSTS)}", file=sys.stderr)
        return 1
    urls = load_keys_gate().tunnel_inventory(a.unit_dir, inventory)
    try:
        operators = json.loads(a.operators.read_text()) if a.operators else None
        if operators is not None and not (isinstance(operators, dict) and operators
                                          and all(isinstance(v, str) for v in operators.values())):
            print("--operators must be a non-empty JSON object of name -> address", file=sys.stderr)
            return 1
        obs = Observer(hosts, {h: Rpc(urls[h]) for h in HOSTS}, a.out, cache_series=not a.no_cache_series,
                       operators=operators)
    except RefuseStart as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 2
    run_loops(obs, a.duration)
    return 0


if __name__ == "__main__":
    sys.exit(main())
