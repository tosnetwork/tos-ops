#!/usr/bin/env python3
"""T1 judge (memo public-testnet/T1-PLAN-20261110 §5; T1-PRB-DESIGN-20261110 v3.1 §5).

  t1-judge.py --record RECORD.json --record-sha256 HEX --observe OBSERVE_DIR --load LOAD_DIR [--out VERDICT.json]

Reads only retained evidence: the observer's series (t1-observe.py, t1-boundaries.py) and the load supervisor's
directory (t1-load.py: load.jsonl, the ramp's journal.jsonl, the read client's CONTEXT / requests / RESULT). All of
it is read through the evidence contract (t1_evidence.py): every row is checked against its producer's schema
first, and a criterion whose files violate the contract can at best be INCONCLUSIVE. It recomputes every §5
criterion from that evidence and the frozen acceptance record, and prints one verdict:

  PASS          every criterion passed on complete evidence
  FAIL          at least one criterion failed (a near miss is not reclassified)
  INCONCLUSIVE  no criterion failed, but at least one could not be established (missing, incomplete or
                contract-violating evidence)

The schedule, the windows and every threshold come from the record, never from the evidence being judged.
Absence of a recorded violation is never a pass: each series must be positively present and continuous. An
action without a valid `delivered` record is not delivered. Stored verdicts (a read window's `pass` flag, the
observer's `agree`) are ignored and recomputed from the underlying measurements.
Exit status: 0 PASS, 1 FAIL, 3 INCONCLUSIVE, 2 refused (the record does not match or is incomplete).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import t1_evidence as E  # noqa: E402

HOSTS = E.HOSTS
DATA_PATHS = E.DATA_PATHS
DURATION = 259_200
DECLARED_RATE = 2  # transfers/s (T1-PLAN §3.2)
READ_RATE = 8  # scheduled read requests/s (T1-PLAN §3.1)
READ_ENDPOINTS = 4
# The pinned T1 read inventory (read_client.T1_ENDPOINTS; a test keeps the two equal).
T1_READ_ENDPOINTS = ("http://127.0.0.1:18081/jsonRPC", "http://127.0.0.1:38081/jsonRPC",
                     "http://127.0.0.1:28081/jsonRPC", "http://127.0.0.1:48084/jsonRPC")
# The observer's own coverage rule for a log read (t1-observe.py; a test keeps these equal): the active log was
# read this round and no read file is more than LOG_LAG_BYTES behind.
LOG_LAG_BYTES = 1024 * 1024
ACTIVE_LOG = "node.log"
LOG_READ_STATUSES = ("baseline", "read", "new", "shrunk", "rewritten", "over_cap")
CHILDREN = ("ramp", "reads")
READ_METHODS = ("getMasterchainInfo", "getAddressInformation", "getTransactions")
PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
JUDGE_REQUIRED = {
    "max_chain_gap_s": "§5.1: no masterchain gap above this (60)",
    "head_series_gap_s": "a head series gap beyond this makes the stall check incomplete",
    "ids_series_gap_s": "§5.2: agreed common-height ids must be observed at least this often",
    "resource_series_gap_s": "a resource series gap beyond this makes §5.2–5.4 incomplete",
    "logs_series_gap_s": "§5.5: each host's log reads must be at least this frequent (coverage)",
    "clock_series_gap_s": "collector health: an ok clock verdict per host at least this often",
    "fees_series_gap_s": "§5.8: each operator's balance readings at least this often",
    "divergence_s": "§5.2: ids disagreeing longer than this is a persistent divergence",
    "rss_anon_max_bytes": "§5.3: absolute RssAnon bound",
    "rss_growth_e2e_bytes": "§5.3: growth at the same session phase, first vs last full term",
    "rss_growth_rolling_bytes": "§5.3: growth at the same session phase over rolling_terms consecutive terms",
    "rolling_terms": "§5.3: terms in a rolling window",
    "phases_per_term": "§5.3: comparable session positions per term",
    "mem_available_floor_bytes": "§5.3: MemAvailable floor",
    "disk_free_floor_bytes": "§5.4: free space floor",
    "disk_free_floor_inodes": "§5.4: free inode floor",
    "disk_bytes_per_block_max": "§5.4: the frozen per-block bound",
    "read_window_s": "§5.6: the read window (600)",
    "read_deadline_s": "§5.6: a request completed within this counts",
    "read_completed_fraction": "§5.6: completed-within-deadline per window ≥ this × scheduled (0.9)",
    "read_error_fraction_max": "§5.6: errors per window ≤ this fraction",
    "write_start_max_s": "§5.7: the first transfer must be signed within this after the start (preparation)",
    "write_end_slack_s": "§5.7: the last transfer must be signed within this before the cutoff (drain, margin)",
    "write_hourly_floor_fraction": "§5.7: delivered per hour ≥ this × the declared rate × 3600",
    "backlog_max_actions": "§5.7: executed-but-undelivered actions at any time",
    "max_cost_nano": "§5.8: the spend cap",
    "operator_floor_nano": "§5.8: no operator below this",
    "first_boundary": "§5.1: the pinned schedule",
    "period": "§5.1: the pinned schedule",
}
# The evidence files each criterion depends on: a contract violation in any of them caps it at INCONCLUSIVE.
CRITERION_FILES = {
    "5.1 no stall": ("chain",),
    "5.1 handovers and key gate": ("boundaries",),
    "5.2 no restart, OOM or divergence": ("resources", "chain"),
    "5.3 bounded memory": ("resources",),
    "5.4 bounded disk": ("resources", "chain"),
    "5.5 no safety line": ("safety", "cache"),
    "5.6 reads": ("reads", "reads/CONTEXT.json", "reads/RESULT.json", "reads/requests.jsonl"),
    "5.7 writes": ("journal",),
    "5.8 operators": ("fees",),
    "collector clock": ("clock",),
    "run completed": ("load",),
}


class Refuse(Exception):
    pass


def finite(v) -> bool:
    return type(v) in (int, float) and math.isfinite(v)


def load_record(path: Path, sha: str) -> dict:
    if not path.is_file():
        raise Refuse(f"no acceptance record at {path}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
        raise Refuse("acceptance record sha256 does not match")
    rec = json.loads(path.read_text())
    judge = rec.get("judge") if isinstance(rec, dict) else None
    if not isinstance(judge, dict):
        raise Refuse("acceptance record has no judge section")
    for key, why in JUDGE_REQUIRED.items():
        if not finite(judge.get(key)) or judge[key] <= 0:
            raise Refuse(f"acceptance record judge.{key} must be a finite number > 0 ({why})")
    ops = judge.get("operators")
    if not (isinstance(ops, list) and ops and all(isinstance(o, str) and o for o in ops) and len(set(ops)) == len(ops)):
        raise Refuse("acceptance record judge.operators must list every pinned operator")
    return judge


def rows(path: Path) -> list[dict]:
    """A JSONL series; a torn last line (a writer killed mid-line) is dropped, any other bad line is an error."""
    if not path.exists():
        return []
    lines = path.read_bytes().split(b"\n")
    out = []
    for i, raw in enumerate(lines):
        if not raw.strip():
            continue
        try:
            out.append(json.loads(raw))
        except ValueError:
            if i == len(lines) - 1:
                continue
            raise
    return out


def result(status: str, **facts) -> dict:
    return {"status": status, **facts}


def max_gap(times: list[float], start: float, end: float) -> float:
    """The longest stretch of [start, end] without an observation."""
    ts = sorted(t for t in times if start <= t <= end)
    edges = [start, *ts, end]
    return max(b - a for a, b in zip(edges, edges[1:]))


def inside(rs: list[dict], t0: float, t1: float) -> list[dict]:
    return [r for r in rs if t0 <= r["ts"] <= t1]


# ---------------------------------------------------------------- the run lifecycle


def window(ev: E.Evidence) -> tuple[float, float, list[dict]]:
    starts = ev.of("load", "load/start")
    if not starts:
        raise Refuse("load.jsonl has no valid start row: the run never started")
    s = starts[0]
    if s["mode"] != "t1" or s["cutoff_in_s"] != DURATION:
        raise Refuse(f"load.jsonl is a {s['mode']} run of {s['cutoff_in_s']} s, not the {DURATION} s T1 run")
    return s["ts"], s["ts"] + DURATION, ev.of("load")


def judge_completion(log: list[dict], t0: float, t1: float) -> dict:
    """A clean run has exactly: start, ramp_done, cutoff (no reasons) at the full duration, terminated with every
    process group gone, end with result cutoff. Any stop fails; anything else missing or contradictory is
    inconclusive."""
    kinds = [r["kind"] for r in log]
    stops = [r for r in log if r["kind"] in ("stop", "refused", "alarm")]
    if stops:
        return result(FAIL, stops=[s.get("reasons") or s.get("reason") for s in stops])
    cutoff = [r for r in log if r["kind"] == "cutoff"]
    term = [r for r in log if r["kind"] == "terminated"]
    end = [r for r in log if r["kind"] == "end"]
    problems = []
    if kinds.count("start") != 1 or kinds.count("ramp_done") != 1:
        problems.append("start and ramp_done must each appear once")
    if len(cutoff) != 1 or cutoff[0]["reasons"] != [] or cutoff[0]["ts"] < t1 - 60:
        problems.append("no single cutoff row at the full duration")
    if len(term) != 1 or sorted(term[0]["children"]) != sorted(CHILDREN) or any(
            c["group_alive"] is not False for c in term[0]["children"].values()):
        problems.append("termination of both children (ramp and reads) is not confirmed")
    if len(end) != 1 or end[0]["result"] != "cutoff" or kinds[-1] != "end":
        problems.append("the run has no clean end")
    # The lifecycle in order, with wall times that never go back: start, ramp_done, cutoff, terminated, end.
    order = [k for k in kinds if k in ("start", "ramp_done", "cutoff", "terminated", "end")]
    times = [r["ts"] for r in log if r["kind"] in ("start", "ramp_done", "cutoff", "terminated", "end")]
    if order != ["start", "ramp_done", "cutoff", "terminated", "end"] \
            or any(b < a for a, b in zip(times, times[1:])):
        problems.append("the lifecycle is out of order or its times go back")
    if problems:
        return result(INCONCLUSIVE, problems=problems)
    return result(PASS)


# ---------------------------------------------------------------- §5.1 no stall, handovers


def judge_stall(heads: list[dict], t0: float, t1: float, j: dict) -> dict:
    per_host = {h: [r["ts"] for r in heads if r["host"] == h] for h in HOSTS}
    worst_series = {h: max_gap(ts, t0, t1) for h, ts in per_host.items()}
    progress, top = [], -1
    for r in sorted(heads, key=lambda r: r["ts"]):
        if r["id"][2] > top:
            top = r["id"][2]
            progress.append(r["ts"])
    gap = max_gap(progress, t0, t1) if progress else t1 - t0
    if gap > j["max_chain_gap_s"]:
        return result(FAIL, max_chain_gap_s=gap, limit=j["max_chain_gap_s"])
    if any(g > j["head_series_gap_s"] for g in worst_series.values()):
        return result(INCONCLUSIVE, reason="a head series has gaps", series_gaps=worst_series)
    return result(PASS, max_chain_gap_s=gap, series_gaps=worst_series)


def judge_boundaries(ev: E.Evidence, t0: float, t1: float, j: dict) -> dict:
    expected = []
    b = j["first_boundary"]
    while b <= t1:
        if b >= t0:
            expected.append(b)
        b += j["period"]
    outcome = {}
    for r in ev.of("boundaries", "boundaries/checked", "boundaries/missed", "boundaries/interrupted",
                   "boundaries/schedule_mismatch"):
        outcome[r["boundary"]] = r
    bad, missing = [], []
    for b in expected:
        r = outcome.get(b)
        if r is None or r["outcome"] in ("missed", "interrupted"):
            missing.append(b)
        elif r["outcome"] != "checked":
            bad.append((b, r["outcome"]))
        elif not (r["collect_exit"] == 0 and r["verify_exit"] == 0 and r.get("keys_exit") == 0
                  and isinstance(r["handover_report"], dict) and r["handover_report"].get("result") == "PASS"
                  and isinstance(r["keys_verdict"], dict)
                  and r["keys_verdict"].get("verdict") == "PASS-FOUR-SIGNER-COVERAGE-PINNED-KEYS"):
            bad.append((b, "a check did not pass"))
    if bad:
        return result(FAIL, failed=bad, expected=len(expected))
    if missing or not expected:
        return result(INCONCLUSIVE, unchecked=missing, expected=len(expected))
    return result(PASS, checked=len(expected))


# ---------------------------------------------------------------- §5.2 no restart or OOM, no divergence


def resource_rows(ev: E.Evidence, t0: float, t1: float) -> dict[str, list[dict]]:
    """Each host's complete resource rows in the window (incomplete and failed probes only count as gaps)."""
    out = {h: [] for h in HOSTS}
    for r in inside(ev.of("resources", "resources/complete"), t0, t1):
        out[r["host"]].append(r)
    return out


def identity(r: dict) -> tuple:
    u = r["unit"]
    return (u["main_pid"], u["n_restarts"], r["boot_id"], r["oom_kill"])


def judge_restarts(res: dict, ev: E.Evidence, t0: float, t1: float, j: dict) -> dict:
    changed, incomplete = [], []
    for h, rs in res.items():
        if max_gap([r["ts"] for r in rs], t0, t1) > j["resource_series_gap_s"]:
            incomplete.append(h)
        ids = {identity(r) for r in rs}
        inactive = [r["ts"] for r in rs if r["unit"]["active_state"] != "active"]
        if len(ids) > 1 or inactive:
            changed.append({"host": h, "identities": sorted(map(str, ids)), "inactive_at": inactive[:5]})
    ids_rows = sorted(inside(ev.of("chain", "chain/ids"), t0, t1), key=lambda r: r["ts"])
    # Agreement is recomputed from the four complete ids, never taken from the stored flag.
    agreed, longest, since = [], 0.0, None
    for r in ids_rows:
        full = [tuple(r["ids"][h]) for h in HOSTS if h in r["ids"]]
        agree = len(full) == len(HOSTS) and len(set(full)) == 1
        if agree:
            agreed.append(r["ts"])
            since = None
        elif len(full) == len(HOSTS):  # four complete ids that differ
            since = r["ts"] if since is None else since
            longest = max(longest, r["ts"] - since)
    if changed or longest > j["divergence_s"]:
        return result(FAIL, changed=changed, longest_divergence_s=longest)
    if max_gap(agreed, t0, t1) > j["ids_series_gap_s"]:
        incomplete.append("agreed common-height ids")
    if incomplete:
        return result(INCONCLUSIVE, incomplete_series=incomplete)
    return result(PASS, longest_divergence_s=longest, agreed_ids=len(agreed))


# ---------------------------------------------------------------- §5.3 bounded memory


def judge_memory(res: dict, t0: float, t1: float, j: dict) -> dict:
    period, k, phases = j["period"], int(j["rolling_terms"]), int(j["phases_per_term"])
    phase_len = period / phases
    over, growth, floor_breach, incomplete = [], {}, [], []
    for h, complete in res.items():
        if not complete:
            incomplete.append(h)
            continue
        rss = [r["proc"]["RssAnon"] for r in complete]
        if max(rss) > j["rss_anon_max_bytes"]:
            over.append({"host": h, "max": max(rss)})
        avail = [r["mem"]["MemAvailable"] for r in complete]
        if min(avail) < j["mem_available_floor_bytes"]:
            floor_breach.append({"host": h, "min": min(avail)})
        # Comparable session position: the median RssAnon of each phase of each term, compared phase by phase
        # across terms. Every full term inside the window must have every phase observed.
        cells: dict[tuple[int, int], list[float]] = {}
        for r in complete:
            off = r["ts"] - j["first_boundary"]
            cells.setdefault((int(off // period), int((off % period) // phase_len)), []).append(r["proc"]["RssAnon"])
        first_term = math.ceil((t0 - j["first_boundary"]) / period)
        last_term = math.floor((t1 - j["first_boundary"]) / period) - 1
        terms = list(range(first_term, last_term + 1))
        need = 0.9 * phase_len / 60
        missing = [(t, p) for t in terms for p in range(phases) if len(cells.get((t, p), [])) < need]
        if len(terms) < 2 or missing:
            incomplete.append(f"{h}: {len(missing)} term phases unobserved" if missing else f"{h}: < 2 full terms")
            continue
        med = {key: statistics.median(v) for key, v in cells.items()}
        e2e = max(med[(terms[-1], p)] - med[(terms[0], p)] for p in range(phases))
        rolling = max(med[(terms[i + d], p)] - med[(terms[i], p)]
                      for p in range(phases) for i in range(len(terms)) for d in range(1, k)
                      if i + d < len(terms))
        growth[h] = {"e2e": e2e, "rolling": rolling, "terms": len(terms)}
        if e2e > j["rss_growth_e2e_bytes"] or rolling > j["rss_growth_rolling_bytes"]:
            over.append({"host": h, "growth": growth[h]})
    if over or floor_breach:
        return result(FAIL, over=over, mem_available=floor_breach, growth=growth)
    if incomplete:
        return result(INCONCLUSIVE, incomplete_series=incomplete, growth=growth)
    return result(PASS, growth=growth)


# ---------------------------------------------------------------- §5.4 bounded disk


def judge_disk(res: dict, heads: list[dict], j: dict) -> dict:
    if not heads:
        return result(INCONCLUSIVE, reason="no chain heads in the window")
    blocks = max(r["id"][2] for r in heads) - min(r["id"][2] for r in heads)
    bad, incomplete, per_block = [], [], {}
    for h, complete in res.items():
        if not complete:
            incomplete.append(h)
            continue
        for path in DATA_PATHS:
            series = [r["disks"][path] for r in complete]
            if min(d["free_bytes"] for d in series) < j["disk_free_floor_bytes"] or \
                    min(d["free_inodes"] for d in series) < j["disk_free_floor_inodes"]:
                bad.append(f"{h}:{path} below its floor")
            used = series[0]["free_bytes"] - series[-1]["free_bytes"]
            rate = used / blocks if blocks > 0 else 0.0
            per_block[f"{h}:{path}"] = rate
            if rate > j["disk_bytes_per_block_max"]:
                bad.append(f"{h}:{path} grows {rate:.0f} B/block")
    if bad:
        return result(FAIL, failures=bad, bytes_per_block=per_block)
    if incomplete:
        return result(INCONCLUSIVE, incomplete_series=incomplete)
    return result(PASS, bytes_per_block=per_block, blocks=blocks)


# ---------------------------------------------------------------- §5.5 safety, with positive coverage


def log_read_covers(files: dict) -> bool:
    """The observer's rule: the active log is among the files read this round, none more than LOG_LAG_BYTES
    behind."""
    read = [e for e in files.values() if e["status"] in LOG_READ_STATUSES]
    if not any(e["name"] == ACTIVE_LOG for e in read):
        return False
    return all(e.get("behind", 0) <= LOG_LAG_BYTES for e in read)


def judge_safety(ev: E.Evidence, t0: float, t1: float, j: dict) -> dict:
    hits = ev.of("safety")
    gaps = inside(ev.of("cache", "cache/coverage_gap"), t0, t1)
    if hits:
        return result(FAIL, safety_lines=len(hits), first=hits[0]["line"])
    # Coverage must be positive: every host's logs read (non-baseline) throughout the window, each read meeting the
    # observer's own rule.
    reads = {h: [r["ts"] for r in ev.of("cache", "cache/read") if r["host"] == h and r["baseline"] is False
                 and log_read_covers(r["files"])] for h in HOSTS}
    uncovered = [h for h, ts in reads.items() if max_gap(ts, t0, t1) > j["logs_series_gap_s"]]
    if gaps or uncovered:
        return result(INCONCLUSIVE, coverage_gaps=len(gaps), uncovered_hosts=uncovered)
    return result(PASS)


def judge_clock(ev: E.Evidence, t0: float, t1: float, j: dict) -> dict:
    clk = inside(ev.of("clock"), t0, t1)
    bad = [r for r in clk if r["verdict"] == "skewed"]
    ok = {h: [r["ts"] for r in clk if r["host"] == h and r["verdict"] == "ok"] for h in HOSTS}
    if bad:
        return result(INCONCLUSIVE, skewed=[(r["host"], r["ts"]) for r in bad][:10])
    if any(max_gap(ts, t0, t1) > j["clock_series_gap_s"] for ts in ok.values()):
        return result(INCONCLUSIVE, reason="a host lacks regular ok clock verdicts")
    return result(PASS)


# ---------------------------------------------------------------- §5.6 reads, recomputed


def judge_reads(ev: E.Evidence, j: dict) -> dict:
    ctx, res = ev.read_context, ev.read_result
    if ctx is None:
        return result(INCONCLUSIVE, reason="no valid CONTEXT.json: the read client never started")
    packet, started = ctx["packet"], ctx["started_monotonic_seconds"]
    width = j["read_window_s"]
    if (packet["duration_seconds"], packet["window_seconds"], packet["requests_per_second"]) != \
            (DURATION, width, READ_RATE):
        return result(INCONCLUSIVE, reason="the read client's packet does not match the frozen schedule",
                      packet={k: packet[k] for k in ("duration_seconds", "window_seconds", "requests_per_second")})
    if sorted(packet["endpoints"]) != sorted(T1_READ_ENDPOINTS):
        return result(INCONCLUSIVE, reason="the read packet's endpoints are not the pinned T1 inventory",
                      endpoints=packet["endpoints"])
    n = DURATION // int(width)
    scheduled = READ_RATE * width
    win = [{"ok": 0, "errors": 0, "endpoints": set(), "methods": set()} for _ in range(n)]
    foreign = 0
    for r in ev.of("reads", "reads/request"):
        if r["endpoint"] not in T1_READ_ENDPOINTS:
            foreign += 1
            continue
        i = int((r["offered_monotonic_seconds"] - started) // width)
        if not 0 <= i < n:
            continue
        w = win[i]
        w["endpoints"].add(r["endpoint"])
        w["methods"].add(r["method"])
        if r["error"] is not None:
            w["errors"] += 1
        elif r["latency_seconds"] <= j["read_deadline_s"]:
            w["ok"] += 1
    failed = []
    for i, w in enumerate(win):
        total = w["ok"] + w["errors"]
        if (w["ok"] < j["read_completed_fraction"] * scheduled
                or (total and w["errors"] / total > j["read_error_fraction_max"])
                or len(w["endpoints"]) < READ_ENDPOINTS or not set(READ_METHODS) <= w["methods"]):
            failed.append({"window": i, "ok": w["ok"], "errors": w["errors"], "endpoints": len(w["endpoints"]),
                           "methods": sorted(w["methods"])})
    if failed:
        return result(FAIL, failed_windows=failed[:20], windows=n, scheduled_per_window=scheduled)
    # The read client's own final result: complete, every window closed, no slot skipped for capacity.
    if res is None or res["not_offered_capacity"] or res["windows"] != n or foreign:
        return result(INCONCLUSIVE, reason="no complete read result, a slot not offered, or foreign-endpoint rows",
                      not_offered=None if res is None else res["not_offered_capacity"],
                      windows=None if res is None else res["windows"], foreign_endpoint_rows=foreign)
    return result(PASS, windows=n)


# ---------------------------------------------------------------- §5.7 writes, §5.8 spend and operators


def judge_writes(ev: E.Evidence, t0: float, t1: float, j: dict) -> dict:
    attempts = {r["id"]: r for r in ev.of("journal", "journal/attempt/transfer", "journal/attempt/funding")}
    observed = {r["id"]: r for r in ev.of("journal", "journal/observed/transfer", "journal/observed/funding")}
    delivered = {(r["id"], r["action"]): r for r in ev.of("journal", "journal/delivered")}
    transfers = {aid: a for aid, a in attempts.items() if a["role"] == "transfer"}
    if not transfers:
        return result(FAIL, reason="no transfer was ever signed", delivered=0)
    # The write windows come from the frozen schedule, never from the surviving signatures.
    w0, w1 = t0 + j["write_start_max_s"], t1 - j["write_end_slack_s"]
    signed = [a["signed_at"] for a in transfers.values()]
    good, by_hour, done_at, exec_at, bad_index = 0, {}, {}, {}, 0
    for aid, a in transfers.items():
        o = observed.get(aid)
        if o is not None and len(o["failure"]) == len(a["actions"]):
            for i in range(len(a["actions"])):
                exec_at[(aid, i)] = o["utime"]
    for (aid, i), d in delivered.items():
        a, o = transfers.get(aid), observed.get(aid)
        if a is None or o is None:
            continue
        n = len(a["actions"])
        if not 0 <= i < n or len(o["failure"]) != n:
            bad_index += 1
            continue
        # A delivery counts only with its sender's action sent, its receipt clean, and a time between the
        # sender's execution and the cutoff (the ramp drains before it), so a receipt from outside the run never
        # resolves an action.
        if d["receipt_failure"] is not None or o["failure"][i] is not None \
                or not o["utime"] <= d["recipient_utime"] <= t1:
            continue
        good += 1
        done_at[(aid, i)] = d["recipient_utime"]
        h = int((d["recipient_utime"] - w0) // 3600)
        by_hour[h] = by_hour.get(h, 0) + 1
    hours = int((w1 - w0) // 3600)
    floor = j["write_hourly_floor_fraction"] * DECLARED_RATE * 3600
    short = [(h, by_hour.get(h, 0)) for h in range(hours) if by_hour.get(h, 0) < floor]
    # Backlog: executed actions whose delivery has not happened yet, at every execution and delivery.
    events = sorted([(t, 1) for t in exec_at.values()] + [(done_at[k], -1) for k in done_at if k in exec_at])
    outstanding, peak = 0, 0
    for _, step in events:
        outstanding += step
        peak = max(peak, outstanding)
    total_actions = sum(len(a["actions"]) for a in transfers.values())
    unresolved = total_actions - good
    # Spend: every executed external's fee; one whose fee the node did not report leaves the cap unproven.
    fees = sum(o["fee"] for o in observed.values() if o["fee"] is not None)
    fee_unknown = sorted(aid for aid, o in observed.items() if o["fee"] is None)
    late_start = min(signed) > w0
    early_end = max(signed) < w1
    facts = dict(delivered=good, hours=hours, hourly_floor=floor, short_hours=short[:20], backlog_peak=peak,
                 unresolved_actions=unresolved, fees_nano=fees, fee_unknown=len(fee_unknown),
                 conflicting_receipts=len(ev.conflicts), bad_action_index=bad_index,
                 first_signed_late=late_start, last_signed_early=early_end)
    if short or late_start or early_end or peak > j["backlog_max_actions"] or fees > j["max_cost_nano"] \
            or unresolved or ev.conflicts:
        return result(FAIL, **facts)
    if fee_unknown or bad_index:
        return result(INCONCLUSIVE, first_fee_unknown=fee_unknown[:5], **facts)
    return result(PASS, **facts)


def judge_operators(ev: E.Evidence, t0: float, t1: float, j: dict) -> dict:
    """§5.8, as scoped by 13.493: every pinned operator's balance is observed throughout the run and never below the
    floor. Per-transaction fee accounting is the fee watch's job, not the judge's (13.493)."""
    readings = inside(ev.of("fees", "fees/reading"), t0, t1)
    low = sorted({r["operator"] for r in readings if r["balance_nano"] < j["operator_floor_nano"]})
    if low:
        return result(FAIL, below_floor=low)
    gaps = {o: max_gap([r["ts"] for r in readings if r["operator"] == o], t0, t1) for o in j["operators"]}
    thin = [o for o, g in gaps.items() if g > j["fees_series_gap_s"]]
    if thin:
        return result(INCONCLUSIVE, operators_without_readings=thin)
    return result(PASS, readings=len(readings))


# ---------------------------------------------------------------- the verdict


def verdict(rec: dict, obs: Path, load_dir: Path) -> dict:
    ev = E.load(obs, load_dir)
    t0, t1, log = window(ev)
    res = resource_rows(ev, t0, t1)
    heads = inside(ev.of("chain", "chain/head"), t0, t1)
    criteria = {
        "5.1 no stall": judge_stall(heads, t0, t1, rec),
        "5.1 handovers and key gate": judge_boundaries(ev, t0, t1, rec),
        "5.2 no restart, OOM or divergence": judge_restarts(res, ev, t0, t1, rec),
        "5.3 bounded memory": judge_memory(res, t0, t1, rec),
        "5.4 bounded disk": judge_disk(res, heads, rec),
        "5.5 no safety line": judge_safety(ev, t0, t1, rec),
        "5.6 reads": judge_reads(ev, rec),
        "5.7 writes": judge_writes(ev, t0, t1, rec),
        "5.8 operators": judge_operators(ev, t0, t1, rec),
        "collector clock": judge_clock(ev, t0, t1, rec),
        "run completed": judge_completion(log, t0, t1),
    }
    # The evidence contract: a criterion whose files violate it is at best INCONCLUSIVE (a FAIL stays a FAIL).
    for name, c in criteria.items():
        broken = ev.violations(*CRITERION_FILES[name])
        if broken:
            c["contract_violations"] = broken
            if c["status"] == PASS:
                c["status"] = INCONCLUSIVE
    statuses = {c["status"] for c in criteria.values()}
    overall = FAIL if FAIL in statuses else INCONCLUSIVE if INCONCLUSIVE in statuses else PASS
    return {"verdict": overall, "window": [t0, t1], "criteria": criteria}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--record", type=Path, required=True)
    ap.add_argument("--record-sha256", required=True)
    ap.add_argument("--observe", type=Path, required=True)
    ap.add_argument("--load", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    try:
        rec = load_record(a.record, a.record_sha256)
        v = verdict(rec, a.observe, a.load)
    except Refuse as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(v, indent=2, sort_keys=True, default=str)
    if a.out:
        a.out.write_text(text + "\n")
    print(text)
    return {PASS: 0, FAIL: 1, INCONCLUSIVE: 3}[v["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
