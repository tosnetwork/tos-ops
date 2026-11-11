#!/usr/bin/env python3
"""T1 judge (memo public-testnet/T1-PLAN-20261110 §5; T1-PRB-DESIGN-20261110 v3.1 §5).

  t1-judge.py --record RECORD.json --record-sha256 HEX --observe OBSERVE_DIR --load LOAD_DIR [--out VERDICT.json]

Reads only retained evidence: the observer's series (t1-observe.py, t1-boundaries.py) and the load supervisor's
directory (t1-load.py: load.jsonl, the ramp's journal.jsonl, the read client's requests.jsonl). It recomputes every
§5 criterion from that evidence and the frozen acceptance record, and prints one verdict:

  PASS          every criterion passed on complete evidence
  FAIL          at least one criterion failed (a near miss is not reclassified)
  INCONCLUSIVE  no criterion failed, but at least one could not be established (missing or incomplete evidence)

The schedule, the windows and every threshold come from the record, never from the evidence being judged.
Absence of a recorded violation is never a pass: each series must be positively present and continuous. An
action without a valid `delivered` record is not delivered. Stored verdicts (a read window's `pass` flag) are
ignored and recomputed from the underlying measurements.
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

HOSTS = ("node-1", "node-2", "node-3", "node-4")
DATA_PATHS = ("/var/lib/tos/validator", "/var/log/tos")
DURATION = 259_200
DECLARED_RATE = 2  # transfers/s (T1-PLAN §3.2)
READ_RATE = 8  # scheduled read requests/s (T1-PLAN §3.1)
READ_ENDPOINTS = 4
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


# ---------------------------------------------------------------- the run lifecycle


def window(load_dir: Path) -> tuple[float, float, list[dict]]:
    log = rows(load_dir / "load.jsonl")
    start = next((r for r in log if r.get("kind") == "start"), None)
    if start is None or not finite(start.get("ts")):
        raise Refuse("load.jsonl has no start row: the run never started")
    return start["ts"], start["ts"] + DURATION, log


def judge_completion(log: list[dict], t0: float, t1: float) -> dict:
    """A clean run has exactly: start, ramp_done, cutoff (no reasons) at the full duration, terminated with every
    process group gone, end with result cutoff. Any stop fails; anything else missing or contradictory is
    inconclusive."""
    kinds = [r.get("kind") for r in log]
    stops = [r for r in log if r.get("kind") in ("stop", "refused", "alarm")]
    if stops:
        return result(FAIL, stops=[s.get("reasons") or s.get("reason") for s in stops])
    cutoff = [r for r in log if r.get("kind") == "cutoff"]
    term = [r for r in log if r.get("kind") == "terminated"]
    end = [r for r in log if r.get("kind") == "end"]
    problems = []
    if kinds.count("start") != 1 or kinds.count("ramp_done") != 1:
        problems.append("start and ramp_done must each appear once")
    if len(cutoff) != 1 or cutoff[0].get("reasons") not in ([], None) or not finite(cutoff[0].get("ts")) \
            or cutoff[0]["ts"] < t1 - 60:
        problems.append("no single cutoff row at the full duration")
    if len(term) != 1 or not isinstance(term[0].get("children"), dict) or not term[0]["children"] or any(
            c.get("group_alive") is not False for c in term[0]["children"].values()):
        problems.append("termination of every child is not confirmed")
    if len(end) != 1 or end[0].get("result") != "cutoff" or kinds[-1] != "end":
        problems.append("the run has no clean end")
    if problems:
        return result(INCONCLUSIVE, problems=problems)
    return result(PASS)


# ---------------------------------------------------------------- §5.1 no stall, handovers


def heads_in(obs: Path, t0: float, t1: float) -> list[dict]:
    return [r for r in rows(obs / "chain.jsonl") if r.get("kind") == "head" and isinstance(r.get("id"), list)
            and len(r["id"]) == 5 and type(r["id"][2]) is int and finite(r.get("ts")) and t0 <= r["ts"] <= t1]


def judge_stall(heads: list[dict], t0: float, t1: float, j: dict) -> dict:
    per_host = {h: [r["ts"] for r in heads if r.get("host") == h] for h in HOSTS}
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


def judge_boundaries(obs: Path, t0: float, t1: float, j: dict) -> dict:
    expected = []
    b = j["first_boundary"]
    while b <= t1:
        if b >= t0:
            expected.append(b)
        b += j["period"]
    outcome = {}
    for r in rows(obs / "boundaries.jsonl"):
        if "outcome" in r:
            outcome[r["boundary"]] = r
    bad, missing = [], []
    for b in expected:
        r = outcome.get(b)
        if r is None or r["outcome"] in ("missed", "interrupted"):
            missing.append(b)
        elif r["outcome"] != "checked":
            bad.append((b, r["outcome"]))
        elif not (r.get("collect_exit") == 0 and r.get("verify_exit") == 0 and r.get("keys_exit") == 0
                  and isinstance(r.get("handover_report"), dict) and r["handover_report"].get("result") == "PASS"
                  and isinstance(r.get("keys_verdict"), dict)
                  and r["keys_verdict"].get("verdict") == "PASS-FOUR-SIGNER-COVERAGE-PINNED-KEYS"):
            bad.append((b, "a check did not pass"))
    if bad:
        return result(FAIL, failed=bad, expected=len(expected))
    if missing or not expected:
        return result(INCONCLUSIVE, unchecked=missing, expected=len(expected))
    return result(PASS, checked=len(expected))


# ---------------------------------------------------------------- §5.2 no restart or OOM, no divergence


def resource_rows(obs: Path, t0: float, t1: float) -> dict[str, list[dict]]:
    out = {h: [] for h in HOSTS}
    for r in rows(obs / "resources.jsonl"):
        if r.get("host") in out and finite(r.get("ts")) and t0 <= r["ts"] <= t1:
            out[r["host"]].append(r)
    return out


def identity(r: dict):
    u = r.get("unit") if isinstance(r.get("unit"), dict) else {}
    ident = (u.get("main_pid"), u.get("n_restarts"), r.get("boot_id"), r.get("oom_kill"))
    ok = (type(ident[0]) is int and ident[0] > 0 and type(ident[1]) is int and ident[1] >= 0
          and isinstance(ident[2], str) and ident[2] and type(ident[3]) is int and ident[3] >= 0)
    return ident if ok else None


def judge_restarts(res: dict, obs: Path, t0: float, t1: float, j: dict) -> dict:
    changed, incomplete = [], []
    for h, rs in res.items():
        complete = [r for r in rs if r.get("complete") is True]
        if max_gap([r["ts"] for r in complete], t0, t1) > j["resource_series_gap_s"]:
            incomplete.append(h)
        idents = [identity(r) for r in complete]
        if any(i is None for i in idents):
            incomplete.append(f"{h}: unreadable identity")
        ids = {i for i in idents if i is not None}
        inactive = [r["ts"] for r in complete if (r.get("unit") or {}).get("active_state") != "active"]
        if len(ids) > 1 or inactive:
            changed.append({"host": h, "identities": sorted(map(str, ids)), "inactive_at": inactive[:5]})
    ids_rows = sorted((r for r in rows(obs / "chain.jsonl") if r.get("kind") == "ids" and finite(r.get("ts"))
                       and t0 <= r["ts"] <= t1 and "error" not in r), key=lambda r: r["ts"])
    # Agreement is recomputed from the four complete ids, never taken from the stored flag.
    agreed, longest, since = [], 0.0, None
    for r in ids_rows:
        got = r.get("ids") if isinstance(r.get("ids"), dict) else {}
        full = [tuple(got[h]) for h in HOSTS if isinstance(got.get(h), list) and len(got[h]) == 5]
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
    for h, rs in res.items():
        complete = [r for r in rs if r.get("complete") is True and isinstance(r.get("proc"), dict)
                    and finite(r["proc"].get("RssAnon"))]
        if not complete:
            incomplete.append(h)
            continue
        rss = [r["proc"]["RssAnon"] for r in complete]
        if max(rss) > j["rss_anon_max_bytes"]:
            over.append({"host": h, "max": max(rss)})
        avail = [r["mem"]["MemAvailable"] for r in complete
                 if isinstance(r.get("mem"), dict) and finite(r["mem"].get("MemAvailable"))]
        if len(avail) != len(complete) or min(avail, default=0) < j["mem_available_floor_bytes"]:
            floor_breach.append({"host": h, "min": min(avail, default=None)})
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
    for h, rs in res.items():
        complete = [r for r in rs if r.get("complete") is True and isinstance(r.get("disks"), dict)]
        if not complete:
            incomplete.append(h)
            continue
        for path in DATA_PATHS:
            series = [r["disks"].get(path) for r in complete]
            if any(not (isinstance(d, dict) and finite(d.get("free_bytes")) and finite(d.get("free_inodes")))
                   for d in series):
                incomplete.append(f"{h}:{path}")
                continue
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


def judge_safety(obs: Path, t0: float, t1: float, j: dict) -> dict:
    hits = [r for r in rows(obs / "safety.jsonl") if r.get("kind") == "safety_line"]
    cache = rows(obs / "cache.jsonl")
    gaps = [r for r in cache if r.get("kind") == "coverage_gap" and finite(r.get("ts")) and t0 <= r["ts"] <= t1]
    if hits:
        return result(FAIL, safety_lines=len(hits), first=hits[0].get("line"))
    # Coverage must be positive: every host's logs read (non-baseline) throughout the window.
    reads = {h: [r["ts"] for r in cache if r.get("kind") == "read" and r.get("host") == h and r.get("baseline") is False
                 and finite(r.get("ts"))] for h in HOSTS}
    uncovered = [h for h, ts in reads.items() if max_gap(ts, t0, t1) > j["logs_series_gap_s"]]
    if gaps or uncovered:
        return result(INCONCLUSIVE, coverage_gaps=len(gaps), uncovered_hosts=uncovered)
    return result(PASS)


def judge_clock(obs: Path, t0: float, t1: float, j: dict) -> dict:
    clk = [r for r in rows(obs / "clock.jsonl") if finite(r.get("ts")) and t0 <= r["ts"] <= t1]
    bad = [r for r in clk if r.get("verdict") == "skewed"]
    ok = {h: [r["ts"] for r in clk if r.get("host") == h and r.get("verdict") == "ok"] for h in HOSTS}
    if bad:
        return result(INCONCLUSIVE, skewed=[(r.get("host"), r.get("ts")) for r in bad][:10])
    if any(max_gap(ts, t0, t1) > j["clock_series_gap_s"] for ts in ok.values()):
        return result(INCONCLUSIVE, reason="a host lacks regular ok clock verdicts")
    return result(PASS)


# ---------------------------------------------------------------- §5.6 reads, recomputed


def judge_reads(load_dir: Path, j: dict) -> dict:
    reads = load_dir / "reads"
    ctx_path = reads / "CONTEXT.json"
    if not ctx_path.exists():
        return result(INCONCLUSIVE, reason="the read client never started")
    ctx = json.loads(ctx_path.read_text())
    packet, started = ctx.get("packet", {}), ctx.get("started_monotonic_seconds")
    width = j["read_window_s"]
    if (packet.get("duration_seconds"), packet.get("window_seconds"), packet.get("requests_per_second")) != \
            (DURATION, width, READ_RATE) or not finite(started):
        return result(INCONCLUSIVE, reason="the read client's packet does not match the frozen schedule",
                      packet={k: packet.get(k) for k in ("duration_seconds", "window_seconds", "requests_per_second")})
    n = DURATION // int(width)
    scheduled = READ_RATE * width
    win = [{"ok": 0, "errors": 0, "lat": [], "endpoints": set(), "methods": set()} for _ in range(n)]
    bad_rows = 0
    path = reads / "requests.jsonl"
    if not path.exists():
        return result(INCONCLUSIVE, reason="no request records")
    with path.open() as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                bad_rows += 1
                continue
            off = r.get("offered_monotonic_seconds")
            if not (finite(off) and finite(r.get("latency_seconds"))):
                bad_rows += 1
                continue
            i = int((off - started) // width)
            if not 0 <= i < n:
                continue
            w = win[i]
            w["endpoints"].add(r.get("endpoint"))
            w["methods"].add(r.get("method"))
            if r.get("error") is not None:
                w["errors"] += 1
            elif r["latency_seconds"] <= j["read_deadline_s"]:
                w["ok"] += 1
                w["lat"].append(r["latency_seconds"])
    failed = []
    for i, w in enumerate(win):
        total = w["ok"] + w["errors"]
        if (w["ok"] < j["read_completed_fraction"] * scheduled
                or (total and w["errors"] / total > j["read_error_fraction_max"])
                or len(w["endpoints"]) < READ_ENDPOINTS or not set(READ_METHODS) <= w["methods"]):
            failed.append({"window": i, "ok": w["ok"], "errors": w["errors"], "endpoints": len(w["endpoints"]),
                           "methods": sorted(m for m in w["methods"] if isinstance(m, str))})
    if failed:
        return result(FAIL, failed_windows=failed[:20], windows=n, scheduled_per_window=scheduled)
    latest = reads / "LATEST.json"
    lag = json.loads(latest.read_text()).get("not_offered_capacity") if latest.exists() else None
    if lag is None or lag or bad_rows:
        return result(INCONCLUSIVE, reason="scheduling lag, unreadable rows or no final read status",
                      not_offered=lag, bad_rows=bad_rows)
    return result(PASS, windows=n)


# ---------------------------------------------------------------- §5.7 writes, §5.8 spend and operators


def journal(load_dir: Path):
    attempts, observed, delivered, conflicts = {}, {}, {}, 0
    for r in rows(load_dir / "ramp" / "journal.jsonl"):
        t, aid = r.get("type"), r.get("id")
        if t == "attempt":
            attempts[aid] = r
        elif t == "observed":
            observed[aid] = r
        elif t == "delivered":
            key = (aid, r.get("action"))
            if key in delivered and delivered[key] != r:
                conflicts += 1
            delivered[key] = r
    return attempts, observed, delivered, conflicts


def valid_delivery(d: dict, a: dict, o) -> bool:
    """A delivery counts only with every producer field valid: an action index of its own attempt, the sender's
    action sent, a recipient transaction, a finite recipient time, and receipt_failure present and None."""
    n = len(a.get("actions") or [])
    i = d.get("action")
    if type(i) is not int or not 0 <= i < n:
        return False
    if "receipt_failure" not in d or d["receipt_failure"] is not None:
        return False
    if not (isinstance(d.get("recipient_tx"), str) and d["recipient_tx"]) or not finite(d.get("recipient_utime")):
        return False
    if not isinstance(o, dict):
        return False
    fail = o.get("failure")
    per = fail if isinstance(fail, list) else [fail] * n
    return i < len(per) and per[i] is None


def judge_writes(load_dir: Path, t0: float, t1: float, j: dict) -> dict:
    attempts, observed, delivered, conflicts = journal(load_dir)
    transfers = {aid: a for aid, a in attempts.items() if a.get("role") == "transfer"}
    if not transfers:
        return result(FAIL, reason="no transfer was ever signed", delivered=0)
    # The write windows come from the frozen schedule, never from the surviving signatures.
    w0, w1 = t0 + j["write_start_max_s"], t1 - j["write_end_slack_s"]
    signed = [a.get("signed_at") for a in transfers.values() if finite(a.get("signed_at"))]
    good, by_hour, done_at, exec_at = 0, {}, {}, {}
    for aid, a in transfers.items():
        o = observed.get(aid)
        if isinstance(o, dict) and finite(o.get("utime")):
            for i in range(len(a.get("actions") or [])):
                exec_at[(aid, i)] = o["utime"]
    for (aid, i), d in delivered.items():
        a = transfers.get(aid)
        if a is None or not valid_delivery(d, a, observed.get(aid)):
            continue
        good += 1
        done_at[(aid, i)] = d["recipient_utime"]
        h = int((d["recipient_utime"] - w0) // 3600)
        by_hour[h] = by_hour.get(h, 0) + 1
    hours = int((w1 - w0) // 3600)
    floor = j["write_hourly_floor_fraction"] * DECLARED_RATE * 3600
    short = [(h, by_hour.get(h, 0)) for h in range(hours) if by_hour.get(h, 0) < floor]
    # Backlog: executed actions whose delivery has not happened yet, at every hour end and at every execution.
    events = sorted([(t, 1) for t in exec_at.values()] + [(done_at[k], -1) for k in done_at if k in exec_at])
    outstanding, peak = 0, 0
    for _, step in events:
        outstanding += step
        peak = max(peak, outstanding)
    total_actions = sum(len(a.get("actions") or []) for a in transfers.values())
    unresolved = total_actions - good
    fees = sum(o.get("fee") for o in observed.values() if finite(o.get("fee")))
    late_start = min(signed, default=t1) > w0
    early_end = max(signed, default=t0) < w1
    facts = dict(delivered=good, hours=hours, hourly_floor=floor, short_hours=short[:20], backlog_peak=peak,
                 unresolved_actions=unresolved, fees_nano=fees, conflicting_receipts=conflicts,
                 first_signed_late=late_start, last_signed_early=early_end)
    if short or late_start or early_end or peak > j["backlog_max_actions"] or fees > j["max_cost_nano"] \
            or unresolved or conflicts:
        return result(FAIL, **facts)
    return result(PASS, **facts)


def judge_operators(obs: Path, t0: float, t1: float, j: dict) -> dict:
    """§5.8, as scoped by 13.493: every pinned operator's balance is observed throughout the run and never below the
    floor. Per-transaction fee accounting is the fee watch's job, not the judge's (13.493)."""
    readings = [r for r in rows(obs / "fees.jsonl") if finite(r.get("balance_nano")) and finite(r.get("ts"))
                and t0 <= r["ts"] <= t1]
    low = sorted({r.get("operator") for r in readings if r["balance_nano"] < j["operator_floor_nano"]})
    if low:
        return result(FAIL, below_floor=low)
    gaps = {o: max_gap([r["ts"] for r in readings if r.get("operator") == o], t0, t1) for o in j["operators"]}
    thin = [o for o, g in gaps.items() if g > j["fees_series_gap_s"]]
    if thin:
        return result(INCONCLUSIVE, operators_without_readings=thin)
    return result(PASS, readings=len(readings))


# ---------------------------------------------------------------- the verdict


def verdict(rec: dict, obs: Path, load_dir: Path) -> dict:
    t0, t1, log = window(load_dir)
    res = resource_rows(obs, t0, t1)
    heads = heads_in(obs, t0, t1)
    criteria = {
        "5.1 no stall": judge_stall(heads, t0, t1, rec),
        "5.1 handovers and key gate": judge_boundaries(obs, t0, t1, rec),
        "5.2 no restart, OOM or divergence": judge_restarts(res, obs, t0, t1, rec),
        "5.3 bounded memory": judge_memory(res, t0, t1, rec),
        "5.4 bounded disk": judge_disk(res, heads, rec),
        "5.5 no safety line": judge_safety(obs, t0, t1, rec),
        "5.6 reads": judge_reads(load_dir, rec),
        "5.7 writes": judge_writes(load_dir, t0, t1, rec),
        "5.8 operators": judge_operators(obs, t0, t1, rec),
        "collector clock": judge_clock(obs, t0, t1, rec),
        "run completed": judge_completion(log, t0, t1),
    }
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
