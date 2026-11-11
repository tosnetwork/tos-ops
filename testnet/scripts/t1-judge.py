#!/usr/bin/env python3
"""T1 judge (memo public-testnet/T1-PLAN-20261110 §5; T1-PRB-DESIGN-20261110 v3.1 §5).

  t1-judge.py --record RECORD.json --record-sha256 HEX --observe OBSERVE_DIR --load LOAD_DIR [--out VERDICT.json]

Reads only retained evidence: the observer's series (t1-observe.py, t1-boundaries.py) and the load supervisor's
directory (t1-load.py: load.jsonl, the ramp's journal.jsonl, the read client's WINDOW files). It recomputes every
§5 criterion from that evidence and the frozen acceptance record, and prints one verdict:

  PASS          every criterion passed on complete evidence
  FAIL          at least one criterion failed (a near miss is not reclassified)
  INCONCLUSIVE  no criterion failed, but at least one could not be established (missing or incomplete evidence)

Each criterion's result and the facts it rests on are in the verdict. Missing evidence is never inferred: an
action without a `delivered` record is not delivered, a series with a gap beyond its limit is incomplete.
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
READ_WINDOW_REQUESTS = 4800
PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
JUDGE_REQUIRED = {
    "max_chain_gap_s": "§5.1: no masterchain gap above this (60)",
    "head_series_gap_s": "a head series gap beyond this makes the stall check incomplete",
    "resource_series_gap_s": "a resource series gap beyond this makes §5.2–5.4 incomplete",
    "divergence_s": "§5.2: ids disagreeing longer than this is a persistent divergence",
    "rss_anon_max_bytes": "§5.3: absolute RssAnon bound",
    "rss_growth_e2e_bytes": "§5.3: end-to-end growth bound (first vs last complete term)",
    "rss_growth_rolling_bytes": "§5.3: rolling growth bound over rolling_terms consecutive terms",
    "rolling_terms": "§5.3: terms in a rolling window",
    "mem_available_floor_bytes": "§5.3: MemAvailable floor",
    "disk_free_floor_bytes": "§5.4: free space floor",
    "disk_free_floor_inodes": "§5.4: free inode floor",
    "disk_bytes_per_block_max": "§5.4: the frozen per-block bound",
    "write_hourly_floor_fraction": "§5.7: delivered per hour ≥ this × the declared rate × 3600",
    "backlog_max_actions": "§5.7: undelivered actions at any hour end",
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


# ---------------------------------------------------------------- the run window


def window(load_dir: Path) -> tuple[float, float, dict]:
    log = rows(load_dir / "load.jsonl")
    start = next((r for r in log if r.get("kind") == "start"), None)
    end = next((r for r in log if r.get("kind") == "end"), None)
    if start is None:
        raise Refuse("load.jsonl has no start row: the run never started")
    stops = [r for r in log if r.get("kind") == "stop"]
    return start["ts"], start["ts"] + DURATION, {"end": end, "stops": stops, "ramp_done": any(
        r.get("kind") == "ramp_done" for r in log)}


# ---------------------------------------------------------------- §5.1 no stall, handovers


def judge_stall(obs: Path, t0: float, t1: float, j: dict) -> dict:
    heads = [r for r in rows(obs / "chain.jsonl") if r.get("kind") == "head" and "id" in r and t0 <= r["ts"] <= t1]
    per_host = {h: [r["ts"] for r in heads if r["host"] == h] for h in HOSTS}
    worst_series = {h: max_gap(ts, t0, t1) for h, ts in per_host.items()}
    # The chain advances when the highest seqno seen on any host rises.
    progress, top = [], -1
    for r in sorted(heads, key=lambda r: r["ts"]):
        if r["id"][2] > top:
            top = r["id"][2]
            progress.append(r["ts"])
    gap = max_gap(progress, t0, t1) if progress else t1 - t0
    if gap > j["max_chain_gap_s"]:
        return result(FAIL, max_chain_gap_s=gap, limit=j["max_chain_gap_s"])
    blind = {h: g for h, g in worst_series.items() if g > j["head_series_gap_s"]}
    if len(blind) == len(HOSTS):
        return result(INCONCLUSIVE, reason="no head series was continuous", series_gaps=worst_series)
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
        if r.get("host") in out and t0 <= r.get("ts", -1) <= t1:
            out[r["host"]].append(r)
    return out


def judge_restarts(res: dict, obs: Path, t0: float, t1: float, j: dict) -> dict:
    changed, incomplete = [], []
    for h, rs in res.items():
        complete = [r for r in rs if r.get("complete") is True]
        if max_gap([r["ts"] for r in complete], t0, t1) > j["resource_series_gap_s"]:
            incomplete.append(h)
        ids = {(r["unit"]["main_pid"], r["unit"]["n_restarts"], r["boot_id"], r["oom_kill"]) for r in complete}
        inactive = [r["ts"] for r in complete if r["unit"].get("active_state") != "active"]
        if len(ids) > 1 or inactive:
            changed.append({"host": h, "identities": sorted(map(str, ids)), "inactive_at": inactive[:5]})
    # A persistent divergence: the common-height ids disagree for longer than the limit.
    ids_rows = sorted((r for r in rows(obs / "chain.jsonl") if r.get("kind") == "ids" and "agree" in r
                       and t0 <= r["ts"] <= t1), key=lambda r: r["ts"])
    longest, since = 0.0, None
    for r in ids_rows:
        if r["agree"] is False:
            since = r["ts"] if since is None else since
            longest = max(longest, r["ts"] - since)
        else:
            since = None
    if changed or longest > j["divergence_s"]:
        return result(FAIL, changed=changed, longest_divergence_s=longest)
    if incomplete:
        return result(INCONCLUSIVE, incomplete_series=incomplete)
    return result(PASS, longest_divergence_s=longest)


# ---------------------------------------------------------------- §5.3 bounded memory


def judge_memory(res: dict, t0: float, t1: float, j: dict) -> dict:
    period, k = j["period"], int(j["rolling_terms"])
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
        avail = [r["mem"]["MemAvailable"] for r in complete if finite(r["mem"].get("MemAvailable"))]
        if not avail or min(avail) < j["mem_available_floor_bytes"]:
            floor_breach.append({"host": h, "min": min(avail) if avail else None})
        # Comparable session position: the median RssAnon of each complete term (same position in every term).
        terms: dict[int, list[float]] = {}
        for r in complete:
            terms.setdefault(int((r["ts"] - j["first_boundary"]) // period), []).append(r["proc"]["RssAnon"])
        full = [statistics.median(v) for _, v in sorted(terms.items()) if len(v) >= 0.9 * period / 60]
        if len(full) < 2:
            incomplete.append(h)
            continue
        e2e = full[-1] - full[0]
        rolling = max((max(full[i:i + k]) - full[i] for i in range(0, max(1, len(full) - k + 1))), default=0)
        growth[h] = {"e2e": e2e, "rolling": rolling, "terms": len(full)}
        if e2e > j["rss_growth_e2e_bytes"] or rolling > j["rss_growth_rolling_bytes"]:
            over.append({"host": h, "growth": growth[h]})
    if over or floor_breach:
        return result(FAIL, over=over, mem_available=floor_breach, growth=growth)
    if incomplete:
        return result(INCONCLUSIVE, incomplete_series=incomplete, growth=growth)
    return result(PASS, growth=growth)


# ---------------------------------------------------------------- §5.4 bounded disk


def judge_disk(res: dict, obs: Path, t0: float, t1: float, j: dict) -> dict:
    heads = [r for r in rows(obs / "chain.jsonl") if r.get("kind") == "head" and "id" in r and t0 <= r["ts"] <= t1]
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
            if any(not isinstance(d, dict) for d in series):
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


# ---------------------------------------------------------------- §5.5 safety


def judge_safety(obs: Path, t0: float, t1: float) -> dict:
    hits = [r for r in rows(obs / "safety.jsonl") if r.get("kind") == "safety_line"]
    gaps = [r for r in rows(obs / "cache.jsonl") if r.get("kind") == "coverage_gap" and t0 <= r.get("ts", -1) <= t1]
    if hits:
        return result(FAIL, safety_lines=len(hits), first=hits[0].get("line"))
    if gaps:
        return result(INCONCLUSIVE, coverage_gaps=len(gaps))
    return result(PASS)


# ---------------------------------------------------------------- §5.6 reads


def judge_reads(load_dir: Path) -> dict:
    reads = load_dir / "reads"
    ctx = reads / "CONTEXT.json"
    if not ctx.exists():
        return result(INCONCLUSIVE, reason="the read client never started")
    packet = json.loads(ctx.read_text())["packet"]
    expect = math.ceil(packet["duration_seconds"] / packet["window_seconds"])
    windows = {}
    for p in sorted(reads.glob("WINDOW-*.json")):
        w = json.loads(p.read_text())
        windows[w["index"]] = w
    failed = [i for i, w in windows.items() if w.get("pass") is not True]
    if failed:
        return result(FAIL, failed_windows=failed[:20], windows=len(windows), expected=expect)
    latest = reads / "LATEST.json"
    lag = json.loads(latest.read_text()).get("not_offered_capacity") if latest.exists() else None
    if len(windows) < expect:
        return result(INCONCLUSIVE, windows=len(windows), expected=expect)
    if lag:
        return result(INCONCLUSIVE, reason="scheduled requests not offered (scheduling lag)", not_offered=lag)
    return result(PASS, windows=len(windows))


# ---------------------------------------------------------------- §5.7 writes, §5.8 spend


def journal(load_dir: Path) -> tuple[dict, dict, dict]:
    attempts, observed, delivered = {}, {}, {}
    for r in rows(load_dir / "ramp" / "journal.jsonl"):
        t, aid = r.get("type"), r.get("id")
        if t == "attempt":
            attempts[aid] = r
        elif t == "observed":
            observed[aid] = r
        elif t == "delivered":
            delivered[(aid, r.get("action"))] = r
    return attempts, observed, delivered


def judge_writes(load_dir: Path, t0: float, t1: float, j: dict) -> dict:
    attempts, observed, delivered = journal(load_dir)
    # Only the load transfers count (bench/t4/ramp.py journals them with role "transfer"); funding does not.
    transfers = {aid: a for aid, a in attempts.items() if a.get("role") == "transfer"}
    first = min((a.get("signed_at", t1) for a in transfers.values()), default=None)
    if first is None:
        return result(FAIL, reason="no transfer was ever signed", delivered=0)
    ok_by_hour: dict[int, int] = {}
    good = 0
    for (aid, i), d in delivered.items():
        a = transfers.get(aid)
        if a is None or d.get("receipt_failure") is not None or not finite(d.get("recipient_utime")):
            continue
        o = observed.get(aid)
        fail = o.get("failure") if o else "not observed"
        per = fail if isinstance(fail, list) else [fail] * len(a.get("actions") or [])
        if i >= len(per) or per[i] is not None:
            continue
        hour = int((d["recipient_utime"] - first) // 3600)
        ok_by_hour[hour] = ok_by_hour.get(hour, 0) + 1
        good += 1
    # The declared signing window runs from the first to the last signed transfer: the ramp ends signing before
    # the cutoff (its preparation, final drain and margin), so the hours after it are not write hours. A run that
    # stopped early fails "run completed" instead.
    last = max(a.get("signed_at", first) for a in transfers.values())
    hours = int((last - first) // 3600)
    floor = j["write_hourly_floor_fraction"] * DECLARED_RATE * 3600
    short = [(h, ok_by_hour.get(h, 0)) for h in range(hours) if ok_by_hour.get(h, 0) < floor]
    undelivered = sum(len(a.get("actions") or []) for a in transfers.values()) - good
    fees = sum(o.get("fee") or 0 for o in observed.values() if finite(o.get("fee")))
    facts = dict(delivered=good, hours=hours, hourly_floor=floor, short_hours=short[:20],
                 unresolved_actions=undelivered, fees_nano=fees)
    # Zero delivered with any transfer signed is already a FAIL below (all of them unresolved), and no transfer at
    # all is the FAIL above, so no separate "nothing delivered" rule is needed here.
    if short or fees > j["max_cost_nano"]:
        return result(FAIL, **facts)
    if undelivered:
        return result(FAIL, **facts, reason="unresolved transfers after the drain")
    return result(PASS, **facts)


def judge_operators(obs: Path, t0: float, t1: float, j: dict) -> dict:
    fees = [r for r in rows(obs / "fees.jsonl") if t0 <= r.get("ts", -1) <= t1]
    readings = [r for r in fees if finite(r.get("balance_nano"))]
    if not readings:
        return result(INCONCLUSIVE, reason="no operator balance readings")
    low = sorted({r["operator"] for r in readings if r["balance_nano"] < j["operator_floor_nano"]})
    if low:
        return result(FAIL, below_floor=low)
    return result(PASS, readings=len(readings))


# ---------------------------------------------------------------- the verdict


def verdict(rec: dict, obs: Path, load_dir: Path) -> dict:
    t0, t1, run = window(load_dir)
    res = resource_rows(obs, t0, t1)
    criteria = {
        "5.1 no stall": judge_stall(obs, t0, t1, rec),
        "5.1 handovers and key gate": judge_boundaries(obs, t0, t1, rec),
        "5.2 no restart, OOM or divergence": judge_restarts(res, obs, t0, t1, rec),
        "5.3 bounded memory": judge_memory(res, t0, t1, rec),
        "5.4 bounded disk": judge_disk(res, obs, t0, t1, rec),
        "5.5 no safety line": judge_safety(obs, t0, t1),
        "5.6 reads": judge_reads(load_dir),
        "5.7 writes": judge_writes(load_dir, t0, t1, rec),
        "5.8 operators": judge_operators(obs, t0, t1, rec),
    }
    if run["stops"]:
        criteria["run completed"] = result(FAIL, stops=[s.get("reasons") for s in run["stops"]])
    elif run["end"] is None or not run["ramp_done"]:
        criteria["run completed"] = result(INCONCLUSIVE, reason="the run has no clean end")
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
