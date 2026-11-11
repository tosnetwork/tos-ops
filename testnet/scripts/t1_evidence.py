"""The T1 evidence contract: one schema per record type the judge consumes, taken from its producer.

The judge (t1-judge.py) reads evidence only through `load()`. Every row of every file is classified by its
discriminator and checked against its schema before any criterion sees it. A row that is not valid JSON, has a
duplicate member name, has an unknown type, kind or role, refers to a record that does not exist, or misses a field
or carries a field of the wrong type is a *contract violation*. Violations are never dropped silently: they are
listed per file, and every criterion that depends on that file can at best be INCONCLUSIVE. Fields the producer
writes but the schema does not list are ignored; they never stand in for a required field.

Producers, pinned (the samples in tests/data/t1-evidence/ are frozen from a live run of exactly these):
  observer      tos-ops testnet/scripts/t1-observe.py, t1_probe.py, t1-boundaries.py
  supervisor    tos-ops testnet/scripts/t1-load.py
  reads         tos-ops testnet/scripts/sustained_read_load.py, read_client.py
  writes        tos bench/t4/ramp.py, bench/shard/journal.py, bench/shard/remote.py at 4fb9ee703
A change to any producer pin needs the samples re-captured and this table re-checked against them.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Callable

HOSTS = ("node-1", "node-2", "node-3", "node-4")
DATA_PATHS = ("/var/lib/tos/validator", "/var/log/tos")
Check = Callable[[Any], bool]


# ---------------------------------------------------------------- field checks


def INT(v) -> bool:
    return type(v) is int


def NAT(v) -> bool:
    return type(v) is int and v >= 0


def NUM(v) -> bool:
    return type(v) in (int, float) and math.isfinite(v)


def STR(v) -> bool:
    return isinstance(v, str)


def TEXT(v) -> bool:
    return isinstance(v, str) and v != ""


def BOOL(v) -> bool:
    return type(v) is bool


def HOST(v) -> bool:
    return v in HOSTS


def null_or(check: Check) -> Check:
    return lambda v: v is None or check(v)


def one_of(*values) -> Check:
    return lambda v: isinstance(v, (str, int)) and not isinstance(v, bool) and v in values


def list_of(check: Check, length: int | None = None) -> Check:
    return lambda v: isinstance(v, list) and (length is None or len(v) == length) and all(check(x) for x in v)


def dict_of(check: Check) -> Check:
    return lambda v: isinstance(v, dict) and all(isinstance(k, str) and check(x) for k, x in v.items())


def shape(spec: dict[str, Check]) -> Check:
    """A dict with every field of `spec` present and valid (extra fields allowed)."""
    return lambda v: isinstance(v, dict) and all(k in v and c(v[k]) for k, c in spec.items())


def either(*checks: Check) -> Check:
    return lambda v: any(c(v) for c in checks)


def exit_code(v) -> bool:
    return type(v) is int or v == "timeout"


# ---------------------------------------------------------------- the schemas

OBS_BASE = {"ts": NUM, "host": HOST, "sent": NUM, "received": NUM}
LOG_FILE_READ = shape({"name": STR, "size": NAT, "start": NAT, "offset": NAT, "status": STR, "behind": NAT, "fp": STR})
LOG_FILE_BASELINE = shape({"name": STR, "size": NAT, "start": NAT, "offset": NAT, "status": one_of("baseline"),
                           "fp": STR})
LOG_FILE_DUP = shape({"name": STR, "id": STR, "status": one_of("duplicate")})
LOG_FILE_ERROR = shape({"name": STR, "status": lambda s: isinstance(s, str) and s.startswith("error")})
READ_STATUSES = ("read", "new", "shrunk", "rewritten", "over_cap")


def log_file(e) -> bool:
    if not isinstance(e, dict):
        return False
    s = e.get("status")
    if s == "baseline":
        return LOG_FILE_BASELINE(e)
    if s in READ_STATUSES:
        return LOG_FILE_READ(e)
    if s == "duplicate":
        return LOG_FILE_DUP(e)
    return LOG_FILE_ERROR(e)


HEAD_ID = lambda v: (isinstance(v, list) and len(v) == 5 and INT(v[0]) and NAT(v[2])  # noqa: E731
                     and TEXT(v[3]) and TEXT(v[4]))
DISK = shape({"free_bytes": NAT, "size_bytes": NAT, "free_inodes": NAT, "total_inodes": NAT})

SCHEMAS: dict[str, dict[str, Check]] = {
    # t1-observe.py resources: a probe that failed (:364), an incomplete report and a complete one (:374-376).
    "resources/error": {**OBS_BASE, "error": STR},
    "resources/incomplete": {**OBS_BASE, "complete": lambda v: v is False, "missing": list_of(STR)},
    "resources/complete": {
        **OBS_BASE, "complete": lambda v: v is True, "missing": list_of(STR), "sample_clock": NUM,
        "unit": shape({"main_pid": INT, "n_restarts": NAT, "active_state": STR}),
        "proc": shape({"RssAnon": NAT}), "mem": shape({"MemAvailable": NAT}), "oom_kill": NAT, "boot_id": TEXT,
        "disks": shape({p: DISK for p in DATA_PATHS}),
    },
    # cache.jsonl (:368, :389, :403-406)
    "cache/error": {**OBS_BASE, "kind": one_of("error"), "error": STR},
    "cache/read": {**OBS_BASE, "kind": one_of("read"), "baseline": BOOL, "files": dict_of(log_file),
                   "lines": list_of(lambda x: isinstance(x, dict)), "vanished": list_of(STR)},
    "cache/coverage_gap": {**OBS_BASE, "kind": one_of("coverage_gap"), "id": STR, "name": null_or(STR),
                           "reason": STR, "bytes": null_or(NAT)},
    # safety.jsonl (:407-408)
    "safety/safety_line": {**OBS_BASE, "kind": one_of("safety_line"), "file": STR, "line": STR},
    # clock.jsonl (:499-500)
    "clock": {"ts": NUM, "host": HOST, "verdict": one_of("ok", "skewed", "uncertain", "unmeasured"),
              "best": null_or(shape({"offset": NUM, "bound": NUM})), "tries": list_of(lambda x: isinstance(x, dict)),
              "limit": NUM},
    # chain.jsonl (:519-568)
    "chain/head": {"ts": NUM, "kind": one_of("head"), "host": HOST, "id": HEAD_ID, "gen_utime": NAT},
    "chain/head_error": {"ts": NUM, "kind": one_of("head"), "host": HOST, "error": STR},
    "chain/cadence_miss": {"ts": NUM, "kind": one_of("cadence_miss"), "host": HOST, "elapsed": NUM},
    "chain/regression": {"ts": NUM, "kind": one_of("regression", "identity_change"), "host": HOST,
                         "from": list_of(lambda x: True), "to": list_of(lambda x: True)},
    "chain/ids": {"ts": NUM, "kind": one_of("ids"), "seqno": NAT,
                  "ids": lambda d: isinstance(d, dict) and all(HOST(k) and HEAD_ID(x) for k, x in d.items()),
                  "agree": BOOL},
    "chain/ids_error": {"ts": NUM, "kind": one_of("ids"), "error": STR},
    # fees.jsonl (:591-597)
    "fees/reading": {"ts": NUM, "operator": HOST, "address": TEXT, "answers": dict_of(NAT), "errors": list_of(STR),
                     "balance_nano": NAT, "disagree": BOOL},
    "fees/error": {"ts": NUM, "operator": HOST, "address": TEXT, "answers": dict_of(NAT), "errors": list_of(STR),
                   "error": STR},
    # t1-boundaries.py (:165-187)
    "boundaries/checked": {"ts": NUM, "boundary": NAT, "outcome": one_of("checked"), "dir": STR,
                           "sources": list_of(STR), "collect_exit": exit_code, "verify_exit": exit_code,
                           "keys_exit": exit_code, "handover_report": either(lambda v: isinstance(v, dict), STR),
                           "keys_verdict": either(lambda v: isinstance(v, dict), STR), "ended": NUM},
    "boundaries/missed": {"ts": NUM, "boundary": NAT, "outcome": one_of("missed"), "reason": STR},
    "boundaries/interrupted": {"ts": NUM, "boundary": NAT, "outcome": one_of("interrupted"), "dir": STR,
                               "reason": STR},
    "boundaries/schedule_mismatch": {"ts": NUM, "boundary": NAT, "outcome": one_of("schedule_mismatch"),
                                     "term": lambda v: isinstance(v, dict), "reason": STR},
    "boundaries/term_error": {"ts": NUM, "boundary": NAT, "error": STR},
    "boundaries/planned": {"ts": NUM, "planned": NAT, "term": null_or(lambda v: isinstance(v, dict))},
    # t1-load.py load.jsonl (:476-529)
    "load/start": {"ts": NUM, "kind": one_of("start"), "cutoff_in_s": NAT, "snapshot": lambda v: isinstance(v, dict),
                   "mode": one_of("t1", "calibration")},
    "load/ramp_done": {"ts": NUM, "kind": one_of("ramp_done"), "elapsed_s": NUM},
    "load/cutoff": {"ts": NUM, "kind": one_of("cutoff"), "reasons": list_of(STR), "elapsed_s": NUM,
                    "undelivered": NAT},
    "load/stop": {"ts": NUM, "kind": one_of("stop"), "reasons": list_of(STR)},
    "load/refused": {"ts": NUM, "kind": one_of("refused"), "reasons": list_of(STR)},
    "load/alarm": {"ts": NUM, "kind": one_of("alarm"), "reason": STR},
    "load/terminated": {"ts": NUM, "kind": one_of("terminated"),
                        "children": dict_of(shape({"rc": null_or(INT), "group_alive": BOOL}))},
    "load/end": {"ts": NUM, "kind": one_of("end"), "result": one_of("stop", "cutoff")},
    # ramp journal.jsonl (journal.py:93-221, ramp.py, remote.py)
    "journal/run": {"type": one_of("run"), "version": INT, "tool": STR, "wallet": TEXT, "time": NUM},
    "journal/end": {"type": one_of("end"), "time": NUM},
    "journal/attempt/transfer": {
        "type": one_of("attempt"), "id": TEXT, "role": one_of("transfer"), "sender": TEXT, "wallet": NAT,
        "seqno": NAT, "nonce": NAT, "deadline": NAT, "external": TEXT, "boc": TEXT,
        "actions": lambda v: isinstance(v, list) and len(v) > 0 and all(
            shape({"destination": TEXT, "value": NAT, "mode": INT})(a) for a in v),
        "fee_bound": NAT, "prior": null_or(STR), "time": NUM, "signed_at": NUM, "step": NAT, "intended": NUM,
        "endpoint": TEXT},
    "journal/attempt/funding": {
        "type": one_of("attempt"), "id": TEXT, "role": one_of("funding"), "sender": TEXT, "seqno": NAT,
        "nonce": NAT, "deadline": NAT, "external": TEXT, "boc": TEXT,
        "actions": list_of(shape({"destination": TEXT, "value": NAT, "mode": INT})), "time": NUM, "signed_at": NUM},
    "journal/sent": {"type": one_of("sent"), "id": TEXT, "time": NUM,
                     "state": one_of("accepted", "refused", "ambiguous"), "reason": null_or(STR)},
    # transfer path: ramp.py included() :876-884; failure is one entry per action (ledger.py:110, 254, 284)
    "journal/observed/transfer": {"type": one_of("observed"), "id": TEXT, "time": NUM, "tx": TEXT, "tx_mc": NAT,
                                  "utime": NAT, "fee": null_or(NAT), "failure": list_of(null_or(STR))},
    # funding path: remote.py:982, journal.py Verdict.as_dict() :552-571
    "journal/observed/funding": {"type": one_of("observed"), "id": TEXT, "time": NUM, "verdict": one_of("executed"),
                                 "tx": TEXT, "lt": NAT, "utime": NAT, "fee": null_or(NAT),
                                 "block": list_of(INT, 3), "problems": list_of(STR), "out_msgs": list_of(
                                     lambda m: isinstance(m, dict))},
    "journal/delivered": {"type": one_of("delivered"), "id": TEXT, "time": NUM, "action": NAT, "recipient_tx": TEXT,
                          "recipient_mc": NAT, "recipient_utime": NAT, "receipt_failure": null_or(STR)},
    "journal/expired": {"type": one_of("expired"), "id": TEXT, "time": NUM, "chain_now": NAT},
    "journal/unknown": {"type": one_of("unknown"), "id": TEXT, "time": NUM, "reason": null_or(STR)},
    # read client: requests.jsonl rows (read_client.py:152-158, sustained_read_load.py:170-171)
    "reads/request": {"endpoint": TEXT, "method": TEXT, "latency_seconds": NUM, "response_bytes": NAT,
                      "error": null_or(STR), "offered_monotonic_seconds": NUM, "finished_monotonic_seconds": NUM},
    # CONTEXT.json (:179-190) and RESULT.json (:281-294)
    "reads/context": {"packet": shape({"duration_seconds": NAT, "window_seconds": NAT, "requests_per_second": NUM,
                                       "endpoints": list_of(TEXT), "address": TEXT}),
                      "started_monotonic_seconds": NUM, "deadline_monotonic_seconds": NUM, "boot_id": TEXT},
    "reads/result": {"status": one_of("DECLARED_READ_LOAD_WINDOWS_COMPLETE"), "boot_id": TEXT,
                     "started_monotonic_seconds": NUM, "completed": NAT, "errors": NAT, "not_offered_capacity": NAT,
                     "windows": NAT, "requests_sha256": lambda v: isinstance(v, str) and len(v) == 64},
}


# ---------------------------------------------------------------- classification


def classify(file: str, r: dict) -> str | None:
    """The schema a row must satisfy, from its discriminator; None for a row of an unknown type."""
    kind = r.get("kind")
    if file == "resources":
        if "error" in r and "complete" not in r:
            return "resources/error"
        return "resources/complete" if r.get("complete") is True else "resources/incomplete"
    if file == "cache":
        return {"error": "cache/error", "read": "cache/read", "coverage_gap": "cache/coverage_gap"}.get(kind)
    if file == "safety":
        return "safety/safety_line" if kind == "safety_line" else None
    if file == "clock":
        return "clock"
    if file == "chain":
        if kind == "head":
            return "chain/head_error" if "error" in r else "chain/head"
        if kind == "ids":
            return "chain/ids_error" if "error" in r else "chain/ids"
        return {"cadence_miss": "chain/cadence_miss", "regression": "chain/regression",
                "identity_change": "chain/regression"}.get(kind)
    if file == "fees":
        return "fees/error" if "error" in r and "balance_nano" not in r else "fees/reading"
    if file == "boundaries":
        if "planned" in r:
            return "boundaries/planned"
        if "outcome" not in r:
            return "boundaries/term_error"
        return {"checked": "boundaries/checked", "missed": "boundaries/missed",
                "interrupted": "boundaries/interrupted",
                "schedule_mismatch": "boundaries/schedule_mismatch"}.get(r.get("outcome"))
    if file == "load":
        name = f"load/{kind}"
        return name if name in SCHEMAS else None
    return None


# ---------------------------------------------------------------- reading


class Evidence:
    """Valid rows per file and schema, and every contract violation per file."""

    def __init__(self) -> None:
        self.rows: dict[str, list[tuple[str, dict]]] = {}
        self.bad: dict[str, list[str]] = {}
        self.missing: list[str] = []
        self.conflicts: list[tuple] = []  # journal deliveries recorded twice with different content
        self.read_context: dict | None = None
        self.read_result: dict | None = None

    def violate(self, file: str, why: str) -> None:
        self.bad.setdefault(file, []).append(why)

    def of(self, file: str, *schemas: str) -> list[dict]:
        return [r for s, r in self.rows.get(file, []) if not schemas or s in schemas]

    def violations(self, *files: str) -> dict[str, Any]:
        out = {f: self.bad[f][:5] + ([f"... {len(self.bad[f])} in all"] if len(self.bad[f]) > 5 else [])
               for f in files if self.bad.get(f)}
        missing = [f for f in files if f in self.missing]
        if missing:
            out["missing_files"] = missing
        return out


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError(f"duplicate member names {sorted({k for k in keys if keys.count(k) > 1})}")
    return dict(pairs)


def parse(raw: bytes):
    return json.loads(raw, object_pairs_hook=_no_duplicate_keys)


def jsonl(path: Path, ev: Evidence, file: str) -> list[dict]:
    """Parsed rows of a JSONL file. A torn final line (a writer killed mid-line) is dropped; any other unparsable
    line or a non-object row is a violation."""
    lines = path.read_bytes().split(b"\n")
    out = []
    for i, raw in enumerate(lines):
        if not raw.strip():
            continue
        try:
            r = parse(raw)
        except ValueError as exc:
            if i == len(lines) - 1:
                continue
            ev.violate(file, f"line {i + 1}: {exc}")
            continue
        if not isinstance(r, dict):
            ev.violate(file, f"line {i + 1}: not an object")
            continue
        out.append(r)
    return out


def check(ev: Evidence, file: str, name: str | None, r: dict, where: str) -> bool:
    if name is None:
        ev.violate(file, f"{where}: unknown record type {r.get('kind', r.get('type', r.get('outcome')))!r}")
        return False
    bad = [k for k, c in SCHEMAS[name].items() if k not in r or not c(r[k])]
    if bad:
        ev.violate(file, f"{where}: {name} with missing or invalid {bad}")
        return False
    ev.rows.setdefault(file, []).append((name, r))
    return True


OBSERVER_FILES = {"resources": True, "cache": True, "chain": True, "clock": True, "fees": True, "boundaries": True,
                  "safety": False}  # the safety file exists only once a line was found


def load(obs: Path, load_dir: Path) -> Evidence:
    ev = Evidence()
    for file, required in OBSERVER_FILES.items():
        path = obs / f"{file}.jsonl"
        if not path.exists():
            if required:
                ev.missing.append(file)
            continue
        for i, r in enumerate(jsonl(path, ev, file)):
            check(ev, file, classify(file, r), r, f"line {i + 1}")
    path = load_dir / "load.jsonl"
    if not path.exists():
        ev.missing.append("load")
    else:
        for i, r in enumerate(jsonl(path, ev, "load")):
            check(ev, "load", classify("load", r), r, f"line {i + 1}")
    load_journal(load_dir / "ramp" / "journal.jsonl", ev)
    load_reads(load_dir / "reads", ev)
    return ev


def load_journal(path: Path, ev: Evidence) -> None:
    """Attempts first; every other event must refer to an attempt, and an observed record follows its attempt's
    role. Byte-identical repeats of a record are one record; a different record under the same key is a conflict,
    kept apart in `conflicts` (for deliveries) or a violation (for anything else)."""
    if not path.exists():
        ev.missing.append("journal")
        return
    rows = jsonl(path, ev, "journal")
    roles = {}
    for r in rows:
        if r.get("type") == "attempt" and isinstance(r.get("id"), str):
            roles.setdefault(r["id"], r.get("role"))
    seen: dict[tuple, dict] = {}
    for i, r in enumerate(rows):
        t, where = r.get("type"), f"line {i + 1}"
        if t in ("run", "end"):
            check(ev, "journal", f"journal/{t}", r, where)
            continue
        if t == "attempt":
            role = r.get("role")
            name = f"journal/attempt/{role}" if role in ("transfer", "funding") else None
        elif t == "observed":
            role = roles.get(r.get("id"))
            if role is None:
                ev.violate("journal", f"{where}: observed record of no attempt {r.get('id')!r}")
                continue
            name = f"journal/observed/{role}" if role in ("transfer", "funding") else None
        elif t in ("sent", "delivered", "expired", "unknown"):
            if r.get("id") not in roles:
                ev.violate("journal", f"{where}: {t} record of no attempt {r.get('id')!r}")
                continue
            name = f"journal/{t}"
        else:
            name = None
        key = (t, r.get("id"), r.get("action") if t == "delivered" else r.get("state") if t == "sent" else None)
        if key in seen:
            if seen[key] == r:
                continue  # an identical rewrite of the same record
            if t == "delivered":
                ev.conflicts.append(key)
            else:
                ev.violate("journal", f"{where}: a different {t} record for {r.get('id')!r}")
            continue
        if check(ev, "journal", name, r, where):
            seen[key] = r


def load_reads(reads: Path, ev: Evidence) -> None:
    """CONTEXT.json, requests.jsonl and RESULT.json. The result's requests_sha256 and completed / errors counts must
    equal the journal's exact bytes and rows; requests must be distinct (by their offer time)."""
    for name, schema in (("CONTEXT.json", "reads/context"), ("RESULT.json", "reads/result")):
        p = reads / name
        if not p.exists():
            ev.missing.append(f"reads/{name}")
            continue
        try:
            d = parse(p.read_bytes())
        except ValueError as exc:
            ev.violate("reads", f"{name}: {exc}")
            continue
        if isinstance(d, dict) and check(ev, "reads", schema, d, name):
            if name == "CONTEXT.json":
                ev.read_context = d
            else:
                ev.read_result = d
    path = reads / "requests.jsonl"
    if not path.exists():
        ev.missing.append("reads/requests.jsonl")
        return
    data = path.read_bytes()
    rows = jsonl(path, ev, "reads")
    offers = set()
    for i, r in enumerate(rows):
        if not check(ev, "reads", "reads/request", r, f"requests line {i + 1}"):
            continue
        off = r["offered_monotonic_seconds"]
        if off in offers:
            ev.violate("reads", f"requests line {i + 1}: a second record of the request offered at {off}")
        offers.add(off)
    res = ev.read_result
    if res is not None:
        if hashlib.sha256(data).hexdigest() != res["requests_sha256"]:
            ev.violate("reads", "requests.jsonl does not hash to RESULT.json requests_sha256")
        if res["completed"] != len(rows) or res["errors"] != sum(1 for r in rows if r.get("error") is not None):
            ev.violate("reads", "requests.jsonl rows do not match RESULT.json completed / errors")
