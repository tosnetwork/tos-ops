#!/usr/bin/env python3
"""T1 boundary checks (read-only, memo public-testnet/T1-PLAN-20261110 §4.4).

  t1-boundaries.py --inventory hosts.json --unit-dir DIR --global-config G --zerostate Z --out DIR --end UNIXTIME

At every validator-set switch from now until --end, it runs:
  1. check-handover.py collect + verify on all four named validator sources (check-handover alone accepts two;
     T1 requires four), collection starting 360 s before the switch;
  2. check-validator-keys.py (the four-signer gate) on all four sources, for blocks after the switch.
Each boundary is taken from the chain: the `until` of the current set (ConfigParam 34), read from all four
sources, which must agree. One row per boundary goes to DIR/boundaries.jsonl: the boundary, the exit status of
each step, the verdicts, and the evidence directories. A boundary whose term cannot be read, or whose checks
cannot run, is a row with its error, never a silent skip. The next boundary is read again after each one.

Exit statuses of the checks are recorded, not interpreted: the T1 judge applies §5.1 to them.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "production"))
import network_check  # noqa: E402

HOSTS = ("node-1", "node-2", "node-3", "node-4")
LEAD = 360  # collection starts this long before the switch, as in the odd-hour checks
KEYS_WAIT = 600  # the four-signer gate retries for this long after the switch


def load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def rpc(url: str, method: str, **params) -> dict:
    body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=15) as reply:
        answer = json.loads(reply.read(1024 * 1024 + 1))
    if not isinstance(answer, dict) or "result" not in answer:
        raise RuntimeError(str(answer)[:200])
    return answer["result"]


def current_term(urls: dict[str, str], fetch=rpc) -> dict:
    """The current set's since/until, from all four sources; they must agree."""
    seen = {}
    for host, url in urls.items():
        cfg = fetch(url, "getConfigParam", param=34)
        cell = network_check.lib.parse_boc(base64.b64decode(cfg["config"]["bytes"]))
        s = network_check.decode_set(cell)
        seen[host] = (s["since"], s["until"])
    if len(set(seen.values())) != 1 or len(seen) != len(HOSTS):
        raise RuntimeError(f"sources disagree on ConfigParam 34: {seen}")
    since, until = next(iter(seen.values()))
    return {"since": since, "until": until}


def handover_argv(boundary: int, urls: dict[str, str], gcfg: Path, out: Path) -> tuple[list, list]:
    collect = [sys.executable, "-I", str(HERE / "check-handover.py"), "collect", "--boundary", str(boundary)]
    for host in HOSTS:
        collect += ["--rpc", urls[host]]
    collect += ["--genesis-config", str(gcfg), "--span", "100", "--max-wait", "900", "--interval", "0.6",
                "--lock-dir", str(out / "lock"), "--out", str(out / "collect")]
    verify = [sys.executable, "-I", str(HERE / "check-handover.py"), "verify", "--genesis-config", str(gcfg),
              "--out", str(out / "collect")]
    return collect, verify


def keys_argv(boundary: int, a, out: Path) -> list:
    argv = [sys.executable, "-I", str(HERE / "check-validator-keys.py"), "--global-config", str(a.global_config),
            "--zerostate", str(a.zerostate), "--inventory", str(a.inventory), "--unit-dir", str(a.unit_dir)]
    for host in HOSTS:
        argv += ["--source", host]
    return argv + ["--since", str(boundary), "--wait", str(KEYS_WAIT), "--out", str(out / "keys")]


def verdict(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        return f"unreadable: {exc}"


def one_boundary(boundary: int, a, urls, run=subprocess.run, now=time.time, sleep=time.sleep) -> dict:
    out = a.out / f"boundary-{boundary}"
    out.mkdir(parents=True, exist_ok=False)
    (out / "lock").mkdir(mode=0o700)
    wait = boundary - LEAD - now()
    if wait > 0:
        sleep(wait)
    row = {"boundary": boundary, "dir": str(out), "sources": list(HOSTS)}
    collect, verify = handover_argv(boundary, urls, a.global_config, out)
    for name, argv, timeout in (("collect", collect, LEAD + 1800), ("verify", verify, 1800),
                                ("keys", keys_argv(boundary, a, out), KEYS_WAIT + 600)):
        with (out / f"{name}.log").open("w") as log:
            try:
                r = run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
                row[f"{name}_exit"] = r.returncode
            except subprocess.TimeoutExpired:
                row[f"{name}_exit"] = "timeout"
    row["handover_report"] = verdict(out / "collect" / "report.json")
    row["keys_verdict"] = verdict(out / "keys" / "VERDICT.json")
    row["ended"] = now()
    return row


def append(path: Path, row: dict) -> None:
    with path.open("a") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def run_boundaries(a, urls, fetch=rpc, run=subprocess.run, now=time.time, sleep=time.sleep) -> int:
    a.out.mkdir(parents=True, exist_ok=True)
    rows = a.out / "boundaries.jsonl"
    done = set()
    while now() < a.end:
        try:
            term = current_term(urls, fetch)
        except Exception as exc:  # recorded, then retried: a boundary is never skipped silently
            append(rows, {"ts": now(), "error": f"term unreadable: {type(exc).__name__}: {exc}"[:300]})
            sleep(60)
            continue
        boundary = term["until"]
        if boundary in done or boundary > a.end:
            # The switch already handled (or past the end): wait for the next set.
            if boundary > a.end:
                break
            sleep(60)
            continue
        append(rows, {"ts": now(), "planned": boundary, "term": term})
        row = one_boundary(boundary, a, urls, run, now, sleep)
        append(rows, {"ts": now(), **row})
        done.add(boundary)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inventory", type=Path, required=True)
    ap.add_argument("--unit-dir", type=Path, default=Path.home() / ".config/systemd/user")
    ap.add_argument("--global-config", type=Path, required=True)
    ap.add_argument("--zerostate", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--end", type=int, required=True, help="unix time after which no new boundary starts")
    a = ap.parse_args(argv)
    urls = load("check_validator_keys", "check-validator-keys.py").tunnel_inventory(
        a.unit_dir, json.loads(a.inventory.read_text()))
    return run_boundaries(a, {h: urls[h] for h in HOSTS})


if __name__ == "__main__":
    sys.exit(main())
