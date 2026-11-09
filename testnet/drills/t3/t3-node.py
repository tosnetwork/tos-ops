#!/usr/bin/env python3
"""One validator's T3 stop, kill or trusted-ledger start, run ON the host as root.

  t3-node.py node-N --stop
  t3-node.py node-N --kill
  t3-node.py node-N --start --binding DEV:INO
  t3-node.py node-N --after-kill T0 --binding DEV:INO

Derived from the epoch-6 restart script (e6-install-76af.py) with its release and
install lines removed: the units, the ledger (dev, inode) binding, the log markers,
the 36 x 5 s wait and the refusal patterns are kept. Standard library only; the
coordinator copies it to /root/t3-node.py and checks its sha256.

  --stop        stop the elections task, then the validator; no validator-engine may remain.
  --kill        SIGKILL the validator through systemd and wait for its automatic restart
                (Restart=on-failure); if it is not active 60 s after the kill, start it once.
  --start       start the validator, wait up to 180 s for "trusted, " plus an own
                masterchain signature after the start, with the ledger binding unchanged;
                only then start the elections task.
  --after-kill  the same marker check from T0 (the kill time); no unit is touched.

Refusals: "unknown history"/"untrusted" leave the validator running (a fenced node signs
again after its fence block) and the elections task stopped; a full decision log,
equivocation, double sign or a conflicting decision stops the elections task and the
validator, as the source script did. It never touches tos-testnet-dht and never deletes,
moves or recreates a ledger or database. It prints one JSON result line.

Exit codes: 0 done, 2 usage or a refused precondition, 3 unexpected ledger state,
4 no trusted re-sign within 180 s, 5 ledger directory replaced or a second engine present.
"""

from __future__ import annotations

import datetime
import glob
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

NODES = ("node-1", "node-2", "node-3", "node-4")
VALIDATOR = "tos-testnet-validator"
ELECTIONS = "tos-testnet-elections"
LEDGER = Path("/var/lib/tos/validator/consensus/signing-ledger")
LOGS = "/var/log/tos/validator/node.log*"
MARKER_GREP = (
    "signing ledger|consensus: own signature|signing decision log|equivocation|double.sign"
    "|conflicts with a decision already recorded|unknown history|untrusted"
)
UNTRUSTED = re.compile(r"unknown history|untrusted|cannot.*decision log", re.I)
UNSAFE = re.compile(
    r"signing decision log .* is full|equivocation|double.sign"
    r"|conflicts with a decision already recorded",
    re.I,
)
STAMP = re.compile(r"\[(20\d\d-\d\d-\d\d \d\d:\d\d:\d\d)")
WAIT_ATTEMPTS = 36
WAIT_STEP = 5.0
KILL_RESTART_WAIT = 60.0


class Refused(Exception):
    def __init__(self, code: int, result: str, **detail):
        super().__init__(result)
        self.code = code
        self.result = result
        self.detail = detail


def run(args: list[str], timeout: int = 150) -> str:
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise Refused(2, "COMMAND-FAILED", args=args, rc=r.returncode, stderr=r.stderr[-1000:])
    return r.stdout + r.stderr


def active(unit: str) -> bool:
    return subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def engine_running() -> bool:
    return subprocess.run(["pidof", "validator-engine"], capture_output=True).returncode == 0


def show(unit: str, prop: str) -> str:
    return run(["systemctl", "show", "-p", prop, "--value", unit]).strip()


def binding_now() -> tuple[int, int]:
    st = LEDGER.stat()
    return (st.st_dev, st.st_ino)


def parse_binding(text: str) -> tuple[int, int]:
    m = re.fullmatch(r"(\d+):(\d+)", text or "")
    if not m:
        raise Refused(2, "BAD-BINDING", binding=text)
    return (int(m[1]), int(m[2]))


def line_time(line: str) -> float | None:
    """The engine's UTC timestamp of a log line, in whole seconds, or None."""
    m = STAMP.search(line)
    if not m:
        return None
    stamp = datetime.datetime.strptime(m[1], "%Y-%m-%d %H:%M:%S")
    return stamp.replace(tzinfo=datetime.timezone.utc).timestamp()


def lines_since(text: str, t0: float) -> list[str]:
    """Only lines with a parsed engine UTC timestamp at/after t0 count."""
    rows = []
    for line in text.splitlines():
        t = line_time(line)
        if t is not None and t >= t0:
            rows.append(line)
    return rows


def classify(lines: list[str]) -> tuple[str, list[str]]:
    """'unsafe', 'untrusted', 'resigned' or 'waiting', with the own-signature lines."""
    text = "\n".join(lines)
    if UNSAFE.search(text):
        return "unsafe", []
    if UNTRUSTED.search(text):
        return "untrusted", []
    sig = [
        line
        for line in lines
        if "consensus: own signature: first" in line and "(-1,8000000000000000)" in line
    ]
    if "trusted, " in text and sig:
        return "resigned", sig
    return "waiting", sig


def markers(t0: float) -> list[str]:
    r = subprocess.run(
        ["grep", "-ahE", MARKER_GREP, *sorted(glob.glob(LOGS))],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if r.returncode not in (0, 1):
        raise Refused(2, "LOG-READ-FAILED", rc=r.returncode)
    return lines_since(r.stdout, t0)


def await_markers(t0: float) -> tuple[str, list[str], list[str]]:
    lines: list[str] = []
    for _ in range(WAIT_ATTEMPTS):
        time.sleep(WAIT_STEP)
        lines = markers(t0)
        state, sig = classify(lines)
        if state != "waiting":
            return state, lines, sig
    return "timeout", lines, []


def do_stop(node: str) -> dict:
    binding = binding_now()
    t0 = time.time()
    run(["systemctl", "stop", ELECTIONS, VALIDATOR])
    stopped = time.time()
    if engine_running():
        raise Refused(5, "ENGINE-STILL-RUNNING", t0=t0)
    return dict(
        result="STOPPED", node=node, t0=t0, stopped_utc=stopped, ledger_binding=list(binding)
    )


def do_kill(node: str) -> dict:
    if not active(VALIDATOR):
        raise Refused(2, "VALIDATOR-NOT-ACTIVE")
    binding = binding_now()
    old_pid = show(VALIDATOR, "MainPID")
    t0 = time.time()
    run(["systemctl", "kill", "--signal=SIGKILL", VALIDATOR])
    fallback = False
    restarted = None
    while time.time() < t0 + KILL_RESTART_WAIT:
        time.sleep(2)
        pid = show(VALIDATOR, "MainPID")
        if active(VALIDATOR) and pid not in ("0", old_pid):
            restarted = time.time()
            break
    if restarted is None:
        fallback = True
        run(["systemctl", "start", VALIDATOR])
        restarted = time.time()
        if not active(VALIDATOR):
            raise Refused(2, "NOT-ACTIVE-AFTER-FALLBACK-START", t0=t0)
    if binding_now() != binding:
        raise Refused(5, "LEDGER-REPLACED", t0=t0)
    return dict(
        result="RESTARTED-BY-SYSTEMD" if not fallback else "STARTED-AFTER-FALLBACK",
        node=node,
        t0=t0,
        restarted_utc=restarted,
        old_pid=old_pid,
        new_pid=show(VALIDATOR, "MainPID"),
        n_restarts=show(VALIDATOR, "NRestarts"),
        ledger_binding=list(binding),
    )


def finish_markers(node: str, t0: float, binding: tuple[int, int], start: bool) -> dict:
    state, lines, sig = await_markers(t0)
    base = dict(node=node, t0=t0, checked_utc=time.time(), lines=lines[-40:])
    if state == "unsafe":
        if start:
            run(["systemctl", "stop", ELECTIONS, VALIDATOR])
        raise Refused(
            3, "STOPPED-UNEXPECTED-LEDGER-STATE" if start else "UNEXPECTED-LEDGER-STATE", **base
        )
    if state == "untrusted":
        # Fenced: it signs again after its fence block. Elections stay stopped; the ledger
        # is diagnosed, never touched.
        raise Refused(3, "UNTRUSTED-FENCED", **base)
    if state == "timeout":
        raise Refused(4, "INCONCLUSIVE-NO-TRUSTED-RESIGN", **base)
    if binding_now() != binding:
        raise Refused(5, "LEDGER-REPLACED", **base)
    base["signature"] = sig[0][:300]
    base["ledger_binding"] = list(binding)
    return base


def do_start(node: str, binding: tuple[int, int]) -> dict:
    if active(VALIDATOR):
        raise Refused(2, "ALREADY-ACTIVE")
    if engine_running():
        raise Refused(5, "SECOND-ENGINE-PRESENT")
    if binding_now() != binding:
        raise Refused(5, "LEDGER-REPLACED")
    if not (LEDGER / "ledger").is_file():
        raise Refused(2, "MISSING-LEDGER-HEADER")
    t0 = int(time.time())
    run(["systemctl", "start", VALIDATOR])
    out = finish_markers(node, t0, binding, start=True)
    run(["systemctl", "start", ELECTIONS])
    if not (active(VALIDATOR) and active(ELECTIONS)):
        raise Refused(2, "UNITS-NOT-ACTIVE", **out)
    out["result"] = "TRUSTED-RESIGNED"
    out["elections_started_utc"] = time.time()
    return out


def do_after_kill(node: str, t0: float, binding: tuple[int, int]) -> dict:
    out = finish_markers(node, t0, binding, start=False)
    out["result"] = "TRUSTED-RESIGNED"
    return out


def main(argv: list[str]) -> int:
    try:
        if len(argv) < 2 or argv[0] not in NODES:
            raise Refused(2, "USAGE")
        node, mode, rest = argv[0], argv[1], argv[2:]
        if os.geteuid() != 0:
            raise Refused(2, "NOT-ROOT")
        opts = dict(zip(rest[::2], rest[1::2]))
        if mode == "--stop" and not rest:
            out = do_stop(node)
        elif mode == "--kill" and not rest:
            out = do_kill(node)
        elif mode == "--start" and set(opts) == {"--binding"} and len(rest) == 2:
            out = do_start(node, parse_binding(opts["--binding"]))
        elif mode == "--after-kill" and len(rest) == 3:
            t0 = int(float(rest[0]))
            more = dict(zip(rest[1::2], rest[2::2]))
            if set(more) != {"--binding"}:
                raise Refused(2, "USAGE")
            out = do_after_kill(node, t0, parse_binding(more["--binding"]))
        else:
            raise Refused(2, "USAGE")
    except Refused as e:
        print(
            json.dumps(dict(result=e.result, node=argv[0] if argv else None, **e.detail)),
            flush=True,
        )
        return e.code
    except Exception as e:  # report one JSON line, never a bare traceback
        print(json.dumps(dict(result="ERROR", error=repr(e)[:500])), flush=True)
        return 2
    print(json.dumps(out), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
