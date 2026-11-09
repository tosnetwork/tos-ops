#!/usr/bin/env python3
"""One validator's T3 stop, kill, start or quarantine, run ON the host as root.

  t3-node.py node-N --stop --run RUN [--restore-after SECONDS]
  t3-node.py node-N --kill --run RUN
  t3-node.py node-N --start-engine --run RUN --binding DEV:INO
  t3-node.py node-N --await-signing T0 --run RUN --binding DEV:INO
  t3-node.py node-N --start --run RUN --binding DEV:INO      (start-engine, then await-signing)
  t3-node.py node-N --after-kill T0 --run RUN --binding DEV:INO
  t3-node.py node-N --quarantine --run RUN

Derived from the epoch-6 restart script (e6-install-76af.py) with its release and install
lines removed: the units, the ledger (dev, inode) binding, the log markers, the 36 x 5 s
wait and the refusal patterns are kept. Standard library only; the coordinator copies it to
/root/t3-node.py and checks its sha256.

  --stop           stop the elections task, then the validator; no validator-engine may
                   remain. With --restore-after, first arm and verify a host-local timer
                   (t3-restore-RUN) that starts the validator after SECONDS, so the host comes
                   back even if the coordinator is gone; no timer, no stop.
  --kill           SIGKILL the validator through systemd and wait for its automatic restart
                   (Restart=on-failure); if it is not active 60 s after the kill, start it once.
  --start-engine   start the validator only and return; it never waits for signing.
  --await-signing  wait up to 180 s after T0 for "trusted, " plus an own masterchain
                   signature, the ledger binding unchanged; only then start the elections task
                   and cancel the restore timer. Elections start only here.
  --after-kill     the same marker check from T0 (the kill time); no unit is touched.
  --quarantine     cancel the restore timer, stop the elections task and the validator, write
                   /root/t3-quarantine-RUN and report the ledger listing. No start mode runs
                   while any /root/t3-quarantine-* exists; the coordinator clears it by hand.

Refusals: "unknown history"/"untrusted" leave the validator running and the elections task
stopped: the node stays fenced (its admission stays fenced through the fence block's
catchain plus two) and may not sign within 180 s, which is not an error of any other host. A
conflicting decision, a double sign, equivocation or a full decision log is a safety stop:
the host quarantines itself as --quarantine does. It never touches tos-testnet-dht and never
deletes, moves or recreates a ledger or database. It prints one JSON result line.

Exit codes: 0 done, 2 usage or a refused precondition, 3 untrusted (fenced) or a safety
quarantine, 4 no trusted re-sign within 180 s, 5 ledger directory replaced or a second engine
present, 6 quarantined host.
"""

from __future__ import annotations

import argparse
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
QUARANTINE = "/root/t3-quarantine-"
RESTORE_ARGV = "argv[]=/usr/bin/systemctl start tos-testnet-validator"
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
RUN_NAME = re.compile(r"t3-\d{8}T\d{4}Z-S[1-4]")
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


def quiet(args: list[str]) -> int:
    return subprocess.run(args, capture_output=True, text=True, timeout=150).returncode


def active(unit: str) -> bool:
    return subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def engine_running() -> bool:
    return subprocess.run(["pidof", "validator-engine"], capture_output=True).returncode == 0


def show(unit: str, prop: str) -> str:
    return run(["systemctl", "show", "-p", prop, "--value", unit]).strip()


def binding_now() -> tuple[int, int]:
    st = LEDGER.stat()
    return (st.st_dev, st.st_ino)


def parse_binding(text: str | None) -> tuple[int, int]:
    m = re.fullmatch(r"(\d+):(\d+)", text or "")
    if not m:
        raise Refused(2, "BAD-BINDING", binding=text)
    return (int(m[1]), int(m[2]))


def quarantined() -> list[str]:
    return sorted(glob.glob(QUARANTINE + "*"))


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


def timespan(text: str) -> float:
    """Seconds of a systemd timespan such as '1d 4h 13min 50.843801s'."""
    unit = {
        "y": 31557600,
        "month": 2629800,
        "w": 604800,
        "d": 86400,
        "h": 3600,
        "min": 60,
        "s": 1,
        "ms": 1e-3,
        "us": 1e-6,
    }
    parts = re.findall(r"([\d.]+)\s*(month|min|ms|us|y|w|d|h|s)\b", text)
    if not parts or re.sub(r"[\d.]+\s*(month|min|ms|us|y|w|d|h|s)\b", "", text).strip():
        raise ValueError(f"not a timespan: {text!r}")
    return sum(float(n) * unit[u] for n, u in parts)


def arm_restore(run_name: str, seconds: int) -> dict:
    unit = f"t3-restore-{run_name}"
    run(
        [
            "systemd-run",
            f"--unit={unit}",
            f"--on-active={seconds}s",
            "/usr/bin/systemctl",
            "start",
            VALIDATOR,
        ]
    )
    left = timespan(show(unit + ".timer", "NextElapseUSecMonotonic")) - time.monotonic()
    execs = show(unit + ".service", "ExecStart")
    if (
        not active(unit + ".timer")
        or RESTORE_ARGV not in execs
        or not (seconds - 30 <= left <= seconds + 5)
    ):
        quiet(["systemctl", "stop", unit + ".timer"])
        raise Refused(2, "RESTORE-TIMER-NOT-VERIFIED", left=left, exec=execs[:200])
    return dict(unit=unit, left=round(left, 1))


def cancel_restore(run_name: str) -> None:
    quiet(["systemctl", "stop", f"t3-restore-{run_name}.timer"])


def ledger_listing() -> dict:
    try:
        st = LEDGER.stat()
        names = sorted(os.listdir(LEDGER))
        return dict(
            binding=[st.st_dev, st.st_ino],
            entries=[dict(name=n, bytes=(LEDGER / n).stat().st_size) for n in names],
        )
    except OSError as e:
        return dict(error=repr(e))


def do_quarantine(node: str, run_name: str, reason: str) -> dict:
    cancel_restore(run_name)
    rc = quiet(["systemctl", "stop", ELECTIONS, VALIDATOR])
    marker = Path(QUARANTINE + run_name)
    marker.write_text(json.dumps(dict(node=node, reason=reason, utc=time.time())) + "\n")
    return dict(
        result="QUARANTINED",
        node=node,
        reason=reason,
        stop_rc=rc,
        engine_running=engine_running(),
        ledger=ledger_listing(),
        marker=str(marker),
    )


def do_stop(node: str, run_name: str, restore_after: int | None) -> dict:
    binding = binding_now()
    timer = arm_restore(run_name, restore_after) if restore_after else None
    t0 = time.time()
    run(["systemctl", "stop", ELECTIONS, VALIDATOR])
    stopped = time.time()
    if engine_running():
        raise Refused(5, "ENGINE-STILL-RUNNING", t0=t0)
    return dict(
        result="STOPPED",
        node=node,
        t0=t0,
        stopped_utc=stopped,
        ledger_binding=list(binding),
        restore_timer=timer,
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


def do_start_engine(node: str, binding: tuple[int, int]) -> dict:
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
    return dict(result="ENGINE-STARTED", node=node, t0=t0)


def do_await(
    node: str, t0: float, binding: tuple[int, int], run_name: str, start_elections: bool
) -> dict:
    state, lines, sig = await_markers(t0)
    base = dict(node=node, t0=t0, checked_utc=time.time(), lines=lines[-40:])
    if state == "unsafe":
        q = do_quarantine(node, run_name, "unsafe ledger marker")
        raise Refused(3, "SAFETY-QUARANTINED", quarantine=q, **base)
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
    if start_elections:
        run(["systemctl", "start", ELECTIONS])
        cancel_restore(run_name)
        if not (active(VALIDATOR) and active(ELECTIONS)):
            raise Refused(2, "UNITS-NOT-ACTIVE", **base)
        base["elections_started_utc"] = time.time()
    base["result"] = "TRUSTED-RESIGNED"
    return base


def parse(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    ap.add_argument("node", choices=NODES)
    mode = ap.add_mutually_exclusive_group(required=True)
    for m in ("--stop", "--kill", "--start-engine", "--start", "--quarantine"):
        mode.add_argument(m, action="store_true")
    mode.add_argument("--await-signing", type=float, metavar="T0")
    mode.add_argument("--after-kill", type=float, metavar="T0")
    ap.add_argument("--run", required=True)
    ap.add_argument("--binding")
    ap.add_argument("--restore-after", type=int)
    try:
        a = ap.parse_args(argv)
    except (argparse.ArgumentError, SystemExit) as e:
        raise Refused(2, "USAGE", error=str(e)[:200]) from None
    if not RUN_NAME.fullmatch(a.run):
        raise Refused(2, "USAGE", error="bad --run")
    if a.restore_after is not None and not (a.stop and 60 <= a.restore_after <= 1800):
        raise Refused(2, "USAGE", error="--restore-after is 60..1800 s and only with --stop")
    return a


def main(argv: list[str]) -> int:
    node = argv[0] if argv else None
    try:
        a = parse(argv)
        if os.geteuid() != 0:
            raise Refused(2, "NOT-ROOT")
        starts = a.start_engine or a.start or a.await_signing is not None
        if starts and quarantined():
            raise Refused(6, "QUARANTINED", markers=quarantined())
        if a.stop:
            out = do_stop(a.node, a.run, a.restore_after)
        elif a.kill:
            out = do_kill(a.node)
        elif a.quarantine:
            out = do_quarantine(a.node, a.run, "coordinator safety abort")
        elif a.start_engine:
            out = do_start_engine(a.node, parse_binding(a.binding))
        elif a.start:
            b = parse_binding(a.binding)
            e = do_start_engine(a.node, b)
            out = do_await(a.node, e["t0"], b, a.run, start_elections=True)
        elif a.await_signing is not None:
            out = do_await(a.node, int(a.await_signing), parse_binding(a.binding), a.run, True)
        else:
            out = do_await(a.node, int(a.after_kill), parse_binding(a.binding), a.run, False)
    except Refused as e:
        print(json.dumps(dict(result=e.result, node=node, **e.detail)), flush=True)
        return e.code
    except Exception as e:  # report one JSON line, never a bare traceback
        print(json.dumps(dict(result="ERROR", node=node, error=repr(e)[:500])), flush=True)
        return 2
    print(json.dumps(out), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
