#!/usr/bin/env python3
"""Recover the host uplink when its NIC transmit queue wedges.

The on-board Intel I219 (e1000e) can stop transmitting permanently under
sustained load: the kernel logs "Detected Hardware Unit Hang" every two
seconds and the driver never resets the adapter, so the host loses every
network path (DNS, Tailscale, GitHub) while the rest of the system keeps
running. This watchdog detects that state and restores the link without a
power cycle.

Detection, checked every poll interval:
  * hang reports for the interface in the kernel log since the last poll, or
  * the default gateway failing to answer for several consecutive polls.

Recovery escalates: re-apply offload settings and bounce the link; if the
previous recovery did not bring the link back, reload the driver instead.
Recoveries are rate-limited so a dead upstream router cannot turn into a
reset loop.
"""

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass

HANG_PATTERN = "Detected Hardware Unit Hang"


@dataclass
class Policy:
    hang_reports: int = 2
    ping_failures: int = 6
    min_interval_s: float = 120.0


@dataclass
class State:
    consecutive_ping_failures: int = 0
    last_recovery: float = float("-inf")
    failed_recoveries: int = 0
    pending_check: bool = False


def decide(policy, state, hang_reports, ping_ok, now):
    """Return the action for one poll: None, "bounce" or "reload"."""
    if ping_ok:
        state.consecutive_ping_failures = 0
    else:
        state.consecutive_ping_failures += 1

    if state.pending_check:
        state.pending_check = False
        if ping_ok and hang_reports == 0:
            state.failed_recoveries = 0
        else:
            state.failed_recoveries += 1

    wedged = hang_reports >= policy.hang_reports
    unreachable = state.consecutive_ping_failures >= policy.ping_failures
    if not (wedged or unreachable):
        return None
    if now - state.last_recovery < policy.min_interval_s:
        return None

    state.last_recovery = now
    state.pending_check = True
    return "reload" if state.failed_recoveries > 0 else "bounce"


def log(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def run(argv, dry_run):
    if dry_run:
        log("dry_run", argv=argv)
        return True
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        log("command_failed", argv=argv, rc=result.returncode,
            stderr=result.stderr.strip()[-400:])
        return False
    return True


def count_hang_reports(iface, since_epoch):
    result = subprocess.run(
        ["journalctl", "-k", "-q", "--no-pager", "-o", "cat",
         f"--since=@{int(since_epoch)}"],
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        log("journal_read_failed", rc=result.returncode)
        return 0
    marker = f"{iface}: {HANG_PATTERN}"
    return sum(1 for line in result.stdout.splitlines() if marker in line)


def default_gateway(iface):
    result = subprocess.run(["ip", "-j", "route", "show", "default", "dev", iface],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None
    try:
        routes = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None
    for route in routes:
        if route.get("gateway"):
            return route["gateway"]
    return None


def gateway_answers(iface):
    gateway = default_gateway(iface)
    if gateway is None:
        return False
    result = subprocess.run(["ping", "-n", "-q", "-c", "2", "-W", "2", "-I", iface, gateway],
                            capture_output=True, check=False)
    return result.returncode == 0


def apply_offloads(iface, dry_run):
    return run(["ethtool", "-K", iface, "tso", "off", "gso", "off"], dry_run)


def wait_for_interface(iface, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if subprocess.run(["ip", "link", "show", iface], capture_output=True,
                          check=False).returncode == 0:
            return True
        time.sleep(1)
    return False


def recover(action, iface, driver, dry_run):
    if action == "reload":
        ok = run(["modprobe", "-r", driver], dry_run) and run(["modprobe", driver], dry_run)
        # The interface reappears asynchronously after the module loads.
        if not dry_run:
            ok = wait_for_interface(iface, 30) and ok
    else:
        ok = run(["ip", "link", "set", iface, "down"], dry_run)
        if not dry_run:
            time.sleep(2)
        ok = run(["ip", "link", "set", iface, "up"], dry_run) and ok
    ok = apply_offloads(iface, dry_run) and ok
    ok = run(["networkctl", "reconfigure", iface], dry_run) and ok
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--interface", default="eno1")
    parser.add_argument("--driver", default="e1000e")
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--dry-run", action="store_true",
                        help="log the recovery commands instead of running them")
    parser.add_argument("--polls", type=int, default=0,
                        help="stop after this many polls (0 = run forever)")
    args = parser.parse_args()

    policy = Policy()
    state = State()
    since = time.time()
    polls = 0
    log("started", interface=args.interface, driver=args.driver, dry_run=args.dry_run)
    while True:
        poll_start = time.time()
        hangs = count_hang_reports(args.interface, since)
        since = poll_start
        ping_ok = gateway_answers(args.interface)
        action = decide(policy, state, hangs, ping_ok, time.monotonic())
        if action is not None:
            log("recovering", action=action, hang_reports=hangs, ping_ok=ping_ok,
                ping_failures=state.consecutive_ping_failures)
            ok = recover(action, args.interface, args.driver, args.dry_run)
            log("recovered" if ok else "recovery_incomplete", action=action)
            # Hang reports logged during our own recovery must not count next poll.
            since = time.time()
        polls += 1
        if args.polls and polls >= args.polls:
            return 0
        time.sleep(max(0.0, args.interval - (time.time() - poll_start)))


if __name__ == "__main__":
    sys.exit(main())
