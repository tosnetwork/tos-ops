"""Root-owned slot control for the CI supervisor.

Socket-activated per connection (Accept=yes): file descriptor 0 is the
connection. One request is read, from the supervisor account only (checked
with SO_PEERCRED), within one absolute deadline:

    up N G       want generation G of slot N running
    down N G     want generation G of slot N stopped
    cleanup N G  retry the stopped generation G's cleanup
    status N     the unit's state, MainPID and the slot's recorded intent

The helper owns each slot's intent: {latest generation, desired up|down}, in a
root-only file. A request for an older generation than the latest does
nothing, so a delayed stop or cleanup can never touch a newer VM. Within one
generation "down" wins: a delayed "up" can never restart a VM that was asked
to stop. Every request on a slot runs under that slot's lock.
"""

from __future__ import annotations

import fcntl
import json
import os
import pwd
import re
import select
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

SUPERVISOR = "tos-ci"
RUN = Path("/run/tos-ci")
REQUEST = re.compile(r"^(?:(up|down|cleanup) ([123]) ([0-9]{1,12})|(status) ([123]))\n$")
MAX_LINE = 64
READ_DEADLINE = 2.0


# ------------------------------------------------------------- pure logic


def parse(line: bytes) -> tuple[str, int, int | None] | None:
    """(verb, slot, generation or None for status) of a well-formed request."""
    if len(line) > MAX_LINE:
        return None
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        return None
    match = REQUEST.fullmatch(text)
    if not match:
        return None
    if match.group(4):
        return ("status", int(match.group(5)), None)
    return (match.group(1), int(match.group(2)), int(match.group(3)))


def transition(verb: str, generation: int, intent: dict) -> tuple[dict, str, str]:
    """(new intent, action, reply) for up/down/cleanup against the recorded intent.

    action is one of "start", "stop", "cleanup" or "none".
    """
    latest, desired = intent["latest"], intent["desired"]
    if generation < latest:
        return intent, "none", "stale"
    if verb == "down":
        return {"latest": generation, "desired": "down"}, "stop", "ok"
    if verb == "up":
        if generation > latest:
            return {"latest": generation, "desired": "up"}, "start", "ok"
        if desired == "up":
            return intent, "start", "ok"
        return intent, "none", "down wins"
    if verb == "cleanup":
        if generation == latest and desired == "down":
            return intent, "cleanup", "ok"
        return intent, "none", "stale" if generation != latest else "not down"
    raise ValueError(verb)


# --------------------------------------------------------------- host side


def unit(slot: int) -> str:
    return f"tos-ci-vm@{slot}.service"


def systemctl(*args: str, timeout: float = 180) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=timeout)


def read_intent(slot: int) -> dict:
    try:
        data = json.loads((RUN / f"slot{slot}.state").read_text())
        if isinstance(data.get("latest"), int) and data.get("desired") in ("up", "down"):
            return data
    except (OSError, ValueError):
        pass
    return {"latest": 0, "desired": "down"}


def write_intent(slot: int, intent: dict) -> None:
    path = RUN / f"slot{slot}.state"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(intent))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def vm_gone(slot: int) -> bool:
    """The unit is not running and nothing of the slot's account or QEMU remains."""
    if systemctl("is-active", unit(slot), timeout=10).stdout.strip() in ("active", "activating", "deactivating"):
        return False
    account = f"tos-ci-slot{slot}"
    if subprocess.run(["pgrep", "-u", account], capture_output=True).returncode == 0:
        return False
    return subprocess.run(["pgrep", "-f", f"qemu-system-x86_64 -name tos-ci-vm-{slot}"], capture_output=True).returncode != 0


def perform(verb: str, slot: int, generation: int | None) -> str:
    with open(RUN / f"slot{slot}.op.lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        intent = read_intent(slot)
        if verb == "status":
            active = systemctl("is-active", unit(slot), timeout=10).stdout.strip() or "unknown"
            pid = systemctl("show", "-p", "MainPID", "--value", unit(slot), timeout=10).stdout.strip()
            return json.dumps({"active": active, "pid": int(pid) if pid.isdigit() else 0, **intent})
        new_intent, action, reply = transition(verb, generation, intent)
        if new_intent != intent:
            write_intent(slot, new_intent)
        if action == "start":
            if systemctl("is-active", unit(slot), timeout=10).stdout.strip() != "active":
                systemctl("reset-failed", unit(slot), timeout=10)
                result = systemctl("start", unit(slot))
                reply = "ok" if result.returncode == 0 else f"error {result.returncode}"
        elif action == "stop":
            result = systemctl("stop", unit(slot))
            reply = "ok" if result.returncode == 0 else f"error {result.returncode}"
        elif action == "cleanup":
            if not vm_gone(slot):
                reply = "busy"
            else:
                result = subprocess.run(["/usr/lib/tos-ci/slot-cleanup", str(slot)], capture_output=True, timeout=120)
                reply = "ok" if result.returncode == 0 else f"error {result.returncode}"
        return reply


def peer_uid(conn: socket.socket) -> int:
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def read_line(conn: socket.socket) -> bytes:
    """One request line, within a single absolute deadline."""
    deadline = time.monotonic() + READ_DEADLINE
    data = b""
    while not data.endswith(b"\n") and len(data) <= MAX_LINE:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select([conn], [], [], remaining)
        if not ready:
            break
        chunk = conn.recv(MAX_LINE + 1 - len(data))
        if not chunk:
            break
        data += chunk
    return data


def main() -> int:
    conn = socket.socket(fileno=0)
    try:
        if peer_uid(conn) != pwd.getpwnam(SUPERVISOR).pw_uid:
            conn.sendall(b"refused peer\n")
            return 1
        request = parse(read_line(conn))
        if request is None:
            conn.sendall(b"refused request\n")
            return 1
        conn.sendall((perform(*request) + "\n").encode("ascii"))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
