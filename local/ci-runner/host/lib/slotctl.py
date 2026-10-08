"""Root-owned slot control for the CI supervisor.

Socket-activated per connection (Accept=yes): file descriptor 0 is the
connection. Exactly one request is read: "start N", "stop N" or "status N"
with N in 1..3, from the supervisor account only (checked with SO_PEERCRED).
Only the matched verb and digit reach the systemctl command line.
"""

from __future__ import annotations

import pwd
import re
import select
import socket
import struct
import subprocess
import sys

SUPERVISOR = "tos-ci"
REQUEST = re.compile(r"^(start|stop|status) ([123])\n$")
MAX_LINE = 64
READ_DEADLINE = 2.0


def parse(line: bytes) -> tuple[str, str] | None:
    """The verb and slot of a well-formed request, or None."""
    if len(line) > MAX_LINE:
        return None
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        return None
    match = REQUEST.fullmatch(text)
    return (match.group(1), match.group(2)) if match else None


def peer_uid(conn: socket.socket) -> int:
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def read_line(conn: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n") and len(data) <= MAX_LINE:
        ready, _, _ = select.select([conn], [], [], READ_DEADLINE)
        if not ready:
            break
        chunk = conn.recv(MAX_LINE + 1 - len(data))
        if not chunk:
            break
        data += chunk
    return data


def run(verb: str, slot: str) -> str:
    unit = f"tos-ci-vm@{slot}.service"
    if verb == "status":
        active = subprocess.run(
            ["systemctl", "is-active", unit], capture_output=True, text=True, timeout=10
        ).stdout.strip()
        pid = subprocess.run(
            ["systemctl", "show", "-p", "MainPID", "--value", unit],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        return f"{active or 'unknown'} {pid if pid.isdigit() else 0}"
    result = subprocess.run(
        ["systemctl", verb, unit], capture_output=True, text=True, timeout=180
    )
    return "ok" if result.returncode == 0 else f"error {result.returncode}"


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
        conn.sendall((run(*request) + "\n").encode("ascii"))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
