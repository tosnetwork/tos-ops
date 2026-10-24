"""The setup port admission must refuse a live node port and accept a TIME-WAIT.

The loop is taken verbatim from setup-testnet.sh; only its port list is replaced.
"""

import re
import socket
import time
from pathlib import Path

import pytest

SETUP = Path(__file__).resolve().parents[1] / "scripts" / "setup-testnet.sh"


def admission(port: int):
    text = SETUP.read_text()
    match = re.search(r"^for port in \[.*?\]:\n(?:    .*\n)+", text, re.M)
    assert match, "port admission loop not found in setup-testnet.sh"
    loop = re.sub(r"\[.*?\]", f"[{port}]", match.group(0), count=1)
    exec(loop, {"socket": socket})


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def engine_listener(port: int) -> socket.socket:
    # The engine's TCP listener sets both options (tdutils ServerSocketFd).
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("127.0.0.1", port))
    s.listen()
    return s


def test_time_wait_left_by_a_stopped_listener_is_admitted():
    port = free_port()
    server = engine_listener(port)
    client = socket.create_connection(("127.0.0.1", port))
    accepted, _ = server.accept()
    accepted.close()  # the listener's side closes first and keeps the TIME-WAIT
    time.sleep(0.2)
    client.close()
    server.close()
    with socket.socket() as plain:
        with pytest.raises(OSError):
            plain.bind(("127.0.0.1", port))  # the state this admission must tolerate
    admission(port)


def test_live_tcp_listener_is_refused():
    port = free_port()
    with engine_listener(port):
        with pytest.raises(OSError):
            admission(port)


def test_live_udp_socket_is_refused():
    port = free_port()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as node:
        node.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # as the engine does
        node.bind(("127.0.0.1", port))
        with pytest.raises(OSError):
            admission(port)
