"""Real loopback HTTP, synthetic envelopes only: no wallet, key or node calls."""

import contextlib
import http.client
import http.server
import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest

import election_rpc_gate as rpc
from election_send_gate import GateError, SendGate

CONTEXT = dict(
    case="synthetic-http",
    genesis_root="1" * 64,
    genesis_file="2" * 64,
    cli_sha256="3" * 64,
)


def receipt(context, operation):
    return dict(context=context, operation=operation, proof_digest="4" * 64)


class Backend(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.calls.append(request["method"])
        mode = self.server.mode
        if mode == "lost":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.close_connection = True
            return
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request["id"] if mode != "wrong-id" else "foreign",
                "result": {"synthetic": True},
            }
        ).encode()
        try:
            if mode == "drip":
                message = (
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\n\r\n"
                    + body
                )
                for byte in message:
                    self.connection.sendall(bytes([byte]))
                    time.sleep(0.03)
                self.close_connection = True
                return
            if mode == "oversize":
                body = b" " * (rpc.LIMIT + 1 - len(body)) + body
            wire = (
                (f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
                if mode in ("chunked", "ambiguous")
                else body
            )
            self.send_response(200)
            if mode in ("chunked", "ambiguous"):
                self.send_header("Transfer-Encoding", "chunked")
            if mode != "chunked":
                self.send_header("Content-Length", str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)
        except (BrokenPipeError, ConnectionResetError):
            pass


@contextlib.contextmanager
def running(server):
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


@pytest.fixture
def environment(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    backend.calls = []
    backend.mode = "ok"
    with running(backend):
        gate = SendGate(directory, CONTEXT)
        gate.authorize(receipt)
        server = rpc.RPCGate(
            ("127.0.0.1", 0),
            backend.server_port,
            gate,
            total_timeout=1,
            backend_timeout=0.2,
        )
        with running(server):
            yield SimpleNamespace(
                gate=gate, server=server, backend=backend, directory=directory
            )
        gate.close()


def request(server, method="getConfigParam", *, payload=None, path="/jsonRPC"):
    if payload is None:
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": {"boc": "AAAA"} if method in rpc.WRITE_METHODS else {},
            }
        ).encode()
    connection = http.client.HTTPConnection(*server.server_address, timeout=3)
    try:
        connection.request(
            "POST", path, body=payload, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_closed_reads_and_sends_never_reach_backend(environment):
    env = environment
    env.gate.hold()
    assert request(env.server)[0] == 503
    assert request(env.server, "sendBoc")[0] == 503
    assert env.backend.calls == []


@pytest.mark.parametrize("method", sorted(rpc.WRITE_METHODS))
def test_both_write_routes_share_one_durable_latch(environment, method):
    env = environment
    assert request(env.server)[0] == 200
    assert request(env.server, method)[0] == 200
    assert not env.gate.metrics()["admitted"]
    other = next(iter(rpc.WRITE_METHODS - {method}))
    assert request(env.server, other)[0] == 503
    assert request(env.server)[0] == 503
    assert env.backend.calls == ["getConfigParam", method]
    assert env.server.counts["forward_attempts"] == 1


def test_lost_backend_reply_stays_latched_without_retry(environment):
    env = environment
    env.backend.mode = "lost"
    assert request(env.server, "sendBoc")[0] == 503
    env.backend.mode = "ok"
    assert request(env.server, "sendBoc")[0] == 503
    assert request(env.server)[0] == 503
    assert env.backend.calls == ["sendBoc"]
    assert env.gate.metrics()["operation"] == 1


def test_only_explicit_context_bound_confirmation_allows_next_send(environment):
    env = environment
    assert request(env.server, "sendBoc")[0] == 200
    with pytest.raises(GateError):
        env.gate.authorize(
            lambda c, n: dict(context=c, operation=0, proof_digest="4" * 64)
        )
    assert request(env.server)[0] == 503
    env.gate.authorize(receipt)  # Synthetic verifier, not a native confirmation claim.
    assert request(env.server, "sendBoc")[0] == 200
    assert env.backend.calls == ["sendBoc", "sendBoc"]
    assert env.gate.metrics()["operation"] == 2


@pytest.mark.parametrize("mode", ["wrong-id", "ambiguous", "oversize"])
def test_bad_backend_response_closes_admission(environment, mode):
    env = environment
    env.backend.mode = mode
    assert request(env.server)[0] == 503
    env.backend.mode = "ok"
    assert request(env.server, "sendBoc")[0] == 503
    assert env.backend.calls == ["getConfigParam"]


def test_chunked_backend_is_bounded_and_supported(environment):
    env = environment
    env.backend.mode = "chunked"
    status, body = request(env.server)
    assert status == 200 and json.loads(body)["result"]["synthetic"]


def test_backend_drip_is_a_total_deadline_not_a_per_read_timeout(environment):
    env = environment
    env.backend.mode = "drip"
    start = time.monotonic()
    try:
        status = request(env.server)[0]
    except (OSError, http.client.RemoteDisconnected):
        status = None
    assert time.monotonic() - start < 0.8, "whole backend exchange deadline failed"
    assert status == 503
    assert (
        env.backend.calls == ["getConfigParam"] and not env.gate.metrics()["admitted"]
    )


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"jsonrpc":"2.0","id":1,"method":"getConfigParam","params":{},"id":2}',
        b'{"jsonrpc":"2.0","method":"getConfigParam","params":{}}',
        b'{"jsonrpc":"2.0","id":1,"method":"sendMessage","params":{}}',
        b'{"jsonrpc":"2.0","id":1,"method":"sendBoc","params":{"boc":"AAAA","other":1}}',
        b'{"jsonrpc":"2.0","id":1,"method":"getConfigParam","params":{"x":NaN}}',
    ],
)
def test_malformed_or_alternate_write_envelope_never_forwards(environment, body):
    env = environment
    assert request(env.server, payload=body)[0] == 503
    assert env.backend.calls == [] and not env.gate.metrics()["admitted"]


@pytest.mark.parametrize(
    "path", ["/", "/jsonRPC?reset=true", "/authorize", "http://example.invalid/jsonRPC"]
)
def test_no_proxy_or_http_reauthorization_route(environment, path):
    env = environment
    assert request(env.server, path=path)[0] == 503
    assert env.backend.calls == []


def test_ambiguous_frontend_framing_never_forwards(environment):
    env = environment
    with socket.create_connection(env.server.server_address, timeout=2) as connection:
        port = env.server.server_address[1]
        body = json.dumps(
            dict(jsonrpc="2.0", id=1, method="getConfigParam", params={})
        ).encode()
        connection.sendall(
            f"POST /jsonRPC HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\ncontent-length: {len(body)}\r\n\r\n".encode()
            + body
        )
        assert b"503" in connection.recv(4096)
    assert env.backend.calls == []


@pytest.mark.parametrize("body_phase", [False, True])
def test_frontend_drip_cannot_extend_exchange_deadline(environment, body_phase):
    env = environment
    env.server.total_timeout = 0.1
    start = time.monotonic()
    with socket.create_connection(env.server.server_address, timeout=2) as connection:
        if body_phase:
            port = env.server.server_address[1]
            connection.sendall(
                f"POST /jsonRPC HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n".encode()
            )
        for _ in range(30):
            try:
                connection.sendall(b"P")
            except (BrokenPipeError, ConnectionResetError):
                break
            time.sleep(0.025)
    assert time.monotonic() - start < 0.8
    assert env.backend.calls == [] and not env.gate.metrics()["admitted"]


def test_publication_stays_inside_core_read_lock(environment, monkeypatch):
    env = environment
    original = rpc.Handler.publish
    entered, release, attempted, acquired = (threading.Event() for _ in range(4))
    actual_mutex = env.gate._mutex

    class ObservedMutex:
        def __enter__(self):
            sender = threading.current_thread().name == "sender"
            if sender:
                attempted.set()
            result = actual_mutex.__enter__()
            if sender:
                acquired.set()
            return result

        def __exit__(self, *args):
            return actual_mutex.__exit__(*args)

    env.gate._mutex = ObservedMutex()

    def publish(self, body, deadline, status=200):
        entered.set()
        assert release.wait(2)
        return original(self, body, deadline, status)

    monkeypatch.setattr(rpc.Handler, "publish", publish)
    results = []
    client = threading.Thread(target=lambda: results.append(request(env.server)[0]))
    client.start()
    assert entered.wait(2)
    sender = threading.Thread(
        name="sender", target=lambda: env.gate.forward_once(lambda n: None)
    )
    sender.start()
    try:
        assert attempted.wait(2)
        assert not acquired.wait(0.1), "read lock released before HTTP publication"
    finally:
        release.set()
        client.join(2)
        sender.join(2)
    assert acquired.is_set() and results == [200]
    assert not client.is_alive() and not sender.is_alive()


def test_request_budget_saturates_and_stops_forwarding(environment, monkeypatch):
    env = environment
    monkeypatch.setattr(rpc, "MAX_REQUESTS", 2)
    assert request(env.server)[0] == 200 and request(env.server)[0] == 200
    for _ in range(5):
        try:
            assert request(env.server)[0] == 503
        except (BrokenPipeError, ConnectionResetError, http.client.RemoteDisconnected):
            # The budget refuses before consuming another request body. A
            # connection close is allowed; counters/backend and gate state
            # below prove the intended refusal, not just any network error.
            pass
    assert len(env.backend.calls) == 2 and env.server.counts["requests"] == 3
    assert not env.gate.metrics()["admitted"]


def test_only_explicit_loopback_addresses_and_deadlines_are_accepted(environment):
    env = environment
    for address, port in [
        (("0.0.0.0", 0), 1),
        (("localhost", 0), 1),
        (("127.0.0.1", 0), True),
    ]:
        with pytest.raises(rpc.ProtocolError):
            rpc.RPCGate(address, port, env.gate)
    with pytest.raises(rpc.ProtocolError):
        rpc.RPCGate(
            ("127.0.0.1", 0), env.backend.server_port, env.gate, total_timeout=100
        )


def test_new_http_instance_cannot_restore_a_pending_send_permission(environment):
    env = environment
    assert request(env.server, "sendBoc")[0] == 200
    env.gate.close()
    with SendGate(env.directory, CONTEXT) as restored:
        with running(
            rpc.RPCGate(("127.0.0.1", 0), env.backend.server_port, restored)
        ) as server:
            assert request(server)[0] == 503
            assert request(server, "sendBocReturnHash")[0] == 503
            assert restored.metrics()["operation"] == 1
    assert env.backend.calls == ["sendBoc"]
