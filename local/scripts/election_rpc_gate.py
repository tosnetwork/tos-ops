"""Bounded, serial loopback RPC adapter for an isolated single-producer test.

No native receipt verifier or controller is implemented here. The caller must
prove the backend network, sole producer/endpoint, and exact original settlement
before each SendGate authorization. There is no HTTP authorization/reset route.
Already delivered reads cannot be revoked from another signer.
"""

import asyncio
import json
import re
import socketserver
import time

from election_send_gate import unique_object

LIMIT = 1 << 20
HEADER_LIMIT = 16384
MAX_REQUESTS = 100000
READ_METHODS = frozenset(
    {
        "getMasterchainInfo",
        "getConfigParam",
        "getAddressInformation",
        "getExtendedAddressInformation",
        "getWalletInformation",
        "getAddressBalance",
        "runGetMethod",
        "runGetMethodStd",
        "getTransactions",
        "lookupBlock",
        "getBlockHeader",
    }
)
WRITE_METHODS = frozenset({"sendBoc", "sendBocReturnHash"})


class ProtocolError(ValueError):
    pass


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("whole exchange deadline")
    return value


def headers(raw, response=False):
    lines = raw[:-4].split(b"\r\n")
    first = lines.pop(0).split(b" ")
    if response:
        if (
            len(first) < 2
            or first[0] not in (b"HTTP/1.0", b"HTTP/1.1")
            or first[1] != b"200"
        ):
            raise ProtocolError("backend HTTP refusal")
    elif first not in (
        [b"POST", b"/jsonRPC", b"HTTP/1.0"],
        [b"POST", b"/jsonRPC", b"HTTP/1.1"],
    ):
        raise ProtocolError("unsupported request target")
    result = {}
    for line in lines:
        name, separator, value = line.partition(b":")
        name = name.lower()
        if (
            not separator
            or not re.fullmatch(rb"[a-z0-9!#$%&'*+.^_`|~-]+", name)
            or name in result
        ):
            raise ProtocolError("ambiguous header")
        result[name] = value.strip()
    return result


def request_body(connection, deadline, port):
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        connection.settimeout(remaining(deadline))
        data = connection.recv(min(4096, HEADER_LIMIT + 1 - len(raw)))
        if not data:
            raise ProtocolError("incomplete request header")
        raw.extend(data)
        if b"\r\n\r\n" not in raw and len(raw) >= HEADER_LIMIT:
            raise ProtocolError("request header bound")
    head, body = bytes(raw).split(b"\r\n\r\n", 1)
    if len(head) + 4 > HEADER_LIMIT:
        raise ProtocolError("request header bound")
    values = headers(head + b"\r\n\r\n")
    size = values.get(b"content-length", b"")
    if (
        values.get(b"host") != f"127.0.0.1:{port}".encode()
        or b"transfer-encoding" in values
        or not size.isdigit()
        or len(size) > 10
        or not 0 < int(size) <= LIMIT
    ):
        raise ProtocolError("request framing or host")
    if (
        values.get(b"content-type", b"").split(b";", 1)[0].lower()
        != b"application/json"
    ):
        raise ProtocolError("JSON content type required")
    size = int(size)
    if len(body) > size:
        raise ProtocolError("pipelined request refused")
    body = bytearray(body)
    while len(body) < size:
        connection.settimeout(remaining(deadline))
        data = connection.recv(min(65536, size - len(body)))
        if not data:
            raise ProtocolError("incomplete request body")
        body.extend(data)
    return bytes(body)


def rpc_envelope(body):
    def invalid_constant(_value):
        raise ProtocolError("nonfinite JSON number")

    value = json.loads(
        body, object_pairs_hook=unique_object, parse_constant=invalid_constant
    )
    if (
        type(value) is not dict
        or set(value) != {"jsonrpc", "id", "method", "params"}
        or value["jsonrpc"] != "2.0"
    ):
        raise ProtocolError("single JSONRPC request required")
    identifier = value["id"]
    if not (
        type(identifier) is int
        and 0 <= identifier < 1 << 64
        or type(identifier) is str
        and 1 <= len(identifier) <= 64
    ):
        raise ProtocolError("request id bound")
    method = value["method"]
    if (
        not isinstance(method, str)
        or method not in READ_METHODS | WRITE_METHODS
        or type(value["params"]) is not dict
    ):
        raise ProtocolError("unapproved RPC method or params")
    if method in WRITE_METHODS:
        params = value["params"]
        if (
            set(params) != {"boc"}
            or not isinstance(params["boc"], str)
            or not params["boc"]
            or len(params["boc"]) % 4
            or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", params["boc"])
        ):
            raise ProtocolError("exact encoded send body required")
    return value


async def backend_exchange(port, payload):
    # Whole connect/header/chunk/body lifetime is wrapped by wait_for below.
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, limit=HEADER_LIMIT
    )
    try:
        writer.write(
            (
                f"POST /jsonRPC HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode()
            + payload
        )
        await writer.drain()
        raw = await reader.readuntil(b"\r\n\r\n")
        if len(raw) > HEADER_LIMIT:
            raise ProtocolError("response header bound")
        values = headers(raw, response=True)
        transfer, size = values.get(b"transfer-encoding"), values.get(b"content-length")
        if transfer is not None and size is not None:
            raise ProtocolError("ambiguous backend framing")
        body = bytearray()
        if transfer is not None:
            if transfer.lower() != b"chunked":
                raise ProtocolError("unsupported backend framing")
            while True:
                line = await reader.readuntil(b"\r\n")
                token = line[:-2].split(b";", 1)[0]
                if (
                    len(line) > 128
                    or not 0 < len(token) <= 16
                    or any(c not in b"0123456789abcdefABCDEF" for c in token)
                ):
                    raise ProtocolError("chunk bound")
                amount = int(token, 16)
                if amount > LIMIT - len(body):
                    raise ProtocolError("response body bound")
                if amount == 0:
                    trailers = 0
                    while True:
                        line = await reader.readuntil(b"\r\n")
                        trailers += len(line)
                        if trailers > HEADER_LIMIT:
                            raise ProtocolError("trailer bound")
                        if line == b"\r\n":
                            break
                    break
                body.extend(await reader.readexactly(amount))
                if await reader.readexactly(2) != b"\r\n":
                    raise ProtocolError("chunk terminator")
        elif (
            size is not None
            and size.isdigit()
            and len(size) <= 10
            and int(size) <= LIMIT
        ):
            body.extend(await reader.readexactly(int(size)))
        else:
            raise ProtocolError("explicit bounded framing required")
        return bytes(body)
    finally:
        writer.close()


class RPCGate(socketserver.TCPServer):
    request_queue_size = 8
    allow_reuse_address = False

    def __init__(
        self, address, backend_port, gate, *, total_timeout=5.0, backend_timeout=2.5
    ):
        if (
            type(address) is not tuple
            or len(address) != 2
            or address[0] != "127.0.0.1"
            or type(address[1]) is not int
            or not 0 <= address[1] <= 65535
        ):
            raise ProtocolError("exact loopback listen address required")
        if type(backend_port) is not int or not 1 <= backend_port <= 65535:
            raise ProtocolError("explicit loopback backend port required")
        if any(
            type(t) not in (int, float) or not 0.05 <= t <= 10
            for t in (total_timeout, backend_timeout)
        ):
            raise ProtocolError("bounded total deadlines required")
        self.backend_port, self.gate = backend_port, gate
        self.total_timeout, self.backend_timeout = total_timeout, backend_timeout
        self.counts = dict(requests=0, read_attempts=0, forward_attempts=0, denied=0)
        super().__init__(address, Handler)
        if self.server_address[1] == backend_port:
            self.server_close()
            raise ProtocolError("recursive backend refused")

    def increment(self, field):
        self.counts[field] = min(MAX_REQUESTS + 1, self.counts[field] + 1)

    def handle_error(self, *_args):
        # No request/payload/credential or exception text is logged.
        self.gate.hold()
        self.increment("denied")


class Handler(socketserver.BaseRequestHandler):
    def publish(self, body, deadline, status=200):
        response = (
            f"HTTP/1.1 {status} RPC\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode() + body
        self.request.settimeout(remaining(deadline))
        self.request.sendall(response)

    def handle(self):
        server = self.server
        deadline = time.monotonic() + server.total_timeout
        identifier = None
        server.increment("requests")
        try:
            if server.counts["requests"] > MAX_REQUESTS:
                raise ProtocolError("request budget exhausted")
            body = request_body(self.request, deadline, server.server_address[1])
            envelope = rpc_envelope(body)
            identifier = envelope["id"]
            method = envelope["method"]

            def exchange_and_publish():
                async def bounded():
                    return await asyncio.wait_for(
                        backend_exchange(server.backend_port, body),
                        timeout=min(server.backend_timeout, remaining(deadline)),
                    )

                result = asyncio.run(bounded())
                value = json.loads(result, object_pairs_hook=unique_object)
                if (
                    type(value) is not dict
                    or value.get("jsonrpc") != "2.0"
                    or type(value.get("id")) is not type(identifier)
                    or value["id"] != identifier
                ):
                    raise ProtocolError("backend response identity mismatch")
                self.publish(result, deadline)

            if method in WRITE_METHODS:

                def forward(_operation):
                    server.increment("forward_attempts")
                    return exchange_and_publish()

                server.gate.forward_once(forward)
            else:

                def read():
                    server.increment("read_attempts")
                    return exchange_and_publish()

                server.gate.admitted_read(read)
        except Exception:
            server.gate.hold()
            server.increment("denied")
            # The original native verifier/controller, not this reply, decides
            # settlement. Error responses and client retries never clear a latch.
            error = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "error": {
                        "code": -32091,
                        "message": "isolated admission held; readonly reconciliation required",
                    },
                }
            ).encode()
            try:
                self.publish(error, deadline, status=503)
            except (OSError, TimeoutError):
                pass
