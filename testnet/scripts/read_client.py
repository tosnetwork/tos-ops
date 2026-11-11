"""One bounded plain-HTTP loopback RPC operation with a total async deadline."""

import asyncio
import base64
import json
import time

# The two R2 sources, then the four validator tunnels of the T1 profile (node-1..4, inventory-bound).
T1_ENDPOINTS = {
    "http://127.0.0.1:18081/jsonRPC": 18081,
    "http://127.0.0.1:38081/jsonRPC": 38081,
    "http://127.0.0.1:28081/jsonRPC": 28081,
    "http://127.0.0.1:48084/jsonRPC": 48084,
}
ENDPOINTS = {
    "http://127.0.0.1:48081/jsonRPC": 48081,
    "http://127.0.0.1:48083/jsonRPC": 48083,
}


def port_of(endpoint):
    """The loopback port of an approved endpoint (R2 or T1), or None."""
    return ENDPOINTS.get(endpoint, T1_ENDPOINTS.get(endpoint))
LIMIT = 1048576
NETWORK_DEADLINE_SECONDS = 2.5
DEADLINE_BOUNDS = (0.5, 10.0)  # a calibrated per-request deadline must lie inside these


class ProtocolError(RuntimeError):
    pass


class NamespaceError(RuntimeError):
    pass


async def exchange(port, payload):
    reader, writer = await asyncio.open_connection("127.0.0.1", port, limit=16384)
    try:
        writer.write(
            (
                f"POST /jsonRPC HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode()
            + payload
        )
        await writer.drain()
        raw = await reader.readuntil(b"\r\n\r\n")
        if len(raw) > 16384:
            raise ProtocolError("header bound")
        lines = raw[:-4].split(b"\r\n")
        status = lines.pop(0).split(b" ")
        if len(status) < 2 or status[0] not in (b"HTTP/1.0", b"HTTP/1.1") or status[1] != b"200":
            raise ProtocolError("HTTP status")
        headers = {}
        for line in lines:
            name, separator, value = line.partition(b":")
            name = name.lower()
            if not separator or name in headers:
                raise ProtocolError("ambiguous headers")
            headers[name] = value.strip()
        transfer, length = (
            headers.get(b"transfer-encoding"),
            headers.get(b"content-length"),
        )
        if transfer is not None and length is not None:
            raise ProtocolError("ambiguous framing")
        body = bytearray()
        if transfer is not None:
            if transfer.lower() != b"chunked":
                raise ProtocolError("unknown transfer framing")
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
                    raise ProtocolError("body bound")
                if amount == 0:
                    trailers = 0
                    while True:
                        line = await reader.readuntil(b"\r\n")
                        trailers += len(line)
                        if trailers > 16384:
                            raise ProtocolError("trailer bound")
                        if line == b"\r\n":
                            break
                    break
                body.extend(await reader.readexactly(amount))
                if await reader.readexactly(2) != b"\r\n":
                    raise ProtocolError("chunk terminator")
        elif length is not None:
            if not length.isdigit() or len(length) > 10 or int(length) > LIMIT:
                raise ProtocolError("length bound")
            body.extend(await reader.readexactly(int(length)))
        else:
            raise ProtocolError("explicit response framing required")
        return bytes(body)
    finally:
        writer.close()


def request(endpoint, method, address, deadline=NETWORK_DEADLINE_SECONDS):
    started = time.monotonic()
    error, size = None, 0
    try:
        if not (type(deadline) in (int, float) and DEADLINE_BOUNDS[0] <= deadline <= DEADLINE_BOUNDS[1]):
            raise ProtocolError("deadline bound")
        if port_of(endpoint) is None or method not in (
            "getMasterchainInfo",
            "getAddressInformation",
            "getTransactions",
        ):
            raise ProtocolError("unapproved request")
        params = {} if method == "getMasterchainInfo" else {"address": address}
        if method == "getTransactions":
            params["limit"] = 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode()

        async def bounded():
            return await asyncio.wait_for(
                exchange(port_of(endpoint), payload), timeout=deadline
            )

        raw = asyncio.run(bounded())
        size = len(raw)
        value = json.loads(raw)
        if value.get("error") is not None or "result" not in value:
            raise ProtocolError("RPC refusal")
        if method == "getMasterchainInfo":
            try:
                initial = value["result"]["init"]
                if (
                    initial["workchain"] != -1
                    or initial["seqno"] != 0
                    or base64.b64decode(initial["root_hash"], validate=True).hex()
                    != "ff60459cb8a51708548290afa16fd4df80d16775bf3c13392146a6d1b5662d57"
                    or base64.b64decode(initial["file_hash"], validate=True).hex()
                    != "3b374df5ebd18368d4bf0eb374704771daf8dacd85175605f3bfd1c7a922a039"
                ):
                    raise ValueError("genesis")
            except (KeyError, ValueError, TypeError) as exc:
                raise NamespaceError("RPC namespace cannot be established") from exc
    except Exception as exc:
        error = type(exc).__name__
    return {
        "endpoint": endpoint,
        "method": method,
        "latency_seconds": time.monotonic() - started,
        "response_bytes": size,
        "error": error,
    }
