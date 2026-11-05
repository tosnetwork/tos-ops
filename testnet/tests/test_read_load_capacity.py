"""Actual loopback HTTP, no real RPC, wallet, keys or value operations."""

import base64
import http.server
import json
import threading
import time

import pytest
import read_client
import sustained_read_load as load


def packet(duration=6):
    return {
        "duration_seconds": duration,
        "requests_per_second": 8,
        "window_seconds": duration,
        "endpoints": list(read_client.ENDPOINTS),
        "address": "0:ce32c0cfd54873d65fdd4b8b1710605ae2176734a1015d2d2c1ea00d8025f15a",
    }


@pytest.fixture
def slow_rpc(monkeypatch):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            time.sleep(0.6)  # Valid p95/p99, but four workers cannot sustain8rps.
            initial = {
                "workchain": -1,
                "seqno": 0,
                "root_hash": base64.b64encode(
                    bytes.fromhex(
                        "ff60459cb8a51708548290afa16fd4df80d16775bf3c13392146a6d1b5662d57"
                    )
                ).decode(),
                "file_hash": base64.b64encode(
                    bytes.fromhex(
                        "3b374df5ebd18368d4bf0eb374704771daf8dacd85175605f3bfd1c7a922a039"
                    )
                ).decode(),
            }
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"init": initial}}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01))
    thread.start()
    # Logical topology remains frozen; only test transport addresses are replaced.
    monkeypatch.setattr(
        read_client, "ENDPOINTS", dict.fromkeys(read_client.ENDPOINTS, server.server_port)
    )
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_allowed_rpc_latency_does_not_make_sender_drop_declared_rate(tmp_path, slow_rpc):
    result = load.run(packet(), tmp_path / "run")
    assert result["status"] == "DECLARED_READ_LOAD_WINDOWS_COMPLETE"
    window = json.loads((tmp_path / "run/WINDOW-0000.json").read_text())
    assert window["errors"] == 0
    assert window["p95_upper_seconds"] <= 2 and window["p99_upper_seconds"] <= 5
    assert window["completed"] >= 44  # 90% of48 actual requests, no threshold relaxation.
    assert window["offered_fraction"] >= 0.9 and window["pass"] is True
    rows = [json.loads(line) for line in (tmp_path / "run/requests.jsonl").read_text().splitlines()]
    assert len(rows) == result["completed"] == window["completed"]
    assert all(r["finished_monotonic_seconds"] >= r["offered_monotonic_seconds"] for r in rows)


def test_reverting_to_four_workers_still_fails_fixed_rate_threshold(
    tmp_path, slow_rpc, monkeypatch
):
    monkeypatch.setattr(load, "worker_budget", lambda _rate: 4)
    with pytest.raises(RuntimeError, match="Declared read-window criteria failed"):
        load.run(packet(), tmp_path / "run")
    report = json.loads((tmp_path / "run/WINDOW-0000.json").read_text())
    assert not report["pass"] and report["offered_fraction"] < 0.9
    assert report["errors"] == 0
    assert report["p95_upper_seconds"] <= 2 and report["p99_upper_seconds"] <= 5


@pytest.mark.parametrize("rate", [True, 0, -1, 17, 1.5])
def test_invalid_worker_rate_never_allocates_unbounded_threads(rate):
    with pytest.raises(RuntimeError, match="Read worker rate bound"):
        load.worker_budget(rate)


def test_network_budget_change_cannot_silently_allocate_over48_workers(monkeypatch):
    monkeypatch.setattr(load, "NETWORK_DEADLINE_SECONDS", 100)
    with pytest.raises(RuntimeError, match="Read worker budget exceeds48"):
        load.worker_budget(16)


def test_maximum_declared_rate_fits_the_hard_worker_bound():
    assert 1 <= load.worker_budget(16) <= 48
