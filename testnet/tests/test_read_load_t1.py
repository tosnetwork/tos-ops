"""The T1 profile of sustained_read_load.py (memo public-testnet/T1-PRB-DESIGN-20261110 §3), with a fake request.

The R2 configuration is covered, unchanged, by test_read_load_capacity.py.
"""

import pytest
import read_client
import sustained_read_load as load

ADDRESS = "-1:" + "1e" * 32


def t1_packet(**over):
    p = {
        "profile": "t1",
        "duration_seconds": 2,
        "requests_per_second": 8,
        "window_seconds": 2,
        "endpoints": list(read_client.T1_ENDPOINTS),
        "address": ADDRESS,
        "network_deadline_seconds": 3.0,
    }
    p.update(over)
    return p


@pytest.fixture
def fake_request(monkeypatch):
    calls = []

    def request(endpoint, method, address, deadline):
        calls.append((endpoint, method, address, deadline))
        return {"endpoint": endpoint, "method": method, "latency_seconds": 0.01, "response_bytes": 10, "error": None}
    monkeypatch.setattr(load, "request", request)
    return calls


def test_t1_profile_rotates_over_the_four_validators_with_the_calibrated_deadline(tmp_path, fake_request):
    result = load.run(t1_packet(), tmp_path / "out")
    assert result["status"] == "DECLARED_READ_LOAD_WINDOWS_COMPLETE"
    endpoints = [c[0] for c in fake_request]
    assert set(endpoints) == set(read_client.T1_ENDPOINTS)
    assert endpoints[:4] == list(read_client.T1_ENDPOINTS)
    assert {c[3] for c in fake_request} == {3.0} and {c[2] for c in fake_request} == {ADDRESS}
    assert result["maximum_inflight"] == load.worker_budget_for(8, 3.0) == 28


@pytest.mark.parametrize("over,message", [
    ({"endpoints": list(read_client.T1_ENDPOINTS)[:3]}, "Exact T1 four-validator topology required"),
    ({"endpoints": list(read_client.ENDPOINTS)}, "Exact T1 four-validator topology required"),
    ({"address": "not-an-address"}, "T1 read address must be a raw address"),
    ({"address": "0:" + "AB" * 32}, "T1 read address must be a raw address"),
    ({"network_deadline_seconds": 0.1}, "T1 network deadline bound"),
    ({"network_deadline_seconds": 30}, "T1 network deadline bound"),
    ({"network_deadline_seconds": True}, "T1 network deadline bound"),
    ({"network_deadline_seconds": None}, "T1 network deadline bound"),
    ({"profile": "t2"}, "Unknown read profile"),
])
def test_t1_profile_refuses_anything_unpinned_before_any_request(tmp_path, fake_request, over, message):
    with pytest.raises(RuntimeError, match=message):
        load.run(t1_packet(**over), tmp_path / "out")
    assert fake_request == [] and not (tmp_path / "out").exists()


def test_the_worker_bound_stays_48_for_a_calibrated_deadline():
    assert load.worker_budget_for(16, 2.5) == load.worker_budget(16)
    with pytest.raises(RuntimeError, match="exceeds48"):
        load.worker_budget_for(16, 10.0)
    with pytest.raises(RuntimeError, match="rate bound"):
        load.worker_budget_for(17, 1.0)


def test_request_refuses_a_deadline_outside_its_bounds():
    r = read_client.request(list(read_client.T1_ENDPOINTS)[0], "getMasterchainInfo", ADDRESS, deadline=99)
    assert r["error"] == "ProtocolError"


def test_request_refuses_an_unapproved_endpoint():
    r = read_client.request("http://127.0.0.1:9/jsonRPC", "getMasterchainInfo", ADDRESS)
    assert r["error"] == "ProtocolError"
