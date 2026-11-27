"""The local client cannot turn a retry into another prepared purchase."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

p = Path(__file__).parents[1] / "scripts/local-pq-service-token-buyer.py"
spec = importlib.util.spec_from_file_location("token_buyer", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture(tmp_path):
    offer, archive = tmp_path / "offer.json", tmp_path / "source.tar"
    offer.write_text(json.dumps({"capability_id": "cap", "version": "1.0.0"}))
    archive.write_bytes(b"canonical archive supplied by the SDK")
    return SimpleNamespace(
        step="prepare",
        case="sample_case",
        offer=offer,
        archive=archive,
        socket=Path("/run/agent.sock"),
        state=tmp_path / "state",
    )


def test_repeated_prepare_never_creates_another_purchase(tmp_path, monkeypatch):
    args = fixture(tmp_path)
    calls = []

    def call(_socket, method, params):
        calls.append((method, params))
        disk = json.loads((args.state / "sample_case.json").read_text())
        assert disk["identity"]["archive_hash"]
        return (
            {"quote_id": "quote"} if method == "quote" else {"request_hash": "request"}
        )

    monkeypatch.setattr(m, "call", call)
    assert m.execute(args) == {"request_hash": "request"}
    assert m.execute(args) == {"request_hash": "request"}
    assert [v[0] for v in calls] == ["quote", "prepare"]
    args.archive.write_bytes(b"different")
    with pytest.raises(m.Refused, match="different offer"):
        m.execute(args)
    assert len(calls) == 2


def test_lost_prepare_reply_reuses_quote_and_idempotency_key(tmp_path, monkeypatch):
    args = fixture(tmp_path)
    requests = []
    quotes = []

    def call(_socket, method, params):
        if method == "quote":
            quotes.append(method)
            return {"quote_id": "quote" + str(len(quotes))}
        requests.append(params)
        if len(requests) == 1:
            raise OSError("lost reply before any confirmation")
        return {"request_hash": "request"}

    monkeypatch.setattr(m, "call", call)
    with pytest.raises(OSError):
        m.execute(args)
    assert m.execute(args) == {"request_hash": "request"}
    assert requests[0] == requests[1]


def test_client_requests_payment_but_cannot_confirm(tmp_path, monkeypatch):
    args = fixture(tmp_path)
    monkeypatch.setattr(
        m,
        "call",
        lambda _p, method, _v: (
            {"quote_id": "quote"} if method == "quote" else {"request_hash": "request"}
        ),
    )
    m.execute(args)
    args.step = "request-payment"
    called = []
    monkeypatch.setattr(
        m,
        "call",
        lambda p, method, params: (
            called.append((method, params)) or {"state": "prepared"}
        ),
    )
    assert m.execute(args) == {"state": "prepared"}
    assert called == [
        ("request_payment", {"request_hash": "request", "wait_seconds": 0})
    ]
