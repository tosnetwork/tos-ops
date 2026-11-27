"""The archive supplies cells, never authority or an alternate finalized head."""

import base64
import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = Path(
    os.environ.get(
        "TOS_RETAINED_TRANSACTION_HELPER",
        Path(__file__).parent / "helpers/retained_transactions_rpc.py",
    )
)
SPEC = importlib.util.spec_from_file_location("retained_rpc", PATH)
rpc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rpc)
BOC = (
    ROOT
    / "local/evidence/usdt-recognition/t18/buyer-funded/transactions/393126000001-8b9b77c819a2763c94c3fb7cb939c9fcc52eabc8bc716f4893c213f16dc50fcc.boc"
)
ACCOUNT = "0:d12563503aa251f30884e34e5a4103411fa001198302542c94c4d5bbf6bd89b1"
HASH = "8b9b77c819a2763c94c3fb7cb939c9fcc52eabc8bc716f4893c213f16dc50fcc"


@pytest.fixture
def cells():
    cache = rpc.Cells()
    cache.add(BOC.read_bytes())
    return cache


def query(**change):
    params = {
        "address": ACCOUNT,
        "limit": 10,
        "lt": "393126000001",
        "hash": base64.b64encode(bytes.fromhex(HASH)).decode(),
    }
    params.update(change)
    return {"jsonrpc": "2.0", "id": 7, "method": "getTransactions", "params": params}


def pruned(url, raw):
    return 500, json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "error": {"code": -32603, "message": "lt not in db"},
        }
    ).encode()


def test_archive_retains_exact_cell_and_does_not_invent_a_terminal(cells):
    status, raw, cached = rpc.answer(
        json.dumps(query()).encode(), "unused", cells, transport=pruned
    )
    assert status == 200 and cached
    rows = json.loads(raw)["result"]
    assert len(rows) == 1
    assert base64.b64decode(rows[0]["data"]) == BOC.read_bytes()
    s = rpc.ops.lib.Slice(rpc.ops.lib.parse_boc(base64.b64decode(rows[0]["data"])))
    s.bits(4 + 256 + 64 + 256)
    assert s.bits(64) != 0, "the archived prefix still requires its real predecessor"
    with pytest.raises(ValueError, match="absent"):
        cells.page(query(lt="1")["params"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("hash", base64.b64encode(bytes.fromhex("11" * 32)).decode()),
        ("address", "0:" + "22" * 32),
        ("lt", "393126000002"),
    ],
)
def test_archive_requires_exact_hash_account_and_lt(cells, field, value):
    with pytest.raises(ValueError, match="absent"):
        cells.page(query(**{field: value})["params"])


@pytest.mark.parametrize(
    "change",
    [
        {"limit": 0},
        {"limit": 1001},
        {"lt": "0"},
        {"lt": str(2**64)},
        {"hash": "not base64"},
        {"address": "not-address"},
    ],
)
def test_invalid_page_refuses(cells, change):
    with pytest.raises((ValueError, KeyError)):
        cells.page(query(**change)["params"])


def test_non_pruning_error_never_uses_the_cache(cells):
    body = b'{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"upstream unavailable"}}'
    assert rpc.answer(
        json.dumps(query()).encode(), "unused", cells, transport=lambda *_: (500, body)
    ) == (500, body, False)


def test_http_auth_refusal_is_not_an_archive_lookup(cells):
    body = pruned(None, None)[1]
    assert rpc.answer(
        json.dumps(query()).encode(), "unused", cells, transport=lambda *_: (401, body)
    ) == (401, body, False)


def test_current_state_and_each_upstream_are_forwarded_byte_for_byte(cells):
    raw = b'{"jsonrpc":"2.0","id":1,"method":"getAddressInformation","params":{}}'
    seen = []
    body = b'{"jsonrpc":"2.0", "id":1, "result":{"state":"active"}}'

    def fetch(url, data):
        seen.append((url, data))
        return 200, body

    for upstream in ("node4", "node5", "node6"):
        assert rpc.answer(raw, upstream, cells, transport=fetch) == (200, body, False)
    assert seen == [(u, raw) for u in ("node4", "node5", "node6")]


def test_reference_route_and_unknown_methods_cannot_submit(cells):
    for method in ("sendBoc", "sendBocReturnHash", "sign", "setConfig"):
        raw = json.dumps(dict(query(), method=method)).encode()
        with pytest.raises(ValueError, match="method not permitted"):
            rpc.answer(
                raw,
                "unused",
                cells,
                transport=lambda *_: pytest.fail("refused RPC forwarded"),
            )


def test_explicit_source_route_forwards_a_submission_once_without_fallback(cells):
    seen = []
    raw = json.dumps(dict(query(), method="sendBoc")).encode()

    def source(url, data):
        seen.append((url, data))
        return pruned(None, None)

    result = rpc.answer(raw, "node1", cells, submit=True, transport=source)
    assert seen == [("node1", raw)] and result == (*pruned(None, None), False)


def test_source_transport_error_is_not_retried(cells):
    calls = []

    def source(*args):
        calls.append(args)
        raise OSError("unknown send result")

    with pytest.raises(OSError):
        rpc.answer(
            json.dumps(dict(query(), method="sendBoc")).encode(),
            "node1",
            cells,
            submit=True,
            transport=source,
        )
    assert len(calls) == 1


def test_archive_entry_and_byte_bounds(monkeypatch):
    monkeypatch.setattr(rpc, "MAX_ENTRIES", 0)
    with pytest.raises(ValueError, match="entry bound"):
        rpc.Cells().add(BOC.read_bytes())
    monkeypatch.setattr(rpc, "MAX_ENTRIES", 4096)
    monkeypatch.setattr(rpc, "MAX_BYTES", 1)
    with pytest.raises(ValueError, match="byte bound"):
        rpc.Cells().add(BOC.read_bytes())


@pytest.mark.parametrize(
    "bad",
    [
        "https://example.invalid",
        "http://127.0.0.1:8011?key=x",
        "http://user@127.0.0.1:8011",
        "http://127.0.0.1:8011/other",
    ],
)
def test_only_loopback_rpc_endpoints(bad):
    with pytest.raises(ValueError):
        rpc.endpoint(bad)


@pytest.mark.parametrize("wrong", ["root", "file", "global"])
def test_genesis_and_on_chain_global_id_are_required(monkeypatch, wrong):
    class Node:
        def __init__(self, _):
            pass

        def call(self, method, **params):
            if method == "getMasterchainInfo":
                return {
                    "init": {
                        "root_hash": base64.b64encode(
                            bytes.fromhex(("33" if wrong == "root" else "11") * 32)
                        ).decode(),
                        "file_hash": base64.b64encode(
                            bytes.fromhex(("44" if wrong == "file" else "22") * 32)
                        ).decode(),
                    }
                }
            assert method == "getConfigParam" and params["param"] == 19
            cell = rpc.ops.lib.Cell(
                (2 if wrong == "global" else 3).to_bytes(4, "big"), 32, []
            )
            return {
                "config": {
                    "bytes": base64.b64encode(rpc.ops.lib.serialize_boc(cell)).decode()
                }
            }

    monkeypatch.setattr(rpc.ops, "Node", Node)
    with pytest.raises(ValueError, match="genesis differs|global id 3"):
        rpc.identity("unused", "11" * 32, "22" * 32)
