"""Refusal fixtures never select a network or asset through a recognition bypass."""

import base64
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/local-token-refusal.py"
spec = importlib.util.spec_from_file_location("local_refusal", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.mark.parametrize("global_id", [2, -3, 0])
def test_refusal_driver_refuses_nonlocal_before_any_send(tmp_path, global_id):
    root, file = "11" * 32, "22" * 32
    (tmp_path / "network.json").write_text(
        json.dumps(
            {"global_id": global_id, "zerostate_root": root, "zerostate_file": file}
        )
    )

    class Chain:
        validator_urls = ("a", "b", "c")

        def call(self, *a, **kw):
            raise AssertionError("must refuse before any RPC")

    with pytest.raises(module.u.Refused, match="only local global id"):
        module.local_only(
            SimpleNamespace(data=tmp_path, approved_genesis=root),
            Chain(),
            module.u.State(tmp_path),
        )


def test_refusal_driver_requires_approved_genesis_and_each_peer(tmp_path):
    root, file = "11" * 32, "22" * 32
    (tmp_path / "network.json").write_text(
        json.dumps({"global_id": 3, "zerostate_root": root, "zerostate_file": file})
    )

    class Chain:
        validator_urls = ("a", "b", "c")

        def config(self, param, *, url):
            assert param == 19
            return module.u.Builder().int(3, 32).end()

        def call(self, *a, url, **kw):
            return {
                "init": {
                    "root_hash": base64.b64encode(bytes.fromhex(root)).decode(),
                    "file_hash": base64.b64encode(bytes.fromhex(file)).decode(),
                }
            }

    state = module.u.State(tmp_path)
    module.local_only(
        SimpleNamespace(data=tmp_path, approved_genesis=root), Chain(), state
    )
    assert state.get("network") == {"global_id": 3, "genesis": root}
    with pytest.raises(module.u.Refused, match="approved local genesis"):
        module.local_only(
            SimpleNamespace(data=tmp_path, approved_genesis="33" * 32), Chain(), state
        )

    class Wrong(Chain):
        def call(self, *a, url, **kw):
            result = super().call(*a, url=url, **kw)
            if url == "c":
                result["init"]["root_hash"] = base64.b64encode(bytes(32)).decode()
            return result

    with pytest.raises(module.u.Refused, match="endpoint genesis mismatch"):
        module.local_only(
            SimpleNamespace(data=tmp_path, approved_genesis=root), Wrong(), state
        )


def test_marker_is_visible_in_normal_origin():
    assert bytes.fromhex(module.SOURCE_TOKEN) == b"LOCAL_ONLY_TEST_REFU"
    assert len(bytes.fromhex(module.SOURCE_TOKEN)) == 20
    assert module.LABEL == "LOCAL-ONLY-TEST-REFUSAL-v1"


def test_signing_finishes_before_an_extra_alias_candidate(tmp_path, monkeypatch):
    gov = module.u.governance_module()
    (tmp_path / "network.json").write_text("{}")
    (tmp_path / "testnet-ports.json").write_text(
        json.dumps(
            {
                "nodes": [
                    {"idx": i, "role": "validator" if i < 5 else "candidate"}
                    for i in (1, 2, 3, 4, 7)
                ]
            }
        )
    )
    (tmp_path / "elections").mkdir()
    for i in (1, 2, 3, 4, 7):
        (tmp_path / "elections" / f"console-{i}.private.json").write_text(
            json.dumps(
                {
                    "address": str(i),
                    "client_private_key": {"key": "unused"},
                    "server_public_key": {"key": "unused"},
                }
            )
        )
    monkeypatch.setattr(gov, "config_cell", lambda *a: None)
    monkeypatch.setattr(gov, "validator_count", lambda *a: 4)
    monkeypatch.setattr(gov, "tl_key_file", lambda *a: None)

    seen = []

    def run(argv, **kw):
        index = int(argv[argv.index("-a") + 1])
        seen.append(index)
        Path(argv[-1].split()[-1]).write_bytes(bytes([4 if index == 7 else index]))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(gov.subprocess, "run", run)
    monkeypatch.setattr(
        gov,
        "parse_vote",
        lambda raw, proposal: (
            raw[0] - 1,
            SimpleNamespace(hash=lambda: bytes([raw[0]]) * 32),
        ),
    )
    try:
        votes = gov.sign_local(
            SimpleNamespace(
                local_network=tmp_path / "network.json", rpc="local", console="unused"
            ),
            "11" * 32,
        )
    except gov.lib.TestnetError:
        votes = {}
    assert seen == [1, 2, 3, 4]
    assert set(votes) == {"0", "1", "2", "3"}


@pytest.mark.parametrize("changed", [False, True])
def test_recognition_adds_test_entry_without_replacing_existing(
    tmp_path, monkeypatch, changed
):
    old_dir = tmp_path / "old"
    old_dir.mkdir()
    original = {
        "master": "11" * 32,
        "status": "active",
        "origin": {"source_chain_id": 1},
    }
    (old_dir / "config84-spec.json").write_text(json.dumps({"assets": [original]}))
    old_cell = module.u.Builder().uint(1, 8).end()
    (old_dir / "config84.boc").write_bytes(module.u.lib.serialize_boc(old_cell))
    root = tmp_path / "new"
    root.mkdir(mode=0o700)
    state = module.u.State(root)
    state.set("mint", {"minter": "0:" + "22" * 32})
    state.set(
        "tvm",
        {
            "bridge": "-1:" + "33" * 32,
            "minter_code_hash": "44" * 32,
            "wallet_code_hash": "55" * 32,
        },
    )

    def build(argv, **kwargs):
        Path(argv[argv.index("--out") + 1]).write_bytes(
            module.u.lib.serialize_boc(module.u.Builder().uint(2, 8).end())
        )
        return "{}"

    monkeypatch.setattr(module.service, "run", build)
    monkeypatch.setattr(module, "preflight_registration", lambda *a: None)
    monkeypatch.setattr(
        module.u, "node_release_evidence", lambda *a: root / "release.json"
    )
    calls = []

    def adopt(args, state, chain, tools, param, boc, extra):
        calls.append(param)
        return {"param": param}

    monkeypatch.setattr(module.u, "adopt", adopt)

    class Chain:
        def config(self, param):
            assert param == 84
            return module.u.Builder().uint(3, 8).end() if changed else old_cell

    args = SimpleNamespace(bridge_state=old_dir, tosctl=Path("cli"), data=tmp_path)
    if changed:
        with pytest.raises(module.u.Refused, match="changed outside"):
            module.recognize(args, state, Chain(), None)
        assert not calls
    else:
        module.recognize(args, state, Chain(), None)
        built = json.loads((root / "config84-local-only-test-spec.json").read_text())
        assert built["assets"][0] == original
        assert len(built["assets"]) == 2
        assert built["assets"][1]["origin"]["source_token"] == module.SOURCE_TOKEN
        assert built["assets"][1]["wallet_code_hash"] == "55" * 32
        assert calls == [84]


@pytest.mark.parametrize(
    "registered,balance,refused",
    [(False, 111, False), (False, 109, True), (True, 0, False)],
)
def test_quote_precedes_any_proposal_plan(
    tmp_path, monkeypatch, registered, balance, refused
):
    cell = module.u.Builder().uint(1, 8).end()
    gov = SimpleNamespace(
        proposal_cell=lambda *a: cell,
        status=lambda *a: {} if registered else None,
        parse_vote_setup=lambda *a: {"min_store_sec": 5},
        proposal_price=lambda *a: 100,
        REGISTER_HEADROOM=5,
        ops=SimpleNamespace(FEE_ALLOWANCE_NANOTOS=5),
        elections=SimpleNamespace(address_from_file=lambda *a: "payer"),
    )
    monkeypatch.setattr(module.u, "governance_module", lambda: gov)
    chain = SimpleNamespace(
        url="local", config=lambda *a: cell, balance=lambda *a: balance
    )
    state = SimpleNamespace(root=tmp_path)
    if refused:
        with pytest.raises(module.u.Refused, match="fund before planning"):
            module.preflight_registration(None, state, chain, cell)
    else:
        module.preflight_registration(None, state, chain, cell)


def test_occupied_slot_refuses_before_staging_or_funding(tmp_path, monkeypatch):
    state = module.u.State(tmp_path)

    def staged(*a):
        raise AssertionError("must refuse before staging or funding")

    monkeypatch.setattr(module, "build", staged)
    chain = SimpleNamespace(config=lambda *a: module.u.Builder().uint(1, 8).end())
    with pytest.raises(module.u.Refused, match="occupied by another namespace"):
        module.namespace(None, state, chain, None)


@pytest.mark.parametrize(
    "status", ["planned", "signed", "broadcast", "settled", "failed"]
)
def test_source_payer_open_operations_are_never_bypassed(tmp_path, monkeypatch, status):
    journal = SimpleNamespace(for_wallet=lambda *a: [{"state": status}])
    gov = SimpleNamespace(ops=SimpleNamespace(Journal=lambda *a: journal))
    monkeypatch.setattr(module.u, "governance_module", lambda: gov)
    state = module.u.State(tmp_path)
    args = SimpleNamespace(ceremony=tmp_path)
    if status in ("planned", "signed", "broadcast"):
        with pytest.raises(module.u.Refused, match="open operation"):
            module.require_original_payer_clear(args, state, "payer")
    else:
        module.require_original_payer_clear(args, state, "payer")


def test_test_namespace_has_a_reserved_local_source_chain_id(tmp_path):
    assert module.TEST_SOURCE_CHAIN_ID == int.from_bytes(b"LOCALT10", "big")
    assert module.TEST_SOURCE_CHAIN_ID > 2**32
    state = module.u.State(tmp_path)
    state.set("evm", {"chain_id": 56})
    with pytest.raises(module.u.Refused, match="legacy test chain id"):
        module.namespace(None, state, None, None)


def test_marker_cannot_choose_the_wallet_code_hash(tmp_path, monkeypatch):
    import hashlib

    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    output = root / "local-only-test-build"
    output.mkdir()
    wallet = b"controlled staged source"
    for name in ("token-wallet-local-only-test.fc", "token-wallet.fc"):
        (output / name).write_bytes(wallet)
    marker = {
        "label": module.LABEL,
        "global_id": 3,
        "wallet_code_hash": "00" * 32,
        "wallet_source_sha256": hashlib.sha256(wallet).hexdigest(),
    }
    (output / "LOCAL-ONLY-TEST.json").write_text(json.dumps(marker))
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    for name in ("new-bridge.fif", "new-multisig.fif"):
        (contracts / name).write_text("")
    tools = SimpleNamespace(contracts=contracts, func=Path("func"))
    monkeypatch.setattr(
        module.service,
        "run",
        lambda *a, **kw: pytest.fail("unverified marker reached compilation"),
    )
    with pytest.raises(module.u.Refused, match="marker code hash"):
        module.build(SimpleNamespace(), module.u.State(root), None, tools)


def test_wallet_pin_matches_the_real_accepted_build():
    record = json.loads(
        (
            Path(__file__).parents[1]
            / "evidence/service-token-returned-local-20261126.json"
        ).read_text()
    )
    assert module.TEST_WALLET_CODE_HASH == record["code_hashes"]["token-wallet"]
