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


@pytest.mark.parametrize("actual", ["00" * 32, module.TEST_WALLET_CODE_HASH])
def test_compiled_wallet_must_match_the_pin(tmp_path, monkeypatch, actual):
    import hashlib

    output = tmp_path / "local-only-test-build"
    output.mkdir()
    wallet = b"staged fixture source"
    for name in ("token-wallet-local-only-test.fc", "token-wallet.fc"):
        (output / name).write_bytes(wallet)
    (output / "LOCAL-ONLY-TEST.json").write_text(
        json.dumps(
            {
                "label": module.LABEL,
                "global_id": 3,
                "wallet_code_hash": module.TEST_WALLET_CODE_HASH,
                "wallet_source_sha256": hashlib.sha256(wallet).hexdigest(),
            }
        )
    )
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    for name in ("new-bridge.fif", "new-multisig.fif"):
        (contracts / name).write_text("")
    monkeypatch.setattr(module.service, "run", lambda *a, **kw: "")
    tools = SimpleNamespace(
        contracts=contracts,
        func=Path("func"),
        fift_run=lambda root, name: (
            "HASH "
            + (actual if name == "hash-local-only-test-token-wallet.fif" else "11" * 32)
        ),
    )
    state = module.u.State(tmp_path)
    if actual == module.TEST_WALLET_CODE_HASH:
        _, hashes = module.build(SimpleNamespace(), state, None, tools)
        assert hashes["token-wallet"] == actual
        assert state.get("build")["code_hashes"] == hashes
    else:
        with pytest.raises(
            module.u.Refused, match="compiled test wallet code hash differs"
        ):
            module.build(SimpleNamespace(), state, None, tools)
        assert state.get("build") is None


def test_fresh_refusal_origin_builds_and_preflights_without_value_movement(
    tmp_path, monkeypatch
):
    import os

    cli = os.environ.get("TOS_SERVICE_TOSCTL")
    if not cli:
        pytest.skip("set TOS_SERVICE_TOSCTL to the pinned CLI for the real builder")
    assert module.TEST_SOURCE_CHAIN_ID == 56
    assert 0 <= module.TEST_SOURCE_CHAIN_ID < 2**32
    bridge_state = tmp_path / "original"
    bridge_state.mkdir()
    # The original CP84 entry is retained, while the fresh namespace is added.
    spec = {
        "assets": [
            {
                "master": "11" * 32,
                "status": "active",
                "decimals": 6,
                "minter_code_hash": "44" * 32,
                "wallet_code_hash": "55" * 32,
                "max_liability_per_actor": "10000000",
                "origin": {
                    "kind": "token_bridge",
                    "bridge_address": "33" * 32,
                    "source_chain_id": 56,
                    "source_token": "66" * 20,
                },
            }
        ]
    }
    original_spec = bridge_state / "config84-spec.json"
    original_spec.write_text(json.dumps(spec))
    original_boc = bridge_state / "config84.boc"
    module.service.run(
        [
            cli,
            "vote",
            "offer",
            "settlement-assets",
            "build",
            "--spec",
            str(original_spec),
            "--out",
            str(original_boc),
        ]
    )
    old = module.u.lib.parse_boc(original_boc.read_bytes())
    root = tmp_path / "fresh"
    root.mkdir(mode=0o700)
    state = module.u.State(root)
    state.set("mint", {"minter": "0:" + "22" * 32})
    state.set(
        "tvm",
        {
            "bridge": "-1:" + "77" * 32,
            "minter_code_hash": "44" * 32,
            "wallet_code_hash": module.TEST_WALLET_CODE_HASH,
        },
    )
    (root / "keys").mkdir(mode=0o700)
    (root / "keys/payer.addr").write_bytes(
        bytes.fromhex("88" * 32) + bytes.fromhex("ffffffff")
    )
    gov = module.u.governance_module()
    monkeypatch.setattr(gov, "status", lambda *a: None)
    monkeypatch.setattr(module.u, "governance_module", lambda: gov)
    cp11 = module.u.lib.parse_boc(
        (
            Path(__file__).parents[2] / "testnet/tests/data/governance/cp11.boc"
        ).read_bytes()
    )
    checks = []

    class Chain:
        url = "unused-local-read"

        def config(self, param):
            assert param in (84, 11)
            return old if param == 84 else cp11

        def balance(self, address):
            assert address == "-1:" + "88" * 32
            checks.append("quoted-payer-balance")
            return 1000 * module.u.NANO

    monkeypatch.setattr(
        module.u, "node_release_evidence", lambda *a: root / "release.json"
    )

    def no_broadcast(args, state, chain, tools, param, boc, extra):
        # This is the first value-moving boundary: stop before proposal/signing.
        assert checks == ["quoted-payer-balance"]
        assert param == 84
        entries = gov.decode_settlement_assets(module.u.lib.parse_boc(boc.read_bytes()))
        origin = entries["22" * 32]["origin"]
        assert origin["source_chain_id"] == 56
        assert origin["source_token"] == module.SOURCE_TOKEN
        assert entries["22" * 32]["wallet_code_hash"] == module.TEST_WALLET_CODE_HASH
        assert entries["11" * 32] == gov.decode_settlement_assets(old)["11" * 32]
        checks.append("build-and-preflight-complete-no-send")
        return {"not_sent": True}

    monkeypatch.setattr(module.u, "adopt", no_broadcast)
    module.recognize(
        SimpleNamespace(bridge_state=bridge_state, tosctl=Path(cli), data=tmp_path),
        state,
        Chain(),
        None,
    )
    assert checks == ["quoted-payer-balance", "build-and-preflight-complete-no-send"]
