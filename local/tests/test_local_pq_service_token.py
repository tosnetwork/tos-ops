"""No network or custody tools are used by these safety controls."""

import base64
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import nacl.signing
import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/local-pq-service-token.py"
spec = importlib.util.spec_from_file_location("service_token", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_network_pins_are_checked_before_reuse(tmp_path):
    root, file = "11" * 32, "22" * 32
    (tmp_path / "network.json").write_text(
        json.dumps({"global_id": 3, "zerostate_root": root, "zerostate_file": file})
    )

    class Chain:
        validator_urls = ("node-a", "node-b", "node-c")

        def call(self, method, *, url):
            return {
                "init": {
                    "root_hash": base64.b64encode(bytes.fromhex(root)).decode(),
                    "file_hash": base64.b64encode(bytes.fromhex(file)).decode(),
                }
            }

    state = module.usdc.State(tmp_path)
    state.set("network", {"genesis": root})
    module.check_network(SimpleNamespace(data=tmp_path), Chain(), state)
    state.set("network", {"genesis": "33" * 32})
    with pytest.raises(module.usdc.Refused, match="another genesis"):
        module.check_network(SimpleNamespace(data=tmp_path), Chain(), state)


def test_document_id_cannot_change_its_meaning(tmp_path):
    state = module.usdc.State(tmp_path)
    state.set("owner", "owner")
    state.set(
        "op-command",
        {"kind": "send", "args": ["--token-amount", "1"], "sender": "owner"},
    )
    state.set("op-document", {"body_hash": "old"})
    assert (
        module.cli_document(None, state, None, "op", "send", "--token-amount", "1")[
            "body_hash"
        ]
        == "old"
    )
    with pytest.raises(module.usdc.Refused, match="different inputs"):
        module.cli_document(None, state, None, "op", "send", "--token-amount", "2")


@pytest.mark.parametrize("subwallet", [42, 0x55534443])
@pytest.mark.parametrize("delivered", [True, False])
def test_owner_journals_exact_message_and_does_not_repeat(
    tmp_path, delivered, subwallet
):
    state = module.usdc.State(tmp_path)

    class Chain:
        seq = 0
        sends = 0

        def balance(self, address):
            return 10**12

        def send(self, message):
            self.sends += 1
            record = module.usdc.State(tmp_path).intent("send")
            assert record["hash"] == message.hash().hex()
            assert record["state"] == "signed"
            header = module.usdc.lib.Slice(message.refs[0])
            header.bits(512 + 32)
            assert header.bits(32) == subwallet
            self.seq += 1

        def wait(self, label, predicate):
            assert predicate()

        def executed_external(self, address, message_hash, since):
            record = state.intent("send")
            return {
                "took_effect": True,
                "out": [record["expected"]] if delivered else [],
            }

    chain = Chain()
    owner = module.Owner.__new__(module.Owner)
    owner.chain = chain
    owner.address = "0:" + "11" * 32
    owner.subwallet_id = subwallet
    owner.key = nacl.signing.SigningKey.generate()
    owner.seqno = lambda: chain.seq
    destination = "0:" + "22" * 32
    if delivered:
        owner.transfer(state, "send", destination, 10**9)
        owner.transfer(state, "send", destination, 10**9)
        assert chain.sends == 1
    else:
        with pytest.raises(module.usdc.Refused, match="took the journaled message"):
            owner.transfer(state, "send", destination, 10**9)
        with pytest.raises(module.usdc.Refused, match="took the journaled message"):
            owner.transfer(state, "send", destination, 10**9)
        assert chain.sends == 1


def test_independent_resolver_failure_is_never_a_pass(tmp_path, monkeypatch):
    state = module.usdc.State(tmp_path)
    state.set("deployment", {"address": "actor"})
    (tmp_path / "rail.json").write_text(
        json.dumps(
            {
                "rpc_endpoints": ["a", "b", "c"],
                "registry_code_boc_file": "code",
                "registry_code_hash": "hash",
                "actor_code_hash": "actor-code",
            }
        )
    )
    monkeypatch.setattr(module, "run", lambda *a, **kw: '{"result":"fail"}')
    with pytest.raises(module.usdc.Refused, match="independent verifier"):
        module.verify(
            SimpleNamespace(
                verifier=Path("verifier"), case="responded", operation_args=[]
            ),
            state,
            None,
            None,
        )


@pytest.mark.parametrize(
    "operation", ["expire", "sweep-expired-request", "sweep-returned"]
)
def test_deadline_gate_precedes_signing(tmp_path, monkeypatch, operation):
    state = module.usdc.State(tmp_path)
    state.set("deployment", {"address": "actor"})
    view = {
        "found": True,
        "read_at": {"gen_utime": 100},
        "response_deadline": 200,
        "refund_claim_deadline": 300,
        "return_deadline": 400,
    }
    monkeypatch.setattr(module, "run", lambda *a, **kw: json.dumps(view))
    args = SimpleNamespace(
        case="deadline",
        operation_args=[
            "--operation",
            operation,
            "--id" if operation == "sweep-returned" else "--request-id",
            "1",
        ],
        tosctl=Path("cli"),
        sender_wallet="owner",
        step="send",
    )
    monkeypatch.setattr(
        module, "Owner", lambda *args: pytest.fail("signer reached before the deadline")
    )
    with pytest.raises(module.usdc.Refused, match="deadline has not arrived"):
        module.send_operation(args, state, None, None)
    assert not state.intents()


def test_a_pending_request_is_not_a_completed_lifecycle(tmp_path, monkeypatch):
    state = module.usdc.State(tmp_path)
    state.set("deployment", {"address": "actor"})
    (tmp_path / "rail.json").write_text(
        json.dumps(
            {
                "rpc_endpoints": ["a", "b", "c"],
                "registry_code_boc_file": "code",
                "registry_code_hash": "hash",
                "actor_code_hash": "actor-code",
            }
        )
    )
    monkeypatch.setattr(
        module,
        "run",
        lambda *a, **kw: '{"result":"pass","requests":[{"state":"pending"}]}',
    )
    with pytest.raises(module.usdc.Refused, match="required lifecycle state"):
        module.verify(
            SimpleNamespace(
                verifier=Path("verifier"), case="refunded", operation_args=[]
            ),
            state,
            None,
            None,
        )


@pytest.mark.parametrize("failure", [None, "unbacked", "disagreement"])
def test_snapshot_binds_all_facts_and_checks_backing(tmp_path, failure):
    state = module.usdc.State(tmp_path)
    state.set("deployment", {"address": "actor", "wallet": "wallet"})

    class Chain:
        validator_urls = ("a", "b", "c")

        def call(self, rpc_method, /, *, url, **params):
            if rpc_method == "getMasterchainInfo":
                return {"last": {"seqno": 100}}
            assert params["seqno"] == 98
            if rpc_method == "lookupBlock":
                return {
                    "root_hash": "bad"
                    if failure == "disagreement" and url == "c"
                    else "same"
                }
            if rpc_method == "getAddressInformation":
                return {"state": "active"}
            if params["method"] == "get_token_ledger":
                return {"exit_code": 0, "stack": [["num", "0"]] * 4 + [["num", "1"]]}
            if params["method"] == "get_wallet_data":
                # Other wallet-data fields are slices and must not be parsed as amounts.
                return {
                    "exit_code": 0,
                    "stack": [
                        ["slice", "owner"],
                        ["num", "0" if failure == "unbacked" else "1"],
                    ],
                }
            return {"exit_code": 0, "stack": [["num", "0"]] * 9}

    if failure:
        with pytest.raises(module.usdc.Refused, match="invariant|disagree"):
            module.snapshot(state, Chain(), "snapshot")
    else:
        result = module.snapshot(state, Chain(), "snapshot")
        assert result["wallet_balance_atomic"] == 1
        assert result["rpc_count"] == 3


@pytest.mark.parametrize("change", [None, "recipient", "amount", "kind", "bound"])
def test_owner_audit_requires_the_exact_recovery(tmp_path, monkeypatch, change):
    state = module.usdc.State(tmp_path)
    state.set("owner", "0:" + "11" * 32)
    state.set("deployment", {"address": "actor"})
    monkeypatch.setattr(module, "snapshot", lambda *a: {"checkpoint": 10})
    tid = {"lt": "7", "hash": base64.b64encode(bytes.fromhex("22" * 32)).decode()}

    class Chain:
        validator_urls = ("a", "b", "c")

        def call(self, rpc_method, /, **params):
            if rpc_method == "getAddressInformation":
                assert params["seqno"] == 10
                return {"last_transaction_id": tid}
            return {
                "transactions": [{"transaction_id": tid, "data": "public-cell"}]
                * (64 if change == "bound" else 1)
            }

    decoded = {
        "lt": 7,
        "hash": "22" * 32,
        "took_effect": True,
        "logs": [
            {
                "Outcome": {
                    "Kind": 3 if change == "kind" else 6,
                    "Amount": 1000001 if change == "amount" else 1000000,
                    "Outcome": 0,
                    "Recipient": {
                        "Workchain": 0,
                        "Address": base64.b64encode(
                            bytes.fromhex(
                                ("33" if change == "recipient" else "11") * 32
                            )
                        ).decode(),
                    },
                }
            }
        ],
    }
    monkeypatch.setattr(module, "run", lambda *a, **kw: json.dumps(decoded))
    if change:
        with pytest.raises(
            module.usdc.Refused,
            match="exceeds the bound" if change == "bound" else "outcome is not proven",
        ):
            module.audit_owner(
                SimpleNamespace(fixture=Path("fixture")), state, Chain(), None
            )
    else:
        assert (
            len(
                module.audit_owner(
                    SimpleNamespace(fixture=Path("fixture")), state, Chain(), None
                )
            )
            == 1
        )


@pytest.mark.parametrize("value", ["../outside", "with/slash", "a" * 81])
def test_case_names_cannot_escape_the_evidence_directory(value):
    with pytest.raises(module.argparse.ArgumentTypeError):
        module.case_name(value)


def publication_fixture(tmp_path):
    state = module.usdc.State(tmp_path)
    state.set("owner", "owner")
    state.set("deployment", {"address": "actor", "code_hash": "aa" * 32})
    token = {"actors": [{"address": "actor"}]}
    module.save_document(tmp_path / "rail.json", {"token": token})
    config = {
        "wallet_address": "owner",
        "state_dir": str(tmp_path),
        "network": {
            "network_id": "tos:global-id:3",
            "genesis_root_hash": "sha256:" + "11" * 32,
            "genesis_file_hash": "sha256:" + "22" * 32,
        },
        "agent_id": "agent_" + "33" * 32,
        "actor_code_hash": "tvm-cell-sha256:" + "aa" * 32,
        "registry_code_hash": "tvm-cell-sha256:" + "bb" * 32,
        "tosctl": {"config_path": "custody.json"},
        "packet_controller": "packet",
        "chain_global_config_file": "global.json",
    }
    path = tmp_path / "published.json"
    module.save_document(path, config)
    module.save_document(
        tmp_path / "publication-controller.json",
        {"key_id": "cc" * 32, "public_key": "dd" * 1312},
    )
    args = SimpleNamespace(
        provider_runtime=Path("provider"), published_config=path, tosctl=Path("tosctl")
    )
    return args, state, config


@pytest.mark.parametrize(
    "field,value",
    [
        ("wallet_address", "another"),
        ("actor_code_hash", "changed"),
        ("network", {"network_id": "public"}),
    ],
)
def test_publication_refuses_changed_identity_before_signing(
    tmp_path, monkeypatch, field, value
):
    args, state, config = publication_fixture(tmp_path)
    config[field] = value
    module.save_document(args.published_config, config)

    def forbidden(*_args, **_kwargs):
        pytest.fail("identity refusal reached custody")

    monkeypatch.setattr(module, "run", forbidden)
    with pytest.raises(module.usdc.Refused):
        module.publish(args, state, None, None)


def test_publication_journals_registration_identity_before_its_signature(
    tmp_path, monkeypatch
):
    args, state, config = publication_fixture(tmp_path)
    module.save_document(
        tmp_path / "publication-init.json",
        {"agent_id": config["agent_id"], "agent_address": "agent-address"},
    )
    manifest = tmp_path / "canonical.cbor"
    manifest.write_bytes(b"canonical")
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if "manifest" in argv:
            return json.dumps(
                {"manifest_digest": "sha256:" + "ee" * 32, "path": str(manifest)}
            )
        # The identity and nonces must survive a crash before building the
        # registry signature. The custody process must use its subcommand config.
        saved = module.usdc.State(tmp_path).get("publication")
        assert saved is not None
        assert saved["manifest_digest"] == "sha256:" + "ee" * 32
        assert len(saved["nonce"]) == 64 and len(saved["object_nonce"]) == 64
        assert argv[:4] == ["tosctl", "agent", "--config", "custody.json"]
        raise module.usdc.Refused("stop before registration signature")

    monkeypatch.setattr(module, "run", run)
    with pytest.raises(module.usdc.Refused, match="before registration signature"):
        module.publish(args, state, None, None)
    first = state.get("publication")
    with pytest.raises(module.usdc.Refused, match="before registration signature"):
        module.publish(args, state, None, None)
    assert state.get("publication") == first
    assert len(calls) == 4


def test_work_buyer_destination_cannot_change_on_rerun(tmp_path):
    state = module.usdc.State(tmp_path)
    state.set("work-buyer", "0:" + "11" * 32)
    with pytest.raises(module.usdc.Refused, match="identity changed"):
        module.fund_work_buyer(
            SimpleNamespace(destination="0:" + "22" * 32), state, None, None
        )


def test_work_buyer_cannot_be_masterchain(tmp_path):
    state = module.usdc.State(tmp_path)
    with pytest.raises(module.usdc.Refused, match="basechain"):
        module.fund_work_buyer(
            SimpleNamespace(destination="-1:" + "22" * 32), state, None, None
        )


def test_completed_work_funding_does_not_require_an_unspent_balance(tmp_path):
    state = module.usdc.State(tmp_path)
    destination = "0:" + "22" * 32
    state.set("work-buyer", destination)
    state.put_intent("fund-work-buyer", {"state": "done"})
    state.put_intent("tokens-work-buyer", {"state": "done", "hash": "hash"})
    state.evidence(
        "tokens-work-buyer", {"send": {"hash": "hash"}, "credited_atomic": 3000000}
    )
    # A None chain proves the completed path neither looks at the current
    # balance (which can have been spent) nor makes another transfer.
    module.fund_work_buyer(SimpleNamespace(destination=destination), state, None, None)
    assert (
        json.loads((tmp_path / "evidence/work-buyer-funded.json").read_text())[
            "credited_atomic"
        ]
        == 3000000
    )


def test_publication_refuses_a_running_provider(tmp_path, monkeypatch):
    args, state, _config = publication_fixture(tmp_path)
    monkeypatch.setattr(
        module,
        "publish_locked",
        lambda *args: pytest.fail("active provider reached publication"),
    )
    with (tmp_path / "serve.lock").open("a") as lock:
        module.fcntl.flock(lock, module.fcntl.LOCK_EX)
        with pytest.raises(module.usdc.Refused, match="stop the local provider"):
            module.publish(args, state, None, None)


@pytest.mark.parametrize("bad", [None, "supply", "references"])
def test_supply_audit_is_checkpoint_bound_and_accounts_for_every_wallet(tmp_path, bad):
    state = module.usdc.State(tmp_path)
    state.set("owner", "owner")
    state.set("deployment", {"address": "actor"})
    state.set("work-buyer", "buyer")
    bridge = {
        "mint": {"minter": "master", "balance_atomic": 25},
        "wallets": {"buyer": "original"},
    }
    ids = {
        name: "0:" + f"{i:064x}"
        for i, name in enumerate(("original", "owner", "actor", "buyer"), 1)
    }

    class Chain:
        validator_urls = ("node-a", "node-b", "node-c")

        def get(self, _master, method, address):
            assert method == "get_wallet_address"
            # The test substitutes owner slices below, retaining the real
            # address-cell decoder for returned wallet addresses.
            return [
                (
                    "cell",
                    {
                        "bytes": module.usdc.boc64(
                            module.usdc.Builder().addr(ids[address]).end()
                        )
                    },
                )
            ]

        def call(self, rpc_method, *, url, **params):
            if rpc_method == "getMasterchainInfo":
                return {"last": {"seqno": 100}}
            assert params["seqno"] == 98
            if rpc_method == "lookupBlock":
                return {
                    "seqno": 98,
                    "hash": "other"
                    if bad == "references" and url == "node-c"
                    else "block",
                }
            if rpc_method == "getAddressInformation":
                return {"state": "active"}
            assert rpc_method == "runGetMethod"
            amount = (
                25
                if params["method"] == "get_token_data"
                else (
                    {
                        ids["original"]: 20,
                        ids["owner"]: 2,
                        ids["actor"]: 1,
                        ids["buyer"]: 2,
                    }[params["address"]]
                )
            )
            if bad == "supply" and params["method"] == "get_token_data":
                amount = 26
            return {"exit_code": 0, "stack": [["num", str(amount)]]}

    import unittest.mock

    with unittest.mock.patch.object(
        module.usdc, "slice_of", side_effect=lambda address: address
    ):
        if bad:
            with pytest.raises(module.usdc.Refused):
                module.audit_supply(None, state, Chain(), bridge)
        else:
            module.audit_supply(None, state, Chain(), bridge)
            proof = json.loads((tmp_path / "evidence/token-supply.json").read_text())
            assert proof["supply_atomic"] == 25 and proof["rpc_count"] == 3
            assert sum(proof["balances_atomic"].values()) == 25


def test_audit_follows_short_pages_and_compares_the_reference_cursors():
    class Chain:
        def __init__(self, disagree=False):
            self.calls = []
            self.disagree = disagree

        def call(self, rpc_method, *, url, **params):
            assert rpc_method == "getTransactionsStd"
            self.calls.append((url, params["lt"]))
            if params["lt"] == "20":
                return {
                    "transactions": [
                        {"transaction_id": {"lt": "20", "hash": "a"}, "data": "first"}
                    ],
                    "previous_transaction_id": {
                        "lt": "10",
                        "hash": "other" if self.disagree and url == "c" else "b",
                    },
                }
            return {
                "transactions": [
                    {
                        "transaction_id": {"lt": "10", "hash": "b"},
                        "data": "older receipt",
                    }
                ],
                "previous_transaction_id": {"lt": "0", "hash": ""},
            }

    chain = Chain()
    rows = module.read_audit_rows(
        chain, "actor", {"lt": "20", "hash": "a"}, ["a", "b", "c"]
    )
    assert [r[1] for r in rows] == ["first", "older receipt"]
    assert len(chain.calls) == 6
    with pytest.raises(module.usdc.Refused, match="cursors differ"):
        module.read_audit_rows(
            Chain(True), "actor", {"lt": "20", "hash": "a"}, ["a", "b", "c"]
        )


def test_refusal_fee_topup_requires_the_independently_marked_build(
    tmp_path, monkeypatch
):
    state = module.usdc.State(tmp_path)
    sent = []
    owner = SimpleNamespace(
        address="owner", transfer=lambda *a, **kw: sent.append(a) or {"state": "done"}
    )
    monkeypatch.setattr(module, "Owner", lambda *a: owner)
    bridge = {"mint": {"buyer": "test-buyer"}}
    chain = SimpleNamespace(balance=lambda *a: 4 * module.usdc.NANO)
    with pytest.raises(module.usdc.Refused, match="marked local refusal namespace"):
        module.fund_refusal_buyer(None, state, chain, bridge)
    assert not sent
    bridge["build"] = {"label": "LOCAL-ONLY-TEST-REFUSAL-v1"}
    module.fund_refusal_buyer(None, state, chain, bridge)
    assert sent[0][1:4] == ("fund-refusal-buyer", "test-buyer", 2 * module.usdc.NANO)


@pytest.mark.parametrize("operation", ["claim-refund", "claim-returned"])
def test_shared_destination_flag_reaches_the_actual_send_parser(
    tmp_path, monkeypatch, operation
):
    bridge = tmp_path / "bridge"
    bridge.mkdir(mode=0o700)
    (bridge / "state.json").write_text("{}")
    captured = []
    monkeypatch.setattr(module.usdc, "Chain", lambda *a: None)
    monkeypatch.setattr(module, "check_network", lambda *a: None)
    monkeypatch.setattr(
        module, "send_operation", lambda args, *a: captured.extend(args.operation_args)
    )
    destination = "0:" + "22" * 32
    monkeypatch.setattr(
        "sys.argv",
        [
            str(SCRIPT),
            "send",
            "--state",
            str(tmp_path / "state"),
            "--bridge-state",
            str(bridge),
            "--running-tos",
            str(tmp_path),
            "--tools-tos",
            str(tmp_path),
            "--fixture",
            str(tmp_path / "fixture"),
            "--case",
            "refund",
            "--operation",
            operation,
            "--destination",
            destination,
        ],
    )
    module.main()
    assert captured == ["--operation", operation, "--destination", destination]
