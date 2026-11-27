"""No network or custody tools are used by these safety controls."""

import base64
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import nacl.signing
import pytest

SCRIPT = Path(
    os.environ.get(
        "TOS_SERVICE_TOKEN_DRIVER",
        Path(__file__).parents[1] / "scripts/local-pq-service-token.py",
    )
)
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

        def config(self, param, *, url):
            assert param == 19
            return module.usdc.Builder().int(3, 32).end()

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
            SimpleNamespace(urls=["a", "b", "c", "d", "e", "f"]),
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
            SimpleNamespace(urls=["a", "b", "c", "d", "e", "f"]),
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


@pytest.mark.parametrize("bad", [None, "supply", "references", "sum"])
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
            if bad == "sum" and params.get("address") == ids["actor"]:
                amount += 1
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
    monkeypatch.setattr(
        module, "archived_action", lambda args, state, chain, action: action()
    )
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


@pytest.mark.parametrize("bad", ["root", "file", "global_id", "absent_id"])
def test_endpoint_network_identity_is_on_chain(tmp_path, bad):
    root, file = "11" * 32, "22" * 32
    (tmp_path / "network.json").write_text(
        json.dumps({"global_id": 3, "zerostate_root": root, "zerostate_file": file})
    )

    class Chain:
        validator_urls = ("a", "b", "c")

        def config(self, param, *, url):
            assert param == 19
            if bad == "absent_id" and url == "b":
                return None
            return (
                module.usdc.Builder()
                .int(2 if bad == "global_id" and url == "b" else 3, 32)
                .end()
            )

        def call(self, method, *, url):
            assert method == "getMasterchainInfo"
            return {
                "init": {
                    "root_hash": base64.b64encode(
                        bytes.fromhex(
                            "33" * 32 if bad == "root" and url == "b" else root
                        )
                    ).decode(),
                    "file_hash": base64.b64encode(
                        bytes.fromhex(
                            "44" * 32 if bad == "file" and url == "b" else file
                        )
                    ).decode(),
                }
            }

    with pytest.raises(module.usdc.Refused):
        module.check_network(
            SimpleNamespace(data=tmp_path), Chain(), module.usdc.State(tmp_path)
        )


def test_owner_refuses_an_expired_unaccepted_message(tmp_path, monkeypatch):
    state = module.usdc.State(tmp_path)

    class Chain:
        sends = 0

        def send(self, message):
            self.sends += 1
            pytest.fail("expired message reached broadcast")

        def executed_external(self, *args):
            return None

    chain = Chain()
    owner = module.Owner.__new__(module.Owner)
    owner.chain, owner.address = chain, "0:" + "11" * 32
    owner.seqno = lambda: 4
    state.put_intent(
        "expired",
        {
            "wallet": owner.address,
            "seqno": 4,
            "valid_until": 99,
            "boc": module.usdc.boc64(module.usdc.Builder().end()),
            "expected": {},
            "state": "signed",
            "hash": "ab" * 32,
        },
    )
    monkeypatch.setattr(module.time, "time", lambda: 100)
    with pytest.raises(module.usdc.Refused, match="expired"):
        owner.send_once(state, "expired", lambda: None)
    assert chain.sends == 0


def test_unresolved_owner_send_prevents_a_new_signature(tmp_path):
    state = module.usdc.State(tmp_path)
    owner = module.Owner.__new__(module.Owner)
    owner.address = "0:" + "11" * 32
    state.put_intent("old", {"wallet": owner.address, "state": "signed"})
    owner.seqno = lambda: pytest.fail("unresolved send reached signing")
    with pytest.raises(module.usdc.Refused, match="unresolved owner send"):
        owner.send_once(state, "new", lambda: pytest.fail("built another message"))


def test_second_resolver_uses_nodes_four_to_six(tmp_path, monkeypatch):
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
    seen = []

    def run(args):
        seen.extend(args)
        return json.dumps({"result": "pass", "requests": [{"state": "responded"}]})

    monkeypatch.setattr(module, "run", run)
    module.verify(
        SimpleNamespace(verifier=Path("verifier"), case="responded", operation_args=[]),
        state,
        SimpleNamespace(urls=["a", "b", "c", "d", "e", "f"]),
        None,
    )
    assert seen[seen.index("--rpc") + 1] == "d,e,f"
    provenance = json.loads(
        (tmp_path / "evidence/verify-responded-provenance.json").read_text()
    )
    assert provenance["resolver_endpoints"] == ["d", "e", "f"]
    with pytest.raises(module.usdc.Refused, match="overlap"):
        module.verify(
            SimpleNamespace(
                verifier=Path("verifier"), case="responded", operation_args=[]
            ),
            state,
            SimpleNamespace(urls=["a", "b", "c", "a", "e", "f"]),
            None,
        )


def test_saved_public_receipts_match_their_hashes_and_index():
    import hashlib

    root = Path(__file__).parents[1] / "evidence/service-token-public-20261126"
    index = json.loads((root / "INDEX.json").read_text())
    assert index["complete"] is False
    assert "not captured before pruning" in index["limitation"]
    transactions = 0
    for row in index["files"]:
        path = root / row["file"]
        assert path.resolve().is_relative_to(root.resolve())
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
        if row["kind"] == "transaction-boc":
            transactions += 1
            assert (
                module.usdc.lib.parse_boc(raw).hash().hex() == row["transaction_hash"]
            )
        else:
            assert json.loads(raw)["result"] == "pass"
    assert transactions == 8


def test_all_value_commands_use_the_archive_barrier(tmp_path, monkeypatch):
    import ast

    tree = ast.parse(SCRIPT.read_text())
    main = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"
    )
    guarded = []
    for node in ast.walk(main):
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.comparators[0], ast.Set)
        ):
            values = {
                x.value
                for x in node.test.comparators[0].elts
                if isinstance(x, ast.Constant)
            }
            if "fund" in values:
                assert any(
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "archived_action"
                    for call in ast.walk(node)
                )
                guarded.append(values)
    assert guarded == [
        {
            "fund",
            "fund-refusal-buyer",
            "deploy",
            "call",
            "send",
            "topup",
            "publish",
            "fund-work-buyer",
        }
    ]


def test_verifier_refusal_is_saved_durably_before_it_is_reported(tmp_path, monkeypatch):
    state = module.EvidenceState(tmp_path)
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
        module, "run", lambda *a: '{"result":"fail","reason":"injected refusal"}'
    )
    with pytest.raises(module.usdc.Refused, match="independent verifier"):
        module.verify(
            SimpleNamespace(verifier=Path("verify"), case="monitor", operation_args=[]),
            state,
            SimpleNamespace(urls=["a", "b", "c", "d", "e", "f"]),
            None,
        )
    report = next((tmp_path / "archive/verifiers").glob("*.json"))
    assert json.loads(report.read_text())["reason"] == "injected refusal"
    module.archive.StepJournal(tmp_path / "archive").validate_verifiers()


def test_each_send_is_archived_before_another_send_inside_the_same_step(
    tmp_path, monkeypatch
):
    state = module.EvidenceState(tmp_path)
    state.archive_chain = SimpleNamespace(urls=["a", "b", "c", "d", "e", "f"])
    state.archive_genesis = {"root": "root", "file": "file"}
    captures = []

    class Collector:
        def __init__(self, directory, endpoints, genesis):
            self.directory = directory
            assert endpoints == ["d", "e", "f"]

        def capture_wait(self, roots):
            captures.append(roots)
            module.archive.sync_write(self.directory / "tx.boc", b"transaction")
            return {
                "files": [
                    {"file": "tx.boc", "sha256": module.archive.digest(b"transaction")}
                ]
            }

    monkeypatch.setattr(module.archive, "TransactionArchive", Collector)
    first = {
        "wallet": "0:" + "11" * 32,
        "state": "done",
        "tx": {"lt": 1, "hash": "22" * 32},
    }
    state.put_intent("first", first)
    assert len(captures) == 1
    assert (tmp_path / "archive/sends/first/manifest.json").exists()
    state.put_intent("second", {**first, "tx": {"lt": 2, "hash": "33" * 32}})
    assert len(captures) == 2
    (tmp_path / "archive/sends/first/tx.boc").write_bytes(b"damaged")
    with pytest.raises(module.archive.Refused, match="missing or changed"):
        state.put_intent("third", {**first, "tx": {"lt": 3, "hash": "44" * 32}})
    assert len(captures) == 2


def test_publication_lock_is_private_for_the_provider_runtime(tmp_path, monkeypatch):
    import stat

    state = module.usdc.State(tmp_path)
    directory = tmp_path / "provider-state"
    directory.mkdir(mode=0o700)
    config = tmp_path / "provider.json"
    config.write_text(json.dumps({"state_dir": str(directory)}))
    monkeypatch.setattr(module, "publish_locked", lambda *args: None)
    module.publish(
        SimpleNamespace(provider_runtime=Path("provider"), published_config=config),
        state,
        None,
        None,
    )
    assert stat.S_IMODE((directory / "serve.lock").stat().st_mode) == 0o600


def test_fresh_monitor_evidence_is_complete_and_recheckable():
    import hashlib

    evidence = Path(__file__).parents[1] / "evidence"
    folder = evidence / "service-token-monitor-public-20261127"
    record = json.loads(
        (evidence / "service-token-monitor-local-20261127.json").read_text()
    )
    index = json.loads((folder / "INDEX.json").read_text())
    assert index["complete"] is True
    assert len(record["archive_steps"]) == index["steps"] == 15
    assert len(record["transactions"]) == index["transaction_bocs"] == 35
    crosscheck = record["master_supply_crosscheck"]
    original = (
        json.dumps(crosscheck["observation"], indent=2, sort_keys=True) + "\n"
    ).encode()
    assert hashlib.sha256(original).hexdigest() == crosscheck["original_sha256"]
    assert crosscheck["removed_json_pointers"] == []
    assert len(crosscheck["observation"]["steps"]) == 15
    assert all(
        step["master_supply_atomic"] == step["sum_wallets_atomic"] == 25000000
        for step in crosscheck["observation"]["steps"]
    )
    assert record["provider_final"]["state"] == "acked"
    assert [v["slot_state"] for v in record["injections"]] == ["admitted", "admitted"]
    assert "asset alarm refuses" in record["injections"][0]["refusal_text"]
    assert "monitor report is stale" in record["injections"][1]["refusal_text"]
    for item in record["transactions"]:
        raw = (folder / item["file"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == item["sha256"]
        assert module.usdc.lib.parse_boc(raw).hash().hex() == item["transaction_hash"]
    states = set()
    entries = json.loads((folder / "SANITIZATION.json").read_text())["entries"]
    assert len(entries) == index["verifier_outputs"] == 21
    for entry in entries:
        raw = (folder / entry["archive_file"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["sanitized_sha256"]
        module.archive.verify_citations(evidence, entry)
        output = json.loads(raw)
        if output.get("schema") == "tos-service-verify/token/v1":
            states.update(v["state"] for v in output["requests"])
    # Check the real resolver outputs, independently of any particular schema label.
    for item in record["verifier_outputs"]:
        output = json.loads((folder / item["file"]).read_text())
        if "requests" in output:
            assert output["result"] == "pass"
            states.update(v["state"] for v in output["requests"])
    assert {"pending", "responded"} <= states
    assert all(
        step["invariant"] and step["supply_atomic"] == 25000000
        for step in record["invariants"]["steps"]
    )


def test_historical_gap_does_not_exempt_any_new_or_pending_send(tmp_path, monkeypatch):
    state = module.EvidenceState(tmp_path)
    old = {
        "wallet": "0:" + "11" * 32,
        "state": "done",
        "tx": {"lt": 1, "hash": "22" * 32},
    }
    state.put_intent("historical", old)
    data = tmp_path / "data"
    data.mkdir()
    (data / "network.json").write_text(
        json.dumps({"zerostate_root": "root", "zerostate_file": "file"})
    )
    state.bind_archive(SimpleNamespace(urls=["a", "b", "c", "d", "e", "f"]), data)
    legacy = json.loads((tmp_path / "archive/legacy-before-archive.json").read_text())
    assert legacy["complete"] is False and set(legacy["records"]) == {"historical"}
    state.archive_completed_sends()
    captured = []

    class Collector:
        def __init__(self, directory, endpoints, genesis):
            self.directory = directory

        def capture_wait(self, roots):
            captured.extend(roots)
            raise OSError("injected storage failure")

    monkeypatch.setattr(module.archive, "TransactionArchive", Collector)
    with pytest.raises(OSError, match="storage failure"):
        state.put_intent("new", {**old, "tx": {"lt": 2, "hash": "33" * 32}})
    state.bind_archive(state.archive_chain, data)
    assert set(state.archive_legacy) == {"historical"}
    with pytest.raises(OSError, match="storage failure"):
        state.archive_completed_sends()
    assert len(captured) == 2
    assert all(x["lt"] == 2 for x in captured)
    assert set(state.archive_legacy) == {"historical"}


def test_recover_unsigned_topup_does_not_block_a_new_step(tmp_path):
    state = module.usdc.State(tmp_path)
    state.put_intent("earlier", {"state": "done", "tx": {"hash": "old"}})
    state.archive_completed_sends = lambda: None
    args = SimpleNamespace(
        step="topup",
        case="undeployed",
        operation_args=[],
        destination=None,
        sender_wallet="owner",
        data=tmp_path,
    )

    def refuse():
        raise module.usdc.Refused("wallet is not deployed")

    with pytest.raises(module.usdc.Refused, match="wallet is not deployed"):
        module.archived_action(args, state, None, refuse)
    result = module.recover_archive(args, state, None)
    assert result["outcome"] == "not_sent"
    journal = module.archive.StepJournal(state.root / "archive")
    assert journal.read()["pending"] is None
    assert (
        json.loads((journal.directory / "topup-undeployed/not-sent.json").read_text())[
            "signed_intents_changed"
        ]
        is False
    )


@pytest.mark.parametrize(
    "change", ["signed", "done", "removed", "publish", "already-signed"]
)
def test_recover_without_finished_action_keeps_uncertain_steps_fenced(tmp_path, change):
    state = module.usdc.State(tmp_path)
    state.archive_completed_sends = lambda: None
    state.put_intent("earlier", {"state": "done"})
    if change == "already-signed":
        state.put_intent("earlier", {"state": "signed", "boc": "previous-attempt"})
    args = SimpleNamespace(
        step="publish" if change == "publish" else "topup",
        case="interrupted",
        operation_args=[],
        destination=None,
        sender_wallet="owner",
        data=tmp_path,
    )

    def refuse():
        raise module.usdc.Refused("interrupted")

    with pytest.raises(module.usdc.Refused):
        module.archived_action(args, state, None, refuse)
    if change in ("signed", "done"):
        state.put_intent("new-send", {"state": change})
    elif change == "removed":
        state.data["intents"] = {}
    with pytest.raises(module.archive.Refused, match="resume its original"):
        module.recover_archive(args, state, None)
    assert (
        module.archive.StepJournal(state.root / "archive").read()["pending"] is not None
    )


@pytest.mark.parametrize(
    "fault", [None, "missing", "different", "wrong-block", "wrong-height"]
)
def test_refund_deadline_after_expire_uses_one_checkpoint(tmp_path, fault):
    point = {"seqno": 123, "root_hash": "11" * 32, "gen_utime": 1000}
    view = {"found": False, "read_at": point}

    class Chain:
        validator_urls = ("a", "b", "c")

        def call(self, rpc_method, **kw):
            assert rpc_method == "runGetMethod"
            assert kw["seqno"] == 123 and kw["method"] == "get_refund"
            stack = [
                ["num", "1"],
                ["slice", {}],
                ["num", "1000000"],
                ["num", "200000000"],
                ["num", "100000000"],
                ["num", "1100"],
            ]
            if fault == "missing":
                stack[0] = ["num", "0"]
            if fault == "different" and kw["url"] == "c":
                stack[-1] = ["num", "1101"]
            result = {
                "exit_code": 0,
                "stack": list(reversed(stack)),
                "block_id": {
                    "seqno": 124 if fault == "wrong-height" else 123,
                    "root_hash": base64.b64encode(
                        bytes.fromhex(
                            "22" * 32 if fault == "wrong-block" else "11" * 32
                        )
                    ).decode(),
                },
            }
            return result

    if fault:
        with pytest.raises(module.usdc.Refused):
            module.refund_deadline(Chain(), "actor", "0", view)
    else:
        result = module.refund_deadline(Chain(), "actor", "0", view)
        assert result["found"] and result["refund_claim_deadline"] == 1100
        assert result["read_at"]["gen_utime"] < result["refund_claim_deadline"]
        assert view["found"] is False


@pytest.mark.parametrize("now, sends", [(1000, 0), (1200, 1)])
def test_sweep_preflight_uses_refund_deadline_without_weakening_it(
    tmp_path, monkeypatch, now, sends
):
    state = module.usdc.State(tmp_path)
    state.set("deployment", {"address": "actor"})
    args = SimpleNamespace(
        case="sweep",
        operation_args=["--operation", "sweep-expired-request", "--request-id", "0"],
        sender_wallet="owner",
        step="send",
        tosctl=tmp_path / "tosctl",
    )
    view = {"found": False, "read_at": {"gen_utime": now}}
    monkeypatch.setattr(module, "run", lambda *a, **k: json.dumps(view))
    calls = []

    def refund(*unused):
        calls.append("refund-read")
        return dict(view, found=True, refund_claim_deadline=1100)

    monkeypatch.setattr(module, "refund_deadline", refund)
    monkeypatch.setattr(module, "snapshot", lambda *a: None)
    monkeypatch.setattr(module.time, "sleep", lambda *a: None)
    monkeypatch.setattr(
        module,
        "cli_document",
        lambda *a, **k: {
            "destination": "actor",
            "value_nanotos": "1",
            "body_boc": module.usdc.boc64(module.usdc.Builder().end()),
        },
    )

    class Owner:
        address = "owner"

        def transfer(self, *a, **k):
            calls.append("send")
            return {}

    monkeypatch.setattr(module, "Owner", lambda *a: Owner())
    if sends:
        module.send_operation(args, state, None, {})
    else:
        with pytest.raises(module.usdc.Refused, match="deadline has not arrived"):
            module.send_operation(args, state, None, {})
    assert calls.count("send") == sends
    assert calls[0] == "refund-read"
