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


@pytest.mark.parametrize("delivered", [True, False])
def test_owner_journals_exact_message_and_does_not_repeat(tmp_path, delivered):
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


@pytest.mark.parametrize("operation", ["expire", "sweep-expired-request"])
def test_deadline_gate_precedes_signing(tmp_path, monkeypatch, operation):
    state = module.usdc.State(tmp_path)
    state.set("deployment", {"address": "actor"})
    view = {
        "found": True,
        "read_at": {"gen_utime": 100},
        "response_deadline": 200,
        "refund_claim_deadline": 300,
    }
    monkeypatch.setattr(module, "run", lambda *a, **kw: json.dumps(view))
    args = SimpleNamespace(
        case="deadline",
        operation_args=["--operation", operation, "--request-id", "1"],
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
            match="history exceeds" if change == "bound" else "outcome is not proven",
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
