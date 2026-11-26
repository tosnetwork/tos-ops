#!/usr/bin/env python3
"""Journaled token-actor lifecycle checks on the existing local network.

This driver never creates or resets a network. Keys and signed messages stay
in the private --state directory. The bridge and minted balance come from the
existing local-pq-usdc.py run. Each send is bound to an immutable step name.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("local_usdc", HERE / "local-pq-usdc.py")
assert SPEC is not None and SPEC.loader is not None
usdc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(usdc)


def require(ok, detail):
    usdc.require(ok, detail)


def run(argv, *, cwd=None, data=None):
    p = subprocess.run(
        argv,
        input=data,
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=180,
        check=False,
    )
    require(p.returncode == 0, f"{Path(argv[0]).name} refused: {p.stderr[-1800:]}")
    return p.stdout


def prepare(args, state, chain, bridge):
    network = json.loads((args.data / "network.json").read_text())
    require(network["global_id"] == 3, "only local global id 3 is allowed")
    current = chain.account(bridge["mint"]["buyer_token_wallet"])
    wallet_code = usdc.from64(current["code"])
    require(
        wallet_code.hash().hex() == bridge["tvm"]["wallet_code_hash"],
        "T5 wallet code changed",
    )
    keys = usdc.private_dir(state.root / "keys")
    if not (keys / "owner.addr").exists():
        (keys / "gid.fif").write_text("3 constant tos-global-id\n")
        run(
            [
                str(args.running_tos / "build/crypto/fift"),
                "-I",
                f"{args.tools_tos}/crypto/fift/lib:{args.tools_tos}/crypto/smartcont:{keys}",
                "-L",
                str(keys / "gid.fif"),
                "-s",
                str(args.tools_tos / "crypto/smartcont/new-wallet-v3.fif"),
                "0",
                "42",
                "owner",
            ],
            cwd=keys,
        )
    for artifact in keys.iterdir():
        if artifact.is_file():
            artifact.chmod(0o600)
    addr = (keys / "owner.addr").read_bytes()
    require(len(addr) == 36, "invalid owner address artifact")
    owner = f"{int.from_bytes(addr[32:], 'big', signed=True)}:{addr[:32].hex()}"
    code_path = (
        args.tools_tos / "crypto/smartcont/tos-service-actor-token-v1-test.boc.base64"
    )
    inputs = {
        "owner": owner,
        "master": bridge["mint"]["minter"],
        "wallet_code_boc": current["code"],
        "actor_code_boc": code_path.read_text().strip(),
        "price_atomic": "1000000",
        "max_liability_atomic": "10000000",
        "metadata_hash": hashlib.sha256(b"local-token-lifecycle-v1").hexdigest(),
    }
    plan = json.loads(run([str(args.fixture)], data=json.dumps(inputs)))
    if state.get("deployment"):
        require(state["deployment"] == plan, "the prepared actor identity changed")
    else:
        state.set("deployment", plan)
        state.set("owner", owner)
        state.set("inputs", inputs)
        state.set("network", {"global_id": 3, "genesis": network["zerostate_root"]})
    state.evidence(
        "prepared",
        {
            "owner": owner,
            "actor": plan["address"],
            "wallet": plan["wallet"],
            "code_hash": plan["code_hash"],
        },
    )


def fund(args, state, chain, bridge):
    require(state.get("deployment"), "run prepare first")
    owner = state["owner"]
    deployer = usdc.Wallet(
        chain, (args.bridge_state / "keys/deployer.pk").read_bytes(), -1
    )
    require(
        deployer.address == bridge["wallets"]["deployer"],
        "T5 deployer identity changed",
    )
    # Leave the deployer's remaining T5 allocation untouched.
    receipt = deployer.transfer(
        state, "fund-owner", owner, 20 * usdc.NANO, bounce=False
    )
    state.evidence("fund-owner", receipt)
    message = usdc.lib.parse_boc((state.root / "keys/owner-query.boc").read_bytes())
    intent = state.intent("activate-owner")
    if intent is None:
        intent = {
            "hash": message.hash().hex(),
            "state": "signed",
            "created_at": int(time.time()),
        }
        state.put_intent("activate-owner", intent)
    if intent["state"] != "done":
        require(intent["hash"] == message.hash().hex(), "activation identity changed")
        if not chain.active(owner):
            chain.send(message)
            chain.wait("owner activation", lambda: chain.active(owner))
        tx = chain.executed_external(owner, intent["hash"], intent["created_at"] - 60)
        require(tx and tx["took_effect"], "activation not found; nothing re-signed")
        intent.update(state="done", tx=tx)
        state.put_intent("activate-owner", intent)
    state.evidence("activate-owner", intent)


class Owner(usdc.Wallet):
    """The local expiring wallet-v3 envelope; same durable T5 send journal."""

    def __init__(self, chain, state):
        super().__init__(
            chain, (state.root / "keys/owner.pk").read_bytes(), 0, state["owner"]
        )

    def send_once(self, state, intent, build, mode=3, deploy=False):
        require(not deploy, "owner is activated separately")
        record = state.intent(intent)
        if record is None:
            for name, previous in state.intents().items():
                require(
                    previous.get("wallet") != self.address
                    or previous.get("state") == "done",
                    f"unresolved owner send {name}",
                )
            seqno = self.seqno()
            outgoing = build()
            expiry = int(time.time()) + 300
            signed = (
                usdc.Builder()
                .int(3, 32)
                .uint(42, 32)
                .uint(expiry, 32)
                .uint(seqno, 32)
                .uint(mode, 8)
                .ref(outgoing)
                .end()
            )
            body = (
                usdc.Builder()
                .raw(self.key.sign(signed.hash()).signature)
                .append(signed)
                .end()
            )
            message = usdc.external(self.address, body)
            record = {
                "wallet": self.address,
                "seqno": seqno,
                "valid_until": expiry,
                "boc": usdc.boc64(message),
                "hash": message.hash().hex(),
                "expected": usdc.message_summary(outgoing),
                "created_at": int(time.time()),
                "state": "signed",
            }
            state.put_intent(intent, record)
        if record["state"] == "done":
            return record
        require(
            record["state"] != "accepted_not_sent",
            usdc.accepted_not_sent(intent, record),
        )
        if self.seqno() == record["seqno"]:
            require(
                time.time() < record["valid_until"],
                "signed message expired; reconcile, do not re-sign",
            )
            self.chain.send(usdc.from64(record["boc"]))
            self.chain.wait("owner seqno", lambda: self.seqno() > record["seqno"])
        tx = self.chain.executed_external(
            self.address, record["hash"], record["created_at"] - 60
        )
        require(tx is not None, "owner send not found; nothing re-signed")
        record.update(
            tx=tx,
            state="done"
            if tx["took_effect"] and record["expected"] in tx["out"]
            else "accepted_not_sent",
        )
        state.put_intent(intent, record)
        require(record["state"] == "done", usdc.accepted_not_sent(intent, record))
        return record


def deploy(args, state, chain, bridge):
    plan = state["deployment"]
    owner = Owner(chain, state)
    receipt = owner.transfer(
        state,
        "deploy-actor",
        plan["address"],
        5 * usdc.NANO,
        init=usdc.from64(plan["state_init_boc"]),
        bounce=False,
    )
    chain.wait("actor deployment", lambda: chain.active(plan["address"]))
    require(
        usdc.from64(chain.account(plan["address"])["code"]).hash().hex()
        == plan["code_hash"],
        "deployed code mismatch",
    )
    state.evidence(
        "deploy-actor",
        {
            "send": receipt,
            "service_data": [
                str(v) for v in chain.get(plan["address"], "get_service_data")
            ],
        },
    )


def snapshot(state, chain, name):
    actor = state["deployment"]["address"]
    wallet = state["deployment"]["wallet"]
    urls = chain.validator_urls[:3]
    seqno = (
        min(chain.call("getMasterchainInfo", url=u)["last"]["seqno"] for u in urls) - 2
    )
    values = []
    for url in urls:
        block = chain.call(
            "lookupBlock",
            url=url,
            workchain=-1,
            shard="-9223372036854775808",
            seqno=seqno,
        )

        def getter(address, method, url=url, numeric_count=None):
            result = chain.call(
                "runGetMethod",
                url=url,
                address=address,
                method=method,
                stack=[],
                seqno=seqno,
            )
            require(
                result.get("exit_code") == 0, f"{method} refused at checkpoint {seqno}"
            )
            ordered = list(reversed(result["stack"]))
            return [usdc.num(v) for v in ordered[:numeric_count]]

        ledger = getter(actor, "get_token_ledger")
        account = chain.call(
            "getAddressInformation", url=url, address=wallet, seqno=seqno
        )
        balance = (
            getter(wallet, "get_wallet_data", numeric_count=1)[0]
            if account.get("state") == "active"
            else 0
        )
        require(balance + ledger[3] >= sum(ledger), "token backing invariant violated")
        values.append(
            {
                "block": block,
                "token_ledger": ledger,
                "wallet_balance_atomic": balance,
                "native_ledger": getter(actor, "get_native_ledger"),
            }
        )
    require(
        all(v == values[0] for v in values), "references disagree at the checkpoint"
    )
    result = {"checkpoint": seqno, "rpc_count": len(urls), **values[0]}
    state.evidence(name, result)
    return result


def cli_document(args, state, chain, label, kind, *extra, sender=None):
    saved = state.get(label + "-document")
    command = {"kind": kind, "args": list(extra), "sender": sender or state["owner"]}
    prior = state.get(label + "-command")
    if prior is None:
        require(
            not saved, "unbound prepared document requires read-only reconciliation"
        )
        state.set(label + "-command", command)
    else:
        require(prior == command, "step name reused with different inputs")
    if saved:
        return saved
    config = state.root / "tosctl-config.json"
    if not config.exists():
        value = json.loads((args.bridge_state / "tosctl-config.json").read_text())
        value["chain_rpc"] = {"urls": [chain.url], "api_key": None}
        config.write_text(json.dumps(value) + "\n")
        config.chmod(0o600)
    doc = json.loads(
        run(
            [
                str(args.tosctl),
                "agent",
                "--config",
                str(config),
                "service-token",
                kind,
                "--address",
                state["deployment"]["address"],
                "--code-profile",
                "test",
                "--sender",
                sender or state["owner"],
                "--build-only",
                *extra,
            ]
        )
    )
    require(
        doc["version"] == "tosctl.service-actor-token.prepared-message.v1",
        "unexpected message document",
    )
    state.set(label + "-document", doc)
    return doc


def call_case(args, state, chain, bridge):
    label = args.case
    require(
        label in ("responded", "refunded", "swept", "funding-refused", "surplus"),
        "unsupported case",
    )
    buyer = usdc.wallets(chain, args.bridge_state / "keys")["buyer"]
    request_hash = hashlib.sha256(("local-token-t10-" + label).encode()).hexdigest()
    terms = format(
        usdc.num(chain.get(state["deployment"]["address"], "get_terms_hash")[0]), "064x"
    )
    doc = cli_document(
        args,
        state,
        chain,
        "call-" + label,
        "call",
        "--request-hash",
        request_hash,
        "--expected-terms-hash",
        terms,
        sender=buyer.address,
    )
    body = usdc.from64(doc["body_boc"])
    if label in ("funding-refused", "surplus"):
        details = doc["details"]
        inputs = {
            "query_id": 0,
            "amount_atomic": "1000000",
            "forward_nanotos": "100000000"
            if label == "surplus"
            else details["forward_tos_amount"],
            "actor": state["deployment"]["address"],
            "response": buyer.address,
            "request_hash": request_hash,
            "terms_hash": "00" * 32 if label == "funding-refused" else terms,
        }
        built = json.loads(run([str(args.fixture), "funding"], data=json.dumps(inputs)))
        body = usdc.from64(built["body_boc"])
        state.set("call-" + label + "-inputs", inputs)
    snapshot(state, chain, "before-call-" + label)
    receipt = buyer.transfer(
        state, "call-" + label, doc["destination"], int(doc["value_nanotos"]), body
    )
    state.evidence("call-" + label, {"send": receipt, "request_hash": request_hash})
    time.sleep(6)
    snapshot(state, chain, "after-call-" + label)


def send_operation(args, state, chain, bridge):
    label = args.case
    require(label, "operation requires a unique case name")
    if "--operation" in args.operation_args and state.intent(label) is None:
        op = args.operation_args[args.operation_args.index("--operation") + 1]
        if op in ("expire", "sweep-expired-request"):
            request_id = args.operation_args[
                args.operation_args.index("--request-id") + 1
            ]
            view = json.loads(
                run(
                    [
                        str(args.tosctl),
                        "agent",
                        "--config",
                        str(state.root / "tosctl-config.json"),
                        "service-token",
                        "request-show",
                        "--address",
                        state["deployment"]["address"],
                        "--code-profile",
                        "test",
                        "--request-id",
                        request_id,
                        "--format",
                        "json",
                    ]
                )
            )
            field = "response_deadline" if op == "expire" else "refund_claim_deadline"
            require(
                view.get("found") and view["read_at"]["gen_utime"] >= view[field],
                f"{op} deadline has not arrived",
            )
    owner = (
        usdc.wallets(chain, args.bridge_state / "keys")["buyer"]
        if args.sender_wallet == "buyer"
        else Owner(chain, state)
    )
    doc = cli_document(
        args,
        state,
        chain,
        label,
        "top-up" if args.step == "topup" else "send",
        *args.operation_args,
        sender=owner.address,
    )
    snapshot(state, chain, "before-" + label)
    receipt = owner.transfer(
        state,
        label,
        doc["destination"],
        int(doc["value_nanotos"]),
        usdc.from64(doc["body_boc"]),
    )
    state.evidence(label, receipt)
    time.sleep(6)
    snapshot(state, chain, "after-" + label)


def verify(args, state, chain, bridge):
    require(args.verifier is not None, "--verifier is required")
    require(args.case, "verify requires --case")
    config = json.loads((state.root / "rail.json").read_text())
    document = json.loads(
        run(
            [
                str(args.verifier),
                "--network-domain",
                str(state.root / "network.json"),
                "--rpc",
                ",".join(config["rpc_endpoints"]),
                "--registry-code-boc",
                config["registry_code_boc_file"],
                "--registry-code-hash",
                config["registry_code_hash"],
                "--actor-code-hash",
                config["actor_code_hash"],
                "--asset-pins",
                str(state.root / "pins.json"),
                "--actor",
                state["deployment"]["address"],
                *(
                    args.operation_args
                    or [
                        "--request-hash",
                        hashlib.sha256(
                            ("local-token-t10-" + args.case).encode()
                        ).hexdigest(),
                    ]
                ),
            ]
        )
    )
    require(document["result"] == "pass", "independent verifier refused")
    expected = {
        "responded": "responded",
        "refunded": "refunded",
        "swept": "swept",
        "returned": "returned",
    }.get(args.case)
    if expected:
        require(
            len(document.get("requests", [])) == 1
            and document["requests"][0]["state"] == expected,
            "independent resolver has not reached the required lifecycle state",
        )
    if args.case in ("funding-refused", "surplus"):
        expected = "funding_returned" if args.case == "funding-refused" else "surplus"
        require(
            any(r["state"] == expected for r in document.get("funding_refusals", [])),
            "funding outcome not proven",
        )
    state.evidence("verify-" + args.case, document)


def read_audit_rows(chain, actor, head, urls):
    rows = []
    cursor = head
    seen = set()
    while int(cursor["lt"]) and len(rows) < 64:
        marker = (cursor["lt"], cursor["hash"])
        require(marker not in seen, "audit cursor repeats")
        seen.add(marker)
        pages = [
            chain.call(
                "getTransactionsStd",
                url=url,
                address=actor,
                lt=cursor["lt"],
                hash=cursor["hash"],
                limit=min(16, 64 - len(rows)),
            )
            for url in urls
        ]
        page_rows = [
            [(tx["transaction_id"], tx["data"]) for tx in page["transactions"]]
            for page in pages
        ]
        require(
            all(value == page_rows[0] for value in page_rows),
            "transaction cells differ between references",
        )
        require(
            page_rows[0] and page_rows[0][0][0] == cursor,
            "audit page does not start at its anchor",
        )
        require(
            len(page_rows[0]) <= min(16, 64 - len(rows)), "audit page exceeds the bound"
        )
        following = [
            page.get("previous_transaction_id") or {"lt": "0", "hash": ""}
            for page in pages
        ]
        require(
            all(value == following[0] for value in following),
            "audit cursors differ between references",
        )
        require(
            int(following[0]["lt"]) < int(cursor["lt"]), "audit cursor does not advance"
        )
        rows.extend(page_rows[0])
        cursor = following[0]
    return rows


def audit_owner(args, state, chain, bridge):
    common = snapshot(state, chain, "owner-audit-backing")
    actor = state["deployment"]["address"]
    urls = chain.validator_urls[:3]
    heads = [
        chain.call(
            "getAddressInformation", url=u, address=actor, seqno=common["checkpoint"]
        )["last_transaction_id"]
        for u in urls
    ]
    require(all(h == heads[0] for h in heads), "actor heads differ at checkpoint")
    rows = read_audit_rows(chain, actor, heads[0], urls)
    decoded = []
    for tid, boc in rows:
        request = {
            "actor": actor,
            "lt": int(tid["lt"]),
            "hash": base64.b64decode(tid["hash"]).hex(),
            "boc": boc,
        }
        decoded.append(
            json.loads(
                run([str(args.fixture), "transaction"], data=json.dumps(request))
            )
        )
    outcomes = [
        {"transaction": {"lt": tx["lt"], "hash": tx["hash"]}, "outcome": log["Outcome"]}
        for tx in decoded
        if tx["took_effect"]
        for log in tx.get("logs", [])
        if log.get("Outcome")
    ]
    recovery = [
        row
        for row in outcomes
        if row["outcome"]["Kind"] == 6
        and row["outcome"]["Outcome"] == 0
        and row["outcome"]["Amount"] == 1000000
        and row["outcome"]["Recipient"]["Workchain"] == 0
        and base64.b64decode(row["outcome"]["Recipient"]["Address"]).hex()
        == state["owner"][2:]
    ]
    require(len(recovery) == 1, "the exact surplus recovery outcome is not proven")
    state.evidence(
        "owner-audit",
        {
            "checkpoint": common["checkpoint"],
            "rpc_count": len(urls),
            "outcomes": outcomes,
            "transactions": decoded,
        },
    )
    return outcomes


def configure(args, state, chain, bridge):
    require(args.tosctl and args.tosctl.is_file(), "--tosctl is required")
    root = state.root
    network = json.loads((args.data / "network.json").read_text())
    pin = {
        "Master": bridge["mint"]["minter"],
        "Bridge": bridge["tvm"]["bridge"],
        "BridgeConfigParam": 79,
        "Decimals": 6,
        "SourceChainID": 1,
        "SourceToken": list(bytes.fromhex(bridge["evm"]["token"][2:])),
        **{
            name: "tvm-cell-sha256:" + bridge["tvm"][field]
            for name, field in (
                ("BridgeCodeHash", "bridge_code_hash"),
                ("MinterCodeHash", "minter_code_hash"),
                ("WalletCodeHash", "wallet_code_hash"),
            )
        },
    }
    actor = {
        "address": state["deployment"]["address"],
        "code_hash": "tvm-cell-sha256:" + state["deployment"]["code_hash"],
        "asset_id": "test-usdc",
        "master": pin["Master"],
        "capability_id": args.capability_id,
        "version": "1.0.0",
        "manifest_file": str(root / "manifest.cbor"),
        "min_price_atomic": "1",
        "max_price_atomic": "1000000",
        "max_liability_atomic": "10000000",
        "max_storage_fee_nanotos": "200000000",
        "max_cleanup_bounty_nanotos": "100000000",
        "min_actor_free_nanotos": "100000000",
        "min_wallet_nanotos": "200000000",
    }
    domain = {
        "network_id": "local-usdc-t10",
        "genesis_root_hash": "sha256:" + network["zerostate_root"],
        "genesis_file_hash": "sha256:" + network["zerostate_file"],
    }
    config = {
        "network": domain,
        "rpc_endpoints": chain.validator_urls[:3],
        "quorum": 2,
        "registry_code_boc_file": str(
            args.tools_tos
            / "crypto/smartcont/tos-service-native-registry-v1.boc.base64"
        ),
        "registry_code_hash": json.loads(
            (
                args.tools_tos
                / "crypto/smartcont/tos-service-native-registry-v1.release.json"
            ).read_text()
        )["code_hash"],
        "actor_code_hash": actor["code_hash"],
        "state_dir": str(root / "provider-state"),
        "wallet_name": "owner",
        "wallet_address": state["owner"],
        "tosctl": {
            "binary": str(args.tosctl),
            "sha256": hashlib.sha256(args.tosctl.read_bytes()).hexdigest(),
            "config_path": str(root / "owner-tosctl.json"),
            "vault_url_env": "VAULT_URL",
        },
        "token": {
            "pins": [pin],
            "actors": [actor],
            "monitor_report": str(root / "monitor.json"),
        },
    }
    for name, value in (
        ("rail.json", config),
        ("pins.json", [pin]),
        ("network.json", domain),
    ):
        path = root / name
        path.write_text(json.dumps(value, indent=2) + "\n")
        path.chmod(0o600)
    private = json.loads((args.bridge_state / "tosctl-config.json").read_text())
    private["chain_rpc"] = {"urls": [chain.url], "api_key": None}
    private["wallets"] = {
        "owner": {
            "key": (root / "keys/owner.pk").read_bytes().hex(),
            "version": "V3R2",
            "subwallet_id": 42,
            "workchain": 0,
        }
    }
    path = root / "owner-tosctl.json"
    path.write_text(json.dumps(private) + "\n")
    path.chmod(0o600)
    # This config has no registry publication authority. The capability id must
    # name an independently published token offer before offer/buyer checks.
    state.evidence(
        "configuration",
        {
            "network": domain,
            "actor": actor["address"],
            "capability_id": args.capability_id,
            "published": False,
            "tosctl_sha256": config["tosctl"]["sha256"],
        },
    )


def check_network(args, chain, state):
    approved = json.loads((args.data / "network.json").read_text())
    require(approved["global_id"] == 3, "only local global id 3 is allowed")
    genesis = approved["zerostate_root"]
    if state.get("network"):
        require(
            state["network"]["genesis"] == genesis, "journal belongs to another genesis"
        )
    for url in chain.validator_urls[:3]:
        initial = chain.call("getMasterchainInfo", url=url)["init"]
        require(
            base64.b64decode(initial["root_hash"]).hex() == genesis,
            "endpoint genesis mismatch",
        )
        require(
            base64.b64decode(initial["file_hash"]).hex() == approved["zerostate_file"],
            "endpoint genesis file mismatch",
        )


def fund_work_buyer(args, state, chain, bridge):
    require(args.destination, "funding needs the new local buyer address")
    wc, _ = usdc.split(args.destination)
    require(wc == 0, "buyer must be basechain")
    bound = state.get("work-buyer")
    if bound is None:
        state.set("work-buyer", args.destination)
    else:
        require(bound == args.destination, "work buyer identity changed")
    completed = state.root / "evidence/tokens-work-buyer.json"
    if completed.exists():
        proof = json.loads(completed.read_text())
        intent = state.intent("tokens-work-buyer")
        native = state.intent("fund-work-buyer")
        require(
            intent is not None
            and intent["state"] == "done"
            and native is not None
            and native["state"] == "done"
            and proof["send"]["hash"] == intent["hash"]
            and proof["credited_atomic"] == 3000000,
            "funding evidence does not match the durable send",
        )
        state.evidence("work-buyer-funded", proof)
        return
    deployer = usdc.Wallet(
        chain, (args.bridge_state / "keys/deployer.pk").read_bytes(), -1
    )
    require(deployer.address == bridge["wallets"]["deployer"], "funding source changed")
    if state.intent("fund-work-buyer") is None:
        require(
            chain.balance(deployer.address) >= 7 * usdc.NANO,
            "preserve at least one TOS at source",
        )
    receipt = deployer.transfer(
        state, "fund-work-buyer", args.destination, 6 * usdc.NANO, bounce=False
    )
    state.evidence("fund-work-buyer", receipt)
    buyer = usdc.wallets(chain, args.bridge_state / "keys")["buyer"]
    body = (
        usdc.Builder()
        .uint(0x0F8A7EA5, 32)
        .uint(10, 64)
        .coins(3000000)
        .addr(args.destination)
        .addr(buyer.address)
        .bit(False)
        .coins(0)
        .bit(False)
        .end()
    )
    receipt = buyer.transfer(
        state,
        "tokens-work-buyer",
        bridge["mint"]["buyer_token_wallet"],
        500000000,
        body,
    )
    target = usdc.read_address(
        usdc.stack_cell(
            chain.get(
                bridge["mint"]["minter"],
                "get_wallet_address",
                usdc.slice_of(args.destination),
            )[0]
        )
    )
    chain.wait(
        "buyer token credit",
        lambda: (
            chain.active(target)
            and usdc.num(chain.get(target, "get_wallet_data")[0]) == 3000000
        ),
    )
    state.evidence(
        "tokens-work-buyer",
        {"send": receipt, "token_wallet": target, "credited_atomic": 3000000},
    )


def audit_supply(args, state, chain, bridge):
    master = bridge["mint"]["minter"]
    owners = {
        "bridge_buyer": bridge["wallets"]["buyer"],
        "actor_owner": state["owner"],
        "actor": state["deployment"]["address"],
    }
    if state.get("work-buyer"):
        owners["work_buyer"] = state["work-buyer"]
    wallets = {
        name: usdc.read_address(
            usdc.stack_cell(
                chain.get(master, "get_wallet_address", usdc.slice_of(owner))[0]
            )
        )
        for name, owner in owners.items()
    }
    require(len(set(wallets.values())) == len(wallets), "supply audit repeats a wallet")
    urls = chain.validator_urls[:3]
    seqno = (
        min(chain.call("getMasterchainInfo", url=url)["last"]["seqno"] for url in urls)
        - 2
    )
    rows = []
    for url in urls:
        block = chain.call(
            "lookupBlock",
            url=url,
            workchain=-1,
            shard="-9223372036854775808",
            seqno=seqno,
        )

        def first(address, method, url=url):
            response = chain.call(
                "runGetMethod",
                url=url,
                address=address,
                method=method,
                stack=[],
                seqno=seqno,
            )
            require(response.get("exit_code") == 0, "supply getter refused")
            return usdc.num(next(reversed(response["stack"])))

        balances = {}
        for name, wallet in wallets.items():
            account = chain.call(
                "getAddressInformation", url=url, address=wallet, seqno=seqno
            )
            balances[name] = (
                first(wallet, "get_wallet_data")
                if account.get("state") == "active"
                else 0
            )
        supply = first(master, "get_token_data")
        require(
            supply == bridge["mint"]["balance_atomic"],
            "the approved minted supply changed",
        )
        require(
            sum(balances.values()) == supply,
            "wallet balances do not reconcile with minted supply",
        )
        rows.append(
            {"block": block, "balances_atomic": balances, "supply_atomic": supply}
        )
    require(all(row == rows[0] for row in rows), "supply references disagree")
    state.evidence(
        "token-supply",
        {"checkpoint": seqno, "wallets": wallets, "rpc_count": len(urls), **rows[0]},
    )


def save_document(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as out:
        os.chmod(temporary, 0o600)
        json.dump(value, out, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(args, state, chain, bridge):
    """Bind the existing local actor to a registered provider Capability."""
    require(
        args.provider_runtime and args.published_config,
        "publication needs provider runtime and its initialized configuration",
    )
    config = json.loads(args.published_config.read_text())
    with (Path(config["state_dir"]) / "serve.lock").open("a") as serve_lock:
        try:
            fcntl.flock(serve_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise usdc.Refused("stop the local provider before publication") from error
        publish_locked(args, state, chain, bridge, config)


def publish_locked(args, state, chain, bridge, config):
    original = json.loads((state.root / "rail.json").read_text())
    require(config["wallet_address"] == state["owner"], "publication owner changed")
    require(
        config["network"]["network_id"] == "tos:global-id:3",
        "publication is local only",
    )
    require(
        config["actor_code_hash"].removeprefix("tvm-cell-sha256:")
        == state["deployment"]["code_hash"],
        "publication actor code changed",
    )
    name = "token-work-attestor"
    controller_path = state.root / "publication-controller.json"
    if controller_path.exists():
        controller = json.loads(controller_path.read_text())
    else:
        # A lost reply is recovered by querying the same vault name, not by
        # generating a replacement identity.
        command = [
            str(args.tosctl),
            "agent",
            "--config",
            config["tosctl"]["config_path"],
            "native-registry",
        ]
        queried = subprocess.run(
            [*command, "controller", "--name", name],
            capture_output=True,
            text=True,
            check=False,
        )
        raw = (
            queried.stdout
            if queried.returncode == 0
            else run([*command, "new-controller", "--name", name])
        )
        controller = json.loads(raw)
        require(
            controller["name"] == name and controller["suite"] == "ML-DSA-44",
            "invalid attestor controller",
        )
        controller_path.write_text(json.dumps(controller) + "\n")
        controller_path.chmod(0o600)
    config["token"] = original["token"]
    actor_config = config["token"]["actors"][0]
    actor_config["manifest_file"] = str(state.root / "manifest.cbor")
    config["token"]["monitor_report"] = str(state.root / "monitor.json")
    save_document(args.published_config, config)
    manifest_dir = usdc.private_dir(state.root / "publication-manifests")
    manifest = json.loads(
        run(
            [
                str(args.provider_runtime),
                "manifest",
                "--token-config",
                str(args.published_config),
                "--provider-agent",
                config["agent_id"],
                "--actor",
                state["deployment"]["address"],
                "--code-hash",
                config["actor_code_hash"],
                "--attestor",
                "mldsa44:" + controller["key_id"],
                "--version",
                "1.0.0",
                "--out-dir",
                str(manifest_dir),
            ]
        )
    )
    prior = state.get("publication")
    if prior is None:
        import secrets

        prior = {
            "agent_id": config["agent_id"],
            "manifest_digest": manifest["manifest_digest"],
            "nonce": secrets.token_hex(32),
            "object_nonce": secrets.token_hex(32),
            "attestor": controller["key_id"],
        }
        state.set("publication", prior)
    require(
        prior["agent_id"] == config["agent_id"]
        and prior["manifest_digest"] == manifest["manifest_digest"]
        and prior["attestor"] == controller["key_id"],
        "publication identity changed",
    )
    registration = state.get("publication-registration")
    if registration is None:
        init = json.loads((state.root / "publication-init.json").read_text())
        require(init["agent_id"] == config["agent_id"], "Agent handoff changed")
        registration = json.loads(
            run(
                [
                    str(args.tosctl),
                    "agent",
                    "--config",
                    config["tosctl"]["config_path"],
                    "native-registry",
                    "action",
                    "--global-config",
                    config["chain_global_config_file"],
                    "--network-label",
                    config["network"]["network_id"],
                    "--kind",
                    "register-capability",
                    "--agent",
                    init["agent_address"],
                    "--nonce",
                    prior["nonce"],
                    "--object-nonce",
                    prior["object_nonce"],
                    "--version",
                    "1.0.0",
                    "--manifest",
                    prior["manifest_digest"].removeprefix("sha256:"),
                    "--signer",
                    config["packet_controller"],
                ]
            )
        )
        state.set("publication-registration", registration)
    receipt = Owner(chain, state).transfer(
        state,
        "publication-register-capability",
        registration["destination"],
        2 * usdc.NANO,
        usdc.from64(registration["body_boc"]),
    )
    state.evidence(
        "publication-register-capability",
        {
            "send": receipt,
            "capability": registration["target_id"],
            "final_target": registration["final_target"],
        },
    )
    chain.wait(
        "published Capability", lambda: chain.active(registration["final_target"])
    )
    views = []
    for url in chain.validator_urls[:3]:
        view = chain.call(
            "getAddressInformation", url=url, address=registration["final_target"]
        )
        require(view.get("state") == "active", "Capability absent on a reference")
        views.append(usdc.from64(view["code"]).hash().hex())
    require(
        all(
            v == config["registry_code_hash"].removeprefix("tvm-cell-sha256:")
            for v in views
        ),
        "Capability code differs",
    )
    actor_config["capability_id"] = "cap_" + registration["target_id"]
    raw = Path(manifest["path"]).read_bytes()
    (state.root / "manifest.cbor").write_bytes(raw)
    (state.root / "manifest.cbor").chmod(0o600)
    metadata = json.loads(
        run(
            [
                str(args.provider_runtime),
                "metadata",
                "--network-id",
                config["network"]["network_id"],
                "--genesis-root-hash",
                config["network"]["genesis_root_hash"],
                "--genesis-file-hash",
                config["network"]["genesis_file_hash"],
                "--capability-id",
                actor_config["capability_id"],
                "--provider-agent",
                config["agent_id"],
                "--manifest-digest",
                manifest["manifest_digest"],
            ]
        )
    )["metadata_hash"]
    for label, extra in [
        (
            "publication-attestor",
            [
                "--operation",
                "rotate-attestor-key",
                "--new-attestor-pubkey",
                controller["public_key"],
            ],
        ),
        (
            "publication-policy",
            ["--operation", "update-policy", "--metadata-hash", metadata],
        ),
    ]:
        document = cli_document(args, state, chain, label, "send", *extra)
        receipt = Owner(chain, state).transfer(
            state,
            label,
            document["destination"],
            int(document["value_nanotos"]),
            usdc.from64(document["body_boc"]),
            bounce=True,
        )
        state.evidence(label, {"send": receipt, "details": document["details"]})
    config["provider"] = {
        "capability_id": actor_config["capability_id"],
        "version": "1.0.0",
        "manifest_file": actor_config["manifest_file"],
        "attestor_controller": name,
        "respond_budget_seconds": 120,
        "executor_socket": str(state.root / "executor.sock"),
    }
    save_document(args.published_config, config)
    state.evidence(
        "publication",
        {
            "agent_id": config["agent_id"],
            "capability_id": actor_config["capability_id"],
            "manifest_digest": manifest["manifest_digest"],
            "metadata_hash": metadata,
        },
    )


def case_name(value):
    if not 1 <= len(value) <= 80 or any(
        c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in value
    ):
        raise argparse.ArgumentTypeError(
            "case must be 1-80 lowercase letters, digits or hyphens"
        )
    return value


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "step",
        choices=(
            "prepare",
            "configure",
            "publish",
            "fund-work-buyer",
            "audit-owner",
            "audit-supply",
            "fund",
            "deploy",
            "status",
            "call",
            "send",
            "snapshot",
            "verify",
            "topup",
        ),
    )
    p.add_argument("--data", type=Path, default=Path("/data"))
    p.add_argument("--bridge-state", type=Path, default=Path("/data/usdc"))
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--running-tos", type=Path, required=True)
    p.add_argument("--tools-tos", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--tosctl", type=Path)
    p.add_argument("--verifier", type=Path)
    p.add_argument("--provider-runtime", type=Path)
    p.add_argument("--published-config", type=Path)
    p.add_argument("--capability-id", default="cap_" + "44" * 32)
    p.add_argument("--case", type=case_name)
    p.add_argument("--destination")
    p.add_argument("--sender-wallet", choices=("owner", "buyer"), default="owner")
    args, extra = p.parse_known_args()
    args.operation_args = extra
    require(not extra or args.step in ("send", "topup", "verify"), "unknown arguments")
    root = usdc.private_dir(args.state)
    with (root / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = usdc.State(root)
        chain = usdc.Chain(args.data)
        check_network(args, chain, state)
        bridge = json.loads((args.bridge_state / "state.json").read_text())
        if args.step == "status":
            print(
                json.dumps(
                    {
                        "owner": state.get("owner"),
                        "deployment": state.get("deployment"),
                        "intents": {
                            k: {
                                "state": v["state"],
                                "hash": v.get("hash"),
                                "tx": v.get("tx"),
                            }
                            for k, v in state.intents().items()
                        },
                    },
                    indent=2,
                )
            )
        elif args.step == "call":
            call_case(args, state, chain, bridge)
        elif args.step in ("send", "topup"):
            send_operation(args, state, chain, bridge)
        elif args.step == "fund-work-buyer":
            fund_work_buyer(args, state, chain, bridge)
        elif args.step == "audit-supply":
            audit_supply(args, state, chain, bridge)
        elif args.step == "audit-owner":
            audit_owner(args, state, chain, bridge)
        elif args.step == "snapshot":
            snapshot(state, chain, args.case or "snapshot")
        else:
            globals()[args.step](args, state, chain, bridge)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (usdc.Refused, usdc.lib.TestnetError) as e:
        raise SystemExit(str(e)) from e
