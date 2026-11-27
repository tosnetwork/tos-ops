#!/usr/bin/env python3
"""Journaled local USDT setup and append-only asset recognition.

The local source clock uses one-second blocks and real finalized checkpoints.
Namespace, mint and adoption default to dry runs. Preparation uses the real
receipt's address. Adoption rechecks a fresh monitor, bridge-derived identity,
record preservation and the chain's current critical-vote rules.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import shutil
import time
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("local_usdc", HERE / "local-pq-usdc.py")
u = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(u)
import transaction_archive as archive

GENESIS = {
    "root": "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366",
    "file": "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769",
}
SOURCE = HERE.parent / "contracts/test-usdt/LocalUSDT.sol"
MAX_LIABILITY = 10_000_000


def require(condition, message):
    u.require(condition, message)


def artifact_at(path, build_log):
    artifact = json.loads(Path(path).read_text())
    expected = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    require(
        artifact["contractName"] == "LocalUSDT"
        and artifact["source_sha256"] == expected,
        "artifact source differs; rebuild the fixture",
    )
    lines = Path(build_log).read_text().splitlines()
    receipt = json.loads(lines[0])
    require(
        receipt["source_sha256"] == expected
        and receipt["compiler"] == artifact["compiler"]
        and lines[-1] == "EXIT 0",
        "build log does not match this artifact",
    )
    for key in ("bytecode", "deployedBytecode"):
        require(
            isinstance(artifact[key], str) and artifact[key].startswith("0x"),
            "invalid artifact code",
        )
        code = bytes.fromhex(artifact[key][2:])
        require(0 < len(code) <= 65536, "artifact code length")
    return artifact


class EvidenceState(u.State):
    """Archive each canonical source receipt before another send can begin."""

    def __init__(self, root, evm):
        super().__init__(root)
        self.evm = evm
        self.chain = None

    def put_intent(self, name, record):
        super().put_intent(name, record)
        if record.get("kind") == "evm" and record.get("state") == "done":
            self.retain_source(name, record)
        if record.get("kind") == "tos" and record.get("state") == "done":
            self.retain_tos(name, record)

    def retain_tos(self, name, record):
        require(self.chain is not None, "TOS archive is not bound")
        tx = record["tx"]
        root = {"account": record["wallet"], "lt": int(tx["lt"]), "hash": tx["hash"]}
        identity = archive.digest(json.dumps(root, sort_keys=True).encode())
        archive.StepJournal(self.root / "archive/sends").run(
            name,
            identity,
            lambda: None,
            lambda directory: archive.TransactionArchive(
                directory, self.chain.urls[3:6], GENESIS
            ).capture_wait([root]),
        )

    def retain_source(self, name, record):
        require(archive.LABEL.fullmatch(name), "invalid source evidence name")
        tx = self.evm.rpc("eth_getTransactionByHash", record["tx"])
        receipt = self.evm.rpc("eth_getTransactionReceipt", record["tx"])
        require(
            tx and receipt and tx["hash"] == receipt["transactionHash"] == record["tx"],
            "source transaction disappeared",
        )
        require(
            tx["from"].lower() == record["from"].lower()
            and int(tx["nonce"], 16) == record["nonce"]
            and (tx["to"] or None) == (record["to"] or None)
            and tx["input"].lower() == record["data"].lower()
            and int(tx["value"], 16) == 0,
            "source transaction differs from intent",
        )
        header = self.evm.rpc("eth_getBlockByNumber", receipt["blockNumber"], False)
        require(
            header["hash"] == receipt["blockHash"] == tx["blockHash"],
            "source receipt is not canonical",
        )
        target = self.root / "source-transactions" / (name + ".json")
        value = {"transaction": tx, "receipt": receipt, "block": header}
        if target.exists():
            require(json.loads(target.read_text()) == value, "source evidence changed")
        else:
            archive.document(target, value)
        # The source fixture produces normal interval blocks. Never substitute
        # latest for finalized or advance finality by a state override.
        deadline = time.monotonic() + 180
        while True:
            point = self.evm.rpc("eth_getBlockByNumber", "finalized", False)
            if int(point["number"], 16) >= int(receipt["blockNumber"], 16):
                break
            require(
                time.monotonic() < deadline,
                "source finality pending; rerun this same step",
            )
            time.sleep(2)
        require(
            self.evm.rpc("eth_getBlockByNumber", receipt["blockNumber"], False)["hash"]
            == header["hash"],
            "source finality reorg",
        )
        finality_path = self.root / "source-finality" / (name + ".json")
        finality = {
            "transaction": record["tx"],
            "receipt_block": header["hash"],
            "finalized": point,
        }
        if finality_path.exists():
            saved = json.loads(finality_path.read_text())
            require(
                saved["transaction"] == record["tx"]
                and saved["receipt_block"] == header["hash"],
                "source finality evidence differs",
            )
            require(
                self.evm.rpc(
                    "eth_getBlockByNumber", saved["finalized"]["number"], False
                )["hash"]
                == saved["finalized"]["hash"],
                "archived source finality reorg",
            )
        else:
            archive.document(finality_path, finality)
        require(
            int(receipt["status"], 16) == 1,
            "source transaction reverted; evidence retained",
        )

    def recover_source(self):
        for name, record in self.intents().items():
            if record.get("kind") == "evm" and record.get("state") == "done":
                self.retain_source(name, record)
            if record.get("kind") == "tos" and record.get("state") == "done":
                self.retain_tos(name, record)

    def evidence(self, name, value):
        require(archive.LABEL.fullmatch(name), "invalid evidence name")
        path = self.root / "evidence" / (name + ".json")
        archive.document(path, value)
        return path


class View:
    """One canonical finalized TOS checkpoint, corroborated by nodes 4-6."""

    def __init__(self, chain, directory):
        self.chain, self.urls = chain, chain.urls[3:6]
        self.point = archive.TransactionArchive(
            directory, self.urls, GENESIS
        ).checkpoint()
        require(
            u.lib.Slice(self.config(19)).bits(32) == 3,
            "not the approved local global id",
        )

    def read(self, method, /, **params):
        values = [
            self.chain.call(method, url=url, seqno=self.point["seqno"], **params)
            for url in self.urls
        ]
        require(
            all(
                archive.block_key(v["block_id"]) == archive.block_key(self.point)
                for v in values
            ),
            "read escaped the canonical checkpoint",
        )
        if method == "runGetMethod":
            # The RPC enumerates the VM stack top first. Callers use the
            # getter's declared tuple order, as the existing chain reader does.
            values = [dict(v, stack=list(reversed(v["stack"]))) for v in values]
        return values

    def config(self, param):
        roots = [
            u.lib.parse_boc(base64.b64decode(v["config"]["bytes"]))
            for v in self.read("getConfigParam", param=param, with_proof=True)
        ]
        require(
            all(c.hash() == roots[0].hash() for c in roots),
            "config references disagree",
        )
        return roots[0]

    def account(self, address):
        values = self.read("getAddressInformation", address=address)
        require(all(v == values[0] for v in values), "account references disagree")
        return values[0]

    def minter(self, bridge, token):
        content = u.Builder().uint(1, 32).uint(int(token, 16), 160).uint(6, 8).end()
        values = self.read(
            "runGetMethod",
            address=bridge,
            method="get_minter_address",
            stack=[["tvm.Cell", u.boc64(content)]],
        )
        require(all(v["exit_code"] == 0 for v in values), "minter getter refused")
        addresses = [u.read_address(u.stack_cell(v["stack"][0])) for v in values]
        require(len(set(addresses)) == 1, "minter getters disagree")
        return addresses[0]


def bridge_codes(view, source):
    gov = u.governance_module()
    bridge = source["tvm"]["bridge"]
    require(
        gov.bridge_address_of(view.config(79)) == bridge.split(":")[1],
        "slot 79 names a different bridge",
    )
    account = view.account(bridge)
    code = u.lib.parse_boc(base64.b64decode(account["code"]))
    require(
        code.hash().hex() == source["tvm"]["bridge_code_hash"], "bridge code differs"
    )
    data = u.lib.parse_boc(base64.b64decode(account["data"]))
    cursor = u.lib.Slice(data)
    cursor.bits(64)
    require(
        cursor.bits(32) == 1 and cursor.bits(160) == int(source["evm"]["bridge"], 16),
        "bridge source namespace differs",
    )
    minter, wallet = data.refs[:2]
    require(
        minter.hash().hex() == source["tvm"]["minter_code_hash"]
        and wallet.hash().hex() == source["tvm"]["wallet_code_hash"],
        "bridge-owned codes differ",
    )
    return bridge, minter, wallet


def derive_master(bridge, token, minter_code, wallet_code):
    content = u.Builder().uint(1, 32).uint(int(token, 16), 160).uint(6, 8).end()
    tail = (
        u.Builder()
        .addr(bridge)
        .uint(0, 129)
        .uint(0, 128)
        .uint(0, 128)
        .uint(0, 32)
        .uint(0, 3)
        .end()
    )
    data = (
        u.Builder()
        .uint(0, 128)
        .coins(0)
        .coins(0)
        .coins(0)
        .coins(0)
        .ref(content)
        .ref(wallet_code)
        .ref(tail)
        .end()
    )
    return u.address_of(u.state_init(minter_code, data), 0)


def record_cells(value):
    """Record value cells, excluding dictionary labels that change on append."""
    return u.governance_module().settlement_record_cells(value)


def check_preserved(old, new):
    before, after = record_cells(old), record_cells(new)
    for master, payload in before.items():
        require(
            master in after and after[master] == payload,
            "an existing record's value cells changed or disappeared",
        )
    return {m: hashlib.sha256(v).hexdigest() for m, v in before.items()}


def check_append(old, new):
    # Compare actual value cells before relying on decoded-field equality.
    retained = check_preserved(old, new)
    gov = u.governance_module()
    prior, candidate = (
        gov.decode_settlement_assets(old),
        gov.decode_settlement_assets(new),
    )
    change = gov.settlement_assets_change(prior, candidate)
    return {
        "preserved": retained,
        "entries": len(candidate),
        "validation_visits": gov.validation_visits(new),
        "change": change,
    }


def namespace(args, state, evm, source, artifact):
    require(evm.chain_id() == 1, "not the approved source chain")
    sender = source["evm"]["deployer"]
    require(evm.code(source["evm"]["bridge"]) != "0x", "original source bridge missing")
    init = (
        artifact["bytecode"]
        + evm.abi_encode("constructor(uint256)", "1000000000000")[2:]
    )
    existing = state.intent("deploy-usdt")
    if existing is not None:
        require(
            existing["data"] == init and existing["from"].lower() == sender.lower(),
            "existing deployment intent differs; reconcile it",
        )
    else:
        latest = int(evm.rpc("eth_getTransactionCount", sender, "latest"), 16)
        require(latest == evm.nonce(sender), "source payer has a pending transaction")
    estimate = (
        int(evm.rpc("eth_estimateGas", {"from": sender, "data": init}), 16)
        if existing is None
        else existing["gas"]
    )
    require(0 < estimate <= 3_000_000, "source deployment gas over budget")
    if not args.execute:
        return {
            "dry_run": True,
            "sender": sender,
            "init_sha256": hashlib.sha256(bytes.fromhex(init[2:])).hexdigest(),
            "gas": estimate,
            "source_sha256": artifact["source_sha256"],
        }
    if existing is None:
        balance = int(evm.rpc("eth_getBalance", sender, "latest"), 16)
        price = int(evm.rpc("eth_gasPrice"), 16)
        require(
            balance >= estimate * price * 2 + 10**18,
            "source payer reserve insufficient",
        )
    record = u.evm_send_once(
        evm,
        state,
        "deploy-usdt",
        sender,
        None,
        init,
        gas=estimate,
        meta={"source_sha256": artifact["source_sha256"]},
    )
    require(
        record.get("status") == 1 and record.get("contract"),
        "deployment not confirmed; reconcile the original intent",
    )
    token = record["contract"].lower()
    require(
        evm.code(token).lower() == artifact["deployedBytecode"].lower(),
        "deployed runtime differs from built fixture",
    )
    return archive_namespace(state, evm, record, token, artifact)


def archive_namespace(state, evm, record, token, artifact):
    tx = evm.rpc("eth_getTransactionByHash", record["tx"])
    receipt = evm.rpc("eth_getTransactionReceipt", record["tx"])
    require(
        tx
        and receipt
        and receipt["status"] == "0x1"
        and receipt["contractAddress"].lower() == token,
        "deployment receipt disappeared or differs",
    )
    block = evm.rpc("eth_getBlockByNumber", receipt["blockNumber"], False)
    require(
        block["hash"] == receipt["blockHash"] == tx["blockHash"],
        "source receipt is not canonical",
    )
    finalized = evm.rpc("eth_getBlockByNumber", "finalized", False)
    result = {
        "token": token,
        "transaction_hash": record["tx"],
        "receipt": receipt,
        "transaction": tx,
        "block": block,
        "source_sha256": artifact["source_sha256"],
        "runtime_sha256": hashlib.sha256(
            bytes.fromhex(artifact["deployedBytecode"][2:])
        ).hexdigest(),
    }
    # Preserve the mined receipt immediately, even while source finality lags.
    path = state.root / "evidence" / "namespace-mined.json"
    if path.exists():
        require(
            json.loads(path.read_text()) == result,
            "recorded namespace evidence differs",
        )
    else:
        archive.document(path, result)
    status = {
        "token": token,
        "transaction_hash": record["tx"],
        "source_finalized": int(finalized["number"], 16)
        >= int(receipt["blockNumber"], 16),
        "source_finalized_height": int(finalized["number"], 16),
    }
    state.set("namespace", status)
    return status


def mint(args, state, evm, source, chain, artifact):
    require(
        state.get("namespace", {}).get("source_finalized") is True,
        "namespace must finalize first",
    )
    token = state["namespace"]["token"]
    require(
        evm.code(token).lower() == artifact["deployedBytecode"].lower(),
        "namespace code differs",
    )
    require(evm.call(token, "decimals()(uint256)") == "6", "source decimals differ")
    require(
        evm.call(token, "basisPointsRate()(uint256)") == "0",
        "mint rehearsal requires no source fee",
    )
    state.set("evm", {**source["evm"], "token": token})
    state.set("tvm", source["tvm"])
    state.set("wallets", source["wallets"])
    bridge, sender, locker = (
        source["evm"]["bridge"],
        source["evm"]["deployer"],
        source["evm"]["locker"],
    )
    amount = u.LOCK_AMOUNT
    caps = [str(x) for x in u.LOCK_CAPS]
    if not args.execute:
        return {
            "dry_run": True,
            "token": token,
            "amount_atomic": amount,
            "caps": caps,
            "buyer": source["wallets"]["buyer"],
        }
    u.CAST[0] = args.cast
    if state.intent("usdt-caps") is None:
        require(
            u.evm_values(evm.call(bridge, u.CAPS, token))[0] == "0",
            "unexpected pre-existing source cap",
        )
    last = u.evm_values(evm.call(bridge, "lastLockCapNonce(address)(uint256)", token))[
        0
    ]
    u.evm_vote(
        evm,
        state,
        args.keys,
        "usdt-caps",
        "getNewLockCapId(address,uint256,uint256,uint256,uint256,uint256)(bytes32)",
        [token, *caps, str(int(last) + 1)],
        "voteForLockCap(address,uint256,uint256,uint256,uint256,uint256,(address,bytes)[])",
        [token, *caps, str(int(last) + 1)],
    )
    require(u.evm_values(evm.call(bridge, u.CAPS, token)) == caps, "source caps differ")
    u.evm_send_once(
        evm,
        state,
        "usdt-locker-funds",
        sender,
        token,
        "transfer(address,uint256)",
        locker,
        str(amount),
    )
    if state.intent("usdt-approve") is None:
        require(
            u.evm_values(
                evm.call(token, "allowance(address,address)(uint256)", locker, bridge)
            )[0]
            == "0",
            "clear unknown allowance before preparing a new approval",
        )
    u.evm_send_once(
        evm,
        state,
        "usdt-approve",
        locker,
        token,
        "approve(address,uint256)",
        bridge,
        str(amount),
    )
    planned = (
        (state.intent("usdt-lock") or {})
        .get("meta", {})
        .get("n", u.lock_nonce(evm, bridge))
    )
    target = "0x" + u.split(source["wallets"]["buyer"])[1].hex()
    record = u.evm_send_once(
        evm,
        state,
        "usdt-lock",
        locker,
        bridge,
        u.LOCK,
        token,
        str(amount),
        target,
        meta={"n": planned},
    )
    require(record["status"] == 1, "source lock refused")
    actual = u.evm_values(
        evm.call(
            bridge, "locks(uint64)(address,address,uint256,uint32,uint8)", str(planned)
        )
    )
    require(
        actual[0].lower() == locker.lower()
        and actual[1].lower() == token.lower()
        and int(actual[2]) == amount
        and int(actual[3]) == u.GENERATION
        and int(actual[4]) == 1,
        "source lock differs from intent",
    )
    state.set(
        "lock",
        {
            "n": planned,
            "amount": amount,
            "to_address_hash": target,
            "tx": {k: record[k] for k in ("tx", "block", "status")},
        },
    )
    tools = u.Tools(args)
    u.step_mint(args, state, chain, tools, args.keys)
    return qualify(state, source, chain)


def qualify(state, source, chain):
    amount = state["lock"]["amount"]
    token = state["namespace"]["token"]
    record = state.intent("usdt-lock")
    view = View(chain, state.root / "mint-references")
    minter = state["mint"]["minter"]
    supply = view.read(
        "runGetMethod", address=minter, method="get_supply_state", stack=[]
    )
    require(
        all(
            v["exit_code"] == 0
            and u.num(v["stack"][0]) == amount
            and u.num(v["stack"][1]) == 0
            for v in supply
        ),
        "finalized supply differs",
    )
    require(
        u.lib.parse_boc(base64.b64decode(view.account(minter)["code"])).hash().hex()
        == source["tvm"]["minter_code_hash"],
        "minted master code differs",
    )
    report = {
        "token": token,
        "master": minter,
        "amount_atomic": amount,
        "checkpoint": view.point,
        "source_lock": record["tx"],
        "archive": "archive/sends",
    }
    state.evidence("mint-finalized", report)
    return report


def prepare(args, state, evm, source, artifact, view, codes):
    record = state.intent("deploy-usdt")
    require(
        record is not None and record.get("state") == "done",
        "deploy the real namespace first; predictions are not records",
    )
    ns = archive_namespace(state, evm, record, record["contract"].lower(), artifact)
    require(evm.chain_id() == 1, "not the approved source chain")
    token = ns["token"]
    require(
        evm.code(token).lower() == artifact["deployedBytecode"].lower(),
        "namespace code differs",
    )
    require(evm.call(token, "decimals()(uint256)") == "6", "source decimals differ")
    bridge, minter, wallet = codes
    master = derive_master(bridge, token, minter, wallet)
    require(
        view.minter(bridge, token) == master, "getter and independent StateInit differ"
    )
    require(
        derive_master(bridge, source["evm"]["token"], minter, wallet)
        == view.minter(bridge, source["evm"]["token"])
        == source["mint"]["minter"],
        "USDC derivation differs",
    )
    gov = u.governance_module()
    old = view.config(84)
    prior = gov.decode_settlement_assets(old)
    require(
        master.split(":")[1] not in prior,
        "master already recognized; do not build another proposal",
    )
    entry = {
        "master": master.split(":")[1],
        "status": "active",
        "decimals": 6,
        "minter_code_hash": minter.hash().hex(),
        "wallet_code_hash": wallet.hash().hex(),
        "max_liability_per_actor": str(MAX_LIABILITY),
        "origin": {
            "kind": "token_bridge",
            "bridge_address": bridge.split(":")[1],
            "source_chain_id": 1,
            "source_token": token[2:],
        },
    }
    spec = {"assets": [dict(master=m, **v) for m, v in prior.items()] + [entry]}
    archive.document(state.root / "config84-spec.json", spec)
    result = u.subprocess.run(
        [
            str(args.tosctl),
            "vote",
            "offer",
            "settlement-assets",
            "build",
            "--spec",
            str(state.root / "config84-spec.json"),
            "--out",
            str(state.root / "config84.boc"),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    require(result.returncode == 0, "canonical CP84 builder refused")
    value = u.lib.parse_boc((state.root / "config84.boc").read_bytes())
    checks = check_append(old, value)
    deployed = view.account(master).get("state") == "active"
    # This tool has no proposal/vote path. Minting and the reviewed collector
    # gate remain separate, even when a structurally valid value is prepared.
    report = dict(
        schema="tos-local-usdt-preflight/1",
        token=token,
        master=master,
        bridge_param=79,
        checkpoint=view.point,
        **checks,
        baseline_hash=old.hash().hex(),
        candidate_hash=value.hash().hex(),
        source_finalized=ns["source_finalized"],
        master_deployed=deployed,
        governance_ready=False,
        holds=["Use adopt after the collector and finalized mint qualification pass."],
    )
    archive.sync_write(state.root / "baseline-config84.boc", u.lib.serialize_boc(old))
    archive.document(state.root / "preflight.json", report)
    return report


def monitor_gate(policy, report, expected, point, now=None):
    now = time.time() if now is None else now
    require(
        policy["network"] == GENESIS["root"]
        and report["schema"] == "tos-settlement-report/1",
        "monitor network or schema differs",
    )
    actual = {a["id"]: (a["master"], a["source_token"]) for a in policy["assets"]}
    require(
        actual == expected and len(actual) == len(policy["assets"]),
        "monitor assets differ from the proposed namespace",
    )
    stamp = report["checkpoint"]["utime"]
    height = report["checkpoint"]["height"]
    require(
        type(stamp) is int
        and type(height) is int
        and 0 <= height <= point["seqno"]
        and -5 <= now - stamp <= 120,
        "monitor checkpoint is stale or future",
    )
    require(
        not report["provider_pause_assets"] and not report["alarms"],
        "monitor is alarmed",
    )


def adopt(args, state, source, chain, view):
    candidate = state.root / "config84.boc"
    baseline = u.lib.parse_boc((state.root / "baseline-config84.boc").read_bytes())
    value = u.lib.parse_boc(candidate.read_bytes())
    checks = check_append(baseline, value)
    require(
        state.get("mint") and state["namespace"]["source_finalized"],
        "finalized mint required before governance",
    )
    bridge, minter, wallet = bridge_codes(view, source)
    master = derive_master(bridge, state["namespace"]["token"], minter, wallet)
    require(
        master
        == state["mint"]["minter"]
        == view.minter(bridge, state["namespace"]["token"]),
        "proposal minter identity differs",
    )
    entry = checks["change"]["after"]
    require(
        checks["change"]["master"] == master.split(":")[1]
        and entry["minter_code_hash"] == minter.hash().hex()
        and entry["wallet_code_hash"] == wallet.hash().hex()
        and entry["origin"]["source_token"] == state["namespace"]["token"][2:]
        and entry["origin"]["source_chain_id"] == 1
        and entry["origin"]["bridge_address"] == bridge.split(":")[1]
        and entry["decimals"] == 6
        and entry["status"] == "active"
        and checks["entries"] == 3
        and entry["max_liability_per_actor"] == str(MAX_LIABILITY),
        "proposed asset differs from bridge-anchored derivation",
    )
    report = json.loads((args.monitor_state / "report.json").read_text())
    policy = json.loads((args.monitor_state / "policy.json").read_text())
    monitor_gate(
        policy,
        report,
        {
            "usdc": (source["mint"]["minter"], source["evm"]["token"]),
            "usdt": (master, state["namespace"]["token"]),
        },
        view.point,
    )
    current = view.config(84)
    require(
        current.hash() in (baseline.hash(), value.hash()),
        "recognition changed since preparation",
    )
    tools = u.Tools(args)
    evidence = u.node_release_evidence(state, chain, args.data)
    payer = u.payer_files(args, state, tools, args.keys)
    args.ceremony = args.source_state.parent / "ceremony"
    archive_args = SimpleNamespace(
        ceremony=args.ceremony,
        evidence_dir=state.root / "archive/governance",
        archive_rpc=chain.urls[3:6],
        rpc=chain.validator_urls[0],
        confirm_rpc=chain.validator_urls[1],
    )
    common = [
        "--ceremony",
        str(args.ceremony),
        "--tos-root",
        str(tools.tos),
        "--fift",
        str(tools.fift),
        "--rpc",
        chain.validator_urls[0],
        "--confirm-rpc",
        chain.validator_urls[1],
        "--payer-key",
        payer["key"],
        "--payer-addr",
        payer["addr"],
        "--payer-subwallet",
        str(u.PAYER_SUBWALLET),
    ]
    original = u.governance

    def archived_governance(arguments, *argv, check=True):
        extra = []
        if argv[0] in ("propose", "vote"):
            extra = [
                "--evidence-dir",
                str(archive_args.evidence_dir),
                *[
                    arg
                    for url in archive_args.archive_rpc
                    for arg in ("--archive-rpc", url)
                ],
            ]
        return original(arguments, *argv, *extra, check=check)

    u.governance = archived_governance
    try:
        if not args.execute:
            if current.hash() == value.hash():
                return {"already_adopted": True, "value_hash": value.hash().hex()}
            quote = u.governance(
                args,
                "propose",
                *common,
                "--param",
                "84",
                "--value-boc",
                str(candidate),
                "--node-release-evidence",
                str(evidence),
                "--dry-run",
            )
            return {
                "dry_run": True,
                "value_hash": value.hash().hex(),
                "quote": quote.stdout,
            }
        gov = u.governance_module()
        operations = gov.elections.operations_for(archive_args, 3)
        gov.recover_governance_archive(archive_args, operations)
        result = u.adopt(
            args,
            state,
            chain,
            tools,
            84,
            candidate,
            ["--node-release-evidence", str(evidence)],
        )
        gov.recover_governance_archive(archive_args, operations)
        state.evidence("adopted-config84", result)
        final_view = View(chain, state.root / "adoption-references")
        require(
            final_view.config(84).hash() == value.hash(),
            "finalized recognition differs",
        )
        for i, url in enumerate(final_view.urls, 4):
            response = chain.call(
                "getConfigParam",
                url=url,
                seqno=final_view.point["seqno"],
                param=84,
                with_proof=True,
            )
            archive.document(
                state.root / "evidence" / f"config84-node-{i}.json", response
            )
        archive.document(
            state.root / "evidence/adoption-checkpoint.json", final_view.point
        )
        return {
            "adopted": True,
            "value_hash": value.hash().hex(),
            "checkpoint": final_view.point,
            "entries": 3,
            "archive": "archive/governance",
        }
    finally:
        u.governance = original


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "step", choices=("clock", "namespace", "mint", "qualify", "prepare", "adopt")
    )
    parser.add_argument("--data", type=Path, default=Path("/data"))
    parser.add_argument("--source-state", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--build-log", type=Path, required=True)
    parser.add_argument("--tos-root", required=True)
    parser.add_argument("--tosctl", required=True)
    parser.add_argument("--cast", default=shutil.which("cast") or "cast")
    parser.add_argument("--evm-rpc", default="http://127.0.0.1:18545")
    parser.add_argument(
        "--monitor-state", type=Path, default=Path("/data/usdt-t15-monitor")
    )
    parser.add_argument("--governance-timeout", type=int, default=3600)
    parser.add_argument("--keys", type=Path, default=Path("/data/usdc/keys"))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        require(
            args.evm_rpc.startswith("http://127.0.0.1:"),
            "local source endpoint required",
        )
        root = u.private_dir(args.state)
        with (root / "driver.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            source = json.loads(args.source_state.read_text())
            require(
                all(r.get("state") == "done" for r in source["intents"].values()),
                "original source run has unresolved operations",
            )
            chain = u.Chain(args.data)
            view = View(chain, root / "references")
            codes = bridge_codes(view, source)
            artifact = artifact_at(args.artifact, args.build_log)
            args.evm_artifacts = ""
            evm = u.Evm(u.Tools(args))
            state = EvidenceState(root, evm)
            state.chain = chain
            state.recover_source()
            if args.step == "clock":
                require(evm.chain_id() == 1, "not the approved source chain")
                clock = {
                    "interval_seconds": 1,
                    "genesis": GENESIS["root"],
                    "source_chain_id": 1,
                }
                if args.execute:
                    state.set("source_clock_intent", clock)
                    evm.rpc("evm_setIntervalMining", 1)
                    state.set("source_clock", clock)
                print(json.dumps({"source_clock": clock, "dry_run": not args.execute}))
                return 0
            if args.step == "adopt":
                report = adopt(args, state, source, chain, view)
                print(json.dumps(report, sort_keys=True))
                return 0
            if args.step in ("mint", "qualify"):
                report = (
                    mint(args, state, evm, source, chain, artifact)
                    if args.step == "mint"
                    else qualify(state, source, chain)
                )
                print(json.dumps(report, sort_keys=True))
                return 0
            report = (
                namespace(args, state, evm, source, artifact)
                if args.step == "namespace"
                else prepare(args, state, evm, source, artifact, view, codes)
            )
            print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, u.Refused, u.lib.TestnetError) as error:
        print("local USDT preparation refused: " + str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
