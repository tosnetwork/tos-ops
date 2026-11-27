#!/usr/bin/env python3
"""Stablecoin final acceptance on the existing local PQ network.

Local development only. It reuses the bridge, the stand-in oracle keys and the
test wallets of the test-USDC run (/data/usdc) and the LocalUSDT namespace of the
second-asset run (/data/usdt-t15). It never creates a network, a bridge or a
recognition record, and it refuses any source endpoint other than loopback and
any TOS network other than the approved local genesis.

Every value step is journaled before it is sent (the shared EVM and TOS send
journals of local-pq-usdc.py) and archived as soon as it finalizes: an EVM
transaction with its canonical receipt and source finality, a TOS transaction
with its transitive message graph on nodes 4-6 (transaction_archive). The next
send refuses while an earlier one is not archived. Value steps default to a dry
run; --execute sends.

Steps:

  status        caps, flags and balances of both assets (read-only)
  fund-buyer    pay the bridge buyer local TOS for mint fees from the original
                governance payer (a wallet v3 holding an unused local allocation)
  fund-locker   move source tokens from the token holder to the EVM locker
  caps          an oracle-quorum voteForLockCap for one asset
  probe         simulate a lock at one pinned source block and require the
                named refusal (no transaction is sent)
  lock          approve exactly, lock, pay the mint fee, vote the v5 swap, and
                reconstruct the minted supply on nodes 4-6
  disable       an oracle-quorum voteForDisableToken (disable or re-enable)
  switch-lock   an oracle-quorum voteForSwitchLock (the bridge-wide pause)
  issuer        a LocalUSDT owner call: blacklist/unblacklist the bridge,
                pause/unpause, set the transfer fee
  burn          burn wrapped tokens on TOS to an EVM receiver (T19 prepared body)
  unlock        oracle-sign the burn's LOG_BURN and submit Bridge.unlock
  observe       retain the running monitor's current report (read-only)
  reconcile     supply against backing for both assets at one checkpoint

Run as root from the tos-ops root, with the running tos checkout's environment.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import re
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "testnet" / "scripts"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


u = _load("local_usdc", HERE / "local-pq-usdc.py")
t = _load("local_usdt", HERE / "local-pq-usdt.py")
archive = t.archive
lib = u.lib

NANO = u.NANO
ASSETS = ("usdc", "usdt")
# Reasons Bridge.lock gives for each refusal this driver may be asked to show.
REASONS = {
    "per-lock": "lock: over the per-lock cap",
    "total": "lock: over the token cap",
    "hourly": "lock: over the hourly cap",
    "daily": "lock: over the daily cap",
    "disabled": "lock: disabled token",
    "paused": "Lock is currently disabled",
    "issuer-paused": "sender frozen or paused",
}
ISSUER_OPS = {
    "blacklist-bridge": "addBlackList(address)",
    "unblacklist-bridge": "removeBlackList(address)",
    "pause": "pause()",
    "unpause": "unpause()",
    "set-fee": "setParams(uint256,uint256)",
}
CAP_ID = "getNewLockCapId(address,uint256,uint256,uint256,uint256,uint256)(bytes32)"
CAP_VOTE = "voteForLockCap(address,uint256,uint256,uint256,uint256,uint256,(address,bytes)[])"
DISABLE_ID = "getNewDisableToken(bool,address,uint256)(bytes32)"
DISABLE_VOTE = "voteForDisableToken(bool,address,uint256,(address,bytes)[])"
SWITCH_ID = "getNewLockStatusId(bool,uint256)(bytes32)"
SWITCH_VOTE = "voteForSwitchLock(bool,uint256,(address,bytes)[])"
SWAP = "(address,address,uint256,(bytes32,bytes32,uint64))"
SWAP_ID = f"getSwapDataId({SWAP})(bytes32)"
UNLOCK = f"unlock({SWAP},(address,bytes)[])"
LOCKS = "locks(uint64)(address,address,uint256,uint32,uint8)"
LOCK_EVENT = "Lock(address,address,bytes32,uint256,uint256,uint8,uint64,uint32)"
LOG_BURN = 0xC0470CCF
OP_BURN = 0x595F07BC
WALLET_V3_TTL = 600
# The checker's emergency codes (testnet/scripts/check-settlement.py): each latches
# an incident and names its asset alone in provider_pause_assets.
EMERGENCIES = {
    "bridge_frozen",
    "token_paused",
    "destroyed_funds",
    "token_deprecated",
    "token_upgrade",
    "unexplained_decrease",
    "backing_shortfall",
}
MAX_AMOUNT = 2**120 - 1


def require(condition, message):
    u.require(condition, message)


def positive(value, name):
    require(type(value) is int and 0 < value <= MAX_AMOUNT, f"{name} must be in 1..2^120-1")
    return value


# ---------------------------------------------------------------- assets


def assets(usdc_state: dict, usdt_state: dict) -> dict:
    """Each asset's fixed identities, from the two original runs' records."""
    require(
        usdc_state["evm"]["bridge"] == usdt_state["evm"]["bridge"],
        "the two runs name different EVM bridges",
    )
    require(
        usdc_state["tvm"]["bridge"] == usdt_state["tvm"]["bridge"],
        "the two runs name different TOS bridges",
    )
    out = {}
    for name, record in (("usdc", usdc_state), ("usdt", usdt_state)):
        token = record["evm"]["token"].lower()
        if name == "usdt":
            token = record["namespace"]["token"].lower()
        out[name] = {
            "token": token,
            "minter": record["mint"]["minter"],
            "buyer_token_wallet": record["mint"]["buyer_token_wallet"],
            "wrapped_token_data": record["mint"]["wrapped_token_data"],
        }
    require(out["usdc"]["token"] != out["usdt"]["token"], "the two assets share a token")
    require(out["usdc"]["minter"] != out["usdt"]["minter"], "the two assets share a minter")
    return out


class AssetState:
    """The acceptance state seen as one asset's bridge run, for the shared mint
    helpers (pay_and_vote reads state['evm']['token'] and state['tvm']). Intents
    stay in the one acceptance journal."""

    def __init__(self, state, token: str):
        self.state, self.token = state, token

    def __getitem__(self, key):
        if key == "evm":
            return {**self.state["evm"], "token": self.token}
        return self.state[key]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def intents(self):
        return self.state.intents()

    def intent(self, name):
        return self.state.intent(name)

    def put_intent(self, name, record):
        self.state.put_intent(name, record)


# ---------------------------------------------------------------- source reads


def values(evm, to, signature, *args, block=None):
    argv = ["call", to, signature, *args]
    if block is not None:
        argv[1:1] = ["--block", str(block)]
    return u.evm_values(evm.tools.cast_run(*argv).stdout)


def pinned_block(evm) -> dict:
    block = evm.rpc("eth_getBlockByNumber", "latest", False)
    return {
        "number": int(block["number"], 16),
        "hash": block["hash"],
        "timestamp": int(block["timestamp"], 16),
    }


def cap_state(evm, bridge, token, block=None) -> dict:
    argv = ["call", bridge, u.CAP_STATE, token]
    if block is not None:
        argv[1:1] = ["--block", str(block)]
    text = evm.tools.cast_run(*argv).stdout
    # cast prints the tuple on one line and annotates numbers ("1000 [1e3]").
    raw = [re.sub(r" \[[^\]]*\]", "", line).strip() for line in text.splitlines() if line.strip()]
    require(len(raw) == 4, f"unexpected getLockCapState output: {text!r}")
    caps = [c.strip() for c in raw[0].strip("()").split(",")]
    require(len(caps) == 4, f"unexpected cap tuple: {raw[0]!r}")
    return {
        "total": int(caps[0]),
        "per_lock": int(caps[1]),
        "hourly": int(caps[2]),
        "daily": int(caps[3]),
        "hour_used": int(raw[1]),
        "day_used": int(raw[2]),
        "available": int(raw[3]),
    }


def source_facts(evm, state, asset, block=None) -> dict:
    bridge, token = state["evm"]["bridge"], state["assets"][asset]["token"]
    facts = {
        "cap": cap_state(evm, bridge, token, block),
        "bridge_balance": int(
            values(evm, token, "balanceOf(address)(uint256)", bridge, block=block)[0]
        ),
        "disabled": values(evm, bridge, "disabledTokens(address)(bool)", token, block=block)[0]
        == "true",
        "allow_lock": values(evm, bridge, "allowLock()(bool)", block=block)[0] == "true",
        "lock_nonce": int(values(evm, bridge, "lockNonce()(uint64)", block=block)[0]),
    }
    if asset == "usdt":
        facts["bridge_blacklisted"] = (
            values(evm, token, "isBlackListed(address)(bool)", bridge, block=block)[0] == "true"
        )
        facts["paused"] = values(evm, token, "paused()(bool)", block=block)[0] == "true"
        facts["fee_basis_points"] = int(
            values(evm, token, "basisPointsRate()(uint256)", block=block)[0]
        )
        facts["maximum_fee"] = int(values(evm, token, "maximumFee()(uint256)", block=block)[0])
    return facts


def finalized_source(evm) -> dict:
    point = evm.rpc("eth_getBlockByNumber", "finalized", False)
    return {"number": int(point["number"], 16), "hash": point["hash"]}


# ---------------------------------------------------------------- TOS reads


def supply_at(view, minter) -> int:
    answers = view.read("runGetMethod", address=minter, method="get_supply_state", stack=[])
    require(all(a["exit_code"] == 0 for a in answers), "supply getter refused")
    supplies = [u.num(a["stack"][0]) for a in answers]
    require(len(set(supplies)) == 1, "references disagree on the supply")
    return supplies[0]


def wallet_balance_at(view, wallet) -> int:
    account = view.account(wallet)
    if account.get("state") != "active":
        return 0
    answers = view.read("runGetMethod", address=wallet, method="get_wallet_data", stack=[])
    require(all(a["exit_code"] == 0 for a in answers), "wallet getter refused")
    balances = [u.num(a["stack"][0]) for a in answers]
    require(len(set(balances)) == 1, "references disagree on the wallet balance")
    return balances[0]


def live_wallet_balance(chain, wallet) -> int:
    if not chain.active(wallet):
        return 0
    return u.num(chain.get(wallet, "get_wallet_data")[0])


# ---------------------------------------------------------------- wallet v3


class WalletV3(u.Wallet):
    """The governance payer: a TOS wallet v3 (wallet-v3.fif's signed layout: global
    id, subwallet, valid-until, seqno, mode, message). Sent at most once, with the
    same reconciliation as Wallet.send_once; an expired message never runs and is
    never re-signed automatically."""

    def __init__(self, chain, seed: bytes, address: str, subwallet: int):
        import nacl.signing

        self.chain, self.key = chain, nacl.signing.SigningKey(seed)
        self.address, self.subwallet, self.init = address, subwallet, None

    def seqno(self) -> int:
        info = self.chain.account(self.address)
        require(info.get("state") == "active", f"{self.address} is not active")
        data = lib.Slice(u.from64(info["data"]))
        seqno, subwallet = data.bits(32), data.bits(32)
        require(subwallet == self.subwallet, "the payer's subwallet differs")
        require(data.bytes(32) == bytes(self.key.verify_key), "the payer key differs")
        return seqno

    def send_once(self, state, intent, build, mode: int = 3, deploy: bool = False) -> dict:
        record = state.intent(intent)
        if record is None:
            for other, pending in state.intents().items():
                require(
                    pending.get("wallet") != self.address or pending.get("state") == "done",
                    f"{self.address} has an unfinished send ({other}); run that step again first",
                )
            seqno = self.seqno()
            outgoing = build()
            valid_until = int(time.time()) + WALLET_V3_TTL
            signed = (
                u.Builder()
                .int(lib.LOCAL_GLOBAL_ID, 32)
                .uint(self.subwallet, 32)
                .uint(valid_until, 32)
                .uint(seqno, 32)
                .uint(mode, 8)
                .ref(outgoing)
                .end()
            )
            body = u.Builder().raw(self.key.sign(signed.hash()).signature).append(signed).end()
            message = u.external(self.address, body)
            record = {
                "kind": "tos",
                "wallet": self.address,
                "seqno": seqno,
                "valid_until": valid_until,
                "boc": u.boc64(message),
                "hash": message.hash().hex(),
                "expected": u.message_summary(outgoing),
                "created_at": int(time.time()),
                "state": "signed",
            }
            state.put_intent(intent, record)
        if record["state"] == "done":
            return record
        if record["state"] == "accepted_not_sent":
            raise u.Refused(u.accepted_not_sent(intent, record))
        seqno = record["seqno"]
        if self.seqno() == seqno:
            require(
                time.time() < record["valid_until"],
                f"{intent}: the signed message expired unsent; inspect it, nothing is re-signed",
            )
            self.chain.send(u.from64(record["boc"]))
            self.chain.wait(f"{self.address} seqno {seqno + 1}", lambda: self.seqno() > seqno)
        require(self.seqno() > seqno, f"{intent}: the payer's seqno is behind the recorded one")
        tx = self.chain.executed_external(self.address, record["hash"], record["created_at"] - 60)
        require(
            tx is not None,
            f"{intent}: seqno {seqno} of {self.address} was used, but not by the journaled "
            f"message {record['hash']}; nothing is marked done",
        )
        record["tx"] = tx
        delivered = tx["took_effect"] and record["expected"] in tx["out"]
        record["state"] = "done" if delivered else "accepted_not_sent"
        state.put_intent(intent, record)
        if not delivered:
            raise u.Refused(u.accepted_not_sent(intent, record))
        return record


def payer_wallet(chain, keys: Path) -> WalletV3:
    raw = (keys / "payer.addr").read_bytes()
    require(len(raw) == 36, "payer.addr is not a 36-byte address file")
    address = lib.Slice(lib.Cell(raw, 288, []))
    account = address.bytes(32).hex()
    wc = int.from_bytes(address.bytes(4), "big", signed=True)
    return WalletV3(chain, u.key_file(keys / "payer.pk"), f"{wc}:{account}", u.PAYER_SUBWALLET)


# ---------------------------------------------------------------- steps


def step_fund_buyer(args, state, chain):
    amount = positive(args.tos, "--tos") * NANO
    payer = payer_wallet(chain, args.keys)
    buyer = u.wallets(chain, args.keys)["buyer"]
    plan = {
        "from": payer.address,
        "to": buyer.address,
        "nanotos": amount,
        "payer_balance": chain.balance(payer.address),
        "buyer_balance": chain.balance(buyer.address),
    }
    if not args.execute:
        return {"dry_run": True, **plan}
    require(plan["payer_balance"] >= amount + NANO, "the payer cannot pay this amount")
    record = payer.transfer(state, args.label, buyer.address, amount, bounce=False)
    result = {**plan, "seqno": record["seqno"], "tx": record["tx"]}
    state.evidence(args.label, result)
    return result


def step_fund_locker(args, state, evm):
    asset = state["assets"][args.asset]
    amount = positive(args.amount, "--amount")
    holder, locker = state["evm"]["deployer"], state["evm"]["locker"]
    held = int(values(evm, asset["token"], "balanceOf(address)(uint256)", locker)[0])
    plan = {"asset": args.asset, "holder": holder, "locker": locker, "held": held, "amount": amount}
    if not args.execute:
        return {"dry_run": True, **plan}
    record = u.evm_send_once(
        evm,
        state,
        args.label,
        holder,
        asset["token"],
        "transfer(address,uint256)",
        locker,
        str(amount),
    )
    require(record["status"] == 1, "funding the locker failed")
    after = int(values(evm, asset["token"], "balanceOf(address)(uint256)", locker)[0])
    result = {**plan, "tx": record["tx"], "block": record["block"], "after": after}
    state.evidence(args.label, result)
    return result


def check_caps(total, per_lock, hourly, daily):
    if (total, per_lock, hourly, daily) == (0, 0, 0, 0):
        return
    for value, name in ((total, "total"), (per_lock, "per-lock"), (hourly, "hourly")):
        positive(value, name)
    positive(daily, "daily")
    require(per_lock <= hourly <= daily, "caps must satisfy per-lock <= hourly <= daily")


def step_caps(args, state, evm):
    asset = state["assets"][args.asset]
    bridge, token = state["evm"]["bridge"], asset["token"]
    caps = [args.total, args.per_lock, args.hourly, args.daily]
    check_caps(*caps)
    before = cap_state(evm, bridge, token)
    record = state.intent(args.label)
    if record is None:
        last = int(values(evm, bridge, "lastLockCapNonce(address)(uint256)", token)[0])
        nonce = last + 1
    else:
        require(
            record.get("args", [])[:5] == [token, *(str(c) for c in caps)],
            f"{args.label} was journaled with other caps; use a new label",
        )
        nonce = int(record["args"][5])
    plan = {"asset": args.asset, "token": token, "caps": caps, "nonce": nonce, "before": before}
    if not args.execute:
        return {"dry_run": True, **plan}
    vote_args = [token, *(str(c) for c in caps), str(nonce)]
    vote = u.evm_vote(evm, state, args.keys, args.label, CAP_ID, vote_args, CAP_VOTE, vote_args)
    after = cap_state(evm, bridge, token)
    require(
        [after["total"], after["per_lock"], after["hourly"], after["daily"]] == caps,
        "the bridge's caps are not the voted ones",
    )
    result = {**plan, "vote": {k: vote.get(k) for k in ("tx", "block", "status")}, "after": after}
    state.evidence(args.label, result)
    return result


def simulate_lock(evm, state, asset, amount, block) -> tuple[bool, str]:
    bridge = state["evm"]["bridge"]
    locker, token = state["evm"]["locker"], state["assets"][asset]["token"]
    target = "0x" + u.split(state["buyer"])[1].hex()
    out = evm.tools.cast_run(
        "call",
        "--block",
        str(block),
        "--from",
        locker,
        bridge,
        u.LOCK,
        token,
        str(amount),
        target,
        check=False,
    )
    return out.returncode == 0, (out.stderr or out.stdout).strip()


def approve_exact(evm, state, label, asset, amount):
    """Lock tooling approves the exact amount, and first clears a non-zero
    allowance (LocalUSDT, like Tether, refuses a non-zero to non-zero change)."""
    token, bridge, locker = (
        state["assets"][asset]["token"],
        state["evm"]["bridge"],
        state["evm"]["locker"],
    )
    allowance = int(
        values(evm, token, "allowance(address,address)(uint256)", locker, bridge)[0]
    )
    if state.intent(label + "-approve-clear") is not None or (
        allowance and state.intent(label + "-approve") is None
    ):
        cleared = u.evm_send_once(
            evm, state, label + "-approve-clear", locker, token,
            "approve(address,uint256)", bridge, "0",
        )
        require(cleared["status"] == 1, "clearing the allowance failed")
    approved = u.evm_send_once(
        evm, state, label + "-approve", locker, token, "approve(address,uint256)", bridge,
        str(amount),
    )
    require(approved["status"] == 1, "the exact approval failed")
    now = int(values(evm, token, "allowance(address,address)(uint256)", locker, bridge)[0])
    return {"before": allowance, "approved": amount, "after": now, "tx": approved["tx"]}


def clear_approval(evm, state, label, asset):
    token, bridge, locker = (
        state["assets"][asset]["token"],
        state["evm"]["bridge"],
        state["evm"]["locker"],
    )
    record = u.evm_send_once(
        evm, state, label + "-approve-reset", locker, token, "approve(address,uint256)",
        bridge, "0",
    )
    require(record["status"] == 1, "resetting the allowance failed")
    now = int(values(evm, token, "allowance(address,address)(uint256)", locker, bridge)[0])
    require(now == 0, "the allowance did not return to zero")
    return record["tx"]


def step_probe(args, state, evm):
    """A lock over a cap (or of a disabled/paused token) is refused for that named
    reason at one pinned source block. The probe needs a real allowance so that
    the transfer itself succeeds and the cap check decides; it approves exactly,
    simulates, and resets the allowance to zero. No lock is sent."""
    amount = positive(args.amount, "--amount")
    reason = REASONS[args.expect]
    locker = state["evm"]["locker"]
    token = state["assets"][args.asset]["token"]
    held = int(values(evm, token, "balanceOf(address)(uint256)", locker)[0])
    if not args.execute:
        return {"dry_run": True, "asset": args.asset, "amount": amount, "expect": reason}
    require(held >= amount, "the locker holds less than the probe; fund it first")
    approval = approve_exact(evm, state, args.label, args.asset, amount)
    block = pinned_block(evm)
    ok, output = simulate_lock(evm, state, args.asset, amount, block["number"])
    facts = source_facts(evm, state, args.asset, block["number"])
    reset = clear_approval(evm, state, args.label, args.asset)
    require(not ok, f"a lock of {amount} was admitted at block {block['number']}: {facts}")
    require(reason in output, f"the lock was refused for another reason: {output[-400:]}")
    result = {
        "asset": args.asset,
        "amount": amount,
        "expected_reason": reason,
        "revert": output[-400:],
        "block": block,
        "facts_at_block": facts,
        "approval": approval,
        "approval_reset_tx": reset,
    }
    state.evidence(args.label, result)
    return result


def lock_event(evm, receipt_tx, bridge, n):
    """The Lock event of lock n in its own receipt: (received, newBalance, decimals)."""
    receipt = evm.rpc("eth_getTransactionReceipt", receipt_tx)
    topic = evm.tools.cast_run("keccak", LOCK_EVENT).stdout.strip().lower()
    found = []
    for log in receipt["logs"]:
        if log["address"].lower() != bridge.lower() or log["topics"][0].lower() != topic:
            continue
        data = bytes.fromhex(log["data"][2:])
        require(len(data) == 32 * 5, "a Lock event of another layout")
        # Indexed: from, token, to_addr_hash. Data: value, new_bridge_balance,
        # decimals, nonce, generation.
        words = [int.from_bytes(data[i : i + 32], "big") for i in range(0, len(data), 32)]
        if words[3] == n:
            found.append(
                {
                    "value": words[0],
                    "new_bridge_balance": words[1],
                    "decimals": words[2],
                    "n": words[3],
                    "generation": words[4],
                    "to_addr_hash": log["topics"][3],
                }
            )
    require(len(found) == 1, f"lock {n} has {len(found)} Lock events in its receipt")
    return found[0]


def step_lock(args, state, evm, chain):
    asset_name = args.asset
    asset = state["assets"][asset_name]
    amount = positive(args.amount, "--amount")
    bridge, locker, token = state["evm"]["bridge"], state["evm"]["locker"], asset["token"]
    buyer = u.wallets(chain, args.keys)["buyer"]
    require(buyer.address == state["buyer"], "the buyer key names another wallet")
    target = "0x" + u.split(buyer.address)[1].hex()
    lock_intent = args.label + "-lock"
    record = state.intent(lock_intent)
    if not args.execute:
        block = pinned_block(evm)
        return {
            "dry_run": True,
            "asset": asset_name,
            "amount": amount,
            "facts": source_facts(evm, state, asset_name, block["number"]),
            "block": block,
        }
    progress = state.get("locks", {}).get(args.label)
    if progress is None:
        require(record is None, f"{lock_intent} exists without its progress record")
        held = int(values(evm, token, "balanceOf(address)(uint256)", locker)[0])
        require(held >= amount, "the locker holds less than the lock; fund it first")
        progress = {
            "asset": asset_name,
            "amount": amount,
            "supply_before": u.num(chain.get(asset["minter"], "get_supply_state")[0]),
            "wallet_before": live_wallet_balance(chain, asset["buyer_token_wallet"]),
            "n": int(values(evm, bridge, "lockNonce()(uint64)")[0]),
        }
        state.set("locks", {**state.get("locks", {}), args.label: progress})
    require(
        progress["asset"] == asset_name and progress["amount"] == amount,
        f"{args.label} was journaled for another asset or amount; use a new label",
    )
    approval = approve_exact(evm, state, args.label, asset_name, amount)
    if record is None:
        block = pinned_block(evm)
        ok, output = simulate_lock(evm, state, asset_name, amount, block["number"])
        require(ok, f"the lock would be refused; nothing is sent: {output[-400:]}")
    n = progress["n"]
    locked = u.evm_send_once(
        evm, state, lock_intent, locker, bridge, u.LOCK, token, str(amount), target,
        meta={"n": n},
    )
    require(locked["status"] == 1, f"the lock failed: {locked}")
    entry = values(evm, bridge, LOCKS, str(n))
    require(
        entry[0].lower() == locker.lower()
        and entry[1].lower() == token.lower()
        and int(entry[3]) == u.GENERATION
        and int(entry[4]) == 1,
        f"lock {n} is not this open lock of the token",
    )
    received = int(entry[2])
    event = lock_event(evm, locked["tx"], bridge, n)
    require(event["value"] == received, "the Lock event's amount differs from the record")
    require(event["decimals"] == u.TOKEN_DECIMALS, "the Lock event's decimals differ")
    require(
        event["generation"] == u.GENERATION and event["to_addr_hash"].lower() == target.lower(),
        "the Lock event names another generation or recipient",
    )
    require(0 < received <= amount, "the bridge received more than was sent")
    receipts = u.pay_and_vote(
        AssetState(state, token), chain, args.keys, buyer, state["tvm"], {"n": n, "amount": received}
    )
    wallet = asset["buyer_token_wallet"]
    expected_wallet = progress["wallet_before"] + received
    chain.wait(
        "the minted tokens in the buyer's wallet",
        lambda: live_wallet_balance(chain, wallet) == expected_wallet,
        timeout=240,
    )
    view = t.View(chain, state.root / "references" / args.label)
    supply = supply_at(view, asset["minter"])
    balance = wallet_balance_at(view, wallet)
    require(
        supply == progress["supply_before"] + received,
        f"finalized supply {supply} is not {progress['supply_before']} + {received}",
    )
    require(balance == expected_wallet, "the finalized buyer wallet balance differs")
    swap = [u.num(x) for x in chain.get(state["tvm"]["bridge"], "get_swap", n)]
    watermark = u.num(chain.get(state["tvm"]["bridge"], "get_bridge_state")[6])
    require(
        swap[0] == 2 or (swap[0] == -1 and watermark > n),
        f"swap {n} is not consumed: {swap}, watermark {watermark}",
    )
    result = {
        "asset": asset_name,
        "requested": amount,
        "received": received,
        "fee_withheld": amount - received,
        "n": n,
        "lock": {k: locked.get(k) for k in ("tx", "block", "status")},
        "lock_event": event,
        "approval": approval,
        "mint_receipts": receipts,
        "second_resolver": {
            "endpoints": view.urls,
            "checkpoint": view.point,
            "supply": supply,
            "buyer_wallet_balance": balance,
        },
        "source_after": source_facts(evm, state, asset_name),
    }
    state.evidence(args.label, result)
    return result


def step_disable(args, state, evm):
    token = state["assets"][args.asset]["token"]
    bridge = state["evm"]["bridge"]
    disable = args.mode == "disable"
    record = state.intent(args.label)
    if record is None:
        nonce = int(values(evm, bridge, "lastDisableTokenNonce(address)(uint256)", token)[0]) + 1
    else:
        require(
            record["args"][:2] == [str(disable).lower(), token],
            f"{args.label} was journaled for another vote; use a new label",
        )
        nonce = int(record["args"][2])
    vote_args = [str(disable).lower(), token, str(nonce)]
    before = source_facts(evm, state, args.asset)
    if not args.execute:
        return {"dry_run": True, "asset": args.asset, "disable": disable, "nonce": nonce}
    vote = u.evm_vote(
        evm, state, args.keys, args.label, DISABLE_ID, vote_args, DISABLE_VOTE, vote_args
    )
    after = source_facts(evm, state, args.asset)
    require(after["disabled"] is disable, "the token's disabled flag is not the voted one")
    result = {
        "asset": args.asset,
        "disable": disable,
        "nonce": nonce,
        "before": before,
        "after": after,
        "vote": {k: vote.get(k) for k in ("tx", "block", "status")},
    }
    state.evidence(args.label, result)
    return result


def step_switch_lock(args, state, evm):
    bridge = state["evm"]["bridge"]
    allow = args.mode == "allow"
    record = state.intent(args.label)
    if record is None:
        nonce = int(values(evm, bridge, "lastLockStatusNonce()(uint256)")[0]) + 1
    else:
        require(
            record["args"][0] == str(allow).lower(),
            f"{args.label} was journaled for another vote; use a new label",
        )
        nonce = int(record["args"][1])
    vote_args = [str(allow).lower(), str(nonce)]
    if not args.execute:
        return {"dry_run": True, "allow": allow, "nonce": nonce}
    vote = u.evm_vote(evm, state, args.keys, args.label, SWITCH_ID, vote_args, SWITCH_VOTE, vote_args)
    now = values(evm, bridge, "allowLock()(bool)")[0] == "true"
    require(now is allow, "allowLock is not the voted value")
    result = {
        "allow": allow,
        "nonce": nonce,
        "vote": {k: vote.get(k) for k in ("tx", "block", "status")},
        "usdc": source_facts(evm, state, "usdc"),
        "usdt": source_facts(evm, state, "usdt"),
    }
    state.evidence(args.label, result)
    return result


def step_issuer(args, state, evm):
    """A LocalUSDT owner call. The fixture's fee bounds (basisPoints < 20,
    maxFee < 50 whole tokens) are checked here as well as by the contract."""
    require(args.asset == "usdt", "only the LocalUSDT fixture has issuer controls")
    token, bridge = state["assets"]["usdt"]["token"], state["evm"]["bridge"]
    owner = values(evm, token, "owner()(address)")[0]
    signature = ISSUER_OPS[args.op]
    if args.op in ("blacklist-bridge", "unblacklist-bridge"):
        call_args = [bridge]
    elif args.op == "set-fee":
        require(
            args.basis_points is not None and args.max_fee is not None,
            "set-fee needs --basis-points and --max-fee",
        )
        require(0 <= args.basis_points < 20 and 0 <= args.max_fee < 50, "fee bounds")
        call_args = [str(args.basis_points), str(args.max_fee)]
    else:
        call_args = []
    before = source_facts(evm, state, "usdt")
    if not args.execute:
        return {"dry_run": True, "op": args.op, "owner": owner, "before": before}
    record = u.evm_send_once(evm, state, args.label, owner, token, signature, *call_args)
    require(record["status"] == 1, f"{args.op} failed")
    after = source_facts(evm, state, "usdt")
    expected = {
        "blacklist-bridge": ("bridge_blacklisted", True),
        "unblacklist-bridge": ("bridge_blacklisted", False),
        "pause": ("paused", True),
        "unpause": ("paused", False),
    }.get(args.op)
    if expected:
        require(after[expected[0]] is expected[1], f"{args.op} did not take effect")
    else:
        require(
            after["fee_basis_points"] == args.basis_points
            and after["maximum_fee"] == args.max_fee * 10**u.TOKEN_DECIMALS,
            "the fee is not the set one",
        )
    result = {
        "op": args.op,
        "owner": owner,
        "tx": record["tx"],
        "block": record["block"],
        "before": before,
        "after": after,
    }
    state.evidence(args.label, result)
    return result


def burn_logs(boc: bytes) -> dict:
    """A transaction's account, lt and hash, and every LOG_BURN external message it
    sent, decoded from its own cells. The token bridge's body is exactly 704 bits:
    destination(160), amount(128), token(160), from_address_hash(256)."""
    root = lib.parse_boc(boc)
    s = lib.Slice(root)
    require(s.bits(4) == 0b0111, "not a transaction")
    account, lt = s.bytes(32).hex(), s.bits(64)
    m = lib.Slice(root.refs[0])
    if m.bits(1):
        m.take_ref()
    logs = []
    if m.bits(1):
        entries = lib.hashmap_items(m.take_ref(), 15)
        for key in sorted(entries):
            message = entries[key].take_ref()
            ms = lib.Slice(message)
            if ms.bits(2) != 0b11:  # not ext_out_msg_info
                continue
            require(ms.bits(2) == 0b10 and ms.bits(1) == 0, "an external from a non-std source")
            ms.bits(8 + 256)
            require(ms.bits(2) == 0b01, "an external to a non-extern destination")
            length = ms.bits(9)
            topic = ms.bits(length)
            ms.bits(64 + 32)
            require(ms.bits(1) == 0, "an external with a StateInit")
            if length != 256 or topic != LOG_BURN:
                continue
            require(ms.bits(1) == 1, "LOG_BURN body is not in a reference")
            body = ms.take_ref()
            bits = u.cell_bits(body)
            require(len(bits) == 704 and not body.refs, "LOG_BURN body has another layout")
            logs.append(
                {
                    "destination": "0x" + format(int(bits[0:160], 2), "040x"),
                    "amount": int(bits[160:288], 2),
                    "token": "0x" + format(int(bits[288:448], 2), "040x"),
                    "from_address_hash": format(int(bits[448:704], 2), "064x"),
                }
            )
    return {"account": account, "lt": lt, "hash": root.hash().hex(), "logs": logs}


def issuer_binding(state, asset, monitor_binding: Path) -> dict:
    """The T19 issuer binding of the LocalUSDT fixture, with its runtime code pinned
    by the monitor's reviewed source binding (read-only)."""
    require(asset == "usdt", "only the legacy-USDT fixture has a T19 issuer profile")
    token = state["assets"][asset]["token"]
    pins = json.loads(monitor_binding.read_text())
    pinned = [a for a in pins["assets"] if a["token"].lower() == token]
    require(len(pinned) == 1 and pinned[0]["profile"] == "legacy_usdt", "no reviewed issuer pin")
    return {
        "schema": "tos-settlement-issuer/1",
        "chain_id": u.EVM_CHAIN_ID,
        "token": token,
        "code_sha256": pinned[0]["code_sha256"],
        "profile": "legacy_usdt",
        "bridge": state["evm"]["bridge"],
        "master": state["assets"][asset]["minter"],
        "wallet": state["assets"][asset]["buyer_token_wallet"],
    }


def redemption_module():
    return _load("prepare_token_redemption", HERE.parent.parent / "testnet/scripts/prepare-token-redemption.py")


def step_burn(args, state, evm, chain):
    """Burn wrapped tokens to an EVM receiver. The body is the T19 tool's: it reads
    the issuer's blacklist, pause, deprecation and fee at a finalized source block
    first and refuses before building anything. The prepared document, with its
    received-amount preview, is journaled before the burn is signed."""
    asset = state["assets"][args.asset]
    amount = positive(args.amount, "--amount")
    receiver = args.receiver.lower()
    burns = state.get("burns", {})
    prepared = burns.get(args.label, {}).get("prepared")
    if prepared is None:
        redemption = redemption_module()
        binding = issuer_binding(state, args.asset, args.monitor_state / "binding.json")
        query_id = int.from_bytes(hashlib.sha256(args.label.encode()).digest()[:8], "big")
        prepared = redemption.prepare(
            redemption.issuer.source.RPC(args.evm_rpc), binding, receiver, amount, query_id
        )
        if not args.execute:
            return {"dry_run": True, "prepared": prepared}
        require(
            live_wallet_balance(chain, asset["buyer_token_wallet"]) >= amount,
            "the buyer holds less than the burn",
        )
        burns = {
            **burns,
            args.label: {
                "asset": args.asset,
                "amount": amount,
                "receiver": receiver,
                "prepared": prepared,
                "supply_before": u.num(chain.get(asset["minter"], "get_supply_state")[0]),
                "wallet_before": live_wallet_balance(chain, asset["buyer_token_wallet"]),
            },
        }
        state.set("burns", burns)
    entry = state["burns"][args.label]
    require(
        entry["asset"] == args.asset and entry["amount"] == amount and entry["receiver"] == receiver,
        f"{args.label} was journaled for another burn; use a new label",
    )
    body = u.from64(prepared["body_boc"])
    require(body.hash().hex() == prepared["body_hash"], "the prepared body changed")
    require(prepared["destination"] == asset["buyer_token_wallet"], "the burn names another wallet")
    buyer = u.wallets(chain, args.keys)["buyer"]
    intent = args.label + "-burn"
    record = buyer.transfer(state, intent, asset["buyer_token_wallet"], u.BURN_FEE, body)
    # The burn's graph (wallet, minter, bridge) was archived on nodes 4-6 when the
    # send finished; the bridge's own transaction carries LOG_BURN.
    manifest = archive.StepJournal(state.root / "archive/sends").validate(
        intent, json.loads((state.root / "archive/sends/steps.json").read_text())["completed"][intent]
    )
    bridge_account = u.split(state["tvm"]["bridge"])[1].hex()
    found = []
    for item in manifest["files"]:
        if not item["file"].startswith("transactions/"):
            continue
        decoded = burn_logs((state.root / "archive/sends" / intent / item["file"]).read_bytes())
        if decoded["account"] == bridge_account and decoded["logs"]:
            found.append(decoded)
    require(len(found) == 1 and len(found[0]["logs"]) == 1, "the burn has no single LOG_BURN")
    log = found[0]["logs"][0]
    require(
        log["destination"] == receiver
        and log["amount"] == amount
        and log["token"] == asset["token"]
        and log["from_address_hash"] == u.split(buyer.address)[1].hex(),
        f"LOG_BURN differs from the burn: {log}",
    )
    view = t.View(chain, state.root / "references" / args.label)
    supply = supply_at(view, asset["minter"])
    balance = wallet_balance_at(view, asset["buyer_token_wallet"])
    require(supply == entry["supply_before"] - amount, "the finalized supply did not fall by the burn")
    require(balance == entry["wallet_before"] - amount, "the buyer's balance did not fall by the burn")
    result = {
        "asset": args.asset,
        "amount": amount,
        "receiver": receiver,
        "preview": {k: prepared[k] for k in ("amount_atomic", "received_atomic", "issuer_fee_atomic", "warning", "issuer")},
        "burn_send": {"seqno": record["seqno"], "tx": record["tx"]},
        "bridge_transaction": {k: found[0][k] for k in ("account", "lt", "hash")},
        "log_burn": log,
        "second_resolver": {"endpoints": view.urls, "checkpoint": view.point, "supply": supply,
                            "buyer_wallet_balance": balance},
    }
    state.set("burns", {**state["burns"], args.label: {**entry, "result": result}})
    state.evidence(args.label, result)
    return result


def step_unlock(args, state, evm):
    """Oracle-sign a recorded burn and submit Bridge.unlock (SafeERC20 safeTransfer:
    LocalUSDT's transfer returns no bool). The receiver gets the amount less the
    issuer fee; the bridge's balance falls by the full amount."""
    burn = state.get("burns", {}).get(args.burn, {}).get("result")
    require(burn is not None, f"no recorded burn {args.burn}")
    receiver = args.receiver.lower()
    require(burn["receiver"] == receiver, "the unlock names another receiver than the burn")
    token, bridge = state["assets"][burn["asset"]]["token"], state["evm"]["bridge"]
    log, tx = burn["log_burn"], burn["bridge_transaction"]
    swap = (
        f"({receiver},{token},{log['amount']},"
        f"(0x{log['from_address_hash']},0x{tx['hash']},{tx['lt']}))"
    )
    before = {
        "receiver": int(values(evm, token, "balanceOf(address)(uint256)", receiver)[0]),
        "bridge": int(values(evm, token, "balanceOf(address)(uint256)", bridge)[0]),
        "facts": source_facts(evm, state, burn["asset"]),
    }
    if not args.execute:
        return {"dry_run": True, "swap": swap, "before": before}
    progress = state.get("unlocks", {}).get(args.label)
    if progress is None:
        progress = {"burn": args.burn, "before": before}
        state.set("unlocks", {**state.get("unlocks", {}), args.label: progress})
    require(progress["burn"] == args.burn, f"{args.label} was journaled for another burn")
    vote = u.evm_vote(evm, state, args.keys, args.label, SWAP_ID, [swap], UNLOCK, [swap])
    before = progress["before"]
    after = {
        "receiver": int(values(evm, token, "balanceOf(address)(uint256)", receiver)[0]),
        "bridge": int(values(evm, token, "balanceOf(address)(uint256)", bridge)[0]),
    }
    facts = before["facts"]
    fee = 0
    if burn["asset"] == "usdt":
        fee = min(log["amount"] * facts["fee_basis_points"] // 10000, facts["maximum_fee"])
    require(before["bridge"] - after["bridge"] == log["amount"], "the bridge did not pay the amount")
    require(
        after["receiver"] - before["receiver"] == log["amount"] - fee,
        "the receiver did not get the amount less the issuer fee",
    )
    require(
        int(burn["preview"]["received_atomic"]) == log["amount"] - fee,
        "the T19 preview differs from what the receiver got",
    )
    result = {
        "burn": args.burn,
        "swap": swap,
        "vote": {k: vote.get(k) for k in ("tx", "block", "status")},
        "before": before,
        "after": after,
        "issuer_fee": fee,
        "received": log["amount"] - fee,
    }
    state.evidence(args.label, result)
    return result


def step_observe(args, state):
    """Retain the running monitor's published report, snapshot digest and incident
    latches. Read-only: the monitor's lock is not taken and nothing is written to
    its state directory."""
    root = args.monitor_state
    report = json.loads((root / "report.json").read_text())
    snapshot = (root / "snapshot.json").read_bytes()
    incidents = json.loads((root / "incidents.json").read_text())
    observation = json.loads(snapshot)
    sources = {
        a["id"]: {
            k: a.get(k)
            for k in (
                "bridge_balance",
                "wrapped_supply",
                "lock_cap",
                "bridge_blacklisted",
                "paused",
                "fee_basis_points",
                "maximum_fee",
                "balance_events",
            )
        }
        for a in observation["assets"]
    }
    result = {
        "report": report,
        "report_age_seconds": int(time.time()) - report["checkpoint"]["utime"],
        "incidents": incidents,
        "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
        "snapshot_checkpoint": observation["checkpoint"],
        "source_checkpoint": observation["source_checkpoint"],
        "assets": sources,
    }
    if args.expect_clean:
        require(
            report["checkpoint"]["utime"] == observation["checkpoint"]["utime"]
            and result["report_age_seconds"] <= 120,
            "the monitor report is stale",
        )
        require(
            not report["alarms"]
            and not report["latched_incidents"]
            and not report["provider_pause_assets"]
            and not incidents,
            f"the monitor is not clean: {report['alarms']} {report['latched_incidents']}",
        )
    if args.expect_alarm:
        asset, code = args.expect_alarm.split(":", 1)
        require(
            any(a["asset"] == asset and a["code"] == code for a in report["alarms"]),
            f"the monitor did not raise {args.expect_alarm}: {report['alarms']}",
        )
        if code in EMERGENCIES:
            require(
                report["provider_pause_assets"] == [asset]
                and args.expect_alarm in report["latched_incidents"],
                f"{args.expect_alarm} is not latched for that asset alone: "
                f"{report['provider_pause_assets']} {report['latched_incidents']}",
            )
    archive.StepJournal(state.root / "archive" / "monitor").retain_verifier(args.label, result)
    state.evidence(args.label, result)
    return result


def step_reconcile(args, state, evm, chain):
    """Supply against backing for both assets: the TOS minter supply at one
    checkpoint on nodes 4-6, and the bridge balance at one finalized source block.
    Every lock this run made is minted, so the two must be equal when no lock or
    burn is open."""
    view = t.View(chain, state.root / "references" / args.label)
    point = finalized_source(evm)
    out = {"checkpoint": view.point, "source_finalized": point, "assets": {}}
    for name in ASSETS:
        asset = state["assets"][name]
        supply = supply_at(view, asset["minter"])
        facts = source_facts(evm, state, name, point["number"])
        out["assets"][name] = {
            "wrapped_supply": supply,
            "bridge_balance": facts["bridge_balance"],
            "reconciled": supply == facts["bridge_balance"],
            "source": facts,
        }
    if args.expect_reconciled:
        for name, item in out["assets"].items():
            require(item["reconciled"], f"{name} supply {item['wrapped_supply']} != backing "
                    f"{item['bridge_balance']}")
    state.evidence(args.label, out)
    return out


def step_status(args, state, evm, chain):
    return {
        name: {
            **source_facts(evm, state, name),
            "wrapped_supply": u.num(chain.get(state["assets"][name]["minter"], "get_supply_state")[0]),
            "buyer_wallet": live_wallet_balance(chain, state["assets"][name]["buyer_token_wallet"]),
        }
        for name in ASSETS
    } | {"buyer_tos": chain.balance(state["buyer"])}


# ---------------------------------------------------------------- main


def label(text):
    require(archive.LABEL.fullmatch(text) is not None, f"invalid label {text!r}")
    return text


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument(
        "step",
        choices=(
            "status",
            "fund-buyer",
            "fund-locker",
            "caps",
            "probe",
            "lock",
            "disable",
            "switch-lock",
            "issuer",
            "burn",
            "unlock",
            "observe",
            "reconcile",
        ),
    )
    p.add_argument("--data", type=Path, default=Path("/data"))
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--usdc-state", type=Path, default=Path("/data/usdc/state.json"))
    p.add_argument("--usdt-state", type=Path, default=Path("/data/usdt-t15/state.json"))
    p.add_argument("--keys", type=Path, default=Path("/data/usdc/keys"))
    p.add_argument("--monitor-state", type=Path, default=Path("/data/usdt-t15-monitor"))
    p.add_argument("--tos-root", required=True)
    p.add_argument("--tosctl", default="")
    p.add_argument("--cast", default=shutil.which("cast") or "cast")
    p.add_argument("--evm-rpc", default="http://127.0.0.1:18545")
    p.add_argument("--label", type=label)
    p.add_argument("--asset", choices=ASSETS)
    p.add_argument("--amount", type=int)
    p.add_argument("--tos", type=int)
    p.add_argument("--total", type=int)
    p.add_argument("--per-lock", type=int)
    p.add_argument("--hourly", type=int)
    p.add_argument("--daily", type=int)
    p.add_argument("--expect", choices=sorted(REASONS))
    p.add_argument("--mode", choices=("disable", "enable", "allow", "stop"))
    p.add_argument("--op", choices=sorted(ISSUER_OPS))
    p.add_argument("--basis-points", type=int)
    p.add_argument("--max-fee", type=int)
    p.add_argument("--receiver")
    p.add_argument("--burn", type=label)
    p.add_argument("--expect-clean", action="store_true")
    p.add_argument("--expect-alarm", help="asset:code the monitor must report")
    p.add_argument("--expect-reconciled", action="store_true")
    p.add_argument("--execute", action="store_true")
    return p


NEEDS = {
    "fund-buyer": ("label", "tos"),
    "fund-locker": ("label", "asset", "amount"),
    "caps": ("label", "asset", "total", "per_lock", "hourly", "daily"),
    "probe": ("label", "asset", "amount", "expect"),
    "lock": ("label", "asset", "amount"),
    "disable": ("label", "asset", "mode"),
    "switch-lock": ("label", "mode"),
    "issuer": ("label", "asset", "op"),
    "burn": ("label", "asset", "amount", "receiver"),
    "unlock": ("label", "asset", "burn", "receiver"),
    "observe": ("label",),
    "reconcile": ("label",),
}


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        require(args.evm_rpc.startswith("http://127.0.0.1:"), "local source endpoint required")
        for field in NEEDS.get(args.step, ()):
            require(getattr(args, field) is not None, f"{args.step} needs --{field.replace('_', '-')}")
        if args.step == "disable":
            require(args.mode in ("disable", "enable"), "disable takes --mode disable|enable")
        if args.step == "switch-lock":
            require(args.mode in ("allow", "stop"), "switch-lock takes --mode allow|stop")
        u.CAST[0] = args.cast
        root = u.private_dir(args.state)
        with (root / "driver.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            usdc_state = json.loads(args.usdc_state.read_text())
            usdt_state = json.loads(args.usdt_state.read_text())
            chain = u.Chain(args.data)
            args.evm_artifacts = ""
            evm = u.Evm(u.Tools(args))
            require(evm.chain_id() == u.EVM_CHAIN_ID, "not the approved local source chain")
            state = t.EvidenceState(root, evm)
            state.chain = chain
            t.View(chain, root / "references" / "startup")  # approved genesis on nodes 4-6
            fixed = assets(usdc_state, usdt_state)
            base = {
                "bridge": usdc_state["evm"]["bridge"].lower(),
                "deployer": usdc_state["evm"]["deployer"],
                "locker": usdc_state["evm"]["locker"],
                "oracles": usdc_state["evm"]["oracles"],
            }
            for key, value in (
                ("assets", fixed),
                ("evm", base),
                ("tvm", usdc_state["tvm"]),
                ("buyer", usdc_state["wallets"]["buyer"]),
            ):
                if state.get(key) is None:
                    state.set(key, value)
                require(state[key] == value, f"the recorded {key} differs from the source runs")
            state.recover_source()
            if args.step == "status":
                result = step_status(args, state, evm, chain)
            elif args.step == "fund-buyer":
                result = step_fund_buyer(args, state, chain)
            elif args.step == "fund-locker":
                result = step_fund_locker(args, state, evm)
            elif args.step == "caps":
                result = step_caps(args, state, evm)
            elif args.step == "probe":
                result = step_probe(args, state, evm)
            elif args.step == "lock":
                result = step_lock(args, state, evm, chain)
            elif args.step == "disable":
                result = step_disable(args, state, evm)
            elif args.step == "switch-lock":
                result = step_switch_lock(args, state, evm)
            elif args.step == "issuer":
                result = step_issuer(args, state, evm)
            elif args.step == "burn":
                result = step_burn(args, state, evm, chain)
            elif args.step == "unlock":
                result = step_unlock(args, state, evm)
            elif args.step == "observe":
                result = step_observe(args, state)
            elif args.step == "reconcile":
                result = step_reconcile(args, state, evm, chain)
            else:
                raise u.Refused(f"{args.step} is not implemented in this revision")
            print(json.dumps(result, indent=1, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, u.Refused, lib.TestnetError) as error:
        print("stablecoin acceptance refused: " + str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
