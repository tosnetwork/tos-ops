"""Tests for testnet_ops: the journal, the gate, settlement, and the manual paths,
on the asynchronous fake chain (fakechain.py) and on real node answers and
messages captured from the d7ef85b4c rehearsal (data/ops-*.json)."""

import base64
import json
import os
import time

import chainbuild
import fakechain
import pytest
import testnet_lib as lib
import testnet_ops as ops
from conftest import DATA
from fakechain import NANO, build_external, internal_message

BOOT = "-1:" + "11" * 32
DEST = "-1:" + "de" * 32
OTHER = "-1:" + "0f" * 32
EMPTY = lib.cell_from_bits("").hash().hex()


class Crash(Exception):
    pass


@pytest.fixture
def world(tmp_path, monkeypatch):
    chain = fakechain.Chain()
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir()
    (ceremony / "genesis.json").write_text(json.dumps({"zero_state": chain.zero_state}))
    chain.wallet(BOOT, 100_000 * NANO, public_key="b0" * 32)
    monkeypatch.setattr(ops, "SETTLE_SECONDS", 60)

    def now():
        return chain.now

    def sleep(seconds):
        chain.tick()

    operations = ops.Operations(
        ceremony, [chain.node("http://a"), chain.node("http://b")], 2, clock=now, sleep=sleep
    )
    return chain, operations, ceremony


def params(value=5 * NANO, destination=DEST, wallet=BOOT, kind="fund", **extra):
    out = {
        "kind": kind,
        "wallet": wallet,
        "destination": destination,
        "value": value,
        "bounce": False,
        "body_hash": EMPTY,
        "state_init_hash": None,
        "subwallet": 0x504F4F4C if wallet == OWNER else 0,
    }
    out.update(extra)
    return out


def signer(
    chain,
    wallet=BOOT,
    destination=DEST,
    value=5 * NANO,
    bounce=False,
    body=None,
    global_id=2,
    ttl=300,
    mode=3,
    seqno_offset=0,
    salt=b"",
    subwallet=None,
):
    calls = []
    subwallet = (0x504F4F4C if wallet == OWNER else 0) if subwallet is None else subwallet

    def sign(seqno):
        calls.append(seqno)
        internal = internal_message(destination, value, bounce, body=body)
        return build_external(
            wallet,
            global_id,
            seqno + seqno_offset,
            chain.now + ttl,
            internal,
            mode=mode,
            subwallet=subwallet,
            salt=salt + bytes([len(calls)]),
        )

    sign.calls = calls
    return sign


def run(operations, op_id="fund-a", p=None, sign=None, chain=None, **kw):
    return operations.run(op_id, p or params(), sign or signer(chain), lambda d: None, **kw)


# ---------------------------------------------------------------- happy path


def test_a_transfer_settles_from_the_chain(world):
    chain, operations, ceremony = world
    record = run(operations, chain=chain)
    assert record["state"] == "settled"
    assert record["evidence"]["destination_tx"]
    assert chain.account(DEST)["balance"] == 5 * NANO
    lines = [
        json.loads(line)["state"]
        for line in (ceremony / "operations/fund-a.jsonl").read_text().splitlines()
    ]
    assert lines == ["planned", "signed", "broadcast", "settled"]
    assert len(chain.sent) == 1


NOT_APPLIED_MESSAGE = (
    "getAccountState: [Error : 651 : cannot load block (-1,8000000000000000,338211):ab:cd"
    " : block (-1,8000000000000000,338211) is not applied (last known masterchain block: 338209)]"
)


def lagging(node, methods, failures, monkeypatch):
    """`node` answers its first `failures` calls of `methods` as a node that has not
    applied the block yet; returns the list of every call it received."""
    monkeypatch.setattr(lib, "NOT_APPLIED_FIRST_DELAY", 0.001)
    monkeypatch.setattr(lib, "NOT_APPLIED_MAX_DELAY", 0.002)
    monkeypatch.setattr(lib, "NOT_APPLIED_RETRY_SECONDS", 0.05)
    original, calls, refused = getattr(node.rpc, "wrapped", node.rpc), [], []

    def rpc(url, rpc_method, /, **kw):
        calls.append(rpc_method)
        if rpc_method in methods and len(refused) < failures:
            refused.append(rpc_method)
            raise lib.RpcError(
                url, rpc_method, -32603, "UPSTREAM_UNAVAILABLE", NOT_APPLIED_MESSAGE, True
            )
        return original(url, rpc_method, **kw)

    node.rpc = rpc
    return calls


@pytest.mark.parametrize("failures", [1, 2])
@pytest.mark.parametrize("index", [0, 1])
def test_a_preflight_read_waits_for_a_lagging_validator(world, monkeypatch, failures, index):
    chain, operations, _ = world
    calls = lagging(operations.nodes[index], {"getAddressInformation"}, failures, monkeypatch)
    record = run(operations, chain=chain)
    assert record["state"] == "settled" and len(chain.sent) == 1
    assert calls.count("getAddressInformation") > failures


def test_a_preflight_read_still_not_applied_after_the_bound_is_unknown(world, monkeypatch):
    chain, operations, _ = world
    sign = signer(chain)
    # more refusals than the bound admits, few enough that an unbounded read ends
    lagging(operations.nodes[1], {"getAddressInformation"}, 200, monkeypatch)
    with pytest.raises(ops.Unknown, match="is not applied"):
        run(operations, sign=sign)
    assert sign.calls == [] and chain.sent == []


def test_a_validator_that_caught_up_must_still_agree(world, monkeypatch):
    chain, operations, _ = world
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(BOOT, NANO, False)))
    chain.settle_all()
    behind = chain.node("http://b", lag=True)
    calls = lagging(behind, {"getAddressInformation", "getTransactionsStd"}, 2, monkeypatch)
    pair = ops.Operations(
        operations.ceremony,
        [chain.node("http://a"), behind],
        2,
        clock=lambda: chain.now,
        sleep=lambda s: chain.tick(),
    )
    with pytest.raises(ops.Unknown, match="disagree"):
        pair.history(BOOT, None)
    assert len(calls) > 2


def test_a_send_answered_not_applied_is_not_repeated(world, monkeypatch):
    chain, operations, _ = world
    calls = lagging(operations.nodes[0], {"sendBoc"}, 1, monkeypatch)
    with pytest.raises(ops.Unknown, match="is not applied"):
        run(operations, chain=chain)
    assert calls.count("sendBoc") == 1 and chain.sent == []
    assert operations.journal.record("fund-a")["state"] == "signed"


def test_a_settled_operation_is_never_sent_again(world):
    chain, operations, _ = world
    sign = signer(chain)
    run(operations, sign=sign, chain=chain)
    run(operations, sign=sign, chain=chain)
    assert sign.calls == [1] and len(chain.sent) == 1


def test_a_credit_to_an_undeployed_wallet_settles_although_aborted(world):
    chain, operations, _ = world
    record = run(operations, chain=chain)
    delivery = chain.account(DEST)["txs"][-1]
    assert delivery["aborted"] is True and delivery["compute"]["success"] is False
    assert record["state"] == "settled"


# ---------------------------------------------------------------- the message checks


@pytest.mark.parametrize(
    "change,message",
    [
        ({"destination": OTHER}, "not the intended transfer"),
        ({"value": 6 * NANO}, "not the intended transfer"),
        ({"bounce": True}, "not the intended transfer"),
        ({"body": lib.cell_from_bits("1")}, "not the intended transfer"),
        ({"global_id": 1}, "global id 1"),
        ({"seqno_offset": 1}, "seqno"),
        ({"ttl": 4000}, "expires"),
        ({"ttl": -5}, "expires"),
        ({"mode": 128}, "send mode"),
        ({"wallet": OTHER}, "not the signing wallet"),
    ],
)
def test_a_message_that_is_not_the_intended_one_is_refused_before_journaling(
    world, change, message
):
    chain, operations, ceremony = world
    with pytest.raises(ops.OperationRefused, match=message):
        run(operations, sign=signer(chain, **change), chain=chain)
    assert chain.sent == []
    assert ops.state_of(operations.journal.record("fund-a")) == "planned"


def test_a_host_message_may_live_120_s_at_most(world):
    chain, operations, _ = world
    p = params(kind="deploy-pool")
    with pytest.raises(ops.OperationRefused, match="expires"):
        operations.run("deploy-x", p, signer(chain, ttl=300), lambda d: None)
    assert chain.sent == []


# ---------------------------------------------------------------- the gate


def test_unexplained_outgoing_activity_refuses(world):
    chain, operations, _ = world
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(OTHER, NANO, False)))
    chain.settle_all()
    with pytest.raises(ops.OperationRefused, match="no settled or failed operation explains"):
        run(operations, chain=chain)
    assert len(chain.sent) == 1


def test_a_message_to_the_wallet_itself_needs_no_operation(world):
    chain, operations, _ = world
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(BOOT, NANO, False)))
    chain.settle_all()
    assert run(operations, chain=chain)["state"] == "settled"


def test_a_baseline_accounts_for_history_before_the_journal(world):
    chain, operations, _ = world
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(OTHER, NANO, False)))
    chain.settle_all()
    operations.set_baseline(BOOT, "epoch started before the journal")
    assert run(operations, chain=chain)["state"] == "settled"


def test_a_baseline_is_refused_over_a_planned_operation(world):
    chain, operations, _ = world
    operations.begin("planned-a", params())
    with pytest.raises(ops.OperationRefused, match="operation planned-a is open"):
        operations.set_baseline(BOOT, "would hide the planned payment's history")


def test_an_unexplained_transaction_after_the_baseline_refuses(world):
    chain, operations, _ = world
    operations.set_baseline(BOOT, "x") if chain.account(BOOT)["txs"] else None
    run(operations, chain=chain)
    chain.send(build_external(BOOT, 2, 2, chain.now + 300, internal_message(OTHER, NANO, False)))
    chain.settle_all()
    with pytest.raises(ops.OperationRefused, match="explains"):
        run(operations, "fund-b", chain=chain)


def settled_lt(operations, op_id):
    return int(operations.journal.record(op_id)["evidence"]["wallet_tx_lt"])


def prune_history(operations, monkeypatch, before):
    """Validators that have collected every transaction at or below lt `before`, as
    a node answers: a page stops before a collected transaction (and names it as
    the previous one); a request that starts at one fails."""
    for node in operations.nodes:

        def rpc(url, rpc_method, /, _original=node.rpc, **kw):
            if rpc_method != "getTransactionsStd":
                return _original(url, rpc_method, **kw)
            if int(kw["lt"]) <= before:
                raise lib.RpcError(url, rpc_method, -32603, "INTERNAL_ERROR", "lt not in db", False)
            answer = _original(url, rpc_method, **kw)
            txs = answer["transactions"]
            for i, tx in enumerate(txs):
                if int(tx["transaction_id"]["lt"]) <= before:
                    return dict(
                        answer, transactions=txs[:i], previous_transaction_id=tx["transaction_id"]
                    )
            return answer

        monkeypatch.setattr(node, "rpc", rpc)


def credit(chain, wallet):
    """An incoming transfer: a transaction of `wallet` that sends nothing."""
    if OTHER not in chain.accounts:
        chain.wallet(OTHER, 100 * NANO, public_key="0f" * 32)
    seqno = chain.account(OTHER)["seqno"]
    chain.send(
        build_external(OTHER, 2, seqno, chain.now + 300, internal_message(wallet, NANO, False))
    )
    chain.settle_all()


def test_a_settled_operation_starts_the_history_once_older_history_is_pruned(world, monkeypatch):
    chain, operations, _ = world
    run(operations, chain=chain)
    run(operations, "fund-b", chain=chain)
    credit(chain, BOOT)
    # Everything before fund-b's own transaction is collected; a credit follows it.
    prune_history(operations, monkeypatch, settled_lt(operations, "fund-b") - 1)
    assert (
        operations.history_start(BOOT)["hash"]
        == operations.journal.record("fund-b")["evidence"]["wallet_tx"]
    )
    assert run(operations, "fund-c", chain=chain)["state"] == "settled"


def test_an_idle_wallet_needs_no_pruned_transaction(world, monkeypatch):
    chain, operations, _ = world
    run(operations, chain=chain)
    # fund-a's transaction is the head and is itself collected.
    prune_history(operations, monkeypatch, settled_lt(operations, "fund-a"))
    assert run(operations, "fund-b", chain=chain)["state"] == "settled"


def test_unexplained_activity_after_the_settled_operation_still_refuses(world, monkeypatch):
    chain, operations, _ = world
    run(operations, chain=chain)
    chain.send(build_external(BOOT, 2, 2, chain.now + 300, internal_message(OTHER, NANO, False)))
    chain.settle_all()
    prune_history(operations, monkeypatch, settled_lt(operations, "fund-a") - 1)
    with pytest.raises(ops.OperationRefused, match="no settled or failed operation explains"):
        run(operations, "fund-b", chain=chain)


def test_a_record_without_a_recorded_lt_is_reached_by_hash(world, monkeypatch):
    chain, operations, _ = world
    run(operations, chain=chain)
    run(operations, "fund-b", chain=chain)
    credit(chain, BOOT)
    prune_history(operations, monkeypatch, settled_lt(operations, "fund-b") - 1)
    path = operations.journal.path("fund-b")
    lines = [dict(line) for line in operations.journal.lines("fund-b")]
    for line in lines:
        (line.get("evidence") or {}).pop("wallet_tx_lt", None)
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    assert operations.history_start(BOOT)["lt"] == "0"
    assert run(operations, "fund-c", chain=chain)["state"] == "settled"


def test_a_later_baseline_wins_over_an_older_settled_operation(world):
    chain, operations, _ = world
    run(operations, chain=chain)
    chain.send(build_external(BOOT, 2, 2, chain.now + 300, internal_message(OTHER, NANO, False)))
    chain.settle_all()
    operations.set_baseline(BOOT, "a transfer a person accounted for")
    assert operations.history_start(BOOT) == operations.journal.baseline(BOOT)
    assert run(operations, "fund-b", chain=chain)["state"] == "settled"


@pytest.mark.parametrize("which", ["lag", "broken"])
def test_history_the_validators_do_not_agree_on_refuses(tmp_path, which):
    chain = fakechain.Chain()
    ceremony = tmp_path / "c"
    ceremony.mkdir()
    (ceremony / "genesis.json").write_text(json.dumps({"zero_state": chain.zero_state}))
    chain.wallet(BOOT, 100 * NANO)
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(BOOT, NANO, False)))
    chain.settle_all()
    operations = ops.Operations(
        ceremony,
        [chain.node("http://a"), chain.node("http://b", **{which: True})],
        2,
        clock=lambda: chain.now,
        sleep=lambda s: chain.tick(),
    )
    with pytest.raises(ops.OperationRefused):
        run(operations, chain=chain)
    assert chain.sent[1:] == []


def test_another_network_is_refused(world):
    chain, operations, ceremony = world
    (ceremony / "genesis.json").write_text(
        json.dumps({"zero_state": {"root_hash": "x", "file_hash": "y"}})
    )
    with pytest.raises(ops.OperationRefused, match="another network"):
        run(operations, chain=chain)


def test_two_validators_are_required():
    with pytest.raises(ops.OperationRefused, match="two different validators"):
        ops.Operations("/c", [ops.Node("http://a"), ops.Node("http://a")], 2)


def test_an_open_operation_blocks_its_wallet(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "broadcast")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    with pytest.raises(ops.OperationRefused, match="fund-a of .* is open"):
        run(operations, "fund-b", chain=chain)


# ---------------------------------------------------------------- interruptions


def crash_at(monkeypatch, op_id, point):
    def crash(i, p):
        if (i, p) == (op_id, point):
            raise Crash(p)

    monkeypatch.setattr(ops, "crash_point", crash)


@pytest.mark.parametrize("point", ["signed", "broadcast", "delivered"])
def test_an_interrupted_operation_is_never_resent_by_a_rerun(world, monkeypatch, point):
    chain, operations, _ = world
    sign = signer(chain)
    crash_at(monkeypatch, "fund-a", point)
    with pytest.raises(Crash):
        run(operations, sign=sign, chain=chain)
    monkeypatch.undo()
    chain.settle_all()
    with pytest.raises(ops.OperationRefused, match="open"):
        run(operations, sign=sign, chain=chain)
    assert sign.calls == [1]
    assert len(chain.sent) == (0 if point == "signed" else 1)


def test_interrupted_after_planning_signs_once(world, monkeypatch):
    chain, operations, _ = world
    sign = signer(chain)
    crash_at(monkeypatch, "fund-a", "planned")
    with pytest.raises(Crash):
        run(operations, sign=sign, chain=chain)
    monkeypatch.undo()
    assert run(operations, sign=sign, chain=chain)["state"] == "settled"
    assert len(chain.sent) == 1


def test_signed_not_broadcast_is_resubmitted_with_the_identical_message(world, monkeypatch):
    chain, operations, ceremony = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    with pytest.raises(ops.OperationRefused, match="can still execute"):
        operations.record_failed("fund-a", "c")
    record = operations.journal.record("fund-a")
    settled = operations.resubmit("fund-a")
    assert settled["state"] == "settled"
    assert chain.sent == [record["external_hash"]]


def test_resubmit_refuses_an_accepted_or_expired_message(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "broadcast")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    chain.settle_all()
    with pytest.raises(ops.OperationRefused, match="accepted"):
        operations.resubmit("fund-a")


def test_delivered_before_the_settled_line_is_recorded_by_a_person(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "delivered")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    record = operations.journal.record("fund-a")
    outcome, evidence = operations.settle(record)
    with pytest.raises(ops.OperationRefused, match="not this operation"):
        operations.record_settled("fund-a", "00" * 32)
    done = operations.record_settled("fund-a", evidence["wallet_tx"])
    assert done["state"] == "settled"
    assert run(operations, "fund-b", chain=chain)["state"] == "settled"


# ---------------------------------------------------------------- failure evidence


def test_expired_never_accepted_is_failure_form_c(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    chain.now += 300
    with pytest.raises(ops.OperationRefused, match="can still execute"):
        operations.record_failed("fund-a", "c")
    chain.now += 200
    failed = operations.record_failed("fund-a", "c")
    assert failed["state"] == "failed" and failed["evidence"]["form"] == "c"
    assert run(operations, "fund-b", chain=chain)["state"] == "settled"


def test_a_seqno_taken_by_another_message_is_failure_form_d(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    with pytest.raises(ops.OperationRefused, match="not consumed"):
        operations.record_failed("fund-a", "d")
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(OTHER, NANO, False)))
    chain.settle_all()
    failed = operations.record_failed("fund-a", "d")
    assert failed["evidence"]["consumed_by"]
    # The competing transfer is still unexplained.
    with pytest.raises(ops.OperationRefused, match="explains"):
        run(operations, "fund-b", chain=chain)


def test_form_d_needs_the_wallet_identity_unchanged(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(OTHER, NANO, False)))
    chain.settle_all()
    account = chain.account(BOOT)
    account["data"] = fakechain.wallet_data(2, 0, "cc" * 32)
    with pytest.raises(ops.OperationRefused, match="identity"):
        operations.record_failed("fund-a", "d")


def test_an_accepted_message_that_emitted_nothing_is_failure_a(world):
    chain, operations, _ = world
    chain.account(BOOT)["balance"] = NANO * 2  # less than the value: mode 3 ignores the error
    with pytest.raises(ops.OperationRefused, match="failed"):
        run(operations, chain=chain, prerequisites=None)
    record = operations.journal.record("fund-a")
    assert record["state"] == "failed" and record["evidence"]["form"] == "a"


def test_record_failed_needs_terminal_evidence(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "delivered")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    evidence = operations.settle(operations.journal.record("fund-a"))[1]
    with pytest.raises(ops.OperationRefused, match="no terminal failure"):
        operations.record_failed("fund-a", "a", evidence["wallet_tx"])
    # (c) reads expiry first, then absence: refused for each in turn.
    with pytest.raises(ops.OperationRefused, match="can still execute"):
        operations.record_failed("fund-a", "c")
    chain.now += 500
    with pytest.raises(ops.OperationRefused, match="accepted"):
        operations.record_failed("fund-a", "c")


# ---------------------------------------------------------------- activation


def activation(chain, public_key="5a" * 32):
    init = fakechain.wallet_state_init(public_key)
    address = f"-1:{init.hash().hex()}"
    boc = build_external(address, 2, 0, ops.ACTIVATION_VALID_UNTIL, init=init, subwallet=0x504F4F4C)
    p = {
        "kind": "activate-owner",
        "wallet": address,
        "destination": address,
        "value": 0,
        "bounce": False,
        "body_hash": None,
        "state_init_hash": init.hash().hex(),
        "code_hash": fakechain.WALLET_CODE.hash().hex(),
        "public_key": public_key,
        "subwallet": 0x504F4F4C,
    }
    return address, boc, p


def test_an_activation_settles_from_its_transaction_and_the_wallet_state(world):
    chain, operations, _ = world
    address, boc, p = activation(chain)
    chain.account(address)["balance"] = 10 * NANO
    record = operations.run("activate-x", p, lambda seqno: boc, lambda d: None)
    assert record["state"] == "settled"


def test_an_activation_never_expires_but_form_d_can_apply(world, monkeypatch):
    chain, operations, _ = world
    address, boc, p = activation(chain)
    crash_at(monkeypatch, "activate-x", "signed")
    with pytest.raises(Crash):
        operations.run("activate-x", p, lambda seqno: boc, lambda d: None)
    monkeypatch.undo()
    chain.now += 10**6
    with pytest.raises(ops.OperationRefused, match="never expires"):
        operations.record_failed("activate-x", "c")
    # Another valid initialization (same StateInit, another signature) took seqno 0.
    other = build_external(
        address,
        2,
        0,
        ops.ACTIVATION_VALID_UNTIL,
        init=fakechain.wallet_state_init("5a" * 32),
        subwallet=0x504F4F4C,
        salt=b"x",
    )
    chain.send(other)
    chain.settle_all()
    failed = operations.record_failed("activate-x", "d")
    assert failed["evidence"]["form"] == "d"


def test_an_activation_is_resubmitted_identically(world, monkeypatch):
    chain, operations, _ = world
    address, boc, p = activation(chain)
    crash_at(monkeypatch, "activate-x", "signed")
    with pytest.raises(Crash):
        operations.run("activate-x", p, lambda seqno: boc, lambda d: None)
    monkeypatch.undo()
    chain.now += 10**6
    chain.account(address)["balance"] = 10 * NANO
    assert operations.resubmit("activate-x")["state"] == "settled"


# ---------------------------------------------------------------- withdrawals


POOL = "-1:" + "50" * 32
OWNER = "-1:" + "0e" * 32


def pool_behaviour(refuse=False, owner_bounces=False):
    """A single-nominator pool: plain transfers accepted; the owner's WITHDRAW paid
    back with the remaining value; anyone else's WITHDRAW refused and bounced."""

    def behave(chain, address, account, message, in_msg):
        value = int(message["value"])
        account["balance"] += value
        body = message.get("_body")
        is_withdraw = body is not None and body.bits >= 32 and lib.Slice(body).bits(32) == 0x1000
        if not is_withdraw:
            chain.record_tx(address, in_msg, [], credit=value)
            return
        if refuse or message["source"] != OWNER:
            account["balance"] -= value
            out = [
                chain.emit(
                    address, message["source"], value - NANO // 100, False, None, bounced=True
                )
            ]
            chain.record_tx(address, in_msg, out, success=False, credit=value)
            return
        s = lib.Slice(body)
        s.bits(32 + 64)
        asked = ops.read_coins(s)
        pay = min(asked, account["balance"] - value - NANO) + value - NANO // 200
        account["balance"] -= pay
        out = [chain.emit(address, OWNER, pay, True, None)]
        chain.record_tx(address, in_msg, out, credit=value)

    return behave


def owner_behaviour(bounces):
    def behave(chain, address, account, message, in_msg):
        value = int(message["value"])
        if bounces:
            out = [chain.emit(address, message["source"], value, False, None, bounced=True)]
            chain.record_tx(address, in_msg, out, success=False, credit=value)
            return
        account["balance"] += value
        chain.record_tx(address, in_msg, [], credit=value)

    return behave


def withdraw_body(nanotos):
    return lib.cell_from_bits(
        "0" * 19 + "1" + "0" * 12 + format(1, "064b") + fakechain.coins_bits(nanotos)
    )


def withdraw_world(world, refuse=False, owner_bounces=False):
    chain, operations, ceremony = world
    chain.wallet(OWNER, 10 * NANO, public_key="0e" * 32, subwallet=0x504F4F4C)
    chain.account(POOL).update(state="active", balance=10_000 * NANO)
    chain.behaviour[POOL] = pool_behaviour(refuse)
    if owner_bounces:
        chain.behaviour[OWNER] = owner_behaviour(True)
    return chain, operations


def withdraw(operations, chain, op_id="withdraw-1", nanotos=5 * NANO, salt=b"", all_amount=False):
    body = withdraw_body(nanotos)
    p = params(
        NANO,
        POOL,
        OWNER,
        kind="withdraw",
        bounce=True,
        body_hash=body.hash().hex(),
        requested_nanotos=None if all_amount else nanotos,
    )
    return operations.run(
        op_id, p, signer(chain, OWNER, POOL, NANO, True, body, salt=salt), lambda d: None
    )


def test_a_withdrawal_settles_when_the_owner_retained_the_payment(world):
    chain, operations = withdraw_world(world)
    record = withdraw(operations, chain)
    assert record["state"] == "settled"
    assert record["evidence"]["paid_nanotos"] >= 5 * NANO
    assert record["evidence"]["owner_tx"]


def test_a_payment_that_bounces_at_the_owner_is_a_terminal_failure_it_accounts_for(world):
    chain, operations = withdraw_world(world, owner_bounces=True)
    with pytest.raises(ops.OperationRefused, match="did not retain"):
        withdraw(operations, chain)
    record = operations.journal.record("withdraw-1")
    evidence = record["evidence"]
    assert record["state"] == "failed" and evidence["form"] == "b"
    assert evidence["owner_tx"] in evidence["explains"] and evidence["receipt_out"]
    # The owner wallet is not blocked: the bounce is accounted for.
    del chain.behaviour[OWNER]
    assert withdraw(operations, chain, "withdraw-2", salt=b"2")["state"] == "settled"


def test_a_pool_that_refuses_is_failure_b_and_its_messages_are_explained(world):
    chain, operations = withdraw_world(world, refuse=True)
    with pytest.raises(ops.OperationRefused, match="failed"):
        withdraw(operations, chain)
    record = operations.journal.record("withdraw-1")
    assert record["state"] == "failed" and record["evidence"]["form"] == "b"
    # The owner wallet is not blocked by it: the next withdrawal passes the gate.
    chain.behaviour[POOL] = pool_behaviour(False)
    assert withdraw(operations, chain, "withdraw-2", salt=b"2")["state"] == "settled"


def test_a_bounced_payment_is_not_counted_as_paid(world):
    chain, operations = withdraw_world(world, refuse=True)
    with pytest.raises(ops.OperationRefused):
        withdraw(operations, chain)
    assert "paid_nanotos" not in operations.journal.record("withdraw-1")["evidence"]


def test_a_new_withdrawal_is_judged_on_its_own_message(world, monkeypatch):
    # An earlier withdrawal in flight, then settled; a second one must not be
    # credited with the first one's success when it fails.
    chain, operations = withdraw_world(world)
    withdraw(operations, chain)
    chain.behaviour[POOL] = pool_behaviour(refuse=True)
    with pytest.raises(ops.OperationRefused, match="failed"):
        withdraw(operations, chain, "withdraw-2", salt=b"2")
    first = operations.journal.record("withdraw-1")["evidence"]
    second = operations.journal.record("withdraw-2")["evidence"]
    assert second["wallet_tx"] != first["wallet_tx"]


# ---------------------------------------------------------------- records


def test_parameters_never_change_in_any_state(world):
    chain, operations, _ = world
    run(operations, chain=chain)
    with pytest.raises(ops.OperationRefused, match="other parameters"):
        run(operations, p=params(6 * NANO), chain=chain)


def test_a_failed_operation_is_never_retried_under_its_id(world):
    chain, operations, _ = world
    chain.account(BOOT)["balance"] = NANO
    with pytest.raises(ops.OperationRefused):
        run(operations, chain=chain)
    chain.account(BOOT)["balance"] = 100 * NANO
    with pytest.raises(ops.OperationRefused, match="failed"):
        run(operations, chain=chain)


def test_a_torn_record_is_refused(world):
    chain, operations, ceremony = world
    run(operations, chain=chain)
    path = ceremony / "operations/fund-a.jsonl"
    path.write_text(path.read_text() + '{"state": "set')
    with pytest.raises(ops.OperationRefused, match="ends in a torn line"):
        operations.journal.record("fund-a")


def test_a_second_run_on_the_same_wallet_waits_for_the_lock(world):
    chain, operations, _ = world
    with operations.journal.lock(BOOT):
        with pytest.raises(ops.OperationRefused, match="holds the operations journal lock"):
            run(operations, chain=chain)


def test_records_are_fsynced_with_their_directory(world, monkeypatch):
    chain, operations, ceremony = world
    synced = []
    real = os.fsync
    monkeypatch.setattr(ops.os, "fsync", lambda fd: synced.append(fd) or real(fd))
    run(operations, chain=chain)
    assert len(synced) >= 8  # each of four lines: the file and the directory


def test_reconcile_reports_open_operations_and_unexplained_activity(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "broadcast")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    chain.send(build_external(BOOT, 2, 2, chain.now + 300, internal_message(OTHER, NANO, False)))
    chain.settle_all()
    report = operations.reconcile([BOOT])
    [row] = report["operations"]
    assert row["state"] == "broadcast" and row["chain"][0] == "settled"
    # The open operation's own transfer is unexplained until it is recorded, and the
    # unrelated one stays unexplained.
    assert [u["wallet"] for u in report["unexplained"]] == [BOOT, BOOT]


# ---------------------------------------------------------------- history paging


def test_history_pages_back_to_the_beginning_and_dedups(world, monkeypatch):
    chain, operations, _ = world
    monkeypatch.setattr(ops, "HISTORY_PAGE", 2)
    for seqno in range(1, 8):
        chain.send(
            build_external(BOOT, 2, seqno, chain.now + 300, internal_message(BOOT, NANO, False))
        )
        chain.settle_all()
    history = operations.nodes[0].history(BOOT, None)
    # Each self-transfer is two transactions: the wallet's and the delivery to itself.
    assert len(history) == 14 and len({t["hash"] for t in history}) == 14


def test_history_without_progress_or_past_its_cap_is_unknown(world, monkeypatch):
    chain, operations, _ = world
    for seqno in range(1, 5):
        chain.send(
            build_external(BOOT, 2, seqno, chain.now + 300, internal_message(BOOT, NANO, False))
        )
        chain.settle_all()
    with pytest.raises(ops.Unknown, match="boundary"):
        operations.nodes[0].history(BOOT, {"lt": "1", "hash": "ff" * 32})
    monkeypatch.setattr(ops, "HISTORY_PAGE", 1)
    monkeypatch.setattr(ops, "HISTORY_PAGES", 2)
    with pytest.raises(ops.Unknown, match="longer than"):
        operations.nodes[0].history(BOOT, None)


def test_malformed_answers_are_unknown_not_tracebacks():
    for data in (None, "", "!!", base64.b64encode(b"not a bag of cells").decode()):
        with pytest.raises(ops.Unknown):
            ops.verify_transaction(data, "aa" * 32, BOOT, 1)
    with pytest.raises(ops.Unknown):
        ops.b64hash(None)


# ---------------------------------------------------------------- real messages and answers


REAL = json.loads((DATA / "ops-operations.json").read_text())
ANSWERS = json.loads((DATA / "ops-node-answers.json").read_text())


@pytest.mark.parametrize("op_id", sorted(REAL))
def test_real_messages_decode_to_their_journaled_identity(op_id):
    record = REAL[op_id]
    decoded = ops.decode_external(base64.b64decode(record["boc"]))
    assert decoded["external_hash"] == record["external_hash"]
    assert decoded["destination"] == record["wallet"] and decoded["global_id"] == 2
    assert decoded["seqno"] == record["seqno"]
    if record["kind"] == "activate-owner":
        assert decoded["init_hash"] == record["state_init_hash"] and decoded["internal"] is None
    else:
        internal = decoded["internal"]
        assert (internal["destination"], internal["value"], internal["bounce"]) == (
            record["destination"],
            record["value"],
            record["bounce"],
        )
        assert internal["body_hash"] == record["body_hash"]
        assert internal["init_hash"] == record["state_init_hash"]


def test_real_transactions_decode_to_what_the_node_summarised():
    # The node's summaries are never read; on real transactions they agree with the
    # facts decoded from each BOC, which is checked against its id and account.
    credits = 0
    for wallet, answer in ANSWERS.items():
        for tx in answer["page"]["transactions"]:
            tid = tx["transaction_id"]
            n = ops.verify_transaction(
                tx["data"], ops.b64hash(tid["hash"]).hex(), wallet, int(tid["lt"])
            )
            incoming = tx["in_msg"]
            assert n["in_kind"] == incoming["kind"]
            assert n["in_hash"] == ops.b64hash(incoming["hash"]).hex()
            assert n["aborted"] == tx["aborted"]
            assert n["compute_success"] == bool(tx["compute"] and tx["compute"].get("success"))
            assert [m["hash"] for m in n["out"]] == [
                ops.b64hash(m["hash"]).hex() for m in tx["out_msgs"]
            ]
            if n["in_kind"] == "internal":
                assert n["credit"] == n["in_value"] == int(incoming["value"])
                assert n["in_source"] == ops.party(incoming["source"])
                credits += 1
    assert credits >= 5


def test_a_real_transaction_is_bound_to_its_account_and_lt():
    wallet, answer = next(iter(ANSWERS.items()))
    tx = answer["page"]["transactions"][0]
    tid = tx["transaction_id"]
    tx_hash = ops.b64hash(tid["hash"]).hex()
    with pytest.raises(ops.Unknown, match="belongs to"):
        ops.verify_transaction(tx["data"], tx_hash, OTHER, int(tid["lt"]))
    with pytest.raises(ops.Unknown, match="belongs to"):
        ops.verify_transaction(tx["data"], tx_hash, wallet, int(tid["lt"]) + 1)
    with pytest.raises(ops.Unknown, match="hashes to"):
        ops.verify_transaction(tx["data"], "00" * 32, wallet, int(tid["lt"]))


def test_a_bounced_credit_is_failure_b(world):
    chain, operations, _ = world

    def bounce(chain_, address, account, message, in_msg):
        out = [
            chain_.emit(
                address, message["source"], int(message["value"]), False, None, bounced=True
            )
        ]
        chain_.record_tx(address, in_msg, out, credit=int(message["value"]))

    chain.behaviour[DEST] = bounce
    with pytest.raises(ops.OperationRefused, match="failed"):
        run(operations, chain=chain)
    assert operations.journal.record("fund-a")["evidence"]["form"] == "b"


def test_a_receipt_crediting_another_amount_is_not_retained(world):
    chain, operations = withdraw_world(world)

    def short(chain_, address, account, message, in_msg):
        value = int(message["value"])
        account["balance"] += value - 1
        chain_.record_tx(address, in_msg, [], credit=value - 1)

    chain.behaviour[OWNER] = short
    with pytest.raises(ops.OperationRefused, match="did not retain"):
        withdraw(operations, chain)


def test_resubmit_refuses_once_the_seqno_moved(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(BOOT, NANO, False)))
    chain.settle_all()
    with pytest.raises(ops.OperationRefused, match="seqno moved"):
        operations.resubmit("fund-a")
    assert len(chain.sent) == 1


def test_resubmit_refuses_an_expired_message(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    chain.now += 400
    with pytest.raises(ops.OperationRefused, match="expired"):
        operations.resubmit("fund-a")
    assert chain.sent == []


def test_inclusive_pages_are_deduplicated(world, monkeypatch):
    chain, operations, _ = world
    monkeypatch.setattr(ops, "HISTORY_PAGE", 3)
    for seqno in range(1, 6):
        chain.send(
            build_external(BOOT, 2, seqno, chain.now + 300, internal_message(BOOT, NANO, False))
        )
        chain.settle_all()
    inclusive = chain.node("http://c", inclusive=True)
    history = inclusive.history(BOOT, None)
    assert len(history) == 10 and len({t["hash"] for t in history}) == 10


def test_a_page_without_progress_is_unknown(world, monkeypatch):
    chain, operations, _ = world
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(BOOT, NANO, False)))
    chain.settle_all()
    node = chain.node("http://c")
    real = node.rpc

    def stuck(url, method, /, **params):
        answer = real(url, method, **params)
        if method == "getTransactionsStd":
            answer["previous_transaction_id"] = dict(answer["transactions"][0]["transaction_id"])
        return answer

    node.rpc = stuck
    monkeypatch.setattr(ops, "HISTORY_PAGE", 1)
    with pytest.raises(ops.Unknown, match="no progress"):
        node.history(BOOT, None)


def test_histories_the_validators_disagree_on_are_unknown(world):
    chain, operations, _ = world
    chain.send(build_external(BOOT, 2, 1, chain.now + 300, internal_message(BOOT, NANO, False)))
    chain.settle_all()
    lagging = ops.Operations(
        operations.ceremony,
        [chain.node("http://a"), chain.node("http://b", lag=True)],
        2,
        clock=lambda: chain.now,
        sleep=lambda s: chain.tick(),
    )
    with pytest.raises(ops.Unknown, match="disagree"):
        lagging.history(BOOT, None)


def test_a_wallet_that_emitted_more_than_the_required_message_failed(world):
    chain, operations, _ = world
    chain.extra_out[BOOT] = (OTHER, NANO)
    with pytest.raises(ops.OperationRefused, match="failed"):
        run(operations, chain=chain)
    record = operations.journal.record("fund-a")
    assert record["evidence"]["form"] == "a"
    # The extra transfer is explained by the failed record, not hidden.
    assert record["evidence"]["explains"] == [record["evidence"]["wallet_tx"]]


def test_a_destination_that_failed_without_bouncing_is_failure_b(world):
    chain, operations, _ = world

    def refuse(chain_, address, account, message, in_msg):
        account["balance"] += int(message["value"])
        chain_.record_tx(address, in_msg, [], success=False, credit=int(message["value"]))

    chain.account(DEST).update(state="active")
    chain.behaviour[DEST] = refuse
    p = params(kind="principal", bounce=True)
    with pytest.raises(ops.OperationRefused, match="failed"):
        operations.run("principal-x", p, signer(chain, bounce=True), lambda d: None)
    assert operations.journal.record("principal-x")["evidence"]["form"] == "b"


def test_a_receipt_that_sends_on_is_not_retained(world):
    chain, operations = withdraw_world(world)

    def forwards(chain_, address, account, message, in_msg):
        value = int(message["value"])
        out = [chain_.emit(address, OTHER, value, False, None)]
        chain_.record_tx(address, in_msg, out, credit=value)

    chain.behaviour[OWNER] = forwards
    with pytest.raises(ops.OperationRefused, match="did not retain"):
        withdraw(operations, chain)


# ---------------------------------------------------------------- fix plan 3


def test_two_runs_racing_on_one_operation_sign_and_send_once(world, monkeypatch):
    # The reviewer's interleaving: B pauses before it takes the lock (where it used
    # to read the record), A runs the operation to settlement, B resumes. B finds
    # the operation settled under the lock and signs nothing.
    import threading

    chain, operations, ceremony = world
    b_ops = ops.Operations(
        ceremony,
        [chain.node("http://a"), chain.node("http://b")],
        2,
        clock=lambda: chain.now,
        sleep=lambda s: chain.tick(),
    )
    paused, resume = threading.Event(), threading.Event()
    real_lock = ops.Journal.lock

    def lock(self, wallet=None):
        if threading.current_thread().name == "B" and not resume.is_set():
            paused.set()
            resume.wait(10)
        return real_lock(self, wallet)

    monkeypatch.setattr(ops.Journal, "lock", lock)
    sign = signer(chain)
    results = {}

    def b_run():
        results["b"] = b_ops.run("fund-a", params(), sign, lambda d: None)

    thread = threading.Thread(target=b_run, name="B")
    thread.start()
    assert paused.wait(10)
    results["a"] = run(operations, sign=sign, chain=chain)
    resume.set()
    thread.join(10)
    assert results["a"]["state"] == results["b"]["state"] == "settled"
    assert sign.calls == [1] and len(chain.sent) == 1
    transfers = [t for t in chain.account(BOOT)["txs"] if t["out_msgs"]]
    assert len(transfers) == 1


def test_a_run_refused_by_the_held_lock_returns_the_settled_result_later(world):
    chain, operations, ceremony = world
    sign = signer(chain)
    with operations.journal.lock():
        with pytest.raises(ops.OperationRefused, match="journal lock"):
            run(operations, sign=sign, chain=chain)
    first = run(operations, sign=sign, chain=chain)
    again = run(operations, sign=sign, chain=chain)
    assert first["state"] == again["state"] == "settled" and sign.calls == [1]


def test_one_id_is_bound_to_one_wallet(world):
    chain, operations, _ = world
    run(operations, "w-1", chain=chain)
    chain.wallet(OWNER, 100 * NANO, subwallet=0x504F4F4C)
    with pytest.raises(ops.OperationRefused, match="other parameters"):
        operations.run("w-1", params(wallet=OWNER), signer(chain, OWNER), lambda d: None)


def test_settlement_never_reads_the_json_summary(world):
    chain, operations, ceremony = world

    def lie(answer):
        for tx in answer["transactions"]:
            tx["aborted"] = True
            tx["compute"] = {"success": False}
            for m in tx["out_msgs"]:
                m["value"] = "1"
                m["destination"] = OTHER
        return answer

    liars = ops.Operations(
        ceremony,
        [chain.node("http://a", tamper=lie), chain.node("http://b", tamper=lie)],
        2,
        clock=lambda: chain.now,
        sleep=lambda s: chain.tick(),
    )
    assert run(liars, chain=chain)["state"] == "settled"


def test_a_changed_boc_under_the_original_id_is_unknown(world):
    chain, operations, ceremony = world
    run(operations, chain=chain)

    def swap(answer):
        for tx in answer["transactions"]:
            other = lib.serialize_boc(lib.cell_from_bits("0111"))
            tx["data"] = base64.b64encode(other).decode()
        return answer

    node = chain.node("http://c", tamper=swap)
    with pytest.raises(ops.Unknown, match="hashes to"):
        node.history(BOOT, None)


def test_validators_reporting_different_transactions_disagree(world):
    chain, operations, ceremony = world
    run(operations, chain=chain)
    real = chain.account(BOOT)["txs"]

    def other_tx(answer):
        if answer["transactions"]:
            cell = fakechain.transaction_cell(
                BOOT, int(real[-1]["transaction_id"]["lt"]), None, [], True, False, None
            )
            answer["transactions"][0]["data"] = base64.b64encode(lib.serialize_boc(cell)).decode()
            answer["transactions"][0]["transaction_id"] = {
                "lt": real[-1]["transaction_id"]["lt"],
                "hash": base64.b64encode(cell.hash()).decode(),
            }
        return answer

    split = ops.Operations(
        ceremony,
        [chain.node("http://a"), chain.node("http://b", tamper=other_tx)],
        2,
        clock=lambda: chain.now,
        sleep=lambda s: chain.tick(),
    )
    with pytest.raises(ops.Unknown, match="disagree"):
        split.history(BOOT, None)


@pytest.mark.parametrize("value", [5 * NANO, 50_000_000])
def test_a_credit_one_nanotos_short_is_failure_b(world, value):
    chain, operations, _ = world

    def short(chain_, address, account, message, in_msg):
        credited = int(message["value"]) - 1
        account["balance"] += credited
        chain_.record_tx(
            address, in_msg, [], success=False, aborted=True, credit=credited, skipped=True
        )

    chain.behaviour[DEST] = short
    p = params(value)
    with pytest.raises(ops.OperationRefused, match="credited"):
        operations.run("fund-a", p, signer(chain, value=value), lambda d: None)
    assert operations.journal.record("fund-a")["evidence"]["form"] == "b"


@pytest.mark.parametrize("subwallet", [1, 0x504F4F4C])
def test_a_message_for_another_subwallet_is_refused(world, subwallet):
    chain, operations, _ = world
    with pytest.raises(ops.OperationRefused, match="subwallet"):
        run(operations, sign=signer(chain, subwallet=subwallet), chain=chain)
    assert chain.sent == []


def test_a_whole_line_is_written_through_short_writes(world, monkeypatch):
    chain, operations, ceremony = world
    real = os.write
    monkeypatch.setattr(ops.os, "write", lambda fd, data: real(fd, data[:7]))
    assert run(operations, chain=chain)["state"] == "settled"
    lines = (ceremony / "operations/fund-a.jsonl").read_text().splitlines()
    assert [json.loads(line)["state"] for line in lines] == [
        "planned",
        "signed",
        "broadcast",
        "settled",
    ]


@pytest.mark.parametrize("failure", ["zero", "raise"])
def test_a_failed_journal_write_refuses_before_any_broadcast(world, monkeypatch, failure):
    chain, operations, ceremony = world
    real = os.write
    calls = {"n": 0}

    def write(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:
            return real(fd, data)  # the planned line
        if failure == "zero":
            return 0
        real(fd, data[:5])
        raise OSError("disk full")

    monkeypatch.setattr(ops.os, "write", write)
    with pytest.raises((ops.OperationRefused, OSError)):
        run(operations, chain=chain)
    assert chain.sent == []


# -- attempts after a terminal failure


def failed_fund(world):
    chain, operations, _ = world
    chain.account(BOOT)["balance"] = NANO  # accepted, emits nothing: failure a
    with pytest.raises(ops.OperationRefused, match="failed"):
        run(operations, chain=chain)
    chain.account(BOOT)["balance"] = 100 * NANO
    return chain, operations


def test_a_retry_creates_one_successor_that_settles_once(world):
    chain, operations = failed_fund(world)
    successor = operations.retry("fund-a", "the wallet was short")
    assert successor["id"] == "fund-a.attempt-2" and successor["predecessor"] == "fund-a"
    with pytest.raises(ops.OperationRefused, match="planned"):
        operations.retry("fund-a", "again")
    sign = signer(chain)
    record = run(operations, "fund-a", sign=sign, chain=chain)
    assert record["id"] == "fund-a.attempt-2" and record["state"] == "settled"
    assert operations.journal.record("fund-a")["state"] == "failed"
    assert run(operations, "fund-a", sign=sign, chain=chain)["id"] == "fund-a.attempt-2"
    assert len(sign.calls) == 1
    with pytest.raises(ops.OperationRefused, match="settled"):
        operations.retry("fund-a", "after success")


def test_a_retry_keeps_the_steps_parameters(world):
    chain, operations = failed_fund(world)
    operations.retry("fund-a", "reason")
    with pytest.raises(ops.OperationRefused, match="other parameters"):
        run(operations, "fund-a", p=params(6 * NANO), chain=chain)


def test_retry_needs_a_failed_newest_attempt(world, monkeypatch):
    chain, operations, _ = world
    with pytest.raises(ops.OperationRefused, match="no attempt"):
        operations.retry("fund-a", "nothing yet")
    crash_at(monkeypatch, "fund-a", "broadcast")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    with pytest.raises(ops.OperationRefused, match="broadcast"):
        operations.retry("fund-a", "open")


def test_concurrent_retries_create_at_most_one_successor(world):
    import threading

    chain, operations = failed_fund(world)
    outcomes = []

    def attempt():
        try:
            outcomes.append(operations.retry("fund-a", "parallel")["id"])
        except ops.OperationRefused as exc:
            outcomes.append(str(exc))

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count("fund-a.attempt-2") == 1
    assert [n for n, _ in operations.journal.attempts("fund-a")] == [1, 2]


def test_a_crash_while_creating_a_successor_leaves_none_or_one(world, monkeypatch):
    chain, operations = failed_fund(world)
    real = os.write
    monkeypatch.setattr(
        ops.os,
        "write",
        lambda fd, data: real(fd, data[:9]) and (_ for _ in ()).throw(OSError("crash")),
    )
    with pytest.raises(OSError):
        operations.retry("fund-a", "torn")
    monkeypatch.undo()
    # Published whole or not at all: no successor exists, the journal reads, and the
    # retry can be asked for again without touching any record.
    assert [n for n, _ in operations.journal.attempts("fund-a")] == [1]
    assert operations.journal.all()
    successor = operations.retry("fund-a", "again")
    assert successor["id"] == "fund-a.attempt-2"
    assert run(operations, "fund-a", chain=chain)["state"] == "settled"
    assert len(chain.sent) == 2


def test_a_successor_interrupted_before_signing_signs_once(world, monkeypatch):
    chain, operations = failed_fund(world)
    operations.retry("fund-a", "reason")
    sign = signer(chain)
    monkeypatch.setattr(
        operations, "gate", lambda wallet, op_id: (_ for _ in ()).throw(Crash("gate"))
    )
    with pytest.raises(Crash):
        run(operations, "fund-a", sign=sign, chain=chain)
    monkeypatch.undo()
    assert run(operations, "fund-a", sign=sign, chain=chain)["state"] == "settled"
    assert len(sign.calls) == 1


# -- resubmit preconditions


def signed_not_sent(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    return chain, operations


def test_resubmit_refuses_a_changed_wallet_identity(world, monkeypatch):
    chain, operations = signed_not_sent(world, monkeypatch)
    chain.account(BOOT)["data"] = fakechain.wallet_data(1, 0, "cd" * 32)
    with pytest.raises(ops.OperationRefused, match="identity"):
        operations.resubmit("fund-a")
    assert chain.sent == []


def test_resubmit_refuses_when_any_validator_is_past_the_expiry(world, monkeypatch):
    chain, operations, ceremony = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    skewed = ops.Operations(
        ceremony,
        [chain.node("http://a"), chain.node("http://b", utime_offset=400)],
        2,
        clock=lambda: chain.now,
        sleep=lambda s: chain.tick(),
    )
    with pytest.raises(ops.OperationRefused, match="expired"):
        skewed.resubmit("fund-a")
    # And (c) needs every validator past the margin: one is, the other is not yet.
    chain.now += 500
    behind = ops.Operations(
        ceremony,
        [chain.node("http://a"), chain.node("http://b", utime_offset=-400)],
        2,
        clock=lambda: chain.now,
        sleep=lambda s: chain.tick(),
    )
    with pytest.raises(ops.OperationRefused, match="can still execute"):
        behind.record_failed("fund-a", "c")
    assert chain.sent == []


def test_resubmit_refuses_a_wallet_that_cannot_pay(world, monkeypatch):
    chain, operations = signed_not_sent(world, monkeypatch)
    chain.account(BOOT)["balance"] = 5 * NANO
    with pytest.raises(ops.OperationRefused, match="cannot pay"):
        operations.resubmit("fund-a")
    assert chain.sent == []


def test_resubmit_refuses_an_activation_of_an_account_that_is_not_uninitialized(world, monkeypatch):
    chain, operations, _ = world
    address, boc, p = activation(chain)
    crash_at(monkeypatch, "activate-x", "signed")
    with pytest.raises(Crash):
        operations.run("activate-x", p, lambda seqno: boc, lambda d: None)
    monkeypatch.undo()
    chain.account(address)["balance"] = 10 * NANO
    chain.account(address)["state"] = "active"
    chain.account(address)["code"] = fakechain.WALLET_CODE
    chain.account(address)["data"] = fakechain.wallet_data(1, 0x504F4F4C, "77" * 32)
    with pytest.raises(ops.OperationRefused, match="cannot run"):
        operations.resubmit("activate-x")
    assert chain.sent == []


def test_watching_an_operation_another_run_settled_returns_its_record(world):
    chain, operations, _ = world
    settled = run(operations, chain=chain)
    assert operations.watch("fund-a")["evidence"] == settled["evidence"]


def test_an_activation_is_resubmitted_only_with_its_fee_budget(world, monkeypatch):
    chain, operations, _ = world
    address, boc, p = activation(chain)
    crash_at(monkeypatch, "activate-x", "signed")
    with pytest.raises(Crash):
        operations.run("activate-x", p, lambda seqno: boc, lambda d: None)
    monkeypatch.undo()
    chain.account(address)["balance"] = ops.ACTIVATION_FEE_NANOTOS - 1
    with pytest.raises(ops.OperationRefused, match="fee budget"):
        operations.resubmit("activate-x")
    assert chain.sent == []
    chain.account(address)["balance"] = 10 * NANO
    assert operations.resubmit("activate-x")["state"] == "settled"
    assert len(chain.sent) == 1


def test_form_d_names_the_transaction_that_took_the_records_own_seqno(world, monkeypatch):
    # X lands between the boundary and the signature (taking seqno 1, so the
    # message signs seqno 2); Y then takes seqno 2. (d) names Y, never X.
    chain, operations, _ = world
    real_seqno = operations.seqno

    def x_lands_first(wallet):
        if not chain.account(BOOT)["txs"]:
            chain.send(
                build_external(
                    BOOT, 2, 1, chain.now + 300, internal_message(OTHER, NANO, False), salt=b"x"
                )
            )
            chain.settle_all()
        return real_seqno(wallet)

    monkeypatch.setattr(operations, "seqno", x_lands_first)
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    record = operations.journal.record("fund-a")
    assert record["seqno"] == 2
    chain.send(
        build_external(
            BOOT, 2, 2, chain.now + 300, internal_message(OTHER, 2 * NANO, False), salt=b"y"
        )
    )
    chain.settle_all()
    x, y = [t for t in chain.account(BOOT)["txs"] if t["in_msg"]["kind"] == "external"]
    failed = operations.record_failed("fund-a", "d")
    consumed = failed["evidence"]["consumed_by"]
    assert consumed == ops.b64hash(y["transaction_id"]["hash"]).hex()
    assert consumed != ops.b64hash(x["transaction_id"]["hash"]).hex()


def batch_external(wallet, seqno, valid_until, transfers):
    """A correctly shaped wallet v3 message with several transfers (mode + ref each)."""
    import hashlib

    signature = hashlib.sha512(b"batch" + bytes([seqno])).digest()
    signed = "".join(format(b, "08b") for b in signature)
    signed += (
        format(2, "032b") + format(0, "032b") + format(valid_until, "032b") + format(seqno, "032b")
    )
    signed += "00000011" * len(transfers)
    body = lib.cell_from_bits(signed, [internal_message(d, v, False) for d, v in transfers])
    bits = "10" + "00" + fakechain.addr_bits(wallet) + "0000" + "0" + "1"
    return lib.serialize_boc(lib.cell_from_bits(bits, [body]))


def test_form_d_names_a_competing_batch_and_leaves_its_transfers_unexplained(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    chain.send(batch_external(BOOT, 1, chain.now + 300, [(OTHER, NANO), (DEST, 2 * NANO)]))
    chain.settle_all()
    batch = [t for t in chain.account(BOOT)["txs"] if t["in_msg"]["kind"] == "external"][0]
    assert len(batch["out_msgs"]) == 2
    failed = operations.record_failed("fund-a", "d")
    assert failed["evidence"]["consumed_by"] == ops.b64hash(batch["transaction_id"]["hash"]).hex()
    assert failed["evidence"]["explains"] == []
    with pytest.raises(ops.OperationRefused, match="explains"):
        run(operations, "fund-b", chain=chain)


def external_txs(chain, wallet):
    return [t for t in chain.account(wallet)["txs"] if t["in_msg"]["kind"] == "external"]


def test_form_d_skips_an_attempt_that_aborted_at_the_records_seqno(world, monkeypatch):
    # X computes and then aborts in the action phase: the seqno stays, and Y, the
    # actual consumer, takes it. (d) names Y alone.
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    chain.abort_next[BOOT] = 1
    chain.send(
        build_external(BOOT, 2, 1, chain.now + 300, internal_message(OTHER, NANO, False), salt=b"x")
    )
    chain.settle_all()
    assert chain.account(BOOT)["seqno"] == 1
    with pytest.raises(ops.OperationRefused, match="not consumed"):
        operations.record_failed("fund-a", "d")
    chain.send(
        build_external(BOOT, 2, 1, chain.now + 300, internal_message(OTHER, NANO, False), salt=b"y")
    )
    chain.settle_all()
    x, y = external_txs(chain, BOOT)
    assert x["aborted"] is True and x["compute"]["success"] is True
    failed = operations.record_failed("fund-a", "d")
    assert failed["evidence"]["consumed_by"] == ops.b64hash(y["transaction_id"]["hash"]).hex()


def test_an_aborted_run_of_the_message_is_not_its_settlement_or_failure(world):
    chain, operations, _ = world
    chain.abort_next[BOOT] = 1
    with pytest.raises(ops.OperationRefused, match="ran and aborted"):
        run(operations, chain=chain)
    record = operations.journal.record("fund-a")
    assert record["state"] == "broadcast"
    (attempt,) = external_txs(chain, BOOT)
    attempt_hash = ops.b64hash(attempt["transaction_id"]["hash"]).hex()
    outcome, evidence = operations.settle(record)
    assert outcome == "pending" and evidence["aborted_attempts"] == [attempt_hash]
    with pytest.raises(ops.OperationRefused, match="no terminal failure"):
        operations.record_failed("fund-a", "a", attempt_hash)
    with pytest.raises(ops.OperationRefused, match="not consumed"):
        operations.record_failed("fund-a", "d")
    # The same message runs again and takes effect.
    settled = operations.resubmit("fund-a")
    assert settled["state"] == "settled"
    assert settled["evidence"]["wallet_tx"] != attempt_hash
    assert chain.account(DEST)["balance"] == 5 * NANO


def test_an_aborted_run_of_the_message_still_lets_it_expire(world):
    chain, operations, _ = world
    chain.abort_next[BOOT] = 1
    with pytest.raises(ops.OperationRefused, match="ran and aborted"):
        run(operations, chain=chain)
    chain.now += 500
    failed = operations.record_failed("fund-a", "c")
    assert failed["evidence"]["form"] == "c"


def test_an_aborted_activation_is_not_a_failure_and_is_resubmitted(world):
    chain, operations, _ = world
    address, boc, p = activation(chain)
    chain.account(address)["balance"] = 10 * NANO
    chain.abort_next[address] = 1
    with pytest.raises(ops.OperationRefused, match="ran and aborted"):
        operations.run("activate-x", p, lambda seqno: boc, lambda d: None)
    assert chain.account(address)["state"] == "uninit"
    assert operations.resubmit("activate-x")["state"] == "settled"


def test_a_destination_that_aborted_after_computing_is_failure_b(world):
    chain, operations, _ = world

    def abort(chain_, address, account, message, in_msg):
        chain_.record_tx(address, in_msg, [], success=True, aborted=True, credit=0)

    chain.account(DEST).update(state="active")
    chain.behaviour[DEST] = abort
    p = params(kind="principal", bounce=True)
    with pytest.raises(ops.OperationRefused, match="failed"):
        operations.run("principal-x", p, signer(chain, bounce=True), lambda d: None)
    assert operations.journal.record("principal-x")["evidence"]["form"] == "b"


def broadcast_late(chain, operations, op_id="fund-a"):
    """Send the journaled message of an open record and let it execute."""
    chain.send(base64.b64decode(operations.journal.record(op_id)["boc"]))
    chain.settle_all()


def test_form_d_refuses_when_the_message_itself_lands_between_the_reads(world, monkeypatch):
    # Absent at the first read; then the message lands and takes the seqno itself.
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    real_identity = operations.identity

    def lands_now(wallet):
        broadcast_late(chain, operations)
        return real_identity(wallet)

    monkeypatch.setattr(operations, "identity", lands_now)
    with pytest.raises(ops.OperationRefused, match="itself took effect"):
        operations.record_failed("fund-a", "d")
    monkeypatch.undo()
    assert operations.journal.record("fund-a")["state"] == "signed"
    assert operations.settle(operations.journal.record("fund-a"))[0] == "settled"


def test_form_c_reads_absence_only_after_expiry(world, monkeypatch):
    # The message executes during the pause before the block times are read.
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    chain.now += 250
    real_utimes = operations.utimes

    def delivered_in_the_pause():
        broadcast_late(chain, operations)
        chain.now += 400
        return real_utimes()

    monkeypatch.setattr(operations, "utimes", delivered_in_the_pause)
    with pytest.raises(ops.OperationRefused, match="accepted"):
        operations.record_failed("fund-a", "c")
    monkeypatch.undo()
    assert operations.journal.record("fund-a")["state"] == "signed"
    assert operations.settle(operations.journal.record("fund-a"))[0] == "settled"


@pytest.mark.parametrize("form", ["c", "d"])
def test_no_failure_record_for_a_message_that_took_effect(world, monkeypatch, form):
    # Whatever (c) or (d) concluded, the last read before the record decides.
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "delivered")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    monkeypatch.undo()
    claimed = {"form": form, "explains": []}
    monkeypatch.setattr(operations, "prove_expired", lambda record: claimed)
    monkeypatch.setattr(operations, "prove_consumed", lambda record: claimed)
    with pytest.raises(ops.OperationRefused, match="took effect after all"):
        operations.record_failed("fund-a", form)
    assert operations.journal.record("fund-a")["state"] == "broadcast"


@pytest.mark.parametrize("decision", ["gate", "settle"])
@pytest.mark.parametrize("changed", ["zero_state", "global_id"])
def test_each_decision_rechecks_the_network(world, monkeypatch, decision, changed):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    record = operations.journal.record("fund-a")
    operations.check_network()
    if changed == "zero_state":
        chain.zero_state = {"root_hash": "wrong", "file_hash": "wrong"}
        message = "another network"
    else:
        chain.global_id = 999
        message = "global id"
    sent = list(chain.sent)
    with pytest.raises(ops.OperationRefused, match=message):
        if decision == "gate":
            operations.gate(BOOT, "fund-a")
        else:
            operations.settle(record)
    assert chain.sent == sent
    assert operations.journal.record("fund-a")["state"] == "signed"


@pytest.mark.parametrize("reader", ["both", "history", "utimes", "find_delivery"])
def test_shared_reads_revalidate_each_endpoint(world, reader):
    chain, operations, _ = world
    operations.check_network()
    chain.global_id = 999
    with pytest.raises(ops.OperationRefused, match="global id"):
        if reader == "both":
            operations.both(lambda node: node.seqno(BOOT))
        elif reader == "history":
            operations.history(BOOT, None)
        elif reader == "utimes":
            operations.utimes()
        else:
            operations.find_delivery(DEST, "00" * 32, 0)


def test_chain_reads_use_the_two_validator_helper():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(ops.Operations))
    direct = []
    for method in tree.body[0].body:
        if not isinstance(method, ast.FunctionDef):
            continue
        if method.name in {"__init__", "check_network", "read_both", "run", "resubmit"}:
            continue  # Identity checks, helper implementation and single broadcast only.
        for node in ast.walk(method):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == "self" and node.attr == "nodes":
                    direct.append(method.name)
    assert direct == [], f"chain reads bypass the two-validator helper: {direct}"


@pytest.mark.parametrize("all_amount", [False, True])
def test_a_capped_withdrawal_is_failed_unless_all_was_requested(world, all_amount):
    chain, operations = withdraw_world(world)
    chain.account(POOL)["balance"] = 3 * NANO
    before = chain.account(OWNER)["balance"]
    if all_amount:
        record = withdraw(operations, chain, all_amount=True)
        assert record["state"] == "settled"
    else:
        with pytest.raises(ops.OperationRefused, match="less than requested"):
            withdraw(operations, chain)
        record = operations.journal.record("withdraw-1")
        assert record["state"] == "failed" and record["evidence"]["form"] == "b"
    evidence = record["evidence"]
    assert 0 < evidence["paid_nanotos"] < 5 * NANO
    assert chain.account(OWNER)["balance"] > before
    if not all_amount:
        assert evidence["owner_tx"] in evidence["explains"]
        # The short payment is accounted for, so a separate operation can proceed.
        chain.account(POOL)["balance"] = 10_000 * NANO
        assert withdraw(operations, chain, op_id="withdraw-2")["state"] == "settled"


@pytest.fixture
def election_world(world):
    chain, operations, ceremony = world
    (ceremony / "pools.json").write_text(json.dumps({"node-1": {"operator": BOOT, "pool": DEST}}))
    election = chain.now + 3600
    calls = []
    j = json.loads((ceremony / "genesis.json").read_text())
    j["election_params"] = dict(zip(lib.ELECTION_PARAM_NAMES, (14400, 7200, 1800, 7200)))
    (ceremony / "genesis.json").write_text(json.dumps(j))
    for node in operations.nodes:
        original = node.rpc

        def rpc(url, method, /, _original=original, **kw):
            calls.append((url, method, kw))
            if method == "getConfigParam" and kw["param"] == 15:
                cell = lib.cell_from_bits(
                    "".join(format(n, "032b") for n in (14400, 7200, 1800, 7200))
                )
                return {"config": {"bytes": base64.b64encode(lib.serialize_boc(cell)).decode()}}
            return _original(url, method, **kw)

        node.rpc = rpc
    body = stake_order(election)
    return chain, operations, ceremony, body, calls


# The value tosctl's election task attaches to a pool order: ELECTOR_STAKE_FEE + NPOOL_COMPUTE_FEE.
STAKE_ORDER = NANO + NANO // 5


def stake_order(election, *, algorithm=1, suffix="", refs=None):
    """A pool NEW_STAKE order in tosctl's nominator::new_stake layout: op, query id, stake,
    ML-DSA-44 algorithm, public key ref, election id, max factor, ADNL, signature ref."""
    key, signature = lib.cell_from_bits("1" * 8), lib.cell_from_bits("0" * 8)
    return lib.cell_from_bits(
        format(0x4E73744B, "032b")
        + "0" * 64
        + fakechain.coins_bits(10002 * NANO)
        + format(algorithm, "016b")
        + format(election, "032b")
        + format(1 << 16, "032b")
        + "1" * 256
        + suffix,
        [key, signature] if refs is None else refs,
    )


def send_election_message(chain, body, destination=DEST, value=STAKE_ORDER):
    chain.send(
        build_external(
            BOOT, 2, 1, chain.now + 300, internal_message(destination, value, False, body=body)
        )
    )
    chain.settle_all()


def test_election_message_explains_history_and_is_visible_in_reconcile(election_world):
    chain, operations, _, body, calls = election_world
    send_election_message(chain, body)
    chain.now += 18000  # long after: the message's historical window is what matters
    report = operations.reconcile([BOOT])
    assert report["unexplained"] == []
    assert len(report["explained"]) == 1
    [row] = report["explained"]
    assert row["explained_by"] == "election-new-stake" and row["wallet"] == BOOT
    assert row["tx"] and row["election_id"] == 1_800_003_600
    assert run(operations, chain=chain)["state"] == "settled"
    current = [(url, kw) for url, method, kw in calls if method == "getConfigParam"]
    assert {url for url, _ in current} == {"http://a", "http://b"}
    assert all("seqno" not in kw for _, kw in current)
    assert not any(
        method == "runGetMethod" and kw.get("method") == "active_election_id"
        for _, method, kw in calls
    )
    assert row["query_id"] == 0 and row["stake_nanotos"] == 10002 * NANO


@pytest.mark.parametrize(
    "bad",
    [
        "pool",
        "budget",
        "outside",
        "two",
        "body",
        "no-pool",
        "disagreement",
        "changed-config",
        "before-window",
        "after-window",
        "stake-id",
        "malformed-config",
        "algorithm",
        "trailing",
        "no-signature",
    ],
)
def test_non_election_activity_stays_unexplained(election_world, bad):
    chain, operations, ceremony, body, _ = election_world
    if bad == "no-pool":
        (ceremony / "pools.json").unlink()
    if bad == "two":
        chain.extra_out[BOOT] = (OTHER, NANO)
    if bad == "before-window":
        chain.now -= 4000
    if bad == "after-window":
        chain.now += 2000
    if bad == "stake-id":
        body = stake_order(chain.now + 36000)
    if bad == "body":
        body = lib.cell_from_bits(
            format(0x47657424, "032b")
            + "0" * 64
            + fakechain.coins_bits(10002 * NANO)
            + format(chain.now + 3600, "032b")
        )
    if bad == "algorithm":
        body = stake_order(chain.now + 3600, algorithm=0)
    if bad == "trailing":
        body = stake_order(chain.now + 3600, suffix="0")
    if bad == "no-signature":
        body = stake_order(chain.now + 3600, refs=[lib.cell_from_bits("")])
    if bad == "outside":
        chain.now += 20000
    if bad in ("changed-config", "disagreement", "malformed-config"):
        for node in operations.nodes:
            original = node.rpc

            def rpc(url, method, /, _original=original, **kw):
                if method == "getConfigParam" and kw["param"] == 15:
                    if bad == "malformed-config":
                        return {"config": {"bytes": "AA=="}}
                    if bad == "changed-config" or url == "http://b":
                        cell = lib.cell_from_bits(
                            "".join(format(n, "032b") for n in (14400, 7100, 1800, 7200))
                        )
                        return {
                            "config": {"bytes": base64.b64encode(lib.serialize_boc(cell)).decode()}
                        }
                return _original(url, method, **kw)

            node.rpc = rpc
    send_election_message(
        chain,
        body,
        OTHER if bad == "pool" else DEST,
        STAKE_ORDER + 1 if bad == "budget" else STAKE_ORDER,
    )
    with pytest.raises(ops.OperationRefused):
        run(operations, chain=chain)
    assert len(chain.sent) == 1
    assert operations.reconcile([BOOT])["unexplained"]


def test_stake_order_value_inclusive_boundary(election_world):
    chain, operations, _, body, _ = election_world
    send_election_message(chain, body, value=STAKE_ORDER)
    assert run(operations, chain=chain)["state"] == "settled"


def test_stake_order_value_comes_from_the_profile(election_world, monkeypatch):
    chain, operations, _, body, _ = election_world
    profile = lib.load_profile()
    profile["elections"]["stake_order_nanotos"] = NANO
    profile_path = operations.ceremony / "custom-profile.json"
    profile_path.write_text(json.dumps(profile))
    operations.profile_path = profile_path
    send_election_message(chain, body, value=NANO + 1)
    with pytest.raises(ops.OperationRefused):
        run(operations, chain=chain)


def test_busy_destination_settles_without_paging_its_history(world):
    chain, operations, _ = world
    record = run(operations, chain=chain)
    incoming = {"_cell": fakechain.message_cell(OTHER, DEST, 0, False)}
    for _ in range(ops.HISTORY_PAGES * ops.HISTORY_PAGE + 1):
        chain.record_tx(DEST, incoming, [], credit=0)
    with pytest.raises(ops.Unknown, match="history longer"):
        operations.nodes[0].history(DEST, None)
    for node in operations.nodes:
        original = node.rpc

        def rpc(url, method, /, _original=original, **kw):
            assert not (method == "getTransactionsStd" and kw["address"] == DEST)
            return _original(url, method, **kw)

        node.rpc = rpc
    state, evidence = operations.settle(dict(record, state="broadcast"))
    assert state == "settled" and evidence["destination_tx"]


def test_missing_delivery_is_pending_without_history_scan(world, monkeypatch):
    chain, operations, _ = world
    crash_at(monkeypatch, "fund-a", "signed")
    with pytest.raises(Crash):
        run(operations, chain=chain)
    record = operations.journal.record("fund-a")
    chain.send(base64.b64decode(record["boc"]))
    chain.tick()  # Source executes; internal message is still queued.
    state, evidence = operations.settle(record)
    assert state == "pending" and evidence["reason"] == "the message is not delivered yet"


@pytest.mark.parametrize("bad", ["block", "header", "boc", "order", "empty-page", "loop", "range"])
def test_delivery_search_refuses_unbound_or_nonprogressing_answers(world, monkeypatch, bad):
    chain, operations, _ = world
    record = run(operations, chain=chain)
    node = operations.nodes[1]
    original = node.rpc

    def rpc(url, method, /, **kw):
        result = original(url, method, **kw)
        if method == "lookupBlock" and bad == "range":
            result["workchain"] = 0
        if method == "getBlockHeader" and kw.get("seqno") != 10:
            if bad == "header":
                result["id"]["file_hash"] = base64.b64encode(b"z" * 32).decode()
            if bad == "loop":
                result["end_lt"] = "0"
        if method == "getBlockTransactionsExt":
            if bad == "block":
                result["id"]["root_hash"] = base64.b64encode(b"z" * 32).decode()
            if bad == "empty-page":
                result.update(transactions=[], incomplete=True)
            if result["transactions"]:
                if bad == "boc":
                    result["transactions"][0]["hash"] = base64.b64encode(b"z" * 32).decode()
                if bad == "order":
                    result["transactions"] *= 2
        return result

    node.rpc = rpc
    with pytest.raises(ops.Unknown):
        operations.settle(dict(record, state="broadcast"))


def test_delivery_search_has_an_explicit_block_budget(world, monkeypatch):
    chain, operations, _ = world
    record = run(operations, chain=chain)
    monkeypatch.setattr(ops, "DELIVERY_BLOCKS", 1)
    with pytest.raises(ops.Unknown, match="exceeds 1 shard blocks"):
        operations.settle(dict(record, state="broadcast"))


def test_election_message_reads_no_expired_state(election_world):
    chain, operations, _, body, calls = election_world
    send_election_message(chain, body)
    chain.now += 10 * 86400
    for node in operations.nodes:
        original = node.rpc

        def no_archive(url, method, /, _original=original, **kw):
            if method == "lookupBlock" or (
                method in {"getConfigParam", "runGetMethod"} and "seqno" in kw
            ):
                raise lib.TestnetError("expired historical state")
            return _original(url, method, **kw)

        node.rpc = no_archive
    report = operations.reconcile([BOOT])
    assert (
        not report["unexplained"] and report["explained"][0]["explained_by"] == "election-new-stake"
    )
    assert not any(method == "lookupBlock" for _, method, _ in calls)


def test_election_message_current_config_is_compared_to_genesis_not_profile(election_world):
    chain, operations, ceremony, body, _ = election_world
    send_election_message(chain, body)
    p = ceremony / "genesis.json"
    genesis = json.loads(p.read_text())
    genesis["election_params"]["stake_held_for"] += 1
    p.write_text(json.dumps(genesis))
    report = operations.reconcile([BOOT])
    assert report["unexplained"] and not report["explained"]


def test_delivery_matches_the_exact_inbound_hash(world):
    chain, operations, _ = world
    record = run(operations, chain=chain)
    tx = operations.find_wallet_tx(record)
    message = tx["out"][0]
    assert operations.find_delivery(DEST, "ff" * 32, message["created_lt"]) is None


def test_delivery_requires_both_validators(world):
    chain, operations, _ = world
    record = run(operations, chain=chain)
    node = operations.nodes[1]
    original = node.rpc

    def missing(url, method, /, **kw):
        result = original(url, method, **kw)
        if method == "getBlockTransactionsExt":
            result["transactions"] = []
            result["incomplete"] = False
        return result

    node.rpc = missing
    with pytest.raises(ops.Unknown, match="disagree"):
        operations.settle(dict(record, state="broadcast"))


def test_delivery_paginates_one_block_by_account_and_lt(world, monkeypatch):
    chain, operations, _ = world
    record = run(operations, chain=chain)
    monkeypatch.setattr(ops, "DELIVERY_PAGE", 1)
    pages = []
    for node in operations.nodes:
        original = node.rpc

        def rpc(url, method, /, _original=original, **kw):
            block = _original(url, "lookupBlock", workchain=-1, lt="9000")
            if method == "lookupBlock":
                return dict(block)
            if method == "getBlockHeader" and kw["seqno"] == 9000:
                return {"id": dict(block), "end_lt": "1002"}
            if method == "getBlockTransactionsExt":
                pages.append((url, dict(kw)))
                rows = [
                    {
                        "account": address.split(":")[1],
                        "lt": t["transaction_id"]["lt"],
                        "hash": t["transaction_id"]["hash"],
                        "data": t["data"],
                    }
                    for address, account in chain.accounts.items()
                    for t in account["txs"]
                ]
                rows.sort(key=lambda r: (r["account"], int(r["lt"])))
                if "after_lt" in kw:
                    rows = [
                        r
                        for r in rows
                        if (r["account"], int(r["lt"])) > (kw["after_account"], int(kw["after_lt"]))
                    ]
                return {"id": dict(block), "transactions": rows[:1], "incomplete": len(rows) > 1}
            return _original(url, method, **kw)

        node.rpc = rpc
    assert operations.settle(dict(record, state="broadcast"))[0] == "settled"
    assert len(pages) == 4
    cursors = [kw for _, kw in pages if "after_lt" in kw]
    assert len(cursors) == 2
    assert all(
        kw["after_account"] == BOOT.split(":")[1] and kw["after_lt"] == "1001" for kw in cursors
    )


def test_masterchain_delivery_uses_the_full_masterchain_shard(world):
    chain, operations, _ = world
    for node in operations.nodes:
        original = node.rpc

        def rpc(url, method, /, _original=original, **kw):
            if method == "lookupBlock" and kw["workchain"] == lib.MASTERCHAIN:
                assert int(kw["shard"]) == lib.MASTERCHAIN_SHARD
            return _original(url, method, **kw)

        node.rpc = rpc
    assert run(operations, chain=chain)["state"] == "settled"


ELECTION_TASK_MESSAGES = [
    ("new-stake", 0x4E73744B, NANO + NANO // 5),
    ("recover-stake", 0x47657424, NANO // 5),
    ("update-validator-set", 0x06, NANO // 5),
    ("validator-deposit", 0x04, 10 * NANO),
    ("process-withdraw-requests", 0x02, NANO // 5),
]


def election_task_body(opcode, stake_body, *, query_id=1800000000, limit=8, suffix="", refs=()):
    if opcode == 0x4E73744B:
        return stake_body
    bits = format(opcode, "032b") + format(query_id, "064b")
    if opcode == 0x02:
        bits += format(limit, "08b")
    return lib.cell_from_bits(bits + suffix, list(refs))


@pytest.mark.parametrize("kind,opcode,ceiling", ELECTION_TASK_MESSAGES)
def test_each_election_task_message_is_explained(election_world, kind, opcode, ceiling):
    chain, operations, _, stake_body, calls = election_world
    body = election_task_body(opcode, stake_body)
    send_election_message(chain, body, value=ceiling)
    chain.now += 10 * 86400
    report = operations.reconcile([BOOT])
    assert not report["unexplained"]
    [row] = report["explained"]
    assert row["explained_by"] == f"election-{kind}"
    assert row["wallet"] == BOOT and row["out"][0]["value"] == ceiling
    assert row["query_id"] == (0 if kind == "new-stake" else 1800000000)
    if kind != "new-stake":
        assert "election_id" not in row
        assert not any(method == "getConfigParam" for _, method, _ in calls)
    assert run(operations, chain=chain)["state"] == "settled"


@pytest.mark.parametrize("kind,opcode,ceiling", ELECTION_TASK_MESSAGES)
@pytest.mark.parametrize("bad", ["pool", "budget", "opcode", "two", "zero"])
def test_each_election_task_message_keeps_shared_refusals(
    election_world, kind, opcode, ceiling, bad
):
    chain, operations, _, stake_body, _ = election_world
    body = election_task_body(opcode, stake_body)
    if bad == "opcode":
        # Keep the expected fields, changing only the opcode to an unrecognized one.
        bits = format(0x7702, "032b") + format(
            lib.Slice(body).bits(body.bits) & ((1 << (body.bits - 32)) - 1),
            f"0{body.bits - 32}b",
        )
        body = lib.cell_from_bits(bits, list(body.refs))
    if bad == "two":
        chain.extra_out[BOOT] = (OTHER, NANO)
    send_election_message(
        chain,
        body,
        destination=OTHER if bad == "pool" else DEST,
        value=ceiling + 1 if bad == "budget" else (0 if bad == "zero" else ceiling),
    )
    report = operations.reconcile([BOOT])
    assert report["unexplained"] and not report["explained"]
    with pytest.raises(ops.OperationRefused):
        run(operations, chain=chain)
    assert len(chain.sent) == 1


@pytest.mark.parametrize("opcode", [0x47657424, 0x06, 0x04, 0x02])
@pytest.mark.parametrize("bad", ["truncated", "bits", "refs", "init"])
def test_recovery_and_maintenance_require_exact_bodies(election_world, opcode, bad):
    chain, operations, _, stake_body, _ = election_world
    body = election_task_body(
        opcode,
        stake_body,
        suffix="0" if bad == "bits" else "",
        refs=[lib.cell_from_bits("")] if bad == "refs" else [],
    )
    if bad == "truncated":
        body = lib.cell_from_bits(format(opcode, "032b"))
    init = fakechain.wallet_state_init("ab" * 32) if bad == "init" else None
    chain.send(
        build_external(
            BOOT,
            2,
            1,
            chain.now + 300,
            internal_message(DEST, NANO // 5, False, body=body, init=init),
        )
    )
    chain.settle_all()
    report = operations.reconcile([BOOT])
    assert report["unexplained"] and not report["explained"]


@pytest.mark.parametrize("limit", [0, 7, 9, 255])
def test_withdrawal_queue_processing_uses_the_runner_batch_size(election_world, limit):
    chain, operations, _, stake_body, _ = election_world
    send_election_message(chain, election_task_body(0x02, stake_body, limit=limit), value=NANO // 5)
    report = operations.reconcile([BOOT])
    assert report["unexplained"] and not report["explained"]


def test_new_operation_is_not_journaled_before_its_gate_passes(world):
    chain, operations, _ = world
    operations.begin("blocked-plan", params())
    before = operations.journal.all()
    for name in ("load-refill-1", "load-relayer-1"):
        with pytest.raises(ops.OperationRefused, match="open"):
            run(operations, name, chain=chain)
        assert operations.journal.record(name) is None, "a refused load restart left a new plan"
    assert operations.journal.all() == before
    assert chain.sent == []


def planned_fund(world):
    chain, operations, _ = world
    chain.now = int(time.time()) + 10
    with operations.journal.lock():
        record = operations.begin("unsigned-refill", params())
    return chain, operations, record


def test_abandon_unsigned_fund_dry_run_then_terminal_record(world):
    chain, operations, record = planned_fund(world)
    original = operations.journal.lines(record["id"])
    preview = operations.record_abandoned(record["id"], dry_run=True)
    assert preview["state"] == "planned" and preview["dry_run"]
    assert len(preview["evidence"]["observations"]) == 2
    assert all(o["matching_transactions"] == [] for o in preview["evidence"]["observations"])
    assert operations.journal.lines(record["id"]) == original
    result = operations.record_abandoned(record["id"])
    assert result["state"] == "failed"
    assert result["evidence"]["form"] == "unsigned-fund-plan-abandoned"
    assert operations.journal.lines(record["id"])[0] == original[0]
    assert len(operations.journal.lines(record["id"])) == 2
    with pytest.raises(ops.OperationRefused, match="unsigned planned"):
        operations.record_abandoned(record["id"])
    assert len(operations.journal.lines(record["id"])) == 2
    assert chain.sent == []
    operations.gate(BOOT, "next-refill")


@pytest.mark.parametrize(
    "field,value", [("boc", "bytes"), ("external_hash", "ab" * 32), ("seqno", 1)]
)
def test_abandon_refuses_any_signing_evidence(world, field, value):
    _, operations, record = planned_fund(world)
    operations.journal.append(record["id"], {"state": "planned", field: value})
    before = operations.journal.lines(record["id"])
    with pytest.raises(ops.OperationRefused, match="signing evidence"):
        operations.record_abandoned(record["id"])
    assert operations.journal.lines(record["id"]) == before


@pytest.mark.parametrize("emitted", [False, True])
def test_abandon_refuses_a_matching_wallet_transaction_even_without_outputs(world, emitted):
    chain, operations, record = planned_fund(world)
    boc = signer(chain)(chain.account(BOOT)["seqno"])
    if emitted:
        chain.send(boc)
        chain.tick()
    else:
        root = lib.parse_boc(boc)
        incoming = {
            "kind": "external",
            "hash": base64.b64encode(root.hash()).decode(),
            "_cell": root,
        }
        chain.record_tx(BOOT, incoming, [], success=False, aborted=True)
    before = operations.journal.lines(record["id"])
    with pytest.raises(ops.OperationRefused, match="matches the planned fund"):
        operations.record_abandoned(record["id"])
    assert operations.journal.lines(record["id"]) == before


def test_abandon_does_not_use_a_baseline_to_hide_a_matching_transfer(world):
    chain, operations, record = planned_fund(world)
    chain.send(signer(chain)(chain.account(BOOT)["seqno"]))
    chain.tick()
    operations.journal.set_baseline(BOOT, operations.head(BOOT), "test boundary")
    with pytest.raises(ops.OperationRefused, match="matches the planned fund"):
        operations.record_abandoned(record["id"])


def test_abandon_rechecks_after_its_first_absence_read(world, monkeypatch):
    chain, operations, record = planned_fund(world)
    original = operations.fund_plan_absence
    count = 0

    def read(*args):
        nonlocal count
        result = original(*args)
        count += 1
        if count == 1:
            chain.send(signer(chain)(chain.account(BOOT)["seqno"]))
            chain.tick()
        return result

    monkeypatch.setattr(operations, "fund_plan_absence", read)
    with pytest.raises(ops.OperationRefused, match="matches the planned fund"):
        operations.record_abandoned(record["id"])
    assert operations.journal.record(record["id"])["state"] == "planned"


@pytest.mark.parametrize("failure", ["timeout", "disagree", "stale"])
def test_abandon_unknown_is_not_absence(world, monkeypatch, failure):
    _, operations, record = planned_fund(world)
    if failure == "stale":
        monkeypatch.setattr(operations, "utimes", lambda: [0, 0])
    elif failure == "timeout":

        def broken(*args):
            raise ops.Unknown("history timeout")

        monkeypatch.setattr(operations.nodes[1], "history", broken)
    else:
        chain = world[0]
        chain.send(signer(chain, destination=OTHER)(chain.account(BOOT)["seqno"]))
        chain.tick()
        monkeypatch.setattr(operations.nodes[1], "history", lambda *args: [])
    with pytest.raises(ops.Unknown):
        operations.record_abandoned(record["id"])
    assert operations.journal.record(record["id"])["state"] == "planned"


def test_signing_before_the_signed_journal_write_cannot_broadcast(world, monkeypatch):
    chain, operations, _ = world
    chain.now = int(time.time()) + 10
    original = operations.journal.append
    sign = signer(chain)

    def fail_write(op_id, entry):
        if entry["state"] == "signed":
            raise OSError("signed journal fsync failed")
        return original(op_id, entry)

    monkeypatch.setattr(operations.journal, "append", fail_write)
    with pytest.raises(OSError, match="fsync"):
        run(operations, sign=sign, chain=chain)
    assert sign.calls == [1]
    assert chain.sent == []
    assert operations.journal.record("fund-a")["state"] == "planned"
    monkeypatch.setattr(operations.journal, "append", original)
    assert operations.record_abandoned("fund-a")["state"] == "failed"


def test_abandon_does_not_touch_another_wallet(world):
    chain, operations, record = planned_fund(world)
    chain.wallet(OTHER, 100 * NANO, public_key="0f" * 32)
    operations.begin("other-wallet-plan", params(wallet=OTHER))
    other_before = operations.journal.lines("other-wallet-plan")
    chain.send(signer(chain, wallet=OTHER)(chain.account(OTHER)["seqno"]))
    chain.tick()
    assert operations.record_abandoned(record["id"])["state"] == "failed"
    assert operations.journal.lines("other-wallet-plan") == other_before


def test_abandon_refuses_non_funding_plans(world):
    _, operations, record = planned_fund(world)
    operations.journal.append(record["id"], {"state": "planned", "kind": "activate-owner"})
    with pytest.raises(ops.OperationRefused, match="unsigned planned fund"):
        operations.record_abandoned(record["id"])


def test_abandon_ignores_a_matching_transfer_before_the_plan(world):
    chain, operations, record = planned_fund(world)
    from datetime import datetime, timezone

    since = int(
        datetime.strptime(record["utc"], "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=timezone.utc)
        .timestamp()
    )
    chain.now = since - 10
    chain.send(signer(chain)(chain.account(BOOT)["seqno"]))
    chain.tick()
    chain.now = since + 20
    assert operations.record_abandoned(record["id"])["state"] == "failed"


def test_abandon_stops_before_unavailable_history_older_than_the_plan(world, monkeypatch):
    chain, operations, record = planned_fund(world)
    since = int(time.time())
    chain.now = since - 20
    chain.send(signer(chain, destination=OTHER)(chain.account(BOOT)["seqno"]))
    chain.settle_all()
    chain.now = since + 20
    for node in operations.nodes:
        real = node.rpc
        calls = []

        def limited(url, method, /, _real=real, _calls=calls, **params):
            if method == "getTransactionsStd":
                _calls.append(params)
                if params["lt"] != _calls[0]["lt"] or params["limit"] != 1:
                    raise lib.TestnetError("older history has been collected")
            return _real(url, method, **params)

        monkeypatch.setattr(node, "rpc", limited)
    assert operations.record_abandoned(record["id"])["state"] == "failed"


# ------------------------------------------------ bootstrap closed-prefix checkpoints


@pytest.fixture
def checkpoint_world(world, monkeypatch):
    chain, operations, ceremony = world
    genesis = json.loads((ceremony / "genesis.json").read_text())
    genesis["main_wallet_public_key"] = "b0" * 32
    (ceremony / "genesis.json").write_text(json.dumps(genesis))
    monkeypatch.setattr(
        ops, "BOOTSTRAP_CODE_HASH", fakechain.WALLET_CODE.hash().hex(), raising=False
    )
    chain.account(BOOT)["seqno"] = 0
    account = chain.account(BOOT)
    account["data"] = fakechain.wallet_data(
        account["seqno"], account["subwallet"], account["public_key"]
    )
    return world


def checkpoint_prune(operations, monkeypatch, before=None, error="pruned"):
    for node in operations.nodes:
        original = node.rpc

        def rpc(url, method, _original=original, **kw):
            if method == "getTransactionsStd" and (before is None or int(kw["lt"]) <= before):
                if error == "empty":
                    return {"transactions": []}
                raise lib.RpcError(
                    url,
                    method,
                    -32603 if error == "pruned" else -503,
                    "INTERNAL_ERROR",
                    "lt not in db" if error == "pruned" else "timeout",
                    False,
                )
            return _original(url, method, **kw)

        monkeypatch.setattr(node, "rpc", rpc)


def checkpoint_legacy(world):
    chain, operations, _ = world
    result = run(operations, "checkpoint-first", chain=chain)
    # A legacy receipt has the same terminal acknowledgement, without a certificate.
    path = operations.journal.path(result["id"])
    lines = [dict(line) for line in operations.journal.lines(result["id"])]
    for line in lines:
        line.pop("checkpoint", None)
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    return result


def test_checkpoint_pruned_legacy_prefix_and_readonly_migration(checkpoint_world, monkeypatch):
    chain, operations, _ = checkpoint_world
    first = checkpoint_legacy(checkpoint_world)
    checkpoint_prune(operations, monkeypatch)
    before = operations.journal.path(first["id"]).read_bytes()
    report = operations.record_checkpoint(first["id"], dry_run=True)
    assert report["counter_interval"] == [0, 1]
    assert report["pruned_gap"] and len(report["observations"]) == 2
    assert "only by the coordinator" in report["assumption"]
    assert operations.journal.path(first["id"]).read_bytes() == before
    operations.record_checkpoint(first["id"])
    size = operations.journal.path(first["id"]).stat().st_size
    operations.record_checkpoint(first["id"])
    assert operations.journal.path(first["id"]).stat().st_size == size
    operations.gate(BOOT, "future")
    assert operations.reconcile([BOOT])["unexplained"] == []
    assert operations.journal.path(first["id"]).stat().st_size == size


def test_checkpoint_anchor_is_not_fetched(checkpoint_world, monkeypatch):
    chain, operations, _ = checkpoint_world
    first = run(operations, "checkpoint-first", chain=chain)
    cp = first.get("checkpoint")
    assert cp is not None, first.get("checkpoint_refusal")
    checkpoint_prune(operations, monkeypatch, before=int(cp["head"]["lt"]))
    operations.gate(BOOT, "future")
    second = run(operations, "checkpoint-second", chain=chain)
    assert second.get("checkpoint"), second.get("checkpoint_refusal")
    assert second["checkpoint"]["previous"] == cp["digest"]
    operations.gate(BOOT, "future")


@pytest.mark.parametrize("damage", ["missing", "duplicate", "unsigned", "wrong-hash", "unexecuted"])
def test_checkpoint_counter_needs_verified_receipts(checkpoint_world, monkeypatch, damage):
    chain, operations, _ = checkpoint_world
    first = checkpoint_legacy(checkpoint_world)
    checkpoint_prune(operations, monkeypatch)
    if damage == "duplicate":
        for line in operations.journal.lines(first["id"]):
            operations.journal.append("checkpoint-duplicate", line)
    else:
        evidence = dict(first["evidence"])
        fields = {}
        if damage == "missing":
            evidence.pop("wallet_tx")
        elif damage == "unsigned":
            fields["boc"] = None
        elif damage == "unexecuted":
            chain.account(BOOT)["seqno"] = 0
            chain.account(BOOT)["data"] = fakechain.wallet_data(0, 0, "b0" * 32)
        else:
            fields["external_hash"] = "0" * 64
        operations.journal.append(first["id"], dict(fields, state="settled", evidence=evidence))
    with pytest.raises(ops.OperationRefused):
        operations.record_checkpoint(first["id"], dry_run=True)
    assert operations.bootstrap_certificate(BOOT) is None


@pytest.mark.parametrize("error", ["empty", "timeout"])
def test_checkpoint_partial_history_is_not_pruning(checkpoint_world, monkeypatch, error):
    _, operations, _ = checkpoint_world
    first = checkpoint_legacy(checkpoint_world)
    checkpoint_prune(operations, monkeypatch, error=error)
    with pytest.raises(ops.Unknown):
        operations.record_checkpoint(first["id"], dry_run=True)


def test_checkpoint_unexplained_consumer_cannot_be_hidden(checkpoint_world, monkeypatch):
    chain, operations, _ = checkpoint_world
    first = run(operations, "checkpoint-first", chain=chain)
    chain.send(signer(chain)(1))
    chain.tick()
    with pytest.raises(ops.Unknown, match="unexplained seqno 1"):
        operations.gate(BOOT, "future")
    checkpoint_prune(operations, monkeypatch)
    with pytest.raises(ops.Unknown, match="unexplained seqno 1"):
        operations.record_checkpoint(first["id"], dry_run=True)


@pytest.mark.parametrize("field", ["code", "public_key", "subwallet", "seqno", "state", "overflow"])
def test_checkpoint_incarnation_change_refused(checkpoint_world, field):
    chain, operations, _ = checkpoint_world
    run(operations, "checkpoint-first", chain=chain)
    account = chain.account(BOOT)
    if field == "overflow":
        field = "seqno"
        account["seqno"] = 0xFFFFFFFF
        account["data"] = fakechain.wallet_data(0xFFFFFFFF, 0, account["public_key"])
        with pytest.raises(ops.Unknown):
            operations.gate(BOOT, "future")
        return
    account[field] = {
        "code": lib.cell_from_bits("0"),
        "public_key": "12" * 32,
        "subwallet": 5,
        "seqno": 0,
        "state": "uninitialized",
    }[field]
    account = chain.account(BOOT)
    account["data"] = fakechain.wallet_data(
        account["seqno"], account["subwallet"], account["public_key"]
    )
    with pytest.raises(ops.Unknown):
        operations.gate(BOOT, "future")


def test_checkpoint_certificate_binding_and_fork_refused(checkpoint_world):
    chain, operations, _ = checkpoint_world
    first = run(operations, "checkpoint-first", chain=chain)
    cp = dict(first["checkpoint"])
    cp["post_seqno"] += 1
    operations.journal.append(first["id"], {"state": "settled", "checkpoint": cp})
    with pytest.raises(ops.Unknown, match="digest"):
        operations.gate(BOOT, "future")


def test_checkpoint_append_failure_does_not_replace_parent(checkpoint_world, monkeypatch):
    chain, operations, _ = checkpoint_world
    first = run(operations, "checkpoint-first", chain=chain)
    cp = first["checkpoint"]
    original = operations.journal.append

    def fail(op_id, entry):
        if entry.get("checkpoint"):
            raise OSError("fsync refused")
        original(op_id, entry)

    monkeypatch.setattr(operations.journal, "append", fail)
    with pytest.raises(OSError, match="fsync"):
        run(operations, "checkpoint-second", chain=chain)
    assert operations.bootstrap_certificate(BOOT) == cp


def test_checkpoint_two_validators_must_agree(checkpoint_world, monkeypatch):
    chain, operations, _ = checkpoint_world
    first = checkpoint_legacy(checkpoint_world)
    node = operations.nodes[1]
    original = node.rpc

    def disagree(url, method, **kw):
        answer = original(url, method, **kw)
        if method == "getAddressInformation" and kw["address"] == BOOT:
            answer["data"] = base64.b64encode(
                lib.serialize_boc(fakechain.wallet_data(2, 0, "b0" * 32))
            ).decode()
        return answer

    monkeypatch.setattr(node, "rpc", disagree)
    with pytest.raises(ops.Unknown, match="disagree"):
        operations.record_checkpoint(first["id"], dry_run=True)
    assert operations.bootstrap_certificate(BOOT) is None


def test_checkpoint_valid_digest_fork_refused(checkpoint_world):
    chain, operations, _ = checkpoint_world
    first = run(operations, "checkpoint-first", chain=chain)
    cp = dict(first["checkpoint"])
    cp["assumption"] += " conflicting"
    cp["digest"] = ops.certificate_digest({k: v for k, v in cp.items() if k != "digest"})
    operations.journal.append(first["id"], {"state": "settled", "checkpoint": cp})
    with pytest.raises(ops.Unknown, match="fork"):
        operations.gate(BOOT, "future")


def test_checkpoint_retry_does_not_inherit_certificate(world):
    _, operations, _ = world
    operations.journal.append(
        "checkpoint-failed",
        dict(
            params(),
            state="failed",
            evidence={"form": "b"},
            checkpoint={"digest": "untrusted"},
            gate_witness={"head": "stale"},
            checkpoint_refusal="old",
        ),
    )
    successor = operations.retry("checkpoint-failed", "retry verified failure")
    assert "checkpoint" not in successor
    assert "gate_witness" not in successor
    assert "checkpoint_refusal" not in successor


def test_checkpoint_unsigned_abandonment_does_not_consume_counter(checkpoint_world):
    chain, operations, _ = checkpoint_world
    first = checkpoint_legacy(checkpoint_world)
    operations.journal.append(
        "checkpoint-abandoned",
        dict(
            params(),
            state="failed",
            evidence={"form": "unsigned-fund-plan-abandoned", "explains": []},
        ),
    )
    report = operations.record_checkpoint(first["id"], dry_run=True)
    assert len(report["receipts"]) == 1 and report["post_seqno"] == 1


def test_checkpoint_open_records_refuse_migration(checkpoint_world):
    chain, operations, _ = checkpoint_world
    first = checkpoint_legacy(checkpoint_world)
    operations.journal.append("checkpoint-open", dict(params(), state="planned"))
    with pytest.raises(ops.OperationRefused, match="open"):
        operations.record_checkpoint(first["id"], dry_run=True)


def test_checkpoint_terminal_survives_uncertifiable_prefix(checkpoint_world, monkeypatch):
    chain, operations, _ = checkpoint_world
    first = checkpoint_legacy(checkpoint_world)
    record = operations.journal.record(first["id"])
    checkpoint_prune(operations, monkeypatch)
    evidence = dict(record["evidence"])
    # The recorded operation is real, but an additional consumer is unexplained.
    chain.send(signer(chain)(1))
    chain.tick()
    operations.append_terminal(record, "settled", evidence)
    result = operations.journal.record(first["id"])
    assert result["state"] == "settled" and result["evidence"] == evidence
    assert "unexplained seqno" in result["checkpoint_refusal"]
    assert operations.bootstrap_certificate(BOOT) is None


def test_checkpoint_all_entry_points_share_verifier():
    import inspect

    for method in (
        ops.Operations.gate,
        ops.Operations.reconcile,
        ops.Operations.append_terminal,
        ops.Operations.record_checkpoint,
    ):
        assert "verify_bootstrap_prefix(" in inspect.getsource(method)
    assert "self.gate(wallet, op_id)" in inspect.getsource(ops.Operations.run)
    for method in (
        ops.Operations.watch,
        ops.Operations.record_settled,
        ops.Operations.record_failed,
    ):
        assert "self.append_terminal(" in inspect.getsource(method)
    assert "self.bootstrap_tail(" in inspect.getsource(ops.Operations.wallet_attempts)


def test_checkpoint_interior_receipt_gap_refused(checkpoint_world, monkeypatch):
    chain, operations, _ = checkpoint_world
    first = checkpoint_legacy(checkpoint_world)
    second = run(operations, "checkpoint-second", chain=chain)
    # Remove certificates to exercise legacy migration, not an already certified prefix.
    for record in (first, second):
        path = operations.journal.path(record["id"])
        lines = operations.journal.lines(record["id"])
        for line in lines:
            line.pop("checkpoint", None)
            if record["id"] == first["id"] and line["state"] == "settled":
                line["evidence"].pop("wallet_tx", None)
        path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    checkpoint_prune(operations, monkeypatch)
    with pytest.raises(ops.Unknown, match="unexplained seqno"):
        operations.record_checkpoint(second["id"], dry_run=True)


def test_checkpoint_pruned_history_uses_verified_anchor(checkpoint_world, monkeypatch):
    chain, operations, _ = checkpoint_world
    run(operations, "checkpoint-first", chain=chain)
    checkpoint_prune(operations, monkeypatch)
    try:
        operations.gate(BOOT, "future")
    except ops.OperationRefused as exc:
        pytest.fail(f"gate still requests pruned pre-checkpoint history: {exc}")


def test_checkpoint_pruned_head_regression_refused(checkpoint_world, monkeypatch):
    chain, operations, _ = checkpoint_world
    first = run(operations, "checkpoint-first", chain=chain)
    incoming = internal_message(BOOT, NANO, False)
    chain.record_tx(BOOT, dict(ops.decode_message(incoming), _cell=incoming), [], credit=NANO)
    operations.record_checkpoint(first["id"])
    chain.account(BOOT)["txs"].pop()
    checkpoint_prune(operations, monkeypatch)
    with pytest.raises(ops.Unknown, match="head regressed"):
        operations.gate(BOOT, "future")


# ------------------------------------------------ the bootstrap wallet's final sweep

BLACK = ops.BLACKHOLE


@pytest.fixture
def sweep_world(checkpoint_world):
    """A pinned bootstrap wallet on a chain whose ConfigParam 5 burns at the blackhole."""
    chain, _, _ = checkpoint_world
    chain.blackhole = BLACK
    chain.config[5] = chainbuild.burning_config()
    chain.head_bounds_lt = True
    return checkpoint_world


def sweep_params(**extra):
    extra = {"value": 0, "destination": BLACK, **extra}
    return params(kind="sweep", label="sweep-bootstrap", **extra)


def sweep_signer(chain, **kw):
    kw.setdefault("destination", BLACK)
    kw.setdefault("value", 0)
    kw.setdefault("mode", ops.SWEEP_MODE)
    return signer(chain, **kw)


def sweep(operations, chain, op_id="sweep-bootstrap", p=None, sign=None):
    return operations.run(op_id, p or sweep_params(), sign or sweep_signer(chain), lambda d: None)


def swept(operations, chain, op_id="sweep-bootstrap"):
    """Run the sweep until it waits for its burn block; (record, pending evidence)."""
    with pytest.raises(ops.OperationRefused, match="fetch block"):
        sweep(operations, chain, op_id)
    record = operations.journal.record(op_id)
    outcome, evidence = operations.settle(record)
    assert outcome == "pending", evidence
    return record, evidence


def burn_block(chain, evidence, flow=None, include=True, global_id=2, extra_txs=None):
    """The burn block's file, registered so the chain names it by its file hash."""
    seqno = int(evidence["destination_block"]["seqno"])
    blackhole = chain.account(BLACK)["txs"]
    cells = {
        int(t["transaction_id"]["lt"]): chainbuild.tx_cell(t)
        for t in blackhole
        if int(t["transaction_id"]["lt"]) == seqno and include
    }
    cells.update(extra_txs or {})
    boc = chainbuild.block(
        global_id,
        seqno,
        seqno,
        seqno,
        flow or chainbuild.balanced_flow(evidence["burned_nanotos"]),
        {BLACK.split(":")[1]: cells},
    )
    chain.blocks[seqno] = boc
    return boc


def settle_burn(operations, evidence, boc, op_id="sweep-bootstrap"):
    return operations.record_settled(op_id, evidence["wallet_tx"], ops.burn_expect(boc))


def test_a_sweep_burns_the_whole_balance_and_deletes_the_wallet(sweep_world):
    chain, operations, ceremony = sweep_world
    run(operations, "fund-a", chain=chain)
    before = chain.account(BOOT)["balance"]
    record, evidence = swept(operations, chain)
    lines = [
        json.loads(x)["state"]
        for x in operations.journal.path(record["id"]).read_text().splitlines()
    ]
    assert lines == ["planned", "signed", "broadcast"]
    assert int(record["search_lt"]) > 0 and record["seqno"] == 1
    # The chain: the wallet is gone, all of it went to the blackhole and was burned.
    assert chain.account(BOOT)["deleted"] and chain.account(BOOT)["balance"] == 0
    assert evidence["wallet_end_status"] == "nonexist"
    assert evidence["burned_nanotos"] == before - NANO // 100
    assert evidence["wallet_after"] == [{"state": "uninitialized", "balance": 0}] * 2
    assert "credit" not in evidence["reason"]
    boc = burn_block(chain, evidence)
    settled = settle_burn(operations, evidence, boc)
    assert settled["state"] == "settled"
    burn = settled["evidence"]["burn"]
    assert burn["value_flow"]["burned"] == evidence["burned_nanotos"]
    assert burn["blackhole_transactions"] == [
        {
            "tx": settled["evidence"]["destination_tx"],
            "lt": int(evidence["destination_block"]["seqno"]),
            "nanotos": evidence["burned_nanotos"],
        }
    ]
    assert burn["sweep_message"] == settled["evidence"]["message"]
    # The terminal certificate covers the deleted wallet up to the sweep's counter.
    cp = operations.bootstrap_certificate(BOOT)
    assert cp["deleted"] is True and cp["post_seqno"] == record["seqno"] + 1
    assert cp["head"]["hash"] == settled["evidence"]["wallet_tx"]
    assert "checkpoint_refusal" not in settled


def test_a_settled_sweep_retires_the_bootstrap_wallet(sweep_world):
    chain, operations, _ = sweep_world
    record, evidence = swept(operations, chain)
    settle_burn(operations, evidence, burn_block(chain, evidence))
    assert operations.bootstrap_retired(BOOT) == record["id"]
    with pytest.raises(ops.OperationRefused, match="has been swept"):
        run(operations, "fund-after", chain=chain)
    with pytest.raises(ops.OperationRefused, match="has been swept"):
        sweep(operations, chain, "sweep-again")
    report = operations.reconcile([BOOT])
    assert report["unexplained"] == []
    assert report["retired"][0]["swept_by"] == record["id"]
    assert report["retired"][0]["burned_nanotos"] == evidence["burned_nanotos"]
    # Retirement concerns only the bootstrap source; other wallets still sign.
    assert operations.bootstrap_retired(OTHER) is None


def test_a_retired_wallet_that_reads_active_again_is_unexplained(sweep_world):
    chain, operations, _ = sweep_world
    _, evidence = swept(operations, chain)
    settle_burn(operations, evidence, burn_block(chain, evidence))
    chain.account(BOOT)["deleted"] = False
    chain.account(BOOT)["state"] = "active"
    report = operations.reconcile([BOOT])
    assert "reads active" in report["unexplained"][0]["unknown"]


@pytest.mark.parametrize(
    "sign_kw, p_kw, message",
    [
        ({"mode": 3}, {}, "send mode 160"),
        ({"mode": 128}, {}, "send mode 160"),
        ({"bounce": True}, {"bounce": True}, "non-bounce"),
        ({"destination": DEST}, {"destination": DEST}, "to the blackhole"),
        ({"value": NANO}, {"value": NANO}, "value 0"),
    ],
)
def test_only_the_exact_final_transfer_is_signed_as_a_sweep(sweep_world, sign_kw, p_kw, message):
    chain, operations, _ = sweep_world
    with pytest.raises(ops.OperationRefused, match=message):
        sweep(operations, chain, p=sweep_params(**p_kw), sign=sweep_signer(chain, **sign_kw))
    assert chain.sent == []
    assert operations.journal.record("sweep-bootstrap")["state"] == "planned"


def test_a_funding_signed_with_the_sweep_mode_is_refused(sweep_world):
    chain, operations, _ = sweep_world
    with pytest.raises(ops.OperationRefused, match="send mode 3"):
        run(operations, chain=chain, sign=signer(chain, mode=ops.SWEEP_MODE))
    assert chain.sent == []


def test_a_sweep_needs_the_pinned_bootstrap_wallet(world):
    chain, operations, _ = world
    with pytest.raises(ops.OperationRefused, match="pinned bootstrap"):
        sweep(operations, chain)
    assert chain.sent == [] and operations.journal.record("sweep-bootstrap") is None


def test_a_sweep_that_did_not_delete_the_wallet_failed(sweep_world):
    chain, operations, _ = sweep_world
    chain.keep_swept = True
    with pytest.raises(ops.OperationRefused, match="not deleted"):
        sweep(operations, chain)
    record = operations.journal.record("sweep-bootstrap")
    assert record["state"] == "failed" and record["evidence"]["form"] == "a"


def test_a_sweep_credited_at_the_blackhole_is_not_burned(sweep_world):
    chain, operations, _ = sweep_world
    chain.blackhole = None  # ConfigParam 5 not in force: an ordinary account is credited
    with pytest.raises(ops.OperationRefused, match="not burned"):
        sweep(operations, chain)
    record = operations.journal.record("sweep-bootstrap")
    assert record["state"] == "failed" and record["evidence"]["form"] == "b"
    # It took effect: the bootstrap wallet is retired all the same.
    assert operations.bootstrap_retired(BOOT) == "sweep-bootstrap"


@pytest.mark.parametrize("point", ["signed", "broadcast"])
def test_an_interrupted_sweep_is_settled_from_its_signed_boundary(sweep_world, monkeypatch, point):
    chain, operations, _ = sweep_world
    run(operations, "fund-a", chain=chain)
    crash_at(monkeypatch, "sweep-bootstrap", point)
    with pytest.raises(Crash):
        sweep(operations, chain)
    monkeypatch.setattr(ops, "crash_point", lambda *a: None)
    if point == "signed":
        assert chain.sent == [chain.sent[0]]  # only the funding went out
        with pytest.raises(ops.OperationRefused, match="fetch block"):
            operations.resubmit("sweep-bootstrap")
    chain.settle_all()
    assert chain.account(BOOT)["deleted"]
    # A rerun refuses the open operation; reconcile shows it from the chain alone.
    with pytest.raises(ops.OperationRefused, match="is open"):
        sweep(operations, chain)
    row = next(
        r for r in operations.reconcile([BOOT])["operations"] if r["id"] == "sweep-bootstrap"
    )
    outcome, evidence = row["chain"]
    assert outcome == "pending" and "fetch block" in evidence["reason"]
    settled = settle_burn(operations, evidence, burn_block(chain, evidence))
    assert settled["state"] == "settled"
    assert operations.bootstrap_certificate(BOOT)["deleted"] is True


def test_a_deleted_wallet_no_journaled_sweep_explains_is_unknown(sweep_world):
    chain, operations, _ = sweep_world
    run(operations, "fund-a", chain=chain)
    chain.account(BOOT)["deleted"] = True
    with pytest.raises(ops.Unknown, match="exactly one must explain"):
        operations.gate(BOOT, "next")


def test_a_sweep_without_its_signed_search_boundary_is_unknown(sweep_world):
    chain, operations, _ = sweep_world
    record, _ = swept(operations, chain)
    path = operations.journal.path(record["id"])
    lines = [json.loads(x) for x in path.read_text().splitlines()]
    for line in lines:
        line.pop("search_lt", None)
    path.write_text("".join(json.dumps(x) + "\n" for x in lines))
    with pytest.raises(ops.Unknown, match="search boundary"):
        operations.settle(operations.journal.record(record["id"]))


def test_a_deleted_wallet_validators_disagree_on_is_unknown(sweep_world, monkeypatch):
    chain, operations, _ = sweep_world
    record, _ = swept(operations, chain)
    real = operations.nodes[1].external_runs
    monkeypatch.setattr(operations.nodes[1], "external_runs", lambda *a: real(*a)[:-1])
    with pytest.raises(ops.Unknown, match="disagree"):
        operations.settle(operations.journal.record(record["id"]))


def test_the_burn_block_must_be_the_blackhole_transactions_block(sweep_world):
    chain, operations, _ = sweep_world
    _, evidence = swept(operations, chain)
    good = burn_block(chain, evidence)
    with pytest.raises(ops.OperationRefused, match="file hash"):
        settle_burn(operations, evidence, good + b"\x00")
    assert operations.journal.record("sweep-bootstrap")["state"] == "broadcast"


@pytest.mark.parametrize(
    "damage, message",
    [
        ("burned-short", "does not reconcile"),
        ("value-flow-v1", "does not reconcile"),
        ("unbalanced", "does not balance"),
        ("no-transaction", "no transaction of the blackhole"),
        ("other-network", "not the masterchain block"),
        ("credited-burn", "not a burn"),
    ],
)
def test_a_burn_the_block_does_not_account_for_refuses(sweep_world, damage, message):
    chain, operations, _ = sweep_world
    _, evidence = swept(operations, chain)
    burned = evidence["burned_nanotos"]
    kw = {}
    if damage == "burned-short":
        kw["flow"] = chainbuild.balanced_flow(burned - 1)
    elif damage == "unbalanced":
        kw["flow"] = dict(chainbuild.balanced_flow(burned), created=1)
    elif damage == "no-transaction":
        kw["include"] = False
        kw["flow"] = chainbuild.balanced_flow(0)
    elif damage == "other-network":
        kw["global_id"] = 3
    elif damage == "credited-burn":
        credited = fakechain.transaction_cell(
            BLACK,
            int(evidence["destination_block"]["seqno"]) + 1,
            internal_message(BLACK, NANO, False),
            [],
            False,
            False,
            NANO,
        )
        kw["extra_txs"] = {int(evidence["destination_block"]["seqno"]) + 1: credited}
    if damage == "value-flow-v1":
        seqno = int(evidence["destination_block"]["seqno"])
        cell = chainbuild.tx_cell(
            next(t for t in chain.account(BLACK)["txs"] if int(t["transaction_id"]["lt"]) == seqno)
        )
        boc = chainbuild.block(
            2,
            seqno,
            seqno,
            seqno,
            chainbuild.balanced_flow(0),
            {BLACK.split(":")[1]: {seqno: cell}},
            v2=False,
        )
        chain.blocks[seqno] = boc
    else:
        boc = burn_block(chain, evidence, **kw)
    with pytest.raises(ops.OperationRefused, match=message):
        settle_burn(operations, evidence, boc)
    assert operations.journal.record("sweep-bootstrap")["state"] == "broadcast"


@pytest.mark.parametrize("config", [chainbuild.burning_config(num=1, denom=2), None])
def test_the_burn_is_verified_only_under_the_decided_config_param_5(sweep_world, config):
    chain, operations, _ = sweep_world
    _, evidence = swept(operations, chain)
    boc = burn_block(chain, evidence)
    chain.config[5] = config
    with pytest.raises(lib.TestnetError):
        settle_burn(operations, evidence, boc)
    assert operations.journal.record("sweep-bootstrap")["state"] == "broadcast"


def test_a_sweep_before_deletion_settles_through_the_ordinary_head(sweep_world):
    # Until the account is gone the head is read as always; the search is not used.
    chain, operations, _ = sweep_world
    record = None
    with pytest.raises(ops.OperationRefused):
        sweep(operations, chain, sign=sweep_signer(chain, ttl=1))  # expires unexecuted
    record = operations.journal.record("sweep-bootstrap")
    assert not chain.account(BOOT).get("deleted")
    chain.now += 400
    failed = operations.record_failed(record["id"], "c")
    assert failed["state"] == "failed" and failed["evidence"]["form"] == "c"
    # An expired sweep never took effect: the wallet is not retired and may be swept again.
    assert operations.bootstrap_retired(BOOT) is None


def test_an_owner_fund_settles_like_a_funding(world):
    chain, operations, _ = world
    chain.wallet(OWNER, 50 * NANO, public_key="0e" * 32, subwallet=0x504F4F4C)
    record = run(
        operations,
        "owner-fund-a",
        p=params(wallet=OWNER, kind="owner-fund", destination=OTHER),
        sign=signer(chain, wallet=OWNER, destination=OTHER),
    )
    assert record["state"] == "settled"
    assert chain.account(OTHER)["balance"] == 5 * NANO
