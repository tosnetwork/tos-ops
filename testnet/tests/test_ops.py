"""Tests for testnet_ops: the journal, the gate, settlement, and the manual paths,
on the asynchronous fake chain (fakechain.py) and on real node answers and
messages captured from the d7ef85b4c rehearsal (data/ops-*.json)."""

import base64
import json
import os

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
):
    calls = []

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


def test_an_unexplained_transaction_after_the_baseline_refuses(world):
    chain, operations, _ = world
    operations.set_baseline(BOOT, "x") if chain.account(BOOT)["txs"] else None
    run(operations, chain=chain)
    chain.send(build_external(BOOT, 2, 2, chain.now + 300, internal_message(OTHER, NANO, False)))
    chain.settle_all()
    with pytest.raises(ops.OperationRefused, match="explains"):
        run(operations, "fund-b", chain=chain)


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


def withdraw(operations, chain, op_id="withdraw-1", nanotos=5 * NANO, salt=b""):
    body = withdraw_body(nanotos)
    p = params(NANO, POOL, OWNER, kind="withdraw", bounce=True, body_hash=body.hash().hex())
    return operations.run(
        op_id, p, signer(chain, OWNER, POOL, NANO, True, body, salt=salt), lambda d: None
    )


def test_a_withdrawal_settles_when_the_owner_retained_the_payment(world):
    chain, operations = withdraw_world(world)
    record = withdraw(operations, chain)
    assert record["state"] == "settled"
    assert record["evidence"]["paid_nanotos"] >= 5 * NANO
    assert record["evidence"]["owner_tx"]


def test_a_payment_that_bounces_at_the_owner_is_not_settled(world):
    chain, operations = withdraw_world(world, owner_bounces=True)
    with pytest.raises(ops.OperationRefused, match="not settled"):
        withdraw(operations, chain)
    outcome, evidence = operations.settle(operations.journal.record("withdraw-1"))
    assert outcome == "pending" and evidence["reason"] == "payment emitted, not retained"


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
        with pytest.raises(ops.OperationRefused, match="holds the lock"):
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
    with pytest.raises(ops.Unknown):
        ops.normalize({"in_msg": {"hash": 5}}, "aa", 1)
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


def test_real_history_pages_normalize_and_credits_decode():
    credits = 0
    for wallet, answer in ANSWERS.items():
        for tx in answer["page"]["transactions"]:
            tid = tx["transaction_id"]
            n = ops.normalize(tx, ops.b64hash(tid["hash"]).hex(), int(tid["lt"]))
            if n["in_kind"] == "internal":
                assert ops.credit_of(base64.b64decode(n["data"])) == n["in_value"]
                credits += 1
    assert credits >= 5


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


def test_a_receipt_crediting_another_amount_is_not_retained(world, monkeypatch):
    chain, operations = withdraw_world(world)
    monkeypatch.setattr(ops, "credit_of", lambda data: 1)
    with pytest.raises(ops.OperationRefused, match="not settled"):
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
    with pytest.raises(ops.OperationRefused, match="not settled"):
        withdraw(operations, chain)
