"""Mode 130 by real execution of the pinned self-pay Quantum wallet code (codex plan review, change 5).

Each case runs the wallet's own code in the transaction emulator, with a real ML-DSA-44 signature from the pinned
signer and a throwaway key, and then judges the result with the tool's own settle_sweep. Nothing reaches a network.
Run with T1_SWEEP_EMULATOR set to the pinned revision's libemulator.so; without it the module is skipped and says
why (the PR records the run that executed it)."""

import importlib.util
import sys
import time

import pytest
from conftest import SCRIPTS

import t1_sweep_emu as E

pytestmark = pytest.mark.skipif(E.available() is not None, reason=E.available() or "")

spec = importlib.util.spec_from_file_location("t1_sweep_emu_tool", SCRIPTS / "t1-sweep.py")
tool = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tool
spec.loader.exec_module(tool)

BAL = 85 * 10**9


@pytest.fixture(scope="module")
def world():
    m = tool.bench_modules(E.TOS)
    now = int(time.time())
    return m, E.World(m, now), E.Emulator(now)


def sweep(world, balance, mode=tool.SEND_ALL, nonce=0, index=0):
    m, w, emu = world
    out = emu.run(w.account(w.loads[index], balance), w.sweep_external(index, nonce, w.bench.address, mode))
    return out


def credit(world, sender_out):
    """The bench wallet receiving the swept message, executed by its own code; tx is a journal.AccountTx."""
    m, w, emu = world
    p = E.parse(m, sender_out, m.remote.raw(w.loads[0].address))
    msg = p["raw"].out_msgs[0]
    out = emu.run(w.account(w.bench, 10**9), msg)
    assert out["success"], out
    r = E.parse(m, out, m.remote.raw(w.bench.address))
    r["account_tx"] = m.jr.AccountTx(tx=r["tx"], utime=w.now, compute_success=r["tx"].phase_failure is None, raw={})
    return r


def test_mode_130_sends_the_whole_balance_and_the_recipient_is_credited(world):
    m, w, _ = world
    out = sweep(world, BAL)
    assert out["success"], out
    p = E.parse(m, out, m.remote.raw(w.loads[0].address))
    tx = p["tx"]
    assert not tx.aborted and tx.action_success is True and tx.phase_failure is None
    assert len(tx.out_msgs) == 1 and tx.out_msgs[0].destination == m.remote.raw(w.bench.address)
    assert not tx.out_msgs[0].bounced and p["balance_after"] == 0
    # the accounting equation: what is not sent and not in the transaction's fees is the forwarding fee
    fwd = p["raw"].out_msgs[0].info.fwd_fee
    assert BAL - tx.out_msgs[0].value - tx.fee == fwd and 0 < fwd <= tool.FWD_TOLERANCE_NANO
    r = credit(world, out)
    assert r["tx"].in_msg.value == tx.out_msgs[0].value and r["tx"].phase_failure is None
    proof = tool.settle_sweep(tx, m.remote.raw(w.loads[0].address), m.remote.raw(w.bench.address), BAL,
                              [[r["account_tx"]], [r["account_tx"]]], [0, 0])
    assert proof["problems"] == [] and proof["value"] == tx.out_msgs[0].value and len(proof["receipts"]) == 2


def test_mode_128_alone_moves_nothing(world):
    # the wallet requires +2 on every send (wallet-v5-action-list.fc:60-70): 128 alone emits no message, and
    # the sweep check refuses it
    m, w, _ = world
    out = sweep(world, BAL, mode=128)
    p = E.parse(m, out, m.remote.raw(w.loads[0].address))
    assert p["tx"].out_msgs == () and p["balance_after"] > BAL - 10**8
    proof = tool.settle_sweep(p["tx"], m.remote.raw(w.loads[0].address), m.remote.raw(w.bench.address), BAL,
                              [[], []], [p["balance_after"]] * 2)
    assert proof["problems"]


def test_an_action_skipped_for_want_of_funds_is_not_a_sweep(world):
    # enough for the computation, not for the forwarding: +2 skips the send, and the transaction itself succeeds
    m, w, _ = world
    out = sweep(world, 1_800_000)
    p = E.parse(m, out, m.remote.raw(w.loads[0].address))
    assert out["success"] and not p["tx"].aborted and p["tx"].out_msgs == () and p["balance_after"] > 0
    assert p["raw"].description.action.skipped_actions == 1
    proof = tool.settle_sweep(p["tx"], m.remote.raw(w.loads[0].address), m.remote.raw(w.bench.address), 1_800_000,
                              [[], []], [p["balance_after"]] * 2)
    assert any("expected one internal message" in x for x in proof["problems"])


def test_a_wallet_too_poor_to_pay_for_the_computation_refuses_the_external(world):
    out = sweep(world, 500_000)
    assert out["success"] is False


def test_the_sweep_skips_a_wallet_whose_balance_does_not_cover_its_fee_bound(world):
    # the plan's threshold sits above every balance the emulator shows cannot be swept whole
    assert tool.MIN_LEFT_NANO > 2_000_000


def test_a_replayed_sweep_is_not_executed_again(world):
    m, w, emu = world
    first = sweep(world, BAL)
    again = emu.run(first["shard_account"], w.sweep_external(0, 0, w.bench.address, tool.SEND_ALL))
    assert again["success"] is False or E.parse(m, again, m.remote.raw(w.loads[0].address))["tx"].out_msgs == ()


def test_a_sweep_to_the_wrong_destination_fails_the_check(world):
    m, w, _ = world
    out = sweep(world, BAL)
    p = E.parse(m, out, m.remote.raw(w.loads[0].address))
    proof = tool.settle_sweep(p["tx"], m.remote.raw(w.loads[0].address), m.remote.raw(w.loads[1].address), BAL,
                              [[], []], [0, 0])
    assert proof["problems"]


def test_a_recipient_credit_of_another_value_fails_the_check(world):
    m, w, _ = world
    out = sweep(world, BAL)
    p = E.parse(m, out, m.remote.raw(w.loads[0].address))
    r = credit(world, out)["account_tx"]
    bad = r.tx.__class__(**{**r.tx.__dict__, "in_msg": r.tx.in_msg.__class__(**{**r.tx.in_msg.__dict__, "value": 1})})
    wrong = m.jr.AccountTx(tx=bad, utime=r.utime, compute_success=True, raw={})
    proof = tool.settle_sweep(p["tx"], m.remote.raw(w.loads[0].address), m.remote.raw(w.bench.address), BAL,
                              [[wrong], [r]], [0, 0])
    assert any("did not credit" in x for x in proof["problems"])


def test_a_balance_that_does_not_add_up_fails_the_check(world):
    m, w, _ = world
    out = sweep(world, BAL)
    p = E.parse(m, out, m.remote.raw(w.loads[0].address))
    r = credit(world, out)["account_tx"]
    # claim the wallet held 1 TOS more than it did: the difference is not a forwarding fee
    proof = tool.settle_sweep(p["tx"], m.remote.raw(w.loads[0].address), m.remote.raw(w.bench.address),
                              BAL + 10**9, [[r], [r]], [0, 0])
    assert any("not a forwarding fee" in x for x in proof["problems"])


def test_an_aged_wallet_with_real_storage_is_swept_exactly(world):
    # codex code review r1: the storage used of a live T1 load wallet (43 cells, 23,350 bits) and three days of
    # unpaid storage; the storage fee joins the transaction's total fees and the equation still holds exactly
    m, w, emu = world
    out = emu.run(w.account(w.loads[0], BAL, cells=43, bits=23_350, age=3 * 86_400),
                  w.sweep_external(0, 0, w.bench.address, tool.SEND_ALL))
    assert out["success"], out
    p = E.parse(m, out, m.remote.raw(w.loads[0].address))
    tx = p["tx"]
    fresh = E.parse(m, sweep(world, BAL), m.remote.raw(w.loads[0].address))["tx"]
    assert tx.fee > fresh.fee, "three days of storage must cost something"
    fwd = p["raw"].out_msgs[0].info.fwd_fee
    assert BAL - tx.out_msgs[0].value - tx.fee == fwd and p["balance_after"] == 0
    r = credit(world, out)["account_tx"]
    proof = tool.settle_sweep(tx, m.remote.raw(w.loads[0].address), m.remote.raw(w.bench.address), BAL,
                              [[r], [r]], [0, 0])
    assert proof["problems"] == []
