"""t1-sweep orchestration against a fake chain: refusals, ordering, no resend, stop on the first inexact sweep, and
the ramp's lock. The wallets, seeds and signatures are real (throwaway key, pinned code and signer); only the chain
is faked. Skipped without the pinned tos checkout and signer (see t1_sweep_emu.available)."""

import base64
import importlib.util
import json
import sys
import time
from types import SimpleNamespace

import pytest
from conftest import SCRIPTS

import t1_sweep_emu as E

_why = None if (E.SIGNER.is_file() and (E.TOS / "build/crypto/func").exists()) else "no pinned tos checkout or signer"
pytestmark = pytest.mark.skipif(_why is not None, reason=_why or "")

spec = importlib.util.spec_from_file_location("t1_sweep_tool", SCRIPTS / "t1-sweep.py")
tool = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tool
spec.loader.exec_module(tool)

ZERO = {"workchain": -1, "shard": -9223372036854775808, "seqno": 0,
        "root_hash": "/2BFnLilFwhUgpCvoW/U34DRZ3W/PBM5IUam0bVmLVc=",
        "file_hash": "OzdN9evRg2jUvw6zdHBHcdr42s2FF1YF87/Rx6kioDk="}
BAL = 85 * 10**9
FEE, FWD = 1_776_456, 44_446
BOUND = 2_000_000


@pytest.fixture(scope="module")
def env():
    m = tool.bench_modules(E.TOS)
    w = E.World(m, int(time.time()))
    return m, w


def b64(cell):
    return base64.b64encode(cell.to_boc()).decode()


class FakeChain:
    def __init__(self, m, w, balances, *, init=None, global_id=2, disagree=None, send_error=None,
                 verdict="executed", recipient=True, dest_state="active", after=None):
        self.m, self.w = m, w
        self.bal = {m.remote.raw(x.address): b for x, b in zip(w.loads, balances)}
        self.init, self.global_id = init or ZERO, global_id
        self.disagree, self.send_error, self.verdict, self.recipient = disagree, send_error, verdict, recipient
        self.dest_state, self.after = dest_state, after
        self.sent, self.journal_at_send, self.journal = [], [], None
        self.out = {}

    async def network(self):
        return [{"init": dict(self.init), "global_id": self.global_id}] * 2

    async def account(self, address):
        if address == self.m.remote.raw(self.w.bench.address):
            return [{"state": self.dest_state, "balance": "1000000000"}] * 2
        i = next(k for k, x in enumerate(self.w.loads) if self.m.remote.raw(x.address) == address)
        wl = self.w.loads[i]
        ans = {"state": "active", "balance": str(self.bal[address]), "code": b64(wl.state_init.code),
               "data": b64(wl.state_init.data)}
        other = dict(ans, balance=str(self.bal[address] + 1)) if self.disagree == i else ans
        return [ans, other]

    async def now(self):
        return 1_800_000_000

    async def fee_config(self):
        return SimpleNamespace()

    async def send(self, external):
        self.journal_at_send.append(self.journal.read_text() if self.journal else "")
        self.sent.append(external)
        if self.send_error:
            raise self.send_error

    async def confirm(self, record):
        jr, t2 = self.m.jr, self.m.t2check
        if self.verdict != "executed":
            return jr.Verdict(self.verdict, "fake", None)
        sender, dest = record["sender"], record["actions"][0]["destination"]
        value = self.bal[sender] - FEE - FWD
        msg = t2.Msg(hash=f"{len(self.sent):064x}", kind="internal", source=sender, destination=dest, value=value)
        tx = t2.Tx(hash="a" * 64, account=sender, lt=5, block=(0, -(1 << 63), 9), in_msg=t2.Msg(
            hash=record["external"], kind="external", destination=sender), out_msgs=(msg,), action_success=True,
            fee=FEE, phase_failure=None)
        found = jr.AccountTx(tx=tx, utime=1_800_000_001, compute_success=True, raw={})
        self.out[sender] = (msg, self.bal[sender])
        self.bal[sender] = 0 if self.after is None else self.after
        return jr.Verdict("executed", None, found, jr.emission_problems(found, record), 0, 1_800_000_002)

    async def history(self, address, since):
        if not self.recipient:
            return [[], []]
        t2 = self.m.t2check
        txs = [t2.Tx(hash=f"b{k:063x}", account=address, lt=6 + k, block=(0, -(1 << 63), 10), in_msg=t2.Msg(
            hash=msg.hash, kind="internal", source=msg.source, destination=address, value=msg.value),
            action_success=None, fee=1000, phase_failure=None) for k, (msg, _) in enumerate(self.out.values())]
        return [txs, txs]


def run(env, chain, tmp_path, go=True, monkeypatch=None):
    m, w = env
    monkeypatch.setattr(m.remote, "external_fee_bound", lambda *a: SimpleNamespace(total=BOUND))
    out = tmp_path / "out"
    out.mkdir()
    journal = m.jr.Journal(out / "journal.jsonl")
    journal.append({"type": "run", "version": 1, "tool": "t1-sweep", "wallet": "x", "time": 0})
    chain.journal = out / "journal.jsonl"
    logs = []
    a = SimpleNamespace(go=go, out=out)
    dest = m.remote.raw(w.bench.address)
    rc = __import__("asyncio").run(tool.run(a, m, chain, None, journal, w.signer, w.bench, w.loads, w.seeds,
                                             w.loads[0].state_init.code.hash.hex(), dest, ZERO, log=logs.append))
    rows = [json.loads(x) for x in (out / "journal.jsonl").read_text().splitlines()]
    return rc, rows, logs, out


def test_a_dry_run_signs_and_sends_nothing(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL])
    rc, rows, logs, _ = run(env, chain, tmp_path, go=False, monkeypatch=monkeypatch)
    assert rc == 0 and chain.sent == [] and [r["type"] for r in rows] == ["run"]
    assert any("dry run" in x for x in logs) and any("2 of 2 wallets" in x for x in logs)


def test_both_wallets_are_swept_and_proved(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL])
    rc, rows, logs, out = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    assert rc == 0 and len(chain.sent) == 2
    types = [r["type"] for r in rows]
    assert types == ["run", "attempt", "sent", "observed", "delivered", "attempt", "sent", "observed", "delivered"]
    att = [r for r in rows if r["type"] == "attempt"]
    assert all(a["role"] == "sweep" and a["actions"] == [{"destination": m.remote.raw(w.bench.address),
                                                          "value": 0, "mode": 130}] for a in att)
    assert json.loads((out / "RESULT.json").read_text())["status"] == "done"


def test_each_attempt_is_journaled_before_its_send(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL])
    run(env, chain, tmp_path, monkeypatch=monkeypatch)
    for k, text in enumerate(chain.journal_at_send):
        attempts = [json.loads(x) for x in text.splitlines() if '"type":"attempt"' in x]
        assert len(attempts) == k + 1, "the attempt was not on disk when its external was sent"


def test_an_ambiguous_send_is_never_resent_and_stops_the_run(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL], send_error=TimeoutError("no answer"), verdict="undetermined")
    rc, rows, logs, out = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    assert rc == 1 and len(chain.sent) == 1
    assert [r["type"] for r in rows] == ["run", "attempt", "sent", "unknown"]
    assert json.loads((out / "RESULT.json").read_text())["status"] == "stopped"


def test_a_refused_send_stops_the_run(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL], send_error=m.rpc.RpcError("sendBoc", 200, {"code": -32602}))
    rc, rows, _, _ = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    assert rc == 1 and len(chain.sent) == 1 and rows[-1]["type"] == "sent" and rows[-1]["state"] == "refused"


def test_a_missing_recipient_transaction_stops_before_the_next_wallet(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL], recipient=False)
    rc, rows, logs, _ = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    assert rc == 1 and len(chain.sent) == 1 and "delivered" not in [r["type"] for r in rows]
    assert any("destination transactions import" in x for x in logs)


def test_a_wallet_not_emptied_stops_the_run(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL], after=5)
    rc, _, logs, _ = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    assert rc == 1 and any("still holds" in x for x in logs)


def test_a_wallet_below_its_fee_bound_is_skipped(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BOUND + 1000, BAL])
    rc, rows, logs, _ = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    assert rc == 0 and len(chain.sent) == 1
    assert [r["wallet"] for r in rows if r["type"] == "attempt"] == [1]


@pytest.mark.parametrize("over,match", [
    ({"init": dict(ZERO, root_hash="A" * 43 + "=")}, "epoch-6"),
    ({"global_id": 3}, "epoch-6"),
    ({"disagree": 0}, "disagree"),
    ({"dest_state": "uninit"}, "not active"),
])
def test_refusals_sign_nothing(env, tmp_path, monkeypatch, over, match):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL], **over)
    with pytest.raises(tool.Refuse, match=match):
        run(env, chain, tmp_path, monkeypatch=monkeypatch)
    assert chain.sent == []


def test_a_destination_among_the_sources_is_refused(env, tmp_path, monkeypatch):
    m, w = env
    monkeypatch.setattr(m.remote, "external_fee_bound", lambda *a: SimpleNamespace(total=BOUND))
    chain = FakeChain(m, w, [BAL, BAL])
    a = SimpleNamespace(go=True, out=tmp_path)
    with pytest.raises(tool.Refuse, match="one of the swept wallets"):
        __import__("asyncio").run(tool.run(a, m, chain, None, None, w.signer, w.bench, w.loads, w.seeds, "x",
                                           m.remote.raw(w.loads[1].address), ZERO, log=lambda *_: None))
    assert chain.sent == []


@pytest.mark.parametrize("field,value,match", [
    ("retired", 2, "unretired"), ("epoch", 1, "epoch 0"), ("version", 2, "version 1")])
def test_a_wallet_state_that_is_not_the_derived_wallet_is_refused(env, field, value, match):
    m, w = env
    wl = w.loads[0]
    q = tool.parse_qsp(b64(wl.state_init.data), m.core.Cell)
    q[field] = value
    data = (m.core.Builder().store_uint(q["version"], 8).store_uint(q["seqno"], 32).store_uint(q["wallet_id"], 32)
            .store_uint(q["retired"], 16).store_uint(q["epoch"], 64).store_uint(q["primary_nonce"], 64)
            .store_uint(q["rescue_nonce"], 64).store_ref(wl.authority).end_cell())
    ans = {"state": "active", "balance": "1", "code": b64(wl.state_init.code), "data": b64(data)}
    with pytest.raises(tool.Refuse, match=match):
        tool.check_wallet_state(ans, wl, wl.state_init.code.hash.hex(), m.core.Cell)


def test_another_authority_or_code_is_refused(env):
    m, w = env
    a, b = w.loads
    ans = {"state": "active", "balance": "1", "code": b64(b.state_init.code), "data": b64(b.state_init.data)}
    with pytest.raises(tool.Refuse, match="authority"):
        tool.check_wallet_state(ans, a, a.state_init.code.hash.hex(), m.core.Cell)
    with pytest.raises(tool.Refuse, match="code hash"):
        tool.check_wallet_state(ans, a, "0" * 64, m.core.Cell)


def test_the_ramp_lock_is_exclusive_and_the_sweep_journal_is_registered(env, tmp_path):
    m, w = env
    state = m.jr.WalletState(tmp_path / "state", "0:" + "ab" * 32)
    with pytest.raises(m.jr.WalletLocked):
        m.jr.WalletState(tmp_path / "state", "0:" + "ab" * 32)
    j = tmp_path / "sweep" / "journal.jsonl"
    state.register(j)
    assert state.journals() == [j]
    state.release()
    m.jr.WalletState(tmp_path / "state", "0:" + "ab" * 32).release()


# ---------------------------------------------------------------- settle_sweep on synthetic summaries


def _pair(m, sender, dest, *, bounced=False, phase=None, account=None, aborted=False):
    t2 = m.t2check
    msg = t2.Msg(hash="c" * 64, kind="internal", source=sender, destination=dest, bounced=bounced,
                 value=BAL - FEE - FWD)
    tx = t2.Tx(hash="d" * 64, account=sender, lt=5, block=(0, 0, 1), in_msg=None, out_msgs=(msg,),
               action_success=True, fee=FEE, phase_failure=None)
    r = t2.Tx(hash="e" * 64, account=account or dest, lt=6, block=(0, 0, 2), aborted=aborted,
              in_msg=t2.Msg(hash=msg.hash, kind="internal", source=sender, destination=dest, value=msg.value,
                            bounced=bounced), action_success=None, fee=1, phase_failure=phase)
    return tx, r


def test_a_clean_synthetic_sweep_settles(env):
    m, w = env
    s_, d_ = "0:" + "1" * 64, "0:" + "2" * 64
    tx, r = _pair(m, s_, d_)
    assert tool.settle_sweep(tx, s_, d_, BAL, [[r], [r]], [0, 0])["problems"] == []


@pytest.mark.parametrize("over,match", [
    ({"bounced": True}, "bounced"),
    ({"phase": "compute phase did not succeed"}, "did not credit"),
    ({"aborted": True}, "did not credit"),
    ({"account": "0:" + "3" * 64}, "did not credit"),
])
def test_a_recipient_side_that_is_not_a_clean_credit_fails(env, over, match):
    m, w = env
    s_, d_ = "0:" + "1" * 64, "0:" + "2" * 64
    tx, r = _pair(m, s_, d_, **over)
    problems = tool.settle_sweep(tx, s_, d_, BAL, [[r], [r]], [0, 0])["problems"]
    assert any(match in x for x in problems), problems


def test_the_recipient_must_be_proved_on_both_rpcs(env):
    m, w = env
    s_, d_ = "0:" + "1" * 64, "0:" + "2" * 64
    tx, r = _pair(m, s_, d_)
    problems = tool.settle_sweep(tx, s_, d_, BAL, [[r], []], [0, 0])["problems"]
    assert problems == ["rpc 1: 0 destination transactions import the swept message"]


def test_a_sweep_without_fees_reported_fails(env):
    m, w = env
    s_, d_ = "0:" + "1" * 64, "0:" + "2" * 64
    tx, r = _pair(m, s_, d_)
    tx = tx.__class__(**{**tx.__dict__, "fee": None})
    assert any("no total fees" in x for x in tool.settle_sweep(tx, s_, d_, BAL, [[r], [r]], [0, 0])["problems"])


def test_a_message_to_another_account_fails_even_when_the_destination_shows_a_credit(env):
    # only the emitted message's own destination can catch this: the recipient side looks clean
    m, w = env
    s_, d_, other = "0:" + "1" * 64, "0:" + "2" * 64, "0:" + "4" * 64
    tx, r = _pair(m, s_, other)
    r = r.__class__(**{**r.__dict__, "account": d_})
    problems = tool.settle_sweep(tx, s_, d_, BAL, [[r], [r]], [0, 0])["problems"]
    assert any("expected one internal message" in x for x in problems), problems


def test_two_messages_are_not_one_sweep(env):
    m, w = env
    s_, d_ = "0:" + "1" * 64, "0:" + "2" * 64
    tx, r = _pair(m, s_, d_)
    extra = tx.out_msgs[0].__class__(**{**tx.out_msgs[0].__dict__, "hash": "f" * 64, "value": 1})
    tx = tx.__class__(**{**tx.__dict__, "out_msgs": tx.out_msgs + (extra,)})
    problems = tool.settle_sweep(tx, s_, d_, BAL, [[r], [r]], [0, 0])["problems"]
    assert any("expected one internal message" in x for x in problems), problems
