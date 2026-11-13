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
                 verdict="executed", recipient=True, dest_state="active", after=None, lag=0):
        self.m, self.w = m, w
        self.bal = {m.remote.raw(x.address): b for x, b in zip(w.loads, balances)}
        self.init, self.global_id = init or ZERO, global_id
        self.disagree, self.send_error, self.verdict, self.recipient = disagree, send_error, verdict, recipient
        self.dest_state, self.after = dest_state, after
        self.sent, self.journal_at_send, self.journal = [], [], None
        self.out = {}
        # the second RPC lags: until `lag` pauses have passed it shows the balance before the sweep and no receipt
        self.lag, self.pauses = lag, 0
        self.t = 0.0  # the fake monotonic clock: pauses advance it

    def clock(self):
        return self.t

    def lagging(self):
        return self.pauses < self.lag

    async def pause(self, seconds):
        assert seconds == tool.POLL
        self.pauses += 1
        self.t += seconds

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
        if self.lagging() and address in self.out:
            other = dict(ans, balance=str(self.out[address][1]))
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
        txs = [self.m.jr.AccountTx(tx=t2.Tx(hash=f"b{k:063x}", account=address, lt=6 + k, block=(0, -(1 << 63), 10),
                                            in_msg=t2.Msg(hash=msg.hash, kind="internal", source=msg.source,
                                                          destination=address, value=msg.value),
                                            action_success=None, fee=1000, phase_failure=None),
                                   utime=1_800_000_003 + k, compute_success=True, raw={})
               for k, (msg, _) in enumerate(self.out.values())]
        return [txs, [] if self.lagging() else txs]


def run(env, chain, tmp_path, go=True, monkeypatch=None, state=None):
    m, w = env
    own = state is None
    state = state or m.jr.WalletState(tmp_path / "state-run", "0:" + "ef" * 32)
    monkeypatch.setattr(m.remote, "external_fee_bound", lambda *a: SimpleNamespace(total=BOUND))
    out = tmp_path / "out"
    out.mkdir(parents=True)
    journal = m.jr.Journal(out / "journal.jsonl")
    journal.append(tool.run_record(m, w.bench, w.loads, m.remote.raw(w.bench.address), 123))
    chain.journal = out / "journal.jsonl"
    logs = []
    a = SimpleNamespace(go=go, out=out)
    dest = m.remote.raw(w.bench.address)
    try:
        rc = __import__("asyncio").run(tool.run(a, m, chain, state, journal, w.signer, w.bench, w.loads, w.seeds,
                                                 w.loads[0].state_init.code.hash.hex(), dest, ZERO, log=logs.append))
    finally:
        if own:
            state.release()
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
    state = m.jr.WalletState(tmp_path / "state-x", "0:" + "ef" * 32)
    try:
        with pytest.raises(tool.Refuse, match="one of the swept wallets"):
            __import__("asyncio").run(tool.run(a, m, chain, state, None, w.signer, w.bench, w.loads, w.seeds, "x",
                                               m.remote.raw(w.loads[1].address), ZERO, log=lambda *_: None))
    finally:
        state.release()
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
    return tx, m.jr.AccountTx(tx=r, utime=1_800_000_009, compute_success=phase is None, raw={})


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
    r = r.__class__(tx=r.tx.__class__(**{**r.tx.__dict__, "account": d_}), utime=r.utime,
                    compute_success=True, raw={})
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



# ---------------------------------------------------------------- the registry and recovery (codex code review r1)


def test_a_completed_sweep_journal_reads_cleanly_for_the_ramps_reconcile(env, tmp_path, monkeypatch):
    # an unsupported run record would block every later ramp or sweep run (finding 1)
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL])
    rc, _, _, out = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    read = m.jr.read_journal(out / "journal.jsonl")
    assert rc == 0 and read.errors == [] and read.run["tool"] == "t1-sweep"
    assert all(read.settled(aid) for aid in read.attempts)


def _registry(m, tmp_path, journal):
    state = m.jr.WalletState(tmp_path / "state", "0:" + "cd" * 32)
    state.register(journal)
    return state


def _interrupted(env, tmp_path, monkeypatch, recipient):
    """A first run that stops after the sender transaction was observed and before a receipt was journaled."""
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL], recipient=recipient)
    rc, rows, _, out = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    return m, w, chain, rc, rows, out


def test_a_sweep_interrupted_after_its_sender_was_observed_is_proved_before_anything_else(env, tmp_path, monkeypatch):
    m, w, chain, rc, rows, out = _interrupted(env, tmp_path, monkeypatch, recipient=False)
    assert rc == 1 and "observed" in [r["type"] for r in rows] and "delivered" not in [r["type"] for r in rows]
    state = _registry(m, tmp_path, out / "journal.jsonl")
    try:
        chain.recipient = True  # the receipt is now visible
        pending = __import__("asyncio").run(tool.recover_receipts(m, chain, state))
    finally:
        state.release()
    assert pending == []
    late = [r for r in m.jr.read_journal(out / "journal.jsonl").events.values() for r in r
            if r["type"] == "delivered"]
    assert len(late) == 1 and late[0]["proved_later"] is True and late[0]["recipient_utime"] > 0


def test_a_sweep_whose_receipt_cannot_be_proved_blocks_every_later_run(env, tmp_path, monkeypatch):
    # finding 2: the registry's reconcile alone calls this journal clean; the sweep's own recovery must not
    m, w, chain, rc, rows, out = _interrupted(env, tmp_path, monkeypatch, recipient=False)
    state = _registry(m, tmp_path, out / "journal.jsonl")
    try:
        pending = __import__("asyncio").run(tool.recover_receipts(m, chain, state))
    finally:
        state.release()
    assert len(pending) == 1 and "destination transactions import" in pending[0]
    assert "delivered" not in [r["type"] for r in [__import__("json").loads(x) for x in
                                                    (out / "journal.jsonl").read_text().splitlines()]]


def test_recovery_ignores_ramp_journals_and_proved_sweeps(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL])
    _, _, _, out = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    ramp = tmp_path / "ramp.jsonl"
    j = m.jr.Journal(ramp)
    j.append({"type": "run", "version": 1, "tool": "t4-ramp", "wallet": "x", "mc_start": 1, "time": 0})
    j.close()
    before = (out / "journal.jsonl").read_text()
    state = _registry(m, tmp_path, out / "journal.jsonl")
    state.register(ramp)
    try:
        assert __import__("asyncio").run(tool.recover_receipts(m, chain, state)) == []
    finally:
        state.release()
    assert (out / "journal.jsonl").read_text() == before, "a proved sweep was proved again"


def test_the_delivered_record_carries_real_coordinates_or_null(env, tmp_path, monkeypatch):
    # finding 3: no made-up zero coordinates
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL])
    _, rows, _, _ = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    for d in (r for r in rows if r["type"] == "delivered"):
        assert d["recipient_mc"] is None and d["recipient_utime"] >= 1_800_000_003
        assert d["recipient_block"] == [0, -(1 << 63), 10] and d["rpcs_proved"] == 2



def test_a_later_run_refuses_while_an_earlier_receipt_is_unproved(env, tmp_path, monkeypatch):
    # the whole point of finding 2: a second run must not plan, sign or report done
    m, w, chain, rc, rows, out = _interrupted(env, tmp_path, monkeypatch, recipient=False)
    state = _registry(m, tmp_path, out / "journal.jsonl")
    sent_before = len(chain.sent)
    try:
        with pytest.raises(tool.Refuse, match="no proven receipt"):
            run(env, chain, tmp_path / "second", monkeypatch=monkeypatch, state=state)
    finally:
        state.release()
    assert len(chain.sent) == sent_before


def test_a_sweep_observed_with_problems_is_never_counted(env, tmp_path, monkeypatch):
    m, w, chain, rc, rows, out = _interrupted(env, tmp_path, monkeypatch, recipient=False)
    lines = (out / "journal.jsonl").read_text().splitlines()
    rewritten = []
    for x in lines:
        r = __import__("json").loads(x)
        if r["type"] == "observed":
            r["problems"] = ["action phase did not succeed"]
        rewritten.append(__import__("json").dumps(r, sort_keys=True, separators=(",", ":")))
    (out / "journal.jsonl").write_text("\n".join(rewritten) + "\n")
    chain.recipient = True
    state = _registry(m, tmp_path, out / "journal.jsonl")
    try:
        pending = __import__("asyncio").run(tool.recover_receipts(m, chain, state))
    finally:
        state.release()
    assert len(pending) == 1 and "executed with problems" in pending[0]


def _without_observed(m, out):
    """The journal as a crash right after the send leaves it, and the registry resolution the reconcile writes
    for that execution (its Verdict.as_dict, as WalletState.reconcile records it)."""
    path = out / "journal.jsonl"
    rows = [json.loads(x) for x in path.read_text().splitlines()]
    obs = next(r for r in rows if r["type"] == "observed")
    kept = [r for r in rows if r["type"] not in ("observed", "delivered", "end")]
    path.write_text("".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in kept))
    verdict = {k: v for k, v in obs.items() if k not in ("type", "id", "time")}
    return obs["id"], verdict


def _resolve(m, state, journal, aid, verdict):
    w = m.jr.Journal(state.dir / "resolved", create=False, types=m.jr.STATE_TYPES)
    try:
        w.append({"type": "resolved", "time": 0, "journal": str(journal), "id": aid, "external": "x",
                  "journaled": "accepted", **verdict})
    finally:
        w.close()


def _recover(m, chain, state):
    return __import__("asyncio").run(tool.recover_receipts(m, chain, state))


def test_an_execution_found_only_by_the_registry_reconcile_still_needs_its_receipt(env, tmp_path, monkeypatch):
    # codex r2 finding 1: a crash before `observed`; the reconcile records the execution only in its resolutions
    m, w, chain, rc, rows, out = _interrupted(env, tmp_path, monkeypatch, recipient=False)
    aid, verdict = _without_observed(m, out)
    assert verdict["verdict"] == "executed"
    state = _registry(m, tmp_path, out / "journal.jsonl")
    try:
        _resolve(m, state, out / "journal.jsonl", aid, verdict)
        pending = _recover(m, chain, state)
        assert len(pending) == 1 and "destination transactions import" in pending[0]
        chain.recipient = True
        assert _recover(m, chain, state) == []
    finally:
        state.release()
    late = [e for e in m.jr.read_journal(out / "journal.jsonl").events[aid] if e["type"] == "delivered"]
    assert len(late) == 1 and late[0]["proved_later"] is True


def test_a_sweep_with_no_observation_and_no_resolution_is_never_assumed_unexecuted(env, tmp_path, monkeypatch):
    m, w, chain, rc, rows, out = _interrupted(env, tmp_path, monkeypatch, recipient=True)
    aid, verdict = _without_observed(m, out)
    state = _registry(m, tmp_path, out / "journal.jsonl")
    try:
        pending = _recover(m, chain, state)
        # both wallets were swept; neither observation survives the crash
        assert len(pending) == 2 and all("not determined" in p for p in pending)
        _resolve(m, state, out / "journal.jsonl", aid, {"verdict": "undetermined", "reason": "x", "chain_now": 1})
        assert "not determined" in _recover(m, chain, state)[0]
    finally:
        state.release()


def test_a_sweep_the_chain_proved_unexecuted_needs_no_receipt(env, tmp_path, monkeypatch):
    m, w, chain, rc, rows, out = _interrupted(env, tmp_path, monkeypatch, recipient=False)
    aid, verdict = _without_observed(m, out)
    state = _registry(m, tmp_path, out / "journal.jsonl")
    try:
        _resolve(m, state, out / "journal.jsonl", aid, {"verdict": "not_executed", "reason": None, "chain_now": 1})
        assert _recover(m, chain, state) == []
    finally:
        state.release()


@pytest.mark.parametrize("where", ["journal", "registry"])
def test_a_sweep_executed_twice_is_never_counted(env, tmp_path, monkeypatch, where):
    # codex r2 finding 2: remote.settle refuses duplicates; recovery must too, whatever recorded the execution
    m, w, chain, rc, rows, out = _interrupted(env, tmp_path, monkeypatch, recipient=False)
    chain.recipient = True
    path = out / "journal.jsonl"
    state = _registry(m, tmp_path, path)
    try:
        if where == "journal":
            lines = [json.loads(x) for x in path.read_text().splitlines()]
            for r in lines:
                if r["type"] == "observed":
                    r["problems"], r["duplicates"] = [], 1
            path.write_text("".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in lines))
        else:
            aid, verdict = _without_observed(m, out)
            _resolve(m, state, path, aid, {**verdict, "problems": [], "duplicates": 1})
        pending = _recover(m, chain, state)
    finally:
        state.release()
    assert len(pending) == 1 and "duplicates 1" in pending[0]
    assert "delivered" not in [json.loads(x)["type"] for x in path.read_text().splitlines()]


def test_only_the_bench_wallet_is_a_destination(env, tmp_path, monkeypatch):
    # coordinator review: no operator-chosen destination; an active wc0 account that is not the bench is refused
    m, w = env
    monkeypatch.setattr(m.remote, "external_fee_bound", lambda *a: SimpleNamespace(total=BOUND))
    chain = FakeChain(m, w, [BAL, BAL])
    a = SimpleNamespace(go=True, out=tmp_path)
    state = m.jr.WalletState(tmp_path / "state-x", "0:" + "ef" * 32)
    try:
        with pytest.raises(tool.Refuse, match="not the bench wallet"):
            __import__("asyncio").run(tool.run(a, m, chain, state, None, w.signer, w.bench, w.loads, w.seeds, "x",
                                               "0:" + "77" * 32, ZERO, log=lambda *_: None))
    finally:
        state.release()
    assert chain.sent == []


def test_the_cli_has_no_destination_option(tmp_path, capsys):
    with pytest.raises(SystemExit):
        tool.main(["--key-file", str(tmp_path / "k"), "--out", str(tmp_path / "o"), "--to", "0:" + "77" * 32])
    assert "unrecognized arguments: --to" in capsys.readouterr().err


def test_a_lagging_rpc_is_read_again_until_it_shows_the_sweep(env, tmp_path, monkeypatch):
    # coordinator review: the RPC that confirmed the sender is ahead; the others are read again, not judged at once
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL], lag=3)
    rc, rows, logs, _ = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    assert rc == 0 and chain.pauses == 3
    assert [r["type"] for r in rows].count("delivered") == 2


def test_an_rpc_that_never_shows_the_sweep_stops_the_run_after_the_wait(env, tmp_path, monkeypatch):
    m, w = env
    chain = FakeChain(m, w, [BAL, BAL], lag=10**9)
    rc, rows, logs, _ = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    assert rc == 1 and len(chain.sent) == 1
    assert chain.pauses == int(tool.PROOF_WAIT // tool.POLL) - 1
    assert "delivered" not in [r["type"] for r in rows]


def test_recovery_reads_a_lagging_rpc_again(env, tmp_path, monkeypatch):
    m, w, chain, rc, rows, out = _interrupted(env, tmp_path, monkeypatch, recipient=False)
    chain.recipient, chain.lag, chain.pauses = True, 2, 0
    state = _registry(m, tmp_path, out / "journal.jsonl")
    try:
        assert _recover(m, chain, state) == []
    finally:
        state.release()
    assert chain.pauses == 2


class SlowChain(FakeChain):
    """After the first send, every account read takes `slow` real seconds; its clock is the real one."""

    def __init__(self, *a, slow, **k):
        super().__init__(*a, **k)
        self.slow = slow

    def clock(self):
        return time.monotonic()

    async def account(self, address):
        if self.sent:
            await __import__("asyncio").sleep(self.slow)
        return await super().account(address)


def test_proof_wait_bounds_the_elapsed_time_reads_included(env, tmp_path, monkeypatch):
    # codex r4: PROOF_WAIT counted rounds, not time; a slow RPC held the wallet lock far past it
    m, w = env
    monkeypatch.setattr(tool, "PROOF_WAIT", 0.3)
    chain = SlowChain(m, w, [BAL, BAL], slow=5.0)
    t0 = time.monotonic()
    rc, rows, logs, _ = run(env, chain, tmp_path, monkeypatch=monkeypatch)
    took = time.monotonic() - t0
    assert rc == 1 and len(chain.sent) == 1 and took < 2.0, took
    assert any("no complete read" in x for x in logs if x.startswith("STOP"))
    assert "delivered" not in [r["type"] for r in rows]


class _SlowRpc(__import__("http.server").server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        time.sleep(3)
        try:
            body = json.dumps({"ok": True, "result": {}}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *a):
        pass


def test_a_live_read_cancelled_at_the_deadline_does_not_hold_the_wallet_lock(env, tmp_path, monkeypatch):
    # codex r5: the pinned transport reads in asyncio.to_thread; asyncio.run joins that thread before it returns,
    # so the lock was held for the whole slow read. A real HTTP RPC that answers after 3 s, a real LiveChain.
    import http.server
    import threading
    m, w = env
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SlowRpc)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        monkeypatch.setattr(tool, "PROOF_WAIT", 0.3)
        chain = tool.LiveChain(m, [url, url])
        state = m.jr.WalletState(tmp_path / "state-live", "0:" + "ef" * 32)
        t0 = time.monotonic()
        try:
            proof = __import__("asyncio").run(tool.prove_sweep(chain, None, "0:" + "11" * 32, "0:" + "22" * 32,
                                                               BAL, 0))
        finally:
            state.release()
        again = m.jr.WalletState(tmp_path / "state-live", "0:" + "ef" * 32)  # the lock is free again
        again.release()
        took = time.monotonic() - t0
    finally:
        server.shutdown()
    assert "no complete read" in proof["problems"][0]
    assert took < 1.5, f"asyncio.run held the wallet lock {took:.1f} s for a cancelled read"


def _transport(monkeypatch, urlopen):
    monkeypatch.setattr(tool.urllib.request, "urlopen", urlopen)
    aio = __import__("asyncio")
    return aio.run(aio.wait_for(tool.daemon_transport("http://127.0.0.1:9/", b"{}", 1.0), 5))


def _http_error(body_error=None):
    import io
    import urllib.error

    class Err(urllib.error.HTTPError):
        def read(self, *a):
            if body_error is not None:
                raise body_error
            return b"busy"

    return Err("http://127.0.0.1:9/", 503, "unavailable", {}, io.BytesIO(b""))


def test_the_daemon_transport_returns_an_http_error_as_its_status(monkeypatch):
    def urlopen(*a, **k):
        raise _http_error()
    assert _transport(monkeypatch, urlopen) == (503, b"busy")


def test_a_failure_reading_an_error_body_reaches_the_caller(monkeypatch):
    # codex r6: an exception inside the HTTPError handler skipped delivery; the caller waited forever
    def urlopen(*a, **k):
        raise _http_error(OSError("error body lost"))
    with pytest.raises(OSError, match="error body lost"):
        _transport(monkeypatch, urlopen)


def test_a_connection_failure_reaches_the_caller(monkeypatch):
    def urlopen(*a, **k):
        raise ConnectionRefusedError("refused")
    with pytest.raises(ConnectionRefusedError):
        _transport(monkeypatch, urlopen)


@pytest.mark.parametrize("value", ["0", "257", "-1"])
def test_the_wallet_count_is_bounded(tmp_path, capsys, value):
    with pytest.raises(SystemExit):
        tool.main(["--key-file", str(tmp_path / "k"), "--out", str(tmp_path / "o"), "--wallets", value])
    assert "--wallets must be in [1, 256]" in capsys.readouterr().err
