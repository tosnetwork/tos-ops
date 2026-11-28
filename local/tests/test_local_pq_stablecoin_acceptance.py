"""Stablecoin acceptance driver controls; no node, source chain or key is used."""

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load(
    "stablecoin_acceptance",
    Path(
        os.environ.get(
            "TOS_STABLECOIN_DRIVER",
            ROOT / "local/scripts/local-pq-stablecoin-acceptance.py",
        )
    ),
)
u, lib = m.u, m.lib
Refused = u.Refused

USDC = "0x" + "11" * 20
USDT = "0x" + "22" * 20
BRIDGE = "0x" + "33" * 20
LOCKER = "0x" + "44" * 20
BUYER = "0:" + "55" * 32


def run_state(token, minter, wallet, tvm_bridge="-1:" + "66" * 32):
    return {
        "evm": {
            "bridge": BRIDGE,
            "token": token,
            "deployer": "0x" + "77" * 20,
            "locker": LOCKER,
            "oracles": [],
        },
        "namespace": {"token": token},
        "tvm": {"bridge": tvm_bridge},
        "mint": {
            "minter": minter,
            "buyer_token_wallet": wallet,
            "wrapped_token_data": [1, 2, 6],
        },
        "wallets": {"buyer": BUYER},
    }


def test_assets_bind_each_run_and_refuse_a_shared_identity():
    usdc = run_state(USDC, "0:" + "a1" * 32, "0:" + "b1" * 32)
    usdt = run_state(USDT, "0:" + "a2" * 32, "0:" + "b2" * 32)
    fixed = m.assets(usdc, usdt)
    assert fixed["usdc"]["token"] == USDC and fixed["usdt"]["token"] == USDT
    with pytest.raises(Refused, match="share a minter"):
        m.assets(usdc, run_state(USDT, "0:" + "a1" * 32, "0:" + "b2" * 32))
    with pytest.raises(Refused, match="share a token"):
        m.assets(usdc, run_state(USDC, "0:" + "a2" * 32, "0:" + "b2" * 32))
    with pytest.raises(Refused, match="different TOS bridges"):
        m.assets(
            usdc, run_state(USDT, "0:" + "a2" * 32, "0:" + "b2" * 32, "-1:" + "99" * 32)
        )


@pytest.mark.parametrize(
    "caps, message",
    [
        ((1000, 100, 200, 500), None),
        ((0, 0, 0, 0), None),
        ((1000, 0, 200, 500), "per-lock must be"),
        ((1000, 300, 200, 500), "per-lock <= hourly <= daily"),
        ((1000, 100, 600, 500), "per-lock <= hourly <= daily"),
        ((0, 100, 200, 500), "total must be"),
        ((2**120, 100, 200, 500), "total must be"),
    ],
)
def test_cap_votes_are_checked_before_signing(caps, message):
    if message is None:
        m.check_caps(*caps)
    else:
        with pytest.raises(Refused, match=message):
            m.check_caps(*caps)


def burn_transaction(account, topic=m.LOG_BURN, body_bits=704, length=256):
    """A transaction cell whose one out message is an external LOG_BURN."""
    B = u.Builder
    destination = int("aa" * 20, 16)
    body = (
        B()
        .uint(destination, 160)
        .uint(7_000_000, 128)
        .raw(bytes.fromhex(USDT[2:]))
        .uint(int("55" * 32, 16), 256)
    )
    if body_bits != 704:
        body = B().uint(0, body_bits)
    external = (
        B()
        .uint(0b11, 2)
        .uint(0b10, 2)
        .uint(0, 1)
        .uint(255, 8)
        .raw(bytes.fromhex(account))
        .uint(0b01, 2)
        .uint(length, 9)
        .uint(topic, length)
        .uint(0, 64)
        .uint(0, 32)
        .uint(0, 1)
        .uint(1, 1)
        .ref(body.end())
        .end()
    )
    # One-entry HashmapE 15: a leaf with a full 15-bit label.
    label = B().uint(0b10, 2).uint(0b1111, 4).uint(0, 15).ref(external).end()
    messages = B().uint(0, 1).uint(1, 1).ref(label).end()
    return (
        B()
        .uint(0b0111, 4)
        .raw(bytes.fromhex(account))
        .uint(12345, 64)
        .raw(bytes(32))
        .uint(0, 64)
        .uint(0, 32)
        .uint(0, 15)
        .uint(0, 4)
        .ref(messages)
        .end()
    )


def test_log_burn_is_decoded_from_the_bridge_transaction_cells():
    account = "66" * 32
    decoded = m.burn_logs(lib.serialize_boc(burn_transaction(account)))
    assert decoded["account"] == account and decoded["lt"] == 12345
    assert decoded["logs"] == [
        {
            "destination": "0x" + "aa" * 20,
            "amount": 7_000_000,
            "token": USDT,
            "from_address_hash": "55" * 32,
        }
    ]


def test_other_externals_are_not_burns_and_a_short_body_refuses():
    account = "66" * 32
    other = m.burn_logs(lib.serialize_boc(burn_transaction(account, topic=0x1234)))
    assert other["logs"] == []
    with pytest.raises(Refused, match="another layout"):
        m.burn_logs(lib.serialize_boc(burn_transaction(account, body_bits=640)))


class Chain:
    def __init__(self, seqno=7):
        self.seqno_value, self.sent = seqno, []
        self.key = None

    def account(self, address):
        data = (
            u.Builder()
            .uint(self.seqno_value, 32)
            .uint(u.PAYER_SUBWALLET, 32)
            .raw(self.key)
        )
        return {"state": "active", "data": u.boc64(data.end())}

    def send(self, message):
        self.sent.append(message)

    def wait(self, what, predicate, timeout=120, interval=2):
        raise Refused("timed out waiting for " + what)

    def balance(self, address):
        return 10**12


class Journal:
    def __init__(self):
        self.data = {}

    def intents(self):
        return self.data

    def intent(self, name):
        return self.data.get(name)

    def put_intent(self, name, record):
        self.data[name] = json.loads(json.dumps(record))


def payer(chain):
    wallet = m.WalletV3(chain, b"\x01" * 32, "-1:" + "88" * 32, u.PAYER_SUBWALLET)
    chain.key = bytes(wallet.key.verify_key)
    return wallet


def test_wallet_v3_signs_the_network_id_subwallet_expiry_and_seqno():
    chain = Chain(seqno=7)
    wallet = payer(chain)
    journal = Journal()
    with pytest.raises(Refused, match="timed out"):
        wallet.transfer(journal, "fund", BUYER, 5 * u.NANO, bounce=False)
    record = journal.intent("fund")
    assert record["state"] == "signed" and record["seqno"] == 7
    message = u.from64(record["boc"])
    body = lib.Slice(
        message.refs[0] if message.refs and len(message.refs) > 1 else message
    )
    sent = chain.sent[0]
    assert sent.hash() == message.hash()
    # The signed part: external header, then signature(512) and the v3 fields.
    s = lib.Slice(message)
    s.bits(2)
    s.bits(2)
    assert s.bits(2) == 0b10
    s.bits(1 + 8 + 256)
    lib.read_grams(s)
    s.bits(1)  # no StateInit
    if s.bits(1):
        s = lib.Slice(s.take_ref())
    s.bytes(64)
    assert s.bits(32) == lib.LOCAL_GLOBAL_ID
    assert s.bits(32) == u.PAYER_SUBWALLET
    assert s.bits(32) == record["valid_until"]
    assert s.bits(32) == 7
    del body


def test_wallet_v3_never_resends_an_expired_message():
    chain = Chain(seqno=7)
    wallet = payer(chain)
    journal = Journal()
    with pytest.raises(Refused):
        wallet.transfer(journal, "fund", BUYER, 5 * u.NANO, bounce=False)
    record = journal.intent("fund")
    journal.put_intent("fund", dict(record, valid_until=0))
    with pytest.raises(Refused, match="expired unsent"):
        wallet.transfer(journal, "fund", BUYER, 5 * u.NANO, bounce=False)
    assert len(chain.sent) == 1


def test_wallet_v3_refuses_another_subwallet():
    chain = Chain()
    wallet = m.WalletV3(chain, b"\x01" * 32, "-1:" + "88" * 32, u.PAYER_SUBWALLET + 1)
    chain.key = bytes(wallet.key.verify_key)
    with pytest.raises(Refused, match="subwallet differs"):
        wallet.seqno()


class State(Journal):
    def __init__(self, root):
        super().__init__()
        self.root = root
        self.values = {
            "evm": {"bridge": BRIDGE, "locker": LOCKER, "deployer": "0x" + "77" * 20},
            "assets": {
                "usdt": {
                    "token": USDT,
                    "minter": "0:" + "a2" * 32,
                    "buyer_token_wallet": "0:" + "b2" * 32,
                },
                "usdc": {
                    "token": USDC,
                    "minter": "0:" + "a1" * 32,
                    "buyer_token_wallet": "0:" + "b1" * 32,
                },
            },
            "buyer": BUYER,
            "tvm": {"bridge": "-1:" + "66" * 32},
        }
        self.evidenced = {}

    def __getitem__(self, key):
        return self.values[key]

    def get(self, key, default=None):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = json.loads(json.dumps(value))

    def evidence(self, name, value):
        self.evidenced[name] = value


def probe_args(**extra):
    return SimpleNamespace(
        label="probe",
        asset="usdt",
        amount=101,
        expect="per-lock",
        execute=True,
        **extra,
    )


@pytest.fixture
def probe_world(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(m, "values", lambda *a, **k: ["1000"])
    monkeypatch.setattr(
        m, "pinned_block", lambda evm: {"number": 9, "hash": "0x09", "timestamp": 1}
    )
    monkeypatch.setattr(m, "source_facts", lambda *a, **k: {"cap": {}})
    monkeypatch.setattr(
        m, "approve_exact", lambda *a: calls.append("approve") or {"approved": 101}
    )
    monkeypatch.setattr(
        m, "clear_approval", lambda *a: calls.append("reset") or "0xreset"
    )
    return State(tmp_path), calls


def test_probe_requires_the_named_refusal_and_always_resets_the_allowance(
    monkeypatch, probe_world
):
    state, calls = probe_world
    monkeypatch.setattr(
        m,
        "simulate_lock",
        lambda *a: (False, "execution reverted: lock: over the per-lock cap"),
    )
    result = m.step_probe(probe_args(), state, None)
    assert result["expected_reason"] == m.REASONS["per-lock"] and calls == [
        "approve",
        "reset",
    ]
    assert result["block"]["number"] == 9


def test_probe_refuses_another_reason(monkeypatch, probe_world):
    state, calls = probe_world
    monkeypatch.setattr(
        m,
        "simulate_lock",
        lambda *a: (False, "execution reverted: lock: over the daily cap"),
    )
    with pytest.raises(Refused, match="another reason"):
        m.step_probe(probe_args(), state, None)
    assert calls == ["approve", "reset"]


def test_probe_refuses_an_admitted_lock(monkeypatch, probe_world):
    state, calls = probe_world
    monkeypatch.setattr(m, "simulate_lock", lambda *a: (True, ""))
    with pytest.raises(Refused, match="was admitted"):
        m.step_probe(probe_args(), state, None)
    assert calls == ["approve", "reset"] and not state.evidenced


def test_probe_dry_run_sends_nothing(monkeypatch, probe_world):
    state, calls = probe_world
    args = probe_args()
    args.execute = False
    assert m.step_probe(args, state, None)["dry_run"] is True
    assert calls == []


class Tools:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def cast_run(self, *argv, check=True):
        self.calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=self.answers.pop(0), stderr="")


def test_approval_is_cleared_before_an_exact_one(monkeypatch, tmp_path):
    sent = []

    def send(evm, state, intent, sender, to, signature, *args, **kwargs):
        sent.append((intent, signature, args))
        return {"status": 1, "tx": "0x" + intent}

    monkeypatch.setattr(m.u, "evm_send_once", send)
    answers = iter([["5"], ["100"]])
    monkeypatch.setattr(m, "values", lambda *a, **k: next(answers))
    result = m.approve_exact(None, State(tmp_path), "lock", "usdt", 100)
    assert [s[0] for s in sent] == ["lock-approve-clear", "lock-approve"]
    assert sent[0][2] == (BRIDGE, "0") and sent[1][2] == (BRIDGE, "100")
    assert result["before"] == 5 and result["after"] == 100


def test_zero_allowance_is_approved_exactly_without_a_clear(monkeypatch, tmp_path):
    sent = []
    monkeypatch.setattr(
        m.u,
        "evm_send_once",
        lambda e, s, intent, *a, **k: sent.append(intent) or {"status": 1, "tx": "0x1"},
    )
    answers = iter([["0"], ["100"]])
    monkeypatch.setattr(m, "values", lambda *a, **k: next(answers))
    m.approve_exact(None, State(tmp_path), "lock", "usdt", 100)
    assert sent == ["lock-approve"]


def chain_get(address, method, *args):
    if method == "get_supply_state":
        return [["num", "25"]]
    if method == "get_swap":
        return [["num", "2"], ["num", "0"], ["num", "0"]]
    return [["num", "0"]] * 8


def lock_world(monkeypatch, tmp_path, simulate=(True, ""), received=100, supply=None):
    state = State(tmp_path)
    sent = []
    chain = SimpleNamespace(
        get=chain_get,
        wait=lambda what, predicate, timeout=0: (
            predicate()
            or (_ for _ in ()).throw(Refused("timed out waiting for " + what))
        ),
    )
    monkeypatch.setattr(
        m.u, "wallets", lambda chain, keys: {"buyer": SimpleNamespace(address=BUYER)}
    )
    monkeypatch.setattr(
        m, "live_wallet_balance", lambda chain, wallet: 10 + (received if sent else 0)
    )
    monkeypatch.setattr(
        m, "pinned_block", lambda evm: {"number": 9, "hash": "0x09", "timestamp": 1}
    )
    monkeypatch.setattr(m, "simulate_lock", lambda *a: simulate)
    monkeypatch.setattr(m, "approve_exact", lambda *a: {"approved": 100})

    def values(evm, to, signature, *args, block=None):
        if signature.startswith("balanceOf"):
            return ["1000"]
        if signature.startswith("lockNonce"):
            return ["4"]
        if signature == m.LOCKS:
            return [LOCKER, USDT, str(received), "1", "1"]
        raise AssertionError(signature)

    monkeypatch.setattr(m, "values", values)

    def send(evm, state_, intent, *args, **kwargs):
        sent.append(intent)
        return {"status": 1, "tx": "0xlock", "block": 3}

    monkeypatch.setattr(m.u, "evm_send_once", send)
    target = "0x" + "55" * 32
    monkeypatch.setattr(
        m,
        "lock_event",
        lambda evm, tx, bridge, n: {
            "value": received,
            "decimals": 6,
            "generation": 1,
            "to_addr_hash": target,
            "n": n,
            "new_bridge_balance": 0,
        },
    )
    monkeypatch.setattr(
        m.u, "pay_and_vote", lambda *a: sent.append("mint") or {"pay_swap": 1}
    )
    view = SimpleNamespace(urls=["r4", "r5", "r6"], point={"seqno": 1})
    monkeypatch.setattr(m.t, "View", lambda chain, directory: view)
    monkeypatch.setattr(
        m, "supply_at", lambda view, minter: 25 + received if supply is None else supply
    )
    monkeypatch.setattr(m, "wallet_balance_at", lambda view, wallet: 10 + received)
    monkeypatch.setattr(m, "source_facts", lambda *a, **k: {"cap": {}})
    args = SimpleNamespace(
        label="canary-a", asset="usdt", amount=100, execute=True, keys=Path("/k")
    )
    return state, chain, args, sent


def test_lock_mints_the_received_delta_and_rechecks_supply(monkeypatch, tmp_path):
    state, chain, args, sent = lock_world(monkeypatch, tmp_path, received=90)
    chain.get = chain_get
    result = m.step_lock(args, state, None, chain)
    assert sent == ["canary-a-lock", "mint"]
    assert result["received"] == 90 and result["fee_withheld"] == 10
    assert result["second_resolver"]["supply"] == 115


def test_lock_refused_in_simulation_sends_nothing(monkeypatch, tmp_path):
    state, chain, args, sent = lock_world(
        monkeypatch, tmp_path, simulate=(False, "lock: over the hourly cap")
    )
    with pytest.raises(Refused, match="would be refused"):
        m.step_lock(args, state, None, chain)
    assert sent == []


def test_lock_supply_that_does_not_match_refuses(monkeypatch, tmp_path):
    state, chain, args, _sent = lock_world(monkeypatch, tmp_path, supply=124)
    chain.get = chain_get
    with pytest.raises(Refused, match="finalized supply"):
        m.step_lock(args, state, None, chain)


def test_lock_label_cannot_be_reused_for_another_amount(monkeypatch, tmp_path):
    state, chain, args, sent = lock_world(monkeypatch, tmp_path)
    state.set(
        "locks",
        {
            "canary-a": {
                "asset": "usdt",
                "amount": 50,
                "n": 4,
                "supply_before": 25,
                "wallet_before": 10,
            }
        },
    )
    with pytest.raises(Refused, match="another asset or amount"):
        m.step_lock(args, state, None, chain)
    assert sent == []


def unlock_world(monkeypatch, tmp_path, fee_bps=10, received_delta=None, preview=None):
    state = State(tmp_path)
    amount = 1_000_000
    fee = min(amount * fee_bps // 10000, 49 * 10**6)
    state.set(
        "burns",
        {
            "burn-a": {
                "result": {
                    "asset": "usdt",
                    "receiver": "0x" + "aa" * 20,
                    "log_burn": {"amount": amount, "from_address_hash": "55" * 32},
                    "bridge_transaction": {"hash": "66" * 32, "lt": 9},
                    "preview": {
                        "received_atomic": str(preview if preview else amount - fee)
                    },
                }
            }
        },
    )
    paid = []
    balances = {"receiver": 0, "bridge": 5_000_000}

    def values(evm, to, signature, holder, block=None):
        return [str(balances["receiver" if holder == "0x" + "aa" * 20 else "bridge"])]

    monkeypatch.setattr(m, "values", values)
    monkeypatch.setattr(
        m,
        "source_facts",
        lambda *a, **k: {"fee_basis_points": fee_bps, "maximum_fee": 49 * 10**6},
    )

    def vote(evm, state_, keys, intent, *a):
        paid.append(intent)
        balances["bridge"] -= amount
        balances["receiver"] += (
            amount - fee if received_delta is None else received_delta
        )
        return {"status": 1, "tx": "0xunlock", "block": 4}

    monkeypatch.setattr(m.u, "evm_vote", vote)
    args = SimpleNamespace(
        label="unlock-a",
        burn="burn-a",
        receiver="0x" + "AA" * 20,
        execute=True,
        keys=Path("/k"),
    )
    return state, args, paid


def test_unlock_pays_the_amount_less_the_issuer_fee(monkeypatch, tmp_path):
    state, args, paid = unlock_world(monkeypatch, tmp_path)
    result = m.step_unlock(args, state, None)
    assert (
        paid == ["unlock-a"]
        and result["issuer_fee"] == 1000
        and result["received"] == 999_000
    )
    assert "(0x" + "55" * 32 + ",0x" + "66" * 32 + ",9))" in result["swap"]


def test_unlock_receiver_short_of_the_preview_refuses(monkeypatch, tmp_path):
    state, args, _ = unlock_world(monkeypatch, tmp_path, received_delta=998_000)
    with pytest.raises(Refused, match="less the issuer fee"):
        m.step_unlock(args, state, None)


def test_unlock_preview_that_differs_refuses(monkeypatch, tmp_path):
    state, args, _ = unlock_world(monkeypatch, tmp_path, preview=1_000_000)
    with pytest.raises(Refused, match="T19 preview differs"):
        m.step_unlock(args, state, None)


def test_unlock_to_another_receiver_than_the_burn_refuses(monkeypatch, tmp_path):
    state, args, paid = unlock_world(monkeypatch, tmp_path)
    args.receiver = "0x" + "bb" * 20
    with pytest.raises(Refused, match="another receiver"):
        m.step_unlock(args, state, None)
    assert paid == []


def monitor_dir(tmp_path, alarms=(), incidents=None, age=0):
    import time

    now = int(time.time()) - age
    checkpoint = {"hash": "aa", "height": 1, "utime": now}
    (tmp_path / "report.json").write_text(
        json.dumps(
            {
                "alarms": list(alarms),
                "latched_incidents": sorted(incidents or {}),
                "provider_pause_assets": [],
                "checkpoint": checkpoint,
            }
        )
    )
    (tmp_path / "snapshot.json").write_text(
        json.dumps(
            {
                "checkpoint": checkpoint,
                "source_checkpoint": {"height": 2},
                "assets": [{"id": "usdt"}],
            }
        )
    )
    (tmp_path / "incidents.json").write_text(json.dumps(incidents or {}))
    return tmp_path


@pytest.mark.parametrize(
    "alarms, incidents, age, message",
    [
        ([{"code": "hourly_headroom"}], None, 0, "not clean"),
        ([], {"usdt:bridge_frozen": {}}, 0, "not clean"),
        ([], None, 600, "stale"),
    ],
)
def test_clean_observation_refuses_alarms_latches_and_staleness(
    monkeypatch, tmp_path, alarms, incidents, age, message
):
    monkeypatch.setattr(m.time, "sleep", lambda seconds: None)
    (tmp_path / "monitor").mkdir()
    root = monitor_dir(tmp_path / "monitor", alarms, incidents, age)
    state = State(tmp_path / "state")
    args = SimpleNamespace(
        label="observe", monitor_state=root, expect_clean=True, expect_alarm=None
    )
    with pytest.raises(Refused, match=message):
        m.step_observe(args, state)


def test_clean_observation_is_retained(tmp_path):
    (tmp_path / "monitor").mkdir()
    root = monitor_dir(tmp_path / "monitor")
    state = State(tmp_path / "state")
    args = SimpleNamespace(
        label="observe-1", monitor_state=root, expect_clean=True, expect_alarm=None
    )
    result = m.step_observe(args, state)
    assert result["report"]["alarms"] == [] and "observe-1" in state.evidenced
    retained = json.loads(
        (tmp_path / "state/archive/monitor/retained-verifiers.json").read_text()
    )
    assert len(retained) == 1


def test_reconcile_refuses_unbacked_supply(monkeypatch, tmp_path):
    state = State(tmp_path)
    view = SimpleNamespace(urls=[], point={"seqno": 1})
    monkeypatch.setattr(m.t, "View", lambda chain, directory: view)
    monkeypatch.setattr(m, "finalized_source", lambda evm: {"number": 5, "hash": "0x5"})
    monkeypatch.setattr(m, "supply_at", lambda view, minter: 100)
    monkeypatch.setattr(
        m,
        "source_facts",
        lambda evm, state, name, block=None: {
            "bridge_balance": 100 if name == "usdc" else 99
        },
    )
    args = SimpleNamespace(label="reconcile", expect_reconciled=True)
    with pytest.raises(Refused, match="usdt supply 100 != backing 99"):
        m.step_reconcile(args, state, None, None)
    args.expect_reconciled = False
    result = m.step_reconcile(args, state, None, None)
    assert (
        result["assets"]["usdc"]["reconciled"]
        and not result["assets"]["usdt"]["reconciled"]
    )


@pytest.mark.parametrize("bps, maximum", [(20, 10), (5, 50), (-1, 1)])
def test_issuer_fee_outside_the_fixture_bounds_refuses_before_sending(
    monkeypatch, tmp_path, bps, maximum
):
    monkeypatch.setattr(m, "values", lambda *a, **k: ["0x" + "77" * 20])
    monkeypatch.setattr(m, "source_facts", lambda *a, **k: {})
    sent = []
    monkeypatch.setattr(
        m.u,
        "evm_send_once",
        lambda *a, **k: sent.append(a) or {"status": 0, "tx": "0x", "block": 1},
    )
    args = SimpleNamespace(
        label="fee",
        asset="usdt",
        op="set-fee",
        basis_points=bps,
        max_fee=maximum,
        execute=True,
    )
    with pytest.raises(Refused, match="fee bounds"):
        m.step_issuer(args, State(tmp_path), None)
    assert sent == []


def test_issuer_controls_exist_only_for_the_usdt_fixture(tmp_path):
    args = SimpleNamespace(label="x", asset="usdc", op="pause", execute=True)
    with pytest.raises(Refused, match="LocalUSDT"):
        m.step_issuer(args, State(tmp_path), None)


def test_cap_state_parses_the_annotated_tuple():
    tools = Tools(
        [
            (
                "(1000000000 [1e9], 100000000 [1e8], 200000000 [2e8], 500000000 [5e8])\n"
                "100000000 [1e8]\n0\n100000000 [1e8]\n"
            )
        ]
    )
    caps = m.cap_state(SimpleNamespace(tools=tools), BRIDGE, USDC, block=7)
    assert caps == {
        "total": 10**9,
        "per_lock": 10**8,
        "hourly": 2 * 10**8,
        "daily": 5 * 10**8,
        "hour_used": 10**8,
        "day_used": 0,
        "available": 10**8,
    }
    assert tools.calls[0][:3] == ("call", "--block", "7")


def test_source_endpoint_must_be_loopback(capsys):
    code = m.main(
        [
            "status",
            "--state",
            "/nonexistent",
            "--tos-root",
            "/x",
            "--evm-rpc",
            "http://10.0.0.1:8545",
        ]
    )
    assert code == 2 and "local source endpoint required" in capsys.readouterr().out


def test_a_latch_on_disk_is_not_clean_even_if_the_report_omits_it(tmp_path):
    (tmp_path / "monitor").mkdir()
    root = monitor_dir(tmp_path / "monitor")
    (root / "incidents.json").write_text(json.dumps({"usdt:bridge_frozen": {}}))
    args = SimpleNamespace(
        label="observe", monitor_state=root, expect_clean=True, expect_alarm=None
    )
    with pytest.raises(Refused, match="not clean"):
        m.step_observe(args, State(tmp_path / "state"))


def resolution_world(
    monkeypatch,
    tmp_path,
    blacklisted=False,
    disabled=False,
    alarms=(),
    incidents=None,
    publish=True,
):
    import time

    (tmp_path / "monitor").mkdir()
    root = monitor_dir(tmp_path / "monitor", alarms)
    latched = (
        incidents
        if incidents is not None
        else {"usdt:bridge_frozen": {"x": 1}, "usdc:token_paused": {"y": 2}}
    )
    (root / "incidents.json").write_text(json.dumps(latched))
    for name in ("previous", "policy", "binding"):
        (root / f"{name}.json").write_text("{}")
    monkeypatch.setattr(m, "finalized_source", lambda evm: {"number": 9, "hash": "0x9"})
    monkeypatch.setattr(
        m,
        "source_facts",
        lambda *a, **k: {
            "bridge_blacklisted": blacklisted,
            "paused": False,
            "disabled": disabled,
            "allow_lock": True,
        },
    )
    sleeps = []

    def tick(seconds):
        sleeps.append(seconds)
        if publish:
            report = json.loads((root / "report.json").read_text())
            report["checkpoint"]["utime"] = int(time.time()) + 1
            report["checkpoint"]["height"] += 1
            report["latched_incidents"] = sorted(
                json.loads((root / "incidents.json").read_text())
            )
            (root / "report.json").write_text(json.dumps(report))

    monkeypatch.setattr(m.time, "sleep", tick)
    state = State(tmp_path / "state")
    state.root.mkdir()
    args = SimpleNamespace(
        label="resolve",
        incident="usdt:bridge_frozen",
        monitor_state=root,
        authorization="coordinator approved the drill",
        execute=True,
    )
    return state, args, root


def test_resolution_removes_only_the_named_latch_and_keeps_copies(
    monkeypatch, tmp_path
):
    state, args, root = resolution_world(monkeypatch, tmp_path)
    result = m.step_resolve_incident(args, state, None)
    assert json.loads((root / "incidents.json").read_text()) == {
        "usdc:token_paused": {"y": 2}
    }
    before = json.loads(
        (state.root / "incident-resolution/resolve/before-incidents.json").read_text()
    )
    assert "usdt:bridge_frozen" in before and result["other_incidents_kept"] == [
        "usdc:token_paused"
    ]


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"blacklisted": True}, "still holds"),
        ({"disabled": True}, "re-enable the token"),
        ({"alarms": [{"asset": "usdt", "code": "bridge_frozen"}]}, "still reports"),
        ({"incidents": {}}, "is not latched"),
    ],
)
def test_resolution_refuses_while_its_condition_holds(
    monkeypatch, tmp_path, kwargs, message
):
    state, args, root = resolution_world(monkeypatch, tmp_path, **kwargs)
    before = (root / "incidents.json").read_bytes()
    with pytest.raises(Refused, match=message):
        m.step_resolve_incident(args, state, None)
    assert (root / "incidents.json").read_bytes() == before


def test_resolution_refuses_while_the_checker_holds_its_lock(monkeypatch, tmp_path):
    import fcntl

    state, args, root = resolution_world(monkeypatch, tmp_path)
    before = (root / "incidents.json").read_bytes()
    with (root / "monitor.lock").open("a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(BlockingIOError):
            m.step_resolve_incident(args, state, None)
    assert (root / "incidents.json").read_bytes() == before


def test_resolution_requires_a_fresh_report_afterwards(monkeypatch, tmp_path):
    state, args, _root = resolution_world(monkeypatch, tmp_path, publish=False)
    clock = iter(range(0, 10**6, 1000))
    monkeypatch.setattr(m.time, "monotonic", lambda: next(clock))
    with pytest.raises(Refused, match="no fresh report"):
        m.step_resolve_incident(args, state, None)


def test_observation_waits_for_the_published_report(monkeypatch, tmp_path):
    (tmp_path / "monitor").mkdir()
    root = monitor_dir(tmp_path / "monitor")
    published = (root / "report.json").read_text()
    stale = json.loads(published)
    stale["checkpoint"] = dict(stale["checkpoint"], utime=0)
    (root / "report.json").write_text(json.dumps(stale))
    monkeypatch.setattr(
        m.time, "sleep", lambda seconds: (root / "report.json").write_text(published)
    )
    args = SimpleNamespace(
        label="observe", monitor_state=root, expect_clean=True, expect_alarm=None
    )
    assert m.step_observe(args, State(tmp_path / "state"))["report"]["alarms"] == []


BYPASS = "http://127.0.0.1:18545@review.invalid:8545"


@pytest.mark.parametrize(
    "url, ok",
    [
        ("http://127.0.0.1:18545", True),
        ("http://127.0.0.2:18545", True),
        ("http://[::1]:18545", True),
        ("http://localhost:18545", True),
        (BYPASS, False),
        ("http://user@127.0.0.1:18545", False),
        ("http://review.invalid:8545", False),
        ("http://10.0.0.1:8545", False),
        ("https://127.0.0.1:18545", False),
        ("http://127.0.0.1", False),
        ("http://127.0.0.1.review.invalid:8545", False),
        ("http://127.0.0.1:notaport", False),
    ],
)
def test_source_endpoint_host_is_parsed_not_prefix_matched(url, ok):
    assert m.loopback_url(url) is ok


def test_the_userinfo_bypass_is_refused_before_any_read(capsys):
    code = m.main(
        ["status", "--state", "/nonexistent", "--tos-root", "/x", "--evm-rpc", BYPASS]
    )
    assert code == 2 and "local source endpoint required" in capsys.readouterr().out


@pytest.mark.parametrize("field", ["height", "hash"])
def test_same_utime_with_another_checkpoint_is_not_one_publication(
    monkeypatch, tmp_path, field
):
    monkeypatch.setattr(m.time, "sleep", lambda seconds: None)
    (tmp_path / "monitor").mkdir()
    root = monitor_dir(tmp_path / "monitor")
    snapshot = json.loads((root / "snapshot.json").read_text())
    snapshot["checkpoint"][field] = 2 if field == "height" else "bb"
    (root / "snapshot.json").write_text(json.dumps(snapshot))
    args = SimpleNamespace(
        label="observe", monitor_state=root, expect_clean=True, expect_alarm=None
    )
    with pytest.raises(Refused, match="stale"):
        m.step_observe(args, State(tmp_path / "state"))


def test_a_report_changing_between_reads_is_not_one_publication(monkeypatch, tmp_path):
    (tmp_path / "monitor").mkdir()
    root = monitor_dir(tmp_path / "monitor")
    reads = {"n": 0}
    original = m.Path.read_bytes

    def read_bytes(path):
        data = original(path)
        if path.name == "report.json":
            reads["n"] += 1
            if reads["n"] % 2 == 0:
                return data.replace(b'"alarms": []', b'"alarms": [] ')
        return data

    monkeypatch.setattr(m.Path, "read_bytes", read_bytes)
    monkeypatch.setattr(m.time, "sleep", lambda seconds: None)
    args = SimpleNamespace(
        label="observe", monitor_state=root, expect_clean=True, expect_alarm=None
    )
    with pytest.raises(Refused, match="stale"):
        m.step_observe(args, State(tmp_path / "state"))


def test_resolution_needs_a_higher_checkpoint_not_only_a_new_utime(
    monkeypatch, tmp_path
):
    import time as clock

    state, args, root = resolution_world(monkeypatch, tmp_path, publish=False)

    def same_height(seconds):
        report = json.loads((root / "report.json").read_text())
        report["checkpoint"]["utime"] = int(clock.time()) + 5
        (root / "report.json").write_text(json.dumps(report))

    monkeypatch.setattr(m.time, "sleep", same_height)
    # Each wait advances the clock 50 s, so a newer utime is published before the
    # 120 s deadline, but never a higher checkpoint.
    ticks = iter(range(0, 10**6, 50))
    monkeypatch.setattr(m.time, "monotonic", lambda: next(ticks))
    with pytest.raises(Refused, match="no fresh report"):
        m.step_resolve_incident(args, state, None)
