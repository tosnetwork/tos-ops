"""Checks the pool traffic verifier against single-point false positives."""

import asyncio
import base64
import importlib.util
import json
import random
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
spec = importlib.util.spec_from_file_location(
    "privacy", SCRIPTS.joinpath("local-pq-privacy.py")
)
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


def state():
    return dict(
        commitment_root="123",
        nullifier_root="456",
        commitment_next_index=7,
        nullifier_next_index=3,
        native_liability=100,
        backed=-1,
    )


def test_exact_state():
    privacy.verify_state(state(), state())


@pytest.mark.parametrize("name", privacy.METHODS)
def test_state_mutation(name):
    actual = state()
    actual[name] = int(actual[name]) + 1
    with pytest.raises(ValueError, match="differ"):
        privacy.verify_state(actual, state())


def test_missing_state():
    actual = state()
    actual.pop("backed")
    with pytest.raises(ValueError, match="incomplete"):
        privacy.verify_state(actual, state())


def message(value=100, digest=b"a", source="0:" + "11" * 32, dest="0:" + "22" * 32):
    return SimpleNamespace(
        hash=digest,
        value=value,
        source=SimpleNamespace(account_address=source),
        destination=SimpleNamespace(account_address=dest),
    )


def test_payout():
    msg = message()
    privacy.verify_withdrawal(200, 298, 100, 2, msg, msg, "0:" + "11" * 32, "0:" + "22" * 32)


@pytest.mark.parametrize("change", ["delta", "fee", "hash", "value", "source", "destination"])
def test_wrong_payout(change):
    sent, received = message(), message()
    after, fee = 298, 2
    if change == "delta":
        after += 1
    if change == "fee":
        fee = -1
    if change == "hash":
        received.hash = b"b"
    if change == "value":
        received.value += 1
    if change == "source":
        received.source.account_address = "0:" + "33" * 32
    if change == "destination":
        received.destination.account_address = "0:" + "33" * 32
    with pytest.raises(ValueError):
        privacy.verify_withdrawal(
            200, after, 100, fee, sent, received, "0:" + "11" * 32, "0:" + "22" * 32
        )


def test_a_missing_lite_client_is_refused_before_anything_is_written(tmp_path):
    # The service runs from a snapshot without a build tree; it must use the
    # installed lite-client and refuse to start when that is absent.
    args = SimpleNamespace(
        nodes=7,
        min_interval=20.0,
        max_interval=60.0,
        count=0,
        lite_client=tmp_path / "absent-lite-client",
        output=tmp_path / "out",
    )
    with pytest.raises(RuntimeError, match="does not exist"):
        asyncio.run(privacy.run(args))
    assert not args.output.exists()


def test_pool_state_queries_the_validated_lite_client(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        privacy.local,
        "get_method",
        lambda lite_client, data, address, name: calls.append(lite_client) or 0,
    )
    lite_client = tmp_path / "tos-lite-client"
    args = SimpleNamespace(lite_client=lite_client, data=tmp_path, build=tmp_path / "build")
    asyncio.run(privacy.pool_state(args, "0:" + "ab" * 32))
    assert calls and set(calls) == {lite_client}


def test_the_lite_client_defaults_to_the_installed_binary(monkeypatch):
    seen = {}

    def capture(coroutine):
        seen["args"] = coroutine.cr_frame.f_locals["args"]
        coroutine.close()

    monkeypatch.setattr(privacy.asyncio, "run", capture)
    monkeypatch.setattr(sys, "argv", ["local-pq-privacy.py"])
    privacy.main()
    assert seen["args"].lite_client == privacy.local.INSTALLED_LITE_CLIENT


def test_no_notes_deposits():
    plan = privacy.plan_operation([], 0, BOOT, COSTS, SETPOINT, random.Random(0))
    assert plan["operation"] == "deposit" and plan["amount"] == privacy.DENOMINATIONS[0]


# ---------------------------------------------------------------- traffic model
#
# The generator's rules (local_pool_traffic.rs): deposits and withdrawals are
# denominations; a transfer or withdrawal spends two distinct notes into two
# positive notes, a withdrawal splitting the change after its fee; a deposit
# attaches amount + deposit gas, a transfer or withdrawal attaches transact gas.

# The deployed generator's resources (operation "resources"), 2026-10-08.
RESOURCES = {"withdrawal_fee": 20_000_000, "deposit_gas_ceiling": 230_000, "transact_gas_ceiling": 1_510_000}
COSTS = privacy.Costs(RESOURCES)
NANO = privacy.NANO
SETPOINT = 50 * NANO
BOOT = [200 * NANO] * 3  # what each private-traffic wallet is funded with
# Message fees outside the attached value: conservative upper bounds, so the
# simulated lifetime is a lower bound.
WALLET_FEE = 50_000_000
PAYOUT_FEE = 10_000_000


class Simulation:
    """Applies planned operations under the generator's rules and checks conservation each step."""

    def __init__(self, balances, notes=()):
        self.balances = list(balances)
        self.notes = [dict(n) for n in notes]
        self.next_index = max((n["index"] for n in self.notes), default=-1) + 1
        self.liability = sum(n["amount"] for n in self.notes)
        self.drained = 0  # attached gas, message fees and withdrawal fees
        self.total = sum(self.balances) + self.liability
        self.ops = []

    def add(self, amount, owner):
        self.notes.append({"index": self.next_index, "amount": amount, "owner": owner})
        self.next_index += 1

    def apply(self, op):
        sender = op["sender"]
        assert op["recipient"] != sender
        if op["operation"] == "deposit":
            assert op["amount"] in privacy.DENOMINATIONS
            cost = COSTS.deposit_value(op["amount"]) + WALLET_FEE
            self.balances[sender] -= cost
            self.drained += COSTS.deposit_gas + WALLET_FEE
            self.liability += op["amount"]
            self.add(op["amount"], op["owner"])
        else:
            assert len(set(op["inputs"])) == 2
            inputs = [n for n in self.notes if n["index"] in op["inputs"]]
            assert len(inputs) == 2
            self.notes = [n for n in self.notes if n["index"] not in op["inputs"]]
            total = sum(n["amount"] for n in inputs)
            self.balances[sender] -= COSTS.transact_value + WALLET_FEE
            self.drained += COSTS.transact_value + WALLET_FEE
            if op["operation"] == "transfer":
                outputs = (op["amount"], total - op["amount"])
            else:
                assert op["amount"] in privacy.DENOMINATIONS
                change = total - op["amount"] - COSTS.withdrawal_fee
                outputs = (change // 2, change - change // 2)
                self.liability -= op["amount"] + COSTS.withdrawal_fee
                self.drained += COSTS.withdrawal_fee + PAYOUT_FEE
                self.balances[op["recipient"]] += op["amount"] - PAYOUT_FEE
            assert all(o > 0 for o in outputs), "two positive output notes required"
            for o in outputs:
                self.add(o, op["owner"])
        assert min(self.balances) >= 0, "a wallet paid more than it held"
        assert self.liability == sum(n["amount"] for n in self.notes)
        assert sum(self.balances) + self.liability + self.drained == self.total, "value not conserved"
        self.ops.append(op["operation"])

    def step(self, rng):
        op = privacy.plan_operation(self.notes, self.liability, self.balances, COSTS, SETPOINT, rng)
        if "exhausted" not in op:
            self.apply(op)
        return op


def test_bounded_from_an_empty_pool_until_fees_exhaust_the_funding():
    # The bootstrap's 600 TOS last until fees alone have spent it; meanwhile
    # the pool holds no more than the set-point and one deposit, so the wallets
    # never strand their value in notes.
    sim, rng = Simulation(BOOT), random.Random(1)
    for i in range(100_000):
        op = sim.step(rng)
        if "exhausted" in op:
            break
        if i >= 200:
            assert sim.liability <= SETPOINT + privacy.DENOMINATIONS[0], sim.liability
    else:
        raise AssertionError("finite funding never ran out")
    assert op == {"exhausted": "no-funding"}
    # With conservative message fees: about 90 hours at the driver's 20-60 s pacing.
    assert i > 7_500, i
    assert {"deposit", "transfer", "withdraw"} <= set(sim.ops)
    # What was left in notes is at most the set-point band; the rest went to fees.
    assert sim.liability <= SETPOINT + privacy.DENOMINATIONS[0]


def test_the_real_434_tos_liability_comes_back():
    # About what the stopped run left: 434 TOS in notes of mixed sizes, wallets nearly empty.
    rng = random.Random(2)
    notes, left, index = [], 434 * NANO, 0
    while left > 0:
        amount = min(left, rng.choice((NANO, 2 * NANO, 3 * NANO, 7 * NANO, NANO // 3)))
        notes.append({"index": index, "amount": amount, "owner": index % 3})
        left -= amount
        index += 1
    sim = Simulation([3 * NANO, 2 * NANO, 2 * NANO], notes)
    for _ in range(5_000):
        assert "exhausted" not in sim.step(rng)
        if sim.liability <= SETPOINT + privacy.DENOMINATIONS[0]:
            break
    assert sim.liability <= SETPOINT + privacy.DENOMINATIONS[0]
    assert sum(sim.balances) > 350 * NANO  # the notes' value is back in the wallets


def test_funding_ends_in_exhaustion_not_failure():
    sim, rng = Simulation([8 * NANO] * 3), random.Random(3)
    for i in range(200_000):
        op = sim.step(rng)
        if "exhausted" in op:
            break
    else:
        raise AssertionError("finite funding never ran out")
    assert op["exhausted"] in ("no-funding", "no-inputs", "no-private-value")
    # A lower bound on the run's length from this funding, with conservative fees.
    assert i > 100


def old_policy_step(state, rng, sequence):
    """The driver's previous choice and random ring sender, kept as the red control."""
    notes = state["notes"]
    operation = (("deposit", "deposit", "transfer", "withdraw")[sequence] if sequence < 4
                 else rng.choice(("deposit", "transfer", "withdraw")))
    if len(notes) < 2:
        operation = "deposit"
    source = rng.randrange(3)
    ring = {"sender": source, "recipient": (source + 1) % 3}
    if operation == "deposit":
        return {"operation": operation, "amount": rng.choice((NANO, NANO, NANO, 10 * NANO)),
                "owner": rng.randrange(3), **ring}
    inputs = rng.sample(notes, 2)
    total = sum(n["amount"] for n in inputs)
    fee = 20_000_000 if operation == "withdraw" else 0
    maximum = min(NANO, total - fee - 2)
    if maximum < 1 or (operation == "withdraw" and total - fee - 2 < NANO):
        return {"operation": "deposit", "amount": NANO, "owner": rng.randrange(3), **ring}
    return {"operation": operation,
            "amount": (rng.choice([v for v in privacy.DENOMINATIONS if v <= total - fee - 2])
                       if operation == "withdraw" else rng.randint(1, maximum)),
            "owner": rng.choice([i for i in range(3) if i != inputs[0]["owner"]]),
            "inputs": [n["index"] for n in inputs], **ring}


def test_red_control_the_old_policy_drains_a_wallet():
    sim, rng = Simulation(BOOT), random.Random(1)
    for sequence in range(20_000):
        op = old_policy_step({"notes": sim.notes}, rng, sequence)
        value = (COSTS.deposit_value(op["amount"]) if op["operation"] == "deposit" else COSTS.transact_value)
        if sim.balances[op["sender"]] < value + NANO:  # the old check: "funding wallet too low"
            break
        sim.apply(op)
    else:
        raise AssertionError("the old policy never drained a wallet")
    assert sim.liability > SETPOINT


def test_consolidation_concentrates_non_dust_notes_until_a_withdrawal():
    # 0.4 TOS notes: no pair funds a 1 TOS withdrawal, but together they can.
    notes = [{"index": i, "amount": 4 * NANO // 10, "owner": i % 3} for i in range(200)]
    sim, rng = Simulation(BOOT, notes), random.Random(4)
    largest = max(n["amount"] for n in sim.notes)
    for _ in range(50):
        op = sim.step(rng)
        if op["operation"] == "withdraw":
            break
        assert op["operation"] == "transfer" and op["amount"] == 1
        now = max(n["amount"] for n in sim.notes)
        assert now > largest, "consolidation made no progress"
        largest = now
    else:
        raise AssertionError("consolidation never enabled a withdrawal")


def test_a_large_note_with_dust_withdraws_directly():
    notes = [{"index": 0, "amount": 60 * NANO, "owner": 0}] + [
        {"index": i, "amount": 1, "owner": i % 3} for i in range(1, 30)]
    op = privacy.plan_operation(notes, sum(n["amount"] for n in notes), BOOT, COSTS, SETPOINT, random.Random(5))
    assert op["operation"] == "withdraw" and op["amount"] == 10 * NANO


def test_below_half_the_set_point_always_deposits():
    # Transfers and withdrawals are feasible too; below half the set-point the choice is a deposit.
    notes = [{"index": i, "amount": 5 * NANO, "owner": i % 3} for i in range(4)]
    for seed in range(50):
        op = privacy.plan_operation(notes, 20 * NANO, BOOT, COSTS, SETPOINT, random.Random(seed))
        assert op["operation"] == "deposit", seed


def test_all_dust_deposits_when_affordable():
    dust = [{"index": i, "amount": 1, "owner": i % 3} for i in range(10)]
    op = privacy.plan_operation(dust, 10, BOOT, COSTS, SETPOINT, random.Random(6))
    assert op["operation"] == "deposit"


# A wallet that can pay transact gas but not the smallest deposit.
POOR = [3 * NANO // 2] * 3


def test_exhausted_no_funding():
    op = privacy.plan_operation([], 0, [NANO // 10] * 3, COSTS, SETPOINT, random.Random(7))
    assert op == {"exhausted": "no-funding"}


def test_exhausted_no_inputs():
    one = [{"index": 0, "amount": 5 * NANO, "owner": 0}]
    assert privacy.plan_operation(one, 5 * NANO, POOR, COSTS, SETPOINT, random.Random(8)) == {"exhausted": "no-inputs"}


def test_exhausted_no_private_value():
    dust = [{"index": i, "amount": 1, "owner": i % 3} for i in range(10)]
    op = privacy.plan_operation(dust, 10, POOR, COSTS, SETPOINT, random.Random(9))
    assert op == {"exhausted": "no-private-value"}


def test_roles_are_balance_aware_and_distinct():
    balances = [50 * NANO, 150 * NANO, 150 * NANO]  # a tie between 1 and 2 breaks by index
    notes = [{"index": i, "amount": 30 * NANO, "owner": i % 3} for i in range(4)]
    op = privacy.plan_operation(notes, 120 * NANO, balances, COSTS, SETPOINT, random.Random(10))
    assert op["operation"] == "withdraw"
    assert op["sender"] == 1 and op["recipient"] == 0


def test_gas_fee_matches_the_generators_formula():
    # local_pool_traffic.rs fee(): 667 + ceil((gas - 100) * 436907 / 65536)
    assert privacy.gas_fee(230_000) == 667 + -(-(229_900 * 436907) // 65536)
    assert privacy.gas_fee(100) == 667


# ------------------------------------------------------------ checkpoint resume

from pytosiq_core import begin_cell  # noqa: E402

POOL = "0:" + "ab" * 32
NETWORK = {"zerostate_root": "zz", "global_id": -239}
TX = begin_cell().store_uint(42, 32).end_cell()
TX_BOC = base64.b64encode(TX.to_boc()).decode()


def model():
    return {"zerostate_root": "zz", "pool": POOL, "state": {"notes": [], "liability": 0}, "expected": state()}


def legacy_row():
    # The shape of the stopped run's sequence-672 record, values replaced.
    return {"at": 1.0, "kind": "confirmed", "sequence": 672, "operation": "deposit",
            "counts": {"deposit": 281, "transfer": 241, "withdraw": 150}, "amount_nanotos": NANO,
            "elapsed_seconds": 20.6, "nodes_agree": 7, "expected": state(), "transaction_bocs": [TX_BOC, None]}


def new_row():
    return {**legacy_row(), "state_sha256": privacy.canonical_sha256(model()["state"]),
            "global_id": -239, "pool": POOL}


def resume(**override):
    args = dict(model=model(), row=legacy_row(), network=dict(NETWORK), address=POOL, recomputed=state(),
                onchain=state(), pool_last_tx_hash=TX.hash, pending=False)
    args.update(override)
    privacy.verify_checkpoint(**args)


def test_a_legacy_record_resumes_when_everything_agrees():
    resume()


def test_a_new_record_resumes_when_everything_agrees():
    resume(row=new_row())


@pytest.mark.parametrize("case", ["pending", "zerostate", "pool", "recomputed", "model", "onchain", "last_tx",
                                  "not_confirmed", "missing"])
def test_a_legacy_resume_refuses_each_mismatch(case):
    bad = {"pending": dict(pending=True),
           "zerostate": dict(network={**NETWORK, "zerostate_root": "other"}),
           "pool": dict(address="0:" + "cd" * 32),
           "recomputed": dict(recomputed={**state(), "commitment_root": "1"}),
           "model": dict(model={**model(), "expected": {**state(), "nullifier_root": "1"}}),
           "onchain": dict(onchain={**state(), "native_liability": 1}),
           "last_tx": dict(pool_last_tx_hash=b"\x00" * 32),
           "not_confirmed": dict(row={**legacy_row(), "kind": "failed"}),
           "missing": dict(row=None)}[case]
    with pytest.raises((ValueError, TypeError)):
        resume(**bad)


@pytest.mark.parametrize("case", ["state", "global_id", "pool"])
def test_a_new_record_resume_refuses_each_mismatch(case):
    row = new_row()
    row[{"state": "state_sha256", "global_id": "global_id", "pool": "pool"}[case]] = (
        "0" * 64 if case == "state" else (-1 if case == "global_id" else "0:" + "cd" * 32))
    with pytest.raises(ValueError):
        resume(row=row)


def test_last_confirmed_reads_the_newest_record(tmp_path):
    rows = [legacy_row(), {**legacy_row(), "sequence": 673}, {"kind": "failed", "error": "x"}]
    (tmp_path / "transfers.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert privacy.last_confirmed(tmp_path)["sequence"] == 673
