"""Tests for the bootstrap wallet's sweep and the owner-funded paths of
testnet-elections.py (sweep, top-up, record --block-boc, load --funding-owner), on
the fake chain with ConfigParam 5, the validator sets and the Elector's data in their
real layouts (chainbuild.py)."""

import argparse
import base64
import importlib.util
import json
from pathlib import Path

import chainbuild
import fakechain
import pytest
import testnet_lib as lib
from conftest import SCRIPTS
from fakechain import NANO

spec = importlib.util.spec_from_file_location(
    "testnet_elections_sweep", SCRIPTS / "testnet-elections.py"
)
elections = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elections)
ops = elections.ops

BOOT = elections.BOOTSTRAP_WALLET
BLACK = ops.BLACKHOLE
NAMES = ("node-1", "node-2", "node-3", "node-4")
GENESIS_T = 1_799_000_000


def pool_of(name):
    return "-1:" + bytes([0x50 + NAMES.index(name)]).hex() * 32


def operator_of(name):
    return "-1:" + bytes([0x60 + NAMES.index(name)]).hex() * 32


def owner_key(name):
    return bytes([0x70 + NAMES.index(name)]).hex() * 32


def owner_of(name):
    return fakechain.wallet_address(owner_key(name))


def pool_ids():
    return [pool_of(n).split(":")[1] for n in NAMES]


class Sweep:
    """A ceremony after onboarding and two elections, on a fake chain."""

    def __init__(self, tmp_path, monkeypatch):
        self.chain = chain = fakechain.Chain()
        chain.blackhole = BLACK
        chain.head_bounds_lt = True
        chain.config[5] = chainbuild.burning_config()
        self.ceremony = ceremony = tmp_path / "ceremony"
        (ceremony / "secret").mkdir(parents=True, mode=0o700)
        (ceremony / "pool-owners").mkdir()
        (ceremony / "genesis.json").write_text(
            json.dumps(
                {
                    "zero_state": chain.zero_state,
                    "main_wallet_public_key": "b0" * 32,
                    "source_date_epoch": GENESIS_T,
                }
            )
        )
        (ceremony / "secret" / "main-wallet.pk").write_bytes(b"\x01" * 32)
        (ceremony / "main-wallet.addr").write_bytes(
            bytes.fromhex("11" * 32) + (-1).to_bytes(4, "big", signed=True)
        )
        monkeypatch.setattr(ops, "BOOTSTRAP_CODE_HASH", fakechain.WALLET_CODE.hash().hex())
        monkeypatch.setattr(ops, "SETTLE_SECONDS", 60)
        chain.wallet(BOOT, 80_151 * NANO, public_key="b0" * 32, seqno=0)
        pools = {}
        for name in NAMES:
            pools[name] = {
                "pool": pool_of(name),
                "owner": owner_of(name),
                "operator": operator_of(name),
                "principal_sent": True,
            }
            chain.wallet(operator_of(name), 10 * NANO, public_key="6" + "0" * 63, subwallet=7)
            chain.wallet(owner_of(name), 5 * NANO, public_key=owner_key(name), subwallet=0x504F4F4C)
            paths = elections.pool_owner_paths(ceremony, name)
            paths["key"].write_bytes(b"\x02" * 32)
            paths["addr"].write_bytes(
                bytes.fromhex(owner_of(name).split(":")[1]) + (-1).to_bytes(4, "big", signed=True)
            )
        (ceremony / "pools.json").write_text(json.dumps(pools))
        # Every pool is a registered validator; the first two are the genesis set.
        records = [{"validator_id": pool_of(name).split(":")[1]} for name in NAMES]
        (ceremony / "genesis-records.json").write_text(json.dumps(records))
        (ceremony / "genesis-set.json").write_text(json.dumps(records[:2]))
        self.operations = ops.Operations(
            ceremony,
            [chain.node("http://a"), chain.node("http://b")],
            2,
            clock=lambda: chain.now,
            sleep=lambda s: chain.tick(),
        )
        journal = self.operations.journal
        for name in NAMES:
            for step, wallet in (
                ("fund-op", BOOT),
                ("fund-owner", BOOT),
                ("principal", owner_of(name)),
            ):
                journal.append(
                    f"{step}-{name}", {"state": "planned", "kind": "fund", "wallet": wallet}
                )
                journal.append(f"{step}-{name}", {"state": "settled"})
        self.first = chainbuild.validator_set(pool_ids(), GENESIS_T + 21600, GENESIS_T + 28800)
        self.second = chainbuild.validator_set(pool_ids(), GENESIS_T + 28800, GENESIS_T + 36000)
        self.members = {pid: (10_002 * NANO, False) for pid in pool_ids()}
        self.install()
        self.signed = []

        def sign(
            args,
            global_id,
            key,
            address_file,
            to,
            subwallet,
            seqno,
            amount,
            bounce,
            init=None,
            body=None,
            run=None,
            mode=3,
        ):
            self.signed.append({"to": to, "amount": amount, "bounce": bounce, "mode": mode})
            wallet = (
                f"{int.from_bytes(address_file[32:], 'big', signed=True)}:{address_file[:32].hex()}"
            )
            init_cell = lib.parse_boc(Path(init).read_bytes()) if init else None
            return fakechain.build_external(
                wallet,
                global_id,
                seqno,
                chain.now + 300,
                fakechain.internal_message(
                    to, elections.parse_tos(amount, "a") if amount != "0" else 0, bounce, init_cell
                ),
                mode=mode,
                subwallet=subwallet,
            )

        monkeypatch.setattr(elections, "sign_wallet_v3", sign)
        self.args = argparse.Namespace(
            ceremony=str(ceremony),
            tos_root=str(tmp_path / "tos"),
            fift="fift",
            rpc="http://a",
            id=elections.SWEEP_ID,
            dry_run=False,
        )

    def install(self, first=None, second=None, members=None, extra_past=None):
        """ConfigParam 32 and 34 and the Elector's results for them."""
        first = self.first if first is None else first
        second = self.second if second is None else second
        members = self.members if members is None else members
        self.chain.config[32] = first or None
        self.chain.config[34] = second
        past = [
            {"election_id": GENESIS_T + 21600, "set": self.first, "members": dict(members)},
            {"election_id": GENESIS_T + 28800, "set": self.second, "members": dict(members)},
        ] + (extra_past or [])
        elector = self.chain.account(elections.ELECTOR)
        elector.update(
            state="active", code=fakechain.WALLET_CODE, data=chainbuild.elector_data(past)
        )

    def burn_block(self, evidence):
        seqno = int(evidence["destination_block"]["seqno"])
        tx = next(
            t for t in self.chain.account(BLACK)["txs"] if int(t["transaction_id"]["lt"]) == seqno
        )
        boc = chainbuild.block(
            2,
            seqno,
            seqno,
            seqno,
            chainbuild.balanced_flow(evidence["burned_nanotos"]),
            {BLACK.split(":")[1]: {seqno: chainbuild.tx_cell(tx)}},
        )
        self.chain.blocks[seqno] = boc
        return boc


@pytest.fixture
def world(tmp_path, monkeypatch):
    return Sweep(tmp_path, monkeypatch)


def forget(w, name, steps=elections.ONBOARDING_STEPS):
    """Remove onboarding operations of `name` from the journal, as if never run."""
    for step in steps:
        w.operations.journal.path(f"{step}-{name}").unlink()


def without(w, name):
    """Both elected sets and the Elector's results without `name`'s pool."""
    keep = [pid for pid in pool_ids() if pid != pool_of(name).split(":")[1]]
    w.first = chainbuild.validator_set(keep, GENESIS_T + 21600, GENESIS_T + 28800)
    w.second = chainbuild.validator_set(keep, GENESIS_T + 28800, GENESIS_T + 36000)
    w.members = {pid: v for pid, v in w.members.items() if pid in keep}
    w.install()


def run_sweep(world, **changes):
    args = argparse.Namespace(**dict(vars(world.args), **changes))
    return elections.sweep(args, world.operations, 2)


# ---------------------------------------------------------------- prerequisites


def test_the_sweep_prerequisites_hold_after_two_elections(world):
    found = elections.sweep_prerequisites(world.args, world.operations)
    assert found["config_param_5"] == {"blackhole": BLACK, "fee_burn": [0, 1]}
    sets = found["elected_sets"]
    assert sets["config_param_32"]["set_hash"] == world.first.hash().hex()
    assert sets["config_param_34"]["set_hash"] == world.second.hash().hex()
    assert set(sets["config_param_34"]["stakes_nanotos"]) == set(pool_ids())
    assert found["operator_floor_nanotos"] == elections.FIRST_RECOVERY_NANOTOS + NANO


def damage_config5_absent(w):
    w.chain.config[5] = None


def damage_blackhole_elsewhere(w):
    w.chain.config[5] = chainbuild.burning_config(blackhole="ee" * 32)


def damage_no_blackhole(w):
    w.chain.config[5] = chainbuild.burning_config(blackhole=None)


def damage_fee_burn(w):
    w.chain.config[5] = chainbuild.burning_config(num=1, denom=2)


def damage_second_set_missing(w):
    # Only the first election has installed its set: ConfigParam 32 is empty.
    w.install(first=False, second=w.first)


def damage_previous_is_the_genesis_set(w):
    genesis = chainbuild.validator_set(pool_ids(), GENESIS_T, GENESIS_T + 21600)
    w.install(first=genesis)


def damage_set_misses_a_pool(w):
    other = chainbuild.validator_set(
        pool_ids()[:3] + ["99" * 32], GENESIS_T + 28800, GENESIS_T + 36000
    )
    w.second = other
    w.install()


def damage_stake_missing(w):
    w.install(members={pid: v for pid, v in w.members.items() if pid != pool_ids()[2]})


def damage_stake_banned(w):
    w.install(members=dict(w.members, **{pool_ids()[1]: (10_002 * NANO, True)}))


def damage_two_results_for_one_set(w):
    # Two Elector results committing to the same set: which election it was is unknown.
    w.install(extra_past=[{"election_id": GENESIS_T + 99, "set": w.second, "members": w.members}])


def damage_sets_out_of_order(w):
    w.install(first=w.second, second=w.first)


def damage_operator_below_floor(w):
    w.chain.account(operator_of("node-3"))["balance"] = elections.FIRST_RECOVERY_NANOTOS + NANO - 1


def damage_onboarding_open(w):
    w.operations.journal.append(
        "principal-node-2.attempt-2",
        {"state": "planned", "kind": "fund", "wallet": owner_of("node-2")},
    )


def damage_bootstrap_operation_open(w):
    w.operations.journal.append("fund-extra", {"state": "signed", "kind": "fund", "wallet": BOOT})


def damage_three_pools(w):
    pools = json.loads((w.ceremony / "pools.json").read_text())
    del pools["node-4"]
    (w.ceremony / "pools.json").write_text(json.dumps(pools))


def damage_an_unregistered_pool(w):
    # The same count, but one pool is no registered validator.
    pools = json.loads((w.ceremony / "pools.json").read_text())
    pools["node-4"]["pool"] = "-1:" + "cd" * 32
    (w.ceremony / "pools.json").write_text(json.dumps(pools))


def damage_a_team_pool_unrecorded(w):
    pools = json.loads((w.ceremony / "pools.json").read_text())
    del pools["node-1"]
    (w.ceremony / "pools.json").write_text(json.dumps(pools))


def damage_a_foreign_validator(w):
    # Every funded pool stands, and one more validator no registered pool names.
    w.second = chainbuild.validator_set(
        pool_ids() + ["99" * 32], GENESIS_T + 28800, GENESIS_T + 36000
    )
    w.install()


def damage_external_half_onboarded(w):
    # An external pool was funded but its principal never reached the pool.
    forget(w, "node-4", ("principal",))


@pytest.mark.parametrize(
    "damage, message",
    [
        (damage_config5_absent, "ConfigParam 5"),
        (damage_blackhole_elsewhere, "names blackhole"),
        (damage_no_blackhole, "names blackhole None"),
        (damage_fee_burn, "burns 1/2"),
        (damage_second_set_missing, "ConfigParam 32 is not an installed validator set"),
        (damage_previous_is_the_genesis_set, "no single Elector result"),
        (damage_set_misses_a_pool, r"lacks the pools of \['node-4'\].*sweep --exclude"),
        (damage_stake_missing, "no frozen, unbanned stake"),
        (damage_stake_banned, "no frozen, unbanned stake"),
        (damage_two_results_for_one_set, "no single Elector result"),
        (damage_sets_out_of_order, "not older"),
        (damage_operator_below_floor, "first recovery"),
        (damage_onboarding_open, "principal-node-2.attempt-2 is not settled"),
        (damage_bootstrap_operation_open, "fund-extra is open"),
        (damage_three_pools, "holds validators no funded registered pool names"),
        (damage_an_unregistered_pool, "which genesis-records.json does not register"),
        (damage_a_team_pool_unrecorded, "records no pool for genesis validators"),
        (damage_a_foreign_validator, "holds validators no funded registered pool names"),
        (damage_external_half_onboarded, "principal-node-4 is not settled.*sweep --exclude node-4"),
    ],
)
def test_a_sweep_waits_for_every_prerequisite(world, damage, message):
    damage(world)
    with pytest.raises(lib.TestnetError, match=message):
        elections.sweep_prerequisites(world.args, world.operations)
    for dry_run in (True, False):
        with pytest.raises(lib.TestnetError):
            run_sweep(world, dry_run=dry_run)
    assert world.signed == [] and world.chain.sent == []


def test_each_prerequisite_is_read_on_both_validators(world, monkeypatch):
    # One validator serves other Elector results: the two disagree.
    real = world.operations.nodes[1].rpc
    other = chainbuild.elector_data(
        [
            {"election_id": GENESIS_T + 21600, "set": world.first, "members": world.members},
            {
                "election_id": GENESIS_T + 28800,
                "set": world.second,
                "members": {pid: (10_003 * NANO, False) for pid in pool_ids()},
            },
        ]
    )

    def lagging(url, method, /, **params):
        answer = real(url, method, **params)
        if method == "getAddressInformation" and params["address"] == elections.ELECTOR:
            answer = dict(answer, data=base64.b64encode(lib.serialize_boc(other)).decode())
        return answer

    monkeypatch.setattr(world.operations.nodes[1], "rpc", lagging)
    with pytest.raises(ops.Unknown, match="disagree"):
        elections.sweep_prerequisites(world.args, world.operations)


# ---------------------------------------------------------------- dry run, sweep, record


def test_the_dry_run_checks_everything_and_signs_nothing(world, capsys):
    report = run_sweep(world, dry_run=True)
    assert report["signed"] is False and world.signed == [] and world.chain.sent == []
    assert not world.operations.journal.path(elections.SWEEP_ID).exists()
    transfer = report["transfer"]
    assert (transfer["mode"], transfer["value"], transfer["bounce"]) == (160, 0, False)
    assert transfer["destination"] == BLACK and transfer["seqno"] == 0
    assert report["burns_at_most_nanotos"] == 80_151 * NANO
    assert "only by the coordinator" in report["assumption"]
    assert json.loads(capsys.readouterr().out)["dry_run"] is True


def test_the_sweep_signs_mode_160_and_settles_with_its_burn_block(world, tmp_path):
    with pytest.raises(ops.OperationRefused, match="fetch block"):
        run_sweep(world)
    assert world.signed == [{"to": BLACK, "amount": "0", "bounce": False, "mode": 160}]
    record = world.operations.journal.record(elections.SWEEP_ID)
    _, evidence = world.operations.settle(record)
    block = tmp_path / "burn-block.boc"
    block.write_bytes(world.burn_block(evidence))
    record_args = argparse.Namespace(
        **dict(
            vars(world.args),
            command="record",
            id=elections.SWEEP_ID,
            settled=True,
            failed=None,
            abandoned=False,
            checkpoint=False,
            hint=evidence["wallet_tx"],
            block_boc=block,
        )
    )
    elections.manual(record_args, world.operations)
    settled = world.operations.journal.record(elections.SWEEP_ID)
    assert settled["state"] == "settled"
    assert settled["evidence"]["burn"]["value_flow"]["burned"] == evidence["burned_nanotos"]
    assert world.chain.account(BOOT)["deleted"]
    # Asking again reports the settled sweep; another id is refused.
    assert run_sweep(world)["state"] == "settled"
    with pytest.raises(lib.TestnetError, match="already swept"):
        run_sweep(world, id="sweep-two")


def test_record_without_the_block_leaves_the_sweep_open(world):
    with pytest.raises(ops.OperationRefused):
        run_sweep(world)
    record = world.operations.journal.record(elections.SWEEP_ID)
    _, evidence = world.operations.settle(record)
    with pytest.raises(ops.OperationRefused, match="not settled"):
        world.operations.record_settled(elections.SWEEP_ID, evidence["wallet_tx"])
    assert world.operations.journal.record(elections.SWEEP_ID)["state"] == "broadcast"


def test_a_block_file_is_only_for_a_sweep(world, tmp_path):
    world.operations.journal.append("fund-x", {"state": "signed", "kind": "fund", "wallet": BOOT})
    args = argparse.Namespace(
        **dict(
            vars(world.args),
            command="record",
            id="fund-x",
            settled=True,
            failed=None,
            abandoned=False,
            checkpoint=False,
            hint="00",
            block_boc=tmp_path / "x",
        )
    )
    with pytest.raises(lib.TestnetError, match="not a sweep"):
        elections.manual(args, world.operations)


def swept(world, tmp_path):
    with pytest.raises(ops.OperationRefused):
        run_sweep(world)
    record = world.operations.journal.record(elections.SWEEP_ID)
    _, evidence = world.operations.settle(record)
    world.operations.record_settled(
        elections.SWEEP_ID, evidence["wallet_tx"], ops.burn_expect(world.burn_block(evidence))
    )


@pytest.mark.parametrize("dry_run", [True, False])
def test_fund_is_refused_after_the_sweep_even_as_a_dry_run(world, tmp_path, dry_run):
    swept(world, tmp_path)
    signed = len(world.signed)
    args = argparse.Namespace(
        **dict(
            vars(world.args),
            to=operator_of("node-1"),
            amount="1",
            label="late",
            op_id=None,
            dry_run=dry_run,
        )
    )
    with pytest.raises(lib.TestnetError, match="has been swept"):
        elections.fund(args, world.operations, 2)
    assert len(world.signed) == signed


# ---------------------------------------------------------------- owner-funded paths


def top_up_args(world, **changes):
    base = dict(
        vars(world.args), name="node-1", id="top-up-node-1-1", new=True, amount="2", dry_run=False
    )
    base.update(changes)
    return argparse.Namespace(**base)


def test_a_top_up_after_the_sweep_comes_from_the_pool_owner(world, tmp_path):
    swept(world, tmp_path)
    before = world.chain.account(operator_of("node-1"))["balance"]
    assert elections.top_up(top_up_args(world, dry_run=True), world.operations, 2) == {
        "dry_run": True
    }
    assert not world.operations.journal.path("top-up-node-1-1").exists()
    result = elections.top_up(top_up_args(world), world.operations, 2)
    record = world.operations.journal.record("top-up-node-1-1")
    assert record["kind"] == "owner-fund" and record["wallet"] == owner_of("node-1")
    assert record["bounce"] is False and record["state"] == "settled"
    assert world.signed[-1] == {
        "to": operator_of("node-1"),
        "amount": "2.000000000",
        "bounce": False,
        "mode": 3,
    }
    assert world.chain.account(operator_of("node-1"))["balance"] == before + 2 * NANO
    assert result["operator_tx"] == record["evidence"]["destination_tx"]
    # The same id reports, never funds twice; --new on it is refused.
    elections.top_up(top_up_args(world, new=False), world.operations, 2)
    assert world.chain.account(operator_of("node-1"))["balance"] == before + 2 * NANO
    with pytest.raises(lib.TestnetError, match="exists"):
        elections.top_up(top_up_args(world), world.operations, 2)


@pytest.mark.parametrize(
    "change, message",
    [
        ({"amount": "0"}, "positive"),
        ({"amount": "4"}, "cannot pay"),  # 5 TOS: 4 + a 1 TOS withdrawal message + fee
        ({"name": "node-9"}, "records no pool"),
        ({"new": False}, "create a top-up with --new"),
    ],
)
def test_a_top_up_is_refused_before_signing(world, change, message):
    for dry_run in (True, False):
        with pytest.raises(lib.TestnetError, match=message):
            elections.top_up(top_up_args(world, dry_run=dry_run, **change), world.operations, 2)
    assert world.signed == []


def test_a_top_up_needs_an_active_operator_wallet(world):
    world.chain.account(operator_of("node-1"))["state"] = "uninit"
    with pytest.raises(lib.TestnetError, match="not active"):
        elections.top_up(top_up_args(world), world.operations, 2)
    assert world.signed == []


def test_load_is_funded_by_the_owner_never_the_bootstrap_wallet(world, monkeypatch):
    calls = []
    monkeypatch.setattr(elections, "owner_transfer", lambda *a, **kw: calls.append((a, kw)))
    args = argparse.Namespace(
        **dict(vars(world.args), state=str(world.ceremony / "state"), funding_owner="node-2")
    )
    driver = object.__new__(elections.LoadDriver)
    driver.args, driver.operations, driver.global_id = args, world.operations, 2
    driver.fund_from_owner("0:" + "46" * 32, 4 * NANO, "load-wallet", None)
    ((a, kw),) = calls
    assert a[3] == "node-2" and a[5] == "owner-fund" and a[7] == 4 * NANO
    assert kw["bounce"] is False
    assert BOOT not in json.dumps([list(map(str, a)), {k: str(v) for k, v in kw.items()}])
    # Its prerequisite keeps the owner's withdrawal money: 5 TOS cannot pay 5 more.
    with pytest.raises(lib.TestnetError, match="cannot pay"):
        a[9]()
    calls.clear()
    driver.fund_from_owner("0:" + "46" * 32, 2 * NANO, "load-wallet", None)
    calls[0][0][9]()


def test_load_stops_when_the_funding_owner_runs_low(world, monkeypatch):
    args = argparse.Namespace(
        **dict(
            vars(world.args),
            state=str(world.ceremony / "state"),
            funding_owner="node-2",
            owner_floor="100",
            watch_rpc=[],
            wallet_floor="0.000000001",
            relayer_floor="0.000000001",
        )
    )
    driver = object.__new__(elections.LoadDriver)
    driver.args, driver.operations, driver.global_id = args, world.operations, 2
    driver.refill_error = None
    driver.chain = elections.Chain("http://a", world.chain.node("http://a").rpc)
    monkeypatch.setattr(elections, "head_age", lambda chain: 0)
    reason = driver.check_safety(operator_of("node-1"), [])
    assert reason and "funding owner" in reason
    args.owner_floor = "1"
    assert driver.check_safety(operator_of("node-1"), []) is None


def test_the_sweep_mode_reaches_the_wallet_script(tmp_path):
    seen = []

    def fake_run(argv, cwd, capture_output, text):
        seen.append(argv)
        (Path(cwd) / "query.boc").write_bytes(b"boc")
        return argparse.Namespace(returncode=0, stdout="", stderr="")

    key = tmp_path / "k.pk"
    key.write_bytes(b"\x01" * 32)
    args = argparse.Namespace(tos_root=str(tmp_path), fift="fift")
    import importlib

    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    fresh.sign_wallet_v3(args, 2, key, b"a" * 36, BLACK, 0, 3, "0", False, run=fake_run, mode=160)
    fresh.sign_wallet_v3(args, 2, key, b"a" * 36, BLACK, 0, 3, "1", False, run=fake_run)
    sweep_argv, plain_argv = seen
    assert sweep_argv[sweep_argv.index("-m") + 1] == "160" and "-n" in sweep_argv
    assert sweep_argv[sweep_argv.index("signer") + 4] == "0"
    assert "-m" not in plain_argv


# ---------------------------------------------------------------- owner-fund to a named destination

PRI = "0:" + "a1" * 32


def owner_fund_args(world, **changes):
    base = dict(
        vars(world.args),
        name="node-1",
        id="pri-e6-sender-b",
        new=True,
        to=PRI,
        amount="2",
        purpose="pri e6 sender-b",
        dry_run=False,
    )
    base.update(changes)
    return argparse.Namespace(**base)


def test_an_owner_funds_a_named_undeployed_wallet(world):
    before = world.chain.account(owner_of("node-1"))["balance"]
    assert elections.owner_fund(owner_fund_args(world, dry_run=True), world.operations, 2) == {
        "dry_run": True
    }
    assert not world.operations.journal.path("pri-e6-sender-b").exists()
    assert world.signed == []
    result = elections.owner_fund(owner_fund_args(world), world.operations, 2)
    record = world.operations.journal.record("pri-e6-sender-b")
    assert record["kind"] == "owner-fund" and record["wallet"] == owner_of("node-1")
    assert record["destination"] == PRI and record["value"] == 2 * NANO
    assert record["purpose"] == "pri e6 sender-b" and record["label"] == "owner-fund-node-1"
    assert record["bounce"] is False and record["state"] == "settled"
    assert world.signed == [{"to": PRI, "amount": "2.000000000", "bounce": False, "mode": 3}]
    assert world.chain.account(PRI)["balance"] == 2 * NANO
    assert world.chain.account(owner_of("node-1"))["balance"] < before - 2 * NANO
    assert result["destination_tx"] == record["evidence"]["destination_tx"]
    # The same id reports and never funds twice; --new on it is refused.
    elections.owner_fund(owner_fund_args(world, new=False), world.operations, 2)
    assert world.chain.account(PRI)["balance"] == 2 * NANO and len(world.signed) == 1
    with pytest.raises(lib.TestnetError, match="exists"):
        elections.owner_fund(owner_fund_args(world), world.operations, 2)
    # Another transfer under the same id is refused, not merged.
    with pytest.raises(lib.TestnetError, match="another transfer"):
        elections.owner_fund(owner_fund_args(world, new=False, amount="3"), world.operations, 2)


@pytest.mark.parametrize(
    "change, message",
    [
        ({"amount": "0"}, "positive"),
        ({"amount": "-1"}, "TOS|positive|amount"),
        ({"amount": "4"}, "cannot pay"),  # 5 TOS: 4 + a 1 TOS withdrawal message + fee
        # 3.9 + this transfer's 0.1 fee + the 1.1 TOS withdrawal reserve > 5 TOS.
        ({"amount": "3.9"}, "cannot pay"),
        ({"to": PRI + "\n"}, "not a raw"),
        ({"to": owner_of("node-1")}, "node-1's owner"),
        ({"to": owner_of("node-2")}, "node-2's owner"),
        ({"to": pool_of("node-1")}, "node-1's pool"),
        ({"to": BLACK}, "the blackhole"),
        ({"to": elections.ELECTOR}, "the Elector"),
        ({"to": operator_of("node-1")}, "not a workchain-0 address"),
        ({"to": "0:12"}, "not a raw"),
        ({"purpose": ""}, "--purpose"),
        ({"purpose": "Bad\nlabel"}, "--purpose"),
        ({"name": "node-9"}, "records no pool"),
        ({"id": "../x"}, "not an operation id"),
        ({"new": False}, "create a transfer with --new"),
    ],
)
def test_an_owner_fund_is_refused_before_signing_and_leaves_no_record(world, change, message):
    for dry_run in (True, False):
        with pytest.raises(lib.TestnetError, match=message):
            elections.owner_fund(
                owner_fund_args(world, dry_run=dry_run, **change), world.operations, 2
            )
    assert world.signed == []
    assert not world.operations.journal.path("pri-e6-sender-b").exists()
    # Nothing is left open: the owner's other operations still run.
    elections.top_up(top_up_args(world), world.operations, 2)
    assert world.operations.journal.record("top-up-node-1-1")["state"] == "settled"


def test_an_owner_fund_is_refused_while_another_operation_of_the_owner_is_open(world):
    world.operations.journal.append(
        "withdraw-node-1-x", {"state": "signed", "kind": "withdraw", "wallet": owner_of("node-1")}
    )
    with pytest.raises(lib.TestnetError, match="withdraw-node-1-x"):
        elections.owner_fund(owner_fund_args(world), world.operations, 2)
    assert world.signed == []
    assert not world.operations.journal.path("pri-e6-sender-b").exists()


def test_an_owner_fund_with_an_unknown_outcome_is_reconciled_never_resent(world, monkeypatch):
    def lost(boc):
        raise lib.TestnetError("connection reset after the request was written")

    monkeypatch.setattr(world.chain, "send", lost)
    with pytest.raises(lib.TestnetError):
        elections.owner_fund(owner_fund_args(world), world.operations, 2)
    record = world.operations.journal.record("pri-e6-sender-b")
    assert record["state"] == "signed" and record.get("external_hash")
    assert len(world.signed) == 1
    # Running it again neither signs nor sends: the open record sends the operator to reconcile.
    with pytest.raises(lib.TestnetError, match="reconcile"):
        elections.owner_fund(owner_fund_args(world, new=False), world.operations, 2)
    assert len(world.signed) == 1
    # It also fences every other operation of the owner.
    with pytest.raises(lib.TestnetError, match="pri-e6-sender-b"):
        elections.top_up(top_up_args(world), world.operations, 2)
    # And it cannot be abandoned: a signed copy exists.
    with pytest.raises(lib.TestnetError, match="unsigned planned"):
        world.operations.record_abandoned("pri-e6-sender-b")
    assert world.chain.account(PRI)["balance"] == 0


# ---------------------------------------------------------------- external validators that did not stand


def test_a_registered_external_never_funded_is_listed_and_its_allocation_burned(world):
    # node-4 registered at genesis, was never onboarded and never stood.
    forget(world, "node-4")
    without(world, "node-4")
    found = elections.sweep_prerequisites(world.args, world.operations)
    assert found["stood"] == ["node-1", "node-2", "node-3"]
    assert found["not_onboarded"] == ["node-4"] and found["excluded"] == {}
    report = run_sweep(world, dry_run=True)
    assert report["prerequisites"]["not_onboarded"] == ["node-4"]
    # The whole remaining balance, node-4's allocation with it, is burned.
    assert report["burns_at_most_nanotos"] == world.chain.account(BOOT)["balance"]
    with pytest.raises(ops.OperationRefused, match="fetch block"):
        run_sweep(world)
    assert world.signed == [{"to": BLACK, "amount": "0", "bounce": False, "mode": 160}]


def test_a_registered_validator_without_a_pool_is_not_onboarded(world):
    path = world.ceremony / "genesis-records.json"
    path.write_text(json.dumps(json.loads(path.read_text()) + [{"validator_id": "ce" * 32}]))
    found = elections.sweep_prerequisites(world.args, world.operations)
    assert found["not_onboarded"] == ["validator id " + "ce" * 8 + " (no pool recorded)"]


def test_a_funded_external_that_never_stood_refuses_until_excluded(world):
    without(world, "node-4")
    with pytest.raises(lib.TestnetError, match=r"lacks the pools of \['node-4'\]"):
        run_sweep(world)
    assert world.signed == []
    # A dry run checks the exclusion and records nothing.
    report = run_sweep(world, dry_run=True, exclude=["node-4"], reason="host never came up")
    assert report["prerequisites"]["excluded"] == {"node-4": "host never came up"}
    assert not world.operations.journal.path("sweep-exclude-node-4").exists()
    with pytest.raises(ops.OperationRefused, match="fetch block"):
        run_sweep(world, exclude=["node-4"], reason="host never came up")
    record = world.operations.journal.record("sweep-exclude-node-4")
    assert record["state"] == "settled" and record["kind"] == elections.SWEEP_EXCLUSION_KIND
    assert record["pool"] == pool_of("node-4") and record["reason"] == "host never came up"
    assert "withdrawn later" in record["note"]
    assert world.signed == [{"to": BLACK, "amount": "0", "bounce": False, "mode": 160}]
    # Later checks honor the recorded exclusion without --exclude.
    found = elections.sweep_prerequisites(world.args, world.operations)
    assert found["excluded"] == {"node-4": "host never came up"}


def test_a_half_onboarded_external_can_be_excluded(world):
    forget(world, "node-4", ("principal",))
    without(world, "node-4")
    found = elections.sweep_prerequisites(world.args, world.operations, {"node-4": "no principal"})
    assert found["stood"] == ["node-1", "node-2", "node-3"]
    assert found["excluded"] == {"node-4": "no principal"}


def test_an_excluded_pool_may_still_be_in_a_set(world):
    found = elections.sweep_prerequisites(world.args, world.operations, {"node-4": "late"})
    assert "node-4" not in found["stood"] and found["excluded"] == {"node-4": "late"}


@pytest.mark.parametrize(
    "exclude, reason, message",
    [
        (["node-1"], "down", "team pool: a genesis validator is never excluded"),
        (["node-4"], None, "--exclude needs --reason"),
        (["node-4"], "  ", "--exclude needs --reason"),
        ([], "why", "--reason goes with --exclude"),
        (["node 4"], "why", "not a node name"),
    ],
)
def test_an_exclusion_is_refused_unless_it_is_well_formed(world, exclude, reason, message):
    without(world, "node-1")
    with pytest.raises(lib.TestnetError, match=message):
        run_sweep(world, exclude=exclude, reason=reason)
    assert world.signed == []
    assert not world.operations.journal.path("sweep-exclude-node-1").exists()


def test_a_never_funded_external_needs_no_exclusion(world):
    forget(world, "node-4")
    without(world, "node-4")
    with pytest.raises(lib.TestnetError, match="never funded: it needs no exclusion"):
        run_sweep(world, exclude=["node-4"], reason="gone")
    assert not world.operations.journal.path("sweep-exclude-node-4").exists()


def test_an_exclusion_is_not_recorded_while_another_prerequisite_fails(world):
    without(world, "node-4")
    world.chain.config[5] = None
    with pytest.raises(lib.TestnetError, match="ConfigParam 5"):
        run_sweep(world, exclude=["node-4"], reason="host never came up")
    assert not world.operations.journal.path("sweep-exclude-node-4").exists()
    assert world.signed == []


@pytest.mark.parametrize("dry_run", [True, False])
def test_an_exclusion_of_a_name_without_a_pool_is_refused_up_front(world, dry_run):
    without(world, "node-4")
    with pytest.raises(lib.TestnetError, match="node-9 has no pool in pools.json"):
        run_sweep(world, dry_run=dry_run, exclude=["node-9"], reason="unknown")
    assert world.signed == [] and world.chain.sent == []
    assert not world.operations.journal.path("sweep-exclude-node-9").exists()
