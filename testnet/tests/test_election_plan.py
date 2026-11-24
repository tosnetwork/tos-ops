"""Tests for the December 5 network configuration: a genesis set of the team's two
validators, up to 19 external validators from the first election, and the stake,
weight and funding plan testnet_lib.election_plan derives from the number of
external validators (E).

The Elector arithmetic is checked against a direct reading of elector-code.fc
(process_new_stake keeps 1 TOS of each order; try_elect caps each stake at
max_factor x the smallest elected stake and weighs it by (stake << 60) / total).
"""

import copy
import json
import os
from fractions import Fraction
from pathlib import Path

import pytest
import testnet_lib as lib
from conftest import SCRIPTS

NANO = 10**9
PROFILE_PATH = SCRIPTS.parent / "network" / "profile.json"
PRODUCTION = SCRIPTS.parent / "network" / "profile-production-timing.json"


def profile():
    return copy.deepcopy(lib.load_profile())


def planned(external, base=None):
    """The repository profile with the ceremony's values for `external` set."""
    p = copy.deepcopy(base or lib.load_profile())
    plan = lib.election_plan(p, external=external)
    p["elections"]["external_validators"] = external
    p["elections"]["team_stake_multiple"] = plan["team_stake_multiple"]
    p["elections"]["bootstrap_wallet_tos"] = plan["bootstrap_wallet_tos"]
    p["genesis"]["total_supply_tos"] = plan["total_supply_tos"]
    return p


def wide_tosctl(monkeypatch):
    """A tosctl that accepts a max factor of 10, as ConfigParam 17 does."""
    monkeypatch.setattr(lib, "TOSCTL_MAX_FACTOR", Fraction(10))
    p = profile()
    p["elections"]["max_factor"] = "10.0"
    return p


def expected_bootstrap(p, external):
    """The bootstrap wallet, summed here independently of election_plan."""
    e = p["elections"]
    unit = e["stake_tos"]
    multiple = max(Fraction(1), Fraction(external, 2))
    team_principal = e["pool_tos"] + 2 * (int(multiple * unit) - unit)
    owner_extra = e["pool_owner_reserve_tos"] + e["pool_deploy_tos"]
    team = 2 * (e["operator_funding_tos"] + team_principal + owner_extra)
    others = external * (e["operator_funding_tos"] + e["pool_tos"] + owner_extra)
    transfers = 2 * (2 + external) + 1
    fees = -(-transfers * e["bootstrap_transfer_fee_nanotos"] // NANO)
    return team + others + e["bootstrap_margin_tos"] + fees


# ---------------------------------------------------------------- the repository profile


def test_the_repository_profile_is_the_decided_configuration():
    p = lib.load_profile()
    g, e = p["genesis"], p["elections"]
    assert g["validators"] == 2
    assert g["validator_num"] == {
        "max_validators": 21,
        "max_main_validators": 21,
        "min_validators": 2,
    }
    assert g["stake_limits"] == {
        "min_stake_tos": 10000,
        "max_stake_tos": 10000000,
        "min_total_stake_tos": 20000,
        "max_factor": 10,
    }
    assert e["max_external_validators"] == 19 and e["team_weight_percent"] == 50
    assert e["max_factor"] == "3.0" and e["stake_tos"] == 10002
    # The ceremony sets these once registration closes.
    for value in (
        e["external_validators"],
        e["team_stake_multiple"],
        e["bootstrap_wallet_tos"],
        g["total_supply_tos"],
    ):
        assert value is None
    assert lib.election_plan(p, required=False) is None
    with pytest.raises(lib.TestnetError, match="external_validators is not set"):
        lib.election_plan(p)
    with pytest.raises(lib.TestnetError, match="positive whole number"):
        lib.genesis_supply_targets(p)
    assert "four hosts" not in p["status_note"] and "Epoch 8 is" not in p["status_note"]


def test_the_production_timing_profile_differs_only_in_its_schedule():
    a, b = json.loads(PROFILE_PATH.read_text()), json.loads(PRODUCTION.read_text())
    for p in (a, b):
        for key in ("status", "status_note"):
            p.pop(key)
        for key in ("election_params", "initial_set_valid_for_seconds", "schedule_note"):
            p["genesis"].pop(key)
    assert a == b
    lib.load_profile(PRODUCTION)


# ---------------------------------------------------------------- the plan, E = 0, 1, 5, 19


def test_no_external_validator_leaves_the_team_alone():
    plan = lib.election_plan(profile(), external=0)
    assert plan["team_stake_multiple"] == "1" and plan["team_stake_tos"] == 10002
    assert plan["team_pool_principal_tos"] == 20010
    assert plan["bootstrap_transfers"] == 5 and plan["bootstrap_transfer_fees_tos"] == 1
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(profile(), 0) == 40105
    assert plan["total_supply_tos"] == 41105
    assert plan["team_weight_percent"] == 100


def test_one_external_validator_leaves_the_team_at_exactly_two_thirds():
    # The Elector's minimum keeps the team at one unit each: 2 of 3 units is two
    # thirds, which is not more than two thirds, so neither side finalizes alone.
    plan = lib.election_plan(profile(), external=1)
    assert plan["team_stake_multiple"] == "1"
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(profile(), 1) == 60132
    assert Fraction(plan["team_weight_percent"]).limit_denominator(1000) == Fraction(200, 3)


def test_five_external_validators_give_the_team_half_the_weight():
    plan = lib.election_plan(profile(), external=5)
    assert plan["team_stake_multiple"] == "2.5" and plan["team_stake_tos"] == 25005
    assert plan["team_pool_principal_tos"] == 20010 + 2 * 15003 == 50016
    assert plan["team_owner_funding_tos"] == 50016 + 5 + 2
    assert plan["external_owner_funding_tos"] == 20010 + 5 + 2
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(profile(), 5) == 200252
    assert abs(plan["team_weight_percent"] - 50) < 0.01


def test_nineteen_external_validators_need_a_tosctl_that_allows_the_team_multiple():
    # tosctl's election task allows a max factor of at most 3.0: a 9.5-unit team
    # stake would count as 3 units and the external validators would hold the chain.
    with pytest.raises(lib.TestnetError, match="tosctl's election task at most 3.0"):
        lib.election_plan(profile(), external=19)


def test_nineteen_external_validators_with_max_factor_10(monkeypatch):
    p = wide_tosctl(monkeypatch)
    plan = lib.election_plan(p, external=19)
    assert plan["team_stake_multiple"] == "9.5" and plan["team_stake_tos"] == 95019
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(p, 19)
    assert abs(plan["team_weight_percent"] - 50) < 0.01
    with pytest.raises(lib.TestnetError, match="exceed the 19 seats"):
        lib.election_plan(p, external=20)


@pytest.mark.parametrize("external", range(0, 6))
def test_every_e_the_current_tosctl_allows_is_planned(external):
    plan = lib.election_plan(profile(), external=external)
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(profile(), external)


@pytest.mark.parametrize("external", range(6, 20))
def test_every_e_above_five_waits_for_tosctl(external, monkeypatch):
    with pytest.raises(lib.TestnetError, match="max factor of 3.0"):
        lib.election_plan(profile(), external=external)
    # With tosctl at 10 the same E is planned at 50 %.
    plan = lib.election_plan(wide_tosctl(monkeypatch), external=external)
    assert abs(plan["team_weight_percent"] - 50) < 0.01


# ---------------------------------------------------------------- the weights, as the Elector sets them


def weights(p, external):
    """Team and external weight from the Elector simulation, as election_plan uses it."""
    limits = lib.genesis_limits(p)
    plan = lib.election_plan(p, external=external)
    f = int(lib.tosctl_max_factor(p) * lib.MAX_FACTOR_ONE)
    team = [("team-%d" % i, plan["team_stake_tos"] * NANO - NANO, f) for i in range(2)]
    others = [("ext-%d" % i, plan["unit_stake_tos"] * NANO - NANO, f) for i in range(external)]
    elected, why = lib.simulate_election(team + others, limits)
    assert elected is not None, why
    team_w = sum(m["weight"] for m in elected if m["label"].startswith("team"))
    total = sum(m["weight"] for m in elected)
    return team_w, total - team_w, total, len(elected)


@pytest.mark.parametrize("external", [1, 2, 3, 4, 5])
def test_neither_side_alone_reaches_more_than_two_thirds(external):
    team, others, total, count = weights(profile(), external)
    assert count == 2 + external
    assert 3 * team <= 2 * total and 3 * others <= 2 * total
    # And the chain needs both: neither side's weight is above the finality cutoff.
    assert team < total and others < total


def test_the_team_alone_elects_itself_and_holds_everything():
    team, others, total, count = weights(profile(), 0)
    assert count == 2 and others == 0 and team == total


# ---------------------------------------------------------------- election limits


def test_the_template_min_total_stake_would_stall_a_team_only_election():
    p = profile()
    p["genesis"]["stake_limits"]["min_total_stake_tos"] = 40000
    # Two unit stakes of 10,001 TOS in the Elector: 20,002 < 40,000.
    with pytest.raises(lib.TestnetError, match="team pools alone .* below min_total_stake"):
        lib.election_plan(p, required=False)
    # 20,002 is the most a floor may be with E = 0.
    p["genesis"]["stake_limits"]["min_total_stake_tos"] = 20002
    lib.election_plan(p, external=0)
    p["genesis"]["stake_limits"]["min_total_stake_tos"] = 20003
    with pytest.raises(lib.TestnetError, match="below min_total_stake"):
        lib.election_plan(p, external=0)


def test_min_validators_above_the_genesis_set_is_refused():
    p = profile()
    p["genesis"]["validator_num"]["min_validators"] = 4
    with pytest.raises(lib.TestnetError, match="concludes an election"):
        lib.genesis_limits(p)


def test_a_config_param_17_max_factor_of_one_cuts_the_team_stake():
    p = profile()
    p["genesis"]["stake_limits"]["max_factor"] = 1
    lib.election_plan(p, external=2)  # one unit each: nothing to cut
    with pytest.raises(lib.TestnetError, match="counts at most 1.0 units"):
        lib.election_plan(p, external=3)


def test_a_tosctl_max_factor_outside_its_range_is_refused():
    p = profile()
    for value in ("10.0", "0.5", "three", 3):
        p["elections"]["max_factor"] = value
        with pytest.raises(lib.TestnetError, match="tosctl's election task refuses"):
            lib.election_plan(p, external=0)


def test_max_external_validators_is_the_seats_beside_the_genesis_set():
    p = profile()
    p["elections"]["max_external_validators"] = 20
    with pytest.raises(lib.TestnetError, match="less the genesis set's 2"):
        lib.election_plan(p, external=0)


def test_the_simulation_follows_the_elector_on_a_dropped_small_stake():
    limits = lib.genesis_limits(profile())
    one = lib.MAX_FACTOR_ONE
    # At max factor 1 a small stake drags every stake down to it; the Elector
    # leaves it out when the total is larger without it.
    members = [("a", 30_000 * NANO, one), ("b", 30_000 * NANO, one), ("c", 10_001 * NANO, one)]
    elected, _ = lib.simulate_election(members, limits)
    assert [m["label"] for m in elected] == ["a", "b"]
    # Below min_stake a stake is not a member at all.
    elected, why = lib.simulate_election([("a", 9_999 * NANO, one)] * 2, limits)
    assert elected is None and "min_total_stake" in why


# ---------------------------------------------------------------- the profile's ceremony values


def test_a_planned_profile_loads_and_any_wrong_value_refuses():
    p = planned(5)
    assert lib.election_plan(p)["external_validators"] == 5
    for section, key, value in (
        ("elections", "bootstrap_wallet_tos", 200251),
        ("elections", "team_stake_multiple", "2"),
        ("genesis", "total_supply_tos", 200252),
        ("elections", "external_validators", 4),
    ):
        wrong = copy.deepcopy(p)
        wrong[section][key] = value
        with pytest.raises(lib.TestnetError, match="is not"):
            lib.election_plan(wrong)


def test_ceremony_values_are_set_together():
    p = profile()
    p["elections"]["bootstrap_wallet_tos"] = 40105
    with pytest.raises(lib.TestnetError, match="sets them together"):
        lib.election_plan(p, required=False)


def test_load_profile_refuses_a_wrong_bootstrap_total(tmp_path):
    p = planned(2)
    p["elections"]["bootstrap_wallet_tos"] += 1
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(p))
    with pytest.raises(lib.TestnetError, match="bootstrap_wallet_tos"):
        lib.load_profile(path)


def test_pool_amounts_per_role():
    p = planned(4)
    team, other = lib.pool_amounts(p, True), lib.pool_amounts(p, False)
    assert team["stake"] == 20004 * NANO and team["principal"] == 40014 * NANO
    assert team["owner_funding"] == (40014 + 5 + 2) * NANO
    assert other["stake"] == 10002 * NANO and other["principal"] == 20010 * NANO
    assert other["owner_funding"] == (20010 + 5 + 2) * NANO
    # An external pool needs no plan; a team pool does.
    assert lib.pool_amounts(profile(), False) == other
    with pytest.raises(lib.TestnetError, match="external_validators is not set"):
        lib.pool_amounts(profile(), True)


def test_the_plan_command_writes_a_planned_copy(tmp_path, capsys):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "coordinator_plan", SCRIPTS / "testnet-coordinator.py"
    )
    coordinator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(coordinator)
    out = tmp_path / "planned.json"
    assert coordinator.main(["plan", "--external-validators", "3", "--write", str(out)]) == 0
    printed = json.loads(capsys.readouterr().out.split("\nwrote ")[0])
    assert printed["set_in_profile"] == {
        "elections.external_validators": 3,
        "elections.team_stake_multiple": "1.5",
        "elections.bootstrap_wallet_tos": expected_bootstrap(profile(), 3),
        "genesis.total_supply_tos": expected_bootstrap(profile(), 3) + 1000,
    }
    assert lib.election_plan(lib.load_profile(out))["team_stake_tos"] == 15003
    # Never overwritten, and an impossible E is refused.
    assert coordinator.main(["plan", "--external-validators", "3", "--write", str(out)]) == 1
    assert coordinator.main(["plan", "--external-validators", "7"]) == 1


# ---------------------------------------------------------------- the template patch


TEMPLATE_LINES = [
    "#!/usr/bin/create-state -s",
    lib.TEMPLATE_BOOTSTRAP_LINE,
    lib.TEMPLATE_VALIDATOR_NUM_LINE,
    lib.TEMPLATE_STAKE_LIMITS_LINE,
    "{ file>B",
    lib.TEMPLATE_MANIFEST_SIZE_LINE,
    "  {",
    "    17 swap register-validator",
    lib.TEMPLATE_MANIFEST_LOOP_LINE,
    lib.TEMPLATE_MANIFEST_END_LINE,
]
LIMITS = lib.genesis_limits(lib.load_profile())


def test_the_patch_replaces_exactly_the_genesis_set_lines():
    out = lib.patch_genesis_set("\n".join(TEMPLATE_LINES), LIMITS, 40105).split("\n")
    assert out == [
        "#!/usr/bin/create-state -s",
        "TM$40105 constant main_wallet_genesis_balance",
        "21 21 2 config.validator_num!",
        "TM$10000 TM$10000000 TM$20000 sg~10 config.validator_stake_limits!",
        "{ file>B",
        '  dup Blen 2752 <> abort"PQ manifest must contain exactly 2 1376-byte records"',
        "  {",
        "    17 swap register-validator",
        "  } 2 times drop",
        lib.TEMPLATE_MANIFEST_END_LINE,
    ]


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda t: t + ["22 22 3 config.validator_num!"], "config.validator_num!"),
        (lambda t: t + ["TM$1 TM$2 TM$3 sg~1 config.validator_stake_limits!"], "stake_limits"),
        (
            lambda t: t + ["TM$1 constant main_wallet_genesis_balance"],
            "main_wallet_genesis_balance",
        ),
        (lambda t: [x for x in t if x != lib.TEMPLATE_VALIDATOR_NUM_LINE], "validator_num"),
        (
            lambda t: [x for x in t if x != lib.TEMPLATE_MANIFEST_SIZE_LINE],
            "not found exactly once",
        ),
        (lambda t: t[:-1] + ["} : other-word"], "not the reviewed one"),
        (lambda t: t + ["  } 4 times drop"], "times drop"),
    ],
)
def test_the_patch_refuses_an_unreviewed_template(change, message):
    with pytest.raises(lib.TestnetError, match=message):
        lib.patch_genesis_set("\n".join(change(list(TEMPLATE_LINES))), LIMITS, 40105)


def test_the_patch_applies_to_the_canonical_template():
    root = os.environ.get("TOS_ROOT")
    if not root:
        pytest.skip("TOS_ROOT not set")
    text = (Path(root) / "crypto/smartcont/gen-zerostate.fif").read_text()
    out = lib.patch_genesis_set(text, LIMITS, 40105)
    changed = [(a, b) for a, b in zip(text.split("\n"), out.split("\n"), strict=True) if a != b]
    assert len(changed) == 5
    assert ("  } 4 times drop", "  } 2 times drop") in changed
