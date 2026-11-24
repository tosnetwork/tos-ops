"""Tests for the December 5 network configuration: a genesis set of the team's two
validators, up to 19 external validators from the first election, and the stake,
weight and funding plan testnet_lib.election_plan derives from the number of
external validators (E).

The Elector arithmetic is checked against a direct reading of elector-code.fc
(process_new_stake keeps 1 TOS of what arrives; try_elect caps each stake at
max_factor x the smallest elected stake and weighs it by (stake << 60) / total)
and against the onboarding rehearsal of 2026-11-24 (memo
public-testnet/DEC5-REHEARSAL-20261124.md): what arrives is the stake plus what
is left of tosctl's 1.2 TOS stake order after the pool's fees.
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


def credit(p, stake_tos):
    """The Elector's record of a pool stake order, computed here from the profile:
    the stake, plus the stake order's value less the pool's fees, less the
    Elector's 1 TOS."""
    e = p["elections"]
    return stake_tos * NANO + e["stake_order_nanotos"] - e["pool_new_stake_cost_nanotos"] - NANO


def old_tosctl_factor():
    """The profile with the team staking at tosctl's former ceiling, 3.0."""
    p = profile()
    p["elections"]["max_factor"] = "3.0"
    return p


def expected_bootstrap(p, external):
    """The bootstrap wallet, summed here independently of election_plan."""
    e = p["elections"]
    unit = e["stake_tos"]
    multiple = max(Fraction(1), Fraction(external + 1, 2))
    # The team order rule: multiple x (unit - 1) + 1, rounded down.
    team_stake = int(multiple * (unit - 1)) + 1
    team_principal = e["pool_tos"] + 2 * (team_stake - unit)
    owner_extra = e["pool_owner_reserve_tos"] + e["pool_deploy_tos"]
    team = 2 * (e["operator_funding_tos"] + team_principal + owner_extra)
    others = external * (e["operator_funding_tos"] + e["pool_tos"] + owner_extra)
    transfers = 2 * (2 + external) + 1
    fees = -(-transfers * e["bootstrap_transfer_fee_nanotos"] // NANO)
    return team + others + e["bootstrap_margin_tos_per_pool"] * (2 + external) + fees


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
    assert e["max_factor"] == "10.0" and e["external_max_factor"] == "3.0"
    assert e["stake_tos"] == 10002 and e["bootstrap_margin_tos_per_pool"] == 13
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
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(profile(), 0) == 40081
    assert plan["bootstrap_margin_tos"] == 26
    assert plan["total_supply_tos"] == 41081
    assert plan["team_weight_percent"] == 100 and plan["team_finalizes_alone"] is True
    # One team pool alone is fewer than min_validators: that election fails, and the
    # genesis set or the previous set stays in office.
    assert plan["partial_sets"]["one_team_pool_absent"]["elected"] is False


def test_one_external_validator_leaves_the_team_finalizing_alone():
    # (1+1)/2 = 1 unit each: 2 of 3 units is two thirds, and TOS finalizes at two
    # thirds, so the team finalizes alone (allowed: the safe direction). The
    # external validator never does.
    plan = lib.election_plan(profile(), external=1)
    assert plan["team_stake_multiple"] == "1"
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(profile(), 1) == 60121
    assert Fraction(plan["team_weight_percent"]).limit_denominator(1000) == Fraction(200, 3)
    assert plan["team_finalizes_alone"] is True and plan["external_finalizes_alone"] is False
    one = plan["partial_sets"]["one_team_pool_absent"]
    assert one["elected"] and not one["external_finalizes_alone"]


def test_five_external_validators_give_the_team_just_over_half():
    plan = lib.election_plan(profile(), external=5)
    # (5+1)/2 = 3 units: 3 x (10,002 - 1) + 1.
    assert plan["team_stake_multiple"] == "3" and plan["team_stake_tos"] == 30004
    assert plan["team_pool_principal_tos"] == 20010 + 2 * 20002 == 60014
    assert plan["team_owner_funding_tos"] == 60014 + 5 + 2
    assert plan["external_owner_funding_tos"] == 20010 + 5 + 2
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(profile(), 5) == 220289
    # 6 units against 5.
    assert abs(plan["team_weight_percent"] - 600 / 11) < 0.01
    assert plan["team_finalizes_alone"] is False


def test_nineteen_external_validators_with_max_factor_10():
    plan = lib.election_plan(profile(), external=19)
    # Ten units: an order of 100,011 TOS, credited as 100,011.1788215, under
    # ConfigParam 17's cap of 10 x 10,002.1788215 = 100,021.788215.
    assert plan["team_stake_multiple"] == "10" and plan["team_stake_tos"] == 100011
    assert plan["team_credit_nanotos"] == 100_011_178_821_500
    assert plan["team_credit_nanotos"] <= 10 * plan["unit_credit_nanotos"]
    assert plan["team_max_factor"] == "10.0" and plan["external_max_factor"] == "3.0"
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(profile(), 19) == 780877
    assert abs(plan["team_weight_percent"] - 2000 / 39) < 0.01
    partial = plan["partial_sets"]
    assert partial["team_finalizes_alone_with_externals"] == list(range(10))
    assert abs(100 - partial["one_team_pool_absent"]["team_weight_percent"] - 3800 / 58) < 0.01
    assert plan["liveness"] == {
        "externals_online_needed_both_team_up": 7,
        "externals_online_needed_one_team_down": 16,
    }
    with pytest.raises(lib.TestnetError, match="exceed the 19 seats"):
        lib.election_plan(profile(), external=20)


@pytest.mark.parametrize("external", range(0, 20))
def test_every_e_is_planned(external):
    plan = lib.election_plan(profile(), external=external)
    assert plan["bootstrap_wallet_tos"] == expected_bootstrap(profile(), external)
    if external >= 3:
        assert 50 <= plan["team_weight_percent"] < 200 / 3
    assert plan["team_finalizes_alone"] is (external <= 1)


@pytest.mark.parametrize("external", range(6, 20))
def test_a_team_factor_of_3_would_cap_the_team_above_five_external(external):
    # tosctl's former ceiling: a team stake above about three units would be cut
    # and the external validators would outweigh the team.
    with pytest.raises(lib.TestnetError, match="max factor of 3.0"):
        lib.election_plan(old_tosctl_factor(), external=external)
    lib.election_plan(old_tosctl_factor(), external=5)


def test_a_team_factor_below_the_team_multiple_is_refused():
    p = profile()
    p["elections"]["max_factor"] = "9.0"
    lib.election_plan(p, external=17)
    # 9.5 units at E = 18 are above a max factor of 9.
    with pytest.raises(lib.TestnetError, match="max factor of 9.0"):
        lib.election_plan(p, external=18)


def test_external_pools_keep_the_tosctl_default():
    p = profile()
    p["elections"]["external_max_factor"] = "10.0"
    with pytest.raises(lib.TestnetError, match="external pools keep it"):
        lib.election_plan(p, external=0)


# ---------------------------------------------------------------- the weights, as the Elector sets them


def elector_sets(p, external):
    """(both team pools, one team pool absent) elected sets, simulated here from the
    plan's stake orders, each credited as the Elector records it (credit()), with
    integer weights."""
    limits = lib.genesis_limits(p)
    plan = lib.election_plan(p, external=external)
    ft = int(lib.tosctl_max_factor(p) * lib.MAX_FACTOR_ONE)
    fe = int(lib.tosctl_max_factor(p, "external_max_factor") * lib.MAX_FACTOR_ONE)
    team = [("team-%d" % i, credit(p, plan["team_stake_tos"]), ft) for i in range(2)]
    others = [("ext-%d" % i, credit(p, plan["unit_stake_tos"]), fe) for i in range(external)]
    both, why = lib.simulate_election(team + others, limits)
    assert both is not None and len(both) == 2 + external, why
    one, _ = lib.simulate_election(team[:1] + others, limits)
    return both, one


def shares(elected):
    team = sum(m["weight"] for m in elected if m["label"].startswith("team"))
    total = sum(m["weight"] for m in elected)
    return team, total - team, total


@pytest.mark.parametrize("external", range(0, 20))
def test_the_external_validators_never_reach_two_thirds(external):
    """The hard invariant, pinned with the exact Elector arithmetic: strictly below
    two thirds (TOS finalizes at signed * 3 >= total * 2), in the full set and with
    either team pool absent."""
    both, one = elector_sets(profile(), external)
    _, others, total = shares(both)
    assert 3 * others < 2 * total
    # Every stake counts in full: no max factor cuts the team.
    assert all(m["true_stake_nanotos"] == m["stake_nanotos"] for m in both)
    if one is not None:
        _, others, total = shares(one)
        assert 3 * others < 2 * total
    else:
        assert external == 0  # one pool is fewer than min_validators
    # With every pool elected the team finalizes alone only below E = 2.
    team, _, total = shares(both)
    assert (3 * team >= 2 * total) is (external <= 1)


def test_the_team_alone_elects_itself_and_holds_everything():
    both, one = elector_sets(profile(), 0)
    team, others, total = shares(both)
    assert len(both) == 2 and others == 0 and team == total and one is None


# ---------------------------------------------------------------- the two-thirds guards


def test_externals_reaching_two_thirds_with_every_pool_elected_are_refused(monkeypatch):
    # A rule that leaves the team at one unit: 19 external units against 2.
    monkeypatch.setattr(lib, "team_stake_multiple_rule", lambda external: Fraction(1))
    with pytest.raises(lib.TestnetError, match="finalize without the team"):
        lib.election_plan(profile(), external=19)


def test_externals_reaching_two_thirds_with_one_team_pool_absent_are_refused(monkeypatch):
    # A team just under the earlier E/2 rule: with both team pools the external
    # validators hold about half, but with one absent 4 units against 1.9, more
    # than two thirds. (At exactly E/2 the integer weights round the external
    # side just below two thirds.)
    monkeypatch.setattr(
        lib,
        "team_stake_multiple_rule",
        lambda external: max(Fraction(1), Fraction(external, 2) - Fraction(1, 10)),
    )
    with pytest.raises(lib.TestnetError, match="one team pool absent"):
        lib.election_plan(profile(), external=4)


def test_a_team_share_outside_half_to_two_thirds_is_refused_from_three_externals(monkeypatch):
    monkeypatch.setattr(lib, "team_stake_multiple_rule", lambda external: Fraction(external + 1))
    with pytest.raises(lib.TestnetError, match=r"outside \[50 %, two thirds\)"):
        lib.election_plan(profile(), external=3)


def test_finality_is_at_two_thirds_inclusive():
    assert lib.finalizes(2, 3) and lib.finalizes(200, 300) and not lib.finalizes(199, 300)


# ---------------------------------------------------------------- the Elector's credit, as rehearsed

# Rehearsal of 2026-11-24 (memo public-testnet/DEC5-REHEARSAL-20261124.md), E = 2,
# team stake orders 15,002 TOS and external 10,002 TOS: the Elector recorded
# 15,002.1788215 and 10,002.1788215 TOS, total 50,008.715286; ConfigParam 34 gave
# the team 2 x 345866405092531622 and the external pools 2 x 230594347210891865, a
# team share of 59.99826 %.
REHEARSED_CREDITS = (15_002_178_821_500, 10_002_178_821_500)
REHEARSED_WEIGHTS = (345866405092531622, 230594347210891865)


def test_the_credit_model_is_the_rehearsed_elector_record():
    p = profile()
    # tosctl attaches 1.2 TOS; the pool keeps its fees and forwards the rest with the
    # stake (send mode 64); the Elector keeps 1 TOS.
    assert p["elections"]["stake_order_nanotos"] == 1_200_000_000
    assert lib.credit_surplus(p) == 178_821_500
    assert lib.elector_credit(15_002 * NANO, lib.credit_surplus(p)) == REHEARSED_CREDITS[0]
    assert credit(p, 10_002) == REHEARSED_CREDITS[1]
    assert 2 * sum(REHEARSED_CREDITS) == 50_008_715_286_000


def test_the_rehearsed_weights_and_share_are_reproduced_exactly():
    p = profile()
    plan = lib.election_plan(p, external=2)
    assert (plan["team_stake_tos"], plan["unit_stake_tos"]) == (15_002, 10_002)
    assert (plan["team_credit_nanotos"], plan["unit_credit_nanotos"]) == REHEARSED_CREDITS
    both, _ = elector_sets(p, 2)
    weights = {m["label"].split("-")[0]: m["weight"] for m in both}
    assert (weights["team"], weights["ext"]) == REHEARSED_WEIGHTS
    assert round(plan["team_weight_percent"], 5) == 59.99826
    # The earlier stake - 1 TOS model said 59.99920 %.
    assert round(plan["team_weight_percent"], 5) != 59.9992


def test_the_team_credit_never_exceeds_its_multiple_of_a_unit():
    """The order rule keeps the team's credit at most multiple x a unit credit, for
    any surplus the Elector adds: so ConfigParam 17's factor 10 never cuts it."""
    p = profile()
    unit = p["elections"]["stake_tos"]
    for external in range(20):
        multiple = lib.team_stake_multiple_rule(external)
        stake = lib.team_stake_tos(multiple, unit)
        for surplus in (0, 178_821_500, 999_999_999, 5 * NANO):
            team = lib.elector_credit(stake * NANO, surplus)
            assert team <= multiple * lib.elector_credit(unit * NANO, surplus)


def test_a_stake_order_that_does_not_cover_the_fees_is_refused():
    p = profile()
    p["elections"]["pool_new_stake_cost_nanotos"] = 300_000_000
    with pytest.raises(lib.TestnetError, match="does not cover"):
        lib.election_plan(p, external=0)


# ---------------------------------------------------------------- election limits


def test_the_template_min_total_stake_would_stall_a_team_only_election():
    p = profile()
    p["genesis"]["stake_limits"]["min_total_stake_tos"] = 40000
    # Two unit stakes credited as 10,002.1788215 TOS each: 20,004.357643 < 40,000.
    with pytest.raises(lib.TestnetError, match="team pools alone .* below min_total_stake"):
        lib.election_plan(p, required=False)
    # 20,004 is the most a floor may be with E = 0.
    p["genesis"]["stake_limits"]["min_total_stake_tos"] = 20004
    lib.election_plan(p, external=0)
    p["genesis"]["stake_limits"]["min_total_stake_tos"] = 20005
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
    lib.election_plan(p, external=1)  # one unit each: nothing to cut
    with pytest.raises(lib.TestnetError, match="counts at most 1.0 units"):
        lib.election_plan(p, external=2)


def test_a_tosctl_max_factor_outside_its_range_is_refused():
    p = profile()
    for value in ("101.0", "0.5", "three", 3):
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
        ("elections", "bootstrap_wallet_tos", 220288),
        ("elections", "team_stake_multiple", "2.5"),
        ("genesis", "total_supply_tos", 220289),
        ("elections", "external_validators", 4),
    ):
        wrong = copy.deepcopy(p)
        wrong[section][key] = value
        with pytest.raises(lib.TestnetError, match="is not"):
            lib.election_plan(wrong)


def test_ceremony_values_are_set_together():
    p = profile()
    p["elections"]["bootstrap_wallet_tos"] = 40081
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
    assert team["stake"] == 25003 * NANO and team["principal"] == 50012 * NANO
    assert team["owner_funding"] == (50012 + 5 + 2) * NANO
    assert team["max_factor"] == "10.0" and other["max_factor"] == "3.0"
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
        "elections.team_stake_multiple": "2",
        "elections.bootstrap_wallet_tos": expected_bootstrap(profile(), 3),
        "genesis.total_supply_tos": expected_bootstrap(profile(), 3) + 1000,
    }
    assert lib.election_plan(lib.load_profile(out))["team_stake_tos"] == 20003
    # Never overwritten, and an impossible E is refused.
    assert coordinator.main(["plan", "--external-validators", "3", "--write", str(out)]) == 1
    assert coordinator.main(["plan", "--external-validators", "20"]) == 1


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
    out = lib.patch_genesis_set("\n".join(TEMPLATE_LINES), LIMITS, 40081).split("\n")
    assert out == [
        "#!/usr/bin/create-state -s",
        "TM$40081 constant main_wallet_genesis_balance",
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


@pytest.mark.parametrize("external", range(0, 20))
def test_both_team_pools_absent_is_reported(external):
    """Not prevented by stakes: without both team pools the external validators
    elect themselves from E = 2 and hold everything. Reported, not refused."""
    case = lib.election_plan(profile(), external=external)["partial_sets"]["both_team_pools_absent"]
    assert "runbook" in case["guarded_by"]
    if external >= 2:
        assert case["concluded"] and case["elected"]
        assert case["external_finalizes_alone"] and case["team_weight_percent"] == 0
    else:
        assert not case["concluded"]  # fewer than min_validators


def test_the_one_team_guard_applies_to_any_concluded_election(monkeypatch):
    """The guard reads the one-team election whenever it concludes, even when the
    Elector leaves some member out."""
    real = lib._partial_election

    def leaves_one_out(team_members, external_members, limits):
        result = real(team_members, external_members, limits)
        if len(team_members) == 1 and external_members:
            result = dict(result, elected=False, external_finalizes_alone=True)
        return result

    monkeypatch.setattr(lib, "_partial_election", leaves_one_out)
    with pytest.raises(lib.TestnetError, match="one team pool absent"):
        lib.election_plan(profile(), external=3)
