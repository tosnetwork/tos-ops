"""Tests for the supply and burn readers of testnet_lib: ConfigParam 5, the zero
state's accounts and the coordinator's epoch genesis check, a block's ValueFlow and
account blocks, and the epoch-6 and production-timing schedules.

Real bytes anchor every reader:

* zerostate-v16-auth.boc is create-state output of the canonical template before
  the CFG-01 change (100,000 TOS bootstrap wallet, no ConfigParam 5): the
  account reader must find exactly that, and the genesis check must refuse it.
* zerostate-epoch6-candidate.boc is create-state output of the merged CFG-01
  template (tos 5d8b4d3ad, the merge of tos #365, which carries the bootstrap lines
  itself: an 80,151 TOS wallet, ConfigParam 5 = blackhole -1:ff...ff burning 0/1, 5
  critical), with global id 2, SOURCE_DATE_EPOCH 1793000000, the epoch-6 AUTH tag
  rule, the epoch-6 ConfigParam 15 and the disposable test key 0x53 repeated, made
  by create_state() below; test_the_epoch6_profile_schedule_reaches_the_zero_state
  regenerates it and requires the same bytes.
* masterchain-block-seq12.boc is a real masterchain block (tos
  test/pq-native/x02-config34-fixtures/z01-seq12-block.boc; its sha256 is its
  recorded file hash).
"""

import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path

import chainbuild
import pytest
import testnet_lib as lib
from conftest import DATA

NANO = 10**9
OLD_STATE = (DATA / "zerostate-v16-auth.boc").read_bytes()
CANDIDATE = (DATA / "zerostate-epoch6-candidate.boc").read_bytes()
CANDIDATE_RHASH = (DATA / "zerostate-epoch6-candidate.rhash").read_bytes()
BLOCK = (DATA / "masterchain-block-seq12.boc").read_bytes()
BLOCK_FILE_HASH = "c4b33e125a555681be0d93c0c0d473d9d05c32d905c4b9ec197af7df52f6ee11"
EPOCH6 = {
    "initial_set_valid_for": 21600,
    "elected_for": 7200,
    "elections_start_before": 3600,
    "elections_end_before": 900,
    "stake_held_for": 3600,
}
EPOCH6_EPOCH = 1793000000


# The epoch-6 candidate's supply; the repository profile leaves its own to the
# ceremony (elections.external_validators, then election_plan).
EPOCH6_TARGETS = (80_151 * NANO, 81_151 * NANO)


def targets():
    return EPOCH6_TARGETS


def planned_profile(external):
    profile = copy.deepcopy(lib.load_profile())
    plan = lib.election_plan(profile, external=external)
    profile["elections"]["external_validators"] = external
    profile["elections"]["team_stake_multiple"] = plan["team_stake_multiple"]
    profile["elections"]["bootstrap_wallet_tos"] = plan["bootstrap_wallet_tos"]
    profile["genesis"]["total_supply_tos"] = plan["total_supply_tos"]
    return profile


def check(boc, schedule=None):
    wallet, total = targets()
    return lib.zero_state_bootstrap(boc, wallet, total, schedule or EPOCH6)


# ---------------------------------------------------------------- ConfigParam 5


def test_the_decided_burning_config_is_accepted():
    config = lib.check_burning_config(chainbuild.burning_config())
    assert config == {"blackhole": lib.BLACKHOLE, "fee_burn": (0, 1)}


@pytest.mark.parametrize(
    "cell, message",
    [
        (chainbuild.burning_config(blackhole="11" * 32), "names blackhole -1:1111"),
        (chainbuild.burning_config(blackhole=None), "names blackhole None"),
        (chainbuild.burning_config(num=1, denom=2), "burns 1/2"),
        (chainbuild.burning_config(num=0, denom=0), "TL-B refuses"),
        (chainbuild.burning_config(num=2, denom=1), "TL-B refuses"),
        (lib.cell_from_bits("00000010" + "0" * 65), "not burning_config"),
        (lib.cell_from_bits(chainbuild.bits(1, 8) + "1"), "malformed"),
        (
            lib.cell_from_bits(
                chainbuild.bits(1, 8)
                + "1"
                + "1" * 256
                + chainbuild.bits(0, 32)
                + chainbuild.bits(1, 32)
                + "0"
            ),
            "data after",
        ),
    ],
)
def test_any_other_burning_config_is_refused(cell, message):
    with pytest.raises(lib.TestnetError, match=message):
        lib.check_burning_config(cell)


# ---------------------------------------------------------------- the zero state


def test_the_account_reader_reads_real_create_state_output():
    supply = lib.zero_state_supply(OLD_STATE)
    assert supply["balances"] == {
        "11" * 32: 100_000 * NANO,
        "33" * 32: 500 * NANO,
        "55" * 32: 500 * NANO,
    }
    assert supply["total_balance"] == 101_000 * NANO


def test_the_genesis_check_refuses_the_template_before_cfg01():
    # The red control of the check: the canonical genesis it replaces has no
    # ConfigParam 5 and a 100,000 TOS bootstrap wallet.
    with pytest.raises(lib.TestnetError, match="no ConfigParam 5"):
        check(OLD_STATE)


def test_the_epoch6_candidate_passes_the_genesis_check():
    assert lib.parse_boc(CANDIDATE).hash() == CANDIDATE_RHASH
    found = check(CANDIDATE)
    assert found["blackhole"] == lib.BLACKHOLE and found["fee_burn"] == [0, 1]
    assert found["bootstrap_wallet"] == "-1:" + "11" * 32
    assert found["bootstrap_wallet_nanotos"] == 80_151 * NANO
    assert found["total_balance_nanotos"] == 81_151 * NANO
    assert found["election_params_read_back"] == [EPOCH6[n] for n in lib.ELECTION_PARAM_NAMES]
    assert found["config_param_5_critical"] is True


def with_params(boc, monkeypatch, **changes):
    root, global_id, params = lib.zero_state_config(boc)
    params = dict(params)
    for number, cell in changes.items():
        number = int(number[1:])
        if cell is None:
            params.pop(number)
        else:
            params[number] = cell
    monkeypatch.setattr(lib, "zero_state_config", lambda _boc: (root, global_id, params))


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"p5": None}, "no ConfigParam 5"),
        ({"p5": chainbuild.burning_config(num=1, denom=2)}, "burns 1/2"),
        ({"p5": chainbuild.burning_config(blackhole="ee" * 32)}, "names blackhole"),
    ],
)
def test_the_genesis_check_refuses_another_config_param_5(monkeypatch, changes, message):
    with_params(CANDIDATE, monkeypatch, **changes)
    with pytest.raises(lib.TestnetError, match=message):
        check(CANDIDATE)


def test_the_genesis_check_requires_config_param_5_critical(monkeypatch):
    params = lib.zero_state_config(CANDIDATE)[2]
    critical = sorted(lib.hashmap_items(params[10], 32))
    assert 5 in critical
    without = chainbuild.hashmap({k: ("", []) for k in critical if k != 5}, 32)
    with_params(CANDIDATE, monkeypatch, p10=without)
    with pytest.raises(lib.TestnetError, match="not critical"):
        check(CANDIDATE)


@pytest.mark.parametrize(
    "wallet, total, message",
    [
        (100_000, 81_151, "holds 80151000000000 nanotos, expected 100000000000000"),
        (80_150, 81_151, "expected 80150000000000"),
        (80_151, 81_150, "holds 81151000000000 nanotos, expected 81150000000000"),
    ],
)
def test_the_genesis_check_refuses_another_supply(wallet, total, message):
    with pytest.raises(lib.TestnetError, match=message):
        lib.zero_state_bootstrap(CANDIDATE, wallet * NANO, total * NANO, EPOCH6)


def test_the_genesis_check_reads_config_param_15_back():
    with pytest.raises(lib.TestnetError, match="ConfigParam 15 in the zero state"):
        check(CANDIDATE, dict(EPOCH6, elected_for=14400))


def test_the_profile_supply_targets_are_the_planned_ones():
    profile = planned_profile(2)
    assert lib.genesis_supply_targets(profile) == (80_161 * NANO, 81_161 * NANO)
    profile["genesis"]["total_supply_tos"] = 81_150
    with pytest.raises(lib.TestnetError, match="plus 1000 TOS"):
        lib.genesis_supply_targets(profile)
    del profile["elections"]["bootstrap_wallet_tos"]
    with pytest.raises(lib.TestnetError, match="bootstrap_wallet_tos"):
        lib.genesis_supply_targets(profile)


# ---------------------------------------------------------------- blocks


def test_the_block_reader_reads_a_real_masterchain_block():
    assert hashlib.sha256(BLOCK).hexdigest() == BLOCK_FILE_HASH
    block = lib.read_block(BLOCK)
    assert (block["global_id"], block["workchain"], block["seqno"]) == (3, -1, 12)
    assert block["masterchain"] and block["start_lt"] <= block["end_lt"]
    flow = block["value_flow"]
    assert flow["version"] == 1 and flow["burned"] == 0
    assert flow["from_prev_blk"] + flow["recovered"] + flow["created"] + flow["fees_imported"] == (
        flow["to_next_blk"] + flow["fees_collected"]
    )
    lts = [lt for txs in block["transactions"].values() for lt in txs]
    assert lts and all(block["start_lt"] <= lt <= block["end_lt"] for lt in lts)


def test_a_block_is_only_read_with_its_exotic_state_update_admitted():
    with pytest.raises(lib.TestnetError, match="exotic"):
        lib.parse_boc(BLOCK)
    cells, root = lib.parse_boc_cells(BLOCK, exotic=True)
    update = cells[root].refs[2]
    assert update.exotic
    with pytest.raises(lib.TestnetError, match="exotic"):
        cells[root].hash()


def test_a_value_flow_v2_carries_the_burn_and_must_balance():
    flow = chainbuild.balanced_flow(7 * NANO)
    read = lib.value_flow(chainbuild.value_flow(flow))
    assert read["version"] == 2 and read["burned"] == 7 * NANO
    with pytest.raises(lib.TestnetError, match="does not balance"):
        lib.value_flow(chainbuild.value_flow(dict(flow, burned=7 * NANO + 1)))
    with pytest.raises(lib.TestnetError, match="not a ValueFlow"):
        lib.value_flow(lib.cell_from_bits(chainbuild.bits(0x12345678, 32)))


# ---------------------------------------------------------------- schedules


PRODUCTION = Path(lib.PROFILE_PATH).with_name("profile-production-timing.json")


def test_the_production_timing_profile_is_the_canonical_template_schedule():
    profile = lib.load_profile(PRODUCTION)
    expected = {key: mainnet for key, _name, mainnet in lib.TEMPLATE_SCHEDULE_CONSTANTS}
    assert lib.validator_schedule(profile) == expected
    assert lib.validator_schedule(profile) != lib.validator_schedule(lib.load_profile())


def test_the_production_timing_profile_differs_only_in_its_schedule():
    testnet = json.loads(lib.PROFILE_PATH.read_text())
    rehearsal = json.loads(PRODUCTION.read_text())
    for profile in (testnet, rehearsal):
        for key in ("status", "status_note"):
            profile.pop(key)
        for key in ("election_params", "schedule_note"):
            profile["genesis"].pop(key)
    assert rehearsal == testnet


def tos_template():
    root = os.environ.get("TOS_ROOT")
    if not root:
        pytest.skip("TOS_ROOT not set")
    return (Path(root) / "crypto/smartcont/gen-zerostate.fif").read_text()


def test_the_production_timing_profile_matches_the_tos_template():
    text = tos_template()
    schedule = lib.validator_schedule(lib.load_profile(PRODUCTION))
    for key, name, _ in lib.TEMPLATE_SCHEDULE_CONSTANTS:
        assert f"{schedule[key]} constant {name}" in text.split("\n")


def epoch6_candidate(text):
    """The canonical template with the CFG-01 bootstrap lines: 80,151 TOS, ConfigParam
    5 (blackhole -1:ff...ff, 0/1) and 5 critical. The tos PR writes ConfigParam 5
    with its own Fift word; the cell is the same."""
    pairs = [
        (
            "TM$100000 constant main_wallet_genesis_balance",
            "TM$80151 constant main_wallet_genesis_balance",
        ),
        (
            "dns_root_addr config.dns_root_smc!",
            "dns_root_addr config.dns_root_smc!\n"
            "<b x{01} s, 1 1 u, -1 256 i, 0 32 u, 1 32 u, b> 5 config!",
        ),
        (
            "( -999 -1000 -1001 0 1 3 4 8 9 10 12 14 15 16 17 19 32 34 36 ) config.critical_params!",
            "( -999 -1000 -1001 0 1 3 4 5 8 9 10 12 14 15 16 17 19 32 34 36 ) config.critical_params!",
        ),
        (
            "( -999 -1000 -1001 0 1 3 4 8 9 10 12 14 15 16 17 19 32 34 36 48 ) config.critical_params!",
            "( -999 -1000 -1001 0 1 3 4 5 8 9 10 12 14 15 16 17 19 32 34 36 48 ) config.critical_params!",
        ),
    ]
    if pairs[0][1] in text:
        return text  # the merged CFG-01 template carries them itself
    for old, new in pairs:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    return text


def disposable_records(count):
    """`count` disposable genesis records (a public key is any 1312 bytes here)."""
    records = []
    for n in range(1, count + 1):
        public = hashlib.shake_256(b"public-%d" % n).digest(lib.PQ_PUBLIC_KEY_BYTES)
        records.append(
            {
                "validator_id": hashlib.sha256(b"staking-account-%d" % n).hexdigest(),
                "adnl_id": hashlib.sha256(b"adnl-%d" % n).hexdigest(),
                "public_key": public.hex(),
                "key_id": lib.pq_key_id(public).hex(),
            }
        )
    return records


def create_state(tmp_path, text, epoch, validators=4):
    root = Path(os.environ["TOS_ROOT"])
    binary = Path(os.environ.get("CREATE_STATE_PATH", root / "build/crypto/create-state"))
    if not binary.is_file():
        pytest.fail("build create-state before testing the generated genesis")
    (tmp_path / "testnet.fif").write_text(text)
    records = disposable_records(validators)
    (tmp_path / "validator-pq.pub").write_bytes(lib.pack_manifest(records))
    # Deterministic disposable test key, never a network identity.
    (tmp_path / "main-wallet.pk").write_bytes(bytes([0x53]) * 32)
    run = subprocess.run(
        [
            str(binary),
            "-I",
            f"{root / 'crypto/fift/lib'}:{root / 'crypto/smartcont'}",
            "-I",
            str(binary.parent / "smartcont"),
            "-s",
            str(tmp_path / "testnet.fif"),
        ],
        cwd=tmp_path,
        env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)),
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
    return (tmp_path / "zerostate.boc").read_bytes()


def test_the_epoch6_profile_schedule_reaches_the_zero_state(tmp_path):
    profile = lib.load_profile()
    schedule = lib.validator_schedule(profile)
    tag = lib.derive_auth_network_tag("tos-public-testnet", 2, 6)
    patched = lib.patch_template(epoch6_candidate(tos_template()), 2, EPOCH6_EPOCH, schedule, tag)
    boc = create_state(tmp_path, patched, EPOCH6_EPOCH)
    assert list(lib.zero_state_election_params(boc)) == [
        schedule[name] for name in lib.ELECTION_PARAM_NAMES
    ]
    found = check(boc, schedule)
    assert found["bootstrap_wallet_nanotos"] == 80_151 * NANO
    # The committed candidate is exactly this output of the merged template.
    assert "TM$80151" in tos_template(), "TOS_ROOT predates the CFG-01 template (tos #365)"
    assert boc == CANDIDATE


def test_the_production_timing_schedule_reaches_the_zero_state(tmp_path):
    schedule = lib.validator_schedule(lib.load_profile(PRODUCTION))
    tag = lib.derive_auth_network_tag("tos-public-testnet", 2, 6)
    patched = lib.patch_template(epoch6_candidate(tos_template()), 2, EPOCH6_EPOCH, schedule, tag)
    boc = create_state(tmp_path, patched, EPOCH6_EPOCH)
    assert list(lib.zero_state_election_params(boc)) == [65536, 16384, 8192, 32768]
    check(boc, schedule)


@pytest.mark.parametrize("external", [0, 5])
def test_the_december_genesis_set_and_limits_reach_the_zero_state(tmp_path, external):
    """The canonical template patched for the team-only genesis set: create-state
    reads two manifest records, and ConfigParam 16, 17 and 34 and the bootstrap
    balance read back from the generated state are the profile's."""
    profile = planned_profile(external)
    plan = lib.election_plan(profile)
    limits = lib.genesis_limits(profile)
    schedule = lib.validator_schedule(profile)
    tag = lib.derive_auth_network_tag("tos-public-testnet", 2, 9)
    patched = lib.patch_genesis_set(
        lib.patch_template(tos_template(), 2, EPOCH6_EPOCH, schedule, tag),
        limits,
        plan["bootstrap_wallet_tos"],
    )
    boc = create_state(tmp_path, patched, EPOCH6_EPOCH, validators=2)
    wallet, total = lib.genesis_supply_targets(profile)
    found = lib.zero_state_bootstrap(boc, wallet, total, schedule)
    assert found["bootstrap_wallet_nanotos"] == plan["bootstrap_wallet_tos"] * NANO
    assert found["total_balance_nanotos"] == plan["total_supply_tos"] * NANO
    records = disposable_records(2)
    genesis_set = lib.check_zero_state_genesis_set(boc, limits, records)
    assert genesis_set["validators"] == 2
    assert genesis_set["config_param_16"] == {
        "max_validators": 21,
        "max_main_validators": 21,
        "min_validators": 2,
    }
    assert genesis_set["config_param_17"] == {
        "min_stake_nanotos": 10_000 * NANO,
        "max_stake_nanotos": 10_000_000 * NANO,
        "min_total_stake_nanotos": 20_000 * NANO,
        "max_factor": 10 << 16,
    }
    read = lib.zero_state_genesis_set(boc)
    assert read["main"] == 2 and len({v["weight"] for v in read["validators"]}) == 1
    # The read-back refuses another set, other limits or a second manifest order.
    with pytest.raises(lib.TestnetError, match="validator set is 2 validators other than"):
        lib.check_zero_state_genesis_set(boc, limits, records[::-1])
    with pytest.raises(lib.TestnetError, match="ConfigParam 16"):
        lib.check_zero_state_genesis_set(boc, dict(limits, min_validators=4), records)
    with pytest.raises(lib.TestnetError, match="ConfigParam 17"):
        lib.check_zero_state_genesis_set(boc, dict(limits, min_total_stake_tos=40000), records)


def test_the_patched_template_refuses_a_four_record_manifest(tmp_path):
    profile = planned_profile(0)
    patched = lib.patch_genesis_set(
        lib.patch_template(
            tos_template(),
            2,
            EPOCH6_EPOCH,
            lib.validator_schedule(profile),
            lib.derive_auth_network_tag("tos-public-testnet", 2, 9),
        ),
        lib.genesis_limits(profile),
        lib.election_plan(profile)["bootstrap_wallet_tos"],
    )
    root = Path(os.environ["TOS_ROOT"])
    binary = Path(os.environ.get("CREATE_STATE_PATH", root / "build/crypto/create-state"))
    (tmp_path / "testnet.fif").write_text(patched)
    (tmp_path / "validator-pq.pub").write_bytes(lib.pack_manifest(disposable_records(4)))
    (tmp_path / "main-wallet.pk").write_bytes(bytes([0x53]) * 32)
    run = subprocess.run(
        [
            str(binary),
            "-I",
            f"{root / 'crypto/fift/lib'}:{root / 'crypto/smartcont'}",
            "-I",
            str(binary.parent / "smartcont"),
            "-s",
            str(tmp_path / "testnet.fif"),
        ],
        cwd=tmp_path,
        env=dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH6_EPOCH)),
        capture_output=True,
        text=True,
    )
    assert run.returncode != 0
    assert "exactly 2 1376-byte records" in run.stdout + run.stderr
