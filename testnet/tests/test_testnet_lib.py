"""Tests for testnet_lib. The fixtures in data/ are real public tool output.

consensus-key-report.txt is `tos-pq-consensus-key generate` output and
dht-node-loopback.json is `generate-random-id -m dht` output, both captured
from a loopback rehearsal: the key id derivation and the DHT record checks are
tested against what the tools actually print, not against our own encoding.
"""

import base64
import copy
import hashlib
import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import testnet_lib as lib
from conftest import DATA, one_key_list, serialize_boc

REPORT = (DATA / "consensus-key-report.txt").read_text()
DHT_NODE = json.loads((DATA / "dht-node-loopback.json").read_text())
RECORD = json.loads((DATA / "record-loopback.json").read_text())


def public_record(n: int) -> dict:
    """A self-consistent record with distinct identities (a public key is any 1312 bytes here)."""
    public = hashlib.shake_256(b"public-%d" % n).digest(lib.PQ_PUBLIC_KEY_BYTES)
    return {
        "operator": f"operator-{n}",
        "validator_id": hashlib.sha256(b"staking-account-%d" % n).hexdigest(),
        "adnl_id": hashlib.sha256(b"adnl-%d" % n).hexdigest(),
        "public_key": public.hex(),
        "key_id": lib.pq_key_id(public).hex(),
        "address": f"44.0.0.{n}:30001",
    }


# ---------------------------------------------------------------- profile and global id


def test_repository_profile_loads():
    profile = lib.load_profile()
    assert profile["global_id"]["value"] == 2
    assert lib.confirmed_global_id(profile) == 2
    assert profile["genesis"]["validators"] == 2
    assert profile["features"]["shielded_pool"] == "disabled"
    assert "shielded_pool_record" not in profile["features"]
    assert lib.shielded_pool_record(profile) is None
    assert profile["features"]["energy"] == "disabled"


EPOCH6_POOL = json.loads((DATA / "profile-epoch6-shielded-pool.json").read_text())


def _restricted():
    """The repository profile carrying epoch 6's AUTH tag and restricted pool record."""
    profile = copy.deepcopy(lib.load_profile())
    profile["genesis"]["auth_network_tag"] = copy.deepcopy(EPOCH6_POOL["auth_network_tag"])
    profile["features"] = copy.deepcopy(EPOCH6_POOL["features"])
    return profile


def test_the_epoch6_record_fixture_loads(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(_restricted()))
    assert lib.shielded_pool_record(lib.load_profile(path))["network"]["epoch"] == 6


def test_the_epoch6_record_does_not_carry_over_to_another_epoch(tmp_path):
    profile = _restricted()
    profile["genesis"]["auth_network_tag"] = lib.load_profile()["genesis"]["auth_network_tag"]
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    with pytest.raises(lib.TestnetError, match="AUTH tag"):
        lib.load_profile(path)


def test_the_shielded_pool_record_is_bound_to_its_epoch():
    profile = _restricted()
    record = lib.shielded_pool_record(profile)
    assert record["network"]["global_id"] == 2
    assert record["network"]["auth_network_tag"] == profile["genesis"]["auth_network_tag"]["value"]
    assert record["pool"]["address"] == "0:" + record["pool"]["state_init_hash"]
    assert record["pool"]["address"] == (
        "0:60b33d9dbd3e6e4a45a6cf3f3693106186c3911cd75c8c26cb6a679294c29a34"
    )
    assert record["groth16"]["vk_sha256"] == (
        "49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c"
    )


def _rec(p):
    return p["features"]["shielded_pool_record"]


def _set(path, value):
    def change(p):
        *parents, last = path.split(".")
        node = _rec(p)
        for key in parents:
            node = node[int(key)] if isinstance(node, list) else node[key]
        node[last] = value

    return change


def _drop(path):
    def change(p):
        *parents, last = path.split(".")
        node = _rec(p)
        for key in parents:
            node = node[int(key)] if isinstance(node, list) else node[key]
        del node[last]

    return change


# Each case is written to a profile file and refused by load_profile itself.
MALFORMED_RECORDS = [
    # The three cases of the review: a dropped hash, a foreign version, a non-list.
    (
        "dropped code_boc_sha256",
        _drop("pool.code_boc_sha256"),
        "missing keys \\['code_boc_sha256'\\]",
    ),
    ("global_version 999", _set("network.global_version", 999), "global version 999"),
    ("gate_decisions a string", _set("gate_decisions", "approved"), "must be a non-empty list"),
    # Keys.
    ("unknown top-level key", _set("extra", 1), "unknown keys \\['extra'\\]"),
    ("unknown pool key", _set("pool.owner", "x"), "unknown keys \\['owner'\\]"),
    ("missing network name", _drop("network.name"), "missing keys \\['name'\\]"),
    ("missing gas ceiling", _drop("pool.gas_ceilings.bounce"), "missing keys \\['bounce'\\]"),
    ("gate decision without by", _drop("gate_decisions.0.by"), "missing keys \\['by'\\]"),
    ("gate decision extra key", _set("gate_decisions.0.extra", "x"), "unknown keys"),
    # Types and formats.
    ("short hex", _set("pool.data_hash", "ab" * 31), "pool.data_hash must be 64"),
    ("upper-case hex", _set("pool.code_hash", "AB" * 32), "pool.code_hash must be 64"),
    ("commit not 40 hex", _set("network.runtime_commit", "ab" * 32), "runtime_commit must be 40"),
    ("address format", _set("pool.address", "-1:" + "60" * 32), "workchain-0 raw address"),
    ("address not the StateInit", _set("pool.address", "0:" + "11" * 32), "StateInit hash"),
    ("bool as integer", _set("network.global_id", True), "global_id must be a positive"),
    ("string as integer", _set("pool.withdrawal_fee_nanotos", "20000000"), "positive integer"),
    ("denominations unsorted", _set("pool.denominations_tos", [10, 1]), "increasing"),
    ("denominations empty", _set("pool.denominations_tos", []), "increasing"),
    ("gas ceilings not an object", _set("pool.gas_ceilings", [1, 2, 3, 4]), "must be an object"),
    ("empty gate decisions", _set("gate_decisions", []), "non-empty list"),
    ("gate decision not an object", _set("gate_decisions", ["approved"]), "must be an object"),
    ("gate decision date", _set("gate_decisions.0.date", "yesterday"), "YYYY-MM-DD"),
    ("empty scope", _set("scope", " "), "scope must be a non-empty string"),
    ("vk_bytes", _set("groth16.vk_bytes", 1247), "vk_bytes must be 1248"),
    ("recovery slot", _set("profile.recovery_payload_slot", 1), "recovery_payload_slot must be 2"),
    ("floor above endowment", _set("pool.immutable_reserve_floor_tos", 101), "floor exceeds"),
    # Bindings to the enclosing profile.
    ("network name", _set("network.name", "tos-local-dev"), "network name"),
    ("global id", _set("network.global_id", 3), "global id 3"),
    ("epoch", _set("network.epoch", 5), "epoch 5"),
    ("AUTH tag", _set("network.auth_network_tag", "00" * 32), "AUTH tag"),
    ("record status", _set("status", "disabled"), "needs a record with the same status"),
]


@pytest.mark.parametrize(
    "change, message", [c[1:] for c in MALFORMED_RECORDS], ids=[c[0] for c in MALFORMED_RECORDS]
)
def test_load_profile_refuses_a_malformed_shielded_pool_record(tmp_path, change, message):
    profile = _restricted()
    change(profile)
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    with pytest.raises(lib.TestnetError, match=message):
        lib.load_profile(path)


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda p: p["features"].update(shielded_pool="enabled"), "unknown shielded pool status"),
        (lambda p: p["features"].update(shielded_pool="disabled"), "present while"),
        (lambda p: p["features"].pop("shielded_pool_record"), "needs a record"),
        (lambda p: p["features"].update(energy="enabled"), "unknown energy status"),
        (lambda p: p["features"].update(privacy="on"), "unknown keys"),
        (lambda p: p["genesis"]["auth_network_tag"].update(campaign_epoch=7), "epoch"),
        (lambda p: p["genesis"].update(global_version=17), "global version"),
    ],
)
def test_load_profile_refuses_an_inconsistent_feature_block(tmp_path, change, message):
    profile = _restricted()
    change(profile)
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    with pytest.raises(lib.TestnetError, match=message):
        lib.load_profile(path)


def test_a_disabled_pool_without_a_record_loads(tmp_path):
    profile = _restricted()
    profile["features"]["shielded_pool"] = "disabled"
    del profile["features"]["shielded_pool_record"]
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    assert lib.shielded_pool_record(lib.load_profile(path)) is None


def test_both_repository_profiles_load():
    # Every script loads one of these whether or not it touches the pool.
    for name in ("profile.json", "profile-production-timing.json"):
        profile = lib.load_profile(lib.PROFILE_PATH.with_name(name))
        assert lib.shielded_pool_record(profile) is None


@pytest.mark.parametrize("value", [1, 3, 0, True, 2**31, -(2**31) - 1, "2", None])
def test_global_id_refuses_mainnet_local_and_malformed(value):
    with pytest.raises(lib.TestnetError):
        lib.check_global_id(value)


@pytest.mark.parametrize("value", [2, -2, 7002, 2**31 - 1, -(2**31)])
def test_global_id_accepts_other_int32(value):
    assert lib.check_global_id(value) == value


@pytest.mark.parametrize("status", ["PROPOSED", "confirmed", None])
def test_genesis_refuses_an_unconfirmed_global_id(status):
    profile = lib.load_profile()
    profile["global_id"]["status"] = status
    with pytest.raises(lib.TestnetError, match="not CONFIRMED"):
        lib.confirmed_global_id(profile)


def test_confirmation_does_not_admit_mainnet_or_local():
    profile = lib.load_profile()
    for value in (1, 3):
        profile["global_id"]["value"] = value
        with pytest.raises(lib.TestnetError):
            lib.confirmed_global_id(profile)


def test_profile_refuses_colliding_ports(tmp_path):
    profile = json.loads(lib.PROFILE_PATH.read_text())
    profile["ports"]["dht_udp"] = profile["ports"]["adnl_udp"] + profile["ports"]["quic_udp_offset"]
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    with pytest.raises(lib.TestnetError, match="collide"):
        lib.load_profile(path)


def test_profile_refuses_mainnet_global_id(tmp_path):
    profile = json.loads(lib.PROFILE_PATH.read_text())
    profile["global_id"]["value"] = 1
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    with pytest.raises(lib.TestnetError, match="mainnet"):
        lib.load_profile(path)


# ---------------------------------------------------------------- consensus key


def test_key_id_derivation_matches_the_real_tool():
    key_id, public = lib.parse_consensus_key_report(REPORT)
    assert lib.pq_key_id(public) == key_id


def test_report_with_a_foreign_key_id_is_refused():
    lines = REPORT.splitlines()
    forged = [("key_id    " + "11" * 32) if line.startswith("key_id") else line for line in lines]
    with pytest.raises(lib.TestnetError, match="does not match"):
        lib.parse_consensus_key_report("\n".join(forged))


def test_report_without_algorithm_is_refused():
    with pytest.raises(lib.TestnetError, match="mldsa44"):
        lib.parse_consensus_key_report(REPORT.replace("mldsa44", "mldsa65"))


def test_adnl_short_id_is_sha256_of_the_tl_public_key():
    key = base64.b64decode(DHT_NODE["id"]["key"])
    assert lib.adnl_short_id(key) == hashlib.sha256(bytes.fromhex("c6b41348") + key).digest()


# ---------------------------------------------------------------- operator records


def test_rehearsal_record_is_valid_under_rehearsal(monkeypatch):
    monkeypatch.setenv(lib.REHEARSAL_ENV, "1")
    assert lib.check_operator_record(RECORD)["key_id"] == RECORD["key_id"]


def test_loopback_record_is_refused_outside_rehearsal(monkeypatch):
    monkeypatch.delenv(lib.REHEARSAL_ENV, raising=False)
    with pytest.raises(lib.TestnetError, match="not a public"):
        lib.check_operator_record(RECORD)


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("validator_id", "00" * 32, "must not be zero"),
        ("adnl_id", "ab" * 31, "32 bytes"),
        ("key_id", "12" * 32, "does not match"),
        ("operator", "Operator One", "short lower-case"),
        ("address", "44.0.0.1", "public-ipv4"),
        ("address", "100.64.0.1:30001", "not a public"),
        ("address", "10.0.0.1:30001", "not a public"),
    ],
)
def test_record_field_refusals(monkeypatch, field, value, match):
    monkeypatch.delenv(lib.REHEARSAL_ENV, raising=False)
    record = public_record(1)
    record[field] = value
    with pytest.raises(lib.TestnetError, match=match):
        lib.check_operator_record(record)


def test_record_with_extra_field_is_refused():
    record = public_record(1)
    record["seed"] = "00" * 32
    with pytest.raises(lib.TestnetError, match="unexpected"):
        lib.check_operator_record(record)


def test_operator_set_has_the_count_it_is_given():
    with pytest.raises(lib.TestnetError, match="exactly 2 operator records, not 3"):
        lib.check_operator_set([public_record(n) for n in range(1, 4)], 2)
    with pytest.raises(lib.TestnetError, match="exactly 4 operator records, not 5"):
        lib.check_operator_set([public_record(n) for n in range(1, 6)], 4)
    with pytest.raises(lib.TestnetError, match="nonempty"):
        lib.check_operator_set([])
    # Without a count any number of distinct records is a set: the registered
    # records hold the genesis set and every external validator.
    assert len(lib.check_operator_set([public_record(n) for n in range(1, 8)])) == 7


@pytest.mark.parametrize("field", ["validator_id", "adnl_id", "operator", "address"])
def test_operator_set_refuses_shared_identities(field):
    records = [public_record(n) for n in range(1, 5)]
    records[3][field] = records[0][field]
    with pytest.raises(lib.TestnetError, match=f"same {field}"):
        lib.check_operator_set(records)


def test_operator_set_refuses_a_shared_consensus_key():
    records = [public_record(n) for n in range(1, 5)]
    records[3]["public_key"], records[3]["key_id"] = records[0]["public_key"], records[0]["key_id"]
    with pytest.raises(lib.TestnetError, match="same key_id"):
        lib.check_operator_set(records)


def test_operator_set_refuses_two_validators_on_one_host(monkeypatch):
    monkeypatch.delenv(lib.REHEARSAL_ENV, raising=False)
    records = [public_record(n) for n in range(1, 5)]
    records[3]["address"] = "44.0.0.1:30011"
    with pytest.raises(lib.TestnetError, match="one host"):
        lib.check_operator_set(records)


@pytest.mark.parametrize("field", ["validator_id", "key_id", "adnl_id"])
def test_reset_refuses_an_identity_from_an_earlier_epoch(field):
    earlier = [public_record(n) for n in range(1, 5)]
    fresh = lib.check_operator_set([public_record(n) for n in range(5, 9)])
    lib.check_fresh_identities(fresh, [earlier])
    fresh[2][field] = earlier[0][field]
    with pytest.raises(lib.TestnetError, match=f"reuses {field}"):
        lib.check_fresh_identities(fresh, [earlier])


def test_reset_compares_identities_case_insensitively():
    earlier = [public_record(n) for n in range(1, 5)]
    for record in earlier:
        record["key_id"] = record["key_id"].upper()
    fresh = lib.check_operator_set([public_record(n) for n in range(5, 9)])
    fresh[0]["key_id"] = earlier[3]["key_id"].lower()
    with pytest.raises(lib.TestnetError, match="reuses key_id"):
        lib.check_fresh_identities(fresh, [earlier])


def test_reset_checks_every_earlier_epoch():
    first = [public_record(n) for n in range(1, 5)]
    second = [public_record(n) for n in range(5, 9)]
    fresh = lib.check_operator_set([public_record(n) for n in range(9, 13)])
    fresh[1]["validator_id"] = first[2]["validator_id"]
    with pytest.raises(lib.TestnetError, match="reuses validator_id"):
        lib.check_fresh_identities(fresh, [second, first])


def test_reset_refuses_a_malformed_previous_file():
    fresh = lib.check_operator_set([public_record(n) for n in range(1, 5)])
    with pytest.raises(lib.TestnetError, match="JSON list"):
        lib.check_fresh_identities(fresh, [{"validator_id": "x"}])


def test_manifest_packs_index_order_and_size():
    records = lib.check_operator_set([public_record(n) for n in range(1, 5)])
    packed = lib.pack_manifest(records)
    assert len(packed) == 5504
    record_size = 32 + 32 + 1312
    for index, record in enumerate(records):
        chunk = packed[index * record_size : (index + 1) * record_size]
        assert chunk[:32].hex() == record["validator_id"]
        assert chunk[32:64].hex() == record["adnl_id"]
        assert chunk[64:].hex() == record["public_key"]
    assert lib.manifest_input(records)[2] == {
        "validator_id": records[2]["validator_id"],
        "adnl_id": records[2]["adnl_id"],
        "public_key": records[2]["public_key"],
    }


# ---------------------------------------------------------------- template


# The shape of the canonical template around the replaced lines: the pins,
# the five schedule constants, the schedule guards that read them, ConfigParam
# 15 written from them and the initial set written from orig_vset_valid_for.
TEMPLATE = "\n".join(
    [
        lib.TEMPLATE_FIRST_LINE,
        lib.TEMPLATE_AUTH_GUARD_LINE,
        "wc_master setworkchain",
        lib.TEMPLATE_GLOBAL_ID_LINE,
        "0x544F5301 default-subwallet-id!",
        lib.TEMPLATE_EPOCH_LINE,
        lib.TEMPLATE_EPOCH_ABORT_LINE,
        "21600 constant orig_vset_valid_for",
        "65536 constant validators_elected_for",
        "16384 constant elections_start_before",
        "8192 constant elections_end_before",
        "32768 constant stakes_frozen_for",
        lib.TEMPLATE_SCHEDULE_GUARD_LINE,
        "bootstrap_until elections_start_before - now max constant first_election_open",
        lib.TEMPLATE_ELECTION_PARAMS_LINE,
        "1 1 9 config.validator_num!",
        "now dup orig_vset_valid_for + 0 config.validators!",
    ]
)
SCHEDULE = {
    "initial_set_valid_for": 21600,
    "elected_for": 14400,
    "elections_start_before": 7200,
    "elections_end_before": 1800,
    "stake_held_for": 7200,
}
TAG = lib.derive_auth_network_tag("tos-public-testnet", 2, 4)

# Epoch 5 as its published genesis.json records it: genesis 2026-10-24 11:00 UTC,
# a 6 h initial set, the first election open 15:00-16:30 UTC and its set in
# office at 17:00 UTC (a 7,200 s lead), then 14,400 s terms.
EPOCH5_SOURCE_DATE_EPOCH = 1792839600
EPOCH5_SCHEDULE = {
    "initial_set_valid_for": 21600,
    "elected_for": 14400,
    "elections_start_before": 7200,
    "elections_end_before": 1800,
    "stake_held_for": 7200,
}
EPOCH5_CONSTANTS = {
    "orig_vset_valid_for": 21600,
    "validators_elected_for": 14400,
    "elections_start_before": 7200,
    "elections_end_before": 1800,
    "stakes_frozen_for": 7200,
}
EPOCH5_FIRST_ELECTION = {"opens": 1792854000, "closes": 1792859400, "takes_office": 1792861200}
# Epoch 6: the 2 h schedule epoch 5 adopted by its live ConfigParam 15 vote, with the
# same 6 h initial set (CFG-01 plan, test-lead resolution of amendment 3).
EPOCH6_SCHEDULE = {
    "initial_set_valid_for": 21600,
    "elected_for": 7200,
    "elections_start_before": 3600,
    "elections_end_before": 900,
    "stake_held_for": 3600,
}
EPOCH6_TEST_EPOCH = 1793000000
# The December 5 schedule: 24 h terms (owner: at least 24 h between election cycles).
DEC5_SCHEDULE = {
    "initial_set_valid_for": 86400,
    "elected_for": 86400,
    "elections_start_before": 43200,
    "elections_end_before": 7200,
    "stake_held_for": 21600,
}
EPOCH5_TAG = bytes.fromhex("3edc0460815cddd18f2b878004f50d7191d0dbd34d772d298b281e0767d7fd2c")


def schedule_constants(text):
    """{constant name: value} for every `<n> constant <name>` the schedule uses."""
    names = {name for _, name, _ in lib.TEMPLATE_SCHEDULE_CONSTANTS}
    found = {}
    for line in text.split("\n"):
        parts = line.split()
        if len(parts) == 3 and parts[1] == "constant" and parts[2] in names:
            assert parts[2] not in found
            found[parts[2]] = int(parts[0])
    return found


def test_patch_replaces_the_pins_and_the_schedule_only():
    # Another lifetime than the template's 6 h shows the constant is replaced.
    patched = lib.patch_template(
        TEMPLATE, 2, 1800000000, dict(SCHEDULE, initial_set_valid_for=25200), TAG
    )
    before, after = TEMPLATE.split("\n"), patched.split("\n")
    # One line inserted after the first: the AUTH network tag, before the guard reads it.
    assert after[0] == lib.TEMPLATE_FIRST_LINE
    assert (
        after[1]
        == f"0x{TAG.hex()} constant quantum-network-tag   // TOS public testnet AUTH network tag"
    )
    assert after[2] == lib.TEMPLATE_AUTH_GUARD_LINE
    after = after[:1] + after[2:]
    changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    assert changed == [3, 5, 6, 7, 8, 9, 10, 11]
    assert after[3].startswith("2 setglobalid")
    assert after[5] == "1800000000 constant mainnet_genesis_utime"
    assert "1800000000" in after[6]
    assert after[7:12] == [
        "25200 constant orig_vset_valid_for",
        "14400 constant validators_elected_for",
        "7200 constant elections_start_before",
        "1800 constant elections_end_before",
        "7200 constant stakes_frozen_for",
    ]
    # The guards and the writers keep reading the names.
    assert after[12:] == before[12:]


def test_patch_puts_the_epoch5_schedule_above_the_guard():
    patched = lib.patch_template(TEMPLATE, 2, EPOCH5_SOURCE_DATE_EPOCH, EPOCH5_SCHEDULE, EPOCH5_TAG)
    lines = patched.split("\n")
    guard = lines.index(lib.TEMPLATE_SCHEDULE_GUARD_LINE)
    assert schedule_constants("\n".join(lines[:guard])) == EPOCH5_CONSTANTS
    assert schedule_constants("\n".join(lines[guard:])) == {}


def test_the_december_schedule_is_the_repository_profile():
    assert lib.validator_schedule(lib.load_profile()) == DEC5_SCHEDULE
    # First election T + 12 h to T + 22 h, in office at T + 24 h, then 24 h terms.
    t = EPOCH6_TEST_EPOCH
    s = DEC5_SCHEDULE
    bootstrap_until = t + s["initial_set_valid_for"]
    opens = max(bootstrap_until - s["elections_start_before"], t)
    takes_office = opens + s["elections_start_before"]
    closes = takes_office - s["elections_end_before"]
    assert (opens - t, closes - t, takes_office - t) == (43200, 79200, 86400)
    assert closes - opens == 10 * 3600  # longer than a night in every time zone
    assert takes_office + s["elected_for"] - t == 172800
    # About 13 elected terms in the 14-day test.
    assert (14 * 86400 - s["initial_set_valid_for"]) // s["elected_for"] == 13


def test_two_stakes_per_pool_suffice_on_the_december_schedule():
    """A stake placed for the term starting at S is frozen until S + elected_for +
    stake_held_for; the election after next opens at S + 2 x elected_for -
    elections_start_before. The first must come back before the third is needed."""
    s = DEC5_SCHEDULE
    returns = s["elected_for"] + s["stake_held_for"]
    third_opens = 2 * s["elected_for"] - s["elections_start_before"]
    assert (returns, third_opens) == (108000, 129600)  # S + 30 h, S + 36 h
    assert returns <= third_opens


def test_epoch5_schedule_record_matches_the_template_arithmetic():
    # The template's own guard arithmetic, which the genesis record must match.
    t = EPOCH5_SOURCE_DATE_EPOCH
    bootstrap_until = t + EPOCH5_SCHEDULE["initial_set_valid_for"]
    opens = max(bootstrap_until - EPOCH5_SCHEDULE["elections_start_before"], t)
    takes_office = opens + EPOCH5_SCHEDULE["elections_start_before"]
    closes = takes_office - EPOCH5_SCHEDULE["elections_end_before"]
    assert {"opens": opens, "closes": closes, "takes_office": takes_office} == (
        EPOCH5_FIRST_ELECTION
    )
    assert takes_office <= bootstrap_until and opens < closes < takes_office


def test_patch_refuses_a_template_without_the_tag_guard_or_with_its_own_tag():
    with pytest.raises(lib.TestnetError, match="guard"):
        lib.patch_template(
            TEMPLATE.replace(lib.TEMPLATE_AUTH_GUARD_LINE, "// gone"), 2, 1800000000, SCHEDULE, TAG
        )
    for definition in (
        "0x01 constant quantum-network-tag",
        "1 constant quantum-admission-candidate",
    ):
        with pytest.raises(lib.TestnetError, match="already defines"):
            lib.patch_template(TEMPLATE + "\n" + definition, 2, 1800000000, SCHEDULE, TAG)
    with pytest.raises(lib.TestnetError, match="first line"):
        lib.patch_template(
            TEMPLATE.replace(lib.TEMPLATE_FIRST_LINE, "#!/bin/sh"), 2, 1800000000, SCHEDULE, TAG
        )
    with pytest.raises(lib.TestnetError, match="reserved"):
        lib.patch_template(TEMPLATE, 2, 1800000000, SCHEDULE, b"\x42" * 32)


def test_patch_refuses_a_changed_template():
    with pytest.raises(lib.TestnetError, match="exactly once"):
        lib.patch_template(
            TEMPLATE.replace(lib.TEMPLATE_GLOBAL_ID_LINE, "1 setglobalid"),
            2,
            1800000000,
            SCHEDULE,
            TAG,
        )
    doubled = TEMPLATE + "\n" + lib.TEMPLATE_EPOCH_LINE
    with pytest.raises(lib.TestnetError, match="exactly once"):
        lib.patch_template(doubled, 2, 1800000000, SCHEDULE, TAG)
    gone = [lib.TEMPLATE_SCHEDULE_GUARD_LINE, lib.TEMPLATE_ELECTION_PARAMS_LINE]
    gone += [f"{value} constant {name}" for _, name, value in lib.TEMPLATE_SCHEDULE_CONSTANTS]
    for line in gone:
        with pytest.raises(lib.TestnetError, match="exactly once"):
            lib.patch_template(TEMPLATE.replace(line, "// moved"), 2, 1800000000, SCHEDULE, TAG)


def test_patch_refuses_the_template_before_the_named_schedule():
    # The shape before the template checked its first election: ConfigParam 15
    # as literals and the initial set assigned near the end. Its guard-free
    # schedule cannot be reviewed the same way, so it is refused.
    old = (
        TEMPLATE.replace(
            lib.TEMPLATE_ELECTION_PARAMS_LINE, "65536 32768 8192 32768 config.election_params!"
        )
        .replace(lib.TEMPLATE_SCHEDULE_GUARD_LINE + "\n", "")
        .replace("21600 constant orig_vset_valid_for\n", "")
        + "\n21600 =: orig_vset_valid_for"
    )
    with pytest.raises(lib.TestnetError, match="exactly once"):
        lib.patch_template(old, 2, 1800000000, SCHEDULE, TAG)


def test_patch_refuses_a_schedule_the_guard_would_not_check():
    lines = TEMPLATE.split("\n")
    guard = lines.index(lib.TEMPLATE_SCHEDULE_GUARD_LINE)
    # A constant moved below the guard.
    moved = lines[:]
    moved.insert(guard, moved.pop(moved.index("8192 constant elections_end_before")))
    with pytest.raises(lib.TestnetError, match="after its schedule guard"):
        lib.patch_template("\n".join(moved), 2, 1800000000, SCHEDULE, TAG)
    # A constant rebound after the patched definition.
    for rebinding in ("16384 =: elections_start_before", "1 constant  stakes_frozen_for"):
        with pytest.raises(lib.TestnetError, match="more than once"):
            lib.patch_template(TEMPLATE + "\n" + rebinding, 2, 1800000000, SCHEDULE, TAG)
    # ConfigParam 15 written before the guard ran.
    early = lines[:]
    early.insert(guard, early.pop(early.index(lib.TEMPLATE_ELECTION_PARAMS_LINE)))
    with pytest.raises(lib.TestnetError, match="before its schedule guard"):
        lib.patch_template("\n".join(early), 2, 1800000000, SCHEDULE, TAG)
    for value in (0, 2**32, True, "7200"):
        with pytest.raises(lib.TestnetError, match="out of range"):
            lib.patch_template(
                TEMPLATE, 2, 1800000000, dict(SCHEDULE, elections_end_before=value), TAG
            )


def test_patch_refuses_mainnet_id_and_old_epoch():
    with pytest.raises(lib.TestnetError):
        lib.patch_template(TEMPLATE, 1, 1800000000, SCHEDULE, TAG)
    with pytest.raises(lib.TestnetError, match="later"):
        lib.patch_template(TEMPLATE, 2, 1789434000, SCHEDULE, TAG)


def tos_template():
    root = os.environ.get("TOS_ROOT")
    if not root:
        pytest.skip("TOS_ROOT not set")
    from pathlib import Path

    return (Path(root) / "crypto/smartcont/gen-zerostate.fif").read_text()


def test_patch_matches_the_tos_template_when_available():
    text = tos_template()
    assert schedule_constants(text) == {
        name: value for _, name, value in lib.TEMPLATE_SCHEDULE_CONSTANTS
    }
    patched = lib.patch_template(
        text, 2, 1800000000, dict(SCHEDULE, initial_set_valid_for=25200), TAG
    )
    lines = patched.split("\n")
    assert lines[1].startswith(f"0x{TAG.hex()} constant quantum-network-tag")
    del lines[1]
    diff = [(a, b) for a, b in zip(text.split("\n"), lines) if a != b]
    # Three pins and the five schedule constants, nothing else.
    assert len(diff) == 8
    # With the repository's own lifetime that constant stays as it is.
    lines = lib.patch_template(text, 2, 1800000000, SCHEDULE, TAG).split("\n")
    del lines[1]
    assert len([1 for a, b in zip(text.split("\n"), lines) if a != b]) == 7


def test_patch_puts_the_epoch5_schedule_into_the_tos_template():
    patched = lib.patch_template(
        tos_template(), 2, EPOCH5_SOURCE_DATE_EPOCH, EPOCH5_SCHEDULE, EPOCH5_TAG
    )
    lines = patched.split("\n")
    guard = lines.index(lib.TEMPLATE_SCHEDULE_GUARD_LINE)
    assert schedule_constants("\n".join(lines[:guard])) == EPOCH5_CONSTANTS
    assert schedule_constants(patched) == EPOCH5_CONSTANTS
    assert lines.index(lib.TEMPLATE_ELECTION_PARAMS_LINE) > guard


# ---------------------------------------------------------------- validator schedule


def schedule_profile(**changes):
    profile = copy.deepcopy(lib.load_profile())
    genesis = profile["genesis"]
    for name, value in changes.items():
        if name == "initial_set_valid_for":
            genesis["initial_set_valid_for_seconds"] = value
        else:
            genesis["election_params"][name] = value
    return profile


def test_repository_schedule_is_the_decided_one():
    assert lib.validator_schedule(lib.load_profile()) == DEC5_SCHEDULE


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"elections_end_before": 43200}, "end_before < elections_start_before"),
        ({"elections_start_before": 86400}, "start_before < elected_for"),
        # The first stake would still be frozen when the election after next opens.
        ({"stake_held_for": 43201}, "two stakes per pool would not suffice"),
        ({"elections_start_before": 64801}, "two stakes per pool would not suffice"),
        (
            {
                "initial_set_valid_for": DEC5_SCHEDULE["elections_start_before"]
                + lib.MIN_FIRST_ELECTION_LEAD_SECONDS
                - 1
            },
            "at least 3600",
        ),
        ({"elected_for": 0}, "out of range"),
        ({"stake_held_for": True}, "out of range"),
        ({"elected_for": "14400"}, "out of range"),
        ({"initial_set_valid_for": None}, "out of range"),
    ],
)
def test_schedule_refuses_an_unworkable_profile(changes, message):
    with pytest.raises(lib.TestnetError, match=message):
        lib.validator_schedule(schedule_profile(**changes))


def test_schedule_refuses_missing_or_extra_election_params():
    profile = schedule_profile()
    del profile["genesis"]["election_params"]["stake_held_for"]
    with pytest.raises(lib.TestnetError, match="exactly"):
        lib.validator_schedule(profile)
    profile = schedule_profile()
    profile["genesis"]["election_params"]["validators_elected_for"] = 1
    with pytest.raises(lib.TestnetError, match="exactly"):
        lib.validator_schedule(profile)


def test_schedule_accepts_the_least_lead_time():
    least = DEC5_SCHEDULE["elections_start_before"] + lib.MIN_FIRST_ELECTION_LEAD_SECONDS
    assert lib.validator_schedule(schedule_profile(initial_set_valid_for=least))


def test_load_profile_refuses_an_unworkable_schedule(tmp_path):
    # Every script loads the profile first, so a bad schedule must stop them all,
    # not only the genesis step that patches the template.
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(schedule_profile(elections_end_before=43200)))
    with pytest.raises(lib.TestnetError, match="end_before"):
        lib.load_profile(path)


def test_units_use_the_profile_retention():
    from pathlib import Path

    retention = lib.load_profile()["retention"]
    systemd = Path(lib.HERE).parent / "systemd"
    for role in ("validator", "fullnode"):
        unit = (systemd / f"tos-testnet-{role}.service").read_text()
        ttl = retention[role]
        assert f"--state-ttl {ttl['state_ttl']} --archive-ttl {ttl['archive_ttl']}" in unit, role


def test_validator_logs_stay_under_the_owner_cap():
    # The engine writes one log file per thread plus the main one, and each keeps
    # keep_files rotated copies; the session stats file adds its own bound. The
    # owner capped all of it at 2 GB per validator. A change to -t, the log
    # flags or the profile that breaks the cap fails here.
    import re
    from pathlib import Path

    logs = lib.load_profile()["retention"]["validator_logs"]
    unit = (Path(lib.HERE).parent / "systemd" / "tos-testnet-validator.service").read_text()
    threads = int(re.search(r"(?m)^\s+-t (\d+) \\$", unit).group(1))
    rotate = int(re.search(r"--log-rotate-mb (\d+)", unit).group(1))
    keep = int(re.search(r"--log-keep-files (\d+)", unit).group(1))
    assert (rotate, keep) == (logs["rotate_mb"], logs["keep_files"])
    total = (threads + 1) * (keep + 1) * rotate + logs["session_stats_max_mb"]
    assert total <= logs["max_total_mb"] == 2048, total


def test_engine_units_cap_rocksdb_caches_at_one_gib():
    # Owner decision 2026-10-15: each RocksDB cache is capped at 1 GiB on
    # validators and full nodes, testnet and production alike. CellDb V2 only
    # honours a smaller --celldb-cache-size when --celldb-cache-min-size is
    # set too; without it the cache is raised to about 4.66 GiB.
    import re
    from pathlib import Path

    root = Path(lib.HERE).parent.parent
    gib = 1 << 30
    units = [
        root / "testnet" / "systemd" / "tos-testnet-validator.service",
        root / "testnet" / "systemd" / "tos-testnet-fullnode.service",
        root / "production" / "systemd" / "tos-validator.service",
    ]
    for path in units:
        unit = path.read_text()
        # The testnet validator carries the CellDb value in TOS_CELLDB_CACHE_BYTES, so
        # the resources drop-in can lower it; its default is still 1 GiB.
        celldb = re.findall(r"(?m)^Environment=TOS_CELLDB_CACHE_BYTES=(\d+)$", unit)
        if path == units[0]:
            assert celldb == [str(gib)], path
            flag = r"\$\{TOS_CELLDB_CACHE_BYTES\}"
            assert len(re.findall(rf"--celldb-cache-size {flag}(?:\s|$)", unit)) == 1, path
            assert len(re.findall(rf"--celldb-cache-min-size {flag}(?:\s|$)", unit)) == 1, path
            assert not re.findall(r"--celldb-cache(?:-min)?-size \d", unit), path
        else:
            assert celldb == [], path
            assert re.findall(r"--celldb-cache-size (\d+)", unit) == [str(gib)], path
            assert re.findall(r"--celldb-cache-min-size (\d+)", unit) == [str(gib)], path
        assert re.findall(r"(?m)^Environment=TOS_ROCKSDB_BLOCK_CACHE_SIZE=(\d+)$", unit) == [
            str(gib)
        ], path
    # The design document embeds the production unit; the two must not drift.
    doc = (root / "production" / "Production-Node.md").read_text()
    assert units[2].read_text() in doc


def test_validators_serve_json_rpc_without_the_wallet_index():
    # The validator's own loopback JSON-RPC serves its operator tool; the wallet index
    # belongs to RPC nodes. A full node is an RPC node and keeps it.
    import re
    from pathlib import Path

    root = Path(lib.HERE).parent.parent
    validators = [
        root / "testnet" / "systemd" / "tos-testnet-validator.service",
        root / "production" / "systemd" / "tos-validator.service",
    ]
    for path in validators:
        unit = path.read_text()
        assert re.findall(r"--json-rpc-address 127\.0\.0\.1:8081\b", unit), path
        assert unit.count("--json-rpc-without-wallet-index") == 1, path
    fullnode = (root / "testnet" / "systemd" / "tos-testnet-fullnode.service").read_text()
    assert "--json-rpc-without-wallet-index" not in fullnode
    rehearsal = (root / "testnet" / "scripts" / "rehearse-loopback.sh").read_text()
    assert "--json-rpc-without-wallet-index" in rehearsal


# ---------------------------------------------------------------- global config


def test_zero_state_uses_standard_base64():
    raw = bytes([0xFB, 0xFF] * 16)
    entry = lib.zero_state_entry(raw, raw)
    assert "+" in entry["root_hash"] or "/" in entry["root_hash"]
    assert base64.b64decode(entry["root_hash"], validate=True) == raw
    assert entry["shard"] == -(2**63) and entry["workchain"] == -1 and entry["seqno"] == 0


def test_zero_state_refuses_zero_hash():
    with pytest.raises(lib.TestnetError):
        lib.zero_state_entry(bytes(32), b"\x01" * 32)


def test_real_dht_record_passes_under_rehearsal(monkeypatch):
    monkeypatch.setenv(lib.REHEARSAL_ENV, "1")
    assert lib.check_dht_node(copy.deepcopy(DHT_NODE))["@type"] == "dht.node"


def test_loopback_dht_record_is_refused_outside_rehearsal(monkeypatch):
    monkeypatch.delenv(lib.REHEARSAL_ENV, raising=False)
    with pytest.raises(lib.TestnetError, match="not a public"):
        lib.check_dht_node(copy.deepcopy(DHT_NODE))


def test_dht_record_without_signature_is_refused(monkeypatch):
    monkeypatch.setenv(lib.REHEARSAL_ENV, "1")
    node = copy.deepcopy(DHT_NODE)
    node["signature"] = ""
    with pytest.raises(lib.TestnetError, match="signature"):
        lib.check_dht_node(node)


def test_global_config_needs_two_distinct_dht_nodes(monkeypatch):
    monkeypatch.setenv(lib.REHEARSAL_ENV, "1")
    profile = lib.load_profile()
    zero = lib.zero_state_entry(b"\x01" * 32, b"\x02" * 32)
    with pytest.raises(lib.TestnetError, match="at least two"):
        lib.global_config(zero, [copy.deepcopy(DHT_NODE)], profile)
    with pytest.raises(lib.TestnetError, match="same key"):
        lib.global_config(zero, [copy.deepcopy(DHT_NODE), copy.deepcopy(DHT_NODE)], profile)


def test_global_config_shape(monkeypatch):
    monkeypatch.setenv(lib.REHEARSAL_ENV, "1")
    other = copy.deepcopy(DHT_NODE)
    other["id"]["key"] = base64.b64encode(b"\x07" * 32).decode()
    zero = lib.zero_state_entry(b"\x01" * 32, b"\x02" * 32)
    config = lib.global_config(zero, [copy.deepcopy(DHT_NODE), other], lib.load_profile())
    assert config["validator"]["zero_state"] == zero
    assert "init_block" not in config["validator"]
    assert config["dht"]["k"] == 6 and len(config["dht"]["static_nodes"]["nodes"]) == 2
    assert not lib.is_pregenesis(config)


def test_pregenesis_config_is_recognizable_and_nonzero():
    config = lib.pregenesis_config(lib.load_profile())
    assert lib.is_pregenesis(config)
    zero = config["validator"]["zero_state"]
    assert any(base64.b64decode(zero["root_hash"])) and any(base64.b64decode(zero["file_hash"]))
    assert config["dht"]["static_nodes"]["nodes"] == []


def test_ip_to_tl_is_signed():
    assert lib.ip_to_tl("127.0.0.1") == 2130706433
    assert lib.ip_to_tl("203.0.113.1") == int.from_bytes(bytes([203, 0, 113, 1]), "big") - 2**32


# ---------------------------------------------------------------- files


def test_write_new_refuses_overwrite_and_ignores_umask(tmp_path):
    path = tmp_path / "out"
    old = os.umask(0o077)
    try:
        lib.write_new(path, b"x", 0o644)
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    with pytest.raises(lib.TestnetError, match="never overwritten"):
        lib.write_new(path, b"y")
    assert path.read_bytes() == b"x"


def test_write_new_refuses_a_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("keep")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises((lib.TestnetError, OSError)):
        lib.write_new(link, b"y")
    assert target.read_text() == "keep"


def test_private_dir_refuses_shared_modes(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    with pytest.raises(lib.TestnetError, match="group or others"):
        lib.private_dir(shared)


def test_empty_dir_refuses_content(tmp_path):
    used = tmp_path / "used"
    used.mkdir(mode=0o700)
    (used / "file").write_text("x")
    with pytest.raises(lib.TestnetError, match="not empty"):
        lib.empty_dir(used)


def serve_jsonrpc(result):
    """A one-shot local JSON-RPC server; returns its URL and the list it records request bodies into."""
    return serve_answer({"jsonrpc": "2.0", "id": 1, "result": result})


def serve_answer(answer, status=200):
    """A one-shot local server answering one POST with `answer` (JSON, or raw bytes) and `status`."""
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            body = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}/jsonRPC", seen


def test_rpc_passes_a_parameter_named_method_through():
    # runGetMethod names its getter `method`; that must reach the node as a
    # parameter, not collide with the JSON-RPC method name.
    url, seen = serve_jsonrpc({"exit_code": 0, "stack": [["num", "0x5"]]})
    result = lib.rpc(url, "runGetMethod", address="-1:" + "11" * 32, method="seqno", stack=[])
    assert result["stack"] == [["num", "0x5"]]
    assert seen[0]["method"] == "runGetMethod"
    assert seen[0]["params"] == {"address": "-1:" + "11" * 32, "method": "seqno", "stack": []}


# JSON-RPC answers in the shape tos validator-engine gives them since tos #227
# (validator-engine/json-rpc-contract.h): a method error is HTTP 200 with a typed
# error object; only a refusal before the method runs uses another status, with
# the same body.


def error_answer(code, reason, message, retryable=False):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": code,
            "message": message,
            "data": {"schema_version": 1, "reason": reason, "retryable": retryable},
        },
    }


def test_rpc_sends_named_params_in_a_strict_envelope():
    url, seen = serve_jsonrpc({"last": {"seqno": "7"}})
    assert lib.rpc(url, "getMasterchainInfo") == {"last": {"seqno": "7"}}
    assert seen == [{"jsonrpc": "2.0", "id": 1, "method": "getMasterchainInfo", "params": {}}]


def test_rpc_raises_the_typed_error_object():
    url, _ = serve_answer(error_answer(-32004, "CONFIG_PARAM_ABSENT", "config param 48 not found"))
    with pytest.raises(lib.RpcError) as caught:
        lib.rpc(url, "getConfigParam", param=48)
    error = caught.value
    assert (error.code, error.reason, error.retryable) == (-32004, "CONFIG_PARAM_ABSENT", False)
    assert "CONFIG_PARAM_ABSENT -32004: config param 48 not found" in str(error)


# The node's rate-limit refusal, byte for byte as tos d7ef85b4c writes it
# (validator-engine/json-rpc-http-policy.h, rate_limited_response): HTTP 429, sent
# before the request is read, so its id is null.
NODE_RATE_LIMITED = (
    b'{"jsonrpc":"2.0","id":null,"error":{"code":-32005,'
    b'"message":"Rate limit exceeded (per-IP)",'
    b'"data":{"schema_version":1,"reason":"RATE_LIMITED","retryable":true}}}'
)


def test_rpc_reads_the_nodes_rate_limit_refusal():
    url, _ = serve_answer(NODE_RATE_LIMITED, 429)
    with pytest.raises(lib.RpcError) as caught:
        lib.rpc(url, "getMasterchainInfo")
    assert caught.value.retryable is True and caught.value.reason == "RATE_LIMITED"
    assert caught.value.code == -32005


@pytest.mark.parametrize("status", lib.RPC_PRE_DISPATCH_STATUSES)
def test_rpc_reads_every_pre_dispatch_refusal(status):
    body = dict(error_answer(-32000, "UNAUTHORIZED", "refused"), id=None)
    url, _ = serve_answer(body, status)
    with pytest.raises(lib.RpcError, match="UNAUTHORIZED -32000: refused"):
        lib.rpc(url, "getMasterchainInfo")


@pytest.mark.parametrize(
    "status,body", [(502, b"<html>bad gateway</html>"), (500, NODE_RATE_LIMITED)]
)
def test_rpc_refuses_a_status_the_node_does_not_answer_with(status, body):
    url, _ = serve_answer(body, status)
    with pytest.raises(lib.TestnetError, match=f"HTTP {status}") as caught:
        lib.rpc(url, "getMasterchainInfo")
    assert not isinstance(caught.value, lib.RpcError)


def test_rpc_refuses_a_pre_dispatch_status_without_a_json_rpc_body():
    url, _ = serve_answer(b"<html>too many</html>", 429)
    with pytest.raises(lib.TestnetError, match="HTTP 429 without a JSON-RPC body") as caught:
        lib.rpc(url, "getMasterchainInfo")
    assert not isinstance(caught.value, lib.RpcError)


@pytest.mark.parametrize(
    "answer,message",
    [
        ({"id": 1, "result": {}}, "not a JSON-RPC 2.0 answer"),
        ({"jsonrpc": "2.0", "id": 2, "result": {}}, "request id 2"),
        # id null only on an error object: a result always echoes the request's id
        ({"jsonrpc": "2.0", "id": None, "result": {}}, "request id None"),
        ({"jsonrpc": "2.0", "id": 1}, "neither"),
        (dict(error_answer(-32603, "INTERNAL_ERROR", "x"), result={}), "both"),
        # the shape before tos #227: a string error and an ok flag
        ({"ok": False, "jsonrpc": "2.0", "id": 1, "error": "LITE_SERVER_NOTREADY"}, "malformed"),
        ({"jsonrpc": "2.0", "id": 1, "error": {"code": "1", "message": "x"}}, "malformed"),
    ],
)
def test_rpc_refuses_answers_outside_the_contract(answer, message):
    with pytest.raises(lib.TestnetError, match=message) as caught:
        lib.rpc_result(answer, "http://node", "getMasterchainInfo")
    assert not isinstance(caught.value, lib.RpcError)


def test_rpc_never_branches_on_an_ok_field():
    # A success is its result; an `ok` field (gone since tos #227) changes nothing.
    assert lib.rpc_result({"jsonrpc": "2.0", "id": 1, "result": 5}, "u", "m") == 5
    assert lib.rpc_result({"ok": False, "jsonrpc": "2.0", "id": 1, "result": 5}, "u", "m") == 5


# ---------------------------------------------------------------- AUTH network tag


def test_profile_tag_is_sha256_of_its_rule():
    profile = lib.load_profile()
    entry = lib.profile_auth_network_tag(profile)
    rule = "TOS-AUTH-NETWORK-TAG-v1;network=tos-public-testnet;global_id=2;epoch=8"
    assert entry["rule"] == rule
    assert entry["tag"] == hashlib.sha256(rule.encode()).digest()
    assert entry["tag"].hex() == "b7d72ce529d8d73dcf0332a2d9984a4ce08191126075e8799cfff7d5211f2011"


@pytest.mark.parametrize(
    "change,message",
    [
        ({"value": "00" * 32}, "reserved"),
        ({"value": "e3" * 31}, "64 hexadecimal"),
        ({"campaign_epoch": 9}, "not SHA-256"),
        ({"rule": "something else"}, "not SHA-256"),
        ({"status": "PROPOSED"}, "status"),
        ({"campaign_epoch": True}, "campaign_epoch"),
    ],
)
def test_profile_tag_refusals(change, message):
    profile = copy.deepcopy(lib.load_profile())
    profile["genesis"]["auth_network_tag"].update(change)
    with pytest.raises(lib.TestnetError, match=message):
        lib.profile_auth_network_tag(profile)


@pytest.mark.parametrize(
    "tag", ["42" * 32, "43" * 32, "45" * 32, "46" * 32, bytes(range(32)).hex(), "00" * 32]
)
def test_reserved_tags_are_refused(tag):
    with pytest.raises(lib.TestnetError, match="reserved"):
        lib.check_auth_network_tag(tag)


def test_supplied_tag_must_be_the_announced_one():
    profile = lib.load_profile()
    value = profile["genesis"]["auth_network_tag"]["value"]
    supplied = lib.supplied_auth_network_tag(profile, {"TOS_AUTH_NETWORK_TAG": value.upper()})
    assert supplied.hex() == value
    with pytest.raises(lib.TestnetError, match="not set"):
        lib.supplied_auth_network_tag(profile, {})
    with pytest.raises(lib.TestnetError, match="announces"):
        lib.supplied_auth_network_tag(profile, {"TOS_AUTH_NETWORK_TAG": "ab" * 31 + "cd"})


# ---------------------------------------------------------------- zero state AUTH policy

# A real version-16 zero state: create-state at tos d7ef85b4c with the epoch-4 AUTH
# tag, from a loopback rehearsal (global id 2), and create-state's own root hash.
ZERO_STATE = (DATA / "zerostate-v16-auth.boc").read_bytes()
ZERO_STATE_RHASH = (DATA / "zerostate-v16-auth.rhash").read_bytes()
FIXTURE_TAG = bytes.fromhex("e36440a2e7704d9e26c79c5d9ba462507783b18404e876da9a232d38722e28fd")
CONFIG48_HASH = "900a85305f8ad2f6bea6b0f51955659a5298bf41ae59cea44f5edaeeddb55d68"


def test_cell_hash_matches_create_state():
    assert lib.parse_boc(ZERO_STATE).hash() == ZERO_STATE_RHASH


def test_real_zero_state_auth_policy():
    auth = lib.zero_state_auth_policy(ZERO_STATE, ZERO_STATE_RHASH, 2, 16, FIXTURE_TAG)
    assert auth["network_tag_hex"] == FIXTURE_TAG.hex()
    assert auth["config_param_48_hash_hex"] == CONFIG48_HASH
    assert auth["policy_identity_sha256"] == (
        "5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0"
    )
    assert (auth["sequence"], auth["retired"], auth["deadline"]) == (0, 0, None)
    assert auth["global_version"] == 16


@pytest.mark.parametrize(
    "rhash,global_id,version,tag,message",
    [
        (b"\x00" * 32, 2, 16, FIXTURE_TAG, "root hash"),
        (ZERO_STATE_RHASH, 3, 16, FIXTURE_TAG, "global id 2"),
        (ZERO_STATE_RHASH, 2, 17, FIXTURE_TAG, "version 16, expected 17"),
        (ZERO_STATE_RHASH, 2, 16, b"\x01" * 32, "carries tag"),
    ],
)
def test_zero_state_auth_policy_refusals(rhash, global_id, version, tag, message):
    with pytest.raises(lib.TestnetError, match=message):
        lib.zero_state_auth_policy(ZERO_STATE, rhash, global_id, version, tag)


def config_params():
    return lib.zero_state_config(ZERO_STATE)[2]


def rebuild(cell, flip_bit=None):
    """A copy of a cell with one data bit flipped."""
    data = bytearray(cell.data)
    if flip_bit is not None:
        data[flip_bit // 8] ^= 0x80 >> (flip_bit % 8)
    return lib.Cell(bytes(data), cell.bits, list(cell.refs))


@pytest.mark.parametrize(
    "bit,message",
    [
        (0, "a1 AUTH policy"),  # the record tag
        (8 + 256 + 63, None),  # sequence 1: decoded, then refused by the genesis check
        (8 + 256 + 64 + 15, "unknown suite"),  # a retired bit no suite owns
        (8 + 256 + 64 + 16, "schedule reference"),  # schedule flag without a reference
        (600, "policy identity"),  # the last bit of the identity hash
    ],
)
def test_auth_policy_mutations(bit, message):
    cell = rebuild(config_params()[48], flip_bit=bit)
    if message is None:
        assert lib.auth_policy(cell)["sequence"] == 1
    else:
        with pytest.raises(lib.TestnetError, match=message):
            lib.auth_policy(cell)


def test_mandatory_and_critical_membership_is_read_from_the_lists():
    assert list(lib.hashmap_items(one_key_list(47), 32)) == [47]
    params = config_params()
    assert 48 in lib.hashmap_items(params[9], 32)
    assert 48 in lib.hashmap_items(params[10], 32)
    assert 47 in lib.hashmap_items(params[9], 32)
    assert -999 % 2**32 in lib.hashmap_items(params[10], 32)
    assert 2 not in lib.hashmap_items(params[9], 32)
    assert lib.config_version(params[8])[0] == 16


def test_parse_boc_refuses_damage():
    with pytest.raises(lib.TestnetError, match="not a bag of cells"):
        lib.parse_boc(b"\x00" * 16)
    with pytest.raises(lib.TestnetError, match="truncated"):
        lib.parse_boc(ZERO_STATE[:-40])


@pytest.mark.parametrize("number,name", [(9, "mandatory"), (10, "critical")])
def test_zero_state_auth_policy_refuses_a_policy_outside_the_lists(monkeypatch, number, name):
    real = lib.zero_state_config

    def without_48(boc):
        root, global_id, params = real(boc)
        return root, global_id, {**params, number: one_key_list(47)}

    monkeypatch.setattr(lib, "zero_state_config", without_48)
    with pytest.raises(lib.TestnetError, match=f"not {name}"):
        lib.zero_state_auth_policy(ZERO_STATE, ZERO_STATE_RHASH, 2, 16, FIXTURE_TAG)


def test_serialized_boc_round_trips():
    for cell in (config_params()[48], config_params()[9], lib.parse_boc(ZERO_STATE)):
        assert lib.parse_boc(serialize_boc(cell)).hash() == cell.hash()


def test_historical_genesis_is_not_the_new_admission_profile():
    # This pinned historical fixture remains unchanged; it predates CP21=20,000.
    with pytest.raises(lib.TestnetError, match="ConfigParam 21 gas_credit is 10000"):
        lib.zero_state_gas_credits(ZERO_STATE)


def test_historical_genesis_still_carries_the_controller_policy():
    # The same pinned fixture predates the removal of ConfigParam 47.
    with pytest.raises(lib.TestnetError, match="still defines retired ConfigParam 47"):
        lib.zero_state_retired_params(ZERO_STATE)


@pytest.mark.parametrize(
    "mandatory,critical,refused",
    [(48, 48, None), (47, 48, "still mandatory"), (48, 47, "still critical")],
)
def test_retired_param_guard_reads_both_lists(monkeypatch, mandatory, critical, refused):
    params = {9: one_key_list(mandatory), 10: one_key_list(critical)}
    monkeypatch.setattr(lib, "zero_state_config", lambda boc: (None, 2, params))
    if refused is None:
        lib.zero_state_retired_params(b"")
    else:
        with pytest.raises(lib.TestnetError, match=f"ConfigParam 47 is {refused}"):
            lib.zero_state_retired_params(b"")


@pytest.mark.parametrize("missing", [9, 10])
def test_retired_param_guard_needs_both_lists(monkeypatch, missing):
    params = {9: one_key_list(48), 10: one_key_list(48)}
    del params[missing]
    monkeypatch.setattr(lib, "zero_state_config", lambda boc: (None, 2, params))
    with pytest.raises(lib.TestnetError, match=f"no ConfigParam {missing}"):
        lib.zero_state_retired_params(b"")


def test_generated_genesis_has_the_adopted_gas_credits(tmp_path):
    import subprocess
    from pathlib import Path

    root = os.environ.get("TOS_ROOT")
    if not root:
        pytest.skip("TOS_ROOT not set")
    root = Path(root)
    binary = Path(os.environ.get("CREATE_STATE_PATH", root / "build/crypto/create-state"))
    if not binary.is_file():
        pytest.fail("build create-state before testing the generated genesis")
    template = (root / "crypto/smartcont/gen-zerostate.fif").read_text()
    epoch = 1800000000
    patched = lib.patch_template(template, 2, epoch, SCHEDULE, TAG)
    (tmp_path / "testnet.fif").write_text(patched)
    (tmp_path / "validator-pq.pub").write_bytes(
        lib.pack_manifest([public_record(i) for i in range(1, 5)])
    )
    # Deterministic disposable test key, never a network identity.
    (tmp_path / "main-wallet.pk").write_bytes(bytes([0x53]) * 32)
    subprocess.run(
        [
            str(binary),
            "-I",
            str(root / "crypto/fift/lib") + ":" + str(root / "crypto/smartcont"),
            "-I",
            str(binary.parent / "smartcont"),
            "-s",
            str(tmp_path / "testnet.fif"),
        ],
        cwd=tmp_path,
        env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)),
        check=True,
        capture_output=True,
    )
    assert lib.zero_state_gas_credits((tmp_path / "zerostate.boc").read_bytes()) == {
        20: 10000,
        21: 20000,
    }
    lib.zero_state_retired_params((tmp_path / "zerostate.boc").read_bytes())


def run_create_state(tmp_path, patched, epoch):
    """Run the pinned create-state on a patched template; the completed process."""
    import subprocess
    from pathlib import Path

    root = os.environ.get("TOS_ROOT")
    if not root:
        pytest.skip("TOS_ROOT not set")
    root = Path(root)
    binary = Path(os.environ.get("CREATE_STATE_PATH", root / "build/crypto/create-state"))
    if not binary.is_file():
        pytest.fail("build create-state before testing the generated genesis")
    (tmp_path / "testnet.fif").write_text(patched)
    (tmp_path / "validator-pq.pub").write_bytes(
        lib.pack_manifest([public_record(i) for i in range(1, 5)])
    )
    # Deterministic disposable test key, never a network identity.
    (tmp_path / "main-wallet.pk").write_bytes(bytes([0x53]) * 32)
    return subprocess.run(
        [
            str(binary),
            "-I",
            str(root / "crypto/fift/lib") + ":" + str(root / "crypto/smartcont"),
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


def test_epoch5_schedule_passes_the_template_guard_and_reaches_the_zero_state(tmp_path):
    patched = lib.patch_template(
        tos_template(), 2, EPOCH5_SOURCE_DATE_EPOCH, EPOCH5_SCHEDULE, EPOCH5_TAG
    )
    run = run_create_state(tmp_path, patched, EPOCH5_SOURCE_DATE_EPOCH)
    assert run.returncode == 0, run.stdout + run.stderr
    params = lib.zero_state_config((tmp_path / "zerostate.boc").read_bytes())[2]
    election = params[15].data
    assert [int.from_bytes(election[i : i + 4], "big") for i in range(0, 16, 4)] == [
        EPOCH5_SCHEDULE[name] for name in lib.ELECTION_PARAM_NAMES
    ]
    # ConfigParam 34: validators_ext#12 utime_since:uint32 utime_until:uint32.
    current = params[34].data
    assert current[0] == 0x12
    assert int.from_bytes(current[1:5], "big") == EPOCH5_SOURCE_DATE_EPOCH
    assert int.from_bytes(current[5:9], "big") == EPOCH5_FIRST_ELECTION["takes_office"]


def test_template_guard_checks_the_patched_schedule(tmp_path):
    # Valid for the template's own constants, so only the patched values can
    # make the guard refuse: a lead longer than the bootstrap term.
    schedule = dict(EPOCH5_SCHEDULE, elections_start_before=30000, elected_for=65536)
    patched = lib.patch_template(tos_template(), 2, EPOCH5_SOURCE_DATE_EPOCH, schedule, EPOCH5_TAG)
    run = run_create_state(tmp_path, patched, EPOCH5_SOURCE_DATE_EPOCH)
    assert run.returncode != 0
    assert "first election would extend the bootstrap validator term" in run.stdout + run.stderr
    assert not (tmp_path / "zerostate.boc").exists()


def gas_prices_cell(tag, credit, flat=False, damage=None):
    fields = [32768000, 1000000] + ([1000000] if tag == 0xDE else [])
    fields += [credit, 2500000, 100000000, 1000000000]
    data = bytes([tag]) + b"".join(value.to_bytes(8, "big") for value in fields)
    if flat:
        data = bytes([0xD1]) + (100).to_bytes(8, "big") + (1000000).to_bytes(8, "big") + data
    refs = []
    if damage == "truncated":
        data = data[:-8]
    elif damage == "trailing-bits":
        data += b"\x00"
    elif damage == "trailing-ref":
        refs = [lib.Cell(b"", 0, [])]
    return lib.Cell(data, len(data) * 8, refs)


@pytest.mark.parametrize("tag", [0xDD, 0xDE])
@pytest.mark.parametrize("flat", [False, True])
@pytest.mark.parametrize("damage", ["truncated", "trailing-bits", "trailing-ref"])
def test_gas_credit_guard_refuses_malformed_prices(monkeypatch, tag, flat, damage):
    # The credit itself is right; only the cell around it is damaged.
    params = {20: gas_prices_cell(tag, 10000, flat), 21: gas_prices_cell(tag, 20000, flat, damage)}
    monkeypatch.setattr(lib, "zero_state_config", lambda boc: (None, 2, params))
    with pytest.raises(lib.TestnetError, match="ConfigParam 21 (is malformed|has data after)"):
        lib.zero_state_gas_credits(b"")


def test_gas_credit_guard_accepts_flat_prefixed_prices(monkeypatch):
    params = {
        20: gas_prices_cell(0xDE, 10000, flat=True),
        21: gas_prices_cell(0xDD, 20000, flat=True),
    }
    monkeypatch.setattr(lib, "zero_state_config", lambda boc: (None, 2, params))
    assert lib.zero_state_gas_credits(b"") == {20: 10000, 21: 20000}


@pytest.mark.parametrize("tag", [0xDD, 0xDE])
@pytest.mark.parametrize(
    "mc,wc,refused", [(10000, 20000, None), (20000, 20000, 20), (10000, 10000, 21)]
)
def test_gas_credit_guard_checks_both_workchains(monkeypatch, tag, mc, wc, refused):
    def gas_cell(credit):
        fields = [32768000, 1000000] + ([1000000] if tag == 0xDE else [])
        fields += [credit, 2500000, 100000000, 1000000000]
        data = bytes([tag]) + b"".join(value.to_bytes(8, "big") for value in fields)
        return lib.Cell(data, len(data) * 8, [])

    monkeypatch.setattr(
        lib, "zero_state_config", lambda boc: (None, 2, {20: gas_cell(mc), 21: gas_cell(wc)})
    )
    if refused is None:
        assert lib.zero_state_gas_credits(b"") == {20: mc, 21: wc}
    else:
        with pytest.raises(lib.TestnetError, match=f"ConfigParam {refused} gas_credit"):
            lib.zero_state_gas_credits(b"")


# ---------------------------------------------------------------- reads at a block not applied yet

# The answer a node a block or two behind gave a load refill in the live soak:
# a read at the network's newest masterchain block, which this node had not applied.
NOT_APPLIED_MESSAGE = (
    "getAccountState: [Error : 651 : cannot load block (-1,8000000000000000,338211):"
    "ab:cd : block (-1,8000000000000000,338211) is not applied"
    " (last known masterchain block: 338209)]"
)


def not_applied(url="http://a", method="getAddressInformation"):
    return lib.RpcError(url, method, -32603, "UPSTREAM_UNAVAILABLE", NOT_APPLIED_MESSAGE, True)


def test_the_nodes_not_applied_answer_is_classified_from_the_wire():
    url, _ = serve_answer(error_answer(-32603, "UPSTREAM_UNAVAILABLE", NOT_APPLIED_MESSAGE, True))
    with pytest.raises(lib.RpcError) as caught:
        lib.rpc(url, "getAddressInformation", address="-1:" + "00" * 32)
    assert lib.block_not_applied(caught.value)


OTHER_ERRORS = [
    # the same reason, but a timeout or another not-ready answer
    lib.RpcError("u", "m", -32603, "UPSTREAM_UNAVAILABLE", "getAccountState: timeout", True),
    lib.RpcError(
        "u", "m", -32603, "UPSTREAM_UNAVAILABLE", "[Error : 651 : state is not ready]", True
    ),
    lib.RpcError("u", "m", -32603, "UPSTREAM_UNAVAILABLE", "block x is not applied", True),
    # the not-applied text under another reason, or not marked retryable
    lib.RpcError("u", "m", -32004, "BLOCK_UNAVAILABLE", NOT_APPLIED_MESSAGE, False),
    lib.RpcError("u", "m", -32603, "INTERNAL_ERROR", NOT_APPLIED_MESSAGE, False),
    lib.RpcError("u", "m", -32603, "VERIFICATION_BACKEND_FAILURE", NOT_APPLIED_MESSAGE, True),
    lib.RpcError("u", "m", -32603, "UPSTREAM_UNAVAILABLE", NOT_APPLIED_MESSAGE, False),
    lib.RpcError("u", "m", -32005, "RATE_LIMITED", "Rate limit exceeded (per-IP)", True),
    # a transport failure is not a node's answer at all
    lib.TestnetError(f"u m: HTTP 502 {NOT_APPLIED_MESSAGE}"),
]


def test_only_the_not_applied_answer_is_classified_as_such():
    assert lib.block_not_applied(not_applied())
    for error in OTHER_ERRORS:
        assert not lib.block_not_applied(error), error


class FlakyRpc:
    """Raises each of `errors` in turn, then answers; records every call."""

    def __init__(self, *errors, answer=None):
        self.errors, self.answer, self.calls = list(errors), answer, []

    def __call__(self, url, method, /, **params):
        self.calls.append((method, params))
        if self.errors:
            raise self.errors.pop(0)
        return self.answer


class FakeTime:
    def __init__(self):
        self.now, self.slept = 1000.0, []

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds

    def clock(self):
        return self.now


@pytest.mark.parametrize("failures", [1, 2])
def test_a_read_waits_for_the_node_to_apply_the_block(failures):
    rpc = FlakyRpc(*[not_applied()] * failures, answer={"state": "active", "balance": "7"})
    t = FakeTime()
    read = lib.retrying_reads(rpc, t.sleep, t.clock)
    assert read("http://a", "getAddressInformation", address="x", timeout=5) == rpc.answer
    assert rpc.calls == [("getAddressInformation", {"address": "x", "timeout": 5})] * (failures + 1)
    assert t.slept == [0.5, 1.0][:failures]


def test_a_read_still_not_applied_after_the_bound_fails_as_before():
    rpc = FlakyRpc(*[not_applied()] * 1000)
    t = FakeTime()
    read = lib.retrying_reads(rpc, t.sleep, t.clock)
    with pytest.raises(lib.RpcError) as caught:
        read("http://a", "getAddressInformation", address="x")
    assert lib.block_not_applied(caught.value)
    assert sum(t.slept) == lib.NOT_APPLIED_RETRY_SECONDS == 30
    assert t.slept[:4] == [0.5, 1.0, 2.0, 4.0] and max(t.slept) == lib.NOT_APPLIED_MAX_DELAY
    assert len(rpc.calls) == len(t.slept) + 1 == 11


@pytest.mark.parametrize("error", OTHER_ERRORS)
def test_other_errors_are_raised_without_a_retry(error):
    rpc = FlakyRpc(error, answer={})
    t = FakeTime()
    with pytest.raises(type(error)):
        lib.retrying_reads(rpc, t.sleep, t.clock)("http://a", "getAddressInformation")
    assert len(rpc.calls) == 1 and t.slept == []


def test_a_send_is_never_retried():
    rpc = FlakyRpc(not_applied(method="sendBoc"), answer={})
    t = FakeTime()
    read = lib.retrying_reads(rpc, t.sleep, t.clock)
    with pytest.raises(lib.RpcError):
        read("http://a", "sendBoc", boc="AA==")
    assert rpc.calls == [("sendBoc", {"boc": "AA=="})] and t.slept == []


def test_wrapping_twice_keeps_one_bound():
    read = lib.retrying_reads(FlakyRpc())
    assert lib.retrying_reads(read) is read


def test_two_stakes_boundary_is_accepted():
    # stake_held_for + elections_start_before == elected_for: back just in time.
    assert lib.validator_schedule(schedule_profile(stake_held_for=43200))
