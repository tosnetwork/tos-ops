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

import pytest
import testnet_lib as lib
from conftest import DATA

REPORT = (DATA / "consensus-key-report.txt").read_text()
DHT_NODE = json.loads((DATA / "dht-node-loopback.json").read_text())
RECORD = json.loads((DATA / "record-loopback.json").read_text())


def public_record(n: int) -> dict:
    """A self-consistent record with distinct identities (a public key is any 1312 bytes here)."""
    public = hashlib.shake_256(b"public-%d" % n).digest(lib.PQ_PUBLIC_KEY_BYTES)
    return {
        "operator": f"operator-{n}",
        "controller_id": hashlib.sha256(b"controller-%d" % n).hexdigest(),
        "adnl_id": hashlib.sha256(b"adnl-%d" % n).hexdigest(),
        "public_key": public.hex(),
        "key_id": lib.pq_key_id(public).hex(),
        "address": f"44.0.0.{n}:30001",
    }


# ---------------------------------------------------------------- profile and global id


def test_repository_profile_loads():
    profile = lib.load_profile()
    assert profile["global_id"]["value"] == 2
    assert profile["genesis"]["validators"] == 4
    assert profile["features"]["shielded_pool"] == "disabled"


@pytest.mark.parametrize("value", [1, 3, 0, True, 2**31, -(2**31) - 1, "2", None])
def test_global_id_refuses_mainnet_local_and_malformed(value):
    with pytest.raises(lib.TestnetError):
        lib.check_global_id(value)


@pytest.mark.parametrize("value", [2, -2, 7002, 2**31 - 1, -(2**31)])
def test_global_id_accepts_other_int32(value):
    assert lib.check_global_id(value) == value


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
        ("controller_id", "00" * 32, "must not be zero"),
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


def test_operator_set_must_have_four():
    with pytest.raises(lib.TestnetError, match="exactly four"):
        lib.check_operator_set([public_record(n) for n in range(1, 4)])
    with pytest.raises(lib.TestnetError, match="exactly four"):
        lib.check_operator_set([public_record(n) for n in range(1, 6)])


@pytest.mark.parametrize("field", ["controller_id", "adnl_id", "operator", "address"])
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


def test_manifest_packs_index_order_and_size():
    records = lib.check_operator_set([public_record(n) for n in range(1, 5)])
    packed = lib.pack_manifest(records)
    assert len(packed) == 5504
    record_size = 32 + 32 + 1312
    for index, record in enumerate(records):
        chunk = packed[index * record_size : (index + 1) * record_size]
        assert chunk[:32].hex() == record["controller_id"]
        assert chunk[32:64].hex() == record["adnl_id"]
        assert chunk[64:].hex() == record["public_key"]
    assert lib.manifest_input(records)[2] == {
        "controller_id": records[2]["controller_id"],
        "adnl_id": records[2]["adnl_id"],
        "public_key": records[2]["public_key"],
    }


# ---------------------------------------------------------------- template


TEMPLATE = "\n".join(
    [
        "wc_master setworkchain",
        lib.TEMPLATE_GLOBAL_ID_LINE,
        "0x544F5301 default-subwallet-id!",
        lib.TEMPLATE_EPOCH_LINE,
        lib.TEMPLATE_EPOCH_ABORT_LINE,
        "131072 =: orig_vset_valid_for",
    ]
)


def test_patch_replaces_only_the_three_pins():
    patched = lib.patch_template(TEMPLATE, 2, 1800000000)
    before, after = TEMPLATE.split("\n"), patched.split("\n")
    changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    assert changed == [1, 3, 4]
    assert after[1].startswith("2 setglobalid")
    assert after[3] == "1800000000 constant mainnet_genesis_utime"
    assert "1800000000" in after[4]
    assert after[5] == before[5]


def test_patch_refuses_a_changed_template():
    with pytest.raises(lib.TestnetError, match="exactly once"):
        lib.patch_template(
            TEMPLATE.replace(lib.TEMPLATE_GLOBAL_ID_LINE, "1 setglobalid"), 2, 1800000000
        )
    doubled = TEMPLATE + "\n" + lib.TEMPLATE_EPOCH_LINE
    with pytest.raises(lib.TestnetError, match="exactly once"):
        lib.patch_template(doubled, 2, 1800000000)


def test_patch_refuses_mainnet_id_and_old_epoch():
    with pytest.raises(lib.TestnetError):
        lib.patch_template(TEMPLATE, 1, 1800000000)
    with pytest.raises(lib.TestnetError, match="later"):
        lib.patch_template(TEMPLATE, 2, 1789434000)


def test_patch_matches_the_tos_template_when_available():
    root = os.environ.get("TOS_ROOT")
    if not root:
        pytest.skip("TOS_ROOT not set")
    from pathlib import Path

    text = (Path(root) / "crypto/smartcont/gen-zerostate.fif").read_text()
    patched = lib.patch_template(text, 2, 1800000000)
    diff = [(a, b) for a, b in zip(text.split("\n"), patched.split("\n")) if a != b]
    assert len(diff) == 3


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
