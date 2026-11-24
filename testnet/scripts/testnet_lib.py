"""Shared helpers for the public testnet ceremony and operator scripts.

Standard library only: an operator host runs these without a tos Python
environment. Every function that writes refuses to overwrite and never follows
a symlink, because the ceremony outputs (manifest, zerostate, global config)
are published and must not change silently once produced.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from fractions import Fraction
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROFILE_PATH = HERE.parent / "network" / "profile.json"

MAINNET_GLOBAL_ID = 1
LOCAL_GLOBAL_ID = 3
PQ_PUBLIC_KEY_BYTES = 1312
HASH_BYTES = 32
MASTERCHAIN = -1
MASTERCHAIN_SHARD = -(2**63)
PQ_KEY_DOMAIN = b"TOS-PQ-CONSENSUS-KEY-v1"
PQ_ALGORITHM_MLDSA44 = 1
ED25519_PUBLIC_TL_PREFIX = bytes.fromhex("c6b41348")
ED25519_PRIVATE_TL_PREFIX = bytes.fromhex("17236849")

# The lines of the canonical template a testnet ceremony replaces: the three
# that pin it to mainnet, and the five named constants that set the validator
# schedule. Exactly these and nothing else; any other difference in the
# template is a change the ceremony did not review, so it is refused.
TEMPLATE_GLOBAL_ID_LINE = "1 setglobalid   // TOS mainnet global_id"
TEMPLATE_EPOCH_LINE = "1789434000 constant mainnet_genesis_utime"
TEMPLATE_EPOCH_ABORT_LINE = 'now mainnet_genesis_utime = not abort"SOURCE_DATE_EPOCH must be 1789434000 for TOS mainnet genesis"'
# The schedule constants, keyed by validator_schedule()'s names. The template
# defines them once, checks the first election against them, then writes
# ConfigParam 15 and the initial set from them. The mainnet initial set lasts
# 6 h since tos #206 (131,072 s before it).
TEMPLATE_SCHEDULE_CONSTANTS = (
    ("initial_set_valid_for", "orig_vset_valid_for", 21600),
    ("elected_for", "validators_elected_for", 65536),
    ("elections_start_before", "elections_start_before", 16384),
    ("elections_end_before", "elections_end_before", 8192),
    ("stake_held_for", "stakes_frozen_for", 32768),
)
# The template's first schedule guard. Every schedule constant must be defined
# above it, so the guard checks the values the ceremony chose.
TEMPLATE_SCHEDULE_GUARD_LINE = "now orig_vset_valid_for + constant bootstrap_until"
# ConfigParam 15 must be written from the constants, not from literals.
TEMPLATE_ELECTION_PARAMS_LINE = (
    "validators_elected_for elections_start_before elections_end_before stakes_frozen_for "
    "config.election_params!"
)
# A version-16 genesis needs a public AUTH network tag (ConfigParam 48) defined
# before the template's own guard runs. The ceremony inserts the definition
# right after the first line; the guard must still be there to refuse a
# template run without it.
TEMPLATE_FIRST_LINE = "#!/usr/bin/create-state -s"
TEMPLATE_AUTH_GUARD_LINE = (
    'def? quantum-network-tag not abort"Version 16 Genesis requires an explicit AUTH network tag"'
)
AUTH_TAG_CONSTANT = "quantum-network-tag"

# ConfigParam 15, in the order config.election_params! takes it.
ELECTION_PARAM_NAMES = (
    "elected_for",
    "elections_start_before",
    "elections_end_before",
    "stake_held_for",
)
# Operators fund their staking accounts and deposit the stake after the chain
# is live and before the first election opens; this is the least time they get.
MIN_FIRST_ELECTION_LEAD_SECONDS = 3600


class TestnetError(Exception):
    """A refusal: the input is not what the ceremony or the operator expects."""


# A raw address whose workchain is negative (-1:<64 hex>, the masterchain). argparse
# reads a separate token that starts with "-" and is not a negative number as an
# option, so `--pool -1:<hex>` fails with "expected one argument"; `--pool=-1:<hex>`
# works. Printed and documented commands use the `=` form.
HYPHEN_ADDRESS = re.compile(r"^-[0-9]+:[0-9A-Fa-f]{64}$")


def join_address_values(argv: list[str]) -> list[str]:
    """argv with every `--opt -1:<hex>` pair joined into `--opt=-1:<hex>`.

    Only a long option without its own `=` followed by a token that is exactly a
    raw negative-workchain address is joined. No option name and no other value
    has that shape, and argparse refuses such a token wherever it stands, so the
    join changes nothing argparse would have accepted."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if (
            token.startswith("--")
            and len(token) > 2
            and "=" not in token
            and i + 1 < len(argv)
            and HYPHEN_ADDRESS.match(argv[i + 1])
        ):
            out.append(f"{token}={argv[i + 1]}")
            i += 2
            continue
        out.append(token)
        i += 1
    return out


def cli_argv(argv: list[str] | None) -> list[str]:
    """The arguments a script's main() parses: `argv`, or the process's own, with
    space-separated masterchain addresses joined to their options."""
    return join_address_values(list(sys.argv[1:] if argv is None else argv))


# ---------------------------------------------------------------- profile


def load_profile(path: Path = PROFILE_PATH) -> dict[str, Any]:
    profile = json.loads(Path(path).read_text())
    if profile.get("schema_version") != 1:
        raise TestnetError(f"{path}: unsupported schema_version")
    global_id = profile.get("global_id", {}).get("value")
    check_global_id(global_id)
    validator_schedule(profile)
    # The limits and the stake rule are checked on every load; the ceremony values
    # (the external count and what follows from it) once they are set.
    election_plan(profile, required=False)
    ports = profile.get("ports", {})
    required = (
        "adnl_udp",
        "quic_udp_offset",
        "console_tcp",
        "liteserver_tcp",
        "dht_udp",
        "json_rpc_loopback",
        "exporter_loopback",
    )
    for name in required:
        value = ports.get(name)
        if not isinstance(value, int) or not 0 < value < 65536:
            raise TestnetError(f"profile port {name} is missing or out of range: {value!r}")
    public = [ports["adnl_udp"], ports["adnl_udp"] + ports["quic_udp_offset"], ports["dht_udp"]]
    if ports["adnl_udp"] + ports["quic_udp_offset"] > 65535 or len(set(public)) != len(public):
        raise TestnetError("profile UDP ports collide or the derived QUIC port is out of range")
    shielded_pool_record(profile)
    return profile


SHIELDED_POOL_DISABLED = "disabled"
SHIELDED_POOL_RESTRICTED = "restricted-epoch-6-test"
SHIELDED_POOL_EPOCH = 6


SHIELDED_POOL_VK_BYTES = 1248
SHIELDED_POOL_RECOVERY_SLOT = 2
FEATURE_KEYS = {"shielded_pool", "energy", "note", "shielded_pool_record"}


def _hex(n: int):
    pattern = re.compile(f"[0-9a-f]{{{n}}}")

    def check(value: Any, where: str) -> None:
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise TestnetError(f"shielded pool record: {where} must be {n} lowercase hex digits")

    return check


def _text(value: Any, where: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise TestnetError(f"shielded pool record: {where} must be a non-empty string")


def _positive(value: Any, where: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise TestnetError(f"shielded pool record: {where} must be a positive integer")


def _date(value: Any, where: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]", value):
        raise TestnetError(f"shielded pool record: {where} must be a YYYY-MM-DD date")


def _address(value: Any, where: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"0:[0-9a-f]{64}", value):
        raise TestnetError(f"shielded pool record: {where} must be a workchain-0 raw address")


def _denominations(value: Any, where: str) -> None:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(v, int) or isinstance(v, bool) or v <= 0 for v in value)
        or value != sorted(set(value))
    ):
        raise TestnetError(f"shielded pool record: {where} must be increasing positive integers")


_HEX64, _HEX40 = _hex(64), _hex(40)
_GAS = {"topup": _positive, "deposit": _positive, "transact": _positive, "bounce": _positive}
_DECISION = {"item": _text, "decision": _text, "by": _text, "date": _date, "record": _text}
SHIELDED_POOL_SCHEMA: dict[str, Any] = {
    "status": _text,
    "scope": _text,
    "metadata_only": _text,
    "network": {
        "name": _text,
        "epoch": _positive,
        "global_id": _positive,
        "global_version": _positive,
        "zero_state_root_hash": _HEX64,
        "zero_state_file_hash": _HEX64,
        "auth_network_tag": _HEX64,
        "config_param_48_hash": _HEX64,
        "runtime_commit": _HEX40,
    },
    "pool": {
        "address": _address,
        "code_hash": _HEX64,
        "data_hash": _HEX64,
        "state_init_hash": _HEX64,
        "state_init_boc_sha256": _HEX64,
        "code_boc_sha256": _HEX64,
        "data_boc_sha256": _HEX64,
        "manifest_sha256": _HEX64,
        "execution_domain": _HEX64,
        "initial_endowment_tos": _positive,
        "immutable_reserve_floor_tos": _positive,
        "withdrawal_fee_nanotos": _positive,
        "denominations_tos": _denominations,
        "gas_ceilings": _GAS,
        "note": _text,
    },
    "profile": {
        "path": _text,
        "source_commit": _HEX40,
        "source_blob": _HEX40,
        "file_sha256": _HEX64,
        "profile_hash": _HEX64,
        "poseidon2_manifest_sha256": _HEX64,
        "recovery_payload_slot": lambda v, w: None,  # bound below
    },
    "groth16": {
        "ceremony": _text,
        "vk_sha256": _HEX64,
        "vk_bytes": _positive,
        "proving_key_sha256": _HEX64,
        "transcript": _HEX64,
        "trust_assumption": _text,
    },
    "gate_decisions": [_DECISION],
    "plan": _text,
}


def _check_shape(value: Any, schema: Any, where: str) -> None:
    """Exactly the schema's keys, each of its type and format; lists of one shape."""
    if isinstance(schema, dict):
        if not isinstance(value, dict):
            raise TestnetError(f"shielded pool record: {where} must be an object")
        missing, unknown = set(schema) - set(value), set(value) - set(schema)
        if missing or unknown:
            raise TestnetError(
                f"shielded pool record: {where} has missing keys {sorted(missing)} "
                f"and unknown keys {sorted(unknown)}"
            )
        for key, sub in schema.items():
            _check_shape(value[key], sub, f"{where}.{key}")
    elif isinstance(schema, list):
        if not isinstance(value, list) or not value:
            raise TestnetError(f"shielded pool record: {where} must be a non-empty list")
        for i, item in enumerate(value):
            _check_shape(item, schema[0], f"{where}[{i}]")
    else:
        schema(value, where)


def shielded_pool_record(profile: dict[str, Any]) -> dict[str, Any] | None:
    """The shielded pool's activation record, or None while the feature is disabled.

    The flag is metadata: it deploys and protects nothing. A restricted status
    must carry a record of exactly the schema's keys, types and formats, bound
    to this profile: its network name, global id, global version, the AUTH tag
    of the same epoch, and an address that is the StateInit hash. Any other
    status, a record without that status, or a record while disabled is refused.
    """
    features = profile.get("features", {})
    if not isinstance(features, dict) or set(features) - FEATURE_KEYS:
        raise TestnetError(
            f"profile features has unknown keys {sorted(set(features) - FEATURE_KEYS)}"
        )
    if features.get("energy") != "disabled":
        raise TestnetError(f"unknown energy status {features.get('energy')!r}")
    status = features.get("shielded_pool")
    record = features.get("shielded_pool_record")
    if status == SHIELDED_POOL_DISABLED:
        if "shielded_pool_record" in features:
            raise TestnetError("shielded pool record present while the feature is disabled")
        return None
    if status != SHIELDED_POOL_RESTRICTED:
        raise TestnetError(f"unknown shielded pool status {status!r}")
    if not isinstance(record, dict) or record.get("status") != status:
        raise TestnetError("a restricted shielded pool needs a record with the same status")
    _check_shape(record, SHIELDED_POOL_SCHEMA, "record")
    network, pool = record["network"], record["pool"]
    genesis = profile.get("genesis", {})
    tag = genesis.get("auth_network_tag", {})
    bindings = (
        ("network name", network["name"], profile.get("network")),
        ("global id", network["global_id"], profile.get("global_id", {}).get("value")),
        ("global version", network["global_version"], genesis.get("global_version")),
        ("AUTH tag", network["auth_network_tag"], tag.get("value")),
        ("epoch", network["epoch"], tag.get("campaign_epoch")),
    )
    for what, ours, theirs in bindings:
        if ours != theirs:
            raise TestnetError(
                f"shielded pool record: {what} {ours!r} differs from the profile's {theirs!r}"
            )
    if network["epoch"] != SHIELDED_POOL_EPOCH:
        raise TestnetError("shielded pool record: the restricted test is for epoch 6 only")
    if pool["address"] != "0:" + pool["state_init_hash"]:
        raise TestnetError("shielded pool record: the address is not 0:<StateInit hash>")
    if not 0 < pool["immutable_reserve_floor_tos"] <= pool["initial_endowment_tos"]:
        raise TestnetError("shielded pool record: the reserve floor exceeds the endowment")
    if record["groth16"]["vk_bytes"] != SHIELDED_POOL_VK_BYTES:
        raise TestnetError(
            f"shielded pool record: groth16.vk_bytes must be {SHIELDED_POOL_VK_BYTES}"
        )
    slot = record["profile"]["recovery_payload_slot"]
    if slot != SHIELDED_POOL_RECOVERY_SLOT or isinstance(slot, bool):
        raise TestnetError(
            f"shielded pool record: profile.recovery_payload_slot must be {SHIELDED_POOL_RECOVERY_SLOT}"
        )
    return record


# ---------------------------------------------------------------- validator resources

# install-node.sh activate --role validator --cache-bytes N --memory-max SIZE [--memory-high SIZE]
# writes these as a drop-in of the validator unit. The unit's defaults are the 1 GiB
# caches (owner decision 2026-10-15), so a drop-in may only lower them.
RESOURCE_CACHE_MIN = 64 << 20
RESOURCE_CACHE_MAX = 1 << 30
# Each cgroup limit leaves at least this beside the two caches: memtables, the cell
# cache, consensus candidates and allocator retention are not cache-bounded.
RESOURCE_HEADROOM = 1 << 30
RESOURCES_UNIT = "tos-testnet-validator.service"
RESOURCES_DROP_IN = "50-resources.conf"
_SIZE_UNITS = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30}


def resource_size(value: str, what: str, suffixes: bool = True) -> int:
    """A positive byte count: decimal digits, optionally with a 1024-based K, M or G."""
    pattern = r"([1-9][0-9]{0,15})([KMG]?)" if suffixes else r"([1-9][0-9]{0,15})()"
    match = re.fullmatch(pattern, value) if isinstance(value, str) else None
    if match is None:
        form = "bytes or a K/M/G size" if suffixes else "a positive byte count"
        raise TestnetError(f"{what} must be {form}, not {value!r}")
    return int(match.group(1)) * _SIZE_UNITS[match.group(2)]


def mem_total_bytes(meminfo: str) -> int:
    match = re.search(r"(?m)^MemTotal:\s+([0-9]+) kB$", meminfo)
    if match is None:
        raise TestnetError("MemTotal not found in /proc/meminfo")
    return int(match.group(1)) * 1024


def validator_resources(
    cache_bytes: str, memory_max: str, memory_high: str | None, mem_total: int
) -> dict[str, Any]:
    """The checked values of a validator resources drop-in, or TestnetError."""
    cache = resource_size(cache_bytes, "--cache-bytes", suffixes=False)
    if not RESOURCE_CACHE_MIN <= cache <= RESOURCE_CACHE_MAX:
        raise TestnetError(
            f"--cache-bytes {cache} is outside {RESOURCE_CACHE_MIN}..{RESOURCE_CACHE_MAX} "
            "(64 MiB up to the 1 GiB cap)"
        )
    floor = 2 * cache + RESOURCE_HEADROOM
    high = resource_size(memory_high, "--memory-high") if memory_high else None
    top = resource_size(memory_max, "--memory-max")
    for what, value in (("--memory-max", top), ("--memory-high", high)):
        if value is not None and value < floor:
            raise TestnetError(
                f"{what} {value} leaves less than 1 GiB beside two caches of {cache} "
                f"(at least {floor})"
            )
    if high is not None and high >= top:
        raise TestnetError(f"--memory-high {high} must be below --memory-max {top}")
    if top > mem_total:
        raise TestnetError(f"--memory-max {top} exceeds this host's MemTotal {mem_total}")
    return {"cache_bytes": cache, "memory_max_bytes": top, "memory_high_bytes": high}


def validator_resources_drop_in(resources: dict[str, Any]) -> str:
    """The drop-in text: the cgroup limits and both caches, nothing else."""
    lines = [
        "# Written by install-node.sh activate --role validator (validator resources).",
        "# Do not edit by hand; rerun activate with the same or new reviewed values.",
        "[Service]",
        f"MemoryMax={resources['memory_max_bytes']}",
    ]
    if resources["memory_high_bytes"] is not None:
        lines.append(f"MemoryHigh={resources['memory_high_bytes']}")
    lines += [
        f"Environment=TOS_ROCKSDB_BLOCK_CACHE_SIZE={resources['cache_bytes']}",
        f"Environment=TOS_CELLDB_CACHE_BYTES={resources['cache_bytes']}",
    ]
    return "\n".join(lines) + "\n"


def write_validator_resources(
    out_dir: str, cache_bytes: str, memory_max: str, memory_high: str, meminfo_path: str
) -> None:
    """install-node.sh's helper: write the drop-in and its record into out_dir."""
    resources = validator_resources(
        cache_bytes,
        memory_max,
        memory_high or None,
        mem_total_bytes(Path(meminfo_path).read_text()),
    )
    text = validator_resources_drop_in(resources)
    record = {
        "unit": RESOURCES_UNIT,
        "drop_in": f"{RESOURCES_UNIT}.d/{RESOURCES_DROP_IN}",
        "drop_in_sha256": hashlib.sha256(text.encode()).hexdigest(),
        **resources,
    }
    (Path(out_dir) / RESOURCES_DROP_IN).write_text(text)
    (Path(out_dir) / "validator-resources.json").write_text(json.dumps(record, indent=2) + "\n")


def validator_schedule(profile: dict[str, Any]) -> dict[str, int]:
    """The initial set's lifetime and ConfigParam 15, checked against each other.

    Returns {"initial_set_valid_for": s, "elected_for": s, ...}. A schedule the
    Elector would accept but that cannot work is refused here, before a zero
    state commits to it: an election window that is empty or does not end
    before the term starts, or a first election that opens before operators
    can have their stakes ready.
    """
    genesis = profile.get("genesis", {})
    params = genesis.get("election_params", {})
    if not isinstance(params, dict) or set(params) != set(ELECTION_PARAM_NAMES):
        raise TestnetError(f"genesis election_params must name exactly {ELECTION_PARAM_NAMES}")
    values = {"initial_set_valid_for": genesis.get("initial_set_valid_for_seconds")}
    values.update({name: params[name] for name in ELECTION_PARAM_NAMES})
    for name, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < 2**32:
            raise TestnetError(f"genesis schedule {name} is missing or out of range: {value!r}")
    if (
        not values["elections_end_before"]
        < values["elections_start_before"]
        < values["elected_for"]
    ):
        raise TestnetError(
            "election params need elections_end_before < elections_start_before < elected_for"
        )
    lead = values["initial_set_valid_for"] - values["elections_start_before"]
    if lead < MIN_FIRST_ELECTION_LEAD_SECONDS:
        raise TestnetError(
            f"the first election would open {lead} s after genesis; operators need at least "
            f"{MIN_FIRST_ELECTION_LEAD_SECONDS} s to fund and deposit their stakes"
        )
    return values


# ---------------------------------------------------------------- election plan

# The genesis set is the team's validators only. External validators register
# their records and pools before genesis and join from the first election; how
# many there are (E) is known only when registration closes, so the ceremony sets
# elections.external_validators, and with it the team stake multiple, the bootstrap
# wallet and the genesis supply, which election_plan() derives and checks.

# The largest max factor tosctl's election task accepts: 1.0..100.0, upstream's
# validator-elect-req.fif bound (tos tosctl node-control: ElectionsConfig::validate,
# `config elections max-factor` and the runner before it signs a stake). Releases
# before that change refuse anything above 3.0; a team pool's onboarding probes the
# host's tosctl (validator_host.check_tosctl_max_factor) so an old one refuses
# loudly instead of capping the team's weight.
TOSCTL_MAX_FACTOR = Fraction(100)
# tosctl's own default max factor, which external pools keep.
TOSCTL_DEFAULT_MAX_FACTOR = Fraction(3)
# The Elector keeps 1 TOS of every stake message for its confirmation
# (elector-code.fc process_new_stake: msg_value -= 1000000000).
ELECTOR_CONFIRMATION_NANOTOS = 10**9
# The template's stake-limit ceilings: Tomi values are VarUInteger 16, max_factor
# is a 16.16 fraction in 32 bits.
MAX_FACTOR_ONE = 1 << 16
VALIDATOR_NUM_FIELDS = ("max_validators", "max_main_validators", "min_validators")
STAKE_LIMIT_FIELDS = ("min_stake_tos", "max_stake_tos", "min_total_stake_tos", "max_factor")
# What the ceremony sets once registration closes, all together or none.
PLAN_INPUTS = (
    ("elections", "external_validators"),
    ("elections", "team_stake_multiple"),
    ("elections", "bootstrap_wallet_tos"),
    ("genesis", "total_supply_tos"),
)
# How far the team's weight share may sit from elections.team_weight_percent, in
# percentage points: the Elector's 1 TOS confirmation and integer weights move it
# by a few thousandths.
TEAM_WEIGHT_TOLERANCE = Fraction(1, 100)


def _whole(value: Any, where: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise TestnetError(
            f"profile {where} must be a whole number of at least {minimum}: {value!r}"
        )
    return value


def genesis_limits(profile: dict[str, Any]) -> dict[str, int]:
    """The genesis set size, ConfigParam 16 and ConfigParam 17 the profile decides.

    Returns {"validators", "max_validators", "max_main_validators",
    "min_validators", "min_stake_tos", "max_stake_tos", "min_total_stake_tos",
    "max_factor"} (max_factor a whole multiple). The genesis set must be able to
    conclude an election on its own (min_validators <= the genesis set) and fit
    among the main validators."""
    genesis = profile.get("genesis", {})
    count = _whole(genesis.get("validators"), "genesis.validators", 1)
    values: dict[str, int] = {"validators": count}
    for section, fields in (
        ("validator_num", VALIDATOR_NUM_FIELDS),
        ("stake_limits", STAKE_LIMIT_FIELDS),
    ):
        block = genesis.get(section)
        if not isinstance(block, dict) or set(block) != set(fields):
            raise TestnetError(f"profile genesis.{section} must name exactly {fields}")
        for name in fields:
            values[name] = _whole(block[name], f"genesis.{section}.{name}", 1)
    if values["max_validators"] >= 1 << 16:
        raise TestnetError("genesis.validator_num.max_validators does not fit 16 bits")
    if (
        not values["min_validators"]
        <= count
        <= values["max_main_validators"]
        <= values["max_validators"]
    ):
        raise TestnetError(
            "genesis.validator_num needs min_validators <= genesis.validators <= "
            "max_main_validators <= max_validators, so that the genesis set alone "
            f"concludes an election: {values}"
        )
    if values["min_stake_tos"] > values["max_stake_tos"]:
        raise TestnetError("genesis.stake_limits.min_stake_tos is above max_stake_tos")
    if values["max_factor"] * MAX_FACTOR_ONE >= 1 << 32:
        raise TestnetError("genesis.stake_limits.max_factor does not fit ConfigParam 17")
    return values


def tosctl_max_factor(profile: dict[str, Any], key: str = "max_factor") -> Fraction:
    """elections.max_factor (a team pool's) or elections.external_max_factor (an
    external pool's), what enable-elections.sh gives tosctl, as a fraction."""
    text = profile.get("elections", {}).get(key)
    try:
        value = Fraction(text) if isinstance(text, str) else None
    except (ValueError, ZeroDivisionError):
        value = None
    if value is None or not 1 <= value <= TOSCTL_MAX_FACTOR:
        raise TestnetError(
            f"profile elections.{key} {text!r} must be a decimal string from 1.0 to "
            f"{float(TOSCTL_MAX_FACTOR)}: tosctl's election task refuses any other"
        )
    return value


def max_factor_text(value: Fraction) -> str:
    """The decimal tosctl takes: "10.0", "2.5"."""
    return str(float(value))


def team_stake_multiple_rule(external: int) -> Fraction:
    """The team's stake per pool in units: (E+1)/2, and at least one (the Elector's
    minimum). Both team pools then hold E+1 units against the E external ones,
    just above half, and with one team pool absent the external pools hold
    E/(E + (E+1)/2) = 2E/(3E+1), strictly below two thirds."""
    return max(Fraction(1), Fraction(external + 1, 2))


def team_stake_tos(multiple: Fraction, unit: int) -> int:
    """The team pool's stake order in whole TOS: multiple x (unit - 1) + 1, rounded
    down. Whatever the Elector credits on top of an order (`elector_credit`), the
    team pool's credit is then at most `multiple` unit credits:
    multiple x (unit + c) - (multiple x (unit - 1) + 1 + c) = (multiple - 1)(1 + c)
    >= 0. So at ConfigParam 17's max factor 10 a 10-unit team stake is never cut."""
    return int(multiple * (unit - 1)) + 1


def elector_credit(stake_nanotos: int, surplus_nanotos: int) -> int:
    """What the Elector records for a pool's stake order. tosctl sends the pool
    stake_order_nanotos (ELECTOR_STAKE_FEE 1 TOS + NPOOL_COMPUTE_FEE 0.2 TOS) with
    the stake amount in the body; the pool sends the stake to the Elector with send
    mode 64, adding what is left of that 1.2 TOS after its own compute and
    forwarding fees; process_new_stake keeps 1 TOS. `surplus_nanotos` is
    stake_order_nanotos - pool_new_stake_cost_nanotos - 1 TOS."""
    return stake_nanotos + surplus_nanotos


def credit_surplus(profile: dict[str, Any]) -> int:
    """elections.stake_order_nanotos less the pool's measured cost and the Elector's 1 TOS."""
    e = profile.get("elections", {})
    order = _whole(e.get("stake_order_nanotos"), "elections.stake_order_nanotos", 1)
    cost = _whole(e.get("pool_new_stake_cost_nanotos"), "elections.pool_new_stake_cost_nanotos")
    surplus = order - cost - ELECTOR_CONFIRMATION_NANOTOS
    if surplus < 0:
        raise TestnetError(
            "elections.stake_order_nanotos does not cover the pool's cost and the Elector's 1 TOS"
        )
    return surplus


def finalizes(weight: int, total: int) -> bool:
    """TOS finalizes with at least two thirds of the weight (tos quorum.h
    has_quorum: signed * 3 >= total * 2; Simplex's quorum threshold ceil(2t/3))."""
    return 3 * weight >= 2 * total


def multiple_text(value: Fraction) -> str:
    return str(value.numerator) if value.denominator == 1 else str(float(value))


def simulate_election(
    members: list[tuple[str, int, int]], limits: dict[str, int]
) -> tuple[list[dict[str, Any]] | None, str]:
    """The Elector's choice (elector-code.fc conduct_elections and try_elect) for
    `members`, each (label, stake as the Elector holds it in nanotos, max factor in
    16.16). Returns (elected, "") or (None, why the election fails). Ties are
    ordered by label; the Elector orders them by stake time."""
    min_stake = limits["min_stake_tos"] * NANOTOS
    max_stake = limits["max_stake_tos"] * NANOTOS
    min_total = limits["min_total_stake_tos"] * NANOTOS
    max_factor = limits["max_factor"] * MAX_FACTOR_ONE
    admitted = [m for m in members if m[1] >= min_stake]
    total = sum(m[1] for m in admitted)
    if total < min_total:
        return None, f"the total stake {total / NANOTOS} TOS is below min_total_stake"
    ordered = sorted(admitted, key=lambda m: (-m[1], m[0]))
    n = min(len(ordered), limits["max_validators"])
    least = max(limits["min_validators"], 1)
    if n < least:
        return None, f"{n} stakes, fewer than min_validators {least}"
    capped = [(label, min(stake, max_stake), min(f, max_factor)) for label, stake, f in ordered]
    best, chosen = 0, 0
    for i in range(least, n + 1):
        floor = capped[i - 1][1]
        if floor < min_stake:
            continue
        candidate = sum(min(s, (f * floor) >> 16) for _, s, f in capped[:i])
        if candidate > best:
            best, chosen = candidate, i
    if chosen == 0 or best < min_total:
        return None, f"the best set stakes {best / NANOTOS} TOS, below min_total_stake"
    floor = capped[chosen - 1][1]
    elected = []
    for label, stake, f in capped[:chosen]:
        true_stake = min(stake, (f * floor) >> 16)
        elected.append(
            {
                "label": label,
                "stake_nanotos": stake,
                "true_stake_nanotos": true_stake,
                "weight": (true_stake << 60) // best,
            }
        )
    return elected, ""


def election_plan(
    profile: dict[str, Any], required: bool = True, external: int | None = None
) -> dict[str, Any] | None:
    """What the profile's election parameters imply for E external validators, checked.

    E is `external` when given (the coordinator's `plan` command), else the
    profile's elections.external_validators. With the profile's E, the profile's
    team_stake_multiple, bootstrap_wallet_tos and genesis.total_supply_tos must be
    exactly the derived values. Before the ceremony sets E (null) only the
    limits are checked, and the result is None unless `required`, which refuses.

    Refuses unless: an election of the team pools alone concludes and elects
    them all (also for E = 0); with E external pools every pool is elected and no
    team stake is cut by a max factor; the external validators never hold two
    thirds of the weight (TOS finalizes at two thirds, `finalizes`), with every
    pool elected or with one team pool absent from the election; and with E >= 3
    the team's share is in [elections.team_weight_percent, two thirds). The team
    holding two thirds is allowed and reported (team_finalizes_alone: E = 0 and
    1, or when few external validators stand), as are the partial sets and the
    number of external validators the elected set needs online."""
    limits = genesis_limits(profile)
    e = profile.get("elections", {})
    unit = _whole(e.get("stake_tos"), "elections.stake_tos", 1)
    pool_tos = _whole(e.get("pool_tos"), "elections.pool_tos", 1)
    if pool_tos < 2 * unit:
        raise TestnetError("elections.pool_tos must hold two stakes of elections.stake_tos")
    reserve = _whole(e.get("pool_owner_reserve_tos"), "elections.pool_owner_reserve_tos")
    deploy = _whole(e.get("pool_deploy_tos"), "elections.pool_deploy_tos", 1)
    operator = _whole(e.get("operator_funding_tos"), "elections.operator_funding_tos", 1)
    margin = _whole(
        e.get("bootstrap_margin_tos_per_pool"), "elections.bootstrap_margin_tos_per_pool"
    )
    transfer_fee = _whole(
        e.get("bootstrap_transfer_fee_nanotos"), "elections.bootstrap_transfer_fee_nanotos", 1
    )
    target = _whole(e.get("team_weight_percent"), "elections.team_weight_percent", 1)
    if target >= 100:
        raise TestnetError("elections.team_weight_percent must be below 100")
    factor = (
        tosctl_max_factor(profile),
        tosctl_max_factor(profile, "external_max_factor"),
        credit_surplus(profile),
    )
    if factor[1] != TOSCTL_DEFAULT_MAX_FACTOR:
        raise TestnetError(
            f"profile elections.external_max_factor must be tosctl's default "
            f"{max_factor_text(TOSCTL_DEFAULT_MAX_FACTOR)}: external pools keep it"
        )
    team = limits["validators"]
    max_external = _whole(e.get("max_external_validators"), "elections.max_external_validators")
    if max_external != limits["max_validators"] - team:
        raise TestnetError(
            f"elections.max_external_validators {max_external} is not max_validators "
            f"{limits['max_validators']} less the genesis set's {team}"
        )
    given = {key: profile.get(section, {}).get(key) for section, key in PLAN_INPUTS}
    from_profile = external is None
    if from_profile:
        if given["external_validators"] is None:
            if any(value is not None for value in given.values()):
                raise TestnetError(
                    f"profile {[k for k, v in given.items() if v is not None]} are set but "
                    "elections.external_validators is not; the ceremony sets them together"
                )
            # The team alone must always be able to elect itself.
            _plan_for(
                limits,
                unit,
                pool_tos,
                reserve,
                deploy,
                operator,
                margin,
                transfer_fee,
                target,
                factor,
                0,
            )
            if required:
                raise TestnetError(
                    "profile elections.external_validators is not set: the ceremony sets it, "
                    "with the values `testnet-coordinator.py plan` derives, once external "
                    "registration closes"
                )
            return None
        external = given["external_validators"]
    external = _whole(external, "elections.external_validators")
    if external > max_external:
        raise TestnetError(
            f"{external} external validators exceed the {max_external} seats beside the "
            f"genesis set's {team}"
        )
    # The team-only election is checked whatever E is: an election no external
    # validator joins must still conclude.
    _plan_for(
        limits, unit, pool_tos, reserve, deploy, operator, margin, transfer_fee, target, factor, 0
    )
    plan = _plan_for(
        limits,
        unit,
        pool_tos,
        reserve,
        deploy,
        operator,
        margin,
        transfer_fee,
        target,
        factor,
        external,
    )
    if from_profile:
        try:
            multiple = Fraction(str(given["team_stake_multiple"]))
        except (ValueError, ZeroDivisionError):
            multiple = None
        if multiple != Fraction(plan["team_stake_multiple"]):
            raise TestnetError(
                f"profile elections.team_stake_multiple {given['team_stake_multiple']!r} is not "
                f"{plan['team_stake_multiple']}, the multiple for {external} external validators"
            )
        for section, key in PLAN_INPUTS[2:]:
            if given[key] != plan[key]:
                raise TestnetError(
                    f"profile {section}.{key} {given[key]!r} is not {plan[key]}, what "
                    f"{external} external validators need (testnet-coordinator.py plan)"
                )
    return plan


def _plan_for(
    limits,
    unit,
    pool_tos,
    reserve,
    deploy,
    operator,
    margin,
    transfer_fee,
    target,
    factor,
    external,
) -> dict[str, Any]:
    team = limits["validators"]
    multiple = team_stake_multiple_rule(external)
    team_stake = team_stake_tos(multiple, unit)
    if team_stake > limits["max_stake_tos"]:
        raise TestnetError(f"a team stake of {team_stake} TOS exceeds max_stake_tos")
    # Two stakes per pool (the first and the overlapping second election), and the
    # unit pool's headroom above its two stakes.
    team_principal = pool_tos + 2 * (team_stake - unit)
    # Every pool owner may deploy its own pool (onboard --no-host), so each owner
    # gets the deployment on top of its reserve: what it keeps for a withdrawal is
    # then the reserve however the pool was deployed.
    team_owner = team_principal + reserve + deploy
    external_owner = pool_tos + reserve + deploy
    pools = team + external
    # fund-op- and fund-owner- for every pool, and the sweep.
    transfers = 2 * pools + 1
    fees = -(-transfers * transfer_fee // NANOTOS)
    # The margin covers a retried funding transfer or a fee rise; both are per pool.
    margin_total = margin * pools
    bootstrap = (
        team * (operator + team_owner)
        + external * (operator + external_owner)
        + margin_total
        + fees
    )
    # `factor` is (team max factor, external max factor, the Elector's credit
    # surplus over the stake amount).
    team_factor, external_factor, surplus = factor
    team_f16 = int(team_factor * MAX_FACTOR_ONE)
    external_f16 = int(external_factor * MAX_FACTOR_ONE)
    team_credit = elector_credit(team_stake * NANOTOS, surplus)
    unit_credit = elector_credit(unit * NANOTOS, surplus)
    team_members = [(f"team-{i}", team_credit, team_f16) for i in range(team)]
    external_members = [(f"external-{i}", unit_credit, external_f16) for i in range(external)]
    alone, why = simulate_election(team_members, limits)
    if alone is None or len(alone) != team:
        raise TestnetError(
            f"an election of the {team} team pools alone at {team_stake} TOS each would fail "
            f"({why or 'not every team pool elected'}); check genesis.validator_num and "
            "genesis.stake_limits (min_total_stake_tos)"
        )
    elected, why = simulate_election(team_members + external_members, limits)
    if elected is None or len(elected) != pools:
        raise TestnetError(
            f"an election of {team} team and {external} external pools would not elect them all "
            f"({why or 'some left out'})"
        )
    for member in elected:
        if (
            member["label"].startswith("team-")
            and member["true_stake_nanotos"] != member["stake_nanotos"]
        ):
            limit = min(Fraction(limits["max_factor"]), team_factor)
            raise TestnetError(
                f"with {external} external validators the team stakes {multiple_text(multiple)} "
                f"units, but a max factor of {float(limit)} counts at most {float(limit)} units "
                f"(ConfigParam 17 allows {limits['max_factor']}, the team's tosctl "
                f"elections.max_factor {float(team_factor)}); the team's weight would fall "
                "below its share"
            )
    team_weight, external_weight, total = side_weights(elected)
    # The hard invariant: the external validators never hold two thirds, so they
    # cannot finalize without the team, with every pool elected or with either team
    # pool absent from the election.
    if finalizes(external_weight, total):
        raise TestnetError(
            f"with {external} external validators they would hold at least two thirds of "
            "the weight and finalize without the team"
        )
    one_team = _partial_election(team_members[:-1], external_members, limits)
    # Whatever that election elects, if it concludes at all.
    if one_team["concluded"] and one_team["external_finalizes_alone"]:
        raise TestnetError(
            f"with {external} external validators and one team pool absent the external "
            "validators would hold at least two thirds of the weight and finalize alone"
        )
    share = Fraction(100 * team_weight, total)
    if external >= 3 and not target <= share < Fraction(200, 3):
        raise TestnetError(
            f"with {external} external validators the team holds {float(share):.4f} % of the "
            f"weight, outside [{target} %, two thirds)"
        )
    partial = [
        _partial_election(team_members, external_members[:k], limits) for k in range(external + 1)
    ]
    alone = [k for k, case in enumerate(partial) if case["team_finalizes_alone"]]
    # Liveness of the elected set of all pools: how many external validators must be
    # online for two thirds, with both team validators up and with one down.
    each = elected[-1]["weight"] if external else 0
    team_each = team_weight // team

    def needed(team_up: int) -> int | None:
        for k in range(external + 1):
            if finalizes(team_up * team_each + k * each, total):
                return k
        return None

    return {
        "team_validators": team,
        "external_validators": external,
        "team_stake_multiple": multiple_text(multiple),
        "unit_stake_tos": unit,
        "team_stake_tos": team_stake,
        "team_pool_principal_tos": team_principal,
        "external_pool_principal_tos": pool_tos,
        "team_owner_funding_tos": team_owner,
        "external_owner_funding_tos": external_owner,
        "operator_funding_tos": operator,
        "bootstrap_transfers": transfers,
        "bootstrap_transfer_fees_tos": fees,
        "bootstrap_margin_tos": margin_total,
        "bootstrap_wallet_tos": bootstrap,
        "total_supply_tos": bootstrap + GENESIS_SYSTEM_ACCOUNTS_TOS,
        "team_weight_percent": float(share),
        "team_finalizes_alone": finalizes(team_weight, total),
        "external_finalizes_alone": False,
        "team_only_election": f"elects the {team} team pools",
        "partial_sets": {
            "externals_standing_with_both_team_pools": [
                {"externals": k, **case} for k, case in enumerate(partial)
            ],
            "team_finalizes_alone_with_externals": alone,
            "one_team_pool_absent": one_team,
            # Not prevented by stakes: if both team pools miss an election (both
            # hosts run the same tosctl and election config), the external
            # validators elect themselves and hold all of the weight from E = 2.
            # The ceremony's runbook checks the Elector before each election closes.
            "both_team_pools_absent": dict(
                _partial_election([], external_members, limits),
                guarded_by="runbook: confirm both team stakes in the Elector before close",
            ),
        },
        "liveness": {
            "externals_online_needed_both_team_up": needed(team),
            "externals_online_needed_one_team_down": needed(team - 1),
        },
        "team_max_factor": max_factor_text(team_factor),
        "team_credit_nanotos": team_credit,
        "unit_credit_nanotos": unit_credit,
        "external_max_factor": max_factor_text(external_factor),
    }


def side_weights(elected: list[dict[str, Any]]) -> tuple[int, int, int]:
    """(team weight, external weight, total) of an elected set from simulate_election."""
    total = sum(m["weight"] for m in elected)
    team = sum(m["weight"] for m in elected if m["label"].startswith("team-"))
    return team, total - team, total


def _partial_election(team_members, external_members, limits) -> dict[str, Any]:
    """What an election of only these members gives: whether it elects them all,
    each side's share and whether either side finalizes alone."""
    elected, why = simulate_election(team_members + external_members, limits)
    if elected is None:
        return {"concluded": False, "elected": False, "why": why}
    team, others, total = side_weights(elected)
    return {
        "concluded": True,
        "elected": len(elected) == len(team_members) + len(external_members),
        "team_weight_percent": float(Fraction(100 * team, total)),
        "team_finalizes_alone": finalizes(team, total),
        "external_finalizes_alone": finalizes(others, total),
    }


def pool_amounts(profile: dict[str, Any], team: bool) -> dict[str, int]:
    """One pool's onboarding amounts in nanotos: {"stake", "principal", "owner_funding",
    "operator_funding", "deploy"}, and "max_factor", the decimal its tosctl election
    task stakes with. A team pool's needs the ceremony's plan; an external pool's
    are the unit amounts and tosctl's default max factor, and do not."""
    e = profile["elections"]
    if team:
        plan = election_plan(profile)
        stake, principal = plan["team_stake_tos"], plan["team_pool_principal_tos"]
        factor = max_factor_text(tosctl_max_factor(profile))
    else:
        stake, principal = int(e["stake_tos"]), int(e["pool_tos"])
        factor = max_factor_text(tosctl_max_factor(profile, "external_max_factor"))
    deploy = int(e["pool_deploy_tos"])
    return {
        "stake": stake * NANOTOS,
        "principal": principal * NANOTOS,
        "owner_funding": (principal + int(e["pool_owner_reserve_tos"]) + deploy) * NANOTOS,
        "operator_funding": int(e["operator_funding_tos"]) * NANOTOS,
        "deploy": deploy * NANOTOS,
        "max_factor": factor,
    }


def confirmed_global_id(profile: dict[str, Any]) -> int:
    """The global id a genesis may be generated with: valid, and confirmed by the owner.

    A zero state carries its global id forever; every block and every wallet
    signature commits to it. An unconfirmed value must never reach one.
    """
    entry = profile.get("global_id", {})
    if entry.get("status") != "CONFIRMED":
        raise TestnetError(
            f"global id {entry.get('value')!r} is {entry.get('status')!r}, not CONFIRMED; "
            "the owner decides it (decision D03) before any genesis"
        )
    return check_global_id(entry.get("value"))


def check_global_id(value: Any) -> int:
    """A testnet global id is a signed int32 that is neither mainnet's nor local's."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TestnetError(f"global id must be an integer, got {value!r}")
    if not -(2**31) <= value < 2**31:
        raise TestnetError(f"global id {value} is not a signed 32-bit integer")
    if value == MAINNET_GLOBAL_ID:
        raise TestnetError("global id 1 is mainnet's replay domain")
    if value == LOCAL_GLOBAL_ID:
        raise TestnetError("global id 3 is the local development network's replay domain")
    if value == 0:
        raise TestnetError("global id 0 is unset")
    return value


# ---------------------------------------------------------------- encodings


def parse_hex(value: Any, size: int, what: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]+", value):
        raise TestnetError(f"{what} must be hexadecimal")
    data = bytes.fromhex(value)
    if len(data) != size:
        raise TestnetError(f"{what} must be {size} bytes, got {len(data)}")
    if not any(data):
        raise TestnetError(f"{what} must not be zero")
    return data


def parse_b64(value: Any, size: int, what: str) -> bytes:
    if not isinstance(value, str):
        raise TestnetError(f"{what} must be a base64 string")
    try:
        data = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise TestnetError(f"{what} is not standard base64: {exc}") from exc
    if len(data) != size:
        raise TestnetError(f"{what} must be {size} bytes, got {len(data)}")
    return data


def b64(data: bytes) -> str:
    """Standard base64: the engine's TL JSON decoder refuses the url-safe alphabet."""
    return base64.b64encode(data).decode()


def pq_key_id(public_key: bytes) -> bytes:
    """The consensus key id the genesis generator and the node derive from a public key."""
    if len(public_key) != PQ_PUBLIC_KEY_BYTES:
        raise TestnetError("an ML-DSA-44 public key is 1312 bytes")
    algorithm = PQ_ALGORITHM_MLDSA44.to_bytes(2, "little")
    return hashlib.sha256(PQ_KEY_DOMAIN + algorithm + public_key).digest()


def adnl_short_id(ed25519_public: bytes) -> bytes:
    """The ADNL short id of an Ed25519 transport key: SHA-256 of its pub.ed25519 TL object."""
    if len(ed25519_public) != 32:
        raise TestnetError("an Ed25519 public key is 32 bytes")
    return hashlib.sha256(ED25519_PUBLIC_TL_PREFIX + ed25519_public).digest()


def ip_to_tl(ip: str) -> int:
    """An IPv4 address as the signed int32 the TL address list carries."""
    address = ipaddress.IPv4Address(ip)
    value = int(address)
    return value - 2**32 if value >= 2**31 else value


REHEARSAL_ENV = "TESTNET_REHEARSAL_ALLOW_PRIVATE"


def require_public_ipv4(ip: str) -> str:
    """Refuse an address the internet cannot reach (private, loopback, shared, reserved).

    A single-host rehearsal sets TESTNET_REHEARSAL_ALLOW_PRIVATE=1 to run the
    same ceremony on loopback; a published ceremony never does.
    """
    address = ipaddress.IPv4Address(ip)
    if not address.is_global or address.is_multicast:
        if os.environ.get(REHEARSAL_ENV) != "1":
            raise TestnetError(f"{ip} is not a public IPv4 address")
    return ip


# ---------------------------------------------------------------- files


def write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Create `path` with `data`; refuse an existing file or a symlink, ignore the umask."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise TestnetError(
            f"{path} already exists; ceremony outputs are never overwritten"
        ) from exc
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new_json(path: Path, value: Any, mode: int = 0o644) -> None:
    write_new(path, (json.dumps(value, indent=2, sort_keys=False) + "\n").encode(), mode)


def private_dir(path: Path) -> Path:
    """Create (or accept) a directory that only its owner can enter."""
    path = Path(path)
    if path.is_symlink():
        raise TestnetError(f"{path} is a symlink")
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise TestnetError(f"{path} is not a directory")
    if info.st_uid != os.geteuid():
        raise TestnetError(f"{path} is owned by another user")
    if info.st_mode & 0o077:
        raise TestnetError(f"{path} is accessible to group or others")
    return path


def empty_dir(path: Path) -> Path:
    """Create a new, empty, private directory; refuse one that already has content."""
    path = Path(path)
    if path.exists() and any(path.iterdir()):
        raise TestnetError(f"{path} is not empty; use a new directory")
    return private_dir(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """Run a tool and refuse on failure, keeping its stderr in the error."""
    result = subprocess.run(argv, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise TestnetError(
            f"{Path(argv[0]).name} exited {result.returncode}: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result


# ---------------------------------------------------------------- consensus key


def parse_consensus_key_report(text: str) -> tuple[bytes, bytes]:
    """Parse `tos-pq-consensus-key show|generate` output into (key_id, public_key).

    The tool prints `algorithm mldsa44`, `key_id <hex>` and `public <hex>`. The
    key id is recomputed from the public key, so a report that does not match
    its own key is refused rather than trusted.
    """
    fields: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            fields[parts[0]] = parts[1]
    if fields.get("algorithm") != "mldsa44":
        raise TestnetError("consensus key report does not name algorithm mldsa44")
    key_id = parse_hex(fields.get("key_id"), HASH_BYTES, "key_id")
    public = parse_hex(fields.get("public"), PQ_PUBLIC_KEY_BYTES, "public key")
    if pq_key_id(public) != key_id:
        raise TestnetError("consensus key report: key_id does not match the public key")
    return key_id, public


# ---------------------------------------------------------------- engine config


def engine_adnl_ids(config: dict[str, Any], category: int) -> list[bytes]:
    ids = []
    for entry in config.get("adnl", []):
        if entry.get("category") == category:
            ids.append(parse_b64(entry.get("id"), HASH_BYTES, "engine adnl id"))
    return ids


def validator_adnl_id(config: dict[str, Any]) -> bytes:
    """The transport identity a genesis validator publishes.

    The engine's first start creates one category-0 ADNL key (also its DHT
    identity) and one category-1 key (its full-node identity). The genesis
    record names the category-0 key: the node treats a PQ validator ADNL id as
    its own only if config.json lists it, and the category-0 key is the one
    reachable through the published address.
    """
    ids = engine_adnl_ids(config, 0)
    if len(ids) != 1:
        raise TestnetError(
            f"expected exactly one category-0 ADNL id in config.json, found {len(ids)}; "
            "was the database created by a fresh first start?"
        )
    return ids[0]


# ---------------------------------------------------------------- operator records


RECORD_FIELDS = ("operator", "validator_id", "adnl_id", "public_key", "key_id", "address")


def check_operator_record(record: dict[str, Any]) -> dict[str, Any]:
    """Validate one operator's public submission. Returns it normalized to lower-case hex."""
    if not isinstance(record, dict):
        raise TestnetError("an operator record is a JSON object")
    missing = [name for name in RECORD_FIELDS if name not in record]
    if missing:
        raise TestnetError(f"operator record lacks {missing}")
    extra = sorted(set(record) - set(RECORD_FIELDS))
    if extra:
        raise TestnetError(f"operator record has unexpected fields {extra}")
    operator = record["operator"]
    if not isinstance(operator, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", operator):
        raise TestnetError("operator must be a short lower-case name (letters, digits, dashes)")
    validator = parse_hex(record["validator_id"], HASH_BYTES, "validator_id")
    adnl = parse_hex(record["adnl_id"], HASH_BYTES, "adnl_id")
    public = parse_hex(record["public_key"], PQ_PUBLIC_KEY_BYTES, "public_key")
    key_id = parse_hex(record["key_id"], HASH_BYTES, "key_id")
    if pq_key_id(public) != key_id:
        raise TestnetError(f"{operator}: key_id does not match public_key")
    address = record["address"]
    if not isinstance(address, str) or ":" not in address:
        raise TestnetError(f"{operator}: address must be <public-ipv4>:<udp-port>")
    host, _, port = address.rpartition(":")
    require_public_ipv4(host)
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise TestnetError(f"{operator}: bad port in address {address}")
    return {
        "operator": operator,
        "validator_id": validator.hex(),
        "adnl_id": adnl.hex(),
        "public_key": public.hex(),
        "key_id": key_id.hex(),
        "address": address,
    }


def check_operator_set(records: list[Any], count: int | None = None) -> list[dict[str, Any]]:
    """Validate a list of operator records that must not share any identity or host.

    `count`, when given, is the exact number of records (the genesis set is
    genesis.validators); otherwise any nonempty list is accepted."""
    if not isinstance(records, list) or not records:
        raise TestnetError("an operator record set is a nonempty JSON list")
    if count is not None and len(records) != count:
        raise TestnetError(
            f"the genesis set is exactly {count} operator records, not {len(records)}"
        )
    checked = [check_operator_record(r) for r in records]
    for field in ("operator", "validator_id", "adnl_id", "key_id", "address"):
        values = [r[field] for r in checked]
        if len(set(values)) != len(values):
            raise TestnetError(f"two genesis records share the same {field}")
    hosts = [r["address"].rpartition(":")[0] for r in checked]
    if len(set(hosts)) != len(hosts) and os.environ.get(REHEARSAL_ENV) != "1":
        raise TestnetError(
            "two genesis validators share one host; the testnet runs one validator per host"
        )
    return checked


REUSE_FIELDS = ("validator_id", "key_id", "adnl_id")


def check_fresh_identities(records: list[dict[str, Any]], previous: list[list[Any]]) -> None:
    """Refuse a genesis set that reuses any identity of an earlier testnet epoch.

    Every testnet epoch uses global id 2, so epochs share one replay domain. A
    reused consensus key would make a stake authorization or vote signed for
    the old epoch verify on the new one, and a reused staking account carries
    the old epoch's wallet keys. `previous` is the record lists of earlier epochs (their
    genesis-records.json, plus records the coordinator kept for validators that
    joined later); only identities in them can be checked.
    """
    seen: dict[str, set[str]] = {field: set() for field in REUSE_FIELDS}
    for epoch in previous:
        if not isinstance(epoch, list):
            raise TestnetError("a previous-epoch file is a JSON list of operator records")
        for record in epoch:
            if not isinstance(record, dict):
                raise TestnetError("a previous-epoch record is a JSON object")
            for field in REUSE_FIELDS:
                value = record.get(field)
                if isinstance(value, str):
                    seen[field].add(value.lower())
    for record in records:
        for field in REUSE_FIELDS:
            if record[field] in seen[field]:
                raise TestnetError(
                    f"{record['operator']} reuses {field} {record[field]} from an earlier testnet "
                    "epoch; a reset genesis needs fresh staking accounts and consensus keys"
                )


# ---------------------------------------------------------------- wallet identities


WALLETS_FILE = "wallets.json"
GENESIS_FILE = "genesis.json"
BOOTSTRAP_WALLET_LABEL = "bootstrap"
WALLET_PUBKEY_PREFIX = "pubkey:"
RAW_ADDRESS = re.compile(r"^-?[0-9]+:[0-9a-f]{64}$")
FIFT_PUBLIC_MARKER = "WALLET-PUBLIC-KEY"
# Prints the Ed25519 public key of the 32-byte private key file named by the
# first argument, with the same loader create-state uses for main-wallet.pk.
# Only the public key is printed.
FIFT_PUBLIC_PROGRAM = (
    f'"TosUtil.fif" include\n$1 load-keypair drop ."{FIFT_PUBLIC_MARKER} " Bx. cr\n'
)


def check_raw_address(address: str) -> str:
    """A raw `workchain:hex` address, lower-cased; anything else is refused."""
    address = str(address).lower()
    # fullmatch: `$` would also accept a trailing newline.
    if not RAW_ADDRESS.fullmatch(address):
        raise TestnetError(f"not a raw workchain:hex address: {address!r}")
    return address


def wallet_identity(value: Any) -> str:
    """A wallet identity in one canonical spelling.

    Either `pubkey:<64 hex>` (an Ed25519 public key, for a wallet whose address
    does not depend on its key, like the bootstrap wallet at -1:111...1) or a
    raw `workchain:hex` address (for a wallet whose address is a function of its
    key). Hex is lower-cased and the workchain written as a plain integer, so
    one account spelled two ways compares equal.
    """
    if not isinstance(value, str):
        raise TestnetError(f"a wallet identity is a string, got {value!r}")
    if value[: len(WALLET_PUBKEY_PREFIX)].lower() == WALLET_PUBKEY_PREFIX:
        key = parse_hex(value[len(WALLET_PUBKEY_PREFIX) :], 32, "wallet public key")
        return WALLET_PUBKEY_PREFIX + key.hex()
    workchain, account = check_raw_address(value).split(":")
    return f"{int(workchain)}:{account}"


def check_wallet_map(value: Any, what: str) -> dict[str, str]:
    """A label -> identity map, each identity normalized."""
    if not isinstance(value, dict):
        raise TestnetError(f"{what} is a JSON object of wallet label -> identity")
    out = {}
    for label, identity in value.items():
        if not isinstance(label, str) or not label:
            raise TestnetError(f"{what} has an empty or non-string wallet label")
        out[label] = wallet_identity(identity)
    return out


def check_fresh_wallets(wallets: dict[str, str], previous: list[dict[str, str]]) -> dict[str, str]:
    """Refuse wallets that reuse a wallet identity of an earlier testnet epoch.

    Every testnet epoch uses global id 2, so epochs share one replay domain. A
    wallet whose key comes back on a new epoch accepts again any message signed
    for it on an earlier one while the message is still valid; for the
    bootstrap wallet the address is fixed, so only its key tells two epochs
    apart. `previous` is one label -> identity map per earlier epoch. An empty
    one is refused: a check that saw nothing would otherwise pass. Returns
    `wallets` normalized.
    """
    seen: dict[str, str] = {}
    for index, epoch in enumerate(previous):
        checked = check_wallet_map(epoch, "a previous epoch's wallet record")
        if not checked:
            raise TestnetError(
                f"previous epoch {index + 1} names no wallet identity; refusing to pass a check "
                "that saw nothing"
            )
        for label, identity in checked.items():
            seen.setdefault(identity, label)
    fresh = check_wallet_map(wallets, "the wallet record")
    for label, identity in fresh.items():
        if identity in seen:
            raise TestnetError(
                f"wallet {label} reuses {identity} (wallet {seen[identity]} of an earlier testnet "
                "epoch); a reset needs fresh wallet keys"
            )
    return fresh


def parse_fift_public_key(text: str) -> bytes:
    """The public key FIFT_PUBLIC_PROGRAM prints: exactly one marker line with 32 bytes."""
    lines = [line.split() for line in text.splitlines() if line.startswith(FIFT_PUBLIC_MARKER)]
    if len(lines) != 1 or len(lines[0]) != 2:
        raise TestnetError("fift did not print exactly one wallet public key")
    return parse_hex(lines[0][1], 32, "wallet public key")


def wallet_public_key(fift: Path, fift_lib: Path, key: Path, runner: Any = None) -> bytes:
    """The Ed25519 public key of a wallet private key file, derived with fift.

    The private key is read by fift in place; it is never copied or printed.
    """
    key = Path(key)
    if key.is_symlink() or not key.is_file():
        raise TestnetError(f"{key} is not a regular file")
    if key.stat().st_size != 32:
        raise TestnetError(f"{key} is not a 32-byte private key")
    runner = runner or run
    with tempfile.TemporaryDirectory(prefix="wallet-pub-") as work:
        script = Path(work) / "wallet-public.fif"
        script.write_text(FIFT_PUBLIC_PROGRAM)
        result = runner(
            [str(fift), "-I", str(fift_lib), "-s", str(script), str(key.resolve())],
            timeout=60,
        )
    return parse_fift_public_key(result.stdout)


def previous_wallets(ceremony: Path, derive_public: Any = None) -> dict[str, str]:
    """The wallet identities an earlier epoch's ceremony directory records.

    Reads wallets.json and genesis.json's main_wallet_public_key. A ceremony
    from before either existed gives its bootstrap key through
    secret/main-wallet.pk, from which `derive_public(path) -> bytes` takes the
    public key. A directory that yields nothing is refused.
    """
    ceremony = Path(ceremony)
    if not ceremony.is_dir():
        raise TestnetError(f"previous ceremony {ceremony} is not a directory")
    wallets: dict[str, str] = {}
    path = ceremony / WALLETS_FILE
    if path.is_file():
        wallets = check_wallet_map(json.loads(path.read_text()), str(path))
    genesis_path = ceremony / GENESIS_FILE
    genesis = json.loads(genesis_path.read_text()) if genesis_path.is_file() else {}
    if not isinstance(genesis, dict):
        raise TestnetError(f"{genesis_path} is not a JSON object")
    bootstrap = None
    if "main_wallet_public_key" in genesis:
        key = parse_hex(genesis["main_wallet_public_key"], 32, f"{genesis_path} main wallet key")
        bootstrap = WALLET_PUBKEY_PREFIX + key.hex()
    elif BOOTSTRAP_WALLET_LABEL not in wallets:
        secret = ceremony / "secret" / "main-wallet.pk"
        if secret.exists():
            if derive_public is None:
                raise TestnetError(f"{secret} needs fift to derive its public key")
            bootstrap = WALLET_PUBKEY_PREFIX + bytes(derive_public(secret)).hex()
    if bootstrap is not None:
        if wallets.get(BOOTSTRAP_WALLET_LABEL, bootstrap) != bootstrap:
            raise TestnetError(
                f"previous ceremony {ceremony}: {WALLETS_FILE} and {GENESIS_FILE} disagree "
                "on the bootstrap wallet key"
            )
        wallets[BOOTSTRAP_WALLET_LABEL] = bootstrap
    if not wallets:
        raise TestnetError(
            f"previous ceremony {ceremony} records no wallet identity (no {WALLETS_FILE}, "
            f"no main_wallet_public_key in {GENESIS_FILE}, no secret/main-wallet.pk); "
            "refusing to pass a check that saw nothing"
        )
    return wallets


@contextmanager
def wallet_records_lock(ceremony: Path):
    """Serialize wallet and pool identity updates across ceremony processes."""
    ceremony = Path(ceremony)
    lock_path = ceremony / f".{WALLETS_FILE}.lock"
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        lock = os.open(lock_path, flags, 0o644)
    except OSError as exc:
        raise TestnetError(f"cannot lock {lock_path}: {exc}") from exc
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        os.close(lock)


def record_wallets(ceremony: Path, wallets: dict[str, str]) -> dict[str, str]:
    """Add wallets to the ceremony's public wallets.json; never change an entry.

    A label already recorded with the same identity is accepted (a rerun); with
    a different identity it is refused. The file is replaced atomically under a
    lock, so concurrent runs against one ceremony do not lose entries. Returns
    the whole record.
    """
    ceremony = Path(ceremony)
    fresh = check_wallet_map(wallets, "the wallet record")
    path = ceremony / WALLETS_FILE
    with wallet_records_lock(ceremony):
        if path.is_symlink():
            raise TestnetError(f"{path} is a symlink")
        existing = (
            check_wallet_map(json.loads(path.read_text()), str(path)) if path.exists() else {}
        )
        merged = dict(existing)
        for label, identity in fresh.items():
            if label in existing and existing[label] != identity:
                raise TestnetError(
                    f"{path} records wallet {label} as {existing[label]}, not {identity}; "
                    "a recorded wallet identity is never changed"
                )
            merged[label] = identity
        if merged != existing or not path.exists():
            tmp = ceremony / f".{WALLETS_FILE}.{os.getpid()}.tmp"
            if tmp.exists() or tmp.is_symlink():
                tmp.unlink()
            write_new_json(tmp, merged)
            os.replace(tmp, path)
        return merged


def manifest_input(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    """The exact input tos scripts/prepare-pq-genesis-manifest.py accepts (order = index)."""
    return [
        {
            "validator_id": r["validator_id"],
            "adnl_id": r["adnl_id"],
            "public_key": r["public_key"],
        }
        for r in records
    ]


MANIFEST_RECORD_BYTES = HASH_BYTES * 2 + PQ_PUBLIC_KEY_BYTES


def pack_manifest(records: list[dict[str, Any]]) -> bytes:
    """validator-pq.pub, one 1,376-byte record per genesis validator in index order,
    computed independently of the tos packer."""
    if not records:
        raise TestnetError("a manifest needs at least one genesis validator")
    # The tos packer's field rules: every field nonzero and unique.
    for name in ("validator_id", "adnl_id", "public_key"):
        values = [bytes.fromhex(r[name]) for r in records]
        if not all(any(v) for v in values) or len(set(values)) != len(values):
            raise TestnetError(f"manifest {name} values must be nonzero and unique")
    out = b"".join(
        bytes.fromhex(r["validator_id"])
        + bytes.fromhex(r["adnl_id"])
        + bytes.fromhex(r["public_key"])
        for r in records
    )
    if len(out) != len(records) * MANIFEST_RECORD_BYTES:
        raise TestnetError("manifest has the wrong size")
    return out


# ---------------------------------------------------------------- genesis template


def patch_template(
    text: str, global_id: int, epoch: int, schedule: dict[str, int], auth_tag: bytes
) -> str:
    """Return the canonical template with its mainnet pins and schedule replaced
    and the AUTH network tag defined.

    `schedule` is what validator_schedule() returns, `auth_tag` what
    supplied_auth_network_tag() returns. Each replaced line must occur exactly
    once. The schedule is the template's named constants: each must be bound
    once, above the template's schedule guard, so the guard checks the
    ceremony's values and ConfigParam 15 is written from them. A template that
    changed around these lines has not been reviewed for a testnet ceremony and
    is refused, and so is one that already defines a tag or selects the frozen
    admission candidate.
    """
    check_global_id(global_id)
    tag = check_auth_network_tag(auth_tag.hex() if isinstance(auth_tag, bytes) else auth_tag)
    if text.count(TEMPLATE_AUTH_GUARD_LINE) != 1:
        raise TestnetError("the template's AUTH network tag guard is not there exactly once")
    if f"constant {AUTH_TAG_CONSTANT}" in text or "constant quantum-admission-candidate" in text:
        raise TestnetError("the template already defines an AUTH tag or the admission candidate")
    if not isinstance(epoch, int) or epoch <= 1789434000:
        raise TestnetError("the testnet genesis epoch must be later than the mainnet template's")
    pins = (
        (TEMPLATE_GLOBAL_ID_LINE, f"{global_id} setglobalid   // TOS public testnet global_id"),
        (TEMPLATE_EPOCH_LINE, f"{epoch} constant mainnet_genesis_utime"),
        (
            TEMPLATE_EPOCH_ABORT_LINE,
            f'now mainnet_genesis_utime = not abort"SOURCE_DATE_EPOCH must be {epoch} for this TOS testnet genesis"',
        ),
    )
    lines = text.split("\n")

    def only(line: str) -> int:
        hits = [i for i, candidate in enumerate(lines) if candidate == line]
        if len(hits) != 1:
            raise TestnetError(f"template line not found exactly once: {line!r}")
        return hits[0]

    guard = only(TEMPLATE_SCHEDULE_GUARD_LINE)
    if only(TEMPLATE_ELECTION_PARAMS_LINE) < guard:
        raise TestnetError("the template writes ConfigParam 15 before its schedule guard")
    for old, new in pins:
        lines[only(old)] = new
    for key, name, mainnet in TEMPLATE_SCHEDULE_CONSTANTS:
        value = schedule[key]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < 2**32:
            raise TestnetError(f"schedule {key} is out of range: {value!r}")
        index = only(f"{mainnet} constant {name}")
        # The guard must check the ceremony's value, and nothing may rebind it after.
        if index > guard:
            raise TestnetError(f"the template defines {name} after its schedule guard")
        binding = re.compile(rf"(constant|=:)\s+{re.escape(name)}\b")
        if any(binding.search(line) for i, line in enumerate(lines) if i != index):
            raise TestnetError(f"the template binds {name} more than once")
        lines[index] = f"{value} constant {name}"
    if lines[0] != TEMPLATE_FIRST_LINE:
        raise TestnetError(f"the template's first line is not {TEMPLATE_FIRST_LINE!r}")
    lines.insert(
        1,
        f"0x{tag.hex()} constant {AUTH_TAG_CONSTANT}   // TOS public testnet AUTH network tag",
    )
    return "\n".join(lines)


# The canonical lines that fix the genesis set at four validators, the election
# limits (ConfigParam 16 and 17) and the bootstrap wallet's balance. A testnet
# genesis replaces exactly these; each must occur exactly once.
TEMPLATE_VALIDATOR_NUM_LINE = "21 21 4 config.validator_num!"
TEMPLATE_STAKE_LIMITS_LINE = "TM$10000 TM$10000000 TM$40000 sg~1 config.validator_stake_limits!"
TEMPLATE_BOOTSTRAP_LINE = "TM$80151 constant main_wallet_genesis_balance"
TEMPLATE_MANIFEST_SIZE_LINE = (
    '  dup Blen 5504 <> abort"PQ manifest must contain exactly four 1376-byte records"'
)
TEMPLATE_MANIFEST_LOOP_LINE = "  } 4 times drop"
TEMPLATE_MANIFEST_END_LINE = "} : load-pq-keys-from-file"
GENESIS_SET_REPLACED = [
    "genesis set size (manifest length and loader loop)",
    "ConfigParam 16 (validator counts)",
    "ConfigParam 17 (stake limits and max factor)",
    "bootstrap wallet balance",
]


def patch_genesis_set(text: str, limits: dict[str, int], bootstrap_tos: int) -> str:
    """Return `text` (patch_template's output) with the genesis set size, ConfigParam
    16, ConfigParam 17 and the bootstrap wallet's balance replaced.

    `limits` is what genesis_limits() returns, `bootstrap_tos` the plan's
    bootstrap_wallet_tos. The manifest loader reads genesis.validators records,
    each registered with the template's equal weight. The words that write
    ConfigParam 16 and 17 and bind the balance must appear only on the replaced
    lines, so nothing in the template overrides them."""
    count = limits["validators"]
    if not isinstance(bootstrap_tos, int) or isinstance(bootstrap_tos, bool) or bootstrap_tos <= 0:
        raise TestnetError(
            f"the bootstrap wallet balance must be positive whole TOS: {bootstrap_tos!r}"
        )
    lines = text.split("\n")

    def only(line: str) -> int:
        hits = [i for i, candidate in enumerate(lines) if candidate == line]
        if len(hits) != 1:
            raise TestnetError(f"template line not found exactly once: {line!r}")
        return hits[0]

    for word, line in (
        ("config.validator_num!", TEMPLATE_VALIDATOR_NUM_LINE),
        ("config.validator_stake_limits!", TEMPLATE_STAKE_LIMITS_LINE),
        ("constant main_wallet_genesis_balance", TEMPLATE_BOOTSTRAP_LINE),
        ("times drop", TEMPLATE_MANIFEST_LOOP_LINE),
    ):
        uses = [candidate for candidate in lines if word in candidate]
        if uses != [line]:
            raise TestnetError(f"the template uses {word!r} other than on {line!r}: {uses}")
    loop = only(TEMPLATE_MANIFEST_LOOP_LINE)
    size = only(TEMPLATE_MANIFEST_SIZE_LINE)
    if not size < loop or lines[loop + 1] != TEMPLATE_MANIFEST_END_LINE:
        raise TestnetError("the template's manifest loader is not the reviewed one")
    replacements = (
        (
            TEMPLATE_VALIDATOR_NUM_LINE,
            f"{limits['max_validators']} {limits['max_main_validators']} "
            f"{limits['min_validators']} config.validator_num!",
        ),
        (
            TEMPLATE_STAKE_LIMITS_LINE,
            f"TM${limits['min_stake_tos']} TM${limits['max_stake_tos']} "
            f"TM${limits['min_total_stake_tos']} sg~{limits['max_factor']} "
            "config.validator_stake_limits!",
        ),
        (TEMPLATE_BOOTSTRAP_LINE, f"TM${bootstrap_tos} constant main_wallet_genesis_balance"),
        (
            TEMPLATE_MANIFEST_SIZE_LINE,
            f"  dup Blen {count * MANIFEST_RECORD_BYTES} <> "
            f'abort"PQ manifest must contain exactly {count} 1376-byte records"',
        ),
        (TEMPLATE_MANIFEST_LOOP_LINE, f"  }} {count} times drop"),
    )
    for old, new in replacements:
        lines[only(old)] = new
    return "\n".join(lines)


VALIDATOR_PQ_TAG = 0xB3
VALIDATORS_EXT_TAG = 0x12


def zero_state_genesis_set(boc: bytes) -> dict[str, Any]:
    """ConfigParam 16, ConfigParam 17 and the validator set (ConfigParam 34) of a zero
    state: {"validator_num": {...}, "stake_limits": {... in nanotos, max_factor
    16.16}, "validators": [{"validator_id", "key_id", "adnl_id", "weight"}, ...],
    "main": n, "total_weight": w}."""
    params = zero_state_config(boc)[2]
    for number in (16, 17, 34):
        if number not in params:
            raise TestnetError(f"the zero state has no ConfigParam {number}")
    s = Slice(params[16])
    num = dict(zip(VALIDATOR_NUM_FIELDS, (s.bits(16), s.bits(16), s.bits(16)), strict=True))
    if not s.end():
        raise TestnetError("ConfigParam 16 has data after its three counts")
    s = Slice(params[17])
    stake = {
        "min_stake_nanotos": read_grams(s),
        "max_stake_nanotos": read_grams(s),
        "min_total_stake_nanotos": read_grams(s),
        "max_factor": s.bits(32),
    }
    if not s.end():
        raise TestnetError("ConfigParam 17 has data after its four values")
    s = Slice(params[34])
    if s.bits(8) != VALIDATORS_EXT_TAG:
        raise TestnetError("ConfigParam 34 is not a validators_ext set")
    s.bits(64)  # utime_since, utime_until
    total, main, total_weight = s.bits(16), s.bits(16), s.bits(64)
    validators = []
    entries = hashmap_items(s.take_ref(), 16) if s.bits(1) else {}
    for index in sorted(entries):
        v = entries[index]
        if v.bits(8) != VALIDATOR_PQ_TAG:
            raise TestnetError(f"validator {index} is not a post-quantum descriptor")
        validator_id = v.bits(256)
        v.bits(16)  # algorithm
        key_id = v.bits(256)
        v.take_ref()  # public key
        weight, adnl = v.bits(64), v.bits(256)
        validators.append(
            {
                "validator_id": f"{validator_id:064x}",
                "key_id": f"{key_id:064x}",
                "adnl_id": f"{adnl:064x}",
                "weight": weight,
            }
        )
    if total != len(validators):
        raise TestnetError(f"ConfigParam 34 says {total} validators and holds {len(validators)}")
    if total_weight != sum(v["weight"] for v in validators):
        raise TestnetError(
            f"ConfigParam 34 says total weight {total_weight}, but its validators weigh "
            f"{sum(v['weight'] for v in validators)}"
        )
    return {
        "validator_num": num,
        "stake_limits": stake,
        "validators": validators,
        "main": main,
        "total_weight": total_weight,
    }


def check_zero_state_genesis_set(
    boc: bytes, limits: dict[str, int], records: list[dict[str, Any]]
) -> dict[str, Any]:
    """Refuse a zero state whose ConfigParam 16, 17 or validator set is not the
    profile's limits and the genesis set `records` (index order); return what
    genesis.json records."""
    found = zero_state_genesis_set(boc)
    num = {name: limits[name] for name in VALIDATOR_NUM_FIELDS}
    if found["validator_num"] != num:
        raise TestnetError(f"ConfigParam 16 is {found['validator_num']}, expected {num}")
    stake = {
        "min_stake_nanotos": limits["min_stake_tos"] * NANOTOS,
        "max_stake_nanotos": limits["max_stake_tos"] * NANOTOS,
        "min_total_stake_nanotos": limits["min_total_stake_tos"] * NANOTOS,
        "max_factor": limits["max_factor"] * MAX_FACTOR_ONE,
    }
    if found["stake_limits"] != stake:
        raise TestnetError(f"ConfigParam 17 is {found['stake_limits']}, expected {stake}")
    expected = [(r["validator_id"], r["key_id"], r["adnl_id"]) for r in records]
    actual = [(v["validator_id"], v["key_id"], v["adnl_id"]) for v in found["validators"]]
    if actual != expected:
        raise TestnetError(
            f"the zero state's validator set is {len(actual)} validators other than the "
            f"{len(expected)} genesis records"
        )
    if found["main"] != len(records) or len({v["weight"] for v in found["validators"]}) != 1:
        raise TestnetError("the genesis validators are not all main validators of equal weight")
    return {
        "config_param_16": found["validator_num"],
        "config_param_17": found["stake_limits"],
        "validators": len(actual),
        "validator_ids": [v[0] for v in actual],
        "weight_each": found["validators"][0]["weight"],
    }


# ---------------------------------------------------------------- AUTH network tag

# The public namespace ConfigParam 48 carries. tos assigns none implicitly: a
# version-16 genesis refuses to run without one (crypto/smartcont/gen-zerostate.fif),
# and tos tooling takes it as 64 hexadecimal digits in TOS_AUTH_NETWORK_TAG.
AUTH_NETWORK_TAG_ENV = "TOS_AUTH_NETWORK_TAG"
AUTH_TAG_RULE_DOMAIN = "TOS-AUTH-NETWORK-TAG-v1"
# The exact policy identity tos checks (doc/auth-policy-v1.md, crypto/fift/lib/Config.fif).
AUTH_POLICY_PROFILE = (
    b"TOS-AUTH-POLICY-v1;config=48;tag=a1;suite=1;retired=u16;sequence=u64;"
    b"deadline=u32;network=bits256;monotonic"
)
AUTH_POLICY_SPEC_HASH = hashlib.sha256(AUTH_POLICY_PROFILE).digest()
AUTH_POLICY_TAG = 0xA1
# Namespaces others already use: tos's frozen mainnet admission candidate
# (0x42 repeated) and the public test values of tos CI and its harnesses (one
# repeated byte, or bytes 00..1f). A testnet sharing one would share its replay domain.
RESERVED_AUTH_TAGS = {bytes([b]) * 32 for b in range(256)} | {bytes(range(32))}
AUTH_TAG_STATUSES = ("CHOSEN", "CONFIRMED")


def auth_network_tag_rule(network: str, global_id: int, campaign_epoch: int) -> str:
    """The ASCII string whose SHA-256 is a testnet epoch's AUTH network tag."""
    return f"{AUTH_TAG_RULE_DOMAIN};network={network};global_id={global_id};epoch={campaign_epoch}"


def derive_auth_network_tag(network: str, global_id: int, campaign_epoch: int) -> bytes:
    return hashlib.sha256(
        auth_network_tag_rule(network, global_id, campaign_epoch).encode("ascii")
    ).digest()


def check_auth_network_tag(value: Any) -> bytes:
    """A tag as tos takes it: exactly 64 hexadecimal digits, and not a reserved value."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise TestnetError("the AUTH network tag must be exactly 64 hexadecimal digits")
    tag = bytes.fromhex(value)
    if tag in RESERVED_AUTH_TAGS:
        raise TestnetError(
            "the AUTH network tag is a reserved value (the mainnet admission candidate's "
            "or a tos test namespace)"
        )
    return tag


def profile_auth_network_tag(profile: dict[str, Any]) -> dict[str, Any]:
    """The profile's AUTH network tag entry, checked against its derivation rule."""
    entry = profile.get("genesis", {}).get("auth_network_tag")
    if not isinstance(entry, dict):
        raise TestnetError("the profile has no genesis.auth_network_tag")
    epoch = entry.get("campaign_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise TestnetError(f"genesis.auth_network_tag.campaign_epoch is invalid: {epoch!r}")
    if entry.get("status") not in AUTH_TAG_STATUSES:
        raise TestnetError(
            f"genesis.auth_network_tag.status is {entry.get('status')!r}, not one of "
            f"{AUTH_TAG_STATUSES}"
        )
    tag = check_auth_network_tag(entry.get("value"))
    global_id = check_global_id(profile.get("global_id", {}).get("value"))
    network = profile.get("network", "")
    rule = auth_network_tag_rule(network, global_id, epoch)
    if entry.get("rule") != rule or tag != derive_auth_network_tag(network, global_id, epoch):
        raise TestnetError(f"genesis.auth_network_tag is not SHA-256 of {rule!r}")
    return {"tag": tag, "rule": rule, "campaign_epoch": epoch, "status": entry["status"]}


def supplied_auth_network_tag(profile: dict[str, Any], environ: Any) -> bytes:
    """The tag the ceremony runs with: TOS_AUTH_NETWORK_TAG, equal to the profile's.

    The environment is the input tos tooling takes; the profile is what was
    announced. Both must name the same value, so neither a stale shell nor an
    edited profile changes the namespace on its own.
    """
    expected = profile_auth_network_tag(profile)
    value = environ.get(AUTH_NETWORK_TAG_ENV)
    if value is None:
        raise TestnetError(
            f"{AUTH_NETWORK_TAG_ENV} is not set; export the profile's genesis.auth_network_tag "
            f"value ({expected['tag'].hex()})"
        )
    tag = check_auth_network_tag(value)
    if tag != expected["tag"]:
        raise TestnetError(
            f"{AUTH_NETWORK_TAG_ENV} is {value.lower()}, but the profile announces "
            f"{expected['tag'].hex()} ({expected['rule']})"
        )
    return tag


# ---------------------------------------------------------------- bag of cells

BOC_MAGIC = bytes.fromhex("b5ee9c72")


class Cell:
    """An ordinary cell: data bits, references, and its representation hash."""

    __slots__ = ("data", "bits", "refs", "exotic", "_hash", "_depth")

    def __init__(self, data: bytes, bits: int, refs: list[Cell], exotic: bool = False):
        self.data, self.bits, self.refs = data, bits, refs
        # An exotic or higher-level cell (a Merkle update or pruned branch in a
        # block) is only ever walked past: its hash, and so any ancestor's, is
        # not computed here.
        self.exotic = exotic
        self._hash: bytes | None = None
        self._depth: int | None = None

    def depth(self) -> int:
        if self._depth is None:
            self._depth = 1 + max(r.depth() for r in self.refs) if self.refs else 0
        return self._depth

    def hash(self) -> bytes:
        """The representation hash (level 0), as the node's get_hash() computes it."""
        if self.exotic:
            raise TestnetError("the hash of an exotic cell is not computed here")
        if self._hash is None:
            full, rem = divmod(self.bits, 8)
            descriptor = bytes([len(self.refs), full * 2 + (1 if rem else 0)])
            body = self.data[:full]
            if rem:
                kept = self.data[full] & (0xFF << (8 - rem)) & 0xFF
                body += bytes([kept | (0x80 >> rem)])
            digest = hashlib.sha256(descriptor + body)
            for ref in self.refs:
                digest.update(ref.depth().to_bytes(2, "big"))
            for ref in self.refs:
                digest.update(ref.hash())
            self._hash = digest.digest()
        return self._hash


def cell_from_bits(bits: str, refs: Any = ()) -> Cell:
    """An ordinary cell from a string of 0/1 and its references."""
    if len(bits) > 1023 or set(bits) - {"0", "1"} or len(refs) > 4:
        raise TestnetError("not a cell: at most 1023 bits and 4 references")
    padded = bits + "0" * (-len(bits) % 8)
    data = int(padded, 2).to_bytes(len(padded) // 8, "big") if bits else b""
    return Cell(data, len(bits), list(refs))


class Slice:
    """Reads a cell's bits and references in order."""

    def __init__(self, cell: Cell):
        self.cell, self.pos, self.ref = cell, 0, 0

    def remaining(self) -> int:
        return self.cell.bits - self.pos

    def bits(self, n: int) -> int:
        if n < 0 or self.pos + n > self.cell.bits:
            raise TestnetError("cell underflow")
        value = 0
        for i in range(self.pos, self.pos + n):
            value = (value << 1) | ((self.cell.data[i // 8] >> (7 - i % 8)) & 1)
        self.pos += n
        return value

    def bytes(self, n: int) -> bytes:
        return self.bits(8 * n).to_bytes(n, "big") if n else b""

    def take_ref(self) -> Cell:
        if self.ref >= len(self.cell.refs):
            raise TestnetError("cell has no more references")
        self.ref += 1
        return self.cell.refs[self.ref - 1]

    def end(self) -> bool:
        return self.remaining() == 0 and self.ref == len(self.cell.refs)


def serialize_boc(root: Cell) -> bytes:
    """A single-root bag of ordinary cells, without index or checksum."""
    order: list[Cell] = []
    seen: set[int] = set()

    def visit(cell: Cell) -> None:
        if id(cell) in seen:
            return
        seen.add(id(cell))
        for ref in cell.refs:
            visit(ref)
        order.append(cell)

    visit(root)
    order.reverse()
    index = {id(cell): i for i, cell in enumerate(order)}
    ref_size = 1 if len(order) < 256 else 2
    body = bytearray()
    for cell in order:
        full, rem = divmod(cell.bits, 8)
        data = cell.data[:full]
        if rem:
            data += bytes([(cell.data[full] & (0xFF << (8 - rem)) & 0xFF) | (0x80 >> rem)])
        body += bytes([len(cell.refs), full * 2 + (1 if rem else 0)]) + data
        for ref in cell.refs:
            body += index[id(ref)].to_bytes(ref_size, "big")
    count = len(order).to_bytes(ref_size, "big")
    header = bytes([ref_size, 4]) + count + (1).to_bytes(ref_size, "big") + bytes(ref_size)
    return BOC_MAGIC + header + len(body).to_bytes(4, "big") + bytes(ref_size) + bytes(body)


def parse_boc(boc: bytes) -> Cell:
    """The single root of a bag of cells. Only ordinary level-0 cells are admitted."""
    cells, root = parse_boc_cells(boc)
    return cells[root]


def parse_boc_cells(boc: bytes, exotic: bool = False) -> tuple[list[Cell], int]:
    """Every cell of a single-root bag of cells, and the root's index.

    With `exotic`, exotic and higher-level cells are admitted as Cell(exotic=True):
    a block's state update is a Merkle update whose hash is never needed, only
    the ordinary cells beside it (its value flow, its transactions)."""
    pos = 0

    def take(size: int) -> int:
        nonlocal pos
        if pos + size > len(boc):
            raise TestnetError("the bag of cells is truncated")
        value = int.from_bytes(boc[pos : pos + size], "big")
        pos += size
        return value

    if boc[:4] != BOC_MAGIC or len(boc) < 6:
        raise TestnetError("not a bag of cells")
    pos = 4
    flags = take(1)
    ref_size, off_size = flags & 7, take(1)
    if not 1 <= ref_size <= 4 or not 1 <= off_size <= 8:
        raise TestnetError("the bag of cells has a malformed header")
    count, roots, _absent, _total = take(ref_size), take(ref_size), take(ref_size), take(off_size)
    if roots != 1:
        raise TestnetError(f"the bag of cells has {roots} roots, expected one")
    root = take(ref_size)
    if flags & 0x80:
        take(count * off_size)
    raw: list[tuple[bytes, int, list[int], bool]] = []
    for _ in range(count):
        d1, d2 = take(1), take(1)
        special = bool(d1 & 8 or d1 >> 5)
        if special and not exotic:
            raise TestnetError("the bag of cells holds an exotic or higher-level cell")
        if d1 & 16:
            take((bin(d1 >> 5).count("1") + 1) * (32 + 2))
        refs = d1 & 7
        if refs > 4:
            raise TestnetError("a cell has more than four references")
        size = (d2 + 1) // 2
        data = boc[pos : pos + size]
        if len(data) != size:
            raise TestnetError("the bag of cells is truncated")
        pos += size
        bits = 8 * size
        if d2 & 1:
            last = data[-1]
            if not last:
                raise TestnetError("a cell's completion tag is missing")
            bits = 8 * size - (last & -last).bit_length()
        raw.append((data, bits, [take(ref_size) for _ in range(refs)], special))
    if root >= count:
        raise TestnetError("the bag of cells names a root it does not hold")
    cells: list[Cell | None] = [None] * count
    for index in range(count - 1, -1, -1):
        data, bits, refs, special = raw[index]
        if any(r <= index or r >= count for r in refs):
            raise TestnetError("a cell refers backwards or outside the bag")
        cells[index] = Cell(data, bits, [cells[r] for r in refs], special)  # type: ignore[misc]
    return cells, root  # type: ignore[return-value]


def hashmap_items(cell: Cell, key_bits: int) -> dict[int, Slice]:
    """Every entry of a non-empty Hashmap key_bits X: key -> a slice at its value."""
    items: dict[int, Slice] = {}

    def walk(node: Cell, prefix: int, left: int) -> None:
        s = Slice(node)
        width = left.bit_length()
        if s.bits(1) == 0:  # hml_short: unary length, then the bits
            length = 0
            while s.bits(1):
                length += 1
            label = s.bits(length) if length <= left else 0
        elif s.bits(1) == 0:  # hml_long
            length = s.bits(width)
            label = s.bits(length) if length <= left else 0
        else:  # hml_same
            bit = s.bits(1)
            length = s.bits(width)
            label = ((1 << length) - 1) if bit else 0
        if length > left:
            raise TestnetError("a hashmap label is longer than its key")
        prefix, left = (prefix << length) | label, left - length
        if left == 0:
            items[prefix] = s
            return
        for branch in (0, 1):
            walk(s.take_ref(), (prefix << 1) | branch, left - 1)

    walk(cell, 0, key_bits)
    return items


# ---------------------------------------------------------------- zero state AUTH policy

SHARD_STATE_TAG = 0x9023AFE2
MC_STATE_EXTRA_TAG = 0xCC26
CONFIG_VERSION_TAG = 0xC4


def zero_state_config(boc: bytes) -> tuple[Cell, int, dict[int, Cell]]:
    """The zero state's root cell, global id and ConfigParams (number -> cell)."""
    root = parse_boc(boc)
    s = Slice(root)
    if s.bits(32) != SHARD_STATE_TAG:
        raise TestnetError("the zero state is not a ShardStateUnsplit")
    global_id = s.bits(32)
    global_id -= (global_id >> 31) << 32
    if len(root.refs) != 4:
        raise TestnetError("the zero state has no masterchain extra (McStateExtra)")
    extra = Slice(root.refs[3])
    if extra.bits(16) != MC_STATE_EXTRA_TAG:
        raise TestnetError("the zero state's McStateExtra has the wrong tag")
    if extra.bits(1):
        extra.take_ref()  # shard_hashes
    extra.bits(256)  # config_addr
    params = {}
    for number, value in hashmap_items(extra.take_ref(), 32).items():
        params[number] = value.take_ref()
    return root, global_id, params


def config_version(cell: Cell) -> tuple[int, int]:
    """ConfigParam 8: (global version, capabilities)."""
    s = Slice(cell)
    if cell.bits != 104 or cell.refs or s.bits(8) != CONFIG_VERSION_TAG:
        raise TestnetError("ConfigParam 8 is not capabilities#c4")
    return s.bits(32), s.bits(64)


def auth_policy(cell: Cell) -> dict[str, Any]:
    """ConfigParam 48 decoded as tos unpack_auth_policy reads it, or a refusal."""
    s = Slice(cell)
    if cell.bits != 601 or s.bits(8) != AUTH_POLICY_TAG:
        raise TestnetError("ConfigParam 48 is not an a1 AUTH policy record")
    network = s.bytes(32)
    sequence, retired = s.bits(64), s.bits(16)
    if retired & ~2:
        raise TestnetError(f"ConfigParam 48 retires an unknown suite ({retired:#x})")
    has_schedule = s.bits(1)
    if len(cell.refs) != has_schedule:
        raise TestnetError("ConfigParam 48 schedule reference does not match its flag")
    deadline = None
    if has_schedule:
        entries = hashmap_items(s.take_ref(), 8)
        if list(entries) != [1] or entries[1].remaining() != 32:
            raise TestnetError("ConfigParam 48 schedule is not one suite-1 deadline")
        deadline = entries[1].bits(32)
    if s.bytes(32) != AUTH_POLICY_SPEC_HASH or not s.end():
        raise TestnetError("ConfigParam 48 does not carry the v1 policy identity")
    return {"network": network, "sequence": sequence, "retired": retired, "deadline": deadline}


def zero_state_gas_credits(boc: bytes) -> dict[int, int]:
    """Refuse a newly generated genesis with a different admission credit profile."""
    params = zero_state_config(boc)[2]
    credits = {}
    for number, expected in ((20, 10000), (21, 20000)):
        if number not in params:
            raise TestnetError(f"the zero state has no ConfigParam {number}")
        prices = Slice(params[number])
        try:
            tag = prices.bits(8)
            if tag == 0xD1:  # gas_flat_pfx
                prices.bits(64)
                prices.bits(64)
                tag = prices.bits(8)
            if tag not in (0xDD, 0xDE):
                raise TestnetError(f"ConfigParam {number} has an unknown gas price tag")
            for _ in range(3 if tag == 0xDE else 2):  # special_gas_limit exists only in #de
                prices.bits(64)
            credits[number] = prices.bits(64)
            for _ in range(3):  # block_gas_limit, freeze_due_limit, delete_due_limit
                prices.bits(64)
        except TestnetError as error:
            if "unknown gas price tag" in str(error):
                raise
            raise TestnetError(f"ConfigParam {number} is malformed: {error}") from error
        if not prices.end():
            raise TestnetError(f"ConfigParam {number} has data after its gas prices")
        if credits[number] != expected:
            raise TestnetError(
                f"ConfigParam {number} gas_credit is {credits[number]}, expected {expected}"
            )
    return credits


# ConfigParam 47 listed the validator controller codes. tos removed it with the
# controller when a validator came to be staked by its sending account; a tree
# from before that still defines it and makes it mandatory and critical.
RETIRED_CONFIG_PARAMS = (47,)


def zero_state_retired_params(boc: bytes) -> None:
    """Refuse a newly generated genesis that still defines or requires a retired ConfigParam."""
    params = zero_state_config(boc)[2]
    for number in (9, 10):
        if number not in params:
            raise TestnetError(f"the zero state has no ConfigParam {number}")
    for retired in RETIRED_CONFIG_PARAMS:
        if retired in params:
            raise TestnetError(
                f"the zero state still defines retired ConfigParam {retired}; "
                "build it from a tos tree that no longer has it"
            )
        for number, name in ((9, "mandatory"), (10, "critical")):
            if retired in hashmap_items(params[number], 32):
                raise TestnetError(
                    f"retired ConfigParam {retired} is still {name} (ConfigParam {number})"
                )


def zero_state_auth_policy(
    boc: bytes, root_hash: bytes, global_id: int, global_version: int, tag: bytes
) -> dict[str, Any]:
    """Check a version-16 zero state's AUTH policy and return what the ceremony records.

    The conditions tos validate_auth_policy_config applies (ConfigParam 48
    present and well formed, and in both ConfigParam 9 and 10 from version 16),
    plus what this genesis must be: this tag, sequence zero, nothing retired, no
    deadline, the profile's global id and version. The parser is first checked
    against create-state's own root hash.
    """
    root, actual_global_id, params = zero_state_config(boc)
    if root.hash() != root_hash:
        raise TestnetError("the zero state's root hash differs from create-state's .rhash")
    if actual_global_id != global_id:
        raise TestnetError(f"the zero state carries global id {actual_global_id}")
    for number in (8, 9, 10, 48):
        if number not in params:
            raise TestnetError(f"the zero state has no ConfigParam {number}")
    version, capabilities = config_version(params[8])
    if version != global_version:
        raise TestnetError(f"ConfigParam 8 is version {version}, expected {global_version}")
    policy = auth_policy(params[48])
    if policy["network"] != tag:
        raise TestnetError(
            f"ConfigParam 48 carries tag {policy['network'].hex()}, expected {tag.hex()}"
        )
    if policy["sequence"] or policy["retired"] or policy["deadline"] is not None:
        raise TestnetError("an initial AUTH policy has sequence 0, nothing retired, no deadline")
    for number, name in ((9, "mandatory"), (10, "critical")):
        if 48 not in hashmap_items(params[number], 32):
            raise TestnetError(f"ConfigParam 48 is not {name} (ConfigParam {number})")
    return {
        "network_tag_hex": tag.hex(),
        "config_param_48_hash_hex": params[48].hash().hex(),
        "policy_identity_sha256": AUTH_POLICY_SPEC_HASH.hex(),
        "sequence": 0,
        "retired": 0,
        "deadline": None,
        "mandatory_and_critical": True,
        "global_version": version,
        "capabilities": capabilities,
    }


# ---------------------------------------------------------------- supply and burning

# The masterchain blackhole ConfigParam 5 names (memo STATUS 13.254): inbound value
# to it is destroyed in its credit phase and counted in the block's ValueFlow.burned.
# It is also where the bootstrap wallet's final transfer (mode 128 + 32) goes.
BLACKHOLE = "-1:" + "ff" * 32
# TOS burns no fees: ConfigParam 5's fee_burn_num / fee_burn_denom.
FEE_BURN = (0, 1)
BURNING_CONFIG_TAG = 0x01
NANOTOS = 10**9
BOOTSTRAP_ACCOUNT = "11" * 32
# The genesis accounts beside the bootstrap wallet: the Elector and the Config
# contract, 500 TOS each, in the canonical template.
GENESIS_SYSTEM_ACCOUNTS_TOS = 1000
BLOCK_TAG = 0x11EF55AA
BLOCK_INFO_TAG = 0x9BC7A987
BLOCK_EXTRA_TAG = 0x4A33F6FD
VALUE_FLOW_TAG = 0xB8E48DFB
VALUE_FLOW_V2_TAG = 0x3EBF98B7


def read_grams(s: Slice) -> int:
    """Grams (VarUInteger 16): a 4-bit byte length, then the value."""
    return s.bits(8 * s.bits(4))


def read_currency_collection(s: Slice, allow_extra: bool = False) -> int:
    """CurrencyCollection: grams, then (Maybe ^ExtraCurrencyCollection). TOS has no
    extra currencies; one is refused unless the caller only skips the value."""
    grams = read_grams(s)
    if s.bits(1):
        if not allow_extra:
            raise TestnetError("extra currencies are not expected here")
        s.take_ref()
    return grams


def hashmap_label(s: Slice, left: int) -> tuple[int, int]:
    """A HmLabel at the slice: (label value, label length), refusing an overlong one."""
    width = left.bit_length()
    if s.bits(1) == 0:  # hml_short
        length = 0
        while s.bits(1):
            length += 1
        if length > left:
            raise TestnetError("a hashmap label is longer than its key")
        return s.bits(length), length
    if s.bits(1) == 0:  # hml_long
        length = s.bits(width)
        if length > left:
            raise TestnetError("a hashmap label is longer than its key")
        return s.bits(length), length
    bit, length = s.bits(1), s.bits(width)  # hml_same
    if length > left:
        raise TestnetError("a hashmap label is longer than its key")
    return ((1 << length) - 1) if bit else 0, length


def hashmap_aug_items(root: Slice, key_bits: int) -> dict[int, Slice]:
    """Every leaf of a HashmapAug key_bits X Y whose edge starts at `root`:
    key -> a slice at the leaf's extra (Y), which its value (X) follows. A fork's
    extra is not read: its two children are its first two references."""
    items: dict[int, Slice] = {}

    def walk(s: Slice, prefix: int, left: int) -> None:
        label, length = hashmap_label(s, left)
        prefix, left = (prefix << length) | label, left - length
        if left == 0:
            if prefix in items:
                raise TestnetError("a hashmap key occurs twice")
            items[prefix] = s
            return
        children = (s.take_ref(), s.take_ref())
        for branch, child in enumerate(children):
            walk(Slice(child), (prefix << 1) | branch, left - 1)

    walk(root, 0, key_bits)
    return items


def hashmap_aug_e_items(s: Slice, key_bits: int, read_extra) -> tuple[dict[int, Slice], Any]:
    """A HashmapAugE at the slice (ahme_empty$0 extra / ahme_root$1 ^root extra):
    (its leaves as hashmap_aug_items gives them, the root extra read_extra returns);
    the slice is left after the root extra."""
    if s.bits(1) == 0:
        return {}, read_extra(s)
    root = s.take_ref()
    return hashmap_aug_items(Slice(root), key_bits), read_extra(s)


def burning_config(cell: Cell) -> dict[str, Any]:
    """ConfigParam 5: burning_config#01 blackhole_addr:(Maybe bits256)
    fee_burn_num:# fee_burn_denom:#, decoded and checked as the TL-B constrains it."""
    s = Slice(cell)
    try:
        if s.bits(8) != BURNING_CONFIG_TAG:
            raise TestnetError("ConfigParam 5 is not burning_config#01")
        blackhole = f"-1:{s.bytes(32).hex()}" if s.bits(1) else None
        num, denom = s.bits(32), s.bits(32)
    except TestnetError as exc:
        raise TestnetError(f"ConfigParam 5 is malformed: {exc}") from exc
    if not s.end():
        raise TestnetError("ConfigParam 5 has data after its burning config")
    if denom < 1 or num > denom:
        raise TestnetError(f"ConfigParam 5 burns {num}/{denom}, which the TL-B refuses")
    return {"blackhole": blackhole, "fee_burn": (num, denom)}


def check_burning_config(cell: Cell) -> dict[str, Any]:
    """Refuse unless ConfigParam 5 is the decided one: the blackhole -1:ff...ff and
    no fee burning. Without the blackhole a transfer there creates an ordinary
    account holding the value instead of destroying it."""
    config = burning_config(cell)
    if config["blackhole"] != BLACKHOLE:
        raise TestnetError(f"ConfigParam 5 names blackhole {config['blackhole']}, not {BLACKHOLE}")
    if config["fee_burn"] != FEE_BURN:
        raise TestnetError(
            f"ConfigParam 5 burns {config['fee_burn'][0]}/{config['fee_burn'][1]} of fees, not 0/1"
        )
    return config


def depth_balance(s: Slice) -> int:
    """DepthBalanceInfo: split_depth:(#<= 30) balance:CurrencyCollection -> balance."""
    s.bits(5)
    return read_currency_collection(s)


def zero_state_supply(boc: bytes) -> dict[str, Any]:
    """The zero state's accounts and total balance, as the state commits to them.

    Each ShardAccounts leaf's DepthBalanceInfo carries its account's balance and
    the dictionary root's extra their sum; total_balance is the state's own
    figure. All three must agree, or the state is refused."""
    root = parse_boc(boc)
    if Slice(root).bits(32) != SHARD_STATE_TAG or len(root.refs) != 4:
        raise TestnetError("the zero state is not a masterchain ShardStateUnsplit")
    try:
        leaves, accounts_total = hashmap_aug_e_items(Slice(root.refs[1]), 256, depth_balance)
        balances = {f"{key:064x}": depth_balance(leaf) for key, leaf in leaves.items()}
        totals = Slice(root.refs[2])
        totals.bits(64 + 64)  # overload and underload history
        total_balance = read_currency_collection(totals)
    except TestnetError as exc:
        raise TestnetError(f"the zero state's accounts are malformed: {exc}") from exc
    if sum(balances.values()) != accounts_total or accounts_total != total_balance:
        raise TestnetError(
            f"the zero state's balances do not add up: accounts {sum(balances.values())}, "
            f"dictionary {accounts_total}, total_balance {total_balance}"
        )
    return {"balances": balances, "total_balance": total_balance}


def zero_state_election_params(boc: bytes) -> tuple[int, int, int, int]:
    """ConfigParam 15 of the zero state, in ELECTION_PARAM_NAMES order."""
    params = zero_state_config(boc)[2]
    if 15 not in params:
        raise TestnetError("the zero state has no ConfigParam 15")
    s = Slice(params[15])
    values = tuple(s.bits(32) for _ in ELECTION_PARAM_NAMES)
    if not s.end():
        raise TestnetError("ConfigParam 15 has data after its four values")
    return values  # type: ignore[return-value]


def zero_state_bootstrap(
    boc: bytes, bootstrap_nanotos: int, total_nanotos: int, schedule: dict[str, int]
) -> dict[str, Any]:
    """Refuse a genesis that is not the decided epoch configuration; return what
    genesis.json records.

    ConfigParam 5 names the blackhole -1:ff...ff and burns no fees, and is
    critical (ConfigParam 10), so no ordinary vote can point it at a spendable
    account; the bootstrap wallet -1:111...1 holds exactly the profile's amount and
    the state exactly the profile's total; ConfigParam 15 is the profile's
    schedule, read back from the state rather than from the template."""
    params = zero_state_config(boc)[2]
    if 5 not in params:
        raise TestnetError(
            "the zero state has no ConfigParam 5: a transfer to the blackhole would "
            "create an ordinary account instead of burning; build it from a tos tree "
            "whose template sets it"
        )
    burning = check_burning_config(params[5])
    if 10 not in params or 5 not in hashmap_items(params[10], 32):
        raise TestnetError("ConfigParam 5 is not critical (ConfigParam 10)")
    supply = zero_state_supply(boc)
    held = supply["balances"].get(BOOTSTRAP_ACCOUNT)
    if held != bootstrap_nanotos:
        raise TestnetError(
            f"the bootstrap wallet -1:{BOOTSTRAP_ACCOUNT} holds {held} nanotos, "
            f"expected {bootstrap_nanotos}"
        )
    if supply["total_balance"] != total_nanotos:
        raise TestnetError(
            f"the zero state holds {supply['total_balance']} nanotos, expected {total_nanotos}"
        )
    expected = tuple(schedule[name] for name in ELECTION_PARAM_NAMES)
    actual = zero_state_election_params(boc)
    if actual != expected:
        raise TestnetError(f"ConfigParam 15 in the zero state is {actual}, expected {expected}")
    return {
        "config_param_5_hash_hex": params[5].hash().hex(),
        "blackhole": burning["blackhole"],
        "fee_burn": list(burning["fee_burn"]),
        "config_param_5_critical": True,
        "bootstrap_wallet": f"-1:{BOOTSTRAP_ACCOUNT}",
        "bootstrap_wallet_nanotos": held,
        "total_balance_nanotos": supply["total_balance"],
        "election_params_read_back": list(actual),
    }


def genesis_supply_targets(profile: dict[str, Any]) -> tuple[int, int]:
    """(bootstrap wallet, total supply) in nanotos as the profile decides them; the
    total is the bootstrap wallet plus the template's two 500-TOS system accounts."""
    elections = profile.get("elections", {})
    wallet = elections.get("bootstrap_wallet_tos")
    total = profile.get("genesis", {}).get("total_supply_tos")
    for name, value in (
        ("elections.bootstrap_wallet_tos", wallet),
        ("genesis.total_supply_tos", total),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise TestnetError(f"profile {name} must be a positive whole number of TOS: {value!r}")
    if total != wallet + GENESIS_SYSTEM_ACCOUNTS_TOS:
        raise TestnetError(
            f"genesis.total_supply_tos {total} is not the bootstrap wallet {wallet} plus "
            f"{GENESIS_SYSTEM_ACCOUNTS_TOS} TOS of system accounts"
        )
    return wallet * NANOTOS, total * NANOTOS


# ---------------------------------------------------------------- blocks and value flow


def value_flow(cell: Cell) -> dict[str, int]:
    """A block's ValueFlow (v1 or v2), every field in nanotos; v1 has burned 0.

    The flow must balance as the validator checks it (block::ValueFlow::validate):
    from_prev_blk + imported + fees_imported + created + minted + recovered ==
    to_next_blk + exported + fees_collected + burned."""
    s = Slice(cell)
    try:
        tag = s.bits(32)
        if tag not in (VALUE_FLOW_TAG, VALUE_FLOW_V2_TAG):
            raise TestnetError(f"not a ValueFlow ({tag:#x})")
        first = Slice(s.take_ref())
        flow = {
            name: read_currency_collection(first)
            for name in ("from_prev_blk", "to_next_blk", "imported", "exported")
        }
        flow["fees_collected"] = read_currency_collection(s)
        flow["burned"] = read_currency_collection(s) if tag == VALUE_FLOW_V2_TAG else 0
        second = Slice(s.take_ref())
        for name in ("fees_imported", "recovered", "created", "minted"):
            flow[name] = read_currency_collection(second)
        if not (first.end() and second.end() and s.end()):
            raise TestnetError("data after its fields")
    except TestnetError as exc:
        raise TestnetError(f"the block's ValueFlow is malformed: {exc}") from exc
    flow["version"] = 2 if tag == VALUE_FLOW_V2_TAG else 1
    credit = sum(
        flow[k]
        for k in ("from_prev_blk", "imported", "fees_imported", "created", "minted", "recovered")
    )
    debit = sum(flow[k] for k in ("to_next_blk", "exported", "fees_collected", "burned"))
    if credit != debit:
        raise TestnetError(f"the block's ValueFlow does not balance: {credit} in, {debit} out")
    return flow


def read_block(boc: bytes) -> dict[str, Any]:
    """A block from its file bytes: global id, BlockInfo's identity and lt range,
    its ValueFlow, and the transaction cells of each account (account hex -> {lt:
    transaction cell}). The state update (a Merkle update) is not read."""
    cells, index = parse_boc_cells(boc, exotic=True)
    root = cells[index]
    s = Slice(root)
    try:
        if s.bits(32) != BLOCK_TAG or len(root.refs) != 4:
            raise TestnetError("not a block")
        global_id = s.bits(32)
        global_id -= (global_id >> 31) << 32
        info = Slice(root.refs[0])
        if info.bits(32) != BLOCK_INFO_TAG:
            raise TestnetError("not a BlockInfo")
        info.bits(32)  # version
        not_master = info.bits(1)
        info.bits(7 + 8)  # merge/split flags, key_block, vert_seqno_incr; flags
        seqno = info.bits(32)
        info.bits(32)  # vert_seq_no
        if info.bits(2) != 0:
            raise TestnetError("not a ShardIdent")
        info.bits(6)  # shard_pfx_bits
        workchain = info.bits(32)
        workchain -= (workchain >> 31) << 32
        info.bits(64)  # shard_prefix
        gen_utime, start_lt, end_lt = info.bits(32), info.bits(64), info.bits(64)
        extra = Slice(root.refs[3])
        if extra.bits(32) != BLOCK_EXTRA_TAG:
            raise TestnetError("not a BlockExtra")
        extra.take_ref()  # in_msg_descr
        extra.take_ref()  # out_msg_descr
        account_blocks = Slice(extra.take_ref())
        leaves, _ = hashmap_aug_e_items(
            account_blocks, 256, lambda x: read_currency_collection(x, allow_extra=True)
        )
        transactions: dict[str, dict[int, Cell]] = {}
        for key, leaf in leaves.items():
            read_currency_collection(leaf, allow_extra=True)
            if leaf.bits(4) != 0x5:
                raise TestnetError("not an AccountBlock")
            account = leaf.bytes(32).hex()
            if int(account, 16) != key:
                raise TestnetError("an AccountBlock under another account's key")
            txs = {}
            for lt, tx in hashmap_aug_items(leaf, 64).items():
                read_currency_collection(tx, allow_extra=True)
                txs[lt] = tx.take_ref()
            transactions[account] = txs
    except TestnetError as exc:
        raise TestnetError(f"the block cannot be read: {exc}") from exc
    return {
        "global_id": global_id,
        "workchain": workchain,
        "seqno": seqno,
        "masterchain": not not_master,
        "gen_utime": gen_utime,
        "start_lt": start_lt,
        "end_lt": end_lt,
        "value_flow": value_flow(root.refs[1]),
        "transactions": transactions,
    }


# ---------------------------------------------------------------- global config


def zero_state_entry(root_hash: bytes, file_hash: bytes) -> dict[str, Any]:
    if len(root_hash) != HASH_BYTES or len(file_hash) != HASH_BYTES:
        raise TestnetError("zero state hashes are 32 bytes each")
    if not any(root_hash) or not any(file_hash):
        raise TestnetError("zero state hashes must not be zero")
    return {
        "workchain": MASTERCHAIN,
        "shard": MASTERCHAIN_SHARD,
        "seqno": 0,
        "root_hash": b64(root_hash),
        "file_hash": b64(file_hash),
    }


def address_list(ip: str, port: int) -> dict[str, Any]:
    return {
        "@type": "adnl.addressList",
        "addrs": [{"@type": "adnl.address.udp", "ip": ip_to_tl(ip), "port": port}],
        "version": 0,
        "reinit_date": 0,
        "priority": 0,
        "expire_at": 0,
    }


def check_dht_node(node: dict[str, Any]) -> dict[str, Any]:
    """A signed dht.node as generate-random-id -m dht prints it."""
    if node.get("@type") != "dht.node":
        raise TestnetError("DHT node record is not a dht.node")
    node_id = node.get("id", {})
    if node_id.get("@type") != "pub.ed25519":
        raise TestnetError("DHT node id is not pub.ed25519")
    parse_b64(node_id.get("key"), 32, "DHT node public key")
    parse_b64(node.get("signature"), 64, "DHT node signature")
    addrs = node.get("addr_list", {}).get("addrs", [])
    if len(addrs) != 1 or addrs[0].get("@type") != "adnl.address.udp":
        raise TestnetError("DHT node must publish exactly one UDP address")
    require_public_ipv4(str(ipaddress.IPv4Address(addrs[0]["ip"] % 2**32)))
    return node


def global_config(
    zero_state: dict[str, Any], dht_nodes: list[dict[str, Any]], profile: dict[str, Any]
) -> dict[str, Any]:
    if len(dht_nodes) < 2:
        raise TestnetError(
            "publish at least two DHT nodes; one DHT host is a single point of failure"
        )
    keys = [n["id"]["key"] for n in dht_nodes]
    if len(set(keys)) != len(keys):
        raise TestnetError("two DHT node records carry the same key")
    dht = profile["dht"]
    return {
        "@type": "config.global",
        "dht": {
            "@type": "dht.config.global",
            "k": dht["k"],
            "a": dht["a"],
            "static_nodes": {"@type": "dht.nodes", "nodes": [check_dht_node(n) for n in dht_nodes]},
        },
        "validator": {
            "@type": "validator.config.global",
            "zero_state": zero_state,
            "hardforks": [],
        },
    }


def pregenesis_config(profile: dict[str, Any]) -> dict[str, Any]:
    """A global config good only for the engine's first start before genesis exists.

    validator-engine parses -C before it writes config.json on a first start,
    and refuses a zero hash, but it exits right after writing config.json and
    never uses these values. The placeholder hashes spell PREGENESIS so that a
    node accidentally started on this file cannot be mistaken for any network.
    """
    marker = hashlib.sha256(b"TOS-TESTNET-PREGENESIS-PLACEHOLDER").digest()
    return {
        "@type": "config.global",
        "dht": {
            "@type": "dht.config.global",
            "k": profile["dht"]["k"],
            "a": profile["dht"]["a"],
            "static_nodes": {"@type": "dht.nodes", "nodes": []},
        },
        "validator": {
            "@type": "validator.config.global",
            "zero_state": zero_state_entry(marker, marker),
            "hardforks": [],
        },
    }


def is_pregenesis(config: dict[str, Any]) -> bool:
    marker = b64(hashlib.sha256(b"TOS-TESTNET-PREGENESIS-PLACEHOLDER").digest())
    return config.get("validator", {}).get("zero_state", {}).get("root_hash") == marker


# ---------------------------------------------------------------- JSON-RPC


RPC_REQUEST_ID = 1
# The statuses the node answers with before a method runs (json-rpc-http-policy.h:
# authentication, unknown GET path, method, content type, rate limit), each with
# the same JSON-RPC error body. Every method error is HTTP 200.
RPC_PRE_DISPATCH_STATUSES = (401, 404, 405, 415, 429)


class RpcError(TestnetError):
    """A node's JSON-RPC 2.0 error object (tos validator-engine/json-rpc-contract.h).

    `reason` is the stable machine-readable name a client branches on, `code` the
    JSON-RPC code it travels under, `retryable` whether the same request can
    succeed later (a timeout, a node not ready, a rate limit).
    """

    def __init__(
        self, url: str, method: str, code: int, reason: str, message: str, retryable: bool
    ):
        super().__init__(f"{url} {method}: {reason or 'error'} {code}: {message}")
        self.code, self.reason, self.message, self.retryable = code, reason, message, retryable


def rpc_result(answer: Any, url: str, method: str) -> Any:
    """The result of one decoded JSON-RPC 2.0 answer, or a refusal.

    The node answers {jsonrpc: "2.0", id, result} or {jsonrpc: "2.0", id,
    error: {code, message, data: {schema_version, reason, retryable}}}, at
    HTTP 200 for every method error. Anything else (no envelope, another id,
    both or neither of result and error, an error that is not an object) is
    refused rather than read.
    """
    if not isinstance(answer, dict) or answer.get("jsonrpc") != "2.0":
        raise TestnetError(f"{url} {method}: not a JSON-RPC 2.0 answer: {str(answer)[:200]}")
    # A refusal made before the request was read (rate limit, authentication) cannot
    # know the id and answers with id null; a result always echoes the id.
    if answer.get("id") != RPC_REQUEST_ID and not ("error" in answer and answer.get("id") is None):
        raise TestnetError(f"{url} {method}: the answer is for request id {answer.get('id')!r}")
    if ("error" in answer) == ("result" in answer):
        raise TestnetError(f"{url} {method}: the answer has both or neither of result and error")
    if "result" in answer:
        return answer["result"]
    error = answer["error"]
    if (
        not isinstance(error, dict)
        or not isinstance(error.get("code"), int)
        or isinstance(error.get("code"), bool)
        or not isinstance(error.get("message"), str)
    ):
        raise TestnetError(f"{url} {method}: malformed JSON-RPC error {str(error)[:200]}")
    data = error.get("data") if isinstance(error.get("data"), dict) else {}
    reason = data.get("reason") if isinstance(data.get("reason"), str) else ""
    raise RpcError(
        url, method, error["code"], reason, error["message"], data.get("retryable") is True
    )


def rpc(url: str, method: str, /, timeout: float = 10, **params: Any) -> Any:
    """One JSON-RPC 2.0 call with named parameters. Environment proxies are
    ignored: the named node must answer.

    `url` and `method` are positional-only, so a call's own parameters may use
    those names: `runGetMethod` takes the getter as its `method` parameter.
    The node refuses positional (array) parameters; this sends none. A method
    error raises RpcError. A refusal made before the method runs (401, 404,
    405, 415, 429) carries the same error body and raises RpcError too; a
    status without a JSON-RPC body raises TestnetError.
    """
    body = json.dumps(
        {"jsonrpc": "2.0", "id": RPC_REQUEST_ID, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(url, body, {"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            answer = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code not in RPC_PRE_DISPATCH_STATUSES:
            raise TestnetError(f"{url} {method}: HTTP {exc.code}") from exc
        try:
            answer = json.load(exc)
        except ValueError:
            raise TestnetError(f"{url} {method}: HTTP {exc.code} without a JSON-RPC body") from exc
        if not isinstance(answer, dict) or "error" not in answer:
            raise TestnetError(f"{url} {method}: HTTP {exc.code}: {str(answer)[:200]}") from exc
    except ValueError as exc:
        raise TestnetError(f"{url} {method}: the answer is not JSON") from exc
    return rpc_result(answer, url, method)


# A node answers a read at a masterchain block it has not applied yet (it is a
# block or two behind the network) with UPSTREAM_UNAVAILABLE, retryable, and
# the query path's error 651 "not ready": "cannot load block (...) : block (...)
# is not applied". Catching up takes seconds, so a read waits for it, within a
# bound, instead of failing the operation that made it.
NOT_APPLIED_RETRY_SECONDS = 30.0
NOT_APPLIED_FIRST_DELAY = 0.5
NOT_APPLIED_MAX_DELAY = 4.0
NOT_APPLIED_TEXT = re.compile(r"\bError : 651 : .*\bis not applied\b", re.DOTALL)
# A send is never repeated here: whether it reached the network is for the
# operation's journal to establish, not for a transport retry to guess.
NEVER_RETRIED_METHODS = frozenset({"sendBoc"})


def block_not_applied(exc: BaseException) -> bool:
    """True only for a node's answer that it has not applied the block yet."""
    return (
        isinstance(exc, RpcError)
        and exc.reason == "UPSTREAM_UNAVAILABLE"
        and exc.retryable
        and NOT_APPLIED_TEXT.search(exc.message) is not None
    )


def retrying_reads(rpc, sleep=None, clock=None):
    """`rpc` with every read retried while the node answers block_not_applied.

    The delay doubles from NOT_APPLIED_FIRST_DELAY up to NOT_APPLIED_MAX_DELAY,
    and the read gives up with the node's last answer once
    NOT_APPLIED_RETRY_SECONDS have passed since its first attempt. Any other
    error, and every NEVER_RETRIED_METHODS call, is raised at once. Wrapping a
    wrapped call returns it unchanged, so the bound is never multiplied.
    """
    if getattr(rpc, "retries_not_applied", False):
        return rpc

    def call(url: str, method: str, /, **params: Any) -> Any:
        if method in NEVER_RETRIED_METHODS:
            return rpc(url, method, **params)
        wait = sleep or time.sleep
        now = clock or time.monotonic
        deadline = now() + NOT_APPLIED_RETRY_SECONDS
        delay = NOT_APPLIED_FIRST_DELAY
        while True:
            try:
                return rpc(url, method, **params)
            except RpcError as exc:
                if not block_not_applied(exc):
                    raise
                remaining = deadline - now()
                if remaining <= 0:
                    raise
                wait(min(delay, remaining))
                delay = min(delay * 2, NOT_APPLIED_MAX_DELAY)

    call.retries_not_applied = True  # type: ignore[attr-defined]
    call.wrapped = rpc  # type: ignore[attr-defined]
    return call
