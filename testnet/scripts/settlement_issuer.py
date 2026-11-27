"""Finalized, hash-pinned issuer checks shared by redemption previews.

Endpoint observations are not cross-domain proofs. The operator-owned binding
pins the asset route and runtime code; a failed getter never becomes a safe
state. No signing or sending methods are exposed.
"""

import importlib.util
import re
import time
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "settlement_source_reader", Path(__file__).with_name("collect-settlement-evm.py")
)
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)
Invalid = source.Invalid
MAX_FINALIZED_AGE = 1800
MAX_FUTURE_SKEW = 30


def require(ok, message):
    if not ok:
        raise Invalid(message)


def validate_binding(binding):
    require(
        set(binding)
        == {"schema", "chain_id", "token", "code_sha256", "profile", "master", "wallet"},
        "issuer binding fields differ",
    )
    require(binding["schema"] == "tos-settlement-issuer/1", "unknown issuer binding schema")
    require(
        type(binding["chain_id"]) is int and 0 < binding["chain_id"] < 2**32, "invalid issuer chain"
    )
    require(binding["profile"] in ("standard", "legacy_usdt"), "unknown issuer profile")
    require(re.fullmatch(r"[0-9a-f]{64}", binding["code_sha256"] or ""), "invalid issuer code pin")
    require(int(source.address(binding["token"]), 16) != 0, "zero issuer address")
    for field in ("master", "wallet"):
        require(
            isinstance(binding[field], str) and re.fullmatch(r"0:[0-9a-f]{64}", binding[field]),
            "invalid bound token " + field,
        )


def fresh(target, now):
    age = now() - source.quantity(target["timestamp"])
    require(
        -MAX_FUTURE_SKEW <= age <= MAX_FINALIZED_AGE,
        "issuer finalized read is stale or future-dated",
    )


def read_issuer(rpc, binding, receiver, now=time.time):
    validate_binding(binding)
    receiver = source.address(receiver)
    require(int(receiver, 16) != 0, "zero redemption receiver")
    require(source.quantity(rpc.call("eth_chainId")) == binding["chain_id"], "issuer chain differs")
    target = source.block(rpc, "finalized")
    fresh(target, now)
    point = dict(blockHash=target["hash"], requireCanonical=True)
    token = source.address(binding["token"])
    require(source.code_hash(rpc, token, point) == binding["code_sha256"], "issuer code differs")
    legacy = binding["profile"] == "legacy_usdt"
    blacklist = "blacklist_legacy" if legacy else "blacklist_standard"
    blacklisted = source.read_bool(rpc, token, blacklist, point, receiver)
    require(not blacklisted, "redemption receiver is blacklisted")
    paused = source.read_bool(rpc, token, "paused", point)
    require(not paused, "issuer token is paused")
    deprecated = source.read_bool(rpc, token, "deprecated", point) if legacy else False
    require(not deprecated, "issuer token is deprecated")
    rate = source.read_uint(rpc, token, "fee", point) if legacy else 0
    maximum = source.read_uint(rpc, token, "maximum", point) if legacy else 0
    require(rate < 10000, "issuer fee rate is outside bounds")
    require(
        source.block(rpc, target["number"])["hash"] == target["hash"], "issuer checkpoint changed"
    )
    fresh(target, now)
    return dict(
        schema="tos-settlement-issuer-read/1",
        chain_id=binding["chain_id"],
        token=token,
        profile=binding["profile"],
        receiver=receiver,
        block_hash=target["hash"],
        block_number=source.quantity(target["number"]),
        block_time=source.quantity(target["timestamp"]),
        fee_basis_points=rate,
        maximum_fee=str(maximum),
    )


def received_amount(amount, observation):
    require(type(amount) is int and 0 < amount < 2**120, "amount is outside Coins range")
    fee = min(amount * observation["fee_basis_points"] // 10000, int(observation["maximum_fee"]))
    require(0 <= fee < amount, "issuer fee consumes the full amount")
    return amount - fee, fee
