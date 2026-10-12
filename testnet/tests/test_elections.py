"""Tests for testnet-elections.py.

operations-plan-epoch1.txt is real `tosctl controller operations plan` output
from epoch 1 (tos 442884a33), so the plan parser is pinned to what the tool
prints. The pool deploy result follows tosctl's DeployPoolResult, which it
prints with serde_json::to_string_pretty after its progress lines.
"""

import base64
import importlib.util
import json

import pytest
import testnet_lib as lib
from conftest import DATA, SCRIPTS

spec = importlib.util.spec_from_file_location("testnet_elections", SCRIPTS / "testnet-elections.py")
elections = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elections)

PLAN = (DATA / "operations-plan-epoch1.txt").read_text()
CONTROLLER = "21380987703eb9b03e8ec236bf23a457a44aea36118c4f467bfd082ca1d32a77"


def test_plan_gives_the_signing_request_and_the_value():
    plan = elections.parse_operations_plan(PLAN, 2, CONTROLLER)
    assert plan["epoch"] == "0"
    assert plan["nonce"] == "0"
    assert plan["valid_until"] == "1791789269"
    assert plan["payload"].startswith("te6cc")
    assert plan["value_nanotos"] == 23558960000


def test_plan_for_another_network_or_controller_is_refused():
    with pytest.raises(lib.TestnetError, match="global id"):
        elections.parse_operations_plan(PLAN, 1, CONTROLLER)
    with pytest.raises(lib.TestnetError, match="controller"):
        elections.parse_operations_plan(PLAN, 2, "ab" * 32)


def test_plan_without_capital_section_or_command_is_refused():
    with pytest.raises(lib.TestnetError, match="Capital required"):
        elections.parse_operations_plan(PLAN.replace("Capital required", "Capital"), 2, CONTROLLER)
    with pytest.raises(lib.TestnetError, match="signing command"):
        elections.parse_operations_plan(PLAN.replace("fund-operations", "fund-ops"), 2, CONTROLLER)


def test_plan_that_needs_a_top_up_first_is_refused():
    with pytest.raises(lib.TestnetError, match="top-up"):
        elections.parse_operations_plan("Step 0: top up the controller\n" + PLAN, 2, CONTROLLER)


POOL = "-1:" + "5c" * 32


def deploy_output(**fields):
    result = {
        "config": "/var/lib/tos-ctl/tosctl-config.json",
        "account_state": {"address": "-1:" + "ee" * 32, "state": "active"},
        "address": POOL,
        "deployed": True,
        "error": None,
    }
    result.update(fields)
    progress = "Deploy wallet -1:" + "aa" * 32 + "...\n\nWait for wallets deploy: 1...\n"
    return progress + json.dumps(result, indent=2) + "\n"


def test_pool_deploy_reads_the_result_object_only():
    assert elections.parse_pool_deploy(deploy_output()) == POOL


@pytest.mark.parametrize(
    "fields, message",
    [
        ({"deployed": False}, "not deployed"),
        ({"error": "timeout"}, "not deployed"),
        ({"address": "EQ-friendly"}, "raw"),
    ],
)
def test_pool_deploy_failures_are_refused(fields, message):
    with pytest.raises(lib.TestnetError, match=message):
        elections.parse_pool_deploy(deploy_output(**fields))


def test_pool_deploy_without_a_result_is_refused():
    with pytest.raises(lib.TestnetError, match="no deploy result"):
        elections.parse_pool_deploy("Deploy wallet ...\nerror: no route\n")


def friendly(workchain: int, account: bytes, tag: int = 0x11) -> str:
    body = bytes([tag, workchain & 0xFF]) + account
    return base64.urlsafe_b64encode(body + b"\x00\x00").decode()


def test_friendly_address_converts_to_raw():
    account = bytes(range(32))
    assert elections.raw_from_friendly(friendly(-1, account)) == "-1:" + account.hex()
    assert (
        elections.raw_from_friendly(friendly(0, account).replace("-", "+").replace("_", "/"))
        == "0:" + account.hex()
    )
    with pytest.raises(lib.TestnetError):
        elections.raw_from_friendly(base64.urlsafe_b64encode(b"short").decode())


def test_first_transaction_is_the_birth():
    txs = [
        {"transaction_id": {"lt": "300"}, "data": base64.b64encode(b"later").decode()},
        {"transaction_id": {"lt": "9"}, "data": base64.b64encode(b"birth").decode()},
        {"transaction_id": {"lt": "120"}, "data": base64.b64encode(b"middle").decode()},
    ]
    assert elections.first_transaction_boc(txs) == b"birth"
    with pytest.raises(lib.TestnetError):
        elections.first_transaction_boc([])


def test_raw_address_check():
    assert elections.check_raw_address("-1:" + "AB" * 32) == "-1:" + "ab" * 32
    for bad in ("-1:" + "ab" * 31, "EQabc", "-1:" + "zz" * 32):
        with pytest.raises(lib.TestnetError):
            elections.check_raw_address(bad)


def test_repository_profile_has_the_election_amounts():
    e = lib.load_profile()["elections"]
    assert e["stake_tos"] == 10002
    assert e["pool_tos"] >= 2 * e["stake_tos"]
    assert 4 * e["operator_funding_tos"] <= 100000
    assert e["operator_funding_tos"] >= e["pool_tos"] + e["controller_deploy_tos"] + 50
