"""Tests for testnet-elections.py.

The pool deploy result follows tosctl's DeployPoolResult, which it prints with
serde_json::to_string_pretty after its progress lines.
"""

import base64
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path

import fakechain
import pytest
import testnet_lib as lib
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("testnet_elections", SCRIPTS / "testnet-elections.py")
elections = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elections)
REAL_ENSURE_POOL_OWNER = elections.ensure_pool_owner


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


def test_raw_address_check():
    assert elections.check_raw_address("-1:" + "AB" * 32) == "-1:" + "ab" * 32
    for bad in ("-1:" + "ab" * 31, "EQabc", "-1:" + "zz" * 32):
        with pytest.raises(lib.TestnetError):
            elections.check_raw_address(bad)


# Dated measurements, not values derived from chain config: the epoch-5 bootstrap
# analysis (BOOTSTRAP-AMOUNT.md, 2026-10-28, from the epoch-5 operation journals and
# operator balance snapshots of 2026-10-24).
# The most operator cash any validator spent through its first stake recovery and
# third stake order, its 2 TOS pool deployment included (node-1).
MEASURED_OPERATOR_CASH_NANOTOS = 5_933_747_311
# One stake order and recovery window, the allowance for one failed submission.
FAILURE_ALLOWANCE_NANOTOS = 1_442_093_644
# The eight funding transfers' measured wallet fees plus the sweep budgeted at the
# largest of them.
BOOTSTRAP_TRANSFER_FEES_NANOTOS = 28_622_334


def check_election_amounts(e):
    assert e["stake_tos"] == 10002
    assert e["pool_tos"] >= 2 * e["stake_tos"]
    # The principal reaches the pool from its offline owner, never through the
    # operator wallet on the host, which gets fee money only.
    assert e["operator_funding_tos"] < e["stake_tos"]
    # Fee money must carry the operator through its first returned stake with one
    # failed submission: nothing refills it from the bootstrap wallet after the sweep.
    assert e["operator_funding_tos"] * NANO >= (
        MEASURED_OPERATOR_CASH_NANOTOS + FAILURE_ALLOWANCE_NANOTOS
    )
    # tosctl's election task attaches ELECTOR_STAKE_FEE + NPOOL_COMPUTE_FEE to a pool order.
    assert e["stake_order_nanotos"] == 1_200_000_000
    # The per-transfer allowance covers the measured eight funding transfers and the
    # sweep, with room: at most about three times the measured cost.
    allowance = 9 * e["bootstrap_transfer_fee_nanotos"]
    assert BOOTSTRAP_TRANSFER_FEES_NANOTOS <= allowance <= 4 * BOOTSTRAP_TRANSFER_FEES_NANOTOS
    # An owner keeps a withdrawal message and its fee after onboarding, whoever
    # deployed its pool (the owner's funding carries the deployment as well).
    assert (
        e["pool_owner_reserve_tos"] * NANO
        >= elections.OWNER_MESSAGE_NANOTOS + (elections.ops.FEE_ALLOWANCE_NANOTOS // 10) * 3
    )
    # The margin scales with the pools and is never below epoch 6's 50 TOS for four;
    # the transfer allowance still rounds up to the 1 TOS epoch 6 kept for its fees.
    assert 4 * e["bootstrap_margin_tos_per_pool"] >= 50
    assert -(-allowance // NANO) == 1
    assert -(-(2 * 21 + 1) * e["bootstrap_transfer_fee_nanotos"] // NANO) == 1


def test_repository_profile_has_the_election_amounts():
    check_election_amounts(lib.load_profile()["elections"])


@pytest.mark.parametrize(
    "field, value",
    [
        # 6 TOS covers the measured spend but not the failure allowance.
        ("operator_funding_tos", 6),
        # Less than the measured transfer fees.
        ("bootstrap_transfer_fee_nanotos", 3_000_000),
        # Far above them: the sweep burns it, but the genesis supply says otherwise.
        ("bootstrap_transfer_fee_nanotos", 125_000_000),
        # A margin below epoch 6's for four pools.
        ("bootstrap_margin_tos_per_pool", 12),
        # No withdrawal left to an owner that deployed its pool.
        ("pool_owner_reserve_tos", 1),
    ],
)
def test_the_election_amount_guard_catches_a_wrong_value(field, value):
    e = dict(lib.load_profile()["elections"], **{field: value})
    with pytest.raises(AssertionError):
        check_election_amounts(e)


# ---------------------------------------------------------------- load

WALLET = "0:" + "46" * 32
RELAYER = "0:" + "8b" * 32


def test_query_ids_skip_the_missing_bit_and_wrap():
    assert elections.next_query_id(0) == 1
    assert elections.next_query_id(1021) == 1022
    # bit 1023 of a row does not exist: 1022 is followed by the next row's first id
    assert elections.next_query_id(1022) == 1024
    assert elections.next_query_id((5 << 10) | 1022) == 6 << 10
    last = elections.HIGHLOAD_QUERY_ID_LIMIT - 2  # low ten bits 1022
    assert elections.next_query_id(last) == 0
    with pytest.raises(lib.TestnetError):
        elections.next_query_id(elections.HIGHLOAD_QUERY_ID_LIMIT)


def test_query_id_progression_never_yields_an_unusable_id():
    seen = set()
    query_id = 3000
    for _ in range(5000):
        query_id = elections.next_query_id(query_id)
        assert query_id & 1023 != 1023
        assert query_id not in seen
        seen.add(query_id)
    # control: the same check catches a plain increment
    assert any((q + 1) & 1023 == 1023 for q in range(3000, 8000))


def test_rate_follows_target_gas_and_block_interval():
    gas = elections.batch_gas(254)
    assert gas == 79_546 + 2_708 * 254
    rate = elections.batch_rate(10_000_000, 840_000, 0.4)
    assert rate == pytest.approx(10_000_000 / 840_000 / 0.4)
    # twice the target, twice the rate; twice the interval, half the rate
    assert elections.batch_rate(20_000_000, 840_000, 0.4) == pytest.approx(2 * rate)
    assert elections.batch_rate(10_000_000, 840_000, 0.8) == pytest.approx(rate / 2)


@pytest.mark.parametrize(
    "target, gas, interval",
    [(0, 840_000, 0.4), (10_000_000, 0, 0.4), (10_000_000, 840_000, 0), (20_000_001, 1, 1)],
)
def test_rate_refuses_impossible_inputs(target, gas, interval):
    with pytest.raises(lib.TestnetError):
        elections.batch_rate(target, gas, interval)


def test_batch_size_is_bounded():
    for bad in (0, 255):
        with pytest.raises(lib.TestnetError):
            elections.batch_gas(bad)
    assert elections.batch_gas(1) > 0


def test_pack_size_keeps_external_messages_near_two_per_second():
    assert elections.pack_size(0.5) == 1
    assert elections.pack_size(2) == 1
    assert elections.pack_size(5) == 3
    assert elections.pack_size(40) == elections.SUBMISSIONS_PER_EXTERNAL
    with pytest.raises(lib.TestnetError):
        elections.pack_size(0)


def test_send_window_admits_at_most_its_limit():
    window = elections.SendWindow(limit=3, window=10.0)
    for t in (0.0, 1.0, 2.0):
        assert window.allow(t)
        window.record(t)
    assert not window.allow(9.9)  # control: the fourth send in the window is refused
    assert window.allow(10.5)  # the first send has left the window


def test_block_interval_from_shard_heads():
    assert elections.block_interval({"s": 100}, {"s": 125}, 10.0) == pytest.approx(0.4)
    two = elections.block_interval({"a": 1, "b": 1}, {"a": 11, "b": 21}, 10.0)
    assert two == pytest.approx(10.0 * 2 / 30)
    with pytest.raises(lib.TestnetError):
        elections.block_interval({"s": 100}, {"s": 100}, 10.0)


def test_block_interval_across_a_shard_merge_and_split():
    # Two children merged back into the whole shard during the window (seen live under load).
    merged = elections.block_interval({"4000": 532007, "c000": 532004}, {"8000": 532032}, 10.0)
    assert merged == pytest.approx(10.0 / 25)
    split = elections.block_interval({"8000": 529800}, {"4000": 529825, "c000": 529824}, 10.0)
    assert split == pytest.approx(10.0 / 25)
    with pytest.raises(lib.TestnetError):
        elections.block_interval({"4000": 532007}, {"8000": 532007}, 10.0)


def test_request_program_binds_network_wallet_and_ids():
    text = elections.request_program(
        2, WALLET, [RELAYER], 254, 50_000, 3600, [(7, 1000), (8, 1000)]
    )
    assert "2 constant gid" in text
    assert f"0 0x{'46' * 32} 2constant hl" in text
    assert "3600 constant wallet-timeout" in text
    assert "254 constant action-count" in text
    assert f"0 0x{'8b' * 32} Addr, 50000 Tomi," in text
    assert "7 1000 request" in text and '"req-8.boc"' in text


@pytest.mark.parametrize(
    "kwargs",
    [
        {"requests": [(1023, 1)]},  # an id that does not exist
        {"requests": [(1 << 23, 1)]},
        {"actions": 255},
        {"actions": 0},
        {"recipients": []},
        {"transfer_nanotos": -1},
    ],
)
def test_request_program_refuses_bad_arguments(kwargs):
    args = dict(
        global_id=2,
        wallet=WALLET,
        recipients=[RELAYER],
        actions=10,
        transfer_nanotos=1,
        timeout=3600,
        requests=[(1, 1)],
    )
    args.update(kwargs)
    with pytest.raises(lib.TestnetError):
        elections.request_program(**args)


def test_external_body_carries_each_submission_with_its_value():
    body = elections.external_body(
        "relayer-3", RELAYER, 0x10AD0003, 17, 1_800_000_000, [(5, 99), (6, 99)], "ext-3.boc"
    )
    assert f"{0x10AD0003} 32 u, 1800000000 32 u, 17 32 u," in body
    assert body.count("submission 99 to-wallet ref,") == 2
    assert '"relayer-3.pk" load-keypair' in body and '"ext-3.boc" B>file' in body
    program = elections.externals_program(2, WALLET, [body])
    assert program.index("2constant hl") < program.index(body)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"submissions": []},
        {"submissions": [(1, 1)] * 5},  # a wallet-v3 external carries at most four
        {"submissions": [(1, 0)]},
        {"relayer_base": "../x"},
        {"out_name": "a b.boc"},
    ],
)
def test_external_body_refuses_bad_arguments(kwargs):
    args = dict(
        relayer_base="relayer-0",
        relayer=RELAYER,
        relayer_subwallet=1,
        seqno=0,
        valid_until=1,
        submissions=[(1, 1)],
        out_name="ext.boc",
    )
    args.update(kwargs)
    with pytest.raises(lib.TestnetError):
        elections.external_body(**args)


# A full batch observed on a loopback network at tos 703c2a5cb: the relayer attached
# 17,966,407 nanotos and the wallet sent 12,299,655 back first; its get_required_value
# quoted 1,072,669 for one transfer and 1,094,669 for two.
QUOTE_ONE = 1_072_669
QUOTE_TWO = 1_094_669


def submission_tx(value=17_966_407, refund=12_299_655, success=True):
    out = [{"created_lt": "11", "value": "50000"}, {"created_lt": "10", "value": str(refund)}]
    return {
        "in_msg": {"kind": "internal", "value": str(value)},
        "out_msgs": out,
        "compute": {"success": success},
    }


def test_gas_is_read_back_from_a_submission():
    price, lump = elections.price_and_lump(QUOTE_ONE, QUOTE_TWO)
    assert price == pytest.approx(6.6667, rel=1e-4)
    assert lump == pytest.approx(66_667, abs=50)
    gas = elections.gas_from_transaction(submission_tx(), price, lump)
    assert gas == pytest.approx(840_012, abs=100)
    # control: taking the last message instead of the first refund would be far off
    wrong = elections.gas_from_transaction(submission_tx(refund=50_000), price, lump)
    assert wrong > 2 * gas


def test_gas_ignores_what_is_not_an_executed_submission():
    price, lump = elections.price_and_lump(QUOTE_ONE, QUOTE_TWO)
    assert elections.gas_from_transaction(submission_tx(success=False), price, lump) is None
    assert elections.gas_from_transaction({"in_msg": None, "out_msgs": []}, price, lump) is None
    with pytest.raises(lib.TestnetError):
        elections.price_and_lump(QUOTE_TWO, QUOTE_ONE)


def test_submission_value_covers_the_quote():
    assert elections.submission_value(10_000_000) > 10_000_000
    with pytest.raises(lib.TestnetError):
        elections.submission_value(0)


def test_tos_amounts_parse_exactly():
    assert elections.parse_tos("50", "x") == 50 * 10**9
    assert elections.parse_tos("0.000000001", "x") == 1
    for bad in ("0", "-1", "1e3", "1.0000000001", "abc"):
        with pytest.raises(lib.TestnetError):
            elections.parse_tos(bad, "x")


class FakeRpc:
    """Answers the read calls a dry run makes and records every call; a broadcast fails
    the test."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, method, /, **params):
        self.calls.append(method)
        if method == "sendBoc":
            raise AssertionError("a dry run broadcast a message")
        if method == "getAddressInformation":
            return {"state": "uninitialized", "balance": "0"}
        raise AssertionError(f"unexpected call {method}")


def load_args(tmp_path, **extra):
    args = dict(
        ceremony=str(tmp_path / "ceremony"),
        tos_root=str(tmp_path / "tos"),
        fift=str(tmp_path / "tos" / "build" / "crypto" / "fift"),
        rpc="http://fake/jsonRPC",
        key_tool="tos-pq-key",
        state=str(tmp_path / "state"),
        actions_per_batch=254,
        transfers="skip",
        transfer_nanotos=50_000,
        wallet_timeout=3600,
        relayers=4,
        send_rpc=None,
        dry_run=True,
        previous_ceremony=[],
        funding_owner="node-1",
        owner_floor="100",
    )
    args.update(extra)
    return elections.argparse.Namespace(**args)


def fake_tools(monkeypatch, state):
    """Fift and the key tool, replaced by stand-ins that write the files the real ones
    would, so only the driver's own decisions are under test."""

    def ensure_keys(self, relayers):
        lib.private_dir(state)
        self.timeout = 3600
        return WALLET, [elections.Relayer(i, RELAYER) for i in range(relayers)]

    def fift(self, program, cwd):
        out = []
        for qid in (int(m) for m in __import__("re").findall(r"^(\d+) \d+ request", program, 8)):
            (cwd / f"req-{qid}.boc").write_bytes(b"request")
            out.append(f"REQ {qid} {'ab' * 32}")
        for name in __import__("re").findall(r'"(ext-[^"]+)" B>file', program):
            (cwd / name).write_bytes(b"external")
        return "\n".join(out) + "\n"

    def run(argv, **kwargs):
        assert argv[1] == "sign"
        return elections.subprocess.CompletedProcess(argv, 0, "cd" * 2420, "")

    monkeypatch.setattr(elections.LoadDriver, "ensure_keys", ensure_keys)
    monkeypatch.setattr(elections.LoadDriver, "fift", fift)
    monkeypatch.setattr(lib, "run", run)


def test_dry_run_signs_one_batch_and_broadcasts_nothing(tmp_path, monkeypatch):
    state = tmp_path / "state"
    fake_tools(monkeypatch, state)
    rpc = FakeRpc()
    driver = elections.LoadDriver(load_args(tmp_path), elections.Chain("http://fake", rpc), 2)
    assert driver.run() == {}
    assert "sendBoc" not in rpc.calls
    [work] = state.glob("dry-run-*")
    report = json.loads((work / "dry-run.json").read_text())
    assert report["query_ids"] == [0]
    assert report["transfer_nanotos"] == elections.SKIP_TRANSFER_NANOTOS
    assert (work / report["external"]).read_bytes() == b"external"
    assert len((work / "sig-0.bin").read_bytes()) == elections.MLDSA44_SIGNATURE_BYTES
    # the next run continues after the id the dry run used
    assert json.loads((state / "load-state.json").read_text())["next_query_id"] == 1
    # control: the fake refuses a broadcast, so a dry run that sent would fail here
    with pytest.raises(AssertionError, match="broadcast"):
        elections.Chain("http://fake", rpc).send_boc(b"x")


NOT_APPLIED = lib.RpcError(
    "http://fake",
    "getAddressInformation",
    -32603,
    "UPSTREAM_UNAVAILABLE",
    "getAccountState: [Error : 651 : cannot load block (-1,8000000000000000,338211):ab:cd"
    " : block (-1,8000000000000000,338211) is not applied (last known masterchain block: 338209)]",
    True,
)


class LaggingRpc:
    """A node `failures` reads behind: each read is refused as not applied until then."""

    def __init__(self, failures, error=NOT_APPLIED):
        self.failures, self.error, self.calls = failures, error, []

    def __call__(self, url, method, /, **params):
        self.calls.append(method)
        if method == "sendBoc":
            raise AssertionError("the refill broadcast outside fund()")
        if len(self.calls) <= self.failures:
            raise self.error
        return {"state": "active", "balance": "0"}


class OneRound:
    """A refill thread's stop event that lets exactly one round run."""

    def __init__(self):
        self.rounds = 0

    def wait(self, _seconds):
        self.rounds += 1
        return self.rounds > 1

    def is_set(self):
        return False


def refill_once(tmp_path, monkeypatch, rpc):
    monkeypatch.setattr(lib, "NOT_APPLIED_FIRST_DELAY", 0.001)
    monkeypatch.setattr(lib, "NOT_APPLIED_MAX_DELAY", 0.002)
    monkeypatch.setattr(lib, "NOT_APPLIED_RETRY_SECONDS", 0.05)
    args = load_args(tmp_path, relayer_amount="10", dry_run=False)
    driver = elections.LoadDriver(args, elections.Chain("http://fake", rpc), 2)
    funded = []
    monkeypatch.setattr(driver, "fund_from_owner", lambda *a: funded.append(a[:3]))
    driver.refill([elections.Relayer(3, RELAYER)], OneRound())
    return driver, funded


@pytest.mark.parametrize("failures", [1, 2])
def test_a_refill_read_waits_for_a_lagging_node(tmp_path, monkeypatch, failures):
    rpc = LaggingRpc(failures)
    driver, funded = refill_once(tmp_path, monkeypatch, rpc)
    assert driver.refill_error is None
    assert funded == [(RELAYER, 10 * elections.NANO, "load-refill-3")]
    assert rpc.calls == ["getAddressInformation"] * (failures + 1)


def test_a_refill_read_still_not_applied_after_the_bound_is_a_safety_stop(tmp_path, monkeypatch):
    # Far more refusals than the bound admits (each wait is at least 1 ms), and few
    # enough that a read without a bound gets an answer and the test sees it.
    rpc = LaggingRpc(200)
    driver, funded = refill_once(tmp_path, monkeypatch, rpc)
    assert driver.refill_error, "the read outlasted its bound"
    assert driver.refill_error.startswith("refilling relayer 3: http://fake getAddressInformation")
    assert "UPSTREAM_UNAVAILABLE -32603" in driver.refill_error
    assert "is not applied" in driver.refill_error
    assert funded == [] and 2 < len(rpc.calls) < 200


@pytest.mark.parametrize(
    "error",
    [
        lib.RpcError("http://fake", "m", -32603, "UPSTREAM_UNAVAILABLE", "timeout", True),
        lib.RpcError("http://fake", "m", -32004, "BLOCK_UNAVAILABLE", NOT_APPLIED.message, False),
        lib.TestnetError("http://fake getAddressInformation: HTTP 502"),
    ],
)
def test_other_refill_read_errors_stop_at_once(tmp_path, monkeypatch, error):
    rpc = LaggingRpc(200, error)
    driver, funded = refill_once(tmp_path, monkeypatch, rpc)
    assert driver.refill_error == f"refilling relayer 3: {error}"
    assert funded == [] and rpc.calls == ["getAddressInformation"]


def test_a_load_send_is_never_retried(monkeypatch):
    monkeypatch.setattr(lib, "NOT_APPLIED_RETRY_SECONDS", 5.0)
    calls = []

    def send(url, method, /, **params):
        calls.append(method)
        raise NOT_APPLIED

    with pytest.raises(lib.RpcError):
        elections.Chain("http://fake", send).send_boc(b"x")
    assert calls == ["sendBoc"]


@pytest.mark.parametrize("target", ["3", "6", "6.000000002"])
def test_refill_threshold_must_precede_safety_stop(tmp_path, target):
    args = load_args(
        tmp_path,
        dry_run=False,
        batches_per_second=1.0,
        target_gas_per_block=None,
        duration=120,
        max_retries=0,
        relayer_amount=target,
        relayer_floor="2",
    )
    with pytest.raises(lib.TestnetError, match="refill threshold.*must exceed"):
        elections.check_load_args(args)


@pytest.mark.parametrize("target", ["10", "6.000000003"])
def test_refill_threshold_uses_exact_nanotos(tmp_path, target):
    args = load_args(
        tmp_path,
        dry_run=False,
        batches_per_second=1.0,
        target_gas_per_block=None,
        duration=120,
        max_retries=0,
        relayer_amount=target,
        relayer_floor="2",
    )
    elections.check_load_args(args)


def test_load_arguments_are_checked():
    good = load_args(__import__("pathlib").Path("/nonexistent"), dry_run=False)
    good.batches_per_second = 1.0
    good.target_gas_per_block = None
    good.duration = 10
    good.max_retries = 1
    elections.check_load_args(good)
    for field, value in (
        ("batches_per_second", None),
        ("duration", 0),
        ("wallet_timeout", 0),
        ("actions_per_batch", 255),
        ("transfer_nanotos", -1),
        # Load is funded by a pool owner, never by the bootstrap wallet.
        ("funding_owner", None),
    ):
        bad = elections.argparse.Namespace(**vars(good))
        setattr(bad, field, value)
        with pytest.raises(lib.TestnetError):
            elections.check_load_args(bad)


# ---------------------------------------------------------------- chain

OPERATOR = "-1:294974d03f4c811d5b550812f633d188d7c035923151e267fe208ec52b2fd4d6"
NANO = 10**9


def test_chain_reads_the_open_election():
    def rpc(url, method, /, **params):
        assert params["address"] == elections.ELECTOR and params["method"] == "active_election_id"
        return {"exit_code": 0, "stack": [["num", "0x6ab6d8f1"]]}

    chain = elections.Chain("http://fake", rpc)
    assert chain.active_election() == 0x6AB6D8F1


# ---------------------------------------------------------------- non-root operator tool


class Captured:
    """Stands in for subprocess.run in Host: records the ssh argv and stdin."""

    def __init__(self, returncode=0):
        self.calls = []
        self.returncode = returncode

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        out = b"" if "input" in kwargs else ""
        return subprocess.CompletedProcess(argv, self.returncode, stdout=out, stderr=out)


def test_host_runs_tosctl_as_its_own_user_with_the_env_from_root(monkeypatch):
    run = Captured()
    monkeypatch.setattr(elections.subprocess, "run", run)
    elections.Host("192.0.2.1", "key").tosctl("wallet ls", 60)
    [(argv, _)] = run.calls
    command = argv[-1]
    assert argv[:2] == ["ssh", "-i"] and "root@192.0.2.1" in argv
    assert command.startswith("set -a; . /etc/tos/tosctl.env; set +a; cd /var/lib/tos-ctl; ")
    assert "timeout 60 runuser -u tos-ctl -- tosctl wallet ls 2>&1" in command
    assert " tosctl" not in command.replace("runuser -u tos-ctl -- tosctl", "")


def test_host_put_writes_the_file_as_the_owner_with_mode_0600(monkeypatch, tmp_path):
    real_run = subprocess.run  # the module is shared, so keep the real one before patching
    run = Captured()
    monkeypatch.setattr(elections.subprocess, "run", run)
    local = tmp_path / "local.boc"
    local.write_bytes(b"\xb5\xee\x9c\x72 boc")
    remote = tmp_path / "state" / "node-x.boc"
    remote.parent.mkdir()
    elections.Host("192.0.2.1", "key").put(local, str(remote), "tos-ctl")
    [(argv, kwargs)] = run.calls
    command = argv[-1]
    prefix = "runuser -u tos-ctl -- "
    assert command.startswith(prefix)
    assert kwargs["input"] == local.read_bytes()
    # What runuser would run as tos-ctl, run here as this user.
    real = real_run(
        ["bash", "-c", command[len(prefix) :]], input=kwargs["input"], capture_output=True
    )
    assert real.returncode == 0, real.stderr
    assert remote.read_bytes() == local.read_bytes()
    assert remote.stat().st_mode & 0o777 == 0o600
    assert not (remote.parent / (remote.name + ".tmp")).exists()


def test_host_put_failure_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(elections.subprocess, "run", Captured(returncode=1))
    (tmp_path / "f").write_bytes(b"x")
    with pytest.raises(lib.TestnetError, match="as tos-ctl failed"):
        elections.Host("192.0.2.1", "key").put(tmp_path / "f", "/var/lib/tos-ctl/f", "tos-ctl")


def test_elections_unit_runs_as_tos_ctl_with_matching_hardening():
    text = (SCRIPTS.parent / "systemd" / "tos-testnet-elections.service").read_text()
    for line in (
        "User=tos-ctl",
        "Group=tos-ctl",
        "UMask=0077",
        "EnvironmentFile=/etc/tos/tosctl.env",
        "Restart=always",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectHome=true",
        "ProtectSystem=strict",
        "ReadWritePaths=/var/lib/tos-ctl",
        "CapabilityBoundingSet=",
    ):
        assert f"\n{line}\n" in text, line
    assert "User=root" not in text


def test_no_testnet_or_production_unit_runs_as_root():
    repo = SCRIPTS.parent.parent
    units = sorted((repo / "testnet" / "systemd").glob("*.service"))
    units += sorted((repo / "production" / "systemd").glob("*.service"))
    assert len(units) >= 8
    for unit in units:
        text = unit.read_text()
        if "WantedBy=default.target" in text:
            continue  # a user unit: it runs as the coordinator's own login user
        assert "\nUser=" in text and "\nUser=root" not in text, unit.name


def test_production_elections_unit_keeps_the_testnet_sandbox():
    repo = SCRIPTS.parent.parent
    service = {}
    for path in (
        repo / "testnet" / "systemd" / "tos-testnet-elections.service",
        repo / "production" / "systemd" / "tos-elections.service",
    ):
        section = path.read_text().split("[Service]\n", 1)[1].split("\n[", 1)[0]
        service[path.name] = sorted(
            line for line in section.splitlines() if line and not line.startswith("#")
        )
    assert service["tos-testnet-elections.service"] == service["tos-elections.service"]


def test_host_scripts_never_run_tosctl_as_root():
    import re

    command = re.compile(r"(?<![\w-])tosctl (?:key|config|wallet|deploy|service)\b")
    for name in ("init-operator.sh", "enable-elections.sh"):
        for number, line in enumerate((SCRIPTS / name).read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for found in command.finditer(line):
                assert line[: found.start()].endswith("as_ctl "), f"{name}:{number}: {line}"
        assert 'as_ctl() { runuser -u "$USER_NAME" -- "$@"; }' in (SCRIPTS / name).read_text()


def test_shell_scripts_parse_and_the_privilege_scripts_pass_shellcheck():
    import shutil

    for script in sorted(SCRIPTS.glob("*.sh")):
        result = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert result.returncode == 0, f"{script.name}: {result.stderr}"
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck is not installed")
    # The scripts that create users, change owners or run tosctl as its user.
    checked = [
        SCRIPTS / name
        for name in (
            "init-operator.sh",
            "enable-elections.sh",
            "retire-host.sh",
            "migrate-nonroot-services.sh",
        )
    ]
    result = subprocess.run(["shellcheck", *map(str, checked)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout[-2000:]


# ---------------------------------------------------------------- the pool owner (offline)

# Onboarding and withdrawal on the asynchronous fake chain (fakechain.py): every
# value-moving step is an operation; the host builds the operator's messages
# (`wallet send --build-only`) and the coordinator checks, journals and sends them.

COLD_OWNER = None  # set per test from the owner key the fake creates
HOST_WALLET = "-1:" + "6b" * 32
OP_KEY = "0b" * 32
OP_WALLET = fakechain.wallet_address(OP_KEY, 698983191)
BOARD_NOW = fakechain.Chain().now  # the fake chain's clock when onboarding starts


@pytest.fixture
def pinned_tos():
    root = Path(os.environ.get("TOS_ROOT", Path.home() / "tos"))
    if not (root / elections.SINGLE_NOMINATOR_CODE).is_file():
        pytest.skip("TOS_ROOT has no single-nominator code")
    return root


def num(value):
    return ["num", hex(value)]


class BoardingHost:
    """The validator host: init-operator.sh, tosctl (configuration and the operator
    wallet's messages, built and never sent), enable-elections.sh and the node log."""

    def __init__(self, chain, tweak=None):
        self.chain, self.tweak = chain, tweak or {}
        self.config = {"pools": {}, "bindings": {}}
        self.commands = []
        self.operator = fakechain.wallet_address(OP_KEY, 698983191)
        # The validator id the node reports holding its consensus key for.
        self.bound = None
        self.elections_on = False

    def run(self, command, timeout=300):
        self.commands.append(command)
        if elections.vh.MAX_FACTOR_MARKER in command:
            # The max-factor probe on a copy of tosctl's configuration.
            factor = command.split("elections max-factor ")[1].split()[0]
            if float(factor) > self.tweak.get("tosctl_max_factor", 100.0):
                return "Error: max-factor must be in range [1.0..3.0]\nPROBE-REFUSED\n"
            return f"{elections.vh.MAX_FACTOR_MARKER} {self.tweak.get('reads_back', factor)}\n"
        if "init-operator.sh" in command:
            body = bytes([0x11, 0xFF]) + bytes.fromhex(self.operator.split(":")[1]) + b"\x00\x00"
            return f"op-node-1 {base64.urlsafe_b64encode(body).decode()}\n"
        if command.startswith("cat "):
            return json.dumps(self.config)
        if "post-quantum consensus custody" in command:
            if self.bound is None:
                return ""
            return (
                f"[ 2][t 1][2026-10-23 00:00:00.000000000] post-quantum consensus custody: "
                f"validator_id {self.bound} key_id {'ab' * 32} valid_from 0 expire_at 0\n"
            )
        if "enable-elections.sh" in command:
            self.elections_on = True
            return "active\n"
        if command.startswith("systemctl is-active tos-testnet-elections.service"):
            return "active\n" if self.elections_on else "inactive\n"
        if command.startswith("systemctl "):
            return ""
        raise AssertionError(command)

    def tosctl(self, arguments, timeout=240):
        self.commands.append("tosctl " + arguments)
        words = arguments.split()

        def flag(name, default=None):
            return words[words.index(name) + 1] if name in words else default

        if arguments.startswith("wallet activate"):
            account = self.chain.account(self.operator)
            init = fakechain.wallet_state_init(OP_KEY, 698983191)
            self.chain.send(
                fakechain.build_external(
                    self.operator,
                    2,
                    0,
                    elections.ops.ACTIVATION_VALID_UNTIL,
                    init=init,
                    subwallet=698983191,
                )
            )
            self.chain.settle_all()
            assert account["state"] == "active"
            account["subwallet"] = 698983191
            return ""
        if arguments.startswith("wallet send") and "--build-only" in arguments:
            destination = self.tweak.get("destination", flag("--to"))
            value = int(flag("--amount-nanotos")) + self.tweak.get("value_delta", 0)
            init_b64, body_b64 = flag("--state-init-boc"), flag("--body-boc")
            init = lib.parse_boc(base64.b64decode(init_b64)) if init_b64 else None
            body = lib.parse_boc(base64.b64decode(body_b64)) if body_b64 else None
            seqno = self.chain.account(self.operator)["seqno"] + self.tweak.get("seqno_delta", 0)
            boc = fakechain.build_external(
                self.operator,
                self.tweak.get("global_id", 2),
                seqno,
                self.chain.now + self.tweak.get("ttl", 120),
                fakechain.internal_message(destination, value, "--bounce" in words, init, body),
                subwallet=698983191,
            )
            return (
                json.dumps(
                    {
                        "version": "tosctl.wallet-prepared-send.v1",
                        "message_boc_base64": base64.b64encode(boc).decode(),
                    }
                )
                + "\n"
            )
        if arguments.startswith("config pool add"):
            self.config["pools"][flag("--name")] = {
                "address": flag("--address"),
                "owner": flag("--owner"),
            }
            return ""
        if arguments.startswith("config bind add"):
            self.config["bindings"][flag("--node")] = {
                "wallet": flag("--wallet"),
                "pool": flag("--pool"),
            }
            return ""
        raise AssertionError(arguments)


@pytest.fixture
def boarding(tmp_path, pinned_tos, monkeypatch):
    chain = fakechain.Chain()
    ceremony = tmp_path / "ceremony"
    (ceremony / "secret").mkdir(parents=True, mode=0o700)
    ceremony.chmod(0o700)
    (ceremony / "genesis.json").write_text(json.dumps({"zero_state": chain.zero_state}))
    (ceremony / "secret" / "main-wallet.pk").write_bytes(b"\x01" * 32)
    (ceremony / "main-wallet.addr").write_bytes(
        bytes.fromhex("11" * 32) + (-1).to_bytes(4, "big", signed=True)
    )
    chain.wallet(elections.BOOTSTRAP_WALLET, 100_000 * NANO, public_key="b0" * 32)
    host = BoardingHost(chain)
    owner_key = "0e" * 32
    owner = fakechain.wallet_address(owner_key)

    def ensure_owner(args, name, global_id, previous, run=None):
        paths = elections.pool_owner_paths(Path(args.ceremony), name)
        paths["key"].write_bytes(b"\x02" * 32)
        paths["addr"].parent.mkdir(exist_ok=True)
        paths["addr"].write_bytes(
            bytes.fromhex(owner.split(":")[1]) + (-1).to_bytes(4, "big", signed=True)
        )
        paths["init"].write_bytes(
            fakechain.build_external(
                owner,
                2,
                0,
                elections.ops.ACTIVATION_VALID_UNTIL,
                init=fakechain.wallet_state_init(owner_key),
                subwallet=0x504F4F4C,
            )
        )
        return owner

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
    ):
        wallet = (
            f"{int.from_bytes(address_file[32:], 'big', signed=True)}:{address_file[:32].hex()}"
        )
        body_cell = lib.parse_boc(Path(body).read_bytes()) if body else None
        init_cell = lib.parse_boc(Path(init).read_bytes()) if init else None
        return fakechain.build_external(
            wallet,
            global_id,
            seqno,
            chain.now + 300,
            fakechain.internal_message(
                to, elections.parse_tos(amount, "a"), bounce, init_cell, body_cell
            ),
            subwallet=subwallet,
        )

    monkeypatch.setattr(elections, "Host", lambda h, k: host)
    monkeypatch.setattr(elections, "ensure_pool_owner", ensure_owner)
    monkeypatch.setattr(elections, "sign_wallet_v3", sign)
    monkeypatch.setattr(elections.time, "sleep", lambda s: chain.tick())
    monkeypatch.setattr(elections.ops, "SETTLE_SECONDS", 60)
    monkeypatch.setattr(elections.ops.time, "time", lambda: chain.now)
    operations = elections.ops.Operations(
        ceremony,
        [chain.node("http://a"), chain.node("http://b")],
        2,
        clock=lambda: chain.now,
        sleep=lambda s: chain.tick(),
    )
    args = elections.argparse.Namespace(
        name="node-1",
        host="h",
        ssh_key="k",
        ceremony=str(ceremony),
        tos_root=str(pinned_tos),
        fift="fift",
        rpc="http://a",
        previous_ceremony=[],
    )
    # Before genesis: the operator wallet the host printed, the offline owner and
    # the pool they derive, which genesis then names as the validator id.
    staking = elections.stake_pool(
        elections.argparse.Namespace(**dict(vars(args), operator=host.operator)), 2
    )
    pool = staking["pool"]
    (ceremony / "genesis-records.json").write_text(
        json.dumps([{"validator_id": staking["validator_id"]}])
    )
    # A registered pool outside the genesis set: it stakes the unit amounts.
    # Tests of a team pool name it in genesis-set.json themselves.
    (ceremony / "genesis-set.json").write_text("[]")
    host.bound = staking["validator_id"]
    return {
        "chain": chain,
        "ops": operations,
        "host": host,
        "args": args,
        "owner": owner,
        "pool": pool,
        "ceremony": ceremony,
        "tos": pinned_tos,
    }


def onboard(b):
    elections.onboard(b["args"], b["ops"], 2, lib.load_profile())


def settled_ids(b):
    return sorted(r["id"] for r in b["ops"].journal.all() if r and r["state"] == "settled")


ALL_STEPS = [
    "fund-op-node-1",
    "fund-owner-node-1",
    "activate-owner-node-1",
    "deploy-pool-node-1",
    "principal-node-1",
]


def test_onboard_moves_every_value_once_through_operations(boarding):
    b = boarding
    onboard(b)
    e = lib.load_profile()["elections"]
    assert settled_ids(b) == sorted(ALL_STEPS)
    chain, owner = b["chain"], b["owner"]
    pool = elections.pool_address(
        elections.single_nominator_code(b["tos"]), owner, b["host"].operator
    )
    assert pool == b["pool"]
    assert chain.account(pool)["balance"] == (e["pool_deploy_tos"] + e["pool_tos"]) * NANO
    assert elections.read_pools(b["ceremony"])["node-1"]["principal_sent"] is True
    # Exactly five value messages and the operator's own deployment were ever sent.
    assert len(chain.sent) == len(ALL_STEPS) + 1
    assert "enable-elections.sh" in b["host"].commands[-1]


def test_onboard_rerun_sends_nothing(boarding):
    b = boarding
    onboard(b)
    sent = list(b["chain"].sent)
    onboard(b)
    assert b["chain"].sent == sent


def test_the_node_must_sign_for_the_pool_before_elections_are_enabled(boarding):
    b = boarding
    b["host"].bound = "cd" * 32
    with pytest.raises(lib.TestnetError, match="signs stake authorizations for cdcd"):
        onboard(b)
    assert "principal-node-1" in settled_ids(b)
    assert not any("enable-elections" in c for c in b["host"].commands)
    b["host"].bound = None
    with pytest.raises(lib.TestnetError, match="no post-quantum consensus custody line"):
        onboard(b)
    b["host"].bound = b["pool"].split(":")[1]
    onboard(b)
    assert "enable-elections.sh" in b["host"].commands[-1]


def test_a_pool_short_of_two_stakes_is_not_ready(boarding, monkeypatch):
    b = boarding
    profile = lib.load_profile()
    profile["elections"]["stake_tos"] = profile["elections"]["pool_tos"] // 2 + 1
    with pytest.raises(lib.TestnetError, match="less than two stakes"):
        elections.onboard(b["args"], b["ops"], 2, profile)
    assert not any("enable-elections" in c for c in b["host"].commands)


def test_a_host_wallet_other_than_the_recorded_operator_is_refused(boarding):
    b = boarding
    b["host"].operator = HOST_WALLET
    with pytest.raises(lib.TestnetError, match="not the recorded operator wallet"):
        onboard(b)
    assert b["chain"].sent == [] and b["ops"].journal.all() == []


def test_onboarding_needs_the_pool_recorded_and_named_by_genesis(boarding):
    b = boarding
    records = b["ceremony"] / "genesis-records.json"
    records.write_text(json.dumps([{"validator_id": "cd" * 32}]))
    with pytest.raises(lib.TestnetError, match="not a validator id in the genesis records"):
        onboard(b)
    (b["ceremony"] / "pools.json").unlink()
    with pytest.raises(lib.TestnetError, match="records no staking pool for node-1"):
        onboard(b)
    assert b["chain"].sent == [] and b["host"].commands == []


def test_a_recorded_pool_that_does_not_derive_is_refused(boarding):
    b = boarding
    path = b["ceremony"] / "pools.json"
    pools = json.loads(path.read_text())
    pools["node-1"]["pool"] = "-1:" + "cd" * 32
    path.write_text(json.dumps(pools))
    (b["ceremony"] / "genesis-records.json").write_text(json.dumps([{"validator_id": "cd" * 32}]))
    with pytest.raises(lib.TestnetError, match="but its owner and operator derive"):
        onboard(b)
    assert b["chain"].sent == []


def test_stake_pool_records_the_roles_and_refuses_reused_or_basechain_wallets(boarding):
    b = boarding
    args = elections.argparse.Namespace(**dict(vars(b["args"]), operator=b["host"].operator))
    again = elections.stake_pool(args, 2)
    assert again["pool"] == b["pool"]
    assert elections.read_pools(b["ceremony"])["node-1"] == {
        "pool": b["pool"],
        "owner": b["owner"],
        "operator": b["host"].operator,
    }
    wallets = json.loads((b["ceremony"] / "wallets.json").read_text())
    assert wallets["op-node-1"] == b["host"].operator
    with pytest.raises(lib.TestnetError, match="never changed"):
        elections.stake_pool(
            elections.argparse.Namespace(**dict(vars(args), operator=HOST_WALLET)), 2
        )
    basechain = elections.argparse.Namespace(**dict(vars(args), name="node-2", operator=WALLET))
    with pytest.raises(lib.TestnetError, match="not in the masterchain"):
        elections.stake_pool(basechain, 2)
    previous = b["ceremony"].parent / "previous"
    previous.mkdir()
    (previous / "wallets.json").write_text(json.dumps({"op-node-1": OPERATOR}))
    reused = elections.argparse.Namespace(
        **dict(vars(args), name="node-3", operator=OPERATOR, previous_ceremony=[str(previous)])
    )
    with pytest.raises(lib.TestnetError, match="reuses"):
        elections.stake_pool(reused, 2)


def crash(monkeypatch, op_id, point):
    def hook(i, p):
        if (i, p) == (op_id, point):
            raise KeyboardInterrupt(f"{i}:{p}")

    monkeypatch.setattr(elections.ops, "crash_point", hook)


@pytest.mark.parametrize("op_id", ALL_STEPS)
@pytest.mark.parametrize("point", ["signed", "broadcast", "delivered"])
def test_an_interrupted_onboarding_never_sends_value_twice(boarding, monkeypatch, op_id, point):
    b = boarding
    crash(monkeypatch, op_id, point)
    with pytest.raises(KeyboardInterrupt):
        onboard(b)
    monkeypatch.setattr(elections.ops, "crash_point", lambda i, p: None)
    b["chain"].settle_all()
    sent = list(b["chain"].sent)
    with pytest.raises(lib.TestnetError, match="open"):
        onboard(b)
    assert b["chain"].sent == sent
    # A person resolves it, and the rerun completes without a second message.
    record = b["ops"].journal.record(op_id)
    if point == "signed":
        b["ops"].resubmit(
            op_id,
            expect=elections.expect_for(b["args"], record)
            if record["kind"] in elections.ops.HOST_KINDS
            else None,
        )
    else:
        evidence = b["ops"].settle(
            record,
            elections.expect_for(b["args"], record)
            if record["kind"] in elections.ops.HOST_KINDS
            else None,
        )[1]
        b["ops"].record_settled(
            op_id,
            evidence["wallet_tx"],
            elections.expect_for(b["args"], record)
            if record["kind"] in elections.ops.HOST_KINDS
            else None,
        )
    onboard(b)
    assert settled_ids(b) == sorted(ALL_STEPS)
    externals = b["chain"].sent
    assert len(externals) == len(set(externals)) == len(ALL_STEPS) + 1


@pytest.mark.parametrize(
    "tweak,message",
    [
        ({"destination": HOST_WALLET}, "not the intended transfer"),
        ({"value_delta": NANO}, "not the intended transfer"),
        ({"global_id": 1}, "global id 1"),
        ({"seqno_delta": 1}, "seqno"),
        ({"ttl": 600}, "expires"),
        ({"ttl": -1}, "expires"),
    ],
)
def test_a_host_built_message_other_than_intended_is_never_sent(boarding, tweak, message):
    b = boarding
    b["host"].tweak = tweak
    with pytest.raises(lib.TestnetError, match=message):
        onboard(b)
    # Only what is built here went out before the first host-built message (the pool
    # deployment): both bootstrap fundings and the two wallets' self-deployments.
    assert len(b["chain"].sent) == 4
    assert b["ops"].journal.record("deploy-pool-node-1")["state"] != "settled"


def test_the_principal_waits_for_the_owner_credit(boarding, monkeypatch):
    # The owner funding is in flight when the run stops: the principal is not signed.
    b = boarding
    crash(monkeypatch, "fund-owner-node-1", "broadcast")
    with pytest.raises(KeyboardInterrupt):
        onboard(b)
    monkeypatch.setattr(elections.ops, "crash_point", lambda i, p: None)
    with pytest.raises(lib.TestnetError, match="open"):
        onboard(b)
    assert b["ops"].journal.record("principal-node-1") is None


def test_a_principal_that_never_left_the_owner_is_failed_not_sent(boarding, monkeypatch):
    b = boarding
    real = elections.owner_transfer

    def drain(*args, **kwargs):
        b["chain"].account(b["owner"])["balance"] = NANO  # spent between the check and the send
        return real(*args, **kwargs)

    monkeypatch.setattr(elections, "owner_transfer", drain)
    with pytest.raises(lib.TestnetError):
        onboard(b)
    # Refused before signing: the owner's balance is checked right before the signature.
    record = b["ops"].journal.record("principal-node-1")
    assert record["state"] == "planned"
    assert not elections.read_pools(b["ceremony"]).get("node-1", {}).get("principal_sent")
    assert not any("enable-elections" in c for c in b["host"].commands)


def test_configuration_steps_resume_one_by_one(boarding, monkeypatch):
    b = boarding
    real = b["host"].tosctl

    def stop_after_pool_add(arguments, timeout=240):
        out = real(arguments, timeout)
        if arguments.startswith("config pool add"):
            raise KeyboardInterrupt("after pool add")
        return out

    monkeypatch.setattr(b["host"], "tosctl", stop_after_pool_add)
    with pytest.raises(KeyboardInterrupt):
        onboard(b)
    monkeypatch.setattr(b["host"], "tosctl", real)
    onboard(b)
    assert b["host"].config["bindings"]["node-1"] == {"wallet": "op-node-1", "pool": "pool-node-1"}
    assert sum(c.startswith("tosctl config pool add") for c in b["host"].commands) == 1


def test_a_pool_configured_otherwise_on_the_host_is_refused(boarding):
    b = boarding
    b["host"].config["pools"]["pool-node-1"] = {
        "address": HOST_WALLET,
        "owner": HOST_WALLET,
    }
    with pytest.raises(lib.TestnetError, match="configured on the host"):
        onboard(b)


# -- withdraw (P2-B and explicit ids)


def boarded(boarding):
    onboard(boarding)
    chain, owner = boarding["chain"], boarding["owner"]
    pool = elections.read_pools(boarding["ceremony"])["node-1"]["pool"]
    chain.behaviour[pool] = pool_behaviour(owner)
    return pool


def pool_behaviour(owner, refuse=False):
    def behave(chain, address, account, message, in_msg):
        value = int(message["value"])
        account["balance"] += value
        body = message.get("_body")
        if body is None or body.bits < 32 or lib.Slice(body).bits(32) != 0x1000:
            chain.record_tx(address, in_msg, [], credit=value)
            return
        roles = account.get("roles_override")
        stored_owner = roles[0] if roles else owner
        if refuse or message["source"] != stored_owner:
            account["balance"] -= value
            chain.record_tx(
                address,
                in_msg,
                [chain.emit(address, message["source"], value, False, None, bounced=True)],
                success=False,
                credit=value,
            )
            return
        s = lib.Slice(body)
        s.bits(96)
        asked = elections.ops.read_coins(s)
        pay = min(asked, account["balance"] - value - NANO) + value - NANO // 200
        account["balance"] -= pay
        chain.record_tx(
            address, in_msg, [chain.emit(address, owner, pay, True, None)], credit=value
        )

    return behave


def withdraw_args(b, **extra):
    args = dict(
        vars(b["args"]),
        id="withdraw-1",
        new=True,
        amount="5",
        all=False,
        dry_run=False,
    )
    args.update(extra)
    return elections.argparse.Namespace(**args)


@pytest.fixture
def withdraw_body_stub(monkeypatch):
    def body(args, amount_tos, work, run=None):
        nanotos = elections.parse_tos(amount_tos, "a")
        path = work / "withdraw.boc"
        path.write_bytes(
            lib.serialize_boc(
                lib.cell_from_bits(
                    format(0x1000, "032b") + format(1, "064b") + fakechain.coins_bits(nanotos)
                )
            )
        )
        return path

    monkeypatch.setattr(elections, "withdraw_body", body)


def elector_idle(chain):
    elector = chain.account(elections.ELECTOR)
    elector["getters"] = {"active_election_id": lambda: {"exit_code": 0, "stack": [num(0)]}}


def test_withdraw_by_explicit_id(boarding, withdraw_body_stub):
    pool = boarded(boarding)
    elector_idle(boarding["chain"])
    result = elections.withdraw(withdraw_args(boarding), boarding["ops"], 2)
    assert result["paid_nanotos"] >= 5 * NANO and result["pool"] == pool
    # The same id again reports its settled outcome and sends nothing.
    sent = list(boarding["chain"].sent)
    elections.withdraw(withdraw_args(boarding, new=False), boarding["ops"], 2)
    assert boarding["chain"].sent == sent
    lines = (boarding["ceremony"] / "withdrawals.jsonl").read_text().splitlines()
    assert len(lines) == 1


@pytest.mark.parametrize(
    "extra,message",
    [
        ({"new": False, "id": "withdraw-9"}, "create a withdrawal with --new"),
        ({"id": "Bad Id"}, "not an operation id"),
    ],
)
def test_withdraw_ids_carry_intent(boarding, withdraw_body_stub, extra, message):
    boarded(boarding)
    elector_idle(boarding["chain"])
    with pytest.raises(lib.TestnetError, match=message):
        elections.withdraw(withdraw_args(boarding, **extra), boarding["ops"], 2)


def test_withdraw_new_on_an_existing_id_and_changed_parameters_are_refused(
    boarding, withdraw_body_stub
):
    boarded(boarding)
    elector_idle(boarding["chain"])
    elections.withdraw(withdraw_args(boarding), boarding["ops"], 2)
    with pytest.raises(lib.TestnetError, match="exists"):
        elections.withdraw(withdraw_args(boarding), boarding["ops"], 2)


def test_withdraw_after_the_validator_was_replaced_still_pays_the_owner(
    boarding, withdraw_body_stub
):
    pool = boarded(boarding)
    chain = boarding["chain"]
    elector_idle(chain)
    data = chain.account(pool)["data"]
    s = lib.Slice(data)
    owner_bits = "".join(str(s.bits(1)) for _ in range(267))
    chain.account(pool)["data"] = lib.cell_from_bits(
        owner_bits + elections.address_bits(HOST_WALLET)
    )
    assert elections.withdraw(withdraw_args(boarding), boarding["ops"], 2)["paid_nanotos"] > 0


@pytest.mark.parametrize("change", ["owner", "code"])
def test_withdraw_refuses_a_pool_with_another_owner_or_code(boarding, withdraw_body_stub, change):
    pool = boarded(boarding)
    chain = boarding["chain"]
    elector_idle(chain)
    if change == "owner":
        data = lib.Slice(chain.account(pool)["data"])
        data.bits(267)
        rest = "".join(str(data.bits(1)) for _ in range(267))
        chain.account(pool)["data"] = lib.cell_from_bits(elections.address_bits(HOST_WALLET) + rest)
    else:
        chain.account(pool)["code"] = lib.cell_from_bits("1")
    sent = list(chain.sent)
    with pytest.raises(lib.TestnetError):
        elections.withdraw(withdraw_args(boarding), boarding["ops"], 2)
    assert chain.sent == sent


def test_withdraw_refuses_while_an_election_is_open(boarding, withdraw_body_stub):
    boarded(boarding)
    elector = boarding["chain"].account(elections.ELECTOR)
    elector["getters"] = {"active_election_id": lambda: {"exit_code": 0, "stack": [num(7)]}}
    with pytest.raises(lib.TestnetError, match="election 7 is open"):
        elections.withdraw(withdraw_args(boarding), boarding["ops"], 2)


# -- change-validator (VAL-03 P1)

PROBE_WALLET = "-1:" + "9c" * 32


def change_pool_behaviour(owner):
    """CHANGE_VALIDATOR_ADDRESS as single-nominator-code.fc: from the stored owner the
    pool replaces its validator; from anyone else it does nothing."""

    def behave(chain, address, account, message, in_msg):
        value = int(message["value"])
        account["balance"] += value
        body = message.get("_body")
        if (
            body is not None
            and body.bits >= 32
            and lib.Slice(body).bits(32) == 0x1001
            and message["source"] == owner
        ):
            s = lib.Slice(body)
            s.bits(96)
            new = elections.ops.read_address(s)
            account["data"] = lib.cell_from_bits(
                elections.address_bits(owner) + elections.address_bits(new)
            )
        chain.record_tx(address, in_msg, [], credit=value)

    return behave


def change_args(b, **extra):
    args = dict(vars(b["args"]), id="p1-to-probe", new=True, to=PROBE_WALLET, dry_run=False)
    args.update(extra)
    return elections.argparse.Namespace(**args)


@pytest.fixture
def change_body_stub(monkeypatch):
    def body(args, validator, work, run=None):
        path = work / "change-validator.boc"
        path.write_bytes(
            lib.serialize_boc(
                lib.cell_from_bits(
                    format(0x1001, "032b") + format(1, "064b") + elections.address_bits(validator)
                )
            )
        )
        return path

    monkeypatch.setattr(elections, "change_validator_body", body)


def changeable(boarding):
    onboard(boarding)
    pool = elections.read_pools(boarding["ceremony"])["node-1"]["pool"]
    boarding["chain"].behaviour[pool] = change_pool_behaviour(boarding["owner"])
    elector_idle(boarding["chain"])
    return pool


def test_change_validator_and_restore(boarding, change_body_stub):
    pool = changeable(boarding)
    chain, owner = boarding["chain"], boarding["owner"]
    operator = elections.pool_roles_both(boarding["ops"], pool)[1]
    result = elections.change_validator(change_args(boarding), boarding["ops"], 2)
    assert (result["previous"], result["validator"]) == (operator, PROBE_WALLET)
    assert elections.pool_roles_both(boarding["ops"], pool) == (owner, PROBE_WALLET)
    # The same id again reports the settled change and sends nothing.
    sent = list(chain.sent)
    elections.change_validator(change_args(boarding, new=False), boarding["ops"], 2)
    assert chain.sent == sent
    back = elections.change_validator(
        change_args(boarding, id="p1-restore", to=operator), boarding["ops"], 2
    )
    assert (back["previous"], back["validator"]) == (PROBE_WALLET, operator)
    assert elections.pool_roles_both(boarding["ops"], pool) == (owner, operator)
    lines = (boarding["ceremony"] / "validator-changes.jsonl").read_text().splitlines()
    assert [json.loads(line)["id"] for line in lines] == ["p1-to-probe", "p1-restore"]


@pytest.mark.parametrize(
    "extra,message",
    [
        ({"to": "0:" + "9c" * 32}, "not a masterchain wallet"),
        ({"to": "not an address"}, "address"),
        ({"new": False, "id": "p1-unknown"}, "create a change with --new"),
        ({"id": "Bad Id"}, "not an operation id"),
    ],
)
def test_change_validator_refuses_bad_requests(boarding, change_body_stub, extra, message):
    changeable(boarding)
    sent = list(boarding["chain"].sent)
    with pytest.raises(lib.TestnetError, match=message):
        elections.change_validator(change_args(boarding, **extra), boarding["ops"], 2)
    assert boarding["chain"].sent == sent


def test_change_validator_refuses_the_pool_its_owner_and_the_current_validator(
    boarding, change_body_stub
):
    pool = changeable(boarding)
    operator = elections.pool_roles_both(boarding["ops"], pool)[1]
    sent = list(boarding["chain"].sent)
    for to in (pool, boarding["owner"]):
        with pytest.raises(lib.TestnetError, match="not a validator wallet"):
            elections.change_validator(change_args(boarding, to=to), boarding["ops"], 2)
    with pytest.raises(lib.TestnetError, match="already holds"):
        elections.change_validator(change_args(boarding, to=operator), boarding["ops"], 2)
    assert boarding["chain"].sent == sent


def test_change_validator_id_keeps_its_target(boarding, change_body_stub):
    changeable(boarding)
    elections.change_validator(change_args(boarding), boarding["ops"], 2)
    with pytest.raises(lib.TestnetError, match="exists"):
        elections.change_validator(change_args(boarding), boarding["ops"], 2)
    with pytest.raises(lib.TestnetError, match="names"):
        elections.change_validator(
            change_args(boarding, new=False, to="-1:" + "9d" * 32), boarding["ops"], 2
        )


def test_change_validator_refuses_while_an_election_is_open(boarding, change_body_stub):
    changeable(boarding)
    elector = boarding["chain"].account(elections.ELECTOR)
    elector["getters"] = {"active_election_id": lambda: {"exit_code": 0, "stack": [num(7)]}}
    sent = list(boarding["chain"].sent)
    with pytest.raises(lib.TestnetError, match="election 7 is open"):
        elections.change_validator(change_args(boarding), boarding["ops"], 2)
    assert boarding["chain"].sent == sent


def test_change_validator_dry_run_signs_nothing(boarding, change_body_stub):
    changeable(boarding)
    sent = list(boarding["chain"].sent)
    assert elections.change_validator(change_args(boarding, dry_run=True), boarding["ops"], 2) == {
        "dry_run": True
    }
    assert boarding["chain"].sent == sent
    assert boarding["ops"].journal.record("p1-to-probe") is None


def test_a_change_settles_only_on_the_new_roles(boarding):
    pool = changeable(boarding)
    owner = boarding["owner"]
    operator = elections.pool_roles_both(boarding["ops"], pool)[1]
    rec = {"destination": pool, "wallet": owner, "validator": PROBE_WALLET}
    state, evidence = elections.validator_changed(boarding["ops"], rec, None, {})
    assert state == "pending" and "does not show" in evidence["reason"]
    rec["validator"] = operator
    assert elections.validator_changed(boarding["ops"], rec, None, {})[0] == "settled"
    rec["wallet"] = PROBE_WALLET
    assert elections.validator_changed(boarding["ops"], rec, None, {})[0] == "failed"


def test_a_principal_resubmit_after_the_pool_roles_changed_is_refused(boarding, monkeypatch):
    b = boarding
    crash(monkeypatch, "principal-node-1", "signed")
    with pytest.raises(KeyboardInterrupt):
        onboard(b)
    monkeypatch.setattr(elections.ops, "crash_point", lambda i, p: None)
    pool = elections.read_pools(b["ceremony"])["node-1"]["pool"]
    data = lib.Slice(b["chain"].account(pool)["data"])
    owner_bits = "".join(str(data.bits(1)) for _ in range(267))
    b["chain"].account(pool)["data"] = lib.cell_from_bits(
        owner_bits + elections.address_bits(HOST_WALLET)
    )
    args = elections.argparse.Namespace(
        **dict(vars(b["args"]), command="resubmit", id="principal-node-1")
    )
    with pytest.raises(lib.TestnetError, match="reports roles"):
        elections.manual(args, b["ops"])
    assert b["ops"].journal.record("principal-node-1")["state"] == "signed"


# -- records, names and the pool address


def test_pool_record_never_changes_its_roles(tmp_path):
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir()
    owner = "-1:" + "0e" * 32
    elections.record_pool(ceremony, "node-1", "-1:" + "50" * 32, owner, OPERATOR)
    assert elections.record_pool(ceremony, "node-1", principal_sent=True)["principal_sent"]
    with pytest.raises(lib.TestnetError, match="owner"):
        elections.record_pool(ceremony, "node-1", owner=OPERATOR)


def test_owner_names_are_checked():
    with pytest.raises(lib.TestnetError, match="not a node name"):
        elections.pool_owner_paths(Path("/c"), "../x")


def test_pool_address_is_the_one_the_pools_init_fif_derives(tmp_path):
    # The pool's own deployment script (single-nominator-pool/init.fif), run by the
    # real fift on the pinned code, is the independent derivation of the address.
    root, fift = real_fift()
    owner = "-1:949ea7cef79e685c0b49735168f7f510f76a16bae7d61d29b980d6ebcb92fabb"
    validator = "-1:38ae2142cf7875f0c43bbc33583ee7876d0c22d6001152646bb390eebfb65d97"
    pool_dir = root / "crypto" / "smartcont" / "single-nominator-pool"
    result = subprocess.run(
        [
            str(fift),
            "-I",
            f"{root / 'crypto' / 'fift' / 'lib'}:{root / 'crypto' / 'smartcont'}",
            "-s",
            str(pool_dir / "init.fif"),
            str(pool_dir / "single-nominator-code.hex"),
            owner,
            validator,
            "pool",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    derived = elections.address_from_file(tmp_path / "pool.addr")
    code = elections.single_nominator_code(root)
    assert elections.pool_address(code, owner, validator) == derived
    # A swapped role order derives another pool.
    assert elections.pool_address(code, validator, owner) != derived


def test_malformed_getter_stacks_are_testnet_errors():
    chain = elections.Chain(
        "u", lambda url, m, **p: {"exit_code": 0, "stack": [["slice", "x"]] * 2}
    )
    with pytest.raises(lib.TestnetError):
        chain.pool_roles("-1:" + "50" * 32)
    three = elections.Chain(
        "u", lambda url, m, **p: {"exit_code": 0, "stack": [["slice", {"bytes": ""}]] * 3}
    )
    with pytest.raises(lib.TestnetError, match="get_roles"):
        three.pool_roles("-1:" + "50" * 32)


# -- the owner key (real fift)


def real_fift():
    root = Path(os.environ.get("TOS_ROOT", Path.home() / "tos"))
    fift = root / "build" / "crypto" / "fift"
    if not os.access(fift, os.X_OK):
        pytest.skip("no fift build under TOS_ROOT")
    return root, fift


def test_real_owner_wallet_key_stays_in_secret_and_the_address_is_stable(tmp_path):
    root, fift = real_fift()
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir()
    args = elections.argparse.Namespace(ceremony=str(ceremony), tos_root=str(root), fift=str(fift))
    first = elections.ensure_pool_owner(args, "node-1", 2, [])
    paths = elections.pool_owner_paths(ceremony, "node-1")
    assert first.startswith("-1:")
    assert stat.S_IMODE(paths["key"].stat().st_mode) == 0o600
    assert stat.S_IMODE(paths["key"].parent.stat().st_mode) == 0o700
    assert paths["init"].read_bytes()[:4] == lib.BOC_MAGIC
    assert json.loads((ceremony / "wallets.json").read_text()) == {"pool-owner-node-1": first}
    # A rerun derives the same address from the kept key, also when the address file is lost.
    assert elections.ensure_pool_owner(args, "node-1", 2, []) == first
    paths["addr"].unlink()
    assert elections.ensure_pool_owner(args, "node-1", 2, []) == first
    with pytest.raises(lib.TestnetError, match="reuses"):
        elections.ensure_pool_owner(args, "node-1", 2, [{"pool-owner-x": first}])


def test_real_owner_without_its_key_is_refused_before_funding(tmp_path):
    root, fift = real_fift()
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir()
    args = elections.argparse.Namespace(ceremony=str(ceremony), tos_root=str(root), fift=str(fift))
    elections.ensure_pool_owner(args, "node-1", 2, [])
    paths = elections.pool_owner_paths(ceremony, "node-1")
    paths["key"].unlink()
    with pytest.raises(lib.TestnetError, match="its key .* does not"):
        elections.ensure_pool_owner(args, "node-1", 2, [])
    # A key that is not the recorded owner's is refused too.
    paths["key"].write_bytes(os.urandom(32))
    with pytest.raises(lib.TestnetError, match="does not belong to the recorded pool owner"):
        elections.ensure_pool_owner(args, "node-1", 2, [])


def test_real_withdraw_body_is_the_pools_withdraw_op(tmp_path):
    root, fift = real_fift()
    args = elections.argparse.Namespace(tos_root=str(root), fift=str(fift))
    body = lib.Slice(lib.parse_boc(elections.withdraw_body(args, "12.5", tmp_path).read_bytes()))
    assert body.bits(32) == 0x1000
    body.bits(64)
    length = body.bits(4)
    assert body.bits(8 * length) == 12_500_000_000


def test_real_change_validator_body_is_the_pools_change_op(tmp_path):
    root, fift = real_fift()
    args = elections.argparse.Namespace(tos_root=str(root), fift=str(fift))
    target = "-1:" + "9c" * 32
    body = lib.Slice(
        lib.parse_boc(elections.change_validator_body(args, target, tmp_path).read_bytes())
    )
    assert body.bits(32) == 0x1001
    body.bits(64)
    assert elections.ops.read_address(body) == target


def read_coins(s):
    length = s.bits(4)
    return s.bits(8 * length)


def test_real_owner_transfer_is_signed_as_asked(tmp_path):
    import time

    root, fift = real_fift()
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir()
    args = elections.argparse.Namespace(ceremony=str(ceremony), tos_root=str(root), fift=str(fift))
    elections.ensure_pool_owner(args, "node-1", 2, [])
    paths = elections.pool_owner_paths(ceremony, "node-1")
    pool = "-1:" + "50" * 32
    before = int(time.time())
    boc = elections.sign_wallet_v3(
        args, 2, paths["key"], paths["addr"].read_bytes(), pool, 0x504F4F4C, 7, "20010.5", True
    )
    after = int(time.time())
    # wallet-v3.fif: ext_in header (7 bits), the wallet's masterchain address (8 + 256),
    # no import fee (4), no init and an inline body (2), the signature (512), then the
    # signed part: global id, subwallet, valid_until, seqno, send mode, the message.
    message = lib.Slice(lib.parse_boc(boc))
    assert message.bits(7) == 0b1000100
    assert message.bits(8) == 0xFF
    assert "-1:" + message.bytes(32).hex() == elections.address_from_file(paths["addr"])
    message.bits(4 + 2 + 512)
    assert message.bits(32) == 2
    assert message.bits(32) == 0x504F4F4C
    valid_until = message.bits(32)
    assert before + 300 <= valid_until <= after + 300
    assert message.bits(32) == 7
    assert message.bits(8) == 3
    internal = lib.Slice(message.take_ref())
    assert internal.bits(2) == 0b01  # int_msg_info, ihr_disabled
    assert internal.bits(1) == 1  # bounce
    assert internal.bits(3) == 0b000  # not bounced, source addr_none
    assert internal.bits(3) == 0b100
    destination_wc = internal.bits(8)
    assert f"{destination_wc - 256}:{internal.bytes(32).hex()}" == pool
    assert read_coins(internal) == 20_010_500_000_000


def test_the_pool_is_checked_again_right_before_the_principal(boarding, monkeypatch):
    b = boarding
    crash(monkeypatch, "principal-node-1", "planned")
    with pytest.raises(KeyboardInterrupt):
        onboard(b)
    monkeypatch.setattr(elections.ops, "crash_point", lambda i, p: None)
    pool = elections.read_pools(b["ceremony"])["node-1"]["pool"]
    data = lib.Slice(b["chain"].account(pool)["data"])
    owner_bits = "".join(str(data.bits(1)) for _ in range(267))
    b["chain"].account(pool)["data"] = lib.cell_from_bits(
        owner_bits + elections.address_bits(HOST_WALLET)
    )
    sent = list(b["chain"].sent)
    with pytest.raises(lib.TestnetError, match="reports roles"):
        onboard(b)
    assert b["chain"].sent == sent


# ---------------------------------------------------------------- fix plan 3


def test_a_settled_withdrawal_id_with_other_parameters_is_refused(boarding, withdraw_body_stub):
    boarded(boarding)
    elector_idle(boarding["chain"])
    elections.withdraw(withdraw_args(boarding), boarding["ops"], 2)
    sent = list(boarding["chain"].sent)
    with pytest.raises(lib.TestnetError, match="other parameters"):
        elections.withdraw(withdraw_args(boarding, new=False, amount="500"), boarding["ops"], 2)
    assert boarding["chain"].sent == sent


def test_a_retried_funding_is_what_the_next_steps_require(boarding, monkeypatch):
    # The owner funding expires unsent and is recorded failed; its retry settles;
    # activation and principal then require the newest attempt, not the failed one.
    b = boarding
    crash(monkeypatch, "fund-owner-node-1", "signed")
    with pytest.raises(KeyboardInterrupt):
        onboard(b)
    monkeypatch.setattr(elections.ops, "crash_point", lambda i, p: None)
    b["chain"].now += 500
    b["ops"].record_failed("fund-owner-node-1", "c")
    b["ops"].retry("fund-owner-node-1", "expired before broadcast")
    onboard(b)
    ids = settled_ids(b)
    assert "fund-owner-node-1.attempt-2" in ids
    assert {"activate-owner-node-1", "deploy-pool-node-1", "principal-node-1"} <= set(ids)
    assert b["ops"].journal.record("fund-owner-node-1")["state"] == "failed"


def test_withdraw_refuses_disagreeing_election_views(boarding, withdraw_body_stub):
    boarded(boarding)
    chain = boarding["chain"]
    elector_idle(chain)
    second = boarding["ops"].nodes[1]
    original = second.rpc

    def rpc(url, method, /, **params):
        if method == "runGetMethod" and params.get("method") == "active_election_id":
            return {"exit_code": 0, "stack": [["num", "0x7"]]}
        return original(url, method, **params)

    second.rpc = rpc
    sent = list(chain.sent)
    with pytest.raises(elections.ops.Unknown, match="disagree"):
        elections.withdraw(withdraw_args(boarding), boarding["ops"], 2)
    assert chain.sent == sent


def test_pool_updates_hold_the_wallet_records_lock(tmp_path, monkeypatch):
    import fcntl

    ceremony = tmp_path / "ceremony"
    ceremony.mkdir()
    original = elections.read_pools
    replace = os.replace
    calls = []

    def assert_locked():
        descriptor = os.open(ceremony / ".wallets.json.lock", os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)

    def read_under_lock(path):
        assert_locked()
        calls.append(path)
        return original(path)

    def replace_under_lock(source, destination):
        assert_locked()
        return replace(source, destination)

    monkeypatch.setattr(elections.os, "replace", replace_under_lock)
    monkeypatch.setattr(elections, "read_pools", read_under_lock)
    elections.record_pool(ceremony, "node-1", owner=OPERATOR)
    elections.record_pool(ceremony, "node-2", owner=HOST_WALLET)
    elections.record_pool(ceremony, "node-1", principal_sent=True)
    assert len(calls) == 3
    pools = original(ceremony)
    assert pools["node-1"] == {"owner": OPERATOR, "principal_sent": True}
    assert pools["node-2"] == {"owner": HOST_WALLET}


@pytest.mark.parametrize("entry", [elections.onboard, elections.withdraw])
def test_ceremony_decisions_do_not_select_one_validator(entry):
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(entry))
    assert not any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "operations"
        and node.attr == "nodes"
        for node in ast.walk(tree)
    ), "ceremony decisions must use the two-validator helper"


def open_withdrawal(boarding, monkeypatch):
    boarded(boarding)
    elector_idle(boarding["chain"])
    crash(monkeypatch, "withdraw-1", "signed")
    with pytest.raises(KeyboardInterrupt):
        elections.withdraw(withdraw_args(boarding), boarding["ops"], 2)
    monkeypatch.setattr(elections.ops, "crash_point", lambda i, p: None)
    return elections.argparse.Namespace(
        **dict(vars(withdraw_args(boarding, new=False)), command="resubmit")
    )


def test_withdrawal_resubmit_refuses_an_open_election(boarding, withdraw_body_stub, monkeypatch):
    args = open_withdrawal(boarding, monkeypatch)
    chain = boarding["chain"]
    chain.account(elections.ELECTOR)["getters"]["active_election_id"] = lambda: {
        "exit_code": 0,
        "stack": [num(7)],
    }
    sent = list(chain.sent)
    with pytest.raises(lib.TestnetError, match="election 7 is open"):
        elections.manual(args, boarding["ops"])
    assert chain.sent == sent
    assert boarding["ops"].journal.record("withdraw-1")["state"] == "signed"


@pytest.mark.parametrize("resubmit", [False, True])
def test_every_withdrawal_send_uses_shared_preflight(
    boarding, withdraw_body_stub, monkeypatch, resubmit
):
    if resubmit:
        args = open_withdrawal(boarding, monkeypatch)
    else:
        boarded(boarding)
        args = withdraw_args(boarding)
    sent = list(boarding["chain"].sent)
    calls = []

    def refuse(operations, tos_root, pool, owner, requested_nanotos):
        calls.append((pool, owner, requested_nanotos))
        raise lib.TestnetError("shared withdrawal preflight refused")

    monkeypatch.setattr(elections, "withdrawal_preflight", refuse)
    with pytest.raises(lib.TestnetError, match="shared withdrawal preflight refused"):
        if resubmit:
            elections.manual(args, boarding["ops"])
        else:
            elections.withdraw(args, boarding["ops"], 2)
    assert len(calls) == 1 and calls[0][2] == 5 * NANO
    assert boarding["chain"].sent == sent


def test_withdraw_all_records_a_variable_payment(boarding, withdraw_body_stub):
    pool = boarded(boarding)
    elector_idle(boarding["chain"])
    result = elections.withdraw(withdraw_args(boarding, all=True, amount=None), boarding["ops"], 2)
    record = boarding["ops"].journal.record("withdraw-1")
    assert record["requested_nanotos"] is None and record["state"] == "settled"
    assert 0 < result["paid_nanotos"] < elections.parse_tos(elections.WITHDRAW_ALL_TOS, "all")
    assert result["pool"] == pool


def test_concurrent_onboards_reuse_one_owner_key_set(boarding, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, Event, Lock

    b = boarding
    boarded(b)
    paths = elections.pool_owner_paths(b["ceremony"], "node-1")
    for path in paths.values():
        path.unlink()
    first_generating, second_entered, second_generating = Event(), Event(), Event()
    counter_lock = Lock()
    calls = []
    ready = Barrier(2)
    entrants = []

    def generate(command, cwd, **kwargs):
        work = Path(cwd)
        with counter_lock:
            calls.append((work / "owner.pk").is_file())
            number = len(calls)
        if number == 1:
            first_generating.set()
            assert second_entered.wait(60)
            # Without serialization the second generator publishes a different key
            # before the first one resumes. With the lock it cannot enter here.
            second_generating.wait(0.2)
        else:
            second_generating.set()
        if not (work / "owner.pk").exists():
            (work / "owner.pk").write_bytes(bytes([number + 1]) * 32)
        own = b["owner"] if (work / "owner.pk").read_bytes() == b"\x02" * 32 else "-1:" + "ef" * 32
        (work / "owner.addr").write_bytes(
            bytes.fromhex(own.split(":")[1]) + (-1).to_bytes(4, "big", signed=True)
        )
        (work / "owner-query.boc").write_bytes(b"init:" + (work / "owner.pk").read_bytes())
        return subprocess.CompletedProcess(command, 0, "", "")

    def ensure(args, name, global_id, previous):
        with counter_lock:
            entrants.append(name)
            number = len(entrants)
        ready.wait(timeout=60)
        if number == 2:
            assert first_generating.wait(60)
            second_entered.set()
        return REAL_ENSURE_POOL_OWNER(args, name, global_id, previous, run=generate)

    class OwnerReady(Exception):
        pass

    def stop_before_owner_funding(args, operations, *a, **kw):
        if args.op_id == "fund-owner-node-1":
            raise OwnerReady
        return operations.journal.record(args.op_id)

    monkeypatch.setattr(
        elections,
        "host_operation",
        lambda operations, host, name, op_id, *a, **kw: operations.journal.record(op_id),
    )
    monkeypatch.setattr(elections, "ensure_pool_owner", ensure)
    monkeypatch.setattr(elections, "fund", stop_before_owner_funding)

    def run():
        with pytest.raises(OwnerReady):
            onboard(b)

    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(run)
        second = workers.submit(run)
        first.result(timeout=90)
        second.result(timeout=90)
    assert calls == [False, True]
    assert paths["key"].read_bytes() == b"\x02" * 32
    assert paths["init"].read_bytes() == b"init:" + paths["key"].read_bytes()
    assert elections.address_from_file(paths["addr"]) == b["owner"]


def test_manual_abandonment_dry_run_and_record(boarding, capsys):
    b = boarding
    b["chain"].now = int(elections.time.time()) + 10
    b["ops"].begin(
        "unsigned-load-refill",
        {
            "kind": "fund",
            "wallet": elections.BOOTSTRAP_WALLET,
            "destination": OPERATOR,
            "value": NANO,
            "body_hash": elections.EMPTY_BODY_HASH,
            "bounce": False,
            "state_init_hash": None,
            "subwallet": 0,
        },
    )
    before = b["ops"].journal.lines("unsigned-load-refill")
    args = elections.argparse.Namespace(
        command="record", id="unsigned-load-refill", abandoned=True, dry_run=True
    )
    elections.manual(args, b["ops"])
    evidence = json.loads(capsys.readouterr().out)
    assert evidence["state"] == "planned" and evidence["dry_run"]
    assert len(evidence["evidence"]["observations"]) == 2
    assert b["ops"].journal.lines(args.id) == before
    args.dry_run = False
    elections.manual(args, b["ops"])
    assert json.loads(capsys.readouterr().out)["state"] == "failed"
    assert b["chain"].sent == []


@pytest.mark.parametrize("dry_run", [True, False])
def test_manual_checkpoint_routes_without_signing(boarding, capsys, monkeypatch, dry_run):
    calls = []

    def checkpoint(op_id, dry_run=False):
        calls.append((op_id, dry_run))
        return {"dry_run": dry_run, "assumption": elections.ops.CUSTODY_ASSUMPTION}

    monkeypatch.setattr(boarding["ops"], "record_checkpoint", checkpoint)
    args = elections.argparse.Namespace(
        command="record", id="terminal", checkpoint=True, dry_run=dry_run
    )
    elections.manual(args, boarding["ops"])
    assert calls == [("terminal", dry_run)]
    assert json.loads(capsys.readouterr().out)["dry_run"] is dry_run
    assert boarding["chain"].sent == []
    assert boarding["ops"].journal.all() == []
