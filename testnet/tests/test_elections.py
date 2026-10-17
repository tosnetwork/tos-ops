"""Tests for testnet-elections.py.

operations-plan-epoch1.txt is real `tosctl controller operations plan` output
from epoch 1 (tos 442884a33), so the plan parser is pinned to what the tool
prints. The pool deploy result follows tosctl's DeployPoolResult, which it
prints with serde_json::to_string_pretty after its progress lines.
"""

import base64
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path

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
    # The principal reaches the pool from its offline owner, never through the
    # operator wallet on the host, which gets fee and operating money only.
    assert e["operator_funding_tos"] < e["stake_tos"]
    assert e["operator_funding_tos"] >= e["controller_deploy_tos"] + e["pool_deploy_tos"] + 50
    per_validator = e["operator_funding_tos"] + e["pool_tos"] + e["pool_owner_reserve_tos"]
    assert 4 * per_validator <= 100000


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
    ):
        bad = elections.argparse.Namespace(**vars(good))
        setattr(bad, field, value)
        with pytest.raises(lib.TestnetError):
            elections.check_load_args(bad)


# ---------------------------------------------------------------- refund

OPERATOR = "-1:294974d03f4c811d5b550812f633d188d7c035923151e267fe208ec52b2fd4d6"
PLAN_VALUE = 23_558_960_000
NANO = 10**9
# ConfigParam 34 as a loopback network's JSON-RPC getConfigParam returned it (tos
# test/pq-native/x02-config34-fixtures, sha256 8209f080...bf1b); the tos decoder
# reads utime_since 1790358449 and utime_until 1790359049 from it.
CONFIG34 = (DATA / "config34-since-1790358449.boc").read_bytes()
SINCE = 1_790_000_000
UNTIL = SINCE + 14_400  # the profile's elected_for


def status_text(stakes, nonce, epoch=0, warnings=()):
    """`tosctl controller operations status` in print_status's layout (with the colour
    codes it may print)."""
    lines = [
        "",
        "\x1b[1mController operating authorization\x1b[0m",
        "─" * 72,
        f"  {'Controller:':<24} -1:{CONTROLLER}",
        f"  {'Funds:':<24} 20.000000000 TOS",
        f"  {'Root authority:':<24} epoch {epoch} nonce {nonce}",
        f"  {'Relay pending:':<24} false",
        f"  {'Stakes remaining:':<24} {stakes}",
        f"  {'Runway:':<24} 3.0 days",
        "",
    ]
    lines += [f"  \x1b[1;31m[BLOCKING]\x1b[0m {w}" for w in warnings] or ["  OK no warnings"]
    return "\n".join(lines) + "\n"


class FakeHost:
    """The validator host: answers status and plan, records every command in order."""

    def __init__(self, statuses, send_error=None, start_error=None):
        self.statuses = list(statuses)
        self.send_error = send_error
        self.start_error = start_error
        self.calls = []

    def run(self, command, timeout=300):
        self.calls.append(("run", command))
        if command.startswith("systemctl start") and self.start_error:
            raise lib.TestnetError(self.start_error)
        return ""

    def tosctl(self, arguments, timeout=240):
        self.calls.append(("tosctl", arguments))
        if arguments.startswith("controller operations status"):
            return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        if arguments.startswith("controller operations plan"):
            return PLAN
        if arguments.startswith("wallet send"):
            if self.send_error:
                raise lib.TestnetError(self.send_error)
            return "sent\n"
        raise AssertionError(f"unexpected tosctl {arguments}")

    def commands(self):
        return [c[1].split(" --")[0] for c in self.calls]


class FakeChain:
    def __init__(self, balances, active=0, term=(SINCE, UNTIL)):
        self.balances = list(balances)
        self.active = active
        self.term = term

    def validator_term(self):
        return self.term

    def active_election(self):
        return self.active

    def account(self, address):
        assert address == OPERATOR
        balance = self.balances.pop(0) if len(self.balances) > 1 else self.balances[0]
        return "active", balance


def refund_setup(tmp_path, **extra):
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir(parents=True)
    (ceremony / "genesis-records.json").write_text(json.dumps([{"controller_id": CONTROLLER}]))
    (ceremony / "wallets.json").write_text(json.dumps({"op-node-1": OPERATOR}))
    controller = tmp_path / "node-1.json"
    controller.write_text(json.dumps({"controller_id": CONTROLLER}))
    args = dict(
        name="node-1",
        host="h",
        ssh_key="k",
        ceremony=str(ceremony),
        controller=str(controller),
        root_seed="root.seed",
        controller_tool="tos-pq-controller",
        target_nanotos=None,
        dry_run=False,
        i_checked_the_window=False,
    )
    args.update(extra)
    return elections.argparse.Namespace(**args)


class Signer:
    def __init__(self):
        self.calls = []

    def __call__(self, tool, seed, gid, controller, plan):
        self.calls.append((gid, controller, plan["nonce"], plan["value_nanotos"]))
        return "te6signedbody"


def run_refund(args, host, chain, signer=None, now=SINCE + 3600):
    return elections.refund(
        args,
        chain,
        2,
        lib.load_profile(),
        host=host,
        now=lambda: now,
        sleep=lambda s: None,
        sign=signer or Signer(),
    )


def test_refund_sends_with_the_service_stopped_and_records_it(tmp_path):
    args = refund_setup(tmp_path, target_nanotos=260 * NANO)
    host = FakeHost([status_text(2, 0), status_text(12, 1)])
    signer = Signer()
    record = run_refund(args, host, FakeChain([100 * NANO, 76 * NANO]), signer)
    assert host.commands() == [
        "controller operations status",
        "controller operations plan",
        "systemctl stop tos-testnet-elections",
        "wallet send",
        "systemctl start tos-testnet-elections",
        "controller operations status",
    ]
    plan_call = host.calls[1][1]
    assert f"--payer {OPERATOR}" in plan_call and "--funds-target-nanotos 260000000000" in plan_call
    send = host.calls[3][1]
    assert f"--amount-nanotos {PLAN_VALUE}" in send and "--body-boc te6signedbody" in send
    assert "--from op-node-1" in send and f"--to -1:{CONTROLLER}" in send
    assert signer.calls == [(2, CONTROLLER, "0", PLAN_VALUE)]
    assert record["verified"] and record["problems"] == []
    assert record["stakes_remaining_after"] == 12 and record["authority_after"] == [0, 1]
    [line] = (tmp_path / "ceremony" / "refunds.jsonl").read_text().splitlines()
    assert json.loads(line)["value_nanotos"] == PLAN_VALUE


def test_refund_defaults_to_the_ten_day_target_not_the_onboarding_one(tmp_path):
    authorization = lib.load_profile()["elections"]["authorization"]
    assert authorization["refund_target_nanotos"] == 260 * NANO
    assert authorization["refund_target_nanotos"] > authorization["funds_target_nanotos"]
    host = FakeHost([status_text(2, 0), status_text(12, 1)])
    run_refund(refund_setup(tmp_path), host, FakeChain([100 * NANO, 76 * NANO]))
    plan_call = host.calls[1][1]
    assert "--funds-target-nanotos 260000000000" in plan_call


def test_refund_starts_the_service_again_when_the_send_fails(tmp_path):
    host = FakeHost([status_text(2, 0)], send_error="vault locked")
    with pytest.raises(lib.TestnetError, match="vault locked"):
        run_refund(refund_setup(tmp_path), host, FakeChain([100 * NANO]))
    assert host.commands()[-3:] == [
        "systemctl stop tos-testnet-elections",
        "wallet send",
        "systemctl start tos-testnet-elections",
    ]
    assert not (tmp_path / "ceremony" / "refunds.jsonl").exists()


def test_refund_says_so_when_the_service_does_not_start_again(tmp_path):
    host = FakeHost([status_text(2, 0)], send_error="timeout", start_error="unit failed")
    with pytest.raises(lib.TestnetError, match="did not start again.*by hand"):
        run_refund(refund_setup(tmp_path), host, FakeChain([100 * NANO]))


def test_refund_that_would_drain_the_operator_wallet_is_refused(tmp_path):
    # 23.56 TOS value + 1 TOS fee allowance + 30 TOS reserve = 54.56 TOS; half a TOS short.
    balance = PLAN_VALUE + NANO + 30 * NANO - NANO // 2
    host = FakeHost([status_text(2, 0)])
    signer = Signer()
    with pytest.raises(lib.TestnetError) as refused:
        run_refund(refund_setup(tmp_path), host, FakeChain([balance]), signer)
    message = str(refused.value)
    assert "short by 0.500000000 TOS" in message
    assert f"fund --to {OPERATOR} --amount 1 " in message
    assert signer.calls == []
    assert not any(c.startswith(("systemctl", "wallet send")) for c in host.commands())
    # control: the same wallet with that half TOS more goes through
    host = FakeHost([status_text(2, 0), status_text(12, 1)])
    assert run_refund(refund_setup(tmp_path / "ok"), host, FakeChain([balance + NANO // 2]))


def test_reserve_formula():
    reserve = 30 * NANO
    assert elections.reserve_shortfall(100 * NANO, 20 * NANO, reserve) == 0
    assert elections.reserve_shortfall(51 * NANO, 20 * NANO, reserve) == 0
    assert elections.reserve_shortfall(51 * NANO - 1, 20 * NANO, reserve) == 1
    with pytest.raises(lib.TestnetError):
        elections.reserve_shortfall(-1, 1, reserve)


def test_operator_reserve_comes_from_the_profile_and_covers_a_stake():
    authorization = lib.load_profile()["elections"]["authorization"]
    assert elections.operator_reserve(authorization) == authorization["operator_reserve_nanotos"]
    assert authorization["operator_reserve_nanotos"] >= elections.STAKE_WALLET_MINIMUM_NANOTOS
    assert elections.STAKE_WALLET_MINIMUM_NANOTOS == 20_200_000_000
    assert elections.operator_reserve({}) == elections.DEFAULT_OPERATOR_RESERVE_NANOTOS
    for bad in (20 * NANO, "30000000000", True):
        with pytest.raises(lib.TestnetError):
            elections.operator_reserve({"operator_reserve_nanotos": bad})


def test_refund_dry_run_signs_and_sends_nothing(tmp_path):
    host = FakeHost([status_text(2, 0)])
    signer = Signer()
    # a dry run inside an election only reports the window
    record = run_refund(
        refund_setup(tmp_path, dry_run=True), host, FakeChain([100 * NANO], active=7), signer
    )
    assert host.commands() == ["controller operations status", "controller operations plan"]
    assert len(signer.calls) == 1
    assert record["value_nanotos"] == PLAN_VALUE and "election 7" in record["window"]
    assert not (tmp_path / "ceremony" / "refunds.jsonl").exists()


@pytest.mark.parametrize("target", [0, -1])
def test_refund_refuses_a_target_that_is_not_positive(tmp_path, target):
    host = FakeHost([status_text(2, 0)])
    with pytest.raises(lib.TestnetError, match="must be positive"):
        run_refund(refund_setup(tmp_path, target_nanotos=target), host, FakeChain([100 * NANO]))
    assert host.calls == []


def test_refund_reports_a_refund_the_status_does_not_show(tmp_path):
    host = FakeHost([status_text(2, 0), status_text(2, 1)])
    with pytest.raises(lib.TestnetError, match="stakes remaining did not increase"):
        run_refund(refund_setup(tmp_path), host, FakeChain([100 * NANO, 76 * NANO]))
    [line] = (tmp_path / "ceremony" / "refunds.jsonl").read_text().splitlines()
    record = json.loads(line)
    assert record["verified"] is False
    assert record["problems"] == ["stakes remaining did not increase"]


def test_refund_reports_a_nonce_that_did_not_move_and_a_blocking_warning(tmp_path):
    host = FakeHost([status_text(2, 0), status_text(12, 0, warnings=["funds below floor"])])
    with pytest.raises(lib.TestnetError, match="nonce did not advance.*BLOCKING"):
        run_refund(refund_setup(tmp_path), host, FakeChain([100 * NANO, 76 * NANO]))


def test_refund_waits_for_the_quiet_part_of_a_term(tmp_path):
    for chain, now, reason in (
        (FakeChain([100 * NANO], active=1790372800), SINCE + 3600, "election 1790372800"),
        (FakeChain([100 * NANO]), SINCE + 599, "took office 599 s ago"),
        (FakeChain([100 * NANO]), UNTIL - 7200 - 600, "next election opens"),
        (FakeChain([100 * NANO]), UNTIL + 50, "next election opens"),  # a failed election
    ):
        host = FakeHost([status_text(2, 0)])
        with pytest.raises(lib.TestnetError, match=reason):
            run_refund(refund_setup(tmp_path / str(now)), host, chain, now=now)
        assert host.calls == []
    # control: the first and the last quiet second, and an override, all go through
    for now in (SINCE + 600, UNTIL - 7801):
        host = FakeHost([status_text(2, 0), status_text(12, 1)])
        assert run_refund(
            refund_setup(tmp_path / f"quiet-{now}"), host, FakeChain([100 * NANO]), now=now
        )
    host = FakeHost([status_text(2, 0), status_text(12, 1)])
    args = refund_setup(tmp_path / "override", i_checked_the_window=True)
    assert run_refund(args, host, FakeChain([100 * NANO], active=5))


def test_refund_needs_an_onboarded_operator(tmp_path):
    args = refund_setup(tmp_path)
    (tmp_path / "ceremony" / "wallets.json").write_text(json.dumps({"op-node-2": OPERATOR}))
    with pytest.raises(lib.TestnetError, match="records no op-node-1"):
        run_refund(args, FakeHost([status_text(2, 0)]), FakeChain([100 * NANO]))


def test_validator_set_term_from_a_real_config_cell():
    assert elections.validator_set_term(CONFIG34) == (1790358449, 1790359049)
    bad_tag = bytearray(CONFIG34)
    bad_tag[CONFIG34.index(bytes.fromhex("126ab6b3b1"))] = 0x13
    with pytest.raises(lib.TestnetError, match="not a validator set"):
        elections.validator_set_term(bytes(bad_tag))
    with pytest.raises(lib.TestnetError):
        elections.validator_set_term(CONFIG34[:12])
    with pytest.raises(lib.TestnetError, match="bag of cells"):
        elections.validator_set_term(b"\x00" + CONFIG34[1:])


def test_chain_reads_the_term_and_the_open_election():
    def rpc(url, method, /, **params):
        if method == "getConfigParam":
            assert params == {"param": 34}
            return {"config": {"bytes": base64.b64encode(CONFIG34).decode()}}
        assert params["address"] == elections.ELECTOR and params["method"] == "active_election_id"
        return {"exit_code": 0, "stack": [["num", "0x6ab6d8f1"]]}

    chain = elections.Chain("http://fake", rpc)
    assert chain.validator_term() == (1790358449, 1790359049)
    assert chain.active_election() == 0x6AB6D8F1


def test_operations_status_is_parsed_through_colour_codes():
    status = elections.parse_operations_status(status_text(7, 3, epoch=1, warnings=["x"]))
    assert status == {
        "stakes_remaining": 7,
        "epoch": 1,
        "nonce": 3,
        "blocking": True,
        "unset": False,
    }
    with pytest.raises(lib.TestnetError, match="Stakes remaining"):
        elections.parse_operations_status("Controller operating authorization\n")


def test_refund_needs_an_operating_authorization_to_renew(tmp_path):
    unset = status_text(0, 0).replace(
        "  Funds:", f"  {'Authorization:':<24} \x1b[1;31mnone recorded\x1b[0m\n  Funds:"
    )
    assert elections.parse_operations_status(unset)["unset"]
    host = FakeHost([unset])
    with pytest.raises(lib.TestnetError, match="no operating authorization"):
        run_refund(refund_setup(tmp_path), host, FakeChain([100 * NANO]))
    assert host.commands() == ["controller operations status"]


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
    remote = tmp_path / "state" / "controller-x-deploy-tx.boc"
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

    command = re.compile(r"(?<![\w-])tosctl (?:key|config|wallet|deploy|controller|service)\b")
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

POOL = "-1:" + "50" * 32
OWNER = "-1:" + "0e" * 32


def owner_ceremony(tmp_path, owner=OWNER):
    ceremony = tmp_path / "ceremony"
    paths = elections.pool_owner_paths(ceremony, "node-1")
    paths["key"].parent.mkdir(parents=True, mode=0o700)
    paths["key"].write_bytes(b"\x01" * 32)
    paths["addr"].parent.mkdir()
    workchain, account = owner.split(":")
    paths["addr"].write_bytes(
        bytes.fromhex(account) + int(workchain).to_bytes(4, "big", signed=True)
    )
    elections.record_pool(ceremony, "node-1", POOL, owner, OPERATOR, "-1:" + CONTROLLER)
    return ceremony


class OwnerChain:
    """The chain as the withdrawal sees it: the pool and owner balances, the owner's seqno."""

    def __init__(self, pool_balance, owner_balance, active=0, pays=None):
        self.balances = {POOL: pool_balance, OWNER: owner_balance}
        self.active, self.pays, self.sent, self.seq = active, pays, [], 7

    def active_election(self):
        return self.active

    def account(self, address):
        return "active", self.balances[address]

    def seqno(self, address):
        assert address == OWNER
        return self.seq

    def send_boc(self, boc):
        self.sent.append(boc)
        self.seq += 1
        if self.pays:
            self.balances[POOL] -= self.pays
            self.balances[OWNER] += self.pays


def withdraw_args(ceremony, **extra):
    args = dict(
        name="node-1",
        ceremony=str(ceremony),
        tos_root="/tos",
        fift="fift",
        rpc="http://fake",
        amount=None,
        all=False,
        during_election=False,
        dry_run=False,
    )
    args.update(extra)
    return elections.argparse.Namespace(**args)


@pytest.fixture
def signer(monkeypatch):
    """Stand-ins for the two fift steps, recording what they were asked to sign."""
    calls = {"sign": [], "body": []}

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
        calls["sign"].append(
            dict(
                key=key,
                to=to,
                subwallet=subwallet,
                seqno=seqno,
                amount=amount,
                bounce=bounce,
                body=body and body.read_bytes(),
            )
        )
        return b"signed-by-owner"

    def body(args, amount_tos, work, run=None):
        calls["body"].append(amount_tos)
        path = work / "withdraw.boc"
        path.write_bytes(b"withdraw " + amount_tos.encode())
        return path

    monkeypatch.setattr(elections, "sign_wallet_v3", sign)
    monkeypatch.setattr(elections, "withdraw_body", body)
    monkeypatch.setattr(elections.time, "sleep", lambda s: None)
    return calls


def test_withdraw_is_signed_by_the_offline_owner_and_recorded(tmp_path, signer):
    ceremony = owner_ceremony(tmp_path)
    chain = OwnerChain(20_000 * NANO, 5 * NANO, pays=10_000 * NANO)
    result = elections.withdraw(withdraw_args(ceremony, amount="10000"), chain, 2)
    [sign] = signer["sign"]
    assert sign["key"] == ceremony / "secret" / "pool-owner-node-1.pk"
    assert (sign["to"], sign["subwallet"], sign["seqno"]) == (POOL, 0x504F4F4C, 7)
    assert sign["bounce"] is True and sign["amount"] == "1.000000000"
    assert sign["body"] == b"withdraw 10000.000000000"
    assert chain.sent == [b"signed-by-owner"]
    assert result["owner_balance_after_nanotos"] == 10_005 * NANO
    logged = json.loads((ceremony / "withdrawals.jsonl").read_text())
    assert logged["requested_nanotos"] == 10_000 * NANO and logged["pool"] == POOL
    assert len(list((ceremony / "sent").glob("*-owner-node-1-seq7-withdraw-*.boc"))) == 1


def test_withdraw_all_asks_for_more_than_the_pool_holds(tmp_path, signer):
    ceremony = owner_ceremony(tmp_path)
    chain = OwnerChain(20_000 * NANO, 5 * NANO, pays=19_998 * NANO)
    elections.withdraw(withdraw_args(ceremony, all=True), chain, 2)
    assert signer["body"] == [elections.WITHDRAW_ALL_TOS]


def test_withdraw_dry_run_signs_and_keeps_but_sends_nothing(tmp_path, signer):
    ceremony = owner_ceremony(tmp_path)
    chain = OwnerChain(20_000 * NANO, 5 * NANO)
    result = elections.withdraw(withdraw_args(ceremony, amount="1", dry_run=True), chain, 2)
    assert result["dry_run"] is True and chain.sent == []
    assert len(list((ceremony / "sent").glob("*.boc"))) == 1
    assert not (ceremony / "withdrawals.jsonl").exists()


@pytest.mark.parametrize(
    "chain_args,extra,message",
    [
        ((20_000 * NANO, 5 * NANO, 1792209863), {"amount": "1"}, "election 1792209863 is open"),
        ((20_000 * NANO, 5 * NANO), {"amount": "19999.5"}, "withdrawable"),
        ((NANO, 5 * NANO), {"all": True}, "holds only"),
    ],
)
def test_withdraw_refusals(tmp_path, signer, chain_args, extra, message):
    ceremony = owner_ceremony(tmp_path)
    chain = OwnerChain(*chain_args)
    with pytest.raises(lib.TestnetError, match=message):
        elections.withdraw(withdraw_args(ceremony, **extra), chain, 2)
    assert chain.sent == [] and signer["sign"] == []


def test_withdraw_refuses_a_pool_recorded_with_another_owner(tmp_path, signer):
    ceremony = owner_ceremony(tmp_path)
    paths = elections.pool_owner_paths(ceremony, "node-1")
    paths["addr"].write_bytes(bytes.fromhex("aa" * 32) + (-1).to_bytes(4, "big", signed=True))
    with pytest.raises(lib.TestnetError, match="recorded owner"):
        elections.withdraw(withdraw_args(ceremony, amount="1"), OwnerChain(20_000 * NANO, 0), 2)


def test_withdraw_reports_a_withdrawal_that_never_arrives(tmp_path, signer):
    ceremony = owner_ceremony(tmp_path)
    with pytest.raises(lib.TestnetError, match="did not reach the owner"):
        elections.withdraw(withdraw_args(ceremony, amount="1"), OwnerChain(20_000 * NANO, 0), 2)


def test_pool_record_never_changes_its_roles(tmp_path):
    ceremony = owner_ceremony(tmp_path)
    assert elections.record_pool(ceremony, "node-1", principal_sent=True)["principal_sent"]
    with pytest.raises(lib.TestnetError, match="owner"):
        elections.record_pool(ceremony, "node-1", owner=OPERATOR)
    assert elections.read_pools(ceremony)["node-1"]["owner"] == OWNER


def test_owner_names_are_checked():
    with pytest.raises(lib.TestnetError, match="not a node name"):
        elections.pool_owner_paths(Path("/c"), "../x")


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
    # A rerun (the address file lost) derives the same wallet from the kept key.
    paths["addr"].unlink()
    assert elections.ensure_pool_owner(args, "node-1", 2, []) == first
    with pytest.raises(lib.TestnetError, match="reuses"):
        elections.ensure_pool_owner(args, "node-1", 2, [{"pool-owner-x": first}])


def test_real_withdraw_body_is_the_pools_withdraw_op(tmp_path):
    root, fift = real_fift()
    args = elections.argparse.Namespace(tos_root=str(root), fift=str(fift))
    body = lib.Slice(lib.parse_boc(elections.withdraw_body(args, "12.5", tmp_path).read_bytes()))
    assert body.bits(32) == 0x1000
    body.bits(64)
    length = body.bits(4)
    assert body.bits(8 * length) == 12_500_000_000


def test_real_owner_transfer_is_signed_for_this_global_id(tmp_path):
    root, fift = real_fift()
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir()
    args = elections.argparse.Namespace(ceremony=str(ceremony), tos_root=str(root), fift=str(fift))
    elections.ensure_pool_owner(args, "node-1", 2, [])
    paths = elections.pool_owner_paths(ceremony, "node-1")
    boc = elections.sign_wallet_v3(
        args, 2, paths["key"], paths["addr"].read_bytes(), POOL, 0x504F4F4C, 0, "1", True
    )
    # wallet-v3.fif: ext_in header (7 bits), the wallet's masterchain address (8 + 256),
    # no import fee (4), no init and an inline body (2), the signature (512), then
    # the signed part, which starts with the global id and the subwallet id.
    message = lib.Slice(lib.parse_boc(boc))
    assert message.bits(7) == 0b1000100
    assert message.bits(8) == 0xFF
    assert "-1:" + message.bytes(32).hex() == elections.address_from_file(paths["addr"])
    message.bits(4 + 2 + 512)
    assert message.bits(32) == 2
    assert message.bits(32) == 0x504F4F4C
