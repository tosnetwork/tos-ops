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
