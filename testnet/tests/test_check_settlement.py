import copy
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check-settlement.py"
spec = importlib.util.spec_from_file_location("check_settlement", SCRIPT)
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)
NOW = 2_000_000_000


def fixture():
    policy = dict(
        schema="tos-settlement-policy/1",
        network="a" * 64,
        max_age_seconds=120,
        thresholds=dict(
            payout_blocks=10,
            returned_seconds=60,
            returned_count=2,
            refusals_count=24,
            rereport_clear_blocks=5,
            rereport_clear_seconds=300,
        ),
        assets=[],
    )
    snapshot = dict(
        schema=monitor.SCHEMA,
        network="a" * 64,
        complete=True,
        checkpoint=dict(height=100, hash="b" * 64, utime=NOW),
        source_checkpoint=dict(height=50, hash="c" * 64, utime=NOW),
        bridge_address="bridge-new",
        recognition=[],
        assets=[],
    )
    for symbol in ("USDC", "USDT"):
        name = symbol.lower()
        policy["assets"].append(
            dict(
                id=name,
                symbol=symbol,
                master=name + "-master",
                source_token=name + "-source",
                implementation="v1",
                min_lock_headroom=10,
                occupancy_percent=90,
                actors=[
                    dict(
                        id=name + "-actor",
                        own_wallet=name + "-wallet",
                        tos_floor=1_000_000_000,
                        wallet_tos_floor=100,
                    )
                ],
            )
        )
        snapshot["recognition"].append(
            dict(master=name + "-master", bridge="bridge-new", bridge_config_param=79, status=1)
        )
        snapshot["assets"].append(
            dict(
                id=name,
                master=name + "-master",
                source_token=name + "-source",
                bridge_balance=500,
                wrapped_supply=100,
                lock_cap=dict(
                    total=1000, available=100, hourly=1000, daily=1000, hour_used=100, day_used=100
                ),
                swap_used=10,
                swap_limit=100,
                channels_used=10,
                channels_limit=100,
                balance_from_hash="c" * 64,
                balance_events=[],
                events_complete=True,
                bridge_blacklisted=False,
                paused=False,
                pause_events=0,
                destroy_events=0,
                fee_basis_points=0,
                maximum_fee=0,
                deprecated=False,
                implementation="v1",
                redemptions=[],
                actors=[
                    dict(
                        id=name + "-actor",
                        own_wallet=name + "-wallet",
                        tos_balance=1_000_000_020,
                        wallet_tos_balance=100,
                        accepting_tokens=True,
                        mismatch_events=0,
                        native_ledger=dict(
                            locked_storage_fees=10,
                            locked_outcome_fees=10,
                            returned_count=0,
                            returns_in_flight=0,
                        ),
                        token_ledger=dict(
                            pending=100, refundable=0, returned=0, in_flight=0, revenue=0
                        ),
                        payouts=[],
                        returned=[],
                        refusals=[],
                        refusals_count=0,
                        rereport_funding=1234,
                    )
                ],
            )
        )
    return policy, snapshot


def codes(policy, snapshot, previous=None):
    return monitor.evaluate(policy, snapshot, previous, now=NOW)["alarms"]


def payout(s, height):
    a = s["actors"][0]
    a["payouts"] = [dict(id="1", amount=10, created_height=height)]
    a["token_ledger"]["in_flight"] = 10


def returned(s, *, count=1, age=60, kind=1):
    a = s["actors"][0]
    a["returned"] = [
        dict(id=str(i), amount=10, kind=kind, paying=0, created_utime=NOW - age)
        for i in range(count)
    ]
    a["native_ledger"]["returned_count"] = count
    a["token_ledger"]["returned"] = count * 10


def refusals(s, count):
    a = s["actors"][0]
    a["refusals_count"] = count
    a["refusals"] = [dict(query_id=str(i), amount=10) for i in range(count)]


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize(
    "code,quiet,loud",
    [
        ("payout_age", lambda a: payout(a, 90), lambda a: payout(a, 89)),
        ("returned_count", lambda a: returned(a, count=1), lambda a: returned(a, count=2)),
        ("returned_age", lambda a: returned(a, age=60), lambda a: returned(a, age=61)),
        ("funding_return_refused", lambda a: returned(a, kind=1), lambda a: returned(a, kind=4)),
        (
            "actor_tos_floor",
            lambda a: None,
            lambda a: a["actors"][0].update(tos_balance=1_000_000_019),
        ),
        (
            "wallet_tos_floor",
            lambda a: None,
            lambda a: a["actors"][0].update(wallet_tos_balance=99),
        ),
        (
            "returns_headroom",
            lambda a: a["actors"][0]["native_ledger"].update(returns_in_flight=447),
            lambda a: a["actors"][0]["native_ledger"].update(returns_in_flight=448),
        ),
        (
            "returns_full",
            lambda a: a["actors"][0]["native_ledger"].update(returns_in_flight=511),
            lambda a: a["actors"][0]["native_ledger"].update(returns_in_flight=512),
        ),
        (
            "not_accepting_tokens",
            lambda a: None,
            lambda a: a["actors"][0].update(accepting_tokens=False),
        ),
        ("refusals_headroom", lambda a: refusals(a, 23), lambda a: refusals(a, 24)),
        ("outcome_mismatch", lambda a: None, lambda a: a["actors"][0].update(mismatch_events=1)),
        (
            "liability_cap",
            lambda a: a["actors"][0]["token_ledger"].update(pending=999),
            lambda a: a["actors"][0]["token_ledger"].update(pending=1000),
        ),
        (
            "supply_cap",
            lambda a: a.update(wrapped_supply=999),
            lambda a: a.update(wrapped_supply=1000),
        ),
        (
            "backing_shortfall",
            lambda a: a.update(wrapped_supply=500),
            lambda a: a.update(wrapped_supply=501),
        ),
        (
            "lock_headroom",
            lambda a: a["lock_cap"].update(available=11),
            lambda a: a["lock_cap"].update(available=10),
        ),
        (
            "bridge_over_cap",
            lambda a: a.update(bridge_balance=1000),
            lambda a: a.update(bridge_balance=1001),
        ),
        (
            "hourly_headroom",
            lambda a: a["lock_cap"].update(hour_used=899),
            lambda a: a["lock_cap"].update(hour_used=900),
        ),
        (
            "daily_headroom",
            lambda a: a["lock_cap"].update(day_used=899),
            lambda a: a["lock_cap"].update(day_used=900),
        ),
        ("swap_window", lambda a: a.update(swap_used=89), lambda a: a.update(swap_used=90)),
        (
            "minter_channels",
            lambda a: a.update(channels_used=89),
            lambda a: a.update(channels_used=90),
        ),
        ("bridge_frozen", lambda a: None, lambda a: a.update(bridge_blacklisted=True)),
        ("token_paused", lambda a: None, lambda a: a.update(paused=True)),
        ("token_paused", lambda a: None, lambda a: a.update(pause_events=1)),
        ("destroyed_funds", lambda a: None, lambda a: a.update(destroy_events=1)),
        (
            "redemption_blocked",
            lambda a: a.update(redemptions=[dict(id="r", blacklisted=False)]),
            lambda a: a.update(redemptions=[dict(id="r", blacklisted=True)]),
        ),
    ],
)
def test_each_alarm_crosses_its_boundary_for_each_asset(index, code, quiet, loud):
    p, s = fixture()
    quiet(s["assets"][index])
    assert code not in {r["code"] for r in codes(p, s)}
    loud(s["assets"][index])
    hits = [r for r in codes(p, s) if r["code"] == code]
    assert hits and {r["asset"] for r in hits} == {p["assets"][index]["id"]}


@pytest.mark.parametrize(
    "key,value,code",
    [
        ("fee_basis_points", 1, "transfer_fee"),
        ("maximum_fee", 1, "transfer_fee"),
        ("deprecated", True, "token_upgrade"),
        ("implementation", "v2", "token_upgrade"),
    ],
)
def test_second_asset_risks(key, value, code):
    p, s = fixture()
    assert not codes(p, s)
    s["assets"][1][key] = value
    expected = [("usdt", code)]
    if key == "deprecated":
        expected.insert(0, ("usdt", "token_deprecated"))
    assert [(r["asset"], r["code"]) for r in codes(p, s)] == expected


def test_recognition_limit_and_bridge_migration():
    p, s = fixture()
    s["recognition"] += [
        dict(master=f"m{i}", bridge="bridge-new", bridge_config_param=79, status=1)
        for i in range(14)
    ]
    assert not codes(p, s)
    s["recognition"].append(
        dict(master="m-extra", bridge="bridge-new", bridge_config_param=79, status=1)
    )
    assert {r["code"] for r in codes(p, s)} == {"recognition_size"}
    s["recognition"] = [
        dict(master="usdc-master", bridge="bridge-old", bridge_config_param=79, status=2)
    ]
    assert not codes(p, s)
    s["recognition"][0]["status"] = 1
    assert {r["code"] for r in codes(p, s)} == {"active_old_bridge"}
    s["recognition"][0]["bridge_config_param"] = 81
    assert not codes(p, s)


@pytest.mark.parametrize("delta,code", [(1, "unexplained_increase"), (-1, "unexplained_decrease")])
def test_balance_changes_require_the_exact_event_delta(delta, code):
    p, prior = fixture()
    s = copy.deepcopy(prior)
    s["checkpoint"].update(height=101, hash="d" * 64)
    s["source_checkpoint"].update(height=51, hash="e" * 64)
    s["assets"][0]["balance_events"] = [
        dict(id="lock", kind="Lock", amount=30),
        dict(id="unlock", kind="Unlock", amount=10),
        dict(id="refund", kind="LockRefunded", amount=5),
    ]
    s["assets"][0]["bridge_balance"] += 15
    assert not codes(p, s, prior)
    s["assets"][0]["bridge_balance"] += delta
    assert {r["code"] for r in codes(p, s, prior)} == {code}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(complete=False),
        lambda s: s.update(network="f" * 64),
        lambda s: s.update(assets=[]),
        lambda s: s["assets"][0].update(actors=[]),
        lambda s: s["assets"][0].update(actors=s["assets"][0]["actors"] * 2),
        lambda s: s["assets"][0].update(events_complete=False),
        lambda s: s["assets"][0]["actors"][0].update(refusals_count=1),
        lambda s: s["assets"][0]["actors"][0].update(own_wallet="foreign"),
        lambda s: s["assets"][0]["actors"][0]["token_ledger"].update(in_flight=1),
        lambda s: s["checkpoint"].update(utime=NOW - 121),
        lambda s: s["checkpoint"].update(utime=NOW + 6),
        lambda s: s["assets"][0].update(bridge_balance=True),
    ],
)
def test_incomplete_or_malformed_evidence_is_never_clear(mutate):
    p, s = fixture()
    mutate(s)
    with pytest.raises((monitor.Invalid, KeyError, TypeError)):
        codes(p, s)


def test_no_rollback_or_frozen_checkpoint_can_pass():
    p, s = fixture()
    with pytest.raises(monitor.Invalid, match="advance"):
        codes(p, s, s)
    prior = copy.deepcopy(s)
    prior["checkpoint"]["height"] += 1
    with pytest.raises(monitor.Invalid, match="rollback"):
        codes(p, s, prior)


def test_funded_outbox_is_durable_once_and_mismatches_are_not_cleared(tmp_path, monkeypatch):
    p, s = fixture()
    refusals(s["assets"][0], 32)
    report = monitor.evaluate(p, s, now=NOW)
    assert len(report["rereports"]) == 32
    assert all(
        r["value_nanotos"] == 1234 and r["destination"] == "usdc-wallet"
        for r in report["rereports"]
    )
    path = tmp_path / "outbox.json"
    monitor.reconcile(path, report, p)
    sendable, _ = monitor.reconcile(path, report, p)
    assert len(monitor.read_json(path)) == 32 == len(sendable)
    calls = []

    def sender(argv, **kw):
        payload = json.loads(kw["input"])
        calls.append(payload)
        assert monitor.read_json(path)[payload["operation_id"]]["state"] == "unknown"
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(argv, 60)
        receipt = dict(
            operation_id=payload["operation_id"],
            status="confirmed",
            transaction_hash="f" * 64,
            compute_success=True,
            action_success=True,
            request_sha256=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
        )
        return subprocess.CompletedProcess(argv, 0, json.dumps(receipt), "")

    monkeypatch.setattr(monitor.subprocess, "run", sender)
    unbounded = dict(limit=32, budget=600, timeout=1)
    assert len(monitor.dispatch(path, ["approved-sender"], sendable, **unbounded)["unknown"]) == 1
    monitor.dispatch(path, ["approved-sender"], sendable, **unbounded)
    assert len(calls) == 32  # unknown/submitted entries never sent again
    payout(s["assets"][0], 100)
    s["assets"][0]["actors"][0]["refusals"][1]["amount"] = 11
    r = monitor.evaluate(p, s, now=NOW)
    assert "refusal_mismatch" in {a["code"] for a in r["alarms"]}
    assert 1 not in {x["query_id"] for x in r["rereports"]}


def test_pause_hook_is_asset_scoped():
    p, s = fixture()
    s["assets"][1]["bridge_blacklisted"] = True
    r = monitor.evaluate(p, s, now=NOW)
    assert r["provider_pause_assets"] == ["usdt"]


def test_cli_invalid_evidence_and_duplicate_keys(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text('{"schema": 1, "schema": 2}')
    assert (
        monitor.main(
            [
                "--policy",
                str(policy),
                "--snapshot",
                str(policy),
                "--state-dir",
                str(tmp_path / "state"),
            ]
        )
        == 2
    )
    assert "observation_invalid" in capsys.readouterr().out


def test_cli_baseline_then_clear_and_emergency_stays_latched(tmp_path, monkeypatch, capsys):
    p, s = fixture()
    monkeypatch.setattr(monitor.time, "time", lambda: NOW)
    policy, snapshot = tmp_path / "policy.json", tmp_path / "snapshot.json"
    policy.write_text(json.dumps(p))
    snapshot.write_text(json.dumps(s))
    args = [
        "--policy",
        str(policy),
        "--snapshot",
        str(snapshot),
        "--state-dir",
        str(tmp_path / "state"),
    ]
    assert monitor.main(args) == 2  # baseline requires explicit approval
    assert not (tmp_path / "state/previous.json").exists()
    assert monitor.main(args + ["--initialize-baseline"]) == 2
    capsys.readouterr()
    s["checkpoint"].update(height=101, hash="d" * 64)
    snapshot.write_text(json.dumps(s))
    assert monitor.main(args) == 0
    s["checkpoint"].update(height=102, hash="e" * 64)
    s["assets"][1]["destroy_events"] = 1
    snapshot.write_text(json.dumps(s))
    assert monitor.main(args) == 1
    capsys.readouterr()
    s["checkpoint"].update(height=103, hash="f" * 64)
    s["assets"][1]["destroy_events"] = 0
    snapshot.write_text(json.dumps(s))
    assert monitor.main(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["provider_pause_assets"] == ["usdt"]
    assert report["latched_incidents"] == ["usdt:destroyed_funds"]


def test_outbox_refreshes_only_before_any_possible_send(tmp_path):
    p, s = fixture()
    refusals(s["assets"][0], 1)
    report = monitor.evaluate(p, s, now=NOW)
    path = tmp_path / "outbox.json"
    monitor.reconcile(path, report, p)
    report["rereports"][0]["value_nanotos"] = 2222
    monitor.reconcile(path, report, p)
    box = monitor.read_json(path)
    key = next(iter(box))
    assert box[key]["request"]["value_nanotos"] == 2222
    box[key]["state"] = "unknown"
    monitor.atomic(path, box)
    report["rereports"][0]["value_nanotos"] = 3333
    sendable, _ = monitor.reconcile(path, report, p)
    assert monitor.read_json(path)[key]["request"]["value_nanotos"] == 2222
    assert not sendable  # an unknown entry is never prepared again


def test_returned_claim_in_flight_does_not_double_count_its_liability():
    p, s = fixture()
    asset = s["assets"][0]
    returned(asset)
    payout(asset, 100)
    actor = asset["actors"][0]
    actor["returned"][0]["paying"] = 1
    actor["token_ledger"]["returned"] = 0
    assert not codes(p, s)
    actor["returned"][0]["paying"] = 2
    with pytest.raises(monitor.Invalid, match="payout missing"):
        codes(p, s)


def test_state_size_limit_refuses_before_replacing_the_old_state(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    monitor.atomic(path, {"old": 1})
    monkeypatch.setattr(monitor, "MAX_BYTES", 20)
    with pytest.raises(monitor.Invalid, match="previous file retained"):
        monitor.atomic(path, {"large": "x" * 100})
    assert monitor.read_json(path) == {"old": 1}


@pytest.mark.parametrize("mode", [0o755, 0o770])
def test_cli_refuses_a_non_private_state_directory(tmp_path, mode):
    state = tmp_path / "state"
    state.mkdir(mode=mode)
    state.chmod(mode)
    assert (
        monitor.main(
            [
                "--policy",
                str(tmp_path / "not-read"),
                "--snapshot",
                str(tmp_path / "not-read"),
                "--state-dir",
                str(state),
            ]
        )
        == 2
    )
    assert not (state / "monitor.lock").exists()


@pytest.mark.parametrize("bad", ["wrong_hash", "compute_failed", "action_failed", "malformed"])
def test_a_bad_sender_receipt_is_unknown_and_never_retried(tmp_path, monkeypatch, bad):
    p, s = fixture()
    refusals(s["assets"][0], 1)
    path = tmp_path / "outbox.json"
    sendable, _ = monitor.reconcile(path, monitor.evaluate(p, s, now=NOW), p)
    calls = []

    def sender(argv, **kw):
        payload = json.loads(kw["input"])
        calls.append(payload)
        receipt = dict(
            operation_id=payload["operation_id"],
            status="confirmed",
            transaction_hash="f" * 64,
            compute_success=True,
            action_success=True,
            request_sha256=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
        )
        if bad == "wrong_hash":
            receipt["request_sha256"] = "0" * 64
        if bad == "compute_failed":
            receipt["compute_success"] = False
        if bad == "action_failed":
            receipt["action_success"] = False
        return subprocess.CompletedProcess(
            argv, 0, "not JSON" if bad == "malformed" else json.dumps(receipt), ""
        )

    monkeypatch.setattr(monitor.subprocess, "run", sender)
    assert len(monitor.dispatch(path, ["approved-sender"], sendable)["unknown"]) == 1
    assert not monitor.dispatch(path, ["approved-sender"], sendable)["attempted"]
    assert len(calls) == 1


def confirm(payload):
    return dict(
        operation_id=payload["operation_id"],
        status="confirmed",
        transaction_hash="f" * 64,
        compute_success=True,
        action_success=True,
        request_sha256=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
    )


class Cli:
    """Runs main() on successive observations; every run advances the TOS checkpoint."""

    def __init__(self, tmp_path, monkeypatch, policy):
        self.now = NOW
        self.state = tmp_path / "state"
        self.policy = tmp_path / "policy.json"
        self.snapshot = tmp_path / "snapshot.json"
        self.policy.write_text(json.dumps(policy))
        self.height = 100
        monkeypatch.setattr(monitor.time, "time", lambda: self.now)

    def run(self, s, *extra):
        s["checkpoint"].update(height=self.height, hash=f"{self.height:064x}", utime=self.now)
        s["source_checkpoint"]["utime"] = self.now
        self.height += 1
        self.snapshot.write_text(json.dumps(s))
        args = ["--policy", str(self.policy), "--snapshot", str(self.snapshot)]
        return monitor.main(args + ["--state-dir", str(self.state), *extra])

    def outbox(self):
        return monitor.read_json(self.state / "rereports.json")

    def report(self):
        return monitor.read_json(self.state / "report.json")

    def codes(self):
        return [(r["asset"], r["code"]) for r in self.report()["alarms"]]


SENDER = ["--rereport-adapter", "approved-sender"]


def test_prepared_request_is_revalidated_before_any_send(tmp_path, monkeypatch, capsys):
    p, s = fixture()
    refusals(s["assets"][0], 1)
    cli = Cli(tmp_path, monkeypatch, p)
    assert cli.run(s, "--initialize-baseline") == 2  # observer-only: query 0 prepared
    ((key, entry),) = cli.outbox().items()
    assert entry["state"] == "prepared"
    calls = []

    def sender(argv, **kw):
        calls.append(json.loads(kw["input"]))
        return subprocess.CompletedProcess(argv, 0, json.dumps(confirm(calls[-1])), "")

    monkeypatch.setattr(monitor.subprocess, "run", sender)
    actor = s["assets"][0]["actors"][0]
    actor["payouts"] = [dict(id="0", amount=10, created_height=100)]
    actor["token_ledger"]["in_flight"] = 10
    actor["refusals"][0]["amount"] = 11
    assert cli.run(s, *SENDER) == 1
    assert ("usdc", "refusal_mismatch") in cli.codes()
    assert calls == []  # the prepared request is no longer eligible
    entry = cli.outbox()[key]
    assert entry["state"] == "withdrawn"
    assert entry["withdrawn"]["reason"] == "ineligible"
    assert entry["withdrawn"]["observed_amount"] == 11
    # The payout settled; the record is now a stale refusal and eligible again.
    actor["payouts"] = []
    actor["token_ledger"]["in_flight"] = 0
    assert cli.run(s, *SENDER) == 0
    assert [c["query_id"] for c in calls] == [0]
    assert cli.outbox()[key]["state"] == "submitted"
    assert cli.outbox()[key]["last_withdrawn"]["reason"] == "ineligible"


def test_prepared_request_for_a_record_cleared_elsewhere_is_withdrawn(tmp_path, monkeypatch):
    p, s = fixture()
    refusals(s["assets"][0], 1)
    cli = Cli(tmp_path, monkeypatch, p)
    assert cli.run(s, "--initialize-baseline") == 2
    calls = []
    monkeypatch.setattr(monitor.subprocess, "run", lambda argv, **kw: calls.append(kw))
    refusals(s["assets"][0], 0)
    assert cli.run(s, *SENDER) == 0
    assert calls == []
    ((entry),) = cli.outbox().values()
    assert entry["state"] == "withdrawn"
    assert entry["withdrawn"]["reason"] == "refusal_absent"


def test_dispatch_sends_only_requests_equal_to_the_current_eligible_set(tmp_path, monkeypatch):
    p, s = fixture()
    refusals(s["assets"][0], 2)
    path = tmp_path / "outbox.json"
    sendable, _ = monitor.reconcile(path, monitor.evaluate(p, s, now=NOW), p)
    calls = []
    monkeypatch.setattr(monitor.subprocess, "run", lambda argv, **kw: calls.append(kw))
    assert not monitor.dispatch(path, ["approved-sender"], {})["attempted"]
    changed = copy.deepcopy(sendable)
    for request in changed.values():
        request["value_nanotos"] += 1
    assert not monitor.dispatch(path, ["approved-sender"], changed)["attempted"]
    assert calls == []
    assert {e["state"] for e in monitor.read_json(path).values()} == {"prepared"}


@pytest.mark.parametrize("mode", ["blocks", "seconds"])
def test_submitted_request_is_tracked_until_its_refusal_clears(tmp_path, monkeypatch, mode):
    p, s = fixture()
    refusals(s["assets"][0], 1)  # stale record: no payout, below the refusal threshold
    cli = Cli(tmp_path, monkeypatch, p)
    calls = []

    def sender(argv, **kw):
        calls.append(json.loads(kw["input"]))
        return subprocess.CompletedProcess(argv, 0, json.dumps(confirm(calls[-1])), "")

    monkeypatch.setattr(monitor.subprocess, "run", sender)
    assert cli.run(s, "--initialize-baseline", *SENDER) == 2
    ((key, entry),) = cli.outbox().items()
    assert entry["state"] == "submitted" and len(calls) == 1
    if mode == "blocks":
        for _ in range(5):  # 1..5 blocks since the send: not yet overdue
            assert cli.run(s, *SENDER) == 0
    else:
        cli.now += 300
        assert cli.run(s, *SENDER) == 0
        cli.now += 1  # two blocks, 301 chain seconds: overdue by seconds alone
    assert cli.run(s, *SENDER) == 1
    assert cli.codes() == [("usdc", "rereport_overdue")]
    assert cli.report()["alarms"][0]["facts"]["operation"] == key
    assert len(calls) == 1  # overdue alarms; it never replays the send
    refusals(s["assets"][0], 0)
    assert cli.run(s, *SENDER) == 0
    entry = cli.outbox()[key]
    assert entry["state"] == "cleared" and entry["cleared"]["previous"] == "submitted"
    refusals(s["assets"][0], 1)  # a cleared query id must never return
    assert cli.run(s, *SENDER) == 1
    assert cli.codes() == [("usdc", "refusal_reappeared")]
    assert len(calls) == 1


def test_unknown_submission_needs_a_reconciled_observation(tmp_path, monkeypatch):
    p, s = fixture()
    refusals(s["assets"][0], 1)
    cli = Cli(tmp_path, monkeypatch, p)
    calls = []

    def sender(argv, **kw):
        calls.append(kw)
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    monkeypatch.setattr(monitor.subprocess, "run", sender)
    assert cli.run(s, "--initialize-baseline", *SENDER) == 2
    ((key, entry),) = cli.outbox().items()
    assert entry["state"] == "unknown"
    for _ in range(8):  # past every clearance bound: still unknown, never replayed
        assert cli.run(s, *SENDER) == 1
        assert cli.codes() == [("usdc", "rereport_unknown")]
        assert cli.report()["unknown_rereports"] == [key]
    assert len(calls) == 1
    refusals(s["assets"][0], 0)
    assert cli.run(s, *SENDER) == 0
    entry = cli.outbox()[key]
    assert entry["state"] == "cleared" and entry["cleared"]["previous"] == "unknown"
    assert len(calls) == 1


def test_emergency_is_published_before_any_dispatch_and_dispatch_is_bounded(
    tmp_path, monkeypatch, capsys
):
    p, s = fixture()
    cli = Cli(tmp_path, monkeypatch, p)
    assert cli.run(s, "--initialize-baseline") == 2
    assert cli.run(s) == 0  # the published report is healthy
    seen = []

    def sender(argv, **kw):
        report = monitor.read_json(cli.state / "report.json")
        incidents = monitor.read_json(cli.state / "incidents.json")
        seen.append(
            (
                report["provider_pause_assets"],
                ("usdt", "token_paused") in [(r["asset"], r["code"]) for r in report["alarms"]],
                sorted(incidents),
            )
        )
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    monkeypatch.setattr(monitor.subprocess, "run", sender)
    s["assets"][1]["paused"] = True
    refusals(s["assets"][0], 31)
    assert cli.run(s, *SENDER) == 1
    assert len(seen) == 4  # default count bound per run
    assert all(v == (["usdt"], True, ["usdt:token_paused"]) for v in seen)
    report = cli.report()
    assert len(report["rereport_dispatch"]["deferred"]) == 27
    assert len(report["unknown_rereports"]) == 4
    assert report["provider_pause_assets"] == ["usdt"]


def test_dispatch_stops_at_its_time_budget(tmp_path, monkeypatch):
    p, s = fixture()
    refusals(s["assets"][0], 31)
    path = tmp_path / "outbox.json"
    sendable, _ = monitor.reconcile(path, monitor.evaluate(p, s, now=NOW), p)
    clock = [0]
    timeouts = []

    def sender(argv, **kw):
        timeouts.append(kw["timeout"])
        clock[0] += kw["timeout"]  # every send times out
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    monkeypatch.setattr(monitor, "monotonic", lambda: clock[0])
    monkeypatch.setattr(monitor.subprocess, "run", sender)
    outcome = monitor.dispatch(path, ["approved-sender"], sendable, limit=32, budget=60, timeout=20)
    assert timeouts == [20, 20, 20]
    assert len(outcome["deferred"]) == 28
    states = [e["state"] for e in monitor.read_json(path).values()]
    assert states.count("unknown") == 3 and states.count("prepared") == 28


def test_dispatch_alternates_assets(tmp_path, monkeypatch):
    p, s = fixture()
    refusals(s["assets"][0], 3)
    refusals(s["assets"][1], 1)
    path = tmp_path / "outbox.json"
    sendable, _ = monitor.reconcile(path, monitor.evaluate(p, s, now=NOW), p)
    sent = []

    def sender(argv, **kw):
        sent.append(json.loads(kw["input"])["asset"])
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    monkeypatch.setattr(monitor.subprocess, "run", sender)
    monitor.dispatch(path, ["approved-sender"], sendable, limit=2)
    assert sent == ["usdc", "usdt"]


@pytest.mark.parametrize(
    "flags",
    [
        ["--rereport-max-per-run", "0"],
        ["--rereport-max-per-run", "33"],
        ["--rereport-budget-seconds", "601"],
        ["--rereport-timeout-seconds", "61"],
        ["--rereport-budget-seconds", "10", "--rereport-timeout-seconds", "20"],
        ["--rereport-budget-seconds", "20", "--rereport-timeout-seconds", "20"],
        ["--rereport-budget-seconds", "39"],
    ],
)
def test_cli_refuses_unbounded_dispatch_settings(tmp_path, monkeypatch, flags):
    p, s = fixture()
    cli = Cli(tmp_path, monkeypatch, p)
    assert cli.run(s, "--initialize-baseline", *flags) == 2
    assert not cli.state.exists()


@pytest.mark.parametrize("key", ["rereport_clear_blocks", "rereport_clear_seconds"])
def test_clearance_thresholds_are_required_and_positive(key):
    p, s = fixture()
    p["thresholds"][key] = 0
    with pytest.raises(monitor.Invalid, match="zero threshold"):
        codes(p, s)
    del p["thresholds"][key]
    with pytest.raises(KeyError):
        codes(p, s)


def test_setup_time_never_disables_dispatch(tmp_path, monkeypatch):
    """Review reproduction: budget == timeout with any elapsed time sent nothing."""
    p, s = fixture()
    refusals(s["assets"][0], 3)
    path = tmp_path / "outbox.json"
    sendable, _ = monitor.reconcile(path, monitor.evaluate(p, s, now=NOW), p)
    clock = [0]
    timeouts = []

    def tick():
        clock[0] += 1  # every clock read costs one second of setup or bookkeeping
        return clock[0]

    def sender(argv, **kw):
        timeouts.append(kw["timeout"])
        clock[0] += kw["timeout"]
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    monkeypatch.setattr(monitor, "monotonic", tick)
    monkeypatch.setattr(monitor.subprocess, "run", sender)
    monitor.dispatch(path, ["approved-sender"], sendable, limit=4, budget=20, timeout=20)
    assert timeouts == [19]  # the remaining budget, not zero attempts
    sendable, _ = monitor.reconcile(path, monitor.evaluate(p, s, now=NOW), p)
    timeouts.clear()
    outcome = monitor.dispatch(path, ["approved-sender"], sendable, limit=4, budget=40, timeout=20)
    assert timeouts == [20, 18]  # capped at the send timeout, then the remainder
    assert len(outcome["deferred"]) == 0 and len(outcome["attempted"]) == 2


def test_a_prepared_request_never_waits_silently(tmp_path, monkeypatch):
    p, s = fixture()
    refusals(s["assets"][0], 1)
    cli = Cli(tmp_path, monkeypatch, p)
    clock = [0]

    def starved():
        clock[0] += 100  # setup alone exhausts every dispatch budget
        return clock[0]

    calls = []
    monkeypatch.setattr(monitor, "monotonic", starved)
    monkeypatch.setattr(monitor.subprocess, "run", lambda argv, **kw: calls.append(kw))
    assert cli.run(s, "--initialize-baseline", *SENDER) == 2
    for _ in range(5):  # 1..5 blocks prepared: within the bound
        assert cli.run(s, *SENDER) == 0
        assert len(cli.report()["rereport_dispatch"]["deferred"]) == 1
    assert cli.run(s, *SENDER) == 1
    assert cli.codes() == [("usdc", "rereport_deferred")]
    assert cli.report()["alarms"][0]["facts"]["blocks"] == 6
    assert calls == []


def test_history_never_takes_an_assets_turn(tmp_path, monkeypatch):
    """Review reproduction: ten cleared USDC entries ahead of the one sendable USDC."""
    p, s = fixture()
    refusals(s["assets"][0], 11)
    refusals(s["assets"][1], 4)
    path = tmp_path / "outbox.json"
    monitor.reconcile(path, monitor.evaluate(p, s, now=NOW), p)
    box = monitor.read_json(path)
    usdc = sorted(k for k, e in box.items() if e["request"]["asset"] == "usdc")
    for key in usdc[:10]:  # history ranked ahead of the last (largest) key
        box[key]["state"] = "cleared"
    monitor.atomic(path, box)
    sendable = {k: e["request"] for k, e in box.items() if e["state"] == "prepared"}
    sent = []

    def sender(argv, **kw):
        sent.append(json.loads(kw["input"])["asset"])
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    monkeypatch.setattr(monitor.subprocess, "run", sender)
    monitor.dispatch(path, ["approved-sender"], sendable)
    assert sent == ["usdc", "usdt", "usdt", "usdt"]


def test_turns_carry_across_truncated_batches(tmp_path, monkeypatch):
    p, s = fixture()
    refusals(s["assets"][0], 2)
    refusals(s["assets"][1], 2)
    path = tmp_path / "outbox.json"
    report = monitor.evaluate(p, s, now=NOW)
    sent = []

    def sender(argv, **kw):
        sent.append(json.loads(kw["input"])["asset"])
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    monkeypatch.setattr(monitor.subprocess, "run", sender)
    for _ in range(4):
        sendable, _ = monitor.reconcile(path, report, p)
        monitor.dispatch(path, ["approved-sender"], sendable, limit=1)
    assert sent == ["usdc", "usdt", "usdc", "usdt"]


@pytest.mark.parametrize("content", ["[]", '{"last_asset": 7}', '{"last_asset": "usdc"'])
def test_a_malformed_dispatch_cursor_refuses_dispatch(tmp_path, monkeypatch, capsys, content):
    p, s = fixture()
    refusals(s["assets"][0], 1)
    cli = Cli(tmp_path, monkeypatch, p)
    assert cli.run(s, "--initialize-baseline") == 2  # observer-only: query 0 prepared
    capsys.readouterr()
    (cli.state / "dispatch-cursor.json").write_text(content)
    calls = []
    monkeypatch.setattr(monitor.subprocess, "run", lambda argv, **kw: calls.append(kw))
    assert cli.run(s, *SENDER) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "INCOMPLETE"
    assert out["alarms"] == [dict(code="observation_invalid")]
    assert calls == []
    assert {e["state"] for e in cli.outbox().values()} == {"prepared"}


def test_deprecated_legacy_asset_is_an_asset_local_emergency():
    policy, snapshot = fixture()
    snapshot["assets"][1]["deprecated"] = True
    report = monitor.evaluate(policy, snapshot, None, NOW)
    assert report["provider_pause_assets"] == ["usdt"], "deprecated asset not paused locally"
    assert any(a["code"] == "token_deprecated" for a in report["alarms"])
