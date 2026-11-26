"""Qualification evidence must reject proxy verification, duplicate IDs and excess funding."""

import base64
import importlib.util
import json
import time
from types import SimpleNamespace

import pytest
import testnet_lib as lib
from load_qualification import Qualification, check_genesis
from testnet_support import SCRIPTS


def audit(tmp_path, **kw):
    return Qualification(
        tmp_path / "state", kw.get("funding_cap", 20), 10, max_pending=kw.get("max_pending", 8)
    )


def carrier(tmp_path, name="ext-0.boc"):
    p = tmp_path / name
    p.write_bytes(b"test-only-unsent-carrier")
    return p


def native_audit(tmp_path):
    from load_finality import Head
    from load_native_observer import NativeObserver

    q = audit(tmp_path)
    c = SimpleNamespace(max_age=10, timeout=8, close=lambda: None)
    o = NativeObserver(c, lambda *a, **k: None, q.halt, boot=lambda: "test-boot")
    head = Head(1, "11" * 32)
    o.window.advance(1, head, head, (), boot_id="test-boot", now=time.monotonic())
    q.attach_native(o)
    return q, o


def test_native_offer_journals_signed_request_not_carrier_digest(tmp_path):
    q, o = native_audit(tmp_path)
    q.offer([0], carrier(tmp_path), {0: "ab" * 32})
    assert o.window.pending[0][0] == "ab" * 32
    events = [json.loads(line) for line in (q.run / "events.jsonl").read_text().splitlines()]
    offered = next(event for event in events if event["event"] == "offered")
    assert offered["signed_request_hashes"] == {"0": "ab" * 32}
    assert offered["native_boot_id"] == "test-boot"
    assert offered["native_offered_monotonic_seconds"] == o.window.pending[0][1]
    assert not q.finish()["safe_to_start_new_run"]


def test_native_offered_journal_failure_retains_unfinished_fence(tmp_path, monkeypatch):
    q, o = native_audit(tmp_path)

    def fail(*args, **kwargs):
        raise OSError("fsync failed")

    monkeypatch.setattr(q, "event", fail)
    with pytest.raises(OSError, match="fsync"):
        q.offer([0], carrier(tmp_path), {0: "ab" * 32})
    assert o.summary()["native_pending"] == 1 and q.offered == 0
    assert not q.finish()["safe_to_start_new_run"]
    with pytest.raises(lib.TestnetError, match="unfinished"):
        audit(tmp_path)


def test_native_verification_requires_exact_bound_receipt_without_rpc(tmp_path):
    from load_finality import Head, SubmitReceipt

    obj = driver()
    q, o = native_audit(tmp_path)
    obj.qualification = q
    q.offer([0], carrier(tmp_path), {0: "ab" * 32})
    q.accept([0])
    obj.processed = lambda *a: pytest.fail("native completion must not query processed RPC")
    obj.processed_on = obj.processed
    checks = [(0, [0], 100)]
    obj.verify_qualified("wallet", checks, now=1)
    assert q.executed == 0 and checks
    new = Head(2, "22" * 32)
    o.window.advance(
        2,
        o.window.head,
        new,
        (SubmitReceipt(0, new, "ab" * 32, 1, 255, 254, 1),),
        boot_id="test-boot",
        now=time.monotonic(),
    )
    obj.verify_qualified("wallet", checks, now=5)
    assert not checks
    result = q.finish()
    assert result["executed"] == 1 and result["native_finality"]["native_finalized"] == 1
    assert result["safe_to_start_new_run"]


def test_native_failure_during_offered_fsync_prevents_broadcast(tmp_path, monkeypatch):
    obj = driver()
    q, o = native_audit(tmp_path)
    obj.qualification = q
    obj.request_hashes = {0: "ab" * 32}
    original = q.event

    def event(kind, **fields):
        original(kind, **fields)
        if kind == "offered":
            o._fail("proof failed during offered fsync")

    monkeypatch.setattr(q, "event", event)
    sent = []
    error = obj.send((None, [0], carrier(tmp_path)), SimpleNamespace(send_boc=sent.append))
    assert error and not sent and obj.stop
    assert q.offered == 1 and o.summary()["native_pending"] == 1
    assert not q.finish()["safe_to_start_new_run"]


def test_native_health_is_refreshed_after_funding_lock_wait(tmp_path, monkeypatch):
    obj = driver()
    q, o = native_audit(tmp_path)
    obj.qualification = q
    obj.args.owner_floor = "1"
    obj.funding_owner = lambda: ("node-1", "public-owner")
    obj.operations = SimpleNamespace(balance=lambda _: 10**12)
    monkeypatch.setitem(type(obj).fund_from_owner.__globals__, "owner_keeps", lambda *a: None)
    signed = []

    def reserved(_to, _amount, _label, _init, _name, prerequisites):
        o.window.last_verified = time.monotonic() - 11
        prerequisites()
        signed.append(True)

    obj._fund_from_owner_reserved = reserved
    with pytest.raises(ValueError, match="stale"):
        obj.fund_from_owner("public-target", 1, "test", None)
    assert not signed and q.funding_unknown and obj.stop
    assert not q.finish()["safe_to_start_new_run"]


@pytest.mark.parametrize("cut", ["before_sign", "after_export"])
def test_native_owner_guard_checks_actual_sign_and_broadcast_boundaries(tmp_path, monkeypatch, cut):
    obj = driver()
    q, o = native_audit(tmp_path)
    g = type(obj).fund_from_owner.__globals__
    # All owner/key/signing operations below are fakes; no real key is read.
    monkeypatch.setitem(
        g,
        "pool_owner_paths",
        lambda *a: {
            "key": SimpleNamespace(is_file=lambda: True),
            "addr": SimpleNamespace(read_bytes=lambda: b"fake-address"),
        },
    )
    monkeypatch.setitem(g, "address_from_file", lambda _: "public-owner")
    signed, broadcast = [], []
    monkeypatch.setitem(g, "sign_wallet_v3", lambda *a, **k: signed.append(True) or b"fake-boc")

    def run(_id, _params, sign, _validate, _prerequisites, _expect, *, export):
        if cut == "before_sign":
            o._fail("failure after wallet identity RPC")
        boc = sign(0)
        if cut == "after_export":
            # Reproduce failure during the export's durable file write.
            original = lib.write_new

            def write_then_fail(*args, **kwargs):
                original(*args, **kwargs)
                o._fail("failure during export fsync")

            monkeypatch.setattr(lib, "write_new", write_then_fail)
        export(boc, 0)
        broadcast.append(True)

    operations = SimpleNamespace(run=run)
    with pytest.raises(ValueError, match="failure"):
        g["owner_transfer"](
            SimpleNamespace(ceremony=str(tmp_path)),
            operations,
            2,
            "node-1",
            "fake-id",
            "owner-fund",
            "public-destination",
            1,
            None,
            lambda: None,
            admission_guard=o.assert_healthy,
        )
    assert len(signed) == (cut == "after_export") and not broadcast
    q.abort()


def test_native_setup_requires_existing_wallet_before_observer_or_signing(tmp_path):
    obj = driver()
    obj.state = tmp_path
    started = []
    obj.start_native_observer = started.append
    with pytest.raises(lib.TestnetError, match="existing deployed"):
        obj.start_native_from_existing_wallet()
    assert not started


def test_native_baseline_precedes_any_relayer_preparation(monkeypatch):
    obj = driver()
    obj.args.relayers = 1
    obj.args.dry_run = False
    obj.args.native_finality = True
    obj.check_qualified_genesis = lambda: None
    monkeypatch.setitem(type(obj).run.__globals__, "previous_wallets", lambda _: [])
    trace = []
    obj.start_native_from_existing_wallet = lambda: trace.append("native baseline")

    def prepare(_count):
        assert trace == ["native baseline"]
        raise RuntimeError("test stops before setup action")

    obj.ensure_keys = prepare
    with pytest.raises(RuntimeError, match="test stops"):
        obj.run()


def test_new_relayer_activation_carrier_signing_is_native_guarded(tmp_path, monkeypatch):
    obj = driver()
    q, o = native_audit(tmp_path)
    obj.qualification = q
    obj.state = tmp_path / "prepared-test-state"
    obj.state.mkdir(mode=0o700)
    (obj.state / "highload.key").write_bytes(b"FAKE-TEST-KEY-NOT-USABLE")
    (obj.state / "highload.addr").write_bytes(b"FAKE-TEST-ADDRESS")
    obj.saved = {"wallet_timeout": 3600}
    obj.args.wallet_timeout = 3600
    obj.global_id = 2
    obj.tos_root = tmp_path
    obj.include = "unused"
    obj.args.fift = "unused"
    g = type(obj).ensure_keys.__globals__
    monkeypatch.setitem(g, "address_from_file", lambda _: "0:" + "11" * 32)
    calls = []
    monkeypatch.setattr(g["subprocess"], "run", lambda *a, **k: calls.append(a))
    o._fail("failure before relayer setup signing")
    with pytest.raises(ValueError, match="relayer setup"):
        obj.ensure_keys(1)
    assert not calls
    q.abort()


def test_qualified_settlement_checks_execution_without_artificial_hold(tmp_path, monkeypatch):
    obj = driver()
    obj.qualification = audit(tmp_path)
    obj.qualification.offer([0], carrier(tmp_path))
    obj.counts["batches_accepted"] = 0
    monkeypatch.setattr(time, "time", lambda: 100)
    relayer = SimpleNamespace(inflight={"seqno": 7, "ids": [0]}, seqno=7, retries=0)
    checks = []
    seen = []
    obj.processed = lambda _wallet, query: seen.append(query) or True
    obj.settle(relayer, 8, checks)
    obj.verify_qualified("public-wallet", checks, now=100)
    assert seen == [0] and not checks
    result = obj.qualification.finish()
    assert result["executed"] == result["accepted"] == 1


def test_unqualified_settlement_retains_ordinary_poll_delay(monkeypatch):
    obj = driver()
    obj.counts["batches_accepted"] = 0
    monkeypatch.setattr(time, "time", lambda: 100)
    relayer = SimpleNamespace(inflight={"seqno": 7, "ids": [0]}, seqno=7, retries=0)
    checks = []
    obj.settle(relayer, 8, checks)
    assert checks[0][0] == 103


def test_every_query_has_terminal_evidence_and_bounded_histogram(tmp_path):
    q = audit(tmp_path)
    q.offer([0, 1, 2], carrier(tmp_path))
    q.accept([0, 1, 2])
    for query in [0, 1, 2]:
        q.terminal(query, True)
    result = q.finish()
    assert result["executed"] == result["offered"] == 3
    assert sum(result["histograms"]["executed"]) == 3
    assert result["pending"] == 0 and result["all_queries_observed_executed"]
    assert len(q.live) == 0 and len(q.seen) == 1024 * 1024
    q2 = audit(tmp_path)
    q2.finish()


def test_last_query_is_not_the_whole_group(tmp_path):
    q = audit(tmp_path)
    q.offer([0, 1], carrier(tmp_path))
    q.accept([0, 1])
    q.terminal(1, True)
    result = q.finish()
    assert result["pending"] == 1 and result["executed"] == 1
    assert not result["all_queries_observed_executed"]
    with pytest.raises(lib.TestnetError, match="unfinished"):
        audit(tmp_path)


def test_failed_terminal_and_unknown_funding_refuse_new_run(tmp_path):
    q = audit(tmp_path)
    q.offer([0], carrier(tmp_path))
    q.terminal(0, False)
    q.uncertain_funding()
    result = q.finish()
    assert not result["safe_to_start_new_run"]
    with pytest.raises(lib.TestnetError, match="unfinished"):
        audit(tmp_path)


def test_funding_ceiling_reserved_before_unknown_and_never_refunded(tmp_path):
    q = audit(tmp_path)
    q.reserve_funding(19, "first")
    q.reserve_funding(1, "exact")
    with pytest.raises(lib.TestnetError, match="funding ceiling"):
        q.reserve_funding(1, "too-much")
    q.uncertain_funding()
    with pytest.raises(lib.TestnetError, match="admission stopped"):
        q.reserve_funding(1, "after-unknown")
    assert q.funded == 20
    q.abort()
    with pytest.raises(lib.TestnetError, match="unfinished"):
        audit(tmp_path)


@pytest.mark.parametrize("bad", [[], [0, 0], [1023], [-1], [1 << 23], [True]])
def test_invalid_queries_refused_before_carrier_copy(tmp_path, bad):
    q = audit(tmp_path)
    with pytest.raises(lib.TestnetError):
        q.offer(bad, carrier(tmp_path))
    assert not list((q.run / "private-outbox").iterdir())
    q.abort()


def test_pending_cap_and_completed_id_reuse(tmp_path):
    q = audit(tmp_path, max_pending=1)
    q.offer([0], carrier(tmp_path))
    with pytest.raises(lib.TestnetError):
        q.offer([1], carrier(tmp_path, "another.boc"))
    q.terminal(0, True)
    with pytest.raises(lib.TestnetError, match="reused"):
        q.offer([0], carrier(tmp_path, "reuse.boc"))
    q.finish()


def test_process_lock_and_observed_fee_boundary(tmp_path):
    q = audit(tmp_path)
    with pytest.raises((BlockingIOError, lib.TestnetError)):
        audit(tmp_path)
    assert not q.observe_fees(9)
    assert q.observe_fees(10)
    q.finish()


def driver():
    spec = importlib.util.spec_from_file_location(
        "qualified_elections", SCRIPTS / "testnet-elections.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    obj = object.__new__(module.LoadDriver)
    obj.counts = {"verified": 0, "unconfirmed": 0}
    obj.stop = False
    obj.args = SimpleNamespace(confirm_rpc="confirm-rpc")
    obj.processed_on = lambda _url, _wallet, _query: True
    obj.check_send_genesis = lambda _route: None
    return obj


def test_driver_checks_each_query_and_does_not_promote_last_proxy(tmp_path):
    obj = driver()
    obj.qualification = audit(tmp_path)
    obj.qualification.offer([0, 1], carrier(tmp_path))
    seen = []

    def processed(_wallet, query):
        seen.append(query)
        return query == 1

    obj.processed = processed
    checks = [(0, [0, 1], 10)]
    obj.verify("public-wallet", checks)
    assert seen == [0, 1]
    assert obj.counts == {"verified": 1, "unconfirmed": 1}
    assert obj.stop and not checks
    result = obj.qualification.finish()
    assert not result["all_queries_observed_executed"]
    events = [
        json.loads(x) for x in (obj.qualification.run / "events.jsonl").read_text().splitlines()
    ]
    assert not any("carrier" in event for event in events)


def test_confirmation_disagreement_is_not_execution(tmp_path):
    obj = driver()
    obj.qualification = audit(tmp_path)
    obj.qualification.offer([0], carrier(tmp_path))
    obj.processed = lambda _wallet, _query: True
    obj.processed_on = lambda _url, _wallet, _query: False
    checks = [(0, [0], 10)]
    obj.verify("public-wallet", checks)
    assert obj.counts["verified"] == 0 and obj.counts["unconfirmed"] == 1
    assert obj.stop
    obj.qualification.finish()


def test_funding_guard_precedes_callback_and_unknown_stops(tmp_path):
    obj = driver()
    obj.qualification = audit(tmp_path)
    obj.funding_owner = lambda: ("test-owner", "test-address")
    sent = []
    obj._fund_from_owner_reserved = lambda _to, amount, *_args: sent.append(amount)
    obj.fund_from_owner("target", 20, "exact", None)
    with pytest.raises(lib.TestnetError, match="funding ceiling"):
        obj.fund_from_owner("target", 1, "excess", None)
    assert sent == [20]
    obj.qualification.finish()


def test_unknown_funding_stops_without_a_new_operation(tmp_path):
    obj = driver()
    obj.qualification = audit(tmp_path)
    obj.funding_owner = lambda: ("test-owner", "test-address")
    attempts = []

    def unknown(*_args):
        attempts.append(True)
        raise TimeoutError("original outcome unknown")

    obj._fund_from_owner_reserved = unknown
    with pytest.raises(TimeoutError):
        obj.fund_from_owner("target", 1, "unknown", None)
    assert obj.stop and attempts == [True] and obj.qualification.funding_unknown
    obj.qualification.abort()
    with pytest.raises(lib.TestnetError, match="unfinished"):
        audit(tmp_path)


def test_full_genesis_both_hashes_not_just_network_id():
    info = {
        "init": {
            "workchain": -1,
            "seqno": 0,
            "root_hash": base64.b64encode(bytes.fromhex("11" * 32)).decode(),
            "file_hash": base64.b64encode(bytes.fromhex("22" * 32)).decode(),
        }
    }
    check_genesis(info, "11" * 32, "22" * 32)
    with pytest.raises(lib.TestnetError, match="genesis"):
        check_genesis(info, "33" * 32, "22" * 32)
    with pytest.raises(lib.TestnetError, match="genesis"):
        check_genesis(info, "11" * 32, "33" * 32)
    info["init"]["seqno"] = 1
    with pytest.raises(lib.TestnetError, match="genesis"):
        check_genesis(info, "11" * 32, "22" * 32)


def test_audit_fence_precedes_rpc_and_original_carrier_survives(tmp_path):
    obj = driver()
    obj.qualification = audit(tmp_path, max_pending=1)
    first = carrier(tmp_path)
    obj.qualification.offer([0], first)
    first.unlink()
    retained = obj.qualification.run / "private-outbox" / "ext-0.boc"
    assert retained.read_bytes() == b"test-only-unsent-carrier"
    calls = []
    route = SimpleNamespace(send_boc=lambda body: calls.append(body))
    error = obj.send((None, [1], carrier(tmp_path, "ext-1.boc")), route)
    assert error and "pending ceiling" in error and not calls
    obj.qualification.abort()


def test_halt_fences_new_funding_and_offers(tmp_path):
    q = audit(tmp_path)
    q.halt("test-unknown")
    with pytest.raises(lib.TestnetError, match="admission stopped"):
        q.reserve_funding(1, "late")
    with pytest.raises(lib.TestnetError, match="admission stopped"):
        q.offer([0], carrier(tmp_path))
    assert q.offered == q.funded == 0
    q.abort()


def test_funding_inflight_cannot_close_run(tmp_path):
    q = audit(tmp_path)
    q.reserve_funding(1, "pending")
    result = q.finish()
    assert result["funding_inflight"] == 1 and not result["safe_to_start_new_run"]
    with pytest.raises(lib.TestnetError, match="unfinished"):
        audit(tmp_path)


def test_ordinary_mode_cannot_bypass_qualified_history(tmp_path):
    from load_qualification import ordinary_state_lock

    q = audit(tmp_path)
    q.abort()
    with pytest.raises(lib.TestnetError, match="qualification mode"):
        ordinary_state_lock(tmp_path / "state")


def test_ordinary_and_qualified_share_process_lock(tmp_path):
    import os

    from load_qualification import ordinary_state_lock

    fd = ordinary_state_lock(tmp_path / "state")
    try:
        with pytest.raises(BlockingIOError):
            audit(tmp_path)
    finally:
        os.close(fd)
    q = audit(tmp_path)
    q.finish()


def test_slow_funding_thread_cannot_publish_safe_finish(tmp_path):
    obj = driver()
    obj.qualification = audit(tmp_path)
    obj.qualification.reserve_funding(1, "still-running")
    joined = []
    thread = SimpleNamespace(join=lambda timeout: joined.append(timeout), is_alive=lambda: True)
    done = SimpleNamespace(set=lambda: None)
    with pytest.raises(lib.TestnetError, match="still active"):
        obj.stop_refiller(thread, done)
    assert joined == [120] and obj.qualification.funding_unknown
    obj.qualification.abort()
    with pytest.raises(lib.TestnetError, match="unfinished"):
        audit(tmp_path)


def test_unknown_send_halts_before_other_parallel_admission(tmp_path):
    obj = driver()
    obj.qualification = audit(tmp_path)
    obj.check_send_genesis = lambda route: None

    def uncertain(_body):
        raise OSError("RPC outcome unknown")

    route = SimpleNamespace(send_boc=uncertain)
    assert obj.send((None, [0], carrier(tmp_path)), route)
    assert obj.stop and obj.qualification.halted
    calls = []
    later = SimpleNamespace(send_boc=lambda body: calls.append(body))
    assert obj.send((None, [1], carrier(tmp_path, "later.boc")), later)
    assert not calls
    obj.qualification.abort()


def test_all_send_routes_get_genesis_checks(tmp_path):
    obj = driver()
    obj.args = SimpleNamespace(
        confirm_rpc="confirm",
        send_rpc=["foreign-send"],
        watch_rpc=[],
        expected_genesis_root="11" * 32,
        expected_genesis_file="22" * 32,
    )
    seen = []

    def rpc(url, _method):
        seen.append(url)
        root = "33" if url == "foreign-send" else "11"
        return {
            "init": {
                "workchain": -1,
                "seqno": 0,
                "root_hash": base64.b64encode(bytes.fromhex(root * 32)).decode(),
                "file_hash": base64.b64encode(bytes.fromhex("22" * 32)).decode(),
            }
        }

    obj.chain = SimpleNamespace(url="primary", rpc=rpc)
    with pytest.raises(lib.TestnetError, match="genesis"):
        obj.check_qualified_genesis()
    assert "foreign-send" in seen


def test_qualified_state_bound_across_runs_and_no_legacy_key_adoption(tmp_path):
    first = {"global_id": 2, "genesis_root": "11" * 32, "genesis_file": "22" * 32}
    q = Qualification(tmp_path / "state", 20, 10, identity=first)
    q.finish()
    with pytest.raises(lib.TestnetError, match="different genesis"):
        Qualification(tmp_path / "state", 20, 10, identity=dict(first, genesis_file="33" * 32))
    q = Qualification(tmp_path / "state", 20, 10, identity=first)
    q.finish()
    legacy = tmp_path / "legacy"
    legacy.mkdir(mode=0o700)
    (legacy / "highload.key").write_text("test-only-placeholder-not-a-key")
    with pytest.raises(lib.TestnetError, match="unbound"):
        Qualification(legacy, 20, 10, identity=first)


def test_default_constructor_cannot_drop_qualification_flag(tmp_path):
    q = audit(tmp_path)
    q.abort()
    args = SimpleNamespace(
        state=tmp_path / "state",
        tos_root=tmp_path,
        fift=tmp_path / "build/crypto/fift",
        actions_per_batch=1,
        transfers="skip",
        transfer_nanotos=1,
        send_rpc=[],
        qualify_load=False,
    )
    chain = SimpleNamespace(url="primary", rpc=lambda *args, **kwargs: None)
    with pytest.raises(lib.TestnetError, match="qualification mode"):
        type(driver())(args, chain, 2)


def test_qualified_query_counter_fsyncs_file_and_directory(tmp_path, monkeypatch):
    import os
    import stat

    obj = driver()
    obj.qualification = audit(tmp_path)
    obj.state = tmp_path / "state"
    obj.saved = {"next_query_id": 17}
    synced = []
    original = os.fsync

    def fsync(fd):
        synced.append("file" if stat.S_ISREG(os.fstat(fd).st_mode) else "directory")
        original(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    obj.save_state()
    assert synced == ["file", "directory"]
    obj.qualification.finish()


def test_exception_cleanup_stops_delayed_refill_before_funding(tmp_path):
    import threading

    obj = driver()
    obj.qualification = audit(tmp_path)
    obj.args.relayer_amount = "1"
    entered, release, cleanup = threading.Event(), threading.Event(), threading.Event()
    calls = []

    def account(_address):
        entered.set()
        assert release.wait(3)
        return "active", 0

    obj.chain = SimpleNamespace(account=account)
    obj.topped_up = 0
    obj.fund_from_owner = lambda *args: calls.append(args)

    class Done:
        def wait(self, timeout):
            return cleanup.wait(min(timeout, 0.01))

        def is_set(self):
            return cleanup.is_set()

        def set(self):
            cleanup.set()
            release.set()

    done = Done()
    thread = threading.Thread(
        target=obj.refill, args=([SimpleNamespace(address="test", index=0)], done)
    )
    thread.start()
    assert entered.wait(3)
    obj.stop_refiller(thread, done)
    assert not thread.is_alive() and obj.stop and obj.qualification.halted and not calls
    obj.qualification.finish()


def test_sent_bytes_are_the_archived_snapshot_after_source_replacement(tmp_path):
    obj = driver()
    obj.qualification = audit(tmp_path)
    path = carrier(tmp_path)
    offer = obj.qualification.offer

    def replacing(ids, source):
        payload = offer(ids, source)
        source.write_bytes(b"different-unsent-replacement")
        return payload

    obj.qualification.offer = replacing
    sent = []
    route = SimpleNamespace(send_boc=lambda payload: sent.append(payload))
    assert obj.send((None, [0], path), route) is None
    archived = obj.qualification.run / "private-outbox" / path.name
    assert sent == [archived.read_bytes()] == [b"test-only-unsent-carrier"]
    assert path.read_bytes() != sent[0]
    obj.qualification.terminal(0, True)
    obj.qualification.finish()


def test_oversized_carrier_refused_before_archiving(tmp_path):
    from load_qualification import MAX_CARRIER_BYTES

    q = audit(tmp_path)
    path = tmp_path / "oversized.boc"
    with path.open("wb") as out:
        out.truncate(MAX_CARRIER_BYTES + 1)
    with pytest.raises(lib.TestnetError, match="size limit"):
        q.offer([0], path)
    assert q.offered == 0 and not list((q.run / "private-outbox").iterdir())
    q.abort()


@pytest.mark.parametrize("bad", ["window", "stopped", "pending", "failed"])
def test_qualified_incomplete_run_returns_failure_and_closes(monkeypatch, bad):
    spec = importlib.util.spec_from_file_location(
        "qualification_exit", SCRIPTS / "testnet-elections.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = {
        "stop_reason": "duration reached",
        "offering_seconds_monotonic": 10,
        "qualification": {"all_queries_observed_executed": True, "safe_to_start_new_run": True},
    }
    if bad == "window":
        result["offering_seconds_monotonic"] = 9
    elif bad == "stopped":
        result["stop_reason"] = "interrupted"
    elif bad == "pending":
        result["qualification"]["safe_to_start_new_run"] = False
    else:
        result["batches_failed"] = 1
    closed = []
    fake = SimpleNamespace(
        run=lambda: result, qualification=True, close=lambda: closed.append(True)
    )
    monkeypatch.setattr(module, "LoadDriver", lambda *args: fake)
    with pytest.raises(lib.TestnetError, match="declared execution window"):
        module.run_load(SimpleNamespace(duration=10), None, 2)
    assert closed == [True]


@pytest.mark.parametrize("send_error", [False, True])
def test_broadcast_timing_preserves_one_send_and_records_after_call(tmp_path, send_error):
    obj = driver()
    q = audit(tmp_path)
    obj.qualification = q
    calls = []

    def send(payload):
        # Diagnostic fsync must never delay dispatch before the HTTP call.
        existing = (q.run / "events.jsonl").read_text()
        assert '"broadcast_timing"' not in existing
        calls.append(payload)
        if send_error:
            raise OSError("connection uncertain")

    error = obj.send(
        (SimpleNamespace(address="public-relayer"), [0], carrier(tmp_path)),
        SimpleNamespace(send_boc=send),
    )
    assert len(calls) == 1
    assert bool(error) == send_error
    events = [json.loads(line) for line in (q.run / "events.jsonl").read_text().splitlines()]
    timing = next(event for event in events if event["event"] == "broadcast_timing")
    assert timing["query_ids"] == [0] and timing["relayer"] == "public-relayer"
    assert timing["outcome"] == ("raised" if send_error else "returned")
    times = [
        timing[key]
        for key in (
            "offer_call_started_monotonic_seconds",
            "offer_call_returned_monotonic_seconds",
            "send_call_started_monotonic_seconds",
            "send_call_finished_monotonic_seconds",
            "monotonic_seconds",
        )
    ]
    assert times == sorted(times)
    assert set(timing) == {
        "event",
        "time_unix",
        "monotonic_seconds",
        "query_ids",
        "relayer",
        "outcome",
        "offer_call_started_monotonic_seconds",
        "offer_call_returned_monotonic_seconds",
        "send_call_started_monotonic_seconds",
        "send_call_finished_monotonic_seconds",
    }
    assert obj.stop == send_error
    assert not q.finish()["safe_to_start_new_run"]


def test_broadcast_timing_journal_failure_stops_without_second_send(tmp_path, monkeypatch):
    obj = driver()
    q = audit(tmp_path)
    obj.qualification = q
    original = q.event

    def event(kind, **fields):
        if kind == "broadcast_timing":
            raise OSError("timing journal unavailable")
        return original(kind, **fields)

    monkeypatch.setattr(q, "event", event)
    sent = []
    error = obj.send((None, [0], carrier(tmp_path)), SimpleNamespace(send_boc=sent.append))
    assert "timing journal" in error and obj.stop and len(sent) == 1
    assert q.halted and not q.finish()["safe_to_start_new_run"]


def cutoff_audit(tmp_path, monkeypatch):
    from load_finality import Head, SubmitReceipt
    from load_native_observer import NativeObserver

    q = audit(tmp_path)
    base = time.monotonic()
    now = [base]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    o = NativeObserver(
        SimpleNamespace(max_age=10, timeout=8, close=lambda: None),
        lambda *a, **k: None,
        q.halt,
        boot=lambda: "test-boot",
        slo_population="fixed-stage",
        cutoff_policy="not-offered",
    )
    old = Head(1, "11" * 32)
    new = Head(2, "22" * 32)
    o.window.advance(1, old, old, (), boot_id="test-boot", now=base)
    o.window.begin_stage(1, boot_id="test-boot", now=base)
    q.attach_native(o)
    now[0] = base + 0.1
    q.offer([0], carrier(tmp_path), {0: "ab" * 32})
    now[0] = base + 0.2
    o.window.advance(
        2,
        old,
        new,
        [SubmitReceipt(0, new, "ab" * 32, 1, 255, 254, 1)],
        boot_id="test-boot",
        now=now[0],
    )
    q.accept([0])
    q.terminal(0, True)
    now[0] = base + 1
    return q, o, now


def test_deadline_preparation_is_recorded_but_never_broadcast(tmp_path, monkeypatch):
    from load_finality_window import AdmissionClosed

    q, o, now = cutoff_audit(tmp_path, monkeypatch)
    obj = driver()
    obj.qualification = q
    obj.request_hashes = {1: "cd" * 32}
    route = SimpleNamespace(send_boc=lambda _: pytest.fail("canceled preparation broadcast"))
    result = obj.send(
        (SimpleNamespace(address="public-fake"), [1], carrier(tmp_path, "late.boc")), route
    )
    assert isinstance(result, AdmissionClosed) and not obj.stop and not q.halted
    assert q.not_offered == 1 and q.offered == q.executed == 1 and o.window.failure is None
    records = [json.loads(x) for x in (q.run / "events.jsonl").read_text().splitlines()]
    assert sum(r["event"] == "not_offered" for r in records) == 1
    assert not any(r["event"] == "broadcast_timing" for r in records)
    with pytest.raises(lib.TestnetError, match="reused"):
        q.offer([1], carrier(tmp_path, "retry.boc"), {1: "cd" * 32})
    o.window.seal(boot_id="test-boot", now=now[0])
    o.window.finish_stage(boot_id="test-boot", now=now[0])
    result = q.finish()
    assert result["safe_to_start_new_run"] and result["native_finality"]["latency_criteria_pass"]
    assert result["not_offered"] == 1 and not result["not_offered_unknown"]


def test_not_offered_journal_failure_keeps_original_fence(tmp_path, monkeypatch):
    q, o, _ = cutoff_audit(tmp_path, monkeypatch)
    obj = driver()
    obj.qualification = q
    obj.request_hashes = {1: "cd" * 32}
    original = q.event

    def event(kind, **fields):
        if kind == "not_offered":
            raise OSError("fake journal fsync failure")
        return original(kind, **fields)

    monkeypatch.setattr(q, "event", event)
    route = SimpleNamespace(send_boc=lambda _: pytest.fail("failed journal broadcast"))
    assert isinstance(
        obj.send(
            (SimpleNamespace(address="public-fake"), [1], carrier(tmp_path, "late.boc")), route
        ),
        str,
    )
    assert obj.stop and q.not_offered_unknown
    assert not q.finish()["safe_to_start_new_run"]


def test_archive_fsync_crossing_cutoff_never_submits(tmp_path, monkeypatch):
    import load_qualification as qualification_module
    from load_finality_window import AdmissionClosed

    q, o, now = cutoff_audit(tmp_path, monkeypatch)
    deadline = now[0]
    now[0] -= 0.1
    sync = qualification_module.sync_directory

    def delayed(path):
        sync(path)
        if path.name == "private-outbox":
            now[0] = deadline + 0.01

    monkeypatch.setattr(qualification_module, "sync_directory", delayed)
    obj = driver()
    obj.qualification = q
    obj.request_hashes = {1: "cd" * 32}
    route = SimpleNamespace(send_boc=lambda _: pytest.fail("late archived carrier submitted"))
    result = obj.send(
        (SimpleNamespace(address="public-fake"), [1], carrier(tmp_path, "late.boc")), route
    )
    assert isinstance(result, AdmissionClosed) and not obj.stop and not q.halted
    assert q.not_offered == 1 and q.offered == 1 and o.window.failure is None
    o.window.seal(boot_id="test-boot", now=now[0])
    o.window.finish_stage(boot_id="test-boot", now=now[0])
    assert q.finish()["native_finality"]["latency_criteria_pass"]


def test_admission_exception_after_http_attempt_is_not_canceled(tmp_path, monkeypatch):
    from load_finality_window import AdmissionClosed

    q, o, now = cutoff_audit(tmp_path, monkeypatch)
    deadline = now[0]
    now[0] -= 0.5
    obj = driver()
    obj.qualification = q
    obj.request_hashes = {1: "cd" * 32}

    def uncertain(_):
        raise AdmissionClosed("test-boot", deadline, deadline)

    result = obj.send(
        (SimpleNamespace(address="public-fake"), [1], carrier(tmp_path, "sent.boc")),
        SimpleNamespace(send_boc=uncertain),
    )
    assert isinstance(result, str) and obj.stop and q.halted
    assert q.not_offered == 0 and o.window.pending
    assert not q.finish()["safe_to_start_new_run"]


@pytest.mark.parametrize("cancel", [False, True])
def test_actual_send_result_loop_does_not_count_canceled_preparations(tmp_path, cancel):
    """Execute the actual result-loop AST with fake frames, not a second implementation."""
    import ast

    from load_finality_window import AdmissionClosed

    source = (SCRIPTS / "testnet-elections.py").read_text()
    tree = ast.parse(source)
    loop = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.For)
        and isinstance(n.iter, ast.Call)
        and ast.unparse(n.iter) == "zip(externals, results, routes)"
    )
    path = tmp_path / "fake.boc"
    path.write_bytes(b"FAKE-NOT-SIGNED")
    relayer = SimpleNamespace(seqno=7, inflight=None)
    counts = {"externals_sent": 0, "batches_sent": 0}
    obj = SimpleNamespace(
        counts=counts, fail=lambda *a: pytest.fail("canceled result treated as failure")
    )
    error = AdmissionClosed("test-boot", 10, 10) if cancel else None
    scope = {
        "self": obj,
        "externals": [(relayer, [1], path)],
        "results": [error],
        "routes": ["fake-route"],
        "work": tmp_path,
        "AdmissionClosed": AdmissionClosed,
        "time": time,
        "EXTERNAL_TTL": 300,
    }
    exec(compile(ast.Module(body=[loop], type_ignores=[]), "actual-result-loop", "exec"), scope)
    assert counts == {"externals_sent": 0 if cancel else 1, "batches_sent": 0 if cancel else 1}
    assert (relayer.inflight is None) == cancel
    assert not path.exists()


def test_a_second_preparation_cannot_clear_unknown_cancel_evidence(tmp_path, monkeypatch):
    from load_finality_window import AdmissionClosed

    q, _, _ = cutoff_audit(tmp_path, monkeypatch)
    original = q.event

    def failed(kind, **fields):
        if kind == "not_offered":
            raise OSError("one failed durable cancellation")
        return original(kind, **fields)

    monkeypatch.setattr(q, "event", failed)
    with pytest.raises(OSError):
        q.offer([1], carrier(tmp_path, "first-late.boc"), {1: "cd" * 32})
    # Another worker can acquire the qualification lock before the first sender
    # reaches its error handler. Success must not erase that earlier unknown.
    monkeypatch.setattr(q, "event", original)
    try:
        q.offer([2], carrier(tmp_path, "second-late.boc"), {2: "ef" * 32})
    except (AdmissionClosed, lib.TestnetError):
        pass
    assert q.not_offered_unknown
    assert not q.finish()["safe_to_start_new_run"]
