"""Qualification evidence must reject proxy verification, duplicate IDs and excess funding."""

import base64
import importlib.util
import json
from types import SimpleNamespace

import pytest
import testnet_lib as lib
from conftest import SCRIPTS
from load_qualification import Qualification, check_genesis


def audit(tmp_path, **kw):
    return Qualification(
        tmp_path / "state", kw.get("funding_cap", 20), 10, max_pending=kw.get("max_pending", 8)
    )


def carrier(tmp_path, name="ext-0.boc"):
    p = tmp_path / name
    p.write_bytes(b"test-only-unsent-carrier")
    return p


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
