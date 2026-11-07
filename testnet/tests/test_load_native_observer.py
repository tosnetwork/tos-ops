"""Worker lifecycle and fail-closed admission, without signing or network traffic."""

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from load_finality import Head, HistoryError, SubmitReceipt
from load_native_observer import NativeObserver

OLD = Head(1, "11" * 32)
NEW = Head(2, "22" * 32)


def capture(seqno, previous=OLD, head=OLD, receipts=()):
    return SimpleNamespace(
        seqno=seqno,
        previous_head=previous,
        head=head,
        receipts=receipts,
        directory=Path("public-capture"),
    )


class Collector:
    max_age = 10
    timeout = 8

    def __init__(self):
        self.calls = []
        self.closed = False
        self.next_capture = lambda: capture(12)

    def capture(self, previous=None):
        self.calls.append((self.max_age, self.timeout, previous))
        if len(self.calls) <= 2:
            return capture(10 + len(self.calls))
        return self.next_capture()

    def close(self):
        self.closed = True


def observer(collector=None, record=None):
    collector = collector or Collector()
    halted = []
    o = NativeObserver(
        collector,
        record or (lambda *a, **k: None),
        halted.append,
        interval=0.1,
        boot=lambda: "test-boot",
    )
    return o, halted


def test_bootstrap_restores_strict_policy_and_has_no_admission():
    c = Collector()
    o, _ = observer(c)
    o.bootstrap()
    assert c.calls == [(30, 30, None), (10, 8, OLD)]
    assert o.window.offered == 0 and o.window.seqno == 12
    assert not o.summary()["historical_replay_coverage"]
    o.finish()
    assert c.closed


def test_offered_and_observation_timestamps_are_exact_window_inputs():
    records = []
    o, _ = observer(record=lambda kind, **fields: records.append((kind, fields)))
    o.bootstrap()
    baseline = records[0][1]
    assert baseline["boot_id"] == "test-boot"
    assert baseline["verified_observation_monotonic_seconds"] == o.window.last_verified
    assert baseline["poll_interval_seconds"] == o.interval
    offered = o.offer({1: "ab" * 32})
    assert offered["boot_id"] == "test-boot"
    assert offered["monotonic_seconds"] == o.window.pending[1][1]
    o.finish()


def test_failed_bootstrap_restores_timeout():
    c = Collector()
    c.capture = lambda: (_ for _ in ()).throw(HistoryError("cold timeout"))
    o, _ = observer(c)
    with pytest.raises(HistoryError, match="cold timeout"):
        o.bootstrap()
    assert (c.max_age, c.timeout) == (10, 8)
    with pytest.raises(HistoryError, match="baseline"):
        o.offer({1: "ab" * 32})


@pytest.mark.parametrize("halt_fails", [False, True])
def test_failed_thread_start_closes_collector_and_finish_preserves_failure(monkeypatch, halt_fails):
    c = Collector()
    o, halted = observer(c)
    o.bootstrap()
    if halt_fails:

        def bad_halt(_reason):
            halted.append(_reason)
            raise OSError("journal unavailable")

        o.halt = bad_halt

    def fail_start():
        raise RuntimeError("cannot start new thread")

    monkeypatch.setattr(
        threading, "Thread", lambda **kw: SimpleNamespace(start=fail_start, ident=None)
    )
    with pytest.raises(RuntimeError, match="cannot start new thread"):
        o.start()
    assert c.closed and halted and o.thread is None
    assert o.finish()["worker_failure"] == "native observer thread could not start"
    with pytest.raises(HistoryError, match="initialized start"):
        o.start()


def test_exception_after_os_thread_started_retains_handle_until_join(monkeypatch):
    ready, release, finished = threading.Event(), threading.Event(), threading.Event()
    c = Collector()

    def blocked_capture():
        ready.set()
        assert release.wait(3)
        return capture(13)

    c.next_capture = blocked_capture
    o, _ = observer(c)
    o.bootstrap()
    real_thread = threading.Thread
    workers = []

    def interrupted_thread(**kwargs):
        thread = real_thread(**kwargs)
        original = thread.start

        def start_then_raise():
            original()
            assert ready.wait(2)
            raise RuntimeError("interrupted after OS thread started")

        thread.start = start_then_raise
        workers.append(thread)
        return thread

    monkeypatch.setattr(threading, "Thread", interrupted_thread)
    with pytest.raises(RuntimeError, match="after OS thread"):
        o.start()
    assert o.thread is workers[0] and o.thread.is_alive() and not c.closed

    def finish():
        o.finish(timeout=2)
        finished.set()

    cleanup = real_thread(target=finish)
    cleanup.start()
    assert not finished.wait(0.05)
    release.set()
    cleanup.join(3)
    assert finished.is_set() and c.closed and not workers[0].is_alive()
    assert o.finish()["worker_failure"] == "native observer thread could not start"
    with pytest.raises(HistoryError, match="initialized start"):
        o.start()


def test_worker_matches_request_digest_and_joins_before_close():
    ready, release = threading.Event(), threading.Event()
    c = Collector()

    def next_capture():
        ready.set()
        assert release.wait(2)
        return capture(13, OLD, NEW, (SubmitReceipt(1, NEW, "ab" * 32, 1, 255, 254, 1),))

    c.next_capture = next_capture
    records = []
    o, halted = observer(c, lambda kind, **fields: records.append((kind, fields)))
    o.bootstrap()
    o.start()
    assert ready.wait(2)
    o.offer({1: "ab" * 32})
    o.draining.set()
    release.set()
    result = o.finish(timeout=2)
    assert result["all_offered_native_finalized"] and result["latency_criteria_pass"]
    assert o.finalized(1) and not o.finalized(2)
    assert not halted and c.closed and not o.thread.is_alive()
    checkpoint = next(fields for kind, fields in records if kind == "native_checkpoint")
    assert checkpoint["boot_id"] == "test-boot"
    assert checkpoint["verified_observation_monotonic_seconds"] == o.window.last_verified


def test_wrong_digest_keeps_pending_and_latches_admission():
    ready, release, failed = threading.Event(), threading.Event(), threading.Event()
    c = Collector()

    def next_capture():
        ready.set()
        assert release.wait(2)
        return capture(13, OLD, NEW, (SubmitReceipt(1, NEW, "cd" * 32, 1, 255, 254, 1),))

    c.next_capture = next_capture
    o, halted = observer(c, lambda *a, **k: failed.set())
    o.bootstrap()
    failed.clear()
    o.start()
    assert ready.wait(2)
    o.offer({1: "ab" * 32})
    release.set()
    assert failed.wait(2)
    o.thread.join(2)
    assert not o.thread.is_alive() and halted
    assert not o.finalized(1) and o.summary()["native_pending"] == 1
    with pytest.raises(HistoryError, match="does not match"):
        o.offer({2: "ef" * 32})
    assert not o.finish()["latency_criteria_pass"]


def test_stale_observation_cannot_admit_new_queries():
    o, _ = observer()
    o.bootstrap()
    with o.window.guard:
        o.window.last_verified = time.monotonic() - 11
    with pytest.raises(HistoryError, match="stale"):
        o.offer({1: "ab" * 32})
    assert o.window.offered == 0


@pytest.mark.parametrize("query", [True, -1, 1 << 23])
def test_lookup_rejects_unbounded_or_boolean_queries(query):
    o, _ = observer()
    with pytest.raises(HistoryError, match="invalid native query"):
        o.finalized(query)
