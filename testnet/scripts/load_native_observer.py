"""Continuous read-only proof worker; admission and durable events stay explicit."""

import threading
import time
from pathlib import Path

from load_finality import HistoryError
from load_finality_window import QUERY_LIMIT, FinalityWindow


def boot_identity():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


class NativeObserver:
    def __init__(
        self, collector, record, halt, *, interval=2, max_pending=8192, boot=boot_identity
    ):
        if not 0.1 <= interval <= 10:
            raise HistoryError("native poll interval must be 0.1..10")
        self.collector, self.record, self.halt = collector, record, halt
        self.interval, self.boot = interval, boot
        self.window = FinalityWindow(
            boot(), max_pending=max_pending, max_proof_age=collector.max_age
        )
        self.failure = None
        self.failure_guard = threading.Lock()
        self.done = threading.Event()
        self.draining = threading.Event()
        self.thread = None

    def _fail(self, reason):
        with self.failure_guard:
            if self.failure is None:
                self.failure = str(reason)[:1024]
            failure = self.failure
        # No observer/window lock is held while entering the qualification lock.
        self.halt("native_observation_failed: " + failure)

    def bootstrap(self):
        """Unscored cold acquisition, followed by a normal-policy fresh baseline.

        No offer is permitted until the strict capture and baseline are durable.
        The longer setup timeout never applies after admission begins.
        """
        age, timeout = self.collector.max_age, self.collector.timeout
        try:
            self.collector.max_age = self.collector.timeout = 30
            warm = self.collector.capture()
        finally:
            self.collector.max_age, self.collector.timeout = age, timeout
        strict = self.collector.capture(warm.head)
        if strict.receipts:
            raise HistoryError("wallet received submissions during native bootstrap")
        with self.window.guard:
            self.window.advance(
                strict.seqno,
                strict.head,
                strict.head,
                (),
                boot_id=self.boot(),
                now=time.monotonic(),
            )
        self.record(
            "native_baseline",
            checkpoint_seqno=strict.seqno,
            head_lt=strict.head.lt,
            head_hash=strict.head.hash,
            capture=str(strict.directory),
        )

    def start(self):
        if self.thread is not None or self.window.last_verified is None or self.done.is_set():
            raise HistoryError("native observer needs one initialized start")
        self.thread = threading.Thread(target=self._work, name="native-finality", daemon=True)
        try:
            self.thread.start()
        except BaseException as startup_error:
            self.done.set()
            try:
                self._fail("native observer thread could not start")
            except BaseException:
                # The sticky failure is set before the halt callback; even a
                # journal error must not prevent closing the owned verifier FD.
                pass
            try:
                # start() can fail after the OS thread is already running.
                # Retain that handle: finish() must join it before closing the
                # collector or permitting the caller to close its journal.
                if self.thread.ident is None:
                    self.thread = None
                    self.collector.close()
            finally:
                raise startup_error

    def assert_healthy(self):
        with self.failure_guard:
            failure = self.failure
        if failure is not None:
            raise HistoryError(failure)
        if self.thread is not None and not self.thread.is_alive():
            raise HistoryError("native observer thread stopped")
        with self.window.guard:
            self.window.healthy(boot_id=self.boot(), now=time.monotonic())

    def offer(self, request_hashes):
        self.assert_healthy()
        with self.window.guard:
            self.window.offer(request_hashes, boot_id=self.boot(), now=time.monotonic())

    def finalized(self, query):
        if type(query) is not int or not 0 <= query < QUERY_LIMIT:
            raise HistoryError("invalid native query lookup")
        with self.window.guard:
            return (
                bool(self.window.seen[query // 8] & (1 << (query % 8)))
                and query not in self.window.pending
            )

    def _work(self):
        try:
            while not self.done.is_set():
                with self.window.guard:
                    pending = len(self.window.pending)
                if self.draining.is_set() and pending == 0:
                    break
                started = time.monotonic()
                try:
                    captured = self.collector.capture()
                    try:
                        with self.window.guard:
                            self.window.advance(
                                captured.seqno,
                                captured.previous_head,
                                captured.head,
                                captured.receipts,
                                boot_id=self.boot(),
                                now=time.monotonic(),
                            )
                    except HistoryError as exc:
                        # Quality failure can settle authentic receipts while
                        # keeping admission failed; never erase that failure.
                        self._fail(exc)
                    self.record(
                        "native_checkpoint",
                        checkpoint_seqno=captured.seqno,
                        capture=str(captured.directory),
                        query_ids=[r.query_id for r in captured.receipts],
                        summary=self.window.summary(),
                    )
                    if self.window.failure is not None and not self.window.drainable_failure:
                        break
                except Exception as exc:
                    self._fail(exc)
                    # Reacquisition is strictly read-only; no offer can pass the
                    # latched failure. The caller bounds the original-run drain.
                self.done.wait(max(0, self.interval - (time.monotonic() - started)))
        except BaseException as exc:
            try:
                self._fail(exc)
            except BaseException:
                pass

    def finish(self, timeout=150):
        if self.thread is None:
            self.collector.close()
            return self.summary()
        self.draining.set()
        self.thread.join(timeout=timeout)
        if self.thread.is_alive():
            self.done.set()
            self.thread.join(timeout=self.collector.timeout + 5)
        if self.thread.is_alive():
            self._fail("native worker did not stop; original run remains unfinished")
            raise HistoryError("native worker did not stop")
        self.collector.close()
        return self.summary()

    def summary(self):
        result = self.window.summary()
        with self.failure_guard:
            result["worker_failure"] = self.failure
        result["latency_criteria_pass"] = result["latency_criteria_pass"] and self.failure is None
        result["historical_replay_coverage"] = False
        return result
