"""Bounded, fail-closed correlation for already native-verified load receipts.

The caller serializes durable offered events before broadcast and persists proof
artifacts before calling advance. This object is not a proof verifier or a
restart/replay mechanism. An unfinished qualified-run fence must survive exit.
"""

import math
import threading

from load_finality import Head, HistoryError, SubmitReceipt

BUCKETS = (0.1, 0.25, 0.5, 1, 2, 3, 5, 10, 20, 30, 60, 120, 300)
QUERY_LIMIT = 1 << 23


class FinalityWindow:
    def __init__(
        self,
        boot_id,
        *,
        max_pending=8192,
        max_proof_age=10,
        max_query_age=30,
        p95_limit=5,
        p99_limit=10,
        slo_population="completion-prefix",
    ):
        if not isinstance(boot_id, str) or not 1 <= len(boot_id) <= 128:
            raise HistoryError("bounded boot identity required")
        if type(max_pending) is not int or not 1 <= max_pending <= 8192:
            raise HistoryError("pending limit must be 1..8192")
        for value in (max_proof_age, max_query_age, p95_limit, p99_limit):
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 300:
                raise HistoryError("bounded positive finality times required")
        if p95_limit > p99_limit:
            raise HistoryError("p95 limit exceeds p99 limit")
        if slo_population not in ("completion-prefix", "fixed-stage"):
            raise HistoryError("invalid native SLO population")
        self.slo_population = slo_population
        self.sealed = self.stage_finalized = False
        self.stage_start = self.stage_deadline = self.sealed_at = None
        self.boot_id = boot_id
        self.max_pending = max_pending
        self.max_proof_age = max_proof_age
        self.max_query_age = max_query_age
        self.p95_limit, self.p99_limit = p95_limit, p99_limit
        self.guard = threading.RLock()
        self.pending = {}
        self.seen = bytearray(QUERY_LIMIT // 8)
        self.histogram = [0] * (len(BUCKETS) + 1)
        self.offered = self.finalized = 0
        self.head = self.seqno = self.last_verified = self.last_clock = None
        self.failure = None
        self.drainable_failure = False
        self.integrity_failure = None

    def _fail(self, reason, *, drainable=False):
        if self.failure is None:
            self.failure = reason
            self.drainable_failure = drainable
        elif not drainable:
            self.drainable_failure = False
            self.integrity_failure = reason
        raise HistoryError(reason)

    def _clock(self, boot_id, now, *, reconcile=False):
        if self.failure is not None and not (reconcile and self.drainable_failure):
            raise HistoryError(self.failure)
        if boot_id != self.boot_id:
            self._fail("finality boot identity changed")
        if (
            type(now) not in (int, float)
            or not math.isfinite(now)
            or now < 0
            or (self.last_clock is not None and now < self.last_clock)
        ):
            self._fail("finality monotonic clock invalid or regressed")
        self.last_clock = now

    def _healthy(self, boot_id, now):
        self._clock(boot_id, now)
        if self.last_verified is None:
            self._fail("native baseline not established")
        if now - self.last_verified > self.max_proof_age:
            self._fail("native proof observation stale", drainable=True)
        if any(now - stamp > self.max_query_age for _, stamp in self.pending.values()):
            self._fail("native query observation overdue", drainable=True)

    def healthy(self, *, boot_id, now):
        with self.guard:
            self._healthy(boot_id, now)

    def offer(self, request_hashes, *, boot_id, now):
        """Register signed request digests, not hashes of private carrier BOCs."""
        with self.guard:
            self._healthy(boot_id, now)
            if self.sealed:
                self._fail("native stage admission sealed")
            if self.slo_population == "fixed-stage" and (
                self.stage_deadline is None or now >= self.stage_deadline
            ):
                self._fail("native fixed stage offering interval not open", drainable=True)
            if (
                type(request_hashes) is not dict
                or not request_hashes
                or len(self.pending) + len(request_hashes) > self.max_pending
            ):
                self._fail("native pending limit or empty offer")
            for query, digest in request_hashes.items():
                if (
                    type(query) is not int
                    or not 0 <= query < QUERY_LIMIT
                    or query & 1023 == 1023
                    or self.seen[query // 8] & (1 << (query % 8))
                ):
                    self._fail("native query invalid or reused")
                if (
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or any(c not in "0123456789abcdef" for c in digest)
                ):
                    self._fail("native signed request digest invalid")
            for query, digest in request_hashes.items():
                self.pending[query] = (digest, now)
                self.seen[query // 8] |= 1 << (query % 8)
            self.offered += len(request_hashes)

    def _quantile(self, percent):
        if not self.finalized:
            return None
        rank = (self.finalized * percent + 99) // 100
        count = 0
        for upper, number in zip((*BUCKETS, float("inf")), self.histogram):
            count += number
            if count >= rank:
                return upper
        raise HistoryError("finality histogram inconsistent")

    def advance(self, seqno, previous_head, head, receipts, *, boot_id, now):
        """Commit a complete decoded segment; the caller has verified its proof.

        Validate every binding before removing anything. Authenticated but slow
        receipts still settle pending entries; their latency stops new admission.
        """
        with self.guard:
            self._clock(boot_id, now, reconcile=True)
            if (
                type(seqno) is not int
                or seqno < 0
                or type(previous_head) is not Head
                or type(head) is not Head
                or type(receipts) not in (list, tuple)
                or len(receipts) > self.max_pending
            ):
                self._fail("native checkpoint shape invalid")
            if self.head is None:
                if previous_head != head or receipts or self.offered:
                    self._fail("native baseline must precede admission")
            elif (
                previous_head != self.head
                or seqno < self.seqno
                or head.lt < self.head.lt
                or (head.lt == self.head.lt and head != self.head)
                or (seqno == self.seqno and head != self.head)
                or (head == self.head and receipts)
            ):
                self._fail("native checkpoint continuity mismatch")
            matched = set()
            latencies = []
            observation_gap = (
                self.last_verified is not None and now - self.last_verified > self.max_proof_age
            )
            for receipt in receipts:
                if (
                    type(receipt) is not SubmitReceipt
                    or type(receipt.query_id) is not int
                    or receipt.query_id in matched
                ):
                    self._fail("native receipt invalid or duplicated")
                row = self.pending.get(receipt.query_id)
                if row is None or row[0] != receipt.request_hash:
                    self._fail("native receipt does not match offered signed request")
                matched.add(receipt.query_id)
                latencies.append(now - row[1])
            for query in matched:
                del self.pending[query]
            for seconds in latencies:
                index = next(
                    (i for i, upper in enumerate(BUCKETS) if seconds <= upper), len(BUCKETS)
                )
                self.histogram[index] += 1
            self.finalized += len(receipts)
            progressed = self.seqno is None or seqno > self.seqno
            self.head, self.seqno = head, seqno
            if progressed:
                self.last_verified = now
            if observation_gap:
                self._fail("native proof observation stale", drainable=True)
            if latencies and max(latencies) > self.max_query_age:
                self._fail("native query observation overdue", drainable=True)
            if (
                self.slo_population == "completion-prefix"
                and self.finalized
                and (self._quantile(95) > self.p95_limit or self._quantile(99) > self.p99_limit)
            ):
                self._fail("native verified finality latency exceeds declared SLO", drainable=True)
            self._healthy(boot_id, now)

    def begin_stage(self, duration, *, boot_id, now):
        with self.guard:
            self._healthy(boot_id, now)
            if self.stage_start is not None or self.offered or self.sealed:
                self._fail("native stage start must precede offers exactly once")
            if (
                type(duration) not in (int, float)
                or not math.isfinite(duration)
                or duration <= 0
                or not math.isfinite(now + duration)
            ):
                self._fail("invalid native stage duration")
            self.stage_start, self.stage_deadline = now, now + duration

    def seal(self, *, boot_id, now):
        with self.guard:
            self._clock(boot_id, now, reconcile=True)
            if self.sealed:
                self._fail("native stage already sealed")
            self.sealed = True
            self.sealed_at = now

    def finish_stage(self, *, boot_id, now):
        with self.guard:
            self._clock(boot_id, now, reconcile=True)
            if not self.sealed or self.stage_finalized:
                self._fail("native stage must be sealed exactly once before final evaluation")
            self.stage_finalized = True
            if self.stage_deadline is None or self.sealed_at < self.stage_deadline:
                self._fail("native fixed stage duration incomplete", drainable=True)
            if not self.offered or self.pending or self.offered != self.finalized:
                self._fail("native final stage population incomplete", drainable=True)
            if self._quantile(95) > self.p95_limit or self._quantile(99) > self.p99_limit:
                self._fail(
                    "native verified final stage latency exceeds declared SLO", drainable=True
                )

    def summary(self):
        with self.guard:
            complete = self.offered > 0 and self.offered == self.finalized and not self.pending
            p95, p99 = self._quantile(95), self._quantile(99)
            return {
                "offered": self.offered,
                "native_finalized": self.finalized,
                "native_pending": len(self.pending),
                "failure": self.failure,
                "readonly_reconciliation_allowed": self.drainable_failure,
                "integrity_failure": self.integrity_failure,
                "all_offered_native_finalized": complete,
                "latency_criteria_pass": complete
                and self.failure is None
                and (self.slo_population == "completion-prefix" or self.stage_finalized),
                "slo_population": self.slo_population,
                "stage_sealed": self.sealed,
                "stage_finalized": self.stage_finalized,
                "stage_start_monotonic_seconds": self.stage_start,
                "stage_deadline_monotonic_seconds": self.stage_deadline,
                "latency_bucket_upper_seconds": [*BUCKETS, "infinity"],
                "histogram": list(self.histogram),
                "p95_upper_seconds": "infinity" if p95 == float("inf") else p95,
                "p99_upper_seconds": "infinity" if p99 == float("inf") else p99,
            }
