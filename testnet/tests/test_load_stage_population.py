"""Explicit final-population policy never changes legacy admission defaults."""

from dataclasses import replace

import pytest
from load_finality import Head, HistoryError
from load_finality_window import FinalityWindow
from test_load_finality_window import BOOT, public_segment


def stage():
    old, new, receipts = public_segment()
    w = FinalityWindow(BOOT, slo_population="fixed-stage")
    w.advance(1, old, old, (), boot_id=BOOT, now=100)
    w.begin_stage(10, boot_id=BOOT, now=100)
    return w, old, new, receipts[0]


def test_early_outlier_requires_seal_and_final_population():
    w, old, new, receipt = stage()
    w.offer({1: receipt.request_hash}, boot_id=BOOT, now=101)
    w.advance(2, old, new, [replace(receipt, query_id=1)], boot_id=BOOT, now=109)
    assert w.summary()["p95_upper_seconds"] == 10
    assert not w.summary()["latency_criteria_pass"]
    hashes = {q: receipt.request_hash for q in range(2, 91)}
    w.offer(hashes, boot_id=BOOT, now=109)
    last = Head(new.lt + 1, "ab" * 32)
    w.advance(3, new, last, [replace(receipt, query_id=q) for q in hashes], boot_id=BOOT, now=110)
    assert not w.summary()["latency_criteria_pass"]
    w.seal(boot_id=BOOT, now=110)
    w.finish_stage(boot_id=BOOT, now=110)
    assert w.summary()["latency_criteria_pass"]
    assert w.summary()["stage_finalized"]
    with pytest.raises(HistoryError, match="sealed"):
        w.offer({91: receipt.request_hash}, boot_id=BOOT, now=110)


@pytest.mark.parametrize("pending", [False, True])
def test_empty_or_pending_final_population_refused(pending):
    w, _, _, r = stage()
    if pending:
        w.offer({1: r.request_hash}, boot_id=BOOT, now=101)
    w.seal(boot_id=BOOT, now=101)
    with pytest.raises(HistoryError, match="incomplete"):
        w.finish_stage(boot_id=BOOT, now=101)
    assert not w.summary()["latency_criteria_pass"]


def test_final_slo_failure_is_sticky():
    w, old, new, r = stage()
    w.offer({1: r.request_hash}, boot_id=BOOT, now=101)
    w.advance(2, old, new, [replace(r, query_id=1)], boot_id=BOOT, now=109)
    w.seal(boot_id=BOOT, now=110)
    with pytest.raises(HistoryError, match="SLO"):
        w.finish_stage(boot_id=BOOT, now=110)
    assert not w.summary()["latency_criteria_pass"]


def test_fixed_stage_does_not_waive_query_age():
    w, old, new, r = stage()
    w.offer({1: r.request_hash}, boot_id=BOOT, now=101)
    # Keep native observations current while original request remains pending.
    w.advance(2, old, old, (), boot_id=BOOT, now=109)
    w.advance(3, old, old, (), boot_id=BOOT, now=118)
    w.advance(4, old, old, (), boot_id=BOOT, now=127)
    with pytest.raises(HistoryError, match="overdue"):
        w.advance(5, old, new, [replace(r, query_id=1)], boot_id=BOOT, now=132)


def test_fixed_stage_requires_seal_before_final_evaluation():
    w, _, _, _ = stage()
    with pytest.raises(HistoryError, match="sealed"):
        w.finish_stage(boot_id=BOOT, now=100)


def test_fixed_stage_deadline_refuses_original_population_extension():
    w, _, _, r = stage()
    with pytest.raises(HistoryError, match="interval not open"):
        w.offer({1: r.request_hash}, boot_id=BOOT, now=110)
    assert w.offered == 0


def test_fixed_stage_early_seal_cannot_pass():
    w, old, new, r = stage()
    w.offer({1: r.request_hash}, boot_id=BOOT, now=101)
    w.advance(2, old, new, [replace(r, query_id=1)], boot_id=BOOT, now=102)
    w.seal(boot_id=BOOT, now=102)
    with pytest.raises(HistoryError, match="duration incomplete"):
        w.finish_stage(boot_id=BOOT, now=102)
    assert not w.summary()["latency_criteria_pass"]
