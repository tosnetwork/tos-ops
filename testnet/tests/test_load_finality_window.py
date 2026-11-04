import json
from dataclasses import replace
from pathlib import Path

import pytest
from load_finality import Head, HistoryError, decode_history
from load_finality_window import FinalityWindow

BOOT = "test-boot"
OLD = Head(1, "11" * 32)
NEW = Head(2, "22" * 32)


def window(**kwargs):
    w = FinalityWindow(BOOT, **kwargs)
    w.advance(10, OLD, OLD, (), boot_id=BOOT, now=100)
    return w


def public_segment():
    data = json.loads((Path(__file__).parent / "data/load-finality-public.json").read_text())
    old, new = Head(**data["previous"]), Head(**data["head"])
    receipts = decode_history(
        data["transactions"],
        verified_head=new,
        previous_head=old,
        wallet=data["wallet"],
        global_id=2,
        subwallet_id=4269,
        skipped_profile=True,
    )
    return old, new, receipts


def test_real_receipts_match_exact_offered_requests_and_latencies():
    old, new, receipts = public_segment()
    w = FinalityWindow(BOOT)
    w.advance(1, old, old, (), boot_id=BOOT, now=100)
    w.offer({r.query_id: r.request_hash for r in receipts}, boot_id=BOOT, now=101)
    w.advance(2, old, new, receipts, boot_id=BOOT, now=104)
    s = w.summary()
    assert s["all_offered_native_finalized"] and s["latency_criteria_pass"]
    assert s["native_finalized"] == 2 and s["native_pending"] == 0
    assert s["p95_upper_seconds"] == s["p99_upper_seconds"] == 3


def test_baseline_required_before_offer_and_failure_sticky():
    w = FinalityWindow(BOOT)
    with pytest.raises(HistoryError, match="baseline not established"):
        w.offer({1: "ab" * 32}, boot_id=BOOT, now=100)
    with pytest.raises(HistoryError, match="baseline not established"):
        w.advance(1, OLD, OLD, (), boot_id=BOOT, now=101)


@pytest.mark.parametrize("bad", [0, 8193, True])
def test_bounded_pending_parameter(bad):
    with pytest.raises(HistoryError, match="pending limit"):
        FinalityWindow(BOOT, max_pending=bad)


@pytest.mark.parametrize("bad", [0, float("inf"), float("nan"), True, 301])
def test_bounded_time_parameters(bad):
    with pytest.raises(HistoryError, match="bounded positive"):
        FinalityWindow(BOOT, max_proof_age=bad)


def test_capacity_and_seen_bitmap_remain_bounded():
    w = window(max_pending=2)
    w.offer({1: "ab" * 32, 2: "cd" * 32}, boot_id=BOOT, now=101)
    assert len(w.seen) == 1 << 20
    with pytest.raises(HistoryError, match="pending limit"):
        w.offer({3: "ef" * 32}, boot_id=BOOT, now=102)
    assert len(w.pending) == 2 and w.offered == 2


@pytest.mark.parametrize("query", [True, -1, 1023, 1 << 23])
def test_invalid_query_cannot_allocate_pending(query):
    w = window()
    with pytest.raises(HistoryError, match="query invalid"):
        w.offer({query: "ab" * 32}, boot_id=BOOT, now=101)
    assert not w.pending and w.offered == 0


def test_offer_batch_validation_is_atomic():
    w = window()
    with pytest.raises(HistoryError, match="digest invalid"):
        w.offer({1: "ab" * 32, 2: "bad"}, boot_id=BOOT, now=101)
    assert not w.pending and not any(w.seen)


def test_wrong_request_digest_is_not_query_id_success():
    old, new, receipts = public_segment()
    w = FinalityWindow(BOOT)
    w.advance(1, old, old, (), boot_id=BOOT, now=100)
    w.offer({r.query_id: r.request_hash for r in receipts}, boot_id=BOOT, now=101)
    bad = (receipts[0], replace(receipts[1], request_hash="ff" * 32))
    with pytest.raises(HistoryError, match="does not match offered signed request"):
        w.advance(2, old, new, bad, boot_id=BOOT, now=104)
    assert w.finalized == 0 and len(w.pending) == 2 and w.head == old


def test_reused_query_refused_after_native_completion():
    old, new, receipts = public_segment()
    w = FinalityWindow(BOOT)
    w.advance(1, old, old, (), boot_id=BOOT, now=100)
    hashes = {r.query_id: r.request_hash for r in receipts}
    w.offer(hashes, boot_id=BOOT, now=101)
    w.advance(2, old, new, receipts, boot_id=BOOT, now=104)
    with pytest.raises(HistoryError, match="query invalid or reused"):
        w.offer(hashes, boot_id=BOOT, now=105)


@pytest.mark.parametrize(
    "now,boot,message",
    [
        (111, BOOT, "proof observation stale"),
        (101, "rebooted", "boot identity changed"),
        (99, BOOT, "clock invalid or regressed"),
        (float("nan"), BOOT, "clock invalid or regressed"),
    ],
)
def test_observation_health_stops_admission(now, boot, message):
    w = window()
    with pytest.raises(HistoryError, match=message):
        w.healthy(boot_id=boot, now=now)
    with pytest.raises(HistoryError, match=message):
        w.offer({1: "ab" * 32}, boot_id=BOOT, now=112)


def test_refresh_cannot_hide_an_observation_gap():
    w = window()
    with pytest.raises(HistoryError, match="proof observation stale"):
        w.advance(11, OLD, OLD, (), boot_id=BOOT, now=111)
    assert w.failure is not None


def test_overdue_query_not_hidden_by_fresh_empty_proofs():
    w = window(max_query_age=5)
    w.offer({1: "ab" * 32}, boot_id=BOOT, now=101)
    w.advance(11, OLD, OLD, (), boot_id=BOOT, now=105)
    with pytest.raises(HistoryError, match="query observation overdue"):
        w.healthy(boot_id=BOOT, now=107)


def test_slow_authentic_receipts_settle_but_do_not_pass_latency():
    old, new, receipts = public_segment()
    w = FinalityWindow(BOOT)
    w.advance(1, old, old, (), boot_id=BOOT, now=100)
    w.offer({r.query_id: r.request_hash for r in receipts}, boot_id=BOOT, now=101)
    with pytest.raises(HistoryError, match="latency exceeds declared SLO"):
        w.advance(2, old, new, receipts, boot_id=BOOT, now=107)
    s = w.summary()
    assert s["all_offered_native_finalized"] and not s["latency_criteria_pass"]
    assert s["native_pending"] == 0 and s["p95_upper_seconds"] == 10


@pytest.mark.parametrize(
    "seq,old,new",
    [
        (9, OLD, NEW),
        (11, NEW, NEW),
        (11, OLD, Head(0, "00" * 32)),
        (11, OLD, Head(1, "ff" * 32)),
        (10, OLD, NEW),
    ],
)
def test_checkpoint_continuity(seq, old, new):
    w = window()
    with pytest.raises(HistoryError, match="continuity mismatch"):
        w.advance(seq, old, new, (), boot_id=BOOT, now=101)


def test_empty_window_is_not_an_acceptance_pass():
    assert not window().summary()["latency_criteria_pass"]


def test_overflow_latency_report_is_strict_json():
    old, new, receipts = public_segment()
    w = FinalityWindow(BOOT)
    w.advance(1, old, old, (), boot_id=BOOT, now=100)
    w.offer({r.query_id: r.request_hash for r in receipts}, boot_id=BOOT, now=101)
    with pytest.raises(HistoryError, match="proof observation stale"):
        w.advance(2, old, new, receipts, boot_id=BOOT, now=500)
    assert w.summary()["p99_upper_seconds"] == "infinity"
    json.dumps(w.summary(), allow_nan=False)
