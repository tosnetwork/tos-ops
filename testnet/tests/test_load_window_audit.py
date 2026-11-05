"""Window mathematics with real SQLite; fake proof-result boundary, no crypto claim."""

# These fixtures exercise the real journal/reader/index pipeline with an explicitly
# fake native boundary, as in the existing replay tests.
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import load_stream_replay as live
import load_window_audit as audit
import pytest
from load_finality import HistoryError
from load_run_replay import EventIndex
from test_load_run_replay import closed_run as closed_run
from test_load_run_replay import fixed_stage_case, store
from test_load_stream_replay import stream_case as stream_case


def sample(tmp_path, *, slow=None, missing=None, duplicate=False, boot=False, latency=1):
    index = EventIndex(tmp_path / "index.sqlite", tmp_path / "qualification-1")
    index.stage_started = {"started_monotonic_seconds": 100, "duration_seconds": 100}
    index.baseline = {"verified_observation_monotonic_seconds": 99, "boot_id": "one"}
    completions = []
    histogram = [0] * (len(audit.BUCKETS) + 1)
    for query in range(100):
        offered = 100 + query
        delay = 20 if query == slow else latency
        index.db.execute(
            "INSERT INTO offers(q,digest,clock,boot) VALUES(?,?,?,?)",
            (query, "00" * 32, offered, "one"),
        )
        if query != missing:
            completions.append((offered + delay, query))
            histogram[
                next(
                    (i for i, upper in enumerate(audit.BUCKETS) if delay <= upper),
                    len(audit.BUCKETS),
                )
            ] += 1
    completions.sort()
    if duplicate:
        completions.append((1000, 0))
    for number, (observed, query) in enumerate(completions):
        event = {
            "verified_observation_monotonic_seconds": observed,
            "boot_id": "other" if boot else "one",
            "query_ids": [query],
        }
        index.db.execute(
            "INSERT INTO checkpoints(number,event) VALUES(?,?)", (number, json.dumps(event))
        )
    index.offers = 100
    return (
        index,
        {"offered": 100, "recomputed_histogram": histogram},
        {"target_batches_per_second": 1, "qualification": {"offered": 100}},
    )


def test_all_windows_pass_and_exact_boundary_goes_to_next_window(tmp_path):
    index, result, summary = sample(tmp_path)
    try:
        report = audit.calculate(index, result, summary, 10)
        assert report["status"] == "DERIVED_WINDOWS_PASS"
        assert [w["offered"] for w in report["windows"]] == [10] * 10
        assert all(w["p99_upper_seconds"] == 1 for w in report["windows"])
    finally:
        index.close()


def test_whole_run_percentiles_can_hide_one_bad_window(tmp_path):
    index, result, summary = sample(tmp_path, slow=9)
    try:
        assert audit.quantile(result["recomputed_histogram"], 0.99) == 1
        report = audit.calculate(index, result, summary, 10)
        assert report["status"] == "DERIVED_WINDOWS_FAIL"
        assert report["windows"][0]["p95_upper_seconds"] == 20
        assert sum(not w["pass"] for w in report["windows"]) == 1
    finally:
        index.close()


@pytest.mark.parametrize(
    "change", ["missing", "duplicate", "boot", "histogram", "population", "target"]
)
def test_incomplete_or_spliced_population_refused(tmp_path, change):
    options = (
        {"missing": 1}
        if change == "missing"
        else {change: True}
        if change in ("duplicate", "boot")
        else {}
    )
    index, result, summary = sample(tmp_path, **options)
    if change == "histogram":
        result["recomputed_histogram"][0] += 1
    if change == "population":
        result["offered"] += 1
    if change == "target":
        summary["target_batches_per_second"] = float("nan")
    try:
        with pytest.raises(HistoryError):
            audit.calculate(index, result, summary, 10)
    finally:
        index.close()


@pytest.mark.parametrize("window", [0, -1, True, 3, 3601])
def test_incomplete_window_partition_refused(tmp_path, window):
    index, result, summary = sample(tmp_path)
    try:
        with pytest.raises(HistoryError):
            audit.calculate(index, result, summary, window)
    finally:
        index.close()


def test_infinite_tail_is_failed_report(tmp_path):
    index, result, summary = sample(tmp_path, latency=500)
    try:
        report = audit.calculate(index, result, summary, 10)
        assert report["status"] == "DERIVED_WINDOWS_FAIL"
        assert report["windows"][0]["p99_upper_seconds"] == "infinity"
    finally:
        index.close()


@pytest.mark.parametrize("change", ["valid", "pin", "journal", "summary", "provisional"])
def test_pinned_closed_reader_artifact_boundary(request, change):
    c = request.getfixturevalue("stream_case")
    fixed_stage_case(c)
    c.summary["target_batches_per_second"] = 2
    store(Path(c.args.summary), c.summary)
    live.run(c.args)
    result_path = Path(c.args.output) / "RESULT.json"
    if change == "provisional":
        result = json.loads(result_path.read_text())
        result["status"] = "LIVE_COVERAGE_NOT_ACCEPTED"
        store(result_path, result)
    pin = hashlib.sha256(result_path.read_bytes()).hexdigest()
    if change == "pin":
        pin = "00" * 32
    if change == "journal":
        with (c.run / "events.jsonl").open("a") as stream:
            stream.write("{}\n")
    if change == "summary":
        with Path(c.args.summary).open("a") as stream:
            stream.write(" ")
    args = SimpleNamespace(
        run=c.run,
        summary=Path(c.args.summary),
        replay_result=result_path,
        replay_result_sha256=pin,
        output=c.run.parent / "windows",
        window_seconds=1,
    )
    if change == "valid":
        assert audit.audit(args)["offered"] == 2
    else:
        with pytest.raises(HistoryError):
            audit.audit(args)
