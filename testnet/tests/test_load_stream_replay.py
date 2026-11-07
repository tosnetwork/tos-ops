"""Real journal/index/history paths, fake native boundary; not crypto evidence."""

import json
from pathlib import Path

import load_run_replay as batch
import load_stream_replay as live
import pytest
from load_finality import HistoryError
from test_load_run_replay import closed_run as closed_run
from test_load_run_replay import fixed_stage_case, store, write_events


class Index:
    def __init__(self):
        self.rows = []

    def add(self, value):
        self.rows.append(value)


def test_partial_append_is_not_copied_or_indexed_until_newline(tmp_path):
    source, copy = tmp_path / "events.jsonl", tmp_path / "copy.jsonl"
    source.write_bytes(b'{"event":"first"}\n{"event":')
    index = Index()
    journal = live.AppendJournal(source, copy)
    try:
        assert journal.pump(index) == 1 and index.rows == [{"event": "first"}]
        assert copy.read_bytes() == b'{"event":"first"}\n'
        with pytest.raises(HistoryError, match="partial final event"):
            journal.seal()
        with source.open("ab") as stream:
            stream.write(b'"second"}\n')
        assert journal.pump(index) == 1
        assert index.rows[-1] == {"event": "second"}
        assert journal.seal() == batch.digest(source.read_bytes())
        assert copy.read_bytes() == source.read_bytes()
    finally:
        journal.close()


@pytest.mark.parametrize("kind", ["truncate", "replace", "rewrite", "oversize"])
def test_journal_source_mutations_cannot_become_complete(tmp_path, kind):
    source = tmp_path / "events.jsonl"
    source.write_bytes(b'{"event":"first"}\n')
    journal = live.AppendJournal(source, tmp_path / "copy.jsonl")
    try:
        journal.pump(Index())
        if kind == "truncate":
            source.write_bytes(b"")
        elif kind == "replace":
            source.unlink()
            source.write_bytes(b'{"event":"first"}\n')
        elif kind == "rewrite":
            source.write_bytes(b'{"event":"other"}\n')
        else:
            with source.open("ab") as stream:
                stream.write(b"x" * (live.MIB + 1))
        with pytest.raises(HistoryError):
            if kind in ("truncate", "replace", "oversize"):
                journal.pump(Index())
            else:
                journal.seal()
    finally:
        journal.close()


@pytest.fixture
def stream_case(request, monkeypatch):
    case = request.getfixturevalue("closed_run")
    for name in ("NativeReplay", "RetainedPrefix", "TlGenerator"):
        monkeypatch.setattr(live, name, getattr(batch, name))
    case.args.max_seconds = case.args.idle_seconds = 5
    case.args.summary = str(case.run.parent / "summary-20000101T000000Z.json")
    store(Path(case.args.summary), case.summary)
    return case


def test_complete_existing_closed_corpus(stream_case):
    case = stream_case
    result = live.run(case.args)
    assert (
        result["status"] == "FULL_STREAMED_CLOSED_RUN_PROOF_HISTORY_DIGEST_CLOCK_COVERAGE_VERIFIED"
    )
    assert case.calls == [0, 1, 2] and result["offered"] == 2
    assert result["events_sha256"] == batch.digest((case.run / "events.jsonl").read_bytes())


def test_verifies_incremental_events_before_close_without_publishing_success(
    stream_case, monkeypatch
):
    case = stream_case
    journal = case.run / "events.jsonl"
    all_lines = journal.read_bytes().splitlines(keepends=True)
    journal.write_bytes(all_lines[0])
    marker = case.run.parent / "qualification-active.json"
    store(marker, {"run": case.run.name, "closed": False})
    transitions = []

    def producer(_seconds):
        assert not (Path(case.args.output) / "RESULT.json").exists()
        if not transitions:
            assert case.calls == [0, 1]
            with journal.open("ab") as stream:
                stream.write(b"".join(all_lines[1:]))
            transitions.append("append")
        else:
            assert case.calls == [0, 1, 2]
            progress = json.loads((Path(case.args.output) / "PROGRESS.json").read_text())
            assert progress["status"] == "LIVE_COVERAGE_NOT_ACCEPTED"
            store(marker, {"run": case.run.name, "closed": True})
            transitions.append("close")

    monkeypatch.setattr(live.time, "sleep", producer)
    assert live.run(case.args)["offered"] == 2
    assert transitions == ["append", "close"]


def test_completed_proofs_do_not_override_original_open_marker(stream_case, monkeypatch):
    case = stream_case
    store(case.run.parent / "qualification-active.json", {"run": case.run.name, "closed": False})

    def still_open(_seconds):
        assert case.calls == [0, 1, 2]
        assert not (Path(case.args.output) / "RESULT.json").exists()
        raise RuntimeError("original remains open")

    monkeypatch.setattr(live.time, "sleep", still_open)
    with pytest.raises(RuntimeError, match="original remains open"):
        live.run(case.args)
    assert not (Path(case.args.output) / "RESULT.json").exists()


def test_final_index_validation_must_not_rewind_verified_observation_clock(
    stream_case, monkeypatch
):
    case = stream_case
    fixed_stage_case(case)
    case.events[-2]["sealed_monotonic_seconds"] = 2.3
    case.events[-1]["finalized_monotonic_seconds"] = 2.4  # Last proven observation is 2.5.
    write_events(case)
    with pytest.raises(HistoryError, match="final population verdict or clock"):
        live.run(case.args)
    assert not (Path(case.args.output) / "RESULT.json").exists()
    # Mutation control: reusing the batch initializer without preserving the
    # streaming clock would admit this contradictory final event.
    monkeypatch.setattr(live, "validate_complete_index", lambda index: index.finish_index())
    case.args.output += "-mutant"
    assert live.run(case.args)["offered"] == 2


@pytest.mark.parametrize(
    "field,value", [("pending", 1), ("safe_to_start_new_run", False), ("funding_unknown", True)]
)
def test_unsafe_original_summary_is_not_coverage_success(stream_case, field, value):
    case = stream_case
    case.summary["qualification"][field] = value
    store(Path(case.args.summary), case.summary)
    with pytest.raises(HistoryError, match="closed reconciled source"):
        live.run(case.args)
    assert not (Path(case.args.output) / "RESULT.json").exists()


def test_empty_partial_and_symlink_summary_controls(stream_case):
    case = stream_case
    path = Path(case.args.summary)
    path.write_bytes(b"")
    assert live.find_summary(case.run) is None
    path.write_bytes(b'{"qualification":')
    assert live.find_summary(case.run) is None
    target = path.with_suffix(".target")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(HistoryError, match="summary type/size"):
        live.find_summary(case.run)


@pytest.mark.parametrize("field,value", [("max_seconds", float("nan")), ("idle_seconds", 0)])
def test_unbounded_or_invalid_horizon_refused_before_output(stream_case, field, value):
    setattr(stream_case.args, field, value)
    with pytest.raises(HistoryError):
        live.run(stream_case.args)
    assert not Path(stream_case.args.output).exists()


def test_output_parent_alias_cannot_write_into_original_run(stream_case):
    case = stream_case
    alias = case.run.parent / "output-alias"
    alias.symlink_to(case.run, target_is_directory=True)
    case.args.output = str(alias / "new-output")
    with pytest.raises(HistoryError, match="canonical output"):
        live.run(case.args)
    assert not (case.run / "new-output").exists()


def test_original_event_rewrite_during_native_work_refuses_completion(stream_case, monkeypatch):
    case = stream_case
    original = live.replay_capture

    def changed(*args):
        result = original(*args)
        if args[1] == 2:
            path = case.run / "events.jsonl"
            raw = path.read_bytes()
            assert b'"monotonic_seconds": 1.1' in raw
            path.write_bytes(raw.replace(b'"monotonic_seconds": 1.1', b'"monotonic_seconds": 1.2'))
        return result

    monkeypatch.setattr(live, "replay_capture", changed)
    with pytest.raises(HistoryError, match="original event prefix changed"):
        live.run(case.args)
    assert not (Path(case.args.output) / "RESULT.json").exists()


def test_journal_changed_after_hash_is_not_silently_accepted(stream_case, monkeypatch):
    case = stream_case
    original = live.AppendJournal.seal

    def append_after_seal(self):
        result = original(self)
        with self.path.open("ab") as stream:
            stream.write(b'{"event":"unexpected"}\n')
        return result

    monkeypatch.setattr(live.AppendJournal, "seal", append_after_seal)
    with pytest.raises(HistoryError, match="changed after final hash"):
        live.run(case.args)
    assert not (Path(case.args.output) / "RESULT.json").exists()


def test_public_directory_is_durable_before_native_work(stream_case, monkeypatch):
    case = stream_case
    synced = []
    original = live.NativeReplay

    class NativeAfterDurability(original):
        def __init__(self, *args):
            assert Path(case.args.output) / "public" in synced, (
                "public context directory not fsynced"
            )
            super().__init__(*args)

    monkeypatch.setattr(live, "sync_directory", lambda path: synced.append(path), raising=False)
    monkeypatch.setattr(live, "NativeReplay", NativeAfterDurability)
    assert live.run(case.args)["offered"] == 2


def test_event_copy_close_error_still_releases_original_descriptor(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_bytes(b"{}\n")
    journal = live.AppendJournal(source, tmp_path / "copy.jsonl")
    original = journal.copy

    class BrokenCopy:
        def close(self):
            original.close()
            raise OSError("injected copy close error")

    journal.copy = BrokenCopy()
    with pytest.raises(OSError, match="copy close error"):
        journal.close()
    assert journal.source.closed


@pytest.mark.parametrize("changed", ["journal", "summary", "marker", "anchor", "capture"])
def test_final_source_checks_follow_result_file_fsync(stream_case, monkeypatch, changed):
    case = stream_case
    original = live.os.fsync
    injected = []

    def fsync(fd):
        name = Path(live.os.readlink(f"/proc/self/fd/{fd}")).name
        if name.startswith("RESULT.json.") and not injected:
            injected.append(changed)
            if changed == "journal":
                with (case.run / "events.jsonl").open("ab") as stream:
                    stream.write(b'{"event":"admission_stopped"}\n')
            elif changed == "summary":
                case.summary["qualification"]["pending"] = 1
                store(Path(case.args.summary), case.summary)
            elif changed == "marker":
                store(
                    case.run.parent / "qualification-active.json",
                    {"run": case.run.name, "closed": False},
                )
            elif changed == "anchor":
                Path(case.args.anchor).write_bytes(b'{"changed":true}\n')
            else:
                (case.run / "native-captures/capture-000003").mkdir()
        return original(fd)

    monkeypatch.setattr(live.os, "fsync", fsync)
    with pytest.raises(HistoryError):
        live.run(case.args)
    assert injected == [changed]
    assert not (Path(case.args.output) / "RESULT.json").exists()
