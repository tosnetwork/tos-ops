"""Acquisition boundary tests; stub proofs are NOT cryptographic verification."""

import base64
import errno
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import load_finality_collector as collector
import pytest
from load_finality import Head, HistoryError
from pytosiq_core import Builder, Cell, Transaction


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def configured(tmp_path, monkeypatch):
    # Stub host capacity for acquisition-unit tests, not for the live probe.
    monkeypatch.setattr(collector.shutil, "disk_usage", lambda _: SimpleNamespace(free=100 << 30))
    public = json.loads((Path(__file__).parent / "data/load-finality-public.json").read_text())
    anchor, lite = tmp_path / "anchor", tmp_path / "lite"
    anchor.write_text("{}")
    lite.write_text("{}")
    binary = Path(shutil.which("true")).resolve()
    args = dict(
        verifier=binary,
        verifier_sha256=digest(binary.read_bytes()),
        anchor=anchor,
        anchor_sha256=digest(anchor.read_bytes()),
        liteserver=lite,
        rpc="http://127.0.0.1:8081/jsonRPC",
        directory=tmp_path / "captures",
        wallet=public["wallet"],
        code_hash="cc" * 32,
        global_id=2,
        global_version=16,
        subwallet_id=4269,
    )
    return args, public


def fake_boundary(c, public, *, edit=None, rows=None):
    proof = {
        "status": "verified",
        "account": {
            "address": public["wallet"],
            "active": True,
            "code_hash": "cc" * 32,
            "last_trans_lt": public["head"]["lt"],
            "last_trans_hash": public["head"]["hash"],
        },
        "config_params": [
            {
                "index": 8,
                "boc": base64.b64encode(
                    Builder()
                    .store_uint(0xC4, 8)
                    .store_uint(16, 32)
                    .store_uint(0, 64)
                    .end_cell()
                    .to_boc()
                ).decode(),
            },
            {
                "index": 19,
                "boc": base64.b64encode(Builder().store_int(2, 32).end_cell().to_boc()).decode(),
            },
        ],
        "target": {"seqno": 99, "gen_utime": int(time.time())},
    }
    if edit:
        edit(proof)

    def run(argv, output, error, deadline, directory, *, native=False):
        assert time.monotonic() < deadline
        assert native and argv[0] == f"/proc/self/fd/{c.native_fd}"
        assert "--state" in argv and "--save-material" in argv
        request = json.loads((directory / "request.json").read_text())
        assert request["mode"] == "live" and request["max_age_seconds"] == c.max_age
        collector.write_file(output, json.dumps(proof).encode())
        collector.write_file(error, b"")
        state = directory / "native-state.json"
        if not state.exists():
            collector.write_file(state, b"{}")

    c._run = run
    c._rpc_page = lambda *_: [
        {"data": x} for x in (public["transactions"] if rows is None else rows)
    ]


def test_real_public_segment_after_stub_acquisition(configured):
    args, public = configured
    c = collector.NativeCollector(**args)
    try:
        fake_boundary(c, public)
        captured = c.capture(Head(**public["previous"]))
        assert [r.query_id for r in captured.receipts] == [1566, 1565]
        assert captured.head == Head(**public["head"])
        assert captured.completed_monotonic <= time.monotonic()
        assert (captured.directory / "result.json").is_file()
        assert c.retained > 0
    finally:
        c.close()
    with pytest.raises(HistoryError, match="collector closed"):
        c.capture()


def test_initial_baseline_does_not_fetch_old_history(configured):
    args, public = configured
    c = collector.NativeCollector(**args)
    try:
        fake_boundary(c, public)
        c._rpc_page = lambda *_: pytest.fail("baseline must not fetch old unbound history")
        captured = c.capture()
        assert captured.receipts == () and captured.previous_head == captured.head
    finally:
        c.close()


@pytest.mark.parametrize("field", ["verifier_sha256", "anchor_sha256"])
def test_wrong_pins_fail_before_capture(configured, field):
    args, _ = configured
    args[field] = "ff" * 32
    with pytest.raises(HistoryError, match="hash mismatch"):
        collector.NativeCollector(**args)


def test_existing_root_cannot_resume_or_rebaseline(configured):
    args, _ = configured
    Path(args["directory"]).mkdir()
    with pytest.raises(FileExistsError):
        collector.NativeCollector(**args)


@pytest.mark.parametrize(
    "url", ["file:///tmp/test", "http://user:secret@localhost/", "http://localhost/?token=test"]
)
def test_credentials_and_non_http_urls_refused(configured, url):
    args, _ = configured
    args["rpc"] = url
    with pytest.raises(HistoryError, match="public RPC URL"):
        collector.NativeCollector(**args)


@pytest.mark.parametrize(
    "change,message",
    [
        (lambda p: p.update(status="refused"), "not verified"),
        (lambda p: p["account"].update(code_hash="dd" * 32), "code identity"),
        (lambda p: p["account"].update(active=False), "code identity"),
        (lambda p: p["target"].update(gen_utime=int(time.time()) - 100), "checkpoint too old"),
    ],
)
def test_unacceptable_native_result_never_returns_progress(configured, change, message):
    args, public = configured
    c = collector.NativeCollector(**args)
    try:
        fake_boundary(c, public, edit=change)
        with pytest.raises(HistoryError, match=message):
            c.capture(Head(**public["previous"]))
        assert not (c.root / "capture-000000/result.json").exists()
    finally:
        c.close()


def test_rpc_wrong_order_fails_before_progress(configured):
    args, public = configured
    c = collector.NativeCollector(**args)
    try:
        fake_boundary(c, public, rows=public["transactions"][::-1])
        with pytest.raises(HistoryError, match="does not match native head"):
            c.capture(Head(**public["previous"]))
    finally:
        c.close()


def test_storage_and_count_guards_precede_native_process(configured):
    args, public = configured
    c = collector.NativeCollector(**args, max_captures=1)
    try:
        fake_boundary(c, public)
        c.capture()
        with pytest.raises(HistoryError, match="retention budget"):
            c.capture()
    finally:
        c.close()


def test_capture_symlink_never_counts_as_retained_evidence(tmp_path):
    (tmp_path / "link").symlink_to("/etc/passwd")
    with pytest.raises(HistoryError, match="symlink refused"):
        collector.capture_size(tmp_path)


def test_sealed_bytes_survive_path_replacement_and_refuse_writes(tmp_path):
    path = tmp_path / "program"
    original = Path(shutil.which("true")).resolve().read_bytes()
    path.write_bytes(original)
    fd = collector.seal_executable(path, digest(original))
    try:
        path.write_bytes(Path(shutil.which("false")).resolve().read_bytes())
        result = subprocess.run([f"/proc/self/fd/{fd}"], pass_fds=(fd,), timeout=5)
        assert result.returncode == 0
        with pytest.raises(OSError) as failure:
            os.write(fd, b"mutation")
        assert failure.value.errno == errno.EPERM
    finally:
        os.close(fd)


def test_owned_subprocess_timeout_is_cleaned_up(configured, tmp_path, monkeypatch):
    args, _ = configured
    c = collector.NativeCollector(**args)
    directory = tmp_path / "timeout"
    directory.mkdir()
    processes = []
    actual_popen = subprocess.Popen

    def tracked(*args, **kwargs):
        process = actual_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(collector.subprocess, "Popen", tracked)
    try:
        with pytest.raises(HistoryError, match="deadline expired"):
            c._run(
                [shutil.which("sleep"), "10"],
                directory / "out",
                directory / "err",
                time.monotonic() + 0.1,
                directory,
            )
    finally:
        c.close()
    assert len(processes) == 1 and processes[0].poll() is not None


def test_failed_oversized_capture_exhausts_budget(configured):
    args, public = configured
    c = collector.NativeCollector(**args)
    try:
        fake_boundary(c, public)
        original = c._run

        def oversized(*args, **kwargs):
            original(*args, **kwargs)
            with (args[4] / "oversized").open("wb") as output:
                output.truncate(collector.MAX_CAPTURE + 1)

        c._run = oversized
        with pytest.raises(HistoryError, match="capture storage limit"):
            c.capture()
        assert c.retained == c.storage_budget
        with pytest.raises(HistoryError, match="retention budget"):
            c.capture()
    finally:
        c.close()


def test_multiple_pages_and_state_carry_forward(configured):
    args, public = configured
    c = collector.NativeCollector(**args)
    pages = []
    try:
        fake_boundary(c, public)

        def page(_path, _cursor, index, _deadline):
            pages.append(index)
            return [{"data": public["transactions"][index]}]

        c._rpc_page = page
        c.capture(Head(**public["previous"]))
        c.capture(Head(**public["head"]))
        assert pages == [0, 1]
        assert (c.root / "capture-000001/native-state.json").read_text() == "{}"
    finally:
        c.close()


def test_free_space_guard_precedes_proof_process(configured, monkeypatch):
    args, public = configured
    c = collector.NativeCollector(**args)
    fake_boundary(c, public)
    monkeypatch.setattr(
        collector.shutil, "disk_usage", lambda _: SimpleNamespace(free=collector.MIN_FREE - 1)
    )
    try:
        with pytest.raises(HistoryError, match="free-space guard"):
            c.capture()
        assert c.captures == 0
    finally:
        c.close()


def test_free_inode_guard_precedes_proof_process(configured, monkeypatch):
    args, public = configured
    c = collector.NativeCollector(**args)
    fake_boundary(c, public)
    monkeypatch.setattr(
        collector.os, "statvfs", lambda _: SimpleNamespace(f_favail=collector.MIN_FREE_INODES - 1)
    )
    try:
        with pytest.raises(HistoryError, match="free-inode guard"):
            c.capture()
        assert c.captures == 0
    finally:
        c.close()


def test_kernel_per_file_output_limit(configured, tmp_path):
    args, _ = configured
    c = collector.NativeCollector(**args)
    directory = tmp_path / "output-limit"
    directory.mkdir()
    try:
        with pytest.raises(HistoryError, match="subprocess refused"):
            c._run(
                [shutil.which("head"), "-c", str(collector.MAX_OUTPUT + 1), "/dev/zero"],
                directory / "out",
                directory / "err",
                time.monotonic() + 5,
                directory,
            )
        assert (directory / "out").stat().st_size <= collector.MAX_OUTPUT
    finally:
        c.close()


def test_empty_rpc_page_refused_at_acquisition_boundary(configured, tmp_path):
    args, _ = configured
    c = collector.NativeCollector(**args)
    path = tmp_path / "rpc-page"
    path.mkdir()

    def response(_argv, output, error, *_):
        collector.write_file(output, b'{"result":[]}')
        collector.write_file(error, b"")

    c._run = response
    try:
        with pytest.raises(HistoryError, match="bounded RPC history page"):
            c._rpc_page(path, Head(1, "11" * 32), 0, time.monotonic() + 5)
    finally:
        c.close()


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("global_id", 3, "native global id mismatch"),
        ("global_version", 17, "native global version mismatch"),
    ],
)
def test_native_network_policy_is_checked(configured, field, value, message):
    args, public = configured
    args[field] = value
    c = collector.NativeCollector(**args)
    try:
        fake_boundary(c, public)
        with pytest.raises(HistoryError, match=message):
            c.capture()
    finally:
        c.close()


def test_default_second_capture_cannot_silently_rebaseline(configured):
    args, public = configured
    older = Transaction.deserialize(
        Cell.one_from_boc(base64.b64decode(public["transactions"][1])).begin_parse()
    )
    middle = {"lt": older.lt, "hash": older.cell.hash.hex()}
    c = collector.NativeCollector(**args)
    try:
        fake_boundary(c, dict(public, head=middle))
        first = c.capture()
        fake_boundary(c, public)
        second = c.capture()
        assert second.previous_head == first.head
        assert [r.query_id for r in second.receipts] == [1566]
    finally:
        c.close()


def test_explicit_mismatched_previous_head_refused_before_acquisition(configured):
    args, public = configured
    c = collector.NativeCollector(**args)
    try:
        fake_boundary(c, public)
        c.capture()
        with pytest.raises(HistoryError, match="does not match last success"):
            c.capture(Head(**public["previous"]))
        assert c.captures == 1
    finally:
        c.close()


def test_final_retention_scan_counts_toward_age_and_deadline(configured, monkeypatch):
    args, public = configured
    c = collector.NativeCollector(**args)
    wall = 1700000000
    fake_boundary(c, public, edit=lambda p: p["target"].update(gen_utime=wall))
    elapsed, scans = [0], [0]
    monkeypatch.setattr(collector.time, "time", lambda: wall + elapsed[0])
    monkeypatch.setattr(collector.time, "monotonic", lambda: 100 + elapsed[0])
    actual_size = collector.capture_size

    def slow_final_scan(path):
        size = actual_size(path)
        scans[0] += 1
        if scans[0] == 2:
            elapsed[0] += 11
        return size

    monkeypatch.setattr(collector, "capture_size", slow_final_scan)
    try:
        with pytest.raises(HistoryError, match="expired during persistence"):
            c.capture()
        assert scans[0] == 2 and c.retained > 0
        assert c.last_head is None and c.state_source is None
    finally:
        c.close()


def test_reported_completion_is_the_exact_deadline_checked_value(configured, monkeypatch):
    args, public = configured
    c = collector.NativeCollector(**args)
    fake_boundary(c, public)
    post_scan, clock_reads, scans = [False], [0], [0]
    actual_size = collector.capture_size

    def clock():
        if not post_scan[0]:
            return 100
        clock_reads[0] += 1
        return 107.99 if clock_reads[0] == 1 else 108.01

    def final_scan(path):
        result = actual_size(path)
        scans[0] += 1
        if scans[0] == 2:
            post_scan[0] = True
        return result

    monkeypatch.setattr(collector, "capture_size", final_scan)
    monkeypatch.setattr(collector.time, "monotonic", clock)
    try:
        captured = c.capture()
        assert captured.completed_monotonic < 108
        assert clock_reads[0] == 1
    finally:
        c.close()


def test_internal_rpc_error_uses_confirm_endpoint_once(configured, tmp_path):
    args, _ = configured
    c = collector.NativeCollector(**args, confirm_rpc="http://127.0.0.1:8083/jsonRPC")
    path = tmp_path / "rpc-page"
    path.mkdir()
    calls = []
    deadline = time.monotonic() + 5

    def response(argv, output, error, end, _directory):
        calls.append((argv[-1], end))
        value = (
            {
                "error": {
                    "code": -32603,
                    "message": "possibly out of sync",
                    "data": {"retryable": False},
                }
            }
            if len(calls) == 1
            else {"result": [{"data": "untrusted-BOC"}]}
        )
        collector.write_file(output, json.dumps(value).encode())
        collector.write_file(error, b"")

    c._run = response
    try:
        assert c._rpc_page(path, Head(1, "11" * 32), 0, deadline) == [{"data": "untrusted-BOC"}]
        assert calls == [(args["rpc"], deadline), ("http://127.0.0.1:8083/jsonRPC", deadline)]
        assert (
            json.loads((path / "rpc-failover/page-0.json").read_text())["error"]["code"] == -32603
        )
        assert json.loads((path / "rpc-0.json").read_text())["result"] == [
            {"data": "untrusted-BOC"}
        ]
        assert json.loads((path / "rpc-0.request.json").read_text())["params"]["lt"] == "1"
    finally:
        c.close()


@pytest.mark.parametrize(
    "first",
    [
        {"result": []},
        {"result": {}},
        {"error": {"code": -32602}},
        {"error": {"code": -32603}, "result": []},
    ],
)
def test_non_internal_or_malformed_pages_do_not_fail_over(configured, tmp_path, first):
    args, _ = configured
    c = collector.NativeCollector(**args, confirm_rpc="http://127.0.0.1:8083/jsonRPC")
    path = tmp_path / "rpc-page"
    path.mkdir()
    calls = []

    def response(argv, output, error, *_):
        calls.append(argv[-1])
        collector.write_file(output, json.dumps(first).encode())
        collector.write_file(error, b"")

    c._run = response
    try:
        with pytest.raises(HistoryError, match="bounded RPC history page"):
            c._rpc_page(path, Head(1, "11" * 32), 0, time.monotonic() + 5)
        assert len(calls) == 1
    finally:
        c.close()


def test_both_internal_errors_stop_after_four_rounds(configured, tmp_path):
    args, _ = configured
    c = collector.NativeCollector(**args, confirm_rpc="http://127.0.0.1:8083/jsonRPC")
    path = tmp_path / "rpc-page"
    path.mkdir()
    calls = []

    def response(argv, output, error, *_):
        calls.append(argv[-1])
        collector.write_file(output, b'{"error":{"code":-32603}}')
        collector.write_file(error, b"")

    c._run = response
    try:
        with pytest.raises(HistoryError, match="bounded RPC history page"):
            c._rpc_page(path, Head(1, "11" * 32), 0, time.monotonic() + 5)
        assert len(calls) == 8
    finally:
        c.close()


@pytest.mark.parametrize(
    "url",
    [
        "http://user:password@localhost/jsonRPC",
        "ftp://localhost/jsonRPC",
        "http://localhost/?token=private",
    ],
)
def test_confirm_url_validated_before_artifacts(configured, url):
    args, _ = configured
    with pytest.raises(HistoryError, match="public RPC URL"):
        collector.NativeCollector(**args, confirm_rpc=url)
    assert not args["directory"].exists()


@pytest.mark.parametrize("wrong_history", [False, True])
@pytest.mark.parametrize("internal_errors", [1, 3])
def test_fallback_rows_still_require_native_boc_chain(configured, wrong_history, internal_errors):
    args, public = configured
    c = collector.NativeCollector(**args, confirm_rpc="http://127.0.0.1:8083/jsonRPC")
    fake_boundary(c, public)
    native_run = c._run
    c._rpc_page = collector.NativeCollector._rpc_page.__get__(c)
    calls = []

    def run(argv, output, error, deadline, directory, *, native=False):
        if native:
            return native_run(argv, output, error, deadline, directory, native=True)
        calls.append(argv[-1])
        rows = public["transactions"][1:] if wrong_history else public["transactions"]
        value = (
            {"error": {"code": -32603}}
            if len(calls) <= internal_errors
            else {"result": [{"data": x} for x in rows]}
        )
        collector.write_file(output, json.dumps(value).encode())
        collector.write_file(error, b"")

    c._run = run
    try:
        if wrong_history:
            with pytest.raises(HistoryError, match="does not match native head"):
                c.capture(Head(**public["previous"]))
            assert c.last_head is None and c.state_source is None
            assert not (c.root / "capture-000000/result.json").exists()
        else:
            capture = c.capture(Head(**public["previous"]))
            assert [r.query_id for r in capture.receipts] == [1566, 1565]
        assert len(calls) == internal_errors + 1
    finally:
        c.close()


@pytest.mark.parametrize(
    "running,filename,accepted",
    [
        (True, "native-state.json.tmp", True),
        (False, "native-state.json.tmp", False),
        (True, "account.tl", False),
    ],
)
def test_atomic_native_state_rename_during_enumeration(
    tmp_path, monkeypatch, running, filename, accepted
):
    directory = tmp_path / "capture"
    directory.mkdir()
    temporary = directory / filename
    temporary.write_bytes(b"new")
    old = Path.lstat
    renamed = []

    def lstat(path, *args, **kwargs):
        if path == temporary and not renamed:
            temporary.rename(directory / "native-state.json")
            renamed.append(True)
        return old(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    if accepted:
        collector.capture_size(directory, native_running=running)
    else:
        with pytest.raises(FileNotFoundError):
            collector.capture_size(directory, native_running=running)
    assert renamed
    assert collector.capture_size(directory) == 3


@pytest.mark.parametrize("native", [False, True])
def test_only_running_native_scan_tolerates_state_rename(configured, tmp_path, monkeypatch, native):
    args, _ = configured
    c = collector.NativeCollector(**args)
    directory = tmp_path / "running"
    directory.mkdir()
    calls = []
    real = collector.capture_size

    def scan(path, *, native_running=False):
        calls.append(native_running)
        return real(path, native_running=native_running)

    monkeypatch.setattr(collector, "capture_size", scan)
    try:
        c._run(
            ["/bin/sleep", "0.12"],
            directory / "out",
            directory / "err",
            time.monotonic() + 5,
            directory,
            native=native,
        )
        assert calls[-1] is False and len(calls) >= 2
        assert all(v is native for v in calls[:-1])
    finally:
        c.close()


@pytest.mark.parametrize(
    "confirm,failures,expected_calls,delays", [(True, 3, 4, [0.25]), (False, 2, 3, [0.25, 0.5])]
)
def test_internal_read_lag_retries_same_cursor_and_deadline(
    configured, tmp_path, monkeypatch, confirm, failures, expected_calls, delays
):
    args, _ = configured
    endpoint = "http://127.0.0.1:8083/jsonRPC" if confirm else None
    c = collector.NativeCollector(**args, confirm_rpc=endpoint)
    path = tmp_path / "page"
    path.mkdir()
    calls = []
    sleeps = []
    deadline = time.monotonic() + 5
    monkeypatch.setattr(collector.time, "sleep", sleeps.append)

    def response(argv, output, error, end, _directory):
        request = Path(argv[argv.index("--data-binary") + 1][1:]).read_bytes()
        calls.append((argv[-1], request, end))
        value = (
            {"error": {"code": -32603, "message": f"lag-{len(calls)}"}}
            if len(calls) <= failures
            else {"result": [{"data": "untrusted"}]}
        )
        collector.write_file(output, json.dumps(value).encode())
        collector.write_file(error, b"")

    c._run = response
    try:
        assert c._rpc_page(path, Head(7, "11" * 32), 0, deadline) == [{"data": "untrusted"}]
        assert len(calls) == expected_calls and sleeps == delays
        assert all(row[1:] == calls[0][1:] for row in calls)
        assert all(row[2] == deadline for row in calls)
        assert [row[0] for row in calls] == [
            args["rpc"] if not confirm or i % 2 == 0 else endpoint for i in range(expected_calls)
        ]
        errors = sorted((path / "rpc-failover").glob("*.json"))
        errors = [p for p in errors if not p.name.endswith(".sources.json")]
        assert len(errors) == failures
        assert {json.loads(p.read_text())["error"]["message"] for p in errors} == {
            f"lag-{i}" for i in range(1, failures + 1)
        }
    finally:
        c.close()


def test_original_deadline_refuses_further_retry_before_sleep(configured, tmp_path, monkeypatch):
    args, _ = configured
    c = collector.NativeCollector(**args, confirm_rpc="http://127.0.0.1:8083/jsonRPC")
    path = tmp_path / "page"
    path.mkdir()
    calls = []
    now = [1.0]
    sleeps = []
    monkeypatch.setattr(collector.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(collector.time, "sleep", sleeps.append)

    def response(argv, output, error, end, _directory):
        calls.append(end)
        collector.write_file(output, b'{"error":{"code":-32603}}')
        collector.write_file(error, b"")
        if len(calls) == 2:
            now[0] = 2.1

    c._run = response
    try:
        with pytest.raises(HistoryError, match="capture deadline expired"):
            c._rpc_page(path, Head(7, "11" * 32), 0, 2.0)
        assert calls == [2.0, 2.0] and sleeps == []
    finally:
        c.close()
