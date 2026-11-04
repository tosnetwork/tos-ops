"""Full reader/control tests with fake native boundary; not cryptographic evidence.

Transaction BOCs are a retained public segment. The separate real-corpus run
must exercise the pinned native verifier for signature/consensus claims.
"""

import base64
import copy
import json
import shutil
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import load_run_replay as replay
import pytest
from load_finality import Head, HistoryError, decode_history
from pytosiq_core import Builder


def block(number):
    return {
        "workchain": -1,
        "shard": "8000000000000000",
        "seqno": number,
        "root_hash": f"{number + 1:064x}",
        "file_hash": f"{number + 2:064x}",
    }


def store(path, value):
    path.write_text(json.dumps(value) + "\n")


@pytest.fixture
def closed_run(tmp_path, monkeypatch):
    public = json.loads((Path(__file__).parent / "data/load-finality-public.json").read_text())
    run = tmp_path / "qualification-1"
    captures = run / "native-captures"
    captures.mkdir(parents=True)
    identity = {
        "wallet": public["wallet"],
        "wallet_code_hash": "cc" * 32,
        "global_id": 2,
        "global_version": 16,
        "subwallet_id": 4269,
    }
    receipts = decode_history(
        public["transactions"],
        verified_head=Head(**public["head"]),
        previous_head=Head(**public["previous"]),
        wallet=public["wallet"],
        global_id=2,
        subwallet_id=4269,
        skipped_profile=True,
    )
    proofs = {}
    for number in range(3):
        cap = captures / f"capture-{number:06d}"
        cap.mkdir()
        material = cap / "material"
        material.mkdir()
        for name in ("chain-0000.tl", "account.tl", "config.tl", "masterchain-info.tl"):
            (material / name).write_bytes(name.encode())
        head = public["head"] if number == 2 else public["previous"]
        proof = {
            "status": "verified",
            "mode": "live",
            "target": block(number),
            "start": block(0),
            "account": {
                "active": True,
                "address": public["wallet"],
                "code_hash": "cc" * 32,
                "data_hash": "dd" * 32,
                "last_trans_lt": head["lt"],
                "last_trans_hash": head["hash"],
            },
            "config_params": [
                {
                    "index": 8,
                    "boc": base64.b64encode(
                        Builder().store_uint(0xC4, 8).store_uint(16, 32).end_cell().to_boc()
                    ).decode(),
                },
                {
                    "index": 19,
                    "boc": base64.b64encode(
                        Builder().store_int(2, 32).end_cell().to_boc()
                    ).decode(),
                },
            ],
        }
        proofs[number] = copy.deepcopy(proof)
        store(cap / "proof.json", proof)
        store(
            cap / "result.json",
            {
                "status": "VERIFIED_CAPTURE",
                "target": block(number),
                "head": head,
                "previous_head": public["previous"],
                "receipts": len(receipts) if number == 2 else 0,
            },
        )
        store(
            cap / "request.json",
            {
                "mode": "live",
                "max_age_seconds": 10,
                "account": public["wallet"],
                "config_params": [8, 19],
            },
        )
        if number == 2:
            store(
                cap / "rpc-0.json",
                {"result": [{"data": value} for value in public["transactions"]]},
            )
    baseline = {
        "event": "native_baseline",
        "capture": str(captures / "capture-000001"),
        "boot_id": "one-boot",
        "verified_observation_monotonic_seconds": 1.0,
        "monotonic_seconds": 1.1,
        "checkpoint_seqno": 1,
        "head_lt": public["previous"]["lt"],
        "head_hash": public["previous"]["hash"],
        "poll_interval_seconds": 0.5,
    }
    offered = {
        "event": "offered",
        "query_ids": [r.query_id for r in receipts],
        "signed_request_hashes": {str(r.query_id): r.request_hash for r in receipts},
        "native_boot_id": "one-boot",
        "native_offered_monotonic_seconds": 1.5,
        "monotonic_seconds": 1.6,
    }
    checkpoint = {
        "event": "native_checkpoint",
        "capture": str(captures / "capture-000002"),
        "boot_id": "one-boot",
        "verified_observation_monotonic_seconds": 2.5,
        "monotonic_seconds": 2.6,
        "checkpoint_seqno": 2,
        "query_ids": [r.query_id for r in receipts],
    }
    events = [baseline, offered, checkpoint]
    (run / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
    histogram = [0] * (len(replay.BUCKETS) + 1)
    histogram[3] = 2
    summary = {
        "wallet": public["wallet"],
        "transfers_mode": "skip",
        "qualification": {
            "run_directory": run.name,
            "safe_to_start_new_run": True,
            "pending": 0,
            "funding_unknown": False,
            "offered": 2,
            "native_finality": {
                "native_pending": 0,
                "native_finalized": 2,
                "histogram": histogram,
                "latency_bucket_upper_seconds": [*replay.BUCKETS, "infinity"],
                "latency_criteria_pass": True,
            },
        },
    }
    files = {
        "summary": summary,
        "anchor": block(0),
        "producer_packet": {"state_directory": str(tmp_path), "calibration_commands": []},
    }
    for key, value in files.items():
        store(tmp_path / (key + ".json"), value)
    (tmp_path / "schema.tl").write_bytes(b"fake schema")
    (tmp_path / "verifier").write_bytes(b"fake ELF boundary is replaced in these tests")
    args = SimpleNamespace(
        run=str(run),
        output=str(tmp_path / "output"),
        summary=str(tmp_path / "summary.json"),
        anchor=str(tmp_path / "anchor.json"),
        producer_packet=str(tmp_path / "producer_packet.json"),
        schema=str(tmp_path / "schema.tl"),
        verifier=str(tmp_path / "verifier"),
        resume=False,
        max_unique_bytes=1 << 20,
        max_captures=100,
        **identity,
    )
    args.events_sha256 = replay.digest((run / "events.jsonl").read_bytes())
    for name in ("summary", "anchor", "schema", "verifier"):
        setattr(args, name + "_sha256", replay.digest(Path(getattr(args, name)).read_bytes()))
    command = [
        "load",
        "--native-finality",
        "--expected-genesis-root",
        block(0)["root_hash"],
        "--expected-genesis-file",
        block(0)["file_hash"],
        "--native-verifier-sha256",
        args.verifier_sha256,
        "--native-anchor-sha256",
        args.anchor_sha256,
        "--native-wallet-code-hash",
        args.wallet_code_hash,
        "--state",
        str(tmp_path),
    ]
    files["producer_packet"]["calibration_commands"] = [{"command": command}]
    store(Path(args.producer_packet), files["producer_packet"])
    args.producer_packet_sha256 = replay.digest(Path(args.producer_packet).read_bytes())
    calls = []
    fail = [False]

    class Native:
        def __init__(self, _verifier, _digest, anchor, _output):
            assert Path(anchor) != Path(args.anchor)
            assert Path(anchor).read_bytes() == Path(args.anchor).read_bytes()

        def __call__(self, request, *_):
            number = json.loads(request)["target"]["seqno"]
            calls.append(number)
            if fail[0] and number == 2:
                fail[0] = False
                raise RuntimeError("injected interrupted replay")
            result = copy.deepcopy(proofs[number])
            result["mode"] = "historical"
            return result

        def close(self):
            pass

    class Prefix:
        def __init__(self, *_):
            pass

        def advance(self, parts, *, start, target, verify):
            return verify(parts)

    monkeypatch.setattr(replay, "NativeReplay", Native)
    monkeypatch.setattr(replay, "RetainedPrefix", Prefix)
    monkeypatch.setattr(replay, "TlGenerator", lambda _: SimpleNamespace(generate=lambda: None))
    monkeypatch.setattr(replay.shutil, "disk_usage", lambda _: SimpleNamespace(free=1 << 40))
    return SimpleNamespace(
        args=args, run=run, events=events, summary=summary, calls=calls, fail=fail, proofs=proofs
    )


def repin(case, name):
    path = Path(getattr(case.args, name))
    setattr(case.args, name + "_sha256", replay.digest(path.read_bytes()))


def write_events(case):
    (case.run / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in case.events))
    case.args.events_sha256 = replay.digest((case.run / "events.jsonl").read_bytes())


def test_full_public_reader_flow_and_archive(closed_run):
    c = closed_run
    result = replay.run(c.args)
    assert (
        result["captures"] == 3
        and result["offered"] == 2
        and result["recomputed_histogram"][3] == 2
    )
    assert c.calls == [0, 1, 2]
    assert (Path(c.args.output) / "RESULT.json").is_file()
    c.args.resume = True
    with pytest.raises(HistoryError, match="already complete"):
        replay.run(c.args)


def test_interruption_resume_reverifies_original_captures(closed_run):
    c = closed_run
    c.fail[0] = True
    with pytest.raises(RuntimeError, match="interrupted replay"):
        replay.run(c.args)
    assert not (Path(c.args.output) / "RESULT.json").exists()
    c.args.resume = True
    result = replay.run(c.args)
    assert c.calls == [0, 1, 2, 0, 1, 2] and result["attempt"] == 1 and result["captures"] == 3


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("digest", "signed digest mismatch"),
        ("boot", "offered boot"),
        ("negative-clock", "invalid monotonic"),
        ("late-offer", "observation precedes"),
        ("missing-checkpoint", "missing or duplicate checkpoint"),
        ("wrong-path", "another run"),
        ("duplicate-offer", "UNIQUE"),
        ("duplicate-checkpoint", "UNIQUE"),
    ],
)
def test_event_tampering_has_specific_refusal(closed_run, mutation, reason):
    c = closed_run
    if mutation == "digest":
        c.events[1]["signed_request_hashes"][str(c.events[1]["query_ids"][0])] = "ee" * 32
    if mutation == "boot":
        c.events[1]["native_boot_id"] = "other"
    if mutation == "negative-clock":
        c.events[1]["native_offered_monotonic_seconds"] = -1
    if mutation == "late-offer":
        c.events[1]["native_offered_monotonic_seconds"] = 3
        c.events[1]["monotonic_seconds"] = 3.1
    if mutation == "missing-checkpoint":
        c.events.pop()
    if mutation == "wrong-path":
        c.events[2]["capture"] = str(
            c.run.parent / "qualification-2/native-captures/capture-000002"
        )
    if mutation == "duplicate-offer":
        c.events.append(copy.deepcopy(c.events[1]))
    if mutation == "duplicate-checkpoint":
        c.events.append(copy.deepcopy(c.events[2]))
    write_events(c)
    with pytest.raises((HistoryError, sqlite3.IntegrityError), match=reason):
        replay.run(c.args)


def test_incomplete_closed_source_refused(closed_run):
    c = closed_run
    c.summary["qualification"]["funding_unknown"] = True
    store(Path(c.args.summary), c.summary)
    repin(c, "summary")
    with pytest.raises(HistoryError, match="closed reconciled source"):
        replay.run(c.args)
    assert not Path(c.args.output).exists()


def test_capture_gap_refused(closed_run):
    c = closed_run
    (c.run / "native-captures/capture-000001").rename(c.run / "removed")
    with pytest.raises(HistoryError, match="capture index gap"):
        replay.run(c.args)


def test_native_account_difference_refused(closed_run):
    c = closed_run
    p = c.run / "native-captures/capture-000002/proof.json"
    v = json.loads(p.read_text())
    v["account"]["data_hash"] = "ee" * 32
    store(p, v)
    with pytest.raises(HistoryError, match="retained account differ"):
        replay.run(c.args)


def test_wrong_transaction_boc_refused(closed_run):
    c = closed_run
    p = c.run / "native-captures/capture-000002/rpc-0.json"
    v = json.loads(p.read_text())
    v["result"][0]["data"] = v["result"][1]["data"]
    store(p, v)
    with pytest.raises(HistoryError, match="history head hash"):
        replay.run(c.args)


def test_wrong_genesis_packet_refused(closed_run):
    c = closed_run
    p = Path(c.args.producer_packet)
    v = json.loads(p.read_text())
    command = v["calibration_commands"][0]["command"]
    command[command.index("--expected-genesis-root") + 1] = "ee" * 32
    store(p, v)
    repin(c, "producer_packet")
    with pytest.raises(HistoryError, match="producer identity differs"):
        replay.run(c.args)


def test_resume_archive_corruption_refused(closed_run):
    c = closed_run
    c.fail[0] = True
    with pytest.raises(RuntimeError):
        replay.run(c.args)
    db = sqlite3.connect(Path(c.args.output) / "proofs.sqlite")
    db.execute(
        "UPDATE blobs SET body=? WHERE digest=(SELECT min(digest) FROM blobs)", (b"corrupt",)
    )
    db.commit()
    db.close()
    c.args.resume = True
    with pytest.raises(ValueError, match="corrupt public proof"):
        replay.run(c.args)


def test_event_pin_and_disk_budget_refusals(closed_run, monkeypatch):
    c = closed_run
    c.args.events_sha256 = "ee" * 32
    with pytest.raises(HistoryError, match="event journal pin"):
        replay.run(c.args)
    c.args.output = str(c.run.parent / "output2")
    c.args.events_sha256 = replay.digest((c.run / "events.jsonl").read_bytes())
    monkeypatch.setattr(replay.shutil, "disk_usage", lambda _: SimpleNamespace(free=1))
    with pytest.raises(HistoryError, match="free disk guard"):
        replay.run(c.args)


def test_snapshot_symlink_and_size_refused(tmp_path):
    p = tmp_path / "file"
    p.write_bytes(b"123")
    link = tmp_path / "link"
    link.symlink_to(p)
    with pytest.raises(OSError):
        replay.snapshot(link)
    with pytest.raises(HistoryError, match="size/type"):
        replay.snapshot(p, 2)


def test_sigterm_reaps_owned_native_helper(tmp_path):
    import os
    import signal
    import subprocess
    import sys
    import time

    # A sealed Python ELF runs a controlled script named verify. It sleeps
    # instead of verifying anything; this exercises process cleanup only.
    (tmp_path / "verify").write_text(
        "import os,time\nopen('native.pid','w').write(str(os.getpid()))\ntime.sleep(60)\n"
    )
    executable = Path(sys.executable).resolve()
    code = """
import pathlib,sys
from load_run_replay import NativeReplay,digest,install_interrupt_handlers
install_interrupt_handlers()
root=pathlib.Path.cwd()
runner=NativeReplay(sys.argv[1],digest(pathlib.Path(sys.argv[1]).read_bytes()),root/'anchor',root)
try:
 runner(b'{}',[b'fake'],b'account',b'config')
finally:
 runner.close()
"""
    env = {
        **os.environ,
        "PYTHONPATH": str(Path(replay.__file__).parent),
        "PYTHONHOME": sys.base_prefix,
    }
    with (tmp_path / "coordinator.stderr").open("w+b") as error:
        process = subprocess.Popen(
            [sys.executable, "-c", code, str(executable)],
            cwd=tmp_path,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=error,
        )
        try:
            deadline = time.monotonic() + 10
            while (
                not (tmp_path / "native.pid").exists()
                and process.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.02)
            if not (tmp_path / "native.pid").exists():
                error.seek(0)
                pytest.fail("controlled native helper did not start: " + error.read().decode())
            native_pid = int((tmp_path / "native.pid").read_text())
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=10) != 0
            with pytest.raises(ProcessLookupError):
                os.kill(native_pid, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def test_negative_delta_cannot_match_forged_histogram(closed_run):
    c = closed_run
    c.events[1]["native_offered_monotonic_seconds"] = 3
    c.events[1]["monotonic_seconds"] = 3.1
    write_events(c)
    c.summary["qualification"]["native_finality"]["histogram"] = [2] + [0] * len(replay.BUCKETS)
    store(Path(c.args.summary), c.summary)
    repin(c, "summary")
    with pytest.raises(HistoryError, match="observation precedes offer"):
        replay.run(c.args)


def test_foreign_native_account_refused(closed_run):
    c = closed_run
    c.proofs[2]["account"]["address"] = "0:" + "ee" * 32
    store(c.run / "native-captures/capture-000002/proof.json", c.proofs[2])
    with pytest.raises(HistoryError, match="account/code identity"):
        replay.run(c.args)


def test_retained_result_target_must_match_native(closed_run):
    c = closed_run
    p = c.run / "native-captures/capture-000002/result.json"
    v = json.loads(p.read_text())
    v["target"] = block(1)
    store(p, v)
    with pytest.raises(HistoryError, match="result target differs"):
        replay.run(c.args)


def test_schema_byte_pin_refused(closed_run):
    c = closed_run
    Path(c.args.schema).write_bytes(b"altered fake schema")
    with pytest.raises(HistoryError, match="public input pin mismatch"):
        replay.run(c.args)


def test_archive_payload_budget_cannot_publish_result(closed_run):
    c = closed_run
    c.args.max_unique_bytes = 1
    with pytest.raises(ValueError, match="byte budget exhausted"):
        replay.run(c.args)
    assert not (Path(c.args.output) / "RESULT.json").exists()


def test_regressed_empty_checkpoint_is_rejected(closed_run):
    c = closed_run
    old = c.run / "native-captures/capture-000002"
    new = c.run / "native-captures/capture-000003"
    shutil.copytree(old, new)
    p = copy.deepcopy(c.proofs[2])
    p["target"] = block(3)
    c.proofs[3] = p
    store(new / "proof.json", p)
    result = json.loads((old / "result.json").read_text())
    result.update(target=block(3), previous_head=result["head"], receipts=0)
    store(new / "result.json", result)
    c.events.append(
        {
            "event": "native_checkpoint",
            "capture": str(new),
            "boot_id": "one-boot",
            "verified_observation_monotonic_seconds": 0.5,
            "monotonic_seconds": 3.0,
            "checkpoint_seqno": 3,
            "query_ids": [],
        }
    )
    write_events(c)
    with pytest.raises(HistoryError, match="checkpoint window clock regressed"):
        replay.run(c.args)


def test_regressed_offered_window_sequence_is_rejected(closed_run):
    c = closed_run
    original = c.events[1]
    events = []
    for pos, q in enumerate(original["query_ids"]):
        e = copy.deepcopy(original)
        e["query_ids"] = [q]
        e["signed_request_hashes"] = {str(q): original["signed_request_hashes"][str(q)]}
        e["native_offered_monotonic_seconds"] = 2.0 if pos == 0 else 1.5
        e["monotonic_seconds"] = 2.1 + pos * 0.1
        events.append(e)
    c.events[1:2] = events
    write_events(c)
    c.summary["qualification"]["native_finality"]["histogram"] = [0, 0, 1, 1] + [0] * 10
    store(Path(c.args.summary), c.summary)
    repin(c, "summary")
    with pytest.raises(HistoryError, match="serialized offered window clock regressed"):
        replay.run(c.args)


def test_callback_record_order_can_differ_from_window_order(closed_run):
    c = closed_run
    old = c.run / "native-captures/capture-000002"
    new = c.run / "native-captures/capture-000003"
    shutil.copytree(old, new)
    original = copy.deepcopy(c.proofs[2])
    original["target"] = block(3)
    c.proofs[3] = original
    store(new / "proof.json", original)
    original_result = json.loads((old / "result.json").read_text())
    original_result["target"] = block(3)
    store(new / "result.json", original_result)
    previous = {
        "lt": c.proofs[1]["account"]["last_trans_lt"],
        "hash": c.proofs[1]["account"]["last_trans_hash"],
    }
    empty = copy.deepcopy(c.proofs[1])
    empty["target"] = block(2)
    c.proofs[2] = empty
    store(old / "proof.json", empty)
    store(
        old / "result.json",
        {
            "status": "VERIFIED_CAPTURE",
            "target": block(2),
            "head": previous,
            "previous_head": previous,
            "receipts": 0,
        },
    )
    (old / "rpc-0.json").unlink()
    final = copy.deepcopy(c.events[2])
    final.update(capture=str(new), checkpoint_seqno=3)
    c.events[2].update(
        query_ids=[], verified_observation_monotonic_seconds=1.2, monotonic_seconds=2.0
    )
    c.events.append(final)
    write_events(c)
    assert replay.run(c.args)["offered"] == 2


def test_public_context_directory_is_synced_before_verification(closed_run, monkeypatch):
    import os
    import stat

    real = os.fsync
    directories = []
    public = Path(closed_run.args.output) / "public"

    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            path = Path(os.readlink("/proc/self/fd/" + str(fd)))
            directories.append(path)
            if path == public:
                assert closed_run.calls == []
        return real(fd)

    monkeypatch.setattr(replay.os, "fsync", fsync)
    replay.run(closed_run.args)
    assert public in directories


def test_failed_result_fsync_leaves_no_partial_final_and_can_resume(closed_run, monkeypatch):
    import os

    c = closed_run
    real = os.fsync
    failed = [False]

    def fsync(fd):
        path = Path(os.readlink("/proc/self/fd/" + str(fd)))
        if (path.name == "RESULT.json" or path.name.startswith("RESULT.json.")) and not failed[0]:
            failed[0] = True
            raise OSError("injected result fsync interruption")
        return real(fd)

    monkeypatch.setattr(replay.os, "fsync", fsync)
    with pytest.raises(OSError, match="result fsync interruption"):
        replay.run(c.args)
    assert not (Path(c.args.output) / "RESULT.json").exists()
    c.args.resume = True
    assert replay.run(c.args)["attempt"] == 1 and c.calls == [0, 1, 2, 0, 1, 2]
