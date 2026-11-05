"""Synthetic admission receipts only; no node, signer or real transaction data."""

import importlib.util
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/election_send_gate.py"
spec = importlib.util.spec_from_file_location("election_send_gate", SCRIPT)
gate_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate_module)
SendGate, GateError = gate_module.SendGate, gate_module.GateError
CONTEXT = dict(
    case="synthetic-case",
    genesis_root="1" * 64,
    genesis_file="2" * 64,
    cli_sha256="3" * 64,
)


def receipt(context, operation):
    return dict(context=context, operation=operation, proof_digest="4" * 64)


@pytest.fixture
def directory(tmp_path):
    result = tmp_path / "journal"
    result.mkdir(mode=0o700)
    return result


def test_closed_gate_does_not_fetch_or_forward(directory):
    with SendGate(directory, CONTEXT) as gate:
        calls = []
        with pytest.raises(GateError):
            gate.admitted_read(lambda: calls.append("read"))
        with pytest.raises(GateError):
            gate.forward_once(lambda _: calls.append("send"))
        assert calls == []


@pytest.mark.parametrize("lost_reply", [False, True])
def test_fsync_precedes_forward_and_reply_never_reopens(
    directory, monkeypatch, lost_reply
):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        durable = []
        original = os.fsync

        def sync(fd):
            original(fd)
            durable.append(True)

        monkeypatch.setattr(gate_module.os, "fsync", sync)

        def forward(operation):
            assert durable and operation == 1
            assert not gate.metrics()["admitted"]
            records = [
                json.loads(row)
                for row in (directory / "send-admission.jsonl").read_text().splitlines()
            ]
            assert records[-1]["payload"]["event"] == "latched"
            if lost_reply:
                raise TimeoutError("synthetic acknowledgement lost")
            return "synthetic acknowledgement only"

        if lost_reply:
            with pytest.raises(TimeoutError):
                gate.forward_once(forward)
        else:
            assert gate.forward_once(forward) == "synthetic acknowledgement only"
        with pytest.raises(GateError):
            gate.forward_once(lambda _: pytest.fail("second forward"))
        with pytest.raises(GateError):
            gate.admitted_read(lambda: pytest.fail("next signing read"))


def test_restart_does_not_restore_prior_unused_read_permission(directory):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        assert gate.admitted_read(lambda: "published") == "published"
    with SendGate(directory, CONTEXT) as gate:
        assert not gate.metrics()["admitted"]
        with pytest.raises(GateError):
            gate.admitted_read(lambda: pytest.fail("stale permission"))
        with pytest.raises(GateError):
            gate.authorize(receipt)


def test_restart_pending_requires_exact_receipt_and_operation(directory):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        gate.forward_once(lambda _: None)
    with SendGate(directory, CONTEXT) as gate:
        with pytest.raises(GateError):
            gate.authorize(
                lambda c, n: dict(context=c, operation=n - 1, proof_digest="4" * 64)
            )
        with pytest.raises(GateError):
            gate.authorize(
                lambda c, n: dict(
                    context=dict(c, genesis_root="5" * 64),
                    operation=n,
                    proof_digest="4" * 64,
                )
            )
        assert not gate.metrics()["admitted"]
        gate.authorize(receipt)
        assert gate.admitted_read(lambda: "new") == "new"
        assert gate.forward_once(lambda n: n) == 2


def test_corruption_partial_and_empty_existing_journals_refuse(directory):
    path = directory / "send-admission.jsonl"
    with SendGate(directory, CONTEXT):
        pass
    original = path.read_bytes()
    for bad in [
        b"",
        original[:-1],
        original.replace(b"synthetic-case", b"corrupt-case"),
    ]:
        path.write_bytes(bad)
        with pytest.raises(GateError):
            SendGate(directory, CONTEXT)
    path.write_bytes(original)
    with SendGate(directory, CONTEXT):
        pass


def test_short_existing_read_is_not_a_valid_prefix(directory, monkeypatch):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        gate.forward_once(lambda _: None)
    original = os.read
    monkeypatch.setattr(
        gate_module.os,
        "read",
        lambda fd, limit: original(fd, limit).splitlines(keepends=True)[0],
    )
    with pytest.raises(GateError, match="incomplete journal read"):
        SendGate(directory, CONTEXT)


def test_failed_fsync_never_forwards_and_poison_is_sticky(directory, monkeypatch):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        original = os.fsync

        def fail(_fd):
            raise OSError("synthetic disk failure")

        monkeypatch.setattr(gate_module.os, "fsync", fail)
        with pytest.raises(OSError):
            gate.forward_once(lambda _: pytest.fail("uncommitted forward"))
        monkeypatch.setattr(gate_module.os, "fsync", original)
        with pytest.raises(GateError):
            gate.admitted_read(lambda: pytest.fail("poisoned read"))
        with pytest.raises(GateError):
            gate.authorize(receipt)


def test_one_process_owner_and_context_cannot_change(directory):
    with SendGate(directory, CONTEXT):
        with pytest.raises(BlockingIOError):
            SendGate(directory, CONTEXT)
    with pytest.raises(GateError):
        SendGate(directory, dict(CONTEXT, case="different-case"))


def test_capacity_refuses_before_another_forward(directory, monkeypatch):
    monkeypatch.setattr(gate_module, "MAX_RECORDS", 3)
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        gate.forward_once(lambda _: None)
        with pytest.raises(GateError, match="capacity"):
            gate.authorize(receipt)
        with pytest.raises(GateError):
            gate.forward_once(lambda _: pytest.fail("beyond bound"))
        assert gate.metrics()["records"] == 3


def test_read_publication_and_forward_are_serialized(directory):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        entered, release, attempted, acquired = (threading.Event() for _ in range(4))
        events = []
        actual_mutex = gate._mutex

        class ObservedMutex:
            def __enter__(self):
                sender = threading.current_thread().name == "sender"
                if sender:
                    attempted.set()
                result = actual_mutex.__enter__()
                if sender:
                    acquired.set()
                return result

            def __exit__(self, *args):
                return actual_mutex.__exit__(*args)

        gate._mutex = ObservedMutex()

        def publish():
            entered.set()
            assert release.wait(2)
            events.append("published")

        reader = threading.Thread(target=lambda: gate.admitted_read(publish))
        sender = threading.Thread(
            name="sender",
            target=lambda: gate.forward_once(lambda _: events.append("forwarded")),
        )
        reader.start()
        assert entered.wait(2)
        sender.start()
        try:
            assert attempted.wait(2)
            # Observe lock acquisition itself, before disk/network callbacks:
            # a slow fsync cannot hide a missing publication lock.
            assert not acquired.wait(0.2), (
                "forward lock acquired before read publication"
            )
        finally:
            release.set()
            reader.join(2)
            sender.join(2)
        assert acquired.is_set() and not reader.is_alive() and not sender.is_alive()
        assert events == ["published", "forwarded"]


def test_process_crash_after_latch_keeps_pending(directory):
    program = """
import importlib.util, json, os, sys
spec=importlib.util.spec_from_file_location('gate', sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
context=json.loads(sys.argv[3])
gate=m.SendGate(sys.argv[2],context)
gate.authorize(lambda c,n:dict(context=c,operation=n,proof_digest='4'*64))
gate.forward_once(lambda n:os._exit(86))
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(SCRIPT),
            str(directory),
            json.dumps(CONTEXT),
        ],
        timeout=10,
    )
    assert result.returncode == 86
    with SendGate(directory, CONTEXT) as gate:
        assert gate.metrics()["operation"] == 1
        with pytest.raises(GateError):
            gate.admitted_read(lambda: pytest.fail("crash reopened"))


def test_group_writable_ancestor_and_symlink_journal_refuse(directory):
    directory.parent.chmod(0o770)
    with pytest.raises(GateError):
        SendGate(directory, CONTEXT)
    directory.parent.chmod(0o700)
    other = directory / "target"
    other.write_text("synthetic")
    (directory / "send-admission.jsonl").symlink_to(other)
    with pytest.raises(OSError):
        SendGate(directory, CONTEXT)


def test_failed_admission_fsync_cannot_be_retried_in_the_same_process(
    directory, monkeypatch
):
    with SendGate(directory, CONTEXT) as gate:
        original = os.fsync

        def fail(_fd):
            raise OSError("synthetic admission fsync failure")

        monkeypatch.setattr(gate_module.os, "fsync", fail)
        with pytest.raises(OSError):
            gate.authorize(receipt)
        monkeypatch.setattr(gate_module.os, "fsync", original)
        assert gate.metrics()["poisoned"] and not gate.metrics()["admitted"]
        with pytest.raises(GateError, match="uncertain"):
            gate.authorize(receipt)


def test_duplicate_json_fields_are_not_reinterpreted_as_a_valid_record(directory):
    with SendGate(directory, CONTEXT):
        pass
    path = directory / "send-admission.jsonl"
    data = path.read_bytes()
    path.write_bytes(
        data.replace(b'"hash":', b'"hash":"' + b"0" * 64 + b'","hash":', 1)
    )
    with pytest.raises(GateError):
        SendGate(directory, CONTEXT)


def test_partial_latch_write_never_forwards_or_reopens(directory, monkeypatch):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        original = os.write
        calls = []

        def partial(fd, value):
            if not calls:
                calls.append(True)
                return original(fd, value[:4])
            raise OSError("synthetic short write then disk failure")

        monkeypatch.setattr(gate_module.os, "write", partial)
        with pytest.raises(OSError):
            gate.forward_once(lambda _: pytest.fail("partial record forwarded"))
        assert gate.metrics()["poisoned"] and not gate.metrics()["admitted"]
    monkeypatch.setattr(gate_module.os, "write", original)
    with pytest.raises(GateError):
        SendGate(directory, CONTEXT)


def fork_case(directory, body):
    prelude = """
import importlib.util, json, os, signal, sys, threading
spec=importlib.util.spec_from_file_location('gate', sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
context=json.loads(sys.argv[3])
gate=m.SendGate(sys.argv[2],context)
gate.authorize(lambda c,n:dict(context=c,operation=n,proof_digest='4'*64))
"""
    return subprocess.run(
        [
            sys.executable,
            "-c",
            prelude + body,
            str(SCRIPT),
            str(directory),
            json.dumps(CONTEXT),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Unix fork ownership boundary")
def test_inherited_process_cannot_reuse_an_admission(directory):
    result = fork_case(
        directory,
        """
reader,writer=os.pipe()
pid=os.fork()
if pid==0:
    os.close(reader)
    try:
        try:gate.forward_once(lambda n:os.write(writer,b'forwarded'))
        except m.GateError:os.write(writer,b'refused')
    finally:
        gate.close();os.close(writer);os._exit(0)
os.close(writer)
os.waitpid(pid,0)
answer=os.read(reader,64);os.close(reader)
assert answer==b'refused', 'inherited child executed a second owner forward'
try:m.SendGate(sys.argv[2],context)
except BlockingIOError:pass
else:raise AssertionError('child close unlocked parent ownership')
assert gate.forward_once(lambda n:n)==1
gate.close()
""",
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Unix fork ownership boundary")
def test_foreign_owner_checks_precede_inherited_mutex_and_close_is_safe(directory):
    result = fork_case(
        directory,
        """
held,release=threading.Event(),threading.Event()
def hold():
    with gate._mutex:
        held.set();release.wait(5)
thread=threading.Thread(target=hold);thread.start();assert held.wait(2)
pid=os.fork()
if pid==0:
    signal.alarm(2)
    gate.close()
    denied=0
    actions=[lambda:gate.authorize(lambda c,n:None),lambda:gate.admitted_read(lambda:None),lambda:gate.forward_once(lambda n:None),gate.metrics,gate.hold]
    for action in actions:
        try:action()
        except m.GateError:denied+=1
    os._exit(0 if denied==5 else 87)
_,status=os.waitpid(pid,0)
release.set();thread.join(2)
assert os.waitstatus_to_exitcode(status)==0, 'foreign owner blocked on inherited mutex or retained authority'
assert not thread.is_alive()
assert gate.forward_once(lambda n:n)==1
gate.close()
""",
    )
    assert result.returncode == 0, result.stderr


def test_hold_drops_permission_without_unlocking_or_rearming(directory):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        gate.hold()
        with pytest.raises(GateError):
            gate.admitted_read(lambda: pytest.fail("held read"))
        with pytest.raises(GateError):
            gate.forward_once(lambda n: pytest.fail("held write"))
        with pytest.raises(GateError):
            gate.authorize(receipt)
        with pytest.raises(BlockingIOError):
            SendGate(directory, CONTEXT)


def test_generation_scopes_late_holds(directory):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)
        previous = gate.admission_version()
        gate.forward_once(lambda _: None)
        gate.authorize(receipt)
        current = gate.admission_version()
        assert current > previous
        assert gate.hold(expected_version=previous) is False
        assert gate.metrics()["admitted"]
        assert gate.hold(expected_version=current) is True
        assert not gate.metrics()["admitted"]


def test_read_failure_closes_admission_before_releasing_mutex(directory):
    with SendGate(directory, CONTEXT) as gate:
        gate.authorize(receipt)

        def failed_read():
            raise OSError("synthetic read failure")

        with pytest.raises(OSError, match="synthetic read failure"):
            gate.admitted_read(failed_read)
        assert not gate.metrics()["admitted"]
        with pytest.raises(GateError):
            gate.admitted_read(lambda: pytest.fail("read after failed callback"))
