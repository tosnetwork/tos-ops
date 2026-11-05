"""Synthetic worker protocol/lifecycle tests; no chain, key, signer or money."""

import hashlib
import json
import itertools
import os
import stat
import time
from pathlib import Path

import pytest

from election_native_receipt import PinnedProgram, ReceiptError, verify_delivery


def program(path, source):
    raw = ("#!/usr/bin/python3\n" + source).encode()
    path.write_bytes(raw)
    path.chmod(0o500)
    return PinnedProgram(path, hashlib.sha256(raw).hexdigest())


def worker_source(mutation="", before="", after=""):
    return f"""
import hashlib,json,os,sys,time,subprocess
from pathlib import Path
args=sys.argv[1:]
assert args[:2]==['wallet','receipt']
assert args[2::2]==['--intent','--sender-pre-state','--recipient-pre-state','--proof-config']
p=Path(args[3]);raw=p.read_bytes();intent=json.loads(raw)
(p.parent/'worker-observed.json').write_text(json.dumps({{'args':args,'environment':dict(os.environ)}}))
{before}
report={{'schema':'tos.operation-delivery-receipt/1','status':'AUTHENTICATED_REQUEST_AND_DELIVERY','operation':intent['operation'],'intent_sha256':hashlib.sha256(raw).hexdigest(),'checkpoint':{{'seqno':100,'root_hash':'6'*64,'file_hash':'7'*64}},'sender_transaction':'8'*64,'recipient_transaction':'9'*64,'delivery_message':'a'*64,'business_acceptance':False,'authorizes_send':False}}
{mutation}
print(json.dumps(report),flush=True)
{after}
"""


@pytest.fixture
def case(tmp_path):
    intent = dict(
        schema="tos.operation-delivery-intent/1",
        operation="synthetic-original-1",
        genesis_root="1" * 64,
        genesis_file="2" * 64,
        sender="0:" + "3" * 64,
        sender_code_hash="4" * 64,
        recipient="-1:" + "5" * 64,
        recipient_code_hash="6" * 64,
        external_message_hash="7" * 64,
        body_hash="8" * 64,
        value_nanotos=100,
        credited_nanotos=100,
        bounce=True,
        rpc=["http://127.0.0.1:8081/jsonRPC", "http://127.0.0.1:8083/jsonRPC"],
        history_limit=128,
        max_age_seconds=30,
        timeout_seconds=2,
    )
    anchor = dict(
        kind="zerostate",
        seqno=0,
        root_hash=intent["genesis_root"],
        file_hash=intent["genesis_file"],
    )
    helper = program(tmp_path / "helper", "raise SystemExit(0)\n")

    monitor = program(
        tmp_path / "monitor",
        "import os,sys,time\nwhile True:\n try:os.killpg(int(sys.argv[1]),0)\n except ProcessLookupError:break\n time.sleep(0.02)\n",
    )
    sequence = itertools.count()

    def execute(
        *,
        mutation="",
        before="",
        after="",
        cli=None,
        helper_pin=None,
        monitor_pin=None,
        intent_value=None,
        anchor_value=None,
        directory=None,
        seconds=3,
    ):
        cli = cli or program(
            tmp_path / f"cli-{next(sequence)}", worker_source(mutation, before, after)
        )
        return verify_delivery(
            cli,
            helper_pin or helper,
            json.dumps(intent_value or intent).encode(),
            b"synthetic-preimage-sender",
            b"synthetic-preimage-recipient",
            json.dumps(anchor_value or anchor).encode(),
            b'{"synthetic":true}',
            directory or tmp_path / "run",
            thermal_monitor=monitor_pin or monitor,
            worker_seconds=seconds,
        )

    return tmp_path, intent, anchor, helper, execute


def test_native_worker_is_readonly_pinned_and_returns_no_authorization(case):
    root, intent, _anchor, _helper, execute = case
    evidence = execute()
    assert evidence.original_message_hash == intent["external_message_hash"]
    assert evidence.authorizes_send is False and evidence.business_acceptance is False
    assert evidence.receipt["authorizes_send"] is False
    assert (
        evidence.intent_sha256
        == hashlib.sha256((root / "run/intent.json").read_bytes()).hexdigest()
    )
    observed = json.loads((root / "run/worker-observed.json").read_text())
    assert observed["environment"]["TOKIO_WORKER_THREADS"] == "2"
    assert observed["environment"]["RAYON_NUM_THREADS"] == "2"
    assert set(observed["environment"]) <= {
        "PATH",
        "LC_ALL",
        "TOKIO_WORKER_THREADS",
        "RAYON_NUM_THREADS",
        "LC_CTYPE",
    }
    assert (
        "--request-file" not in observed["args"] and "--config" not in observed["args"]
    )
    for name in [
        "intent.json",
        "sender-pre-state.boc",
        "recipient-pre-state.boc",
        "anchor.json",
        "lite.json",
        "proof-config.json",
        "receipt.json",
    ]:
        assert stat.S_IMODE((root / "run" / name).stat().st_mode) == 0o400


@pytest.mark.parametrize(
    "mutation",
    [
        "report['authorizes_send']=True",
        "report['business_acceptance']=True",
        "report['authorizes_send']=0",
        "report['schema']='foreign'",
        "report['status']='reported'",
        "report['operation']='other-original'",
        "report['intent_sha256']='0'*64",
        "report['checkpoint']['seqno']=True",
        "report['checkpoint']['extra']=1",
        "report['sender_transaction']='NOT-A-HASH'",
        "report['extra']='unknown'",
    ],
)
def test_receipt_cannot_change_identity_or_upgrade_readonly_meaning(case, mutation):
    root, _intent, _anchor, _helper, execute = case
    with pytest.raises(ReceiptError):
        execute(mutation=mutation)
    assert not (root / "run/receipt.json").exists()


@pytest.mark.parametrize(
    "before",
    [
        "sys.stdout.write(' '*70000);sys.stdout.flush()",
        "print('x'*70000,file=sys.stderr,flush=True)",
        "raise SystemExit(17)",
    ],
)
def test_worker_refusal_or_output_flood_never_becomes_evidence(case, before):
    root, _intent, _anchor, _helper, execute = case
    with pytest.raises(ReceiptError):
        execute(before=before)
    assert not (root / "run/receipt.json").exists()


def test_duplicate_output_keys_are_not_last_writer_wins(case):
    root, _intent, _anchor, _helper, execute = case
    with pytest.raises(ReceiptError, match="invalid public JSON"):
        execute(
            mutation="wire=json.dumps(report);print(wire[:-1]+',\"authorizes_send\":false}',flush=True);raise SystemExit(0)"
        )
    assert not (root / "run/receipt.json").exists()


def test_worker_deadline_kills_owned_worker(case):
    root, _intent, _anchor, _helper, execute = case
    began = time.monotonic()
    with pytest.raises(ReceiptError, match="deadline"):
        execute(
            before="(p.parent/'pid').write_text(str(os.getpid()));time.sleep(10)",
            seconds=1,
        )
    assert time.monotonic() - began < 7
    with pytest.raises(ProcessLookupError):
        os.kill(int((root / "run/pid").read_text()), 0)


def test_success_cleanup_terminates_leftover_same_group_child(case):
    root, _intent, _anchor, _helper, execute = case
    execute(
        before="child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);(p.parent/'child-pid').write_text(str(child.pid))"
    )
    pid = int((root / "run/child-pid").read_text())
    # An exited orphan may wait briefly for the system reaper; it must not run.
    for _ in range(50):
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except FileNotFoundError:
            break
        if state == "Z":
            break
        time.sleep(0.01)
    else:
        pytest.fail("native worker left a running descendant")


@pytest.mark.parametrize("kind", ["wrong-hash", "writable", "symlink", "hardlink"])
def test_wrong_or_mutable_executable_refuses_before_worker(case, kind):
    root, _intent, _anchor, _helper, execute = case
    cli = program(root / "cli", worker_source())
    if kind == "wrong-hash":
        cli = PinnedProgram(cli.path, "0" * 64)
    elif kind == "writable":
        cli.path.chmod(0o700)
    elif kind == "symlink":
        (root / "alias").symlink_to(cli.path)
        cli = PinnedProgram(root / "alias", cli.sha256)
    else:
        os.link(cli.path, root / "alias")
    with pytest.raises((ReceiptError, OSError)):
        execute(cli=cli)
    assert not (root / "run").exists()


def test_helper_identity_and_full_genesis_are_checked_before_spawn(case):
    root, _intent, anchor, helper, execute = case
    with pytest.raises(ReceiptError, match="program identity"):
        execute(helper_pin=PinnedProgram(helper.path, "0" * 64))
    assert not (root / "run").exists()
    with pytest.raises(ReceiptError, match="full genesis"):
        execute(anchor_value=dict(anchor, root_hash="9" * 64))
    assert not (root / "run").exists()


def test_existing_artifacts_are_never_reused_or_overwritten(case):
    root, _intent, _anchor, _helper, execute = case
    execute()
    original = (root / "run/receipt.json").read_bytes()
    with pytest.raises(FileExistsError):
        execute()
    assert (root / "run/receipt.json").read_bytes() == original


def test_valid_report_from_nonzero_worker_is_not_native_success(case):
    root, _intent, _anchor, _helper, execute = case
    with pytest.raises(ReceiptError, match="native delivery refused"):
        execute(after="raise SystemExit(17)")
    assert not (root / "run/receipt.json").exists()


def test_pinned_program_rejects_symlinked_ancestor(case):
    root, _intent, _anchor, _helper, execute = case
    actual = root / "programs"
    actual.mkdir(mode=0o700)
    cli = program(actual / "cli", worker_source())
    (root / "redirect").symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe journal directory"):
        execute(cli=PinnedProgram(root / "redirect/cli", cli.sha256))
    assert not (root / "run").exists()


def test_dead_thermal_watcher_refuses_and_stops_native_worker(case):
    root, _intent, _anchor, _helper, execute = case
    dead_monitor = program(root / "dead-monitor", "raise SystemExit(0)\n")
    began = time.monotonic()
    with pytest.raises(ReceiptError, match="thermal watcher stopped"):
        execute(monitor_pin=dead_monitor, before="time.sleep(10)", seconds=20)
    assert time.monotonic() - began < 3
    assert not (root / "run/receipt.json").exists()


def test_thermal_watcher_release_is_pinned_before_worker(case):
    root, _intent, _anchor, _helper, execute = case
    watcher = PinnedProgram(root / "monitor", "0" * 64)
    with pytest.raises(ReceiptError, match="program identity"):
        execute(monitor_pin=watcher)
    assert not (root / "run").exists()


@pytest.mark.parametrize(
    "diagnostic,category",
    [
        ("approved outgoing action missing", "APPROVED_OUTGOING_MISSING"),
        ("transaction pre-state hash mismatch", "PRE_STATE_HASH_MISMATCH"),
        ("unknown diagnostic", None),
    ],
)
def test_refusal_exposes_only_fixed_category_not_raw_diagnostic(
    case, diagnostic, category
):
    _root, _intent, _anchor, _helper, execute = case
    with pytest.raises(ReceiptError) as caught:
        execute(
            before=f"print('NEVER_ECHO_SYNTHETIC_DETAIL {diagnostic}',file=sys.stderr,flush=True);raise SystemExit(17)"
        )
    assert caught.value.category == category
    assert "NEVER_ECHO" not in str(caught.value) and diagnostic not in str(caught.value)
