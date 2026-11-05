"""Read-only native delivery worker; never an election admission authorizer.

The caller supplies reviewed public inputs and pinned local executables. The only
CLI action is `wallet receipt`, with a pinned thermal watcher. Real Elector business acceptance and sole-producer
control are separate requirements; this module does not call SendGate.authorize.
Run it inside the controller's finite resource-bounded service as well.
"""

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from election_send_gate import HEX, canonical, private_directory, unique_object

MAX_PROGRAM = 256 << 20
MAX_JSON = 64 << 10
MAX_PREIMAGE = 1 << 20
MAX_OUTPUT = 64 << 10
INTENT_FIELDS = frozenset(
    "schema operation genesis_root genesis_file sender sender_code_hash recipient "
    "recipient_code_hash external_message_hash body_hash value_nanotos "
    "credited_nanotos bounce rpc history_limit max_age_seconds timeout_seconds".split()
)
RECEIPT_FIELDS = frozenset(
    "schema status operation intent_sha256 checkpoint sender_transaction "
    "recipient_transaction delivery_message business_acceptance authorizes_send".split()
)


class ReceiptError(ValueError):
    def __init__(self, message, *, category=None):
        super().__init__(message)
        self.category = category


def decode_json(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_JSON:
        raise ReceiptError("bounded public JSON required")

    def nonfinite(_value):
        raise ReceiptError("nonfinite JSON refused")

    try:
        return json.loads(
            raw, object_pairs_hook=unique_object, parse_constant=nonfinite
        )
    except (ValueError, UnicodeError) as error:
        raise ReceiptError("invalid public JSON") from error


def digest(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ReceiptError("canonical public digest required")
    return value


def validate_intent(intent):
    if type(intent) is not dict or set(intent) != INTENT_FIELDS:
        raise ReceiptError("exact public intent schema required")
    if (
        intent["schema"] != "tos.operation-delivery-intent/1"
        or not isinstance(intent["operation"], str)
        or not re.fullmatch(r"[A-Za-z0-9_:.-]{1,128}", intent["operation"])
    ):
        raise ReceiptError("public operation identity required")
    for name in [
        "genesis_root",
        "genesis_file",
        "sender_code_hash",
        "recipient_code_hash",
        "external_message_hash",
        "body_hash",
    ]:
        digest(intent[name])
    for name in ["sender", "recipient"]:
        if not isinstance(intent[name], str) or not re.fullmatch(
            r"(?:-1|0):[0-9a-f]{64}", intent[name]
        ):
            raise ReceiptError("canonical test-chain address required")
    if intent["sender"] == intent["recipient"] or type(intent["bounce"]) is not bool:
        raise ReceiptError("distinct accounts and explicit bounce required")
    for name, low, high in [
        ("value_nanotos", 1, (1 << 64) - 1),
        ("credited_nanotos", 0, (1 << 64) - 1),
        ("history_limit", 1, 1024),
        ("max_age_seconds", 1, 3600),
        ("timeout_seconds", 1, 300),
    ]:
        if type(intent[name]) is not int or not low <= intent[name] <= high:
            raise ReceiptError("public intent bound")
    if (
        intent["credited_nanotos"] > intent["value_nanotos"]
        or type(intent["rpc"]) is not list
        or len(intent["rpc"]) != 2
        or intent["rpc"][0] == intent["rpc"][1]
    ):
        raise ReceiptError("credit and two-source bounds")
    for endpoint in intent["rpc"]:
        if not isinstance(endpoint, str) or len(endpoint) > 2048:
            raise ReceiptError("public RPC endpoint bound")
        url = urlsplit(endpoint)
        if (
            url.scheme not in ("http", "https")
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
        ):
            raise ReceiptError("plain approved public RPC endpoint required")


@dataclass(frozen=True)
class PinnedProgram:
    path: Path
    sha256: str

    @contextmanager
    def opened(self):
        digest(self.sha256)
        if not self.path.is_absolute():
            raise ReceiptError("absolute pinned program required")
        private_directory(self.path.parent)
        fd = os.open(
            self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        )
        try:
            meta = os.fstat(fd)
            if (
                not stat.S_ISREG(meta.st_mode)
                or meta.st_uid not in (0, os.geteuid())
                or meta.st_nlink != 1
                or meta.st_mode & 0o222
                or not meta.st_mode & 0o100
                or not 0 < meta.st_size <= MAX_PROGRAM
            ):
                raise ReceiptError("immutable single-link pinned program required")
            hasher = hashlib.sha256()
            size = 0
            while block := os.read(fd, 1 << 20):
                size += len(block)
                if size > MAX_PROGRAM:
                    raise ReceiptError("program grew beyond bound")
                hasher.update(block)
            if size != meta.st_size or hasher.hexdigest() != self.sha256:
                raise ReceiptError("program identity mismatch")
            yield fd
            after = os.stat(self.path, follow_symlinks=False)
            if (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) != (
                meta.st_dev,
                meta.st_ino,
                meta.st_size,
                meta.st_mtime_ns,
                meta.st_ctime_ns,
            ):
                raise ReceiptError("pinned program changed during worker")
        finally:
            os.close(fd)


def write_public(path, data, limit):
    if not isinstance(data, bytes) or not 0 < len(data) <= limit:
        raise ReceiptError("public input size bound")
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400
    )
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        raise ReceiptError("native worker cleanup unproven") from error


def run_bounded(argv, pass_fd, monitor_fd, seconds):
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "TOKIO_WORKER_THREADS": "2",
            "RAYON_NUM_THREADS": "2",
        },
        pass_fds=(pass_fd,),
        start_new_session=True,
    )
    stdout, stderr = bytearray(), bytearray()
    monitor = None
    try:
        monitor = subprocess.Popen(
            [f"/proc/self/fd/{monitor_fd}", str(process.pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            pass_fds=(monitor_fd,),
            start_new_session=True,
        )
        with selectors.DefaultSelector() as selector:
            for stream, target in [(process.stdout, stdout), (process.stderr, stderr)]:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, target)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ReceiptError("native delivery worker deadline")
                if monitor.poll() is not None and process.poll() is None:
                    raise ReceiptError("thermal watcher stopped before native worker")
                for event, _mask in selector.select(min(remaining, 0.25)):
                    block = os.read(event.fileobj.fileno(), 16384)
                    if not block:
                        selector.unregister(event.fileobj)
                        continue
                    event.data.extend(block)
                    if len(event.data) > MAX_OUTPUT:
                        raise ReceiptError("native worker output bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReceiptError("native delivery worker deadline")
        if process.wait(timeout=remaining) != 0:
            category = None
            for marker, label in [
                (b"approved outgoing action missing", "APPROVED_OUTGOING_MISSING"),
                (b"transaction pre-state hash mismatch", "PRE_STATE_HASH_MISMATCH"),
            ]:
                if marker in stderr:
                    category = label
                    break
            raise ReceiptError(
                "native delivery refused; original operation remains unknown",
                category=category,
            )
        return bytes(stdout)
    except subprocess.TimeoutExpired as error:
        raise ReceiptError("native delivery worker deadline") from error
    finally:
        try:
            try:
                stop_group(process)
            finally:
                if monitor is not None:
                    stop_group(monitor)
        finally:
            process.stdout.close()
            process.stderr.close()


@dataclass(frozen=True)
class DeliveryEvidence:
    receipt: dict
    original_message_hash: str
    intent_sha256: str
    receipt_sha256: str
    artifact_directory: str
    business_acceptance: bool = False
    authorizes_send: bool = False


def verify_delivery(
    cli,
    helper,
    intent_raw,
    sender_preimage,
    recipient_preimage,
    anchor_raw,
    lite_raw,
    directory,
    *,
    thermal_monitor,
    worker_seconds=125,
):
    """Verify one original delivery; returns evidence, NEVER a SendGate verdict.

    Inputs are locally approved public bytes. The new artifact directory is
    retained; existing directories refuse. Resource/cgroup/total-artifact bounds
    also belong to the caller's finite, separately reviewed controller service.
    """
    intent = decode_json(intent_raw)
    validate_intent(intent)
    anchor = decode_json(anchor_raw)
    if (
        type(anchor) is not dict
        or anchor.get("kind") != "zerostate"
        or type(anchor.get("seqno")) is not int
        or anchor["seqno"] != 0
        or anchor.get("root_hash") != intent["genesis_root"]
        or anchor.get("file_hash") != intent["genesis_file"]
    ):
        raise ReceiptError("intent differs from approved full genesis")
    if type(worker_seconds) is not int or not 1 <= worker_seconds <= 305:
        raise ReceiptError("bounded worker deadline required")
    if not isinstance(lite_raw, bytes) or not 0 < len(lite_raw) <= MAX_PREIMAGE:
        raise ReceiptError("public lite config bound")
    if any(
        not isinstance(blob, bytes) or not 0 < len(blob) <= MAX_PREIMAGE
        for blob in [sender_preimage, recipient_preimage]
    ):
        raise ReceiptError("public preimage bound")
    directory = Path(directory)
    private_directory(directory.parent)
    with ExitStack() as stack:
        cli_fd = stack.enter_context(cli.opened())
        stack.enter_context(helper.opened())
        monitor_fd = stack.enter_context(thermal_monitor.opened())
        directory.mkdir(mode=0o700)
        private_directory(directory)
        for name, blob, limit in [
            ("intent.json", intent_raw, MAX_JSON),
            ("sender-pre-state.boc", sender_preimage, MAX_PREIMAGE),
            ("recipient-pre-state.boc", recipient_preimage, MAX_PREIMAGE),
            ("anchor.json", anchor_raw, MAX_JSON),
            ("lite.json", lite_raw, MAX_PREIMAGE),
        ]:
            write_public(directory / name, blob, limit)
        config = {
            "executable": str(helper.path),
            "anchor_file": str(directory / "anchor.json"),
            "liteserver_config": str(directory / "lite.json"),
            "live_state_file": str(directory / "live-state.json"),
            "live_max_age_seconds": intent["max_age_seconds"],
            "timeout_seconds": min(intent["timeout_seconds"], worker_seconds),
            "min_interval_ms": 0,
        }
        write_public(directory / "proof-config.json", canonical(config), MAX_JSON)
        parent = os.open(directory, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        argv = [
            f"/proc/self/fd/{cli_fd}",
            "wallet",
            "receipt",
            "--intent",
            str(directory / "intent.json"),
            "--sender-pre-state",
            str(directory / "sender-pre-state.boc"),
            "--recipient-pre-state",
            str(directory / "recipient-pre-state.boc"),
            "--proof-config",
            str(directory / "proof-config.json"),
        ]
        raw = run_bounded(argv, cli_fd, monitor_fd, worker_seconds)
        report = decode_json(raw)
        if (
            type(report) is not dict
            or set(report) != RECEIPT_FIELDS
            or report["schema"] != "tos.operation-delivery-receipt/1"
            or report["status"] != "AUTHENTICATED_REQUEST_AND_DELIVERY"
            or report["operation"] != intent["operation"]
            or report["intent_sha256"] != hashlib.sha256(intent_raw).hexdigest()
            or report["business_acceptance"] is not False
            or report["authorizes_send"] is not False
        ):
            raise ReceiptError(
                "native receipt identity or read-only semantics mismatch"
            )
        checkpoint = report["checkpoint"]
        if (
            type(checkpoint) is not dict
            or set(checkpoint) != {"seqno", "root_hash", "file_hash"}
            or type(checkpoint["seqno"]) is not int
            or not 0 <= checkpoint["seqno"] <= (1 << 32) - 1
        ):
            raise ReceiptError("native checkpoint schema mismatch")
        for value in [
            checkpoint["root_hash"],
            checkpoint["file_hash"],
            report["sender_transaction"],
            report["recipient_transaction"],
            report["delivery_message"],
        ]:
            digest(value)
        write_public(directory / "receipt.json", raw, MAX_JSON)
        evidence = DeliveryEvidence(
            report,
            intent["external_message_hash"],
            hashlib.sha256(intent_raw).hexdigest(),
            hashlib.sha256(raw).hexdigest(),
            str(directory),
        )
    return evidence
