"""Local-test send admission; no signer, RPC adapter or transaction verifier.

A single financial producer must use the gate's sole RPC endpoint. Its caller
must hold admitted_read through response publication. Already delivered reads
cannot be revoked: concurrent signers and alternative endpoints are unsupported.
Only a trusted, independently reviewed native-receipt verifier may authorize.
The hash chain detects corruption, not an owner rewriting/rolling back storage.
"""

import fcntl
import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path

MAX_BYTES = 1 << 20
MAX_RECORDS = 257
MAX_LINE = 2048
HEX = re.compile(r"[0-9a-f]{64}\Z")


class GateError(ValueError):
    pass


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise GateError("duplicate journal key")
        value[key] = item
    return value


def private_directory(directory):
    directory = Path(directory)
    if not directory.is_absolute():
        raise GateError("absolute private directory required")
    for position, path in enumerate([directory, *directory.parents]):
        meta = path.lstat()
        trusted = meta.st_uid in (0, os.geteuid())
        protected = not meta.st_mode & 0o022 or (
            meta.st_uid == 0 and meta.st_mode & stat.S_ISVTX
        )
        if not stat.S_ISDIR(meta.st_mode) or not trusted or not protected:
            raise GateError("unsafe journal directory or ancestor")
        if position == 0 and (
            meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) != 0o700
        ):
            raise GateError("journal directory must be operator-owned mode0700")
    return directory


class SendGate:
    def __init__(self, directory, context):
        fields = {"case", "genesis_root", "genesis_file", "cli_sha256"}
        if type(context) is not dict or set(context) != fields:
            raise GateError("exact case/network/CLI context required")
        if not isinstance(context["case"], str) or not re.fullmatch(
            r"[a-z0-9-]{1,64}", context["case"]
        ):
            raise GateError("invalid case identity")
        if any(
            not isinstance(context[key], str) or not HEX.fullmatch(context[key])
            for key in fields - {"case"}
        ):
            raise GateError("invalid public context digest")
        self.context = dict(context)
        self._mutex = threading.RLock()
        self._fd = None
        self._admitted = False  # Never restored from an earlier process's permit.
        self._poisoned = False
        self._records = 0
        self._hash = "0" * 64
        self._last = None
        directory = private_directory(directory)
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_APPEND
        path = directory / "send-admission.jsonl"
        try:
            try:
                fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
                created = True
            except FileExistsError:
                fd = os.open(path, flags)
                created = False
            self._fd = fd
            meta = os.fstat(fd)
            if (
                not stat.S_ISREG(meta.st_mode)
                or meta.st_uid != os.geteuid()
                or meta.st_nlink != 1
                or stat.S_IMODE(meta.st_mode) != 0o600
            ):
                raise GateError("unsafe journal file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if created:
                self._append(
                    {"event": "created", "operation": 0, "context": self.context}
                )
                parent = os.open(
                    directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            else:
                self._load()
        except BaseException:
            self.close()
            raise

    def _load(self):
        if not 0 < os.fstat(self._fd).st_size <= MAX_BYTES:
            raise GateError("empty or oversized existing journal")
        os.lseek(self._fd, 0, os.SEEK_SET)
        expected_size = os.fstat(self._fd).st_size
        data = os.read(self._fd, MAX_BYTES + 1)
        if len(data) != expected_size:
            raise GateError("incomplete journal read")
        if not data.endswith(b"\n"):
            raise GateError("incomplete journal record")
        for line in data.splitlines():
            if len(line) > MAX_LINE or self._records >= MAX_RECORDS:
                raise GateError("journal bound exceeded")
            try:
                row = json.loads(line, object_pairs_hook=unique_object)
            except (ValueError, UnicodeError) as error:
                raise GateError("invalid journal encoding") from error
            if type(row) is not dict or set(row) != {"payload", "previous", "hash"}:
                raise GateError("invalid journal shape")
            payload = row["payload"]
            if (
                type(payload) is not dict
                or type(payload.get("sequence")) is not int
                or payload["sequence"] != self._records
            ):
                raise GateError("noncontiguous journal sequence")
            digest = hashlib.sha256(
                bytes.fromhex(self._hash) + canonical(payload)
            ).hexdigest()
            if row["previous"] != self._hash or row["hash"] != digest:
                raise GateError("journal integrity mismatch")
            self._validate_transition(payload)
            self._hash, self._last = digest, payload
            self._records += 1

    def _validate_transition(self, value):
        event, operation = value.get("event"), value.get("operation")
        if type(operation) is not int or not 0 <= operation <= MAX_RECORDS:
            raise GateError("invalid operation sequence")
        if self._last is None:
            if (
                set(value) != {"sequence", "event", "operation", "context"}
                or event != "created"
                or operation != 0
                or value["context"] != self.context
            ):
                raise GateError("journal context mismatch")
        elif event == "admitted":
            if (
                set(value) != {"sequence", "event", "operation", "proof_digest"}
                or self._last["event"] not in ("created", "latched")
                or operation != self._last["operation"]
            ):
                raise GateError("invalid admission transition")
            if not isinstance(value["proof_digest"], str) or not HEX.fullmatch(
                value["proof_digest"]
            ):
                raise GateError("invalid public proof digest")
        elif event == "latched":
            if (
                set(value) != {"sequence", "event", "operation"}
                or self._last["event"] != "admitted"
                or operation != self._last["operation"] + 1
            ):
                raise GateError("invalid forward transition")
        else:
            raise GateError("unknown journal event")

    def _append(self, fields):
        payload = dict(fields, sequence=self._records)
        self._validate_transition(payload)
        digest = hashlib.sha256(
            bytes.fromhex(self._hash) + canonical(payload)
        ).hexdigest()
        line = (
            canonical({"payload": payload, "previous": self._hash, "hash": digest})
            + b"\n"
        )
        if (
            self._records >= MAX_RECORDS
            or len(line) > MAX_LINE
            or os.fstat(self._fd).st_size + len(line) > MAX_BYTES
        ):
            raise GateError("journal capacity exhausted")
        self._poisoned = True
        remaining = memoryview(line)
        while remaining:
            count = os.write(self._fd, remaining)
            if count <= 0:
                raise OSError("journal write made no progress")
            remaining = remaining[count:]
        os.fsync(self._fd)
        self._hash, self._last = digest, payload
        self._records += 1
        self._poisoned = False

    def _healthy(self):
        if self._fd is None or self._poisoned:
            raise GateError("gate closed or storage uncertain")

    def authorize(self, verifier):
        """Trusted verifier returns exact context/operation/public-proof digest.

        Operation0 needs fresh initial native admission; later operations need
        exact original-message settlement. Time, RPC acknowledgement and an
        increased unrelated seqno are not receipt verifiers. This library does
        not implement that native verifier and is not a ready execution tool.
        """
        with self._mutex:
            self._healthy()
            self._admitted = False
            if self._last["event"] == "admitted":
                raise GateError(
                    "unconsumed prior admission cannot be automatically resumed"
                )
            operation = self._last["operation"]
            verdict = verifier(dict(self.context), operation)
            if (
                type(verdict) is not dict
                or set(verdict) != {"context", "operation", "proof_digest"}
                or verdict["context"] != self.context
                or type(verdict["operation"]) is not int
                or verdict["operation"] != operation
            ):
                raise GateError("receipt context or operation mismatch")
            self._append(
                {
                    "event": "admitted",
                    "operation": operation,
                    "proof_digest": verdict["proof_digest"],
                }
            )
            self._admitted = True

    def admitted_read(self, fetch_and_publish):
        """Hold serialization through BOTH backend read and response publication."""
        with self._mutex:
            self._healthy()
            if not self._admitted:
                raise GateError(
                    "RPC reads held pending admission or original settlement"
                )
            return fetch_and_publish()

    def forward_once(self, forward):
        with self._mutex:
            self._healthy()
            if not self._admitted:
                raise GateError("send held pending admission or original settlement")
            self._admitted = False
            operation = self._last["operation"] + 1
            self._append({"event": "latched", "operation": operation})
            # No acknowledge/error path reopens the gate. The caller must bound
            # this callback's entire network exchange and must never retry it.
            return forward(operation)

    def metrics(self):
        with self._mutex:
            return {
                "admitted": self._admitted,
                "poisoned": self._poisoned,
                "records": self._records,
                "operation": self._last["operation"] if self._last else None,
            }

    def close(self):
        with self._mutex:
            self._admitted = False
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
