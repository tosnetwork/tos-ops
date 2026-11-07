#!/usr/bin/env python3
"""Read-only reconciliation of one closed qualified load run (launch gate 3).

    load_fence_reconcile.py --state DIR --ceremony DIR --run qualification-N
        --closed-audit FILE --reservations FILE --owner-matches FILE
        --funding-owner-address ADDR [--operator-wallet ADDR ...]
        --global-id N --genesis-root HEX --genesis-file HEX --min-query-id N
        --chain-reads --source URL --source URL --out NEW_FILE

It answers one question: do the original run's populations (offered, accepted,
executed, native-finalized, pending, unconfirmed, not offered, funding
reservations, operation journals, query-id counter) and its unfinished-run
fence agree with the public closed-run evidence? It never resets, replays,
clears, re-signs or resends anything, and it never writes the fence marker.

Boundaries, each enforced in code and by an audit hook:

* Only allowlisted names are opened, read-only. Each root is walked from / with
  O_NOFOLLOW|O_DIRECTORY at every level; only the leading system prefixes may be
  root-owned, and every component below them must be owned by this uid.
  Keys (highload.key, *.pk, ceremony secret/), signed messages (*.boc,
  ceremony sent/, carrier archives), native captures and dry-run directories
  are never opened. The carrier archive directory is listed for names and
  sizes only.
* No lock is taken. Locks are observed in /proc/locks, twice; the result says
  "free as observed", and a later launch still takes the producer's own lock.
* Operation journals store each signed message inline (the "boc" member). The
  read buffer is the only place those bytes exist here: project_line() nulls
  the member's span in place before any JSON decoding, a line it cannot
  tokenize is wiped and not decoded, and every buffer is wiped before release.
  Journals are never hashed raw; only events.jsonl, the summary and result.json
  (which hold no signed bytes) are.
* Chain reads (required, two sources) are observation only: relayer seqnos and
  each source's masterchain seqno are reported, and never change a verdict.
* Errors carry a logical input id and a byte offset, never content. Core dumps
  are disabled before the first open.

The output is one new file (O_EXCL) of counts, ids, typed hashes, public
addresses and verdict words, checked by a secret scan before it is written.
"""

from __future__ import annotations

# Imported up front: a lazy import while the guard is active would open files.
import _strptime  # noqa: F401
import argparse
import calendar
import hashlib
import json
import math
import os
import re
import resource
import stat
import sys
import time

import testnet_lib as lib

# The high-load wallet's query-id space (testnet-elections.py:1982, load_qualification.py:20).
QUERY_LIMIT = 1 << 23
MAX_SMALL_BYTES = 1 << 24
MAX_EVENTS_BYTES = 1 << 31
MAX_SAMPLE = 64
MAX_LINE_BYTES = 1 << 18
JOURNAL_STATES = ("planned", "signed", "broadcast", "settled", "failed")  # testnet_ops.py:113
OPEN_STATES = ("planned", "signed", "broadcast")
READ_ONLY_RPC = frozenset({"getAddressInformation", "runGetMethod", "getMasterchainInfo"})

RECONCILED, UNRECONCILED, UNKNOWN = "RECONCILED", "UNRECONCILED", "UNKNOWN"
OBSERVED = "OBSERVED"
FENCE_OPEN = "FENCE_OPEN"
UNKNOWN_UNSTABLE = "UNKNOWN_UNSTABLE"
UNKNOWN_PRODUCER_LIVE = "UNKNOWN_PRODUCER_LIVE"
ELIGIBLE = "RECONCILED_LAUNCH_ELIGIBLE"
LOCK_FREE, LOCK_HELD = "FREE_AS_OBSERVED", "HELD"
STATEMENT = "lock free as observed at t0 and t1 only; a launch still takes the producer lock"

EVENT_KINDS = frozenset(
    {
        "offered",
        "not_offered",
        "accepted",
        "executed",
        "unconfirmed",
        "funding_reserved",
        "funding_settled",
        "funding_unknown",
        "admission_stopped",
        "fee_observation",
        "broadcast_timing",
        "native_baseline",
        "native_checkpoint",
        "native_stage_started",
        "native_stage_sealed",
        "native_stage_finalized",
    }
)
# What a journal line keeps after projection (testnet_ops.py:1686, 1744-1753, 1844).
JOURNAL_KEYS = frozenset(
    {
        "state",
        "kind",
        "wallet",
        "destination",
        "value",
        "label",
        "purpose",
        "seqno",
        "external_hash",
        "evidence",
        "utc",
        "name",
    }
)

RUN_NAME = re.compile(r"^qualification-[0-9]{1,20}$")
SUMMARY_NAME = re.compile(r"^summary-[0-9]{8}T[0-9]{6}Z\.json$")
RELAYER_ADDR = re.compile(r"^relayer-([0-9]{1,4})\.addr$")
OUTBOX_NAME = re.compile(r"^ext-([0-9]{1,4})-([0-9]{1,10})-([0-9]{1,7})\.boc$")
JOURNAL_NAME = re.compile(r"^([a-z0-9][a-z0-9._-]{0,80})\.jsonl$")  # testnet_ops.py:52, 838
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ADDRESS = re.compile(r"^-?[0-9]{1,3}:[0-9a-f]{64}$")
RAW_ADDRESS = re.compile(r"^(-?[0-9]{1,3}):([0-9a-fA-F]{64})$")
LABEL = re.compile(r"^load-[a-z]+(?:-[a-z]+)*(?:-[0-9]{1,4})?$")
LOGICAL_ID = re.compile(r"^(?:state|run|prior\[[0-9]+\]|ops|public|proc):[a-z0-9_.\[\]-]{1,64}$")

# Never opened (testnet-elections.py:2431, 2494, 2571, 2587, 2677, 673, 919;
# load_qualification.py:225; load_finality_collector.py:403).
DENIED_PARTS = frozenset({"secret", "sent", "native-captures"})
DENIED_NAMES = frozenset({"highload.key", "highload.pub", "gid.fif", "qualification.lock", ".lock"})
DENIED_SUFFIXES = (".pk", ".key", ".boc", ".tmp", ".bin", ".fif")
DIRECTORY_ONLY = frozenset({"private-outbox", "operations"})


def normalize_address(text) -> str | None:
    """The canonical raw form `wc:hex64` (lower-case hex), or None for any other form."""
    m = RAW_ADDRESS.match(text) if isinstance(text, str) else None
    if not m or not -128 <= int(m.group(1)) <= 127:
        return None
    return f"{int(m.group(1))}:{m.group(2).lower()}"


def denied(path: str, flags: int) -> bool:
    parts = [p for p in path.split("/") if p]
    if not parts:
        return False
    if any(p in DENIED_PARTS or p.startswith("dry-run-") for p in parts):
        return True
    name = parts[-1]
    if name in DIRECTORY_ONLY:
        return not flags & os.O_DIRECTORY
    return name in DENIED_NAMES or name.endswith(DENIED_SUFFIXES)


# ---------------------------------------------------------------- guard


class Refused(Exception):
    """A logical refusal: an input id, a byte offset and a code; never content."""

    def __init__(self, input_id: str, offset: int, code: str):
        super().__init__(code)
        self.input_id, self.offset, self.code = input_id, offset, code

    def __str__(self) -> str:
        return f"{self.code} input={self.input_id} offset={self.offset}"

    def entry(self) -> dict:
        return {"input": self.input_id, "offset": self.offset, "code": self.code}


GUARD = {"active": False, "out": None, "violations": 0, "core_at_first_open": None}
_HOOKED = []


def _audit(event, args):
    if not GUARD["active"]:
        return
    if event != "open":
        return
    path, _mode, flags = args
    if isinstance(path, int) or path is None:
        return
    name = os.fsdecode(path)
    flags = flags or 0
    if GUARD["core_at_first_open"] is None:
        GUARD["core_at_first_open"] = resource.getrlimit(resource.RLIMIT_CORE)[0]
    writing = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
    if denied(name, flags) or (writing and name != GUARD["out"]):
        GUARD["violations"] += 1
        raise PermissionError("refused by the reconcile allowlist")


def install_guard() -> None:
    if not _HOOKED:
        sys.addaudithook(_audit)
        _HOOKED.append(True)


def disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


# ---------------------------------------------------------------- projection


def _skip_ws(buf: bytearray, i: int, end: int) -> int:
    while i < end and buf[i] in b" \t\r\n":
        i += 1
    return i


HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")


def _string_end(buf: bytearray, i: int, end: int) -> int:
    """Index after the JSON string starting at buf[i] == '"', or -1.

    Escapes are validated without decoding: \\" \\\\ \\/ \\b \\f \\n \\r \\t, or \\u and exactly
    four hex digits; any other escape or a control byte refuses the string."""
    i += 1
    while i < end:
        c = buf[i]
        if c == 0x5C:
            if i + 1 >= end:
                return -1
            e = buf[i + 1]
            if e == 0x75:
                if i + 6 > end or not all(buf[k] in HEX_DIGITS for k in range(i + 2, i + 6)):
                    return -1
                i += 6
                continue
            if e not in b'"\\/bfnrt':
                return -1
            i += 2
            continue
        if c == 0x22:
            return i + 1
        if c < 0x20:
            return -1
        i += 1
    return -1


def _value_end(buf: bytearray, i: int, end: int) -> int:
    """Index after the JSON value at buf[i], structure only, or -1."""
    if i >= end:
        return -1
    if buf[i] == 0x22:
        return _string_end(buf, i, end)
    if buf[i] in b"{[":
        depth = 0
        while i < end:
            c = buf[i]
            if c == 0x22:
                i = _string_end(buf, i, end)
                if i < 0:
                    return -1
                continue
            if c in b"{[":
                depth += 1
            elif c in b"}]":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return -1
    while i < end and buf[i] not in b",}] \t\r\n":
        i += 1
    return i


def _wipe(buf: bytearray, start: int, end: int) -> None:
    if end > start:
        buf[start:end] = b" " * (end - start)


def project_line(buf: bytearray, start: int, end: int, input_id: str) -> dict:
    """One JSON object from buf[start:end] with its top-level "boc" string nulled
    in place before anything decodes it.

    The tokenizer tracks string and escape state; a key with an escape, a "boc"
    value that is not a string, two "boc" members or any structural error refuses
    the line: it is wiped in place and never decoded."""
    try:
        spans = []
        i = _skip_ws(buf, start, end)
        if i >= end or buf[i] != 0x7B:
            raise ValueError
        i = _skip_ws(buf, i + 1, end)
        if i < end and buf[i] == 0x7D:
            i += 1
        else:
            while True:
                if i >= end or buf[i] != 0x22:
                    raise ValueError
                key_end = _string_end(buf, i, end)
                if key_end < 0 or 0x5C in buf[i:key_end]:
                    raise ValueError
                is_boc = buf[i:key_end] == b'"boc"'
                i = _skip_ws(buf, key_end, end)
                if i >= end or buf[i] != 0x3A:
                    raise ValueError
                i = _skip_ws(buf, i + 1, end)
                value_end = _value_end(buf, i, end)
                if value_end < 0:
                    raise ValueError
                if is_boc:
                    if buf[i] != 0x22 or value_end - i < 4:
                        raise ValueError
                    spans.append((i, value_end))
                i = _skip_ws(buf, value_end, end)
                if i < end and buf[i] == 0x2C:
                    i = _skip_ws(buf, i + 1, end)
                    continue
                if i < end and buf[i] == 0x7D:
                    i += 1
                    break
                raise ValueError
        if _skip_ws(buf, i, end) != end or len(spans) > 1:
            raise ValueError
        for value_start, value_end in spans:
            buf[value_start : value_start + 4] = b"null"
            _wipe(buf, value_start + 4, value_end)
    except ValueError:
        _wipe(buf, start, end)
        raise Refused(input_id, start, "line_not_tokenizable") from None
    try:
        doc = json.loads(buf[start:end])
    except ValueError:
        _wipe(buf, start, end)
        raise Refused(input_id, start, "line_not_json") from None
    if not isinstance(doc, dict) or doc.get("boc") is not None:
        raise Refused(input_id, start, "line_not_object")
    doc.pop("boc", None)
    return doc


def lines_of(buf: bytearray, input_id: str):
    """(offset, projected dict | Refused) for each newline-terminated line; a torn
    last line is wiped and refused."""
    start = 0
    size = len(buf)
    while start < size:
        nl = buf.find(b"\n", start)
        if nl < 0:
            _wipe(buf, start, size)
            yield start, Refused(input_id, start, "torn_last_line")
            return
        if nl > start:
            try:
                yield start, project_line(buf, start, nl, input_id)
            except Refused as exc:
                yield start, exc
        start = nl + 1


def wipe_buffer(buf: bytearray) -> None:
    buf[0 : len(buf)] = bytes(len(buf))


# ---------------------------------------------------------------- safe reads


def _check(info: os.stat_result, want_dir: bool, input_id: str) -> None:
    kind = stat.S_ISDIR(info.st_mode) if want_dir else stat.S_ISREG(info.st_mode)
    if not kind or info.st_uid != os.geteuid():
        raise Refused(input_id, 0, "not_owned_or_wrong_type")


def identity_of(info: os.stat_result) -> list:
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]


# Leading path components that may be system-owned. Everything below the first
# component outside this set must be owned by this uid (_check).
SYSTEM_PREFIXES = frozenset({"/", "/home", "/tos"})


def _overflow_uid() -> int:
    """The uid an unmapped owner shows as inside a user namespace."""
    try:
        with open("/proc/sys/kernel/overflowuid", "rb") as source:
            return int(source.read(16).strip())
    except (OSError, ValueError):
        return -1


SYSTEM_OWNERS = frozenset({0, _overflow_uid()})


def _check_system(info: os.stat_result, input_id: str) -> None:
    """A system prefix directory: root-owned (or this uid), never writable by
    group or others unless sticky."""
    writable = info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX
    owner_ok = info.st_uid in SYSTEM_OWNERS or info.st_uid == os.getuid()
    if not stat.S_ISDIR(info.st_mode) or not owner_ok or writable:
        raise Refused(input_id, 0, "not_owned_or_wrong_type")


class Reader:
    """Every input opened through a directory fd, read-only, O_NOFOLLOW."""

    FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    DIR = FILE | os.O_DIRECTORY

    def __init__(self):
        self.opened: list[str] = []
        self.idents: dict[str, list] = {}
        self.digests: dict[str, str] = {}
        self.errors: list[dict] = []
        self.fds: list[int] = []

    def close(self) -> None:
        for fd in self.fds:
            os.close(fd)
        self.fds = []

    def _note(self, input_id: str) -> None:
        if input_id not in self.opened:
            self.opened.append(input_id)

    def root(self, path: str, input_id: str) -> int:
        """Walk from / one component at a time, O_NOFOLLOW|O_DIRECTORY at every
        level: system prefixes by rule, everything below owned by this uid."""
        path = os.path.abspath(path)
        parts = [p for p in path.split("/") if p]
        if any(p in (".", "..") for p in parts):
            raise Refused(input_id, 0, "root_unavailable")
        try:
            fd = os.open("/", self.DIR)
        except OSError:
            raise Refused(input_id, 0, "root_unavailable") from None
        walked, system = "/", True
        try:
            _check_system(os.fstat(fd), input_id)
            for part in parts:
                try:
                    child = os.open(part, self.DIR, dir_fd=fd)
                except OSError:
                    raise Refused(input_id, 0, "root_unavailable") from None
                os.close(fd)
                fd = child
                walked = os.path.join(walked, part)
                system = system and walked in SYSTEM_PREFIXES
                if system:
                    _check_system(os.fstat(fd), input_id)
                else:
                    _check(os.fstat(fd), True, input_id)
            if system:
                raise Refused(input_id, 0, "not_owned_or_wrong_type")
        except BaseException:
            os.close(fd)
            raise
        self.fds.append(fd)
        info = os.fstat(fd)
        self.idents[input_id] = [info.st_dev, info.st_ino]
        self._note(input_id)
        return fd

    def subdir(self, parent: int, name: str, input_id: str) -> int:
        try:
            fd = os.open(name, self.DIR, dir_fd=parent)
        except OSError:
            raise Refused(input_id, 0, "directory_unavailable") from None
        self.fds.append(fd)
        info = os.fstat(fd)
        _check(info, True, input_id)
        self.idents[input_id] = [info.st_dev, info.st_ino]
        self._note(input_id)
        return fd

    def listing(self, fd: int) -> list[str]:
        return sorted(os.listdir(fd))

    def lstat(self, parent: int, name: str) -> os.stat_result | None:
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def read(self, parent: int, name: str, input_id: str, limit: int) -> bytearray:
        """The file's bytes in one new buffer (the only copy here)."""
        fd = self._open_file(parent, name, input_id)
        try:
            info = os.fstat(fd)
            _check(info, False, input_id)
            if info.st_size > limit:
                raise Refused(input_id, 0, "too_large")
            buf = bytearray(info.st_size)
            probe = bytearray(1)
            got = 0
            try:
                with memoryview(buf) as view:
                    while got < info.st_size:
                        count = os.readv(fd, [view[got:]])
                        if count == 0:
                            break
                        got += count
                grew = os.readv(fd, [probe])
            except OSError:
                wipe_buffer(buf)
                raise Refused(input_id, got, "unreadable") from None
            except BaseException:
                wipe_buffer(buf)
                raise
            finally:
                wipe_buffer(probe)
            if got != info.st_size or grew:
                wipe_buffer(buf)
                raise Refused(input_id, got, "changed_while_read")
            self.idents[input_id] = identity_of(info)
            self._note(input_id)
            return buf
        finally:
            os.close(fd)

    def _open_file(self, parent: int, name: str, input_id: str) -> int:
        """An allowlisted regular file under `parent`, read-only, O_NOFOLLOW."""
        if denied(name, 0):
            raise Refused(input_id, 0, "denied_name")
        try:
            fd = os.open(name, self.FILE, dir_fd=parent)
        except FileNotFoundError:
            raise Refused(input_id, 0, "missing") from None
        except OSError:
            raise Refused(input_id, 0, "unreadable") from None
        return fd

    def _line_buffer(self) -> bytearray:
        """The one fixed buffer a journal line is read into."""
        return bytearray(MAX_LINE_BYTES)

    def stream_lines(self, parent: int, name: str, input_id: str):
        """(offset, projected dict | Refused) for each line of a journal, read one
        bounded line at a time into a fixed buffer.

        Bytes read past a newline belong to the next line and are wiped before
        the line is projected, so at decode time the buffer holds only this
        line, with its boc already nulled. The buffer is wiped after each line.
        A line longer than the bound, a torn last line or a file that changes
        while it is read refuses the rest of the file."""
        fd = self._open_file(parent, name, input_id)
        buf = self._line_buffer()
        try:
            info = os.fstat(fd)
            _check(info, False, input_id)
            self.idents[input_id] = identity_of(info)
            self._note(input_id)
            position = 0
            while True:
                fill, newline, failed = 0, -1, None
                while newline < 0 and failed is None:
                    if fill >= len(buf):
                        failed = "line_too_long"
                        break
                    try:
                        with memoryview(buf) as view:
                            count = os.preadv(fd, [view[fill : fill + 65536]], position + fill)
                    except OSError:
                        failed = "unreadable"
                        break
                    if count == 0:
                        failed = "torn_last_line" if fill else "end"
                        break
                    found = buf.find(b"\n", fill, fill + count)
                    if found >= 0:
                        _wipe(buf, found + 1, fill + count)  # the next line's bytes
                        newline = found
                    fill += count
                if failed is not None:
                    wipe_buffer(buf)
                    if failed != "end":
                        yield position, Refused(input_id, position, failed)
                    break
                if newline > 0:
                    try:
                        yield position, project_line(buf, 0, newline, input_id)
                    except Refused as exc:
                        yield position, exc
                buf[0:fill] = bytes(fill)
                position += newline + 1
            if identity_of(os.fstat(fd)) != self.idents[input_id] or position != info.st_size:
                if failed == "end":
                    yield position, Refused(input_id, position, "changed_while_read")
        finally:
            wipe_buffer(buf)
            os.close(fd)

    def document(self, parent, name, input_id, raw_hash=False, limit=MAX_SMALL_BYTES) -> dict:
        """One JSON document through project_line. Its sha256 is taken over the raw
        bytes only for events, summary and result (raw_hash); every other document
        is hashed after projection, so a nulled member is never hashed."""
        buf = self.read(parent, name, input_id, limit)
        try:
            if raw_hash:
                self.digests[input_id] = hashlib.sha256(buf).hexdigest()
            doc = project_line(buf, 0, len(buf), input_id)
            if not raw_hash:
                self.digests[input_id] = hashlib.sha256(buf).hexdigest()
            return doc
        finally:
            wipe_buffer(buf)

    def address(self, parent: int, name: str, input_id: str) -> str:
        buf = self.read(parent, name, input_id, 64)
        try:
            if len(buf) != 36:  # testnet-elections.py:2140-2145
                raise Refused(input_id, 0, "not_an_address_file")
            self.digests[input_id] = hashlib.sha256(buf).hexdigest()
            return f"{int.from_bytes(buf[32:], 'big', signed=True)}:{buf[:32].hex()}"
        finally:
            wipe_buffer(buf)


# ---------------------------------------------------------------- locks


def proc_locks(path: str) -> set | None:
    """(major, minor, inode) of every lock in /proc/locks, or None when unreadable."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    held = set()
    for line in b"".join(chunks).decode("ascii", "replace").splitlines():
        for token in line.split():
            m = re.match(r"^([0-9a-f]+):([0-9a-f]+):([0-9]+)$", token)
            if m:
                held.add((int(m.group(1), 16), int(m.group(2), 16), int(m.group(3))))
    return held


def lock_state(info: os.stat_result | None, held: set | None) -> str:
    if info is None or held is None or not stat.S_ISREG(info.st_mode):
        return UNKNOWN
    key = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
    return LOCK_HELD if key in held else LOCK_FREE


# ---------------------------------------------------------------- query ids


def next_query_id(query_id: int) -> int:
    """testnet-elections.py:2060-2068: +1, skip low ten bits 1023, wrap at 2^23."""
    query_id += 1
    if query_id & 1023 == 1023:
        query_id += 1
    return 0 if query_id >= QUERY_LIMIT else query_id


def usable_query_id(value) -> bool:
    return type(value) is int and 0 <= value < QUERY_LIMIT and value & 1023 != 1023


def sample(ids) -> list[int]:
    return sorted(ids)[:MAX_SAMPLE]


# ---------------------------------------------------------------- collection


def _refusal(reader: Reader, exc: Refused) -> None:
    reader.errors.append(exc.entry())


def collect(args, reader: Reader) -> dict:
    """One complete read of every allowlisted input; facts only, no verdicts."""
    facts: dict = {"run": args.run}
    st = reader.root(args.state, "state:root")
    names = reader.listing(st)
    reader.idents["state:listing"] = names
    for key, name, input_id in (
        ("marker", "qualification-active.json", "state:qualification-active"),
        ("identity", "qualification-identity.json", "state:qualification-identity"),
        ("counter", "load-state.json", "state:load-state"),
    ):
        try:
            facts[key] = reader.document(st, name, input_id)
        except Refused as exc:
            _refusal(reader, exc)
    try:
        facts["highload"] = reader.address(st, "highload.addr", "state:highload-addr")
    except Refused as exc:
        _refusal(reader, exc)
    relayers = {}
    for name in names:
        m = RELAYER_ADDR.match(name)
        if m:
            index = int(m.group(1))
            try:
                relayers[index] = reader.address(st, name, f"state:relayer-addr[{index}]")
            except Refused as exc:
                _refusal(reader, exc)
    facts["relayers"] = relayers
    lock = reader.lstat(st, "qualification.lock")
    facts["qualification_lock"] = lock
    reader.idents["state:qualification-lock"] = identity_of(lock)[:2] if lock else None

    runs = []
    for name in names:
        info = reader.lstat(st, name)
        if RUN_NAME.match(name) and info and stat.S_ISDIR(info.st_mode):
            runs.append(name)
    facts["runs"] = runs
    if args.run in runs:
        facts.update(collect_run(reader, st, args.run))
    prior_ids, prior_count = [], 0
    for index, name in enumerate(r for r in runs if r != args.run):
        if int(name.split("-")[1]) > int(args.run.split("-")[1]):
            facts["later_run"] = True
            continue
        prior_count += 1
        try:
            prior_ids.extend(collect_prior(reader, st, name, f"prior[{index}]"))
        except Refused as exc:
            _refusal(reader, exc)
            facts["prior_unreadable"] = True
    facts["prior_ids"], facts["prior_runs"] = prior_ids, prior_count

    summaries = []
    for index, name in enumerate(n for n in names if SUMMARY_NAME.match(n)):
        input_id = f"state:summary[{index}]"
        try:
            doc = reader.document(st, name, input_id, raw_hash=True)
        except Refused as exc:
            _refusal(reader, exc)
            facts["summary_unreadable"] = True
            continue
        qualification = doc.get("qualification")
        if isinstance(qualification, dict) and qualification.get("run_directory") == args.run:
            summaries.append((input_id, qualification))
    facts["summaries"] = [(i, q, reader.digests.get(i)) for i, q in summaries]

    facts.update(collect_journals(reader, args.ceremony))
    for key, path, input_id in (
        ("closed_audit", args.closed_audit, "public:closed-audit"),
        ("reservations", args.reservations, "public:reservations"),
        ("owner_matches", args.owner_matches, "public:owner-matches"),
        ("expected_wallets", args.expected_wallets, "public:expected-wallets"),
    ):
        try:
            facts[key] = public_document(reader, path, input_id)
        except Refused as exc:
            _refusal(reader, exc)
    return facts


def public_document(reader: Reader, path: str, input_id: str):
    """A public evidence file (refused inside the state or ceremony tree by run()).
    It holds no signed bytes; it is decoded from the one read buffer and wiped."""
    parent, name = os.path.split(os.path.abspath(path))
    fd = reader.root(parent, input_id + "-dir")
    buf = reader.read(fd, name, input_id, MAX_SMALL_BYTES)
    try:
        reader.digests[input_id] = hashlib.sha256(buf).hexdigest()
        try:
            return json.loads(buf)
        except ValueError:
            raise Refused(input_id, 0, "line_not_json") from None
    finally:
        wipe_buffer(buf)


def collect_run(reader: Reader, st: int, run: str) -> dict:
    out: dict = {"events": None}
    try:
        rd = reader.subdir(st, run, "run:root")
    except Refused as exc:
        _refusal(reader, exc)
        return out
    try:
        out["result"] = reader.document(rd, "result.json", "run:result", raw_hash=True)
    except Refused as exc:
        _refusal(reader, exc)
    try:
        buf = reader.read(rd, "events.jsonl", "run:events", MAX_EVENTS_BYTES)
    except Refused as exc:
        _refusal(reader, exc)
        buf = None
    if buf is not None:
        try:
            reader.digests["run:events"] = hashlib.sha256(buf).hexdigest()
            events, broken = [], False
            for _offset, item in lines_of(buf, "run:events"):
                if isinstance(item, Refused):
                    _refusal(reader, item)
                    broken = True
                    continue
                events.append(slim_event(item))
            out["events"] = None if broken else events
        finally:
            wipe_buffer(buf)
    try:
        od = reader.subdir(rd, "private-outbox", "run:outbox-listing")
        entries, odd = [], 0
        for name in reader.listing(od):
            m = OUTBOX_NAME.match(name)
            info = reader.lstat(od, name)
            if not m or info is None or not stat.S_ISREG(info.st_mode):
                odd += 1
                continue
            entries.append((int(m.group(1)), int(m.group(2)), int(m.group(3)), info.st_size))
        out["outbox"], out["outbox_odd"] = entries, odd
        reader.idents["run:outbox-entries"] = [[*e] for e in sorted(entries)] + [[odd]]
    except Refused as exc:
        _refusal(reader, exc)
    return out


def slim_event(doc: dict) -> dict:
    """The allowlisted fields of one events.jsonl line (load_qualification.py:156-169)."""
    keep = {
        "event",
        "time_unix",
        "query_ids",
        "query_id",
        "amount_nanotos",
        "label",
        "carrier_bytes",
        "signed_request_hashes",
        "checkpoint_seqno",
        "summary",
    }
    out = {k: doc[k] for k in keep if k in doc}
    summary = out.get("summary")
    if isinstance(summary, dict):
        out["summary"] = {
            k: summary.get(k) for k in ("native_pending", "native_finalized", "offered")
        }
    return out


def collect_prior(reader: Reader, st: int, name: str, tag: str) -> list[int]:
    rd = reader.subdir(st, name, f"{tag}:root")
    buf = reader.read(rd, "events.jsonl", f"{tag}:events", MAX_EVENTS_BYTES)
    ids = []
    try:
        reader.digests[f"{tag}:events"] = hashlib.sha256(buf).hexdigest()  # no signed bytes
        for _offset, item in lines_of(buf, f"{tag}:events"):
            if isinstance(item, Refused):
                raise item
            if item.get("event") in ("offered", "not_offered"):
                ids.extend(item.get("query_ids") or [])
    finally:
        wipe_buffer(buf)
    return ids


def collect_journals(reader: Reader, ceremony: str) -> dict:
    """Every ceremony/operations/*.jsonl journal, merged like testnet_ops.py:858-865
    after projection; baselines and hidden temporaries excluded (testnet_ops.py:877-884)."""
    out: dict = {"journals": None}
    try:
        cr = reader.root(ceremony, "ops:ceremony-root")
        od = reader.subdir(cr, "operations", "ops:listing")
    except Refused as exc:
        _refusal(reader, exc)
        return out
    out["operations_lock"] = reader.lstat(od, ".lock")
    lock = out["operations_lock"]
    reader.idents["ops:lock"] = identity_of(lock)[:2] if lock else None
    records, projection = [], []
    listed = reader.listing(od)
    reader.idents["ops:listing-names"] = listed
    names = [n for n in listed if JOURNAL_NAME.match(n) and not n.startswith(".")]
    for index, name in enumerate(n for n in names if not n.startswith("baseline-")):
        input_id = f"ops:journal[{index}]"
        record = {"index": index, "unknown": False}
        merged, first_utc = {}, None
        try:
            for offset, item in reader.stream_lines(od, name, input_id):
                if isinstance(item, Refused):
                    _refusal(reader, item)
                    record["unknown"] = True
                    continue
                if item.get("state") not in JOURNAL_STATES:  # testnet_ops.py:853
                    reader.errors.append({"input": input_id, "offset": offset, "code": "state"})
                    record["unknown"] = True
                    continue
                kept = {k: item[k] for k in JOURNAL_KEYS if k in item}
                evidence = kept.get("evidence")
                kept["evidence"] = (
                    {"wallet_tx": evidence.get("wallet_tx")} if isinstance(evidence, dict) else {}
                )
                if first_utc is None:
                    first_utc = kept.get("utc")
                if not kept["evidence"].get("wallet_tx"):
                    kept.pop("evidence")
                merged.update(kept)
        except Refused as exc:
            _refusal(reader, exc)
            records.append(dict(record, unknown=True))
            continue
        if not merged:
            record["unknown"] = True
        record.update(merged)
        record["op_id"] = JOURNAL_NAME.match(name).group(1)
        record["first_utc"] = first_utc
        records.append(record)
        projection.append(record)
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
    reader.digests["ops:projection"] = hashlib.sha256(canonical).hexdigest()
    out["journals"] = records
    return out


# ---------------------------------------------------------------- evaluation


def utc_seconds(text) -> float | None:
    try:
        return float(calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")))
    except (TypeError, ValueError):
        return None


def _pop(verdict: str, **counts) -> dict:
    return {"verdict": verdict, **counts}


def _ids(event: dict) -> list | None:
    ids = event.get("query_ids")
    if not isinstance(ids, list) or not all(usable_query_id(q) for q in ids):
        return None
    return ids


def evaluate_events(facts: dict, args) -> tuple[dict, dict]:
    """Population verdicts from events.jsonl and result.json."""
    pops: dict = {}
    extra: dict = {}
    events, result = facts.get("events"), facts.get("result")
    names = (
        "offered",
        "accepted",
        "executed_unconfirmed",
        "pending",
        "native_finalized",
        "not_offered",
        "funding",
    )
    if events is None or not isinstance(result, dict):
        return {n: _pop(UNKNOWN) for n in names}, extra
    if any(e.get("event") not in EVENT_KINDS for e in events):
        return {n: _pop(UNKNOWN, unknown_event_kinds=True) for n in names}, extra

    offered, not_offered, accepted, executed, unconfirmed, native = [], [], [], [], [], set()
    request_pairs, bad = [], 0
    offers = []
    last_native = None
    for e in events:
        kind = e["event"]
        if kind in ("offered", "not_offered", "native_checkpoint", "broadcast_timing"):
            ids = _ids(e)
            if ids is None:
                bad += 1
                continue
            if not ids and kind in ("offered", "not_offered"):
                bad += 1  # an offer of nothing is malformed, not a crash
                continue
            if kind == "offered":
                offered.extend(ids)
                offers.append((ids[0], e.get("carrier_bytes")))
                hashes = e.get("signed_request_hashes")
                if not isinstance(hashes, dict) or set(hashes) != {str(q) for q in ids}:
                    bad += 1
                else:
                    request_pairs.extend((q, hashes[str(q)]) for q in ids)
            elif kind == "not_offered":
                not_offered.extend(ids)
            elif kind == "native_checkpoint":
                native.update(ids)
                if isinstance(e.get("summary"), dict):
                    last_native = e["summary"]
        elif kind in ("accepted", "executed", "unconfirmed"):
            q = e.get("query_id")
            if not usable_query_id(q):
                bad += 1
                continue
            {"accepted": accepted, "executed": executed, "unconfirmed": unconfirmed}[kind].append(q)
        elif kind == "native_stage_finalized" and isinstance(e.get("summary"), dict):
            last_native = e["summary"]
    o, n = set(offered), set(not_offered)
    a, x, u = set(accepted), set(executed), set(unconfirmed)
    audit = facts.get("closed_audit") or {}
    audit_offered = audit.get("offered")
    dup = len(offered) - len(o)
    ok = (
        not bad
        and not dup
        and not (o & n)
        and type(audit_offered) is int
        and len(o) == audit_offered
        and result.get("offered") == len(o)
    )
    pops["offered"] = _pop(
        RECONCILED if ok else UNRECONCILED,
        count=len(o),
        duplicates=dup,
        malformed_events=bad,
        closed_audit_offered=audit_offered if type(audit_offered) is int else None,
    )
    ok = len(accepted) == len(a) and a <= o and result.get("accepted") == len(a)
    pops["accepted"] = _pop(RECONCILED if ok else UNRECONCILED, count=len(a))
    ok = (
        len(executed) == len(x)
        and len(unconfirmed) == len(u)
        and not (x & u)
        and x == o
        and not u
        and result.get("executed") == len(x)
        and result.get("unconfirmed") == len(u)
    )
    pops["executed_unconfirmed"] = _pop(
        RECONCILED if ok else UNRECONCILED, executed=len(x), unconfirmed=len(u)
    )
    pending = o - x - u
    ok = not pending and result.get("pending") == 0
    pops["pending"] = _pop(
        RECONCILED if ok else UNRECONCILED, count=len(pending), sample=sample(pending)
    )
    finality = result.get("native_finality")
    ok = (
        native == o
        and isinstance(finality, dict)
        and finality.get("native_pending") == 0
        and finality.get("native_finalized") == len(o)
        and finality.get("offered") == len(o)
        and isinstance(last_native, dict)
        and last_native.get("native_pending") == 0
    )
    pops["native_finalized"] = _pop(
        RECONCILED if ok else UNRECONCILED,
        count=len(native & o),
        missing=len(o - native),
        foreign=len(native - o),
        native_failure_recorded=isinstance(finality, dict) and finality.get("failure") is not None,
    )
    ok = (
        not n
        and result.get("not_offered") == 0
        and result.get("not_offered_unknown") is False
        and audit.get("not_offered") == 0
    )
    pops["not_offered"] = _pop(RECONCILED if ok else UNRECONCILED, count=len(n))
    pops["funding"], extra["reservations"] = evaluate_funding(events, result, facts)

    serial = "".join(f"{q}:{h}\n" for q, h in sorted(request_pairs)).encode()
    extra["signed_request_hashes_sha256"] = hashlib.sha256(serial).hexdigest()
    extra["offered"], extra["not_offered"], extra["offers"] = o, n, offers
    extra["times"] = [e["time_unix"] for e in events if isinstance(e.get("time_unix"), float)]
    return pops, extra


def evaluate_funding(events, result, facts) -> tuple[dict, list]:
    reservations, inflight, broken, unknown = [], 0, 0, 0
    for e in events:
        kind = e["event"]
        if kind == "funding_reserved":
            amount, label = e.get("amount_nanotos"), e.get("label")
            if (
                inflight != 0
                or type(amount) is not int
                or amount <= 0
                or not isinstance(label, str)
            ):
                broken += 1
            inflight += 1
            reservations.append((label, amount, e.get("time_unix")))
        elif kind == "funding_settled":
            if inflight != 1:
                broken += 1
            inflight -= 1
        elif kind == "funding_unknown":
            unknown += 1
    total = 0
    for _label, amount, _t in reservations:
        total = total + amount if type(amount) is int else total
    public = facts.get("reservations")
    public_pairs = (
        [(r.get("label"), r.get("amount_nanotos")) for r in public]
        if isinstance(public, list) and all(isinstance(r, dict) for r in public)
        else None
    )
    matches = facts.get("owner_matches") or {}
    ok = (
        not broken
        and inflight == 0
        and not unknown
        and public_pairs == [(lab, amt) for lab, amt, _ in reservations]
        and matches.get("count") == len(reservations)
        and matches.get("total_nanotos") == total
        and result.get("funded_nanotos") == total
        and result.get("funding_inflight") == 0
        and result.get("funding_unknown") is False
    )
    labels = [lab for lab, _, _ in reservations if isinstance(lab, str) and LABEL.match(lab)]
    pop = _pop(
        RECONCILED if ok else UNRECONCILED,
        reserved=len(reservations),
        inflight_at_end=inflight,
        sequence_violations=broken,
        funding_unknown_events=unknown,
        total_nanotos=total,
        labels=sorted(set(labels))[:MAX_SAMPLE],
    )
    return pop, reservations


def expected_wallet_set(facts, args) -> dict | None:
    """The public expected wallets, normalised; None when the file is malformed."""
    doc = facts.get("expected_wallets")
    if not isinstance(doc, dict):
        return None
    relayers, operators = doc.get("relayers"), doc.get("operators")
    if not isinstance(relayers, list) or not isinstance(operators, list):
        return None
    out = {
        "highload": normalize_address(doc.get("highload")),
        "funding_owner": normalize_address(doc.get("funding_owner")),
        "relayers": [normalize_address(a) for a in relayers],
        "operators": [normalize_address(a) for a in operators],
    }
    flat = [out["highload"], out["funding_owner"], *out["relayers"], *out["operators"]]
    if None in flat or len(set(flat)) != len(flat):
        return None
    return out


def evaluate_wallets(facts, expected, args) -> dict:
    """The complete wallet set: state address files and public funding matches
    against the public expected set and the declared counts."""
    if expected is None:
        return _pop(UNKNOWN, missing_relayers=0, extra_relayers=0, mismatched_relayers=0)
    state = facts.get("relayers") or {}
    want = dict(enumerate(expected["relayers"]))
    missing = [i for i in want if i not in state]
    extra = [i for i in state if i not in want]
    mismatched = [i for i in want if i in state and state[i] != want[i]]
    matches = facts.get("owner_matches") or {}
    by_label = matches.get("addresses_by_label")
    covered, label_bad = set(), 0
    if isinstance(by_label, dict):
        for label, address in by_label.items():
            m = re.match(r"^load-(?:relayer|refill)-([0-9]{1,4})$", str(label))
            index = int(m.group(1)) if m else None
            if index is None or want.get(index) != normalize_address(address):
                label_bad += 1
            else:
                covered.add(index)
    ok = (
        not missing
        and not extra
        and not mismatched
        and isinstance(by_label, dict)
        and not label_bad
        and covered == set(want)
        and len(expected["relayers"]) == args.expected_relayer_count
        and len(expected["operators"]) == args.expected_operator_count
        and facts.get("highload") == expected["highload"]
        and expected["funding_owner"] == args.funding_owner_address
    )
    return _pop(
        RECONCILED if ok else UNRECONCILED,
        relayers=len(want),
        operators=len(expected["operators"]),
        missing_relayers=len(missing),
        extra_relayers=len(extra),
        mismatched_relayers=len(mismatched),
        unmatched_funding_labels=label_bad,
    )


def evaluate_journals(facts, reservations, window, wallets, owner, relayers=()) -> dict:
    records = facts.get("journals")
    names = ("open_operations", "funding_journal", "owner_pre_run_rows", "owner_during_run")
    if records is None:
        return {n: _pop(UNKNOWN) for n in names}
    unknown = [r for r in records if r.get("unknown")]
    good = [r for r in records if not r.get("unknown")]
    pops = {}
    odd_wallets = 0
    for r in good:
        canonical = normalize_address(r.get("wallet"))
        if canonical is None:
            odd_wallets += 1
            r["wallet_unparsed"] = True
        else:
            r["wallet"] = canonical
    odd_open = [r for r in good if r.get("wallet_unparsed") and r.get("state") in OPEN_STATES]
    open_ops = [r for r in good if r.get("wallet") in wallets and r.get("state") in OPEN_STATES]
    outside = [
        r
        for r in good
        if not r.get("wallet_unparsed")
        and r.get("wallet") not in wallets
        and r.get("state") in OPEN_STATES
    ]
    pops["open_operations"] = _pop(
        UNKNOWN if unknown or odd_open or outside else (UNRECONCILED if open_ops else RECONCILED),
        open=len(open_ops),
        open_outside_expected_wallets=len(outside),
        open_with_unparsed_wallet=len(odd_open),
        unparsed_wallets=odd_wallets,
        unparsed_journals=len(unknown),
        journals=len(records),
    )
    matches = facts.get("owner_matches") or {}
    rows = matches.get("matches") if isinstance(matches.get("matches"), list) else []
    match_tx = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("transaction"), str):
            match_tx[row["transaction"]] = (
                row.get("label"),
                row.get("amount_nanotos"),
                normalize_address(row.get("to")),
            )
    owner_records = [r for r in good if r.get("wallet") == owner]
    for r in owner_records:
        r["_t"] = utc_seconds(r.get("first_utc"))
    load = [r for r in owner_records if r.get("purpose") == "load"]
    used, unmatched, used_tx = set(), 0, set()
    for label, amount, t in reservations:
        floor = math.floor(t) if isinstance(t, float) else None
        candidates = sorted(
            (
                r
                for r in load
                if r["index"] not in used
                and r.get("label") == label
                and r.get("value") == amount
                and r["_t"] is not None
                and floor is not None
                and r["_t"] >= floor - 1
                and str(r.get("op_id", "")).startswith(f"load-{label}-")
            ),
            key=lambda r: (r["_t"], r["op_id"]),
        )
        chosen = candidates[0] if candidates else None
        tx = (chosen or {}).get("evidence", {}).get("wallet_tx")
        index = re.match(r"^load-(?:relayer|refill)-([0-9]{1,4})$", str(label))
        target = (
            relayers[int(index.group(1))] if index and int(index.group(1)) < len(relayers) else None
        )
        destination = normalize_address((chosen or {}).get("destination"))
        if (
            chosen is None
            or chosen.get("state") != "settled"
            or tx not in match_tx
            or tx in used_tx
            or match_tx[tx] != (label, amount, destination)
            or chosen.get("kind") != "owner-fund"
            or destination is None
            or destination != target
        ):
            unmatched += 1
            continue
        used.add(chosen["index"])
        used_tx.add(tx)
    start, end = window
    in_window = [
        r
        for r in owner_records
        if r["_t"] is not None and start is not None and start <= r["_t"] <= end
    ]
    stray_load = [r for r in in_window if r.get("purpose") == "load" and r["index"] not in used]
    non_load = [r for r in in_window if r.get("purpose") != "load"]
    bad_non_load = [
        r
        for r in non_load
        if r.get("state") != "settled" or not r.get("evidence", {}).get("wallet_tx")
    ]
    verdict = RECONCILED if not unmatched and len(used) == len(reservations) else UNRECONCILED
    pops["funding_journal"] = _pop(
        UNKNOWN if unknown else verdict, matched=len(used), unmatched=unmatched
    )
    verdict = UNRECONCILED if stray_load or bad_non_load or start is None else RECONCILED
    pops["owner_during_run"] = _pop(
        UNKNOWN if unknown else verdict,
        records=len(in_window),
        load_unmatched=len(stray_load),
        non_load_settled=len(non_load) - len(bad_non_load),
        non_load_unexplained=len(bad_non_load),
    )
    pre = matches.get("unmatched_owner_rows")
    explained = {
        r.get("evidence", {}).get("wallet_tx")
        for r in owner_records
        if r.get("state") == "settled" and r.get("purpose") != "load"
    }
    if not isinstance(pre, list) or not all(isinstance(p, dict) for p in pre):
        pops["owner_pre_run_rows"] = _pop(UNKNOWN)
    else:
        missing = [p for p in pre if p.get("hash") not in explained or not p.get("hash")]
        pops["owner_pre_run_rows"] = _pop(
            UNKNOWN if unknown else (UNRECONCILED if missing else RECONCILED),
            rows=len(pre),
            unexplained=len(missing),
        )
    return pops


def evaluate_query_ids(facts, extra, args) -> dict:
    o, n = extra.get("offered"), extra.get("not_offered")
    counter = (facts.get("counter") or {}).get("next_query_id")
    if not o:
        return _pop(UNKNOWN, reason_code="no_offers")
    used = o | n
    low, high = min(used), max(used)
    structural = [q for q in range(low, high + 1) if q & 1023 == 1023]
    other = [q for q in range(low, high + 1) if q & 1023 != 1023 and q not in used]
    expected = next_query_id(high)
    out = {
        "min": low,
        "max": high,
        "integers_in_range": high - low + 1,
        "gaps_structural_1023": len(structural),
        "gaps_other": len(other),
        "gaps_other_sample": sample(other),
        "expected_next": expected,
        "counter": counter if type(counter) is int else None,
        "prior_runs": facts.get("prior_runs", 0),
    }
    prior = facts.get("prior_ids") or []
    if facts.get("prior_unreadable") or not all(usable_query_id(q) for q in prior):
        start_verdict = UNKNOWN
    else:
        start = next_query_id(max(prior)) if prior else 0
        out["reconstructed_start"] = start
        if any(q >= low for q in prior):
            start_verdict = UNRECONCILED
        else:
            start_verdict = RECONCILED if start == low == args.min_query_id else UNKNOWN
    if low < args.min_query_id:
        start_verdict = UNRECONCILED
    out["start_verdict"] = start_verdict
    unlogged = []
    if not usable_query_id(counter):
        counter_verdict = UNKNOWN
    elif counter == expected:
        counter_verdict = RECONCILED
    elif counter < expected or counter < low:
        counter_verdict = UNRECONCILED
    else:
        q = expected
        while q != counter and len(unlogged) < QUERY_LIMIT:
            unlogged.append(q)
            q = next_query_id(q)
        counter_verdict = UNKNOWN
    out["counter_verdict"] = counter_verdict
    out["allocated_unlogged"] = len(unlogged)
    out["allocated_unlogged_sample"] = sample(unlogged)
    verdicts = {start_verdict, counter_verdict, UNKNOWN if other else RECONCILED}
    for word in (UNRECONCILED, UNKNOWN):
        if word in verdicts:
            return _pop(word, **out)
    return _pop(RECONCILED, **out)


def evaluate_outbox(facts, extra) -> dict:
    entries = facts.get("outbox")
    if entries is None or not extra.get("offers") and not extra.get("offered"):
        return _pop(UNKNOWN)
    by_first = {}
    for relayer, seqno, first, size in entries:
        by_first.setdefault(first, []).append((relayer, seqno, size))
    missing = mismatched = 0
    claimed = set()
    for first, carrier_bytes in extra.get("offers", []):
        found = by_first.get(first, [])
        if len(found) != 1:
            missing += 1
            continue
        claimed.add(first)
        if found[0][2] != carrier_bytes:
            mismatched += 1
    not_offered_firsts = {f for f in by_first if f in extra.get("not_offered", set())}
    orphans = [f for f in by_first if f not in claimed and f not in not_offered_firsts]
    if missing or mismatched or facts.get("outbox_odd"):
        verdict = UNRECONCILED
    elif orphans:
        verdict = UNKNOWN  # archived but not offered: never counted as success
    else:
        verdict = RECONCILED
    return _pop(
        verdict,
        entries=len(entries),
        offers_without_archive=missing,
        size_mismatches=mismatched,
        archived_not_offered=len(orphans),
        unexpected_names=facts.get("outbox_odd", 0),
    )


def relayer_max_seqno(facts) -> dict:
    out = {}
    for relayer, seqno, _first, _size in facts.get("outbox") or []:
        out[relayer] = max(out.get(relayer, -1), seqno)
    return out


def chain_observation(facts, sources, rpc) -> dict:
    """Read-only relayer seqnos and each source's masterchain seqno at read time.

    Observation only: nothing here clears, decides or downgrades a verdict, and
    an allocated-but-unlogged id stays UNKNOWN whatever the reads show."""
    relayers = facts.get("relayers") or {}
    sources = list(dict.fromkeys(sources))
    expected = relayer_max_seqno(facts)
    heads = []
    for index, source in enumerate(sources):
        try:
            head = read_masterchain_seqno(rpc, source)
        except Exception:
            head = None
        heads.append({"index": index, "masterchain_seqno": head})
    rows, agree, consistent = [], True, True
    for index in sorted(relayers):
        seen = []
        for source in sources:
            try:
                seen.append(read_seqno(rpc, source, relayers[index]))
            except Exception:
                seen.append(None)
        row_agree = bool(seen) and None not in seen and len(set(seen)) == 1
        if None in seen or len(set(seen)) != 1:
            agree = False
        want = expected[index] + 1 if index in expected else None
        matches = None
        if want is not None and row_agree:
            matches = seen[0] == want
            if not matches:
                consistent = False
        rows.append(
            {
                "index": index,
                "outbox_max_seqno_plus_one": want,
                "observed": [s if type(s) is int else None for s in seen],
                "sources_agree": row_agree,
                "matches_outbox": matches,
            }
        )
    return {
        "observation_only": True,
        "sources": heads,
        "relayers": rows,
        "sources_agree": agree and bool(rows) and len(sources) >= 2,
        "outbox_consistent": consistent,
    }


def read_masterchain_seqno(rpc, url: str) -> int:
    if "getMasterchainInfo" not in READ_ONLY_RPC:
        raise PermissionError("not a read-only method")
    info = rpc(url, "getMasterchainInfo")
    seqno = info["last"]["seqno"] if isinstance(info, dict) else None
    if type(seqno) is not int:
        raise ValueError
    return seqno


def read_seqno(rpc, url: str, address: str) -> int:
    """testnet_ops.py:368-378, read-only methods only."""

    def call(method, /, **params):
        if method not in READ_ONLY_RPC:
            raise PermissionError("not a read-only method")
        return rpc(url, method, **params)

    info = call("getAddressInformation", address=address)
    if not isinstance(info, dict) or "state" not in info:
        raise ValueError
    if info["state"] != "active":
        return 0
    result = call("runGetMethod", address=address, method="seqno", stack=[])
    stack = result.get("stack") if isinstance(result, dict) else None
    if result.get("exit_code") != 0 or not stack or not isinstance(stack[0], list):
        raise ValueError
    return int(stack[0][1], 0)


def evaluate(facts: dict, args, chain: dict) -> dict:
    pops, extra = evaluate_events(facts, args)
    result = facts.get("result") if isinstance(facts.get("result"), dict) else {}
    marker = facts.get("marker") if isinstance(facts.get("marker"), dict) else {}
    identity = facts.get("identity") if isinstance(facts.get("identity"), dict) else {}
    audit = facts.get("closed_audit") if isinstance(facts.get("closed_audit"), dict) else {}
    audit_id = audit.get("identity") if isinstance(audit.get("identity"), dict) else {}
    digests = facts.get("digests", {})

    summaries = facts.get("summaries", [])
    summary_hash = summaries[0][2] if len(summaries) == 1 else None
    ok = (
        len(summaries) == 1
        and not facts.get("summary_unreadable")
        and summaries[0][1] == result
        and summary_hash == audit_id.get("summary_sha256")
        and digests.get("run:events") == audit_id.get("events_sha256")
        and identity
        == {
            "global_id": args.global_id,
            "genesis_root": args.genesis_root,
            "genesis_file": args.genesis_file,
        }
        and audit_id.get("global_id") == args.global_id
        and facts.get("highload") == audit_id.get("wallet")
        and marker.get("run") == args.run
        and result.get("run_directory") == args.run
        and not facts.get("later_run")
    )
    pops["identity"] = _pop(
        RECONCILED if ok else UNRECONCILED,
        summaries_for_run=len(summaries),
        later_runs_present=bool(facts.get("later_run")),
    )
    times = extra.get("times") or []
    try:
        start = int(args.run.split("-")[1]) / 1e9
    except (IndexError, ValueError):
        start = None
    window = (math.floor(start) if start else None, math.ceil(max(times)) if times else 0)
    expected = expected_wallet_set(facts, args)
    pops["wallets"] = evaluate_wallets(facts, expected, args)
    wallets = set()
    if expected is not None:
        wallets = {
            expected["highload"],
            expected["funding_owner"],
            *expected["relayers"],
            *expected["operators"],
        }
    pops.update(
        evaluate_journals(
            facts,
            extra.get("reservations", []),
            window,
            wallets,
            args.funding_owner_address,
            expected["relayers"] if expected else (),
        )
    )
    pops["query_ids"] = evaluate_query_ids(facts, extra, args)
    pops["outbox"] = evaluate_outbox(facts, extra)

    closed = marker.get("closed") is True
    safe = result.get("safe_to_start_new_run") is True
    if not isinstance(marker.get("closed"), bool) or not isinstance(
        result.get("safe_to_start_new_run"), bool
    ):
        fence = UNKNOWN
    elif closed and not safe:
        fence = UNRECONCILED  # a closed marker over an unsafe result (LQ:353-355)
    else:
        fence = RECONCILED  # reported as-is; eligibility needs both true
    pops["fence"] = _pop(fence, closed=closed, safe_to_start_new_run=safe)
    return {
        "populations": pops,
        "hashes": {
            "events_sha256": digests.get("run:events"),
            "summary_sha256": summary_hash,
            "result_sha256": digests.get("run:result"),
            "signed_request_hashes_sha256": extra.get("signed_request_hashes_sha256"),
            "operations_projection_sha256": digests.get("ops:projection"),
        },
        "addresses": {
            "highload_address": facts.get("highload"),
            "relayer_addresses": [
                (facts.get("relayers") or {})[i] for i in sorted(facts.get("relayers") or {})
            ],
            "funding_owner_address": args.funding_owner_address,
        },
        "closed": closed,
        "safe": safe,
        "chain_observation": chain,
    }


def overall(locks: dict, stable: bool, body: dict, errors: list) -> tuple[str, bool]:
    if LOCK_HELD in locks.values():
        return UNKNOWN_PRODUCER_LIVE, False
    if not stable:
        return UNKNOWN_UNSTABLE, False
    if UNKNOWN in locks.values():
        return UNKNOWN, False
    words = {p["verdict"] for p in body["populations"].values()}
    if UNRECONCILED in words:
        return UNRECONCILED, False
    if UNKNOWN in words or errors:
        return UNKNOWN, False
    if not (body["closed"] and body["safe"]):
        return FENCE_OPEN, False
    return ELIGIBLE, True


# ---------------------------------------------------------------- output


VERDICT_WORDS = frozenset(
    {
        RECONCILED,
        UNRECONCILED,
        UNKNOWN,
        OBSERVED,
        FENCE_OPEN,
        UNKNOWN_UNSTABLE,
        UNKNOWN_PRODUCER_LIVE,
        ELIGIBLE,
        LOCK_FREE,
        LOCK_HELD,
        "REFUSED_DENYLIST",
        "load-fence-reconcile/1",
        STATEMENT,
    }
)
ERROR_CODES = frozenset(
    {
        "line_not_tokenizable",
        "line_not_json",
        "line_not_object",
        "line_too_long",
        "torn_last_line",
        "not_owned_or_wrong_type",
        "root_unavailable",
        "directory_unavailable",
        "denied_name",
        "missing",
        "unreadable",
        "too_large",
        "changed_while_read",
        "not_an_address_file",
        "state",
        "no_offers",
        "bad_address",
    }
)
SECRET_PATTERNS = (
    re.compile(r"[A-Za-z0-9+/=_-]{48,}"),
    re.compile(r"[0-9a-fA-F]{65,}"),
    re.compile(r"boc|/private|\.pk|\.key|BEGIN", re.IGNORECASE),
)


def scan(value, key: str = "") -> list[str]:
    """Paths of every value that is not an allowlisted type for its field."""
    hits = []
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not re.match(r"^[a-z0-9_]{1,64}$", k) or "boc" in k:
                hits.append(f"{key}.<key>")
                continue
            hits.extend(scan(v, k))
    elif isinstance(value, list):
        for item in value:
            hits.extend(scan(item, key))
    elif isinstance(value, str):
        if key.endswith("_sha256"):
            ok = bool(HEX64.match(value))
        elif key.endswith("_address") or key.endswith("_addresses"):
            ok = bool(ADDRESS.match(value))
        else:
            ok = (
                value in VERDICT_WORDS
                or value in ERROR_CODES
                or bool(RUN_NAME.match(value))
                or bool(LABEL.match(value))
                or bool(LOGICAL_ID.match(value))
            ) and not any(p.search(value) for p in SECRET_PATTERNS if value != STATEMENT)
        if not ok:
            hits.append(key)
    elif not (value is None or isinstance(value, (bool, int))):
        hits.append(key)
    return hits


def write_output(path: str, document: dict) -> None:
    data = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        os.fchmod(fd, 0o644)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def inside(path: str, root: str) -> bool:
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def run(args, rpc=None, proc_locks_path: str = "/proc/locks") -> tuple[int, dict | None]:
    """Two complete reads, lock observations around them, one output document."""
    disable_core_dumps()
    install_guard()
    owner = normalize_address(args.funding_owner_address)
    if owner is None or args.expected_relayer_count < 1 or args.expected_operator_count < 1:
        raise Refused("public:arguments", 0, "bad_address")
    args.funding_owner_address = owner
    for root in (args.state, args.ceremony):
        if inside(os.path.dirname(os.path.abspath(args.out)), root):
            raise Refused("public:out", 0, "denied_name")
        for input_id, path in (
            ("public:closed-audit", args.closed_audit),
            ("public:reservations", args.reservations),
            ("public:owner-matches", args.owner_matches),
            ("public:expected-wallets", args.expected_wallets),
        ):
            if inside(path, root):
                raise Refused(input_id, 0, "denied_name")
    if os.path.lexists(args.out):
        raise Refused("public:out", 0, "denied_name")
    sys.dont_write_bytecode = True
    GUARD.update(active=True, out=None, violations=0, core_at_first_open=None)
    readers = []
    try:
        held0 = proc_locks(proc_locks_path)
        snapshots = []
        for _ in range(2):
            reader = Reader()
            readers.append(reader)
            try:
                facts = collect(args, reader)
            except Refused as exc:
                _refusal(reader, exc)
                facts = {}
            finally:
                reader.close()
            facts["digests"] = dict(reader.digests)
            snapshots.append((facts, reader))
        held1 = proc_locks(proc_locks_path)
        facts, reader = snapshots[1]
        first = snapshots[0][1]
        stable = (
            first.idents == reader.idents
            and first.digests == reader.digests
            and first.opened == reader.opened
            and held0 is not None
            and held1 is not None
        )
        locks = {}
        for name, key in (
            ("qualification_lock", "qualification_lock"),
            ("operations_lock", "operations_lock"),
        ):
            words = {lock_state(facts.get(key), held) for held in (held0, held1)}
            locks[name] = (
                LOCK_HELD if LOCK_HELD in words else (UNKNOWN if UNKNOWN in words else LOCK_FREE)
            )
        chain = chain_observation(facts, args.source, rpc or lib.rpc)
        body = evaluate(facts, args, chain)
        verdict, eligible = overall(locks, stable, body, reader.errors)
        violations = GUARD["violations"]
    finally:
        GUARD["active"] = False
    if violations:
        return 3, None
    document = {
        "schema": "load-fence-reconcile/1",
        "run": args.run if RUN_NAME.match(args.run) else None,
        "verdict": verdict,
        "launch_eligible": eligible,
        "stable": stable,
        "locks": dict(locks, statement=STATEMENT, observations=2),
        "populations": body["populations"],
        "hashes": body["hashes"],
        "addresses": body["addresses"],
        "chain_observation": body["chain_observation"],
        "errors": [e for e in reader.errors if e["code"] in ERROR_CODES][:MAX_SAMPLE],
        "errors_total": len(reader.errors),
        "inputs_opened": reader.opened,
    }
    if scan(document):
        return 2, None
    write_output(args.out, document)
    return (0 if eligible else 1), document


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--state", required=True)
    p.add_argument("--ceremony", required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--closed-audit", required=True)
    p.add_argument("--reservations", required=True)
    p.add_argument("--owner-matches", required=True)
    p.add_argument("--funding-owner-address", required=True)
    p.add_argument("--expected-wallets", required=True)
    p.add_argument("--expected-relayer-count", type=int, required=True)
    p.add_argument("--expected-operator-count", type=int, required=True)
    p.add_argument("--global-id", type=int, required=True)
    p.add_argument("--genesis-root", required=True)
    p.add_argument("--genesis-file", required=True)
    p.add_argument("--min-query-id", type=int, required=True)
    p.add_argument("--chain-reads", action="store_true")
    p.add_argument("--source", action="append", default=[])
    args = p.parse_args(argv)
    if not RUN_NAME.match(args.run):
        p.error("--run must name a qualification-N directory")
    if not args.chain_reads or len(set(args.source)) < 2:
        p.error("--chain-reads with two distinct --source endpoints is required")
    args.funding_owner_address = normalize_address(args.funding_owner_address)
    if args.funding_owner_address is None:
        p.error("addresses must be raw wc:hex64")
    if args.expected_relayer_count < 1 or args.expected_operator_count < 1:
        p.error("expected relayer and operator counts must be positive")
    return args


def logical_excepthook(kind, value, _traceback):
    text = str(value) if isinstance(value, Refused) else kind.__name__
    sys.stderr.write(f"load_fence_reconcile: {text}\n")


def main(argv=None) -> int:
    disable_core_dumps()
    sys.excepthook = logical_excepthook
    sys.dont_write_bytecode = True
    args = parse(argv)
    try:
        code, _document = run(args)
    except Refused as exc:
        sys.stderr.write(f"load_fence_reconcile: {exc}\n")
        return 4
    except BaseException as exc:  # noqa: BLE001 - only the type name may leave
        sys.stderr.write(f"load_fence_reconcile: {type(exc).__name__}\n")
        return 4
    messages = {2: "secret scan refused the output", 3: "allowlist violation"}
    if code in messages:
        sys.stderr.write(f"load_fence_reconcile: {messages[code]}; nothing written\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
