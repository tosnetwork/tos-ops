"""Read-only native proof acquisition and bounded, authenticated RPC history.

No keys, carriers, signatures or admission controls enter this module. The caller
must stop admission on failure and retain the unfinished qualified-run fence.
"""

import base64
import ctypes
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from load_finality import MAX_HISTORY_BYTES, MAX_TRANSACTIONS, Head, HistoryError, decode_history
from pytosiq_core import Cell, Transaction

MAX_INPUT = 1 << 20
MAX_OUTPUT = 8 << 20
MAX_CAPTURE = 64 << 20
MAX_FILES = 512
MIN_FREE = 20 << 30
MIN_FREE_INODES = 8192
# Linux UAPI values, also used by the reviewed sealed-provider runner.
F_ADD_SEALS, F_GET_SEALS = 1033, 1034


def require(ok, reason):
    if not ok:
        raise HistoryError(reason)


def write_file(path, data):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def seal_executable(path, expected):
    """Reuse the reviewed sealed-ELF strategy; hash/copy bounded chunks once."""
    source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    target = None
    try:
        info = os.fstat(source)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 256 << 20, "verifier size/type")
        create = ctypes.CDLL(None, use_errno=True).memfd_create
        create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
        create.restype = ctypes.c_int
        target = create(b"load-native-verifier", 3)  # Linux MFD_CLOEXEC | MFD_ALLOW_SEALING.
        if target < 0:
            target = None
            raise OSError(ctypes.get_errno(), "memfd_create refused")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(source, 1 << 20):
            total += len(chunk)
            require(total <= 256 << 20, "verifier grew past limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                count = os.write(target, view)
                require(count > 0, "short sealed verifier write")
                view = view[count:]
        require(digest.hexdigest() == expected, "verifier hash mismatch")
        os.fchmod(target, 0o500)
        fcntl.fcntl(target, F_ADD_SEALS, 15)
        require(fcntl.fcntl(target, F_GET_SEALS) & 15 == 15, "verifier seals missing")
        return target
    except BaseException:
        if target is not None:
            os.close(target)
        raise
    finally:
        os.close(source)


def bounded_snapshot(source, target, expected=None):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "snapshot must be a regular file")
        data = os.read(fd, MAX_INPUT + 1)
        require(0 < len(data) <= MAX_INPUT, "snapshot size limit")
    finally:
        os.close(fd)
    require(
        expected is None or hashlib.sha256(data).hexdigest() == expected, "snapshot hash mismatch"
    )
    json.loads(data)
    write_file(target, data)


def capture_size(directory):
    total, files = 0, 0
    for path in directory.rglob("*"):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), "capture symlink refused")
        if stat.S_ISREG(info.st_mode):
            files += 1
            total += info.st_size
            require(files <= MAX_FILES and total <= MAX_CAPTURE, "capture storage limit")
        else:
            require(stat.S_ISDIR(info.st_mode), "capture special file refused")
    return total


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_capture(path):
    capture_size(path)
    directories = [path]
    for item in path.rglob("*"):
        if item.is_dir():
            directories.append(item)
        else:
            fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                require(stat.S_ISREG(os.fstat(fd).st_mode), "capture special file refused")
                os.fsync(fd)
            finally:
                os.close(fd)
    for directory in reversed(directories):
        sync_directory(directory)


@dataclass(frozen=True)
class Capture:
    seqno: int
    previous_head: Head
    head: Head
    receipts: tuple
    completed_monotonic: float
    directory: Path


class NativeCollector:
    def __init__(
        self,
        *,
        verifier,
        verifier_sha256,
        anchor,
        anchor_sha256,
        liteserver,
        rpc,
        directory,
        wallet,
        code_hash,
        global_id,
        global_version,
        subwallet_id,
        max_age=10,
        timeout=8,
        max_captures=200000,
        storage_budget=256 << 30,
    ):
        require(type(max_age) is int and 1 <= max_age <= 30, "native age must be 1..30")
        require(
            type(timeout) is int and 1 <= timeout <= max_age, "native timeout exceeds age guard"
        )
        require(type(max_captures) is int and 1 <= max_captures <= 1000000, "capture count limit")
        require(
            type(storage_budget) is int and MAX_CAPTURE <= storage_budget <= 512 << 30,
            "storage budget limit",
        )
        endpoint = urlsplit(rpc)
        require(
            endpoint.scheme in ("http", "https")
            and endpoint.hostname
            and not endpoint.username
            and not endpoint.password
            and not endpoint.fragment
            and not endpoint.query,
            "public RPC URL required",
        )
        require(
            isinstance(wallet, str) and wallet.startswith("0:") and len(wallet) == 66,
            "basechain wallet required",
        )
        Head(0, wallet[2:])
        Head(0, code_hash)
        Head(0, verifier_sha256)
        Head(0, anchor_sha256)
        require(
            type(global_id) is int and type(global_version) is int and type(subwallet_id) is int,
            "integer identity required",
        )
        require(
            -(1 << 31) <= global_id < 1 << 31
            and 0 <= global_version < 1 << 32
            and 0 <= subwallet_id < 1 << 32,
            "native identity range",
        )
        self.root = Path(directory)
        self.root.mkdir(mode=0o700)  # Exclusive run, never resume/rebaseline a prior collector.
        self.native_fd = None
        self.guard = threading.Lock()
        try:
            bounded_snapshot(anchor, self.root / "anchor.json", anchor_sha256)
            bounded_snapshot(liteserver, self.root / "liteserver.json")
            self.native_fd = seal_executable(verifier, verifier_sha256)
            self.curl = shutil.which("curl")
            require(
                self.curl is not None and Path("/usr/bin/prlimit").is_file(),
                "curl/prlimit required",
            )
        except BaseException:
            self.close()
            raise
        self.wallet, self.code_hash = wallet, code_hash
        self.global_id, self.global_version, self.subwallet_id = (
            global_id,
            global_version,
            subwallet_id,
        )
        self.max_age, self.timeout = max_age, timeout
        self.max_captures, self.storage_budget = max_captures, storage_budget
        self.rpc, self.captures, self.retained = rpc, 0, 0
        self.state_source = None
        self.last_head = None
        try:
            sync_directory(self.root)
        except BaseException:
            self.close()
            raise

    def close(self):
        with self.guard:
            if self.native_fd is not None:
                os.close(self.native_fd)
                self.native_fd = None

    def _run(self, argv, output, error, deadline, directory, *, native=False):
        require(time.monotonic() < deadline, "capture deadline expired")
        # Per-file kernel bound plus monitored aggregate bound. A failed capture
        # never advances a window; retain its partial artifacts for diagnosis.
        argv = ["/usr/bin/prlimit", f"--fsize={MAX_OUTPUT}", "--", *argv]
        with output.open("xb") as stdout, error.open("xb") as stderr:
            os.fchmod(stdout.fileno(), 0o600)
            os.fchmod(stderr.fileno(), 0o600)
            process = subprocess.Popen(
                argv, stdout=stdout, stderr=stderr, pass_fds=(self.native_fd,) if native else ()
            )
            try:
                while process.poll() is None:
                    require(time.monotonic() < deadline, "capture deadline expired")
                    capture_size(directory)
                    time.sleep(0.05)
                require(process.returncode == 0, "native/RPC subprocess refused")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                stdout.flush()
                stderr.flush()
                os.fsync(stdout.fileno())
                os.fsync(stderr.fileno())
        require(
            output.stat().st_size <= MAX_OUTPUT and error.stat().st_size <= MAX_INPUT,
            "capture output limit",
        )
        capture_size(directory)

    def _rpc_page(self, path, cursor, page, deadline):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransactions",
            "params": {
                "address": self.wallet,
                "limit": 64,
                "lt": str(cursor.lt),
                "hash": base64.b64encode(bytes.fromhex(cursor.hash)).decode(),
            },
        }
        query, response = path / f"rpc-{page}.request.json", path / f"rpc-{page}.json"
        write_file(query, json.dumps(request).encode())
        remaining = deadline - time.monotonic()
        require(remaining > 0, "capture deadline expired")
        self._run(
            [
                self.curl,
                "--disable",
                "--silent",
                "--show-error",
                "--fail",
                "--proto",
                "=http,https",
                "--max-time",
                str(remaining),
                "--max-filesize",
                str(MAX_OUTPUT),
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@" + str(query),
                self.rpc,
            ],
            response,
            path / f"rpc-{page}.stderr",
            deadline,
            path,
        )
        result = json.loads(response.read_bytes())
        require(
            "error" not in result
            and type(result.get("result")) is list
            and 0 < len(result["result"]) <= 64,
            "bounded RPC history page required",
        )
        return result["result"]

    def capture(self, previous_head=None):
        with self.guard:
            require(self.native_fd is not None, "collector closed")
            if self.last_head is not None:
                require(
                    previous_head is None or previous_head == self.last_head,
                    "collector previous head does not match last success",
                )
                previous_head = self.last_head
            require(
                self.captures < self.max_captures
                and self.retained + MAX_CAPTURE <= self.storage_budget,
                "collector retention budget exhausted",
            )
            require(
                shutil.disk_usage(self.root).free >= MIN_FREE + MAX_CAPTURE,
                "collector free-space guard",
            )
            require(
                os.statvfs(self.root).f_favail >= MIN_FREE_INODES + MAX_FILES,
                "collector free-inode guard",
            )
            path = self.root / f"capture-{self.captures:06d}"
            path.mkdir(mode=0o700)
            self.captures += 1
            deadline = time.monotonic() + self.timeout
            request = {
                "mode": "live",
                "max_age_seconds": self.max_age,
                "account": self.wallet,
                "config_params": [8, 19],
            }
            try:
                write_file(path / "request.json", json.dumps(request).encode())
                if self.state_source is not None:
                    bounded_snapshot(self.state_source, path / "native-state.json")
                self._run(
                    [
                        f"/proc/self/fd/{self.native_fd}",
                        "verify",
                        "--anchor",
                        str(self.root / "anchor.json"),
                        "--request",
                        str(path / "request.json"),
                        "--liteserver",
                        str(self.root / "liteserver.json"),
                        "--state",
                        str(path / "native-state.json"),
                        "--save-material",
                        str(path / "material"),
                        "--min-interval-ms",
                        "0",
                        "--timeout-seconds",
                        str(self.timeout),
                    ],
                    path / "proof.json",
                    path / "proof.stderr",
                    deadline,
                    path,
                    native=True,
                )
                proof = json.loads((path / "proof.json").read_bytes())
                require(proof.get("status") == "verified", "native proof not verified")
                state = path / "native-state.json"
                require(
                    state.is_file()
                    and not state.is_symlink()
                    and state.stat().st_size <= MAX_INPUT,
                    "native state missing or oversized",
                )
                json.loads(state.read_bytes())
                account = proof["account"]
                require(
                    account["address"] == self.wallet
                    and account["active"]
                    and account["code_hash"] == self.code_hash,
                    "native wallet/code identity mismatch",
                )
                configs = {
                    c["index"]: Cell.one_from_boc(base64.b64decode(c["boc"], validate=True))
                    for c in proof["config_params"]
                }
                version = configs[8].begin_parse()
                require(
                    version.load_uint(8) == 0xC4 and version.load_uint(32) == self.global_version,
                    "native global version mismatch",
                )
                require(
                    configs[19].begin_parse().load_int(32) == self.global_id,
                    "native global id mismatch",
                )
                head = Head(account["last_trans_lt"], account["last_trans_hash"])
                previous = head if previous_head is None else previous_head
                cursor, rows, encoded_size, page = head, [], 0, 0
                while cursor != previous:
                    for row in self._rpc_page(path, cursor, page, deadline):
                        if cursor == previous:
                            break
                        encoded = row["data"]
                        require(
                            type(encoded) is str and len(encoded) <= 4 * ((MAX_INPUT + 2) // 3),
                            "transaction size limit",
                        )
                        encoded_size += len(encoded)
                        require(
                            encoded_size <= MAX_HISTORY_BYTES and len(rows) < MAX_TRANSACTIONS,
                            "history budget exceeded",
                        )
                        cell = Cell.one_from_boc(base64.b64decode(encoded, validate=True))
                        require(
                            cell.hash.hex() == cursor.hash, "RPC history does not match native head"
                        )
                        tx = Transaction.deserialize(cell.begin_parse())
                        require(
                            tx.lt == cursor.lt and tx.prev_trans_lt < tx.lt,
                            "RPC history does not match native head",
                        )
                        rows.append(encoded)
                        cursor = Head(tx.prev_trans_lt, tx.prev_trans_hash.hex())
                    page += 1
                    require(time.monotonic() < deadline, "capture deadline expired")
                receipts = decode_history(
                    rows,
                    verified_head=head,
                    previous_head=previous,
                    wallet=self.wallet,
                    global_id=self.global_id,
                    subwallet_id=self.subwallet_id,
                    skipped_profile=True,
                )
                require(
                    0 <= time.time() - proof["target"]["gen_utime"] <= self.max_age,
                    "native checkpoint too old",
                )
                require(time.monotonic() < deadline, "capture deadline expired")
                sync_capture(path)
                write_file(
                    path / "result.json",
                    json.dumps(
                        {
                            "status": "VERIFIED_CAPTURE",
                            "target": proof["target"],
                            "head": vars(head),
                            "previous_head": vars(previous),
                            "receipts": len(receipts),
                        }
                    ).encode(),
                )
                sync_directory(path)
                sync_directory(self.root)
            finally:
                try:
                    self.retained += capture_size(path)
                except BaseException:
                    # Do not allow rejected/oversized evidence to evade the run
                    # budget. Preserve artifacts and refuse every later capture.
                    self.retained = self.storage_budget
                    raise
            require(
                0 <= time.time() - proof["target"]["gen_utime"] <= self.max_age
                and time.monotonic() < deadline,
                "capture expired during persistence",
            )
            completed = time.monotonic()
            self.state_source = path / "native-state.json"
            self.last_head = head
            return Capture(proof["target"]["seqno"], previous, head, receipts, completed, path)
