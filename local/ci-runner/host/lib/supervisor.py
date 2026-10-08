"""CI runner supervisor: single-use VMs in three fixed slots.

Runs as the unprivileged account tos-ci. The main loop never blocks: every
external operation (GitHub, the root slot-control helper, seed writing) is a
child process (op.py) with a hard deadline, killed when it expires. Deadlines
are enforced from the local monotonic clock, whatever GitHub does. All slot
state changes and the admission decision happen under one lock; a result is
applied only if the slot's generation and operation still match.

Each slot moves through: init -> idle -> launching -> running -> stopping -> idle.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import re
import secrets
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

CONFIG_PATH = Path("/etc/tos-ci/config.json")
OP = "/usr/lib/tos-ci/op.py"
LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
DIGITS = re.compile(r"[0-9]{1,20}")
JOB = re.compile(r"[A-Za-z0-9_.-]{1,100}")
REQUEST_KEYS = frozenset(
    {"slot", "vm_nonce", "run_id", "run_attempt", "job", "event", "repository",
     "author", "triggering_actor", "sender", "allowlist_sha256"}
)
MAX_FRAME = 4096
FRAME_DEADLINE = 2.0
OP_DEADLINES = {"slot-up": 60, "slot-down": 60, "slot-status": 15, "slot-cleanup": 150,
                "jit": 20, "runner-status": 20, "runner-delete": 20, "reconcile": 60, "seed": 60}


def log(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


# ---------------------------------------------------------------- allowlist


def parse_allowlist(data: bytes) -> frozenset[str]:
    """The logins in an allowlist file. Empty or malformed content is an error."""
    logins = []
    for raw in data.decode("ascii").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not LOGIN.fullmatch(line):
            raise ValueError("malformed login in allowlist")
        logins.append(line.lower())
    if not logins:
        raise ValueError("allowlist is empty")
    return frozenset(logins)


@dataclass(frozen=True)
class Allowlist:
    data: bytes
    sha256: str
    logins: frozenset[str]

    @classmethod
    def read(cls, path: Path) -> "Allowlist":
        data = path.read_bytes()
        return cls(data, hashlib.sha256(data).hexdigest(), parse_allowlist(data))


# ---------------------------------------------------------------- admission


class Denied(Exception):
    pass


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise Denied("duplicate key")
    return dict(pairs)


def parse_request(frame: bytes) -> dict[str, object]:
    """A schema-checked admission request, or Denied."""
    if len(frame) > MAX_FRAME or not frame.endswith(b"\n"):
        raise Denied("frame too long or unterminated")
    try:
        request = json.loads(frame.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Denied(f"unparsable request: {type(error).__name__}") from error
    if not isinstance(request, dict) or frozenset(request) != REQUEST_KEYS:
        raise Denied("request keys do not match the schema")
    checks = {
        "slot": lambda v: isinstance(v, int) and not isinstance(v, bool) and v in (1, 2, 3),
        "vm_nonce": lambda v: isinstance(v, str) and HEX32.fullmatch(v),
        "run_id": lambda v: isinstance(v, str) and DIGITS.fullmatch(v),
        "run_attempt": lambda v: isinstance(v, str) and DIGITS.fullmatch(v) and len(v) <= 5,
        "job": lambda v: isinstance(v, str) and JOB.fullmatch(v),
        "event": lambda v: v in ("pull_request", "push"),
        "repository": lambda v: isinstance(v, str) and len(v) <= 140,
        "author": lambda v: isinstance(v, str) and LOGIN.fullmatch(v),
        "triggering_actor": lambda v: isinstance(v, str) and LOGIN.fullmatch(v),
        "sender": lambda v: isinstance(v, str) and LOGIN.fullmatch(v),
        "allowlist_sha256": lambda v: isinstance(v, str) and HEX64.fullmatch(v),
    }
    for key, check in checks.items():
        if not check(request[key]):
            raise Denied(f"field {key} is invalid")
    return request


def decide(request: dict[str, object], *, slot: int, nonce: str | None, admitted: bool,
           repository: str, allowlist: Allowlist) -> None:
    """Raise Denied unless this request may be admitted now."""
    if request["slot"] != slot:
        raise Denied("request names another slot")
    if nonce is None or not secrets.compare_digest(str(request["vm_nonce"]), nonce):
        raise Denied("nonce does not belong to the slot's current VM")
    if admitted:
        raise Denied("slot already admitted a job")
    if request["repository"] != repository:
        raise Denied("repository mismatch")
    if request["allowlist_sha256"] != allowlist.sha256:
        raise Denied("the VM evaluated a different allowlist")
    for key in ("author", "triggering_actor", "sender"):
        if str(request[key]).lower() not in allowlist.logins:
            raise Denied(f"{key} is not a trusted login")


# -------------------------------------------------------------- operations


class Handle:
    """A running op.py child that can never block the supervisor.

    stdin, stdout and stderr are private files, not pipes. Every file the
    child or its descendants write is bounded by RLIMIT_FSIZE (prlimit), so a
    runaway child is stopped by the kernel at the bound. The child leads its
    own session: completion and kill both SIGKILL the whole process group, so
    no descendant outlives its operation. kill() never waits; reap() is
    polled until the child is collected, then the files are removed.
    poll() -> None while running, else (ok, result).
    """

    MAX_STDIN = 32 * 1024
    MAX_OUTPUT = 64 * 1024
    FILE_LIMIT = 4 * 1024 * 1024

    def __init__(self, argv: list[str], stdin: bytes | None, op: str = OP, tmp: str | None = None) -> None:
        stdin = stdin or b""
        if len(stdin) > self.MAX_STDIN:
            raise ValueError(f"op stdin of {len(stdin)} bytes exceeds {self.MAX_STDIN}")
        self.dir = Path(tempfile.mkdtemp(prefix="tos-ci-op-", dir=tmp))
        self.result: tuple[bool, dict | str] | None = None
        self.collected = False
        try:
            (self.dir / "in").write_bytes(stdin)
            with open(self.dir / "in", "rb") as fin, open(self.dir / "out", "wb") as fout, \
                    open(self.dir / "err", "wb") as ferr:
                self.proc = subprocess.Popen(
                    ["/usr/bin/prlimit", f"--fsize={self.FILE_LIMIT}", "--",
                     "/usr/bin/python3", "-I", op, *argv],
                    stdin=fin, stdout=fout, stderr=ferr, start_new_session=True, close_fds=True,
                )
        except BaseException:
            # No child exists to reap; the stdin file may hold a secret.
            self._finish_files()
            raise

    def _kill_group(self) -> None:
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def _read(self, name: str) -> bytes:
        with open(self.dir / name, "rb") as f:
            return f.read(self.MAX_OUTPUT + 1)

    def _finish_files(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def poll(self) -> tuple[bool, dict | str] | None:
        if self.result is not None:
            return self.result
        # Look without reaping, so the group id cannot be reused before the
        # group is killed.
        info = os.waitid(os.P_PID, self.proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if info is None:
            return None
        self._kill_group()  # descendants of a finished op do not survive it
        returncode = self.proc.wait()
        self.collected = True
        # A child that hit the bound sees SIGXFSZ, or EFBIG if it ignores the
        # signal (Python does); either way a file is left at the bound.
        at_bound = any((self.dir / name).stat().st_size >= self.FILE_LIMIT for name in ("out", "err"))
        out, err = self._read("out"), self._read("err")
        self._finish_files()
        if at_bound or returncode == -signal.SIGXFSZ:
            self.result = (False, "output exceeded the file size limit")
        elif returncode != 0:
            detail = (err.decode(errors="replace").strip().splitlines() or [f"exit {returncode}"])[-1][:300]
            self.result = (False, detail)
        elif len(out) > self.MAX_OUTPUT:
            self.result = (False, "output too large")
        else:
            try:
                self.result = (True, json.loads(out.decode()))
            except ValueError:
                self.result = (False, "unparsable op output")
        return self.result

    def kill(self) -> None:
        self._kill_group()

    def reap(self) -> bool:
        """True once the child is collected and its files are gone."""
        if not self.collected:
            if self.proc.poll() is None:
                return False
            self.collected = True
        self._finish_files()
        return True


class FailedHandle:
    """An operation that could not start; reported as an ordinary failure."""

    def __init__(self, reason: str) -> None:
        self.result = (False, reason)

    def poll(self) -> tuple[bool, str]:
        return self.result

    def kill(self) -> None:
        pass

    def reap(self) -> bool:
        return True


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def valid_result(kind: str, result: object) -> bool:
    """The successful result of an operation has its kind's exact shape."""
    if not isinstance(result, dict):
        return False
    if kind == "jit":
        return (_is_int(result.get("runner_id")) and isinstance(result.get("name"), str)
                and isinstance(result.get("encoded_jit_config"), str) and bool(result["encoded_jit_config"]))
    if kind == "runner-status":
        return result == {"missing": True} or (
            isinstance(result.get("status"), str) and isinstance(result.get("busy"), bool))
    if kind == "slot-status":
        return (isinstance(result.get("active"), str) and _is_int(result.get("pid")) and result["pid"] >= 0
                and _is_int(result.get("latest")) and result["latest"] >= 0
                and result.get("desired") in ("up", "down"))
    if kind in ("slot-up", "slot-down", "slot-cleanup"):
        return isinstance(result.get("reply"), str)
    if kind in ("seed", "runner-delete"):
        return result.get("ok") is True
    if kind == "reconcile":
        deleted = result.get("deleted")
        return isinstance(deleted, list) and all(isinstance(n, str) for n in deleted)
    return False


@dataclass
class Op:
    kind: str
    generation: int
    op_id: int
    handle: object
    deadline: float


# ---------------------------------------------------------------- the slot


@dataclass
class Slot:
    number: int
    state: str = "init"
    generation: int = 0
    phase: str = ""
    runner_id: int | None = None
    runner_name: str | None = None
    nonce: str | None = None
    jit: str | None = None
    allowlist: Allowlist | None = None
    started: float = 0.0
    online_at: float = 0.0
    admitted_at: float = 0.0
    binding: tuple[str, str, str] | None = None
    qemu_pid: int = 0
    stop_reason: str | None = None
    launch_failed: bool = False
    down_acked: bool = False
    unit_down: bool = False
    op: Op | None = None
    next_status: float = 0.0
    next_api: float = 0.0
    busy_since: float = 0.0
    failures: int = 0
    not_before: float = 0.0
    listener: socket.socket | None = None
    conns: list = field(default_factory=list)
    maint_fd: object = None

    @property
    def admitted(self) -> bool:
        return self.binding is not None


class Supervisor:
    def __init__(self, config: dict, *, spawn: Callable | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.config = config
        self.repository = config["repository"]
        self.store = Path(config["store"])
        self.allowlist_path = Path(config["allowlist"])
        self.drain_path = Path(config["drain_file"])
        self.maintenance_path = Path(config.get("maintenance_lock", "/run/tos-ci/maintenance.lock"))
        self.hard_cap = config["hard_cap_minutes"] * 60
        self.spawn = spawn or (lambda argv, stdin: Handle(argv, stdin))
        self.now = clock
        self.lock = threading.RLock()
        self.allowlist = Allowlist.read(self.allowlist_path)
        self.slots = {n: Slot(n) for n in (1, 2, 3)}
        self.next_op_id = 0
        self.global_op: Op | None = None
        self.pending_deletes: list[int] = []
        self.next_reconcile = 0.0
        self.stopping = threading.Event()
        self.shutdown_started = 0.0
        self.disk_drain = False
        # Children killed before completion, polled until collected.
        self.reaping: list = []

    # -- operations

    def _start_op(self, slot: Slot | None, kind: str, argv: list[str], stdin: bytes | None = None) -> Op:
        self.next_op_id += 1
        try:
            handle = self.spawn(argv, stdin)
        except (OSError, ValueError) as error:
            handle = FailedHandle(f"{kind} could not start: {error}")
        op = Op(kind, slot.generation if slot else 0, self.next_op_id, handle, self.now() + OP_DEADLINES[kind])
        if slot is not None:
            slot.op = op
        else:
            self.global_op = op
        return op

    def _kill_op(self, slot: Slot) -> None:
        if slot.op is not None:
            slot.op.handle.kill()
            self.reaping.append(slot.op.handle)
            log("op_superseded", slot=slot.number, kind=slot.op.kind)
            slot.op = None

    def _poll_op(self, op: Op) -> tuple[bool, dict | str] | None:
        result = op.handle.poll()
        if result is None:
            if self.now() > op.deadline:
                op.handle.kill()
                self.reaping.append(op.handle)
                return False, f"{op.kind} exceeded its {OP_DEADLINES[op.kind]} s deadline"
            return None
        ok, value = result
        if ok and not valid_result(op.kind, value):
            return False, f"{op.kind} returned a malformed result"
        return result

    def _reap(self) -> None:
        self.reaping = [handle for handle in self.reaping if not handle.reap()]

    def _ops_running(self, kind: str) -> bool:
        ops = [s.op for s in self.slots.values()] + [self.global_op]
        return any(op is not None and op.kind == kind for op in ops)

    def _reserved_names(self) -> list[str]:
        """Every runner name a slot holds or is creating; reconciliation keeps them."""
        return [s.runner_name for s in self.slots.values() if s.runner_name]

    # -- allowlist (under the lock)

    def _refresh_allowlist(self) -> bool:
        try:
            current = Allowlist.read(self.allowlist_path)
        except (OSError, ValueError) as error:
            log("allowlist_unreadable", error=str(error))
            current = None
        if current is not None and current.sha256 == self.allowlist.sha256:
            return False
        if current is not None:
            self.allowlist = current
        for slot in self.slots.values():
            if slot.state in ("launching", "running") and not slot.admitted:
                self._mark_stop(slot, "allowlist changed before admission")
        log("allowlist_changed", sha256=current.sha256 if current else None)
        return True

    # -- admission

    def _peer_ok(self, conn: socket.socket, number: int, generation: int) -> bool:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", creds)
        with self.lock:
            slot = self.slots[number]
            expected = slot.qemu_pid if slot.generation == generation else 0
        if not expected or pid != expected:
            return False
        if uid != pwd.getpwnam(f"tos-ci-slot{number}").pw_uid:
            return False
        try:
            cgroup = Path(f"/proc/{pid}/cgroup").read_text()
        except OSError:
            return False
        return f"/tos-ci.slice/tos-ci-vm@{number}.service" in cgroup

    def _read_frame(self, conn: socket.socket) -> bytes | None:
        """One newline-terminated frame; one absolute deadline from its first byte."""
        data, deadline = b"", 0.0
        while not self.stopping.is_set():
            timeout = 1.0 if not data else max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select([conn], [], [], timeout)
            if not ready:
                if data and time.monotonic() >= deadline:
                    return data
                continue
            chunk = conn.recv(MAX_FRAME + 1 - len(data))
            if not chunk:
                return None
            if not data:
                deadline = time.monotonic() + FRAME_DEADLINE
            data += chunk
            if b"\n" in data or len(data) > MAX_FRAME:
                return data
        return None

    def _serve_listener(self, number: int, generation: int, listener: socket.socket) -> None:
        while not self.stopping.is_set():
            try:
                ready, _, _ = select.select([listener], [], [], 1.0)
                if not ready:
                    continue
                conn, _ = listener.accept()
            except (OSError, ValueError):
                return
            if not self._peer_ok(conn, number, generation):
                log("admission_peer_refused", slot=number)
                conn.close()
                continue
            with self.lock:
                slot = self.slots[number]
                if slot.generation != generation or slot.state != "running":
                    conn.close()
                    continue
                slot.conns.append(conn)
            threading.Thread(target=self._serve_conn, args=(number, generation, conn), daemon=True).start()

    def _serve_conn(self, number: int, generation: int, conn: socket.socket) -> None:
        try:
            while not self.stopping.is_set():
                frame = self._read_frame(conn)
                if frame is None:
                    return
                reply = self._admit(number, generation, frame)
                conn.sendall((json.dumps(reply, sort_keys=True) + "\n").encode())
        except (OSError, ValueError):
            return

    def _admit(self, number: int, generation: int, frame: bytes) -> dict:
        with self.lock:
            slot = self.slots[number]
            try:
                request = parse_request(frame)
                if self._refresh_allowlist():
                    raise Denied("allowlist changed while the request was pending")
                if slot.generation != generation:
                    raise Denied("connection belongs to an earlier VM")
                if slot.state != "running" or slot.stop_reason is not None:
                    raise Denied("slot is not running")
                decide(request, slot=number, nonce=slot.nonce, admitted=slot.admitted,
                       repository=self.repository, allowlist=self.allowlist)
            except Denied as denial:
                log("admission_denied", slot=number, reason=str(denial))
                return {"verdict": "denied", "reason": str(denial)}
            slot.binding = (str(request["run_id"]), str(request["run_attempt"]), str(request["job"]))
            slot.admitted_at = self.now()
            log("admission_allowed", slot=number, runner=slot.runner_name, run_id=request["run_id"],
                run_attempt=request["run_attempt"], job=request["job"], event_name=request["event"],
                author=request["author"], triggering_actor=request["triggering_actor"], sender=request["sender"])
            return {"verdict": "allowed", "vm_nonce": request["vm_nonce"], "run_id": request["run_id"],
                    "run_attempt": request["run_attempt"], "job": request["job"]}

    # -- transitions (under the lock)

    def _mark_stop(self, slot: Slot, reason: str, *, launch_failed: bool = False) -> None:
        if slot.state not in ("launching", "running"):
            return
        self._kill_op(slot)
        slot.state, slot.stop_reason = "stopping", reason
        slot.launch_failed = launch_failed
        slot.down_acked = slot.unit_down = False
        log("slot_stopping", slot=slot.number, generation=slot.generation, reason=reason, runner=slot.runner_name)

    def _release_maintenance(self, slot: Slot) -> None:
        if slot.maint_fd is not None:
            try:
                fcntl.flock(slot.maint_fd, fcntl.LOCK_UN)
                slot.maint_fd.close()
            except OSError:
                pass
            slot.maint_fd = None

    def _close_admission(self, slot: Slot) -> None:
        for conn in slot.conns:
            try:
                conn.close()
            except OSError:
                pass
        slot.conns = []
        if slot.listener is not None:
            slot.listener.close()
            slot.listener = None

    def _cleanup_confirmed(self, slot: Slot) -> bool:
        """The last generation that started in this slot has been cleaned.

        Markers hold generations and are compared exactly; file timestamps are
        too coarse to order a start and a cleanup written close together.
        """
        state = self.store / "state"
        try:
            started = (state / f"start-{slot.number}").read_text().strip()
        except FileNotFoundError:
            return True
        except OSError as error:
            log("marker_unreadable", slot=slot.number, error=str(error))
            return False
        try:
            return (state / f"cleanup-{slot.number}").read_text().strip() == started
        except OSError:
            return False

    def _finish(self, slot: Slot) -> None:
        """Teardown confirmed: forget the VM, keeping the slot's generation."""
        self._close_admission(slot)
        self._release_maintenance(slot)
        if slot.runner_id is not None:
            self.pending_deletes.append(slot.runner_id)
        seed = self.store / f"seed{slot.number}" / "seed.iso"
        try:
            seed.unlink(missing_ok=True)
        except OSError as error:
            log("seed_cleanup_failed", slot=slot.number, error=str(error))
        log("slot_finished", slot=slot.number, generation=slot.generation, runner=slot.runner_name,
            admitted=slot.admitted, reason=slot.stop_reason or "vm exited",
            lifetime_s=round(self.now() - slot.started) if slot.started else 0)
        if slot.launch_failed:
            slot.failures += 1
            slot.not_before = self.now() + min(120 * 2 ** (slot.failures - 1), 1800)
        else:
            slot.failures, slot.not_before = 0, 0.0
        keep = {"generation": slot.generation, "failures": slot.failures, "not_before": slot.not_before}
        self.slots[slot.number] = Slot(slot.number, state="idle", **keep)

    # -- the per-slot state machine (under the lock)

    def _on_result(self, slot: Slot, op: Op, ok: bool, result: dict | str) -> None:
        slot.op = None
        kind = op.kind
        if kind == "slot-status":
            if not ok:
                return
            active, pid = result["active"], int(result["pid"])
            if slot.state == "init":
                slot.generation = int(result["latest"])
                slot.state = "stopping"
                slot.stop_reason = "supervisor start"
                return
            if slot.state == "running":
                if active in ("active", "activating"):
                    slot.qemu_pid = pid if active == "active" else 0
                else:
                    self._mark_stop(slot, "vm exited")
            elif slot.state == "stopping":
                slot.unit_down = active not in ("active", "activating", "deactivating")
            return
        if slot.state == "launching":
            if not ok:
                self._mark_stop(slot, f"launch failed: {kind}: {result}", launch_failed=True)
                return
            # Each step only records the next phase; _advance_launch starts it
            # when the coordination rules allow.
            if kind == "reconcile":
                slot.phase = "jit"
            elif kind == "jit":
                if result["name"] != slot.runner_name:
                    self._mark_stop(slot, "launch failed: jit returned another name", launch_failed=True)
                    return
                slot.runner_id = result["runner_id"]
                slot.jit = result["encoded_jit_config"]
                slot.phase = "seed"
            elif kind == "seed":
                slot.jit = None
                self._open_listener(slot)
                slot.phase = "up"
            elif kind == "slot-up":
                if result.get("reply") != "ok":
                    self._mark_stop(slot, f"launch failed: up: {result.get('reply')}", launch_failed=True)
                    return
                slot.state = "running"
                slot.started = self.now()
                slot.next_status = 0.0
                self._release_maintenance(slot)
                log("slot_started", slot=slot.number, generation=slot.generation, runner=slot.runner_name,
                    runner_id=slot.runner_id)
            return
        if slot.state == "running" and kind == "runner-status" and ok:
            if result.get("status") == "online" and not slot.online_at:
                slot.online_at = self.now()
                log("runner_online", slot=slot.number, runner=slot.runner_name,
                    boot_s=round(self.now() - slot.started))
            if result.get("busy") and not slot.admitted:
                slot.busy_since = slot.busy_since or self.now()
            return
        if slot.state == "stopping":
            if kind == "slot-down" and ok and result.get("reply") in ("ok", "stale"):
                slot.down_acked = True
                slot.next_status = 0.0
            elif kind == "slot-cleanup":
                if not ok or result.get("reply") != "ok":
                    log("teardown_unconfirmed", slot=slot.number, generation=slot.generation,
                        detail=result if not ok else result.get("reply"))
                    slot.not_before = self.now() + 30
            elif not ok:
                log("teardown_op_failed", slot=slot.number, kind=kind, error=result)

    def _open_listener(self, slot: Slot) -> None:
        path = Path(f"/run/tos-ci/slot{slot.number}/admission.sock")
        if path.exists() or path.is_symlink():
            path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        os.chmod(path, 0o660)
        listener.listen(4)
        slot.listener = listener
        threading.Thread(target=self._serve_listener, args=(slot.number, slot.generation, listener),
                         daemon=True).start()

    def _try_maintenance_shared(self) -> object | None:
        try:
            fd = open(self.maintenance_path, "r")
        except OSError:
            return None
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return fd
        except OSError:
            fd.close()
            return None

    def _launch(self, slot: Slot) -> None:
        fd = self._try_maintenance_shared()
        if fd is None:
            log("launch_skipped", slot=slot.number, reason="image maintenance in progress")
            slot.not_before = self.now() + 30
            return
        slot.maint_fd = fd
        slot.generation += 1
        slot.nonce = secrets.token_hex(16)
        # Reserved before any JIT request, so every reconciliation from now
        # on keeps this name even while its creation is in flight.
        slot.runner_name = f"tos-ci-s{slot.number}-{slot.nonce[:8]}"
        slot.allowlist = self.allowlist
        slot.state, slot.phase, slot.started = "launching", "sweep", self.now()
        self._advance_launch(slot)

    def _advance_launch(self, slot: Slot) -> None:
        """Start the launch's next step. JIT creation and reconciliation never overlap."""
        if slot.op is not None:
            return
        if slot.phase == "sweep":
            if self._ops_running("jit"):
                return
            stdin = json.dumps({"keep": self._reserved_names(), "prefix": f"tos-ci-s{slot.number}-"}).encode()
            self._start_op(slot, "reconcile", ["reconcile"], stdin)
        elif slot.phase == "jit":
            if self._ops_running("reconcile"):
                return
            self._start_op(slot, "jit", ["jit", str(slot.number), slot.runner_name])
        elif slot.phase == "seed":
            stdin = json.dumps({"nonce": slot.nonce, "jit": slot.jit, "allowlist": slot.allowlist.data.decode(),
                                "audit": bool(self.config.get("audit", False))}).encode()
            self._start_op(slot, "seed", ["seed", str(slot.number)], stdin)
        elif slot.phase == "up":
            self._start_op(slot, "slot-up", ["slot", "up", str(slot.number), str(slot.generation)])

    def _tick_slot(self, slot: Slot, now: float, draining: bool) -> None:
        if slot.op is not None:
            result = self._poll_op(slot.op)
            if result is not None:
                op = slot.op
                try:
                    self._on_result(slot, op, *result)
                except (AttributeError, KeyError, TypeError, ValueError) as error:
                    # A malformed result is that operation failing, never a crash.
                    log("op_result_invalid", slot=slot.number, kind=op.kind, error=f"{type(error).__name__}: {error}")
                    slot.op = None
                    if slot.state == "launching":
                        self._mark_stop(slot, f"launch failed: {op.kind}: invalid result", launch_failed=True)
        slot = self.slots[slot.number]
        if slot.state == "init":
            if slot.op is None:
                self._start_op(slot, "slot-status", ["slot", "status", str(slot.number)])
        elif slot.state == "idle":
            if not draining and now >= slot.not_before and not self.stopping.is_set():
                self._launch(slot)
        elif slot.state in ("launching", "running"):
            age = now - slot.started
            if draining and not slot.admitted:
                self._mark_stop(slot, "draining")
            elif slot.admitted and now - slot.admitted_at > self.hard_cap:
                self._mark_stop(slot, "job exceeded the hard cap")
            elif not slot.admitted and not slot.online_at and age > self.config["boot_deadline_seconds"]:
                self._mark_stop(slot, "no registration within the boot deadline")
            elif not slot.admitted and age > self.config["idle_deadline_seconds"]:
                self._mark_stop(slot, "never admitted a job")
            elif age > self.hard_cap + 35 * 60:
                self._mark_stop(slot, "VM exceeded its lifetime")
            elif slot.busy_since and not slot.admitted and now - slot.busy_since > self.config["unadmitted_busy_seconds"]:
                self._mark_stop(slot, "violation: job activity without admission")
            elif slot.state == "launching":
                self._advance_launch(slot)
            elif slot.state == "running" and slot.op is None:
                if now >= slot.next_status:
                    slot.next_status = now + 5
                    self._start_op(slot, "slot-status", ["slot", "status", str(slot.number)])
                elif now >= slot.next_api and slot.runner_id is not None:
                    slot.next_api = now + 15
                    self._start_op(slot, "runner-status", ["runner-status", str(slot.runner_id)])
        if slot.state == "stopping" and slot.op is None:
            if not slot.down_acked:
                self._start_op(slot, "slot-down", ["slot", "down", str(slot.number), str(slot.generation)])
            elif not slot.unit_down:
                if now >= slot.next_status:
                    slot.next_status = now + 2
                    self._start_op(slot, "slot-status", ["slot", "status", str(slot.number)])
            elif self._cleanup_confirmed(slot):
                self._finish(slot)
            elif now >= slot.not_before:
                self._start_op(slot, "slot-cleanup", ["slot", "cleanup", str(slot.number), str(slot.generation)])

    def _tick_global(self, now: float) -> None:
        if self.global_op is not None:
            result = self._poll_op(self.global_op)
            if result is None:
                return
            if not result[0]:
                log("global_op_failed", kind=self.global_op.kind, error=result[1])
            elif self.global_op.kind == "reconcile" and result[1].get("deleted"):
                log("orphan_registrations_removed", names=result[1]["deleted"])
            self.global_op = None
        if self.pending_deletes:
            self._start_op(None, "runner-delete", ["runner-delete", str(self.pending_deletes.pop(0))])
        elif now >= self.next_reconcile and not self._ops_running("jit"):
            self.next_reconcile = now + 300
            stdin = json.dumps({"keep": self._reserved_names()}).encode()
            self._start_op(None, "reconcile", ["reconcile"], stdin)

    def _disk_ok(self) -> bool:
        pool, root = shutil.disk_usage(self.store), shutil.disk_usage("/")
        pool_free = pool.free / pool.total
        drain = pool_free < 0.15 or root.free < 120e9
        if drain != self.disk_drain:
            log("disk_drain" if drain else "disk_ok", pool_free=round(pool_free, 3), root_free_gb=round(root.free / 1e9))
            self.disk_drain = drain
        if pool_free < 0.08 or root.free < 60e9:
            for slot in self.slots.values():
                self._mark_stop(slot, "disk below the halt threshold")
        return not drain

    def tick(self) -> None:
        now = self.now()
        with self.lock:
            self._refresh_allowlist()
            draining = self.drain_path.exists() or not self._disk_ok() or self.stopping.is_set()
            if self.stopping.is_set():
                waited = now - self.shutdown_started
                for slot in self.slots.values():
                    if not slot.admitted or waited > 600:
                        self._mark_stop(slot, "supervisor stopping")
            for number in (1, 2, 3):
                self._tick_slot(self.slots[number], now, draining)
            self._tick_global(now)
            self._reap()

    def all_quiet(self) -> bool:
        with self.lock:
            return all(s.state == "idle" for s in self.slots.values()) and self.global_op is None and not self.pending_deletes

    def run(self) -> None:
        log("supervisor_starting", allowlist_sha256=self.allowlist.sha256)
        while True:
            self.tick()
            if self.stopping.is_set() and (self.all_quiet() or self.now() - self.shutdown_started > 660):
                break
            time.sleep(1.0)
        log("supervisor_stopped")


def verify_manifest(path: Path) -> None:
    """Refuse to run if any installed unit, drop-in or script changed."""
    for line in path.read_text().splitlines():
        digest, name = line.split(None, 1)
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"manifest mismatch: {name}")


def main() -> int:
    config = json.loads(CONFIG_PATH.read_text())
    verify_manifest(Path(config["manifest"]))
    supervisor = Supervisor(config)

    def on_term(_signum: int, _frame: object) -> None:
        if not supervisor.stopping.is_set():
            supervisor.shutdown_started = supervisor.now()
            supervisor.stopping.set()
            log("supervisor_stopping")

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    supervisor.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
