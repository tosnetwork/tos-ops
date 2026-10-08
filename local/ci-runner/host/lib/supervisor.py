"""CI runner supervisor: single-use VMs in three fixed slots.

Runs as the unprivileged account tos-ci. It holds the GitHub token, asks for
one just-in-time runner configuration per VM, writes each VM's seed, starts
and stops slots only through the root slot-control helper, and answers each
VM's admission request under the same lock that guards allowlist changes.
"""

from __future__ import annotations

import hashlib
import json
import os
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
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_PATH = Path("/etc/tos-ci/config.json")
LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
DIGITS = re.compile(r"[0-9]{1,20}")
JOB = re.compile(r"[A-Za-z0-9_.-]{1,100}")
REQUEST_KEYS = frozenset(
    {
        "slot",
        "vm_nonce",
        "run_id",
        "run_attempt",
        "job",
        "event",
        "repository",
        "author",
        "triggering_actor",
        "sender",
        "allowlist_sha256",
    }
)
MAX_FRAME = 4096
FRAME_DEADLINE = 2.0


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


def decide(
    request: dict[str, object],
    *,
    slot: int,
    nonce: str | None,
    admitted: bool,
    repository: str,
    allowlist: Allowlist,
) -> None:
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


# ------------------------------------------------------------------ GitHub


class GitHub:
    def __init__(self, repository: str, token_path: Path) -> None:
        self.repository = repository
        self.token_path = token_path

    def _request(self, method: str, path: str, body: object | None = None) -> object:
        token = self.token_path.read_text().strip()
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            f"https://api.github.com/repos/{self.repository}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
                "User-Agent": "tos-ci-supervisor",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else None

    def jit_config(self, name: str, labels: list[str]) -> tuple[int, str]:
        result = self._request(
            "POST",
            "/actions/runners/generate-jitconfig",
            {"name": name, "runner_group_id": 1, "labels": labels, "work_folder": "_work"},
        )
        assert isinstance(result, dict)
        return int(result["runner"]["id"]), str(result["encoded_jit_config"])

    def runner(self, runner_id: int) -> dict | None:
        try:
            result = self._request("GET", f"/actions/runners/{runner_id}")
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise
        return result if isinstance(result, dict) else None

    def delete_runner(self, runner_id: int) -> None:
        try:
            self._request("DELETE", f"/actions/runners/{runner_id}")
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise

    def runners_with_label(self, label: str) -> list[dict]:
        found, page = [], 1
        while True:
            result = self._request("GET", f"/actions/runners?per_page=100&page={page}")
            assert isinstance(result, dict)
            runners = result.get("runners", [])
            found += [r for r in runners if label in {x["name"] for x in r.get("labels", [])}]
            if len(runners) < 100:
                return found
            page += 1


# ---------------------------------------------------------------- slot control


def slotctl(path: str, verb: str, slot: int) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(240)
        conn.connect(path)
        conn.sendall(f"{verb} {slot}\n".encode())
        reply = b""
        while not reply.endswith(b"\n"):
            chunk = conn.recv(256)
            if not chunk:
                break
            reply += chunk
    return reply.decode().strip()


# -------------------------------------------------------------------- seed


def cloud_config(files: dict[str, tuple[str, str, str]]) -> str:
    """A #cloud-config with write_files entries: path -> (content, owner, mode)."""
    import base64

    lines = ["#cloud-config", "write_files:"]
    for path, (content, owner, mode) in files.items():
        encoded = base64.b64encode(content.encode()).decode()
        lines += [
            f"  - path: {path}",
            "    encoding: b64",
            f"    content: {encoded}",
            f"    owner: {owner}",
            f"    permissions: '{mode}'",
        ]
    lines += ["runcmd:", "  - [/usr/lib/tos-ci-guest/start-job]"]
    return "\n".join(lines) + "\n"


def write_seed(
    seed_dir: Path, *, slot: int, nonce: str, jit: str, allowlist: Allowlist, audit: bool
) -> None:
    user_data = cloud_config(
        {
            "/etc/tos-ci/jitconfig": (jit, "runner:runner", "0600"),
            "/etc/tos-ci/trusted-logins": (allowlist.data.decode("ascii"), "root:root", "0644"),
            "/etc/tos-ci/vm-nonce": (nonce + "\n", "root:root", "0644"),
            "/etc/tos-ci/slot": (f"{slot}\n", "root:root", "0644"),
            "/etc/tos-ci/audit": ("1\n" if audit else "0\n", "root:root", "0644"),
        }
    )
    meta_data = f"instance-id: tos-ci-{nonce[:16]}\nlocal-hostname: tos-ci-s{slot}\n"
    network = (
        "version: 2\nethernets:\n  nic:\n    match:\n      name: \"en*\"\n"
        "    dhcp4: true\n    dhcp6: false\n    accept-ra: false\n    link-local: []\n"
    )
    with tempfile.TemporaryDirectory(dir=seed_dir) as tmp:
        work = Path(tmp)
        (work / "user-data").write_text(user_data)
        (work / "meta-data").write_text(meta_data)
        (work / "network-config").write_text(network)
        iso = work / "seed.iso"
        subprocess.run(
            [
                "xorriso", "-as", "mkisofs", "-quiet", "-output", str(iso),
                "-volid", "cidata", "-joliet", "-rock",
                str(work / "user-data"), str(work / "meta-data"), str(work / "network-config"),
            ],
            check=True,
            timeout=60,
        )
        os.chmod(iso, 0o640)
        os.replace(iso, seed_dir / "seed.iso")


def remove_seed(seed_dir: Path) -> None:
    for entry in seed_dir.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


# ---------------------------------------------------------------- supervisor


@dataclass
class Slot:
    number: int
    state: str = "idle"  # idle | running
    runner_id: int | None = None
    runner_name: str | None = None
    nonce: str | None = None
    allowlist_sha256: str | None = None
    started: float = 0.0
    online_at: float = 0.0
    admitted_at: float = 0.0
    busy_since_unadmitted: float = 0.0
    binding: tuple[str, str, str] | None = None
    listener: socket.socket | None = None
    stop_reason: str | None = None
    last_api_check: float = 0.0
    threads: list[threading.Thread] = field(default_factory=list)

    @property
    def admitted(self) -> bool:
        return self.binding is not None


class Supervisor:
    def __init__(self, config: dict) -> None:
        self.config = config
        self.repository = config["repository"]
        self.labels = config["labels"]
        self.label = config["label"]
        self.slotctl_path = config["slotctl_socket"]
        self.store = Path(config["store"])
        self.allowlist_path = Path(config["allowlist"])
        self.drain_path = Path(config["drain_file"])
        self.hard_cap = config["hard_cap_minutes"] * 60
        self.github = GitHub(self.repository, Path(config["token"]))
        self.lock = threading.Lock()
        self.allowlist = Allowlist.read(self.allowlist_path)
        self.slots = {n: Slot(n) for n in (1, 2, 3)}
        self.stopping = threading.Event()
        self.disk_drain = False
        self.last_reconcile = 0.0
        # Per-slot launch backoff after a failure: (failures, not before).
        self.backoff: dict[int, tuple[int, float]] = {n: (0, 0.0) for n in (1, 2, 3)}

    # -- allowlist, always under self.lock

    def _refresh_allowlist_locked(self) -> bool:
        """Re-read the allowlist; on a change stop every slot not yet admitted."""
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
            if slot.state == "running" and not slot.admitted:
                self._stop(slot, "allowlist changed before admission")
        log("allowlist_changed", sha256=current.sha256 if current else None)
        return True

    # -- admission

    def _peer_ok(self, conn: socket.socket, slot: Slot) -> bool:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", creds)
        import pwd

        if uid != pwd.getpwnam(f"tos-ci-slot{slot.number}").pw_uid:
            return False
        status = slotctl(self.slotctl_path, "status", slot.number).split()
        return len(status) == 2 and status[0] == "active" and status[1] == str(pid)

    def _read_frame(self, conn: socket.socket) -> bytes | None:
        """One newline-terminated frame; the deadline starts at its first byte."""
        data = b""
        while not self.stopping.is_set():
            timeout = 1.0 if not data else max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select([conn], [], [], timeout)
            if not ready:
                if data and time.monotonic() >= deadline:
                    return data  # incomplete within the deadline: parse will deny
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

    def _serve_admission(self, slot: Slot, listener: socket.socket, nonce: str) -> None:
        while not self.stopping.is_set() and slot.nonce == nonce:
            try:
                ready, _, _ = select.select([listener], [], [], 1.0)
                if not ready:
                    continue
                conn, _ = listener.accept()
            except (OSError, ValueError):
                return  # the slot finished and its listener was closed
            # Every connection is checked as soon as it is accepted, so a
            # wrong peer is refused at once rather than left queued.
            if not self._peer_ok(conn, slot):
                log("admission_peer_refused", slot=slot.number)
                conn.close()
                continue
            threading.Thread(
                target=self._serve_conn, args=(slot, conn, nonce), daemon=True
            ).start()

    def _serve_conn(self, slot: Slot, conn: socket.socket, nonce: str) -> None:
        with conn:
            while slot.nonce == nonce and not self.stopping.is_set():
                try:
                    frame = self._read_frame(conn)
                except (OSError, ValueError):
                    return
                if frame is None:
                    return
                reply = self._admit(slot, frame)
                try:
                    conn.sendall((json.dumps(reply, sort_keys=True) + "\n").encode())
                except OSError:
                    return

    def _admit(self, slot: Slot, frame: bytes) -> dict:
        with self.lock:
            try:
                request = parse_request(frame)
                if self._refresh_allowlist_locked():
                    raise Denied("allowlist changed while the request was pending")
                if slot.state != "running":
                    raise Denied("slot is not running")
                decide(
                    request,
                    slot=slot.number,
                    nonce=slot.nonce,
                    admitted=slot.admitted,
                    repository=self.repository,
                    allowlist=self.allowlist,
                )
            except Denied as denial:
                log("admission_denied", slot=slot.number, reason=str(denial))
                return {"verdict": "denied", "reason": str(denial)}
            slot.binding = (str(request["run_id"]), str(request["run_attempt"]), str(request["job"]))
            slot.admitted_at = time.monotonic()
            log(
                "admission_allowed",
                slot=slot.number,
                runner=slot.runner_name,
                run_id=request["run_id"],
                run_attempt=request["run_attempt"],
                job=request["job"],
                event=request["event"],
                author=request["author"],
                triggering_actor=request["triggering_actor"],
                sender=request["sender"],
            )
            return {
                "verdict": "allowed",
                "vm_nonce": request["vm_nonce"],
                "run_id": request["run_id"],
                "run_attempt": request["run_attempt"],
                "job": request["job"],
            }

    # -- slot lifecycle

    def _launch(self, slot: Slot) -> None:
        nonce = secrets.token_hex(16)
        name = f"tos-ci-s{slot.number}-{nonce[:8]}"
        seed_dir = self.store / f"seed{slot.number}"
        sock_path = Path(f"/run/tos-ci/slot{slot.number}/admission.sock")
        runner_id = None
        try:
            runner_id, jit = self.github.jit_config(name, self.labels)
            with self.lock:
                allowlist = self.allowlist
            write_seed(
                seed_dir,
                slot=slot.number,
                nonce=nonce,
                jit=jit,
                allowlist=allowlist,
                audit=bool(self.config.get("audit", False)),
            )
            if sock_path.exists() or sock_path.is_symlink():
                sock_path.unlink()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(sock_path))
            os.chmod(sock_path, 0o660)
            listener.listen(1)
            slot.__dict__.update(
                state="running",
                runner_id=runner_id,
                runner_name=name,
                nonce=nonce,
                allowlist_sha256=allowlist.sha256,
                started=time.monotonic(),
                online_at=0.0,
                admitted_at=0.0,
                busy_since_unadmitted=0.0,
                binding=None,
                listener=listener,
                stop_reason=None,
            )
            thread = threading.Thread(
                target=self._serve_admission, args=(slot, listener, nonce), daemon=True
            )
            thread.start()
            slot.threads = [thread]
            reply = slotctl(self.slotctl_path, "start", slot.number)
            if reply != "ok":
                raise RuntimeError(f"slot start failed: {reply}")
            log("slot_started", slot=slot.number, runner=name, runner_id=runner_id)
            self.backoff[slot.number] = (0, 0.0)
        except Exception as error:  # noqa: BLE001 - any failure tears the slot down
            failures = self.backoff[slot.number][0] + 1
            delay = min(120 * 2 ** (failures - 1), 1800)
            self.backoff[slot.number] = (failures, time.monotonic() + delay)
            log(
                "slot_launch_failed",
                slot=slot.number,
                error=f"{type(error).__name__}: {error}",
                retry_in_s=delay,
            )
            slot.state = "running"
            slot.runner_id = runner_id
            self._stop(slot, "launch failed")
            self._finish(slot)

    def _stop(self, slot: Slot, reason: str) -> None:
        if slot.stop_reason is None:
            slot.stop_reason = reason
            log("slot_stopping", slot=slot.number, reason=reason, runner=slot.runner_name)
        try:
            slotctl(self.slotctl_path, "stop", slot.number)
        except OSError as error:
            log("slot_stop_failed", slot=slot.number, error=str(error))

    def _finish(self, slot: Slot) -> None:
        """The VM is gone: deregister its runner and forget the slot's secrets."""
        if slot.runner_id is not None:
            try:
                self.github.delete_runner(slot.runner_id)
            except Exception as error:  # noqa: BLE001 - reconcile retries later
                log("deregister_failed", slot=slot.number, error=str(error))
        if slot.listener is not None:
            slot.listener.close()
        try:
            remove_seed(self.store / f"seed{slot.number}")
        except OSError as error:
            log("seed_cleanup_failed", slot=slot.number, error=str(error))
        log(
            "slot_finished",
            slot=slot.number,
            runner=slot.runner_name,
            admitted=slot.admitted,
            reason=slot.stop_reason or "vm exited",
            lifetime_s=round(time.monotonic() - slot.started) if slot.started else 0,
        )
        self.slots[slot.number] = Slot(slot.number)

    def _cleanup_done(self, slot: Slot) -> bool:
        state = self.store / "state"
        start, cleanup = state / f"start-{slot.number}", state / f"cleanup-{slot.number}"
        if not start.exists():
            return True
        return cleanup.exists() and cleanup.stat().st_mtime >= start.stat().st_mtime

    def _check(self, slot: Slot, now: float) -> None:
        status = slotctl(self.slotctl_path, "status", slot.number).split()
        if not status or status[0] not in ("active", "activating", "deactivating"):
            self._finish(slot)
            return
        age = now - slot.started
        if slot.admitted:
            if now - slot.admitted_at > self.hard_cap:
                self._stop(slot, "job exceeded the hard cap")
            return
        if age > self.hard_cap + 35 * 60:
            self._stop(slot, "VM exceeded its lifetime")
            return
        if now - slot.last_api_check < 15:
            return
        slot.last_api_check = now
        try:
            info = self.github.runner(slot.runner_id) if slot.runner_id else None
        except Exception as error:  # noqa: BLE001 - try again next tick
            log("runner_status_failed", slot=slot.number, error=str(error))
            return
        online = bool(info and info.get("status") == "online")
        busy = bool(info and info.get("busy"))
        if online and not slot.online_at:
            slot.online_at = now
            log("runner_online", slot=slot.number, runner=slot.runner_name, boot_s=round(age))
        if not slot.online_at and age > self.config["boot_deadline_seconds"]:
            self._stop(slot, "no registration within the boot deadline")
        elif slot.online_at and not busy and age > self.config["idle_deadline_seconds"]:
            self._stop(slot, "never assigned a job")
        elif busy:
            if not slot.busy_since_unadmitted:
                slot.busy_since_unadmitted = now
            elif now - slot.busy_since_unadmitted > self.config["unadmitted_busy_seconds"]:
                self._stop(slot, "violation: job activity without admission")

    def _disk_ok(self) -> bool:
        pool = shutil.disk_usage(self.store)
        root = shutil.disk_usage("/")
        pool_free = pool.free / pool.total
        drain = pool_free < 0.15 or root.free < 120e9
        halt = pool_free < 0.08 or root.free < 60e9
        if drain != self.disk_drain:
            log("disk_drain" if drain else "disk_ok", pool_free=round(pool_free, 3), root_free_gb=round(root.free / 1e9))
            self.disk_drain = drain
        if halt:
            for slot in self.slots.values():
                if slot.state == "running":
                    self._stop(slot, "disk below the halt threshold")
        return not drain

    def _reconcile(self, initial: bool) -> None:
        tracked = {s.runner_id for s in self.slots.values() if s.runner_id is not None}
        try:
            for runner in self.github.runners_with_label(self.label):
                if runner["id"] not in tracked and (initial or runner.get("status") != "online" or not runner.get("busy")):
                    self.github.delete_runner(runner["id"])
                    log("orphan_registration_removed", runner=runner.get("name"))
        except Exception as error:  # noqa: BLE001 - next reconcile retries
            log("reconcile_failed", error=str(error))

    def start(self) -> None:
        log("supervisor_starting", allowlist_sha256=self.allowlist.sha256)
        for number in self.slots:
            slotctl(self.slotctl_path, "stop", number)
            remove_seed(self.store / f"seed{number}")
        self._reconcile(initial=True)

    def run(self) -> None:
        self.start()
        while not self.stopping.is_set():
            now = time.monotonic()
            with self.lock:
                self._refresh_allowlist_locked()
            disk_ok = self._disk_ok()
            draining = self.drain_path.exists() or not disk_ok
            for slot in list(self.slots.values()):
                if slot.state == "running":
                    if draining and not slot.admitted and slot.stop_reason is None:
                        self._stop(slot, "draining")
                    self._check(slot, now)
                elif (
                    not draining
                    and now >= self.backoff[slot.number][1]
                    and self._cleanup_done(slot)
                ):
                    self._launch(slot)
            if now - self.last_reconcile > 300:
                self.last_reconcile = now
                self._reconcile(initial=False)
            self.stopping.wait(2.0)

    def shutdown(self) -> None:
        """Drain, give admitted jobs up to ten minutes, then stop every slot."""
        log("supervisor_stopping")
        deadline = time.monotonic() + 600
        for slot in self.slots.values():
            if slot.state == "running" and not slot.admitted:
                self._stop(slot, "supervisor stopping")
        while time.monotonic() < deadline:
            running = [s for s in self.slots.values() if s.state == "running"]
            if not running:
                break
            for slot in running:
                self._check(slot, time.monotonic())
            time.sleep(2)
        for slot in self.slots.values():
            if slot.state == "running":
                self._stop(slot, "supervisor stop deadline")
                self._finish(slot)
        self._reconcile(initial=True)
        log("supervisor_stopped")


def verify_manifest(path: Path) -> None:
    """Refuse to run if any installed unit, drop-in or script changed."""
    for line in path.read_text().splitlines():
        digest, name = line.split(None, 1)
        actual = hashlib.sha256(Path(name).read_bytes()).hexdigest()
        if actual != digest:
            raise SystemExit(f"manifest mismatch: {name}")


def main() -> int:
    config = json.loads(CONFIG_PATH.read_text())
    verify_manifest(Path(config["manifest"]))
    supervisor = Supervisor(config)
    worker = threading.Thread(target=supervisor.run, daemon=True)

    def on_term(_signum: int, _frame: object) -> None:
        supervisor.stopping.set()

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    worker.start()
    while worker.is_alive():
        worker.join(1.0)
        if supervisor.stopping.is_set():
            break
    worker.join(30)
    supervisor.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
