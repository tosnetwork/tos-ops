"""Verification-mode audit transport: archive pruning and writing, the guest's
forwarder and closer, and the host's validity rules."""

from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def load(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


prune_mod = load("audit_prune", ROOT / "host" / "lib" / "audit-prune")
writer_mod = load("audit_writer", ROOT / "host" / "lib" / "audit-writer")
forward_mod = load("audit_forward", ROOT / "guest" / "audit-forward")
close_mod = load("audit_close", ROOT / "guest" / "audit-close")
check_mod = load("audit_check", HERE / "live" / "audit-check.py")

NONCE = "0123456789abcdef0123456789abcdef"


class Archive(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        (self.root / ".lock").write_text("")
        for n in (1, 2, 3):
            (self.root / f"slot{n}").mkdir()

    def tearDown(self) -> None:
        for n in (1, 2, 3):
            os.chmod(self.root / f"slot{n}", 0o700)
        self.dir.cleanup()

    def file(self, slot: int, name: str, size: int, age: int) -> Path:
        path = self.root / f"slot{slot}" / f"{name}.log"
        with open(path, "wb") as f:
            f.truncate(size)  # sparse: the budget counts st_size
        stamp = time.time() - age
        os.utime(path, (stamp, stamp))
        return path


class PruneTest(Archive):
    def names(self) -> list[str]:
        return sorted(p.name for p in self.root.glob("slot*/*.log"))

    def test_oldest_closed_files_go_until_the_budget_holds(self) -> None:
        self.file(1, "a", 4, age=50)
        self.file(2, "b", 4, age=40)
        self.file(3, "c", 4, age=30)
        removed = prune_mod.prune(self.root, budget=8, max_closed=20)
        self.assertEqual(removed, ["a.log"])
        self.assertEqual(self.names(), ["b.log", "c.log"])

    def test_the_count_bound(self) -> None:
        for i in range(5):
            self.file(1, f"f{i}", 1, age=100 - i)
        prune_mod.prune(self.root, budget=100, max_closed=2)
        self.assertEqual(self.names(), ["f3.log", "f4.log"])

    def test_an_active_file_is_never_removed(self) -> None:
        active = self.file(1, "old-active", 50, age=100)
        self.file(2, "closed", 4, age=10)
        with open(active, "rb") as held:
            fcntl.flock(held, fcntl.LOCK_SH)
            removed = prune_mod.prune(self.root, budget=4, max_closed=20)
        self.assertEqual(removed, [])
        self.assertTrue(active.exists())

    def test_an_unremovable_file_refuses(self) -> None:
        self.file(1, "stuck", 50, age=100)
        os.chmod(self.root / "slot1", 0o500)
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        with self.assertRaisesRegex(SystemExit, "cannot remove"):
            prune_mod.prune(self.root, budget=4, max_closed=20)

    def test_within_bounds_nothing_is_removed(self) -> None:
        self.file(1, "a", 4, age=10)
        self.assertEqual(prune_mod.prune(self.root, budget=4, max_closed=1), [])


# The writer runs in a child under a real file-size limit, as in its unit.
WRITER_CHILD = """
import importlib.machinery, importlib.util, os, resource, signal, socket, sys
from pathlib import Path
loader = importlib.machinery.SourceFileLoader("w", sys.argv[1])
spec = importlib.util.spec_from_loader("w", loader)
w = importlib.util.module_from_spec(spec); loader.exec_module(w)
cap = int(sys.argv[3])
resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
conn = socket.socket(fileno=int(sys.argv[4]))
root = Path(sys.argv[2])
w.serve(conn, root / "slot1", root / ".lock")
"""


class WriterTest(Archive):
    def start(self, cap: int):
        parent, child = socket.socketpair()
        script = self.root / "child.py"
        script.write_text(WRITER_CHILD)
        proc = subprocess.Popen(
            [sys.executable, "-I", str(script), str(ROOT / "host" / "lib" / "audit-writer"), str(self.root),
             str(cap), str(child.fileno())],
            pass_fds=(child.fileno(),), stdout=subprocess.PIPE, text=True)
        child.close()
        self.addCleanup(proc.kill)
        return parent, proc

    def files(self) -> list[Path]:
        return list((self.root / "slot1").glob("*.log"))

    def test_no_stream_leaves_no_file(self) -> None:
        sock, proc = self.start(1 << 20)
        sock.close()
        self.assertEqual(proc.wait(10), 0)
        self.assertEqual(self.files(), [])

    def test_the_stream_is_archived_and_locked_while_open(self) -> None:
        sock, proc = self.start(1 << 20)
        sock.sendall(b"type=USER msg=audit(1.0:1): x\n")
        for _ in range(100):
            if self.files() and self.files()[0].stat().st_size:
                break
            time.sleep(0.02)
        [path] = self.files()
        self.assertFalse(prune_mod.closed(path))  # the pruner sees it as active
        sock.close()
        self.assertEqual(proc.wait(10), 0)
        self.assertEqual(path.read_bytes(), b"type=USER msg=audit(1.0:1): x\n")
        self.assertTrue(prune_mod.closed(path))

    def test_at_its_cap_the_writer_stops_reading_and_stays_alive(self) -> None:
        cap = 64 * 1024
        sock, proc = self.start(cap)
        sock.settimeout(5)
        sent = 0
        chunk = b"x" * 4096
        try:
            while sent < 16 * cap:
                sock.send(chunk)
                sent += len(chunk)
        except (socket.timeout, BlockingIOError):
            pass  # the writer no longer reads: flow control holds the sender
        time.sleep(0.3)
        self.assertIsNone(proc.poll())
        [path] = self.files()
        self.assertEqual(path.stat().st_size, cap)
        self.assertLess(sent, 16 * cap)


class ForwardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.log = self.root / "audit.log"
        self.port = self.root / "port"
        self.port.write_bytes(b"")
        forward_mod.ACK = str(self.root / "ack")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def run_forward(self):
        errors = []

        def target():
            try:
                forward_mod.forward(str(self.log), str(self.port))
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread, errors

    def ack(self) -> int:
        try:
            return int((self.root / "ack").read_text())
        except (OSError, ValueError):
            return -1

    def wait_ack(self, offset: int) -> None:
        for _ in range(200):
            if self.ack() == offset:
                return
            time.sleep(0.01)
        self.fail(f"ack stayed {self.ack()}, expected {offset}")

    def test_forwards_from_the_first_byte_and_acknowledges(self) -> None:
        self.log.write_bytes(b"one\n")
        self.run_forward()
        self.wait_ack(4)
        with open(self.log, "ab") as f:
            f.write(b"two\n")
        self.wait_ack(8)
        self.assertEqual(self.port.read_bytes(), b"one\ntwo\n")

    def test_rotation_ends_forwarding(self) -> None:
        self.log.write_bytes(b"one\n")
        thread, errors = self.run_forward()
        self.wait_ack(4)
        self.log.rename(self.root / "audit.log.1")
        self.log.write_bytes(b"new\n")
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(str(errors[0]), "rotation")

    def test_a_shrinking_log_ends_forwarding(self) -> None:
        self.log.write_bytes(b"one\ntwo\n")
        thread, errors = self.run_forward()
        self.wait_ack(8)
        with open(self.log, "r+b") as f:
            f.truncate(2)
        thread.join(5)
        self.assertEqual(str(errors[0]), "rotation")


class CloseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.saved = {k: getattr(close_mod, k) for k in ("LOG", "ACK", "LOCK", "STATE", "NONCE", "emit_markers")}
        close_mod.LOG, close_mod.ACK = root / "audit.log", root / "ack"
        close_mod.LOCK, close_mod.STATE, close_mod.NONCE = root / "lock", root / "state", root / "nonce"
        close_mod.NONCE.write_text(NONCE + "\n")
        close_mod.LOG.write_bytes(b"type=DAEMON_START msg=audit(1.0:1): x\n")
        self.emitted = 0

        def emit(nonce: str) -> None:
            self.emitted += 1
            with open(close_mod.LOG, "ab") as f:
                f.write(b"type=USER msg=audit(1.0:2): msg='tos-ci-audit-status lost=0 backlog=0 '\n")
                f.write(f"type=USER msg=audit(1.0:3): msg='tos-ci-audit-end nonce={nonce} '\n".encode())

        close_mod.emit_markers = emit

    def tearDown(self) -> None:
        for k, v in self.saved.items():
            setattr(close_mod, k, v)
        self.dir.cleanup()

    def test_drained_once_the_forwarder_passes_the_marker(self) -> None:
        close_mod.ACK.write_text(f"{10**6}\n")
        self.assertTrue(close_mod.close(time.monotonic() + 2))
        target = int(close_mod.STATE.read_text())
        self.assertEqual(target, len(close_mod.LOG.read_bytes()))

    def test_a_stalled_forwarder_times_out(self) -> None:
        close_mod.ACK.write_text("5\n")
        self.assertFalse(close_mod.close(time.monotonic() + 0.3))

    def test_a_second_call_reuses_the_marker(self) -> None:
        close_mod.ACK.write_text("5\n")
        self.assertFalse(close_mod.close(time.monotonic() + 0.2))  # end-job: timed out
        close_mod.ACK.write_text(f"{10**6}\n")
        self.assertTrue(close_mod.close(time.monotonic() + 2))  # ExecStop: same marker
        self.assertEqual(self.emitted, 1)
        self.assertEqual(close_mod.LOG.read_bytes().count(b"tos-ci-audit-end"), 1)


def archive(*serials_and_types: tuple[int, str], end_nonce: str = NONCE, lost: int = 0, extra: str = "") -> bytes:
    lines = []
    for serial, kind in serials_and_types:
        if kind == "hook":
            lines.append(f'type=EXECVE msg=audit(1.0:{serial}): argc=2 a0="python3" a1="/usr/lib/tos-ci-guest/admission.py"')
        elif kind == "status":
            lines.append(f"type=USER msg=audit(1.0:{serial}): msg='tos-ci-audit-status lost={lost} backlog=0 exe=x'")
        elif kind == "end":
            lines.append(f"type=USER msg=audit(1.0:{serial}): msg='tos-ci-audit-end nonce={end_nonce} exe=x'")
        else:
            lines.append(f"type={kind} msg=audit(1.0:{serial}): x")
    return ("\n".join(lines) + "\n" + extra).encode()


GOOD = [(1, "DAEMON_START"), (2, "SYSCALL"), (2, "hook"), (3, "SYSCALL"), (4, "status"), (5, "end")]


class EvidenceTest(unittest.TestCase):
    def problems(self, data: bytes) -> list[str]:
        return check_mod.evidence(data, NONCE)[0]

    def test_a_complete_stream_is_valid(self) -> None:
        self.assertEqual(self.problems(archive(*GOOD)), [])

    def test_enriched_records_are_one_line_each(self) -> None:
        # auditd's default enriched format appends fields after a \x1d.
        enriched = archive(*GOOD).replace(b": x\n", b': x\x1dAUID="unset" UID="root"\n')
        self.assertIn(b"\x1d", enriched)
        self.assertEqual(self.problems(enriched), [])

    def test_daemon_records_carry_their_own_serials(self) -> None:
        # As observed: DAEMON_START numbered 869 ahead of kernel serials 258..
        shifted = [(869, "DAEMON_START")] + [(s + 257, k) for s, k in GOOD if k != "DAEMON_START"]
        self.assertEqual(self.problems(archive(*shifted)), [])
        # ...and cannot fill a gap in the kernel's sequence.
        gapped = [(260, "DAEMON_ABORT") if s == 260 else (s, k) for s, k in shifted]
        self.assertIn("1 audit serials missing between 259 and 262", self.problems(archive(*gapped)))

    def test_a_suffix_after_the_marker_is_not_evidence(self) -> None:
        self.assertEqual(self.problems(archive(*GOOD, (9, "SYSCALL"))), [])
        self.assertEqual(self.problems(archive(*GOOD, extra="garbage tail")), [])

    def test_truncated_before_the_marker_is_invalid(self) -> None:
        full = archive(*GOOD)
        cut = full[: full.index(b"tos-ci-audit-end") - 20]
        self.assertIn("0 end markers in the archive", self.problems(cut))

    def test_a_dropped_record_is_invalid(self) -> None:
        dropped = [r for r in GOOD if r[0] != 3]
        self.assertIn("1 audit serials missing between 2 and 5", self.problems(archive(*dropped)))

    def test_another_nonce_is_invalid(self) -> None:
        self.assertIn("the end marker carries another nonce", self.problems(archive(*GOOD, end_nonce="f" * 32)))

    def test_two_markers_are_invalid(self) -> None:
        self.assertIn("2 end markers in the archive", self.problems(archive(*GOOD, (6, "end"))))

    def test_lost_records_are_invalid(self) -> None:
        self.assertIn("no single status marker reporting lost=0", self.problems(archive(*GOOD, lost=3)))

    def test_without_the_hook_it_is_invalid(self) -> None:
        no_hook = [r for r in GOOD if r[1] != "hook"]
        self.assertIn("the hook's execution is not in the audit stream", self.problems(archive(*no_hook)))

    def test_console_rules(self) -> None:
        good = "audit on nonce=x\naudit drained\nend-of-life x"
        self.assertEqual(check_mod.console_problems(good), [])
        self.assertTrue(check_mod.console_problems(good.replace("audit drained", "audit drain timeout")))
        # A VM killed hard closes nothing and reports nothing.
        self.assertEqual(check_mod.console_problems(good.replace("audit drained\n", "")),
                         ["console never reports 'audit drained'"])
        self.assertTrue(check_mod.console_problems(good + "\naudit-forward failed: OSError"))
        self.assertTrue(check_mod.console_problems(good.replace("end-of-life x", "")))


if __name__ == "__main__":
    unittest.main()
