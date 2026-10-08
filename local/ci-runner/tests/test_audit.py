"""Verification-mode audit transport: archive pruning and writing, the guest's
forwarder and closer, and the host's validity rules."""

from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import os
import re
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
    sys.modules[name] = module  # dataclasses resolve their module by name
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


# --------------------------------------------------- archive validity and execution
#
# Fixtures follow the records of a real denied lifetime (serials 371-394 of
# nonce 970c835e…): the same record formats, executables, argv shapes and
# parent relations, with every value that could identify a run replaced.

ENRICH = '\x1dUID="root" AUID="unset"'


def hexarg(text: str) -> str:
    return text.encode().hex().upper()


def ex(serial: int, pid: int, ppid: int, uid: int, exe: str, argv: list[str], *,
       arch: str = "c000003e", syscall: int = 59, success: str = "yes", cwd: str | None = None) -> list[str]:
    """SYSCALL + EXECVE records of one exec event, as auditd writes them."""
    lines = [f"type=SYSCALL msg=audit(1791485696.000:{serial}): arch={arch} syscall={syscall} success={success} exit=0 "
             f"a0=0 a1=0 a2=0 a3=0 items=2 ppid={ppid} pid={pid} auid=4294967295 uid={uid} gid={uid} euid={uid} "
             f'suid={uid} fsuid={uid} egid={uid} sgid={uid} fsgid={uid} tty=(none) ses=4294967295 comm="x" exe="{exe}" '
             f'subj=unconfined key="tos-ci-exec"{ENRICH}']
    if success == "yes":
        args = " ".join(f'a{i}="{a}"' if a and " " not in a and '"' not in a else f"a{i}={hexarg(a)}"
                        for i, a in enumerate(argv))
        lines.append(f"type=EXECVE msg=audit(1791485696.000:{serial}): argc={len(argv)} {args}")
    if cwd is not None:
        lines.append(f'type=CWD msg=audit(1791485696.000:{serial}): cwd="{cwd}"')
    lines.append(f"type=PROCTITLE msg=audit(1791485696.000:{serial}): proctitle={hexarg(' '.join(argv))}")
    return lines


def marker(serial: int, text: str, *, kind: str = "USER", result: str = "success") -> str:
    return (f"type={kind} msg=audit(1791485696.600:{serial}): pid=1701 uid=0 auid=4294967295 ses=4294967295 "
            f"subj=unconfined msg='text={text} exe=\"/usr/sbin/auditctl\" hostname=? addr=? terminal=? "
            f"res={result}'{ENRICH}")


HOOK = ["/usr/bin/bash", "-e", "/usr/lib/tos-ci-guest/admission-hook.sh"]
TIMEOUT = ["/usr/bin/timeout", "--kill-after=5", "30", "/usr/bin/python3", "-I", "/usr/lib/tos-ci-guest/admission.py"]
ADMISSION_PY = ["/usr/bin/python3", "-I", "/usr/lib/tos-ci-guest/admission.py"]
EXECUTOR = ["/usr/lib/systemd/systemd-executor", "--deserialize", "10", "--log-level", "info", "--log-target",
            "journal-or-kmsg"]


def lifetime(extra_after_hook: list[list[str]] = (), *, end_nonce: str = NONCE, lost: int = 0,
             status_line: str | None = None, end_line: str | None = None,
             before_hook: list[list[str]] = ()) -> list[str]:
    """Record lines of a denied lifetime, optionally with events before and after the hook."""
    lines = ["type=DAEMON_START msg=audit(1791485690.000:869): op=start ver=3.1.2 format=enriched res=success" + ENRICH]
    lines += ex(360, 1658, 1613, 1000, "/opt/actions-runner/bin/Runner.Worker",
                ["/opt/actions-runner/bin/Runner.Worker", "spawnclient", "149", "152"])
    serial = 361
    for event in before_hook:
        lines += [re.sub(r":\d+\)", f":{serial})", line) for line in event]
        serial += 1
    lines += [re.sub(r":\d+\)", f":{s})", l) for s, l in ((serial, x) for x in ex(0, 1674, 1658, 1000, "/usr/bin/bash", HOOK))]
    lines += [re.sub(r":\d+\)", f":{serial + 1})", l) for l in ex(0, 1674, 1658, 1000, "/usr/bin/timeout", TIMEOUT)]
    lines += [re.sub(r":\d+\)", f":{serial + 2})", l) for l in ex(0, 1676, 1674, 1000, "/usr/bin/python3.12", ADMISSION_PY)]
    serial += 3
    # Pad the kernel sequence the way unrelated records do, so the hook's
    # serials match the observed lifetime regardless of what came before.
    while serial < 375:
        lines.append(f"type=SERVICE_START msg=audit(1791485690.000:{serial}): pid=1 uid=0 msg='unit=x res=success'")
        serial += 1
    for event in extra_after_hook:
        lines += [re.sub(r":\d+\)", f":{serial})", line) for line in event]
        serial += 1
    lines += ex(serial, 1693, 1, 0, "/usr/lib/systemd/systemd-executor", EXECUTOR)
    lines += ex(serial + 1, 1693, 1, 0, "/usr/bin/bash", ["/bin/bash", "/usr/lib/tos-ci-guest/end-job"])
    lines += ex(serial + 2, 1695, 1694, 0, "/usr/bin/cat", ["cat", "/etc/tos-ci/audit"])
    lines += ex(serial + 3, 1696, 1693, 0, "/usr/bin/python3.12", ["/usr/bin/python3", "-I", "/usr/lib/tos-ci-guest/audit-close"])
    lines += ex(serial + 4, 1697, 1696, 0, "/usr/bin/python3.12", [], success="no")  # a PATH search miss
    lines += ex(serial + 5, 1697, 1696, 0, "/usr/sbin/auditctl", ["auditctl", "-s"])
    lines += ex(serial + 6, 1700, 1696, 0, "/usr/sbin/auditctl", ["auditctl", "-m", f"tos-ci-audit-status lost={lost} backlog=0"])
    lines.append(status_line or marker(serial + 7, f"tos-ci-audit-status lost={lost} backlog=0"))
    lines += ex(serial + 8, 1701, 1696, 0, "/usr/sbin/auditctl", ["auditctl", "-m", f"tos-ci-audit-end nonce={end_nonce}"])
    lines.append(end_line or marker(serial + 9, f"tos-ci-audit-end nonce={end_nonce}"))
    return lines


def data(lines: list[str], tail: str = "\n") -> bytes:
    return ("\n".join(lines) + tail).encode()


def at_serial(text: str, serial: int) -> str:
    return re.sub(r":\d+\)", f":{serial})", text, count=1)


class EvidenceTest(unittest.TestCase):
    def problems(self, raw: bytes) -> list[str]:
        return check_mod.evidence(raw, NONCE)[0]

    def test_the_observed_denied_lifetime_is_valid_and_clean(self) -> None:
        problems, kept = check_mod.evidence(data(lifetime()), NONCE)
        self.assertEqual(problems, [])
        self.assertEqual(check_mod.judge("denied", kept)[0], True)

    def test_enriched_records_are_one_line_each(self) -> None:
        self.assertIn(b"\x1d", data(lifetime()))
        self.assertEqual(self.problems(data(lifetime())), [])

    def test_daemon_records_carry_their_own_serials(self) -> None:
        # DAEMON_START is 869 while kernel serials start at 371; it cannot fill a gap either.
        lines = lifetime()
        gapped = [l for l in lines if ":373)" not in l]
        gapped.insert(1, "type=DAEMON_ABORT msg=audit(1.0:373): op=x res=success")
        self.assertIn("1 audit serials missing between 360 and 384", self.problems(data(gapped)))

    def test_a_suffix_after_the_marker_is_not_evidence(self) -> None:
        self.assertEqual(self.problems(data(lifetime() + ex(400, 1800, 1, 0, "/usr/bin/x", ["x"]))), [])
        self.assertEqual(self.problems(data(lifetime(), tail="\ngarbage tail")), [])

    def test_a_dropped_record_is_invalid(self) -> None:
        dropped = [l for l in lifetime() if ":374)" not in l]
        self.assertIn("1 audit serials missing between 360 and 384", self.problems(data(dropped)))

    def test_another_nonce_is_invalid(self) -> None:
        self.assertIn("the end marker carries another nonce", self.problems(data(lifetime(end_nonce="f" * 32))))

    def test_two_markers_are_invalid(self) -> None:
        lines = lifetime() + [marker(390, f"tos-ci-audit-end nonce={NONCE}")]
        self.assertIn("2 end markers in the archive", self.problems(data(lines)))

    def test_lost_records_are_invalid(self) -> None:
        self.assertIn("no single complete status marker reporting lost=0", self.problems(data(lifetime(lost=3))))

    def test_without_the_hook_it_is_invalid(self) -> None:
        no_hook = [l for l in lifetime() if not any(f":{s})" in l for s in (361, 362, 363))]
        # Renumber nothing: the gap is reported too, but the hook check must fire on its own.
        self.assertIn("the hook's execution is not in the audit stream", self.problems(data(no_hook)))

    # Item 1: the marker records must be complete and correctly typed.
    def test_marker_truncations(self) -> None:
        full = data(lifetime())
        at = full.index(f"nonce={NONCE}".encode()) + len(f"nonce={NONCE}")
        newline = full.index(b"\n", at)
        self.assertIn("a malformed or incomplete end marker", self.problems(full[:at]))
        self.assertIn("a malformed or incomplete end marker", self.problems(full[:newline]))
        self.assertEqual(self.problems(full[: newline + 1]), [])

    def test_mistyped_end_markers(self) -> None:
        for name, line in (("another record type", marker(389, f"tos-ci-audit-end nonce={NONCE}", kind="USER_CMD")),
                           ("a failed result", marker(389, f"tos-ci-audit-end nonce={NONCE}", result="failed"))):
            with self.subTest(name):
                problems = self.problems(data(lifetime(end_line=line)))
                self.assertTrue(problems)

    def test_status_marker_must_be_complete_and_typed(self) -> None:
        bad = marker(387, "tos-ci-audit-status lost=0 backlog=0", result="failed")
        self.assertIn("no single complete status marker reporting lost=0",
                      self.problems(data(lifetime(status_line=bad))))
        cut = marker(387, "tos-ci-audit-status lost=0 backlog=0").split("exe=")[0]
        self.assertIn("no single complete status marker reporting lost=0",
                      self.problems(data(lifetime(status_line=cut))))

    def test_console_rules(self) -> None:
        good = "audit on nonce=x\naudit drained\nend-of-life x"
        self.assertEqual(check_mod.console_problems(good), [])
        self.assertTrue(check_mod.console_problems(good.replace("audit drained", "audit drain timeout")))
        # A VM killed hard closes nothing and reports nothing.
        self.assertEqual(check_mod.console_problems(good.replace("audit drained\n", "")),
                         ["console never reports 'audit drained'"])
        self.assertTrue(check_mod.console_problems(good + "\naudit-forward failed: OSError"))
        self.assertTrue(check_mod.console_problems(good.replace("end-of-life x", "")))


class ExecutionTest(unittest.TestCase):
    """Item 3: only explicit rules explain an exec; everything else in a denied lifetime fails."""

    def denied(self, *events: list[str]) -> tuple[bool, str]:
        problems, kept = check_mod.evidence(data(lifetime(list(events))), NONCE)
        self.assertEqual(problems, [])
        return check_mod.judge("denied", kept)

    def assertFails(self, *events: list[str], naming: str) -> None:
        passed, detail = self.denied(*events)
        self.assertFalse(passed, detail)
        self.assertIn(naming, detail)

    def test_touch_under_the_worker(self) -> None:
        self.assertFails(ex(0, 1680, 1658, 1000, "/usr/bin/touch", ["touch", "/tmp/x"]), naming="/usr/bin/touch")

    def test_touch_from_a_custom_shell(self) -> None:
        self.assertFails(ex(0, 1680, 1658, 1000, "/usr/bin/bash", ["bash", "--noprofile", "--norc", "-e", "/tmp/s.sh"]),
                         ex(0, 1681, 1680, 1000, "/usr/bin/touch", ["/bin/touch", "/tmp/x"]), naming="/usr/bin/bash")

    def test_a_container_entrypoint(self) -> None:
        self.assertFails(ex(0, 1800, 1, 0, "/usr/bin/containerd-shim-runc-v2", ["containerd-shim-runc-v2", "-id", "x"]),
                         ex(0, 1801, 1800, 0, "/usr/sbin/runc", ["runc", "init"]),
                         ex(0, 1801, 1800, 0, "/bin/touch", ["touch", "/x"]), naming="containerd-shim")

    def test_a_job_created_service(self) -> None:
        self.assertFails(ex(0, 1810, 1, 0, "/usr/lib/systemd/systemd-executor", EXECUTOR),
                         ex(0, 1810, 1, 0, "/usr/bin/touch", ["/usr/bin/touch", "/x"]), naming="/usr/bin/touch")

    def test_a_32_bit_exec(self) -> None:
        self.assertFails(ex(0, 1680, 1658, 1000, "/usr/bin/touch", ["touch", "/x"], arch="40000003", syscall=11),
                         naming="/usr/bin/touch")

    def test_pid_reuse_confers_no_trust(self) -> None:
        # The hook's bash pid 1674 is later the parent of touch.
        self.assertFails(ex(0, 1690, 1674, 1000, "/usr/bin/touch", ["touch", "/x"]), naming="/usr/bin/touch")

    def test_a_reused_end_job_pid_with_another_argv(self) -> None:
        self.assertFails(ex(0, 1693, 1, 0, "/usr/lib/systemd/systemd-executor", EXECUTOR),
                         ex(0, 1693, 1, 0, "/usr/bin/bash", ["/bin/bash", "/usr/lib/tos-ci-guest/end-job"]),
                         ex(0, 1699, 1693, 0, "/usr/bin/cat", ["cat", "/etc/shadow"]), naming="/etc/shadow")

    AGETTY = ["/sbin/agetty", "-o", "-p -- \\u", "--noclear", "-", "linux"]

    def test_an_unknown_exec_syscall(self) -> None:
        # The exact allowlisted agetty, but through a syscall that is not an exec.
        self.assertTrue(self.denied(ex(0, 1225, 1, 0, "/usr/sbin/agetty", self.AGETTY))[0])
        self.assertFails(ex(0, 1225, 1, 0, "/usr/sbin/agetty", self.AGETTY, syscall=520), naming="agetty")

    def test_an_exact_command_under_the_wrong_parent(self) -> None:
        # auditctl -s is expected only from audit-close.
        self.assertFails(ex(0, 1720, 1, 0, "/usr/sbin/auditctl", ["auditctl", "-s"]), naming="auditctl")

    def test_a_worker_child_before_the_hook(self) -> None:
        # As observed: the runner unpacks a referenced action before the hook runs.
        tar = ex(0, 1670, 1658, 1000, "/usr/bin/tar", ["/usr/bin/tar", "-xzf", "/opt/actions-runner/_work/_actions/_temp_x/y.tar.gz"])
        problems, kept = check_mod.evidence(data(lifetime(before_hook=[tar])), NONCE)
        self.assertEqual(problems, [])
        passed, detail = check_mod.judge("denied", kept)
        self.assertFalse(passed)
        self.assertIn("/usr/bin/tar", detail)

    def test_a_reused_pid_with_another_parent_is_not_in_place(self) -> None:
        # pid 1693 was a systemd-executor child of PID 1; a new process reusing it
        # under another parent cannot inherit "exec in place of the executor".
        self.assertFails(ex(0, 1693, 1, 0, "/usr/lib/systemd/systemd-executor", EXECUTOR),
                         ex(0, 1693, 5555, 0, "/usr/bin/bash", ["/bin/bash", "/usr/lib/tos-ci-guest/end-job"]),
                         naming="end-job")

    def test_explained_boot_services_after_the_hook_pass(self) -> None:
        passed, detail = self.denied(
            ex(0, 980, 1, 0, "/usr/bin/dash", ["/bin/sh", "/usr/bin/savelog", "-m640", "-q", "-p", "-n", "-c", "5", "/var/log/dmesg"]),
            ex(0, 1638, 1637, 0, "/usr/bin/touch", ["touch", "--", "/var/log/dmesg.new"]),
            ex(0, 1637, 980, 0, "/usr/bin/chmod", ["chmod", "--reference=/var/log/dmesg", "--", "/var/log/dmesg.new"]),
            ex(0, 1225, 1, 0, "/usr/sbin/agetty", ["/sbin/agetty", "-o", "-p -- \\u", "--noclear", "-", "linux"]))
        self.assertTrue(passed, detail)

    def test_an_allowed_lifetime_needs_job_execution(self) -> None:
        problems, kept = check_mod.evidence(data(lifetime()), NONCE)
        self.assertEqual(check_mod.judge("allowed", kept)[0], False)
        problems, kept = check_mod.evidence(data(lifetime([ex(0, 1680, 1658, 1000, "/usr/bin/bash", ["bash", "-e", "/x"])])), NONCE)
        self.assertEqual(check_mod.judge("allowed", kept)[0], True)

    def test_split_arguments_are_joined(self) -> None:
        bodies = ['argc=2 a0="cat" a1_len=8 a1[0]=2F657463 a1[1]=2F6F7300']
        self.assertEqual(check_mod.execve_argv(bodies), ["cat", "/etc/os\x00"])
        self.assertIsNone(check_mod.execve_argv(['argc=3 a0="cat" a1="x"']))


T1 = "00ecb0fd-cee1-404b-9f8c-661eb0000001"
T2 = "54d5a02b-866b-4110-be8c-3c0547e00002"
STAGING = f"/opt/actions-runner/_work/_actions/_temp_{T1}/_staging"
TARBALL = f"/opt/actions-runner/_work/_actions/_temp_{T1}/{T2}.tar.gz"


def unpack(*, uid: int = 1000, ppid: int = 1658, argv: list[str] | None = None, cwd: str = STAGING) -> list[list[str]]:
    """As observed: Runner.Worker runs tar, whose decompressor child is gzip."""
    return [ex(0, 1677, ppid, uid, "/usr/bin/tar", argv or ["/usr/bin/tar", "-xzf", TARBALL], cwd=cwd),
            ex(0, 1679, 1677, uid, "/usr/bin/gzip", ["gzip", "-d"], cwd=cwd)]


class ActionUnpackTest(unittest.TestCase):
    """The runner's own pre-hook unpack: explained only on the verified runner, and only exactly."""

    def setUp(self) -> None:
        self.saved = check_mod.active_runner
        check_mod.active_runner = check_mod.VERIFIED_RUNNER

    def tearDown(self) -> None:
        check_mod.active_runner = self.saved

    def judge(self, events: list[list[str]]) -> tuple[bool, str]:
        problems, kept = check_mod.evidence(data(lifetime(before_hook=events)), NONCE)
        self.assertEqual(problems, [])
        return check_mod.judge("denied", kept)

    def test_the_observed_unpack_is_explained_and_counted(self) -> None:
        passed, detail = self.judge(unpack())
        self.assertTrue(passed, detail)
        self.assertIn("action unpacks before the hook: 1", detail)

    def test_another_runner_version_does_not_explain_it(self) -> None:
        check_mod.active_runner = "v2.339.0"
        passed, detail = self.judge(unpack())
        self.assertFalse(passed)
        self.assertIn("/usr/bin/tar", detail)

    def test_only_the_exact_unpack_is_explained(self) -> None:
        other_temp = f"/opt/actions-runner/_work/_actions/_temp_{T2}/{T2}.tar.gz"
        cases = {
            "another working directory": unpack(cwd="/opt/actions-runner/_work/_temp"),
            "a tarball from another staging area": unpack(argv=["/usr/bin/tar", "-xzf", other_temp]),
            "an extra argument": unpack(argv=["/usr/bin/tar", "-xzf", TARBALL, "-C", "/"]),
            "root instead of the runner account": unpack(uid=0),
            "no working directory record": [ex(0, 1677, 1658, 1000, "/usr/bin/tar", ["/usr/bin/tar", "-xzf", TARBALL])],
        }
        for name, events in cases.items():
            with self.subTest(name):
                passed, detail = self.judge(events)
                self.assertFalse(passed, detail)

    def test_gzip_must_work_where_its_tar_does(self) -> None:
        other = f"/opt/actions-runner/_work/_actions/_temp_{T2}/_staging"
        events = [ex(0, 1677, 1658, 1000, "/usr/bin/tar", ["/usr/bin/tar", "-xzf", TARBALL], cwd=STAGING),
                  ex(0, 1679, 1677, 1000, "/usr/bin/gzip", ["gzip", "-d"], cwd=other)]
        passed, detail = self.judge(events)
        self.assertFalse(passed, detail)
        self.assertIn("/usr/bin/gzip", detail)

    def test_an_unpack_outside_the_worker_is_not_one(self) -> None:
        # Under another parent the rule does not apply: after the hook it is
        # simply unexplained, and before it, outside the Worker, not counted.
        problems, kept = check_mod.evidence(data(lifetime(unpack(ppid=1613))), NONCE)
        self.assertEqual(problems, [])
        passed, detail = check_mod.judge("denied", kept)
        self.assertFalse(passed, detail)
        passed, detail = self.judge(unpack(ppid=1613))
        self.assertIn("action unpacks before the hook: 0", detail)


class ReportTest(unittest.TestCase):
    """Item 2: nothing is skipped silently, and expectations are enforced."""

    def run_main(self, consoles: dict, archives: dict, *argv: str) -> tuple[int, str]:
        import contextlib
        import io
        saved = check_mod.consoles, check_mod.archive_for
        check_mod.consoles = lambda since: consoles
        check_mod.archive_for = lambda slot, nonce: archives.get(nonce)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                sys.argv = ["audit-check", "--since", "x", *argv]
                code = check_mod.main()
        finally:
            check_mod.consoles, check_mod.archive_for = saved
        return code, out.getvalue()

    VERDICT = '{"run_id": "77", "tos_ci_admission": "denied"}'

    def good_console(self) -> list[str]:
        return [f"audit on nonce={NONCE}: x", self.VERDICT, "audit drained", f"end-of-life {NONCE}"]

    def test_a_valid_denied_lifetime_meets_its_expectation(self) -> None:
        code, out = self.run_main({(1, "a" * 8): self.good_console()}, {NONCE: data(lifetime())}, "--expect", "77=denied:1")
        self.assertEqual(code, 0, out)

    def test_audit_unavailable_without_a_verdict_is_invalid(self) -> None:
        consoles = {(1, "a" * 8): self.good_console(),
                    (2, "b" * 8): ["audit unavailable: kernel booted without audit=1"]}
        code, out = self.run_main(consoles, {NONCE: data(lifetime())})
        self.assertEqual(code, 1, out)
        self.assertIn("INVALID  slot2", out)

    def test_an_idle_lifetime_is_reported(self) -> None:
        code, out = self.run_main({(1, "a" * 8): self.good_console(), (3, "c" * 8): [f"audit on nonce={'e' * 32}: x"]},
                                  {NONCE: data(lifetime())})
        self.assertEqual(code, 0, out)
        self.assertIn("NO-JOB   slot3", out)

    def test_an_unmet_expectation_is_a_violation(self) -> None:
        code, out = self.run_main({(1, "a" * 8): self.good_console()}, {NONCE: data(lifetime())}, "--expect", "77=denied:2")
        self.assertEqual(code, 1, out)
        self.assertIn("EXPECT", out)

    def test_checking_nothing_fails(self) -> None:
        code, out = self.run_main({}, {})
        self.assertEqual(code, 1, out)

    def test_each_lifetime_is_judged_by_its_own_runner(self) -> None:
        # One window, two runner versions: only the verified one explains the unpack.
        archives, consoles = {}, {}
        for slot, (nonce, runner) in enumerate(((NONCE, "v2.338.0"), ("e" * 32, "v2.339.0"), ("d" * 32, None)), 1):
            # The third has no prepared record, so its runner is unknown.
            prepared = [f"slot {slot} generation 7 prepared on gen-20261008T184938Z.qcow2 (runner {runner})"] if runner else []
            consoles[(slot, f"{slot}" * 8)] = prepared + [f"audit on nonce={nonce}: x", self.VERDICT, "audit drained",
                                                          f"end-of-life {nonce}"]
            archives[nonce] = data(lifetime(end_nonce=nonce, before_hook=unpack()))
        code, out = self.run_main(consoles, archives)
        lines = {l.split()[1]: l for l in out.splitlines() if l.startswith(("PASS", "FAIL"))}
        self.assertTrue(lines["slot1"].startswith("PASS"), out)
        self.assertIn("runner v2.338.0", lines["slot1"])
        self.assertIn("action unpacks before the hook: 1", lines["slot1"])
        self.assertTrue(lines["slot2"].startswith("FAIL"), out)
        self.assertIn("runner v2.339.0", lines["slot2"])
        self.assertTrue(lines["slot3"].startswith("FAIL"), out)
        self.assertIn("runner unknown", lines["slot3"])

    def test_an_old_record_falls_back_to_its_image_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            images = Path(tmp)
            line = "slot 1 generation 7 prepared on gen-20261008T184938Z.qcow2"
            self.assertIsNone(check_mod.lifetime_runner(line, images))  # its image is gone
            (images / "gen-20261008T184938Z.qcow2.manifest").write_text("image x\nrunner v2.338.0 sha256 ab\n")
            self.assertEqual(check_mod.lifetime_runner(line, images), "v2.338.0")
            self.assertIsNone(check_mod.lifetime_runner(line + " (runner unknown)", images))
            self.assertIsNone(check_mod.lifetime_runner("no prepared line", images))

    def test_as_denied_rejudges_an_allowed_run(self) -> None:
        allowed = [f"audit on nonce={NONCE}: x", self.VERDICT.replace("denied", "allowed"), "audit drained", "end-of-life x"]
        archive_ = data(lifetime([ex(0, 1680, 1658, 1000, "/usr/bin/touch", ["touch", "/x"])]))
        code, out = self.run_main({(1, "a" * 8): allowed}, {NONCE: archive_}, "--as-denied", "77")
        self.assertEqual(code, 1, out)
        self.assertIn("/usr/bin/touch", out)


if __name__ == "__main__":
    unittest.main()
