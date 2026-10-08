"""Host-side admission and the slot state machine, with operations stubbed."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("supervisor", HERE.parent / "host" / "lib" / "supervisor.py")
supervisor = importlib.util.module_from_spec(SPEC)
sys.modules["supervisor"] = supervisor  # dataclasses resolve their module by name
SPEC.loader.exec_module(supervisor)

DATA = b"0xlewis\ngtosnetwork-dotcom\ntosmaker\n"
ALLOW = supervisor.Allowlist(DATA, hashlib.sha256(DATA).hexdigest(), supervisor.parse_allowlist(DATA))
NONCE = "0123456789abcdef0123456789abcdef"
REQUEST = {
    "slot": 2, "vm_nonce": NONCE, "run_id": "123456", "run_attempt": "1", "job": "network-safety",
    "event": "pull_request", "repository": "tosnetwork/tos", "author": "gtosnetwork-dotcom",
    "triggering_actor": "gtosnetwork-dotcom", "sender": "gtosnetwork-dotcom", "allowlist_sha256": ALLOW.sha256,
}


def frame(obj: object) -> bytes:
    return (json.dumps(obj) + "\n").encode()


def decide(request: dict, **overrides: object) -> None:
    args = {"slot": 2, "nonce": NONCE, "admitted": False, "repository": "tosnetwork/tos", "allowlist": ALLOW}
    args.update(overrides)
    supervisor.decide(request, **args)


class RequestSchemaTest(unittest.TestCase):
    def test_valid_request_parses(self) -> None:
        self.assertEqual(supervisor.parse_request(frame(REQUEST)), REQUEST)

    def test_malformed_frames_are_denied(self) -> None:
        cases = {
            "oversized": frame({**REQUEST, "job": "x" * 5000}),
            "unterminated": json.dumps(REQUEST).encode(),
            "not json": b"hello\n",
            "not an object": frame([REQUEST]),
            "missing key": frame({k: v for k, v in REQUEST.items() if k != "sender"}),
            "extra key": frame({**REQUEST, "extra": 1}),
            "duplicate key": (json.dumps(REQUEST)[:-1] + ', "slot": 1}\n').encode(),
            "bool slot": frame({**REQUEST, "slot": True}),
            "slot 4": frame({**REQUEST, "slot": 4}),
            "short nonce": frame({**REQUEST, "vm_nonce": "abc"}),
            "event": frame({**REQUEST, "event": "workflow_dispatch"}),
            "login": frame({**REQUEST, "author": "bad login!"}),
            "hash": frame({**REQUEST, "allowlist_sha256": "z" * 64}),
            "run id": frame({**REQUEST, "run_id": "12a"}),
            "invalid utf-8": b"\xff\xfe\n",
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(supervisor.Denied):
                supervisor.parse_request(data)


class DecisionTest(unittest.TestCase):
    def test_current_member_request_is_allowed(self) -> None:
        decide(REQUEST)

    def test_each_refusal(self) -> None:
        cases = [
            ("another slot", REQUEST, {"slot": 1}),
            ("stale nonce", REQUEST, {"nonce": "f" * 32}),
            ("no current VM", REQUEST, {"nonce": None}),
            ("second admission", REQUEST, {"admitted": True}),
            ("repository", {**REQUEST, "repository": "attacker/tos"}, {}),
            ("old allowlist", {**REQUEST, "allowlist_sha256": "0" * 64}, {}),
            ("author", {**REQUEST, "author": "outsider"}, {}),
            ("triggering actor", {**REQUEST, "triggering_actor": "outsider"}, {}),
            ("sender", {**REQUEST, "sender": "outsider"}, {}),
        ]
        for name, request, overrides in cases:
            with self.subTest(name), self.assertRaises(supervisor.Denied):
                decide(request, **overrides)


class AllowlistTest(unittest.TestCase):
    def test_comments_and_case(self) -> None:
        self.assertEqual(supervisor.parse_allowlist(b"# x\nToSMaker\n\n"), frozenset({"tosmaker"}))

    def test_empty_and_malformed_are_errors(self) -> None:
        for data in (b"", b"# only a comment\n", b"bad login\n", b"-leading\n"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                supervisor.parse_allowlist(data)


# ------------------------------------------------------- real child handle


class HandleTest(unittest.TestCase):
    """The real child-process handle: stdin in, one JSON result out, kill."""

    def op_script(self, body: str) -> str:
        self.dir = tempfile.TemporaryDirectory()
        path = Path(self.dir.name) / "op.py"
        path.write_text("import json, sys, time\n" + body)
        return str(path)

    def tearDown(self) -> None:
        self.dir.cleanup()

    def wait(self, handle):
        import time as _time
        for _ in range(200):
            result = handle.poll()
            if result is not None:
                return result
            _time.sleep(0.02)
        self.fail("op did not finish")

    def test_result_and_stdin(self) -> None:
        op = self.op_script('print(json.dumps({"got": sys.stdin.read(), "argv": sys.argv[1:]}))\n')
        handle = supervisor.Handle(["jit", "1"], b"secret", op=op)
        ok, result = self.wait(handle)
        self.assertTrue(ok)
        self.assertEqual(result, {"got": "secret", "argv": ["jit", "1"]})

    def test_failure_reports_the_last_stderr_line(self) -> None:
        op = self.op_script('sys.stderr.write("first\\nboom\\n"); sys.exit(3)\n')
        ok, result = self.wait(supervisor.Handle(["x"], None, op=op))
        self.assertFalse(ok)
        self.assertEqual(result, "boom")

    def test_kill_ends_a_hung_child(self) -> None:
        op = self.op_script("time.sleep(600)\n")
        handle = supervisor.Handle(["x"], None, op=op)
        self.assertIsNone(handle.poll())
        handle.kill()
        self.assertIsNotNone(handle.proc.poll())


# ------------------------------------------------------------ state machine


class StubHandle:
    """An operation child that completes only when the test says so, or never."""

    def __init__(self, argv, stdin) -> None:
        self.argv, self.stdin = argv, stdin
        self.result = None
        self.killed = False

    def poll(self):
        return None if self.killed else self.result

    def kill(self) -> None:
        self.killed = True


class Machine(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        (root / "trusted-logins").write_bytes(DATA)
        (root / "state").mkdir()
        (root / "maintenance.lock").write_text("")
        self.config = {
            "repository": "tosnetwork/tos", "allowlist": str(root / "trusted-logins"),
            "drain_file": str(root / "drain"), "store": str(root), "hard_cap_minutes": 165,
            "boot_deadline_seconds": 180, "idle_deadline_seconds": 1800, "unadmitted_busy_seconds": 60,
            "maintenance_lock": str(root / "maintenance.lock"),
        }
        self.t = 1000.0
        self.handles: list[StubHandle] = []

        def spawn(argv, stdin):
            handle = StubHandle(argv, stdin)
            self.handles.append(handle)
            return handle

        self.sup = supervisor.Supervisor(self.config, spawn=spawn, clock=lambda: self.t)
        self.sup._open_listener = lambda slot: None
        self.sup._disk_ok = lambda: True

    def tearDown(self) -> None:
        self.dir.cleanup()

    def op(self, n: int) -> StubHandle:
        return self.sup.slots[n].op.handle

    def answer(self, n: int, result: dict, ok: bool = True) -> None:
        self.op(n).result = (ok, result)
        self.sup.tick()

    def to_idle(self, n: int, latest: int = 0) -> None:
        """Drive slot n from init to idle: status, down, status inactive."""
        if self.sup.slots[n].op is None:
            self.sup.tick()
        self.answer(n, {"active": "inactive", "pid": 0, "latest": latest, "desired": "down"})
        self.answer(n, {"reply": "ok"})
        self.answer(n, {"active": "inactive", "pid": 0, "latest": latest, "desired": "down"})

    def to_running(self, n: int) -> None:
        self.to_idle(n)
        slot = self.sup.slots[n]
        if slot.state == "idle":
            self.sup.tick()
        self.answer(n, {"deleted": []})  # reconcile sweep
        self.answer(n, {"runner_id": 100 + n, "name": f"tos-ci-s{n}-x", "encoded_jit_config": "secret"})
        self.answer(n, {"ok": True})  # seed
        self.answer(n, {"reply": "ok"})  # up
        self.assertEqual(self.sup.slots[n].state, "running")


class StateMachineTest(Machine):
    def test_startup_continues_from_the_helpers_latest_generation(self) -> None:
        self.to_idle(1, latest=57)
        self.assertEqual(self.sup.slots[1].generation, 57)
        self.sup.tick()
        self.assertEqual(self.sup.slots[1].generation, 58)
        self.assertEqual(self.sup.slots[1].state, "launching")

    def test_launch_reaches_running_and_seeds_secrets_through_stdin(self) -> None:
        self.to_running(1)
        seed_calls = [h for h in self.handles if h.argv[:1] == ["seed"]]
        self.assertEqual(len(seed_calls), 1)
        self.assertIn(b"secret", seed_calls[0].stdin)
        self.assertNotIn("secret", " ".join(seed_calls[0].argv))

    def test_blocked_api_does_not_suspend_the_boot_deadline(self) -> None:
        self.to_running(1)
        self.t += 30
        self.sup.tick()  # status op
        self.answer(1, {"active": "active", "pid": 4242, "latest": 1, "desired": "up"})
        self.t += 10
        self.sup.tick()  # runner-status op, which never returns
        blocked = self.op(1)
        self.assertEqual(blocked.argv[0], "runner-status")
        self.t += 200
        self.sup.tick()
        slot = self.sup.slots[1]
        self.assertEqual(slot.state, "stopping")
        self.assertEqual(slot.stop_reason, "no registration within the boot deadline")
        self.assertTrue(blocked.killed)
        self.assertEqual(self.op(1).argv[:2], ["slot", "down"])

    def test_idle_deadline_without_the_api(self) -> None:
        self.to_running(1)
        slot = self.sup.slots[1]
        slot.online_at = self.t  # registered, then the API goes silent
        self.t += 1801
        self.sup.tick()
        self.assertEqual(self.sup.slots[1].stop_reason, "never admitted a job")

    def test_a_hung_op_is_killed_at_its_deadline(self) -> None:
        self.to_running(1)
        self.t += 30
        self.sup.tick()
        hung = self.op(1)
        self.t += 16
        self.sup.tick()
        self.assertTrue(hung.killed)

    def test_a_stop_supersedes_a_hanging_launch_step(self) -> None:
        self.to_idle(1)
        self.sup.tick()
        self.answer(1, {"deleted": []})
        hanging = self.op(1)  # the JIT request never returns
        self.assertEqual(hanging.argv[0], "jit")
        Path(self.config["drain_file"]).write_text("")
        self.sup.tick()
        self.assertTrue(hanging.killed)
        self.assertEqual(self.sup.slots[1].state, "stopping")
        self.assertEqual(self.op(1).argv[:2], ["slot", "down"])

    def test_a_late_launch_result_cannot_undo_stopping(self) -> None:
        self.to_idle(1)
        self.sup.tick()
        self.answer(1, {"deleted": []})
        self.answer(1, {"runner_id": 101, "name": "tos-ci-s1-x", "encoded_jit_config": "secret"})
        self.answer(1, {"ok": True})
        up = self.op(1)
        self.assertEqual(up.argv[:2], ["slot", "up"])
        Path(self.config["drain_file"]).write_text("")
        self.sup.tick()
        up.result = (True, {"reply": "ok"})  # arrives late
        self.sup.tick()
        self.assertEqual(self.sup.slots[1].state, "stopping")
        self.assertEqual(self.op(1).argv[:2], ["slot", "down"])

    def test_unconfirmed_cleanup_keeps_the_slot_unavailable(self) -> None:
        state = Path(self.config["store"]) / "state"
        (state / "cleanup-1").write_text("0\n")
        self.to_running(1)
        (state / "start-1").write_text("1\n")  # generation 1 started; 0 is the last cleaned
        Path(self.config["drain_file"]).write_text("")
        self.sup.tick()
        self.answer(1, {"reply": "ok"})  # down
        self.t += 3
        self.sup.tick()
        self.answer(1, {"active": "failed", "pid": 0, "latest": 1, "desired": "down"})
        self.assertEqual(self.op(1).argv[:2], ["slot", "cleanup"])
        self.answer(1, {"reply": "error 1"})
        self.assertEqual(self.sup.slots[1].state, "stopping")
        self.t += 40
        self.sup.tick()
        self.assertEqual(self.op(1).argv[:2], ["slot", "cleanup"])
        (state / "cleanup-1").write_text("1\n")  # the real cleanup now completed generation 1
        self.answer(1, {"reply": "ok"})
        self.assertEqual(self.sup.slots[1].state, "idle")

    def test_markers_compare_generations_not_timestamps(self) -> None:
        state = Path(self.config["store"]) / "state"
        slot = self.sup.slots[1]
        (state / "start-1").write_text("7\n")
        (state / "cleanup-1").write_text("7\n")
        self.assertTrue(self.sup._cleanup_confirmed(slot))
        (state / "cleanup-1").write_text("6\n")  # written later, but for an older generation
        self.assertFalse(self.sup._cleanup_confirmed(slot))

    def test_a_malformed_result_fails_the_op_and_does_not_crash(self) -> None:
        self.sup.tick()
        self.answer(1, {"reply": '{"not": "a status"}'})  # what op.py once returned
        self.assertEqual(self.sup.slots[1].state, "init")
        self.sup.tick()
        self.assertEqual(self.op(1).argv[:2], ["slot", "status"])  # retried
        self.to_running(2)
        self.answer(2, {"runner_id": "x"}) if self.sup.slots[2].op else None
        slot = self.sup.slots[3]
        self.to_idle(3)
        self.sup.tick()
        self.answer(3, {"deleted": []})
        self.answer(3, {"unexpected": True})  # a JIT result without its fields
        self.assertEqual(self.sup.slots[3].state, "stopping")
        self.assertTrue(self.sup.slots[3].launch_failed)

    def test_another_slot_proceeds_while_one_hangs(self) -> None:
        self.to_running(1)
        self.t += 30
        self.sup.tick()  # slot 1 status op hangs
        self.to_running(2)
        self.sup.slots[2].nonce = NONCE
        reply = self.sup._admit(2, self.sup.slots[2].generation, frame(REQUEST))
        self.assertEqual(reply["verdict"], "allowed")


class AdmitTest(Machine):
    def setUp(self) -> None:
        super().setUp()
        self.to_running(2)
        self.slot = self.sup.slots[2]
        self.slot.nonce = NONCE
        self.gen = self.slot.generation

    def test_allowed_request_gets_a_matching_reply_and_binds_the_slot(self) -> None:
        reply = self.sup._admit(2, self.gen, frame(REQUEST))
        self.assertEqual(reply["verdict"], "allowed")
        for key in ("vm_nonce", "run_id", "run_attempt", "job"):
            self.assertEqual(reply[key], REQUEST[key])
        self.assertEqual(self.slot.binding, ("123456", "1", "network-safety"))

    def test_second_request_is_denied(self) -> None:
        self.sup._admit(2, self.gen, frame(REQUEST))
        self.assertEqual(self.sup._admit(2, self.gen, frame(REQUEST))["verdict"], "denied")

    def test_stale_generation_is_denied(self) -> None:
        self.assertEqual(self.sup._admit(2, self.gen - 1, frame(REQUEST))["verdict"], "denied")

    def test_stopping_slot_is_denied(self) -> None:
        Path(self.config["drain_file"]).write_text("")
        self.sup.tick()
        self.assertEqual(self.sup._admit(2, self.gen, frame(REQUEST))["verdict"], "denied")
        self.assertIsNone(self.sup.slots[2].binding)

    def test_drain_after_admission_keeps_the_admitted_job(self) -> None:
        self.sup._admit(2, self.gen, frame(REQUEST))
        Path(self.config["drain_file"]).write_text("")
        self.sup.tick()
        self.assertEqual(self.sup.slots[2].state, "running")

    def test_allowlist_change_denies_and_stops_unadmitted_slots(self) -> None:
        (Path(self.config["allowlist"])).write_bytes(b"0xlewis\n")
        reply = self.sup._admit(2, self.gen, frame(REQUEST))
        self.assertEqual(reply["verdict"], "denied")
        self.assertIsNone(self.slot.binding)
        self.assertEqual(self.sup.slots[2].state, "stopping")

    def test_admitted_slot_survives_an_allowlist_change(self) -> None:
        self.sup._admit(2, self.gen, frame(REQUEST))
        (Path(self.config["allowlist"])).write_bytes(b"0xlewis\n")
        self.sup.tick()
        self.assertEqual(self.sup.slots[2].state, "running")


if __name__ == "__main__":
    unittest.main()
