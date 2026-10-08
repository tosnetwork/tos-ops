"""Host-side admission: request schema, decision and allowlist parsing."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
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
    "slot": 2,
    "vm_nonce": NONCE,
    "run_id": "123456",
    "run_attempt": "1",
    "job": "network-safety",
    "event": "pull_request",
    "repository": "tosnetwork/tos",
    "author": "gtosnetwork-dotcom",
    "triggering_actor": "gtosnetwork-dotcom",
    "sender": "gtosnetwork-dotcom",
    "allowlist_sha256": ALLOW.sha256,
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

    def test_revoked_login_is_refused_under_the_new_list(self) -> None:
        data = b"0xlewis\ntosmaker\n"
        new = supervisor.Allowlist(data, hashlib.sha256(data).hexdigest(), supervisor.parse_allowlist(data))
        with self.assertRaises(supervisor.Denied):
            decide({**REQUEST, "allowlist_sha256": new.sha256}, allowlist=new)


class AdmitTest(unittest.TestCase):
    """The request handler itself, not only the decision: it must reply."""

    def setUp(self) -> None:
        import tempfile

        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        (root / "trusted-logins").write_bytes(DATA)
        (root / "token").write_text("unused")
        config = {
            "repository": "tosnetwork/tos", "label": "tos-vm", "labels": ["tos-vm"],
            "token": str(root / "token"), "allowlist": str(root / "trusted-logins"),
            "drain_file": str(root / "drain"), "slotctl_socket": str(root / "none.sock"),
            "store": str(root), "hard_cap_minutes": 165,
        }
        self.sup = supervisor.Supervisor(config)
        self.slot = self.sup.slots[2]
        self.slot.state, self.slot.nonce = "running", NONCE
        self.sup._stop = lambda slot, reason: setattr(slot, "stop_reason", reason)

    def tearDown(self) -> None:
        self.dir.cleanup()

    def test_allowed_request_gets_a_matching_reply_and_binds_the_slot(self) -> None:
        reply = self.sup._admit(self.slot, frame(REQUEST))
        self.assertEqual(reply["verdict"], "allowed")
        for key in ("vm_nonce", "run_id", "run_attempt", "job"):
            self.assertEqual(reply[key], REQUEST[key])
        self.assertEqual(self.slot.binding, ("123456", "1", "network-safety"))

    def test_second_request_is_denied(self) -> None:
        self.sup._admit(self.slot, frame(REQUEST))
        self.assertEqual(self.sup._admit(self.slot, frame(REQUEST))["verdict"], "denied")

    def test_allowlist_change_denies_and_stops_unadmitted_slots(self) -> None:
        other = self.sup.slots[3]
        other.state, other.nonce = "running", "e" * 32
        (Path(self.dir.name) / "trusted-logins").write_bytes(b"0xlewis\n")
        reply = self.sup._admit(self.slot, frame(REQUEST))
        self.assertEqual(reply["verdict"], "denied")
        self.assertIsNone(self.slot.binding)
        self.assertEqual(other.stop_reason, "allowlist changed before admission")

    def test_admitted_slot_survives_an_allowlist_change(self) -> None:
        self.sup._admit(self.slot, frame(REQUEST))
        (Path(self.dir.name) / "trusted-logins").write_bytes(b"0xlewis\n")
        with self.sup.lock:
            self.sup._refresh_allowlist_locked()
        self.assertIsNone(self.slot.stop_reason)


class AllowlistTest(unittest.TestCase):
    def test_comments_and_case(self) -> None:
        self.assertEqual(supervisor.parse_allowlist(b"# x\nToSMaker\n\n"), frozenset({"tosmaker"}))

    def test_empty_and_malformed_are_errors(self) -> None:
        for data in (b"", b"# only a comment\n", b"bad login\n", b"-leading\n"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                supervisor.parse_allowlist(data)


class SeedTest(unittest.TestCase):
    def test_cloud_config_starts_the_job_and_writes_files(self) -> None:
        text = supervisor.cloud_config({"/etc/tos-ci/slot": ("2\n", "root:root", "0644")})
        self.assertTrue(text.startswith("#cloud-config\n"))
        self.assertIn("path: /etc/tos-ci/slot", text)
        self.assertIn("/usr/lib/tos-ci-guest/start-job", text)


if __name__ == "__main__":
    unittest.main()
