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
