"""The guest admission predicate: the two trusted shapes pass, everything else is denied."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("admission", HERE.parent / "guest" / "admission.py")
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)

LOGINS = frozenset({"0xlewis", "gtosnetwork-dotcom", "tosmaker"})
PR_ENV = {
    "GITHUB_EVENT_NAME": "pull_request",
    "GITHUB_REPOSITORY": "tosnetwork/tos",
    "GITHUB_REF": "refs/pull/160/merge",
    "GITHUB_TRIGGERING_ACTOR": "gtosnetwork-dotcom",
}
PR_PAYLOAD = {
    "sender": {"login": "gtosnetwork-dotcom"},
    "pull_request": {
        "user": {"login": "gtosnetwork-dotcom"},
        "base": {"repo": {"full_name": "tosnetwork/tos"}},
        "head": {"repo": {"full_name": "tosnetwork/tos"}},
    },
}
PUSH_ENV = {
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_REPOSITORY": "tosnetwork/tos",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_TRIGGERING_ACTOR": "tosmaker",
}
PUSH_PAYLOAD = {"sender": {"login": "tosmaker"}}


def denied(env: dict, payload: dict) -> bool:
    try:
        admission.evaluate(env, payload, LOGINS)
    except admission.Denied:
        return True
    return False


class AdmissionPredicateTest(unittest.TestCase):
    def test_member_pull_request_is_admitted(self) -> None:
        got = admission.evaluate(PR_ENV, PR_PAYLOAD, LOGINS)
        self.assertEqual(got["author"], "gtosnetwork-dotcom")
        self.assertEqual(got["event"], "pull_request")

    def test_member_push_to_main_is_admitted(self) -> None:
        got = admission.evaluate(PUSH_ENV, PUSH_PAYLOAD, LOGINS)
        self.assertEqual(got["sender"], "tosmaker")

    def test_fork_head_is_denied(self) -> None:
        payload = copy.deepcopy(PR_PAYLOAD)
        payload["pull_request"]["head"]["repo"]["full_name"] = "attacker/tos"
        self.assertTrue(denied(PR_ENV, payload))

    def test_other_base_is_denied(self) -> None:
        payload = copy.deepcopy(PR_PAYLOAD)
        payload["pull_request"]["base"]["repo"]["full_name"] = "attacker/tos"
        self.assertTrue(denied(PR_ENV, payload))

    def test_untrusted_author_is_denied(self) -> None:
        payload = copy.deepcopy(PR_PAYLOAD)
        payload["pull_request"]["user"]["login"] = "outsider"
        self.assertTrue(denied(PR_ENV, payload))

    def test_untrusted_triggering_actor_is_denied(self) -> None:
        self.assertTrue(denied({**PR_ENV, "GITHUB_TRIGGERING_ACTOR": "outsider"}, PR_PAYLOAD))

    def test_missing_triggering_actor_is_denied(self) -> None:
        env = dict(PR_ENV)
        del env["GITHUB_TRIGGERING_ACTOR"]
        self.assertTrue(denied(env, PR_PAYLOAD))

    def test_untrusted_sender_is_denied(self) -> None:
        payload = copy.deepcopy(PR_PAYLOAD)
        payload["sender"]["login"] = "outsider"
        self.assertTrue(denied(PR_ENV, payload))

    def test_other_events_are_denied(self) -> None:
        for event in ("pull_request_target", "workflow_dispatch", "schedule", "workflow_run", ""):
            with self.subTest(event=event):
                self.assertTrue(denied({**PR_ENV, "GITHUB_EVENT_NAME": event}, PR_PAYLOAD))

    def test_push_to_another_ref_is_denied(self) -> None:
        for ref in ("refs/heads/feature", "refs/tags/v1", "refs/heads/main2", ""):
            with self.subTest(ref=ref):
                self.assertTrue(denied({**PUSH_ENV, "GITHUB_REF": ref}, PUSH_PAYLOAD))

    def test_other_repository_is_denied(self) -> None:
        self.assertTrue(denied({**PUSH_ENV, "GITHUB_REPOSITORY": "tosnetwork/other"}, PUSH_PAYLOAD))
        self.assertTrue(denied({**PR_ENV, "GITHUB_REPOSITORY": "attacker/tos"}, PR_PAYLOAD))

    def test_malformed_payloads_are_denied(self) -> None:
        for payload in ({}, {"sender": {}}, {"sender": {"login": ""}}, {"sender": "x"},
                        {"sender": {"login": "tosmaker"}, "pull_request": {}}):
            with self.subTest(payload=payload):
                self.assertTrue(denied(PR_ENV, payload))

    def test_empty_allowlist_is_denied(self) -> None:
        with self.assertRaises(admission.Denied):
            admission.read_allowlist(b"# nobody\n\n")


class AcknowledgementTest(unittest.TestCase):
    REQUEST = {"vm_nonce": "a" * 32, "run_id": "1", "run_attempt": "1", "job": "build"}

    def test_matching_allowed_ack_passes(self) -> None:
        admission.check_ack(self.REQUEST, {"verdict": "allowed", **self.REQUEST})

    def test_denial_and_mismatches_fail(self) -> None:
        bad = [
            {"verdict": "denied", "reason": "x"},
            {"verdict": "allowed", **{**self.REQUEST, "vm_nonce": "b" * 32}},
            {"verdict": "allowed", **{**self.REQUEST, "run_attempt": "2"}},
            {"verdict": "allowed", **{**self.REQUEST, "job": "other"}},
            {"verdict": "allowed", **{**self.REQUEST, "run_id": "2"}},
            {"verdict": "allowed"},
            {},
        ]
        for answer in bad:
            with self.subTest(answer=answer), self.assertRaises(admission.Denied):
                admission.check_ack(self.REQUEST, answer)


if __name__ == "__main__":
    unittest.main()
