"""Missing RPC data is not an invalid certificate; verifier retries stay bounded."""

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
import test_con01_rejudge as judge_fixture
from con01_history import observer
from con01_history.certificate import Refused, SignatureVerifier

DATA = Path(__file__).with_name("data") / "con01-history"


class Availability(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((DATA / "unavailable-signatures.json").read_bytes())
        self.stage = object.__new__(observer.StageA)
        self.stage.init = {}
        self.stage.st = {}
        self.stage.keys = {}

    def test_known_missing_certificate_remains_unaccepted_and_explicit(self):
        result = self.stage.verify_block(self.record)
        self.assertFalse(result["ok"])
        self.assertTrue(result.get("unsupported"), result)
        self.assertEqual(result.get("availability"), "BLOCK_UNAVAILABLE")
        self.assertIn("rid", result)

    def test_unknown_rpc_errors_are_not_reclassified(self):
        value = json.loads(self.record["sigs"])
        value["error"]["data"]["reason"] = "BAD_SIGNATURE"
        self.record["sigs"] = json.dumps(value)
        result = self.stage.verify_block(self.record)
        self.assertFalse(result["ok"])
        self.assertFalse(result.get("unsupported"), result)
        self.assertIn("signature set error", result["reason"])

    def test_result_plus_error_cannot_hide_a_malformed_certificate(self):
        value = json.loads(self.record["sigs"])
        value["result"] = {}
        self.record["sigs"] = json.dumps(value)
        result = self.stage.verify_block(self.record)
        self.assertFalse(result["ok"])
        self.assertFalse(result.get("unsupported"), result)

    def test_incomplete_unavailability_envelope_is_not_reclassified(self):
        original = json.loads(self.record["sigs"])
        for field in ("code", "data"):
            value = copy.deepcopy(original)
            del value["error"][field]
            self.record["sigs"] = json.dumps(value)
            self.assertFalse(self.stage.verify_block(self.record).get("unsupported"))
        value = copy.deepcopy(original)
        value["error"]["data"]["schema_version"] = True
        self.record["sigs"] = json.dumps(value)
        self.assertFalse(self.stage.verify_block(self.record).get("unsupported"))

    def test_unavailable_certificate_does_not_satisfy_boundary(self):
        records, config, bounds = judge_fixture.fixture()
        for record in records:
            if record.get("src") == "node1" and record.get("t") == "blk" and record["seq"] == 4:
                record.update(ok=False, unsupported=True, availability="BLOCK_UNAVAILABLE")
        result = observer.judge(records, config, bounds)
        self.assertNotEqual(result["verdict"], "PASS")


class BoundedTimeout(unittest.TestCase):
    def setUp(self):
        self.verifier = object.__new__(SignatureVerifier)
        self.verifier.fd = 7
        self.args = (bytes(1312), bytes(2420), b"public message")

    def test_timeout_then_success_reverifies_exact_bytes(self):
        with patch(
            "con01_history.certificate.subprocess.run",
            side_effect=[
                subprocess.TimeoutExpired("verifier", 5),
                subprocess.CompletedProcess([], 0),
            ],
        ) as run:
            try:
                self.verifier(*self.args)
            except Refused as error:
                self.fail("timeout was not retried: " + str(error))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0], run.call_args_list[1])

    def test_timeout_exhaustion_is_refused_after_three_attempts(self):
        with patch(
            "con01_history.certificate.subprocess.run",
            side_effect=subprocess.TimeoutExpired("verifier", 5),
        ) as run:
            with self.assertRaisesRegex(Refused, "timeout"):
                self.verifier(*self.args)
        self.assertEqual(run.call_count, 3)

    def test_cryptographic_rejection_is_never_retried(self):
        with patch(
            "con01_history.certificate.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1),
        ) as run:
            with self.assertRaisesRegex(Refused, "verification rejected"):
                self.verifier(*self.args)
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
