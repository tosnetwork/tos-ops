"""Actual public certificate regressions; no chain writes or node checker imports."""

import copy
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "production"))
from con01_history import formats as f  # noqa: E402
from con01_history.audit import verify_files  # noqa: E402
from con01_history.certificate import (  # noqa: E402
    Refused,
    SignatureVerifier,
    governing_key,
    verify_link,
    verify_packet,
)

DATA = Path(__file__).with_name("data") / "con01-history"


class Certificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        program = os.environ.get("CON01_SIGNATURE_VERIFIER")
        digest = os.environ.get("CON01_SIGNATURE_VERIFIER_SHA256")
        if not program or not digest:
            raise RuntimeError("compiled signature verifier and exact SHA required; not a skip")
        cls.checker = SignatureVerifier(Path(program), digest)
        cls.anchor = json.loads((DATA / "anchor.json").read_bytes())
        cls.raw = (DATA / "expired-current-set.tl").read_bytes()
        _, _, links = f.forward_proof(cls.raw)
        cls.link = links[0]

    @classmethod
    def tearDownClass(cls):
        cls.checker.close()
        f.Cell.hd.cache_clear()

    def tearDown(self):
        f.Cell.hd.cache_clear()

    def test_real_expired_schedule_certificate_has_valid_finality(self):
        result = verify_packet(self.raw, self.anchor, self.checker)
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["links"]), 1)
        row = result["links"][0]
        self.assertEqual(row["id"]["seqno"], 264347)
        self.assertEqual(row["term_schedule"], "after_until")
        self.assertEqual(row["header"]["gen_utime"] - row["validator_until"], 1)
        self.assertEqual(row["signers"], 3)
        self.assertGreater(3 * row["signed_weight"], 2 * row["total_weight"])

    def test_corrupted_real_signature_is_rejected(self):
        link = copy.deepcopy(self.link)
        sig = link["cert"]["signatures"][0]
        raw = bytearray(f.D(sig["signature"]))
        raw[100] ^= 1
        sig["signature"] = f.B(raw)
        with self.assertRaisesRegex(Refused, "ML-DSA-44 verification rejected"):
            verify_link(link, self.checker)

    def test_quorum_is_not_inferred_from_validator_membership(self):
        link = copy.deepcopy(self.link)
        link["cert"]["signatures"] = link["cert"]["signatures"][:1]
        with self.assertRaisesRegex(Refused, "insufficient quorum"):
            verify_link(link, self.checker)

    def test_duplicate_signer_cannot_increase_weight(self):
        link = copy.deepcopy(self.link)
        link["cert"]["signatures"].append(copy.deepcopy(link["cert"]["signatures"][0]))
        with self.assertRaisesRegex(Refused, "duplicate signer"):
            verify_link(link, self.checker)

    def test_unknown_algorithm_is_not_accepted_as_mldsa(self):
        link = copy.deepcopy(self.link)
        link["cert"]["signatures"][0]["algorithm_id"] = 2
        with self.assertRaisesRegex(Refused, "unsupported signature algorithm"):
            verify_link(link, self.checker)

    def test_wrong_session_is_rejected_before_signature_backend(self):
        link = copy.deepcopy(self.link)
        link["cert"]["session_id"] = f.B(bytes(32))
        with self.assertRaisesRegex(Refused, "session identity mismatch"):
            verify_link(link, self.checker)

    def test_source_root_must_match_authenticated_config(self):
        link = copy.deepcopy(self.link)
        link["src"]["root_hash"] = f.B(bytes(32))
        with self.assertRaisesRegex(Refused, "source config root mismatch"):
            verify_link(link, self.checker)

    def test_trusted_full_anchor_includes_file_hash(self):
        anchor = dict(self.anchor, file_hash="00" * 32)
        with self.assertRaisesRegex(Refused, "trusted anchor"):
            verify_packet(self.raw, anchor, self.checker)

    def test_retired_key_is_not_selected_after_authenticated_rollover(self):
        old = self.link["src"]
        new = dict(old, seqno=539493, root_hash=f.B(bytes([1]) * 32))
        keys = {0: dict(old, seqno=0), old["seqno"]: old, new["seqno"]: new}
        self.assertEqual(governing_key(keys, 539493), old)
        self.assertEqual(governing_key(keys, 539494), new)
        with self.assertRaisesRegex(Refused, "wrong governing key"):
            verify_link(self.link, self.checker, expected_source=new)

    def test_real_partial_genesis_packet_is_not_a_complete_target_proof(self):
        raw = (DATA / "genesis-partial.tl").read_bytes()
        anchor = json.loads((DATA / "genesis.json").read_bytes())
        packet = verify_packet(raw, anchor, self.checker)
        self.assertFalse(packet["complete"])
        self.assertEqual(packet["end"]["seqno"], 176385)
        self.assertEqual(len(packet["links"]), 16)
        with self.assertRaisesRegex(AssertionError, "incomplete proof packet"):
            f.forward_proof(raw)
        with self.assertRaisesRegex(Refused, "incomplete"):
            verify_files([DATA / "genesis-partial.tl"], anchor, packet["end"], self.checker)

    def test_packet_byte_limit_precedes_decoder(self):
        with self.assertRaisesRegex(Refused, "byte bound"):
            verify_packet(b"X" * (2 * 1024 * 1024 + 1), self.anchor, self.checker)

    def test_oversized_cell_count_precedes_boc_allocation(self):
        value = (
            bytes.fromhex("b5ee9c72")
            + bytes([3, 1])
            + (65537).to_bytes(3, "big")
            + (1).to_bytes(3, "big")
            + bytes(3)
            + bytes(1)
        )
        with self.assertRaisesRegex(AssertionError, "cell/root bound"):
            f.boc(value)

    def test_optimized_python_refuses_assert_based_wire_decoder(self):
        code = "import sys;sys.path.insert(0,sys.argv[1]);import con01_history.formats"
        result = subprocess.run(
            [sys.executable, "-O", "-c", code, str(ROOT / "production")],
            capture_output=True,
            timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"requires checks enabled", result.stderr)

    def test_wrong_verifier_pin_fails_before_crypto(self):
        with self.assertRaisesRegex(Refused, "verifier pin"):
            SignatureVerifier(Path(os.environ["CON01_SIGNATURE_VERIFIER"]), "00" * 32)


if __name__ == "__main__":
    unittest.main()
