"""Trusted pre-sign incident resumption; mock transport, never live fund claims."""

import hashlib
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import test_br1_fund as base

fund = base.fund
Refused = base.Refused


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Resume(unittest.TestCase):
    def setUp(self):
        h = base.Orchestration("test_dry_run_does_not_sign_or_send")
        h.setUp()
        self.addCleanup(h.doCleanups)
        self.h = h
        h.operation, h.amount = fund.CLIENT_OP, fund.CLIENT_AMOUNT
        h.policy["schema"] = fund.CLIENT_SCHEMA
        h.acknowledge = True
        h.reviewed_refusal = True
        policy = h.root / "policy.json"
        policy.write_text(json.dumps(h.policy))
        h.policy_sha256 = sha(policy)
        dry = h.invoke("dry-run")
        plan = json.loads(dry.read_text())["plan"]
        self.plan = plan
        self.old = h.root / "private/br1-public-client-funding-v1.marker.json"
        self.old.write_text(json.dumps(dict(policy_sha256=h.policy_sha256, plan=plan)))
        self.old_hash = sha(self.old)
        source = h.root / "original.py"
        lines = [""] * 418
        lines[415] = 'require(time.time() < deadline, "window expired before signing")'
        lines[417] = "return wallet.sign(message, seqno)"
        source.write_text("\n".join(lines))
        self.source_sha = sha(source)
        log = h.root / "failure.log"
        log.write_text(
            f'Traceback (most recent call last):\n  File "{Path(fund.__file__).resolve()}", line 416, in sign\ncon01_history.certificate.Refused: window expired before signing\n'
        )
        self.receipt = dict(
            schema="tos.br1.reviewed-presign-incident.v1",
            trusted_operator_attestation=True,
            marker_sha256=sha(self.old),
            original_policy=str(policy),
            original_source=str(source),
            failure_log=str(log),
            failure_log_sha256=sha(log),
        )
        h.recovery = h.root / "recovery.json"
        self.save_receipt()
        h.marker = "br1-public-client-presign-resume-v1.marker.json"

    def save_receipt(self):
        self.h.recovery.write_text(json.dumps(self.receipt))
        self.h.recovery_sha256 = sha(self.h.recovery)

    def invoke(self, mode, plan=None):
        with patch.object(fund, "LEGACY_PRESIGN_SOURCE_SHA", self.source_sha):
            return self.h.invoke(mode, plan)

    def assert_no_signature(self, before):
        self.assertEqual(
            (self.h.calls["signs"], self.h.calls["sends"]), (before["signs"], before["sends"])
        )

    def test_resume_dry_never_signs_or_consumes_original_marker(self):
        before = dict(self.h.calls)
        self.invoke("resume-dry-run")
        self.assert_no_signature(before)
        self.assertEqual(sha(self.old), self.old_hash)
        self.assertFalse((self.old.parent / self.h.marker).exists())

    def test_exactly_one_resume_and_original_marker_retained(self):
        dry = self.invoke("resume-dry-run")
        self.invoke("resume-before-sign", dry)
        before = dict(self.h.calls)
        with self.assertRaises(Refused):
            self.invoke("resume-before-sign", dry)
        self.assertEqual(self.h.calls, before)
        self.assertEqual((before["signs"], before["sends"]), (1, 1))
        self.assertEqual(sha(self.old), self.old_hash)

    def test_unreviewed_attestation_refuses(self):
        self.receipt["trusted_operator_attestation"] = False
        self.save_receipt()
        with self.assertRaisesRegex(Refused, "trusted reviewed"):
            self.invoke("resume-dry-run")

    def test_old_nonce_conflict_in_other_operation_refuses(self):
        self.h.data["foreign"] = dict(
            op="different-operation", state="delivered", wallet="source", seqno=3, dry_run=False
        )
        with self.assertRaisesRegex(Refused, "nonce already"):
            self.invoke("resume-dry-run")

    def test_old_plan_cannot_change_destination_or_nonce(self):
        row = json.loads(self.old.read_text())
        row["plan"]["seqno"] = 4
        self.old.write_text(json.dumps(row))
        self.receipt["marker_sha256"] = sha(self.old)
        self.save_receipt()
        with self.assertRaisesRegex(Refused, "plan/nonce"):
            self.invoke("resume-dry-run")

    def test_wrong_guard_failure_is_not_an_unsent_attestation(self):
        log = Path(self.receipt["failure_log"])
        log.write_text("Traceback (most recent call last):\nTimeoutError: unknown after sending\n")
        self.receipt["failure_log_sha256"] = sha(log)
        self.save_receipt()
        with self.assertRaisesRegex(Refused, "guard failure"):
            self.invoke("resume-dry-run")

    def test_modified_source_fails_hash(self):
        Path(self.receipt["original_source"]).write_text("different source")
        with self.assertRaisesRegex(Refused, "SHA"):
            self.invoke("resume-dry-run")

    def test_modified_original_policy_fails_hash(self):
        Path(self.receipt["original_policy"]).write_text("{}")
        with self.assertRaisesRegex(Refused, "SHA"):
            self.invoke("resume-dry-run")

    def test_started_signature_is_irrevocable_fence(self):
        (self.old.parent / "br1-public-client-presign-resume-v1.signing-started.json").write_text(
            "{}"
        )
        with self.assertRaisesRegex(Refused, "signing already"):
            self.invoke("resume-dry-run")

    def test_cut_after_resume_marker_has_zero_new_key_loads(self):
        dry = self.invoke("resume-dry-run")
        before = dict(self.h.calls)
        original = fund.write_new

        def cut(path, value):
            original(path, value)
            if Path(path).name == self.h.marker:
                raise OSError("TEST-ONLY cut after resume marker")

        with patch.object(fund, "write_new", side_effect=cut):
            with self.assertRaises(OSError):
                self.invoke("resume-before-sign", dry)
        self.assertEqual(self.h.calls, before)
        with self.assertRaises(Refused):
            self.invoke("resume-before-sign", dry)
        self.assert_no_signature(before)

    def test_cut_at_signing_fence_prevents_crypto_and_retry(self):
        dry = self.invoke("resume-dry-run")
        before = dict(self.h.calls)
        original = fund.write_new

        def cut(path, value):
            original(path, value)
            if Path(path).name.endswith(".signing-started.json"):
                raise OSError("TEST-ONLY fence cut")

        with patch.object(fund, "write_new", side_effect=cut):
            with self.assertRaises(OSError):
                self.invoke("resume-before-sign", dry)
        self.assert_no_signature(before)
        with self.assertRaises(Refused):
            self.invoke("resume-before-sign", dry)
        self.assert_no_signature(before)

    def test_signature_before_journal_cut_cannot_resign(self):
        dry = self.invoke("resume-dry-run")
        self.h.fail_after_sign = True
        with self.assertRaises(OSError):
            self.invoke("resume-before-sign", dry)
        before = dict(self.h.calls)
        with self.assertRaises(Refused):
            self.invoke("resume-before-sign", dry)
        self.assertEqual(self.h.calls, before)
        self.assertEqual((before["signs"], before["sends"]), (1, 0))

    def test_unknown_send_only_original_readonly_reconcile(self):
        dry = self.invoke("resume-dry-run")
        self.h.unknown = True
        with self.assertRaises(OSError):
            self.invoke("resume-before-sign", dry)
        before = dict(self.h.calls)
        with self.assertRaises(Refused):
            self.invoke("resume-before-sign", dry)
        self.invoke("reconcile")
        self.assert_no_signature(before)
        self.assertEqual(self.h.calls["reconciles"], 1)

    def test_signing_fence_exists_before_underlying_crypto(self):
        calls = []

        class Wallet:
            address = "source"

            def sign(self, *args):
                calls.append("crypto")
                self_check.assertTrue(fence.exists())
                return b"signed"

        class Blueprint:
            address = "source"

            def materialize(self, client):
                return Wallet()

        self_check = self
        fence = self.h.root / "fence.json"
        w = fund.GuardedBlueprint(
            Blueprint(), 3, 100, lambda: fund.write_new(fence, {})
        ).materialize(None)
        with patch.object(fund.time, "time", return_value=99):
            w.sign(b"msg", 3)
        self.assertEqual(calls, ["crypto"])

    def test_exclusive_resume_marker_allows_one_concurrent_creator(self):
        path = self.h.root / "concurrent.marker"

        def attempt(_):
            try:
                fund.write_new(path, {})
                return "created"
            except FileExistsError:
                return "refused"

        with ThreadPoolExecutor(max_workers=2) as executor:
            rows = list(executor.map(attempt, [0, 1]))
        self.assertCountEqual(rows, ["created", "refused"])

    def test_missing_review_ack_precedes_runtime_keys(self):
        self.h.reviewed_refusal = False
        before = dict(self.h.calls)
        with self.assertRaisesRegex(Refused, "pinned reviewed"):
            self.invoke("resume-dry-run")
        self.assertEqual(self.h.calls, before)

    def test_any_unresolved_other_wallet_blocks_resume(self):
        self.h.data["foreign"] = dict(op="other", state="unknown", wallet="other", seqno=99)
        before = dict(self.h.calls)
        with self.assertRaisesRegex(Refused, "unresolved"):
            self.invoke("resume-dry-run")
        self.assertEqual(self.h.calls, before)

    def test_post_signature_window_expiry_has_zero_send_and_fence(self):
        dry = self.invoke("resume-dry-run")
        self.h.expire_after_sign = True
        with self.assertRaisesRegex(Refused, "window expired"):
            self.invoke("resume-before-sign", dry)
        self.assertEqual((self.h.calls["signs"], self.h.calls["sends"]), (1, 0))
        before = dict(self.h.calls)
        with self.assertRaises(Refused):
            self.invoke("resume-before-sign", dry)
        self.assertEqual(self.h.calls, before)

    def test_malformed_source_sequence_refuses(self):
        self.h.data["malformed"] = dict(op="other", state="delivered", wallet="source", seqno="3")
        with self.assertRaisesRegex(Refused, "nonce already"):
            self.invoke("resume-dry-run")

    def test_slow_signing_fence_expiry_never_calls_crypto(self):
        clock = [99]
        calls = []

        class Wallet:
            address = "source"

            def sign(self, *args):
                calls.append("crypto")

        class Blueprint:
            address = "source"

            def materialize(self, client):
                return Wallet()

        def fence():
            clock[0] = 101

        wallet = fund.GuardedBlueprint(Blueprint(), 3, 100, fence).materialize(None)
        with patch.object(fund.time, "time", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(Refused, "after signing fence"):
                wallet.sign(b"msg", 3)
            clock[0] = 99
            with self.assertRaisesRegex(Refused, "already claimed"):
                wallet.sign(b"msg", 3)
        self.assertEqual(calls, [])
