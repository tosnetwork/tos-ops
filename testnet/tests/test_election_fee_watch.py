"""Fail-closed observational fee alerts, independent of any signing workflow."""

import contextlib
import http.client
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
from con01_history import election_fees as fees  # noqa: E402
from con01_history.certificate import Refused  # noqa: E402


def block(seq=0):
    return dict(
        workchain=-1,
        shard="-9223372036854775808",
        seqno=seq,
        root_hash="11" * 32,
        file_hash="22" * 32,
    )


class Fake:
    def __init__(self, url):
        self.url = url
        self.balance = "8100000000"
        self.genesis = block()
        self.age = 1
        self.other = None
        self.account_block = block(97)

    def call(self, method, params):
        if method == "getMasterchainInfo":
            return dict(init=self.genesis, last=block(100))
        if method == "getBlockHeader":
            return dict(id=self.other or block(97), global_id=2, gen_utime=1000 - self.age)
        if method == "getAddressInformation":
            return dict(block_id=self.account_block, balance=self.balance)
        raise AssertionError("unexpected non-read call")


class FeeWatch(unittest.TestCase):
    def setUp(self):
        self.sources = [Fake("a"), Fake("b")]
        self.wallets = {"node-1": "-1:" + "aa" * 32}

    def observe(self):
        return fees.observe(self.sources, self.wallets, block(), lambda: 1000)

    def cli_after_slow_wallet_reads(self, delay):
        clock = [1000]

        class Slow(Fake):
            def call(self, method, params):
                answer = super().call(method, params)
                if method == "getAddressInformation":
                    clock[0] = 1000 + delay
                return answer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "wallets.json").write_text(json.dumps(self.wallets))
            (root / "genesis.json").write_text(json.dumps(block()))
            status = root / "STATUS.json"
            status.write_text(json.dumps({"status": "HEALTHY_FEE_RESERVE"}))
            argv = [
                "fees",
                "--rpc",
                "http://127.0.0.1:1/jsonRPC",
                "--rpc",
                "http://127.0.0.1:2/jsonRPC",
                "--wallets",
                str(root / "wallets.json"),
                "--genesis",
                str(root / "genesis.json"),
                "--out",
                str(status),
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(fees, "FeeRpc", side_effect=[Slow("a"), Slow("b")]),
                mock.patch.object(fees.time, "time", side_effect=lambda: clock[0]),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                code = fees.main()
            return code, json.loads(status.read_bytes())

    def test_slow_successful_reads_replace_health_with_unknown(self):
        code, report = self.cli_after_slow_wallet_reads(61)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "INDETERMINATE")
        self.assertIn("stale or future", report["reason"])

    def test_healthy_report_timestamp_is_observation_completion(self):
        code, report = self.cli_after_slow_wallet_reads(5)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "HEALTHY_FEE_RESERVE")
        self.assertEqual(report["checked_utc"], 1005)
        self.assertEqual(report["valid_until_utc"], 1605)

    def test_early_warning_before_stake_exhaustion(self):
        for source in self.sources:
            source.balance = "5199999999"
        row = self.observe()
        self.assertEqual(row["status"], "LOW_FEE_RUNWAY")
        self.assertFalse(row["wallets"]["node-1"]["cannot_afford_next_stake"])

    def test_exact_threshold_is_healthy(self):
        for source in self.sources:
            source.balance = "5200000000"
        self.assertEqual(self.observe()["status"], "HEALTHY_FEE_RESERVE")

    def test_low_balance_is_critical(self):
        for source in self.sources:
            source.balance = "789690000"
        self.assertTrue(self.observe()["wallets"]["node-1"]["cannot_afford_next_stake"])

    def test_disagreement_never_reports_health(self):
        self.sources[1].balance = "8100000001"
        with self.assertRaisesRegex(Refused, "disagreement"):
            self.observe()

    def test_stale_or_future_sources_refuse(self):
        for age in [61, -1]:
            self.sources[0].age = age
            with self.assertRaisesRegex(Refused, "stale or future"):
                self.observe()

    def test_wrong_genesis_refuses(self):
        self.sources[0].genesis["root_hash"] = "33" * 32
        with self.assertRaisesRegex(Refused, "genesis"):
            self.observe()

    def test_wrong_checkpoint_refuses(self):
        self.sources[0].other = dict(block(97), file_hash="33" * 32)
        with self.assertRaisesRegex(Refused, "full-id"):
            self.observe()

    def test_account_checkpoint_is_not_just_height(self):
        self.sources[0].account_block = dict(block(97), file_hash="33" * 32)
        with self.assertRaisesRegex(Refused, "account read"):
            self.observe()

    def test_malformed_amount_cannot_be_a_healthy_reserve(self):
        for value in ["-1", "NaN", "18446744073709551616", True]:
            for source in self.sources:
                source.balance = value
            with self.assertRaisesRegex(Refused, "invalid nanotOS balance|nanotOS balance exceeds"):
                self.observe()

    def test_one_rpc_cannot_masquerade_as_two(self):
        self.sources[1].url = "a"
        with self.assertRaisesRegex(Refused, "two distinct"):
            self.observe()

    def test_duplicate_wallets_refuse(self):
        self.wallets["node-2"] = self.wallets["node-1"]
        with self.assertRaisesRegex(Refused, "duplicate fee"):
            self.observe()

    def test_non_read_method_refuses_before_network(self):
        rpc = fees.FeeRpc("http://127.0.0.1:1/jsonRPC")
        with self.assertRaisesRegex(Refused, "allowlist"):
            rpc.call("sendBoc", {})

    def test_reply_byte_bound_is_checked_before_json(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self, limit):
                return b" " * limit

        class Opener:
            def open(self, *args, **kwargs):
                return Response()

        rpc = fees.FeeRpc("http://127.0.0.1:1/jsonRPC")
        rpc.opener = Opener()
        with self.assertRaisesRegex(Refused, "response byte bound"):
            rpc.call("getMasterchainInfo", {})

    def test_manifest_population_is_bounded_before_reads(self):
        self.wallets = {f"node-{i}": "-1:" + f"{i:064x}" for i in range(17)}
        with self.assertRaisesRegex(Refused, "bounded masterchain"):
            self.observe()

    def test_status_replaces_previous_health_on_unknown_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "STATUS.json"
            fees.write_status(path, {"status": "HEALTHY_FEE_RESERVE"})
            fees.write_status(path, {"status": "INDETERMINATE"})
            self.assertEqual(json.loads(path.read_bytes())["status"], "INDETERMINATE")

    def test_cli_nonobject_manifest_replaces_health_with_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "wallets.json"
            genesis = root / "genesis.json"
            status = root / "STATUS.json"
            genesis.write_text(json.dumps(block()))
            for value in [["node-1"], "node-1", None, 42]:
                manifest.write_text(json.dumps(value))
                status.write_text(json.dumps({"status": "HEALTHY_FEE_RESERVE"}))
                argv = [
                    "fees",
                    "--rpc",
                    "http://127.0.0.1:1/jsonRPC",
                    "--rpc",
                    "http://127.0.0.1:2/jsonRPC",
                    "--wallets",
                    str(manifest),
                    "--genesis",
                    str(genesis),
                    "--out",
                    str(status),
                ]
                with (
                    mock.patch.object(sys, "argv", argv),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(fees.main(), 2)
                self.assertEqual(json.loads(status.read_bytes())["status"], "INDETERMINATE")
                self.assertTrue(
                    json.loads(status.read_bytes())["reason"].startswith(
                        "Refused: bounded masterchain fee wallet manifest required"
                    )
                )

    def test_protocol_or_unexpected_read_failure_replaces_previous_health(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "wallets.json"
            genesis = root / "genesis.json"
            status = root / "STATUS.json"
            manifest.write_text(json.dumps(self.wallets))
            genesis.write_text(json.dumps(block()))
            argv = [
                "fees",
                "--rpc",
                "http://127.0.0.1:1/jsonRPC",
                "--rpc",
                "http://127.0.0.1:2/jsonRPC",
                "--wallets",
                str(manifest),
                "--genesis",
                str(genesis),
                "--out",
                str(status),
            ]
            for error in [
                http.client.IncompleteRead(b"partial chunk"),
                RuntimeError("unexpected reader failure"),
            ]:
                status.write_text(json.dumps({"status": "HEALTHY_FEE_RESERVE"}))
                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(fees.FeeRpc, "call", side_effect=error),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(fees.main(), 2)
                report = json.loads(status.read_bytes())
                self.assertEqual(report["status"], "INDETERMINATE")
                self.assertIn(type(error).__name__, report["reason"])


if __name__ == "__main__":
    unittest.main()
