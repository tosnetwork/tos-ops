"""Controls for the once-only public service-case runner.

Every guard is exercised red and green with a fake CLI and a fake RPC: a passing test here
proves the guard can refuse, not merely that it stayed quiet.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
spec = importlib.util.spec_from_file_location(
    "service_public_cases", SCRIPTS / "service-public-cases.py"
)
spc = importlib.util.module_from_spec(spec)
sys.modules["service_public_cases"] = spc
spec.loader.exec_module(spc)

GENESIS = {"root_hash": "R" * 44, "file_hash": "F" * 44}
PAYER = "0:" + "11" * 32
CONTRACT = "0:" + "22" * 32
PRIMARY = "http://primary/jsonRPC"
CONFIRM = "http://confirm/jsonRPC"


def tx(lt, hash_, *, in_hash=None, out=(), exit_code=0, aborted=False):
    return {
        "transaction_id": {"lt": str(lt), "hash": hash_},
        "block_id": {"seqno": lt // 10},
        "in_msg": {"hash": in_hash} if in_hash else None,
        "out_msgs": [{"destination": d, "hash": h, "value": "1", "bounced": False} for d, h in out],
        "compute": {"success": not aborted, "exit_code": exit_code, "skipped": False},
        "aborted": aborted,
        "action": {"success": not aborted} if not aborted else None,
    }


class FakeRpc(spc.Rpc):
    """In-memory chain view: per-source transaction lists and balances."""

    def __init__(self):
        super().__init__(PRIMARY, [CONFIRM])
        self.rows = {PRIMARY: {}, CONFIRM: {}}
        self.balances = {}
        self.states = {}
        self.genesis_by_url = {PRIMARY: dict(GENESIS), CONFIRM: dict(GENESIS)}
        self.version = spc.CP8_VERSION
        self.anchor = 0

    def add(self, address, row, sources=(PRIMARY, CONFIRM)):
        for url in sources:
            self.rows[url].setdefault(address, []).insert(0, row)

    def genesis(self, url):
        return self.genesis_by_url[url]

    def head(self, url=None):
        return {"seqno": 1000}

    def global_version(self):
        return self.version

    def rotation_anchor(self):
        return self.anchor

    def info(self, address, url=None):
        rows = self.rows[url or PRIMARY].get(address, [])
        return {
            "balance": str(self.balances.get(address, 0)),
            "state": self.states.get(address, "active"),
            "last_transaction_id": rows[0]["transaction_id"] if rows else None,
        }

    def call(self, method, url=None, **params):
        url = url or PRIMARY
        if method == "getTransactions":
            return list(self.rows[url].get(params["address"], []))[: params["limit"]]
        raise AssertionError(f"unexpected rpc {method}")


class FakeCli:
    """Records argv and plays back scripted (exit code, text, chain effect) per label."""

    def __init__(self, rpc):
        self.rpc = rpc
        self.calls = []
        self.script = {}
        self.calls_count = 0

    def run(self, label, *args, want_json=False):
        self.calls.append((label, list(args)))
        self.calls_count += 1
        rc, text, effect = self.script.get(label, (0, "{}", None))
        if effect:
            effect(self.rpc)
        if want_json and rc == 0:
            return rc, json.loads(text)
        return rc, text

    def check_binary(self):
        return "deadbeef"


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.private = base / "private"
        self.private.mkdir(mode=0o700)
        args = spc.build_parser().parse_args(
            [
                "--private-dir",
                str(self.private),
                "--evidence-dir",
                str(base / "evidence"),
                "--cli",
                "/bin/true",
                "--cli-sha256",
                "deadbeef",
                "--rpc",
                PRIMARY,
                "--confirm-rpc",
                CONFIRM,
                "--genesis-root",
                GENESIS["root_hash"],
                "--genesis-file",
                GENESIS["file_hash"],
                "--stop-ceiling",
                "20",
                "--rotation-anchor",
                "1",
                "--skip-thermal",
                "--date",
                "20261106",
                "status",
            ]
        )
        self.runner = spc.Runner(args)
        self.rpc = FakeRpc()
        self.runner.rpc = self.rpc
        self.cli = FakeCli(self.rpc)
        self.runner.cli = self.cli
        self.rpc.balances[PAYER] = 10**9
        self.rpc.balances[CONTRACT] = 10**9
        spc.SETTLE_TIMEOUT_S = 0.3
        spc.POLL_S = 0.01
        # Keep the clock far from the (anchor=1, period 7200) grid unless a test moves it.
        self.now_patch = mock.patch.object(spc, "now", return_value=1 + 3600)
        self.now_patch.start()

    def tearDown(self):
        self.now_patch.stop()
        self.tmp.cleanup()

    def settle_effect(self, exit_code=0, aborted=False, sources=(PRIMARY, CONFIRM)):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            rpc.add(
                CONTRACT, tx(200, "C1", in_hash="M1", exit_code=exit_code, aborted=aborted), sources
            )

        return effect


class StepControls(RunnerCase):
    def test_green_step_settles_on_every_source(self):
        self.cli.script["s"] = (0, "", self.settle_effect())
        rec = self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertEqual(rec["verdict"], "settled")
        self.assertEqual(rec["tx"]["hash"], "C1")
        self.assertEqual(rec["in_msg_hash"], "M1")
        self.assertTrue(all(rec["confirmed_on"].values()))
        self.assertTrue((self.runner.journal.steps / "s.attempt.json").exists())
        self.assertTrue((self.runner.journal.steps / "s.done.json").exists())

    def test_marker_is_written_before_the_cli_runs(self):
        seen = {}

        def effect(rpc):
            seen["marker"] = (self.runner.journal.steps / "s.attempt.json").exists()
            self.settle_effect()(rpc)

        self.cli.script["s"] = (0, "", effect)
        self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertTrue(seen["marker"])

    def test_same_label_is_refused_and_not_sent_twice(self):
        self.runner.journal.attempt("s", {})
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertIn("already attempted", str(cm.exception))
        self.assertEqual(self.cli.calls, [])

    def test_completed_label_is_replayed_from_the_record_not_resent(self):
        self.cli.script["s"] = (0, "", self.settle_effect())
        first = self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        again = self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertEqual(first["tx"], again["tx"])
        self.assertEqual(len(self.cli.calls), 1)

    def test_lost_reply_is_reconciled_read_only_without_resend(self):
        # CLI exits non-zero but the payer's message did reach the chain.
        self.cli.script["s"] = (7, "", self.settle_effect())
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertIn("unknown", str(cm.exception))
        rec = self.runner.journal.result("s")
        self.assertEqual(rec["verdict"], "unknown")
        self.assertEqual(len(rec["payer_tx_after"]), 1)
        with self.assertRaises(spc.Refusal):
            self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertEqual(len(self.cli.calls), 1)

    def test_cli_refusal_without_a_message_is_recorded_as_refused(self):
        self.cli.script["s"] = (2, "", None)
        with self.assertRaises(spc.Refusal):
            self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertEqual(self.runner.journal.result("s")["verdict"], "cli-refused")

    def test_message_not_observed_is_unknown_and_never_retried(self):
        self.cli.script["s"] = (0, "", None)
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertIn("no retry", str(cm.exception))
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unknown-not-observed")

    def test_missing_on_a_confirmation_source_fails_the_claim(self):
        self.cli.script["s"] = (0, "", self.settle_effect(sources=(PRIMARY,)))
        with self.assertRaises(spc.Refusal):
            self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        rec = self.runner.journal.result("s")
        self.assertEqual(rec["verdict"], "not-confirmed-on-all-sources")
        self.assertFalse(rec["confirmed_on"][CONFIRM])

    def test_unexpected_abort_on_a_success_step_fails(self):
        self.cli.script["s"] = (0, "", self.settle_effect(exit_code=1800, aborted=True))
        with self.assertRaises(spc.Refusal):
            self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unexpected-abort")

    def test_refusal_control_green_requires_abort_code_and_unchanged_state(self):
        self.cli.script["s"] = (0, "", self.settle_effect(exit_code=1800, aborted=True))
        rec = self.runner.step(
            "s",
            ["agent", "x"],
            payer=PAYER,
            observe=CONTRACT,
            expect_exit=1800,
            show=lambda: {"owner": "a"},
        )
        self.assertEqual(rec["verdict"], "refused-as-intended")

    def test_refusal_control_red_when_the_contract_accepted(self):
        self.cli.script["s"] = (0, "", self.settle_effect())
        with self.assertRaises(spc.Refusal):
            self.runner.step(
                "s",
                ["agent", "x"],
                payer=PAYER,
                observe=CONTRACT,
                expect_exit=1800,
                show=lambda: {"owner": "a"},
            )
        self.assertEqual(self.runner.journal.result("s")["verdict"], "refusal-control-failed")

    def test_refusal_control_red_on_wrong_exit_code(self):
        self.cli.script["s"] = (0, "", self.settle_effect(exit_code=1801, aborted=True))
        with self.assertRaises(spc.Refusal):
            self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT, expect_exit=1800)

    def test_refusal_control_red_when_protected_state_moved(self):
        states = iter([{"owner": "a"}, {"owner": "b"}])
        self.cli.script["s"] = (0, "", self.settle_effect(exit_code=1800, aborted=True))
        with self.assertRaises(spc.Refusal):
            self.runner.step(
                "s",
                ["agent", "x"],
                payer=PAYER,
                observe=CONTRACT,
                expect_exit=1800,
                show=lambda: next(states),
            )

    def test_two_messages_from_the_payer_to_the_contract_are_refused(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            rpc.add(PAYER, tx(101, "P2", out=((CONTRACT, "M2"),)))
            rpc.add(CONTRACT, tx(200, "C1", in_hash="M1"))

        self.cli.script["s"] = (0, "", effect)
        with self.assertRaises(spc.Refusal):
            self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)

    def test_drill_exits_after_the_marker_without_calling_the_cli(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH": "s"}):
            with self.assertRaises(SystemExit):
                self.runner.step("s", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertTrue(self.runner.journal.attempted("s"))
        self.assertIsNone(self.runner.journal.result("s"))
        self.assertEqual(self.cli.calls, [])


class PreflightControls(RunnerCase):
    def test_green(self):
        rec = self.runner.preflight()
        self.assertEqual(rec["global_version"], spc.CP8_VERSION)
        self.assertGreaterEqual(rec["quiet_window"]["seconds_to_rotation"], spc.QUIET_S)

    def test_genesis_mismatch_on_a_confirmation_source_refuses(self):
        self.rpc.genesis_by_url[CONFIRM] = {"root_hash": "X" * 44, "file_hash": "Y" * 44}
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.preflight()
        self.assertIn("genesis", str(cm.exception))

    def test_other_global_version_refuses(self):
        self.rpc.version = spc.CP8_VERSION + 1
        with self.assertRaises(spc.Refusal):
            self.runner.preflight()

    def test_quiet_window_refuses_near_rotation(self):
        for offset in (0, 120, spc.ROTATION_PERIOD_S - 300):
            with mock.patch.object(spc, "now", return_value=1 + offset):
                with self.assertRaises(spc.Refusal, msg=f"offset {offset}"):
                    self.runner.preflight()
        with mock.patch.object(spc, "now", return_value=1 + spc.QUIET_S):
            self.runner.preflight()

    def test_wrong_cli_hash_refuses(self):
        self.cli.check_binary = lambda: (_ for _ in ()).throw(spc.Refusal("sha"))
        with self.assertRaises(spc.Refusal):
            self.runner.preflight()

    def test_group_readable_private_dir_refuses(self):
        os.chmod(self.private, 0o750)
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.preflight()
        self.assertIn("0700", str(cm.exception))

    def test_thermal_limit_refuses(self):
        self.runner.args.skip_thermal = False
        with mock.patch.object(spc, "package_temperatures", return_value=[70.0, 90.0]):
            with self.assertRaises(spc.Refusal):
                self.runner.preflight()
        with mock.patch.object(spc, "package_temperatures", return_value=[70.0, 71.0]):
            self.runner.preflight()
        with mock.patch.object(spc, "package_temperatures", return_value=[]):
            with self.assertRaises(spc.Refusal):
                self.runner.preflight()


class FundingControls(RunnerCase):
    def setUp(self):
        super().setUp()
        self.runner.actors_path.write_text(
            json.dumps(
                {"wallets": {w: f"0:{i:02x}" + "00" * 31 for i, w in enumerate(spc.WALLETS)}}
            )
        )

    def addr(self, actor):
        return self.runner.actors()["wallets"][actor]

    def test_plan_matches_the_packet(self):
        plan = self.runner.plan_funding()
        self.assertEqual(plan["total_nanotos"], spc.tos_to_nanotos("12.5"))
        self.assertEqual([p["operation_id"] for p in plan["plan"]][0], "sc-fund-owner-20261106")

    def test_record_needs_the_credit_on_every_source(self):
        self.rpc.balances[self.addr("sc-owner")] = spc.tos_to_nanotos("5")
        row = self.runner.record_funding("sc-owner", "5.0", "op-1")
        self.assertEqual(row["amount_nanotos"], 5 * spc.NANO)
        self.rpc.balances[self.addr("sc-client")] = spc.tos_to_nanotos("2.9")
        with self.assertRaises(spc.Refusal):
            self.runner.record_funding("sc-client", "3.0", "op-2")

    def test_duplicate_operation_id_refuses(self):
        self.rpc.balances[self.addr("sc-owner")] = spc.tos_to_nanotos("5")
        self.runner.record_funding("sc-owner", "5.0", "op-1")
        with self.assertRaises(spc.Refusal):
            self.runner.record_funding("sc-owner", "5.0", "op-1")

    def test_ceiling_refuses_the_record_that_would_cross_it(self):
        for actor in spc.WALLETS:
            self.rpc.balances[self.addr(actor)] = spc.tos_to_nanotos("100")
        self.runner.record_funding("sc-owner", "19.5", "op-1")
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.record_funding("sc-client", "0.6", "op-2")
        self.assertIn("ceiling", str(cm.exception))
        self.runner.record_funding("sc-client", "0.5", "op-3")
        self.assertEqual(self.runner.funded_total(), 20 * spc.NANO)
        with self.assertRaises(spc.Refusal):
            self.runner.plan_funding()

    def test_zero_or_malformed_amounts_refuse(self):
        with self.assertRaises(spc.Refusal):
            self.runner.record_funding("sc-owner", "0", "op-0")
        with self.assertRaises(spc.Refusal):
            spc.tos_to_nanotos("1.0000000001")
        with self.assertRaises(spc.Refusal):
            spc.tos_to_nanotos("abc")


class Helpers(unittest.TestCase):
    def test_amount_round_trip(self):
        for text in ("0.000000001", "1.5", "3088.636365049", "20"):
            n = spc.tos_to_nanotos(text)
            self.assertEqual(spc.tos_to_nanotos(spc.nanotos_text(n)), n)

    def test_quiet_window_distance(self):
        self.assertEqual(spc.quiet_window_distance(1000, 1000), 0)
        self.assertEqual(spc.quiet_window_distance(1000 + 3600, 1000), 3600)
        self.assertEqual(spc.quiet_window_distance(1000 + 7199, 1000), 1)

    def test_boc_root_data_reads_config_param_8(self):
        # Single-cell BOC: GlobalVersion c4 version=16 capabilities=0x1ee.
        data = bytes.fromhex("c4" + "00000010" + "00000000000001ee")
        d2 = len(data) * 2
        boc = (
            bytes.fromhex("b5ee9c72")
            + bytes([0x01, 0x01])  # flags: size 1, no index; offset bytes 1
            + bytes([0x01, 0x01, 0x00])  # cells, roots, absent
            + bytes([2 + len(data)])  # total cell bytes
            + bytes([0x00])  # root index
            + bytes([0x00, d2])
            + data
        )
        root = spc.boc_root_data(boc)
        self.assertEqual(root[0], 0xC4)
        self.assertEqual(int.from_bytes(root[1:5], "big"), 16)
        with self.assertRaises(spc.Refusal):
            spc.boc_root_data(b"\x00" * 8)

    def test_evidence_record_carries_no_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = spc.Journal(Path(tmp) / "ev")
            cli = spc.Cli(Path("/bin/sh"), "x", Path(tmp) / "priv", journal)
            (Path(tmp) / "priv").mkdir(mode=0o700)
            payload = Path(tmp) / "payload.txt"
            payload.write_text("raw-cli-output-stays-private\n")
            with mock.patch.dict(os.environ, {"VAULT_URL": "file:///secret?master_key=00"}):
                self.assertNotIn("VAULT_URL", cli.env())
                rc, text = cli.run("echo", "-c", 'cat "$1"', "sh", str(payload))
            self.assertEqual(rc, 0)
            self.assertIn("raw-cli-output", text)
            events = journal.events.read_text()
            self.assertNotIn("master_key", events)
            self.assertIn('"label": "echo"', events)
            self.assertNotIn("raw-cli-output", events)  # raw output stays in the private dir
            self.assertIn("raw-cli-output", (cli.receipts / "echo.stdout").read_text())


if __name__ == "__main__":
    unittest.main()
