"""Controls for the once-only public service-case runner.

Every guard is exercised red and green with a fake CLI and a fake RPC: a passing test here
proves the guard can refuse, not merely that it stayed quiet. The case plans are checked
against the flags the pinned CLI itself prints (tests/data/service-public-cases-cli-flags.json).
"""

import base64
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
DATA = Path(__file__).resolve().parent / "data"
spec = importlib.util.spec_from_file_location(
    "service_public_cases", SCRIPTS / "service-public-cases.py"
)
spc = importlib.util.module_from_spec(spec)
sys.modules["service_public_cases"] = spc
spec.loader.exec_module(spc)

GENESIS = {"root_hash": "R" * 44, "file_hash": "F" * 44}
PAYER = "0:" + "11" * 32
CONTRACT = "0:" + "22" * 32
SOURCE = "-1:" + "33" * 32
PRIMARY = "http://primary/jsonRPC"
CONFIRM = "http://confirm/jsonRPC"
SINCE, UNTIL = 1_000_000, 1_007_200
MID = SINCE + 3600
WALLETS = {w: f"0:{i:02x}" + "00" * 31 for i, w in enumerate(spc.WALLETS)}


def tx(
    lt,
    hash_,
    *,
    in_hash=None,
    out=(),
    exit_code=0,
    aborted=False,
    success=None,
    action=None,
    kind="internal",
):
    ok = not aborted if success is None else success
    return {
        "transaction_id": {"lt": str(lt), "hash": hash_},
        "block_id": {"seqno": lt // 10},
        "in_msg": {"hash": in_hash, "kind": kind} if in_hash else None,
        "out_msgs": [{"destination": d, "hash": h, "value": "1", "bounced": False} for d, h in out],
        "compute": {"success": ok, "exit_code": exit_code, "skipped": False},
        "aborted": aborted,
        "action": action if action is not None else ({"success": True} if not aborted else None),
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
        self.bounds = (SINCE, UNTIL)
        self.calls = []

    def add(self, address, row, sources=(PRIMARY, CONFIRM)):
        for url in sources:
            self.rows[url].setdefault(address, []).insert(0, row)

    def genesis(self, url):
        return self.genesis_by_url[url]

    def head(self, url=None):
        return {"seqno": 1000}

    def global_version(self):
        return self.version

    def rotation_bounds(self):
        self.calls.append("rotation_bounds")
        return self.bounds

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

    def __init__(self, rpc, private):
        self.rpc = rpc
        self.private = private
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

    def redact(self, args):
        return [a.replace(str(self.private), "<private>") for a in args]


def settle_effect(
    exit_code=0, aborted=False, sources=(PRIMARY, CONFIRM), action=None, success=None
):
    def effect(rpc):
        rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
        rpc.add(
            CONTRACT,
            tx(
                200,
                "C1",
                in_hash="M1",
                exit_code=exit_code,
                aborted=aborted,
                action=action,
                success=success,
            ),
            sources,
        )

    return effect


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.private = base / "private"
        self.private.mkdir(mode=0o700)
        self.evidence = base / "evidence"
        args = spc.build_parser().parse_args(
            [
                "--private-dir",
                str(self.private),
                "--evidence-dir",
                str(self.evidence),
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
                "--skip-thermal",
                "--date",
                "20261106",
                "status",
            ]
        )
        self.runner = spc.Runner(args)
        self.rpc = FakeRpc()
        self.runner.rpc = self.rpc
        self.cli = FakeCli(self.rpc, self.private)
        self.runner.cli = self.cli
        self.rpc.balances[PAYER] = 10**9
        self.rpc.balances[CONTRACT] = 10**9
        self.patches = [
            mock.patch.object(spc, "SETTLE_TIMEOUT_S", 0.2),
            mock.patch.object(spc, "REFUSAL_OBSERVE_S", 0.05),
            mock.patch.object(spc, "POLL_S", 0.01),
            mock.patch.object(spc, "now", return_value=MID),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def step(self, **kw):
        kw.setdefault("payer", PAYER)
        kw.setdefault("observe", CONTRACT)
        return self.runner.step("s", ["agent", "x"], **kw)

    def write_actors(self):
        self.runner.actors_path.write_text(json.dumps({"wallets": WALLETS}))


class StepControls(RunnerCase):
    def test_green_step_settles_on_every_source(self):
        self.cli.script["s"] = (0, "", settle_effect())
        rec = self.step()
        self.assertEqual(rec["verdict"], "settled")
        self.assertEqual(rec["tx"]["hash"], "C1")
        self.assertEqual(rec["in_msg_hash"], "M1")
        self.assertTrue(all(rec["confirmed_on"].values()))
        self.assertTrue((self.runner.journal.steps / "s.attempt.json").exists())
        self.assertTrue((self.runner.journal.steps / "s.done.json").exists())
        self.assertEqual(
            json.loads((self.runner.journal.steps / "s.attempt.json").read_text())["kind"], "value"
        )

    def test_step_records_carry_their_label_for_the_case_verdict(self):
        self.cli.script["s"] = (0, "", settle_effect())
        rec = self.step()
        self.assertEqual(rec["label"], "s")
        self.assertEqual(self.step()["label"], "s")

        def later(rpc):
            rpc.add(PAYER, tx(300, "P2", out=((CONTRACT, "M2"),)))
            rpc.add(CONTRACT, tx(400, "C2", in_hash="M2", exit_code=7, aborted=True))

        self.cli.script["t"] = (0, "", later)
        control = self.runner.step(
            "t", ["agent", "x"], payer=PAYER, observe=CONTRACT, expect_exit=7
        )
        verdict = spc.Runner.verdict(True, [control])
        self.assertEqual(verdict["controls"], {"t": "refused-as-intended"})
        self.assertEqual(verdict["controls_without_on_chain_receipt"], [])
        self.assertEqual(verdict["controls_refused_client_side"], [])
        self.assertTrue(verdict["pass"])
        self.cli.script["u"] = (1, "", None)
        refused = self.runner.step(
            "u", ["agent", "x"], payer=PAYER, observe=CONTRACT, expect_exit=7
        )
        self.assertEqual(refused["label"], "u")
        verdict = spc.Runner.verdict(True, [refused])
        self.assertEqual(verdict["controls_without_on_chain_receipt"], ["u"])
        self.assertFalse(verdict["pass"])

    def test_plain_credit_to_an_account_without_code_settles(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            row = tx(200, "C1", in_hash="M1", aborted=True)
            row["compute"] = {"skipped": True, "skip_reason": 0}
            row["action"] = None
            rpc.add(CONTRACT, row)
            rpc.balances[CONTRACT] += 500_000_000

        self.cli.script["s"] = (0, "", effect)
        rec = self.step()
        self.assertEqual(rec["verdict"], "settled")
        self.assertEqual(rec["settled_as"], "credited-without-compute")

    def test_skipped_compute_without_a_credit_is_an_unexpected_abort(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            row = tx(200, "C1", in_hash="M1", aborted=True)
            row["compute"] = {"skipped": True, "skip_reason": 0}
            rpc.add(CONTRACT, row)

        self.cli.script["s"] = (0, "", effect)
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unexpected-abort")

    def test_skipped_compute_with_a_bounce_is_an_unexpected_abort(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            row = tx(200, "C1", in_hash="M1", aborted=True, out=((PAYER, "B1"),))
            row["compute"] = {"skipped": True, "skip_reason": 0}
            rpc.add(CONTRACT, row)
            rpc.balances[CONTRACT] += 500_000_000

        self.cli.script["s"] = (0, "", effect)
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unexpected-abort")

    def test_executed_step_records_how_it_settled(self):
        self.cli.script["s"] = (0, "", settle_effect())
        self.assertEqual(self.step()["settled_as"], "executed")

    def test_old_payer_send_is_not_attributed_to_a_client_side_refusal(self):
        self.rpc.add(PAYER, tx(50, "P0", out=((CONTRACT, "M0"),)))
        self.cli.script["s"] = (1, "", None)
        rec = self.step(expect_exit=7)
        self.assertEqual(rec["verdict"], "cli-refused-before-broadcast")
        self.assertEqual(rec["before"]["payer_lt"], 50)
        self.assertEqual(rec["payer_tx_after"], [])

    def test_guards_run_before_every_step(self):
        self.cli.script["s"] = (0, "", settle_effect())
        self.step()
        self.assertIn("rotation_bounds", self.rpc.calls)
        self.rpc.bounds = (MID - 100, UNTIL)
        with self.assertRaises(spc.Refusal):
            self.runner.step("t", ["agent", "x"], payer=PAYER, observe=CONTRACT)
        self.assertEqual(len(self.cli.calls), 1)

    def test_marker_is_written_before_the_cli_runs(self):
        seen = {}

        def effect(rpc):
            seen["marker"] = (self.runner.journal.steps / "s.attempt.json").exists()
            settle_effect()(rpc)

        self.cli.script["s"] = (0, "", effect)
        self.step()
        self.assertTrue(seen["marker"])

    def test_same_label_is_refused_and_not_sent_twice(self):
        self.runner.journal.attempt("s", {})
        with self.assertRaises(spc.Refusal) as cm:
            self.step()
        self.assertIn("without a result", str(cm.exception))
        self.assertEqual(self.cli.calls, [])

    def test_completed_label_is_replayed_from_the_record_not_resent(self):
        self.cli.script["s"] = (0, "", settle_effect())
        first = self.step()
        again = self.step()
        self.assertEqual(first["tx"], again["tx"])
        self.assertEqual(len(self.cli.calls), 1)

    def test_failed_label_is_never_replayed_as_success(self):
        self.runner.journal.attempt("s", {})
        self.runner.journal.done("s", {"verdict": "unknown-not-observed"})
        with self.assertRaises(spc.Refusal) as cm:
            self.step()
        self.assertIn("never re-sent", str(cm.exception))
        self.assertEqual(self.cli.calls, [])

    def test_cli_failure_after_one_broadcast_is_judged_by_the_chain(self):
        self.cli.script["s"] = (7, "", settle_effect())
        rec = self.step()
        self.assertEqual(rec["verdict"], "settled")
        self.assertTrue(rec["cli_reported_failure"])
        self.assertEqual(rec["exit_code"], 7)
        self.assertEqual(rec["tx"]["hash"], "C1")
        self.assertEqual(len(rec["payer_tx_after"]), 1)

    def test_lost_reply_after_a_cli_failure_is_unknown_and_never_resent(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))

        self.cli.script["s"] = (7, "", effect)
        with self.assertRaises(spc.Refusal):
            self.step()
        rec = self.runner.journal.result("s")
        self.assertEqual(rec["verdict"], "unknown-not-observed")
        self.assertTrue(rec["cli_reported_failure"])
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(len(self.cli.calls), 1)

    def test_two_broadcasts_after_a_cli_failure_stay_unknown(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            rpc.add(PAYER, tx(101, "P2", out=((CONTRACT, "M2"),)))

        self.cli.script["s"] = (7, "", effect)
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unknown")

    def test_cli_timeout_with_one_broadcast_is_still_unknown(self):
        self.cli.script["s"] = (None, "", settle_effect())
        with self.assertRaises(spc.Refusal):
            self.step()
        rec = self.runner.journal.result("s")
        self.assertEqual(rec["verdict"], "unknown")
        self.assertNotIn("cli_reported_failure", rec)

    def test_cli_timeout_is_unknown_even_without_a_visible_message(self):
        self.cli.script["s"] = (None, "", None)
        with self.assertRaises(spc.Refusal):
            self.step(expect_exit=1800)
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unknown")

    def test_cli_refusal_without_a_message_is_recorded_as_refused(self):
        self.cli.script["s"] = (2, "", None)
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "cli-refused")

    def test_message_not_observed_is_unknown_and_never_retried(self):
        self.cli.script["s"] = (0, "", None)
        with self.assertRaises(spc.Refusal) as cm:
            self.step()
        self.assertIn("no retry", str(cm.exception))
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unknown-not-observed")

    def test_contract_transaction_must_carry_the_payers_message_hash(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            rpc.add(CONTRACT, tx(200, "C1", in_hash="OTHER"))

        self.cli.script["s"] = (0, "", effect)
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unknown-not-observed")

    def test_unrelated_contract_row_is_not_taken_for_the_reply(self):
        def effect(rpc):
            settle_effect()(rpc)
            rpc.add(CONTRACT, tx(300, "X1", in_hash="ZZ", aborted=True, exit_code=9))

        self.cli.script["s"] = (0, "", effect)
        rec = self.step()
        self.assertEqual(rec["verdict"], "settled")
        self.assertEqual(rec["tx"]["hash"], "C1")

    def test_transactions_before_the_baseline_are_not_attributed(self):
        self.rpc.add(PAYER, tx(50, "P0", out=((CONTRACT, "M0"),)))
        self.rpc.add(CONTRACT, tx(60, "C0", in_hash="M0"))
        self.cli.script["s"] = (0, "", None)
        with self.assertRaises(spc.Refusal):
            self.step()
        rec = self.runner.journal.result("s")
        self.assertEqual(rec["verdict"], "unknown-not-observed")
        self.assertEqual(rec["before"]["payer_lt"], 50)
        self.assertEqual(rec["before"]["observe_lt"], 60)

    def test_transaction_page_that_misses_the_baseline_refuses(self):
        for i in range(10):
            self.rpc.add(PAYER, tx(1000 + i, f"P{i}"))
        with self.assertRaises(spc.Refusal):
            self.rpc.transactions_after(PAYER, 5)
        self.assertEqual(len(self.rpc.transactions_after(PAYER, 1005)), 4)

    def test_missing_on_a_confirmation_source_fails_the_claim(self):
        self.cli.script["s"] = (0, "", settle_effect(sources=(PRIMARY,)))
        with self.assertRaises(spc.Refusal):
            self.step()
        rec = self.runner.journal.result("s")
        self.assertEqual(rec["verdict"], "not-confirmed-on-all-sources")
        self.assertFalse(rec["confirmed_on"][CONFIRM])

    def test_unexpected_abort_on_a_success_step_fails(self):
        self.cli.script["s"] = (0, "", settle_effect(exit_code=1800, aborted=True))
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unexpected-abort")

    def test_action_phase_failure_on_a_success_step_fails(self):
        # Compute succeeded, the transaction was not aborted, but the action phase failed.
        self.cli.script["s"] = (0, "", settle_effect(action={"success": False}))
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unexpected-abort")

    def test_aborted_transaction_with_successful_compute_fails(self):
        # Compute exit 0 and success, no action record, but the transaction is aborted.
        self.cli.script["s"] = (0, "", settle_effect(aborted=True, success=True, action=None))
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unexpected-abort")

    def test_attempt_marker_is_exclusive_under_a_race(self):
        self.runner.journal.attempt("s", {"kind": "value"})
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.journal.attempt("s", {"kind": "value"})
        self.assertIn("already attempted", str(cm.exception))

    def test_refusal_control_green_requires_abort_code_and_unchanged_state(self):
        self.cli.script["s"] = (0, "", settle_effect(exit_code=1800, aborted=True))
        rec = self.step(expect_exit=1800, show=lambda: {"owner": "a"})
        self.assertEqual(rec["verdict"], "refused-as-intended")

    def test_refusal_control_red_when_the_contract_accepted(self):
        self.cli.script["s"] = (0, "", settle_effect())
        with self.assertRaises(spc.Refusal):
            self.step(expect_exit=1800, show=lambda: {"owner": "a"})
        self.assertEqual(self.runner.journal.result("s")["verdict"], "refusal-control-failed")

    def test_refusal_control_red_on_wrong_exit_code(self):
        self.cli.script["s"] = (0, "", settle_effect(exit_code=1801, aborted=True))
        with self.assertRaises(spc.Refusal):
            self.step(expect_exit=1800)

    def test_refusal_control_red_when_not_aborted(self):
        self.cli.script["s"] = (0, "", settle_effect(exit_code=1800, aborted=False, success=False))
        with self.assertRaises(spc.Refusal):
            self.step(expect_exit=1800)

    def test_refusal_control_red_when_protected_state_moved(self):
        states = iter([{"owner": "a"}, {"owner": "b"}])
        self.cli.script["s"] = (0, "", settle_effect(exit_code=1800, aborted=True))
        with self.assertRaises(spc.Refusal):
            self.step(expect_exit=1800, show=lambda: next(states))

    def test_two_messages_from_the_payer_to_the_contract_are_refused(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            rpc.add(PAYER, tx(101, "P2", out=((CONTRACT, "M2"),)))
            rpc.add(CONTRACT, tx(200, "C1", in_hash="M1"))

        self.cli.script["s"] = (0, "", effect)
        with self.assertRaises(spc.Refusal) as cm:
            self.step()
        self.assertIn("2 messages", str(cm.exception))
        self.assertEqual(self.runner.journal.result("s")["verdict"], "multiple-sends-observed")

    def test_drill_exits_after_the_marker_without_calling_the_cli(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH": "s"}):
            with self.assertRaises(SystemExit):
                self.step()
        attempt = self.runner.journal.attempt_record("s")
        self.assertEqual(attempt["kind"], "drill")
        self.assertIn("payer_lt", attempt["before"])
        self.assertIsNone(self.runner.journal.result("s"))
        self.assertEqual(self.cli.calls, [])

    def test_private_path_is_redacted_in_records(self):
        self.cli.script["s"] = (0, "", settle_effect())
        rec = self.runner.step(
            "s", ["agent", str(self.private / "x")], payer=PAYER, observe=CONTRACT
        )
        self.assertEqual(rec["argv"], ["agent", "<private>/x"])


class ClientSideRefusal(RunnerCase):
    def test_negative_control_refused_by_the_cli_is_recorded_not_fatal(self):
        self.cli.script["s"] = (1, "", None)
        rec = self.step(expect_exit=1800, show=lambda: {"owner": "a"})
        self.assertEqual(rec["verdict"], "cli-refused-before-broadcast")
        self.assertEqual(rec["payer_tx_after"], [])
        # Replay of that verdict is accepted without a second send.
        again = self.step(expect_exit=1800, show=lambda: {"owner": "a"})
        self.assertEqual(again["verdict"], "cli-refused-before-broadcast")
        self.assertEqual(len(self.cli.calls), 1)

    def test_negative_control_refused_by_the_cli_but_state_moved_fails(self):
        states = iter([{"owner": "a"}, {"owner": "b"}])
        self.cli.script["s"] = (1, "", None)
        with self.assertRaises(spc.Refusal):
            self.step(expect_exit=1800, show=lambda: next(states))
        self.assertEqual(self.runner.journal.result("s")["verdict"], "refusal-control-failed")

    def test_positive_step_refused_by_the_cli_stays_fatal(self):
        self.cli.script["s"] = (1, "", None)
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "cli-refused")

    def test_cli_reports_the_contract_abort_with_a_non_zero_exit(self):
        self.cli.script["s"] = (1, "", settle_effect(exit_code=1800, aborted=True))
        rec = self.step(expect_exit=1800)
        self.assertEqual(rec["verdict"], "refused-as-intended")
        self.assertTrue(rec["cli_reported_failure"])
        self.assertEqual(rec["compute"]["exit_code"], 1800)

    def test_cli_abort_report_with_the_wrong_exit_code_fails_the_control(self):
        self.cli.script["s"] = (1, "", settle_effect(exit_code=1801, aborted=True))
        with self.assertRaises(spc.Refusal):
            self.step(expect_exit=1800)
        self.assertEqual(self.runner.journal.result("s")["verdict"], "refusal-control-failed")

    def test_message_that_lands_during_the_observation_window_is_unknown(self):
        ticks = {"n": 0}
        original = self.rpc.transactions_after

        def late(address, lt, url=None):
            ticks["n"] += 1
            if ticks["n"] == 2:
                self.rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            return original(address, lt, url)

        self.cli.script["s"] = (1, "", None)
        with (
            mock.patch.object(spc, "REFUSAL_OBSERVE_S", 1.0),
            mock.patch.object(self.rpc, "transactions_after", late),
        ):
            with self.assertRaises(spc.Refusal):
                self.step(expect_exit=1800)
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unknown-not-observed")

    def test_case_verdict_flags_controls_without_receipt(self):
        v = spc.Runner.verdict(
            True,
            [
                {"label": "a", "verdict": "refused-as-intended"},
                {"label": "b", "verdict": "cli-refused-before-broadcast"},
            ],
        )
        self.assertFalse(v["pass"])
        self.assertEqual(v["controls_without_on_chain_receipt"], ["b"])
        self.assertTrue(
            spc.Runner.verdict(True, [{"label": "a", "verdict": "refused-as-intended"}])["pass"]
        )
        self.assertFalse(spc.Runner.verdict(False, [])["pass"])


class PreflightControls(RunnerCase):
    def test_green(self):
        rec = self.runner.preflight()
        self.assertEqual(rec["global_version"], spc.CP8_VERSION)
        self.assertEqual(rec["quiet_window"]["seconds_to_boundary"], 3600)

    def test_genesis_mismatch_on_a_confirmation_source_refuses(self):
        self.rpc.genesis_by_url[CONFIRM] = {"root_hash": "X" * 44, "file_hash": "Y" * 44}
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.preflight()
        self.assertIn("genesis", str(cm.exception))

    def test_other_global_version_refuses(self):
        self.rpc.version = spc.CP8_VERSION + 1
        with self.assertRaises(spc.Refusal):
            self.runner.preflight()

    def test_quiet_window_refuses_near_either_boundary_and_past_until(self):
        for ts in (SINCE, SINCE + 120, UNTIL - 300, UNTIL, UNTIL + 500):
            with mock.patch.object(spc, "now", return_value=ts):
                with self.assertRaises(spc.Refusal, msg=f"ts {ts}"):
                    self.runner.preflight()
        with mock.patch.object(spc, "now", return_value=SINCE + spc.QUIET_S):
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
        self.write_actors()

    def test_plan_matches_the_packet_and_records_the_source(self):
        plan = self.runner.plan_funding(SOURCE)
        self.assertEqual(plan["total_nanotos"], spc.tos_to_nanotos("16.0"))
        self.assertEqual(plan["funding_source"], SOURCE)
        self.assertEqual(plan["plan"][0]["operation_id"], "sc-fund-owner-20261106")
        self.assertEqual(self.runner.funding_source(), SOURCE)

    def test_record_needs_the_credit_on_every_source(self):
        self.rpc.balances[WALLETS["sc-owner"]] = spc.tos_to_nanotos("5")
        row = self.runner.record_funding("sc-owner", "5.0", "op-1")
        self.assertEqual(row["amount_nanotos"], 5 * spc.NANO)
        self.rpc.balances[WALLETS["sc-client"]] = spc.tos_to_nanotos("2.9")
        with self.assertRaises(spc.Refusal):
            self.runner.record_funding("sc-client", "3.0", "op-2")

    def test_duplicate_operation_id_and_unknown_actor_refuse(self):
        self.rpc.balances[WALLETS["sc-owner"]] = spc.tos_to_nanotos("5")
        self.runner.record_funding("sc-owner", "5.0", "op-1")
        with self.assertRaises(spc.Refusal):
            self.runner.record_funding("sc-owner", "5.0", "op-1")
        with self.assertRaises(spc.Refusal):
            self.runner.record_funding("sc-nobody", "1.0", "op-9")

    def test_ceiling_refuses_the_record_that_would_cross_it(self):
        for address in WALLETS.values():
            self.rpc.balances[address] = spc.tos_to_nanotos("100")
        self.runner.record_funding("sc-owner", "19.5", "op-1")
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.record_funding("sc-client", "0.6", "op-2")
        self.assertIn("ceiling", str(cm.exception))
        self.runner.record_funding("sc-client", "0.5", "op-3")
        self.assertEqual(self.runner.funded_total(), 20 * spc.NANO)
        with self.assertRaises(spc.Refusal):
            self.runner.plan_funding(SOURCE)

    def test_zero_or_malformed_amounts_refuse(self):
        with self.assertRaises(spc.Refusal):
            self.runner.record_funding("sc-owner", "0", "op-0")
        for bad in ("1.0000000001", "abc", "1.abc", "1_0", "-1", "", "1."):
            with self.assertRaises(spc.Refusal, msg=bad):
                spc.tos_to_nanotos(bad)

    def test_return_funds_only_to_the_recorded_source(self):
        self.runner.plan_funding(SOURCE)
        self.runner.preflight = lambda value_action=True: {}
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.return_funds("-1:" + "44" * 32)
        self.assertIn("not the recorded funding source", str(cm.exception))
        self.assertEqual(self.cli.calls, [])
        out = self.runner.return_funds(SOURCE)  # every wallet is below the keep threshold
        self.assertTrue(all("skipped" in v for v in out.values()))

    def test_activate_refuses_a_marker_without_result(self):
        self.runner.preflight = lambda value_action=True: {}
        self.rpc.states[WALLETS["sc-owner"]] = "uninit"
        self.rpc.balances[WALLETS["sc-owner"]] = spc.NANO
        self.runner.journal.attempt("activate-sc-owner", {})
        with self.assertRaises(spc.Refusal):
            self.runner.activate()
        self.assertEqual(self.cli.calls, [])


class LocalSteps(RunnerCase):
    def test_local_step_is_once_only_and_refuses_failures(self):
        self.cli.script["l"] = (0, '{"address": "0:' + "ab" * 32 + '"}', None)
        first = self.runner.local("l", "agent", "wallet", "show", want_json=True)
        again = self.runner.local("l", "agent", "wallet", "show", want_json=True)
        self.assertEqual(first, again)
        self.assertEqual(len(self.cli.calls), 1)
        self.cli.script["m"] = (4, "", None)
        with self.assertRaises(spc.Refusal):
            self.runner.local("m", "key", "add")
        with self.assertRaises(spc.Refusal):
            self.runner.local("m", "key", "add")
        self.assertEqual(len(self.cli.calls), 2)


class QuorumConfigs(RunnerCase):
    def write_config(self):
        self.cli.config = self.private / "tosctl-config.json"
        self.cli.config.write_text(
            json.dumps(
                {"chain_rpc": {"urls": [PRIMARY.rsplit("/", 1)[0] + "/"]}, "wallets": {"w": {}}}
            )
        )
        self.runner.rpc.confirms = [CONFIRM, "http://127.0.0.1:48083/jsonRPC"]

    def test_two_private_single_endpoint_configs_are_derived_once(self):
        self.write_config()
        paths = self.runner.quorum_configs()
        self.assertEqual(len(paths), 2)
        for path, url in zip(paths, self.runner.rpc.confirms):
            self.assertTrue(Path(path).is_absolute())
            self.assertEqual(Path(path).parent, self.private.resolve())
            self.assertEqual(oct(Path(path).stat().st_mode & 0o777), oct(0o600))
            derived = json.loads(Path(path).read_text())
            self.assertEqual(derived["chain_rpc"]["urls"], [url.rsplit("/", 1)[0] + "/"])
            self.assertEqual(derived["wallets"], {"w": {}})
        stamps = [Path(p).stat().st_mtime_ns for p in paths]
        self.assertEqual(self.runner.quorum_configs(), paths)
        self.assertEqual([Path(p).stat().st_mtime_ns for p in paths], stamps)

    def test_refuses_without_two_confirmation_sources(self):
        self.write_config()
        self.runner.rpc.confirms = [CONFIRM]
        with self.assertRaises(spc.Refusal):
            self.runner.quorum_configs()
        self.runner.rpc.confirms = [CONFIRM, CONFIRM, CONFIRM]
        with self.assertRaises(spc.Refusal):
            self.runner.quorum_configs()


class RetryLabel(RunnerCase):
    def test_only_a_client_side_refusal_with_nothing_sent_gets_a_retry_label(self):
        self.assertEqual(self.runner.retry_label("t"), "t")
        self.runner.journal.attempt("t", {"argv": []})
        self.runner.journal.done("t", {"verdict": "cli-refused", "payer_tx_after": []})
        self.assertEqual(self.runner.retry_label("t"), "t-retry")
        for verdict, after in (
            ("cli-refused", [{"transaction_id": {"hash": "h"}}]),
            ("cli-refused", None),
            ("unknown", []),
            ("settled", []),
            ("cli-refused-before-broadcast", []),
        ):
            label = f"u-{verdict}-{len(after or [])}-{after is None}"
            self.runner.journal.attempt(label, {"argv": []})
            self.runner.journal.done(label, {"verdict": verdict, "payer_tx_after": after})
            self.assertEqual(self.runner.retry_label(label), label, label)

    def test_a_reconciled_record_wins_over_the_done_record(self):
        self.runner.journal.attempt("t", {"argv": []})
        self.runner.journal.done("t", {"verdict": "cli-refused", "payer_tx_after": []})
        self.runner.journal.reconciled("t", {"verdict": "settled", "payer_tx_after": []})
        self.assertEqual(self.runner.retry_label("t"), "t")


class RpcOutage(RunnerCase):
    """A read outage during the post-refusal observation window proves nothing: the outcome
    stays unknown (never a client-side refusal) and the label is never retried."""

    def outage(self):
        return mock.patch.object(
            self.rpc, "transactions_after", side_effect=spc.Refusal("injected read outage")
        )

    def exercise(self, external, negative):
        self.cli.script["s"] = (1, "", None)
        with self.outage():
            with self.assertRaises(spc.Refusal):
                self.step(
                    external=external,
                    expect_exit=1800 if negative else 0,
                    show=lambda: {"owner": "a"},
                )
        record = self.runner.journal.result("s")
        self.assertEqual(record["verdict"], "unknown")
        self.assertTrue(record["broadcast_observation_failed"])
        self.assertEqual(record["payer_tx_after"], [])
        self.assertEqual(self.runner.retry_label("s"), "s")
        with self.assertRaises(spc.Refusal):
            self.step(external=external, expect_exit=1800 if negative else 0)
        self.assertEqual(self.cli.calls_count, 1)

    def test_internal_positive_step_stays_unknown(self):
        self.exercise(False, False)

    def test_internal_negative_control_stays_unknown(self):
        self.exercise(False, True)

    def test_external_positive_step_stays_unknown(self):
        self.exercise(True, False)

    def test_external_negative_control_stays_unknown(self):
        self.exercise(True, True)

    def duplicate(self, external):
        self.cli.script["s"] = (1, "", None)
        with self.outage():
            with self.assertRaises(spc.Refusal):
                self.runner.duplicate_control(
                    "s", ["agent", "x"], PAYER, CONTRACT, TARGET, external=external
                )
        record = self.runner.journal.result("s")
        self.assertEqual(record["verdict"], "unknown")
        self.assertTrue(record["broadcast_observation_failed"])
        self.assertNotIn("client_side_refusal_accepted", record)

    def test_internal_duplicate_control_stays_unknown(self):
        self.duplicate(False)

    def test_external_duplicate_control_stays_unknown(self):
        self.duplicate(True)

    def test_a_clean_observation_window_still_records_a_client_side_refusal(self):
        self.cli.script["s"] = (1, "", None)
        record = self.step(expect_exit=1800, show=lambda: {"owner": "a"})
        self.assertEqual(record["verdict"], "cli-refused-before-broadcast")
        self.assertFalse(record["broadcast_observation_failed"])

    def test_an_outage_that_clears_inside_the_window_still_leaves_unknown(self):
        """One failed read taints the whole window: the later clean polls do not restore the
        client-side verdict, because the chain was not watched for the full window."""
        self.cli.script["s"] = (1, "", None)
        real = self.rpc.transactions_after
        calls = []

        def flaky(*a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise spc.Refusal("injected read outage")
            return real(*a, **k)

        with mock.patch.object(self.rpc, "transactions_after", side_effect=flaky):
            with self.assertRaises(spc.Refusal):
                self.step(expect_exit=1800, show=lambda: {"owner": "a"})
        self.assertGreater(len(calls), 1)
        record = self.runner.journal.result("s")
        self.assertEqual(record["verdict"], "unknown")
        self.assertTrue(record["broadcast_observation_failed"])
        self.assertEqual(record["payer_tx_after"], [])


class Sc05Payout(RunnerCase):
    """SC-05 judges the agent payout from the settle transaction's own outgoing message, so a
    resumed run that replays the recorded settlement does not wait for a second payment."""

    def run_case(self, settle_out_msgs, agent_balance):
        agent = WALLETS["sc-client"]
        self.rpc.balances[agent] = agent_balance

        def step(label, argv, **kw):
            record = {"label": label, "observe": CONTRACT, "argv": list(argv)}
            if kw.get("expect_exit"):
                record["verdict"] = "refused-as-intended"
            else:
                record["verdict"] = "settled"
            if label == "sc05-settle-creator":
                record["out_msgs"] = settle_out_msgs
            return record

        self.runner.step = step
        self.runner.wait_active = lambda *a: None
        self.runner.show = lambda *a: lambda: {"status": "settled"}
        balance_reads = []
        real_balance = self.rpc.balance
        self.rpc.balance = lambda address, url=None: (
            balance_reads.append(address) or real_balance(address, url)
        )
        result = self.runner.case_sc05(WALLETS)
        return result, balance_reads

    def test_recorded_payout_to_the_agent_passes(self):
        agent = WALLETS["sc-client"]
        out = [{"destination": agent, "value": str(600_000_000), "bounced": False, "hash": "T"}]
        result, reads = self.run_case(out, agent_balance=0)
        self.assertTrue(result["agent_paid"])
        self.assertTrue(result["pass"])
        self.assertNotIn(agent, reads)

    def test_a_large_live_balance_does_not_stand_in_for_the_payout(self):
        agent = WALLETS["sc-client"]
        out = [{"destination": agent, "value": str(500_000_000), "bounced": False, "hash": "T"}]
        result, _ = self.run_case(out, agent_balance=10**12)
        self.assertFalse(result["agent_paid"])
        self.assertFalse(result["pass"])

    def test_a_bounced_payout_is_not_a_payment(self):
        agent = WALLETS["sc-client"]
        out = [{"destination": agent, "value": str(600_000_000), "bounced": True, "hash": "T"}]
        result, _ = self.run_case(out, agent_balance=10**12)
        self.assertFalse(result["agent_paid"])


class ReturnFundsReplay(RunnerCase):
    """A replayed return step reports the amount its recorded message carried."""

    def test_replayed_return_reports_the_recorded_amount(self):
        self.write_actors()
        self.runner.plan_funding(SOURCE)
        self.runner.preflight = lambda value_action=True: {}
        owner = WALLETS["sc-owner"]
        self.rpc.balances[owner] = spc.tos_to_nanotos("1.0")
        self.runner.journal.attempt("return-sc-owner", {})
        self.runner.journal.done(
            "return-sc-owner",
            {
                "verdict": "settled",
                "observe": SOURCE,
                "argv": ["wallet", "send", "--amount-nanotos", "123456789"],
                "tx": {"lt": "1", "hash": "OLD"},
            },
        )
        out = self.runner.return_funds(SOURCE)
        self.assertEqual(self.cli.calls, [])
        self.assertEqual(
            out["sc-owner"], {"returned_nanotos": 123456789, "tx": {"lt": "1", "hash": "OLD"}}
        )

    def record_round_one(self):
        self.write_actors()
        self.runner.plan_funding(SOURCE)
        self.runner.preflight = lambda value_action=True: {}
        owner = WALLETS["sc-owner"]
        self.rpc.balances[owner] = spc.tos_to_nanotos("1.0")
        self.runner.journal.attempt("return-sc-owner", {})
        self.runner.journal.done(
            "return-sc-owner",
            {
                "verdict": "settled",
                "observe": SOURCE,
                "argv": ["wallet", "send", "--amount-nanotos", "123456789"],
                "tx": {"lt": "1", "hash": "OLD"},
            },
        )
        return owner

    def test_a_second_round_uses_its_own_labels_and_sends_the_current_balance(self):
        owner = self.record_round_one()

        def effect(rpc):
            rpc.add(owner, tx(100, "P1", out=((SOURCE, "M1"),)))
            rpc.add(SOURCE, tx(200, "S1", in_hash="M1"))

        self.cli.script["return-sc-owner-r2"] = (0, "{}", effect)
        out = self.runner.return_funds(SOURCE, 2)
        self.assertEqual(len(self.cli.calls), 1)
        label, argv = self.cli.calls[0]
        self.assertEqual(label, "return-sc-owner-r2")
        self.assertEqual(
            argv[argv.index("--amount-nanotos") + 1],
            str(spc.tos_to_nanotos("1.0") - spc.tos_to_nanotos("0.05")),
        )
        self.assertEqual(out["sc-owner"]["tx"]["hash"], "S1")
        self.assertEqual(out["sc-owner"]["returned_nanotos"], spc.tos_to_nanotos("0.95"))
        self.assertTrue((self.runner.journal.steps / "return-sc-owner-r2.done.json").exists())
        # round 1 is untouched and still replays its own record
        self.assertEqual(self.runner.return_funds(SOURCE)["sc-owner"]["tx"]["hash"], "OLD")
        self.assertEqual(len(self.cli.calls), 1)

    def test_a_second_round_never_re_sends_itself_or_round_one(self):
        self.record_round_one()
        self.runner.journal.attempt("return-sc-owner-r2", {"kind": "value"})
        with self.assertRaises(spc.Refusal):
            self.runner.return_funds(SOURCE, 2)
        self.assertEqual(self.cli.calls, [])
        with self.assertRaises(spc.Refusal):
            self.runner.return_funds(SOURCE, 0)
        self.assertEqual(self.cli.calls, [])


class ReconcileDuplicate(RunnerCase):
    """A duplicate control that ended `unknown` is reconciled by the duplicate rules, never by
    the positive-step rules that would call a second payout `settled`."""

    def record(self, exit_code=1, utc=None, external=False, head=900):
        rec = {
            "verdict": "unknown",
            "exit_code": exit_code,
            "payer": PAYER,
            "observe": CONTRACT,
            "target": TARGET,
            "external": external,
            "before": {
                "head": {"seqno": head},
                "payer_lt": 50,
                "observe_lt": 60,
                "target_balance": 10**9,
            },
            "payer_tx_after": [],
            "broadcast_observation_failed": True,
        }
        if head is None:
            del rec["before"]["head"]
        if utc is not None:
            rec["utc"] = utc
        self.runner.journal.attempt("d", {})
        self.runner.journal.done("d", rec)
        self.rpc.add(PAYER, tx(50, "P0", out=((CONTRACT, "M0"),)))
        self.rpc.add(CONTRACT, tx(60, "C0", in_hash="M0"))
        self.rpc.balances[TARGET] = 10**9

    def reconcile(self):
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            return self.runner.reconcile("d")

    def test_aborted_account_transaction_is_the_intended_refusal(self):
        self.record()
        settle_effect(exit_code=1337, aborted=True)(self.rpc)
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "refused-as-intended")
        self.assertEqual(rec["transfers_to_target"], [])
        self.assertFalse(rec["target_paid_again"])
        self.assertEqual(rec["tx"]["hash"], "C1")

    def test_second_transfer_to_the_target_is_duplicate_executed(self):
        self.record()
        self.rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
        self.rpc.add(CONTRACT, tx(200, "C1", in_hash="M1", out=((TARGET, "T1"),)))
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "DUPLICATE-EXECUTED")
        self.assertEqual(rec["transfers_to_target"][0]["hash"], "T1")

    def test_a_bounce_to_the_payer_is_not_a_transfer_to_the_target(self):
        self.record()
        self.rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
        self.rpc.add(
            CONTRACT,
            tx(200, "C1", in_hash="M1", exit_code=1337, aborted=True, out=((PAYER, "B1"),)),
        )
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "refused-as-intended")
        self.assertEqual(rec["transfers_to_target"], [])

    def test_target_balance_growth_is_duplicate_executed(self):
        self.record()
        settle_effect(exit_code=0)(self.rpc)
        self.rpc.balances[TARGET] = 10**9 + spc.tos_to_nanotos("0.09")
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "DUPLICATE-EXECUTED")
        self.assertTrue(rec["target_paid_again"])

    def test_accepted_without_transfer_is_recorded_as_such(self):
        self.record()
        settle_effect(exit_code=0)(self.rpc)
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "accepted-without-transfer")

    def test_nothing_sent_after_the_window_is_a_client_side_refusal(self):
        self.record(utc=spc.utc(MID - 200))
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "cli-refused-before-broadcast")
        self.assertTrue(rec["client_side_refusal_accepted"])
        self.assertFalse(rec["target_paid_again"])
        self.assertEqual(rec["payer_tx_after"], [])
        self.assertEqual(set(rec["nothing_sent_confirmed_on"]), {PRIMARY, CONFIRM})
        self.assertEqual(self.runner.journal.result("d")["verdict"], "cli-refused-before-broadcast")

    def test_nothing_sent_inside_the_window_is_refused(self):
        # 100 s after the record is still inside the 120 s settle window.
        self.record(utc=spc.utc(MID - 100))
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("window", str(cm.exception))
        self.assertEqual(self.runner.journal.result("d")["verdict"], "unknown")

    def test_a_source_still_at_the_baseline_block_proves_nothing(self):
        # FakeRpc reports head seqno 1000 on every source; a baseline at 1000 means that
        # source has not advanced since the record and its empty answer is not evidence.
        self.record(utc=spc.utc(MID - 200), head=1000)
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("not advanced", str(cm.exception))
        self.assertEqual(self.runner.journal.result("d")["verdict"], "unknown")

    def test_a_record_without_a_baseline_block_is_refused(self):
        self.record(utc=spc.utc(MID - 200), head=None)
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("baseline block", str(cm.exception))

    def test_nothing_sent_after_a_successful_cli_stays_by_hand(self):
        self.record(exit_code=0, utc=spc.utc(MID - 200))
        with self.assertRaises(spc.Refusal):
            self.reconcile()

    def test_nothing_sent_but_target_paid_is_refused(self):
        self.record(utc=spc.utc(MID - 200))
        self.rpc.balances[TARGET] = 10**9 + spc.tos_to_nanotos("0.09")
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("target balance grew", str(cm.exception))

    def test_a_message_visible_only_on_the_confirmation_source_is_refused(self):
        self.record(utc=spc.utc(MID - 200))
        self.rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)), sources=(CONFIRM,))
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("visible", str(cm.exception))

    def test_nothing_sent_external_duplicate_is_a_client_side_refusal(self):
        self.record(utc=spc.utc(MID - 200), external=True)
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "cli-refused-before-broadcast")
        self.assertTrue(rec["external"])

    def test_an_external_arrival_visible_only_on_one_source_is_refused(self):
        self.record(utc=spc.utc(MID - 200), external=True)
        self.rpc.add(CONTRACT, tx(70, "X1", in_hash="E1", kind="external"), sources=(CONFIRM,))
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("visible", str(cm.exception))

    def test_duplicate_without_a_target_baseline_is_refused(self):
        self.record(utc=spc.utc(MID - 200))
        done = self.runner.journal.result("d")
        del done["before"]["target_balance"]
        self.runner.journal.done("d", done)
        with self.assertRaises(spc.Refusal):
            self.reconcile()


class ReconcileNothingSent(RunnerCase):
    """A step record that ended `unknown` from a failed observation window is settled read-only
    once a fresh read of every source shows that nothing left the payer."""

    def record(self, expect_exit, exit_code=1, utc=None):
        rec = {
            "verdict": "unknown",
            "exit_code": exit_code,
            "payer": PAYER,
            "observe": CONTRACT,
            "expect_exit": expect_exit,
            "before": {
                "head": {"seqno": 900},
                "payer_lt": 50,
                "observe_lt": 60,
                "state": {"owner": "a"},
            },
            "broadcast_observation_failed": True,
        }
        rec["utc"] = spc.utc(MID - 200) if utc is None else utc
        self.runner.journal.attempt("s", {})
        self.runner.journal.done("s", rec)
        self.rpc.add(PAYER, tx(50, "P0", out=((CONTRACT, "M0"),)))
        self.rpc.add(CONTRACT, tx(60, "C0", in_hash="M0"))

    def reconcile(self):
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            return self.runner.reconcile("s")

    def test_negative_control_with_an_untouched_contract_is_a_client_side_refusal(self):
        self.record(expect_exit=1800)
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "cli-refused-before-broadcast")
        self.assertNotIn("client_side_refusal_accepted", rec)
        self.assertTrue(rec["reconciled"])

    def test_negative_control_with_a_changed_contract_is_refused(self):
        self.record(expect_exit=1800)
        self.rpc.add(CONTRACT, tx(70, "C9", in_hash="X9"))
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("after the baseline", str(cm.exception))

    def test_a_contract_change_seen_only_on_the_confirmation_source_is_refused(self):
        self.record(expect_exit=1800)
        self.rpc.add(CONTRACT, tx(70, "C9", in_hash="X9"), sources=(CONFIRM,))
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("after the baseline", str(cm.exception))

    def test_positive_step_is_cli_refused(self):
        self.record(expect_exit=0)
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "cli-refused")

    def test_unreadable_timestamp_is_refused(self):
        self.record(expect_exit=0, utc="yesterday")
        with self.assertRaises(spc.Refusal):
            self.reconcile()


class WithdrawalResume(RunnerCase):
    """SC-04 resumed after its owner withdrawal settled must replay the recorded withdrawal
    against its recorded pre-withdrawal baseline, and must fence an unresolved or invalid one."""

    def record_withdrawal(self, verdict, before, amount, observe=CONTRACT, state="given"):
        record = {
            "label": "sc04-withdraw-owner",
            "verdict": verdict,
            "argv": ["--withdraw-amount", amount],
            "observe": observe,
            "before": {"state": {"withdrawable_revenue": before}},
        }
        if state == "missing":
            record["before"] = {"payer_lt": 1}
        elif state == "empty":
            record["before"] = {"state": {}}
        self.runner.journal.done("sc04-withdraw-owner", record)

    def fake_case(self, current, allow_withdrawal):
        seen = []

        def step(label, argv, **kw):
            seen.append(label)
            if label == "sc04-withdraw-owner" and not allow_withdrawal:
                raise AssertionError("unsafe withdrawal replay reached")
            previous = self.runner.journal.result(label)
            if previous:
                return previous
            verdict = "refused-as-intended" if kw.get("expect_exit") else "settled"
            return {"label": label, "observe": CONTRACT, "verdict": verdict}

        self.runner.step = step
        self.runner.wait_active = lambda *a: None
        self.runner.show = lambda *a: (
            lambda: {
                "next_request_id": 1,
                "pending_count": 0,
                "withdrawable_revenue": current,
            }
        )
        return seen

    def resume(self, before, amount, current):
        self.record_withdrawal("settled", before, amount)
        seen = self.fake_case(current, allow_withdrawal=True)
        result = self.runner.case_sc04(WALLETS)
        self.assertTrue(result["pass"])
        self.assertEqual(result["withdrawn_tos"], amount)
        self.assertIn("sc04-withdraw-owner", seen)
        self.assertEqual(self.cli.calls_count, 0)

    def test_completed_full_withdrawal_resumes(self):
        self.resume("0.05", "0.050000000", "0")

    def test_completed_partial_withdrawal_resumes(self):
        self.resume("0.25", "0.050000000", "0.20")

    def refuse(self, verdict, before, amount, **record):
        self.record_withdrawal(verdict, before, amount, **record)
        self.fake_case("0.25", allow_withdrawal=False)
        with self.assertRaises(spc.Refusal):
            self.runner.case_sc04(WALLETS)

    def test_withdrawal_recorded_without_a_baseline_state_refuses(self):
        self.refuse("settled", "0.25", "0.05", state="missing")

    def test_withdrawal_recorded_with_an_empty_baseline_state_refuses(self):
        self.refuse("settled", "0.25", "0.05", state="empty")

    def test_withdrawal_recorded_against_another_contract_refuses(self):
        self.refuse("settled", "0.25", "0.05", observe="0:" + "99" * 32)

    def test_unresolved_withdrawal_stays_fenced(self):
        self.refuse("unknown", "0.25", "0.05")

    def test_zero_recorded_withdrawal_refuses(self):
        self.refuse("settled", "0.25", "0")

    def test_recorded_amount_above_its_baseline_refuses(self):
        self.refuse("settled", "0.01", "0.05")


class ComponentPrerequisite(RunnerCase):
    """SC-08 spends nothing unless every component result is an object with a literal pass."""

    def exercise(self, failed):
        self.evidence.mkdir(exist_ok=True)
        for name in ("sc02", "sc03", "sc04", "sc05", "sc06", "sc07"):
            record = {"address": CONTRACT, "pass": True}
            if name == "sc04":
                record = failed
            (self.evidence / f"{name}-RESULT.json").write_text(json.dumps(record))
        calls = []

        def step(*a, **k):
            calls.append(a)
            raise AssertionError("value step reached before the prerequisite refusal")

        self.runner.step = step
        with self.assertRaises(spc.Refusal):
            self.runner.case_sc08(WALLETS)
        self.assertEqual(calls, [])
        self.assertEqual(self.cli.calls_count, 0)

    def test_failed_component_stops_before_spending(self):
        self.exercise({"pass": False})

    def test_missing_component_verdict_stops_before_spending(self):
        self.exercise({})

    def test_truthy_string_is_not_a_passing_verdict(self):
        self.exercise({"pass": "true"})

    def test_nonobject_component_refuses(self):
        self.exercise([])


SAMPLE_MSG = lambda: spc.boc_decode(base64.b64decode(spc.SAMPLE_AGENT_REQUEST_BOC))  # noqa: E731
SAMPLE_ACCOUNT = "0:f57374ec5b48c808d1c484acf1eff63437d1c860f251864dbec37ad1027a5599"


class BocCodec(unittest.TestCase):
    """The minimal cell codec reproduces the chain's own message hash, byte for byte."""

    def test_sample_message_hashes_to_the_chain_reported_in_msg_hash(self):
        msg = SAMPLE_MSG()
        self.assertEqual(spc.cell_hash_b64(msg), spc.SAMPLE_AGENT_REQUEST_HASH)

    def test_encoding_is_byte_identical_and_round_trips(self):
        raw = base64.b64decode(spc.SAMPLE_AGENT_REQUEST_BOC)
        msg = spc.boc_decode(raw)
        self.assertEqual(spc.boc_encode(msg), raw)
        self.assertEqual(
            spc.cell_hash_b64(spc.boc_decode(spc.boc_encode(msg))), spc.SAMPLE_AGENT_REQUEST_HASH
        )

    def test_external_message_parts_and_agent_header(self):
        parts = spc.external_message_parts(SAMPLE_MSG())
        self.assertEqual(parts["destination"], SAMPLE_ACCOUNT)
        header = spc.agent_external_header(parts["body"])
        self.assertEqual(header["global_id"], 2)
        self.assertEqual(header["controller_epoch"], 1)
        self.assertEqual(header["seqno"], 2)
        self.assertEqual(header["valid_until"], 1793940905)

    def test_flipping_the_signature_bit_changes_only_the_body_and_the_hash(self):
        msg = SAMPLE_MSG()
        bad = spc.with_flipped_signature_bit(msg)
        self.assertEqual(bad.bits, msg.bits)
        self.assertNotEqual(bad.refs[0].bits[0], msg.refs[0].bits[0])
        self.assertEqual(bad.refs[0].bits[1:], msg.refs[0].bits[1:])
        self.assertNotEqual(spc.cell_hash_b64(bad), spc.SAMPLE_AGENT_REQUEST_HASH)
        self.assertEqual(spc.external_message_parts(bad)["destination"], SAMPLE_ACCOUNT)
        self.assertEqual(
            spc.agent_external_header(bad.refs[0]), spc.agent_external_header(msg.refs[0])
        )

    def test_transaction_in_message_is_the_first_reference_of_the_first_reference(self):
        msg = SAMPLE_MSG()
        tx = spc.Cell("0111" + "0" * 60, [spc.Cell("1", [msg]), spc.Cell("", [])])
        self.assertEqual(spc.cell_hash(spc.transaction_in_message(tx)), spc.cell_hash(msg))
        with self.assertRaises(spc.Refusal):
            spc.transaction_in_message(spc.Cell("0111", [spc.Cell("0", []), spc.Cell("", [])]))

    def test_malformed_bags_are_refused(self):
        raw = base64.b64decode(spc.SAMPLE_AGENT_REQUEST_BOC)
        exotic = raw[:11] + bytes([raw[11] | 8]) + raw[12:]
        root_out_of_range = raw[:10] + bytes([raw[10] | 8]) + raw[11:]
        for bad in (raw[:-1], raw + b"\x00", b"\x00" + raw[1:], exotic, root_out_of_range):
            with self.assertRaises(spc.Refusal, msg=bad[:12].hex()):
                spc.boc_decode(bad)

    def test_invalid_bags_the_node_would_reject_are_refused_not_normalized(self):
        raw = base64.b64decode(spc.SAMPLE_AGENT_REQUEST_BOC)
        empty_cell = bytes.fromhex("b5ee9c72") + bytes([1, 1, 1, 1, 0, 2, 0]) + bytes([0, 0])
        self.assertEqual(spc.boc_decode(empty_cell).bits, "")
        shapes = {
            "overlong completion tag": empty_cell[:9]
            + b"\x03"
            + empty_cell[10:-2]
            + bytes([0, 1, 0x80]),
            "tag outside the last byte": empty_cell[:9]
            + b"\x04"
            + empty_cell[10:-2]
            + bytes([0, 3, 0x80, 0]),
            "level descriptor": empty_cell[:-2] + bytes([0x20, 0]),
            "stored hashes descriptor": empty_cell[:-2] + bytes([0x10, 0]),
            "cache bits flag": empty_cell[:4] + bytes([0x21]) + empty_cell[5:],
            "reserved flag": empty_cell[:4] + bytes([0x09]) + empty_cell[5:],
            "indexed bag": empty_cell[:4]
            + bytes([0x81])
            + empty_cell[5:10]
            + b"\x02"
            + empty_cell[10:],
            "absent cells": empty_cell[:8] + b"\x01" + empty_cell[9:],
            "total size too small": empty_cell[:9] + b"\x01" + empty_cell[10:],
            "offset size zero": empty_cell[:5] + b"\x00" + empty_cell[6:],
            "bad crc": raw[:4] + bytes([raw[4] | 0x40]) + raw[5:] + b"\x00\x00\x00\x00",
        }
        for name, bad in shapes.items():
            with self.assertRaises(spc.Refusal, msg=name):
                spc.boc_decode(bad)

    def test_a_bag_with_a_correct_crc_decodes_to_the_chain_hash(self):
        raw = base64.b64decode(spc.SAMPLE_AGENT_REQUEST_BOC)
        body = raw[:4] + bytes([raw[4] | 0x40]) + raw[5:]
        # independent table-driven crc32c reference
        table = []
        for n in range(256):
            c = n
            for _ in range(8):
                c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
            table.append(c)
        crc = 0xFFFFFFFF
        for b in body:
            crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
        crc ^= 0xFFFFFFFF
        with_crc = body + crc.to_bytes(4, "little")
        self.assertEqual(spc.cell_hash_b64(spc.boc_decode(with_crc)), spc.SAMPLE_AGENT_REQUEST_HASH)
        with self.assertRaises(spc.Refusal):
            spc.boc_decode(with_crc[:-1] + bytes([with_crc[-1] ^ 1]))

    def test_shared_cells_cycles_and_oversize_trees_are_refused_before_expansion(self):
        leaf = spc.Cell("", [])
        dag = leaf
        for _ in range(40):
            dag = spc.Cell("1", [dag, dag])
        started = time.monotonic()
        for op in (spc.cell_hash, spc.cell_depth, spc.boc_encode):
            with self.assertRaises(spc.Refusal):
                op(dag)
        self.assertLess(time.monotonic() - started, 2.0)
        loop = spc.Cell("1", [])
        loop.refs.append(loop)
        with self.assertRaises(spc.Refusal):
            spc.cell_hash(loop)
        small_shared = spc.Cell("1", [leaf, leaf])  # three cells: refused for sharing, not size
        for op in (spc.cell_hash, spc.boc_encode):
            with self.assertRaises(spc.Refusal) as cm:
                op(small_shared)
            self.assertIn("shared", str(cm.exception))
        chain = leaf
        for _ in range(200):
            chain = spc.Cell("0", [chain])
        self.assertEqual(spc.cell_depth(chain), 200)
        self.assertEqual(spc.boc_decode(spc.boc_encode(chain)).refs[0].bits, "0")
        for _ in range(60):
            chain = spc.Cell("0", [chain])
        with self.assertRaises(spc.Refusal):
            spc.boc_encode(chain)

    def test_internal_or_inline_body_messages_are_not_external_requests(self):
        msg = SAMPLE_MSG()
        internal = spc.Cell("0" + msg.bits[1:], msg.refs)
        with self.assertRaises(spc.Refusal):
            spc.external_message_parts(internal)
        inline = spc.Cell(msg.bits[:-1] + "0" + "1" * 8, [])
        with self.assertRaises(spc.Refusal):
            spc.external_message_parts(inline)


class LiveRpcReads(unittest.TestCase):
    """The new JSON-RPC reads build the exact request the node expects (no fakes here)."""

    def setUp(self):
        self.rpc = spc.Rpc(PRIMARY, [CONFIRM])
        self.requests = []

    def serve(self, result):
        outer = self

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()

        def urlopen(req, timeout=0):
            outer.requests.append((req.full_url, json.loads(req.data)))
            return Resp()

        return mock.patch.object(spc.urllib.request, "urlopen", urlopen)

    def test_run_get_method_names_the_contract_method_in_the_params(self):
        with self.serve({"exit_code": 0, "stack": [["num", "0x3"]]}):
            stack = self.rpc.run_get_method(CONTRACT, "get_agent_account_data", CONFIRM)
        self.assertEqual(stack, [["num", "0x3"]])
        url, body = self.requests[0]
        self.assertEqual(url, CONFIRM)
        self.assertEqual(body["method"], "runGetMethod")
        self.assertEqual(
            body["params"], {"address": CONTRACT, "method": "get_agent_account_data", "stack": []}
        )

    def test_run_get_method_refuses_a_nonzero_exit(self):
        with self.serve({"exit_code": 11, "stack": []}):
            with self.assertRaises(spc.Refusal):
                self.rpc.run_get_method(CONTRACT, "get_agent_account_data")

    def test_transaction_by_hash_requires_exactly_the_row_in_the_latest_page(self):
        rows = [tx(5, "T1"), tx(4, "T0")]
        with self.serve(rows):
            self.assertEqual(
                self.rpc.transaction_by_hash(CONTRACT, "T0")["transaction_id"]["lt"], "4"
            )
        self.assertEqual(self.requests[0][1]["params"], {"address": CONTRACT, "limit": 10})
        with self.serve(rows):
            with self.assertRaises(spc.Refusal):
                self.rpc.transaction_by_hash(CONTRACT, "T9")

    def test_send_boc_returns_the_node_refusal_instead_of_raising(self):
        outer = self

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {"code": -32603, "message": "exitcode=1705"},
                    }
                ).encode()

        def urlopen(req, timeout=0):
            outer.requests.append(json.loads(req.data))
            return Resp()

        with mock.patch.object(spc.urllib.request, "urlopen", urlopen):
            answer = self.rpc.send_boc("AAAA")
        self.assertEqual(answer["error"]["message"], "exitcode=1705")
        self.assertEqual(self.requests[0]["params"], {"boc": "AAAA"})


class RefusalBroadcast(RunnerCase):
    """A message the account refuses at admission: the node's own exit code, no arrival, no
    state movement, recorded once."""

    def setUp(self):
        super().setUp()
        self.msg = SAMPLE_MSG()
        self.sent = []
        self.states = {PRIMARY: {"seqno": 3, "controller_epoch": 1, "spent_today": 0}}
        self.states[CONFIRM] = dict(self.states[PRIMARY])
        self.answer = {
            "error": {
                "code": -32603,
                "message": "sendBoc failed: ... exitcode=1705, steps=50",
                "data": None,
            }
        }
        self.rpc.send_boc = lambda boc, url=None: self.sent.append(boc) or self.answer
        self.runner.agent_account_state = lambda account, url=None: dict(
            self.states[url or PRIMARY]
        )
        self.runner.guards = lambda: {}

    def broadcast(self, expect=1705):
        return self.runner.refusal_broadcast("r", self.msg, SAMPLE_ACCOUNT, expect)

    def test_expected_exit_code_with_an_unchanged_account_is_refused_at_admission(self):
        rec = self.broadcast()
        self.assertEqual(rec["verdict"], "refused-at-admission")
        self.assertTrue(rec["admission_refused_with_expected_exit"])
        self.assertEqual(rec["message_hash"], spc.SAMPLE_AGENT_REQUEST_HASH)
        self.assertEqual(rec["arrivals"], {PRIMARY: 0, CONFIRM: 0})
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(base64.b64decode(self.sent[0]), spc.boc_encode(self.msg))
        self.assertEqual(self.runner.journal.result("r")["verdict"], "refused-at-admission")

    def test_an_exit_code_that_merely_starts_with_the_expected_digits_fails(self):
        self.answer = {
            "error": {"code": -32603, "message": "sendBoc failed: exitcode=17050, steps=1"}
        }
        with self.assertRaises(spc.Refusal):
            self.broadcast()
        rec = self.runner.journal.result("r")
        self.assertEqual(rec["admission_exit_code"], 17050)
        self.assertEqual(rec["verdict"], "refusal-control-failed")
        self.assertIsNone(spc.admission_exit_code("rejected, no code"))
        self.assertEqual(spc.admission_exit_code("x exitcode=-13 y"), -13)

    def test_a_different_exit_code_fails_the_control(self):
        with self.assertRaises(spc.Refusal):
            self.broadcast(expect=1704)
        self.assertEqual(self.runner.journal.result("r")["verdict"], "refusal-control-failed")

    def test_an_accepted_broadcast_is_the_failure_even_without_an_arrival_yet(self):
        self.answer = {"result": {"status": 1}}
        with self.assertRaises(spc.Refusal):
            self.broadcast()
        self.assertEqual(self.runner.journal.result("r")["verdict"], "refusal-control-failed")

    def test_an_arrival_inside_the_window_is_executed(self):
        def accept_and_execute(boc, url=None):
            self.rpc.add(SAMPLE_ACCOUNT, tx(10, "X1", in_hash="E1", kind="external"))
            return self.answer

        self.rpc.send_boc = accept_and_execute
        with self.assertRaises(spc.Refusal):
            self.broadcast()
        self.assertEqual(self.runner.journal.result("r")["verdict"], "EXECUTED-OR-STATE-MOVED")

    def test_a_state_move_on_one_source_is_the_failure(self):
        calls = []

        def state(account, url=None):
            calls.append(url)
            moved = len(calls) > 2 and url == CONFIRM
            return {"seqno": 4 if moved else 3, "controller_epoch": 1, "spent_today": 0}

        self.runner.agent_account_state = state
        with self.assertRaises(spc.Refusal):
            self.broadcast()
        self.assertEqual(self.runner.journal.result("r")["verdict"], "EXECUTED-OR-STATE-MOVED")

    def test_a_recorded_refusal_replays_without_a_second_broadcast(self):
        self.broadcast()
        rec = self.broadcast()
        self.assertEqual(rec["verdict"], "refused-at-admission")
        self.assertEqual(len(self.sent), 1)

    def test_a_failed_record_or_a_bare_marker_is_never_re_broadcast(self):
        with self.assertRaises(spc.Refusal):
            self.broadcast(expect=1704)
        with self.assertRaises(spc.Refusal):
            self.broadcast(expect=1704)
        self.assertEqual(len(self.sent), 1)
        self.runner.journal.attempt("m", {})
        with self.assertRaises(spc.Refusal):
            self.runner.refusal_broadcast("m", self.msg, SAMPLE_ACCOUNT, 1705)
        self.assertEqual(len(self.sent), 1)


class Sc03xGates(RunnerCase):
    """SC-03x replays only a request that can no longer execute, bound to the chain's hash."""

    def setUp(self):
        super().setUp()
        self.evidence.mkdir(exist_ok=True)
        (self.evidence / "sc03-RESULT.json").write_text(
            json.dumps({"account": SAMPLE_ACCOUNT, "agent_wallet": PAYER, "pass": True})
        )
        self.runner.journal.attempt("sc03-task-send-2-retry", {})
        self.runner.journal.done(
            "sc03-task-send-2-retry",
            {
                "verdict": "settled",
                "external": True,
                "tx": {"lt": "5", "hash": "T"},
                "in_msg_hash": spc.SAMPLE_AGENT_REQUEST_HASH,
            },
        )
        raw_tx = spc.boc_encode(
            spc.Cell("0111" + "0" * 60, [spc.Cell("1", [SAMPLE_MSG()]), spc.Cell("", [])])
        )
        self.row = {
            "data": base64.b64encode(raw_tx).decode(),
            "in_msg": {"hash": spc.SAMPLE_AGENT_REQUEST_HASH},
        }
        self.rpc.transaction_by_hash = lambda address, h, url=None: self.row
        self.state = {"seqno": 3, "controller_epoch": 1, "spent_today": 0}
        self.runner.agent_account_state = lambda account, url=None: dict(self.state)
        self.broadcasts = []
        self.runner.refusal_broadcast = lambda label, msg, account, expect: (
            self.broadcasts.append(label)
            or {
                "label": label,
                "verdict": "refused-at-admission",
                "expect_exit": expect,
            }
        )
        self.runner.local = lambda *a, **k: None
        self.runner.step = lambda label, argv, **kw: {"label": label, "verdict": "settled"}

    def test_a_still_current_request_is_never_broadcast(self):
        self.state["seqno"] = 2
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03x(WALLETS)
        self.assertIn("still current", str(cm.exception))
        self.assertEqual(self.broadcasts, [])

    def test_a_hash_mismatch_with_the_chain_stops_before_any_broadcast(self):
        self.row = {**self.row, "in_msg": {"hash": "other"}}
        with self.assertRaises(spc.Refusal):
            self.runner.case_sc03x(WALLETS)
        self.assertEqual(self.broadcasts, [])

    def test_a_rotation_that_does_not_advance_the_epoch_stops_before_the_stale_replay(self):
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03x(WALLETS)
        self.assertIn("epoch did not advance", str(cm.exception))
        self.assertEqual(self.broadcasts, ["sc03x-replay", "sc03x-wrong-signer"])

    def test_a_future_controller_epoch_in_the_request_is_never_broadcast(self):
        self.state["seqno"] = 3
        self.state["controller_epoch"] = 0  # the request names epoch 1
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03x(WALLETS)
        self.assertIn("still current", str(cm.exception))
        self.assertEqual(self.broadcasts, [])

    def test_the_pre_rotation_state_is_recorded_before_the_rotation(self):
        with self.assertRaises(spc.Refusal):
            self.runner.case_sc03x(WALLETS)
        pre = self.runner.journal.result("sc03x-rotation-pre-state")
        self.assertEqual(pre["state"], {"seqno": 3, "controller_epoch": 1, "spent_today": 0})

    def test_a_resumed_run_after_the_rotation_reaches_the_same_verdict(self):
        self.runner.journal.attempt("sc03x-rotation-pre-state", {"kind": "local"})
        self.runner.journal.done(
            "sc03x-rotation-pre-state",
            {"exit_code": 0, "state": {"seqno": 3, "controller_epoch": 1, "spent_today": 0}},
        )
        self.state["controller_epoch"] = 2  # the live account already carries the rotation
        out = self.runner.case_sc03x(WALLETS)
        self.assertTrue(out["pass"])
        self.assertEqual(len(self.broadcasts), 3)

    def test_a_resumed_run_whose_rotation_never_landed_refuses(self):
        self.runner.journal.attempt("sc03x-rotation-pre-state", {"kind": "local"})
        self.runner.journal.done(
            "sc03x-rotation-pre-state",
            {"exit_code": 0, "state": {"seqno": 3, "controller_epoch": 1, "spent_today": 0}},
        )
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03x(WALLETS)
        self.assertIn("epoch did not advance", str(cm.exception))

    def test_full_journey_passes_with_three_admission_refusals(self):
        reads = []

        def state(account, url=None):
            reads.append(1)
            return {"seqno": 3, "controller_epoch": 1 if len(reads) == 1 else 2, "spent_today": 0}

        self.runner.agent_account_state = state
        out = self.runner.case_sc03x(WALLETS)
        self.assertTrue(out["pass"])
        self.assertEqual(
            self.broadcasts, ["sc03x-replay", "sc03x-wrong-signer", "sc03x-replay-stale-controller"]
        )
        self.assertEqual(out["original"]["header"]["seqno"], 2)
        self.assertEqual(out["controls"]["sc03x-replay"]["expect_exit"], spc.AGENT_BAD_SEQNO)
        self.assertEqual(
            out["controls"]["sc03x-wrong-signer"]["expect_exit"], spc.AGENT_BAD_SIGNATURE
        )
        self.assertEqual(
            out["controls"]["sc03x-replay-stale-controller"]["expect_exit"],
            spc.AGENT_STALE_CONTROLLER,
        )
        self.assertEqual(out["expiry_control"]["status"], "not-run")


class Sc05xDuplicateSettle(RunnerCase):
    """A second settle of the settled SC-05 task must abort with exit 104 and pay nothing."""

    def setUp(self):
        super().setUp()
        self.evidence.mkdir(exist_ok=True)
        (self.evidence / "sc05-RESULT.json").write_text(
            json.dumps({"address": CONTRACT, "pass": True})
        )
        self.status = "settled"
        self.runner.show = lambda *a: lambda: {"status": self.status}
        self.steps = []

    def fake_step(self, out_msgs):
        def step(label, argv, **kw):
            self.steps.append((label, argv, kw.get("expect_exit")))
            return {
                "label": label,
                "verdict": "refused-as-intended" if kw.get("expect_exit") else "settled",
                "out_msgs": out_msgs,
            }

        self.runner.step = step

    def test_refused_duplicate_without_a_payout_passes(self):
        self.fake_step([{"destination": WALLETS["sc-owner"], "value": "1046613", "bounced": True}])
        out = self.runner.case_sc05x(WALLETS)
        self.assertTrue(out["pass"])
        self.assertFalse(out["agent_paid_again"])
        label, argv, expect = self.steps[0]
        self.assertEqual(label, "sc05x-settle-again")
        self.assertEqual(expect, spc.TASK_SETTLE_NOT_SUBMITTED)
        self.assertEqual(argv[argv.index("--from") + 1], "sc-owner")
        self.assertEqual(argv[argv.index("--operation") + 1], "settle")

    def test_a_second_payout_fails_the_case(self):
        self.fake_step(
            [{"destination": WALLETS["sc-client"], "value": "600000000", "bounced": False}]
        )
        out = self.runner.case_sc05x(WALLETS)
        self.assertTrue(out["agent_paid_again"])
        self.assertFalse(out["pass"])

    def test_even_a_tiny_second_payout_fails_the_case(self):
        self.fake_step(
            [{"destination": WALLETS["sc-client"], "value": "10000000", "bounced": False}]
        )
        out = self.runner.case_sc05x(WALLETS)
        self.assertTrue(out["agent_paid_again"])
        self.assertFalse(out["pass"])

    def test_a_task_that_is_not_settled_is_the_wrong_premise(self):
        self.status = "result_submitted"
        self.fake_step([])
        with self.assertRaises(spc.Refusal):
            self.runner.case_sc05x(WALLETS)
        self.assertEqual(self.steps, [])


class AfterSendDrill(RunnerCase):
    """The after-send drill exits once the CLI has returned, leaving a marker and no record; the
    recovery reconciles the marker read-only and never calls the CLI again."""

    def test_the_process_is_lost_after_the_cli_returned(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH_AFTER_SEND": "s"}):
            with self.assertRaises(SystemExit):
                self.step()
        self.assertEqual(self.cli.calls_count, 1)
        marker = self.runner.journal.attempt_record("s")
        self.assertEqual(marker["kind"], "drill-after-send")
        self.assertIsNone(self.runner.journal.result("s"))

    def test_the_marker_is_reconciled_from_the_exact_message_and_replayed(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH_AFTER_SEND": "s"}):
            self.cli.script["s"] = (0, "{}", settle_effect())
            with self.assertRaises(SystemExit):
                self.step()
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            rec = self.runner.reconcile_attempt("s")
        self.assertEqual(rec["verdict"], "settled")
        self.assertFalse(rec["re_sent"])
        self.assertEqual(rec["reconciled_from"], "attempt-without-result")
        self.assertEqual(rec["tx"]["hash"], "C1")
        self.assertEqual(rec["in_msg_hash"], "M1")
        self.assertEqual(rec["argv"], ["agent", "x"])
        replay = self.step()
        self.assertEqual(replay["verdict"], "settled")
        self.assertEqual(replay["tx"]["hash"], "C1")
        self.assertEqual(self.cli.calls_count, 1)

    def test_nothing_on_chain_stays_by_hand_and_is_not_re_sent(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH_AFTER_SEND": "s"}):
            with self.assertRaises(SystemExit):
                self.step()
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal):
                self.runner.reconcile_attempt("s")
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.cli.calls_count, 1)
        self.assertIsNone(self.runner.journal.result("s"))

    def test_two_payer_sends_after_the_marker_stay_by_hand(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH_AFTER_SEND": "s"}):
            self.cli.script["s"] = (0, "{}", settle_effect())
            with self.assertRaises(SystemExit):
                self.step()
        self.rpc.add(PAYER, tx(300, "P2", out=((CONTRACT, "M2"),)))
        self.rpc.add(CONTRACT, tx(400, "C2", in_hash="M2"))
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal) as cm:
                self.runner.reconcile_attempt("s")
        self.assertIn("per source", str(cm.exception))
        self.assertIn(": 2", str(cm.exception))
        self.assertIsNone(self.runner.journal.result("s"))

    def test_a_second_message_visible_only_on_the_confirmation_source_stays_by_hand(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH_AFTER_SEND": "s"}):
            self.cli.script["s"] = (0, "{}", settle_effect())
            with self.assertRaises(SystemExit):
                self.step()
        self.rpc.add(PAYER, tx(300, "P2", out=((CONTRACT, "M2"),)), sources=(CONFIRM,))
        self.rpc.add(CONTRACT, tx(400, "C2", in_hash="M2"), sources=(CONFIRM,))
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal) as cm:
                self.runner.reconcile_attempt("s")
        self.assertIn(CONFIRM + "': 2", str(cm.exception))
        self.assertIsNone(self.runner.journal.result("s"))

    def test_two_messages_inside_one_payer_transaction_stay_by_hand(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH_AFTER_SEND": "s"}):

            def effect(rpc):
                rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"), (CONTRACT, "M2"))))
                rpc.add(CONTRACT, tx(200, "C1", in_hash="M1"))

            self.cli.script["s"] = (0, "{}", effect)
            with self.assertRaises(SystemExit):
                self.step()
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal):
                self.runner.reconcile_attempt("s")
        self.assertIsNone(self.runner.journal.result("s"))

    def test_sources_that_disagree_on_the_message_or_the_transaction_stay_by_hand(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH_AFTER_SEND": "s"}):

            def effect(rpc):
                rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)), sources=(PRIMARY,))
                rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M9"),)), sources=(CONFIRM,))
                rpc.add(CONTRACT, tx(200, "C1", in_hash="M1"), sources=(PRIMARY,))
                rpc.add(CONTRACT, tx(200, "C1", in_hash="M9"), sources=(CONFIRM,))

            self.cli.script["s"] = (0, "{}", effect)
            with self.assertRaises(SystemExit):
                self.step()
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal) as cm:
                self.runner.reconcile_attempt("s")
            self.assertIn("disagree on the payer's message", str(cm.exception))
            # same message, different contract transaction on the confirmation source
            self.rpc.rows[CONFIRM][PAYER] = [tx(100, "P1", out=((CONTRACT, "M1"),))]
            self.rpc.rows[CONFIRM][CONTRACT] = [tx(200, "C9", in_hash="M1")]
            with self.assertRaises(spc.Refusal) as cm:
                self.runner.reconcile_attempt("s")
            self.assertIn("disagree on the contract transaction", str(cm.exception))
        self.assertIsNone(self.runner.journal.result("s"))

    def external_marker(self):
        self.runner.journal.attempt(
            "x",
            {
                "kind": "drill-after-send",
                "payer": PAYER,
                "observe": CONTRACT,
                "external": True,
                "argv": ["agent", "x"],
                "before": {"payer_lt": 0, "observe_lt": 0, "observe_balance": 0},
            },
        )

    def test_external_arrival_is_reconciled_only_when_every_source_names_one_transaction(self):
        self.external_marker()
        self.rpc.add(CONTRACT, tx(200, "C1", in_hash="E1", kind="external"))
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            rec = self.runner.reconcile_attempt("x")
        self.assertEqual(rec["verdict"], "settled")
        self.assertEqual(rec["in_msg_hash"], "E1")
        self.assertEqual(rec["located_per_source"], {PRIMARY: 1, CONFIRM: 1})

    def test_external_arrival_with_a_different_transaction_on_a_source_stays_by_hand(self):
        self.external_marker()
        self.rpc.add(CONTRACT, tx(200, "C1", in_hash="E1", kind="external"), sources=(PRIMARY,))
        self.rpc.add(CONTRACT, tx(200, "C2", in_hash="E1", kind="external"), sources=(CONFIRM,))
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal) as cm:
                self.runner.reconcile_attempt("x")
        self.assertIn("disagree on the contract transaction", str(cm.exception))
        self.rpc.rows[CONFIRM][CONTRACT] = [
            tx(200, "C1", in_hash="E1", kind="external"),
            tx(210, "C3", in_hash="E3", kind="external"),
        ]
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal):
                self.runner.reconcile_attempt("x")
        self.assertIsNone(self.runner.journal.result("x"))

    def test_two_messages_or_a_missing_confirmation_stay_by_hand(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH_AFTER_SEND": "s"}):
            self.cli.script["s"] = (0, "{}", settle_effect(sources=(PRIMARY,)))
            with self.assertRaises(SystemExit):
                self.step()
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal):
                self.runner.reconcile_attempt("s")
            self.rpc.add(PAYER, tx(300, "P2", out=((CONTRACT, "M2"),)))
            with self.assertRaises(spc.Refusal):
                self.runner.reconcile_attempt("s")
        self.assertIsNone(self.runner.journal.result("s"))

    def test_a_marker_that_already_has_a_result_is_not_reconciled_twice(self):
        self.cli.script["s"] = (0, "{}", settle_effect())
        self.step()
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal):
                self.runner.reconcile_attempt("s")

    def test_a_negative_control_marker_is_judged_by_its_expected_exit(self):
        with mock.patch.dict(os.environ, {"SC_DRILL_CRASH_AFTER_SEND": "s"}):
            self.cli.script["s"] = (0, "{}", settle_effect(exit_code=104, aborted=True))
            with self.assertRaises(SystemExit):
                self.step(expect_exit=104, show=lambda: {"status": "settled"})
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            rec = self.runner.reconcile_attempt("s")
        self.assertEqual(rec["verdict"], "refused-as-intended")


class Sc08xJourney(RunnerCase):
    """SC-08x binds the component contracts into the task's hashes and recovers the resolve
    from an after-send marker without re-sending."""

    def setUp(self):
        super().setUp()
        self.write_actors()
        self.evidence.mkdir(exist_ok=True)
        for i, name in enumerate(("sc02", "sc03", "sc04", "sc05", "sc06", "sc07")):
            addr = f"0:{i + 1:02x}" + "ab" * 31
            (self.evidence / f"{name}-RESULT.json").write_text(
                json.dumps({"address": addr, "pass": True})
            )
            self.rpc.add(addr, tx(100 + i, f"L{i}"))
        self.rpc.balances[WALLETS["sc-owner"]] = spc.tos_to_nanotos("2")
        self.sent = []
        self.state = {"status": "settled"}

        def fake_step(label, argv, payer, observe, expect_exit=0, want_json=False, show=None):
            self.sent.append((label, list(argv)))
            previous = self.runner.journal.result(label)
            if previous:
                return previous
            return {
                "label": label,
                "observe": CONTRACT,
                "verdict": "refused-as-intended" if expect_exit else "settled",
                "tx": {"lt": "1", "hash": "R"},
                "in_msg_hash": "MR",
            }

        self.runner.step = fake_step
        self.runner.show = lambda *argv: lambda: dict(self.state)
        self.runner.wait_active = lambda address, what: None

    def run_case(self):
        out = self.runner.case_sc08x(WALLETS)
        bindings = out["bindings"]
        self.state.update(
            {k: bindings[k] for k in ("result_hash", "evidence_hash", "dispute_hash")}
        )
        return out

    def test_bindings_come_from_the_components_and_are_stored_once(self):
        out = self.run_case()
        b = out["bindings"]
        self.assertEqual(set(b["anchors"]), {"sc02", "sc03", "sc04", "sc05", "sc06", "sc07"})
        self.assertEqual(b["anchors"]["sc02"]["hash"], "L0")
        preimage = "|".join(
            f"{n}:{a['address']}:{a['lt']}:{a['hash']}" for n, a in sorted(b["anchors"].items())
        )
        self.assertEqual(b["preimage"], preimage)
        self.assertEqual(
            b["result_hash"], hashlib.sha256(f"sc08x-result|{preimage}".encode()).hexdigest()
        )
        self.assertNotEqual(b["result_hash"], b["evidence_hash"])
        result_argv = dict(self.sent)["sc08x-result"]
        self.assertEqual(result_argv[result_argv.index("--result-hash") + 1], b["result_hash"])
        self.assertEqual(self.runner.journal.result("sc08x-bindings")["bindings"], b)
        # a later component transaction does not move the stored bindings
        self.rpc.add(b["anchors"]["sc02"]["address"], tx(500, "L9"))
        self.assertEqual(self.runner.component_bindings({}), b)

    def test_final_state_must_carry_the_bound_hashes(self):
        out = self.runner.case_sc08x(WALLETS)  # state lacks the hashes
        self.assertFalse(out["bindings_on_chain"])
        self.assertFalse(out["pass"])

    def test_bound_hashes_without_the_lost_reply_evidence_do_not_pass(self):
        self.run_case()
        self.sent.clear()
        out = self.runner.case_sc08x(WALLETS)
        self.assertTrue(out["bindings_on_chain"])
        self.assertEqual(out["lost_reply_drill"], "not-exercised")
        self.assertFalse(out["lost_reply_recovered_after_forward"])
        self.assertFalse(out["pass"])

    def test_a_rerun_reads_the_lost_reply_evidence_from_the_durable_record(self):
        self.drill_marker_and_fake_reconcile()
        first = self.run_case()
        self.assertFalse(first["pass"])  # the state did not carry the hashes yet
        second = self.runner.case_sc08x(WALLETS)
        self.assertTrue(second["pass"])
        self.assertEqual(second["lost_reply_drill"], "reconciled-after-forward")
        self.assertTrue(second["lost_reply_recovered_after_forward"])
        third = self.runner.case_sc08x(WALLETS)
        self.assertEqual(third["lost_reply_drill"], "reconciled-after-forward")
        self.assertTrue(third["pass"])

    def drill_marker_and_fake_reconcile(self):
        reconciled = []

        def reconcile_attempt(label):
            reconciled.append(label)
            self.runner.journal.done(
                label,
                {
                    "verdict": "settled",
                    "re_sent": False,
                    "reconciled_from": "attempt-without-result",
                },
            )
            return self.runner.journal.result(label)

        self.runner.reconcile_attempt = reconcile_attempt
        self.runner.journal.attempt(
            "sc08x-resolve-verifier", {"kind": "drill-after-send", "before": {"payer_lt": 0}}
        )
        return reconciled

    def test_after_send_marker_is_reconciled_and_never_re_sent(self):
        reconciled = self.drill_marker_and_fake_reconcile()
        out = self.run_case()
        self.assertEqual(reconciled, ["sc08x-resolve-verifier"])
        self.assertEqual(out["lost_reply_drill"], "reconciled-after-forward")
        self.assertEqual(out["resolve"]["re_sent"], False)

    def test_a_plain_marker_without_result_is_by_hand(self):
        reconciled = []
        self.runner.reconcile_attempt = lambda label: reconciled.append(label)
        self.runner.journal.attempt(
            "sc08x-resolve-verifier", {"kind": "value", "before": {"payer_lt": 0}}
        )
        with self.assertRaises(spc.Refusal) as cm:
            self.run_case()
        self.assertIn("not the after-send drill", str(cm.exception))
        self.assertEqual(reconciled, [])
        self.assertNotIn("sc08x-resolve-verifier", [label for label, _ in self.sent])

    def test_underfunded_creator_stops_before_the_create(self):
        self.rpc.balances[WALLETS["sc-owner"]] = spc.tos_to_nanotos("1.0")
        with self.assertRaises(spc.Refusal):
            self.run_case()
        self.assertEqual(self.sent, [])


class DrillRecovery(RunnerCase):
    """The lost-reply recovery of SC-08 re-sends only when the marker is the drill's and the
    chain is provably untouched after it."""

    def setUp(self):
        super().setUp()
        self.write_actors()
        self.evidence.mkdir(exist_ok=True)
        for name in ("sc02", "sc03", "sc04", "sc05", "sc06", "sc07"):
            (self.evidence / f"{name}-RESULT.json").write_text(
                json.dumps({"address": CONTRACT, "pass": True})
            )
        self.sent = []
        runner = self.runner

        def fake_step(label, argv, payer, observe, expect_exit=0, want_json=False, show=None):
            self.sent.append(label)
            return {"label": label, "observe": CONTRACT, "verdict": "settled"}

        runner.step = fake_step
        runner.show = lambda *argv: lambda: {"status": "settled"}
        runner.wait_active = lambda address, what: None
        self.verifier = WALLETS["sc-verifier"]

    def run_case(self):
        return self.runner.case_sc08(WALLETS)

    def test_first_run_sends_the_resolve_under_the_drill_label(self):
        self.run_case()
        self.assertIn("sc08-resolve-verifier", self.sent)
        self.assertNotIn("sc08-resolve-verifier-2", self.sent)

    def test_drill_marker_with_untouched_chain_re_sends_under_a_new_label(self):
        self.runner.journal.attempt(
            "sc08-resolve-verifier", {"kind": "drill", "before": {"payer_lt": 0, "observe_lt": 0}}
        )
        out = self.run_case()
        self.assertEqual(out["lost_reply_drill"], "reconciled")
        self.assertIn("sc08-resolve-verifier-2", self.sent)
        self.assertNotIn("sc08-resolve-verifier", self.sent)
        rec = self.runner.journal.result("sc08-resolve-verifier")
        self.assertEqual(rec["verdict"], "lost-reply-reconciled")
        self.assertFalse(rec["re_sent"])

    def test_real_crash_marker_is_never_re_sent(self):
        self.runner.journal.attempt(
            "sc08-resolve-verifier", {"kind": "value", "before": {"payer_lt": 0, "observe_lt": 0}}
        )
        with self.assertRaises(spc.Refusal):
            self.run_case()
        self.assertNotIn("sc08-resolve-verifier-2", self.sent)
        self.assertEqual(
            self.runner.journal.result("sc08-resolve-verifier")["verdict"], "lost-reply-unresolved"
        )

    def test_drill_marker_with_a_transaction_after_it_is_never_re_sent(self):
        self.runner.journal.attempt(
            "sc08-resolve-verifier", {"kind": "drill", "before": {"payer_lt": 0, "observe_lt": 0}}
        )
        self.rpc.add(self.verifier, tx(10, "V1", out=((CONTRACT, "MV"),)))
        with self.assertRaises(spc.Refusal):
            self.run_case()
        self.assertNotIn("sc08-resolve-verifier-2", self.sent)


class CasePlans(unittest.TestCase):
    """Every case's argument vectors against the pinned CLI's own flag inventory."""

    @classmethod
    def setUpClass(cls):
        cls.flags = json.loads((DATA / "service-public-cases-cli-flags.json").read_text())
        args = spc.build_parser().parse_args(
            [
                "--private-dir",
                "/nonexistent",
                "--evidence-dir",
                "/nonexistent",
                "--cli",
                "/x",
                "--cli-sha256",
                cls.flags["cli_sha256"],
                "--rpc",
                PRIMARY,
                "--genesis-root",
                "r",
                "--genesis-file",
                "f",
                "status",
            ]
        )
        cls.args = args

    def plan(self, name):
        planner = spc.PlanRunner(self.args, WALLETS)
        planner.case_fn(name)(planner.wallets)
        return planner.recorded

    def check(self, planned):
        checker = spc.Runner.__new__(spc.Runner)
        checker.args = self.args
        checker.check_flags(planned, self.flags)

    # Cases that need a CLI newer than the pinned one; the pinned fixture must refuse them.
    NEEDS_NEWER_CLI = {"sc03e"}

    def test_every_case_plans_and_matches_the_cli_flags(self):
        for name in spc.Runner.CASES:
            if name in self.NEEDS_NEWER_CLI:
                continue
            planned = self.plan(name)
            self.assertTrue(planned, name)
            self.check(planned)
            for item in planned:
                for token in item["argv"]:
                    if len(token) == 64:
                        self.assertRegex(token, r"^[0-9a-f]{64}$", item["label"])

    def test_flag_check_is_red_for_an_unknown_flag_or_operation_or_binary(self):
        planned = [{"label": "x", "argv": ["agent", "task", "send", "--nonsense", "1"]}]
        with self.assertRaises(spc.Refusal):
            self.check(planned)
        planned = [{"label": "x", "argv": ["agent", "dispute", "send", "--operation", "fly"]}]
        with self.assertRaises(spc.Refusal):
            self.check(planned)
        with self.assertRaises(spc.Refusal):
            checker = spc.Runner.__new__(spc.Runner)
            checker.args = self.args
            checker.check_flags([], {**self.flags, "cli_sha256": "other"})

    def test_task_parameters_respect_the_contract_minimums(self):
        for name in ("sc05", "sc08"):
            creates = [p for p in self.plan(name) if p["argv"][:3] == ["agent", "task", "create"]]
            self.assertEqual(len(creates), 1)
            argv = creates[0]["argv"]
            review = int(argv[argv.index("--review-period") + 1])
            self.assertGreaterEqual(review, spc.TASK_MIN_REVIEW_PERIOD_S)
            deadline = int(argv[argv.index("--deadline") + 1])
            self.assertGreater(deadline, spc.now() + review)
            sends = [p for p in self.plan(name) if p["argv"][:3] == ["agent", "task", "send"]]
            for s in sends:
                self.assertNotIn("--amount", s["argv"], s["label"])

    def test_service_parameters_follow_the_quoted_terms(self):
        planned = self.plan("sc04")
        deploy = [p for p in planned if p["argv"][:3] == ["agent", "service", "deploy"]][0]
        argv = deploy["argv"]
        amount = spc.tos_to_nanotos(argv[argv.index("--amount") + 1])
        self.assertGreaterEqual(amount, spc.tos_to_nanotos("1.2"))
        storage = spc.tos_to_nanotos(argv[argv.index("--storage-fee") + 1])
        bounty = spc.tos_to_nanotos(argv[argv.index("--cleanup-bounty") + 1])
        self.assertGreaterEqual(storage, spc.tos_to_nanotos("0.1") + bounty)
        self.assertGreaterEqual(int(argv[argv.index("--response-sla") + 1]), 3600)
        self.assertGreaterEqual(int(argv[argv.index("--refund-claim-window") + 1]), 3600)
        for s in planned:
            if s["argv"][:3] == ["agent", "service", "send"]:
                self.assertNotIn("--amount", s["argv"], s["label"])
        withdraw = [
            p for p in planned if "withdraw-revenue" in p["argv"] and p["expect_exit"] == 0
        ][0]
        amount = spc.tos_to_nanotos(
            withdraw["argv"][withdraw["argv"].index("--withdraw-amount") + 1]
        )
        self.assertLessEqual(amount, spc.SERVICE_WITHDRAW_CAP)

    def test_sc03_resolves_each_task_send_through_the_custody_journal(self):
        planned = self.plan("sc03")
        labels = [p["label"] for p in planned]
        for n in ("1", "2"):
            send = labels.index(f"sc03-task-send-{n}")
            resolve = labels.index(f"sc03-task-send-{n}-resolve")
            self.assertLess(send, resolve)
            sent = planned[send]["argv"]
            resolving = planned[resolve]["argv"]
            self.assertEqual(resolving[:3], ["agent", "account", "task-send-resolve"])
            self.assertFalse(planned[resolve]["value"])
            self.assertEqual(
                resolving[resolving.index("--action-id") + 1], sent[sent.index("--action-id") + 1]
            )
            q = resolving.index("--quorum-config")
            self.assertEqual(len(resolving[q + 1 :]), 2)
            self.assertTrue(all(Path(x).is_absolute() for x in resolving[q + 1 :]))
        self.assertLess(labels.index("sc03-task-send-1-resolve"), labels.index("sc03-task-send-2"))

    def test_every_negative_control_pins_a_contract_exit_code(self):
        for name in spc.Runner.CASES:
            for item in self.plan(name):
                if item["value"]:
                    self.assertIsInstance(item["expect_exit"], int, item["label"])
                    self.assertNotEqual(item["expect_exit"], None, item["label"])


TARGET = "0:" + "44" * 32


class DuplicateControl(RunnerCase):
    """The replayed action id is judged from the exact on-chain row, never from silence."""

    def setUp(self):
        super().setUp()
        self.rpc.balances[TARGET] = 10**9

    def dup(self, rc=0, effect=None):
        self.cli.script["d"] = (rc, "", effect)
        return self.runner.duplicate_control(
            "d", ["agent", "account", "task-send"], PAYER, CONTRACT, TARGET
        )

    def test_aborted_account_transaction_is_the_intended_refusal(self):
        rec = self.dup(effect=settle_effect(exit_code=1337, aborted=True))
        self.assertEqual(rec["verdict"], "refused-as-intended")
        self.assertEqual(rec["tx"]["hash"], "C1")
        self.assertEqual(rec["payer_tx"]["hash"], "P1")
        self.assertEqual(rec["compute"]["exit_code"], 1337)
        self.assertTrue(rec["aborted"])
        self.assertFalse(rec["target_paid_again"])
        self.assertTrue(all(rec["confirmed_on"].values()))
        self.assertEqual(self.runner.journal.result("d")["verdict"], "refused-as-intended")

    def test_silence_after_a_successful_cli_is_unknown_not_a_pass(self):
        with self.assertRaises(spc.Refusal):
            self.dup(effect=None)
        self.assertEqual(self.runner.journal.result("d")["verdict"], "unknown-not-observed")
        self.assertEqual(len(self.cli.calls), 1)

    def test_second_transfer_to_the_target_is_the_failure(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            rpc.add(CONTRACT, tx(200, "C1", in_hash="M1", out=((TARGET, "T1"),)))

        rec = self.dup(effect=effect)
        self.assertEqual(rec["verdict"], "DUPLICATE-EXECUTED")
        self.assertEqual(rec["transfers_to_target"][0]["hash"], "T1")

    def test_target_credit_without_a_visible_message_is_still_a_duplicate(self):
        def effect(rpc):
            settle_effect(exit_code=1337, aborted=True)(rpc)
            rpc.balances[TARGET] += spc.tos_to_nanotos("0.1")

        self.assertEqual(self.dup(effect=effect)["verdict"], "DUPLICATE-EXECUTED")

    def test_successful_account_transaction_without_transfer_is_not_a_refusal(self):
        rec = self.dup(effect=settle_effect())
        self.assertEqual(rec["verdict"], "accepted-without-transfer")
        self.assertNotIn(rec["verdict"], spc.REPLAYABLE)

    def test_cli_refusal_with_no_send_has_no_on_chain_row(self):
        rec = self.dup(rc=1)
        self.assertEqual(rec["verdict"], "cli-refused-before-broadcast")
        self.assertNotIn("tx", rec)

    def test_client_side_refusal_is_accepted_only_where_the_case_declares_it(self):
        rec = self.dup(rc=1)
        self.assertTrue(rec["client_side_refusal_accepted"])
        verdict = spc.Runner.verdict(True, [rec])
        self.assertTrue(verdict["pass"])
        self.assertEqual(verdict["controls_refused_client_side"], ["d"])
        self.assertEqual(verdict["controls_without_on_chain_receipt"], [])
        plain = {"label": "x", "verdict": "cli-refused-before-broadcast"}
        self.assertFalse(spc.Runner.verdict(True, [plain])["pass"])
        wrong = dict(rec, verdict="accepted-without-transfer")
        self.assertFalse(spc.Runner.verdict(True, [wrong])["pass"])

    def test_cli_refusal_with_a_send_is_unknown(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))

        with self.assertRaises(spc.Refusal):
            self.dup(rc=1, effect=effect)
        self.assertEqual(self.runner.journal.result("d")["verdict"], "unknown")

    def test_cli_crash_is_unknown(self):
        with self.assertRaises(spc.Refusal):
            self.dup(rc=None)
        self.assertEqual(self.runner.journal.result("d")["verdict"], "unknown")

    def test_old_payer_send_is_not_mistaken_for_a_broadcast(self):
        self.rpc.add(PAYER, tx(50, "P0", out=((CONTRACT, "M0"),)))
        rec = self.dup(rc=1)
        self.assertEqual(rec["verdict"], "cli-refused-before-broadcast")
        self.assertEqual(rec["before"]["payer_lt"], 50)
        self.assertEqual(rec["payer_tx_after"], [])

    def test_missing_confirmation_source_refuses(self):
        with self.assertRaises(spc.Refusal):
            self.dup(effect=settle_effect(exit_code=1337, aborted=True, sources=(PRIMARY,)))
        self.assertEqual(self.runner.journal.result("d")["verdict"], "not-confirmed-on-all-sources")

    def test_two_sends_stop_the_case(self):
        def effect(rpc):
            rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
            rpc.add(PAYER, tx(101, "P2", out=((CONTRACT, "M2"),)))

        with self.assertRaises(spc.Refusal):
            self.dup(effect=effect)
        self.assertEqual(self.runner.journal.result("d")["verdict"], "multiple-sends-observed")

    def test_unrelated_account_row_is_not_taken_for_the_reply(self):
        def effect(rpc):
            settle_effect(exit_code=1337, aborted=True)(rpc)
            rpc.add(CONTRACT, tx(300, "X1", in_hash="ZZ", out=((TARGET, "T9"),)))

        rec = self.dup(effect=effect)
        self.assertEqual(rec["verdict"], "refused-as-intended")
        self.assertEqual(rec["tx"]["hash"], "C1")

    def test_case_refuses_to_run_without_the_flag_fixture(self):
        self.write_actors()
        self.runner.args.flag_fixture = ""
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            with self.assertRaises(spc.Refusal) as cm:
                self.runner.case("sc07")
        self.assertIn("flag fixture", str(cm.exception))
        self.assertEqual(self.cli.calls, [])

    def test_only_a_replayable_verdict_is_replayed(self):
        self.runner.journal.attempt("d", {})
        self.runner.journal.done("d", {"verdict": "refused-as-intended", "tx": {"hash": "C1"}})
        self.assertEqual(self.dup()["tx"]["hash"], "C1")
        self.assertEqual(self.cli.calls, [])
        self.runner.journal.attempt("e", {})
        self.runner.journal.done("e", {"verdict": "accepted-without-transfer"})
        with self.assertRaises(spc.Refusal):
            self.runner.duplicate_control("e", ["agent"], PAYER, CONTRACT, TARGET)
        self.runner.journal.attempt("f", {})
        with self.assertRaises(spc.Refusal):
            self.runner.duplicate_control("f", ["agent"], PAYER, CONTRACT, TARGET)
        self.assertEqual(self.cli.calls, [])

    def test_marker_precedes_the_cli_and_guards_run_first(self):
        seen = {}

        def effect(rpc):
            seen["marker"] = (self.runner.journal.steps / "d.attempt.json").exists()
            settle_effect(exit_code=1337, aborted=True)(rpc)

        self.dup(effect=effect)
        self.assertTrue(seen["marker"])
        self.assertIn("rotation_bounds", self.rpc.calls)
        self.rpc.bounds = (MID - 100, UNTIL)
        with self.assertRaises(spc.Refusal):
            self.runner.duplicate_control("g", ["agent"], PAYER, CONTRACT, TARGET)
        self.assertEqual(len(self.cli.calls), 1)


class Reconcile(RunnerCase):
    """A step that ended `unknown` is reconciled read-only from its single broadcast."""

    def unknown_record(self, expect_exit=1923):
        self.runner.journal.attempt("s", {})
        self.runner.journal.done(
            "s",
            {
                "verdict": "unknown",
                "exit_code": 1,
                "payer": PAYER,
                "observe": CONTRACT,
                "expect_exit": expect_exit,
                "before": {"payer_lt": 50, "observe_lt": 60},
            },
        )
        self.rpc.add(PAYER, tx(50, "P0", out=((CONTRACT, "M0"),)))
        self.rpc.add(CONTRACT, tx(60, "C0", in_hash="M0"))

    def reconcile(self):
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            return self.runner.reconcile("s")

    def test_single_broadcast_with_the_expected_abort_is_refused_as_intended(self):
        self.unknown_record()
        settle_effect(exit_code=1923, aborted=True)(self.rpc)
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "refused-as-intended")
        self.assertTrue(rec["reconciled"])
        self.assertEqual(rec["reconciled_from_verdict"], "unknown")
        self.assertEqual(rec["tx"]["hash"], "C1")
        self.assertEqual(rec["in_msg_hash"], "M1")
        self.assertTrue(all(rec["confirmed_on"].values()))
        self.assertTrue((self.runner.journal.steps / "s.reconciled.json").exists())
        self.assertEqual(
            json.loads((self.runner.journal.steps / "s.done.json").read_text())["verdict"],
            "unknown",
        )
        self.assertEqual(self.runner.journal.result("s")["verdict"], "refused-as-intended")
        self.assertEqual(self.step(expect_exit=1923)["verdict"], "refused-as-intended")
        self.assertEqual(self.cli.calls, [])
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("already reconciled", str(cm.exception))

    def test_wrong_exit_code_is_a_failed_control_and_is_not_replayed(self):
        self.unknown_record()
        settle_effect(exit_code=1900, aborted=True)(self.rpc)
        self.assertEqual(self.reconcile()["verdict"], "refusal-control-failed")
        with self.assertRaises(spc.Refusal):
            self.step(expect_exit=1923)
        self.assertEqual(self.cli.calls, [])

    def test_positive_step_reconciles_to_settled_only_on_success(self):
        self.unknown_record(expect_exit=0)
        settle_effect()(self.rpc)
        self.assertEqual(self.reconcile()["verdict"], "settled")

    def test_unexpected_abort_that_was_a_plain_credit_reconciles_to_settled(self):
        self.unknown_record(expect_exit=0)
        done = json.loads((self.runner.journal.steps / "s.done.json").read_text())
        done["verdict"] = "unexpected-abort"
        done["before"]["observe_balance"] = 0
        (self.runner.journal.steps / "s.done.json").write_text(json.dumps(done))
        self.rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
        row = tx(200, "C1", in_hash="M1", aborted=True)
        row["compute"] = {"skipped": True, "skip_reason": 0}
        row["action"] = None
        self.rpc.add(CONTRACT, row)
        self.rpc.balances[CONTRACT] = 500_000_000
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "settled")
        self.assertEqual(rec["settled_as"], "credited-without-compute")
        self.assertEqual(rec["after"]["observe_balance"], 500_000_000)
        self.assertEqual(self.step()["verdict"], "settled")
        self.assertEqual(self.cli.calls, [])

    def test_unexpected_abort_without_a_real_credit_stays_unexpected(self):
        self.unknown_record(expect_exit=0)
        done = json.loads((self.runner.journal.steps / "s.done.json").read_text())
        done["verdict"] = "unexpected-abort"
        done["before"]["observe_balance"] = 500_000_000
        (self.runner.journal.steps / "s.done.json").write_text(json.dumps(done))
        self.rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
        row = tx(200, "C1", in_hash="M1", aborted=True)
        row["compute"] = {"skipped": True, "skip_reason": 0}
        row["action"] = None
        self.rpc.add(CONTRACT, row)
        self.rpc.balances[CONTRACT] = 500_000_000
        self.assertEqual(self.reconcile()["verdict"], "unexpected-abort")
        with self.assertRaises(spc.Refusal):
            self.step()
        self.assertEqual(self.cli.calls, [])

    def test_positive_step_with_an_abort_is_unexpected(self):
        self.unknown_record(expect_exit=0)
        settle_effect(exit_code=5, aborted=True)(self.rpc)
        self.assertEqual(self.reconcile()["verdict"], "unexpected-abort")

    def test_only_unknown_records_with_exactly_one_broadcast_are_reconciled(self):
        with self.assertRaises(spc.Refusal):
            self.reconcile()
        self.unknown_record()
        with self.assertRaises(spc.Refusal):
            self.reconcile()
        self.rpc.add(PAYER, tx(100, "P1", out=((CONTRACT, "M1"),)))
        self.rpc.add(CONTRACT, tx(200, "C1", in_hash="M1", exit_code=1923, aborted=True))
        self.rpc.add(PAYER, tx(101, "P2", out=((CONTRACT, "M2"),)))
        self.rpc.add(CONTRACT, tx(201, "C2", in_hash="M2", exit_code=1923, aborted=True))
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("2 messages", str(cm.exception))
        self.assertFalse((self.runner.journal.steps / "s.reconciled.json").exists())

    def test_settled_records_are_not_reconciled(self):
        self.unknown_record()
        settle_effect(exit_code=1923, aborted=True)(self.rpc)
        done = json.loads((self.runner.journal.steps / "s.done.json").read_text())
        done["verdict"] = "refusal-control-failed"
        (self.runner.journal.steps / "s.done.json").write_text(json.dumps(done))
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("are reconciled", str(cm.exception))
        self.assertFalse((self.runner.journal.steps / "s.reconciled.json").exists())

    def test_missing_confirmation_source_refuses(self):
        self.unknown_record()
        settle_effect(exit_code=1923, aborted=True, sources=(PRIMARY,))(self.rpc)
        with self.assertRaises(spc.Refusal):
            self.reconcile()
        self.assertFalse((self.runner.journal.steps / "s.reconciled.json").exists())

    def test_old_broadcast_before_the_baseline_does_not_count(self):
        # The only message is older than the baseline, so nothing was sent for this step; the
        # record was written inside the observation window, so it is not settled yet either.
        self.unknown_record()
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("window", str(cm.exception))
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unknown")


def external_effect(exit_code=0, aborted=False, out=(), sources=(PRIMARY, CONFIRM), lt=200):
    def effect(rpc):
        rpc.add(
            CONTRACT,
            tx(
                lt,
                "X1",
                in_hash="E1",
                kind="external",
                exit_code=exit_code,
                aborted=aborted,
                out=out,
            ),
            sources,
        )

    return effect


class ExternalSteps(RunnerCase):
    """A command signed for the contract itself: the proof is its single external arrival."""

    def ext(self, rc=0, effect=None, expect_exit=0):
        self.cli.script["s"] = (rc, "", effect)
        return self.runner.step(
            "s",
            ["agent", "x"],
            payer=CONTRACT,
            observe=CONTRACT,
            expect_exit=expect_exit,
            external=True,
        )

    def test_single_external_arrival_settles(self):
        rec = self.ext(effect=external_effect())
        self.assertEqual(rec["verdict"], "settled")
        self.assertTrue(rec["external"])
        self.assertIsNone(rec["payer_tx"])
        self.assertEqual(rec["tx"]["hash"], "X1")
        self.assertEqual(rec["in_msg_hash"], "E1")
        self.assertTrue(all(rec["confirmed_on"].values()))

    def test_internal_arrival_is_not_an_external_one(self):
        def effect(rpc):
            rpc.add(CONTRACT, tx(200, "C1", in_hash="M1"))

        with self.assertRaises(spc.Refusal):
            self.ext(effect=effect)
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unknown-not-observed")

    def test_no_arrival_is_unknown_not_observed(self):
        with self.assertRaises(spc.Refusal):
            self.ext()
        self.assertEqual(self.runner.journal.result("s")["verdict"], "unknown-not-observed")

    def test_arrival_before_the_baseline_does_not_count(self):
        self.rpc.add(CONTRACT, tx(60, "X0", in_hash="E0", kind="external"))
        with self.assertRaises(spc.Refusal):
            self.ext()
        rec = self.runner.journal.result("s")
        self.assertEqual(rec["verdict"], "unknown-not-observed")
        self.assertEqual(rec["before"]["observe_lt"], 60)

    def test_two_external_arrivals_stop_the_step(self):
        def effect(rpc):
            rpc.add(CONTRACT, tx(200, "X1", in_hash="E1", kind="external"))
            rpc.add(CONTRACT, tx(201, "X2", in_hash="E2", kind="external"))

        with self.assertRaises(spc.Refusal):
            self.ext(effect=effect)
        self.assertEqual(self.runner.journal.result("s")["verdict"], "multiple-sends-observed")

    def test_cli_failure_after_one_external_arrival_is_judged_by_the_chain(self):
        rec = self.ext(rc=1, effect=external_effect(exit_code=77, aborted=True), expect_exit=77)
        self.assertEqual(rec["verdict"], "refused-as-intended")
        self.assertTrue(rec["cli_reported_failure"])

    def test_cli_refusal_without_arrival_is_client_side(self):
        rec = self.ext(rc=1, expect_exit=77)
        self.assertEqual(rec["verdict"], "cli-refused-before-broadcast")

    def test_missing_confirmation_source_refuses(self):
        with self.assertRaises(spc.Refusal):
            self.ext(effect=external_effect(sources=(PRIMARY,)))
        self.assertEqual(self.runner.journal.result("s")["verdict"], "not-confirmed-on-all-sources")


def agent_request(seqno, epoch, valid_until, account=None):
    """SAMPLE_MSG with its signature-covered header rewritten (and optionally re-addressed)."""
    msg = SAMPLE_MSG()
    body = msg.refs[0]
    s = spc.AGENT_EXTERNAL_SIGNATURE_BITS
    bits = (
        body.bits[: s + 64]
        + format(epoch, "064b")
        + format(seqno, "032b")
        + format(valid_until, "032b")
        + body.bits[s + 192 :]
    )
    head = msg.bits
    if account is not None:
        head = head[:15] + format(int(account.split(":")[1], 16), "0256b") + head[271:]
    return spc.Cell(head, [spc.Cell(bits, body.refs)])


class Sc03eExpiry(RunnerCase):
    """SC-03e broadcasts one saved, still-current but expired request exactly once."""

    def setUp(self):
        super().setUp()
        self.evidence.mkdir(exist_ok=True)
        for name in ("sc03", "sc03x"):
            (self.evidence / f"{name}-RESULT.json").write_text(
                json.dumps({"account": SAMPLE_ACCOUNT, "agent_wallet": PAYER, "pass": True})
            )
        self.state = {"seqno": 4, "controller_epoch": 2, "spent_today": 0}
        self.runner.agent_account_state = lambda account, url=None: dict(self.state)
        self.clock = {"utime": 0}
        self.rpc.account_shard_utime = lambda account, url=None: self.clock["utime"]
        self.runner.wait = lambda predicate, timeout=None: (
            self.clock.update(utime=self.clock["utime"] + 10**10) or predicate()
        )
        self.calls = []
        self.answer_override = {}
        self.write_override = None

        def local(label, *argv, want_json=False):
            self.calls.append((label, list(argv)))
            vu = int(argv[argv.index("--valid-until") + 1])
            out = Path(argv[argv.index("--signed-boc-out") + 1])
            msg = agent_request(self.state["seqno"], self.state["controller_epoch"], vu)
            raw = self.write_override if self.write_override is not None else spc.boc_encode(msg)
            out.write_bytes(raw)
            answer = {
                "schema": "tosctl.agent-account.task-send-prepare.v1",
                "state": "broadcasting",
                "action_id": argv[argv.index("--action-id") + 1],
                "account": SAMPLE_ACCOUNT,
                "seqno": self.state["seqno"],
                "controller_epoch": self.state["controller_epoch"],
                "valid_until": vu,
                "exact_signed_boc_digest": "sha256:"
                + hashlib.sha256(spc.boc_encode(msg)).hexdigest(),
            }
            answer.update(self.answer_override)
            return answer

        self.runner.local = local
        self.broadcasts = []

        def broadcast(label, msg, account, expect, raw=None, licence=None):
            self.broadcasts.append((label, expect, raw, spc.cell_hash_b64(msg)))
            record = {
                "label": label,
                "verdict": "refused-at-admission",
                "expect_exit": expect,
                "licence": licence,
            }
            self.runner.journal.attempt(label, record)
            self.runner.journal.done(label, record)
            return record

        self.runner.refusal_broadcast = broadcast

    def test_the_saved_bytes_are_broadcast_once_after_chain_time_passes_the_deadline(self):
        result = self.runner.case_sc03e(WALLETS)
        self.assertTrue(result["pass"])
        [(label, argv)] = self.calls
        self.assertEqual(label, "sc03e-prepare")
        self.assertEqual(argv[:3], ["agent", "account", "task-send-prepare"])
        [(blabel, expect, raw, msg_hash)] = self.broadcasts
        self.assertEqual((blabel, expect), ("sc03e-expired", spc.AGENT_EXPIRED))
        saved = Path(argv[argv.index("--signed-boc-out") + 1])
        self.assertEqual(raw, saved.read_bytes())
        self.assertEqual(oct(saved.parent.stat().st_mode & 0o777), "0o700")
        self.assertTrue(str(saved).startswith(str(self.private)))
        self.assertEqual(result["prepared"]["seqno"], 4)

    def test_a_prepared_answer_for_another_sequence_is_never_broadcast(self):
        self.answer_override = {"seqno": 3}
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03e(WALLETS)
        self.assertIn("task-send-prepare answer seqno=3", str(cm.exception))
        self.assertEqual(self.broadcasts, [])

    def test_a_sequence_that_moves_before_expiry_is_not_an_expiry_control(self):
        original = self.runner.wait_chain_past

        def moved(deadline, account):
            self.state["seqno"] += 1
            return original(deadline, account)

        self.runner.wait_chain_past = moved
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03e(WALLETS)
        self.assertIn("moved before expiry", str(cm.exception))
        self.assertEqual(self.broadcasts, [])

    def test_saved_bytes_that_differ_from_the_printed_digest_are_never_broadcast(self):
        self.write_override = spc.boc_encode(agent_request(4, 2, 1))
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03e(WALLETS)
        self.assertIn("digest", str(cm.exception))
        self.assertEqual(self.broadcasts, [])

    def test_a_chain_that_never_passes_the_deadline_sends_nothing(self):
        self.runner.wait = lambda predicate, timeout=None: False
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03e(WALLETS)
        self.assertIn("did not pass", str(cm.exception))
        self.assertEqual(self.broadcasts, [])

    def test_a_masterchain_past_the_deadline_with_a_stale_shard_sends_nothing(self):
        heads = {
            "seqno": 77,
            "workchain": -1,
            "shard": "-9223372036854775808",
            "root_hash": "m",
            "file_hash": "m",
        }
        shard_top = {
            "workchain": 0,
            "shard": "-9223372036854775808",
            "seqno": 5,
            "root_hash": "s",
            "file_hash": "s",
        }
        times = {"mc": 10**10, "shard": 0}
        rpc = spc.Rpc(PRIMARY, [CONFIRM])
        rpc.head = lambda url=None: heads

        def call(method, url=None, **params):
            if method == "shards":
                return {"shards": [shard_top]}
            if method == "getBlockHeader":
                return {"gen_utime": times["shard" if params["workchain"] == 0 else "mc"]}
            raise AssertionError(method)

        rpc.call = call
        self.runner.rpc = rpc
        self.runner.wait = lambda predicate, timeout=None: predicate()
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03e(WALLETS)
        self.assertIn("shard time did not pass", str(cm.exception))
        self.assertEqual(self.broadcasts, [])
        times["shard"] = 10**10
        result = self.runner.case_sc03e(WALLETS)
        self.assertTrue(result["pass"])
        self.assertEqual(len(self.broadcasts), 1)
        self.assertEqual(set(result["shard_time_at_broadcast"].values()), {10**10})

    def test_the_covering_shard_tip_is_chosen_by_the_account_prefix(self):
        rpc = spc.Rpc(PRIMARY, [CONFIRM])
        rpc.head = lambda url=None: {"seqno": 9}
        left = {
            "workchain": 0,
            "shard": str(0x4000000000000000),
            "seqno": 1,
            "root_hash": "l",
            "file_hash": "l",
        }
        right = {
            "workchain": 0,
            "shard": str(0xC000000000000000 - (1 << 64)),
            "seqno": 2,
            "root_hash": "r",
            "file_hash": "r",
        }
        master = {
            "workchain": -1,
            "shard": str(-(1 << 63)),
            "seqno": 3,
            "root_hash": "m",
            "file_hash": "m",
        }
        seen = []

        def call(method, url=None, **params):
            if method == "shards":
                return {"shards": [master, left, right]}
            seen.append(params["seqno"])
            return {"gen_utime": 100 + params["seqno"]}

        rpc.call = call
        self.assertEqual(rpc.account_shard_utime("0:" + "7f" + "00" * 31), 101)
        self.assertEqual(rpc.account_shard_utime("0:" + "80" + "00" * 31), 102)
        self.assertEqual(seen, [1, 2])
        rpc.call = lambda method, url=None, **p: {"shards": [master]} if method == "shards" else {}
        with self.assertRaises(spc.Refusal):
            rpc.account_shard_utime("0:" + "00" * 32)

    def test_a_resumed_report_keeps_the_times_that_licensed_the_broadcast(self):
        first = self.runner.case_sc03e(WALLETS)
        marker = self.runner.journal.result("sc03e-expired")
        self.assertEqual(marker["licence"]["shard_utime"], first["shard_time_at_broadcast"])
        real = spc.Runner.refusal_broadcast.__get__(self.runner)
        self.runner.refusal_broadcast = real  # a done marker is returned, never re-sent
        self.runner.wait_chain_past = lambda *a: self.fail("resume must not re-read chain time")
        self.runner.read_expiry_probe = lambda path, prepared, account: (b"", SAMPLE_MSG())
        again = self.runner.case_sc03e(WALLETS)
        self.assertEqual(again["shard_time_at_broadcast"], first["shard_time_at_broadcast"])
        self.assertEqual(len(self.broadcasts), 1)

    def test_a_restart_before_the_broadcast_marker_re_judges_and_sends_once(self):
        crashed = {"once": True}
        original = self.runner.read_expiry_probe

        def crash(path, prepared, account):
            if crashed.pop("once", False):
                raise RuntimeError("simulated crash after the expiry check")
            return original(path, prepared, account)

        self.runner.read_expiry_probe = crash
        with self.assertRaises(RuntimeError):
            self.runner.case_sc03e(WALLETS)
        self.assertEqual(self.broadcasts, [])
        waits = []
        judge = self.runner.wait_chain_past
        self.runner.wait_chain_past = lambda d, a: waits.append(d) or judge(d, a)
        result = self.runner.case_sc03e(WALLETS)
        self.assertTrue(result["pass"])
        self.assertEqual(len(waits), 1)
        self.assertEqual(len(self.broadcasts), 1)

    def test_an_attempt_marker_without_a_result_is_never_re_sent(self):
        self.runner.journal.attempt("sc03e-expired", {"kind": "refusal-broadcast"})
        real = spc.Runner.refusal_broadcast.__get__(self.runner)
        sent = []
        self.rpc.send_boc = lambda boc_b64, url=None: sent.append(boc_b64) or {}
        self.runner.refusal_broadcast = real
        self.runner.guards = lambda: {}
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03e(WALLETS)
        self.assertIn("attempted without a result", str(cm.exception))
        self.assertEqual(sent, [])

    def test_the_deadline_must_be_passed_by_the_margin_on_every_source(self):
        seen = {}

        def utime(account, url=None):
            return {PRIMARY: 10**10, CONFIRM: self.clock["deadline"] + spc.EXPIRY_MARGIN_S}[url]

        self.rpc.account_shard_utime = utime
        self.runner.wait = lambda predicate, timeout=None: predicate()
        original = self.runner.check_prepared

        def capture(answer, *a):
            self.clock["deadline"] = answer["valid_until"]
            seen["ok"] = True
            return original(answer, *a)

        self.runner.check_prepared = capture
        with self.assertRaises(spc.Refusal):
            self.runner.case_sc03e(WALLETS)
        self.assertTrue(seen["ok"])
        self.assertEqual(self.broadcasts, [])

    def test_a_saved_request_to_another_account_is_never_broadcast(self):
        self.write_override = b""  # placeholder replaced below
        other = "0:" + "ab" * 32
        msg = agent_request(4, 2, 0, account=other)

        def local(label, *argv, want_json=False):
            vu = int(argv[argv.index("--valid-until") + 1])
            msg2 = agent_request(4, 2, vu, account=other)
            raw = spc.boc_encode(msg2)
            Path(argv[argv.index("--signed-boc-out") + 1]).write_bytes(raw)
            return {
                "schema": "tosctl.agent-account.task-send-prepare.v1",
                "state": "broadcasting",
                "action_id": argv[argv.index("--action-id") + 1],
                "account": SAMPLE_ACCOUNT,
                "seqno": 4,
                "controller_epoch": 2,
                "valid_until": vu,
                "exact_signed_boc_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }

        self.assertTrue(msg.bits)
        self.runner.local = local
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03e(WALLETS)
        self.assertIn("not addressed", str(cm.exception))
        self.assertEqual(self.broadcasts, [])

    def test_sources_that_disagree_on_the_account_stop_before_signing(self):
        self.runner.agent_account_state = lambda account, url=None: (
            {"seqno": 4 if url == PRIMARY else 5, "controller_epoch": 2, "spent_today": 0}
        )
        with self.assertRaises(spc.Refusal) as cm:
            self.runner.case_sc03e(WALLETS)
        self.assertIn("disagree", str(cm.exception))
        self.assertEqual((self.calls, self.broadcasts), ([], []))

    def test_raw_bytes_that_are_not_the_checked_message_are_refused_before_the_attempt(self):
        runner = spc.Runner(self.runner.args)
        runner.rpc = self.rpc
        runner.guards = lambda: {}
        runner.agent_account_state = lambda account, url=None: {"seqno": 1, "controller_epoch": 1}
        runner.wait = lambda predicate, timeout=None: False
        self.rpc.last_lt = lambda address, url=None: 0
        self.rpc.head = lambda url=None: {"seqno": 1000}
        runner.external_arrivals = lambda account, since, url=None: []
        sent = []
        self.rpc.send_boc = lambda boc_b64, url=None: sent.append(boc_b64) or {}
        with self.assertRaises(spc.Refusal) as cm:
            runner.refusal_broadcast(
                "sc03e-mismatch",
                SAMPLE_MSG(),
                SAMPLE_ACCOUNT,
                spc.AGENT_EXPIRED,
                raw=spc.boc_encode(agent_request(9, 9, 9)),
            )
        self.assertIn("not the checked message", str(cm.exception))
        self.assertEqual(sent, [])
        self.assertFalse(runner.journal.attempted("sc03e-mismatch"))
        # The same raw bytes of the checked message go out unchanged.
        raw = spc.boc_encode(SAMPLE_MSG())
        with self.assertRaises(spc.Refusal):
            runner.refusal_broadcast(
                "sc03e-match",
                SAMPLE_MSG(),
                SAMPLE_ACCOUNT,
                spc.AGENT_EXPIRED,
                raw=raw,
                licence={"deadline": 5, "shard_utime": {PRIMARY: 26}},
            )
        self.assertEqual(sent, [base64.b64encode(raw).decode()])
        # The licence is part of the attempt marker, written before the send.
        self.assertEqual(
            runner.journal.attempt_record("sc03e-match")["licence"],
            {"deadline": 5, "shard_utime": {PRIMARY: 26}},
        )


class Sc03eFlagFixture(unittest.TestCase):
    """SC-03e needs task-send-prepare: the pinned CLI fixture refuses it, a fixture that lists
    the command accepts exactly the flags the case uses."""

    @classmethod
    def setUpClass(cls):
        cls.flags = json.loads(spc.FLAG_FIXTURE.read_text())
        cls.args = spc.build_parser().parse_args(
            [
                "--private-dir",
                "/nonexistent",
                "--evidence-dir",
                "/nonexistent",
                "--cli",
                "/x",
                "--cli-sha256",
                cls.flags["cli_sha256"],
                "--rpc",
                PRIMARY,
                "--genesis-root",
                "r",
                "--genesis-file",
                "f",
                "status",
            ]
        )

    def plan(self):
        planner = spc.PlanRunner(self.args, WALLETS)
        planner.case_fn("sc03e")(planner.wallets)
        return planner.recorded

    def test_the_pinned_cli_fixture_refuses_the_case(self):
        checker = spc.Runner.__new__(spc.Runner)
        checker.args = self.args
        with self.assertRaises(spc.Refusal) as cm:
            checker.check_flags(self.plan(), self.flags)
        self.assertIn("task-send-prepare", str(cm.exception))

    def test_the_fixture_recorded_from_the_merge_commit_cli_accepts_the_plan(self):
        # Recorded from tosctl built at tos cf2901a42 (#424 merge): same commands and flags as
        # the pinned fixture plus task-send-prepare and task-send-broadcast.
        flags = json.loads(
            (spc.FLAG_FIXTURE.parent / "service-public-cases-cli-flags-cf2901a.json").read_text()
        )
        self.assertEqual(
            flags["cli_sha256"], "6ff57ea19191347a906ad431efe82b5fdd8439533a2ad6ab4844e10853870a32"
        )
        for path, known in self.flags["commands"].items():
            self.assertEqual(flags["commands"][path], known, path)
        args = spc.build_parser().parse_args(
            [
                "--private-dir",
                "/nonexistent",
                "--evidence-dir",
                "/nonexistent",
                "--cli",
                "/x",
                "--cli-sha256",
                flags["cli_sha256"],
                "--rpc",
                PRIMARY,
                "--genesis-root",
                "r",
                "--genesis-file",
                "f",
                "status",
            ]
        )
        planner = spc.PlanRunner(args, WALLETS)
        planner.case_fn("sc03e")(planner.wallets)
        planned = planner.recorded
        self.assertEqual([p["label"] for p in planned], ["sc03e-prepare"])
        self.assertFalse(planned[0]["value"])
        checker = spc.Runner.__new__(spc.Runner)
        checker.args = args
        checker.check_flags(planned, flags)
        # The new binary also still accepts every other case's plan.
        for name in spc.Runner.CASES:
            p = spc.PlanRunner(args, WALLETS)
            p.case_fn(name)(p.wallets)
            checker.check_flags(p.recorded, flags)


class ExternalDuplicateControl(RunnerCase):
    def setUp(self):
        super().setUp()
        self.rpc.balances[TARGET] = 10**9

    def dup(self, rc=0, effect=None):
        self.cli.script["d"] = (rc, "", effect)
        return self.runner.duplicate_control(
            "d", ["agent", "account", "task-send"], CONTRACT, CONTRACT, TARGET, external=True
        )

    def test_aborted_external_transaction_is_the_intended_refusal(self):
        rec = self.dup(effect=external_effect(exit_code=1337, aborted=True))
        self.assertEqual(rec["verdict"], "refused-as-intended")
        self.assertIsNone(rec["payer_tx"])
        self.assertEqual(rec["tx"]["hash"], "X1")

    def test_external_transfer_to_the_target_is_the_failure(self):
        rec = self.dup(effect=external_effect(out=((TARGET, "T1"),)))
        self.assertEqual(rec["verdict"], "DUPLICATE-EXECUTED")

    def test_client_side_refusal_without_arrival(self):
        self.assertEqual(self.dup(rc=1)["verdict"], "cli-refused-before-broadcast")

    def test_two_external_arrivals_stop_the_control(self):
        def effect(rpc):
            rpc.add(CONTRACT, tx(200, "X1", in_hash="E1", kind="external", aborted=True))
            rpc.add(CONTRACT, tx(201, "X2", in_hash="E2", kind="external", aborted=True))

        with self.assertRaises(spc.Refusal):
            self.dup(effect=effect)
        self.assertEqual(self.runner.journal.result("d")["verdict"], "multiple-sends-observed")

    def test_silence_is_unknown(self):
        with self.assertRaises(spc.Refusal):
            self.dup()
        self.assertEqual(self.runner.journal.result("d")["verdict"], "unknown-not-observed")


class ReconcileExternal(RunnerCase):
    def record(self, verdict="unknown-not-observed", external=None):
        rec = {
            "verdict": verdict,
            "exit_code": 0,
            "payer": CONTRACT,
            "observe": CONTRACT,
            "expect_exit": 0,
            "before": {"payer_lt": 60, "observe_lt": 60, "observe_balance": 10**9},
        }
        if external is not None:
            rec["external"] = external
        self.runner.journal.attempt("s", {})
        self.runner.journal.done("s", rec)
        self.rpc.add(CONTRACT, tx(60, "X0", in_hash="E0", kind="external"))

    def reconcile(self, **kw):
        with mock.patch.object(spc.Runner, "preflight", return_value={}):
            return self.runner.reconcile("s", **kw)

    def test_not_observed_external_step_reconciles_from_its_arrival(self):
        self.record(external=True)
        external_effect()(self.rpc)
        rec = self.reconcile()
        self.assertEqual(rec["verdict"], "settled")
        self.assertTrue(rec["external"])
        self.assertEqual(rec["tx"]["hash"], "X1")
        self.assertIsNone(rec["payer_tx"])
        self.assertEqual(self.runner.journal.result("s")["verdict"], "settled")

    def test_record_without_the_flag_needs_the_explicit_option(self):
        self.record()
        external_effect()(self.rpc)
        with self.assertRaises(spc.Refusal):
            self.reconcile()
        self.assertEqual(self.reconcile(external=True)["verdict"], "settled")

    def test_sender_override_locates_the_internal_message_on_the_contract_side(self):
        self.record(external=True)
        row = tx(200, "C1", in_hash="M1")
        row["in_msg"]["source"] = PAYER
        self.rpc.add(CONTRACT, row)
        stranger = tx(201, "C2", in_hash="M2")
        stranger["in_msg"]["source"] = TARGET
        self.rpc.add(CONTRACT, stranger)
        with self.assertRaises(spc.Refusal):
            self.reconcile()
        rec = self.reconcile(sender=PAYER)
        self.assertEqual(rec["verdict"], "settled")
        self.assertFalse(rec["external"])
        self.assertEqual(rec["sender"], PAYER)
        self.assertEqual(rec["tx"]["hash"], "C1")

    def test_sender_override_refuses_two_or_zero_messages(self):
        self.record(external=True)
        with self.assertRaises(spc.Refusal):
            self.reconcile(sender=PAYER)
        for lt, h, m in ((200, "C1", "M1"), (201, "C2", "M2")):
            row = tx(lt, h, in_hash=m)
            row["in_msg"]["source"] = PAYER
            self.rpc.add(CONTRACT, row)
        with self.assertRaises(spc.Refusal):
            self.reconcile(sender=PAYER)
        self.assertFalse((self.runner.journal.steps / "s.reconciled.json").exists())

    def test_two_arrivals_or_none_refuse(self):
        self.record(external=True)
        with self.assertRaises(spc.Refusal):
            self.reconcile()
        external_effect()(self.rpc)
        self.rpc.add(CONTRACT, tx(201, "X2", in_hash="E2", kind="external"))
        with self.assertRaises(spc.Refusal):
            self.reconcile()
        self.assertFalse((self.runner.journal.steps / "s.reconciled.json").exists())


class FlagFixtureDefault(unittest.TestCase):
    def test_case_defaults_to_the_committed_fixture(self):
        args = spc.build_parser().parse_args(
            [
                "--private-dir",
                "p",
                "--evidence-dir",
                "e",
                "--cli",
                "c",
                "--cli-sha256",
                "s",
                "--rpc",
                PRIMARY,
                "--genesis-root",
                "r",
                "--genesis-file",
                "f",
                "status",
            ]
        )
        self.assertEqual(Path(args.flag_fixture), DATA / "service-public-cases-cli-flags.json")
        self.assertTrue(Path(args.flag_fixture).exists())


class RefusalRedaction(unittest.TestCase):
    def test_private_path_never_reaches_the_evidence_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / "private"
            private.mkdir(mode=0o755)
            evidence = Path(tmp) / "evidence"
            refusal = spc.Refusal(f"private dir {private} mode 0o755 must be 0700")
            with mock.patch.object(spc.Runner, "preflight", side_effect=refusal):
                rc = spc.main(
                    [
                        "--private-dir",
                        str(private),
                        "--evidence-dir",
                        str(evidence),
                        "--cli",
                        "/x",
                        "--cli-sha256",
                        "s",
                        "--rpc",
                        PRIMARY,
                        "--genesis-root",
                        "r",
                        "--genesis-file",
                        "f",
                        "preflight",
                    ]
                )
            self.assertEqual(rc, 3)
            events = (evidence / "events.jsonl").read_text()
            self.assertIn("<private>", events)
            self.assertNotIn(str(private), events)
            crash = OSError(f"cannot open {private}/vault.json")
            with mock.patch.object(spc.Runner, "preflight", side_effect=crash):
                rc = spc.main(
                    [
                        "--private-dir",
                        str(private),
                        "--evidence-dir",
                        str(evidence),
                        "--cli",
                        "/x",
                        "--cli-sha256",
                        "s",
                        "--rpc",
                        PRIMARY,
                        "--genesis-root",
                        "r",
                        "--genesis-file",
                        "f",
                        "preflight",
                    ]
                )
            self.assertEqual(rc, 2)
            events = (evidence / "events.jsonl").read_text()
            self.assertNotIn(str(private), events)


class Helpers(unittest.TestCase):
    def test_transferred_reads_the_record_not_the_chain(self):
        friendly = spc.friendly_addr(TARGET) if hasattr(spc, "friendly_addr") else TARGET
        rec = {"out_msgs": [{"destination": friendly, "value": "100000000", "bounced": False}]}
        self.assertTrue(spc.Runner.transferred(rec, TARGET, "0.09"))
        self.assertFalse(spc.Runner.transferred(rec, TARGET, "0.11"))
        self.assertFalse(spc.Runner.transferred(rec, PAYER, "0.09"))
        bounced = {"out_msgs": [{"destination": TARGET, "value": "100000000", "bounced": True}]}
        self.assertFalse(spc.Runner.transferred(bounced, TARGET, "0.09"))
        self.assertFalse(spc.Runner.transferred({}, TARGET, "0.09"))

    def test_argv_value_comes_from_the_recorded_vector(self):
        rec = {"label": "x", "argv": ["agent", "--action-id", "ab" * 32, "--yes"]}
        self.assertEqual(spc.Runner.argv_value(rec, "--action-id"), "ab" * 32)
        with self.assertRaises(spc.Refusal):
            spc.Runner.argv_value(rec, "--value")
        with self.assertRaises(spc.Refusal):
            spc.Runner.argv_value({"argv": ["--action-id"]}, "--action-id")

    def test_amount_round_trip(self):
        for text in ("0.000000001", "1.5", "3088.636365049", "20"):
            n = spc.tos_to_nanotos(text)
            self.assertEqual(spc.tos_to_nanotos(spc.nanotos_text(n)), n)
        self.assertEqual(spc.state_nanotos(250_000_000), 250_000_000)
        self.assertEqual(spc.state_nanotos("0.25"), 250_000_000)
        self.assertEqual(spc.state_nanotos("250000000"), 250_000_000)
        with self.assertRaises(spc.Refusal):
            spc.state_nanotos(None)

    def test_quiet_window_distance(self):
        self.assertEqual(spc.quiet_window_distance(SINCE, SINCE, UNTIL), 0)
        self.assertEqual(spc.quiet_window_distance(SINCE + 3600, SINCE, UNTIL), 3600)
        self.assertEqual(spc.quiet_window_distance(UNTIL - 1, SINCE, UNTIL), 1)
        self.assertEqual(spc.quiet_window_distance(UNTIL + 900, SINCE, UNTIL), 0)
        self.assertEqual(spc.quiet_window_distance(SINCE - 5, SINCE, UNTIL), 0)

    def test_boc_root_data_reads_config_params_and_refuses_truncation(self):
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
        for bad in (b"\x00" * 8, boc[:-3], boc[:9], b""):
            with self.assertRaises(spc.Refusal):
                spc.boc_root_data(bad)

    def test_evidence_record_carries_no_environment_or_raw_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = spc.Journal(Path(tmp) / "ev")
            cli = spc.Cli(Path("/bin/sh"), "x", Path(tmp) / "priv", journal)
            (Path(tmp) / "priv").mkdir(mode=0o700)
            payload = Path(tmp) / "priv" / "payload.txt"
            payload.write_text("raw-cli-output-stays-private\n")
            with mock.patch.dict(os.environ, {"VAULT_URL": "file:///secret?master_key=00"}):
                self.assertNotIn("VAULT_URL", cli.env())
                rc, text = cli.run("echo", "-c", 'cat "$1"', "sh", str(payload))
            self.assertEqual(rc, 0)
            self.assertIn("raw-cli-output", text)
            events = journal.events.read_text()
            self.assertNotIn("master_key", events)
            self.assertNotIn(tmp, events)  # private path redacted from argv
            self.assertIn("<private>/payload.txt", events)
            self.assertIn('"label": "echo"', events)
            self.assertNotIn("raw-cli-output", events)
            self.assertIn("raw-cli-output", (cli.receipts / "echo.stdout").read_text())

    def test_cli_timeout_returns_none_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = spc.Journal(Path(tmp) / "ev")
            cli = spc.Cli(Path("/bin/sh"), "x", Path(tmp) / "priv", journal)
            (Path(tmp) / "priv").mkdir(mode=0o700)
            with mock.patch.object(spc, "CLI_TIMEOUT_S", 0.2):
                rc, _ = cli.run("slow", "-c", "sleep 2")
            self.assertIsNone(rc)
            self.assertIn('"timed_out": true', journal.events.read_text())

    def test_user_friendly_address_normalises_to_raw(self):
        raw = bytes([0x11, 0x00]) + bytes.fromhex("ab" * 32)
        friendly = base64.urlsafe_b64encode(raw + spc.crc16_xmodem(raw).to_bytes(2, "big")).decode()
        self.assertEqual(spc.norm_addr(friendly), "0:" + "ab" * 32)
        self.assertEqual(spc.norm_addr("0:" + "AB" * 32), "0:" + "ab" * 32)
        self.assertTrue(spc.same_addr(friendly, "0:" + "AB" * 32))
        self.assertFalse(spc.same_addr("garbage", "0:" + "AB" * 32))
        masterchain = bytes([0x11, 0xFF]) + bytes.fromhex("cd" * 32)
        friendly_mc = base64.urlsafe_b64encode(
            masterchain + spc.crc16_xmodem(masterchain).to_bytes(2, "big")
        ).decode()
        self.assertEqual(spc.norm_addr(friendly_mc), "-1:" + "cd" * 32)
        corrupted = friendly[:-1] + ("A" if friendly[-1] != "A" else "B")
        for bad in (corrupted, "0:" + "zz" * 32, "", "x:" + "ab" * 32, None):
            with self.assertRaises(spc.Refusal):
                spc.norm_addr(bad)


if __name__ == "__main__":
    unittest.main()
