"""Controls for the once-only public service-case runner.

Every guard is exercised red and green with a fake CLI and a fake RPC: a passing test here
proves the guard can refuse, not merely that it stayed quiet. The case plans are checked
against the flags the pinned CLI itself prints (tests/data/service-public-cases-cli-flags.json).
"""

import base64
import importlib.util
import json
import os
import sys
import tempfile
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

    def test_every_case_plans_and_matches_the_cli_flags(self):
        for name in spc.Runner.CASES:
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
        self.unknown_record()
        with self.assertRaises(spc.Refusal) as cm:
            self.reconcile()
        self.assertIn("0 messages", str(cm.exception))


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
