"""Decision tests for nic-watchdog.py."""

import importlib.util
import sys
import unittest
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / "host-nic" / "nic-watchdog.py"
_SPEC = importlib.util.spec_from_file_location("nic_watchdog", _PATH)
wd = importlib.util.module_from_spec(_SPEC)
sys.modules["nic_watchdog"] = wd
_SPEC.loader.exec_module(wd)


class DecideTest(unittest.TestCase):
    def setUp(self):
        self.policy = wd.Policy(hang_reports=2, ping_failures=3, min_interval_s=100)
        self.state = wd.State()

    def test_healthy_link_does_nothing(self):
        for t in range(10):
            self.assertIsNone(wd.decide(self.policy, self.state, 0, True, t))

    def test_single_hang_report_is_not_enough(self):
        self.assertIsNone(wd.decide(self.policy, self.state, 1, True, 0))

    def test_hang_reports_trigger_bounce(self):
        self.assertEqual(wd.decide(self.policy, self.state, 2, True, 0), "bounce")

    def test_ping_failures_trigger_only_when_consecutive(self):
        self.assertIsNone(wd.decide(self.policy, self.state, 0, False, 0))
        self.assertIsNone(wd.decide(self.policy, self.state, 0, False, 1))
        self.assertIsNone(wd.decide(self.policy, self.state, 0, True, 2))
        self.assertIsNone(wd.decide(self.policy, self.state, 0, False, 3))
        self.assertIsNone(wd.decide(self.policy, self.state, 0, False, 4))
        self.assertEqual(wd.decide(self.policy, self.state, 0, False, 5), "bounce")

    def test_rate_limit_blocks_back_to_back_recoveries(self):
        self.assertEqual(wd.decide(self.policy, self.state, 5, False, 0), "bounce")
        self.assertIsNone(wd.decide(self.policy, self.state, 5, False, 50))
        self.assertIsNotNone(wd.decide(self.policy, self.state, 5, False, 100))

    def test_failed_bounce_escalates_to_reload(self):
        self.assertEqual(wd.decide(self.policy, self.state, 5, False, 0), "bounce")
        # Still wedged on the poll after the bounce: the bounce failed.
        self.assertIsNone(wd.decide(self.policy, self.state, 5, False, 10))
        self.assertEqual(wd.decide(self.policy, self.state, 5, False, 110), "reload")

    def test_successful_bounce_resets_escalation(self):
        self.assertEqual(wd.decide(self.policy, self.state, 5, False, 0), "bounce")
        self.assertIsNone(wd.decide(self.policy, self.state, 0, True, 10))
        self.assertEqual(wd.decide(self.policy, self.state, 5, True, 200), "bounce")


if __name__ == "__main__":
    unittest.main()
