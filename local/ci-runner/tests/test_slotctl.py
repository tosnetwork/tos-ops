"""Slot control: the request grammar and the intent transitions."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("slotctl", HERE.parent / "host" / "lib" / "slotctl.py")
slotctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(slotctl)

UP5 = {"latest": 5, "desired": "up"}
DOWN5 = {"latest": 5, "desired": "down"}


class GrammarTest(unittest.TestCase):
    def test_accepted(self) -> None:
        self.assertEqual(slotctl.parse(b"up 1 5\n"), ("up", 1, 5))
        self.assertEqual(slotctl.parse(b"down 3 0\n"), ("down", 3, 0))
        self.assertEqual(slotctl.parse(b"cleanup 2 12\n"), ("cleanup", 2, 12))
        self.assertEqual(slotctl.parse(b"status 1\n"), ("status", 1, None))

    def test_refused(self) -> None:
        for line in (
            b"start 1\n", b"stop 1\n", b"up 4 1\n", b"up 0 1\n", b"up 1\n", b"status 1 2\n",
            b"up 1 -1\n", b"up 1 1234567890123\n", b"up 1 5; id\n", b"up 1 5\n\n", b"up  1 5\n",
            b"UP 1 5\n", b"up 1 5", b"up 1 5\r\n", b"cleanup 1\n", b"\xffup 1 5\n", b"",
            b"up 1 " + b"9" * 60 + b"\n",
        ):
            with self.subTest(line=line):
                self.assertIsNone(slotctl.parse(line))


class TransitionTest(unittest.TestCase):
    def check(self, verb, g, intent, action, reply, new=None) -> None:
        got_intent, got_action, got_reply = slotctl.transition(verb, g, dict(intent))
        self.assertEqual((got_action, got_reply), (action, reply), (verb, g, intent))
        self.assertEqual(got_intent, new if new is not None else intent)

    def test_older_generations_never_act(self) -> None:
        for verb in ("up", "down", "cleanup"):
            for intent in (UP5, DOWN5):
                with self.subTest(verb=verb, intent=intent):
                    self.check(verb, 4, intent, "none", "stale")

    def test_newer_generation(self) -> None:
        self.check("up", 6, DOWN5, "start", "ok", {"latest": 6, "desired": "up"})
        self.check("up", 6, UP5, "start", "ok", {"latest": 6, "desired": "up"})
        self.check("down", 6, UP5, "stop", "ok", {"latest": 6, "desired": "down"})
        self.check("cleanup", 6, DOWN5, "none", "stale")

    def test_same_generation_down_wins(self) -> None:
        self.check("up", 5, UP5, "start", "ok")
        self.check("up", 5, DOWN5, "none", "down wins")
        self.check("down", 5, UP5, "stop", "ok", DOWN5)
        self.check("down", 5, DOWN5, "stop", "ok", DOWN5)

    def test_cleanup_only_for_the_stopped_current_generation(self) -> None:
        self.check("cleanup", 5, DOWN5, "cleanup", "ok")
        self.check("cleanup", 5, UP5, "none", "not down")

    def test_late_start_after_stop_never_runs(self) -> None:
        intent = {"latest": 4, "desired": "down"}
        intent, action, _ = slotctl.transition("down", 5, intent)
        self.assertEqual(action, "stop")
        _, action, reply = slotctl.transition("up", 5, intent)
        self.assertEqual((action, reply), ("none", "down wins"))

    def test_late_old_stop_spares_the_newer_vm(self) -> None:
        intent, _, _ = slotctl.transition("up", 6, DOWN5)
        for verb in ("down", "cleanup"):
            self.assertEqual(slotctl.transition(verb, 5, intent)[1:], ("none", "stale"))


if __name__ == "__main__":
    unittest.main()
