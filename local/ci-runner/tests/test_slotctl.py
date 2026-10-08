"""The slot-control grammar accepts only start/stop/status of slots 1-3."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("slotctl", HERE.parent / "host" / "lib" / "slotctl.py")
slotctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(slotctl)


class GrammarTest(unittest.TestCase):
    def test_accepted(self) -> None:
        for verb in ("start", "stop", "status"):
            for slot in "123":
                with self.subTest(verb=verb, slot=slot):
                    self.assertEqual(slotctl.parse(f"{verb} {slot}\n".encode()), (verb, slot))

    def test_refused(self) -> None:
        for line in (
            b"start 4\n", b"start 0\n", b"start 01\n", b"start 1; id\n", b"start 1\n\n",
            b"restart 1\n", b"start  1\n", b"START 1\n", b"start 1", b"start 1\r\n",
            b"start " + b"1" * 100 + b"\n", b"\xffstart 1\n", b"",
        ):
            with self.subTest(line=line):
                self.assertIsNone(slotctl.parse(line))


if __name__ == "__main__":
    unittest.main()
