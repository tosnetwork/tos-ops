"""op.py reconcile: what it deletes, what it defers, what fails it."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("op", HERE.parent / "host" / "lib" / "op.py")
op = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(op)


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.github.com/x", code, "refused", {}, None)


class ReconcileTest(unittest.TestCase):
    RUNNERS = [{"id": 1, "name": "tos-ci-s1-aaaaaaaa"}, {"id": 2, "name": "tos-ci-s1-bbbbbbbb"},
               {"id": 3, "name": "tos-ci-s2-cccccccc"}, {"id": 4, "name": "someone-else"}]

    def reconcile(self, outcomes: dict[int, int | None], keep: list[str], prefix: str | None = None) -> dict:
        deleted_ids = []

        def delete(runner_id: int) -> None:
            code = outcomes.get(runner_id)
            if code is not None:
                raise http_error(code)
            deleted_ids.append(runner_id)

        saved = op.all_runners, op.delete_runner, sys.stdin
        op.all_runners = lambda: self.RUNNERS
        op.delete_runner = delete
        args = {"keep": keep} if prefix is None else {"keep": keep, "prefix": prefix}
        sys.stdin = io.StringIO(json.dumps(args))
        try:
            return op.main(["reconcile"])
        finally:
            op.all_runners, op.delete_runner, sys.stdin = saved

    def test_deletes_unkept_names_in_the_namespace(self) -> None:
        result = self.reconcile({}, keep=["tos-ci-s1-aaaaaaaa"])
        self.assertEqual(result, {"deleted": ["tos-ci-s1-bbbbbbbb", "tos-ci-s2-cccccccc"], "deferred": []})

    def test_a_busy_registration_is_deferred(self) -> None:
        result = self.reconcile({2: 422}, keep=[], prefix="tos-ci-s1-")
        self.assertEqual(result, {"deleted": ["tos-ci-s1-aaaaaaaa"], "deferred": ["tos-ci-s1-bbbbbbbb"]})

    def test_any_other_error_fails_the_op(self) -> None:
        for code in (401, 403, 500):
            with self.subTest(code), self.assertRaises(urllib.error.HTTPError):
                self.reconcile({2: code}, keep=[], prefix="tos-ci-s1-")


if __name__ == "__main__":
    unittest.main()
