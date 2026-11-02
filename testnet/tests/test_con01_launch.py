"""Freeze/resume metadata only; no crypto execution or chain claim."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
from con01_history import launch  # noqa: E402
from con01_history.certificate import Refused  # noqa: E402


class LaunchMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        for src in ("node1", "node3", "node5"):
            folder = self.source / ("src-" + src)
            folder.mkdir()
            (folder / "seg-fixture.jsonl").write_bytes(b"{}\n")
        (self.source / "SEALS.jsonl").write_bytes(b"")
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"fixture": "synthetic metadata only"}))
        self.out = self.root / "frozen"
        self.argv = [
            "launch",
            "--source",
            str(self.source),
            "--config",
            str(self.config),
            "--out",
            str(self.out),
            "--verifier",
            str(self.root / "unused-helper"),
            "--verifier-sha256",
            "11" * 32,
        ]
        self.invoke()

    def invoke(self, resume=False):
        with (
            patch.object(sys, "argv", self.argv + (["--resume"] if resume else [])),
            patch.object(launch.os, "execv") as execute,
        ):
            launch.main()
            execute.assert_called_once()

    def mutate_json(self, name, change):
        path = self.out / name
        obj = json.loads(path.read_bytes())
        change(obj)
        path.write_text(json.dumps(obj))

    def refuse(self, reason):
        before = (self.out / "REPLAY-CONFIG.json").read_bytes()
        with (
            patch.object(sys, "argv", self.argv + ["--resume"]),
            patch.object(launch.os, "execv") as execute,
        ):
            with self.assertRaisesRegex(Refused, reason):
                launch.main()
            execute.assert_not_called()
        self.assertEqual((self.out / "REPLAY-CONFIG.json").read_bytes(), before)

    def test_unchanged_frozen_inputs_resume(self):
        self.invoke(True)

    def test_historical_worker_name_resumes_exact_same_bytes(self):
        def rename(obj):
            files = obj["source_sha256"]
            files["rejudge.py"] = files.pop("_replay.py")

        self.mutate_json("REPLAY-PROVENANCE.json", rename)
        try:
            self.invoke(True)
        except Refused as error:
            self.fail(f"exact historical worker alias refused before resume: {error}")

    def test_relative_output_alias_refuses_before_worker(self):
        self.argv[self.argv.index("--out") + 1] = "frozen"
        prior = Path.cwd()
        os.chdir(self.root)
        try:
            self.refuse("resume config representation changed")
        finally:
            os.chdir(prior)

    def test_changed_approved_config_refuses_before_worker(self):
        self.config.write_bytes(self.config.read_bytes() + b" ")
        self.refuse("approved configuration changed")

    def test_changed_frozen_input_refuses_before_worker(self):
        path = self.out / "REPLAY-CONFIG.json"
        path.write_bytes(path.read_bytes() + b" ")
        self.refuse("frozen input changed")

    def test_changed_verifier_refuses_before_worker(self):
        self.argv[-1] = "22" * 32
        self.refuse("resume verifier digest changed")

    def test_changed_source_refuses_before_worker(self):
        self.argv[self.argv.index("--source") + 1] = str(self.root / "different-source")
        self.refuse("resume source changed")

    def test_incomplete_input_inventory_refuses_before_worker(self):
        self.mutate_json("REPLAY-INPUTS.json", lambda obj: obj.__setitem__("files", {}))
        self.refuse("complete frozen input inventory")

    def test_incomplete_worker_inventory_refuses_before_worker(self):
        self.mutate_json("REPLAY-PROVENANCE.json", lambda obj: obj.__setitem__("source_sha256", {}))
        self.refuse("complete worker revision inventory")

    def test_changed_worker_revision_refuses_before_worker(self):
        self.mutate_json(
            "REPLAY-PROVENANCE.json",
            lambda obj: obj["source_sha256"].__setitem__("observer.py", "00" * 32),
        )
        self.refuse("worker revision changed")


if __name__ == "__main__":
    unittest.main()
