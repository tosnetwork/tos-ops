"""Qualification metadata controls; synthetic already-verified records, no cryptographic claim."""

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
from con01_history import observer, qualify  # noqa: E402
from con01_history.certificate import Refused  # noqa: E402
from test_con01_rejudge import fixture  # noqa: E402


class QualificationMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.replay = self.root / "replay"
        (self.replay / "verified").mkdir(parents=True)
        self.output = self.root / "qualification.json"
        self.control = self.root / "controls.json"
        self.records, cfg, self.bounds = fixture()
        sources = []
        offsets = {}
        for src in ("node1", "node3", "node5"):
            relative = f"src-{src}/seg-test.jsonl"
            path = self.replay / relative
            path.parent.mkdir()
            path.write_bytes(b"{}\n")
            sources.append(dict(path=relative, bytes=3))
            offsets[relative] = 3
        self.snapshot = dict(segments=sources)
        self.state = dict(offsets=offsets, genesis_set=cfg["_genesis_set"])
        package = Path(qualify.__file__).parent
        self.provenance = dict(source_sha256={"observer.py": qualify.sha(package / "observer.py")})
        files = {"production/con01_history/observer.py": qualify.sha(package / "observer.py")}
        self.controls = dict(
            result="PASS",
            files=files,
            rows=[dict(name="baseline", exit=0, test=None)]
            + [
                dict(name=f"guard-{n}", exit=1, test="explicit-test")
                for n in range(qualify.CONTROL_GUARDS)
            ]
            + [dict(name="restored", exit=0, test=None)],
        )
        (self.replay / "REPLAY-CONFIG.json").write_text(json.dumps(cfg))
        (self.replay / "VERDICT.json").write_text("{}")
        self.write()

    def write(self):
        for name, value in [
            ("SNAPSHOT.json", self.snapshot),
            ("REPLAY-PROVENANCE.json", self.provenance),
            ("verified/state.json", self.state),
        ]:
            (self.replay / name).write_text(json.dumps(value))
        self.control.write_text(json.dumps(self.controls))

    def run_qualification(self):
        argv = [
            "qualify",
            "--replay",
            str(self.replay),
            "--controls",
            str(self.control),
            "--out",
            str(self.output),
        ]
        real_judge = observer.judge
        # The judge is still executed; only the explicit tiny fixture's time/window
        # thresholds are used. Production CLI never exposes these overrides.
        with (
            patch.object(sys, "argv", argv),
            patch.object(observer, "load_results", return_value=copy.deepcopy(self.records)),
            patch.object(observer, "seals_check", return_value={"mismatches": []}),
            patch.object(
                observer,
                "judge",
                side_effect=lambda records, cfg: real_judge(records, cfg, self.bounds),
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            qualify.main()

    def test_positive_metadata_fixture_writes_separate_output(self):
        self.run_qualification()
        self.assertEqual(json.loads(self.output.read_text())["verdict"], "PASS")
        self.assertEqual((self.replay / "VERDICT.json").read_text(), "{}")

    def test_incomplete_replay_cannot_qualify(self):
        self.state["offsets"]["src-node1/seg-test.jsonl"] = 0
        self.write()
        with self.assertRaisesRegex(Refused, "incomplete frozen replay"):
            self.run_qualification()
        self.assertFalse(self.output.exists())

    def test_changed_source_cannot_qualify(self):
        self.provenance["source_sha256"]["observer.py"] = "00" * 32
        self.write()
        with self.assertRaisesRegex(Refused, "replay source revision changed"):
            self.run_qualification()

    def test_changed_control_revision_cannot_qualify(self):
        self.controls["files"]["production/con01_history/observer.py"] = "00" * 32
        self.write()
        with self.assertRaisesRegex(Refused, "control revision changed"):
            self.run_qualification()

    def test_missing_controls_cannot_qualify(self):
        self.controls["rows"].pop(1)
        self.write()
        with self.assertRaisesRegex(Refused, "complete guard controls"):
            self.run_qualification()

    def test_frozen_size_change_cannot_qualify(self):
        (self.replay / self.snapshot["segments"][0]["path"]).write_bytes(b"{}\n0")
        self.write()
        with self.assertRaisesRegex(Refused, "frozen segment size changed"):
            self.run_qualification()

    def test_missing_third_source_cannot_qualify(self):
        self.snapshot["segments"].pop()
        self.write()
        with self.assertRaisesRegex(Refused, "three frozen original source"):
            self.run_qualification()


if __name__ == "__main__":
    unittest.main()
