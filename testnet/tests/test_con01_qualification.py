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

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "testnet" / "acceptance"))
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
        self.provenance = dict(
            source_sha256={name: qualify.sha(package / name) for name in qualify.WORKER_MODULES}
        )
        repo = package.parents[2]  # testnet/acceptance/con01_history -> repository root
        tests = repo / "testnet/tests"
        paths = (
            list(package.glob("*.py"))
            + list(tests.glob("test_con01*.py"))
            + list((tests / "data/con01-history").glob("*"))
            + [tests / "con01_rejudge_controls.py"]
        )
        files = {str(path.relative_to(repo)): qualify.sha(path) for path in paths if path.is_file()}
        self.controls = dict(
            result="PASS",
            files=files,
            rows=[dict(name="baseline", exit=0, test=None)]
            + [dict(name=name, exit=1, test=test) for name, test in qualify.CONTROL_TESTS.items()]
            + [dict(name="restored", exit=0, test=None)],
        )
        (self.replay / "REPLAY-CONFIG.json").write_text(json.dumps(cfg))
        (self.replay / "VERDICT.json").write_text("{}")
        self.write()
        (self.replay / "APPROVED-CONFIG.json").write_text(json.dumps(cfg))
        (self.replay / "SEALS.jsonl").write_bytes(b"")
        (self.replay / "SEGMENT-HASHES.json").write_text(
            json.dumps(
                {
                    row["path"]: qualify.sha(self.replay / row["path"])
                    for row in self.snapshot["segments"]
                }
            )
        )
        inputs = {
            "files": {
                name: qualify.sha(self.replay / name)
                for name in (
                    "APPROVED-CONFIG.json",
                    "REPLAY-CONFIG.json",
                    "SNAPSHOT.json",
                    "SEALS.jsonl",
                    "SEGMENT-HASHES.json",
                )
            }
        }
        (self.replay / "REPLAY-INPUTS.json").write_text(json.dumps(inputs))

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

    def test_historical_worker_name_is_exact_byte_alias(self):
        files = self.provenance["source_sha256"]
        files["rejudge.py"] = files.pop("_replay.py")
        self.write()
        try:
            self.run_qualification()
        except Refused as error:
            self.fail(f"exact historical worker alias refused: {error}")
        result = json.loads(self.output.read_bytes())
        self.assertEqual(result["worker_source_files"]["rejudge.py"], "_replay.py")
        self.assertEqual(result["verdict"], "PASS")

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
        self.controls["files"]["testnet/acceptance/con01_history/observer.py"] = "00" * 32
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

    def test_incomplete_control_inventory_cannot_qualify(self):
        original = copy.deepcopy(self.controls["files"])
        for files in (
            {},
            {key: value for key, value in original.items() if not key.endswith("observer.py")},
        ):
            with self.subTest(entries=len(files)):
                self.controls["files"] = files
                self.write()
                with self.assertRaisesRegex(Refused, "complete control revision inventory"):
                    self.run_qualification()

    def test_incomplete_replay_inventory_cannot_qualify(self):
        original = copy.deepcopy(self.provenance["source_sha256"])
        for files in ({}, {key: value for key, value in original.items() if key != "observer.py"}):
            with self.subTest(entries=len(files)):
                self.provenance["source_sha256"] = files
                self.write()
                with self.assertRaisesRegex(Refused, "complete worker revision inventory"):
                    self.run_qualification()

    def test_duplicate_guard_identities_cannot_qualify(self):
        row = copy.deepcopy(self.controls["rows"][1])
        self.controls["rows"][1:-1] = [row] * qualify.CONTROL_GUARDS
        self.write()
        with self.assertRaisesRegex(Refused, "exact unique guard identities"):
            self.run_qualification()

    def test_changed_frozen_inputs_cannot_qualify(self):
        for name in ("APPROVED-CONFIG.json", "REPLAY-CONFIG.json", "SNAPSHOT.json", "SEALS.jsonl"):
            with self.subTest(input=name):
                path = self.replay / name
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                try:
                    with self.assertRaisesRegex(Refused, "frozen replay input identity"):
                        self.run_qualification()
                finally:
                    path.write_bytes(original)

    def test_same_length_frozen_segment_change_cannot_qualify(self):
        (self.replay / self.snapshot["segments"][0]["path"]).write_bytes(b"[]\n")
        with self.assertRaisesRegex(Refused, "frozen segment digest changed"):
            self.run_qualification()

    def test_extra_segment_digest_cannot_qualify(self):
        path = self.replay / "SEGMENT-HASHES.json"
        digests = json.loads(path.read_bytes())
        digests["src-node1/seg-unlisted.jsonl"] = "00" * 32
        path.write_text(json.dumps(digests))
        pins = json.loads((self.replay / "REPLAY-INPUTS.json").read_bytes())
        pins["files"]["SEGMENT-HASHES.json"] = qualify.sha(path)
        (self.replay / "REPLAY-INPUTS.json").write_text(json.dumps(pins))
        with self.assertRaisesRegex(Refused, "complete frozen segment digest inventory"):
            self.run_qualification()

    def test_unlisted_worker_segment_cannot_qualify(self):
        (self.replay / "src-node1/seg-extra.jsonl").write_bytes(b"{}\n")
        with self.assertRaisesRegex(Refused, "complete worker input inventory"):
            self.run_qualification()

    def test_extra_source_directory_cannot_qualify(self):
        (self.replay / "src-unapproved").mkdir()
        with self.assertRaisesRegex(Refused, "exact original source directories"):
            self.run_qualification()


if __name__ == "__main__":
    unittest.main()
