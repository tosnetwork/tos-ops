"""Judge controls use explicit synthetic verified records, never synthetic signatures."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
from con01_history.observer import BOUNDS, judge  # noqa: E402


def fixture():
    sources = ["node1", "node3", "node5"]
    old = dict(hash="old", since=2800, until=10000)
    new = dict(hash="new", since=10000, until=17200)
    cfg = dict(sources=sources, start_seqno=1, _genesis_set=old)
    bounds = dict(BOUNDS, window_s=1, min_handovers=1)
    records = []
    for src in sources:
        for seq in range(1, 9):
            gu = 10000 + (seq - 4) / 2
            cid = [f"root{seq}", f"file{seq}"]
            records.append(
                dict(
                    t="blk",
                    src=src,
                    seq=seq,
                    ok=True,
                    cid=cid,
                    rid=cid[:],
                    parent=[f"root{seq - 1}", f"file{seq - 1}"],
                    parent_seq=seq - 1,
                    gu=gu,
                    utc=gu + 0.1,
                    prevkey=0 if seq <= 4 else 4,
                    key=seq == 4,
                    set="old" if seq <= 4 else "new",
                )
            )
        records.append(dict(t="key", src=src, seq=4, trusted=True, cp32=old, cp34=new, cp36=None))
        for seq in (3, 4):
            records.append(dict(t="shards", src=src, seq=seq, tops=["shard-root"]))
        records.append(dict(t="shp", src=src, seq=4, ok=True))
        for seq in (2, 4, 6):
            records.append(dict(t="head", src=src, utc=10000 + (seq - 4) / 2 + 0.1, head=seq))
    return records, cfg, bounds


class JudgeControls(unittest.TestCase):
    def run_case(self, mutate):
        records, cfg, bounds = fixture()
        baseline = judge(copy.deepcopy(records), cfg, bounds)
        self.assertEqual(baseline["verdict"], "PASS", baseline)
        mutate(records, cfg, bounds)
        result = judge(records, cfg, bounds)
        self.assertNotEqual(result["verdict"], "PASS", result)
        return result

    def test_positive_fixture(self):
        records, cfg, bounds = fixture()
        result = judge(records, cfg, bounds)
        self.assertEqual(result["verdict"], "PASS", result)
        self.assertEqual(result["continuously_verified_runs"], [dict(lo=1, hi=8, blocks=8)])

    def test_production_thresholds_are_not_fixture_thresholds(self):
        records, cfg, _ = fixture()
        self.assertNotEqual(judge(records, cfg)["verdict"], "PASS")
        self.assertEqual(BOUNDS["window_s"], 600)
        self.assertEqual(BOUNDS["min_handovers"], 3)

    def test_rejection_is_not_overwritten_by_later_success(self):
        def change(records, *_):
            r = copy.deepcopy(records[0])
            r.update(ok=False, reason="invalid signature")
            records.append(r)

        result = self.run_case(change)
        self.assertEqual(result["rejected_count"], 1)

    def test_integrity_break(self):
        self.run_case(lambda r, *_: r.append(dict(t="chain", src="node1", ok=False)))

    def test_source_self_conflict(self):
        def change(r, *_):
            x = copy.deepcopy(r[0])
            x["cid"] = ["different", "file"]
            r.append(x)

        self.assertEqual(self.run_case(change)["verdict"], "FAIL")

    def test_cross_source_conflict(self):
        def change(r, *_):
            next(x for x in r if x["t"] == "blk" and x["seq"] == 4)["cid"] = ["different", "file"]

        self.assertEqual(self.run_case(change)["verdict"], "FAIL")

    def test_broken_parent(self):
        def change(r, *_):
            for x in r:
                if x["t"] == "blk" and x["seq"] == 5:
                    x["parent"] = ["wrong", "file"]

        self.assertEqual(self.run_case(change)["verdict"], "FAIL")

    def test_missing_trusted_key(self):
        self.run_case(lambda r, *_: r.__setitem__(slice(None), [x for x in r if x["t"] != "key"]))

    def test_uncertified_source_key_cannot_enter_trust_chain(self):
        def change(r, *_):
            for x in r:
                if x["t"] == "blk" and x["seq"] == 2:
                    x["prevkey"] = 999

        self.run_case(change)

    def test_boundary_requires_three_certificates(self):
        self.run_case(
            lambda r, *_: [
                x.update(ok=False, unsupported=True)
                for x in r
                if x["t"] == "blk" and x["seq"] == 4 and x["src"] == "node5"
            ]
        )

    def test_window_requires_two_sources(self):
        def change(r, cfg, bounds):
            # Isolate certificate count from the independent live-fraction gate.
            bounds["min_live_fraction"] = 0.8
            for x in r:
                if x["t"] == "blk" and x["seq"] == 2 and x["src"] != "node1":
                    x.update(ok=False, unsupported=True)

        self.run_case(change)

    def test_full_ids_require_three_sources(self):
        def change(r, *_):
            next(x for x in r if x["t"] == "blk" and x["seq"] == 2 and x["src"] == "node5").pop(
                "rid"
            )

        self.run_case(change)

    def test_missing_live_heads(self):
        self.run_case(lambda r, *_: r.__setitem__(slice(None), [x for x in r if x["t"] != "head"]))

    def test_shard_inclusion_requires_two_sources(self):
        self.run_case(
            lambda r, *_: r.__setitem__(
                slice(None), [x for x in r if x["t"] != "shp" or x["src"] == "node1"]
            )
        )

    def test_outgoing_boundary_set_must_match(self):
        def change(r, *_):
            for x in r:
                if x["t"] == "blk" and x["seq"] == 4:
                    x["set"] = "new"

        self.assertEqual(self.run_case(change)["verdict"], "FAIL")

    def test_incoming_set_must_certify_following_block(self):
        def change(r, *_):
            for x in r:
                if x["t"] == "blk" and x["seq"] == 5:
                    x["set"] = "old"

        self.assertEqual(self.run_case(change)["verdict"], "FAIL")


if __name__ == "__main__":
    unittest.main()
