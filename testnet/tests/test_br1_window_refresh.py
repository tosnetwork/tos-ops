"""Refresh ordering/trust boundaries with mock RPC, not a cryptographic claim."""

import base64
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
import br1_window as w
from con01_history.certificate import Refused


class Refresh(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        (self.out / "chain").mkdir()

        def block(n):
            return dict(
                workchain=-1,
                shard="-9223372036854775808",
                seqno=n,
                root_hash=base64.b64encode(bytes([n]) * 32).decode(),
                file_hash=base64.b64encode(bytes([n + 1]) * 32).decode(),
            )

        self.anchor, self.join, self.old, self.new = [block(n) for n in (0, 10, 20, 30)]
        self.prefix = dict(
            status="VERIFIED_GENESIS_CHAIN_AND_THREE_SOURCE_SUFFIX",
            anchor=self.anchor,
            target=self.old,
            sources={
                "node5": dict(
                    from_genesis=True, anchor=self.anchor, target=self.old, keys={"10": self.join}
                )
            },
        )
        (self.out / "chain/REPORT.json").write_text(json.dumps(self.prefix))
        self.args = SimpleNamespace(
            out=self.out,
            archive="node5",
            rpc=[
                "node1=http://127.0.0.1:1",
                "node3=http://127.0.0.1:3",
                "node5=http://127.0.0.1:5",
            ],
        )
        self.head = self.new
        self.genesis = self.anchor
        self.mismatch = False
        self.network = 2
        self.keys_mismatch = False
        self.calls = []
        outer = self

        class Rpc:
            def __init__(self, url):
                self.url = url

            def call(self, method, params, path):
                outer.calls.append(method)
                if method == "getMasterchainInfo":
                    return dict(init=outer.genesis, last=outer.head)
                target = copy.deepcopy(outer.new)
                if outer.mismatch and self.url.endswith(":3"):
                    target["file_hash"] = outer.old["file_hash"]
                return dict(global_id=outer.network, id=target)

        self.rpc = Rpc

        def acquire(rpc, join, target, path, verifier):
            self.assertEqual(join, self.join)
            self.assertEqual(target, self.new)
            keys = {"10": self.join}
            if self.keys_mismatch and rpc.url.endswith(":3"):
                keys["11"] = self.old
            self.calls.append("prove")
            return dict(keys=keys, links=[dict(id=target, header={"gen_utime": 100})])

        self.acquire = acquire

    def invoke(self):
        with (
            patch.object(w.audit, "Rpc", self.rpc),
            patch.object(w.audit, "acquire", side_effect=self.acquire),
        ):
            return w.refresh_target(self.args, self.prefix, None)

    def test_new_target_proved_on_all_three_after_prefix(self):
        r = self.invoke()
        self.assertEqual(r["target"], self.new)
        self.assertEqual(len(r["sources"]), 3)
        self.assertEqual(self.calls.count("prove"), 3)
        self.assertEqual(self.calls[:3], ["getMasterchainInfo"] * 3)

    def test_non_genesis_prefix_refused(self):
        self.prefix["sources"]["node5"]["from_genesis"] = False
        with self.assertRaisesRegex(Refused, "genesis prefix"):
            self.invoke()
        self.assertEqual(self.calls, [])

    def test_substituted_genesis_refused(self):
        self.genesis = self.join
        with self.assertRaisesRegex(Refused, "genesis mismatch"):
            self.invoke()

    def test_backward_target_refused(self):
        self.head = self.join
        with self.assertRaisesRegex(Refused, "backwards"):
            self.invoke()

    def test_full_target_mismatch_refused(self):
        self.mismatch = True
        with self.assertRaisesRegex(Refused, "full target"):
            self.invoke()

    def test_key_chain_disagreement_refused(self):
        self.keys_mismatch = True
        with self.assertRaisesRegex(Refused, "key chain"):
            self.invoke()

    def test_wrong_network_refused(self):
        self.network = 3
        with self.assertRaisesRegex(Refused, "public network"):
            self.invoke()
