"""Real retained certificate through the replay observer adapter, not just its library."""

import copy
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "testnet" / "acceptance"))
from con01_history import formats as f  # noqa: E402
from con01_history import observer
from con01_history.certificate import SignatureVerifier, source_params, verify_packet  # noqa: E402

DATA = Path(__file__).with_name("data") / "con01-history"


class ObserverCrypto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = SignatureVerifier(
            Path(os.environ["CON01_SIGNATURE_VERIFIER"]),
            os.environ["CON01_SIGNATURE_VERIFIER_SHA256"],
        )
        cls.addClassCleanup(cls.backend.close)
        cls.raw = (DATA / "expired-current-set.tl").read_bytes()
        cls.anchor = json.loads((DATA / "anchor.json").read_bytes())
        result = verify_packet(cls.raw, cls.anchor, cls.backend)
        if not result["complete"]:
            raise RuntimeError("real fixture not independently verified")

    def setUp(self):
        _, _, links = f.forward_proof(self.raw)
        link = links[0]
        self.stage = object.__new__(observer.StageA)
        self.stage.init = {"fixture": True}
        self.stage.st = {"certified_keys": {str(self.anchor["seqno"]): observer.ids(link["src"])}}
        self.stage.keys = {self.anchor["seqno"]: source_params(link["config"], link["src"])}
        header = f.block_header(link["dest"])
        self.rec = dict(
            src="node1",
            seqno=264347,
            utc=header["gen_utime"] + 0.1,
            hdr=json.dumps(
                {
                    "result": {
                        "id": link["dst"],
                        "prev_key_block_seqno": self.anchor["seqno"],
                        "gen_utime": header["gen_utime"],
                        "is_key_block": False,
                    }
                }
            ),
            proof=json.dumps({"result": {"reply": f.B(self.raw)}}),
        )
        self.previous = observer.SIGNATURE_BACKEND
        observer.SIGNATURE_BACKEND = self.backend
        self.addCleanup(setattr, observer, "SIGNATURE_BACKEND", self.previous)
        self.addCleanup(f.Cell.hd.cache_clear)

    def test_expired_schedule_passes_full_observer(self):
        result = self.stage.verify_block(self.rec)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["gu"] - result["until"], 1)
        self.assertEqual(result["signers"], 3)

    def test_cached_key_file_hash_is_bound_before_verification(self):
        self.assertTrue(self.stage.verify_block(self.rec)["ok"])
        self.stage.st = copy.deepcopy(self.stage.st)
        self.stage.st["certified_keys"][str(self.anchor["seqno"])][1] = f.B(bytes(32))
        result = self.stage.verify_block(self.rec)
        self.assertFalse(result["ok"], result)
        self.assertIn("previously certified full key-block id", result["reason"])


if __name__ == "__main__":
    unittest.main()
