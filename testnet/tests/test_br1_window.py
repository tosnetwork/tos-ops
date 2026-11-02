"""Window decisions over explicit synthetic metadata, not a signature claim."""

import base64
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
import br1_window as window
from con01_history.certificate import Refused


def fixture(now=10000, since=8000, until=15000):
    target = {
        "workchain": -1,
        "shard": "-9223372036854775808",
        "seqno": 100,
        "root_hash": base64.b64encode(b"r" * 32).decode(),
        "file_hash": base64.b64encode(b"f" * 32).decode(),
    }
    current = dict(global_id=2, version=16, total=4, since=since, until=until, set_hash="a" * 64)
    row = dict(
        id=target,
        header={"gen_utime": now - 1},
        term_schedule="within_schedule",
        validator_since=since,
        validator_until=until,
        set_hash=current["set_hash"],
    )
    chain = {
        "status": "VERIFIED_GENESIS_CHAIN_AND_THREE_SOURCE_SUFFIX",
        "target": target,
        "sources": {name: {"links": [copy.deepcopy(row)]} for name in ("node1", "node3", "node5")},
    }
    return chain, [current, copy.deepcopy(current)], [0, 0], now


class Window(unittest.TestCase):
    def test_unknown_proof_status_never_qualifies(self):
        values = fixture()
        values[0]["status"] = "INCONCLUSIVE"
        with self.assertRaises(Refused):
            window.assess(*values)

    def test_validity_never_outlives_oldest_proved_header(self):
        values = fixture()
        values[0]["sources"]["node3"]["links"][-1]["header"]["gen_utime"] = 9971
        result = window.assess(*values)
        self.assertTrue(result["quiet"])
        self.assertLessEqual(result["valid_until_utc"], 10001)

    def test_dynamic_term_and_expiring_nonapproval(self):
        for now in (10000, 900000):
            try:
                result = window.assess(*fixture(now, now - 2000, now + 5000))
            except Refused as error:
                self.fail("dynamic term refused: " + str(error))
            self.assertTrue(result["quiet"])
            self.assertLessEqual(result["valid_until_utc"] - now, 30)
            self.assertFalse(result["public_activation_approved"])

    def test_settlement_boundary(self):
        result = window.assess(*fixture(8904))
        self.assertEqual(result["reasons"], ["term_not_settled"])
        self.assertTrue(window.assess(*fixture(8905))["quiet"])

    def test_handover_boundary(self):
        self.assertTrue(window.assess(*fixture(13199))["quiet"])
        self.assertEqual(window.assess(*fixture(13200))["reasons"], ["too_close_to_handover"])

    def test_active_election_blocks(self):
        chain, configs, _, now = fixture()
        self.assertEqual(
            window.assess(chain, configs, [0, 17], now)["reasons"], ["active_election"]
        )

    def test_malformed_election_is_not_inactive(self):
        for invalid in (False, "0", -1):
            chain, configs, _, now = fixture()
            with self.assertRaises(Refused):
                window.assess(chain, configs, [0, invalid], now)

    def test_stale_or_future_signed_target_refuses(self):
        for stamp in (9900, 10006):
            values = fixture()
            values[0]["sources"]["node3"]["links"][-1]["header"]["gen_utime"] = stamp
            with self.assertRaises(Refused):
                window.assess(*values)

    def test_expired_governing_set_refuses(self):
        values = fixture()
        values[0]["sources"]["node3"]["links"][-1]["term_schedule"] = "after_schedule"
        with self.assertRaises(Refused):
            window.assess(*values)

    def test_config_must_match_certified_governing_set(self):
        values = fixture()
        for config in values[1]:
            config["set_hash"] = "b" * 64
        with self.assertRaises(Refused):
            window.assess(*values)

    def test_config_peer_disagreement_refuses(self):
        values = fixture()
        values[1][1]["until"] += 1
        with self.assertRaises(Refused):
            window.assess(*values)

    def test_source_population_and_full_target_are_required(self):
        values = fixture()
        del values[0]["sources"]["node5"]
        with self.assertRaises(Refused):
            window.assess(*values)
        values = fixture()
        values[0]["sources"]["node5"]["links"][-1]["id"]["file_hash"] = base64.b64encode(
            b"x" * 32
        ).decode()
        with self.assertRaises(Refused):
            window.assess(*values)

    def test_network_and_version_are_not_interchangeable(self):
        for key, invalid in (("global_id", 3), ("version", 15), ("total", 3)):
            values = fixture()
            for config in values[1]:
                config[key] = invalid
            with self.assertRaises(Refused):
                window.assess(*values)


class RealConfig(unittest.TestCase):
    def setUp(self):
        data = Path(__file__).with_name("data") / "br1-window"
        self.key = json.loads((data / "key.json").read_bytes())
        reply = json.loads((data / "config.json").read_bytes())["result"]

        class FixtureRpc:
            def call(self, method, params, path):
                if method != "getProofQuery":
                    raise RuntimeError("not a config proof read")
                return reply

        self.rpc = FixtureRpc()
        self.addCleanup(window.f.Cell.hd.cache_clear)

    def test_real_config_proof_decodes_public_version16_set(self):
        config = window.config(self.rpc, self.key, None)
        self.assertEqual((config["global_id"], config["version"], config["total"]), (2, 16, 4))

    def test_real_config_requires_certified_full_key_identity(self):
        for field in ("root_hash", "file_hash"):
            wrong = dict(self.key)
            wrong[field] = base64.b64encode(bytes(32)).decode()
            with self.assertRaisesRegex(Refused, "differs from certified key"):
                window.config(self.rpc, wrong, None)


class ElectionGetter(unittest.TestCase):
    def invoke(self, value):
        raw = json.dumps(value).encode()

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self, maximum):
                return raw[:maximum]

        class Opener:
            def open(self, request, timeout):
                if json.loads(request.data)["method"] != "runGetMethod":
                    raise RuntimeError("not a read-only getter")
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            return window.election(
                SimpleNamespace(url="http://127.0.0.1:48081/jsonRPC", opener=Opener()),
                Path(directory) / "reply.json",
            )

    def test_single_numeric_getter_is_decoded(self):
        self.assertEqual(self.invoke({"result": {"exit_code": 0, "stack": [["num", "0x0"]]}}), 0)

    def test_extra_or_malformed_getter_fields_refuse(self):
        for stack in ([["num", "0x0", "extra"]], [], [["num"]], ["num"], {"0": ["num", "0x0"]}):
            with self.assertRaises(Refused):
                self.invoke({"result": {"exit_code": 0, "stack": stack}})
        for status in (False, 0.0):
            with self.assertRaises(Refused):
                self.invoke({"result": {"exit_code": status, "stack": [["num", "0x0"]]}})


if __name__ == "__main__":
    unittest.main()
