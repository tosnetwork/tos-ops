import argparse
import base64
import importlib.util
import json

import pytest
import testnet_lib as lib
from conftest import DATA, SCRIPTS, one_key_list, serialize_boc

spec = importlib.util.spec_from_file_location("check_testnet", SCRIPTS / "check-testnet.py")
check_testnet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_testnet)

ZERO = lib.zero_state_entry(b"\x01" * 32, b"\x02" * 32)
NOW = 1_800_000_000
SHARD = str(lib.MASTERCHAIN_SHARD)


def block(seqno, root=b"\x0a"):
    return {
        "workchain": -1,
        "shard": SHARD,
        "seqno": seqno,
        "root_hash": lib.b64(root * 32),
        "file_hash": lib.b64(b"\x0b" * 32),
    }


class FakeNodes:
    """Each node: its zero state, head height and the block it holds at each height."""

    def __init__(self, nodes):
        self.nodes = nodes

    def __call__(self, url, method, **params):
        node = self.nodes[url]
        if method == "getMasterchainInfo":
            return {"init": node.get("init", {**ZERO, "shard": SHARD}), "last": block(node["head"])}
        if method == "getBlockHeader":
            seqno = params["seqno"]
            return {
                "id": node.get("blocks", {}).get(seqno, block(seqno)),
                "global_id": node.get("global_id", 2),
                "gen_utime": node.get("times", {}).get(seqno, node.get("gen_utime", NOW - 5)),
            }
        raise AssertionError(method)


def args(tmp_path, urls, max_age=120):
    genesis = tmp_path / "genesis.json"
    genesis.write_text(json.dumps({"global_id": 2, "zero_state": ZERO}))
    return argparse.Namespace(
        genesis=genesis, rpc=urls, max_age=max_age, genesis_set=None, elected_set=None
    )


def run(tmp_path, nodes, **kwargs):
    return check_testnet.check(
        args(tmp_path, list(nodes), **kwargs), rpc=FakeNodes(nodes), now=lambda: NOW
    )


def test_agreeing_nodes_pass_at_the_common_head(tmp_path):
    summary = run(tmp_path, {"a": {"head": 50}, "b": {"head": 47}})
    assert summary["height"] == 47
    assert summary["global_id"] == 2


def test_one_node_is_not_enough(tmp_path):
    with pytest.raises(lib.TestnetError, match="at least two"):
        run(tmp_path, {"a": {"head": 50}})


def test_same_height_different_block_is_a_disagreement(tmp_path):
    nodes = {"a": {"head": 50}, "b": {"head": 50, "blocks": {50: block(50, root=b"\x0c")}}}
    with pytest.raises(lib.TestnetError, match="disagree"):
        run(tmp_path, nodes)


def test_foreign_zero_state_is_refused(tmp_path):
    foreign = {**lib.zero_state_entry(b"\x09" * 32, b"\x02" * 32), "shard": SHARD}
    with pytest.raises(lib.TestnetError, match="another network"):
        run(tmp_path, {"a": {"head": 5}, "b": {"head": 5, "init": foreign}})


def test_wrong_global_id_is_refused(tmp_path):
    nodes = {"a": {"head": 5, "global_id": 1}, "b": {"head": 5, "global_id": 1}}
    with pytest.raises(lib.TestnetError, match="global id"):
        run(tmp_path, nodes)


def test_stale_head_is_refused(tmp_path):
    nodes = {"a": {"head": 5, "gen_utime": NOW - 600}, "b": {"head": 5, "gen_utime": NOW - 600}}
    with pytest.raises(lib.TestnetError, match="stalled"):
        run(tmp_path, nodes)


def test_one_node_behind_is_named_not_called_a_stall(tmp_path):
    # Epoch 1: one validator lagged, and the checker called the whole network stalled.
    nodes = {
        "a": {"head": 2000, "gen_utime": NOW - 3},
        "b": {"head": 2000, "gen_utime": NOW - 3},
        "lagging": {"head": 1340, "times": {1340: NOW - 660}, "gen_utime": NOW - 3},
    }
    with pytest.raises(lib.TestnetError) as refused:
        run(tmp_path, nodes)
    message = str(refused.value)
    assert "stalled" not in message
    assert "lagging at 1340 (660 blocks behind, head 660 s old)" in message
    assert "a at" not in message and "b at" not in message


def test_a_fresh_node_slightly_behind_passes(tmp_path):
    nodes = {
        "a": {"head": 2000, "gen_utime": NOW - 2},
        "b": {"head": 1998, "times": {1998: NOW - 6}, "gen_utime": NOW - 2},
    }
    summary = run(tmp_path, nodes)
    assert summary["heads"] == {"a": 2000, "b": 1998}
    assert summary["head_ages"] == {"a": 2, "b": 6}


def test_no_block_after_zero_state_is_refused(tmp_path):
    with pytest.raises(lib.TestnetError, match="no masterchain block"):
        run(tmp_path, {"a": {"head": 0}, "b": {"head": 3}})


# ---------------------------------------------------------------- ConfigParam 34 after a rotation


def records(n=4):
    from test_testnet_lib import public_record

    return [public_record(i + 1) for i in range(n)]


def decoded_set(controllers, main=None, since=1_800_000_000, until=1_800_014_400):
    return {
        "utime_since": since,
        "utime_until": until,
        "total": len(controllers),
        "main": len(controllers) if main is None else main,
        "validators": [
            {"controller_id_hex": c, "consensus_key_id_hex": f"{i:064x}"}
            for i, c in enumerate(controllers)
        ],
    }


class FakeNodesWithConfig(FakeNodes):
    def __call__(self, url, method, **params):
        if method == "getConfigParam":
            return {"config": {"bytes": "unused"}}
        return super().__call__(url, method, **params)


def run_elected(tmp_path, decoded, recs=None):
    recs = records() if recs is None else recs
    path = tmp_path / "records.json"
    path.write_text(json.dumps(recs))
    a = args(tmp_path, ["a", "b"])
    a.elected_set = path
    nodes = {"a": {"head": 50}, "b": {"head": 50}}
    return check_testnet.check(
        a, rpc=FakeNodesWithConfig(nodes), now=lambda: NOW, decode=lambda _boc: decoded
    )


def test_elected_set_with_the_records_controllers_passes_and_reports_its_term(tmp_path):
    recs = records()
    summary = run_elected(tmp_path, decoded_set([r["controller_id"] for r in recs]), recs)
    assert summary["config34"]["utime_since"] == 1_800_000_000
    assert summary["config34"]["utime_until"] == 1_800_014_400
    assert summary["config34"]["total"] == 4


def test_elected_set_missing_a_controller_is_refused(tmp_path):
    recs = records()
    controllers = [r["controller_id"] for r in recs[:3]] + ["ab" * 32]
    with pytest.raises(lib.TestnetError, match="controllers differ"):
        run_elected(tmp_path, decoded_set(controllers), recs)


def test_elected_set_of_three_is_refused(tmp_path):
    recs = records()
    with pytest.raises(lib.TestnetError, match="has 3 members"):
        run_elected(tmp_path, decoded_set([r["controller_id"] for r in recs[:3]]), recs)


def test_elected_set_with_a_non_main_member_is_refused(tmp_path):
    recs = records()
    with pytest.raises(lib.TestnetError, match="3 main"):
        run_elected(tmp_path, decoded_set([r["controller_id"] for r in recs], main=3), recs)


def test_genesis_and_elected_set_are_exclusive(capsys):
    with pytest.raises(SystemExit):
        check_testnet.main(
            [
                "--genesis",
                "g",
                "--rpc",
                "a",
                "--rpc",
                "b",
                "--genesis-set",
                "x",
                "--elected-set",
                "y",
            ]
        )


# ---------------------------------------------------------------- ConfigParam 48 (version 16)

ZERO_STATE_PARAMS = lib.zero_state_config((DATA / "zerostate-v16-auth.boc").read_bytes())[2]
TAG_HEX = "e36440a2e7704d9e26c79c5d9ba462507783b18404e876da9a232d38722e28fd"


class FakeNodesWithParams(FakeNodes):
    """getConfigParam answers each number with a cell, as the node does: a BOC in config.bytes."""

    def __init__(self, nodes, params):
        super().__init__(nodes)
        self.params, self.asked = params, []

    def __call__(self, url, method, **params):
        if method == "getConfigParam":
            self.asked.append((params["param"], params["seqno"]))
            boc = serialize_boc(self.params[params["param"]])
            return {"@type": "configInfo", "config": {"bytes": base64.b64encode(boc).decode()}}
        return super().__call__(url, method, **params)


def run_auth(tmp_path, params, recorded_hash=None):
    a = args(tmp_path, ["a", "b"])
    genesis = json.loads(a.genesis.read_text())
    genesis["global_version"] = 16
    genesis["auth_policy"] = {
        "network_tag_hex": TAG_HEX,
        "config_param_48_hash_hex": recorded_hash or ZERO_STATE_PARAMS[48].hash().hex(),
    }
    a.genesis.write_text(json.dumps(genesis))
    nodes = FakeNodesWithParams({"a": {"head": 50}, "b": {"head": 51}}, params)
    return check_testnet.check(a, rpc=nodes, now=lambda: NOW), nodes


def test_live_auth_policy_is_checked_at_the_common_block(tmp_path):
    summary, nodes = run_auth(tmp_path, ZERO_STATE_PARAMS)
    assert summary["config48"] == {
        "version": 16,
        "network_tag_hex": TAG_HEX,
        "sequence": 0,
        "hash_hex": ZERO_STATE_PARAMS[48].hash().hex(),
        "unchanged_since_genesis": True,
        "mandatory_and_critical": True,
    }
    assert sorted(nodes.asked) == [(8, 50), (9, 50), (10, 50), (48, 50)]


def test_live_auth_policy_reports_a_replaced_record(tmp_path):
    summary, _ = run_auth(tmp_path, ZERO_STATE_PARAMS, recorded_hash="00" * 32)
    assert summary["config48"]["unchanged_since_genesis"] is False


def test_live_auth_policy_with_another_tag_is_refused(tmp_path):
    cell = ZERO_STATE_PARAMS[48]
    data = bytearray(cell.data)
    data[1] ^= 0x01  # inside the network tag
    other = lib.Cell(bytes(data), cell.bits, list(cell.refs))
    with pytest.raises(lib.TestnetError, match="carries tag"):
        run_auth(tmp_path, {**ZERO_STATE_PARAMS, 48: other})


@pytest.mark.parametrize("number,name", [(9, "mandatory"), (10, "critical")])
def test_live_auth_policy_outside_a_list_is_refused(tmp_path, number, name):
    with pytest.raises(lib.TestnetError, match=f"not {name}"):
        run_auth(tmp_path, {**ZERO_STATE_PARAMS, number: one_key_list(47)})


def test_live_version_below_the_genesis_is_refused(tmp_path):
    cell = ZERO_STATE_PARAMS[8]
    data = bytearray(cell.data)
    data[4] ^= 0x10  # version 16 -> 0
    with pytest.raises(lib.TestnetError, match="version 0"):
        run_auth(tmp_path, {**ZERO_STATE_PARAMS, 8: lib.Cell(bytes(data), cell.bits, [])})


def test_a_version_16_genesis_without_auth_policy_is_refused(tmp_path):
    # Not skipped: every version-16 genesis the ceremony writes records it.
    a = args(tmp_path, ["a", "b"])
    genesis = json.loads(a.genesis.read_text())
    genesis["global_version"] = 16
    a.genesis.write_text(json.dumps(genesis))
    nodes = FakeNodesWithParams({"a": {"head": 50}, "b": {"head": 50}}, ZERO_STATE_PARAMS)
    with pytest.raises(lib.TestnetError, match="records no auth_policy"):
        check_testnet.check(a, rpc=nodes, now=lambda: NOW)
    assert nodes.asked == []


def test_an_older_genesis_is_checked_without_config48(tmp_path):
    a = args(tmp_path, ["a", "b"])
    genesis = json.loads(a.genesis.read_text())
    genesis["global_version"] = 15
    a.genesis.write_text(json.dumps(genesis))
    summary = check_testnet.check(
        a, rpc=FakeNodes({"a": {"head": 50}, "b": {"head": 50}}), now=lambda: NOW
    )
    assert "config48" not in summary
