import argparse
import importlib.util
import json

import pytest
import testnet_lib as lib
from conftest import SCRIPTS

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
    return argparse.Namespace(genesis=genesis, rpc=urls, max_age=max_age, genesis_set=None)


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
