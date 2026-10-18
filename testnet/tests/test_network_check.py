"""Shared production checks against recorded public chain cells and proof material."""

import argparse
import base64
import copy
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
import testnet_lib as wire

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "production"))
import network_check as n  # noqa: E402

DATA = Path(__file__).parent / "data"
RECORD = json.loads((DATA / "network-check-epoch4.json").read_text())
CELLS = {int(k): wire.parse_boc(base64.b64decode(v)) for k, v in RECORD["params"].items()}
ELECTOR = n.decode_elector(wire.parse_boc(base64.b64decode(RECORD["elector_data"])))
NOW = 1_800_000_000


def block(seq=10):
    return {
        "workchain": -1,
        "shard": n.SHARD,
        "seqno": seq,
        "root_hash": wire.b64(b"a" * 32),
        "file_hash": wire.b64(b"b" * 32),
    }


def identity(gid=2):
    return n.identity_from_config({"validator": {"zero_state": block(0)}}, gid)


class Nodes:
    def __init__(self, gid=2, change=None):
        self.gid, self.change = gid, change or {}

    def __call__(self, url, method, **params):
        change = self.change if url == "b" else {}
        if method == "getMasterchainInfo":
            return {"init": change.get("zero", block(0)), "last": block(10)}
        if method == "getBlockHeader":
            return {
                "id": change.get("id", block(params["seqno"])),
                "global_id": change.get("gid", self.gid),
                "gen_utime": change.get("time", NOW - 5),
                "prev_key_block_seqno": 1,
            }
        raise AssertionError(method)


@pytest.mark.parametrize("gid", [1, 2])
def test_network_identity_is_explicit_for_both_networks(gid):
    args = argparse.Namespace(rpc=["a", "b"], max_age=120)
    assert n.check_agreement(args, identity(gid), Nodes(gid), lambda: NOW)["global_id"] == gid


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"zero": block(1)}, "another network"),
        ({"id": {**block(), "root_hash": wire.b64(b"x" * 32)}}, "disagree"),
        ({"time": NOW - 600}, "behind"),
        ({"gid": 99}, "global id"),
    ],
)
def test_cross_node_refusals(change, reason):
    with pytest.raises(n.NetworkError, match=reason):
        n.check_agreement(
            argparse.Namespace(rpc=["a", "b"], max_age=120),
            identity(),
            Nodes(change=change),
            lambda: NOW,
        )


@pytest.mark.parametrize("gid", [True, 1 << 31, -(1 << 31) - 1])
def test_identity_range(gid):
    with pytest.raises(n.NetworkError, match="global id"):
        identity(gid)


def test_init_block_anchor_is_independent_of_zero_state():
    result = n.identity_from_config(
        {"validator": {"zero_state": block(0), "init_block": block(5)}}, 1
    )
    assert result["anchor"]["seqno"] == 5 and result["zero_state"]["seqno"] == 0


@pytest.mark.parametrize("mutation", ["workchain", "shard", "hash", "seqno"])
def test_invalid_anchor(mutation):
    b = block(0)
    b.update(
        {"workchain": 0}
        if mutation == "workchain"
        else {"shard": "bad"}
        if mutation == "shard"
        else {"root_hash": "bad"}
        if mutation == "hash"
        else {"seqno": -1}
    )
    with pytest.raises(n.NetworkError):
        n.identity_from_config({"validator": {"zero_state": b}}, 1)


def test_recorded_current_set_matches_retained_elector_commitment():
    result = n.compare_elected(n.decode_set(CELLS[34]), ELECTOR)
    assert result["status"] == "PASS" and result["members"] == 4
    assert result["keys_and_order_bound_by"] == "Elector vset_hash"


@pytest.mark.parametrize("field,value", [("id", "00" * 32), ("weight", 0)])
def test_frozen_members_and_weights_must_match(field, value):
    elector = copy.deepcopy(ELECTOR)
    current = n.decode_set(CELLS[34])
    chosen = next(p for p in elector["past"] if p["hash"] == current["hash"])
    chosen["members"][0][field] = value
    with pytest.raises(n.NetworkError, match="members/weights"):
        n.compare_elected(current, elector)


@pytest.mark.parametrize("field,value", [("key_id", "ab" * 32), ("public_key", "cd" * 1312)])
def test_changed_key_cannot_match_the_elector_commitment(field, value):
    changed = n.decode_set(CELLS[34])
    changed["validators"][0][field] = value
    # Changing any serialized descriptor changes the cell commitment, even if
    # frozen identities/weights alone would still look identical.
    changed["hash"] = "ff" * 32
    with pytest.raises(n.NetworkError, match="commitment"):
        n.compare_elected(changed, ELECTOR)


def test_old_record_absence_is_not_success():
    elector = {**ELECTOR, "past": []}
    with pytest.raises(n.NetworkError, match="commitment"):
        n.compare_elected(n.decode_set(CELLS[32]), elector)


def test_genesis_exception_requires_the_independently_bound_initial_hash():
    vset = n.decode_set(CELLS[34])
    empty = {**ELECTOR, "past": []}
    assert (
        n.check_election_sets({34: CELLS[34], 32: None}, empty, True, vset["hash"])["current"][
            "status"
        ]
        == "NOT_APPLICABLE"
    )
    with pytest.raises(n.NetworkError, match="differs from initial"):
        n.check_election_sets({34: CELLS[34], 32: None}, empty, True, "00" * 32)
    with pytest.raises(n.NetworkError, match="commitment"):
        n.check_election_sets({34: CELLS[34], 32: None}, empty, False, vset["hash"])


def test_key_id_is_derived_not_trusted():
    root = CELLS[34]
    s = wire.Slice(root)
    s.bits(8 + 32 + 32 + 16 + 16 + 64)
    leaf = next(iter(n.read_dict(s, 16).values()))
    raw = bytearray(leaf.cell.data)
    offset = leaf.pos + 8 + 256 + 16
    raw[offset // 8] ^= 1 << (7 - offset % 8)
    target = leaf.cell

    def replace(c):
        return wire.Cell(
            bytes(raw) if c is target else c.data, c.bits, [replace(r) for r in c.refs]
        )

    with pytest.raises(n.NetworkError, match="key id"):
        n.decode_set(replace(root))


def test_snapshot_parser_refuses_truncation():
    with pytest.raises(n.NetworkError):
        n.decode_elector(wire.Cell(b"", 0, []))


def test_transport_cannot_write():
    with pytest.raises(n.NetworkError, match="non-read-only"):
        n.PacedRpc()("https://invalid.example/jsonRPC", "sendQuery", body="anything")


def test_config_agreement_and_absence():
    def rpc(url, method, **params):
        if params["param"] == 32:
            raise wire.RpcError(url, method, -32004, "CONFIG_PARAM_ABSENT", "absent", False)
        return {"config": {"bytes": RECORD["params"]["34"]}}

    assert n.same_cells(rpc, ["a", "b"], 34, 5).hash() == CELLS[34].hash()
    assert n.same_cells(rpc, ["a", "b"], 32, 5, optional=True) is None
    with pytest.raises(wire.RpcError):
        n.same_cells(rpc, ["a", "b"], 32, 5)


def proof_library():
    path = os.environ.get("PROOF_VERIFY_LIBRARY")
    if not path:
        root = os.environ.get("TOS_ROOT")
        path = (
            str(Path(root) / "build/lite-client/proof-verify/libtosproofverify.so") if root else ""
        )
    if not Path(path).is_file():
        pytest.skip("set PROOF_VERIFY_LIBRARY to the built consensus verification library")
    return n.ProofVerifier(path)


def proof_fixture():
    root = DATA / "network-check-proof"
    anchor = json.loads((root / "anchor.json").read_text())
    request = json.loads((root / "request.json").read_text())
    parts = [
        (kind, (root / file).read_bytes())
        for kind, file in [
            (2, "chain-0000.tl"),
            (4, "config.tl"),
            (5, "account.tl"),
            (6, "exec-config.tl"),
        ]
    ]
    return anchor, request, parts


def test_real_recorded_proof_verifies():
    a, r, parts = proof_fixture()
    result = proof_library().verify_material(a, r, parts, 1791200932)
    assert result["status"] == "verified"
    assert result["target"]["seqno"] == r["target"]["seqno"]


@pytest.mark.parametrize("mutation", ["signature", "link"])
def test_real_forged_signature_and_broken_link_refused(mutation):
    a, r, parts = proof_fixture()
    chain = bytearray(parts[0][1])
    if mutation == "signature":
        # The TL bytes prefix for a 2420-byte ML-DSA-44 signature, whose
        # payload is raw rather than a BOC; keep TL structure unchanged.
        prefix = b"\xfe\x74\x09\x00"
        offset = chain.find(prefix)
        assert offset >= 0
        assert chain[offset - 4 : offset] == b"\x01\x00\x00\x00"
        chain[offset + 4 + 100] ^= 1
    else:
        offset = chain.find(bytes.fromhex(a["root_hash"]))
        assert offset >= 0
        chain[offset] ^= 1
    parts[0] = (2, bytes(chain))
    with pytest.raises(n.NetworkError, match="verification refused"):
        proof_library().verify_material(a, r, parts, 1791200932)


def test_shared_cli_has_no_parallel_agreement_implementation():
    source = (ROOT / "testnet/scripts/check-testnet.py").read_text()
    assert "shared.check_agreement" in source
    assert "getMasterchainInfo" not in source[source.index("def check(") :]
    entry = (ROOT / "production/scripts/check-network.py").read_text()
    assert "check_network(a)" in entry


def test_production_cli_requires_identity():
    spec = importlib.util.spec_from_file_location(
        "check_network_cli", ROOT / "production/scripts/check-network.py"
    )
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    with pytest.raises(SystemExit):
        cli.main(["--rpc", "https://a.example/jsonRPC"])


def dictionary(entries, size):
    entries = {f"{k:0{size}b}": v for k, v in entries.items()}

    def build(items, bits):
        keys = list(items)
        prefix = 0
        while prefix < bits and len({k[prefix] for k in keys}) == 1:
            prefix += 1
        label = "10" + format(prefix, f"0{bits.bit_length()}b") + keys[0][:prefix]
        if prefix == bits:
            value = next(iter(items.values()))
            payload = "".join(f"{byte:08b}" for byte in value.data)[: value.bits]
            return wire.cell_from_bits(label + payload, value.refs)
        return wire.cell_from_bits(
            label,
            [
                build(
                    {k[prefix + 1 :]: v for k, v in items.items() if k[prefix] == side},
                    bits - prefix - 1,
                )
                for side in ("0", "1")
            ],
        )

    return build(entries, size)


def retained_elector_data():
    past = {}
    for i, number in enumerate((32, 34), 1):
        v = n.decode_set(CELLS[number])
        frozen = {}
        for row in v["validators"]:
            bits = f"{int(row['id'], 16):0256b}{row['weight']:064b}" + "0001" + "00000001" + "0"
            frozen[int(row["id"], 16)] = wire.cell_from_bits(bits)
        bits = (
            f"{v['until'] + 7200:032b}{7200:032b}{int(v['hash'], 16):0256b}"
            + "1"
            + "0001"
            + "00000100"
            + "0000"
            + "0"
        )
        past[i] = wire.cell_from_bits(bits, [dictionary(frozen, 256)])
    current = n.decode_set(CELLS[34])
    return wire.cell_from_bits(
        "001" + "0000" + f"{2:032b}{int(current['hash'], 16):0256b}", [dictionary(past, 32)]
    )


class ProductionNodes(Nodes):
    def __init__(self, change=None):
        super().__init__(change=change)
        self.params = dict(RECORD["params"])
        self.data = retained_elector_data()
        self.proof_calls = []

    def __call__(self, url, method, **params):
        if method == "getConfigParam":
            return {"config": {"bytes": self.params[str(params["param"])]}}
        if method == "getProofQuery":
            self.proof_calls.append(url)
            raise wire.RpcError(url, method, -32601, "METHOD_NOT_FOUND", "unknown query", False)
        if method == "getAddressInformation":
            return {"data": wire.b64(wire.serialize_boc(self.data)), "block_id": block(10)}
        return super().__call__(url, method, **params)


def production_args(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"validator": {"zero_state": block(0)}}))
    return argparse.Namespace(
        global_config=config,
        global_id=2,
        rpc=["a", "b"],
        max_age=120,
        min_version=16,
        expected_auth_tag=n.lib.auth_policy(CELLS[48])["network"].hex(),
        expected_cp48_hash=None,
        proof_library=None,
    )


def test_full_production_pipeline_labels_missing_proof_routes_weaker(tmp_path):
    nodes = ProductionNodes()
    result = n.check_network(production_args(tmp_path), nodes, lambda: NOW)
    assert result["ok"], result
    assert result["strength"] == "node_equality_only"
    assert nodes.proof_calls == ["a", "b"]
    assert any(
        c["name"] == "config34_vs_elector" and c["status"] == "PASS" for c in result["checks"]
    )
    assert any(
        c["name"] == "config32_vs_elector" and c["status"] == "PASS" for c in result["checks"]
    )
    assert any(
        c["name"] == "anchored_finality" and c["status"] == "WEAKER" for c in result["checks"]
    )


@pytest.mark.parametrize("problem", ["tag", "hash", "version", "mandatory", "key", "snapshot"])
def test_production_policy_refusals(tmp_path, problem):
    nodes, args = ProductionNodes(), production_args(tmp_path)
    if problem == "tag":
        args.expected_auth_tag = "00" * 32
    elif problem == "hash":
        args.expected_cp48_hash = "00" * 32
    elif problem == "version":
        args.min_version = 17
    elif problem == "mandatory":
        nodes.params["9"] = wire.b64(
            wire.serialize_boc(dictionary({47: wire.cell_from_bits("")}, 32))
        )
    elif problem == "key":
        args.expected_auth_tag = None
    else:
        nodes.data = wire.cell_from_bits("")
    result = n.check_network(args, nodes, lambda: NOW)
    assert result["ok"] is False, result
    assert result["checks"][-1]["status"] == "FAIL"


def test_a_served_route_with_bad_material_never_falls_back(tmp_path):
    class Unavailable(ProductionNodes):
        def __call__(self, url, method, **params):
            if method == "getProofQuery":
                raise wire.RpcError(url, method, -32603, "INTERNAL_ERROR", "proof failed", False)
            return super().__call__(url, method, **params)

    result = n.check_network(production_args(tmp_path), Unavailable(), lambda: NOW)
    assert not result["ok"]
    assert not any(c["status"] == "WEAKER" for c in result["checks"])


def test_missing_proof_backend_is_not_node_verified(tmp_path):
    class Served(ProductionNodes):
        def __call__(self, url, method, **params):
            return (
                {"reply": "unused"}
                if method == "getProofQuery"
                else super().__call__(url, method, **params)
            )

    result = n.check_network(production_args(tmp_path), Served(), lambda: NOW)
    assert not result["ok"] and "install" in result["checks"][-1]["reason"]


def test_previous_set_must_really_be_previous():
    with pytest.raises(n.NetworkError, match="previous validator term"):
        n.check_election_sets({34: CELLS[34], 32: CELLS[34]}, ELECTOR, False)


def test_elected_set_cannot_hide_missing_config32():
    with pytest.raises(n.NetworkError, match="no ConfigParam 32"):
        n.check_election_sets({34: CELLS[34], 32: None}, ELECTOR, False)


def proven_account(data, address=n.ELECTOR):
    bits = (
        "1"
        + "10"
        + "0"
        + f"{255:08b}"
        + f"{int(address.split(':')[1], 16):0256b}"
        + "000"
        + "000"
        + "000"
        + f"{NOW - 5:032b}"
        + "0"
        + ("0" * 64)
        + "0000"
        + "0"
        + "1"
        + "0"
        + "0"
        + "1"
        + "1"
        + "0"
    )
    return wire.cell_from_bits(bits, [wire.cell_from_bits(""), data])


class VerifiedFixture:
    def __init__(self, data, mutation=None):
        self.data, self.mutation, self.urls = data, mutation, []

    def fetch(self, rpc, url, anchor, target, params, now, account=n.ELECTOR):
        self.urls.append(url)
        cells = [
            {"index": p, "boc": RECORD["params"][str(p)], "cell_hash": CELLS[p].hash().hex()}
            for p in params
        ]
        if self.mutation == "config":
            cells[0]["cell_hash"] = "00" * 32
        return {
            "target": {**target, "gen_utime": NOW - 6 if self.mutation == "time" else NOW - 5},
            "config_params": cells,
            "chain": {"links": 5, "key_blocks": [block(1)]},
            "account": {
                "address": account,
                "active": True,
                "state_boc": wire.b64(wire.serialize_boc(proven_account(self.data, account))),
                "data_hash": "00" * 32 if self.mutation == "data" else self.data.hash().hex(),
            },
        }


class ProofNodes(ProductionNodes):
    def __call__(self, url, method, **params):
        if method == "getProofQuery" and url == "b":
            self.proof_calls.append(url)
            return {"reply": "fixture"}
        return super().__call__(url, method, **params)


def test_supported_second_node_proofs_are_used(tmp_path):
    nodes = ProofNodes()
    verifier = VerifiedFixture(nodes.data)
    result = n.check_network(production_args(tmp_path), nodes, lambda: NOW, verifier)
    assert result["ok"], result
    assert result["strength"] == "anchor_verified"
    assert verifier.urls == ["b"]


@pytest.mark.parametrize("mutation", ["time", "config", "data"])
def test_authenticated_bindings_are_not_replaced_by_reported_metadata(tmp_path, mutation):
    nodes = ProofNodes()
    verifier = VerifiedFixture(nodes.data, mutation)
    result = n.check_network(production_args(tmp_path), nodes, lambda: NOW, verifier)
    assert not result["ok"]
    assert result["checks"][-1]["name"] == "anchored_finality"


def test_proven_account_address_is_checked():
    with pytest.raises(n.NetworkError, match="another address"):
        n.account_data(
            wire.serialize_boc(proven_account(retained_elector_data())), "-1:" + "4" * 64
        )


@pytest.mark.parametrize("set_tag", [0x11, 0x12])
@pytest.mark.parametrize("descriptor", [0x53, 0x73])
def test_classical_descriptor_and_inline_dictionary_forms(set_tag, descriptor):
    bits = f"{descriptor:08b}{0x8E81278A:032b}" + ("01" * 128) + f"{10:064b}"
    if descriptor == 0x73:
        bits += "10" * 128
    entries = dictionary({0: wire.cell_from_bits(bits)}, 16)
    prefix = f"{set_tag:08b}{100:032b}{200:032b}{1:016b}{1:016b}"
    if set_tag == 0x12:
        cell = wire.cell_from_bits(prefix + f"{10:064b}" + "1", [entries])
    else:
        tail = "".join(f"{b:08b}" for b in entries.data)[: entries.bits]
        cell = wire.cell_from_bits(prefix + tail, entries.refs)
    parsed = n.decode_set(cell)
    assert parsed["total"] == 1 and parsed["validators"][0]["weight"] == 10
    assert parsed["validators"][0]["algorithm"] == 0


class HistoricalNodes(ProofNodes):
    def __init__(self):
        super().__init__()
        self.data = wire.parse_boc(base64.b64decode(RECORD["elector_data"]))
        self.lookup = []

    def __call__(self, url, method, **params):
        if method == "lookupBlock":
            assert "unixtime" in params and "utime" not in params
            assert params["unixtime"] == n.decode_set(CELLS[34])["since"] - 1
            self.lookup.append(params)
            return block(5)
        return super().__call__(url, method, **params)


class HistoricalVerifier(VerifiedFixture):
    def fetch(self, rpc, url, anchor, target, params, now, account=n.ELECTOR):
        result = super().fetch(rpc, url, anchor, target, params, now, account)
        if target["seqno"] == 5:
            result["config_params"] = [p for p in result["config_params"] if p["index"] == 1] + [
                {"index": 34, "boc": RECORD["params"]["32"], "cell_hash": CELLS[32].hash().hex()}
            ]
            data = retained_elector_data()
            result["account"]["state_boc"] = wire.b64(wire.serialize_boc(proven_account(data)))
            result["account"]["data_hash"] = data.hash().hex()
        return result


def test_previous_set_is_checked_historically_after_frozen_record_removed(tmp_path):
    nodes = HistoricalNodes()
    verifier = HistoricalVerifier(nodes.data)
    result = n.check_network(production_args(tmp_path), nodes, lambda: NOW, verifier)
    assert result["ok"], result
    assert len(nodes.lookup) == 1
    previous = next(c for c in result["checks"] if c["name"] == "config32_vs_elector")
    assert previous["status"] == "PASS"
    assert previous["evidence"]["historical_block"] == block(5)


def test_unavailable_previous_evidence_keeps_current_pass_but_refuses_whole_run(tmp_path):
    class Missing(HistoricalVerifier):
        def fetch(self, rpc, url, anchor, target, params, now, account=n.ELECTOR):
            if target["seqno"] == 5:
                raise wire.RpcError(
                    url,
                    "getProofQuery",
                    -32603,
                    "INTERNAL_ERROR",
                    "Proof response unavailable",
                    False,
                )
            return super().fetch(rpc, url, anchor, target, params, now, account)

    nodes = HistoricalNodes()
    result = n.check_network(production_args(tmp_path), nodes, lambda: NOW, Missing(nodes.data))
    assert not result["ok"]
    assert any(
        c["name"] == "config34_vs_elector" and c["status"] == "PASS" for c in result["checks"]
    )
    assert result["checks"][-1]["name"] == "config32_vs_elector"
    assert "unavailable" in result["checks"][-1]["reason"]


def test_archival_source_is_tried_only_for_material_unavailability():
    calls = []

    class Backend:
        def fetch(self, rpc, url, *rest):
            calls.append(url)
            if url == "a":
                raise wire.RpcError(
                    url,
                    "getProofQuery",
                    -32603,
                    "INTERNAL_ERROR",
                    "Proof response unavailable",
                    False,
                )
            return {"status": "verified"}

    result, url, missing = n.fetch_proof(Backend(), None, ["a", "b"], None, None, None, NOW)
    assert result["status"] == "verified" and url == "b" and len(missing) == 1
    assert calls == ["a", "b"]


def test_a_forged_proof_is_not_retried_away():
    calls = []

    class Backend:
        def fetch(self, rpc, url, *rest):
            calls.append(url)
            raise n.NetworkError("signature verification refused")

    with pytest.raises(n.NetworkError, match="signature verification refused"):
        n.fetch_proof(Backend(), None, ["a", "b"], None, None, None, NOW)
    assert calls == ["a"]


def test_explicit_global_id_one_uses_the_same_production_pipeline(tmp_path):
    nodes = ProductionNodes()
    args = production_args(tmp_path)
    nodes.gid = 1
    args.global_id = 1
    nodes.params["19"] = wire.b64(wire.serialize_boc(wire.cell_from_bits(f"{1:032b}")))
    result = n.check_network(args, nodes, lambda: NOW)
    assert result["ok"], result
    assert next(c for c in result["checks"] if c["name"] == "global_id")["evidence"] == 1


def test_mandatory_cp48_is_not_skipped_before_version16(tmp_path):
    nodes = ProductionNodes()
    args = production_args(tmp_path)
    old = bytearray(CELLS[8].data)
    old[4] = 15
    nodes.params["8"] = wire.b64(wire.serialize_boc(wire.Cell(bytes(old), CELLS[8].bits, [])))
    args.min_version = 0
    args.expected_auth_tag = None
    result = n.check_network(args, nodes, lambda: NOW)
    assert not result["ok"]
    assert "independently expected AUTH" in result["checks"][-1]["reason"]


def test_real_proven_configuration_and_elector_match_at_the_same_block():
    a, r, parts = proof_fixture()
    result = proof_library().verify_material(a, r, parts, 1791200932)
    config = next(c for c in result["config_params"] if c["index"] == 34)
    vset = n.decode_set(wire.parse_boc(base64.b64decode(config["boc"])))
    data = n.account_data(base64.b64decode(result["account"]["state_boc"]), n.ELECTOR)
    assert n.compare_elected(vset, n.decode_elector(data))["status"] == "PASS"


def test_missing_native_symbols_refuse_cleanly(monkeypatch):
    monkeypatch.setattr(n.ct, "CDLL", lambda _: object())
    with pytest.raises(n.NetworkError, match="consensus proof ABI"):
        n.ProofVerifier("unused")


def test_config1_selects_the_proven_elector_account_and_public_reads(tmp_path):
    address = "-1:" + "4" * 64
    locator = wire.cell_from_bits("0100" * 64)

    class Relocated(ProofNodes):
        def __call__(self, url, method, **params):
            if method == "getAddressInformation":
                assert params["address"] == address
            return super().__call__(url, method, **params)

    class Backend(VerifiedFixture):
        def fetch(self, rpc, url, anchor, target, params, now, account=n.ELECTOR):
            assert account == address
            result = super().fetch(rpc, url, anchor, target, params, now, account)
            result["config_params"] = [p for p in result["config_params"] if p["index"] != 1] + [
                {
                    "index": 1,
                    "boc": wire.b64(wire.serialize_boc(locator)),
                    "cell_hash": locator.hash().hex(),
                }
            ]
            return result

    nodes = Relocated()
    nodes.params["1"] = wire.b64(wire.serialize_boc(locator))
    result = n.check_network(production_args(tmp_path), nodes, lambda: NOW, Backend(nodes.data))
    assert result["ok"], result


def test_zero_init_anchor_cannot_conflict_with_zero_state():
    changed = {**block(0), "root_hash": wire.b64(b"x" * 32)}
    with pytest.raises(n.NetworkError, match="conflicting zero"):
        n.identity_from_config({"validator": {"zero_state": block(0), "init_block": changed}}, 2)


def test_init_anchor_is_compared_even_without_proof_routes(tmp_path):
    args = production_args(tmp_path)
    config = json.loads(args.global_config.read_text())
    config["validator"]["init_block"] = {**block(5), "root_hash": wire.b64(b"x" * 32)}
    args.global_config.write_text(json.dumps(config))
    result = n.check_network(args, ProductionNodes(), lambda: NOW)
    assert not result["ok"]
    assert "init block differs" in result["checks"][-1]["reason"]
