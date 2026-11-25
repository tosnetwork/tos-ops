"""testnet-governance.py: the refusals ConfigParam 84 and the token bridge parameters need.

The values are built here bit by bit from the TL-B in tos crypto/block/block.tlb, and
data/governance/cp84-usdc-local.boc is the value tosctl's builder produced for the
local test asset; both decode to the same record.
"""

import base64
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest
import testnet_lib as lib

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
DATA = Path(__file__).resolve().parent / "data" / "governance"
spec = importlib.util.spec_from_file_location("governance_cp84", SCRIPTS / "testnet-governance.py")
gov = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gov)

BRIDGE = "ab" * 32
TOKEN = "cd" * 20


def bits(value: int, width: int) -> str:
    return format(value, f"0{width}b") if width else ""


def coins(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return bits(length, 4) + (bits(value, 8 * length) if length else "")


def origin(kind=1, bridge=BRIDGE, chain=1, token=TOKEN) -> lib.Cell:
    return lib.cell_from_bits(
        bits(kind, 8) + bits(int(bridge, 16), 256) + bits(chain, 32) + bits(int(token, 16), 160)
    )


def record(status=1, decimals=6, cap=10**10, tag=1, extra="", **kw) -> tuple[str, list]:
    body = (
        bits(tag, 8)
        + bits(status, 8)
        + bits(decimals, 8)
        + "1" * 256
        + "0" * 256
        + coins(cap)
        + extra
    )
    return body, [origin(**kw)]


def hashmap(entries: dict[int, tuple[str, list]], left: int = 256) -> lib.Cell:
    """A Hashmap with hml_long labels: a leaf per key, a fork where keys diverge."""
    keys = sorted(entries)
    width = left.bit_length()
    common = 0
    while common < left and len({k >> (left - common - 1) & 1 for k in keys}) == 1:
        common += 1
    label_value = keys[0] >> (left - common) if common else 0
    label = "10" + bits(common, width) + (bits(label_value, common) if common else "")
    rest = left - common
    if rest == 0:
        value_bits, refs = entries[keys[0]]
        return lib.cell_from_bits(label + value_bits, refs)
    mask = (1 << rest) - 1
    sides = [
        hashmap(
            {
                k & ((1 << (rest - 1)) - 1): entries[k]
                for k in keys
                if (k & mask) >> (rest - 1) == b
            },
            rest - 1,
        )
        for b in (0, 1)
    ]
    return lib.cell_from_bits(label, sides)


def value(entries: dict[int, tuple[str, list]] | None, tag=1, trailing="") -> lib.Cell:
    if not entries:
        return lib.cell_from_bits(bits(tag, 8) + "0" + trailing)
    return lib.cell_from_bits(bits(tag, 8) + "1" + trailing, [hashmap(entries)])


def test_a_record_decodes_exactly():
    decoded = gov.decode_settlement_assets(value({7: record()}))
    entry = decoded[f"{7:064x}"]
    assert entry["status"] == "active" and entry["decimals"] == 6
    assert entry["max_liability_per_actor"] == str(10**10)
    assert entry["origin"] == {
        "kind": "token_bridge",
        "bridge_address": BRIDGE,
        "source_chain_id": 1,
        "source_token": TOKEN,
    }


def test_an_empty_value_decodes_to_no_entries():
    assert gov.decode_settlement_assets(value(None)) == {}


def test_the_value_tosctl_built_for_the_local_asset_decodes():
    path = DATA / "cp84-usdc-local.boc"
    built = json.loads((DATA / "cp84-usdc-local.json").read_text())
    decoded = gov.decode_settlement_assets(lib.parse_boc(path.read_bytes()))
    want = {
        a["master"]: {k: v for k, v in a.items() if k not in ("master", "uncapped")}
        for a in built["value"]["assets"]
    }
    assert decoded == want
    assert lib.parse_boc(path.read_bytes()).hash().hex() == built["value_hash"]


@pytest.mark.parametrize(
    "bad, reason",
    [
        (lambda: value({1: record(status=0)}), "undefined status"),
        (lambda: value({1: record(status=4)}), "undefined status"),
        (lambda: value({1: record(tag=2)}), "unknown settlement asset tag"),
        (lambda: value({1: record(cap=0)}), "must be non-zero"),
        (lambda: value({1: record(extra="1")}), "trailing data"),
        (lambda: value({1: record(kind=3)}), "undefined origin kind"),
        (lambda: value({1: record()}, tag=2), "not settlement_assets_v1"),
        (lambda: value({1: record()}, trailing="1"), "trailing data"),
    ],
)
def test_a_malformed_value_is_refused(bad, reason):
    with pytest.raises(lib.TestnetError, match=reason):
        gov.decode_settlement_assets(bad())


def test_a_non_minimal_coins_length_is_refused():
    body = bits(1, 8) + bits(1, 8) + bits(6, 8) + "0" * 512 + bits(2, 4) + bits(5, 16)
    with pytest.raises(lib.TestnetError, match="non-minimal"):
        gov.decode_settlement_assets(value({1: (body, [origin()])}))


def test_an_origin_of_another_length_is_refused():
    short = lib.cell_from_bits(bits(1, 8) + "0" * 255)
    body, _ = record()
    with pytest.raises(lib.TestnetError, match="origin cell"):
        gov.decode_settlement_assets(value({1: (body, [short])}))


def test_sixteen_entries_pass_and_seventeen_are_refused():
    assert len(gov.decode_settlement_assets(value({k: record() for k in range(16)}))) == 16
    with pytest.raises(lib.TestnetError, match="17 entries, more than 16"):
        gov.decode_settlement_assets(value({k: record() for k in range(17)}))


def test_a_value_over_the_validation_budget_is_refused():
    # Few distinct cells, many visits: the node counts every reference.
    leaf = lib.cell_from_bits("1")
    for _ in range(6):
        leaf = lib.cell_from_bits("", [leaf] * 4)
    with pytest.raises(lib.TestnetError, match="more than 1024 cells"):
        gov.validation_visits(leaf)
    with pytest.raises(lib.TestnetError, match="more than 1024 cells"):
        gov.decode_settlement_assets(lib.cell_from_bits(bits(1, 8) + "1", [leaf]))


def entry(status="active", bridge=BRIDGE, chain=1):
    return {
        "status": status,
        "origin": {"kind": "token_bridge", "bridge_address": bridge, "source_chain_id": chain},
    }


def test_a_change_must_touch_exactly_one_entry():
    one, two = f"{1:064x}", f"{2:064x}"
    assert gov.settlement_assets_change({}, {one: entry()})["action"] == "add"
    assert gov.settlement_assets_change({one: entry()}, {})["action"] == "remove"
    changed = gov.settlement_assets_change({one: entry()}, {one: entry("admission_suspended")})
    assert changed["action"] == "change" and changed["master"] == one
    with pytest.raises(lib.TestnetError, match="changes 2"):
        gov.settlement_assets_change({}, {one: entry(), two: entry()})
    with pytest.raises(lib.TestnetError, match="changes 0"):
        gov.settlement_assets_change({one: entry()}, {one: entry()})


def bridge_params(bridge: str) -> lib.Cell:
    prices = lib.cell_from_bits(coins(1) * 6)
    return lib.cell_from_bits(
        bits(1, 8) + bits(int(bridge, 16), 256) + "0" * 256 + "0" + bits(0, 8) + "0" * 256,
        [prices],
    )


def test_a_bridge_change_is_refused_while_an_active_asset_names_the_old_bridge():
    old, new = bridge_params(BRIDGE), bridge_params("ef" * 32)
    assets = {f"{1:064x}": entry()}
    with pytest.raises(lib.TestnetError, match="still lists active assets"):
        gov.check_bridge_migration(79, old, new, assets)
    # Suspended first, or another chain's slot, or the same bridge: allowed.
    gov.check_bridge_migration(79, old, new, {f"{1:064x}": entry("admission_suspended")})
    gov.check_bridge_migration(81, old, new, assets)
    gov.check_bridge_migration(79, old, bridge_params(BRIDGE), assets)
    gov.check_bridge_migration(79, None, new, assets)


def git_repo(tmp_path: Path, schema: str) -> tuple[Path, str]:
    repo = tmp_path / "tos"
    (repo / "crypto" / "block").mkdir(parents=True)
    (repo / "crypto" / "block" / "block.tlb").write_text(schema)

    def run(*a):
        out = subprocess.run(
            ["git", "-C", str(repo), *a], check=True, capture_output=True, text=True
        )
        return out.stdout.strip()

    run("init", "-q")
    run("add", ".")
    run("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "schema")
    return repo, run("rev-parse", "HEAD")


def evidence(tmp_path: Path, commits: list[str]) -> str:
    path = tmp_path / "releases.json"
    path.write_text(
        json.dumps({"validators": [{"name": f"v{i}", "commit": c} for i, c in enumerate(commits)]})
    )
    return str(path)


def test_the_rollout_precondition_needs_every_validator_on_the_schema(tmp_path):
    repo, commit = git_repo(tmp_path, "_ SettlementAssets = ConfigParam 84; // critical\n")
    assert len(gov.check_node_releases(evidence(tmp_path, [commit] * 4), str(repo), 4)) == 4
    with pytest.raises(lib.TestnetError, match="needs --node-release-evidence"):
        gov.check_node_releases(None, str(repo), 4)
    with pytest.raises(lib.TestnetError, match="names 3 validators; the current set has 4"):
        gov.check_node_releases(evidence(tmp_path, [commit] * 3), str(repo), 4)
    with pytest.raises(lib.TestnetError, match="not a full commit id"):
        gov.check_node_releases(evidence(tmp_path, [commit[:12]] * 4), str(repo), 4)


def test_a_release_without_the_schema_is_refused(tmp_path):
    repo, commit = git_repo(tmp_path, "_ TokenBridgeParams = ConfigParam 79;\n")
    with pytest.raises(lib.TestnetError, match="no ConfigParam 84 schema"):
        gov.check_node_releases(evidence(tmp_path, [commit] * 4), str(repo), 4)


def test_the_validator_count_is_read_from_the_set_header():
    cp34 = lib.cell_from_bits(bits(0x12, 8) + "0" * 64 + bits(4, 16) + bits(4, 16) + "0" * 64)
    assert gov.validator_count(cp34) == 4


def test_pending_proposals_are_listed_with_their_parameter(monkeypatch):
    def proposal(phash, param):
        return [
            "tuple",
            {
                "elements": [
                    ["num", str(phash)],
                    [
                        "tuple",
                        {
                            "elements": [
                                ["num", "1"],
                                ["num", "-1"],
                                [
                                    "tuple",
                                    {
                                        "elements": [
                                            ["num", str(param)],
                                            ["cell", {"bytes": ""}],
                                            ["null"],
                                        ]
                                    },
                                ],
                            ]
                        },
                    ],
                ]
            },
        ]

    answer = {"exit_code": 0, "stack": [["list", {"elements": [proposal(5, 84), proposal(6, 79)]}]]}
    monkeypatch.setattr(gov.lib, "rpc", lambda *a, **kw: answer)
    assert gov.pending_params("http://x") == {f"{5:064x}": 84, f"{6:064x}": 79}
    monkeypatch.setattr(gov.lib, "rpc", lambda *a, **kw: {"exit_code": 0, "stack": [["null"]]})
    assert gov.pending_params("http://x") == {}


def test_a_second_pending_cp84_proposal_is_refused(monkeypatch):
    monkeypatch.setattr(gov, "pending_params", lambda url: {"aa" * 32: 84})
    args = type("A", (), {"rpc": "http://x"})()
    with pytest.raises(lib.TestnetError, match="another ConfigParam 84 proposal is pending"):
        gov.check_settlement_assets_proposal(args, value({1: record()}), None, critical=True)


def test_cp84_must_be_critical():
    args = type("A", (), {"rpc": "http://x"})()
    with pytest.raises(lib.TestnetError, match="must be listed in ConfigParam 10"):
        gov.check_settlement_assets_proposal(args, value({1: record()}), None, critical=False)


def test_adopted_reads_every_named_node(monkeypatch, tmp_path, capsys):
    want = value({1: record()})
    path = tmp_path / "v.boc"
    path.write_bytes(lib.serialize_boc(want))
    served = {"http://a": want, "http://b": want, "http://c": want, "http://d": None}
    monkeypatch.setattr(gov, "config_cell", lambda url, param: served[url])
    args = type(
        "A",
        (),
        {
            "rpc": "http://a",
            "confirm_rpc": "http://b",
            "param": 84,
            "value_boc": str(path),
            "also_rpc": ["http://c"],
        },
    )()
    assert gov.cmd_adopted(args) == 0
    assert "on all 3 nodes" in capsys.readouterr().out
    args.also_rpc = ["http://c", "http://d"]
    assert gov.cmd_adopted(args) == 1


def test_the_local_network_writes_and_then_pins_its_zero_state(tmp_path):
    network = tmp_path / "network.json"
    network.write_text(
        json.dumps(
            {
                "global_id": 3,
                "scope": "local-development",
                "zerostate_root": "11" * 32,
                "zerostate_file": "22" * 32,
            }
        )
    )
    ceremony = tmp_path / "ceremony"
    args = type("A", (), {"local_network": str(network), "ceremony": str(ceremony)})()
    assert gov.network_global_id(args) == lib.LOCAL_GLOBAL_ID
    genesis = json.loads((ceremony / "genesis.json").read_text())
    assert base64.b64decode(genesis["zero_state"]["root_hash"]) == bytes.fromhex("11" * 32)
    network.write_text(
        json.dumps(
            {
                "global_id": 3,
                "scope": "local-development",
                "zerostate_root": "33" * 32,
                "zerostate_file": "22" * 32,
            }
        )
    )
    with pytest.raises(lib.TestnetError, match="names another zero state"):
        gov.network_global_id(args)
    network.write_text(json.dumps({"global_id": 7, "scope": "testnet"}))
    with pytest.raises(lib.TestnetError, match="does not describe the local development network"):
        gov.network_global_id(args)
