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


SINCE = 1_800_000_000
NOW = SINCE + 600


def pq_descr(key_id: int) -> tuple[str, list]:
    """validator_pq#b3 validator_id algorithm_id key_id ^public_key weight adnl_addr."""
    body = (
        bits(0xB3, 8)
        + bits(key_id + 100, 256)
        + bits(1, 16)
        + bits(key_id, 256)
        + bits(17, 64)
        + bits(key_id + 200, 256)
    )
    return body, [lib.cell_from_bits("1" * 8)]


def ed_descr(key: int) -> tuple[str, list]:
    return bits(0x53, 8) + bits(0x8E81278A, 32) + bits(key, 256) + bits(17, 64), []


def cp34(descrs: dict[int, tuple[str, list]], tag=0x12) -> lib.Cell:
    header = bits(tag, 8) + bits(SINCE, 32) + bits(SINCE + 600, 32) + bits(len(descrs), 16) * 2
    if tag == 0x12:
        return lib.cell_from_bits(header + bits(68, 64) + "1", [hashmap(descrs, 16)])
    root = hashmap(descrs, 16)
    return lib.cell_from_bits(header + cell_bits(root), root.refs)


def cell_bits(cell: lib.Cell) -> str:
    return format(int.from_bytes(cell.data, "big"), f"0{8 * len(cell.data)}b")[: cell.bits]


MEMBERS = [f"{k:064x}" for k in (11, 12, 13, 14)]


def current_set():
    return gov.validator_set(cp34({i: pq_descr(11 + i) for i in range(4)}))


def evidence(tmp_path: Path, commit: str, keys=MEMBERS, observed=NOW - 60, output=None) -> str:
    path = tmp_path / "releases.json"
    rows = [
        {
            "name": f"v{i}",
            "public_key": k,
            "commit": commit,
            "observed_at": observed,
            "version_output": output if output is not None else f"[ Commit: {commit}, Date: x]",
        }
        for i, k in enumerate(keys)
    ]
    path.write_text(json.dumps({"validators": rows}))
    return str(path)


def test_the_validator_set_is_decoded_with_its_member_keys():
    pq = current_set()
    assert pq["total"] == 4 and pq["keys"] == MEMBERS and pq["utime_since"] == SINCE
    ed = gov.validator_set(cp34({0: ed_descr(5), 1: ed_descr(6)}, tag=0x11))
    assert ed["keys"] == [f"{5:064x}", f"{6:064x}"]
    assert gov.validator_count(cp34({0: ed_descr(5)})) == 1


def test_the_rollout_precondition_needs_every_member_on_the_schema(tmp_path):
    repo, commit = git_repo(tmp_path, "_ SettlementAssets = ConfigParam 84; // critical\n")
    rows = gov.check_node_releases(evidence(tmp_path, commit), str(repo), current_set(), now=NOW)
    assert [r["public_key"] for r in rows] == MEMBERS
    with pytest.raises(lib.TestnetError, match="needs --node-release-evidence"):
        gov.check_node_releases(None, str(repo), current_set(), now=NOW)


@pytest.mark.parametrize(
    "keys, reason",
    [
        ([MEMBERS[0]] * 4, "a second row"),  # four identical rows
        (MEMBERS[:3], "no release evidence for current validators"),
        (MEMBERS + [f"{99:064x}"], "is not in the current set"),  # an extra row
        ([f"{99:064x}"] * 4, "a second row"),  # four identical rows of a non-member
        ([f"{99 + i:064x}" for i in range(4)], "no release evidence"),  # four non-members
        (MEMBERS[:3] + [f"{99:064x}"], f"current validators {MEMBERS[3]}"),  # one replaced
    ],
)
def test_the_evidence_must_be_exactly_the_current_set(tmp_path, keys, reason):
    repo, commit = git_repo(tmp_path, "_ SettlementAssets = ConfigParam 84;\n")
    with pytest.raises(lib.TestnetError, match=reason):
        gov.check_node_releases(evidence(tmp_path, commit, keys), str(repo), current_set(), now=NOW)


@pytest.mark.parametrize(
    "observed, now, reason",
    [
        (SINCE - 1, NOW, "before the current set took office"),
        (NOW - 60, NOW + 25 * 3600, "not from the last 24 hours"),  # stale
        (NOW + 3600, NOW, "not from the last 24 hours"),  # in the future
        ("yesterday", NOW, "must be whole Unix seconds"),
        (float("nan"), NOW, "must be whole Unix seconds"),  # compares false with any bound
        (float("inf"), NOW, "must be whole Unix seconds"),
        (float("-inf"), NOW, "must be whole Unix seconds"),
        (NOW - 60.5, NOW, "must be whole Unix seconds"),  # a fraction
        (float(NOW - 60), NOW, "must be whole Unix seconds"),  # a float, even a whole one
        (True, NOW, "must be whole Unix seconds"),
        (None, NOW, "must be whole Unix seconds"),
    ],
)
def test_stale_or_undated_evidence_is_refused(tmp_path, observed, now, reason):
    repo, commit = git_repo(tmp_path, "_ SettlementAssets = ConfigParam 84;\n")
    path = evidence(tmp_path, commit, observed=observed)
    with pytest.raises(lib.TestnetError, match=reason):
        gov.check_node_releases(path, str(repo), current_set(), now=now)


def test_the_attested_output_must_name_the_commit(tmp_path):
    repo, commit = git_repo(tmp_path, "_ SettlementAssets = ConfigParam 84;\n")
    path = evidence(tmp_path, commit, output="[ Commit: 0000, Date: x]")
    with pytest.raises(lib.TestnetError, match="does not name"):
        gov.check_node_releases(path, str(repo), current_set(), now=NOW)


def test_a_release_without_the_schema_is_refused(tmp_path):
    repo, commit = git_repo(tmp_path, "_ TokenBridgeParams = ConfigParam 79;\n")
    with pytest.raises(lib.TestnetError, match="no ConfigParam 84 schema"):
        gov.check_node_releases(evidence(tmp_path, commit), str(repo), current_set(), now=NOW)


def test_a_fork_with_a_trailing_bit_is_refused():
    good = value({1: record(), 2: record()})
    fork = good.refs[0]
    bad = lib.cell_from_bits(cell_bits(fork) + "1", fork.refs)
    with pytest.raises(lib.TestnetError, match="exactly its label and two references"):
        gov.decode_settlement_assets(lib.cell_from_bits(cell_bits(good), [bad]))


def test_a_fork_with_a_third_reference_is_refused():
    good = value({1: record(), 2: record()})
    fork = good.refs[0]
    bad = lib.cell_from_bits(cell_bits(fork), [*fork.refs, lib.cell_from_bits("")])
    with pytest.raises(lib.TestnetError, match="exactly its label and two references"):
        gov.decode_settlement_assets(lib.cell_from_bits(cell_bits(good), [bad]))


def test_an_over_long_label_is_refused():
    body, refs = record()
    # hml_long with n = 257 for a 256-bit key: 9 bits can say 257.
    leaf = lib.cell_from_bits("10" + bits(257, 9) + "0" * 257 + body, refs)
    with pytest.raises(lib.TestnetError, match="longer than its key"):
        gov.decode_settlement_assets(lib.cell_from_bits(bits(1, 8) + "1", [leaf]))


def test_pending_proposals_are_listed_with_their_parameter(monkeypatch):
    v = value({1: record()})

    def proposal(phash, param, cell):
        val = (
            ["cell", {"bytes": base64.b64encode(lib.serialize_boc(cell)).decode()}]
            if cell
            else ["null"]
        )
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
                                ["tuple", {"elements": [["num", str(param)], val, ["null"]]}],
                            ]
                        },
                    ],
                ]
            },
        ]

    answer = {
        "exit_code": 0,
        "stack": [["list", {"elements": [proposal(5, 84, v), proposal(6, 79, None)]}]],
    }
    monkeypatch.setattr(gov.lib, "rpc", lambda *a, **kw: answer)
    assert gov.pending_params("http://x") == {f"{5:064x}": 84, f"{6:064x}": 79}
    listed = gov.pending_proposals("http://x")
    assert listed[f"{5:064x}"]["value"].hash() == v.hash() and listed[f"{6:064x}"]["value"] is None
    monkeypatch.setattr(gov.lib, "rpc", lambda *a, **kw: {"exit_code": 0, "stack": [["null"]]})
    assert gov.pending_params("http://x") == {}


class Chain:
    """Config reads and pending proposals for check_rules."""

    def __init__(self, monkeypatch, config: dict, pending: dict):
        self.config, self.pending = config, pending
        monkeypatch.setattr(gov, "config_cell", lambda url, param: self.config.get(param))
        monkeypatch.setattr(gov, "pending_proposals", lambda url: dict(self.pending))


ARGS = type("A", (), {"rpc": "http://x"})()
OLD_BRIDGE, NEW_BRIDGE = bridge_params(BRIDGE), bridge_params("ef" * 32)


def test_a_second_pending_cp84_proposal_is_refused_but_the_same_one_resumes(monkeypatch):
    v = value({1: record()})
    Chain(monkeypatch, {}, {"aa" * 32: {"param": 84, "value": value({2: record()})}})
    with pytest.raises(lib.TestnetError, match="another ConfigParam 84 proposal is pending"):
        gov.check_rules(ARGS, 84, v, "bb" * 32, critical=True)
    # The identical proposal, already registered, is not counted against itself.
    Chain(monkeypatch, {}, {"bb" * 32: {"param": 84, "value": v}})
    assert gov.check_rules(ARGS, 84, v, "bb" * 32, critical=True)["change"]["action"] == "add"


def test_cp84_must_be_critical(monkeypatch):
    Chain(monkeypatch, {}, {})
    with pytest.raises(lib.TestnetError, match="must be listed in ConfigParam 10"):
        gov.check_rules(ARGS, 84, value({1: record()}), "bb" * 32, critical=False)


def test_cp84_waits_for_a_pending_bridge_change(monkeypatch):
    Chain(monkeypatch, {79: OLD_BRIDGE}, {"aa" * 32: {"param": 79, "value": NEW_BRIDGE}})
    with pytest.raises(lib.TestnetError, match="a bridge address change is pending"):
        gov.check_rules(ARGS, 84, value({1: record()}), "bb" * 32, critical=True)
    # A pending 79 proposal that keeps the bridge (a price change) does not block it.
    Chain(monkeypatch, {79: OLD_BRIDGE}, {"aa" * 32: {"param": 79, "value": bridge_params(BRIDGE)}})
    gov.check_rules(ARGS, 84, value({1: record()}), "bb" * 32, critical=True)


def test_a_bridge_change_waits_for_a_pending_cp84_proposal(monkeypatch):
    Chain(monkeypatch, {79: OLD_BRIDGE}, {"aa" * 32: {"param": 84, "value": value({1: record()})}})
    with pytest.raises(lib.TestnetError, match="a ConfigParam 84 proposal is pending"):
        gov.check_rules(ARGS, 79, NEW_BRIDGE, "bb" * 32, critical=False)
    # The first installation of 79 replaces no bridge, and is not held back.
    Chain(monkeypatch, {}, {"aa" * 32: {"param": 84, "value": value({1: record()})}})
    gov.check_rules(ARGS, 79, NEW_BRIDGE, "bb" * 32, critical=False)


def test_a_bridge_change_is_refused_against_the_adopted_record(monkeypatch):
    Chain(monkeypatch, {79: OLD_BRIDGE, 84: value({1: record()})}, {})
    with pytest.raises(lib.TestnetError, match="still lists active assets"):
        gov.check_rules(ARGS, 79, NEW_BRIDGE, "bb" * 32, critical=False)


def test_signing_revalidates_the_rules(monkeypatch, tmp_path):
    # Registered while legal; a ConfigParam 84 proposal has appeared since.
    v79 = NEW_BRIDGE
    Chain(
        monkeypatch,
        {79: OLD_BRIDGE},
        {
            "bb" * 32: {"param": 79, "value": v79},
            "aa" * 32: {"param": 84, "value": value({1: record()})},
        },
    )
    monkeypatch.setattr(gov, "status", lambda url, p: {"critical": False, "wins": 0, "voters": []})
    args = type(
        "A",
        (),
        {
            "rpc": "http://x",
            "proposal": "bb" * 32,
            "ceremony": str(tmp_path),
            "local_network": None,
            "inventory": None,
        },
    )()
    with pytest.raises(lib.TestnetError, match="a ConfigParam 84 proposal is pending"):
        gov.cmd_sign(args)
    with pytest.raises(lib.TestnetError, match="a ConfigParam 84 proposal is pending"):
        gov.revalidate(args, "bb" * 32)


def test_a_first_installation_is_bound_to_the_absent_value(monkeypatch, tmp_path):
    data = Path(__file__).resolve().parent / "data" / "governance"
    cp10, cp11 = (lib.parse_boc((data / n).read_bytes()) for n in ("cp10.boc", "cp11.boc"))
    Chain(monkeypatch, {10: cp10, 11: cp11}, {})
    path = tmp_path / "v.boc"
    path.write_bytes(lib.serialize_boc(NEW_BRIDGE))
    args = type(
        "A",
        (),
        {
            "rpc": "http://x",
            "param": 79,
            "value_boc": str(path),
            "ceremony": str(tmp_path / "c"),
            "dry_run": True,
            "expire_seconds": None,
            "node_release_evidence": None,
        },
    )()
    (tmp_path / "c").mkdir(mode=0o700)
    assert gov.cmd_propose(args) == 0
    plan = json.loads(
        (next((tmp_path / "c" / "governance").iterdir()) / "proposal.json").read_text()
    )
    assert plan["current_hash"] is None and plan["if_hash_equal"] == "00" * 32
    bound = gov.proposal_cell(79, NEW_BRIDGE, bytes(32)).hash().hex()
    assert plan["proposal"] == bound != gov.proposal_cell(79, NEW_BRIDGE, None).hash().hex()


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


def test_a_set_change_between_propose_and_vote_rechecks_the_releases(monkeypatch, tmp_path):
    repo, commit = git_repo(tmp_path, "_ SettlementAssets = ConfigParam 84;\n")
    phash = "cc" * 32
    folder = tmp_path / "ceremony" / "governance" / phash
    folder.mkdir(parents=True)
    # Kept at propose: the old set (11..14).
    (folder / "node-releases.json").write_text(Path(evidence(tmp_path, commit)).read_text())
    v = value({1: record()})
    old_set = cp34({i: pq_descr(11 + i) for i in range(4)})
    chain = Chain(monkeypatch, {34: old_set}, {phash: {"param": 84, "value": v}})
    monkeypatch.setattr(gov, "status", lambda url, p: {"critical": True, "wins": 1, "voters": []})
    monkeypatch.setattr(gov.time, "time", lambda: NOW)
    args = type(
        "A",
        (),
        {
            "rpc": "http://x",
            "ceremony": str(tmp_path / "ceremony"),
            "tos_root": str(repo),
            "node_release_evidence": None,
        },
    )()
    gov.revalidate(args, phash)  # the set that proposed: accepted
    # The set rotates: member 14 leaves and 99 joins, with no evidence.
    chain.config[34] = cp34({0: pq_descr(11), 1: pq_descr(12), 2: pq_descr(13), 3: pq_descr(99)})
    with pytest.raises(
        lib.TestnetError, match=f"no release evidence for current validators {99:064x}"
    ):
        gov.revalidate(args, phash)
    # Fresh evidence for the new set, given to sign or vote, is accepted.
    keys = [f"{k:064x}" for k in (11, 12, 13, 99)]
    args.node_release_evidence = evidence(tmp_path, commit, keys)
    gov.revalidate(args, phash)


def test_a_cp84_round_needs_the_tos_root(monkeypatch, tmp_path):
    Chain(monkeypatch, {}, {"cc" * 32: {"param": 84, "value": value({1: record()})}})
    monkeypatch.setattr(gov, "status", lambda url, p: {"critical": True, "wins": 0, "voters": []})
    args = type(
        "A",
        (),
        {
            "rpc": "http://x",
            "ceremony": str(tmp_path),
            "tos_root": None,
            "node_release_evidence": None,
        },
    )()
    with pytest.raises(lib.TestnetError, match="--tos-root is needed"):
        gov.revalidate(args, "cc" * 32)
