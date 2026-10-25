"""testnet-governance.py against the epoch-5 ConfigParam 15 vote (2026-10-25).

The data under data/governance/ is the live chain's: ConfigParams 10, 11 and 15 before
the change, the proposed value, the registration body that was sent, one validator's
vote body and the Config getter's answer after the second won round. The values pinned
here (proposal hash, price) are what the Config contract computed and kept.
"""

import base64
import importlib.util
import json
from pathlib import Path

import pytest
import testnet_lib as lib
import testnet_ops as ops

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
DATA = Path(__file__).resolve().parent / "data" / "governance"
spec = importlib.util.spec_from_file_location("governance", SCRIPTS / "testnet-governance.py")
gov = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gov)

PROPOSAL = "120080fef5eab97f86763b3b3e4add4943a6a9b17d8da88e486ed57d1ebf53b3"
OLD_CP15 = "b8c63c89fe7b7739084b2833b7ae0a4c6e9cfe3a632685dffe1ecd2c36c0544c"
NEW_CP15 = "d464955c155da7f71a484f0646d4f144758eb701af0e364319e2c79735a2d78a"
# What the Config contract kept for the registration (23 TOS sent, 1.48 TOS returned).
LIVE_PRICE = 21_520_000_000


def cell(name):
    return lib.parse_boc((DATA / name).read_bytes())


def test_the_proposal_is_the_one_the_chain_registered():
    old, new = cell("cp15.boc"), cell("new-cp15.boc")
    assert old.hash().hex() == OLD_CP15
    assert new.hash().hex() == NEW_CP15
    assert gov.proposal_cell(15, new, old.hash()).hash().hex() == PROPOSAL


def test_a_proposal_without_the_current_value_binding_is_another_proposal():
    assert gov.proposal_cell(15, cell("new-cp15.boc"), None).hash().hex() != PROPOSAL


def test_the_registration_body_is_the_one_that_was_sent():
    sent = cell("register-body.boc")
    s = lib.Slice(sent)
    assert s.bits(32) == gov.REGISTER_OP
    query_id = s.bits(64)
    expire = s.bits(32)
    proposal = gov.proposal_cell(15, cell("new-cp15.boc"), cell("cp15.boc").hash())
    assert gov.register_body(query_id, expire, proposal, True).hash() == sent.hash()


def test_cp15_is_critical_and_cp20_is_not():
    keys = gov.signed_keys(cell("cp10.boc"))
    assert 15 in keys and -999 in keys
    assert 20 not in keys


def test_the_price_is_what_the_contract_kept():
    setup = gov.parse_vote_setup(cell("cp11.boc"), critical=True)
    assert (setup["min_wins"], setup["min_store_sec"]) == (3, 5_000_000)
    assert gov.proposal_price(cell("new-cp15.boc"), setup, 5_000_000) == LIVE_PRICE


def test_an_ordinary_setup_needs_two_wins():
    assert gov.parse_vote_setup(cell("cp11.boc"), critical=False)["min_wins"] == 2


def test_a_storage_period_below_the_minimum_is_refused():
    setup = gov.parse_vote_setup(cell("cp11.boc"), critical=True)
    with pytest.raises(lib.TestnetError, match="at least 5000000"):
        gov.proposal_price(cell("new-cp15.boc"), setup, 4_999_999)


def test_the_getter_answer_is_decoded(monkeypatch):
    answer = json.loads((DATA / "get-proposal-round2.json").read_text())
    monkeypatch.setattr(gov.lib, "rpc", lambda *a, **kw: answer)
    st = gov.status("http://x", PROPOSAL)
    assert st["critical"] and st["param"] == 15
    assert st["voters"] == [0, 1, 2, 3]
    assert (st["wins"], st["losses"], st["rounds_remaining"]) == (2, 0, 6)
    assert st["weight_remaining"] < 0


def test_an_absent_proposal_reads_as_none(monkeypatch):
    monkeypatch.setattr(
        gov.lib, "rpc", lambda *a, **kw: {"exit_code": 0, "stack": [["null", None]]}
    )
    assert gov.status("http://x", PROPOSAL) is None


def test_a_console_vote_is_parsed_and_bound_to_its_proposal():
    raw = (DATA / "vote-idx0.boc").read_bytes()
    idx, vote = gov.parse_vote(raw, PROPOSAL)
    assert idx == 0 and len(vote.refs) == 1
    with pytest.raises(lib.TestnetError, match="another proposal"):
        gov.parse_vote(raw, "00" * 32)


def test_a_body_that_is_not_a_vote_is_refused():
    with pytest.raises(lib.TestnetError, match="not a configuration vote"):
        gov.parse_vote((DATA / "register-body.boc").read_bytes(), PROPOSAL)


def test_the_config_kinds_are_journaled_operations():
    assert {"config-propose", "config-vote"} <= set(ops.KINDS)


def test_votes_signed_under_another_set_are_not_sent(tmp_path, monkeypatch):
    folder = tmp_path / "governance" / PROPOSAL
    folder.mkdir(parents=True)
    signed_under = "aa" * 32
    vote = base64.b64encode((DATA / "vote-idx0.boc").read_bytes()).decode()
    (folder / f"round-{signed_under[:16]}.json").write_text(
        json.dumps({"set": signed_under, "votes": {"0": {"host": "node-3", "boc": vote}}})
    )
    monkeypatch.setattr(gov, "current_set_hash", lambda url: "bb" * 32)
    args = type("A", (), {"proposal": PROPOSAL, "rpc": "http://x", "ceremony": str(tmp_path)})()
    with pytest.raises(lib.TestnetError, match="no votes signed under the current set"):
        gov.cmd_vote(args)
