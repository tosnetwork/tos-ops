"""local-pq-usdc.py: the cells the stand-in oracle and the test wallets send.

Each encoding is checked against an independent one: the multisig query against
the layout tos bridge_multisig/query.rs builds and the signatures it verifies,
messages against pytosiq_core, the public key text against Fift's own parser.
"""

import importlib.util
import os
import subprocess
from pathlib import Path

import nacl.signing
import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
spec = importlib.util.spec_from_file_location("local_pq_usdc", SCRIPTS / "local-pq-usdc.py")
usdc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(usdc)
lib = usdc.lib

BRIDGE = "-1:" + "73" * 32


def test_an_internal_message_matches_pytosiq_core():
    from pytosiq_core import Address, Cell, CurrencyCollection, InternalMsgInfo, MessageAny

    # The header, compared with an empty body (both encode it in place).
    ours = usdc.internal(BRIDGE, 5 * usdc.NANO, True)
    theirs = MessageAny(
        info=InternalMsgInfo(
            ihr_disabled=True,
            bounce=True,
            bounced=False,
            src=None,
            dest=Address(BRIDGE),
            value=CurrencyCollection(tomis=5 * usdc.NANO),
            ihr_fee=0,
            fwd_fee=0,
            created_lt=0,
            created_at=0,
        ),
        init=None,
        body=Cell.empty(),
    ).serialize()
    assert ours.hash() == theirs.hash
    # A body is always carried by reference, after the same header and a 1 bit.
    body = usdc.Builder().uint(8, 32).uint(0, 64).end()
    with_body = usdc.internal(BRIDGE, 5 * usdc.NANO, True, body)
    header = usdc.cell_bits(ours)[:-1]
    assert usdc.cell_bits(with_body) == header + "1" and with_body.refs == [body]


def test_the_multisig_query_carries_a_quorum_of_valid_signatures(tmp_path):
    vote = usdc.internal(BRIDGE, usdc.VOTE_VALUE, True, usdc.Builder().uint(4, 32).end())
    query = usdc.multisig_query(tmp_path, vote, 1)
    oracles = usdc.tvm_oracles(tmp_path)
    s = lib.Slice(query)
    root_signature = s.bytes(64)
    signed = usdc.Builder()
    signed.bits = usdc.cell_bits(query)[512:]
    signed.refs = list(query.refs)
    signed = signed.end()
    oracles[0].verify_key.verify(signed.hash(), root_signature)
    assert s.bits(8) == 0 and s.bits(1) == 1
    co = lib.Slice(s.take_ref())
    co_signature, co_index = co.bytes(64), co.bits(8)
    assert co_index == 1 and co.bits(1) == 0 and co.end()
    rest = usdc.Builder()
    rest.bits = usdc.cell_bits(query)[512 + 9 :]
    rest.refs = list(query.refs[1:])
    rest = rest.end()
    oracles[1].verify_key.verify(rest.hash(), co_signature)
    assert s.bits(32) == usdc.MULTISIG_WALLET_ID
    assert s.bits(32) == usdc.lib.LOCAL_GLOBAL_ID
    query_id = s.bits(64)
    assert query_id & 0xFFFFFFFF == 1 and (query_id >> 32) > 7000
    assert s.bits(8) == 3 and s.take_ref().hash() == vote.hash() and s.end()


def test_the_oracle_keys_are_generated_once_and_private(tmp_path):
    first = [bytes(k) for k in usdc.tvm_oracles(tmp_path)]
    assert first == [bytes(k) for k in usdc.tvm_oracles(tmp_path)]
    assert len(set(first)) == usdc.ORACLES
    assert all((tmp_path / f"tvm-oracle-{i}.pk").stat().st_mode & 0o077 == 0 for i in range(3))


def test_the_public_key_text_is_what_fift_parses(tmp_path):
    fift = Path(os.environ["TOS_ROOT"]) / "build" / "crypto" / "fift"
    if not fift.is_file():
        pytest.skip("no built fift in TOS_ROOT")
    key = nacl.signing.SigningKey(b"\x07" * 32).verify_key
    text = usdc.friendly_pubkey(bytes(key))
    script = tmp_path / "p.fif"
    script.write_text(f'"TosUtil.fif" include "{text}" parse-pubkey 256 u>B Bx. cr\n')
    lib_dir = Path(os.environ["TOS_ROOT"]) / "crypto" / "fift" / "lib"
    out = subprocess.run(
        [str(fift), "-I", str(lib_dir), "-s", str(script)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip().lower() == bytes(key).hex()


def test_a_folded_swap_is_never_paid_again():
    assert usdc.swap_needs_payment(-1, 0, 0)
    assert not usdc.swap_needs_payment(-1, 0, 1)  # consumed and folded
    assert not usdc.swap_needs_payment(0, 0, 0)  # already paid
    assert not usdc.swap_needs_payment(2, 3, 0)


def test_cast_annotations_are_dropped():
    assert usdc.evm_values("100000000000 [1e11]\n0\n0x00ab\n") == ["100000000000", "0", "0x00ab"]


def test_the_wrapped_token_data_names_the_source_chain_token_and_decimals():
    state = type("S", (), {"__getitem__": lambda self, k: {"token": "0x" + "5f" * 20}})()
    s = lib.Slice(usdc.token_data(state))
    assert s.bits(32) == usdc.EVM_CHAIN_ID and s.bytes(20) == b"\x5f" * 20
    assert s.bits(8) == 6 and s.end()
