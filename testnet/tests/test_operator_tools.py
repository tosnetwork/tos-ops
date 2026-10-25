"""remove-old-builds.sh and tok01-signer.py."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
KEEP = "4b4892b8d94e33fcb9699a9fd9b8032c12efdfd0"
OLD = "85c679c3454f306eb867e25b1960ae3d757bd3dd"


def run_cleanup(tmp_path, keep=KEEP):
    env = dict(
        os.environ,
        REMOVE_OLD_BUILDS_TEST="1",
        TOS_BUILD_ROOT=str(tmp_path / "build"),
        TOS_OPT_ROOT=str(tmp_path / "opt"),
    )
    return subprocess.run(
        ["bash", str(SCRIPTS / "remove-old-builds.sh"), "--keep", keep],
        env=env,
        capture_output=True,
        text=True,
    )


def layout(tmp_path):
    b = tmp_path / "build"
    for name in (f"build-{KEEP}", f"release-{KEEP}", f"build-{OLD}", f"release-{OLD}"):
        (b / name).mkdir(parents=True)
        (b / name / "x").write_text("x")
    (b / f"build-{OLD}.log").write_text("log")
    (b / "build-tosctl.sh").write_text("#!/bin/sh\n")
    (b / "tosctl-target").mkdir()
    for name in ("tos-testnet.old", f"tos-testnet.prev-{OLD}", "tos-testnet"):
        (tmp_path / "opt" / name).mkdir(parents=True)
    return b


def test_old_revisions_and_the_old_bundle_go_everything_else_stays(tmp_path):
    b = layout(tmp_path)
    r = run_cleanup(tmp_path)
    assert r.returncode == 0, r.stderr
    left = sorted(p.name for p in b.iterdir())
    assert left == sorted(
        [f"build-{KEEP}", f"release-{KEEP}", f"build-{OLD}.log", "build-tosctl.sh", "tosctl-target"]
    )
    assert sorted(p.name for p in (tmp_path / "opt").iterdir()) == sorted(
        [f"tos-testnet.prev-{OLD}", "tos-testnet"]
    )


def test_a_missing_kept_release_is_refused_and_nothing_is_removed(tmp_path):
    b = layout(tmp_path)
    r = run_cleanup(tmp_path, keep="ab" * 20)
    assert r.returncode != 0 and "is missing; refusing" in r.stderr
    assert (b / f"release-{OLD}").is_dir() and (tmp_path / "opt" / "tos-testnet.old").is_dir()


def test_a_short_revision_is_refused(tmp_path):
    layout(tmp_path)
    r = run_cleanup(tmp_path, keep=KEEP[:9])
    assert r.returncode != 0 and "full 40-character commit id" in r.stderr


# ---------------------------------------------------------------- tok01-signer.py

TOS_ROOT = os.environ.get("TOS_ROOT")
needs_tostester = pytest.mark.skipif(
    not TOS_ROOT or not (Path(TOS_ROOT) / "test/tostester/src/contract/wallet_v1.py").is_file(),
    reason="TOS_ROOT with test/tostester is needed",
)


def load_signer():
    spec = importlib.util.spec_from_file_location("tok01_signer", SCRIPTS / "tok01-signer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@needs_tostester
def test_the_signed_body_is_tostesters_wallet_v1_signature():
    pytest.importorskip("nacl")
    signer = load_signer()
    sys.path.insert(0, str(Path(TOS_ROOT) / "test/tostester/src"))
    import nacl.signing
    from contract.contract import tos
    from contract.wallet_v1 import WalletV1, WalletV1Blueprint
    from pytosiq_core import Cell, InternalMsgInfo, MessageAny, WalletMessage

    key = nacl.signing.SigningKey(bytes(range(32)))
    bp = WalletV1Blueprint(workchain=0, private_key=key)
    msg = MessageAny(
        info=InternalMsgInfo(
            ihr_disabled=True,
            bounce=True,
            bounced=False,
            src=bp.address,
            dest=bp.address,
            value=tos(1),
            ihr_fee=0,
            fwd_fee=0,
            created_lt=0,
            created_at=0,
        ),
        init=None,
        body=Cell.empty(),
    )
    expected = WalletV1(None, bp.address, key).sign(WalletMessage(send_mode=3, message=msg), 7)
    cell = Cell.one_from_boc(msg.serialize().to_boc())
    assert signer.signed_body(key, 7, 3, cell).hash == expected.hash
    assert signer.signed_body(key, 8, 3, cell).hash != expected.hash
    assert signer.raw(bp).startswith("0:")


@needs_tostester
def test_keys_are_refused_when_missing_readable_or_off_workchain_0(tmp_path):
    pytest.importorskip("nacl")
    signer = load_signer()
    keys = tmp_path / "keys"
    keys.mkdir()
    with pytest.raises(SystemExit, match="no key"):
        signer.load_key(keys, "0:" + "11" * 32)
    loose = keys / ("22" * 32 + ".key")
    loose.write_bytes(bytes(32))
    loose.chmod(0o644)
    with pytest.raises(SystemExit, match="readable by others"):
        signer.load_key(keys, "0:" + "22" * 32)
    with pytest.raises(SystemExit, match="not on workchain 0"):
        signer.load_key(keys, "-1:" + "22" * 32)
