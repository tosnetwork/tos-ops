"""Tests for the wallet half of the reset identity check.

Every testnet epoch uses global id 2, so a wallet key that survives a reset
accepts again whatever was signed for it before. The bootstrap wallet is
compared by public key (its address is fixed), operator and load-test wallets
by address (a wallet-v3 address is a function of its key).
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import time
from pathlib import Path

import pytest
import testnet_lib as lib
from conftest import SCRIPTS


def load_script(name: str, module: str):
    spec = importlib.util.spec_from_file_location(module, SCRIPTS / name)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


elections = load_script("testnet-elections.py", "testnet_elections_wallets")
coordinator = load_script("testnet-coordinator.py", "testnet_coordinator_wallets")

KEY_A = "pubkey:" + "a1" * 32
KEY_B = "pubkey:" + "b2" * 32
OP_A = "-1:" + "c3" * 32
OP_B = "-1:" + "d4" * 32
HIGHLOAD = "0:" + "e5" * 32
RELAYER = "0:" + "f6" * 32


def earlier_epoch() -> dict:
    return {"bootstrap": KEY_A, "op-a": OP_A, "highload": HIGHLOAD, "relayer-0": RELAYER}


# ---------------------------------------------------------------- the pure check


def test_fresh_wallets_are_accepted_and_normalized():
    fresh = {"bootstrap": KEY_B.upper().replace("PUBKEY", "pubkey"), "op-b": OP_B.upper()}
    assert lib.check_fresh_wallets(fresh, [earlier_epoch()]) == {
        "bootstrap": KEY_B,
        "op-b": OP_B,
    }
    assert lib.check_fresh_wallets(fresh, []) == {"bootstrap": KEY_B, "op-b": OP_B}


@pytest.mark.parametrize(
    "label,identity",
    [("bootstrap", KEY_A), ("op-b", OP_A), ("highload", HIGHLOAD), ("relayer-3", RELAYER)],
)
def test_each_wallet_kind_reused_from_an_earlier_epoch_is_refused(label, identity):
    with pytest.raises(lib.TestnetError, match=f"wallet {label} reuses .*fresh wallet keys"):
        lib.check_fresh_wallets({label: identity}, [earlier_epoch()])


def test_reuse_is_found_whatever_the_spelling():
    for spelling in (
        "PUBKEY:" + "A1" * 32,
        "PubKey:" + "a1" * 32,
    ):
        with pytest.raises(lib.TestnetError, match="reuses pubkey:" + "a1" * 32):
            lib.check_fresh_wallets({"bootstrap": spelling}, [earlier_epoch()])
    for spelling in ("-1:" + "C3" * 32, "-01:" + "c3" * 32):
        with pytest.raises(lib.TestnetError, match="reuses -1:" + "c3" * 32):
            lib.check_fresh_wallets({"op-a": spelling}, [{"x": OP_A.upper()}])
    # the same account on another workchain is another wallet
    lib.check_fresh_wallets({"op-a": "0:" + "c3" * 32}, [earlier_epoch()])


def test_reuse_is_checked_against_every_earlier_epoch():
    second = {"bootstrap": KEY_B}
    with pytest.raises(lib.TestnetError, match="reuses"):
        lib.check_fresh_wallets({"relayer-0": RELAYER}, [second, earlier_epoch()])


def test_an_earlier_epoch_with_no_wallets_is_refused():
    with pytest.raises(lib.TestnetError, match="saw nothing"):
        lib.check_fresh_wallets({"bootstrap": KEY_B}, [{}])


def test_malformed_identities_are_refused():
    for bad in ("pubkey:" + "ab" * 31, "pubkey:" + "00" * 32, "EQabc", "-1:" + "zz" * 32, 7):
        with pytest.raises(lib.TestnetError):
            lib.wallet_identity(bad)
    with pytest.raises(lib.TestnetError, match="JSON object"):
        lib.check_fresh_wallets({"x": OP_B}, [[OP_A]])


# ---------------------------------------------------------------- wallets.json


def test_wallets_record_is_extended_never_changed(tmp_path):
    lib.record_wallets(tmp_path, {"bootstrap": KEY_A})
    lib.record_wallets(tmp_path, {"op-a": OP_A.upper()})
    # a rerun with the same identity is accepted
    lib.record_wallets(tmp_path, {"op-a": OP_A})
    path = tmp_path / lib.WALLETS_FILE
    before = path.read_bytes()
    assert json.loads(before) == {"bootstrap": KEY_A, "op-a": OP_A}
    with pytest.raises(lib.TestnetError, match="never changed"):
        lib.record_wallets(tmp_path, {"highload": HIGHLOAD, "op-a": OP_B})
    assert path.read_bytes() == before
    assert path.stat().st_mode & 0o777 == 0o644


def test_wallets_record_refuses_a_symlink(tmp_path):
    (tmp_path / "elsewhere.json").write_text("{}")
    (tmp_path / lib.WALLETS_FILE).symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(lib.TestnetError, match="symlink"):
        lib.record_wallets(tmp_path, {"bootstrap": KEY_A})


# ---------------------------------------------------------------- previous ceremonies


def test_previous_ceremony_reads_wallets_and_genesis_key(tmp_path):
    (tmp_path / "wallets.json").write_text(json.dumps({"op-a": OP_A}))
    (tmp_path / "genesis.json").write_text(json.dumps({"main_wallet_public_key": "A1" * 32}))
    assert lib.previous_wallets(tmp_path) == {"op-a": OP_A, "bootstrap": KEY_A}


def test_previous_ceremony_whose_records_disagree_is_refused(tmp_path):
    (tmp_path / "wallets.json").write_text(json.dumps({"bootstrap": KEY_B}))
    (tmp_path / "genesis.json").write_text(json.dumps({"main_wallet_public_key": "a1" * 32}))
    with pytest.raises(lib.TestnetError, match="disagree"):
        lib.previous_wallets(tmp_path)


def test_old_ceremony_gives_its_bootstrap_key_through_the_secret(tmp_path):
    (tmp_path / "genesis.json").write_text(json.dumps({"global_id": 2}))
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "main-wallet.pk").write_bytes(b"k" * 32)
    seen = []

    def derive(key: Path) -> bytes:
        seen.append(key)
        return bytes.fromhex("a1" * 32)

    assert lib.previous_wallets(tmp_path, derive) == {"bootstrap": KEY_A}
    assert seen == [secret / "main-wallet.pk"]
    with pytest.raises(lib.TestnetError, match="needs fift"):
        lib.previous_wallets(tmp_path)


def test_previous_ceremony_with_nothing_in_it_is_refused(tmp_path):
    with pytest.raises(lib.TestnetError, match="records no wallet identity"):
        lib.previous_wallets(tmp_path, lambda key: bytes(32))
    (tmp_path / "genesis.json").write_text(json.dumps({"global_id": 2}))
    (tmp_path / "wallets.json").write_text("{}")
    with pytest.raises(lib.TestnetError, match="records no wallet identity"):
        lib.previous_wallets(tmp_path, lambda key: bytes(32))
    with pytest.raises(lib.TestnetError, match="not a directory"):
        lib.previous_wallets(tmp_path / "missing")


# ---------------------------------------------------------------- deriving the public key


class FakeRun:
    def __init__(self, stdout: str):
        self.stdout = stdout
        self.argv = None

    def __call__(self, argv, **kwargs):
        self.argv = argv
        assert (Path(argv[argv.index("-s") + 1])).read_text() == lib.FIFT_PUBLIC_PROGRAM
        return lib.subprocess.CompletedProcess(argv, 0, self.stdout, "")


def test_public_key_is_parsed_from_the_marker_line(tmp_path):
    key = tmp_path / "main-wallet.pk"
    key.write_bytes(b"k" * 32)
    run = FakeRun("Loading private key from file x\nWALLET-PUBLIC-KEY " + "AB" * 32 + "\n")
    assert lib.wallet_public_key(Path("fift"), Path("lib"), key, run) == bytes.fromhex("ab" * 32)
    assert run.argv[-1] == str(key.resolve())
    for bad in (
        "",
        "WALLET-PUBLIC-KEY " + "ab" * 31 + "\n",
        ("WALLET-PUBLIC-KEY " + "ab" * 32 + "\n") * 2,
    ):
        with pytest.raises(lib.TestnetError):
            lib.wallet_public_key(Path("fift"), Path("lib"), key, FakeRun(bad))
    key.write_bytes(b"k" * 31)
    with pytest.raises(lib.TestnetError, match="32-byte"):
        lib.wallet_public_key(Path("fift"), Path("lib"), key, run)


def test_public_key_matches_an_independent_ed25519_derivation(tmp_path):
    """Runs the real fift on a throwaway key; TOS_ROOT names a checkout with a build."""
    root = Path(os.environ.get("TOS_ROOT", Path.home() / "tos"))
    fift = root / "build" / "crypto" / "fift"
    if not os.access(fift, os.X_OK):
        pytest.skip("no fift build under TOS_ROOT")
    signing = pytest.importorskip("nacl.signing")
    key = tmp_path / "throwaway.pk"
    key.write_bytes(os.urandom(32))
    derived = lib.wallet_public_key(fift, root / "crypto" / "fift" / "lib", key)
    assert derived == bytes(signing.SigningKey(key.read_bytes()).verify_key)


# ---------------------------------------------------------------- genesis


PROFILE_TAG = lib.load_profile()["genesis"]["auth_network_tag"]["value"]


def genesis_setup(tmp_path, monkeypatch, wallet_key: bytes):
    """A ceremony with create-state replaced by a stand-in that writes its outputs
    (and main-wallet.pk when run-a has none), and the key derived as sha256."""
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir()
    (ceremony / "validator-pq.pub").write_bytes(b"manifest")
    tos_root = tmp_path / "tos"
    template = tos_root / "crypto" / "smartcont" / "gen-zerostate.fif"
    template.parent.mkdir(parents=True)
    template.write_text("template\n")
    tos_build = tmp_path / "build"
    (tos_build / "crypto").mkdir(parents=True)
    (tos_build / "crypto" / "create-state").write_bytes(b"create-state")
    runs = []

    def create_state(run_dir, args, script):
        runs.append(run_dir.name)
        if not (run_dir / "main-wallet.pk").exists():
            (run_dir / "main-wallet.pk").write_bytes(wallet_key)
        for name in coordinator.OUTPUTS:
            (run_dir / name).write_bytes(hashlib.sha256(name.encode()).digest())
        return "ok\n"

    monkeypatch.setattr(coordinator, "create_state", create_state)
    monkeypatch.setattr(coordinator, "tos_revision", lambda root: "0" * 40)
    monkeypatch.setattr(lib, "patch_template", lambda text, *rest: text + "patched\n")
    monkeypatch.setenv(lib.AUTH_NETWORK_TAG_ENV, PROFILE_TAG)

    def auth_policy(boc, root_hash, global_id, version, tag):
        assert (global_id, version, tag.hex()) == (2, 16, PROFILE_TAG)
        return {"network_tag_hex": tag.hex(), "config_param_48_hash_hex": "48" * 32}

    monkeypatch.setattr(lib, "zero_state_auth_policy", auth_policy)
    # create_state above emits opaque stand-in bytes; real BOC checks have their own tests.
    monkeypatch.setattr(lib, "zero_state_gas_credits", lambda boc: {20: 10000, 21: 20000})
    monkeypatch.setattr(lib, "zero_state_retired_params", lambda boc: None)
    monkeypatch.setattr(
        lib,
        "wallet_public_key",
        lambda fift, fift_lib, key: hashlib.sha256(key.read_bytes()).digest(),
    )
    args = [
        "genesis",
        "--ceremony",
        str(ceremony),
        "--tos-root",
        str(tos_root),
        "--tos-build",
        str(tos_build),
        "--epoch",
        str(int(time.time()) + 600),
    ]
    return ceremony, args, runs


def test_genesis_records_the_bootstrap_key(tmp_path, monkeypatch):
    key = b"\x01" * 32
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, key)
    previous = tmp_path / "epoch-1"
    previous.mkdir()
    (previous / "wallets.json").write_text(json.dumps({"bootstrap": KEY_A}))
    assert coordinator.main(args + ["--previous-ceremony", str(previous)]) == 0
    public = hashlib.sha256(key).hexdigest()
    assert runs == ["run-a", "run-b"]
    assert json.loads((ceremony / "genesis.json").read_text())["main_wallet_public_key"] == public
    assert json.loads((ceremony / "wallets.json").read_text()) == {"bootstrap": "pubkey:" + public}
    assert (ceremony / "main-wallet.pub").read_bytes().hex() == public
    assert not (ceremony / "main-wallet.pk").exists()
    # the new ceremony now serves as the previous one of the next reset
    assert lib.previous_wallets(ceremony) == {"bootstrap": "pubkey:" + public}


def test_genesis_with_a_reused_bootstrap_key_stops_before_the_second_run(
    tmp_path, monkeypatch, capsys
):
    key = b"\x02" * 32
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, key)
    previous = tmp_path / "epoch-1"
    previous.mkdir()
    public = hashlib.sha256(key).hexdigest().upper()
    (previous / "genesis.json").write_text(json.dumps({"main_wallet_public_key": public}))
    assert coordinator.main(args + ["--previous-ceremony", str(previous)]) == 1
    assert "wallet bootstrap reuses" in capsys.readouterr().err
    assert runs == ["run-a"]
    for name in ("genesis.json", "wallets.json", "main-wallet.pub", "zerostate.boc", "secret"):
        assert not (ceremony / name).exists()


def test_genesis_refuses_an_empty_previous_ceremony(tmp_path, monkeypatch, capsys):
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, b"\x03" * 32)
    previous = tmp_path / "epoch-1"
    previous.mkdir()
    assert coordinator.main(args + ["--previous-ceremony", str(previous)]) == 1
    assert "records no wallet identity" in capsys.readouterr().err
    assert runs == []


# ---------------------------------------------------------------- pool


class Stop(Exception):
    pass


def pool_setup(tmp_path, monkeypatch, account: bytes):
    """`pool` before genesis, for the operator wallet init-operator.sh printed."""
    ceremony = tmp_path / "ceremony"
    body = bytes([0x11, 0xFF]) + account
    friendly = base64.urlsafe_b64encode(body + b"\x00\x00").decode()

    def owner(args, name, global_id, previous, run=None):
        raise Stop("pool owner")

    monkeypatch.setattr(elections, "ensure_pool_owner", owner)
    args = elections.argparse.Namespace(
        name="a",
        operator=friendly,
        ceremony=str(ceremony),
        tos_root=str(tmp_path / "tos"),
        fift="fift",
        previous_ceremony=[],
    )
    return ceremony, args


def test_pool_records_the_operator_wallet(tmp_path, monkeypatch):
    ceremony, args = pool_setup(tmp_path, monkeypatch, bytes.fromhex("d4" * 32))
    previous = tmp_path / "epoch-1"
    previous.mkdir()
    (previous / "wallets.json").write_text(json.dumps(earlier_epoch()))
    args.previous_ceremony = [str(previous)]
    # Recorded before the pool owner is made; the owner key comes next.
    with pytest.raises(Stop, match="pool owner"):
        elections.stake_pool(args, 2)
    assert json.loads((ceremony / "wallets.json").read_text()) == {"op-a": OP_B}


def test_pool_refuses_an_operator_wallet_an_earlier_epoch_used(tmp_path, monkeypatch):
    ceremony, args = pool_setup(tmp_path, monkeypatch, bytes.fromhex("c3" * 32))
    previous = tmp_path / "epoch-1"
    previous.mkdir()
    (previous / "wallets.json").write_text(json.dumps({"op-z": OP_A.upper()}))
    args.previous_ceremony = [str(previous)]
    # refused before an owner key is made or a pool derived from the wallet
    with pytest.raises(lib.TestnetError, match="wallet op-a reuses"):
        elections.stake_pool(args, 2)
    assert not (ceremony / "wallets.json").exists()


# ---------------------------------------------------------------- load


def address_file(path: Path, address: str) -> None:
    workchain, account = address.split(":")
    path.write_bytes(bytes.fromhex(account) + int(workchain).to_bytes(4, "big", signed=True))


def carried_state(tmp_path) -> Path:
    """A --state directory as an earlier run left it: every key and address present."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "highload.key").write_bytes(b"k")
    address_file(state / "highload.addr", HIGHLOAD)
    for index, address in enumerate((RELAYER, "0:" + "17" * 32)):
        (state / f"relayer-{index}.pk").write_bytes(b"k" * 32)
        address_file(state / f"relayer-{index}.addr", address)
    return state


def load_driver(tmp_path, previous):
    (tmp_path / "ceremony").mkdir(exist_ok=True)
    args = elections.argparse.Namespace(
        ceremony=str(tmp_path / "ceremony"),
        tos_root=str(tmp_path / "tos"),
        fift=str(tmp_path / "tos" / "build" / "crypto" / "fift"),
        rpc="http://fake/jsonRPC",
        key_tool="tos-pq-key",
        state=str(carried_state(tmp_path)),
        actions_per_batch=254,
        transfers="skip",
        transfer_nanotos=50_000,
        wallet_timeout=3600,
        relayers=2,
        send_rpc=None,
        dry_run=True,
        previous_ceremony=previous,
    )

    def rpc(url, method, /, **params):
        raise AssertionError(f"the chain was asked {method}")

    return elections.LoadDriver(args, elections.Chain("http://fake", rpc), 2)


def test_load_records_its_wallets(tmp_path):
    driver = load_driver(tmp_path, [])
    wallet, relayers = driver.ensure_keys(2)
    assert wallet == HIGHLOAD
    tag = "load-" + HIGHLOAD.split(":")[1][:8]
    assert json.loads((tmp_path / "ceremony" / "wallets.json").read_text()) == {
        f"{tag}/highload": HIGHLOAD,
        f"{tag}/relayer-0": RELAYER,
        f"{tag}/relayer-1": "0:" + "17" * 32,
    }


def test_load_accepts_a_second_state_directory_in_the_same_epoch(tmp_path):
    # Another --state directory of the same epoch has other keys and records
    # them under its own labels; the first directory's entries stay.
    ceremony = tmp_path / "ceremony"
    ceremony.mkdir(exist_ok=True)
    (ceremony / "wallets.json").write_text(
        json.dumps(
            {
                "load-00000000/highload": "0:" + "aa" * 32,
                "load-00000000/relayer-0": "0:" + "bb" * 32,
            }
        )
    )
    load_driver(tmp_path, []).ensure_keys(2)
    recorded = json.loads((ceremony / "wallets.json").read_text())
    assert recorded["load-00000000/relayer-0"] == "0:" + "bb" * 32
    assert len(recorded) == 5


@pytest.mark.parametrize("label,identity", [("highload", HIGHLOAD), ("relayer-0", RELAYER)])
def test_load_refuses_a_state_directory_from_an_earlier_epoch(tmp_path, label, identity):
    previous = tmp_path / "epoch-1"
    previous.mkdir()
    (previous / "wallets.json").write_text(json.dumps({"bootstrap": KEY_A, label: identity}))
    driver = load_driver(tmp_path, [str(previous)])
    # run() asks the chain nothing before the keys are checked
    with pytest.raises(lib.TestnetError, match=f"wallet load-[0-9a-f]{{8}}/{label} reuses"):
        driver.run()
    assert not (tmp_path / "ceremony" / "wallets.json").exists()


def test_load_refuses_an_empty_previous_ceremony(tmp_path):
    previous = tmp_path / "epoch-1"
    previous.mkdir()
    with pytest.raises(lib.TestnetError, match="records no wallet identity"):
        load_driver(tmp_path, [str(previous)]).run()


# ---------------------------------------------------------------- AUTH network tag


def test_genesis_records_the_auth_policy(tmp_path, monkeypatch):
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, b"\x04" * 32)
    assert coordinator.main(args) == 0
    auth = json.loads((ceremony / "genesis.json").read_text())["auth_policy"]
    assert auth["network_tag_hex"] == PROFILE_TAG
    assert auth["config_param_48_hash_hex"] == "48" * 32
    assert auth["network_tag_rule"] == lib.load_profile()["genesis"]["auth_network_tag"]["rule"]


@pytest.mark.parametrize(
    "value,message",
    [
        (None, "is not set"),
        ("ab" * 31, "64 hexadecimal digits"),
        ("42" * 32, "reserved"),
        ("12" * 16 + "34" * 16, "but the profile announces"),
    ],
)
def test_genesis_refuses_a_missing_or_different_tag_before_create_state(
    tmp_path, monkeypatch, capsys, value, message
):
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, b"\x05" * 32)
    if value is None:
        monkeypatch.delenv(lib.AUTH_NETWORK_TAG_ENV)
    else:
        monkeypatch.setenv(lib.AUTH_NETWORK_TAG_ENV, value)
    assert coordinator.main(args) == 1
    assert message in capsys.readouterr().err
    assert runs == []
    assert not (ceremony / "genesis.json").exists()


def test_genesis_refuses_the_tag_of_an_earlier_epoch(tmp_path, monkeypatch, capsys):
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, b"\x06" * 32)
    previous = tmp_path / "epoch-4"
    previous.mkdir()
    (previous / "wallets.json").write_text(json.dumps({"bootstrap": KEY_A}))
    (previous / "genesis.json").write_text(
        json.dumps({"auth_policy": {"network_tag_hex": PROFILE_TAG.upper()}})
    )
    assert coordinator.main(args + ["--previous-ceremony", str(previous)]) == 1
    assert "every epoch needs its own" in capsys.readouterr().err
    assert runs == []


def published(ceremony):
    return sorted(
        name
        for name in coordinator.OUTPUTS
        + (
            "gen-zerostate-testnet.fif",
            "main-wallet.pub",
            "create-state.out",
            "secret/main-wallet.pk",
            "genesis.json",
            "wallets.json",
        )
        if (ceremony / name).exists()
    )


def test_a_refused_auth_policy_publishes_nothing_and_a_retry_succeeds(
    tmp_path, monkeypatch, capsys
):
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, b"\x07" * 32)
    accepted = lib.zero_state_auth_policy

    def refuse(*a):
        raise lib.TestnetError("ConfigParam 48 is not the announced policy")

    monkeypatch.setattr(lib, "zero_state_auth_policy", refuse)
    assert coordinator.main(args) == 1
    assert "ConfigParam 48" in capsys.readouterr().err
    assert runs == ["run-a", "run-b"]
    assert published(ceremony) == []
    # A plain rerun is refused cleanly by the scratch runs it left.
    monkeypatch.setattr(lib, "zero_state_auth_policy", accepted)
    assert coordinator.main(args) == 1
    assert "run-a is not empty" in capsys.readouterr().err
    assert published(ceremony) == []
    # With the scratch runs discarded, the same ceremony directory runs cleanly.
    for run in ("run-a", "run-b"):
        shutil.rmtree(ceremony / run)
    assert coordinator.main(args) == 0
    assert (ceremony / "genesis.json").is_file()
    assert (ceremony / "secret" / "main-wallet.pk").read_bytes() == b"\x07" * 32


@pytest.mark.parametrize("left", ["secret/main-wallet.pk", "zerostate.boc", "main-wallet.pub"])
def test_a_partly_published_genesis_is_refused_before_anything_runs(
    tmp_path, monkeypatch, capsys, left
):
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, b"\x08" * 32)
    (ceremony / left).parent.mkdir(parents=True, exist_ok=True)
    (ceremony / left).write_bytes(b"earlier")
    assert coordinator.main(args) == 1
    assert "an earlier genesis attempt published" in capsys.readouterr().err
    assert runs == []
    assert (ceremony / left).read_bytes() == b"earlier"
    assert published(ceremony) == [left]


@pytest.mark.parametrize(
    "failed_output",
    list(coordinator.OUTPUTS)
    + ["gen-zerostate-testnet.fif", "main-wallet.pub", "create-state.out", "genesis.json"],
)
def test_genesis_interrupted_publication_never_overwrites_on_retry(
    tmp_path, monkeypatch, capsys, failed_output
):
    ceremony, args, _ = genesis_setup(tmp_path, monkeypatch, b"\x09" * 32)
    write_new = lib.write_new
    target = ceremony / failed_output

    def interrupt(path, *a, **k):
        if path == target:
            raise lib.TestnetError("interrupted publication")
        return write_new(path, *a, **k)

    monkeypatch.setattr(lib, "write_new", interrupt)
    assert coordinator.main(args) == 1
    assert "interrupted publication" in capsys.readouterr().err
    retained = {name: (ceremony / name).read_bytes() for name in published(ceremony)}
    assert retained["secret/main-wallet.pk"] == b"\x09" * 32
    assert "genesis.json" not in retained
    monkeypatch.setattr(lib, "write_new", write_new)
    assert coordinator.main(args) == 1
    assert "earlier genesis attempt published" in capsys.readouterr().err
    assert {name: (ceremony / name).read_bytes() for name in published(ceremony)} == retained


def test_a_refused_gas_credit_publishes_nothing(tmp_path, monkeypatch, capsys):
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, b"\x07" * 32)

    def refuse(boc):
        raise lib.TestnetError("ConfigParam 21 gas_credit is 10000, expected 20000")

    monkeypatch.setattr(lib, "zero_state_gas_credits", refuse)
    assert coordinator.main(args) == 1
    assert "ConfigParam 21 gas_credit" in capsys.readouterr().err
    assert runs == ["run-a", "run-b"]
    assert published(ceremony) == []


def test_a_retired_config_param_publishes_nothing(tmp_path, monkeypatch, capsys):
    ceremony, args, runs = genesis_setup(tmp_path, monkeypatch, b"\x07" * 32)

    def refuse(boc):
        raise lib.TestnetError("the zero state still defines retired ConfigParam 47")

    monkeypatch.setattr(lib, "zero_state_retired_params", refuse)
    assert coordinator.main(args) == 1
    assert "retired ConfigParam 47" in capsys.readouterr().err
    assert runs == ["run-a", "run-b"]
    assert published(ceremony) == []


# ---------------------------------------------------------------- manifest after pool


def manifest_records(tmp_path) -> list[Path]:
    paths = []
    for n in range(1, 5):
        public = hashlib.shake_256(b"public-%d" % n).digest(lib.PQ_PUBLIC_KEY_BYTES)
        record = {
            "operator": f"operator-{n}",
            "validator_id": hashlib.sha256(b"pool-%d" % n).hexdigest(),
            "adnl_id": hashlib.sha256(b"adnl-%d" % n).hexdigest(),
            "public_key": public.hex(),
            "key_id": lib.pq_key_id(public).hex(),
            "address": f"44.0.0.{n}:30001",
        }
        path = tmp_path / f"record-{n}.json"
        path.write_text(json.dumps(record))
        paths.append(path)
    return paths


def pool_ceremony(tmp_path, count=4) -> Path:
    """What `pool` leaves: pools.json, wallets.json, public owner files and owner keys."""
    ceremony = lib.private_dir(tmp_path / "ceremony")
    pools = {
        f"node-{n}": {
            "pool": "-1:" + hashlib.sha256(b"pool-%d" % n).hexdigest(),
            "owner": "-1:" + "0e" * 32,
            "operator": "-1:" + "0b" * 32,
        }
        for n in range(1, count + 1)
    }
    (ceremony / "pools.json").write_text(json.dumps(pools))
    (ceremony / "wallets.json").write_text(json.dumps({"op-node-1": "-1:" + "0b" * 32}))
    (ceremony / "pool-owners").mkdir()
    lib.private_dir(ceremony / "secret")
    (ceremony / "secret" / "pool-owner-node-1.pk").write_bytes(b"\x02" * 32)
    return ceremony


def manifest(tmp_path, ceremony):
    root = Path(os.environ.get("TOS_ROOT", Path.home() / "tos"))
    if not (root / "scripts/prepare-pq-genesis-manifest.py").is_file():
        pytest.skip("TOS_ROOT has no genesis manifest packer")
    args = coordinator.argparse.Namespace(
        ceremony=ceremony, tos_root=root, previous=[], records=manifest_records(tmp_path)
    )
    coordinator.cmd_manifest(args)


def test_manifest_follows_the_pool_step_and_names_its_pools(tmp_path):
    ceremony = pool_ceremony(tmp_path)
    manifest(tmp_path, ceremony)
    records = json.loads((ceremony / "genesis-records.json").read_text())
    pools = json.loads((ceremony / "pools.json").read_text())
    assert [r["validator_id"] for r in records] == [
        pools[f"node-{n}"]["pool"].split(":")[1] for n in range(1, 5)
    ]


def test_manifest_refuses_a_validator_id_no_pool_recorded(tmp_path):
    ceremony = pool_ceremony(tmp_path, count=3)
    with pytest.raises(lib.TestnetError, match="operator-4 names validator id"):
        manifest(tmp_path, ceremony)
    assert not (ceremony / "genesis-records.json").exists()


@pytest.mark.parametrize("extra", ["genesis.json", "secret/main-wallet.pk"])
def test_manifest_refuses_a_ceremony_with_more_than_the_pool_outputs(tmp_path, extra):
    ceremony = pool_ceremony(tmp_path)
    (ceremony / extra).write_bytes(b"x")
    with pytest.raises(lib.TestnetError, match="only the outputs of"):
        manifest(tmp_path, ceremony)


def test_create_state_finds_its_inputs_from_relative_paths(tmp_path, monkeypatch):
    # create-state runs inside the run directory, so every path it is handed must
    # still name the same file from there. CEREMONY.md passes `--ceremony ./ceremony`.
    fake = tmp_path / "build/crypto/create-state"
    fake.parent.mkdir(parents=True)
    fake.write_text(
        "#!/bin/sh\n"
        'while [ $# -gt 0 ]; do case "$1" in\n'
        '  -I) [ -d "$2" ] || { echo "no include dir $2"; exit 3; }; shift 2 ;;\n'
        '  -s) [ -f "$2" ] || { echo "cannot locate file $2"; exit 2; }; shift 2 ;;\n'
        "  *) shift ;;\n"
        "esac; done\n"
        "echo created\n"
    )
    fake.chmod(0o755)
    for include in ("root/crypto/fift/lib", "root/crypto/smartcont", "build/crypto/smartcont"):
        (tmp_path / include).mkdir(parents=True)
    run_dir = tmp_path / "ceremony/run-a"
    run_dir.mkdir(parents=True)
    (run_dir / "gen-zerostate-testnet.fif").write_text("")
    monkeypatch.chdir(tmp_path)
    args = argparse.Namespace(epoch=1, tos_build=Path("build"), tos_root=Path("root"))
    relative = Path("ceremony/run-a")
    assert (
        coordinator.create_state(relative, args, relative / "gen-zerostate-testnet.fif")
        == "created\n"
    )
    assert (run_dir / "create-state.log").read_text() == "created\n"
