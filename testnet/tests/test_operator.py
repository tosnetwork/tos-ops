import base64
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import testnet_lib as lib
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("testnet_operator", SCRIPTS / "testnet-operator.py")
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)

HOLD_LOCK = """
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.lockf(fd, fcntl.LOCK_EX)
print("held", flush=True)
time.sleep(60)
"""


def test_config_lock_held_by_another_process_is_refused(tmp_path):
    holder = subprocess.Popen(
        [sys.executable, "-c", HOLD_LOCK, str(tmp_path / "config.json.lock")],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(lib.TestnetError, match="is held"):
            operator.hold_config_lock(tmp_path)
    finally:
        holder.kill()
        holder.wait()
    fd = operator.hold_config_lock(tmp_path)
    os.close(fd)


def test_validator_adnl_id_is_the_single_category_zero_key():
    first = lib.b64(b"\x01" * 32)
    second = lib.b64(b"\x02" * 32)
    config = {"adnl": [{"id": first, "category": 0}, {"id": second, "category": 1}]}
    assert lib.validator_adnl_id(config) == b"\x01" * 32
    config["adnl"].append({"id": second, "category": 0})
    with pytest.raises(lib.TestnetError, match="exactly one"):
        lib.validator_adnl_id(config)


def record_args(tmp_path, monkeypatch, validator_id):
    """A first-start config.json announcing 1.2.3.4:30001 and the real key report."""
    db = tmp_path / "db"
    db.mkdir()
    (db / "config.json").write_text(
        json.dumps(
            {
                "adnl": [{"id": lib.b64(b"\x05" * 32), "category": 0}],
                "addrs": [{"ip": int.from_bytes(bytes([1, 2, 3, 4]), "big"), "port": 30001}],
            }
        )
    )
    report = (Path(__file__).parent / "data" / "consensus-key-report.txt").read_text()
    monkeypatch.setattr(operator, "tool", lambda name: name)
    monkeypatch.setattr(
        operator.lib, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, report, "")
    )
    return operator.argparse.Namespace(
        db=db,
        seed=db / "keys" / "pq-consensus.seed",
        validator_id=validator_id,
        operator="operator-1",
        address="1.2.3.4:30001",
        out=tmp_path / "record.json",
    )


def test_record_names_the_staking_account_as_the_validator_id(tmp_path, monkeypatch):
    pool = "ab" * 32
    operator.cmd_record(record_args(tmp_path, monkeypatch, f"-1:{pool}"))
    record = json.loads((tmp_path / "record.json").read_text())
    assert record["validator_id"] == pool and record["adnl_id"] == "05" * 32
    assert lib.check_operator_record(record) == record


@pytest.mark.parametrize("bad", ["ab" * 31, "00" * 32, "0:" + "ab" * 32])
def test_record_refuses_a_malformed_validator_id(tmp_path, monkeypatch, bad):
    with pytest.raises(lib.TestnetError, match="validator_id"):
        operator.cmd_record(record_args(tmp_path, monkeypatch, bad))
    assert not (tmp_path / "record.json").exists()


def test_configure_adds_a_console_and_keys(tmp_path, monkeypatch):
    """Needs generate-random-id; point TOS_BIN at a release or build directory to run it."""
    bin_dir = Path(os.environ.get("TOS_BIN", "/usr/local/bin"))
    if not os.access(bin_dir / "generate-random-id", os.X_OK):
        pytest.skip("generate-random-id not available")
    monkeypatch.setattr(operator, "BIN", bin_dir)
    db = tmp_path / "db"
    (db / "keyring").mkdir(parents=True, mode=0o700)
    db.chmod(0o700)
    (db / "config.json").write_text(json.dumps({"adnl": [], "control": [], "liteservers": []}))
    (db / "config.json").chmod(0o600)
    args = operator.argparse.Namespace(
        profile=lib.PROFILE_PATH, db=db, role="fullnode", client_dir=tmp_path / "client"
    )
    operator.cmd_configure(args)
    config = json.loads((db / "config.json").read_text())
    server = config["control"][0]
    assert server["port"] == 30002
    assert server["allowed"][0]["permissions"] == 15
    assert config["liteservers"][0]["port"] == 30003
    server_key = db / "keyring" / lib.parse_b64(server["id"], 32, "id").hex().upper()
    assert server_key.stat().st_mode & 0o777 == 0o600
    client_pub = (tmp_path / "client" / "client.pub").read_bytes()
    assert lib.b64(lib.adnl_short_id(client_pub[4:])) == server["allowed"][0]["id"]
    with pytest.raises(lib.TestnetError, match="already has a console"):
        operator.cmd_configure(args)


# ---------------------------------------------------------------- tosctl's master wallet

EPOCH5_MASTER_WALLET = {
    "key": {"name": "master-wallet-secret"},
    "version": "V3R2",
    "subwallet_id": 42,
    "workchain": 0,
}


def tosctl_config(tmp_path, master_wallet):
    """A tosctl-config.json as `tosctl config generate` writes it (master_wallet
    null) or as `config master-wallet set` leaves it."""
    path = tmp_path / "tosctl-config.json"
    path.write_text(json.dumps({"wallets": {}, "pools": {}, "master_wallet": master_wallet}))
    return path


def run_master_wallet(path, *extra):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "testnet-operator.py"),
            "master-wallet",
            "--config",
            str(path),
            *extra,
        ],
        capture_output=True,
        text=True,
    )


def test_the_master_wallet_record_is_epoch_5s():
    assert operator.MASTER_WALLET == EPOCH5_MASTER_WALLET


def test_a_generated_configuration_gets_the_master_wallet(tmp_path):
    result = run_master_wallet(tosctl_config(tmp_path, None))
    assert (result.returncode, result.stdout.strip()) == (0, "set")
    # Not yet configured: --require refuses.
    assert run_master_wallet(tosctl_config(tmp_path, None), "--require").returncode == 1


def test_the_master_wallet_step_is_idempotent(tmp_path):
    path = tosctl_config(tmp_path, EPOCH5_MASTER_WALLET)
    for extra in ((), ("--require",)):
        result = run_master_wallet(path, *extra)
        assert (result.returncode, result.stdout.strip()) == (0, "keep")


@pytest.mark.parametrize(
    "change",
    [
        {"key": {"name": "op-node-1"}},
        {"version": "V4R2"},
        {"subwallet_id": 0},
        {"workchain": -1},
    ],
)
def test_a_different_master_wallet_is_never_replaced(tmp_path, change):
    path = tosctl_config(tmp_path, dict(EPOCH5_MASTER_WALLET, **change))
    before = path.read_bytes()
    result = run_master_wallet(path)
    assert result.returncode == 1
    assert "a different master wallet is configured" in result.stderr
    assert result.stdout == ""
    assert path.read_bytes() == before


def test_a_configuration_without_the_field_is_refused(tmp_path):
    path = tmp_path / "tosctl-config.json"
    path.write_text(json.dumps({"wallets": {}}))
    result = run_master_wallet(path)
    assert result.returncode == 1 and "no master_wallet field" in result.stderr


def test_init_operator_configures_and_checks_the_master_wallet():
    """init-operator.sh asks the helper, sets exactly MASTER_WALLET with tosctl,
    then requires it, before the operator wallet; it never passes --force."""
    script = (SCRIPTS / "init-operator.sh").read_text()
    ask = script.index('testnet-operator.py" master-wallet --config "$CONFIG_PATH")')
    setter = script.index(
        "as_ctl tosctl config master-wallet set --secret-name master-wallet-secret --version V3R2"
    )
    require = script.index('master-wallet --config "$CONFIG_PATH" --require')
    wallet = script.index('tosctl wallet create --name "op-$NAME"')
    assert ask < setter < require < wallet
    assert "--force" not in script
    # The set happens only on the helper's "set", outside the --wallet-only branches.
    assert 'if [ "$master_action" = set ]; then' in script
    # subwallet 42 and workchain 0 are the command's defaults (tosctl master_wallet_cmd.rs).
    assert "--subwallet-id" not in script and "--workchain 0" not in script


SECRET_MARKER = "5ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7"


@pytest.mark.parametrize(
    ("key", "kind"),
    [
        (
            {"type_id": 1, "pvt_key": base64.b64encode(bytes.fromhex(SECRET_MARKER)).decode()},
            "inline private key",
        ),
        (SECRET_MARKER + SECRET_MARKER, "inline key pair"),
        ({"name": "secret-" + SECRET_MARKER}, "vault key"),
    ],
)
def test_the_refusal_never_prints_the_configured_record(tmp_path, key, kind):
    """tosctl accepts inline key material in a master-wallet record; a refusal
    names only the differing fields and the key's kind."""
    path = tosctl_config(tmp_path, dict(EPOCH5_MASTER_WALLET, key=key))
    result = run_master_wallet(path)
    assert result.returncode == 1
    assert "fields that differ: key" in result.stderr
    assert f"key kind: {kind}" in result.stderr
    b64 = base64.b64encode(bytes.fromhex(SECRET_MARKER)).decode()
    for marker in (SECRET_MARKER, b64, SECRET_MARKER[:16]):
        assert marker not in result.stdout and marker not in result.stderr
