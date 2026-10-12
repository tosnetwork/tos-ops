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


def test_controller_refuses_root_equal_to_consensus_key():
    public = bytes(range(256)) * 5 + bytes(32)
    args = operator.argparse.Namespace(
        root_public=public.hex(),
        key_id=lib.pq_key_id(public).hex(),
        tos_root=Path("/nonexistent"),
        tos_build=Path("/nonexistent"),
        out=None,
    )
    with pytest.raises(lib.TestnetError, match="two different keys"):
        operator.cmd_controller(args)


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
