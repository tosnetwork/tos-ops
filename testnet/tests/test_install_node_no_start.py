"""install-node.sh activate --no-start: a full node prepared for bootstrap.

`tosctl node sync bootstrap` installs verified chain data only into a node
database that has never run, with its unit installed but inactive. --no-start
leaves the full node exactly there. Everything runs on the unprivileged fake
host of test_rpc_role.py: no root, no systemd, no live host.
"""

import json

import pytest
from test_rpc_role import documented_steps, fake_host, host  # noqa: F401  (pytest fixtures)

UNIT = "tos-testnet-fullnode.service"


def full_node_steps(*extra: str) -> list[str]:
    """prepare and activate for the full node, as OPERATOR.md documents them."""
    prepare_fullnode, _prepare_rpc, activate_fullnode, _activate_rpc = documented_steps()
    return [prepare_fullnode, " ".join([activate_fullnode, *extra])]


def systemctl_lines(fake_host) -> list[str]:  # noqa: F811
    return [x for x in fake_host.log.read_text().splitlines() if x.startswith("systemctl ")]


def test_no_start_installs_and_enables_the_full_node_without_starting_it(fake_host):  # noqa: F811
    failed = fake_host(full_node_steps("--no-start"))
    assert failed is None, (failed.args, failed.stderr) if failed else ""
    # Installed and enabled, never started: no unit is active.
    assert list(fake_host.state.iterdir()) == []
    lines = systemctl_lines(fake_host)
    assert f"systemctl enable {UNIT}" in lines
    assert not any(x.startswith(("systemctl enable --now", "systemctl start")) for x in lines)
    # A node that never ran has no console to set its submission priority through.
    assert "set-ext-message-pool-options-json" not in fake_host.log.read_text()
    assert (fake_host.prefix / "etc/systemd/system" / UNIT).is_file()
    # Everything else activate does is done: the global config, genesis files
    # and the console client keys are in place.
    db = fake_host.prefix / "var/lib/tos/fullnode"
    assert (fake_host.prefix / "etc/tos/global-config.json").is_file()
    assert len(list((db / "static").iterdir())) == 2
    assert (db / "console-client" / "client").is_file()
    # The engine's first start wrote config.json and the keyring; nothing ran.
    assert json.loads((db / "config.json").read_text())
    for chain_root in ("celldb", "state", "files", "archive"):
        assert not (db / chain_root).exists(), chain_root


def test_without_no_start_activate_still_starts_the_full_node(fake_host):  # noqa: F811
    failed = fake_host(full_node_steps())
    assert failed is None, (failed.args, failed.stderr) if failed else ""
    assert [p.name for p in fake_host.state.iterdir()] == ["tos-testnet-fullnode"]
    assert f"systemctl enable --now {UNIT}" in systemctl_lines(fake_host)
    # The started full node got its submission priority through its own console.
    pool = [
        x
        for x in fake_host.log.read_text().splitlines()
        if "set-ext-message-pool-options-json" in x
    ]
    assert len(pool) == 1 and "/var/lib/tos/fullnode/console-client/client" in pool[0]


@pytest.mark.parametrize("role", ["validator", "rpc", "dht"])
def test_no_start_is_refused_for_every_other_role_before_any_change(host, role):  # noqa: F811
    result = host(
        "activate",
        "--role",
        role,
        "--global-config",
        "/nonexistent",
        "--sha256",
        "0" * 64,
        "--no-start",
    )
    assert result.returncode != 0
    assert "--no-start is for a full node that tosctl node sync bootstrap fills" in result.stderr
    assert host.log.read_text() == ""


@pytest.mark.parametrize("step", ["prepare", "binaries"])
def test_no_start_is_refused_outside_activate(host, step):  # noqa: F811
    result = host(step, "--role", "fullnode", "--no-start")
    assert result.returncode != 0
    assert "--no-start applies only to activate" in result.stderr
    assert host.log.read_text() == ""
