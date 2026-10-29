"""install-node.sh activate --genesis-ceremony: refused outside a genesis validator.

The ceremony asserts that an identity has never signed, so it may run only
where that can be true: activating a validator from the genesis files. Every
misuse is refused before anything is changed. Runs on the unprivileged fake
host of test_rpc_role.py: no root, no systemd, no live host.
"""

import pytest
from test_rpc_role import host  # noqa: F401  (pytest fixture)


@pytest.mark.parametrize("role", ["fullnode", "rpc", "dht"])
def test_ceremony_is_refused_for_every_role_but_a_validator(host, role):  # noqa: F811
    result = host(
        "activate",
        "--role",
        role,
        "--global-config",
        "/nonexistent",
        "--sha256",
        "0" * 64,
        "--genesis",
        "/nonexistent",
        "--genesis-ceremony",
    )
    assert result.returncode != 0
    assert "--genesis-ceremony applies only to activate --role validator" in result.stderr
    assert host.log.read_text() == ""


@pytest.mark.parametrize("step", ["prepare", "binaries"])
def test_ceremony_is_refused_outside_activate(host, step):  # noqa: F811
    result = host(step, "--role", "validator", "--genesis-ceremony")
    assert result.returncode != 0
    assert "--genesis-ceremony applies only to activate --role validator" in result.stderr
    assert host.log.read_text() == ""


def test_ceremony_needs_the_genesis_files(host):  # noqa: F811
    result = host(
        "activate",
        "--role",
        "validator",
        "--global-config",
        "/nonexistent",
        "--sha256",
        "0" * 64,
        "--validator-id",
        "1" * 64,
        "--genesis-ceremony",
    )
    assert result.returncode != 0
    assert "--genesis-ceremony needs --genesis" in result.stderr
    assert host.log.read_text() == ""
