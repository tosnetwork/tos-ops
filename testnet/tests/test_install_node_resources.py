"""install-node.sh activate --role validator --cache-bytes/--memory-max/--memory-high.

A validator on a host below the profile's memory floor (under a recorded
preflight waiver) gets lower RocksDB caches and cgroup limits through one
reviewed drop-in, never a hand edit. Without the options the unit's 1 GiB
defaults apply and nothing extra is written. Every misuse is refused before
anything changes. Runs on the unprivileged fake hosts of test_rpc_role.py:
no root, no systemd, no live host.
"""

import json

import pytest
import testnet_lib as lib
from test_rpc_role import fake_host, host  # noqa: F401  (pytest fixtures)

UNIT = "tos-testnet-validator.service"
DROP_IN = f"etc/systemd/system/{UNIT}.d/50-resources.conf"
RECORD = "etc/tos/validator-resources.json"
MIB, GIB = 1 << 20, 1 << 30
INSTALL = "sudo /opt/tos-testnet/scripts/install-node.sh"
PREPARE = (
    f"{INSTALL} prepare --role validator --public-ip <PUBLIC_IPV4>"
    ' --release "$REL" --rev "$TOS_COMMIT"'
)
ACTIVATE = (
    f"{INSTALL} activate --role validator --global-config <GLOBAL_CONFIG_JSON>"
    " --sha256 <PUBLISHED_SHA256> --genesis <PUBLISHED_GENESIS_DIRECTORY>"
    f" --validator-id {'1' * 64}"
)
V4 = "--cache-bytes 268435456 --memory-max 2400M --memory-high 2200M"


def ok(result):
    assert result is None, (result.args, result.stderr) if result else ""


def stop(fake_host):  # noqa: F811
    for unit in fake_host.state.iterdir():
        unit.unlink()


# ---------------------------------------------------------------- the drop-in itself


def test_activate_with_resources_writes_the_drop_in_and_its_record(fake_host):  # noqa: F811
    ok(fake_host([PREPARE, f"{ACTIVATE} {V4}"]))
    text = (fake_host.prefix / DROP_IN).read_text()
    assert text.splitlines()[2:] == [
        "[Service]",
        f"MemoryMax={2400 * MIB}",
        f"MemoryHigh={2200 * MIB}",
        f"Environment=TOS_ROCKSDB_BLOCK_CACHE_SIZE={256 * MIB}",
        f"Environment=TOS_CELLDB_CACHE_BYTES={256 * MIB}",
    ]
    record = json.loads((fake_host.prefix / RECORD).read_text())
    assert record == {
        "unit": UNIT,
        "drop_in": f"{UNIT}.d/50-resources.conf",
        "drop_in_sha256": lib.hashlib.sha256(text.encode()).hexdigest(),
        "cache_bytes": 256 * MIB,
        "memory_max_bytes": 2400 * MIB,
        "memory_high_bytes": 2200 * MIB,
    }
    log = fake_host.log.read_text().splitlines()
    # The drop-in is in place before the unit's daemon-reload, and the node then starts.
    first_drop_in = next(
        i for i, x in enumerate(log) if x.startswith("install") and DROP_IN[3:] in x
    )
    reload = next(i for i, x in enumerate(log) if x == "systemctl daemon-reload")
    assert first_drop_in < reload
    assert f"systemctl enable --now {UNIT}" in log


def test_memory_high_is_optional(fake_host):  # noqa: F811
    ok(fake_host([PREPARE, f"{ACTIVATE} --cache-bytes 268435456 --memory-max 2400M"]))
    text = (fake_host.prefix / DROP_IN).read_text()
    assert "MemoryHigh" not in text and f"MemoryMax={2400 * MIB}" in text
    assert json.loads((fake_host.prefix / RECORD).read_text())["memory_high_bytes"] is None


def test_without_the_options_no_drop_in_or_record_is_written(fake_host):  # noqa: F811
    ok(fake_host([PREPARE, ACTIVATE]))
    assert not (fake_host.prefix / DROP_IN).exists()
    assert not (fake_host.prefix / DROP_IN).parent.exists()
    assert not (fake_host.prefix / RECORD).exists()
    assert (fake_host.prefix / "etc/systemd/system" / UNIT).is_file()


def test_activate_again_with_the_same_values_keeps_the_drop_in(fake_host):  # noqa: F811
    ok(fake_host([PREPARE, f"{ACTIVATE} {V4}"]))
    before = (fake_host.prefix / DROP_IN).read_bytes()
    stop(fake_host)
    ok(fake_host([f"{ACTIVATE} {V4}"]))
    assert (fake_host.prefix / DROP_IN).read_bytes() == before


def test_activate_with_other_values_refuses_an_existing_drop_in(fake_host):  # noqa: F811
    ok(fake_host([PREPARE, f"{ACTIVATE} {V4}"]))
    before = (fake_host.prefix / DROP_IN).read_bytes()
    stop(fake_host)
    marker = fake_host.log.read_text()
    failed = fake_host([f"{ACTIVATE} --cache-bytes 536870912 --memory-max 2400M"])
    assert failed is not None and "exists with different values" in failed.stderr
    assert (fake_host.prefix / DROP_IN).read_bytes() == before
    assert fake_host.log.read_text() == marker  # refused before any change


def test_activate_without_options_refuses_an_existing_drop_in(fake_host):  # noqa: F811
    ok(fake_host([PREPARE, f"{ACTIVATE} {V4}"]))
    stop(fake_host)
    marker = fake_host.log.read_text()
    failed = fake_host([ACTIVATE])
    assert failed is not None
    assert "exists; pass the values it was written with" in failed.stderr
    assert fake_host.log.read_text() == marker


# ---------------------------------------------------------------- refusals before any change

GOOD = ["--cache-bytes", "268435456", "--memory-max", "2400M"]


def activate_args(role, *extra):
    return (
        "activate",
        "--role",
        role,
        "--global-config",
        "/nonexistent",
        "--sha256",
        "0" * 64,
        *extra,
    )


@pytest.mark.parametrize("role", ["fullnode", "rpc", "dht"])
@pytest.mark.parametrize(
    "option", [GOOD, ["--memory-high", "2200M"], ["--cache-bytes", "268435456"]]
)
def test_resources_are_refused_for_every_role_but_a_validator(host, role, option):  # noqa: F811
    result = host(*activate_args(role, *option))
    assert result.returncode != 0
    assert "apply only to activate --role validator" in result.stderr
    assert host.log.read_text() == ""


@pytest.mark.parametrize("step", ["prepare", "binaries"])
def test_resources_are_refused_outside_activate(host, step):  # noqa: F811
    result = host(step, "--role", "validator", *GOOD)
    assert result.returncode != 0
    assert "apply only to activate --role validator" in result.stderr
    assert host.log.read_text() == ""


@pytest.mark.parametrize(
    "extra",
    [
        ["--cache-bytes", "268435456"],
        ["--memory-max", "2400M"],
        ["--memory-high", "2200M"],
        ["--memory-max", "2400M", "--memory-high", "2200M"],
    ],
)
def test_cache_bytes_and_memory_max_are_required_together(host, extra):  # noqa: F811
    result = host(*activate_args("validator", *extra))
    assert result.returncode != 0
    assert "--cache-bytes and --memory-max are required together" in result.stderr
    assert host.log.read_text() == ""


@pytest.mark.parametrize(
    "extra,message",
    [
        (["--cache-bytes", "1", "--memory-max", "2400M"], "outside"),
        (["--cache-bytes", str(GIB + 1), "--memory-max", "8G"], "outside"),
        (["--cache-bytes", "256M", "--memory-max", "2400M"], "a positive byte count"),
        (["--cache-bytes", "0", "--memory-max", "2400M"], "a positive byte count"),
        (["--cache-bytes", "-268435456", "--memory-max", "2400M"], "a positive byte count"),
        (["--cache-bytes", "268435456", "--memory-max", "2.4G"], "bytes or a K/M/G size"),
        (["--cache-bytes", "268435456", "--memory-max", "2400MB"], "bytes or a K/M/G size"),
        (["--cache-bytes", "268435456", "--memory-max", "1G"], "leaves less than 1 GiB"),
        (
            ["--cache-bytes", "268435456", "--memory-max", "2400M", "--memory-high", "1G"],
            "leaves less than 1 GiB",
        ),
        (
            ["--cache-bytes", "268435456", "--memory-max", "2400M", "--memory-high", "2400M"],
            "must be below --memory-max",
        ),
        (["--cache-bytes", "268435456", "--memory-max", "100000G"], "exceeds this host's MemTotal"),
    ],
)
def test_out_of_range_values_are_refused_before_any_change(host, extra, message):  # noqa: F811
    result = host(*activate_args("validator", *extra))
    assert result.returncode != 0
    assert message in result.stderr, result.stderr
    assert host.log.read_text() == ""


# ---------------------------------------------------------------- the checks themselves

TOTAL = 4 * GIB


def test_the_v4_values_pass_and_the_boundaries_hold():
    v4 = lib.validator_resources("268435456", "2400M", "2200M", TOTAL)
    assert v4 == {
        "cache_bytes": 256 * MIB,
        "memory_max_bytes": 2400 * MIB,
        "memory_high_bytes": 2200 * MIB,
    }
    # Both cache bounds are inclusive; each limit may equal two caches plus 1 GiB.
    floor = 2 * lib.RESOURCE_CACHE_MIN + lib.RESOURCE_HEADROOM
    assert lib.validator_resources(str(lib.RESOURCE_CACHE_MIN), str(floor), None, TOTAL)
    assert lib.validator_resources(str(lib.RESOURCE_CACHE_MAX), "3G", None, TOTAL)
    assert lib.validator_resources("268435456", str(TOTAL), None, TOTAL)
    with pytest.raises(lib.TestnetError, match="outside"):
        lib.validator_resources(str(lib.RESOURCE_CACHE_MIN - 1), "4G", None, TOTAL)
    with pytest.raises(lib.TestnetError, match="leaves less than 1 GiB"):
        lib.validator_resources(str(lib.RESOURCE_CACHE_MIN), str(floor - 1), None, TOTAL)
    with pytest.raises(lib.TestnetError, match="exceeds"):
        lib.validator_resources("268435456", str(TOTAL + 1), None, TOTAL)


@pytest.mark.parametrize(
    "value,expected", [("1", 1), ("2K", 2048), ("3M", 3 * MIB), ("4G", 4 * GIB)]
)
def test_sizes_are_1024_based(value, expected):
    assert lib.resource_size(value, "x") == expected


@pytest.mark.parametrize("value", ["", "0", "01", "1k", "1T", " 1", "1 ", "1.5G", "1e9", None, 5])
def test_malformed_sizes_are_refused(value):
    with pytest.raises(lib.TestnetError):
        lib.resource_size(value, "x")


def test_mem_total_comes_from_meminfo():
    assert lib.mem_total_bytes("MemFree: 1 kB\nMemTotal:     4019876 kB\n") == 4019876 * 1024
    with pytest.raises(lib.TestnetError, match="MemTotal"):
        lib.mem_total_bytes("MemFree: 1 kB\n")


def test_the_drop_in_names_only_the_limits_and_both_caches():
    text = lib.validator_resources_drop_in(
        lib.validator_resources("268435456", "2400M", None, TOTAL)
    )
    body = [x for x in text.splitlines() if x and not x.startswith("#")]
    assert body == [
        "[Service]",
        f"MemoryMax={2400 * MIB}",
        f"Environment=TOS_ROCKSDB_BLOCK_CACHE_SIZE={256 * MIB}",
        f"Environment=TOS_CELLDB_CACHE_BYTES={256 * MIB}",
    ]


def test_the_unit_reads_the_cache_variable_the_drop_in_sets():
    unit = (lib.HERE.parent / "systemd" / UNIT).read_text()
    for variable in ("TOS_ROCKSDB_BLOCK_CACHE_SIZE", "TOS_CELLDB_CACHE_BYTES"):
        assert f"Environment={variable}=" in unit
    assert unit.count("${TOS_CELLDB_CACHE_BYTES}") == 2
