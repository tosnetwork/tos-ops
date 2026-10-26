"""The rpc role: a full node host that also runs tos-wallet-index and tos-rpc.

Role -> binaries in the build, install and fetch tools; the two unit templates'
hardening, loopback listeners, read-only default and start order; the
installer's refusals; and the liteserver configuration tos-rpc trusts.
Everything runs against fakes: no root, no systemd, no live host.
"""

import hashlib
import importlib.util
import ipaddress
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import testnet_lib as lib
from conftest import SCRIPTS

SYSTEMD = SCRIPTS.parent / "systemd"
INSTALL = SCRIPTS / "install-node.sh"
BUILD = SCRIPTS / "build-node-binaries.sh"
PIN = "4b4892b8d94e33fcb9699a9fd9b8032c12efdfd0"
NODE = [
    "validator-engine",
    "validator-engine-console",
    "lite-client",
    "generate-random-id",
    "tos-pq-consensus-key",
]
SERVICES = ["tos-rpc", "tos-wallet-index"]
RPC = NODE + SERVICES
INDEX_UNIT = "tos-testnet-wallet-index.service"
RPC_UNIT = "tos-testnet-rpc.service"
SOURCE_DB = "/var/lib/tos/fullnode"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fetch_release = load("fetch_release_rpc", SCRIPTS / "fetch-release.py")
operator = load("testnet_operator_rpc", SCRIPTS / "testnet-operator.py")


# ---------------------------------------------------------------- role -> binaries


def install_role_binaries(role: str) -> list[str]:
    """Run install-node.sh's own role_binaries function for `role`."""
    text = INSTALL.read_text()
    body = text[text.index("role_binaries() {") :]
    body = body[: body.index("\n}\n") + 3]
    result = subprocess.run(
        ["bash", "-c", f'{body}\nROLE="$1"; role_binaries', "-", role],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.split()


def build_targets(role: str) -> list[str]:
    """The TARGETS build-node-binaries.sh selects for `role`."""
    text = BUILD.read_text()
    for pattern, targets in re.findall(r"(?m)^  ([a-z|]+)\) TARGETS=\(([^)]*)\) ;;$", text):
        if role in pattern.split("|"):
            return targets.split()
    raise AssertionError(f"build-node-binaries.sh has no TARGETS for {role}")


def test_the_rpc_role_is_the_full_node_plus_both_services_everywhere():
    assert build_targets("rpc") == RPC
    assert install_role_binaries("rpc") == RPC
    assert fetch_release.ROLE_BINARIES["rpc"] == RPC
    # The other roles do not carry the services.
    for role in ("validator", "fullnode", "dht"):
        for name in SERVICES:
            assert name not in build_targets(role), role
            assert name not in install_role_binaries(role), role
            assert name not in fetch_release.ROLE_BINARIES[role], role


def test_the_build_copies_the_services_from_their_cmake_directory():
    text = BUILD.read_text()
    assert "  [tos-rpc]=services/tos-rpc\n" in text
    assert "  [tos-wallet-index]=services/tos-wallet-index\n" in text
    # The version line the build prints comes from the engine, not a service
    # without -V.
    assert build_targets("rpc")[0] == "validator-engine"
    assert install_role_binaries("rpc")[0] == "validator-engine"


def test_the_installer_installs_the_services_from_any_release_that_carries_them():
    text = INSTALL.read_text()
    block = text[text.index("ALL_BINARIES=(") :]
    block = block[: block.index(")\n")]
    for name in RPC + ["dht-server"]:
        assert re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", block), name


def test_the_services_are_not_asked_for_a_version_line():
    assert not set(SERVICES) & fetch_release.VERSIONED


# ---------------------------------------------------------------- install-node.sh with fakes


FAKE_ID = """#!/bin/sh
[ "$1" = -u ] && { echo 0; exit 0; }
exit 0
"""
FAKE_SYSTEMCTL = """#!/bin/sh
if [ "$1" = is-active ]; then
  for unit in $FAKE_ACTIVE; do [ "$3" = "$unit" ] && exit 0; done
  exit 3
fi
echo "systemctl $*" >> "$FAKE_LOG"
exit 97
"""
# Anything that would change the host: logged and failed.
FAKE_CHANGE = """#!/bin/sh
echo "$(basename "$0") $*" >> "$FAKE_LOG"
exit 97
"""
# runuser only reads here (the bundle readability check); it runs the command
# as the caller.
FAKE_RUNUSER = """#!/bin/sh
[ "$1" = -u ] && [ "$3" = -- ] || exit 2
shift 3
exec "$@"
"""


@pytest.fixture
def host(tmp_path):
    """install-node.sh run from a copy of the bundle on a fake host.

    The copy's setup-time.sh is a fake too: install-node.sh runs it by its own
    path, and the real one changes the clock setup. Every write the script
    could make (clock setup, account, install, a systemctl change) is logged to
    changes.log and fails."""
    bundle = tmp_path / "testnet"
    shutil.copytree(SCRIPTS.parent, bundle, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    (bundle / "scripts" / "setup-time.sh").write_text(FAKE_CHANGE)
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    for name, text in (
        ("id", FAKE_ID),
        ("systemctl", FAKE_SYSTEMCTL),
        ("install", FAKE_CHANGE),
        ("useradd", FAKE_CHANGE),
        ("runuser", FAKE_RUNUSER),
    ):
        (fakebin / name).write_text(text)
        (fakebin / name).chmod(0o755)
    log = tmp_path / "changes.log"
    log.write_text("")

    def run(*args, active: str = ""):
        env = {"PATH": f"{fakebin}:/usr/bin:/bin", "FAKE_LOG": str(log), "FAKE_ACTIVE": active}
        return subprocess.run(
            ["bash", str(bundle / "scripts" / "install-node.sh"), *args],
            capture_output=True,
            text=True,
            env=env,
        )

    run.log = log
    return run


def make_release(tmp_path: Path, binaries: list[str]) -> Path:
    """A self-consistent release of PIN laid out as build-node-binaries.sh writes it."""
    release = tmp_path / f"release-{PIN}"
    release.mkdir()
    for name in binaries:
        (release / name).write_bytes(f"{name} {PIN}\n".encode())
    (release / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((release / n).read_bytes()).hexdigest()}  {n}\n"
            for n in sorted(binaries)
        )
    )
    (release / "BUILD-INFO").write_text(f"tos_revision {PIN}\n")
    return release


@pytest.mark.parametrize("missing", SERVICES)
@pytest.mark.parametrize("step", ["binaries", "prepare"])
def test_an_rpc_install_from_a_release_without_a_service_is_refused(host, tmp_path, step, missing):
    release = make_release(tmp_path, [n for n in RPC if n != missing])
    result = host(step, "--role", "rpc", "--release", str(release), "--rev", PIN)
    assert result.returncode != 0
    assert f"the release lacks {missing}" in result.stderr, result.stderr
    assert "refused" in result.stderr
    assert host.log.read_text() == ""


def test_a_full_node_release_does_not_satisfy_the_rpc_role(host, tmp_path):
    release = make_release(tmp_path, NODE)
    result = host("binaries", "--role", "rpc", "--release", str(release), "--rev", PIN)
    assert result.returncode != 0
    assert "the release lacks tos-rpc" in result.stderr
    assert host.log.read_text() == ""


NODE_UNITS = [
    "tos-testnet-validator",
    "tos-testnet-fullnode",
    "tos-testnet-dht",
    "tos-testnet-wallet-index",
    "tos-testnet-rpc",
]
ENTRIES = {
    "prepare-rpc": ["prepare", "--role", "rpc"],
    "prepare-fullnode": ["prepare", "--role", "fullnode", "--public-ip", "192.0.2.10"],
    "binaries-rpc": ["binaries", "--role", "rpc"],
    "binaries-dht": ["binaries", "--role", "dht"],
}
# The first write each entry makes once the preflight passes.
FIRST_WRITE = {
    "prepare-rpc": "install -m 0755",
    "prepare-fullnode": "setup-time.sh",
    "binaries-rpc": "install -m 0755",
    "binaries-dht": "install -m 0755",
}


@pytest.mark.parametrize("unit", NODE_UNITS)
@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_prepare_and_binaries_refuse_before_any_write_while_a_service_runs(
    host, tmp_path, entry, unit
):
    release = make_release(tmp_path, RPC + ["dht-server"])
    args = ENTRIES[entry] + ["--release", str(release), "--rev", PIN]
    result = host(*args, active=unit)
    assert result.returncode != 0
    assert f"{unit} is running; stop it first" in result.stderr, result.stderr
    # No clock setup, no account, no install, no systemctl change.
    assert host.log.read_text() == ""


@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_with_nothing_running_the_fakes_record_the_first_write(host, tmp_path, entry):
    # The control for the refusals above: the same command on an idle host
    # gets past the preflight, and its first write shows up in the log.
    release = make_release(tmp_path, RPC + ["dht-server"])
    result = host(*ENTRIES[entry], "--release", str(release), "--rev", PIN)
    assert result.returncode != 0  # the fake write fails
    log = host.log.read_text()
    assert log.splitlines()[0].startswith(FIRST_WRITE[entry]), log


def test_an_unknown_role_is_refused(host):
    result = host("prepare", "--role", "observer")
    assert result.returncode != 0
    assert "--role must be validator, fullnode, rpc or dht" in result.stderr


def function_body(name: str) -> str:
    text = INSTALL.read_text()
    body = text[text.index(f"{name}() {{") :]
    return body[: body.index("\n}\n")]


def test_rpc_activation_checks_before_it_changes_anything():
    body = function_body("activate_rpc")
    first_change = min(
        body.index(marker)
        for marker in ("install -m", "install_unit", "enable --now", "rpc-config")
    )
    for check in (
        "require_role_binaries",
        "id tos-rpc",
        'cmp -s "$GLOBAL_CONFIG" "$ETC/global-config.json"',
        "systemctl is-active --quiet tos-testnet-fullnode",
    ):
        assert body.index(check) < first_change, check
    # The index starts before tos-rpc.
    assert "RPC_UNITS=(tos-testnet-wallet-index.service tos-testnet-rpc.service)" in (
        INSTALL.read_text()
    )
    # The generic activation hands over to it before installing the global config.
    activate = function_body("activate")
    assert activate.index('if [ "$ROLE" = rpc ]; then activate_rpc; return; fi') < activate.index(
        'install -m 0644 -o root -g root "$GLOBAL_CONFIG"'
    )
    assert activate.index("SHA-256 mismatch") < activate.index("activate_rpc")


def test_rpc_preparation_checks_the_binaries_before_it_adds_the_account():
    body = function_body("prepare_rpc")
    assert body.index("install_release") < body.index("require_role_binaries")
    assert body.index("require_role_binaries") < body.index("useradd")
    assert "--shell /usr/sbin/nologin tos-rpc" in body


# ---------------------------------------------------------------- unit templates


def unit_lines(name: str) -> dict[str, list[str]]:
    """Directive -> values, with continuation lines joined and comments dropped."""
    text = (SYSTEMD / name).read_text().replace("\\\n", " ")
    directives: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, _, value = line.partition("=")
        directives.setdefault(key, []).append(value)
    return directives


def exec_argv(directives: dict[str, list[str]], env_file: dict[str, str] | None = None):
    """ExecStart as systemd runs it: unbraced $VAR splits into words, empty gives none."""
    env = dict(v.split("=", 1) for v in directives.get("Environment", []))
    env.update(env_file or {})
    argv = []
    for word in shlex.split(directives["ExecStart"][0]):
        if word.startswith("$"):
            argv += env.get(word[1:], "").split()
        else:
            argv.append(word)
    return argv


def option(argv: list[str], name: str) -> str:
    assert argv.count(name) == 1, (name, argv)
    return argv[argv.index(name) + 1]


def assert_loopback(address: str) -> None:
    ip, _, port = address.rpartition(":")
    assert ipaddress.ip_address(ip).is_loopback, address
    assert 0 < int(port) < 65536


HARDENING = (
    "UMask=0077",
    "NoNewPrivileges=true",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "PrivateTmp=true",
    "CapabilityBoundingSet=",
    "RestartPreventExitStatus=2",
    "KillMode=control-group",
)


@pytest.mark.parametrize("name", [INDEX_UNIT, RPC_UNIT])
def test_rpc_units_keep_the_node_units_hardening(name):
    text = (SYSTEMD / name).read_text()
    for line in HARDENING:
        assert f"\n{line}\n" in text, (name, line)
    directives = unit_lines(name)
    assert directives["User"] != ["root"] and directives["User"]
    assert directives["LimitNOFILE"]


def test_the_index_reads_the_full_node_database_read_only():
    d = unit_lines(INDEX_UNIT)
    argv = exec_argv(d)
    assert argv[0] == "/usr/local/bin/tos-wallet-index"
    source = option(argv, "--source-db")
    data = option(argv, "--data-dir")
    assert source == SOURCE_DB
    assert d["ReadOnlyPaths"] == [source]
    # Its only writable path is its own state directory, outside the source.
    assert d["StateDirectory"] == ["tos-wallet-index"]
    assert data == "/var/lib/tos-wallet-index"
    assert d["ReadWritePaths"] == [data]
    assert d["StateDirectoryMode"] == ["0700"]
    assert not Path(data).is_relative_to(source) and not Path(source).is_relative_to(data)
    # The node database is owner-only, so only its owner can read it.
    assert d["User"] == ["tos"]


def test_the_index_listens_on_loopback_on_its_profile_port():
    ports = lib.load_profile()["ports"]
    listen = option(exec_argv(unit_lines(INDEX_UNIT)), "--listen")
    assert_loopback(listen)
    assert listen == f"127.0.0.1:{ports['wallet_index_loopback']}"
    # Not the full node's operator JSON-RPC port on the same host.
    assert ports["wallet_index_loopback"] != ports["json_rpc_loopback"]
    fullnode = (SYSTEMD / "tos-testnet-fullnode.service").read_text()
    assert f"--json-rpc-address 127.0.0.1:{ports['json_rpc_loopback']}" in fullnode


def test_the_public_rpc_is_read_only_by_default():
    d = unit_lines(RPC_UNIT)
    argv = exec_argv(d)
    assert argv[0] == "/usr/local/bin/tos-rpc"
    assert "--readonly" in argv
    assert not any(a.startswith("--submission-address") for a in argv)
    # Optional files only: no write backend unless one is configured explicitly.
    assert d["EnvironmentFile"] == ["-/etc/tos/tos-rpc.env"]
    assert "TOS_RPC_MODE=--readonly" in d["Environment"]
    # An explicit submission backend replaces --readonly.
    written = exec_argv(d, {"TOS_RPC_MODE": "--submission-address 127.0.0.1:8081"})
    assert "--readonly" not in written
    assert option(written, "--submission-address") == "127.0.0.1:8081"


def test_the_public_rpc_listens_on_loopback_and_reaches_the_index_there():
    ports = lib.load_profile()["ports"]
    d = unit_lines(RPC_UNIT)
    argv = exec_argv(d)
    listen = option(argv, "--listen")
    index = option(argv, "--index-address")
    assert_loopback(listen)
    assert_loopback(index)
    assert listen == f"127.0.0.1:{ports['rpc_http_loopback']}"
    assert index == option(exec_argv(unit_lines(INDEX_UNIT)), "--listen")
    assert option(argv, "--global-config") == "/etc/tos/rpc-liteservers.json"
    # Its own account, with nothing writable and no view of the node or index data.
    assert d["User"] == ["tos-rpc"] and d["Group"] == ["tos-rpc"]
    assert "ReadWritePaths" not in d and "StateDirectory" not in d
    hidden = d["InaccessiblePaths"][0].split()
    assert "-/var/lib/tos" in hidden and "-/var/lib/tos-wallet-index" in hidden


def test_services_start_after_the_full_node_and_the_index():
    index = unit_lines(INDEX_UNIT)
    rpc = unit_lines(RPC_UNIT)
    assert "tos-testnet-fullnode.service" in index["After"][0].split()
    after = rpc["After"][0].split()
    assert "tos-testnet-fullnode.service" in after
    assert "tos-testnet-wallet-index.service" in after


def test_services_follow_maintenance_of_the_node_and_the_index():
    index = unit_lines(INDEX_UNIT)
    rpc = unit_lines(RPC_UNIT)
    # Stop and restart of the node reach the index, of the index reach the RPC.
    assert index["PartOf"] == ["tos-testnet-fullnode.service"]
    assert rpc["PartOf"] == ["tos-testnet-wallet-index.service"]
    # A start of the node starts the index, a start of the index starts the RPC.
    assert index["WantedBy"] == ["tos-testnet-fullnode.service"]
    assert rpc["WantedBy"] == ["tos-testnet-wallet-index.service"]
    # A start of the index while the node is down, or of the RPC while the
    # index is down, is skipped: a condition, not a failing ExecStartPre= that
    # Restart= would retry.
    assert index["ExecCondition"] == [
        "/bin/systemctl is-active --quiet tos-testnet-fullnode.service"
    ]
    assert rpc["ExecCondition"] == [
        "/bin/systemctl is-active --quiet tos-testnet-wallet-index.service"
    ]
    for d in (index, rpc):
        assert "ExecStartPre" not in d
    # Neither pulls a stopped full node back up, and Requisite= (which left the
    # index stopped for good after a node restart) is gone.
    for d in (index, rpc):
        assert "tos-testnet-fullnode.service" not in " ".join(d.get("Wants", []))
        for key in ("Requires", "BindsTo", "Requisite"):
            assert key not in d, key


def test_rpc_activation_enables_through_the_install_sections():
    body = function_body("activate_rpc")
    assert 'systemctl enable --now "$unit"' in body
    assert "--runtime" not in body


def test_the_firewall_example_opens_neither_service_port():
    ports = lib.load_profile()["ports"]
    nft = (SCRIPTS.parent / "firewall" / "tos-testnet.nft").read_text()
    rules = [
        line for line in nft.splitlines() if "dport" in line and not line.lstrip().startswith("#")
    ]
    for port in (ports["rpc_http_loopback"], ports["wallet_index_loopback"]):
        assert not any(re.search(rf"\b{port}\b", rule) for rule in rules), port


# ---------------------------------------------------------------- liteserver configuration


def liteserver_pub() -> bytes:
    return lib.ED25519_PUBLIC_TL_PREFIX + bytes(range(32))


def published_config() -> dict:
    return {
        "@type": "config.global",
        "dht": {"@type": "dht.config.global", "k": 6, "a": 3},
        "liteservers": [{"ip": 1, "port": 1, "id": {"@type": "pub.ed25519", "key": "AA=="}}],
        "liteservers_v2": [],
        "validator": {
            "@type": "validator.config.global",
            "zero_state": {"workchain": -1, "root_hash": lib.b64(b"\x01" * 32)},
        },
    }


def test_rpc_trusts_only_the_local_lite_server(tmp_path):
    config = operator.rpc_liteserver_config(published_config(), liteserver_pub(), 30003)
    assert config["liteservers"] == [
        {
            "ip": lib.ip_to_tl("127.0.0.1"),
            "port": 30003,
            "id": {"@type": "pub.ed25519", "key": lib.b64(bytes(range(32)))},
        }
    ]
    assert config["liteservers"][0]["ip"] == 2130706433
    assert "liteservers_v2" not in config
    # The network identity is the published one.
    assert config["validator"] == published_config()["validator"]
    assert config["dht"] == published_config()["dht"]


def test_rpc_config_writes_a_new_file_through_the_cli(tmp_path):
    (tmp_path / "global.json").write_text(json.dumps(published_config()))
    (tmp_path / "liteserver.pub").write_bytes(liteserver_pub())
    args = [
        "rpc-config",
        "--global-config",
        str(tmp_path / "global.json"),
        "--liteserver-pub",
        str(tmp_path / "liteserver.pub"),
        "--port",
        "30003",
        "--out",
        str(tmp_path / "out.json"),
    ]
    assert operator.main(args) == 0
    written = json.loads((tmp_path / "out.json").read_text())
    assert written["liteservers"][0]["port"] == 30003
    assert (tmp_path / "out.json").stat().st_mode & 0o777 == 0o644
    # Never overwritten.
    assert operator.main(args) == 1


def test_rpc_config_refuses_the_placeholder_config():
    profile = lib.load_profile()
    with pytest.raises(lib.TestnetError, match="placeholder"):
        operator.rpc_liteserver_config(lib.pregenesis_config(profile), liteserver_pub(), 30003)


@pytest.mark.parametrize(
    "key",
    [bytes(range(32)), b"\x00\x00\x00\x00" + bytes(32), liteserver_pub() + b"x"],
)
def test_rpc_config_refuses_a_key_that_is_not_an_ed25519_public_key(key):
    with pytest.raises(lib.TestnetError, match="not a generate-random-id Ed25519 public key"):
        operator.rpc_liteserver_config(published_config(), key, 30003)


@pytest.mark.parametrize("port", [0, 65536])
def test_rpc_config_refuses_a_port_out_of_range(port):
    with pytest.raises(lib.TestnetError, match="out of range"):
        operator.rpc_liteserver_config(published_config(), liteserver_pub(), port)


# ---------------------------------------------------------------- retirement


def test_retirement_stops_the_rpc_services_before_the_full_node_and_drops_the_index():
    text = (SCRIPTS / "retire-host.sh").read_text()
    units = re.search(r"(?ms)^UNITS=\(([^)]*)\)", text).group(1).split()
    for unit in ("tos-testnet-rpc", "tos-testnet-wallet-index"):
        assert units.index(unit) < units.index("tos-testnet-fullnode"), unit
    # An index of the retired chain refuses the next chain's anchor; tos-rpc's
    # liteserver file names the retired network.
    removed = re.findall(r"(?m)^rm -(?:rf --one-file-system|f) (.*)$", text)
    words = " ".join(removed).split()
    assert "/var/lib/tos-wallet-index" in words
    assert "/etc/tos/rpc-liteservers.json" in words
    assert "/etc/tos/tos-rpc.env" not in words
