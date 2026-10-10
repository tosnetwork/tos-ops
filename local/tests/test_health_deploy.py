"""health-deploy.py: generation, preservation, refusals and the activation switch."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location("health_deploy", SCRIPTS / "health-deploy.py")
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)
pki = deploy.pki
NETWORK = "ab" * 32
OTHER = "cd" * 32
ALIASES = [alias for alias, _, _ in deploy.NODES]


class FakeSystem:
    """Seven running nodes, systemd that always obliges, and a stack that is healthy unless told otherwise."""

    def __init__(self, data: Path, network: str = NETWORK):
        self.data = data
        self.network = network
        self.properties = {
            deploy.node_unit(kind, index): {
                "ActiveState": "active",
                "MainPID": str(1000 + index),
                "ExecStart": (
                    f"{{ path=/usr/local/bin/tos-validator-engine ; argv[]=/usr/local/bin/tos-validator-engine "
                    f"-C {data}/tos-global.json -c {data}/testnet/node{index}/config.json "
                    f"--exporter-address {deploy.native_address(index)} --health-node-id {alias} "
                    f"--health-core-metrics --health-native-core-v3 ; ignore_errors=no }}"
                ),
            }
            for alias, index, kind in deploy.NODES
        }
        self.root_units: dict[str, bytes] = {}
        self.restarts = 0
        self.healthy = True
        self.clock = 1_000_000.0

    def unit_properties(self, unit):
        return self.properties[unit]

    def install_root_units(self, units):
        self.root_units = dict(units)

    def reload_user_units(self, units):
        self.user_units = list(units)

    def restart(self, root_units, user_units):
        self.restarts += 1

    def active(self, unit, root):
        return True

    def edge_snapshot(self, state, index):
        if self.rate_limited > 0:
            self.rate_limited -= 1
            return None
        if self.cold > 0:
            self.cold -= 1
            raise pki.Unhealthy(f"edge {index} snapshot answered 503")
        alias = ALIASES[index - 1]
        process = {"source_id": "process", "node_id": alias, "payload": {}}
        if self.native_missing:
            return {"sources": [process]}
        return {"sources": [process, {"source_id": "native_core", "node_id": alias, "payload": {"network_id": self.network}}]}

    native_missing = False
    rate_limited = 0
    cold = 0

    def observe(self, state):
        status = "partial" if self.healthy else "error"
        cache = {"status": "error", "error": {"code": "CACHE_MISS"}, "data": None}
        return [
            {"node": alias, "results": {**{s: {"status": status} for s in pki.CORE_SCOPES}, "host": cache}}
            for alias in ALIASES
        ]

    def sleep(self, seconds):
        self.clock += seconds

    def now(self):
        return self.clock

    def checkpoint(self, point):
        if point == self.kill_at:
            self.kill_at = None
            raise Killed(point)

    kill_at = None


class Killed(Exception):
    """The deployment process died here."""


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    write_network(data, NETWORK)
    tos = tmp_path / "tos"
    release = tos / "tools/node-health-monitor/target/release"
    release.mkdir(parents=True)
    for name in deploy.BINARIES:
        (release / name).write_bytes(f"binary {name}\n".encode())
    root = tmp_path / "health"
    units = tmp_path / "user-units"
    return {"data": data, "tos": tos, "root": root, "units": units, "system": FakeSystem(data)}


def write_network(data: Path, network: str, configured: str | None = None) -> None:
    (data / "network.json").write_text(json.dumps({"zerostate_root": network}))
    root_hash = base64.b64encode(bytes.fromhex(configured or network)).decode()
    (data / "tos-global.json").write_text(json.dumps({"validator": {"zero_state": {"root_hash": root_hash}}}))


def configure(env, *extra) -> int:
    args = ["configure", "--tos-root", str(env["tos"]), "--data", str(env["data"]), *extra]
    deployer = deploy.Deploy
    original = deployer.__init__

    def init(self, root, tos_root, data, system, user_unit_dir=env["units"]):
        original(self, root, tos_root, data, system, user_unit_dir)

    deployer.__init__ = init
    try:
        return deploy.main(args, system=env["system"], root=env["root"])
    finally:
        deployer.__init__ = original


def state_of(env) -> Path:
    return env["root"] / NETWORK[:12]


# --- the happy path -----------------------------------------------------------


def test_first_start_generates_a_complete_bound_stack(env):
    assert configure(env, "--start") == deploy.EXIT_OK
    state = state_of(env)
    assert (env["root"] / "active").read_text().strip() == state.name
    assert not (env["root"] / "activation-pending").exists()
    assert json.loads((state / "deploy.json").read_text()) == {"network": NETWORK, "tos_root": str(env["tos"].resolve())}
    pins = {alias: pki.sha256(pki.first_cert_der((state / "pki" / name).read_bytes())) for alias, name in pki.IDENTITIES.items()}
    for name in pki.INGRESS_CONFIGS:
        peers = json.loads((state / "config" / name).read_text())["peers"]
        assert {p["alias"]: p["certificate_sha256"] for p in peers} == pins
    ingress = json.loads((state / "config/manager-ingress.json").read_text())
    assert (ingress["rate_per_second"], ingress["burst"]) == (deploy.MANAGER_RATE, deploy.MANAGER_BURST)
    witness = json.loads((state / "config/witness-compare.json").read_text())
    assert witness["observers"] == ["observer5", "observer6"] and len(witness["validators"]) == 5
    manager = json.loads((state / "config/manager.json").read_text())
    assert manager["inventory"]["network_id"] == NETWORK
    assert {t["node"] for t in manager["inventory"]["targets"]} == set(ALIASES) | {"monitor"}
    for path in (state / "config").glob("*.json"):
        assert "@" not in path.read_text().replace("@health", "")
    assert sorted(env["system"].root_units) == [f"tos-local-health-edge-{i}.service" for i in range(1, 8)]
    edge = env["system"].root_units["tos-local-health-edge-5.service"].decode()
    assert "tos-pq-observer@5.service -p MainPID" in edge and f" {NETWORK}'" in edge and "127.0.0.1:9015" in edge
    assert (state / "bin/health-witness-compare").read_bytes() == b"binary health-witness-compare\n"
    for name in deploy.TOKENS:
        assert re.fullmatch(r"[0-9a-f]{64}", (state / "config" / f"{name}.token").read_text())
        assert (state / "config" / f"{name}.token").stat().st_mode & 0o777 == 0o600
    assert not list(state.glob("pki-issue-*")), "the scratch directory with the CA key must be gone"


def test_the_generated_unit_set_is_what_pki_rotation_expects(env):
    assert configure(env, "--start") == deploy.EXIT_OK
    state = state_of(env)
    present = sorted(p.name for p in env["units"].glob("*.service")) + list(pki.PKI_UNITS)
    ingress, clients = pki.stack_units(state, present)
    assert "tos-local-health-witness-compare.service" in clients
    # Red control: a stack without its witness unit is refused by the rotation.
    present.remove("tos-local-health-witness-compare.service")
    with pytest.raises(pki.Refusal, match="witness-compare"):
        pki.stack_units(state, present)


def test_repeating_configure_keeps_tokens_pki_and_databases(env):
    assert configure(env, "--start") == deploy.EXIT_OK
    state = state_of(env)
    (state / "evidence/evidence.db").write_bytes(b"evidence")
    (state / "control/control.db").write_bytes(b"control")
    kept = [*(state / "pki").iterdir(), *(state / "config").glob("*.token"), state / "evidence/evidence.db", state / "control/control.db"]
    before = {p: (p.read_bytes(), p.stat().st_ino) for p in kept}
    assert configure(env) == deploy.EXIT_OK
    assert configure(env, "--start") == deploy.EXIT_OK
    assert {p: (p.read_bytes(), p.stat().st_ino) for p in kept} == before


# --- refusals change nothing --------------------------------------------------


def refused_cleanly(env, *extra) -> None:
    assert configure(env, *extra) == deploy.EXIT_REFUSED
    assert not state_of(env).exists()
    assert env["system"].restarts == 0


def test_a_global_config_on_another_zero_state_is_refused(env):
    write_network(env["data"], NETWORK, configured=OTHER)
    refused_cleanly(env, "--start")


@pytest.mark.parametrize(
    "change",
    [
        {"ActiveState": "failed"},
        {"MainPID": "0"},
        {"ExecStart": "argv[]=/usr/local/bin/tos-validator-engine -C /elsewhere/tos-global.json"},
    ],
)
def test_a_node_that_does_not_run_as_expected_is_refused(env, change):
    env["system"].properties["tos-pq-observer@6.service"].update(change)
    refused_cleanly(env, "--start")


def test_a_node_running_under_another_alias_is_refused(env):
    unit = env["system"].properties["tos-pq-validator@2.service"]
    unit["ExecStart"] = unit["ExecStart"].replace("--health-node-id validator2", "--health-node-id validator3")
    refused_cleanly(env, "--start")


def test_missing_binaries_are_refused(env):
    (env["tos"] / "tools/node-health-monitor/target/release/health-witness-compare").unlink()
    refused_cleanly(env, "--start")


def test_a_state_directory_of_another_full_network_is_refused(env):
    state = state_of(env)
    state.mkdir(parents=True)
    (state / "network").write_text(NETWORK[:12] + "0" * 52 + "\n")
    assert configure(env, "--start") == deploy.EXIT_REFUSED
    assert env["system"].restarts == 0


def test_a_partial_pki_is_refused_not_overwritten(env):
    state = state_of(env)
    (state / "pki").mkdir(parents=True)
    (state / "pki/ca.pem").write_bytes(b"old ca")
    assert configure(env, "--start") == deploy.EXIT_REFUSED
    assert (state / "pki/ca.pem").read_bytes() == b"old ca"
    assert sorted(p.name for p in (state / "pki").iterdir()) == ["ca.pem"]


def test_an_unresolved_rotation_is_refused(env):
    state = state_of(env)
    state.mkdir(parents=True)
    (state / pki.JOURNAL).write_text("{}")
    assert configure(env, "--start") == deploy.EXIT_REFUSED
    assert not (state / "config").exists()


def test_a_held_root_lock_is_refused(env):
    import fcntl

    env["root"].mkdir(parents=True)
    with open(env["root"] / "deploy.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        refused_cleanly(env, "--start")


def test_a_foreign_path_in_generated_output_is_refused(tmp_path):
    state = tmp_path / "state"
    deploy.check_generated(state, {"ok.json": f'{{"a": "{state}/config/x", "u": "https://localhost:1/v1/x"}}'.encode()})
    with pytest.raises(pki.Refusal, match="outside the state directory"):
        deploy.check_generated(state, {"bad.json": f'{{"a": "{Path.home()}/elsewhere/x"}}'.encode()})
    with pytest.raises(pki.Refusal, match="placeholder"):
        deploy.check_generated(state, {"bad.json": b'{"n": "@NETWORK@"}'})


# --- switching the active stack -----------------------------------------------


def test_switching_networks_needs_start(env):
    assert configure(env, "--start") == deploy.EXIT_OK
    write_network(env["data"], OTHER)
    env["system"] = FakeSystem(env["data"], OTHER)
    assert configure(env) == deploy.EXIT_REFUSED
    assert (env["root"] / "active").read_text().strip() == NETWORK[:12]
    assert not (env["root"] / OTHER[:12]).exists()


def test_a_failed_switch_keeps_the_pointer_and_stops_rotation(env):
    assert configure(env, "--start") == deploy.EXIT_OK
    write_network(env["data"], OTHER)
    env["system"] = FakeSystem(env["data"], OTHER)
    env["system"].healthy = False
    assert configure(env, "--start") == deploy.EXIT_UNVERIFIED
    assert (env["root"] / "active").read_text().strip() == NETWORK[:12]
    assert (env["root"] / "activation-pending").exists()

    def no_stack(state):
        raise AssertionError("the rotation must refuse before it touches any stack")

    assert pki.main(["rotate"], stack_factory=no_stack, root=env["root"]) == pki.EXIT_REFUSED
    # Fixing the cause and running again finishes the switch.
    env["system"].healthy = True
    assert configure(env, "--start") == deploy.EXIT_OK
    assert (env["root"] / "active").read_text().strip() == OTHER[:12]
    assert not (env["root"] / "activation-pending").exists()


def test_a_switch_killed_between_publishing_and_clearing_the_marker_is_finished_by_a_retry(env):
    assert configure(env, "--start") == deploy.EXIT_OK
    write_network(env["data"], OTHER)
    env["system"] = FakeSystem(env["data"], OTHER)
    env["system"].kill_at = "published"
    with pytest.raises(Killed):
        configure(env, "--start")
    assert (env["root"] / "active").read_text().strip() == OTHER[:12]
    assert (env["root"] / "activation-pending").exists()
    assert pki.main(["rotate"], stack_factory=lambda s: (_ for _ in ()).throw(AssertionError(s)), root=env["root"]) == pki.EXIT_REFUSED
    # Configuring without --start must not leave the switch unverified for good.
    assert configure(env) == deploy.EXIT_REFUSED
    assert configure(env, "--start") == deploy.EXIT_OK
    assert not (env["root"] / "activation-pending").exists()


def test_root_units_are_replaced_atomically(tmp_path, monkeypatch):
    directory = tmp_path / "units"
    directory.mkdir()
    names = [f"tos-local-health-edge-{i}.service" for i in (1, 2)]
    for name in names:
        (directory / name).write_bytes(b"old\n")
    with pytest.raises(pki.Refusal, match="unexpected unit names"):
        deploy.install_atomically(directory, {names[0]: b"new\n", "sshd.service": b"x"})
    assert all((directory / name).read_bytes() == b"old\n" for name in names)
    real_replace, calls = os.replace, []

    def dying_replace(source, destination):
        calls.append(destination)
        if len(calls) == 2:
            raise OSError("killed before the rename")
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", dying_replace)
    with pytest.raises(OSError):
        deploy.install_atomically(directory, {name: b"new\n" for name in names})
    assert [(directory / name).read_bytes() for name in names] == [b"new\n", b"old\n"]
    assert sorted(p.name for p in directory.iterdir()) == names, "no temporary file may be left behind"


def test_a_node_reporting_another_network_fails_verification(env):
    env["system"].network = OTHER
    assert configure(env, "--start") == deploy.EXIT_UNVERIFIED
    assert not (env["root"] / "active").exists()


def test_a_rate_limited_edge_read_is_asked_again(env):
    env["system"].rate_limited = 3
    assert configure(env, "--start") == deploy.EXIT_OK
    env["system"].rate_limited = 10**6
    assert configure(env, "--start") == deploy.EXIT_UNVERIFIED


def test_a_cold_edge_is_waited_for_but_not_forever(env):
    env["system"].cold = 4
    assert configure(env, "--start") == deploy.EXIT_OK
    env["system"].cold = 10**6
    assert configure(env, "--start") == deploy.EXIT_UNVERIFIED


def test_an_edge_without_a_native_sample_fails_verification(env):
    env["system"].native_missing = True
    assert configure(env, "--start") == deploy.EXIT_UNVERIFIED
    assert not (env["root"] / "active").exists()


# --- the PKI rotation finds the active directory ------------------------------


def test_rotation_state_discovery_with_two_retained_networks(tmp_path):
    for name in ("aaaaaaaaaaaa", "bbbbbbbbbbbb"):
        (tmp_path / name).mkdir()
    with pytest.raises(pki.Refusal, match="found 2"):
        pki.state_dir(None, tmp_path)
    (tmp_path / "active").write_text("bbbbbbbbbbbb\n")
    assert pki.state_dir(None, tmp_path) == tmp_path / "bbbbbbbbbbbb"
    for bad in ("cccccccccccc", "../x", ""):
        (tmp_path / "active").write_text(bad)
        with pytest.raises(pki.Refusal):
            pki.state_dir(None, tmp_path)


# --- observation without an environment -----------------------------------------

FAKE_CLIENT = '''
import json
def private_token(path):
    return open(path).read().strip()
def issue(control, operator, node, start, end, leases):
    leases.append("run-" + node)
    return "run-" + node, "grant"
def revoke(control, operator, run):
    return True
class McpSession:
    def __init__(self, *args): pass
    def initialize(self): pass
    def call(self, method, params): return {"tools": [{"name": "tos_get_node_snapshot"}]}
    def snapshot(self, run, node, as_of, component): return {"status": "partial"}
    def close(self): pass
'''


def test_observation_finds_the_recorded_checkout_without_tos_root(tmp_path, monkeypatch):
    tos = tmp_path / "tos"
    client = tos / "tools/node-health-monitor/scripts/sample-query-functional.py"
    client.parent.mkdir(parents=True)
    client.write_text(FAKE_CLIENT)
    state = tmp_path / "state"
    (state / "config").mkdir(parents=True)
    for name in ("query-operator", "query-service"):
        (state / "config" / f"{name}.token").write_text("t\n")
    (state / "deploy.json").write_text(json.dumps({"network": NETWORK, "tos_root": str(tos)}))
    # As systemd starts the PKI service: no TOS_ROOT in the environment.
    monkeypatch.delenv("TOS_ROOT", raising=False)
    rows = pki.Stack(state).observe()
    assert [row["node"] for row in rows] == ALIASES
    assert set(rows[0]["results"]) == {"process", "consensus", "storage", "chain", "host"}
    # Control: without the record there is no checkout to use, and the observation fails.
    (state / "deploy.json").unlink()
    with pytest.raises(pki.Unhealthy, match="names no checkout"):
        pki.Stack(state).observe()


# --- tracked files ------------------------------------------------------------


def test_tracked_files_name_no_home_directory():
    local = SCRIPTS.parent
    tracked = [
        *SCRIPTS.glob("health-*.py"),
        *(local / "health").glob("*"),
        *(local / "systemd/user").glob("tos-local-health-*"),
        *Path(__file__).parent.glob("test_health_*.py"),
    ]
    assert len(tracked) >= 7
    for path in tracked:
        text = path.read_text()
        assert str(Path.home()) not in text, path
        assert not re.search(r"/home/[a-z]", text), path
