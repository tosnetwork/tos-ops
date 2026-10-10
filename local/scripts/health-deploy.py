#!/usr/bin/env python3
"""Configure and start the local health-monitoring stack for the running local PQ network.

    health-deploy.py configure [--start] [--tos-root D] [--data D]

The stack watches the seven nodes that setup-testnet.sh creates: per node a root
edge (process, cgroup and native samples), an edge ingress, a collector, a native
poll and a probe; one manager with its ingress, a witness comparer and the query
service. Everything lives in ~/.local/state/tos-local-health/<network[:12]>; the
binaries come from a built checkout ($TOS_ROOT, tools/node-health-monitor).

configure is safe to repeat. It keeps existing tokens, the PKI and the databases,
issues a PKI only when none exists, and regenerates every config and unit from
this script and local/health/manager-inventory.json. Certificate pins are
computed from the live PKI. Every generated file is validated before the first
one is written, and each is replaced atomically.

The only network it will configure is the one the chain runs: network.json, the
global config and all seven node units must agree. Switching the active stack to
a new network (after a chain reset) requires --start: the units are retargeted
under an activation-pending marker that stops PKI rotation, the stack is
restarted and verified, and only then is it published as active. A failed
verification leaves the marker and the old pointer in place; fix the cause and
run again. A previous network's directory is kept but never restored: after a
reset there is nothing left for it to observe.

Exit status: 0 done, 1 the stack did not verify, 2 refused (nothing changed).
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
TEMPLATE = SCRIPTS.parent / "health" / "manager-inventory.json"
_spec = importlib.util.spec_from_file_location("health_pki", SCRIPTS / "health-pki.py")
pki = sys.modules.setdefault("health_pki", importlib.util.module_from_spec(_spec))
if not hasattr(pki, "Refusal"):
    _spec.loader.exec_module(pki)
Refusal, Unhealthy = pki.Refusal, pki.Unhealthy

EXIT_OK, EXIT_UNVERIFIED, EXIT_REFUSED = 0, 1, 2
# (alias, node index, node unit kind): the layout setup-testnet.sh creates.
NODES = (
    ("validator1", 1, "validator"),
    ("validator2", 2, "validator"),
    ("validator3", 3, "validator"),
    ("validator4", 4, "validator"),
    ("observer5", 5, "observer"),
    ("observer6", 6, "observer"),
    ("validator7", 7, "validator"),
)
BINARIES = (
    "health-edge",
    "health-ingress",
    "health-state",
    "health-collector",
    "health-native-poll",
    "health-probe",
    "health-witness-compare",
    "tos-observability",
)
DIRECTORIES = ("config", "control", "evidence", "query", "sockets", "bin", "pki", "observe")
TOKENS = ("manager-ingest", "manager-read", "query-operator", "query-ingest", "query-service") + tuple(
    f"edge-{index}" for _, index, _ in NODES
)
MANAGER = "127.0.0.1:19490"
MANAGER_TLS = 19590
QUERY = "127.0.0.1:19690"
# The manager ingress admits every frame the stack posts with the probe identity:
# per 15 s tick about 7 probe, 7 collector, 7 witness and 70 native-poll frames,
# sent together. 32/s with a burst of 128 absorbs a whole tick with room to spare.
MANAGER_RATE, MANAGER_BURST = 32, 128
# Concurrent non-heartbeat requests the manager ingress serves (the node default
# is 7). Its 22 clients, 7 probes, 7 native polls, 7 collectors and the witness
# comparer, each hold one request at a time.
MANAGER_REGULAR_REQUESTS = 32
# The manager refuses every write once evidence.db reaches its quota, and its
# retention pass needs to write to free space, so a full database stays full.
# With every source delivered, six hours of evidence is about 250 MB on disk;
# 1 GiB keeps the six-hour window at a quarter of the quota.
EVIDENCE_QUOTA_BYTES = 1 << 30
WITNESS_LAG_BLOCKS = 150
USER_UNIT_DIR = Path.home() / ".config/systemd/user"
ROOT_UNIT_DIR = Path("/etc/systemd/system")
UNIT_PREFIX = "tos-local-health-"
ACTIVE, PENDING, ROOT_LOCK = pki.ACTIVE, pki.PENDING, pki.ROOT_LOCK
RECORD = "deploy.json"


def log(message: str) -> None:
    print(f"health-deploy: {message}", flush=True)


def edge_port(index: int) -> int:
    return 19480 + index


def edge_tls_port(index: int) -> int:
    return 19580 + index


def native_address(index: int) -> str:
    return f"127.0.0.1:{9010 + index}"


def node_unit(kind: str, index: int) -> str:
    return f"tos-pq-{kind}@{index}.service"


# --- the environment ----------------------------------------------------------


class System:
    """systemd, sudo and the network. Tests replace this with a stand-in."""

    def unit_properties(self, unit: str) -> dict[str, str]:
        result = pki.run(["systemctl", "show", unit, "-p", "ActiveState", "-p", "MainPID", "-p", "ExecStart"], timeout=30)
        if result.returncode != 0:
            raise Refusal(f"cannot read {unit}")
        return dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)

    def install_root_units(self, units: dict[str, bytes]) -> None:
        # One root process replaces every unit atomically (see install_atomically).
        payload = json.dumps({name: body.decode() for name, body in units.items()}).encode()
        command = ["sudo", sys.executable, "-I", str(Path(__file__).resolve()), "install-root-units"]
        result = pki.run(command, timeout=60, input_bytes=payload)
        if result.returncode != 0:
            raise Refusal(f"cannot install the root units: {result.stdout.decode(errors='replace').strip()[-300:]}")
        for command in (["daemon-reload"], ["enable", *units]):
            if pki.run(["sudo", "systemctl", *command], timeout=120).returncode != 0:
                raise Refusal(f"systemctl {command[0]} failed for the root units")

    def reload_user_units(self, units: list[str]) -> None:
        for command in (["daemon-reload"], ["enable", *units]):
            if pki.run(["systemctl", "--user", *command], timeout=120).returncode != 0:
                raise Refusal(f"systemctl --user {command[0]} failed")

    def restart(self, root_units: list[str], user_units: list[str]) -> None:
        if pki.run(["sudo", "systemctl", "restart", *root_units], timeout=180).returncode != 0:
            raise Unhealthy("restarting the edges failed")
        if pki.run(["systemctl", "--user", "restart", *user_units], timeout=180).returncode != 0:
            raise Unhealthy("restarting the user units failed")

    def active(self, unit: str, root: bool) -> bool:
        command = ["systemctl", "is-active", unit] if root else ["systemctl", "--user", "is-active", unit]
        return pki.run(command, timeout=30).stdout.decode().strip() == "active"

    def edge_snapshot(self, state: Path, index: int) -> dict | None:
        """The edge's snapshot as the collector reads it, through its TLS ingress.

        None when the ingress rate-limits the read (429): the reader identity
        shares the node ingress's small budget with the collector and native
        poll, so the caller waits and asks again.
        """
        context = ssl.create_default_context(cafile=str(state / "pki" / "ca.pem"))
        context.load_cert_chain(str(state / "pki" / "reader-identity.pem"))
        token = (state / "config" / f"edge-{index}.token").read_text().strip()
        connection = http.client.HTTPSConnection("localhost", edge_tls_port(index), context=context, timeout=15)
        try:
            connection.request("GET", "/v1/edge/snapshot", headers={"Authorization": f"Bearer {token}"})
            response = connection.getresponse()
            body = response.read(262_144)
            if response.status == 429:
                return None
            if response.status != 200:
                raise Unhealthy(f"edge {index} snapshot answered {response.status}")
            return json.loads(body)
        except (OSError, http.client.HTTPException, ValueError) as error:
            raise Unhealthy(f"edge {index} snapshot failed: {error}") from None
        finally:
            connection.close()

    def observe(self, state: Path) -> list[dict]:
        return pki.Stack(state).observe()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def now(self) -> float:
        return time.time()

    def checkpoint(self, point: str) -> None:
        """Tests interrupt the deployment here."""


UNIT_NAME = re.compile(r"tos-local-health-[a-z0-9-]+\.service")


def install_atomically(directory: Path, units: dict[str, bytes]) -> None:
    """Replace each unit in directory atomically, so a unit file is always either its old or its new content.

    Every name is checked before anything is written; each file is written to a
    temporary file in the same directory, fsync'd, renamed over the destination,
    and the directory is fsync'd (pki.durable_write).
    """
    bad = [name for name in units if not UNIT_NAME.fullmatch(name)]
    if bad:
        raise Refusal(f"refusing to install unexpected unit names {bad}")
    for name, body in units.items():
        pki.durable_write(directory / name, body, 0o644)


# --- what the chain runs ------------------------------------------------------


def network_of(data: Path) -> str:
    try:
        network = json.loads((data / "network.json").read_text())["zerostate_root"]
        zero_state = json.loads((data / "tos-global.json").read_text())["validator"]["zero_state"]
        configured = base64.b64decode(zero_state["root_hash"], validate=True).hex()
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise Refusal(f"cannot read the network identity under {data}: {error}") from None
    if not isinstance(network, str) or not re.fullmatch(r"[0-9a-f]{64}", network):
        raise Refusal("network.json has no valid zerostate_root")
    if configured != network:
        raise Refusal(f"tos-global.json runs zero state {configured[:12]}…, network.json names {network[:12]}…")
    return network


def check_nodes(system: System, data: Path) -> None:
    """Each of the seven nodes runs, from the global config, as the alias the monitor expects."""
    for alias, index, kind in NODES:
        unit = node_unit(kind, index)
        properties = system.unit_properties(unit)
        command = properties.get("ExecStart", "")
        wanted = (f"-C {data}/tos-global.json", f"--health-node-id {alias} ", f"--exporter-address {native_address(index)} ")
        if properties.get("ActiveState") != "active" or properties.get("MainPID", "0") in ("", "0"):
            raise Refusal(f"{unit} is not running")
        missing = [option for option in wanted if option not in command + " "]
        if missing:
            raise Refusal(f"{unit} does not run with {missing}")


# --- generation ---------------------------------------------------------------


def pins_of(state: Path) -> dict[str, str]:
    return {
        alias: pki.sha256(pki.first_cert_der((state / "pki" / name).read_bytes()))
        for alias, name in pki.IDENTITIES.items()
    }


def ingress(state: Path, listen: str, upstream: str, pins: dict[str, str], roles: tuple[str, str]) -> dict:
    return {
        "listen": listen,
        "server_name": "localhost",
        "upstream": upstream,
        "cert_file": str(state / "pki/server.pem"),
        "key_file": str(state / "pki/server.key"),
        "ca_file": str(state / "pki/ca.pem"),
        "peers": [
            {"alias": "local_probe", "certificate_sha256": pins["local_probe"], "role": roles[0]},
            {"alias": "local_reader", "certificate_sha256": pins["local_reader"], "role": roles[1]},
        ],
    }


def configs(state: Path, network: str, pins: dict[str, str]) -> dict[str, dict]:
    pki_dir, config = state / "pki", state / "config"
    manager_url = f"https://localhost:{MANAGER_TLS}"
    ingest = str(config / "manager-ingest.token")
    out: dict[str, dict] = {}
    for alias, index, _ in NODES:
        edge_url = f"https://localhost:{edge_tls_port(index)}"
        edge_token = str(config / f"edge-{index}.token")
        out[f"edge-ingress-{index}.json"] = ingress(
            state, f"127.0.0.1:{edge_tls_port(index)}", f"127.0.0.1:{edge_port(index)}", pins,
            ("edge_watchdog", "edge_reader"),
        )
        out[f"collector-{alias}.json"] = {
            "node_id": alias,
            "network_id": network,
            "edge_url": f"{edge_url}/v1/edge/snapshot",
            "ingest_url": f"{manager_url}/v1/manager/snapshot-evidence",
            "ca_file": str(pki_dir / "ca.pem"),
            "identity_file": str(pki_dir / "reader-identity.pem"),
            "ingest_identity_file": str(pki_dir / "probe-identity.pem"),
            "edge_token_file": edge_token,
            "ingest_token_file": ingest,
            "witness": None,
        }
        out[f"native-poll-{index}.json"] = {
            "network_id": network,
            "node_id": alias,
            "scope_id": "node",
            "edge_url": f"{edge_url}/v1/edge/snapshot",
            "manager_url": f"{manager_url}/v1/manager/facts",
            "ca_file": str(pki_dir / "ca.pem"),
            "identity_file": str(pki_dir / "reader-identity.pem"),
            "edge_token_file": edge_token,
            "manager_token_file": ingest,
            "manager_identity_file": str(pki_dir / "probe-identity.pem"),
        }
        out[f"probe-{index}.json"] = {
            "network_id": network,
            "node_id": alias,
            "scope_id": "node",
            "edge_url": f"{edge_url}/v1/edge/heartbeat",
            "manager_url": f"{manager_url}/v1/manager/facts",
            "ca_file": str(pki_dir / "ca.pem"),
            "identity_file": str(pki_dir / "probe-identity.pem"),
            "edge_token_file": edge_token,
            "manager_token_file": ingest,
        }
    out["manager-ingress.json"] = {
        **ingress(state, f"127.0.0.1:{MANAGER_TLS}", MANAGER, pins, ("manager_ingest", "manager_reader")),
        "rate_per_second": MANAGER_RATE,
        "burst": MANAGER_BURST,
        "regular_request_limit": MANAGER_REGULAR_REQUESTS,
    }
    try:
        inventory = json.loads(
            TEMPLATE.read_text().replace("@NETWORK@", network).replace("@REVISION@", f"local-elector-{network[:12]}")
        )
    except (OSError, ValueError) as error:
        raise Refusal(f"cannot read {TEMPLATE}: {error}") from None
    out["manager.json"] = {
        "control_db": str(state / "control/control.db"),
        "evidence_db": str(state / "evidence/evidence.db"),
        "control_quota_bytes": "67108864",
        "evidence_quota_bytes": str(EVIDENCE_QUOTA_BYTES),
        "listen": MANAGER,
        "ingest_token_file": ingest,
        "read_token_file": str(config / "manager-read.token"),
        "receiver": None,
        "evidence_retention_ms": "21600000",
        "witness_retention_ms": "604800000",
        "inventory": inventory,
    }
    nodes = [alias for alias, _, _ in NODES]
    out["query-inventory.json"] = {"network_id": network, "nodes": nodes, "scopes": ["node"]}
    out["witness-compare.json"] = {
        "network_id": network,
        "evidence_db": str(state / "evidence/evidence.db"),
        "manager_url": f"{manager_url}/v1/manager/facts",
        "ca_file": str(pki_dir / "ca.pem"),
        "identity_file": str(pki_dir / "probe-identity.pem"),
        "manager_token_file": ingest,
        "validators": [alias for alias, _, kind in NODES if kind == "validator"],
        "observers": [alias for alias, _, kind in NODES if kind == "observer"],
        "lag_blocks": WITNESS_LAG_BLOCKS,
    }
    return out


def user_unit(name: str, args: list[str]) -> bytes:
    return (
        f"[Unit]\nDescription=Local development health {name}\n[Service]\nType=simple\nUMask=0077\n"
        "NoNewPrivileges=yes\nCPUQuota=50%\nMemoryMax=512M\nMemorySwapMax=0\nTasksMax=64\nRestart=on-failure\n"
        f"RestartSec=15\nExecStart={' '.join(args)}\n[Install]\nWantedBy=default.target\n"
    ).encode()


def user_units(state: Path) -> dict[str, bytes]:
    bin_dir, config = state / "bin", state / "config"
    units = {
        "manager": [bin_dir / "health-state", config / "manager.json"],
        "manager-ingress": [bin_dir / "health-ingress", config / "manager-ingress.json"],
        "witness-compare": [bin_dir / "health-witness-compare", config / "witness-compare.json"],
        "query": [
            bin_dir / "tos-observability", config / "query-inventory.json", QUERY,
            config / "query-operator.token", config / "query-ingest.token", config / "query-service.token",
            state / "query/ledger.db", state / "sockets/control.sock", "-", state / "evidence/evidence.db",
            state / "sockets/mcp.sock", state / "control/control.db",
        ],
    }
    for alias, index, _ in NODES:
        units[f"edge-ingress-{index}"] = [bin_dir / "health-ingress", config / f"edge-ingress-{index}.json"]
        units[f"collector-{index}"] = [bin_dir / "health-collector", config / f"collector-{alias}.json"]
        units[f"native-poll-{index}"] = [bin_dir / "health-native-poll", config / f"native-poll-{index}.json"]
        units[f"probe-{index}"] = [bin_dir / "health-probe", config / f"probe-{index}.json"]
    return {
        f"{UNIT_PREFIX}{name}.service": user_unit(f"{UNIT_PREFIX}{name}", [str(arg) for arg in args])
        for name, args in units.items()
    }


def root_units(state: Path, network: str) -> dict[str, bytes]:
    units = {}
    for alias, index, kind in NODES:
        node = node_unit(kind, index)
        command = (
            f"exec {state}/bin/health-edge {alias} \"$(systemctl show {node} -p MainPID --value)\" "
            f"127.0.0.1:{edge_port(index)} {state}/config/edge-{index}.token {native_address(index)} {network}"
        )
        units[f"{UNIT_PREFIX}edge-{index}.service"] = (
            f"[Unit]\nDescription=Local development health edge {index}\nAfter={node}\nBindsTo={node}\n"
            f"PartOf={node}\n[Service]\nExecStart=/bin/sh -c '{command}'\nRestart=on-failure\nRestartSec=15\n"
            "UMask=0077\nCPUQuota=25%\nMemoryMax=256M\nMemorySwapMax=0\nTasksMax=32\nNoNewPrivileges=yes\n"
            "[Install]\nWantedBy=multi-user.target\n"
        ).encode()
    return units


ALLOWED_SYSTEM_PATHS = ("/bin/sh", "/data/", "/usr/")


def check_generated(state: Path, files: dict[str, bytes]) -> None:
    """No placeholder left, and every absolute path is under the state directory or a fixed system root."""
    for name, data in files.items():
        text = data.decode()
        if "@NETWORK@" in text or "@REVISION@" in text:
            raise Refusal(f"{name} keeps a template placeholder")
        for path in re.findall(r"(?<![\w:/.])(/[A-Za-z0-9_./@-]+)", text):
            if path.startswith(f"{state}/") or path.startswith(ALLOWED_SYSTEM_PATHS) or path.startswith("/v1/"):
                continue
            raise Refusal(f"{name} references {path}, outside the state directory")


# --- the state directory ------------------------------------------------------


def prepare_pki(state: Path) -> None:
    """Keep a complete PKI; issue one when none exists; refuse a partial one."""
    present = [name for name in pki.PKI_FILES if (state / "pki" / name).exists()]
    if len(present) == len(pki.PKI_FILES):
        return
    if present:
        raise Refusal(f"{state / 'pki'} is partial ({present}); restore or remove it by hand")
    scratch = Path(tempfile.mkdtemp(dir=state, prefix="pki-issue-"))
    try:
        issued = pki.issue(scratch, 30)
        for name in pki.PKI_FILES:
            pki.durable_write(state / "pki" / name, issued[name], 0o600)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)  # includes the CA key, which is never kept
    log("issued a new development PKI (30 days)")


def prepare_tokens(state: Path) -> None:
    for name in TOKENS:
        path = state / "config" / f"{name}.token"
        if not path.exists():
            pki.durable_write(path, secrets.token_hex(32).encode(), 0o600)


def file_sha(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


class Deploy:
    def __init__(self, root: Path, tos_root: Path, data: Path, system: System, user_unit_dir: Path = USER_UNIT_DIR):
        self.root, self.tos_root, self.data, self.system = root, tos_root, data, system
        self.user_unit_dir = user_unit_dir

    def configure(self, start: bool) -> int:
        network = network_of(self.data)
        check_nodes(self.system, self.data)
        state = self.root / network[:12]
        recorded = state / "network"
        if recorded.exists() and recorded.read_text().strip() != network:
            raise Refusal(f"{state} belongs to network {recorded.read_text().strip()[:12]}…")
        if (state / pki.JOURNAL).exists():
            raise Refusal(f"a PKI rotation is unresolved in {state}; run health-pki.py rotate --resolve first")
        active = (self.root / ACTIVE).read_text().strip() if (self.root / ACTIVE).exists() else None
        switching = active != state.name
        pending = (self.root / PENDING).exists()
        if switching and not start:
            raise Refusal(f"the active stack is {active}; switching it to {state.name} needs --start")
        if pending and not start:
            raise Refusal(f"a stack switch is unfinished ({self.root / PENDING}); finish it with --start")
        release = self.tos_root / "tools/node-health-monitor/target/release"
        missing = [name for name in BINARIES if not (release / name).is_file()]
        if missing:
            raise Refusal(f"{release} lacks {missing}; build tools/node-health-monitor first")

        for name in DIRECTORIES:
            (state / name).mkdir(parents=True, mode=0o700, exist_ok=True)
        with open(state / "pki.lock", "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refusal("a PKI rotation is in progress") from None
            prepare_pki(state)
            prepare_tokens(state)
            pins = pins_of(state)
            config_files = {
                name: (json.dumps(value, indent=2) + "\n").encode() for name, value in configs(state, network, pins).items()
            }
            users, roots = user_units(state), root_units(state, network)
            check_generated(state, {**config_files, **users, **roots})

            if switching:
                pki.durable_write(
                    self.root / PENDING, json.dumps({"state": state.name, "since": self.system.now()}).encode(), 0o600
                )
            for name in BINARIES:
                if file_sha(release / name) != file_sha(state / "bin" / name):
                    pki.durable_write(state / "bin" / name, (release / name).read_bytes(), 0o755)
            for name, data in config_files.items():
                pki.durable_write(state / "config" / name, data, 0o600)
            pki.durable_write(recorded, f"{network}\n".encode(), 0o600)
            record = {"network": network, "tos_root": str(self.tos_root)}
            pki.durable_write(state / RECORD, (json.dumps(record, indent=2) + "\n").encode(), 0o600)
            self.user_unit_dir.mkdir(parents=True, exist_ok=True)
            for name, data in users.items():
                pki.durable_write(self.user_unit_dir / name, data, 0o644)
            self.system.install_root_units(roots)
            self.system.reload_user_units(sorted(users))
        log(f"configured {state}")
        if not start:
            return EXIT_OK
        try:
            self.system.restart(sorted(roots), sorted(users))
            self.verify(state, network, sorted(roots), sorted(users))
        except Unhealthy as error:
            log(f"NOT VERIFIED: {error}")
            return EXIT_UNVERIFIED
        # Publish, then clear the marker, whether this run started the switch or
        # finishes one an earlier run was interrupted in.
        if switching:
            pki.durable_write(self.root / ACTIVE, f"{state.name}\n".encode(), 0o644)
            log(f"{state.name} is now the active stack")
        self.system.checkpoint("published")
        if (self.root / PENDING).exists():
            (self.root / PENDING).unlink()
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return EXIT_OK

    def verify(self, state: Path, network: str, roots: list[str], users: list[str]) -> None:
        deadline = self.system.now() + 90
        for unit, root in [(u, True) for u in roots] + [(u, False) for u in users]:
            while not self.system.active(unit, root):
                if self.system.now() > deadline:
                    raise Unhealthy(f"{unit} is not active")
                self.system.sleep(2)
        for alias, index, _ in NODES:
            while True:
                # A just-restarted edge answers 503 until its first native sample
                # and its ingress may not listen yet; both are waited out.
                try:
                    problem = native_binding_problem(self.system.edge_snapshot(state, index), alias, network)
                except Unhealthy as error:
                    problem = str(error)
                if problem is None:
                    break
                if self.system.now() > deadline:
                    raise Unhealthy(f"edge {index}: {problem}")
                self.system.sleep(5)
        nodes = {alias for alias, _, _ in NODES}
        deadline = self.system.now() + 300
        problem = "no observation yet"
        while self.system.now() <= deadline:
            self.system.sleep(20)
            try:
                problem = pki.healthy(self.system.observe(state), nodes)
            except Unhealthy as error:
                problem = str(error)
            if problem is None:
                return
        raise Unhealthy(f"monitoring did not come up: {problem}")


def native_binding_problem(snapshot: dict | None, alias: str, network: str) -> str | None:
    """None when the node itself reports the expected alias and network in its native sample."""
    if snapshot is None:
        return "the edge ingress kept rate-limiting the read"
    for source in snapshot.get("sources", []):
        if source.get("source_id") != "native_core":
            continue
        reported = (source.get("payload") or {}).get("network_id")
        if source.get("node_id") != alias or reported != network:
            return f"the native sample names {source.get('node_id')} on {str(reported)[:12]}…"
        return None
    return "no native sample yet"


def main(argv: list[str] | None = None, system: System | None = None, root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    # Internal: run as root by System.install_root_units, units as JSON on stdin.
    sub.add_parser("install-root-units")
    configure = sub.add_parser("configure")
    configure.add_argument("--start", action="store_true")
    configure.add_argument("--tos-root", type=Path, default=os.environ.get("TOS_ROOT"))
    configure.add_argument("--data", type=Path, default=Path("/data"))
    args = parser.parse_args(argv)
    if args.command == "install-root-units":
        try:
            units = {name: body.encode() for name, body in json.loads(sys.stdin.read()).items()}
            install_atomically(ROOT_UNIT_DIR, units)
        except (Refusal, OSError, ValueError, AttributeError) as error:
            log(f"REFUSED: {error}")
            return EXIT_REFUSED
        return EXIT_OK
    root = root or pki.HEALTH_ROOT
    try:
        if args.tos_root is None:
            raise Refusal("set TOS_ROOT or pass --tos-root")
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        with open(root / ROOT_LOCK, "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refusal("another deployment or rotation holds the health-root lock") from None
            deploy = Deploy(root, args.tos_root.resolve(), args.data, system or System())
            return deploy.configure(args.start)
    except Refusal as error:
        log(f"REFUSED: {error}")
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
