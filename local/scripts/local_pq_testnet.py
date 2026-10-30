#!/usr/bin/env python3
"""Prepare and verify a persistent local PQ network with four validators and two observers.

Only prepare generates keys. Deploy sends a local faucet transaction; check
is read-only. The pool uses the development verifying key, never a release key.
"""

import argparse
import asyncio
import base64
import copy
import hashlib
import inspect
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYSTEMD = HERE.parent / "systemd"


def tos_root():
    """The tos checkout (or installed snapshot) whose code and build these drivers use.

    `TOS_ROOT` names a tos checkout. Without it, a driver must be running from
    the root-owned service snapshot, which mirrors the checkout layout and keeps
    the drivers in `<snapshot>/src/scripts`.
    """
    configured = os.environ.get("TOS_ROOT")
    if configured:
        root = Path(configured).resolve()
    else:
        root = HERE.parent
    if not (root / "test/tostester/src").is_dir():
        raise SystemExit(
            f"{root} is not a tos checkout; set TOS_ROOT to the tos repository root"
        )
    # The drivers import tos modules such as tostester and x02_config34_proof.
    # Appended, so a sibling in this directory always wins over a tos module.
    for path in (root / "test/tostester/src", root / "scripts"):
        if str(path) not in sys.path:
            sys.path.append(str(path))
    return root


REPO = tos_root()


VALIDATOR_COUNT = 4
OBSERVER_COUNT = 2
LOCAL_NETWORK = "tos-local-dev"
LOCAL_GLOBAL_ID = 3
# The nodes that stand in local elections; 7 is the non-Genesis candidate.
CANDIDATES = (1, 2, 3, 4, 7)


def auth_network_tag_rule(epoch):
    return f"TOS-AUTH-NETWORK-TAG-v1;network={LOCAL_NETWORK};global_id={LOCAL_GLOBAL_ID};epoch={epoch}"


def local_auth_network_tag(environ, now):
    """The AUTH network tag a version-16 local Genesis commits to, and the rule behind it.

    tos assigns no tag. Each reset gets a new one, derived from the setup time, so a
    signature made for an earlier local chain cannot be replayed on the next. An explicit
    TOS_AUTH_NETWORK_TAG wins; its rule is then unknown.
    """
    given = environ.get("TOS_AUTH_NETWORK_TAG")
    if given is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", given):
            raise RuntimeError("TOS_AUTH_NETWORK_TAG must be exactly 64 hexadecimal digits")
        tag, rule = bytes.fromhex(given), None
    else:
        rule = auth_network_tag_rule(int(now))
        tag = hashlib.sha256(rule.encode("ascii")).digest()
    if len(set(tag)) == 1 or tag == bytes(range(32)):
        raise RuntimeError("the AUTH network tag must not be a reserved value")
    return tag, rule


def topology(data):
    """Plan only: no key generation, native tool, RPC or service invocation."""
    nodes = []
    for idx in range(1, VALIDATOR_COUNT + OBSERVER_COUNT + 1):
        role = "validator" if idx <= VALIDATOR_COUNT else "observer"
        nodes.append(
            {
                "idx": idx,
                "role": role,
                "directory": str(data / "testnet" / f"node{idx}"),
                "validator_port": 2002 + (idx - 1) * 3,
                "liteserver_port": 2003 + (idx - 1) * 3,
                "console_port": 2004 + (idx - 1) * 3,
                "json_rpc_port": 8010 + idx,
                "service": f"tos-pq-{role}@{idx}.service",
                "consensus_member": role == "validator",
            }
        )
    return {
        "status": "PREPARATION_ONLY_NOT_DEPLOYED",
        "mode": "pq",
        "dht_port": 2001,
        "validators": VALIDATOR_COUNT,
        "observers": OBSERVER_COUNT,
        "nodes": nodes,
        "lite_client": {
            "service": "tos-pq-lite-client.service",
            "consensus_member": False,
            "directory": str(data / "lite-client"),
            "config": str(data / "configs" / "observers-lite.json"),
            "upstream_node_ids": [5, 6],
            "listen_ports": [],
        },
        "requires_before_start": [
            "reviewed binaries installed",
            "observer identities and configs generated",
            "one common Genesis",
            "resource and port checks",
        ],
    }


def write_plan(data):
    # Planning runs before setup on a host that may not have /data yet; the
    # missing directories are created the way setup creates /data: owned by
    # the caller (root under sudo), mode 0755, never through a symlink.
    destination = secure_output_dir(data / "preparation", 0o755, create_parents=True)
    write_json(destination / "topology.json", topology(data))
    for name in (
        "tos-pq-observer@.service",
        "tos-pq-lite-client.service",
        "run-local-lite-client.py",
    ):
        source = HERE / name if name.endswith(".py") else SYSTEMD / name
        write_bytes(destination / name, source.read_bytes())
    print(f"Preparation only; no network started: {destination}")


def prepare_observers(data):
    """Extend retained Genesis/configuration offline; never start native tools."""
    from nacl.signing import SigningKey

    manifest = json.loads((data / "testnet-ports.json").read_text())
    if len(manifest["nodes"]) != VALIDATOR_COUNT:
        raise RuntimeError("observer preparation needs the retained four-validator topology")
    for idx in (5, 6):
        if (data / "testnet" / f"node{idx}").exists():
            raise RuntimeError("observer directory already exists")
    template = json.loads((data / "testnet/node1/config.json").read_text())
    global_config = json.loads((data / "tos-global.json").read_text())
    observer_lite = []
    for row in topology(data)["nodes"][VALIDATOR_COUNT:]:
        directory = Path(row["directory"])
        directory.mkdir(mode=0o700)
        keyring = directory / "keyring"
        keyring.mkdir(mode=0o700)

        def new_key():
            key = SigningKey.generate()
            public = b"\xc6\xb4\x13\x48" + bytes(key.verify_key)
            digest = hashlib.sha256(public).digest()
            path = keyring / digest.hex().upper()
            with path.open("xb") as output:
                output.write(b"\x17\x23\x68\x49" + bytes(key))
            path.chmod(0o600)
            return base64.b64encode(digest).decode(), public

        fullnode_id, _ = new_key()
        lite_id, lite_public = new_key()
        console_id, console_public = new_key()
        client = SigningKey.generate()
        client_public = b"\xc6\xb4\x13\x48" + bytes(client.verify_key)
        client_id = base64.b64encode(hashlib.sha256(client_public).digest()).decode()
        private = directory / "console-client.key"
        private.write_bytes(b"\x17\x23\x68\x49" + bytes(client))
        private.chmod(0o600)
        config = copy.deepcopy(template)
        config["out_port"] = 0
        config["addrs"] = [
            {
                "@type": "engine.addr",
                "ip": 2130706433,
                "port": row["validator_port"],
                "categories": [0],
                "priority_categories": [],
            }
        ]
        config["adnl"] = [{"@type": "engine.adnl", "id": fullnode_id, "category": 0}]
        config["dht"] = [{"@type": "engine.dht", "id": fullnode_id}]
        config["fullnode"] = fullnode_id
        config["validators"] = []
        config["collators"] = []
        config["fullnodeslaves"] = []
        config["fullnodemasters"] = []
        config["gc"] = {"@type": "engine.gc", "ids": []}
        config.get("extraconfig", {}).pop("pq_consensus", None)
        config["liteservers"] = [
            {"@type": "engine.liteServer", "id": lite_id, "port": row["liteserver_port"]}
        ]
        config["control"] = [
            {
                "@type": "engine.controlInterface",
                "id": console_id,
                "port": row["console_port"],
                "allowed": [{"@type": "engine.controlProcess", "id": client_id, "permissions": 15}],
            }
        ]
        lite = {
            "ip": 2130706433,
            "port": row["liteserver_port"],
            "id": {"@type": "pub.ed25519", "key": base64.b64encode(lite_public[4:]).decode()},
        }
        observer_lite.append(lite)
        write_json(directory / "config.json", config)
        write_json(directory / "lite-client.json", {"liteservers": [lite]})
        (directory / "console-server.pub").write_bytes(console_public)
        shutil.copytree(data / "testnet/node1/static", directory / "static")
        shutil.copyfile(directory / "config.json", data / "configs" / f"node-{row['idx']}.json")
        shutil.copyfile(
            directory / "lite-client.json", data / "configs" / f"node-{row['idx']}-lite.json"
        )
        manifest["nodes"].append({**row, "fullnode_id": fullnode_id})
    for row in manifest["nodes"][:VALIDATOR_COUNT]:
        row["role"] = "validator"
    global_config["liteservers"].extend(observer_lite)
    write_json(data / "configs/observers-lite.json", {"liteservers": observer_lite})
    write_json(data / "tos-global.json", global_config)
    write_json(data / "configs/global.json", global_config)
    write_json(data / "testnet-ports.json", manifest)
    network = json.loads((data / "network.json").read_text())
    network.update(observers=OBSERVER_COUNT, status="PREPARED_STOPPED_CHAIN_DATA_RESET")
    write_json(data / "network.json", network)
    (data / "lite-client").mkdir(mode=0o700)
    write_plan(data)
    print("Prepared two observer identities/configs; no validator membership or Genesis changed")


def secure_output_dir(path, mode=0o700, create_parents=False):
    """Return `path` as a directory only this user can change.

    Root-run tools write here while unprivileged daemons own other parts of
    /data. The directory must not be a symlink, must belong to the effective
    user and not be writable by anyone else, and its parent must not let
    another user swap it out.

    With `create_parents`, a missing parent is created first under the same
    rules (mode 0755), one level at a time, so every directory created is
    checked against its own parent; an existing ancestor is never changed.
    """
    path = Path(path)
    if create_parents and not os.path.lexists(path.parent):
        secure_output_dir(path.parent, 0o755, create_parents=True)
    try:
        parent = path.parent.lstat()
    except FileNotFoundError:
        raise RuntimeError(f"{path.parent} does not exist") from None
    if not stat.S_ISDIR(parent.st_mode):
        raise RuntimeError(f"{path.parent} is not a directory")
    if parent.st_uid not in (0, os.geteuid()) or parent.st_mode & 0o022:
        raise RuntimeError(f"{path.parent} can be changed by another user; refusing to write in it")
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{path} is not a directory (a symlink is refused)")
    if info.st_uid != os.geteuid():
        raise RuntimeError(f"{path} belongs to uid {info.st_uid}, not {os.geteuid()}")
    os.chmod(path, mode, follow_symlinks=False)
    return path


def open_private(path, flags, mode=0o600):
    """Open `path` without following a symlink at its final component."""
    return os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode)


def write_bytes(path, data, mode=0o644):
    fd = open_private(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        os.fchmod(f.fileno(), mode)


def append_text(path, text, mode=0o600):
    fd = open_private(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, mode)
    with os.fdopen(fd, "a") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())


def write_json(path, value, mode=0o644):
    write_bytes(path, (json.dumps(value, indent=2) + "\n").encode(), mode)


def rpc(port, method, **params):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        {"Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        result = json.load(response)
    if result.get("error") or "result" not in result:
        raise RuntimeError(f"{method}: {result.get('error', result)}")
    return result["result"]


class PatientClient:
    """A toslib client that waits out a lite server's admission limit.

    A lite server refuses a query it will not run now with LITE_SERVER_NOTREADY
    (for example when more than its per-second budget of heavy proof queries
    arrives together). The refused query was never executed, so asking again
    later is safe, including for a message send: the drivers' journal already
    makes sends idempotent. Every other error is raised at once.
    """

    def __init__(self, client, attempts=7, delay=0.5):
        self._client, self._attempts, self._delay = client, attempts, delay

    def __getattr__(self, name):
        attr = getattr(self._client, name)
        if not inspect.iscoroutinefunction(attr):
            return attr

        async def call(*args, **kwargs):
            wait = self._delay
            for attempt in range(self._attempts):
                try:
                    return await attr(*args, **kwargs)
                except Exception as exc:
                    if "LITE_SERVER_NOTREADY" not in str(exc) or attempt + 1 == self._attempts:
                        raise
                    await asyncio.sleep(wait)
                    wait = min(wait * 2, 8)

        return call


MASTERCHAIN_SHARD = "-9223372036854775808"


def lite_config(path, rpc_port=8011):
    """Load a lite-client config whose proof chain starts at the latest key block.

    A client that starts from the zero state proves its way forward through
    every key block since Genesis. With short archive retention those blocks
    are garbage collected within hours, and every newly started client then
    fails with LITE_SERVER_NOTREADY "block handle not in db". The init block
    is read from a local node's JSON-RPC, which these development drivers
    already trust; a production client takes it from its global config.
    """
    from tosapi import tos_api

    config = json.loads(Path(path).read_text())
    head = int(rpc(rpc_port, "getMasterchainInfo")["last"]["seqno"])
    header = rpc(rpc_port, "getBlockHeader", workchain=-1, shard=MASTERCHAIN_SHARD, seqno=head)
    key = int(header["seqno"] if header.get("is_key_block") else header["prev_key_block_seqno"])
    if key > 0:
        block = rpc(rpc_port, "lookupBlock", workchain=-1, shard=MASTERCHAIN_SHARD, seqno=key)
        config["validator"]["init_block"] = {
            "workchain": int(block["workchain"]),
            "shard": int(block["shard"]),
            "seqno": int(block["seqno"]),
            "root_hash": block["root_hash"],
            "file_hash": block["file_hash"],
        }
    return tos_api.Liteclient_config_global.from_dict(config)


def block_id(value):
    # Retain the full block identity; equality of heights alone is insufficient.
    return tuple(value[key] for key in ("workchain", "shard", "seqno", "root_hash", "file_hash"))


def validate_pq_set(decoded, ports):
    expected = {(n["validator_id"], n["pq_key_id"]) for n in ports}
    # The tos decoder names the validator id field controller_id_hex.
    actual = {(n["controller_id_hex"], n["consensus_key_id_hex"]) for n in decoded["validators"]}
    if len(expected) != 4 or decoded["total"] != 4 or decoded["main"] != 4 or actual != expected:
        raise RuntimeError("live ConfigParam34 does not contain the four provisioned PQ identities")


async def prepare(args):
    from tosapi import tos_api
    from tostester.install import Install
    from tostester.network import Network

    data = args.data
    if (data / "testnet").exists():
        raise RuntimeError("existing network; use setup-testnet.sh --clean to reinitialize")
    async with Network(Install(args.build, REPO), data / "testnet", base_port=2000) as network:
        network.config.global_version = 16
        network.config.global_id = LOCAL_GLOBAL_ID
        auth_network_tag, auth_network_tag_rule_text = local_auth_network_tag(os.environ, time.time())
        network.config.auth_network_tag = auth_network_tag
        network.config.deployment_fee_schedule = True
        network.config.shard_validators = 4
        rotating = args.rotate
        wallets = {}
        if rotating:
            import nacl.signing
            from contract import WalletV1Blueprint
            from tostester.pq_initial_validator import deterministic_pq_initial_validator_seed

            election_dir = data / "elections"
            election_dir.mkdir(mode=0o700)
            key_dir = election_dir / "keys"
            key_dir.mkdir(mode=0o700)
            network.config.validator_economics_profile = True
            network.config.validator_election_stage_a_profile = True
            network.config.validator_election_stage_a_elected_for = 600
            network.config.validator_election_stage_a_start_before = 300
            network.config.validator_election_experiment_faucet_balance_nanotos = (
                1_000_000_000 * 10**9
            )
            # Each candidate stakes directly from its own masterchain wallet, so
            # that wallet's account id is the validator id its node is bound to.
            for idx in CANDIDATES:
                key = nacl.signing.SigningKey.generate()
                write_bytes(key_dir / f"wallet-{idx}.pk", bytes(key), 0o600)
                wallets[idx] = WalletV1Blueprint(workchain=-1, private_key=key)
        network.config.bootstrap_validator_set_valid_for = 600 if rotating else 30 * 86400
        dht = network.create_dht_node()
        nodes = []
        for idx in range(1, 5):
            node = network.create_full_node()
            if rotating:
                node.make_initial_pq_validator(
                    wallets[idx].address.hash_part, deterministic_pq_initial_validator_seed(idx)
                )
            else:
                node.make_initial_pq_validator(os.urandom(32), os.urandom(32))
            node.announce_to(dht)
            nodes.append(node)
        for _ in range(OBSERVER_COUNT):
            node = network.create_full_node()
            # No validator configuration or PQ consensus seed for observers.
            node._local_config.validators = []
            node.announce_to(dht)
            nodes.append(node)
        if rotating:
            candidate = network.create_full_node()
            candidate.make_noninitial_pq_validator(
                wallets[7].address.hash_part, deterministic_pq_initial_validator_seed(7)
            )
            candidate.announce_to(dht)
            nodes.append(candidate)
            for idx, wallet in wallets.items():
                node = nodes[idx - 1]
                held = node.pq_initial_validator
                write_json(
                    election_dir / f"candidate-{idx}.json",
                    {
                        "node": idx,
                        "wallet": wallet.address.to_str(is_user_friendly=False),
                        "state_init_b64": base64.b64encode(
                            wallet.state_init.serialize().to_boc()
                        ).decode(),
                        "key_id": held.key_id.hex(),
                        "public_key": held.public_key.hex(),
                        "adnl_id": node.validator_key.id.hex(),
                    },
                )
                write_json(
                    election_dir / f"console-{idx}.private.json",
                    tos_api.EngineConsoleClient_config(
                        address=node._engine_console_addr.address,
                        server_public_key=node._engine_console_server_key.public_key,
                        client_private_key=node._engine_console_client_key.private_key,
                    ).to_dict(),
                    mode=0o600,
                )
            write_json(
                election_dir / "plan.json",
                {
                    "elected_for": 600,
                    "start_before": 300,
                    "end_before": 60,
                    "stake_held_for": 180,
                    "rosters": [[1, 2, 3, 7], [1, 2, 3, 4]],
                    "scope": "local-development-only",
                },
            )
        zs = network._get_or_generate_zerostate()
        # The genesis ceremony: each genesis validator's identity was made for this
        # zerostate and has never signed, so its signing ledger starts complete.
        # Without it every validator waits for a fence block no one can produce.
        # The election candidate (node 7) joins later and never runs it.
        for node in nodes[:VALIDATOR_COUNT]:
            held = node.pq_initial_validator
            ceremony = subprocess.run(
                [
                    str(network.install.pq_consensus_key_exe),
                    "init-signing-ledger",
                    "--genesis-ceremony",
                    str(node._directory),
                    held.validator_id.hex(),
                    zs.masterchain.root_hash.hex(),
                    zs.masterchain.file_hash.hex(),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if ceremony.returncode != 0:
                raise RuntimeError(f"genesis ceremony failed: {ceremony.stderr.strip()}")
        ports = []
        for i, node in enumerate(nodes, 1):
            static = node._directory / "static"
            static.mkdir()
            for state in (zs.masterchain, zs.shardchain):
                shutil.copyfile(state.file, static / state.file_hash.hex().upper())
            (node._directory / "config.json").write_text(node._local_config.to_json())
            (node._directory / "lite-client.json").write_text(node.liteserver_config.to_json())
            node._engine_console_server_key.write_pub_key_file(
                node._directory / "console-server.pub"
            )
            ports.append(
                {
                    "idx": i,
                    "role": "validator"
                    if i <= VALIDATOR_COUNT
                    else "candidate"
                    if i == 7
                    else "observer",
                    "directory": str(node._directory),
                    "validator_port": node._addr.port,
                    "liteserver_port": node._liteserver_addr.port,
                    "console_port": node._engine_console_addr.port,
                    "json_rpc_port": 8010 + i,
                    **(
                        {
                            "validator_id": node.pq_initial_validator.validator_id.hex(),
                            "pq_key_id": node.pq_initial_validator.key_id.hex(),
                        }
                        if node.pq_initial_validator is not None
                        else {}
                    ),
                }
            )
        (dht._directory / "config.json").write_text(dht._local_config.to_json())
        config = tos_api.Config_global(
            dht=tos_api.Dht_config_global(
                static_nodes=tos_api.Dht_nodes(nodes=[dht._signed_address]), k=6, a=3
            ),
            validator=zs.as_validator_config(),
        ).to_dict()
        config["liteservers"] = [
            json.loads(n.liteserver_config.to_json())["liteservers"][0] for n in nodes
        ]
        write_json(data / "tos-global.json", config)
        write_json(
            data / "testnet-ports.json", {"mode": "pq", "dht_port": dht._addr.port, "nodes": ports}
        )
        write_json(
            data / "network.json",
            {
                "mode": "pq",
                "validators": VALIDATOR_COUNT,
                "observers": OBSERVER_COUNT,
                "global_id": LOCAL_GLOBAL_ID,
                "global_version": 16,
                "auth_network_tag": {
                    "value": auth_network_tag.hex(),
                    "rule": auth_network_tag_rule_text,
                },
                "genesis_wallet_address": zs.main_wallet_address.to_str(is_user_friendly=False),
                "zerostate_root": zs.masterchain.root_hash.hex(),
                "zerostate_file": zs.masterchain.file_hash.hex(),
                "genesis_validator_set_expires_unix": int(time.time())
                + (600 if rotating else 30 * 86400),
                "election_period_seconds": 600 if rotating else None,
                "candidates": 1 if rotating else 0,
                "scope": "local-development",
            },
        )
        export = data / "configs"
        export.mkdir()
        for i, node in enumerate(nodes, 1):
            shutil.copyfile(node._directory / "config.json", export / f"node-{i}.json")
            shutil.copyfile(node._directory / "lite-client.json", export / f"node-{i}-lite.json")
            (export / f"node-{i}.json").chmod(0o644)
            (export / f"node-{i}-lite.json").chmod(0o644)
        shutil.copyfile(data / "tos-global.json", export / "global.json")
        (export / "global.json").chmod(0o644)
        observer_lite = {
            "liteservers": [
                json.loads(n.liteserver_config.to_json())["liteservers"][0]
                for n in nodes[VALIDATOR_COUNT : VALIDATOR_COUNT + OBSERVER_COUNT]
            ]
        }
        write_json(export / "observers-lite.json", observer_lite)
        (data / "lite-client").mkdir(mode=0o700)
        export.chmod(0o755)
    print("Prepared four PQ validators, two observers and a standalone lite-client config")


async def wait_network(args):
    import base64

    from pytosiq_core import Cell
    from pytosiq_core.tlb.config import ConfigParam8
    from x02_config34_proof import decode_validator_set

    ports = json.loads((args.data / "testnet-ports.json").read_text())["nodes"]
    validator_ports = [n for n in ports if n.get("role", "validator") == "validator"]
    observer_ports = [n for n in ports if n.get("role") == "observer"]
    if len(validator_ports) != VALIDATOR_COUNT or len(observer_ports) not in (0, OBSERVER_COUNT):
        raise RuntimeError("expected four validators and either zero or two observers")
    deadline = time.monotonic() + args.timeout
    error = None
    while time.monotonic() < deadline:
        try:
            results = await asyncio.gather(
                *[asyncio.to_thread(rpc, n["json_rpc_port"], "getMasterchainInfo") for n in ports]
            )
            height = min(r["last"]["seqno"] for r in results)
            if height < 2:
                raise RuntimeError("waiting for height 2")
            headers = await asyncio.gather(
                *[
                    asyncio.to_thread(
                        rpc,
                        n["json_rpc_port"],
                        "getBlockHeader",
                        workchain=-1,
                        shard="-9223372036854775808",
                        seqno=height,
                    )
                    for n in ports
                ]
            )
            ids = [block_id(h["id"]) for h in headers]
            if len(set(ids)) != 1:
                raise RuntimeError("local nodes disagree on the full block ID")
            version, validators = await asyncio.gather(
                *[
                    asyncio.to_thread(
                        rpc, ports[0]["json_rpc_port"], "getConfigParam", param=param, seqno=height
                    )
                    for param in (8, 34)
                ]
            )
            version_cell = Cell.one_from_boc(base64.b64decode(version["config"]["bytes"]))
            if ConfigParam8.deserialize(version_cell.begin_parse()).version != 16:
                raise RuntimeError("live ConfigParam8 version must be 16")
            validator_cell = Cell.one_from_boc(base64.b64decode(validators["config"]["bytes"]))
            decoded = decode_validator_set(validator_cell)
            if any(n.get("role") == "candidate" for n in ports):
                by_id = {n["idx"]: n for n in ports}
                allowed = [(1, 2, 3, 4), (1, 2, 3, 7)]
                errors = []
                for roster in allowed:
                    try:
                        validate_pq_set(decoded, [by_id[i] for i in roster])
                        break
                    except RuntimeError as exc:
                        errors.append(str(exc))
                else:
                    raise RuntimeError("current elected PQ set differs from both rotation rosters")
            else:
                validate_pq_set(decoded, validator_ports)
            return {
                "height": height,
                "block_id": headers[0]["id"],
                "nodes": len(ports),
                "observers": len(observer_ports),
                "global_version": 16,
                "pq_validators": decoded,
            }
        except (OSError, RuntimeError, KeyError, ValueError) as exc:
            error = str(exc)
            await asyncio.sleep(2)
    raise RuntimeError(f"network did not become ready: {error}")


# The lite-client setup-testnet.sh installs for the services. Root-run drivers
# execute this explicit path: they run from a snapshot that holds no build
# tree, and a PATH search could reach a directory another user can write.
INSTALLED_LITE_CLIENT = Path("/usr/local/bin/tos-lite-client")
# The production stake-order builder (tosctl's pq_pool_stake_order example),
# installed by setup-testnet.sh; the election driver encodes no stake itself.
INSTALLED_STAKE_ORDER_BUILDER = Path("/usr/local/bin/tos-pq-pool-stake-order")


def require_installed_executable(path):
    """Return `path` if it is an executable a root service may run, else refuse.

    The path must be absolute and name a regular file (a symlink is refused)
    that belongs to root or the effective user, is writable by nobody else, and
    is executable.
    """
    path = Path(path)
    if not path.is_absolute():
        raise RuntimeError(f"{path} is not an absolute path")
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise RuntimeError(f"{path} does not exist; install it before starting") from None
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{path} is not a regular file (a symlink is refused)")
    if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise RuntimeError(f"{path} can be changed by another user; refusing to run it")
    if not os.access(path, os.X_OK):
        raise RuntimeError(f"{path} is not executable")
    return path


def get_method(lite_client, data, address, method):
    result = subprocess.run(
        [
            str(lite_client),
            "-C",
            str(data / "configs/node-1-lite.json"),
            "-v",
            "0",
            "-c",
            f"runmethod {address} {method}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    match = re.search(r"result:\s*\[\s*([0-9-]+)\s*\]", result.stdout)
    if result.returncode or not match:
        raise RuntimeError(f"pool get-method {method} failed: {result.stderr[-1000:]}")
    return int(match.group(1))


async def pool_methods(args, pool, initial=False):
    names = ["reserve_floor", "backed"]
    if initial:
        names += ["commitment_root", "nullifier_root", "native_liability", "commitment_next_index"]
    values = {}
    # Pace separate lite clients rather than bursting requests at one connection.
    for name in names:
        values[name] = await asyncio.to_thread(
            get_method, args.build / "lite-client/lite-client", args.data, pool["address"], name
        )
    expected = {"reserve_floor": int(pool["reserve_floor_nanotos"]), "backed": -1}
    if initial:
        expected.update(
            commitment_root=int(pool["commitment_root"]),
            nullifier_root=int(pool["nullifier_root"]),
            native_liability=0,
            commitment_next_index=0,
        )
    if any(values[name] != value for name, value in expected.items()):
        raise RuntimeError(f"pool state differs: {values}")
    return values


async def deploy(args):
    import nacl.signing
    from contract import WalletV1, tos
    from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, StateInit, WalletMessage
    from toslib import ToslibClient
    from toslib.toslib_cdll import ToslibCDLL

    observation = await wait_network(args)
    pooldir = args.data / "shielded-pool"
    pool = json.loads((pooldir / "pool.json").read_text())
    code = Cell.one_from_boc((pooldir / "code.boc").read_bytes())
    state = Cell.one_from_boc((pooldir / "data.boc").read_bytes())
    init = StateInit(code=code, data=state)
    address = Address((0, init.serialize().hash))
    if address.to_str(is_user_friendly=False).lower() != pool["address"].lower():
        raise RuntimeError("pool address does not match the compiled code and data")
    network = json.loads((args.data / "network.json").read_text())
    config = lite_config(args.data / "testnet/node1/lite-client.json")
    cdll = ToslibCDLL(args.build / "toslib/libtoslibjson.so")
    cdll.client_set_verbosity_level(0)
    async with ToslibClient(config, cdll) as client:
        client = PatientClient(client)
        account = await client.raw_get_account_state(address)
        if not account.code:
            key = nacl.signing.SigningKey((args.data / "testnet/state/main-wallet.pk").read_bytes())
            wallet = WalletV1(client, Address(network["genesis_wallet_address"]), key)
            await wallet.send(
                WalletMessage(
                    send_mode=3,
                    message=MessageAny(
                        info=InternalMsgInfo(
                            ihr_disabled=True,
                            bounce=False,
                            bounced=False,
                            src=wallet.address,
                            dest=address,
                            value=tos(100),
                            ihr_fee=0,
                            fwd_fee=0,
                            created_lt=0,
                            created_at=0,
                        ),
                        init=init,
                        body=Cell.empty(),
                    ),
                )
            )
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            account = await client.raw_get_account_state(address)
            if account.code:
                actual = Cell.one_from_boc(account.code)
                if actual.hash != code.hash:
                    raise RuntimeError("on-chain pool code differs from the compiled source")
                record = {
                    **pool,
                    "deployed": True,
                    "balance_nanotos": account.balance,
                    "verified_code_hash": actual.hash.hex(),
                    "network": observation,
                    "deployed_at_unix": int(time.time()),
                }
                record["get_methods"] = await pool_methods(args, pool, initial=True)
                write_json(pooldir / "deployment.json", record)
                print(json.dumps(record, indent=2))
                return
            await asyncio.sleep(2)
    raise RuntimeError("pool deployment did not become active")


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=["plan", "prepare-observers", "prepare", "deploy", "check"]
    )
    parser.add_argument("--data", type=Path, default=Path("/data"))
    parser.add_argument("--build", type=Path, default=REPO / "build")
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Development-only 600-second elections with candidate node 7",
    )
    args = parser.parse_args()
    if args.command == "plan":
        write_plan(args.data)
    elif args.command == "prepare-observers":
        prepare_observers(args.data)
    elif args.command == "prepare":
        await prepare(args)
    elif args.command == "deploy":
        await deploy(args)
    else:
        start = await wait_network(args)
        await asyncio.sleep(3)
        end = await wait_network(args)
        if end["height"] <= start["height"]:
            raise RuntimeError("local network is not advancing")
        pool = json.loads((args.data / "shielded-pool/pool.json").read_text())
        end["pool"] = {"address": pool["address"], "get_methods": await pool_methods(args, pool)}
        print(json.dumps(end, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
