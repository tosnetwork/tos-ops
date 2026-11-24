#!/usr/bin/env python3
"""What a genesis validator operator runs on their own hosts.

Subcommands, in ceremony order:

  pregenesis-config OUT
      Write the placeholder global config the engine's first start needs
      before the real one exists (see testnet_lib.pregenesis_config).

  record --db DIR --seed FILE --validator-id ID --operator NAME --address IP:PORT
      Build the operator's public genesis record from the node database the
      first start created and the consensus seed beside it. ID is the staking
      account, the pool `testnet-elections.py pool` derived for this
      validator (64 hex digits or -1:<64 hex digits>); it is the validator id
      genesis records and the node is bound to. The output holds public
      values only and is what the operator sends to the coordinator.

  configure --db DIR --role validator|fullnode --client-dir DIR
      Phase 2 of the first start, with the node stopped: add a loopback-only
      console (and, on a full node, a lite server) to config.json. The console
      client key is written to --client-dir for the operator; the server keys
      go into the node keyring.

  submission-priority --db DIR [--priority N] [--wait SECONDS]
      On a running full node, give externals submitted to its own lite server
      check priority N (default 1) over externals relayed from the network,
      through the node's console (`set-ext-message-pool-options-json`, which
      validates and persists the setting). Every other pool option is kept.
      Retries until the console answers or --wait expires.

  rpc-config --global-config FILE --liteserver-pub FILE --port N --out FILE
      The liteserver configuration tos-rpc trusts on an rpc host: the
      published global config with its liteservers replaced by the co-hosted
      full node's own lite server on 127.0.0.1:N (the key `configure` wrote to
      the full node's client dir as liteserver.pub). Refuses the placeholder
      config and an existing FILE.

  master-wallet --config FILE [--require]
      What init-operator.sh does about tosctl's master wallet, which the
      election task needs: prints `set` when FILE (tosctl-config.json) has
      none, `keep` when it has exactly the epoch-5 record (vault key
      master-wallet-secret, V3R2, subwallet 42, workchain 0), and refuses any
      other master wallet. --require refuses unless it is configured.

  onboard --name NAME --pool POOL --owner OWNER [--tos-root DIR] [--rpc URL] [--out FILE]
      As root, on the operator's own validator host, after the coordinator
      reports its steps done (testnet-elections.py onboard --no-host): every
      host-side step of election onboarding, each skipped when its result is
      already there, so a rerun changes nothing:
        1. init-operator.sh --name NAME (console key, node registration,
           tosctl's master wallet, the operator wallet op-NAME);
        2. reads POOL from this host's own node (loopback JSON-RPC, or --rpc):
           refuses unless it is active, runs the pinned single-nominator code
           (crypto/smartcont/single-nominator-pool/single-nominator-code.hex
           in --tos-root, default /var/lib/tos-build/tos, the same file the
           coordinator pins), its validator role is op-NAME, its owner role
           is --owner, and it holds two stakes (elections.stake_tos) above
           its storage reserve;
        3. activates op-NAME (`tosctl wallet activate`: the wallet deploys
           itself from the fee money the coordinator sent; nothing else is
           sent) unless it is active, refusing while it holds no fee money;
        4. `tosctl config pool add` and `config bind add` for pool-NAME;
        5. the node's latest `post-quantum consensus custody` line must name
           POOL as its validator id;
        6. enable-elections.sh --name NAME, unless the election task is
           already running (a rerun does not restart it); refuses unless the
           unit is active at the end.
      Prints a JSON summary of public facts (written to --out too) to send to
      the coordinator, who checks the result on chain.

Nothing here generates or reads a wallet key.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402
import testnet_ops as ops  # noqa: E402
import validator_host as vh  # noqa: E402

BIN = Path(os.environ.get("TOS_BIN", "/usr/local/bin"))


def tool(name: str) -> str:
    path = BIN / name
    if not path.is_file() or not os.access(path, os.X_OK):
        raise lib.TestnetError(f"{path} is not an executable; set TOS_BIN to the release binaries")
    return str(path)


def cmd_pregenesis_config(args: argparse.Namespace) -> None:
    profile = lib.load_profile(args.profile)
    lib.write_new_json(args.out, lib.pregenesis_config(profile))
    print(
        f"wrote {args.out}: for the first start only; replace it with the published global config"
    )


def cmd_record(args: argparse.Namespace) -> None:
    config_path = args.db / "config.json"
    config = json.loads(config_path.read_text())
    adnl = lib.validator_adnl_id(config)
    report = lib.run([tool("tos-pq-consensus-key"), "show", str(args.seed)])
    key_id, public = lib.parse_consensus_key_report(report.stdout)
    record = lib.check_operator_record(
        {
            "operator": args.operator,
            "validator_id": args.validator_id.removeprefix("-1:"),
            "adnl_id": adnl.hex(),
            "public_key": public.hex(),
            "key_id": key_id.hex(),
            "address": args.address,
        }
    )
    engine_addrs = [
        f"{ipaddress.IPv4Address(a['ip'] % 2**32)}:{a['port']}" for a in config.get("addrs", [])
    ]
    if args.address not in engine_addrs:
        raise lib.TestnetError(
            f"{args.address} is not the address this node announces ({engine_addrs}); "
            "rerun the first start with -I <public-ip>:<port>"
        )
    if args.out:
        lib.write_new_json(args.out, record)
    print(json.dumps(record, indent=2))


def new_keypair(workdir: Path, name: str) -> tuple[bytes, bytes, bytes]:
    """(private TL bytes, public TL bytes, short id) from generate-random-id -m keys."""
    lib.run([tool("generate-random-id"), "-m", "keys", "-n", str(workdir / name)])
    private = (workdir / name).read_bytes()
    public = (workdir / f"{name}.pub").read_bytes()
    if not private.startswith(lib.ED25519_PRIVATE_TL_PREFIX) or len(private) != 36:
        raise lib.TestnetError("generate-random-id wrote an unexpected private key format")
    if not public.startswith(lib.ED25519_PUBLIC_TL_PREFIX) or len(public) != 36:
        raise lib.TestnetError("generate-random-id wrote an unexpected public key format")
    return private, public, lib.adnl_short_id(public[4:])


def hold_config_lock(db: Path) -> int:
    """Take the engine's own configuration lock, or refuse because a node holds it.

    The engine holds a POSIX fcntl write lock on <db>/config.json.lock for its
    whole life, and tos-pq-consensus-key bind-node takes the same lock. Holding
    it here is what makes editing config.json safe; a file merely existing
    proves nothing.
    """
    import fcntl

    fd = os.open(db / "config.json.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise lib.TestnetError(
            f"{db}/config.json.lock is held: the node (or bind-node) is running; stop it first"
        ) from exc
    return fd


def cmd_configure(args: argparse.Namespace) -> None:
    profile = lib.load_profile(args.profile)
    ports = profile["ports"]
    db = args.db
    config_path = db / "config.json"
    lock = hold_config_lock(db)
    if (db / "config.json.tmp").exists():
        raise lib.TestnetError(
            "config.json.tmp exists: an earlier write did not finish; inspect it first"
        )
    config = json.loads(config_path.read_text())
    if config.get("control"):
        raise lib.TestnetError("config.json already has a console; phase 2 has run")
    keyring = db / "keyring"
    if not keyring.is_dir():
        raise lib.TestnetError(f"{keyring} is missing; run the first start first")
    client_dir = lib.private_dir(args.client_dir)
    with tempfile.TemporaryDirectory(prefix="tos-keys-") as tmp:
        work = Path(tmp)
        server_private, server_public, server_id = new_keypair(work, "console-server")
        client_private, client_public, client_id = new_keypair(work, "console-client")
        lib.write_new(keyring / server_id.hex().upper(), server_private, 0o600)
        lib.write_new(client_dir / "client", client_private, 0o600)
        lib.write_new(client_dir / "client.pub", client_public, 0o644)
        lib.write_new(client_dir / "server.pub", server_public, 0o644)
        config["control"] = [
            {
                "@type": "engine.controlInterface",
                "id": lib.b64(server_id),
                "port": ports["console_tcp"],
                "allowed": [
                    {"@type": "engine.controlProcess", "id": lib.b64(client_id), "permissions": 15}
                ],
            }
        ]
        if args.role == "fullnode":
            lite_private, lite_public, lite_id = new_keypair(work, "liteserver")
            lib.write_new(keyring / lite_id.hex().upper(), lite_private, 0o600)
            lib.write_new(client_dir / "liteserver.pub", lite_public, 0o644)
            config["liteservers"] = [
                {
                    "@type": "engine.liteServer",
                    "id": lib.b64(lite_id),
                    "port": ports["liteserver_tcp"],
                }
            ]
        elif config.get("liteservers"):
            raise lib.TestnetError("a validator serves no lite server; remove it from config.json")
    tmp_path = db / "config.json.tmp"
    lib.write_new(tmp_path, (json.dumps(config, indent=2) + "\n").encode(), 0o600)
    shutil.copymode(config_path, tmp_path)
    os.replace(tmp_path, config_path)
    dir_fd = os.open(db, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    os.close(lock)
    print(
        f"console on TCP {ports['console_tcp']}: firewall it to loopback; client keys in {client_dir}"
    )
    if args.role == "fullnode":
        print(
            f"lite server on TCP {ports['liteserver_tcp']}; publish {client_dir / 'liteserver.pub'}"
        )


LOOPBACK = "127.0.0.1"


def rpc_liteserver_config(global_config: dict, liteserver_pub: bytes, port: int) -> dict:
    """The global config with one trusted liteserver: the local full node's, on loopback."""
    if not isinstance(global_config, dict) or not isinstance(global_config.get("validator"), dict):
        raise lib.TestnetError("the global config has no validator section")
    if lib.is_pregenesis(global_config):
        raise lib.TestnetError("refused: placeholder config")
    if len(liteserver_pub) != 36 or not liteserver_pub.startswith(lib.ED25519_PUBLIC_TL_PREFIX):
        raise lib.TestnetError("the lite server key is not a generate-random-id Ed25519 public key")
    if not 0 < port < 65536:
        raise lib.TestnetError(f"lite server port {port} is out of range")
    config = {k: v for k, v in global_config.items() if k not in ("liteservers", "liteservers_v2")}
    config["liteservers"] = [
        {
            "ip": lib.ip_to_tl(LOOPBACK),
            "port": port,
            "id": {"@type": "pub.ed25519", "key": lib.b64(liteserver_pub[4:])},
        }
    ]
    return config


# tosctl service (the election task) refuses to start without a master wallet,
# and `tosctl config generate` no longer writes an implied one. The record is the
# one the generated configuration used to carry and epoch 5 ran with: the vault
# key master-wallet-secret, wallet V3R2, subwallet 42, workchain 0. The service
# creates that key in the vault on its first start, as it did then; nothing here
# creates or reads a key. init-operator.sh configures it with
# `tosctl config master-wallet set` and checks the result with --require.
MASTER_WALLET = {
    "key": {"name": "master-wallet-secret"},
    "version": "V3R2",
    "subwallet_id": 42,
    "workchain": 0,
}


def master_wallet_action(config: dict) -> str:
    """'set' when the configuration has no master wallet yet, 'keep' when it has
    exactly MASTER_WALLET; refuses anything else, so a configured master wallet,
    which may hold funds, is never replaced."""
    if "master_wallet" not in config:
        raise lib.TestnetError("the tosctl configuration has no master_wallet field")
    current = config["master_wallet"]
    if current is None:
        return "set"
    if current == MASTER_WALLET:
        return "keep"
    # The record may carry key material (tosctl accepts an inline private key or
    # key pair), so the refusal names only the fields that differ and the key's
    # kind, never a value.
    if isinstance(current, dict):
        differ = sorted(
            field
            for field in set(current) | set(MASTER_WALLET)
            if current.get(field) != MASTER_WALLET.get(field)
        )
        kind = key_kind(current.get("key"))
    else:
        differ, kind = ["(not a record)"], "unknown"
    raise lib.TestnetError(
        f"a different master wallet is configured (fields that differ: {', '.join(differ)}; "
        f"key kind: {kind}); expected the vault key master-wallet-secret, V3R2, subwallet 42, "
        "workchain 0; it is never replaced"
    )


def key_kind(key) -> str:
    """The kind of a tosctl KeyConfig, from its shape only (never its contents)."""
    if isinstance(key, dict):
        if set(key) == {"name"}:
            return "vault key"
        if "pvt_key" in key:
            return "inline private key"
        if "pub_key" in key:
            return "public key"
        return "unknown"
    if isinstance(key, str):
        return "inline key pair"
    return "unknown"


def cmd_master_wallet(args: argparse.Namespace) -> None:
    try:
        config = json.loads(args.config.read_text())
    except (OSError, ValueError) as exc:
        raise lib.TestnetError(
            f"cannot read the tosctl configuration {args.config}: {exc}"
        ) from None
    if not isinstance(config, dict):
        raise lib.TestnetError(f"{args.config} is not a tosctl configuration")
    action = master_wallet_action(config)
    if args.require and action != "keep":
        raise lib.TestnetError(f"{args.config} has no master wallet configured")
    print(action)


# A full node serving clients checks its own lite server's submissions and every external the
# network relays to it with the same checkers. Under load the relayed re-checks fill the queue
# and the node refuses its own clients' new messages; a positive priority lets those go first.
# -1 keeps a field's current value.
def submission_priority_options(priority: int) -> dict:
    if not 0 <= priority <= 1000:
        raise lib.TestnetError(f"priority {priority} is outside 0..1000")
    return {
        "max_mempool_messages": -1,
        "num_regular_checkers": -1,
        "num_priority_checkers": -1,
        "max_admission_waiters": -1,
        "max_ext_msg_per_addr": -1,
        "max_ext_msg_per_addr_time_window": -1.0,
        "local_ls_message_priority": priority,
    }


def console_argv(db: Path, port: int, command: str) -> list[str]:
    client_dir = db / "console-client"
    return [
        tool("validator-engine-console"),
        "-a",
        f"{LOOPBACK}:{port}",
        "-k",
        str(client_dir / "client"),
        "-p",
        str(client_dir / "server.pub"),
        "-c",
        command,
        "-t",
        "10",
    ]


def cmd_submission_priority(args: argparse.Namespace) -> None:
    profile = lib.load_profile(args.profile)
    options = submission_priority_options(args.priority)
    deadline = time.monotonic() + args.wait
    with tempfile.TemporaryDirectory(prefix="tos-pool-") as tmp:
        path = Path(tmp) / "ext-message-pool-options.json"
        path.write_text(json.dumps(options) + "\n")
        path.chmod(0o644)
        argv = console_argv(
            args.db, profile["ports"]["console_tcp"], f"set-ext-message-pool-options-json {path}"
        )
        while True:
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
                accepted = result.returncode == 0 and "success" in result.stdout.split()
                detail = (result.stderr.strip() or result.stdout.strip())[-300:]
            except subprocess.TimeoutExpired:
                accepted, detail = False, "the console did not answer within 30 s"
            if accepted:
                break
            if time.monotonic() >= deadline:
                raise lib.TestnetError(f"the console did not accept the pool options: {detail}")
            time.sleep(2)
    print(f"externals submitted to this node's lite server now check at priority {args.priority}")


def cmd_rpc_config(args: argparse.Namespace) -> None:
    try:
        global_config = json.loads(args.global_config.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise lib.TestnetError(f"cannot read {args.global_config}: {exc}") from None
    try:
        public = args.liteserver_pub.read_bytes()
    except OSError as exc:
        raise lib.TestnetError(f"cannot read {args.liteserver_pub}: {exc}") from None
    lib.write_new_json(args.out, rpc_liteserver_config(global_config, public, args.port))
    print(f"wrote {args.out}: tos-rpc trusts the lite server on {LOOPBACK}:{args.port}")


# ---------------------------------------------------------------- onboard (the operator's host)

NANO = 10**9
# init-operator.sh's and enable-elections.sh's rule for NAME.
NODE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
ELECTIONS_UNIT = "tos-testnet-elections.service"
# What the pool keeps for storage (MIN_TOS_FOR_STORAGE in single-nominator-code.fc).
POOL_STORAGE_NANOTOS = NANO
WAIT_ACTIVE_SECONDS = 120
# The pinned single-nominator code (the coordinator derives and checks the pool from
# the same file), in the tos checkout build-tosctl.sh built this host's tosctl from.
SINGLE_NOMINATOR_CODE = Path("crypto/smartcont/single-nominator-pool/single-nominator-code.hex")
DEFAULT_TOS_ROOT = Path("/var/lib/tos-build/tos")


def pinned_pool_code_hash(tos_root: Path) -> bytes:
    path = Path(tos_root) / SINGLE_NOMINATOR_CODE
    try:
        text = path.read_text().strip()
    except OSError as exc:
        raise lib.TestnetError(
            f"cannot read the pinned pool code {path}: pass --tos-root, the tos checkout "
            "at the ceremony commit"
        ) from exc
    return lib.parse_boc(bytes.fromhex(text)).hash()


class NodeReader:
    """Chain reads from this host's own node; nothing is sent through it here."""

    def __init__(self, url: str, rpc=lib.rpc):
        self.url = url
        self.rpc = lib.retrying_reads(rpc)

    def account(self, address: str) -> tuple[str, int]:
        info = self.rpc(self.url, "getAddressInformation", address=address)
        return info["state"], int(info["balance"])

    def pool_roles(self, address: str) -> tuple[str, str]:
        result = self.rpc(self.url, "runGetMethod", address=address, method="get_roles", stack=[])
        return vh.decode_pool_roles(result, address)

    def code_hash(self, address: str) -> bytes | None:
        """The representation hash of the account's code (None without code)."""
        info = self.rpc(self.url, "getAddressInformation", address=address)
        code = info.get("code") or ""
        return lib.parse_boc(base64.b64decode(code)).hash() if code else None


def onboard_host(args: argparse.Namespace, host, reader, profile: dict, sleep=time.sleep) -> dict:
    """The host-side onboarding steps, in order, each decided by what is already there."""
    name = args.name or ""
    if not NODE_NAME.fullmatch(name):
        raise lib.TestnetError("--name must be lower-case letters, digits and dashes")
    pool = lib.check_raw_address(args.pool)
    if not pool.startswith("-1:"):
        raise lib.TestnetError(f"the pool {pool} is not in the masterchain")
    if not args.owner:
        raise lib.TestnetError("--owner is required: the pool owner the coordinator named")
    expected_owner = lib.check_raw_address(args.owner)
    pinned_code = pinned_pool_code_hash(getattr(args, "tos_root", None) or DEFAULT_TOS_ROOT)
    stake = int(profile["elections"]["stake_tos"]) * NANO

    def step(text: str) -> None:
        print(f"== {name}: {text}", flush=True)

    step("operator tool (init-operator.sh)")
    wallet = vh.operator_wallet(
        host.run(f"{vh.SCRIPTS}/init-operator.sh --name {shlex.quote(name)}"), name
    )
    step(f"operator wallet {wallet}")

    step(f"the pool {pool}, read on this node")
    pool_state, pool_balance = reader.account(pool)
    if pool_state != "active":
        raise lib.TestnetError(
            f"the pool is {pool_state} on this node: the coordinator has not deployed it yet, or "
            "this node is not synchronized; rerun after the coordinator's hand-off"
        )
    code_hash = reader.code_hash(pool)
    if code_hash != pinned_code:
        raise lib.TestnetError(
            f"the pool runs code {code_hash.hex() if code_hash else None}, not the pinned "
            f"single-nominator code {pinned_code.hex()}: tell the coordinator (nothing was changed)"
        )
    owner, validator = reader.pool_roles(pool)
    if validator != wallet:
        raise lib.TestnetError(
            f"the pool's validator role is {validator}, not this host's op-{name} {wallet}: "
            "this host cannot stake for it; tell the coordinator (nothing was changed)"
        )
    if owner != expected_owner:
        raise lib.TestnetError(f"the pool's owner is {owner}, not {expected_owner}")
    if pool_balance - POOL_STORAGE_NANOTOS < 2 * stake:
        raise lib.TestnetError(
            f"the pool holds {pool_balance / NANO:.9f} TOS, less than two stakes of "
            f"{stake / NANO:.9f} and its reserve: the coordinator has not sent the principal yet"
        )

    wallet_state, wallet_balance = reader.account(wallet)
    if wallet_state != "active":
        if wallet_balance < ops.ACTIVATION_FEE_NANOTOS:
            raise lib.TestnetError(
                f"op-{name} holds {wallet_balance / NANO:.9f} TOS: the coordinator has not sent "
                f"its fee money yet (fund-op-{name})"
            )
        # No value moves: the wallet deploys itself from its own credit.
        step("activate the operator wallet")
        host.tosctl(f"wallet activate --name op-{name}", 150)
        waited = 0
        while True:
            wallet_state, wallet_balance = reader.account(wallet)
            if wallet_state == "active":
                break
            if waited >= WAIT_ACTIVE_SECONDS:
                raise lib.TestnetError(
                    f"op-{name} did not become active within {WAIT_ACTIVE_SECONDS} s"
                )
            sleep(3)
            waited += 3

    vh.configure_pool(host, name, pool, owner, step)

    step("custody: the node signs for the pool")
    vh.check_custody(host, pool)

    step("election task")
    unit = host.run(f"systemctl is-active {ELECTIONS_UNIT} || true").strip()
    if unit == "active":
        step(f"{ELECTIONS_UNIT} is already running; not restarted")
    else:
        print(host.run(f"{vh.SCRIPTS}/enable-elections.sh --name {shlex.quote(name)}"), end="")
        unit = host.run(f"systemctl is-active {ELECTIONS_UNIT} || true").strip()
    if unit != "active":
        raise lib.TestnetError(
            f"{ELECTIONS_UNIT} is {unit or 'unknown'} after enable-elections.sh; check "
            f"`journalctl -u {ELECTIONS_UNIT}` and rerun"
        )
    return {
        "name": name,
        "operator_wallet": wallet,
        "operator_state": wallet_state,
        "operator_nanotos": wallet_balance,
        "pool": pool,
        "owner": owner,
        "pool_nanotos": pool_balance,
        "custody_validator_id": pool.split(":")[1],
        "elections_unit": unit,
    }


def cmd_onboard(args: argparse.Namespace, host=None, reader=None) -> None:
    if os.geteuid() != 0:
        raise lib.TestnetError("run onboard as root on the validator host")
    profile = lib.load_profile(args.profile)
    url = args.rpc or f"http://127.0.0.1:{profile['ports']['json_rpc_loopback']}/jsonRPC"
    if args.out is not None and (args.out.exists() or args.out.is_symlink()):
        raise lib.TestnetError(f"{args.out} already exists; it is never overwritten")
    result = onboard_host(args, host or vh.LocalHost(), reader or NodeReader(url), profile)
    print(json.dumps(result, indent=2))
    if args.out is not None:
        lib.write_new_json(args.out, result)
        print(f"wrote {args.out}: send it to the coordinator")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", type=Path, default=lib.PROFILE_PATH)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("pregenesis-config")
    p.add_argument("out", type=Path)
    p.set_defaults(func=cmd_pregenesis_config)

    p = sub.add_parser("record")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--seed", type=Path, required=True)
    p.add_argument("--validator-id", required=True, help="the staking account (pool) id")
    p.add_argument("--operator", required=True)
    p.add_argument("--address", required=True, help="<public-ipv4>:<adnl-udp-port>")
    p.add_argument("--out", type=Path)
    p.set_defaults(func=cmd_record)

    p = sub.add_parser("configure")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--role", choices=("validator", "fullnode"), required=True)
    p.add_argument("--client-dir", type=Path, required=True)
    p.set_defaults(func=cmd_configure)

    p = sub.add_parser("submission-priority")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--priority", type=int, default=1)
    p.add_argument("--wait", type=float, default=120.0, help="seconds to wait for the console")
    p.set_defaults(func=cmd_submission_priority)

    p = sub.add_parser("rpc-config")
    p.add_argument("--global-config", type=Path, required=True)
    p.add_argument("--liteserver-pub", type=Path, required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(func=cmd_rpc_config)

    p = sub.add_parser("master-wallet")
    p.add_argument("--config", type=Path, required=True, help="tosctl-config.json")
    p.add_argument("--require", action="store_true", help="refuse unless it is configured")
    p.set_defaults(func=cmd_master_wallet)

    p = sub.add_parser("onboard")
    p.add_argument("--name", required=True, help="the node name (op-NAME, pool-NAME)")
    p.add_argument("--pool", required=True, help="the pool (validator id) as -1:<64 hex>")
    p.add_argument(
        "--owner", required=True, help="the pool owner the coordinator named, checked on chain"
    )
    p.add_argument(
        "--tos-root",
        type=Path,
        default=DEFAULT_TOS_ROOT,
        help="the tos checkout at the ceremony commit (for the pinned pool code)",
    )
    p.add_argument("--rpc", help="this node's JSON-RPC (default: the loopback listener)")
    p.add_argument("--out", type=Path, help="also write the summary here (new file)")
    p.set_defaults(func=cmd_onboard)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except lib.TestnetError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
