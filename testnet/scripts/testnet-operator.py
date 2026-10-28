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

Nothing here generates or reads a wallet key.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

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
    raise lib.TestnetError(
        f"a different master wallet is configured ({json.dumps(current, sort_keys=True)}), "
        f"not {json.dumps(MASTER_WALLET, sort_keys=True)}; it is never replaced"
    )


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

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except lib.TestnetError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
