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

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except lib.TestnetError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
