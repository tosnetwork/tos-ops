#!/usr/bin/env python3
"""Prepare a DHT bootstrap host and print its signed public record.

  testnet-dht.py prepare --db /var/lib/tos/dht --ip <public-ipv4> [--port 30300] --out dht-node.json

dht-server cannot create its own identity before the network exists: it parses
the global config first, and the global config's static DHT nodes are exactly
what this produces. So the key and config.json are made here, the same way the
tos test harness makes them:

  * generate-random-id -m keys creates an Ed25519 key; its ADNL id is the
    SHA-256 of the public key's TL object, and the private key goes into
    <db>/keyring/<ID HEX> (the engine keyring format, mode 0600);
  * config.json announces <ip>:<port> in category 0 and serves DHT with that id;
  * generate-random-id -m dht -k <keyring file> signs the address list, giving
    the dht.node record the coordinator puts into the global config.

Run it as the service account (sudo -u tos) so the keyring belongs to the
process that reads it. The output record is public.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

BIN = Path(os.environ.get("TOS_BIN", "/usr/local/bin"))


def prepare(db: Path, ip: str, port: int, network_id: int) -> dict:
    lib.require_public_ipv4(ip)
    if not 0 < port < 65536:
        raise lib.TestnetError(f"bad port {port}")
    if (db / "config.json").exists():
        raise lib.TestnetError(f"{db}/config.json exists; this DHT identity was already prepared")
    lib.private_dir(db)
    keyring = lib.private_dir(db / "keyring")
    generator = BIN / "generate-random-id"
    if not os.access(generator, os.X_OK):
        raise lib.TestnetError(f"{generator} is not executable; set TOS_BIN")
    with tempfile.TemporaryDirectory(prefix="tos-dht-") as tmp:
        lib.run([str(generator), "-m", "keys", "-n", f"{tmp}/dht"])
        private = Path(tmp, "dht").read_bytes()
        public = Path(tmp, "dht.pub").read_bytes()
    if len(private) != 36 or not private.startswith(lib.ED25519_PRIVATE_TL_PREFIX):
        raise lib.TestnetError("unexpected private key format from generate-random-id")
    if len(public) != 36 or not public.startswith(lib.ED25519_PUBLIC_TL_PREFIX):
        raise lib.TestnetError("unexpected public key format from generate-random-id")
    short_id = lib.adnl_short_id(public[4:])
    key_file = keyring / short_id.hex().upper()
    lib.write_new(key_file, private, 0o600)
    signed = lib.run(
        [
            str(generator),
            "-m",
            "dht",
            "-k",
            str(key_file),
            "-i",
            str(network_id),
            "-a",
            json.dumps(lib.address_list(ip, port)),
        ]
    )
    node = lib.check_dht_node(json.loads(signed.stdout))
    if lib.parse_b64(node["id"]["key"], 32, "DHT public key") != public[4:]:
        raise lib.TestnetError("the signed record names a different key than the keyring holds")
    config = {
        "@type": "engine.validator.config",
        "out_port": 3278,
        "addrs": [
            {
                "@type": "engine.addr",
                "ip": lib.ip_to_tl(ip),
                "port": port,
                "categories": [0],
                "priority_categories": [],
            }
        ],
        "adnl": [{"@type": "engine.adnl", "id": lib.b64(short_id), "category": 0}],
        "dht": [{"@type": "engine.dht", "id": lib.b64(short_id)}],
        "validators": [],
        "collators": [],
        "fullnode": lib.b64(bytes(32)),
        "fullnodeslaves": [],
        "fullnodemasters": [],
        "liteservers": [],
        "control": [],
        "shards_to_monitor": [],
        "gc": {"@type": "engine.gc", "ids": []},
    }
    lib.write_new_json(db / "config.json", config, 0o600)
    return node


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", type=Path, default=lib.PROFILE_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int)
    p.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        profile = lib.load_profile(args.profile)
        port = args.port or profile["ports"]["dht_udp"]
        node = prepare(args.db, args.ip, port, profile["dht"]["network_id"])
        lib.write_new_json(args.out, node)
    except lib.TestnetError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(
        f"DHT identity {lib.adnl_short_id(lib.parse_b64(node['id']['key'], 32, 'key')).hex()} at {args.ip}:{port}"
    )
    print(f"send {args.out} to the coordinator")
    return 0


if __name__ == "__main__":
    sys.exit(main())
