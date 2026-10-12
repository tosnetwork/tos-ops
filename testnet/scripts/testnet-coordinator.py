#!/usr/bin/env python3
"""The coordinator's side of the public testnet genesis ceremony.

Every output is public except main-wallet.pk, and nothing is ever overwritten:
a ceremony that has to change an input starts again in a new directory.

  manifest --ceremony DIR --tos-root DIR RECORD RECORD RECORD RECORD
      Check the four operator records (testnet-operator.py record) and pack
      validator-pq.pub with tos scripts/prepare-pq-genesis-manifest.py. The
      record order is the validator index order. The packed bytes are checked
      against an independent packing of the same records.

  genesis --ceremony DIR --tos-root DIR --tos-build DIR --epoch UNIX_SECONDS
      Copy the canonical template gen-zerostate.fif, replace only its mainnet
      global id and genesis epoch (testnet_lib.patch_template), and run
      create-state with SOURCE_DATE_EPOCH. Then run it a second time in a
      separate directory with the same inputs and the same main wallet key,
      and refuse unless every output is byte-identical. Writes genesis.json.

  global-config --ceremony DIR DHT_NODE.json [DHT_NODE.json ...]
      Build global-config.json from the zero state and the signed DHT records
      (testnet-dht.py prepare), and its SHA-256.

The epoch is the chain's genesis time: blocks cannot be produced before it,
and the four genesis validators are authorized for 131,072 s after it. Choose
it so that the four nodes are installed and started before it, and announce it.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

OUTPUTS = (
    "zerostate.boc",
    "zerostate.rhash",
    "zerostate.fhash",
    "basestate0.boc",
    "basestate0.rhash",
    "basestate0.fhash",
    "main-wallet.addr",
    "elector.addr",
    "config-master.addr",
)
MAX_EPOCH_AHEAD = 14 * 86400
MAX_EPOCH_BEHIND = 3600


def cmd_manifest(args: argparse.Namespace) -> None:
    ceremony = lib.empty_dir(args.ceremony)
    records = lib.check_operator_set([json.loads(Path(p).read_text()) for p in args.records])
    lib.write_new_json(ceremony / "operators.json", lib.manifest_input(records))
    lib.write_new_json(ceremony / "genesis-records.json", records)
    packer = args.tos_root / "scripts/prepare-pq-genesis-manifest.py"
    lib.run(
        [
            sys.executable,
            str(packer),
            str(ceremony / "operators.json"),
            str(ceremony / "validator-pq.pub"),
        ]
    )
    packed = (ceremony / "validator-pq.pub").read_bytes()
    if packed != lib.pack_manifest(records):
        raise lib.TestnetError("the tos packer and the independent packing disagree")
    for index, record in enumerate(records):
        print(
            f"validator {index}: {record['operator']} key_id {record['key_id']} at {record['address']}"
        )
    print(f"validator-pq.pub sha256 {lib.sha256_file(ceremony / 'validator-pq.pub')}")


def tos_revision(tos_root: Path) -> str:
    try:
        head = subprocess.run(
            ["git", "-C", str(tos_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(tos_root), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise lib.TestnetError(f"cannot read the tos revision: {exc}") from exc
    if dirty:
        raise lib.TestnetError(
            "the tos checkout has uncommitted changes; a ceremony runs from a commit"
        )
    return head


def create_state(run_dir: Path, args: argparse.Namespace, script: Path) -> str:
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(args.epoch))
    result = subprocess.run(
        [
            str(args.tos_build / "crypto/create-state"),
            "-I",
            str(args.tos_root / "crypto/fift/lib"),
            "-I",
            str(args.tos_build / "crypto/smartcont"),
            "-I",
            str(args.tos_root / "crypto/smartcont"),
            "-s",
            str(script),
        ],
        cwd=run_dir,
        env=env,
        capture_output=True,
        text=True,
    )
    (run_dir / "create-state.log").write_text(result.stdout + result.stderr)
    if result.returncode != 0:
        raise lib.TestnetError(f"create-state failed in {run_dir}; see create-state.log")
    return result.stdout


def cmd_genesis(args: argparse.Namespace) -> None:
    profile = lib.load_profile(args.profile)
    global_id = lib.confirmed_global_id(profile)
    ceremony = args.ceremony
    manifest = ceremony / "validator-pq.pub"
    if not manifest.is_file():
        raise lib.TestnetError(f"{manifest} is missing; run the manifest step first")
    if (ceremony / "genesis.json").exists():
        raise lib.TestnetError(
            "this ceremony already has a genesis; start a new ceremony directory"
        )
    now = int(time.time())
    if args.epoch < now - MAX_EPOCH_BEHIND or args.epoch > now + MAX_EPOCH_AHEAD:
        raise lib.TestnetError(
            "the epoch must lie between one hour ago and fourteen days ahead; "
            "an old epoch leaves the initial set expired before the first election"
        )
    revision = tos_revision(args.tos_root)
    template = args.tos_root / profile["genesis"]["template"]
    original = template.read_text()
    patched = lib.patch_template(original, global_id, args.epoch)

    runs = [ceremony / "run-a", ceremony / "run-b"]
    for run_dir in runs:
        lib.empty_dir(run_dir)
        shutil.copyfile(manifest, run_dir / "validator-pq.pub")
        lib.write_new(run_dir / "gen-zerostate-testnet.fif", patched.encode())
    stdout = create_state(runs[0], args, runs[0] / "gen-zerostate-testnet.fif")
    wallet_key = runs[0] / "main-wallet.pk"
    if not wallet_key.is_file():
        raise lib.TestnetError("create-state did not write main-wallet.pk")
    os.chmod(wallet_key, 0o600)
    lib.write_new(runs[1] / "main-wallet.pk", wallet_key.read_bytes(), 0o600)
    create_state(runs[1], args, runs[1] / "gen-zerostate-testnet.fif")
    for name in OUTPUTS:
        a, b = runs[0] / name, runs[1] / name
        if not a.is_file() or a.read_bytes() != b.read_bytes():
            raise lib.TestnetError(f"{name} differs between two runs with the same inputs")

    secret = lib.private_dir(ceremony / "secret")
    os.replace(wallet_key, secret / "main-wallet.pk")
    os.remove(runs[1] / "main-wallet.pk")
    for name in OUTPUTS:
        shutil.copyfile(runs[0] / name, ceremony / name)
    lib.write_new(ceremony / "gen-zerostate-testnet.fif", patched.encode())

    rhash = (ceremony / "zerostate.rhash").read_bytes()
    fhash = (ceremony / "zerostate.fhash").read_bytes()
    valid_for = profile["genesis"]["initial_set_valid_for_seconds"]
    utc = datetime.timezone.utc
    summary = {
        "network": profile["network"],
        "global_id": global_id,
        "global_version": profile["genesis"]["global_version"],
        "source_date_epoch": args.epoch,
        "genesis_utc": datetime.datetime.fromtimestamp(args.epoch, utc).isoformat(),
        "initial_set_valid_until_utc": datetime.datetime.fromtimestamp(
            args.epoch + valid_for, utc
        ).isoformat(),
        "zero_state": lib.zero_state_entry(rhash, fhash),
        "zero_state_hex": {"root_hash": rhash.hex(), "file_hash": fhash.hex()},
        "basestate0_hex": {
            "root_hash": (ceremony / "basestate0.rhash").read_bytes().hex(),
            "file_hash": (ceremony / "basestate0.fhash").read_bytes().hex(),
        },
        "sha256": {
            name: lib.sha256_file(ceremony / name)
            for name in (
                "validator-pq.pub",
                "zerostate.boc",
                "basestate0.boc",
                "gen-zerostate-testnet.fif",
            )
        },
        "template": {
            "path": profile["genesis"]["template"],
            "sha256": lib.sha256_file(template),
            "replaced": ["global id", "genesis epoch", "genesis epoch check"],
        },
        "tos_revision": revision,
        "create_state_sha256": lib.sha256_file(args.tos_build / "crypto/create-state"),
        "reproduced": "two independent create-state runs produced identical outputs",
    }
    lib.write_new_json(ceremony / "genesis.json", summary)
    (ceremony / "create-state.out").write_text(stdout)
    print(json.dumps(summary, indent=2))
    print(
        f"main-wallet.pk is the only secret output: {secret / 'main-wallet.pk'} (0600). Move it offline."
    )


def cmd_global_config(args: argparse.Namespace) -> None:
    profile = lib.load_profile(args.profile)
    genesis = json.loads((args.ceremony / "genesis.json").read_text())
    nodes = [json.loads(Path(p).read_text()) for p in args.dht_nodes]
    config = lib.global_config(genesis["zero_state"], nodes, profile)
    out = args.ceremony / "global-config.json"
    lib.write_new_json(out, config)
    digest = lib.sha256_file(out)
    lib.write_new(
        args.ceremony / "global-config.json.sha256", f"{digest}  global-config.json\n".encode()
    )
    print(f"global-config.json sha256 {digest}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", type=Path, default=lib.PROFILE_PATH)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("manifest")
    p.add_argument("--ceremony", type=Path, required=True)
    p.add_argument("--tos-root", type=Path, required=True)
    p.add_argument("records", nargs=4)
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("genesis")
    p.add_argument("--ceremony", type=Path, required=True)
    p.add_argument("--tos-root", type=Path, required=True)
    p.add_argument("--tos-build", type=Path, required=True)
    p.add_argument("--epoch", type=int, required=True)
    p.set_defaults(func=cmd_genesis)

    p = sub.add_parser("global-config")
    p.add_argument("--ceremony", type=Path, required=True)
    p.add_argument("dht_nodes", nargs="+")
    p.set_defaults(func=cmd_global_config)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except lib.TestnetError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
