#!/usr/bin/env python3
"""The coordinator's side of the public testnet genesis ceremony.

Every output is public except main-wallet.pk, and nothing is ever overwritten:
a ceremony that has to change an input starts again in a new directory.
wallets.json (wallet label -> public key or address) is only ever extended:
testnet-elections.py adds the operator and load-test wallets to it, and a
later reset reads it through --previous-ceremony to refuse reused wallet keys.

  manifest --ceremony DIR --tos-root DIR [--previous FILE ...] RECORD RECORD RECORD RECORD
      Check the four operator records (testnet-operator.py record) and pack
      validator-pq.pub with tos scripts/prepare-pq-genesis-manifest.py. The
      record order is the validator index order. The packed bytes are checked
      against an independent packing of the same records. After a reset, pass
      every earlier epoch's genesis-records.json with --previous: all epochs
      share global id 2, so no controller id, consensus key id or ADNL id may
      be reused. Wallet keys are checked by genesis, onboard and load
      (--previous-ceremony).

  genesis --ceremony DIR --tos-root DIR --tos-build DIR --epoch UNIX_SECONDS
          [--previous-ceremony DIR ...]
      Copy the canonical template gen-zerostate.fif, replace only its mainnet
      global id and genesis epoch and the profile's validator schedule
      (ConfigParam 15 and the initial set's lifetime), define the AUTH
      network tag (testnet_lib.patch_template), and run create-state with
      SOURCE_DATE_EPOCH. The tag comes from TOS_AUTH_NETWORK_TAG (64
      hexadecimal digits, as tos tooling takes it) and must equal the
      profile's genesis.auth_network_tag, which is SHA-256 of its rule; a
      tag an earlier epoch's genesis.json recorded is refused. The bootstrap wallet's public key
      is derived from the new main-wallet.pk and, after a reset, checked
      against every earlier epoch's ceremony directory given with
      --previous-ceremony (repeat for each): the bootstrap wallet sits at the
      fixed address -1:111...1 on every epoch, so only a fresh key keeps a
      transfer signed on an earlier epoch from replaying on this one. Then
      create-state runs a second time in a separate directory with the same
      inputs and the same main wallet key, and the step refuses unless every
      output is byte-identical. Then it reads the zero state back (after
      checking its parser against create-state's root hash) and refuses
      unless ConfigParam 8 is the profile's version, ConfigParam 48 is the
      initial AUTH policy for this tag and 48 is in both ConfigParam 9
      (mandatory) and 10 (critical), as the node requires from version 16.
      Writes genesis.json (with main_wallet_public_key and auth_policy: the
      tag, its rule and the ConfigParam 48 cell hash), main-wallet.pub and
      wallets.json.

  global-config --ceremony DIR DHT_NODE.json [DHT_NODE.json ...]
      Build global-config.json from the zero state and the signed DHT records
      (testnet-dht.py prepare), and its SHA-256.

The epoch is the chain's genesis time: blocks cannot be produced before it,
and the four genesis validators are authorized for the profile's
genesis.initial_set_valid_for_seconds after it. Choose
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
# What a genesis publishes into the ceremony directory (genesis.json last).
GENESIS_PUBLISHED = OUTPUTS + (
    "gen-zerostate-testnet.fif",
    "main-wallet.pub",
    "create-state.out",
    "secret/main-wallet.pk",
)
MAX_EPOCH_AHEAD = 14 * 86400
MAX_EPOCH_BEHIND = 3600


def cmd_manifest(args: argparse.Namespace) -> None:
    ceremony = lib.empty_dir(args.ceremony)
    records = lib.check_operator_set([json.loads(Path(p).read_text()) for p in args.records])
    previous = [json.loads(Path(p).read_text()) for p in args.previous]
    lib.check_fresh_identities(records, previous)
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


def wallet_key_deriver(args: argparse.Namespace):
    """Derive a wallet private key file's public key with this build's fift."""
    fift = args.tos_build / "crypto/fift"
    fift_lib = args.tos_root / "crypto/fift/lib"
    return lambda key: lib.wallet_public_key(fift, fift_lib, key)


def cmd_genesis(args: argparse.Namespace) -> None:
    profile = lib.load_profile(args.profile)
    global_id = lib.confirmed_global_id(profile)
    ceremony = args.ceremony
    derive_public = wallet_key_deriver(args)
    previous = [lib.previous_wallets(d, derive_public) for d in args.previous_ceremony]
    manifest = ceremony / "validator-pq.pub"
    if not manifest.is_file():
        raise lib.TestnetError(f"{manifest} is missing; run the manifest step first")
    if (ceremony / "genesis.json").exists():
        raise lib.TestnetError(
            "this ceremony already has a genesis; start a new ceremony directory"
        )
    # A genesis that stopped while publishing leaves some of these and no
    # genesis.json; a rerun would overwrite the saved key. Refuse it outright.
    leftover = [name for name in GENESIS_PUBLISHED if (ceremony / name).exists()]
    if leftover:
        raise lib.TestnetError(
            f"an earlier genesis attempt published {', '.join(leftover)}; nothing is "
            "overwritten: start a new ceremony directory"
        )
    now = int(time.time())
    if args.epoch < now - MAX_EPOCH_BEHIND or args.epoch > now + MAX_EPOCH_AHEAD:
        raise lib.TestnetError(
            "the epoch must lie between one hour ago and fourteen days ahead; "
            "an old epoch leaves the initial set expired before the first election"
        )
    auth_tag = lib.supplied_auth_network_tag(profile, os.environ)
    auth_entry = lib.profile_auth_network_tag(profile)
    for earlier in args.previous_ceremony:
        recorded = previous_auth_tag(earlier)
        if recorded == auth_tag:
            raise lib.TestnetError(
                f"{earlier} already used AUTH network tag {auth_tag.hex()}; every epoch needs its own"
            )
    revision = tos_revision(args.tos_root)
    template = args.tos_root / profile["genesis"]["template"]
    original = template.read_text()
    schedule = lib.validator_schedule(profile)
    patched = lib.patch_template(original, global_id, args.epoch, schedule, auth_tag)

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
    # Before the key is used again or anything is published.
    main_public = derive_public(wallet_key)
    bootstrap = {lib.BOOTSTRAP_WALLET_LABEL: lib.WALLET_PUBKEY_PREFIX + main_public.hex()}
    lib.check_fresh_wallets(bootstrap, previous)
    lib.write_new(runs[1] / "main-wallet.pk", wallet_key.read_bytes(), 0o600)
    create_state(runs[1], args, runs[1] / "gen-zerostate-testnet.fif")
    for name in OUTPUTS:
        a, b = runs[0] / name, runs[1] / name
        if not a.is_file() or a.read_bytes() != b.read_bytes():
            raise lib.TestnetError(f"{name} differs between two runs with the same inputs")

    # Everything is validated and the summary built from run-a, before anything
    # is moved or published.
    built = runs[0]
    rhash = (built / "zerostate.rhash").read_bytes()
    fhash = (built / "zerostate.fhash").read_bytes()
    lib.zero_state_gas_credits((built / "zerostate.boc").read_bytes())
    auth = lib.zero_state_auth_policy(
        (built / "zerostate.boc").read_bytes(),
        rhash,
        global_id,
        profile["genesis"]["global_version"],
        auth_tag,
    )
    auth["network_tag_rule"] = auth_entry["rule"]
    auth["network_tag_status"] = auth_entry["status"]
    valid_for = schedule["initial_set_valid_for"]
    utc = datetime.timezone.utc

    def at(seconds: int) -> str:
        return datetime.datetime.fromtimestamp(args.epoch + seconds, utc).isoformat()

    summary = {
        "network": profile["network"],
        "global_id": global_id,
        "global_version": profile["genesis"]["global_version"],
        "source_date_epoch": args.epoch,
        "genesis_utc": at(0),
        "initial_set_valid_until_utc": at(valid_for),
        "election_params": {name: schedule[name] for name in lib.ELECTION_PARAM_NAMES},
        "first_election": {
            "opens_utc": at(valid_for - schedule["elections_start_before"]),
            "closes_utc": at(valid_for - schedule["elections_end_before"]),
            "set_takes_office_utc": at(valid_for),
        },
        "main_wallet_public_key": main_public.hex(),
        "auth_policy": auth,
        "zero_state": lib.zero_state_entry(rhash, fhash),
        "zero_state_hex": {"root_hash": rhash.hex(), "file_hash": fhash.hex()},
        "basestate0_hex": {
            "root_hash": (built / "basestate0.rhash").read_bytes().hex(),
            "file_hash": (built / "basestate0.fhash").read_bytes().hex(),
        },
        "sha256": {
            # run-a holds byte-identical copies of the manifest and the script.
            name: lib.sha256_file(built / name)
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
            "replaced": [
                "global id",
                "genesis epoch",
                "genesis epoch check",
                "election params",
                "initial set lifetime",
                "AUTH network tag (inserted after the first line)",
            ],
        },
        "tos_revision": revision,
        "create_state_sha256": lib.sha256_file(args.tos_build / "crypto/create-state"),
        "reproduced": "two independent create-state runs produced identical outputs",
    }

    # Publication: never overwrites (each target was checked absent above and is
    # written with write_new); genesis.json, written last, marks it complete.
    secret = lib.private_dir(ceremony / "secret")
    try:
        os.link(wallet_key, secret / "main-wallet.pk")
    except FileExistsError as exc:
        raise lib.TestnetError(
            f"{secret / 'main-wallet.pk'} exists; nothing is overwritten"
        ) from exc
    os.remove(wallet_key)
    os.remove(runs[1] / "main-wallet.pk")
    for name in OUTPUTS:
        lib.write_new(ceremony / name, (built / name).read_bytes())
    lib.write_new(ceremony / "gen-zerostate-testnet.fif", patched.encode())
    lib.write_new(ceremony / "main-wallet.pub", main_public)
    lib.write_new(ceremony / "create-state.out", stdout.encode())
    lib.record_wallets(ceremony, bootstrap)
    lib.write_new_json(ceremony / "genesis.json", summary)
    print(json.dumps(summary, indent=2))
    print(
        f"main-wallet.pk is the only secret output: {secret / 'main-wallet.pk'} (0600). Move it offline."
    )


def previous_auth_tag(ceremony: Path) -> bytes | None:
    """The AUTH network tag an earlier epoch's genesis.json recorded, if it had one."""
    path = Path(ceremony) / "genesis.json"
    if not path.is_file():
        # Refused by previous_wallets unless the directory records a wallet.
        return None
    recorded = json.loads(path.read_text()).get("auth_policy", {}).get("network_tag_hex")
    return None if recorded is None else bytes.fromhex(recorded)


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
    p.add_argument(
        "--previous",
        type=Path,
        action="append",
        default=[],
        help="genesis-records.json of an earlier testnet epoch (repeat for each); a reset "
        "genesis must reuse none of their identities",
    )
    p.add_argument("records", nargs=4)
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("genesis")
    p.add_argument("--ceremony", type=Path, required=True)
    p.add_argument("--tos-root", type=Path, required=True)
    p.add_argument("--tos-build", type=Path, required=True)
    p.add_argument("--epoch", type=int, required=True)
    p.add_argument(
        "--previous-ceremony",
        type=Path,
        action="append",
        default=[],
        help="ceremony directory of an earlier testnet epoch (repeat for each); the bootstrap "
        "wallet key must be fresh",
    )
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
