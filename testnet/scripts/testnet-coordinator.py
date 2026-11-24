#!/usr/bin/env python3
"""The coordinator's side of the public testnet genesis ceremony.

Every output is public except main-wallet.pk, and nothing is ever overwritten:
a ceremony that has to change an input starts again in a new directory.
wallets.json (wallet label -> public key or address) is only ever extended:
testnet-elections.py adds the operator and load-test wallets to it, and a
later reset reads it through --previous-ceremony to refuse reused wallet keys.

  plan --external-validators E [--write FILE]
      Print what the profile's election parameters imply for E external
      validators (testnet_lib.election_plan): the team stake multiple and
      stake, every pool's principal and funding, the bootstrap wallet, the
      genesis supply and the resulting weight split, after checking that a
      team-only election concludes and that E external pools are all elected
      with the team's stakes counted in full. Refused when no such plan
      exists. The ceremony copies elections.external_validators,
      elections.team_stake_multiple, elections.bootstrap_wallet_tos and
      genesis.total_supply_tos from it into the profile; --write FILE writes
      a copy of the profile with them set (a new file only).

  manifest --ceremony DIR --tos-root DIR [--previous FILE ...]
           [--external RECORD ...] RECORD [RECORD ...]
      Check the operator records (testnet-operator.py record): the positional
      ones are the genesis set, exactly genesis.validators of them in
      validator index order (the team's validators); each --external one is
      a registered external validator, exactly elections.external_validators
      of them, which stands from the first election and is not in the zero
      state. Pack validator-pq.pub from the genesis set: with tos
      scripts/prepare-pq-genesis-manifest.py checked against an independent
      packing when the set is four records, which is all that packer takes,
      and otherwise with the independent packing alone (genesis reads the
      set back from the zero state either way). DIR holds only what
      `testnet-elections.py pool` wrote before it (pools.json, wallets.json,
      the pool owners' public files and keys), and the records' validator ids
      must be exactly the staking pools recorded there. Writes
      genesis-set.json (the genesis set) and genesis-records.json (every
      registered record, the genesis set first): onboarding accepts a pool
      genesis-records.json names, and stakes a team multiple for one in
      genesis-set.json. No two records may share an identity or a host. After
      a reset, pass every earlier epoch's genesis-records.json with
      --previous: all epochs share global id 2, so no validator id, consensus
      key id or ADNL id may be reused. Wallet keys are checked by genesis,
      onboard and load (--previous-ceremony).

  genesis --ceremony DIR --tos-root DIR --tos-build DIR --epoch UNIX_SECONDS
          [--previous-ceremony DIR ...]
      Copy the canonical template gen-zerostate.fif, replace only its mainnet
      global id and genesis epoch and the profile's validator schedule
      (ConfigParam 15 and the initial set's lifetime), define the AUTH
      network tag (testnet_lib.patch_template), replace the genesis set size,
      ConfigParam 16 and 17 and the bootstrap balance with the profile's
      (testnet_lib.patch_genesis_set; refused until the ceremony has set
      elections.external_validators and the plan values), and run create-state with
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
      It also refuses unless ConfigParam 5 names the blackhole -1:ff...ff,
      burns no fees (0/1) and is critical; the bootstrap wallet -1:111...1 holds
      exactly elections.bootstrap_wallet_tos and the state exactly
      genesis.total_supply_tos (the wallet plus the Elector's and the Config
      contract's 500 TOS each), the balances adding up; and ConfigParam 15 read
      from the state is the profile's schedule; and ConfigParam 16 and 17 are
      the profile's limits and the validator set is exactly the genesis set
      of genesis-set.json, in order, all main validators of equal weight.
      Writes genesis.json (with
      main_wallet_public_key, auth_policy: the tag, its rule and the ConfigParam
      48 cell hash, and bootstrap: the ConfigParam 5 cell hash, the blackhole and
      the balances), main-wallet.pub and wallets.json.

  global-config --ceremony DIR DHT_NODE.json [DHT_NODE.json ...]
      Build global-config.json from the zero state and the signed DHT records
      (testnet-dht.py prepare), and its SHA-256.

The epoch is the chain's genesis time: blocks cannot be produced before it,
and the genesis validators are authorized for the profile's
genesis.initial_set_valid_for_seconds after it. Choose
it so that the genesis set's nodes are installed and started before it, and announce it.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
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


# The genesis set size tos scripts/prepare-pq-genesis-manifest.py packs.
TOS_PACKER_RECORDS = 4

# What `testnet-elections.py pool` writes into the ceremony before the manifest.
STAKING_ENTRIES = {"pools.json", "wallets.json", ".wallets.json.lock", "pool-owners", "secret"}
STAKING_SECRET = re.compile(r"^pool-owner-[A-Za-z0-9_-]+\.pk$")


def staking_ceremony(path: Path) -> Path:
    """The ceremony directory holding only the staking-account outputs, if any."""
    path = Path(path)
    if not path.exists():
        return lib.empty_dir(path)
    extra = sorted(e.name for e in path.iterdir() if e.name not in STAKING_ENTRIES)
    secret = path / "secret"
    if secret.is_dir():
        extra += sorted(
            f"secret/{e.name}" for e in secret.iterdir() if not STAKING_SECRET.match(e.name)
        )
    if extra:
        raise lib.TestnetError(
            f"{path} holds {extra}; only the outputs of `testnet-elections.py pool` may "
            "precede the manifest, so use a new directory"
        )
    return lib.private_dir(path)


def recorded_staking_accounts(ceremony: Path) -> set[str]:
    """The validator ids (account hex) of the pools `testnet-elections.py pool` recorded."""
    path = Path(ceremony) / "pools.json"
    pools = json.loads(path.read_text()) if path.is_file() else {}
    return {
        str(entry["pool"]).split(":")[1].lower()
        for entry in pools.values()
        if isinstance(entry, dict) and str(entry.get("pool", "")).startswith("-1:")
    }


def cmd_plan(args: argparse.Namespace) -> None:
    profile = lib.load_profile(args.profile)
    plan = lib.election_plan(profile, external=args.external_validators)
    settings = {
        "elections.external_validators": plan["external_validators"],
        "elections.team_stake_multiple": plan["team_stake_multiple"],
        "elections.bootstrap_wallet_tos": plan["bootstrap_wallet_tos"],
        "genesis.total_supply_tos": plan["total_supply_tos"],
    }
    print(json.dumps({"plan": plan, "set_in_profile": settings}, indent=2))
    if args.write:
        planned = json.loads(Path(args.profile).read_text())
        for dotted, value in settings.items():
            section, key = dotted.split(".")
            planned[section][key] = value
        # The written profile must load and pass the same check before it is used.
        lib.write_new_json(args.write, planned)
        lib.load_profile(args.write)
        lib.election_plan(lib.load_profile(args.write))
        print(f"wrote {args.write}")


def cmd_manifest(args: argparse.Namespace) -> None:
    profile = lib.load_profile(args.profile)
    limits = lib.genesis_limits(profile)
    plan = lib.election_plan(profile)
    ceremony = staking_ceremony(args.ceremony)
    genesis_set = [json.loads(Path(p).read_text()) for p in args.records]
    external = [json.loads(Path(p).read_text()) for p in args.external]
    if len(genesis_set) != limits["validators"]:
        raise lib.TestnetError(
            f"the genesis set is genesis.validators = {limits['validators']} records, "
            f"not {len(genesis_set)}"
        )
    if len(external) != plan["external_validators"]:
        raise lib.TestnetError(
            f"the profile registers {plan['external_validators']} external validators "
            f"(elections.external_validators), not the {len(external)} --external records given"
        )
    # One check over every registered record: no identity or host is shared
    # between the genesis set and the external validators either.
    records = lib.check_operator_set(genesis_set + external)
    genesis_set = records[: len(genesis_set)]
    staking = recorded_staking_accounts(ceremony)
    for record in records:
        if record["validator_id"] not in staking:
            raise lib.TestnetError(
                f"{record['operator']} names validator id {record['validator_id']}, which is "
                "no staking pool `testnet-elections.py pool` recorded in this ceremony"
            )
    unnamed = staking - {r["validator_id"] for r in records}
    if unnamed:
        raise lib.TestnetError(
            f"pools.json records pools no record names: {sorted(v[:16] for v in unnamed)}; "
            "every recorded pool must be a registered validator"
        )
    previous = [json.loads(Path(p).read_text()) for p in args.previous]
    lib.check_fresh_identities(records, previous)
    lib.write_new_json(ceremony / "operators.json", lib.manifest_input(genesis_set))
    lib.write_new_json(ceremony / "genesis-set.json", genesis_set)
    lib.write_new_json(ceremony / "genesis-records.json", records)
    independent = lib.pack_manifest(genesis_set)
    if len(genesis_set) == TOS_PACKER_RECORDS:
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
        if packed != independent:
            raise lib.TestnetError("the tos packer and the independent packing disagree")
    else:
        # The tos packer accepts exactly four records. Another genesis set is packed
        # here only; genesis then reads the validator set back from the zero state
        # and refuses unless it is exactly these records in this order.
        lib.write_new(ceremony / "validator-pq.pub", independent)
    for index, record in enumerate(genesis_set):
        print(
            f"validator {index}: {record['operator']} key_id {record['key_id']} at {record['address']}"
        )
    for record in records[len(genesis_set) :]:
        print(
            f"external (from the first election): {record['operator']} validator id "
            f"{record['validator_id']} at {record['address']}"
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
    # create-state runs inside run_dir, so a path relative to the caller's
    # directory (`--ceremony ./ceremony`) would name nothing there.
    run_dir, script = run_dir.resolve(), script.resolve()
    args = argparse.Namespace(
        **{**vars(args), "tos_build": args.tos_build.resolve(), "tos_root": args.tos_root.resolve()}
    )
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
    limits = lib.genesis_limits(profile)
    plan = lib.election_plan(profile)
    if not (ceremony / "genesis-set.json").is_file():
        raise lib.TestnetError("genesis-set.json is missing; run the manifest step first")
    genesis_set = lib.check_operator_set(
        json.loads((ceremony / "genesis-set.json").read_text()), limits["validators"]
    )
    revision = tos_revision(args.tos_root)
    template = args.tos_root / profile["genesis"]["template"]
    original = template.read_text()
    schedule = lib.validator_schedule(profile)
    patched = lib.patch_genesis_set(
        lib.patch_template(original, global_id, args.epoch, schedule, auth_tag),
        limits,
        plan["bootstrap_wallet_tos"],
    )

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
    lib.zero_state_retired_params((built / "zerostate.boc").read_bytes())
    auth = lib.zero_state_auth_policy(
        (built / "zerostate.boc").read_bytes(),
        rhash,
        global_id,
        profile["genesis"]["global_version"],
        auth_tag,
    )
    auth["network_tag_rule"] = auth_entry["rule"]
    auth["network_tag_status"] = auth_entry["status"]
    wallet_nanotos, total_nanotos = lib.genesis_supply_targets(profile)
    bootstrap_check = lib.zero_state_bootstrap(
        (built / "zerostate.boc").read_bytes(), wallet_nanotos, total_nanotos, schedule
    )
    genesis_set_check = lib.check_zero_state_genesis_set(
        (built / "zerostate.boc").read_bytes(), limits, genesis_set
    )
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
        "bootstrap": bootstrap_check,
        "genesis_set": genesis_set_check,
        "election_plan": plan,
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
                *lib.GENESIS_SET_REPLACED,
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

    p = sub.add_parser("plan")
    p.add_argument("--external-validators", type=int, required=True)
    p.add_argument("--write", type=Path)
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("manifest")
    p.add_argument("--ceremony", type=Path, required=True)
    p.add_argument("--tos-root", type=Path, required=True)
    p.add_argument(
        "--external",
        type=Path,
        action="append",
        default=[],
        help="an external validator's record (repeat for each): registered before genesis, "
        "not in the zero state, elected from the first election",
    )
    p.add_argument(
        "--previous",
        type=Path,
        action="append",
        default=[],
        help="genesis-records.json of an earlier testnet epoch (repeat for each); a reset "
        "genesis must reuse none of their identities",
    )
    p.add_argument("records", nargs="+", help="the genesis set's records, in index order")
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
