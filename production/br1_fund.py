"""One fixed Epoch-6 pilot initialization, using the existing PRI journal/transport.

No bootstrap faucet, refill, arbitrary destination/amount, or rebroadcast path.
Policy and dry plan are private, explicitly SHA-pinned operator inputs.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import importlib.util
import json
import math
import os
import stat
import subprocess
import time
from contextlib import AsyncExitStack
from pathlib import Path
from types import SimpleNamespace

from con01_history.certificate import Refused, require

AMOUNT = 5_000_000_000
OP = "br1-pilot-fund-v1"
CLIENT_AMOUNT = 2_000_000_000
CLIENT_OP = "br1-pilot-client-fund-v1"
CLIENT_SCHEMA = "tos.br1.public-client-policy.v1"
OPERATOR_SCHEMA = "tos.br1.public-pilot-policy.v1"
EARLIEST = 1793622922  # 2026-11-02 12:35:22UTC; actual resource gate is separate.
GENESIS_ROOT = "ff60459cb8a51708548290afa16fd4df80d16775bf3c13392146a6d1b5662d57"
GENESIS_FILE = "3b374df5ebd18368d4bf0eb374704771daf8dacd85175605f3bfd1c7a922a039"
TRANSPORT_SHA = "ce95ee51e4e81919264334a1bf0a1811df01b615c3b41466ce9583cb0dfa40c5"
DRIVER_SHA = "6b39f7462af832ed32c852445da76b9da9654461d41bb536457cbf9121fa5630"
FUNDING_CONFIG_SHA = "723f013f035d931908a3709d52343541d6620f891767f4d377db5674abadf4cd"
V3_CODE = "5829bd66ea5884eef70788d0609acad76af5c418aed2fc17709def2224cf9164"
ANCHOR_ID = "1793341151-wallet-init-764909c3"
ANCHOR_HASH = "29d7f4b7b44e3aeab01214e54ba9960cb65046806326c47744b0c95579ccf745"


def read(path, expected=None, limit=1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode) and info.st_size <= limit,
            "input file bound/type",
        )
        raw = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    require(len(raw) <= limit, "input byte bound")
    require(
        expected is None or hashlib.sha256(raw).hexdigest() == expected,
        "input SHA mismatch",
    )
    return raw


def write_new(path, value):
    with Path(path).open("x") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def readiness(policy, now):
    require(now >= EARLIEST, "resource duration bound not reached")
    reports = {
        name: json.loads(read(policy[name]["path"], policy[name]["sha256"]))
        for name in ("resource_gate", "history_gate", "upgrade_gate")
    }
    resource = reports["resource_gate"]
    require(resource["result"] == "PASS", "resource gate not passed")
    require(
        type(resource["observed_seconds"]) in (int, float)
        and math.isfinite(resource["observed_seconds"])
        and resource["observed_seconds"] >= 86400,
        "actual24h observations required",
    )
    require(
        all(
            resource[key] is True
            for key in (
                "identity_matches",
                "resource_limits_passed",
                "samples_complete",
            )
        ),
        "resource measurements incomplete",
    )
    require(
        type(resource["node_count"]) is int and resource["node_count"] == 4,
        "four-node resource gate",
    )
    require(
        resource["engine_sha256"]
        == "8ca8b37ecdaedfc8355415c7206c90192f28c5b88ea145be6eebd0ee5145a70c"
        and resource["cli_sha256"]
        == "f4e7b95b5289994bf34f4c0ecac52770422a577b8af19d28128f89f9ad9549d7",
        "resource release identity",
    )
    history = reports["history_gate"]
    require(
        history["verdict"] == "PASS"
        and type(history["rejected_count"]) is int
        and history["rejected_count"] == 0,
        "historical qualification not passed",
    )
    require(
        history["trust_chain"]["from_genesis"] is True
        and type(history["trust_chain"]["issue_count"]) is int
        and history["trust_chain"]["issue_count"] == 0,
        "historical trust chain",
    )
    require(
        sum(row["status"] == "PASS" for row in history["handovers"]) >= 3,
        "historical handover count",
    )
    upgrade = reports["upgrade_gate"]
    require(
        upgrade["result"] == "PASS"
        and type(upgrade["node_count"]) is int
        and upgrade["node_count"] == 4
        and upgrade["engine_pids_unchanged"] is True,
        "operator-only rollout gate",
    )
    require(
        upgrade["cli_sha256"]
        == "6eeaf23e8e87885b15caef8ba0c6a395b322057cecf1352033afda4b1d1476c8",
        "reviewed election CLI required",
    )
    return reports


def journal_anchor(entries):
    anchor = entries.get(ANCHOR_ID, {})
    require(
        anchor.get("external_hash") == ANCHOR_HASH
        and anchor.get("state") == "delivered",
        "approved PRI journal anchor missing",
    )


def budget(entries, operation=OP, amount=AMOUNT):
    require(
        (operation, amount) in ((OP, AMOUNT), (CLIENT_OP, CLIENT_AMOUNT)),
        "unknown fixed allocation",
    )
    journal_anchor(entries)
    spent = 0
    for entry in entries.values():
        if entry.get("op") == operation and not entry.get("dry_run"):
            require(entry.get("value") == str(amount), "malformed prior pilot funding")
            spent += amount
    require(spent == 0, "pilot funding already journaled: reconcile only")


def load_runtime(policy):
    for path, digest in policy["source_pins"].items():
        require(
            Path(path).suffix not in {".seed", ".pk"},
            "source pins may not read custody seeds",
        )
        read(path, digest, 256 * 1024 * 1024)
    read(policy["driver"], DRIVER_SHA)
    raw = read(policy["transport"], TRANSPORT_SHA)
    read(policy["funding_config"], FUNDING_CONFIG_SHA)
    os.environ.update(
        TOS_ROOT=policy["tos_root"],
        PRI_LOCAL_SCRIPTS=policy["local_scripts"],
        PRI_DRIVER=policy["driver"],
    )
    spec = importlib.util.spec_from_loader(
        "br1_reviewed_pri_transport", loader=None, origin=policy["transport"]
    )
    module = importlib.util.module_from_spec(spec)
    module.__file__ = policy["transport"]
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module.drv


def checked_init(policy, drv, private_check):
    if policy.get("schema") == CLIENT_SCHEMA:
        return checked_client_init(policy, drv, private_check)
    state = Path(policy["provider_state"])
    config = json.loads(read(state / "provider.json"))
    release = config["release"]
    require(
        type(release["global_id"]) is int
        and release["global_id"] == 2
        and release["genesis_root"] == GENESIS_ROOT
        and release["genesis_file"] == GENESIS_FILE,
        "Epoch-6 public scope required",
    )
    raw = read(state / "funding-init.boc", limit=65536)
    cell = drv.Cell.one_from_boc(raw)
    require(
        config["funding_wallet"] == "0:" + cell.hash.hex(), "StateInit/address mismatch"
    )
    init = drv.StateInit.deserialize(cell.begin_parse())
    require(init.code.hash.hex() == V3_CODE, "canonical TOS V3 code required")
    data = init.data.begin_parse()
    require(
        data.load_uint(32) == 0 and data.load_uint(32) == 3, "fresh V3 seq/subwallet"
    )
    public = data.load_bytes(32)
    require(
        data.remaining_bits == 0 and data.remaining_refs == 0, "V3 data trailing fields"
    )
    if private_check:
        # Independent public-key derivation only; no seed bytes leave this process.
        import nacl.signing

        seed_path = state / "funding.seed"
        info = seed_path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.geteuid(),
            "unsafe funding custody seed",
        )
        seed = read(seed_path, limit=32)
        require(
            len(seed) == 32
            and bytes(nacl.signing.SigningKey(seed).verify_key) == public,
            "funding public key mismatch",
        )
    return config["funding_wallet"], init, hashlib.sha256(raw).hexdigest()


def client_vault_identity(client, manifest, drv):
    """Use the pinned CLI's offline public view; never export a private key."""
    executable = Path(client["cli"])
    require(
        executable.is_absolute() and executable.resolve() == executable,
        "canonical client CLI",
    )
    read(executable, client["cli_sha256"], 512 * 1024 * 1024)
    config = Path(client["config"])
    require(
        config.is_absolute() and config.resolve() == config, "canonical client config"
    )
    settings = json.loads(read(config, client["config_sha256"]))
    configured = settings["wallets"][manifest["wallet"]]
    require(
        configured["version"] == "V3R2"
        and type(configured["subwallet_id"]) is int
        and configured["subwallet_id"] == 3
        and type(configured["workchain"]) is int
        and configured["workchain"] == 0,
        "client configured wallet type mismatch",
    )
    key_name = configured["key"]["name"]
    env_path = Path(client["vault_env"])
    info = env_path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o600,
        "unsafe client Vault environment",
    )
    private = json.loads(read(env_path, limit=4096))
    require(
        set(private) == {"VAULT_URL"}
        and type(private["VAULT_URL"]) is str
        and private["VAULT_URL"].startswith("file:///"),
        "local file Vault required",
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(config.parent),
        "NO_COLOR": "1",
        "VAULT_URL": private["VAULT_URL"],
        "RAYON_NUM_THREADS": "2",
        "TOKIO_WORKER_THREADS": "2",
    }
    answers = []
    for command in (["wallet", "ls", "--offline", "--format", "json"], ["key", "ls"]):
        result = subprocess.run(
            [str(executable), *command, "-c", str(config)],
            env=env,
            capture_output=True,
            timeout=30,
        )
        require(
            result.returncode == 0
            and len(result.stdout) <= 256 * 1024
            and len(result.stderr) <= 65536,
            "client public identity read refused",
        )
        answers.append(result.stdout)
    wallets = json.loads(answers[0])
    require(type(wallets) is list and len(wallets) <= 64, "client wallet list bound")
    matches = [row for row in wallets if row.get("name") == manifest["wallet"]]
    require(
        len(matches) == 1
        and drv.Address(matches[0]["address"]).to_str(is_user_friendly=False)
        == manifest["wallet_address"],
        "client configured wallet mismatch",
    )
    public = bytes.fromhex(manifest["public_key_hex"])
    encoded = base64.b64encode(public).decode()
    require(
        any(
            line.split()
            and line.split()[0] == key_name
            and line.split()[1] == "Ed25519"
            and line.split()[-1] == encoded
            for line in answers[1].decode().splitlines()
        ),
        "client Vault public key mismatch",
    )


def checked_client_init(policy, drv, private_check):
    client = policy["client"]
    manifest = json.loads(read(client["manifest"], client["manifest_sha256"], 16384))
    require(
        manifest["schema"] == "tos.br1.public-client.v1"
        and type(manifest["global_id"]) is int
        and manifest["global_id"] == 2
        and manifest["genesis_root"] == GENESIS_ROOT
        and manifest["genesis_file"] == GENESIS_FILE,
        "Epoch-6 client scope required",
    )
    require(
        manifest["wallet_version"] == "V3R2"
        and type(manifest["subwallet_id"]) is int
        and manifest["subwallet_id"] == 3,
        "client wallet version/subwallet",
    )
    public = bytes.fromhex(manifest["public_key_hex"])
    require(len(public) == 32, "client public key width")
    raw = read(client["state_init"], client["state_init_sha256"], 65536)
    cell = drv.Cell.one_from_boc(raw)
    require(
        manifest["wallet_address"] == "0:" + cell.hash.hex(),
        "client StateInit/address mismatch",
    )
    init = drv.StateInit.deserialize(cell.begin_parse())
    require(init.code.hash.hex() == V3_CODE, "canonical TOS V3 client code required")
    data = init.data.begin_parse()
    require(
        data.load_uint(32) == 0
        and data.load_uint(32) == 3
        and data.load_bytes(32) == public
        and data.remaining_bits == 0
        and data.remaining_refs == 0,
        "client V3 data/public key mismatch",
    )
    if private_check:
        client_vault_identity(client, manifest, drv)
    return manifest["wallet_address"], init, hashlib.sha256(raw).hexdigest()


LEGACY_PRESIGN_SOURCE_SHA = (
    "9f9118bde244b1a56837f6a50b48b8a17acb9c631ed40d9c79cd646db94e8922"
)


def checked_presign_recovery(args, policy, marker, plan, entries):
    """A trusted operator incident attestation, never a proof of signature absence."""
    require(
        getattr(args, "acknowledge_reviewed_presign_refusal", False) is True,
        "reviewed pre-sign incident acknowledgement required",
    )
    require(
        policy.get("schema") == CLIENT_SCHEMA, "pre-sign recovery only for client2TOS"
    )
    receipt = json.loads(read(args.recovery, args.recovery_sha256, 16384))
    require(
        receipt["schema"] == "tos.br1.reviewed-presign-incident.v1"
        and receipt["trusted_operator_attestation"] is True,
        "trusted reviewed incident required",
    )
    original = json.loads(read(marker, receipt["marker_sha256"], 16384))
    require(
        original["plan"] == plan and original["policy_sha256"] == args.policy_sha256,
        "pre-sign original plan/nonce changed",
    )
    old_policy = json.loads(
        read(receipt["original_policy"], args.policy_sha256, 128 * 1024)
    )
    require(old_policy == policy, "pre-sign original policy changed")
    source = read(receipt["original_source"], LEGACY_PRESIGN_SOURCE_SHA, 1024 * 1024)
    lines = source.decode().splitlines()
    require(
        lines[415].strip()
        == "require(time.time() < " + 'deadline, "window expired before signing")'
        and lines[417].strip() == "return wallet.sign(message, seqno)",
        "reviewed original pre-sign ordering",
    )
    log = read(
        receipt["failure_log"], receipt["failure_log_sha256"], 1024 * 1024
    ).decode()
    frame = f'File "{Path(__file__).resolve()}", line 416, in sign'
    require(
        log.count("Traceback (most recent call last):") == 1
        and frame in log
        and log.rstrip().endswith(
            "con01_history.certificate.Refused: window expired before signing"
        )
        and "COMPLETE client fund" not in log,
        "not the reviewed pre-sign guard failure",
    )
    prior = [
        row
        for row in entries.values()
        if not row.get("dry_run") and row.get("wallet") == plan["source"]
    ]
    require(
        all(
            type(row.get("seqno")) is int and row["seqno"] != plan["seqno"]
            for row in prior
        ),
        "source nonce already signed or journaled",
    )
    require(
        not (
            marker.parent / "br1-public-client-presign-resume-v1.signing-started.json"
        ).exists(),
        "resume signing already started: reconcile only",
    )
    return receipt


def fresh_window(policy, out):
    # The legacy wallet client uses the configured venv; sealed native proofs
    # require the host Python's memfd API on this deployment.
    command = ["/usr/bin/python3", "-B", "-m", "br1_window"]
    for key in ("anchor", "verifier", "verifier_sha256", "archive", "join_key"):
        command += ["--" + key.replace("_", "-"), str(policy["window"][key])]
    for rpc in policy["window"]["rpc"]:
        command += ["--rpc", rpc]
    command += ["--out", str(out)]
    result = subprocess.run(
        command,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parent)},
        capture_output=True,
        timeout=180,
    )
    require(result.returncode == 0, "no fresh quiet term; no signing")
    window = json.loads(read(out / "WINDOW.json"))
    chain = json.loads(read(out / "chain/REPORT.json"))
    require(
        base64.b64decode(chain["anchor"]["root_hash"]).hex() == GENESIS_ROOT
        and base64.b64decode(chain["anchor"]["file_hash"]).hex() == GENESIS_FILE,
        "window genesis mismatch",
    )
    require(
        window["quiet"] is True and time.time() < window["valid_until_utc"],
        "window expired",
    )
    return window


class GuardedBlueprint:
    def __init__(self, original, seqno, valid_until, before_sign=None):
        self.original, self.seqno, self.valid_until = original, seqno, valid_until
        self.address = original.address
        self.before_sign = before_sign

    def materialize(self, client):
        wallet = self.original.materialize(client)
        expected, deadline = self.seqno, self.valid_until
        claimed = False
        before_sign = self.before_sign

        class Wallet:
            address = wallet.address

            def sign(self, message, seqno):
                nonlocal claimed
                require(not claimed, "signature already claimed")
                require(seqno == expected, "funding nonce changed before signing")
                require(time.time() < deadline, "window expired before signing")
                claimed = True
                if before_sign is not None:
                    before_sign()
                return wallet.sign(message, seqno)

        return Wallet()


async def work(args, policy):
    funding = args.mode in {"fund", "resume-before-sign"}
    resuming = args.mode in {"resume-dry-run", "resume-before-sign"}
    client_allocation = policy.get("schema") == CLIENT_SCHEMA
    operation, amount = (
        (CLIENT_OP, CLIENT_AMOUNT) if client_allocation else (OP, AMOUNT)
    )
    if client_allocation and funding:
        require(
            getattr(args, "acknowledge_client_2_tos", False) is True,
            "explicit new client2TOS allocation acknowledgement required",
        )
    if resuming:
        require(client_allocation, "pre-sign recovery only for client2TOS")
        require(
            getattr(args, "recovery", None) is not None
            and getattr(args, "recovery_sha256", None) is not None
            and getattr(args, "acknowledge_reviewed_presign_refusal", False) is True,
            "pinned reviewed pre-sign incident required",
        )
    guarded = args.mode in {"dry-run", "fund", "resume-dry-run", "resume-before-sign"}
    if funding:
        require(
            args.plan is not None and args.plan_sha256 is not None,
            "fresh dry plan required",
        )
    if guarded:
        readiness(policy, time.time())
    drv = load_runtime(policy)
    run_root = Path(policy["run_dir"])
    require(
        run_root.is_absolute()
        and run_root.resolve() == run_root
        and (run_root / "private/journal-private.jsonl").is_file(),
        "existing canonical PRI run required",
    )
    require(
        (run_root / "private/journal-private.jsonl").stat().st_size <= 16 * 1024 * 1024,
        "journal byte bound",
    )
    run = drv.Run(run_root)
    journal_anchor(run.entries())
    target, init, init_sha = checked_init(policy, drv, False)
    config = json.loads(read(policy["funding_config"], FUNDING_CONFIG_SHA))
    source = config["wallets"][0]
    common = SimpleNamespace(
        global_id=2,
        allow_public=True,
        zero_state=GENESIS_ROOT,
        endpoints="node-1,node-3",
        funding_dir=policy["funding_dir"],
        funding_config=policy["funding_config"],
        dry_run=args.mode in {"dry-run", "resume-dry-run"},
        rebroadcast=False,
    )
    async with AsyncExitStack() as stack:
        endpoints = await drv.open_endpoints(common, stack)
        await drv.check_identity(common, endpoints)
        if args.mode == "reconcile":
            require(
                all(
                    row.get("op") == operation
                    and row.get("destination") == target
                    and row.get("wallet") == source
                    and row.get("value") == str(amount)
                    and row.get("state_init_sha256") == init_sha
                    for row in run.unresolved().values()
                ),
                "another PRI action is unresolved",
            )
            await drv.reconcile(common, run, endpoints)
            return
        require(not run.unresolved(), "unresolved PRI action: reconcile first")
        budget(run.entries(), operation, amount)
        marker = run.private / (
            "br1-public-client-funding-v1.marker.json"
            if client_allocation
            else "br1-public-pilot-funding-v1.marker.json"
        )
        require(
            resuming or not marker.exists(), "funding marker exists: reconcile only"
        )
        states = [
            await peer.client.raw_get_account_state(drv.Address(target))
            for peer in endpoints
        ]
        require(
            all(
                not state.code
                and int(state.balance) in (0, -1)
                and (not state.last_transaction_id or state.last_transaction_id.lt == 0)
                for state in states
            ),
            "target is not a fresh empty account",
        )
        balances = [
            int((await peer.client.raw_get_account_state(drv.Address(source))).balance)
            for peer in endpoints
        ]
        require(
            balances[0] == balances[1] and balances[0] >= amount + 10**9,
            "funding balance disagreement/insufficient reserve",
        )
        seqno = await drv.seqno_of(endpoints, source)
        plan = dict(
            schema="tos.br1.public-funding-plan.v1",
            policy_sha256=args.policy_sha256,
            destination=target,
            source=source,
            amount=amount,
            seqno=seqno,
            state_init_sha256=init_sha,
        )
        if resuming:
            checked_presign_recovery(args, policy, marker, plan, run.entries())
            marker = run.private / "br1-public-client-presign-resume-v1.marker.json"
            require(
                not marker.exists(), "pre-sign resume already attempted: reconcile only"
            )
        if args.mode == "inspect":
            write_new(args.out / "UNSIGNED.json", plan)
            return
        window = fresh_window(policy, args.out / "window")
        checked_target, _, checked_sha = checked_init(policy, drv, True)
        require(
            (checked_target, checked_sha) == (target, init_sha),
            "native initialization changed",
        )
        if funding:
            expected = json.loads(read(args.plan, args.plan_sha256))
            require(
                expected["plan"] == plan and expected["dry_run"] is True,
                "dry plan/nonce/config changed",
            )
            require(
                type(expected["checked_utc"]) in (int, float)
                and 0 <= time.time() - expected["checked_utc"] <= 300,
                "fresh dry run required",
            )
            write_new(
                marker,
                {
                    "policy_sha256": args.policy_sha256,
                    "plan": plan,
                    "reviewed_presign_recovery_sha256": args.recovery_sha256
                    if resuming
                    else None,
                },
            )
        wallets = drv.funding_wallets(common)
        require(
            wallets[0].address.to_str(is_user_friendly=False) == source,
            "approved source wallet mismatch",
        )

        def signing_fence():
            write_new(
                run.private
                / "br1-public-client-presign-resume-v1.signing-started.json",
                {
                    "policy_sha256": args.policy_sha256,
                    "plan": plan,
                    "recovery_sha256": args.recovery_sha256,
                },
            )

        wallets[0] = GuardedBlueprint(
            wallets[0],
            seqno,
            window["valid_until_utc"],
            signing_fence if resuming and funding else None,
        )
        original_send = drv.send_bytes
        writes = 0

        async def once(context, endpoint, boc):
            nonlocal writes
            require(
                writes == 0 and time.time() < window["valid_until_utc"],
                "broadcast already claimed/window expired",
            )
            writes += 1
            return await original_send(context, endpoint, boc)

        drv.send_bytes = once
        result = await drv.submit(
            common,
            run,
            endpoints,
            wallets,
            operation,
            0,
            target,
            amount,
            drv.begin_cell().end_cell(),
            {"pilot_policy_sha256": args.policy_sha256, "state_init_sha256": init_sha},
            {},
            init=init,
            bounce=False,
        )
        if funding:
            require(result.get("state") == "delivered", "original funding not settled")
        write_new(
            args.out / "RESULT.json",
            {
                "plan": plan,
                "dry_run": common.dry_run,
                "result": result,
                "checked_utc": time.time(),
            },
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument(
        "--mode",
        choices=(
            "inspect",
            "dry-run",
            "fund",
            "reconcile",
            "resume-dry-run",
            "resume-before-sign",
        ),
        required=True,
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--plan-sha256")
    parser.add_argument(
        "--acknowledge-client-2-tos",
        action="store_true",
        help="explicitly acknowledge the separate fixed2TOS client allocation, only after operator authorization",
    )
    parser.add_argument("--recovery", type=Path)
    parser.add_argument("--recovery-sha256")
    parser.add_argument("--acknowledge-reviewed-presign-refusal", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    policy = json.loads(read(args.policy, args.policy_sha256, 128 * 1024))
    require(policy["schema"] in (OPERATOR_SCHEMA, CLIENT_SCHEMA), "pilot policy schema")
    args.out.mkdir(mode=0o700, exist_ok=False)
    asyncio.run(work(args, policy))


if __name__ == "__main__":
    try:
        main()
    except Refused as error:
        raise SystemExit("PILOT_FUND_REFUSED: " + str(error)) from None
    except Exception:
        raise SystemExit(
            "PILOT_FUND_REFUSED: runtime/input error; preserve the journal and reconcile, never repeat funding"
        ) from None
