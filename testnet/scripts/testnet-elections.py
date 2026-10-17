#!/usr/bin/env python3
"""Bring the four genesis validators into ordinary elections (coordinator side),
and drive load through a post-quantum high-volume wallet.

  fund    --ceremony DIR --tos-root DIR --fift PATH --rpc URL
          --to ADDRESS --amount TOS --label LABEL [--dry-run]
      Send TOS from the genesis bootstrap wallet (wallet v3 at -1:111...1).
      The transfer is signed with tos crypto/smartcont/wallet-v3.fif and a
      preloaded `<global id> constant tos-global-id`, so the signature commits
      to the testnet global id. Non-bounce, the sender pays fees, 300 s
      expiry. Waits until the wallet's seqno moves on. Every signed transfer
      is kept in DIR/sent/.

  onboard --name NAME --host HOST --ssh-key FILE --ceremony DIR
          --controller FILE --root-seed FILE --controller-tool PATH
          --tos-root DIR --fift PATH --rpc URL [--previous-ceremony DIR]...
      For one genesis validator, in order, stopping at the first failure:
      init-operator.sh on the host; record the operator wallet address as
      op-NAME in DIR/wallets.json, refusing an address an earlier epoch's
      ceremony recorded (see "Resets" below); fund the operator wallet from the
      bootstrap wallet; activate it; deploy the controller (its state init
      from testnet-operator.py controller); make the pool owner, a wallet v3
      in the masterchain (subwallet 0x504F4F4C) whose key is created here in
      DIR/secret/pool-owner-NAME.pk and never leaves this machine (address and
      self-deploy message in DIR/pool-owners/, label pool-owner-NAME in
      wallets.json), fund it from the bootstrap wallet with the stake money
      and activate it; deploy the pool from the operator wallet with only
      pool_deploy_tos, with that owner, the operator wallet as its validator
      and the controller; record it in DIR/pools.json; bind node, wallet and
      pool; import the controller's birth; have the owner send the principal
      (pool_tos) to the pool, signed here;
      plan the operating authorization on the host, sign it here with the
      offline root seed, and send it from the operator wallet; then
      enable-elections.sh. Each step checks its result first, so a rerun
      continues where the last one stopped.

  refund  --name NAME --host HOST --ssh-key FILE --ceremony DIR
          --controller FILE --root-seed FILE --controller-tool PATH
          --tos-root DIR --fift PATH --rpc URL [--target-nanotos N]
          [--dry-run] [--i-checked-the-window]
      Top up an onboarded validator controller's operating funds (a kind-4
      fund_operations renewal), paid by the operator wallet op-NAME recorded in
      DIR/wallets.json. It runs only in the quiet part of a term: it refuses
      while the Elector has an election open, and within 10 minutes of the
      current set taking office (ConfigParam 34 utime_since) or of the next
      election opening (utime_until - elections_start_before); a failed
      election keeps refusing. --i-checked-the-window overrides that after you
      have checked by hand. It plans on the host (funds target
      elections.authorization.refund_target_nanotos, or --target-nanotos), and
      refuses before signing when the operator wallet would keep less than
      elections.authorization.operator_reserve_nanotos after the message value
      and a 1 TOS fee allowance: the election task needs 20.2 TOS there to
      stake. The error names the top-up to `fund` first. Then it signs here
      with the root seed, stops tos-testnet-elections (it holds the tosctl
      vault lock), sends from the operator wallet, starts the service again
      whatever the send did, and checks that the root authority nonce advanced,
      the stakes remaining grew and no [BLOCKING] warning remains. Each sent
      refund is appended to DIR/refunds.jsonl. --dry-run plans, checks the
      reserve and signs, reports the window, and sends nothing.

  withdraw --name NAME --ceremony DIR --tos-root DIR --fift PATH --rpc URL
          (--amount TOS | --all) [--during-election] [--dry-run]
      Take stake principal out of NAME's pool (DIR/pools.json) to its owner.
      The pool's WITHDRAW message (op 0x1000, tos
      crypto/smartcont/single-nominator-pool/withdraw.fif) is signed here with
      the owner's offline key as a bounceable 1 TOS transfer from the owner
      wallet; the pool pays the amount (capped at its balance less the message
      value and 1 TOS storage) and the unspent value back to the owner. Only
      liquid balance can leave: a stake at the Elector returns to the pool when
      the election task recovers it after stake_held_for. Refused while an
      election is open (the task stakes from this balance) unless
      --during-election. Each sent withdrawal is appended to
      DIR/withdrawals.jsonl; --dry-run signs and keeps the message in DIR/sent/.

  load   --ceremony DIR --tos-root DIR --fift PATH --rpc URL --key-tool PATH
          --state DIR [--target-gas-per-block N | --batches-per-second R]
          [--actions-per-batch K] [--duration S] [--relayers N]
          [--send-rpc URL]... [--watch-rpc URL]... [--transfers skip|deliver]
          [--deploy-amount TOS] [--relayer-amount TOS] [--dry-run]
          [--previous-ceremony DIR]...
      Load test through a post-quantum high-volume wallet
      (crypto/smartcont/pq-highload-wallet-code.fc). Once: an ML-DSA-44 key
      (tos-pq-key keygen) and the wallet state (new-pq-highload-wallet.fif)
      are created in the --state directory (0700, keys 0600; never put it in
      a repository), N wallet-v3 relayers on the basechain get their own keys
      there, and the bootstrap wallet funds and deploys all of them through
      `fund`. Their addresses go to DIR/wallets.json as
      load-<wallet address prefix>/highload and .../relayer-I, and an address an earlier epoch recorded is refused, so a
      --state directory is never carried over a reset. The wallet has no external handler: a relayer forwards each
      signed request in an internal message whose value pays the compute, and
      gets the rest back. Batches of K transfers are signed with tos-pq-key
      and go out up to four per relayer external message, spread over the
      --send-rpc endpoints (default --rpc; a node admits 30 external messages
      per 10 s from one JSON-RPC server, so high rates need several), at R
      batches/s or at the rate that puts N gas into each basechain block
      (block interval measured first; gas per batch from the wallet's profile,
      then from its own transactions). --transfers skip (default) asks for
      more than any balance, so the action phase skips each transfer: full
      compute, no message. deliver sends real transfers to the relayers, but a
      collator defers a sender's messages past 10 per block and drains them
      slowly, so it is refused above 40 transfers/s. The relayers pay for every
      batch and are topped up from the bootstrap wallet while the test runs.
      Query ids continue across runs (load-state.json). Each second it prints
      batches sent, accepted (the relayer's seqno moved), failed and executed
      (the wallet recorded the id); at the end it writes summary-<time>.json
      with batches, transfers, gas and the fees spent (balance delta of the
      wallet and the relayers, top-ups included). It stops after the messages
      in flight on SIGINT, and on its own when a --rpc or --watch-rpc node's
      masterchain head is older than 60 s or a balance falls below its floor.
      --dry-run signs one batch into DIR/dry-run-<time>/ and broadcasts nothing.

Resets. Every testnet epoch uses global id 2, so a wallet key that survives a
reset accepts again whatever was signed for it on an earlier epoch. onboard and
load take --previous-ceremony once for every earlier epoch's ceremony directory
and refuse a wallet identity recorded there (its wallets.json, the bootstrap key
in its genesis.json, or for a ceremony older than both its secret/main-wallet.pk,
whose public key fift derives). A previous ceremony that records nothing is
refused. An operator whose host kept /var/lib/tos-ctl over the reset still has
the old wallet key; init-operator.sh then prints the old address and onboard
stops before funding it.

URL is a JSON-RPC endpoint of a live node (for example a validator's loopback
listener through an SSH tunnel, http://127.0.0.1:18081/jsonRPC). The amounts
are network/profile.json `elections`. The root seed and the bootstrap key
never leave this machine; the host only ever sees the signed messages.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

BOOTSTRAP_WALLET = "-1:" + "1" * 64
NANO = 10**9


# ---------------------------------------------------------------- pure helpers


def raw_from_friendly(friendly: str) -> str:
    """A user-friendly address (36 bytes, base64 or base64url) as workchain:hex."""
    data = base64.urlsafe_b64decode(
        friendly.replace("+", "-").replace("/", "_") + "=" * (-len(friendly) % 4)
    )
    if len(data) != 36:
        raise lib.TestnetError(f"not a user-friendly address: {friendly!r}")
    workchain = int.from_bytes(data[1:2], "big", signed=True)
    return f"{workchain}:{data[2:34].hex()}"


check_raw_address = lib.check_raw_address


def previous_wallets(args: argparse.Namespace) -> list[dict[str, str]]:
    """The wallet identities of every earlier epoch named with --previous-ceremony."""
    fift_lib = Path(args.tos_root) / "crypto" / "fift" / "lib"

    def derive(key: Path) -> bytes:
        return lib.wallet_public_key(Path(args.fift), fift_lib, key)

    return [lib.previous_wallets(Path(d), derive) for d in args.previous_ceremony or []]


def record_fresh_wallets(
    ceremony: Path, wallets: dict[str, str], previous: list[dict[str, str]]
) -> None:
    """Refuse a wallet an earlier epoch used, then add it to this epoch's wallets.json."""
    lib.record_wallets(ceremony, lib.check_fresh_wallets(wallets, previous))


def parse_operations_plan(text: str, global_id: int, controller_hex: str) -> dict:
    """The signing request and the message value from `tosctl controller operations plan`.

    Refuses a plan that first needs a capital top-up (a "step 0"), and one that
    names another global id or controller than the one being onboarded.
    """
    if "Capital required" not in text:
        raise lib.TestnetError("the operations plan has no 'Capital required' section")
    if re.search(r"step 0", text, re.IGNORECASE):
        raise lib.TestnetError("the operations plan needs a capital top-up before it can be signed")
    sign = re.search(
        r"tos-pq-controller fund-operations ROOTSEED (\S+) (\S+) (\S+) (\S+) (\S+) (\S+)", text
    )
    value = re.search(r"--amount-nanotos (\d+)", text)
    if not sign or not value:
        raise lib.TestnetError(
            "cannot find the signing command or the amount in the operations plan"
        )
    gid, controller, epoch, nonce, valid_until, payload = sign.groups()
    if gid != str(global_id) or controller.lower() != controller_hex.lower():
        raise lib.TestnetError(
            f"the plan names global id {gid} and controller {controller}, not {global_id} and {controller_hex}"
        )
    return {
        "epoch": epoch,
        "nonce": nonce,
        "valid_until": valid_until,
        "payload": payload,
        "value_nanotos": int(value.group(1)),
    }


def parse_pool_deploy(text: str) -> str:
    """The pool address from `tosctl deploy pool --verbose`, only when it reports deployed.

    The command prints progress lines, then its result (DeployPoolResult:
    config, account_state, address, deployed, error) as one pretty-printed
    JSON object starting at a line of its own. Only that object is read, so an
    address inside account_state or the progress lines cannot be mistaken
    for the pool's.
    """
    start = text.rfind("\n{") + 1  # 0 when the object opens the output
    try:
        result = json.loads(text[start:])
    except json.JSONDecodeError:
        result = None
    if not isinstance(result, dict):
        raise lib.TestnetError(f"no deploy result in the output: {text[-600:]}")
    if result.get("deployed") is not True or result.get("error"):
        raise lib.TestnetError(f"the pool was not deployed: {result.get('error')!r}")
    return check_raw_address(str(result.get("address", "")))


def first_transaction_boc(transactions: list) -> bytes:
    """The earliest transaction of an account: a controller's deployment, its birth."""
    if not transactions:
        raise lib.TestnetError("the account has no transactions")
    first = min(transactions, key=lambda tx: int(tx["transaction_id"]["lt"]))
    return base64.b64decode(first["data"])


# ---------------------------------------------------------------- chain


class Chain:
    def __init__(self, url: str, rpc=lib.rpc):
        self.url = url
        self.rpc = rpc

    def account(self, address: str) -> tuple[str, int]:
        info = self.rpc(self.url, "getAddressInformation", address=address)
        return info["state"], int(info["balance"])

    def seqno(self, address: str) -> int:
        result = self.rpc(self.url, "runGetMethod", address=address, method="seqno", stack=[])
        if result.get("exit_code") != 0:
            raise lib.TestnetError(f"seqno of {address} failed: {result}")
        return int(result["stack"][0][1], 0)

    def send_boc(self, boc: bytes) -> None:
        self.rpc(self.url, "sendBoc", boc=base64.b64encode(boc).decode())

    def transactions(self, address: str, limit: int = 50) -> list:
        return self.rpc(self.url, "getTransactions", address=address, limit=limit)

    def validator_term(self) -> tuple[int, int]:
        """utime_since and utime_until of the current validator set (ConfigParam 34)."""
        param = self.rpc(self.url, "getConfigParam", param=34)
        return validator_set_term(base64.b64decode(param["config"]["bytes"]))

    def active_election(self) -> int:
        """The Elector's open election id, 0 when none is open."""
        result = self.rpc(
            self.url, "runGetMethod", address=ELECTOR, method="active_election_id", stack=[]
        )
        if result.get("exit_code") != 0:
            raise lib.TestnetError(f"active_election_id failed: {result}")
        return int(result["stack"][0][1], 0)

    def wait_active(self, address: str, seconds: int = 90) -> int:
        deadline = time.time() + seconds
        while time.time() < deadline:
            state, balance = self.account(address)
            if state == "active":
                return balance
            time.sleep(3)
        raise lib.TestnetError(f"{address} did not become active within {seconds} s")


# ---------------------------------------------------------------- fund


def sign_wallet_v3(
    args: argparse.Namespace,
    global_id: int,
    key: Path,
    address_file: bytes,
    to: str,
    subwallet: int,
    seqno: int,
    amount: str,
    bounce: bool,
    init: Path | str | None = None,
    body: Path | None = None,
    run=subprocess.run,
) -> bytes:
    """A wallet-v3 transfer signed here, offline, with tos crypto/smartcont/wallet-v3.fif.

    The private key is copied into a private temporary directory only for the
    signing; a preloaded `<global id> constant tos-global-id` makes the signature
    commit to the network's global id. 300 s expiry, the sender pays fees.
    """
    smartcont = Path(args.tos_root) / "crypto" / "smartcont"
    with tempfile.TemporaryDirectory(prefix="sign-") as work:
        work_dir = Path(work)
        lib.write_new(work_dir / "signer.pk", Path(key).read_bytes(), 0o600)
        (work_dir / "signer.addr").write_bytes(address_file)
        (work_dir / "gid.fif").write_text(f"{global_id} constant tos-global-id\n")
        argv = [
            args.fift,
            "-I",
            f"{Path(args.tos_root) / 'crypto' / 'fift' / 'lib'}:{smartcont}",
            "-L",
            "gid.fif",
            "-s",
            str(smartcont / "wallet-v3.fif"),
            "signer",
            to,
            str(subwallet),
            str(seqno),
            amount,
            "-b" if bounce else "-n",
            "-t",
            "300",
        ]
        if init:
            argv += ["-I", str(Path(init).resolve())]
        if body:
            argv += ["-B", str(Path(body).resolve())]
        argv.append("query")
        result = run(argv, cwd=work_dir, capture_output=True, text=True)
        if result.returncode != 0 or not (work_dir / "query.boc").is_file():
            raise lib.TestnetError(f"signing failed: {result.stdout[-400:]} {result.stderr[-400:]}")
        return (work_dir / "query.boc").read_bytes()


def fund(args: argparse.Namespace, chain: Chain, global_id: int) -> None:
    to = check_raw_address(args.to)
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)?", str(args.amount)) or float(args.amount) <= 0:
        raise lib.TestnetError(f"amount must be a positive number of TOS: {args.amount!r}")
    ceremony = Path(args.ceremony)
    key = ceremony / "secret" / "main-wallet.pk"
    if not key.is_file():
        raise lib.TestnetError(f"{key} is missing; the bootstrap key stays with the coordinator")
    seq = chain.seqno(BOOTSTRAP_WALLET)
    boc = sign_wallet_v3(
        args,
        global_id,
        key,
        (ceremony / "main-wallet.addr").read_bytes(),
        to,
        0,
        seq,
        str(args.amount),
        bounce=False,
        init=getattr(args, "init", None),
    )
    sent = lib.private_dir(ceremony / "sent")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    lib.write_new(sent / f"{stamp}-seq{seq}-{args.label}.boc", boc, 0o600)
    print(f"bootstrap seqno {seq}: {args.amount} TOS to {to} ({args.label})")
    if args.dry_run:
        print("dry run: signed and kept, not broadcast")
        return
    chain.send_boc(boc)
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(3)
        if chain.seqno(BOOTSTRAP_WALLET) > seq:
            state, balance = chain.account(to)
            print(f"accepted; {to} is {state} with {balance / NANO:.3f} TOS")
            return
    raise lib.TestnetError(f"the bootstrap wallet's seqno is still {seq} after 90 s")


# ---------------------------------------------------------------- onboard


# The operator tool's state on a validator host, owned by its own non-login user.
TOSCTL_USER = "tos-ctl"
TOSCTL_DIR = "/var/lib/tos-ctl"
TOSCTL_ENV = "/etc/tos/tosctl.env"


class Host:
    def __init__(self, host: str, ssh_key: str, user: str = "root"):
        self.target = f"{user}@{host}"
        self.base = ["ssh", "-i", ssh_key, "-o", "BatchMode=yes", "-p", "22", self.target]

    def run(self, command: str, timeout: int = 300) -> str:
        result = subprocess.run(
            self.base + [command], capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            raise lib.TestnetError(
                f"{self.target}: {command[:80]!r} failed: {(result.stdout + result.stderr)[-800:]}"
            )
        return result.stdout

    def tosctl(self, arguments: str, timeout: int = 240) -> str:
        """tosctl on the host as its own user; root only reads the root-owned env file.

        runuser keeps the exported environment (the vault URL with its master
        key), so the key never appears on a command line, and every file
        tosctl writes under the state directory stays owned by that user.
        """
        return self.run(
            f"set -a; . {TOSCTL_ENV}; set +a; cd {TOSCTL_DIR}; "
            f"timeout {timeout} runuser -u {TOSCTL_USER} -- tosctl {arguments} 2>&1",
            timeout=timeout + 30,
        )

    def put(self, local: Path, remote: str, owner: str) -> None:
        """Write a local file on the host as `owner`, mode 0600.

        A root scp into a service user's directory would leave a file that
        service cannot rewrite; the bytes are streamed to a write that runs
        as the owner, and renamed into place only once complete.
        """
        script = 'umask 077 && cat > "$1.tmp" && mv -f "$1.tmp" "$1"'
        command = (
            f"runuser -u {shlex.quote(owner)} -- sh -c {shlex.quote(script)} "
            f"sh {shlex.quote(remote)}"
        )
        result = subprocess.run(
            self.base + [command], input=Path(local).read_bytes(), capture_output=True, timeout=120
        )
        if result.returncode != 0:
            raise lib.TestnetError(
                f"{self.target}: writing {remote} as {owner} failed: "
                f"{result.stderr.decode(errors='replace')[-400:]}"
            )


def genesis_controller(args: argparse.Namespace) -> dict:
    """The controller document --controller names, refused unless the genesis records list it."""
    controller_doc = json.loads(Path(args.controller).read_text())
    controller_hex = controller_doc["controller_id"]
    records = json.loads((Path(args.ceremony) / "genesis-records.json").read_text())
    if controller_hex not in {r["controller_id"] for r in records}:
        raise lib.TestnetError(f"controller {controller_hex} is not in the genesis records")
    return controller_doc


def sign_operations(
    tool: str, root_seed: str, global_id: int, controller_hex: str, plan: dict, run=subprocess.run
) -> str:
    """The kind-4 request body, signed here with the offline controller root seed."""
    return run(
        [
            tool,
            "fund-operations",
            root_seed,
            str(global_id),
            controller_hex,
            plan["epoch"],
            plan["nonce"],
            plan["valid_until"],
            plan["payload"],
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


# ---------------------------------------------------------------- the pool owner (offline)

# The single-nominator pool has three roles (tos crypto/smartcont/single-nominator-pool):
# the owner holds the funds and alone can withdraw them, the validator (the operator
# wallet on the host) can only send them to the Elector through the controller and
# recover them, and the controller stands in the election. The owner here is a
# wallet v3 in the masterchain whose key is made on this machine, beside the root
# seeds and the bootstrap key, and never copied to a host.
POOL_OWNER_SUBWALLET = 0x504F4F4C
POOLS_FILE = "pools.json"
WITHDRAWALS_FILE = "withdrawals.jsonl"
# The value an owner message carries; the pool sends what it does not spend back
# with the withdrawal (mode 64), so this is only an upper bound on the fee.
OWNER_MESSAGE_NANOTOS = NANO
# What the pool keeps for storage (MIN_TOS_FOR_STORAGE in single-nominator-code.fc).
POOL_STORAGE_NANOTOS = NANO
# --all asks for more than any pool holds; the pool caps a withdrawal at its
# balance less the message value and its storage reserve.
WITHDRAW_ALL_TOS = "1000000000"


def nanotos_text(nanotos: int) -> str:
    if nanotos <= 0:
        raise lib.TestnetError(f"an amount must be positive: {nanotos} nanotos")
    return f"{nanotos // NANO}.{nanotos % NANO:09d}"


def pool_owner_paths(ceremony: Path, name: str) -> dict[str, Path]:
    if not SAFE_NAME.match(name):
        raise lib.TestnetError(f"not a node name: {name!r}")
    public = Path(ceremony) / "pool-owners"
    return {
        "key": Path(ceremony) / "secret" / f"pool-owner-{name}.pk",
        "addr": public / f"{name}.addr",
        "init": public / f"{name}-init.boc",
    }


def ensure_pool_owner(
    args: argparse.Namespace, name: str, global_id: int, previous: list, run=subprocess.run
) -> str:
    """The pool owner's address, its key and init message made once with new-wallet-v3.fif.

    The key goes to the ceremony's private secret/ directory (0600); the address
    and the self-deploy message are public. A rerun reuses them. Refused when an
    earlier epoch recorded the address.
    """
    ceremony = Path(args.ceremony)
    paths = pool_owner_paths(ceremony, name)
    if not paths["addr"].is_file():
        smartcont = Path(args.tos_root) / "crypto" / "smartcont"
        with tempfile.TemporaryDirectory(prefix="pool-owner-") as work:
            work_dir = Path(work)
            (work_dir / "gid.fif").write_text(f"{global_id} constant tos-global-id\n")
            if paths["key"].is_file():
                lib.write_new(work_dir / "owner.pk", paths["key"].read_bytes(), 0o600)
            result = run(
                [
                    args.fift,
                    "-I",
                    f"{Path(args.tos_root) / 'crypto' / 'fift' / 'lib'}:{smartcont}",
                    "-L",
                    "gid.fif",
                    "-s",
                    str(smartcont / "new-wallet-v3.fif"),
                    "-1",
                    str(POOL_OWNER_SUBWALLET),
                    "owner",
                ],
                cwd=work_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )
            made = [work_dir / f for f in ("owner.pk", "owner.addr", "owner-query.boc")]
            if result.returncode != 0 or not all(p.is_file() for p in made):
                raise lib.TestnetError(
                    f"pool owner wallet: {(result.stdout + result.stderr)[-600:]}"
                )
            lib.private_dir(ceremony / "secret")
            if not paths["key"].is_file():
                lib.write_new(paths["key"], made[0].read_bytes(), 0o600)
            paths["addr"].parent.mkdir(mode=0o755, exist_ok=True)
            if not paths["init"].is_file():
                lib.write_new(paths["init"], made[2].read_bytes())
            lib.write_new(paths["addr"], made[1].read_bytes())
    address = address_from_file(paths["addr"])
    if not address.startswith("-1:"):
        raise lib.TestnetError(f"the pool owner {address} is not in the masterchain")
    record_fresh_wallets(ceremony, {f"pool-owner-{name}": address}, previous)
    return address


def read_pools(ceremony: Path) -> dict:
    path = Path(ceremony) / POOLS_FILE
    return json.loads(path.read_text()) if path.is_file() else {}


def record_pool(
    ceremony: Path,
    name: str,
    pool=None,
    owner=None,
    operator=None,
    controller=None,
    principal_sent=None,
) -> dict:
    """Add or complete a validator's pool record in the ceremony's public pools.json.

    The pool, owner, operator and controller of a recorded pool never change.
    """
    pools = read_pools(ceremony)
    entry = dict(pools.get(name, {}))
    for key, value in (
        ("pool", pool),
        ("owner", owner),
        ("operator", operator),
        ("controller", controller),
    ):
        if value is None:
            continue
        value = check_raw_address(value)
        if key in entry and entry[key] != value:
            raise lib.TestnetError(f"{POOLS_FILE} records {name} {key} {entry[key]}, not {value}")
        entry[key] = value
    if principal_sent is not None:
        entry["principal_sent"] = bool(principal_sent)
    pools[name] = entry
    path = Path(ceremony) / POOLS_FILE
    tmp = Path(ceremony) / f".{POOLS_FILE}.{os.getpid()}.tmp"
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    lib.write_new_json(tmp, pools)
    os.replace(tmp, path)
    return entry


def owner_send(
    args: argparse.Namespace,
    chain: Chain,
    global_id: int,
    name: str,
    to: str,
    nanotos: int,
    body: Path | None,
    label: str,
    dry_run: bool = False,
) -> bytes:
    """A bounceable transfer from the pool owner, signed here with its offline key.

    The signed message is kept in the ceremony's sent/ before anything is sent.
    """
    ceremony = Path(args.ceremony)
    paths = pool_owner_paths(ceremony, name)
    if not paths["key"].is_file():
        raise lib.TestnetError(f"{paths['key']} is missing; the pool owner key stays here")
    owner = address_from_file(paths["addr"])
    seq = chain.seqno(owner)
    boc = sign_wallet_v3(
        args,
        global_id,
        paths["key"],
        paths["addr"].read_bytes(),
        check_raw_address(to),
        POOL_OWNER_SUBWALLET,
        seq,
        nanotos_text(nanotos),
        bounce=True,
        body=body,
    )
    sent = lib.private_dir(ceremony / "sent")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    lib.write_new(sent / f"{stamp}-owner-{name}-seq{seq}-{label}.boc", boc, 0o600)
    print(f"pool owner {owner} seqno {seq}: {nanotos / NANO:.9f} TOS to {to} ({label})")
    if dry_run:
        print("dry run: signed and kept, not broadcast")
        return boc
    chain.send_boc(boc)
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(3)
        if chain.seqno(owner) > seq:
            return boc
    raise lib.TestnetError(f"the pool owner's seqno is still {seq} after 90 s")


def withdraw_body(
    args: argparse.Namespace, amount_tos: str, work: Path, run=subprocess.run
) -> Path:
    """The owner's WITHDRAW body (op 0x1000), from the pool's own withdraw.fif."""
    smartcont = Path(args.tos_root) / "crypto" / "smartcont"
    result = run(
        [
            args.fift,
            "-I",
            f"{Path(args.tos_root) / 'crypto' / 'fift' / 'lib'}:{smartcont}",
            "-s",
            str(smartcont / "single-nominator-pool" / "withdraw.fif"),
            amount_tos,
        ],
        cwd=work,
        capture_output=True,
        text=True,
        timeout=60,
    )
    body = work / "withdraw.boc"
    if result.returncode != 0 or not body.is_file():
        raise lib.TestnetError(f"withdraw body: {(result.stdout + result.stderr)[-400:]}")
    return body


def withdraw(args: argparse.Namespace, chain: Chain, global_id: int, sleep=None) -> dict:
    """Take stake principal out of a pool to its offline owner (see the module doc)."""
    sleep = sleep or time.sleep
    name = args.name
    ceremony = Path(args.ceremony)
    record = read_pools(ceremony).get(name)
    if not record or "pool" not in record:
        raise lib.TestnetError(f"{ceremony / POOLS_FILE} records no pool for {name}")
    owner = address_from_file(pool_owner_paths(ceremony, name)["addr"])
    if record["owner"] != owner:
        raise lib.TestnetError(f"the pool's recorded owner {record['owner']} is not {owner}")
    pool = record["pool"]
    election = chain.active_election()
    if election and not args.during_election:
        raise lib.TestnetError(
            f"election {election} is open: the election task stakes from this balance; "
            "withdraw between elections or pass --during-election"
        )
    pool_state, pool_balance = chain.account(pool)
    if pool_state != "active":
        raise lib.TestnetError(f"the pool {pool} is {pool_state}")
    available = pool_balance - POOL_STORAGE_NANOTOS
    if args.all:
        amount_tos = WITHDRAW_ALL_TOS
        requested = None
    else:
        requested = parse_tos(args.amount, "--amount")
        if requested > available:
            raise lib.TestnetError(
                f"the pool holds {pool_balance / NANO:.9f} TOS, {max(available, 0) / NANO:.9f} "
                "withdrawable (staked funds return to the pool after the Elector releases them)"
            )
        amount_tos = nanotos_text(requested)
    if available <= 0:
        raise lib.TestnetError(f"the pool holds only {pool_balance / NANO:.9f} TOS")
    owner_before = chain.account(owner)[1]
    with tempfile.TemporaryDirectory(prefix="withdraw-") as work:
        body = withdraw_body(args, amount_tos, Path(work))
        owner_send(
            args,
            chain,
            global_id,
            name,
            pool,
            OWNER_MESSAGE_NANOTOS,
            body,
            f"withdraw-{'all' if args.all else amount_tos}",
            args.dry_run,
        )
    result = {
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "name": name,
        "pool": pool,
        "owner": owner,
        "requested_nanotos": requested,
        "pool_balance_before_nanotos": pool_balance,
        "owner_balance_before_nanotos": owner_before,
        "dry_run": bool(args.dry_run),
    }
    if args.dry_run:
        return result
    for _ in range(30):
        sleep(3)
        owner_after = chain.account(owner)[1]
        if owner_after > owner_before:
            break
    else:
        raise lib.TestnetError(f"the withdrawal did not reach the owner {owner} in 90 s")
    result["owner_balance_after_nanotos"] = owner_after
    result["pool_balance_after_nanotos"] = chain.account(pool)[1]
    path = ceremony / WITHDRAWALS_FILE
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "a") as out:
        out.write(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2))
    return result


def onboard(args: argparse.Namespace, chain: Chain, global_id: int, profile: dict) -> None:
    name = args.name
    previous = previous_wallets(args)
    elections = profile["elections"]
    controller_doc = genesis_controller(args)
    controller_hex = controller_doc["controller_id"]
    controller = f"-1:{controller_hex}"
    host = Host(args.host, args.ssh_key)
    scripts = "/opt/tos-testnet/scripts"

    def step(text: str) -> None:
        print(f"== {name}: {text}", flush=True)

    step("operator tool")
    last = (
        host.run(f"{scripts}/init-operator.sh --name {shlex.quote(name)}").strip().splitlines()[-1]
    )
    operator = raw_from_friendly(last.split()[1])
    step(f"operator wallet {operator}")
    # A host that kept its tosctl state over a reset still has the old key, and
    # a wallet-v3 address is a function of key, subwallet and workchain.
    record_fresh_wallets(Path(args.ceremony), {f"op-{name}": operator}, previous)

    state, balance = chain.account(operator)
    funding = int(elections["operator_funding_tos"])
    if state != "active" and balance < funding * NANO // 2:
        step(f"fund {funding} TOS from the bootstrap wallet")
        fund_args = argparse.Namespace(
            ceremony=args.ceremony,
            tos_root=args.tos_root,
            fift=args.fift,
            to=operator,
            amount=str(funding),
            label=f"op-{name}",
            dry_run=False,
        )
        fund(fund_args, chain, global_id)
    if chain.account(operator)[0] != "active":
        step("activate the operator wallet")
        host.tosctl(f"wallet activate --name op-{name}", 150)
        chain.wait_active(operator)

    if chain.account(controller)[0] != "active":
        step(f"deploy controller {controller}")
        state_init = controller_doc["state_init_boc_b64"]
        host.tosctl(
            f"wallet send --from op-{name} --to {controller} --amount {elections['controller_deploy_tos']} "
            f"--state-init-boc {shlex.quote(state_init)} --yes",
            150,
        )
        chain.wait_active(controller, 90)
    birth = first_transaction_boc(chain.transactions(controller))
    with tempfile.NamedTemporaryFile(suffix=".boc") as tx:
        Path(tx.name).write_bytes(birth)
        host.put(Path(tx.name), f"{TOSCTL_DIR}/controller-{name}-deploy-tx.boc", TOSCTL_USER)

    # The pool's owner holds the stake principal and is the only role that can
    # take it out. Its key is made here and never leaves this machine; the
    # operator wallet on the host is only the pool's validator role.
    owner = ensure_pool_owner(args, name, global_id, previous)
    step(f"pool owner {owner} (key offline in the ceremony's secret/)")
    principal = int(elections["pool_tos"]) * NANO
    owner_needs = principal + int(elections["pool_owner_reserve_tos"]) * NANO
    owner_state, owner_balance = chain.account(owner)
    recorded = read_pools(Path(args.ceremony)).get(name, {})
    if not recorded.get("principal_sent") and owner_balance < owner_needs:
        step(f"fund the pool owner with {(owner_needs - owner_balance) / NANO:.9f} TOS")
        fund(
            argparse.Namespace(
                ceremony=args.ceremony,
                tos_root=args.tos_root,
                fift=args.fift,
                to=owner,
                amount=nanotos_text(owner_needs - owner_balance),
                label=f"pool-owner-{name}",
                dry_run=False,
            ),
            chain,
            global_id,
        )
    if chain.account(owner)[0] != "active":
        step("activate the pool owner wallet")
        chain.send_boc(pool_owner_paths(Path(args.ceremony), name)["init"].read_bytes())
        chain.wait_active(owner)

    pools = json.loads(host.run(f"cat {TOSCTL_DIR}/tosctl-config.json")).get("pools", {})
    if f"pool-{name}" not in pools:
        step(f"deploy the pool with {elections['pool_deploy_tos']} TOS from the operator wallet")
        pool = parse_pool_deploy(
            host.tosctl(
                f"deploy pool --verbose --node op-{name} --owner {owner} "
                f"--controller {controller} --amount {elections['pool_deploy_tos']}",
                240,
            )
        )
        step(f"pool {pool}")
        record_pool(Path(args.ceremony), name, pool, owner, operator, controller)
        host.tosctl(
            f"config pool add --name pool-{name} --address {pool} --owner {owner} --controller {controller}"
        )
        host.tosctl(f"config bind add --node {name} --wallet op-{name} --pool pool-{name}")
        # The birth import needs the binding, so it comes after `bind add`.
        host.tosctl(
            f"config bind import-birth --node {name} "
            f"--transaction-boc {TOSCTL_DIR}/controller-{name}-deploy-tx.boc "
            f"--output {TOSCTL_DIR}/controller-birth-{name}.boc",
            90,
        )

    record = read_pools(Path(args.ceremony)).get(name)
    if not record:
        raise lib.TestnetError(
            f"pool-{name} is configured on the host but not in the ceremony's {POOLS_FILE}"
        )
    if record["owner"] != owner:
        raise lib.TestnetError(
            f"pool-{name} was recorded with owner {record['owner']}, not {owner}"
        )
    if not record.get("principal_sent"):
        step(f"the pool owner sends the principal, {elections['pool_tos']} TOS, to the pool")
        pool_before = chain.account(record["pool"])[1]
        owner_send(
            args, chain, global_id, name, record["pool"], principal, None, f"principal-{name}"
        )
        deadline = time.time() + 90
        while chain.account(record["pool"])[1] < pool_before + principal - NANO:
            if time.time() > deadline:
                raise lib.TestnetError(f"the principal did not reach {record['pool']} in 90 s")
            time.sleep(3)
        record_pool(Path(args.ceremony), name, principal_sent=True)

    status = host.tosctl(f"controller operations status --controller {controller}", 90)
    if "kind 4 never accepted" in status:
        step("operating authorization")
        auth = elections["authorization"]
        plan = parse_operations_plan(
            host.tosctl(
                f"controller operations plan --controller {controller} --payer {operator} "
                f"--floor-nanotos {auth['floor_nanotos']} --funds-target-nanotos {auth['funds_target_nanotos']} "
                f"--expires-in-days {auth['expires_in_days']}",
                90,
            ),
            global_id,
            controller_hex,
        )
        signed = sign_operations(
            args.controller_tool, args.root_seed, global_id, controller_hex, plan
        )
        host.tosctl(
            f"wallet send --from op-{name} --to {controller} --amount-nanotos {plan['value_nanotos']} "
            f"--body-boc {shlex.quote(signed)} --bounce --yes",
            150,
        )
        time.sleep(10)
        status = host.tosctl(f"controller operations status --controller {controller}", 90)
    if "BLOCKING" in status or "kind 4 never accepted" in status:
        raise lib.TestnetError(f"operating authorization is not in place:\n{status[-1200:]}")
    for line in status.splitlines():
        if re.search(r"Funds:|Expires:|Root authority|Stakes remaining", line):
            print("   " + line.strip())

    step("election task")
    print(host.run(f"{scripts}/enable-elections.sh --name {shlex.quote(name)}"), end="")
    step("done")


# ---------------------------------------------------------------- refund

ELECTOR = "-1:" + "3" * 64
ELECTIONS_SERVICE = "tos-testnet-elections"
# tosctl's election task (tos tosctl/src/node-control/elections/src/runner.rs, send_stake)
# sends POOL_RELAY_BUDGET (20 TOS) from the operator wallet with every stake and refuses
# to stake unless the wallet also holds WALLET_COMPUTE_FEE (0.2 TOS) on top: 20.2 TOS.
# A refund that left less once kept all four validators out of an election.
STAKE_WALLET_MINIMUM_NANOTOS = 20 * NANO + NANO // 5
# Used when the profile names no reserve: the 20.2 TOS above plus a margin.
DEFAULT_OPERATOR_RESERVE_NANOTOS = 30 * NANO
# What the operator wallet's own external message may cost beyond the value it sends.
# Generous on purpose; each refund record keeps what the wallet actually spent.
WALLET_SEND_FEE_ALLOWANCE_NANOTOS = NANO
# No refund this close to a rotation or to the opening of an election.
WINDOW_MARGIN_SECONDS = 600
CONFIRM_ATTEMPTS = 9
CONFIRM_INTERVAL = 10
REFUND_LOG = "refunds.jsonl"
SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def parse_operations_status(text: str) -> dict:
    """What a refund checks in `tosctl controller operations status`: the stakes the
    funds still pay for, the root authority's epoch and nonce, and whether a
    [BLOCKING] warning or a missing authorization stands. tosctl colours only
    headings, markers and "none recorded", never the values read here."""
    stakes = re.search(r"Stakes remaining:\s+(\d+)", text)
    authority = re.search(r"Root authority:\s+epoch (\d+) nonce (\d+)", text)
    if not stakes or not authority:
        raise lib.TestnetError(
            f"no 'Stakes remaining' or 'Root authority' line in the status:\n{text[-1200:]}"
        )
    return {
        "stakes_remaining": int(stakes.group(1)),
        "epoch": int(authority.group(1)),
        "nonce": int(authority.group(2)),
        "blocking": "BLOCKING" in text,
        "unset": "kind 4 never accepted" in text or "none recorded" in text,
    }


def validator_set_term(boc: bytes) -> tuple[int, int]:
    """utime_since and utime_until of a ConfigParam 34 cell, as getConfigParam returns it.

    Reads only the root cell's first nine bytes: validators#11 or validators_ext#12,
    then the two 32-bit times. The bag-of-cells header is walked to find the root.
    """

    def take(at: int, size: int) -> tuple[int, int]:
        if at + size > len(boc):
            raise lib.TestnetError("the validator set BOC is truncated")
        return int.from_bytes(boc[at : at + size], "big"), at + size

    if boc[:4] != bytes.fromhex("b5ee9c72") or len(boc) < 6:
        raise lib.TestnetError("not a bag of cells")
    flags, ref_size, off_size = boc[4], boc[4] & 7, boc[5]
    if not 1 <= ref_size <= 4 or not 1 <= off_size <= 8:
        raise lib.TestnetError("the validator set BOC has a malformed header")
    at = 6
    cells, at = take(at, ref_size)
    roots, at = take(at, ref_size)
    _absent, at = take(at, ref_size)
    _total, at = take(at, off_size)
    if roots != 1:
        raise lib.TestnetError(f"the validator set BOC has {roots} roots")
    root, at = take(at, ref_size)
    if flags & 0x80:  # an index of cell offsets follows
        at += cells * off_size
    if root >= cells:
        raise lib.TestnetError("the validator set BOC names a root it does not hold")
    for index in range(cells):
        d1, at = take(at, 1)
        d2, at = take(at, 1)
        if d1 & 16:  # stored hashes and depths, one pair per level present
            at += (bin(d1 >> 5).count("1") + 1) * (32 + 2)
        data_bytes = (d2 + 1) // 2
        if index == root:
            if d1 & 8 or data_bytes < 9 or at + 9 > len(boc):
                raise lib.TestnetError("the validator set root is not an ordinary cell")
            if boc[at] not in (0x11, 0x12):
                raise lib.TestnetError(f"ConfigParam 34 has tag {boc[at]:#x}, not a validator set")
            since, after = take(at + 1, 4)
            until, _ = take(after, 4)
            return since, until
        at += data_bytes + (d1 & 7) * ref_size
    raise lib.TestnetError("the validator set root was not found")


def window_refusal(
    since: int, until: int, active_election: int, schedule: dict, now: int
) -> str | None:
    """Why a refund must wait now, or None.

    The election task relays stakes through the controller while an election is
    open, and a refund both stops that task and moves the controller's nonce, which
    invalidates a relay planned against the old one. So a refund runs only in the
    quiet part of a term: at least WINDOW_MARGIN_SECONDS after the set took office
    and before the next election opens, with no election open at the Elector. A
    failed election leaves the Elector's election open and the set past its
    utime_until, and both checks then refuse.
    """
    if active_election:
        return f"election {active_election} is open at the Elector (or not yet installed)"
    if now < since + WINDOW_MARGIN_SECONDS:
        return (
            f"the validator set took office {now - since} s ago; wait until "
            f"{since + WINDOW_MARGIN_SECONDS}"
        )
    opens = until - int(schedule["elections_start_before"])
    if now >= opens - WINDOW_MARGIN_SECONDS:
        return (
            f"the next election opens at {opens} ({opens - now} s from now) and the set "
            f"rotates at {until}; wait until {until + WINDOW_MARGIN_SECONDS}"
        )
    return None


def operator_reserve(authorization: dict) -> int:
    """What the operator wallet must still hold after a refund, from the profile."""
    reserve = authorization.get("operator_reserve_nanotos", DEFAULT_OPERATOR_RESERVE_NANOTOS)
    if not isinstance(reserve, int) or isinstance(reserve, bool):
        raise lib.TestnetError(f"operator_reserve_nanotos must be an integer: {reserve!r}")
    if reserve < STAKE_WALLET_MINIMUM_NANOTOS:
        raise lib.TestnetError(
            f"operator_reserve_nanotos {reserve} is below the {STAKE_WALLET_MINIMUM_NANOTOS} "
            "nanotos the election task needs in the operator wallet to stake"
        )
    return reserve


def reserve_shortfall(
    balance: int, value: int, reserve: int, fee: int = WALLET_SEND_FEE_ALLOWANCE_NANOTOS
) -> int:
    """Nanotos the operator wallet lacks to send `value`, pay `fee` and keep `reserve`."""
    if min(balance, value, reserve, fee) < 0:
        raise lib.TestnetError("a balance, value, reserve or fee cannot be negative")
    return max(0, value + fee + reserve - balance)


def recorded_operator(ceremony: Path, name: str) -> str:
    """The operator wallet onboard recorded as op-NAME in the ceremony's wallets.json."""
    path = ceremony / lib.WALLETS_FILE
    wallets = (
        lib.check_wallet_map(json.loads(path.read_text()), str(path)) if path.is_file() else {}
    )
    label = f"op-{name}"
    if label not in wallets:
        raise lib.TestnetError(f"{path} records no {label}; onboard {name} first")
    return check_raw_address(wallets[label])


def append_refund_log(ceremony: Path, record: dict) -> Path:
    path = ceremony / REFUND_LOG
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "a") as out:
        out.write(json.dumps(record, sort_keys=True) + "\n")
    return path


def refund(
    args: argparse.Namespace,
    chain: Chain,
    global_id: int,
    profile: dict,
    host: Host | None = None,
    now=time.time,
    sleep=time.sleep,
    sign=sign_operations,
) -> dict:
    name = args.name
    if not SAFE_NAME.match(name):
        raise lib.TestnetError(f"not a node name: {name!r}")
    authorization = profile["elections"]["authorization"]
    reserve = operator_reserve(authorization)
    target = (
        int(authorization["refund_target_nanotos"])
        if args.target_nanotos is None
        else args.target_nanotos
    )
    if target <= 0:
        raise lib.TestnetError(f"the funds target must be positive: {target}")
    ceremony = Path(args.ceremony)
    controller_hex = genesis_controller(args)["controller_id"]
    controller = f"-1:{controller_hex}"
    operator = recorded_operator(ceremony, name)

    since, until = chain.validator_term()
    reason = window_refusal(
        since, until, chain.active_election(), lib.validator_schedule(profile), int(now())
    )
    if reason:
        if not (args.dry_run or args.i_checked_the_window):
            raise lib.TestnetError(f"not now: {reason}")
        print(f"window: {reason} (continuing: {'dry run' if args.dry_run else 'overridden'})")

    host = host or Host(args.host, args.ssh_key)
    status_command = f"controller operations status --controller {controller}"
    before = parse_operations_status(host.tosctl(status_command, 90))
    if before["unset"]:
        raise lib.TestnetError(f"{controller} has no operating authorization; onboard {name} first")
    balance = chain.account(operator)[1]
    plan = parse_operations_plan(
        host.tosctl(
            f"controller operations plan --controller {controller} --payer {operator} "
            f"--floor-nanotos {int(authorization['floor_nanotos'])} --funds-target-nanotos {target} "
            f"--expires-in-days {int(authorization['expires_in_days'])}",
            90,
        ),
        global_id,
        controller_hex,
    )
    value = plan["value_nanotos"]
    if value <= 0:
        raise lib.TestnetError(f"the plan sends {value} nanotos")
    shortfall = reserve_shortfall(balance, value, reserve)
    if shortfall:
        top_up = -(-shortfall // NANO)
        raise lib.TestnetError(
            f"op-{name} ({operator}) holds {balance / NANO:.9f} TOS; sending {value / NANO:.9f} TOS "
            f"plus up to {WALLET_SEND_FEE_ALLOWANCE_NANOTOS / NANO:.1f} TOS in fees would leave "
            f"less than the {reserve / NANO:.9f} TOS reserve the next stake needs "
            f"(short by {shortfall / NANO:.9f} TOS). Top up the operator wallet with at least "
            f"{top_up} TOS first: testnet-elections.py fund --to {operator} --amount {top_up} "
            f"--label op-{name}-top-up"
        )
    signed = sign(args.controller_tool, args.root_seed, global_id, controller_hex, plan)
    record = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now())),
        "name": name,
        "controller": controller,
        "operator": operator,
        "funds_target_nanotos": target,
        "operator_reserve_nanotos": reserve,
        "value_nanotos": value,
        "plan_epoch": plan["epoch"],
        "plan_nonce": plan["nonce"],
        "valid_until": plan["valid_until"],
        "operator_balance_before_nanotos": balance,
        "stakes_remaining_before": before["stakes_remaining"],
        "authority_before": [before["epoch"], before["nonce"]],
        "window": reason,
    }
    if args.dry_run:
        print(json.dumps(record, indent=2))
        print(
            f"dry run: would send {value / NANO:.9f} TOS from op-{name} to {controller}; "
            f"nothing sent, {ELECTIONS_SERVICE} left running"
        )
        return record

    # The running election task holds the tosctl vault lock: stop it only around the
    # send, and start it again whatever the send did.
    host.run(f"systemctl stop {ELECTIONS_SERVICE}")
    try:
        host.tosctl(
            f"wallet send --from op-{name} --to {controller} --amount-nanotos {value} "
            f"--body-boc {shlex.quote(signed)} --bounce --yes",
            150,
        )
    except BaseException as exc:
        try:
            host.run(f"systemctl start {ELECTIONS_SERVICE}")
        except lib.TestnetError as start:
            raise lib.TestnetError(
                f"the send failed ({exc}) and {ELECTIONS_SERVICE} did not start again: {start}; "
                "start it by hand"
            ) from exc
        raise
    try:
        host.run(f"systemctl start {ELECTIONS_SERVICE}")
    except lib.TestnetError as exc:
        raise lib.TestnetError(
            f"the refund was sent, but {ELECTIONS_SERVICE} did not start again: {exc}; "
            "start it by hand"
        ) from exc

    after = before
    for _ in range(CONFIRM_ATTEMPTS):
        sleep(CONFIRM_INTERVAL)
        after = parse_operations_status(host.tosctl(status_command, 90))
        if (after["epoch"], after["nonce"]) > (before["epoch"], before["nonce"]):
            break
    balance_after = chain.account(operator)[1]
    problems = []
    if (after["epoch"], after["nonce"]) <= (before["epoch"], before["nonce"]):
        problems.append("the root authority nonce did not advance")
    if after["stakes_remaining"] <= before["stakes_remaining"]:
        problems.append("stakes remaining did not increase")
    if after["blocking"]:
        problems.append("a [BLOCKING] warning remains")
    if balance_after < STAKE_WALLET_MINIMUM_NANOTOS:
        problems.append("the operator wallet holds less than the next stake needs")
    record.update(
        operator_balance_after_nanotos=balance_after,
        operator_spent_nanotos=balance - balance_after,
        stakes_remaining_after=after["stakes_remaining"],
        authority_after=[after["epoch"], after["nonce"]],
        verified=not problems,
        problems=problems,
    )
    log = append_refund_log(ceremony, record)
    print(json.dumps(record, indent=2))
    print(f"recorded in {log}")
    if problems:
        raise lib.TestnetError(f"refund for {name} not confirmed: {'; '.join(problems)}")
    return record


# ---------------------------------------------------------------- load

# The post-quantum high-volume wallet (crypto/smartcont/pq-highload-wallet-code.fc) has
# no external handler: a relayer sends it the signed request in an internal message whose
# value pays the compute, and gets the remainder back. The relayers here are ordinary
# wallet-v3 accounts on the basechain, each with its own key and seqno, so several
# requests are in flight at once. By default every transfer in a batch is skipped by the
# action phase (full compute, no message); with --transfers deliver they go back to the
# relayers, so the value recirculates. Either way only fees are consumed.

HIGHLOAD_CONTEXT = b"TOS-PQ-HIGHLOAD-v1"
HIGHLOAD_MAX_ACTIONS = 254
HIGHLOAD_SUBWALLET = 0x10AD
HIGHLOAD_QUERY_ID_LIMIT = 1 << 23
MLDSA44_SIGNATURE_BYTES = 2420
# The wallet's own historical profile (code comment): 79,546 base + 2,708 per action, the
# starting estimate. A full 254-action batch used 840,000-842,000 gas on a loopback
# network at tos 703c2a5cb; the driver replaces the estimate with the chain's figure.
HIGHLOAD_BASE_GAS = 79_546
HIGHLOAD_GAS_PER_ACTION = 2_708
# The wallet's value quote (get_required_value): compute fee for base + per action +
# reserve gas, plus one forwarding lump.
QUOTE_BASE_GAS = 87_600
QUOTE_GAS_PER_ACTION = 3_300
QUOTE_EXTRA_GAS = 60_000
# A transfer worth more than any balance: the action phase skips it (+2 is forced), so
# the batch costs its full compute gas but creates no message.
SKIP_TRANSFER_NANOTOS = 1 << 100
# A collator delivers at most 10 messages per sender per block and defers the rest to the
# dispatch queue, which it drains slowly (about 20 per block on a loopback network).
# Delivered transfers above this rate build a backlog that outlives the test.
MAX_DELIVERED_PER_SECOND = 40
# A node admits at most 30 external messages per 10 s from one lite-server client, and its
# JSON-RPC server is one such client: each --send-rpc endpoint carries at most this many.
# The JSON-RPC server also admits only 600 requests per 10 s from one address.
ENDPOINT_EXTERNALS = 28
ENDPOINT_WINDOW = 10.0
# ConfigParam 23: a basechain block's gas soft limit and hard limit.
BLOCK_GAS_SOFT_LIMIT = 10_000_000
BLOCK_GAS_HARD_LIMIT = 20_000_000
RELAYER_SUBWALLET_BASE = 0x10AD0000
# A wallet-v3 external carries at most four messages.
SUBMISSIONS_PER_EXTERNAL = 4
EXTERNAL_TTL = 60
# A request is dated a little in the past, so a node whose clock lags still accepts it.
CREATED_AT_SLACK = 20
MAX_HEAD_AGE = 60
POLL_SECONDS = 0.5
# How long an accepted batch may wait in the queue before it counts as refused.
EXECUTION_GRACE = 60
STATE_FILE = "load-state.json"

LOAD_FIFT = r"""
"TosUtil.fif" include
// ( B i -- B' )  The i-th 127-byte chunk of B.
{ 127 * B| nip dup Blen 127 min B| drop } : chunk
variable chain-bytes
variable chain-cell
// ( B -- c )  The canonical byte chain: 127 bytes per non-final cell, one continuation each.
{ chain-bytes !
  chain-bytes @ Blen 126 + 127 / 1-
  dup chain-bytes @ swap chunk <b swap B, b> chain-cell !
  { 1- dup chain-bytes @ swap chunk <b swap B, chain-cell @ ref, b> chain-cell ! } over times
  drop chain-cell @
} : byte-chain
variable node
variable at
variable msgs
// ( n -- outlist )  n send actions (mode 1), cycling through the message cells in `msgs`.
{ <b b> node ! 0 at !
  { <b node @ ref, 0x0ec3c86d 32 u, 1 8 u, msgs @ at @ msg-count mod [] ref, b> node !
    at @ 1+ at ! } swap times
  node @
} : out-list
// ( qid created -- request )
{ <b gid 32 i, hl Addr, subwallet 32 u, rot 23 u, swap 64 u, wallet-timeout 22 u,
  action-count out-list ref, b>
} : request
// ( qid -- submission )
{ dup (.) "req-" swap $+ ".boc" $+ file>B B>boc
  swap (.) "sig-" swap $+ ".bin" $+ file>B
  <b 2420 32 u, swap byte-chain ref, b>
  <b 0x50514857 32 u, 0 64 u, rot ref, swap ref, b>
} : submission
// ( submission value -- message )  Bounceable, so a refused submission returns its value.
{ <b b{01} s, 1 1 u, b{000} s, hl Addr, swap Tomi, b{0} s, 0 104 u, b{0} s, b{1} s,
  swap ref, b>
} : to-wallet
"""


def next_query_id(query_id: int) -> int:
    """The id after `query_id`: ids whose low ten bits are 1023 do not exist, and the
    space wraps at 2^23 (an id is remembered for at most two wallet timeouts)."""
    if not 0 <= query_id < HIGHLOAD_QUERY_ID_LIMIT:
        raise lib.TestnetError(f"query id out of range: {query_id}")
    query_id += 1
    if query_id & 1023 == 1023:
        query_id += 1
    return 0 if query_id >= HIGHLOAD_QUERY_ID_LIMIT else query_id


def batch_gas(actions: int) -> int:
    """The wallet's gas for one batch of `actions` transfers, from its own profile."""
    if not 1 <= actions <= HIGHLOAD_MAX_ACTIONS:
        raise lib.TestnetError(f"a batch has 1..{HIGHLOAD_MAX_ACTIONS} transfers, not {actions}")
    return HIGHLOAD_BASE_GAS + HIGHLOAD_GAS_PER_ACTION * actions


def batch_rate(target_gas_per_block: int, gas_per_batch: int, block_interval: float) -> float:
    """Batches per second that put `target_gas_per_block` gas into each basechain block."""
    if target_gas_per_block <= 0 or gas_per_batch <= 0 or block_interval <= 0:
        raise lib.TestnetError("target gas, gas per batch and block interval must be positive")
    if target_gas_per_block > BLOCK_GAS_HARD_LIMIT:
        raise lib.TestnetError(
            f"{target_gas_per_block} gas per block is above the hard limit {BLOCK_GAS_HARD_LIMIT}"
        )
    return target_gas_per_block / gas_per_batch / block_interval


def price_and_lump(required_one: int, required_two: int) -> tuple[float, float]:
    """Nanotos per gas and the forwarding lump, from the wallet's quotes for 1 and 2
    transfers: they differ by exactly QUOTE_GAS_PER_ACTION gas."""
    price = (required_two - required_one) / QUOTE_GAS_PER_ACTION
    if price <= 0:
        raise lib.TestnetError(f"the wallet quotes {required_one} and {required_two}")
    lump = required_one - price * (QUOTE_BASE_GAS + QUOTE_GAS_PER_ACTION + QUOTE_EXTRA_GAS)
    return price, max(lump, 0.0)


def gas_from_transaction(tx: dict, price: float, lump: float) -> int | None:
    """Gas one batch used: the relayer's value minus the refund the wallet sent first,
    less the refund's forwarding lump, at the gas price. None for anything that is not
    an executed submission."""
    in_msg = tx.get("in_msg") or {}
    out = tx.get("out_msgs") or []
    compute = tx.get("compute") or {}
    if in_msg.get("kind") != "internal" or not out or not compute.get("success"):
        return None
    refund = min(out, key=lambda m: int(m["created_lt"]))
    spent = int(in_msg["value"]) - int(refund["value"]) - lump
    if spent <= 0:
        return None
    return round(spent / price)


def submission_value(required_nanotos: int) -> int:
    """What a relayer attaches to a submission: the wallet's own quote plus a margin.
    The wallet sends whatever compute does not use back to the relayer."""
    if required_nanotos <= 0:
        raise lib.TestnetError(f"the wallet quotes {required_nanotos} for a batch")
    return required_nanotos + required_nanotos // 5 + NANO // 100


def parse_tos(value: str, what: str) -> int:
    """A positive TOS amount given on the command line, in nanotos."""
    if not re.fullmatch(r"[0-9]+(\.[0-9]{1,9})?", str(value)):
        raise lib.TestnetError(f"{what} must be a positive number of TOS: {value!r}")
    whole, _, frac = str(value).partition(".")
    nanotos = int(whole) * NANO + int((frac + "0" * 9)[:9])
    if nanotos <= 0:
        raise lib.TestnetError(f"{what} must be positive: {value!r}")
    return nanotos


def fift_address(address: str) -> str:
    """A raw address as the two Fift literals `wc 0x<hex>`."""
    workchain, account = check_raw_address(address).split(":")
    return f"{int(workchain)} 0x{account}"


def address_from_file(path: Path) -> str:
    """The raw address in a Fift .addr file (32-byte account, 4-byte signed workchain)."""
    data = path.read_bytes()
    if len(data) != 36:
        raise lib.TestnetError(f"{path} is not a 36-byte address file")
    return f"{int.from_bytes(data[32:], 'big', signed=True)}:{data[:32].hex()}"


def request_program(
    global_id: int,
    wallet: str,
    recipients: list[str],
    actions: int,
    transfer_nanotos: int,
    timeout: int,
    requests: list[tuple[int, int]],
) -> str:
    """Fift that writes req-<qid>.boc for each (query id, created at) and prints
    `REQ <qid> <hash hex>`, the hash the wallet's key signs."""
    batch_gas(actions)
    if not recipients:
        raise lib.TestnetError("a batch needs at least one recipient")
    if transfer_nanotos < 0:
        raise lib.TestnetError("a transfer cannot be negative")
    lines = [
        f"{int(global_id)} constant gid",
        f"{fift_address(wallet)} 2constant hl",
        f"{HIGHLOAD_SUBWALLET} constant subwallet",
        f"{int(timeout)} constant wallet-timeout",
        f"{int(actions)} constant action-count",
        f"{len(recipients)} constant msg-count",
    ]
    lines.append(LOAD_FIFT)
    messages = [
        f"<b b{{010000}} s, {fift_address(r)} Addr, {int(transfer_nanotos)} Tomi, b{{0}} s, "
        "0 104 u, b{00} s, b>"
        for r in recipients
    ]
    lines.append(" ".join(messages) + f" {len(recipients)} tuple msgs !")
    for query_id, created_at in requests:
        if not 0 <= query_id < HIGHLOAD_QUERY_ID_LIMIT or query_id & 1023 == 1023:
            raise lib.TestnetError(f"not a usable query id: {query_id}")
        lines.append(
            f'{query_id} {int(created_at)} request dup hashB ."REQ {query_id} " Bx. cr '
            f'2 boc+>B "req-{query_id}.boc" B>file'
        )
    return "\n".join(lines) + "\n"


def external_body(
    relayer_base: str,
    relayer: str,
    relayer_subwallet: int,
    seqno: int,
    valid_until: int,
    submissions: list[tuple[int, int]],
    out_name: str,
) -> str:
    """Fift that wraps signed requests (query id, attached value) into one external
    message to a wallet-v3 relayer and writes it to `out_name`. It runs after the
    header from `externals_program`."""
    if not 1 <= len(submissions) <= SUBMISSIONS_PER_EXTERNAL:
        raise lib.TestnetError(f"an external carries 1..{SUBMISSIONS_PER_EXTERNAL} submissions")
    if not re.fullmatch(r"[a-z0-9-]+", relayer_base) or not re.fullmatch(r"[a-z0-9.-]+", out_name):
        raise lib.TestnetError("unexpected file name")
    lines = [
        f"<b gid 32 i, {int(relayer_subwallet)} 32 u, {int(valid_until)} 32 u, {int(seqno)} 32 u,"
    ]
    for query_id, value in submissions:
        if value <= 0:
            raise lib.TestnetError("a submission must carry value")
        lines.append(f"  3 8 u, {int(query_id)} submission {int(value)} to-wallet ref,")
    lines += [
        "b>",
        f'dup hashu "{relayer_base}.pk" load-keypair nip ed25519_sign_uint',
        f"<b b{{1000100}} s, {fift_address(relayer)} addr, 0 Tomi, b{{00}} s, swap B, swap <s s, b>",
        f'2 boc+>B "{out_name}" B>file',
    ]
    return "\n".join(lines) + "\n"


def externals_program(global_id: int, wallet: str, bodies: list[str]) -> str:
    """One Fift run that builds every external of a round."""
    header = [
        f"{int(global_id)} constant gid",
        f"{fift_address(wallet)} 2constant hl",
        f"{HIGHLOAD_SUBWALLET} constant subwallet",
        "0 constant wallet-timeout 1 constant action-count 0 constant msg-count",
        LOAD_FIFT,
    ]
    return "\n".join(header) + "\n" + "".join(bodies)


def parse_request_hashes(text: str) -> dict[int, str]:
    hashes = {}
    for match in re.finditer(r"^REQ (\d+) ([0-9A-Fa-f]{64})\s*$", text, re.MULTILINE):
        hashes[int(match.group(1))] = match.group(2).lower()
    return hashes


def head_age(chain: Chain) -> int:
    """Seconds since the node's masterchain head was generated."""
    last = chain.rpc(chain.url, "getMasterchainInfo")["last"]
    header = chain.rpc(
        chain.url,
        "getBlockHeader",
        workchain=lib.MASTERCHAIN,
        shard=str(lib.MASTERCHAIN_SHARD),
        seqno=int(last["seqno"]),
    )
    return int(time.time()) - int(header["gen_utime"])


def basechain_heads(chain: Chain) -> dict[str, int]:
    """Every basechain shard's top block seqno, as the masterchain head names them."""
    last = chain.rpc(chain.url, "getMasterchainInfo")["last"]
    shards = chain.rpc(chain.url, "shards", seqno=int(last["seqno"]))["shards"]
    return {str(s["shard"]): int(s["seqno"]) for s in shards if int(s["workchain"]) == 0}


def block_interval(before: dict[str, int], after: dict[str, int], seconds: float) -> float:
    """Mean seconds per basechain block in each shard over a window.

    Load splits and merges shards, which renames them; a child's seqno continues from its
    parent's, so without a shard present on both sides the highest seqno still counts the
    blocks of one shard chain."""
    steps = [after[s] - before[s] for s in after if s in before and after[s] > before[s]]
    if not steps and before and after and max(after.values()) > max(before.values()):
        steps = [max(after.values()) - max(before.values())]
    if not steps or seconds <= 0:
        raise lib.TestnetError("no basechain block was produced while measuring")
    return seconds * len(steps) / sum(steps)


def pack_size(rate: float) -> int:
    """Batches per external message: one at low rates (each goes out at once), up to four
    as the rate rises, so the external message count stays near two per second."""
    if rate <= 0:
        raise lib.TestnetError("the rate must be positive")
    return max(1, min(SUBMISSIONS_PER_EXTERNAL, math.ceil(rate / 2)))


class SendWindow:
    """At most `limit` sends in any `window` seconds."""

    def __init__(self, limit: int = ENDPOINT_EXTERNALS, window: float = ENDPOINT_WINDOW):
        if limit <= 0 or window <= 0:
            raise lib.TestnetError("a send window needs a positive limit and length")
        self.limit = limit
        self.window = window
        self.sent: list[float] = []

    def allow(self, now: float) -> bool:
        self.sent = [t for t in self.sent if t > now - self.window]
        return len(self.sent) < self.limit

    def record(self, now: float) -> None:
        self.sent.append(now)


class Relayer:
    def __init__(self, index: int, address: str):
        self.index = index
        self.base = f"relayer-{index}"
        self.subwallet = RELAYER_SUBWALLET_BASE + index
        self.address = address
        self.seqno = 0
        self.inflight: dict | None = None
        self.route: Chain | None = None
        self.retries = 0


class LoadDriver:
    """Keys, deployment and the send loop. All signing material lives in `state`."""

    def __init__(self, args: argparse.Namespace, chain: Chain, global_id: int):
        self.args = args
        self.chain = chain
        self.global_id = global_id
        self.state = Path(args.state)
        self.tos_root = Path(args.tos_root)
        # The wallet code is compiled into the build: <build>/crypto/fift and
        # <build>/crypto/smartcont/auto/pq-highload-wallet-code.fif.
        build = Path(args.fift).resolve().parent.parent
        self.wallet_code = build / "crypto" / "smartcont" / "auto" / "pq-highload-wallet-code.fif"
        self.include = ":".join(
            str(p)
            for p in (
                self.tos_root / "crypto" / "fift" / "lib",
                self.tos_root / "crypto" / "smartcont",
                build / "crypto" / "smartcont",
            )
        )
        self.actions = int(args.actions_per_batch)
        batch_gas(self.actions)
        self.transfer = (
            int(args.transfer_nanotos) if args.transfers == "deliver" else SKIP_TRANSFER_NANOTOS
        )
        self.measured_gas: int | None = None
        self.stop = False
        self.value = 0
        self.counts = {"batches_sent": 0, "batches_accepted": 0, "batches_failed": 0}
        self.counts.update(externals_sent=0, externals_failed=0, verified=0, refused=0)
        self.counts.update(externals_throttled=0, unconfirmed=0)
        self.topped_up = 0
        self.refill_error: str | None = None
        self.endpoints = [
            (Chain(url, chain.rpc), SendWindow()) for url in (args.send_rpc or [chain.url])
        ]
        self.saved = self.load_state()
        self.previous: list[dict[str, str]] = []

    # -- files

    def load_state(self) -> dict:
        path = self.state / STATE_FILE
        if path.is_file():
            return json.loads(path.read_text())
        return {"next_query_id": 0}

    def save_state(self) -> None:
        path = self.state / STATE_FILE
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.saved, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        tmp.replace(path)

    def fift(self, program: str, cwd: Path) -> str:
        script = cwd / f"prog-{os.getpid()}-{time.monotonic_ns()}.fif"
        script.write_text(program)
        try:
            result = subprocess.run(
                [self.args.fift, "-I", self.include, "-s", str(script)],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        finally:
            script.unlink()
        if result.returncode != 0:
            raise lib.TestnetError(f"fift failed: {(result.stdout + result.stderr)[-800:]}")
        return result.stdout

    def gid_file(self) -> Path:
        path = self.state / "gid.fif"
        path.write_text(f"{self.global_id} constant tos-global-id\n")
        return path

    def ensure_keys(self, relayers: int) -> tuple[str, list[Relayer]]:
        """Create the wallet key, the wallet state and the relayer wallets once."""
        lib.private_dir(self.state)
        key = self.state / "highload.key"
        if not key.is_file():
            lib.run([self.args.key_tool, "keygen", str(key)], timeout=30)
        os.chmod(key, 0o600)
        if not (self.state / "highload.addr").is_file():
            if not self.wallet_code.is_file():
                raise lib.TestnetError(f"{self.wallet_code} is missing; --fift must be a build's")
            public = lib.run([self.args.key_tool, "public", str(key)], timeout=30).stdout.strip()
            pub = bytes.fromhex(public)
            if len(pub) != lib.PQ_PUBLIC_KEY_BYTES:
                raise lib.TestnetError(f"the key tool printed {len(pub)} public key bytes")
            (self.state / "highload.pub").write_bytes(pub)
            script = self.tos_root / "crypto" / "smartcont" / "new-pq-highload-wallet.fif"
            result = subprocess.run(
                [
                    self.args.fift,
                    "-I",
                    self.include,
                    "-s",
                    str(script),
                    str(HIGHLOAD_SUBWALLET),
                    str(self.args.wallet_timeout),
                    "highload.pub",
                    "highload",
                ],
                cwd=self.state,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0 or not (self.state / "highload.addr").is_file():
                raise lib.TestnetError(f"wallet state: {(result.stdout + result.stderr)[-600:]}")
            self.saved["wallet_timeout"] = int(self.args.wallet_timeout)
            self.save_state()
        # Every request repeats the timeout the wallet was created with.
        self.timeout = int(self.saved.get("wallet_timeout", self.args.wallet_timeout))
        wallet = address_from_file(self.state / "highload.addr")
        gid = self.gid_file()
        out = []
        for index in range(relayers):
            relayer_base = f"relayer-{index}"
            if not (self.state / f"{relayer_base}.addr").is_file():
                result = subprocess.run(
                    [
                        self.args.fift,
                        "-I",
                        self.include,
                        "-L",
                        str(gid),
                        "-s",
                        str(self.tos_root / "crypto" / "smartcont" / "new-wallet-v3.fif"),
                        "0",
                        str(RELAYER_SUBWALLET_BASE + index),
                        relayer_base,
                    ],
                    cwd=self.state,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode != 0:
                    raise lib.TestnetError(f"relayer {index}: {result.stdout[-400:]}")
            os.chmod(self.state / f"{relayer_base}.pk", 0o600)
            out.append(Relayer(index, address_from_file(self.state / f"{relayer_base}.addr")))
        # A --state directory carried over a reset would reuse every key in it.
        # Labels carry the high-load wallet's address, so a second --state
        # directory in the same epoch records its own wallets beside the first.
        tag = f"load-{wallet.split(':')[1][:8]}"
        wallets = {f"{tag}/highload": wallet}
        wallets.update({f"{tag}/{r.base}": r.address for r in out})
        record_fresh_wallets(Path(self.args.ceremony), wallets, self.previous)
        return wallet, out

    # -- deployment

    def fund_from_bootstrap(self, to: str, nanotos: int, label: str, init: Path | None) -> None:
        amount = f"{nanotos // NANO}.{nanotos % NANO:09d}"
        fund(
            argparse.Namespace(
                ceremony=self.args.ceremony,
                tos_root=self.args.tos_root,
                fift=self.args.fift,
                to=to,
                amount=amount,
                label=label,
                dry_run=False,
                init=init,
            ),
            self.chain,
            self.global_id,
        )

    def deploy(self, wallet: str, relayers: list[Relayer]) -> None:
        target = parse_tos(self.args.deploy_amount, "--deploy-amount")
        state, balance = self.chain.account(wallet)
        if state != "active":
            print(f"deploy the wallet {wallet} with {target / NANO:.3f} TOS", flush=True)
            self.fund_from_bootstrap(
                wallet, target, "load-wallet", self.state / "highload.init.boc"
            )
            self.chain.wait_active(wallet)
        elif balance < target // 2:
            print(f"top up the wallet {wallet} to {target / NANO:.3f} TOS", flush=True)
            self.fund_from_bootstrap(wallet, target - balance, "load-wallet-top-up", None)
        relayer_amount = parse_tos(self.args.relayer_amount, "--relayer-amount")
        for relayer in relayers:
            state, balance = self.chain.account(relayer.address)
            if balance < relayer_amount // 2:
                print(f"fund relayer {relayer.index} {relayer.address}", flush=True)
                self.fund_from_bootstrap(
                    relayer.address, relayer_amount - balance, f"load-relayer-{relayer.index}", None
                )
                state = self.chain.account(relayer.address)[0]
            if state != "active":
                print(f"activate relayer {relayer.index}", flush=True)
                self.chain.send_boc((self.state / f"{relayer.base}-query.boc").read_bytes())
                self.chain.wait_active(relayer.address)
        for relayer in relayers:
            relayer.seqno = self.chain.seqno(relayer.address)

    # -- batches

    def take_query_ids(self, count: int) -> list[int]:
        ids = []
        query_id = int(self.saved["next_query_id"])
        for _ in range(count):
            ids.append(query_id)
            query_id = next_query_id(query_id)
        self.saved["next_query_id"] = query_id
        self.save_state()
        return ids

    def build(
        self, work: Path, wallet: str, recipients: list[str], plan: list[tuple[Relayer, int]]
    ) -> list[tuple[Relayer, list[int], Path]]:
        """Build, sign and wrap: for each (relayer, batches) one external message."""
        total = sum(n for _, n in plan)
        ids = self.take_query_ids(total)
        created = int(time.time()) - CREATED_AT_SLACK
        hashes = parse_request_hashes(
            self.fift(
                request_program(
                    self.global_id,
                    wallet,
                    recipients,
                    self.actions,
                    self.transfer,
                    self.timeout,
                    [(q, created) for q in ids],
                ),
                work,
            )
        )
        if set(hashes) != set(ids):
            raise lib.TestnetError("fift did not build every request")
        context = HIGHLOAD_CONTEXT.hex()
        key = str(self.state / "highload.key")

        def sign(query_id: int) -> None:
            out = lib.run(
                [self.args.key_tool, "sign", key, hashes[query_id], context], timeout=30
            ).stdout.strip()
            signature = bytes.fromhex(out)
            if len(signature) != MLDSA44_SIGNATURE_BYTES:
                raise lib.TestnetError(f"the key tool printed a {len(signature)}-byte signature")
            (work / f"sig-{query_id}.bin").write_bytes(signature)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(sign, ids))
        value = self.value
        bodies = []
        externals = []
        at = 0
        valid_until = int(time.time()) + EXTERNAL_TTL
        for relayer, count in plan:
            mine = ids[at : at + count]
            at += count
            name = f"ext-{relayer.index}-{relayer.seqno}-{mine[0]}.boc"
            bodies.append(
                external_body(
                    relayer.base,
                    relayer.address,
                    relayer.subwallet,
                    relayer.seqno,
                    valid_until,
                    [(q, value) for q in mine],
                    name,
                )
            )
            externals.append((relayer, mine, work / name))
        self.fift(externals_program(self.global_id, wallet, bodies), work)
        for _, _, path in externals:
            if not path.is_file():
                raise lib.TestnetError(f"fift did not write {path.name}")
        return externals

    def links(self, work: Path) -> None:
        """The relayer keys, visible to Fift in the work directory."""
        for path in self.state.glob("relayer-*.pk"):
            target = work / path.name
            if not target.exists():
                target.symlink_to(path)

    # -- safety

    def balances(self, wallet: str, relayers: list[Relayer]) -> dict[str, int]:
        out = {"wallet": self.chain.account(wallet)[1]}
        for relayer in relayers:
            out[relayer.base] = self.chain.account(relayer.address)[1]
        return out

    def refill(self, relayers: list[Relayer], done: threading.Event) -> None:
        """Top relayers back up from the bootstrap wallet, off the send loop: the relayers
        pay for every batch (value for compute, import and forwarding fees)."""
        amount = parse_tos(self.args.relayer_amount, "--relayer-amount")
        while not done.wait(5):
            for relayer in relayers:
                if done.is_set():
                    return
                try:
                    balance = self.chain.account(relayer.address)[1]
                    if balance < amount // 3:
                        self.fund_from_bootstrap(
                            relayer.address,
                            amount - balance,
                            f"load-refill-{relayer.index}",
                            None,
                        )
                        self.topped_up += amount - balance
                except (lib.TestnetError, OSError, KeyError, ValueError) as exc:
                    self.refill_error = f"refilling relayer {relayer.index}: {exc}"
                    return

    def check_safety(self, wallet: str, relayers: list[Relayer]) -> str | None:
        if self.refill_error:
            return self.refill_error
        for url in [self.chain.url] + list(self.args.watch_rpc or []):
            try:
                age = head_age(Chain(url, self.chain.rpc))
            except (lib.TestnetError, OSError, KeyError, ValueError) as exc:
                return f"{url} did not answer: {exc}"
            if age > MAX_HEAD_AGE:
                return f"{url} masterchain head is {age} s old"
        floor = parse_tos(self.args.wallet_floor, "--wallet-floor")
        balance = self.chain.account(wallet)[1]
        if balance < floor:
            return f"the wallet balance {balance / NANO:.3f} TOS is below the floor"
        relayer_floor = parse_tos(self.args.relayer_floor, "--relayer-floor")
        for relayer in relayers:
            balance = self.chain.account(relayer.address)[1]
            if balance < relayer_floor:
                return (
                    f"relayer {relayer.index} balance {balance / NANO:.3f} TOS is below the floor"
                )
        bootstrap = self.chain.account(BOOTSTRAP_WALLET)[1]
        if bootstrap < parse_tos(self.args.bootstrap_floor, "--bootstrap-floor"):
            return f"the bootstrap wallet balance {bootstrap / NANO:.3f} TOS is below the floor"
        return None

    # -- run

    def required_value(self, wallet: str, actions: int | None = None) -> int:
        result = self.chain.rpc(
            self.chain.url,
            "runGetMethod",
            address=wallet,
            method="get_required_value",
            stack=[["num", str(actions or self.actions)]],
        )
        if result.get("exit_code") != 0:
            raise lib.TestnetError(f"get_required_value failed: {result}")
        return int(result["stack"][0][1], 0)

    def processed(self, wallet: str, query_id: int) -> bool:
        result = self.chain.rpc(
            self.chain.url,
            "runGetMethod",
            address=wallet,
            method="processed?",
            stack=[["num", str(query_id)], ["num", "0"]],
        )
        if result.get("exit_code") != 0:
            raise lib.TestnetError(f"processed? failed: {result}")
        return int(result["stack"][0][1], 0) != 0

    def measure_gas(self, wallet: str) -> int | None:
        """Median gas of the wallet's recent executed batches, from the chain."""
        price, lump = price_and_lump(self.required_value(wallet, 1), self.required_value(wallet, 2))
        txs = self.chain.transactions(wallet, 20)
        gas = sorted(g for g in (gas_from_transaction(t, price, lump) for t in txs) if g)
        return gas[len(gas) // 2] if gas else None

    def gas_per_batch(self) -> int:
        return self.measured_gas or batch_gas(self.actions)

    def dry_run(self) -> Path:
        wallet, relayers = self.ensure_keys(1)
        relayer = relayers[0]
        try:
            if self.chain.account(relayer.address)[0] == "active":
                relayer.seqno = self.chain.seqno(relayer.address)
        except (lib.TestnetError, OSError) as exc:
            print(f"cannot read relayer 0 ({exc}); signing with seqno 0")
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        work = lib.private_dir(self.state / f"dry-run-{stamp}")
        self.links(work)
        self.value = submission_value(self.chain_required_or_estimate(wallet))
        [(_, ids, path)] = self.build(work, wallet, [relayer.address], [(relayer, 1)])
        size = path.stat().st_size
        report = {
            "wallet": wallet,
            "relayer": relayer.address,
            "relayer_seqno": relayer.seqno,
            "query_ids": ids,
            "actions": self.actions,
            "transfers_mode": self.args.transfers,
            "transfer_nanotos": self.transfer,
            "submission_value_nanotos": self.value,
            "estimated_gas": batch_gas(self.actions),
            "external_bytes": size,
            "external": path.name,
        }
        lib.write_new_json(work / "dry-run.json", report, 0o600)
        print(json.dumps(report, indent=2))
        print(f"dry run: one batch signed and kept in {work}, nothing broadcast")
        return work

    def chain_required_or_estimate(self, wallet: str) -> int:
        try:
            if self.chain.account(wallet)[0] == "active":
                return self.required_value(wallet)
        except (lib.TestnetError, OSError):
            pass
        # Not deployed yet: the gas price from ConfigParam 21 is not read here, so use a
        # generous fixed quote (10 nanotos per gas).
        return 10 * (batch_gas(self.actions) + 60_000)

    def rate(self) -> tuple[float, float | None]:
        if self.args.batches_per_second:
            return float(self.args.batches_per_second), None
        before = basechain_heads(self.chain)
        start = time.monotonic()
        time.sleep(self.args.measure_seconds)
        interval = block_interval(before, basechain_heads(self.chain), time.monotonic() - start)
        return batch_rate(
            int(self.args.target_gas_per_block), batch_gas(self.actions), interval
        ), interval

    def run(self) -> dict:
        relayer_count = int(self.args.relayers)
        if not 1 <= relayer_count <= 64:
            raise lib.TestnetError("--relayers must be 1..64")
        self.previous = previous_wallets(self.args)
        if self.args.dry_run:
            self.dry_run()
            return {}
        wallet, relayers = self.ensure_keys(relayer_count)
        self.deploy(wallet, relayers)
        recipients = [r.address for r in relayers]
        self.value = submission_value(self.required_value(wallet))
        rate, interval = self.rate()
        delivered = rate * self.actions
        if self.args.transfers == "deliver" and delivered > MAX_DELIVERED_PER_SECOND:
            raise lib.TestnetError(
                f"{delivered:.0f} delivered transfers/s would build a dispatch-queue backlog "
                f"(over {MAX_DELIVERED_PER_SECOND}/s); use --transfers skip or fewer actions"
            )
        reason = self.check_safety(wallet, relayers)
        if reason:
            raise lib.TestnetError(f"not starting: {reason}")
        start_balances = self.balances(wallet, relayers)
        print(
            f"load: {rate:.2f} batches/s of {self.actions} transfers "
            f"(~{rate * batch_gas(self.actions):,.0f} gas/s"
            + (f", block interval {interval:.3f} s" if interval else "")
            + f"), {len(relayers)} relayers, {self.args.duration} s",
            flush=True,
        )
        work = Path(tempfile.mkdtemp(prefix="load-", dir=self.state))
        self.links(work)
        started = time.time()
        stop_reason = "duration reached"
        old_handler = signal.signal(signal.SIGINT, self.on_sigint)
        refill_done = threading.Event()
        refiller = threading.Thread(target=self.refill, args=(relayers, refill_done), daemon=True)
        refiller.start()
        pool = ThreadPoolExecutor(max_workers=max(8, len(relayers)))
        tokens = 0.0
        last = time.monotonic()
        next_log = last + 1
        next_safety = last + 5
        next_poll = last
        pending_checks: list[tuple[float, int]] = []
        log_prev = dict(self.counts)
        try:
            while not self.stop:
                now = time.monotonic()
                if time.time() - started >= self.args.duration:
                    break
                tokens = min(tokens + rate * (now - last), rate * 2 + SUBMISSIONS_PER_EXTERNAL)
                last = now
                if now >= next_poll:
                    next_poll = now + POLL_SECONDS
                    busy = [r for r in relayers if r.inflight]
                    for relayer, seqno in zip(busy, pool.map(self.try_seqno, busy)):
                        self.settle(relayer, seqno, pending_checks)
                free = [r for r in relayers if not r.inflight]
                plan = []
                routes = []
                pack = pack_size(rate)
                for relayer in free:
                    if tokens < pack:
                        break
                    route = next((e for e in self.endpoints if e[1].allow(now)), None)
                    if route is None:
                        break
                    route[1].record(now)
                    plan.append((relayer, pack))
                    routes.append(route[0])
                    tokens -= pack
                if plan:
                    externals = self.build(work, wallet, recipients, plan)
                    results = list(pool.map(self.send, externals, routes))
                    for (relayer, ids, path), error, route in zip(externals, results, routes):
                        self.counts["externals_sent"] += 1
                        self.counts["batches_sent"] += len(ids)
                        path.unlink(missing_ok=True)
                        for q in ids:
                            (work / f"req-{q}.boc").unlink(missing_ok=True)
                            (work / f"sig-{q}.bin").unlink(missing_ok=True)
                        if error:
                            self.fail(relayer, len(ids), error)
                            seqno = self.try_seqno(relayer)
                            if seqno is not None:
                                relayer.seqno = seqno
                        else:
                            relayer.route = route
                            relayer.inflight = {
                                "seqno": relayer.seqno,
                                "ids": ids,
                                "expires": time.time() + EXTERNAL_TTL + 5,
                            }
                self.verify(wallet, pending_checks)
                if self.measured_gas is None and self.counts["verified"] >= 8:
                    rate = self.remeasure(wallet, rate, interval)
                if now >= next_safety:
                    next_safety = now + 5
                    reason = self.check_safety(wallet, relayers)
                    if reason:
                        stop_reason = f"safety stop: {reason}"
                        print(f"load: {stop_reason}", flush=True)
                        break
                if now >= next_log:
                    next_log = now + 1
                    delta = {k: self.counts[k] - log_prev[k] for k in self.counts}
                    log_prev = dict(self.counts)
                    print(
                        f"{time.strftime('%H:%M:%S', time.gmtime())} "
                        f"sent {delta['batches_sent']} accepted {delta['batches_accepted']} "
                        f"failed {delta['batches_failed']} | totals sent "
                        f"{self.counts['batches_sent']} accepted {self.counts['batches_accepted']} "
                        f"failed {self.counts['batches_failed']} executed {self.counts['verified']} "
                        f"refused {self.counts['refused']} in flight "
                        f"{sum(1 for r in relayers if r.inflight)}",
                        flush=True,
                    )
                time.sleep(0.05)
            if self.stop:
                stop_reason = "interrupted"
            # Let what is in flight land or expire, then check the last ones.
            deadline = time.time() + EXTERNAL_TTL + 10
            while any(r.inflight for r in relayers) and time.time() < deadline:
                for relayer in [r for r in relayers if r.inflight]:
                    self.settle(relayer, self.try_seqno(relayer), pending_checks)
                time.sleep(1)
            deadline = time.time() + EXECUTION_GRACE + 5
            while pending_checks and time.time() < deadline:
                self.verify(wallet, pending_checks)
                time.sleep(1)
            for item in pending_checks:
                self.counts["unconfirmed"] += len(item[1])
        finally:
            signal.signal(signal.SIGINT, old_handler)
            pool.shutdown(wait=True)
            refill_done.set()
            refiller.join(timeout=120)
            shutil.rmtree(work, ignore_errors=True)
        ended = time.time()
        end_balances = self.balances(wallet, relayers)
        spent = sum(start_balances.values()) + self.topped_up - sum(end_balances.values())
        accepted = self.counts["batches_accepted"]
        summary = {
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
            "ended": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ended)),
            "seconds": round(ended - started, 1),
            "stop_reason": stop_reason,
            "wallet": wallet,
            "relayers": len(relayers),
            "actions_per_batch": self.actions,
            "transfers_mode": self.args.transfers,
            "transfer_nanotos": self.transfer,
            "target_batches_per_second": round(rate, 3),
            "measured_block_interval": interval,
            "target_gas_per_block": self.args.target_gas_per_block,
            **self.counts,
            "transfers": accepted * self.actions,
            "transfers_delivered": accepted * self.actions
            if self.args.transfers == "deliver"
            else 0,
            "relayer_top_ups_tos": round(self.topped_up / NANO, 6),
            "gas_per_batch": self.gas_per_batch(),
            "gas_per_batch_measured": bool(self.measured_gas),
            "estimated_gas": accepted * self.gas_per_batch(),
            "estimated_gas_per_second": round(
                accepted * self.gas_per_batch() / max(ended - started, 1)
            ),
            "balances_start_nanotos": start_balances,
            "balances_end_nanotos": end_balances,
            "fees_spent_tos": round(spent / NANO, 6),
        }
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started))
        lib.write_new_json(self.state / f"summary-{stamp}.json", summary, 0o600)
        print(json.dumps(summary, indent=2))
        return summary

    def remeasure(self, wallet: str, rate: float, interval: float | None) -> float:
        """Replace the profile estimate with the chain's figure; at a gas target, rescale."""
        try:
            gas = self.measure_gas(wallet)
        except (lib.TestnetError, OSError, KeyError, ValueError) as exc:
            print(f"load: cannot measure gas yet: {exc}", flush=True)
            gas = None
        if gas is None:
            self.measured_gas = 0  # tried; keep the estimate
            return rate
        self.measured_gas = gas
        if interval and self.args.target_gas_per_block:
            rate = batch_rate(int(self.args.target_gas_per_block), gas, interval)
        print(f"load: measured {gas:,} gas per batch; rate {rate:.2f} batches/s", flush=True)
        return rate

    def on_sigint(self, _signum, _frame) -> None:
        print("load: interrupted, stopping after the messages in flight", flush=True)
        self.stop = True

    def try_seqno(self, relayer: Relayer) -> int | None:
        """The relayer's seqno, read where it was sent: the reads spread over the
        endpoints, each of which admits 600 requests per 10 s from one address."""
        try:
            return (relayer.route or self.chain).seqno(relayer.address)
        except (lib.TestnetError, OSError, KeyError, ValueError):
            return None

    def send(self, external: tuple[Relayer, list[int], Path], route: Chain) -> str | None:
        try:
            route.send_boc(external[2].read_bytes())
        except (lib.TestnetError, OSError, ValueError) as exc:
            return str(exc)
        return None

    def fail(self, relayer: Relayer, batches: int, error: str) -> None:
        self.counts["batches_failed"] += batches
        self.counts["externals_failed"] += 1
        if "rate limit" in error:
            # The node's admission window, not this relayer: not a retry.
            self.counts["externals_throttled"] += 1
            return
        relayer.retries += 1
        print(f"relayer {relayer.index}: {error[:200]}", flush=True)
        if relayer.retries > self.args.max_retries:
            raise lib.TestnetError(
                f"relayer {relayer.index} failed {relayer.retries} times in a row: {error[:200]}"
            )

    def settle(self, relayer: Relayer, seqno: int | None, checks: list) -> None:
        flight = relayer.inflight
        if flight is None:
            return
        if seqno is not None and seqno > flight["seqno"]:
            relayer.seqno = seqno
            relayer.inflight = None
            relayer.retries = 0
            self.counts["batches_accepted"] += len(flight["ids"])
            accepted = time.time()
            checks.append((accepted + 3, flight["ids"], accepted + EXECUTION_GRACE))
        elif time.time() > flight["expires"]:
            relayer.inflight = None
            if seqno is not None:
                relayer.seqno = seqno
            self.fail(relayer, len(flight["ids"]), "the external message expired unprocessed")

    def verify(self, wallet: str, checks: list) -> None:
        """Whether the wallet executed accepted batches: one getter call per external.
        A full shard carries inbound messages over to later blocks, so a batch not yet
        executed is checked again until EXECUTION_GRACE after its acceptance."""
        now = time.time()
        for item in [c for c in checks if c[0] <= now]:
            checks.remove(item)
            try:
                done = self.processed(wallet, item[1][-1])
            except (lib.TestnetError, OSError):
                done = None
            if done:
                self.counts["verified"] += len(item[1])
            elif now < item[2]:
                checks.append((now + 3, item[1], item[2]))
            elif done is False:
                self.counts["refused"] += len(item[1])
            else:
                checks.append((now + 3, item[1], item[2]))


def check_load_args(args: argparse.Namespace) -> None:
    if not args.dry_run and not (args.target_gas_per_block or args.batches_per_second):
        raise lib.TestnetError("give --target-gas-per-block or --batches-per-second")
    if args.batches_per_second is not None and args.batches_per_second <= 0:
        raise lib.TestnetError("--batches-per-second must be positive")
    if args.duration <= 0 or args.max_retries < 0:
        raise lib.TestnetError("--duration must be positive and --max-retries not negative")
    if not 1 <= args.wallet_timeout <= 4194303:
        raise lib.TestnetError("--wallet-timeout must be 1..4194303 s")
    if args.transfer_nanotos < 0:
        raise lib.TestnetError("--transfer-nanotos cannot be negative")
    batch_gas(args.actions_per_batch)


# ---------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", type=Path, default=lib.PROFILE_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    for flag in ("--ceremony", "--tos-root", "--fift", "--rpc"):
        common.add_argument(flag, required=True)
    p_fund = sub.add_parser("fund", parents=[common])
    p_fund.add_argument("--to", required=True)
    p_fund.add_argument("--amount", required=True)
    p_fund.add_argument("--label", required=True)
    p_fund.add_argument("--dry-run", action="store_true")
    p_onboard = sub.add_parser("onboard", parents=[common])
    for flag in (
        "--name",
        "--host",
        "--ssh-key",
        "--controller",
        "--root-seed",
        "--controller-tool",
    ):
        p_onboard.add_argument(flag, required=True)
    p_onboard.add_argument("--previous-ceremony", action="append", default=[])
    p_refund = sub.add_parser("refund", parents=[common])
    for flag in (
        "--name",
        "--host",
        "--ssh-key",
        "--controller",
        "--root-seed",
        "--controller-tool",
    ):
        p_refund.add_argument(flag, required=True)
    p_refund.add_argument("--target-nanotos", type=int)
    p_refund.add_argument("--dry-run", action="store_true")
    p_refund.add_argument("--i-checked-the-window", action="store_true")
    p_withdraw = sub.add_parser("withdraw", parents=[common])
    p_withdraw.add_argument("--name", required=True)
    how_much = p_withdraw.add_mutually_exclusive_group(required=True)
    how_much.add_argument("--amount")
    how_much.add_argument("--all", action="store_true")
    p_withdraw.add_argument("--during-election", action="store_true")
    p_withdraw.add_argument("--dry-run", action="store_true")
    p_load = sub.add_parser("load", parents=[common])
    p_load.add_argument("--previous-ceremony", action="append", default=[])
    p_load.add_argument("--key-tool", "--signer", dest="key_tool", required=True)
    p_load.add_argument("--state", required=True)
    p_load.add_argument("--deploy-amount", default="50")
    p_load.add_argument("--relayers", type=int, default=16)
    p_load.add_argument("--relayer-amount", default="50")
    rate = p_load.add_mutually_exclusive_group()
    rate.add_argument("--target-gas-per-block", type=int)
    rate.add_argument("--batches-per-second", type=float)
    p_load.add_argument("--actions-per-batch", type=int, default=HIGHLOAD_MAX_ACTIONS)
    p_load.add_argument("--transfers", choices=("skip", "deliver"), default="skip")
    p_load.add_argument("--transfer-nanotos", type=int, default=50_000)
    p_load.add_argument("--duration", type=int, default=300)
    p_load.add_argument("--wallet-timeout", type=int, default=3600)
    p_load.add_argument("--measure-seconds", type=float, default=15)
    p_load.add_argument("--max-retries", type=int, default=5)
    p_load.add_argument("--wallet-floor", default="5")
    p_load.add_argument("--relayer-floor", default="2")
    p_load.add_argument("--bootstrap-floor", default="100")
    p_load.add_argument("--watch-rpc", action="append")
    p_load.add_argument("--send-rpc", action="append")
    p_load.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        profile = lib.load_profile(args.profile)
        global_id = lib.confirmed_global_id(profile)
        chain = Chain(args.rpc)
        if args.command == "fund":
            fund(args, chain, global_id)
        elif args.command == "load":
            check_load_args(args)
            os.umask(0o077)
            LoadDriver(args, chain, global_id).run()
        elif args.command == "refund":
            refund(args, chain, global_id, profile)
        elif args.command == "withdraw":
            withdraw(args, chain, global_id)
        else:
            onboard(args, chain, global_id, profile)
    except (lib.TestnetError, OSError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"testnet-elections: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
