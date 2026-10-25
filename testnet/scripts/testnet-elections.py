#!/usr/bin/env python3
"""Bring the four genesis validators into ordinary elections (coordinator side),
and drive load through a post-quantum high-volume wallet.

  fund    --ceremony DIR --tos-root DIR --fift PATH --rpc URL --confirm-rpc URL
          --to ADDRESS --amount TOS --label LABEL [--id ID] [--dry-run]
      Send TOS from the genesis bootstrap wallet (wallet v3 at -1:111...1).
      The transfer is signed with tos crypto/smartcont/wallet-v3.fif and a
      preloaded `<global id> constant tos-global-id`, so the signature commits
      to the testnet global id. Non-bounce, the sender pays fees, 300 s
      expiry. It is operation ID (default: the label; see onboard) and returns
      when both validators show it delivered.

  pool    --name NAME --operator ADDRESS --ceremony DIR --tos-root DIR --fift PATH
          [--previous-ceremony DIR]...
      Before genesis, for one genesis validator: record ADDRESS, the operator
      wallet `init-operator.sh --wallet-only` printed on the host, as op-NAME
      in DIR/wallets.json; make the pool owner, a wallet v3 in the masterchain
      (subwallet 0x504F4F4C) whose key is created here in
      DIR/secret/pool-owner-NAME.pk and never leaves this machine (address and
      self-deploy message in DIR/pool-owners/, label pool-owner-NAME in
      wallets.json); and derive the single-nominator pool of that owner and
      validator from the pinned code. The pool is the validator's staking
      account: its address is the validator id the operator's genesis record
      names and the node is bound to. Records pool, owner and operator in
      DIR/pools.json and prints them. Refuses a wallet an earlier epoch's
      ceremony recorded (see "Resets" below). Moves no value, reads no node.

  onboard --name NAME --host HOST --ssh-key FILE --ceremony DIR
          --tos-root DIR --fift PATH --rpc URL --confirm-rpc URL
          [--previous-ceremony DIR]...
      For one genesis validator whose pool `pool` recorded and the genesis
      records name as a validator id, in order, stopping at the first failure:
      init-operator.sh on the host, refusing unless its operator wallet is the
      recorded op-NAME; fund it from the bootstrap wallet with fee money only
      (operator_funding_tos) and activate it; fund the pool owner with the
      stake money and activate it; deploy the pool (the StateInit derived here
      from the pinned code, the owner and the operator wallet) with
      pool_deploy_tos from the operator wallet; configure the pool and the
      binding in tosctl on the host; have the owner send the principal
      (pool_tos); check that the pool holds two stakes and that the node
      reports custody for the pool's id; enable-elections.sh.

      Every step that moves value is an operation (testnet_ops.py; ids
      fund-op-, fund-owner-, activate-owner-, deploy-pool-, principal-NAME)
      journaled in DIR/operations/.
      The operator wallet's messages are built on the host by `tosctl wallet
      send --build-only` and checked, journaled and broadcast from here.
      Before each signature the signing wallet's history since its newest
      settled operation (or its baseline, or all of it when it has neither) is
      read on both --rpc and --confirm-rpc; unexplained transfers, another open
      operation of the wallet or history the two do not agree on refuse.
      Settlement is by hashes, on both. A rerun skips settled operations,
      resumes the configuration from the host's tosctl config, and refuses an
      open operation: a person resolves it with reconcile, record or resubmit.

  withdraw --name NAME --id ID [--new] --ceremony DIR --tos-root DIR --fift PATH
          --rpc URL --confirm-rpc URL (--amount TOS | --all)
          [--dry-run]
      Take stake principal out of NAME's pool (DIR/pools.json) to its owner, as
      operation ID (--new creates it; an existing id never changes its
      parameters, and a settled one only reports its outcome). The pool's
      WITHDRAW (op 0x1000, the pool's own withdraw.fif) is signed here with the
      owner's offline key as a bounceable 1 TOS transfer from the owner wallet.
      Refused while an election is open, and unless
      the pool is the recorded address with the pinned code and the owner role
      (the validator role may have been replaced). It settles when both
      validators show the pool's payment and the owner's transaction that kept
      it, at least the requested --amount (--all accepts a variable payment).
      A short payment is a terminal failure recording what was paid; a settled
      result is appended to DIR/withdrawals.jsonl. Only liquid balance can leave:
      a stake returns to the pool after stake_held_for.

  change-validator --name NAME --id ID [--new] --to ADDR --ceremony DIR
          --tos-root DIR --fift PATH --rpc URL --confirm-rpc URL [--dry-run]
      Give NAME's pool a new validator wallet ADDR (masterchain), as operation
      ID. The pool's CHANGE_VALIDATOR_ADDRESS (op 0x1001, the pool's own
      change-validator.fif) is signed here with the owner's offline key as a
      bounceable 0.1 TOS transfer from the owner wallet; the pool keeps the
      value. Refused while an election is open, when ADDR already holds the
      role, and unless the pool is the recorded address with the pinned code and
      the owner role. It settles when get_roles on both validators shows
      (owner, ADDR); a settled result is appended to DIR/validator-changes.jsonl.
      Restoring the operator wallet is the same command with --to set to it.

  reconcile | record --id ID (--settled | --failed a|b|c|d | --abandoned | --checkpoint) [--hint TX]
          | resubmit --id ID | baseline --wallet ADDR --reason TEXT
          (with --ceremony DIR --tos-root DIR --fift PATH --rpc URL --confirm-rpc URL)
      The person's side of an open operation (testnet_ops.py): reconcile
      prints every record against the chain and every unexplained transfer;
      record verifies the evidence on both validators before it writes;
      resubmit sends the original message while it can still execute;
      baseline accepts a wallet's history from before the journal.

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
reset accepts again whatever was signed for it on an earlier epoch. pool, onboard
and load take --previous-ceremony once for every earlier epoch's ceremony directory
and refuse a wallet identity recorded there (its wallets.json, the bootstrap key
in its genesis.json, or for a ceremony older than both its secret/main-wallet.pk,
whose public key fift derives). A previous ceremony that records nothing is
refused. An operator whose host kept /var/lib/tos-ctl over the reset still has
the old wallet key; init-operator.sh then prints the old address and pool
refuses it before a pool is derived from it.

URL is a JSON-RPC endpoint of a live node (for example a validator's loopback
listener through an SSH tunnel, http://127.0.0.1:18081/jsonRPC). The amounts
are network/profile.json `elections`. The pool owners' keys and the bootstrap
key never leave this machine; the host only ever sees the signed messages.
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
import testnet_ops as ops  # noqa: E402

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

    def code_hash(self, address: str) -> tuple[str, bytes | None]:
        """The account's state and the representation hash of its code (None without code)."""
        info = self.rpc(self.url, "getAddressInformation", address=address)
        code = info.get("code") or ""
        return info["state"], lib.parse_boc(base64.b64decode(code)).hash() if code else None

    def pool_roles(self, address: str) -> tuple[str, str]:
        """A single-nominator pool's get_roles: (owner, validator).

        The node lists a getter's results top of stack first, so the stack reads
        validator, owner."""
        result = self.rpc(self.url, "runGetMethod", address=address, method="get_roles", stack=[])
        stack = result.get("stack") or []
        if result.get("exit_code") != 0 or len(stack) != 2:
            raise lib.TestnetError(f"get_roles of {address} failed: {result}")
        roles = []
        for entry in stack:
            if (
                not isinstance(entry, list)
                or len(entry) != 2
                or entry[0] != "slice"
                or not isinstance(entry[1], dict)
                or not isinstance(entry[1].get("bytes"), str)
            ):
                raise lib.TestnetError(f"get_roles of {address}: not an address slice: {entry}")
            roles.append(std_address(lib.parse_boc(base64.b64decode(entry[1]["bytes"]))))
        validator, owner = roles
        return owner, validator

    def send_boc(self, boc: bytes) -> None:
        self.rpc(self.url, "sendBoc", boc=base64.b64encode(boc).decode())

    def transactions(self, address: str, limit: int = 50) -> list:
        return self.rpc(self.url, "getTransactions", address=address, limit=limit)

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


EMPTY_BODY_HASH = lib.cell_from_bits("").hash().hex()


def operations_for(args: argparse.Namespace, global_id: int) -> ops.Operations:
    """The two validators value-moving steps run against: --rpc and --confirm-rpc."""
    confirm = getattr(args, "confirm_rpc", None)
    if not confirm:
        raise lib.TestnetError(
            "value-moving steps need a second validator: --confirm-rpc URL (another node)"
        )
    return ops.Operations(
        Path(args.ceremony),
        [ops.Node(args.rpc), ops.Node(confirm)],
        global_id,
        profile_path=getattr(args, "profile", lib.PROFILE_PATH),
    )


def fund(args: argparse.Namespace, operations: ops.Operations, global_id: int) -> dict | None:
    """A bootstrap transfer as operation fund `args.op_id` (default: its label)."""
    to = check_raw_address(args.to)
    if not re.fullmatch(r"[0-9]+(\.[0-9]{1,9})?", str(args.amount)) or float(args.amount) <= 0:
        raise lib.TestnetError(f"amount must be a positive number of TOS: {args.amount!r}")
    value = parse_tos(str(args.amount), "--amount")
    ceremony = Path(args.ceremony)
    key = ceremony / "secret" / "main-wallet.pk"
    if not key.is_file():
        raise lib.TestnetError(f"{key} is missing; the bootstrap key stays with the coordinator")
    init = getattr(args, "init", None)
    init_hash = lib.parse_boc(Path(init).read_bytes()).hash().hex() if init else None
    op_id = getattr(args, "op_id", None) or args.label

    def sign(seqno: int) -> bytes:
        return sign_wallet_v3(
            args,
            global_id,
            key,
            (ceremony / "main-wallet.addr").read_bytes(),
            to,
            0,
            seqno,
            nanotos_text(value),
            bounce=False,
            init=init,
        )

    if args.dry_run:
        seqno = operations.seqno(BOOTSTRAP_WALLET)
        boc = sign(seqno)
        sent = lib.private_dir(ceremony / "sent")
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        lib.write_new(sent / f"{stamp}-seq{seqno}-{args.label}-dry-run.boc", boc, 0o600)
        print(f"dry run: bootstrap seqno {seqno}, {args.amount} TOS to {to}; signed, not sent")
        return None

    def prerequisites() -> None:
        balance = operations.balance(BOOTSTRAP_WALLET)
        if balance < value + ops.FEE_ALLOWANCE_NANOTOS:
            raise lib.TestnetError(f"the bootstrap wallet holds {balance / NANO:.9f} TOS")

    params = {
        "kind": "fund",
        "wallet": BOOTSTRAP_WALLET,
        "destination": to,
        "value": value,
        "bounce": False,
        "body_hash": EMPTY_BODY_HASH,
        "state_init_hash": init_hash,
        "label": args.label,
        # The bootstrap wallet is wallet v3 with subwallet 0 (gen-zerostate.fif).
        "subwallet": 0,
    }
    record = operations.run(op_id, params, sign, lambda decoded: None, prerequisites)
    print(f"{op_id}: {args.amount} TOS to {to} settled ({record['evidence']['destination_tx']})")
    return record


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


# ---------------------------------------------------------------- the pool owner (offline)

# The single-nominator pool has two roles (tos crypto/smartcont/single-nominator-pool):
# the owner holds the funds and alone can withdraw them, and the validator (the
# operator wallet on the host) can only order a stake to the Elector and recover it.
# The pool itself stands in the election: its address is the validator id. The
# owner here is a wallet v3 in the masterchain whose key is made on this machine,
# beside the bootstrap key, and never copied to a host.
POOL_OWNER_SUBWALLET = 0x504F4F4C
POOLS_FILE = "pools.json"
WITHDRAWALS_FILE = "withdrawals.jsonl"
# The value an owner message carries; the pool sends what it does not spend back
# with the withdrawal (mode 64), so this is only an upper bound on the fee.
OWNER_MESSAGE_NANOTOS = NANO
VALIDATOR_CHANGES_FILE = "validator-changes.jsonl"
# CHANGE_VALIDATOR_ADDRESS sends nothing back: the pool keeps the message value.
CHANGE_MESSAGE_NANOTOS = NANO // 10
# What the pool keeps for storage (MIN_TOS_FOR_STORAGE in single-nominator-code.fc).
POOL_STORAGE_NANOTOS = NANO
# --all asks for more than any pool holds; the pool caps a withdrawal at its
# balance less the message value and its storage reserve.
WITHDRAW_ALL_TOS = "1000000000"


def nanotos_text(nanotos: int) -> str:
    if nanotos <= 0:
        raise lib.TestnetError(f"an amount must be positive: {nanotos} nanotos")
    return f"{nanotos // NANO}.{nanotos % NANO:09d}"


# The single-nominator code tosctl deploys (its CODE_V1_1 is this file's hex), from
# the pinned tos tree the coordinator runs the ceremony from.
SINGLE_NOMINATOR_CODE = Path("crypto/smartcont/single-nominator-pool/single-nominator-code.hex")


def std_address(cell: lib.Cell) -> str:
    """A MsgAddressInt cell holding addr_std without anycast, as workchain:hex."""
    s = lib.Slice(cell)
    if s.bits(3) != 0b100:
        raise lib.TestnetError("not an addr_std without anycast")
    workchain = s.bits(8)
    workchain -= 256 if workchain > 127 else 0
    address = f"{workchain}:{s.bytes(32).hex()}"
    if not s.end():
        raise lib.TestnetError("trailing data after an address")
    return address


def address_bits(address: str) -> str:
    workchain, account = check_raw_address(address).split(":")
    return "100" + format(int(workchain) & 0xFF, "08b") + format(int(account, 16), "0256b")


def single_nominator_code(tos_root: Path | str) -> lib.Cell:
    text = (Path(tos_root) / SINGLE_NOMINATOR_CODE).read_text().strip()
    return lib.parse_boc(bytes.fromhex(text))


def pool_state_init(code: lib.Cell, owner: str, validator: str) -> lib.Cell:
    """A single-nominator pool's StateInit, as the pool's init.fif and tosctl build it:
    the pinned code and a data cell of the two addresses, owner first."""
    data = lib.cell_from_bits(address_bits(owner) + address_bits(validator))
    # StateInit: no split depth, not special, code and data present, no library.
    return lib.cell_from_bits("00110", [code, data])


def pool_address(code: lib.Cell, owner: str, validator: str) -> str:
    """The masterchain address of a single-nominator pool with these roles."""
    return f"-1:{pool_state_init(code, owner, validator).hash().hex()}"


def verify_pool(chain: Chain, tos_root: Path | str, pool: str, owner: str, operator: str) -> None:
    """Refuse unless `pool` is the single-nominator pool of exactly these roles.

    Three checks, all made from this machine: the address is the one the pinned
    code and the roles derive to; on chain the account is active and runs the
    pinned code; and its get_roles answers this owner and this operator wallet as
    validator. A host that prints another address, or a pool it owns itself, is
    refused before any principal is sent to it.
    """
    code = single_nominator_code(tos_root)
    pool = check_raw_address(pool)
    expected = pool_address(code, owner, operator)
    if pool != expected:
        raise lib.TestnetError(
            f"{pool} is not the pool of owner {owner} and validator {operator}; "
            f"that pool is {expected}"
        )
    state, code_hash = chain.code_hash(pool)
    if state != "active" or code_hash != code.hash():
        raise lib.TestnetError(
            f"{pool} is {state} and runs code {code_hash.hex() if code_hash else None}, not "
            f"the pinned single-nominator code {code.hash().hex()}"
        )
    roles = chain.pool_roles(pool)
    if roles != (owner, operator):
        raise lib.TestnetError(f"{pool} reports roles {roles}, not {(owner, operator)}")


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
    and the self-deploy message are public. A rerun reuses them, and every run
    derives the address from the key again and refuses unless it is the recorded
    one, so nothing is ever funded that this key cannot sign for (an address left
    without its key is refused). Refused when an earlier epoch recorded the address.
    """
    ceremony = Path(args.ceremony)
    with lib.wallet_records_lock(ceremony):
        paths = pool_owner_paths(ceremony, name)
        if paths["addr"].is_file() and not paths["key"].is_file():
            raise lib.TestnetError(
                f"{paths['addr']} exists but its key {paths['key']} does not; nothing that key "
                "cannot sign for is funded"
            )
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
            if paths["addr"].is_file():
                if paths["addr"].read_bytes() != made[1].read_bytes():
                    raise lib.TestnetError(
                        f"{paths['key']} does not belong to the recorded pool owner "
                        f"{address_from_file(paths['addr'])}"
                    )
            else:
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
    principal_sent=None,
) -> dict:
    """Add or complete a validator's pool record in the ceremony's public pools.json.

    The pool, owner and operator of a recorded pool never change.
    """
    with lib.wallet_records_lock(ceremony):
        pools = read_pools(ceremony)
        entry = dict(pools.get(name, {}))
        for key, value in (
            ("pool", pool),
            ("owner", owner),
            ("operator", operator),
        ):
            if value is None:
                continue
            value = check_raw_address(value)
            if key in entry and entry[key] != value:
                raise lib.TestnetError(
                    f"{POOLS_FILE} records {name} {key} {entry[key]}, not {value}"
                )
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


def owner_op_params(ceremony: Path, name: str, owner: str) -> dict:
    """The activation operation's parameters: the owner's own StateInit and key."""
    init = decode_init_message(pool_owner_paths(ceremony, name)["init"].read_bytes())
    return {
        "kind": "activate-owner",
        "wallet": owner,
        "destination": owner,
        "value": 0,
        "bounce": False,
        "body_hash": None,
        "state_init_hash": init["init_hash"],
        "code_hash": init["code_hash"],
        "public_key": init["public_key"],
        "subwallet": init["subwallet"],
    }


def decode_init_message(boc: bytes) -> dict:
    """A self-deployment message (new-wallet-v3.fif writes it): its StateInit's hash,
    code hash and public key (wallet v3 data: seqno, subwallet, public key)."""
    root = lib.parse_boc(boc)
    s = lib.Slice(root)
    if s.bits(2) != 0b10 or ops.read_address(s) is not None:
        raise lib.TestnetError("not an external message")
    ops.read_address(s)
    ops.read_coins(s)
    if not s.bits(1):
        raise lib.TestnetError("the self-deployment carries no StateInit")
    if s.bits(1):
        init = s.take_ref()
    else:
        start, ref_start = s.pos, s.ref
        for width in (5, 2):
            if s.bits(1):
                s.bits(width)
        for _ in range(3):
            if s.bits(1):
                s.take_ref()
        init = ops.span_cell(root, start, s.pos, ref_start, s.ref)
    i = lib.Slice(init)
    if i.bits(1) or i.bits(1) or not i.bits(1) or not i.bits(1) or i.bits(1):
        raise lib.TestnetError("not a wallet StateInit (code and data, nothing else)")
    code, data = i.take_ref(), i.take_ref()
    d = lib.Slice(data)
    d.bits(32)
    subwallet = d.bits(32)
    return {
        "init_hash": init.hash().hex(),
        "code_hash": code.hash().hex(),
        "public_key": d.bytes(32).hex(),
        "subwallet": subwallet,
    }


def owner_transfer(
    args: argparse.Namespace,
    operations: ops.Operations,
    global_id: int,
    name: str,
    op_id: str,
    kind: str,
    pool: str,
    value: int,
    body: Path | None,
    prerequisites,
    extra: dict | None = None,
    expect=None,
) -> dict:
    """A bounceable transfer from the pool owner, signed here with its offline key."""
    ceremony = Path(args.ceremony)
    paths = pool_owner_paths(ceremony, name)
    if not paths["key"].is_file():
        raise lib.TestnetError(f"{paths['key']} is missing; the pool owner key stays here")
    owner = address_from_file(paths["addr"])
    body_hash = lib.parse_boc(body.read_bytes()).hash().hex() if body else EMPTY_BODY_HASH

    def sign(seqno: int) -> bytes:
        boc = sign_wallet_v3(
            args,
            global_id,
            paths["key"],
            paths["addr"].read_bytes(),
            pool,
            POOL_OWNER_SUBWALLET,
            seqno,
            nanotos_text(value),
            bounce=True,
            body=body,
        )
        sent = lib.private_dir(ceremony / "sent")
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        lib.write_new(sent / f"{stamp}-owner-{name}-seq{seqno}-{op_id}.boc", boc, 0o600)
        return boc

    params = {
        "kind": kind,
        "wallet": owner,
        "destination": pool,
        "value": value,
        "bounce": True,
        "body_hash": body_hash,
        "state_init_hash": None,
        "name": name,
        "subwallet": POOL_OWNER_SUBWALLET,
    }
    params.update(extra or {})
    return operations.run(op_id, params, sign, lambda decoded: None, prerequisites, expect)


def owner_role_check(operations: ops.Operations, tos_root, pool: str, owner: str) -> None:
    """For a withdrawal: the recorded pool, active, the pinned code, and the owner
    role, on both validators. The validator role may have been replaced
    (CHANGE_VALIDATOR_ADDRESS); the pool always pays its stored owner."""
    code = single_nominator_code(tos_root)
    for node in operations.nodes:
        chain = Chain(node.url, node.rpc)
        state, code_hash = chain.code_hash(pool)
        if state != "active" or code_hash != code.hash():
            raise lib.TestnetError(f"{pool} is {state} or not the pinned single-nominator code")
        roles = chain.pool_roles(pool)
        if roles[0] != owner:
            raise lib.TestnetError(f"{pool}'s owner is {roles[0]}, not {owner}")


def verify_pool_both(operations: ops.Operations, tos_root, pool, owner, operator):
    for node in operations.nodes:
        verify_pool(Chain(node.url, node.rpc), tos_root, pool, owner, operator)


def withdraw_id_record(operations: ops.Operations, args: argparse.Namespace) -> dict | None:
    record = operations.journal.record(args.id)
    if args.new and record is not None:
        raise lib.TestnetError(f"operation {args.id} exists; --new needs a new id")
    if not args.new and record is None:
        raise lib.TestnetError(f"no operation {args.id}; create a withdrawal with --new")
    return record


def withdrawal_preflight(
    operations: ops.Operations, tos_root, pool: str, owner: str, requested_nanotos: int | None
) -> None:
    """The same safety checks apply before the first send and every resubmission."""
    operations.check_network()
    owner_role_check(operations, tos_root, pool, owner)
    election = operations.both(lambda node: Chain(node.url, node.rpc).active_election())
    if election:
        raise lib.TestnetError(
            f"election {election} is open: the election task stakes from this balance; "
            "withdraw between elections"
        )
    pool_balance = operations.balance(pool)
    available = pool_balance - POOL_STORAGE_NANOTOS
    if available <= 0:
        raise lib.TestnetError(f"the pool holds only {pool_balance / NANO:.9f} TOS")
    if requested_nanotos is not None and requested_nanotos > available:
        raise lib.TestnetError(
            f"the pool holds {pool_balance / NANO:.9f} TOS, {available / NANO:.9f} withdrawable "
            "(staked funds return to the pool after the Elector releases them)"
        )
    if operations.balance(owner) < OWNER_MESSAGE_NANOTOS + ops.FEE_ALLOWANCE_NANOTOS // 10:
        raise lib.TestnetError("the owner wallet cannot pay for the withdrawal message")


def withdraw(args: argparse.Namespace, operations: ops.Operations, global_id: int) -> dict:
    """Take stake principal out of a pool to its offline owner, as operation --id."""
    name = args.name
    ceremony = Path(args.ceremony)
    pool_record = read_pools(ceremony).get(name)
    if not pool_record or "pool" not in pool_record:
        raise lib.TestnetError(f"{ceremony / POOLS_FILE} records no pool for {name}")
    owner = address_from_file(pool_owner_paths(ceremony, name)["addr"])
    if pool_record["owner"] != owner:
        raise lib.TestnetError(f"the pool's recorded owner {pool_record['owner']} is not {owner}")
    pool = pool_record["pool"]
    if not ops.SAFE_ID.match(args.id or ""):
        raise lib.TestnetError(f"not an operation id: {args.id!r}")
    existing = withdraw_id_record(operations, args)
    amount_tos = WITHDRAW_ALL_TOS if args.all else nanotos_text(parse_tos(args.amount, "--amount"))
    principal = operations.journal.record(operations.journal.newest(f"principal-{name}"))
    if existing is None and ops.state_of(principal) != "settled":
        raise lib.TestnetError(f"the principal of {name} is not settled; nothing to withdraw yet")

    requested_nanotos = None if args.all else parse_tos(args.amount, "--amount")

    def prerequisites() -> None:
        withdrawal_preflight(operations, args.tos_root, pool, owner, requested_nanotos)

    with tempfile.TemporaryDirectory(prefix="withdraw-") as work:
        body = withdraw_body(args, amount_tos, Path(work))
        if args.dry_run:
            print(f"dry run: withdrawal {args.id} of {amount_tos} TOS from {pool}; nothing signed")
            prerequisites()
            return {"dry_run": True}
        record = owner_transfer(
            args,
            operations,
            global_id,
            name,
            args.id,
            "withdraw",
            pool,
            OWNER_MESSAGE_NANOTOS,
            body,
            prerequisites,
            {"amount_tos": amount_tos, "requested_nanotos": requested_nanotos},
        )
    result = {
        "id": args.id,
        "name": name,
        "pool": pool,
        "owner": owner,
        "amount_tos": amount_tos,
        "paid_nanotos": record["evidence"]["paid_nanotos"],
        "owner_tx": record["evidence"]["owner_tx"],
        "pool_tx": record["evidence"]["destination_tx"],
    }
    path = ceremony / WITHDRAWALS_FILE
    recorded = (
        {json.loads(line).get("id") for line in path.read_text().splitlines() if line}
        if path.is_file()
        else set()
    )
    if args.id not in recorded:  # asking for a settled id again reports it, once recorded
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "a") as out:
            out.write(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2))
    return result


def change_validator_body(
    args: argparse.Namespace, validator: str, work: Path, run=subprocess.run
) -> Path:
    """The owner's CHANGE_VALIDATOR_ADDRESS body (op 0x1001), from the pool's own
    change-validator.fif."""
    smartcont = Path(args.tos_root) / "crypto" / "smartcont"
    result = run(
        [
            args.fift,
            "-I",
            f"{Path(args.tos_root) / 'crypto' / 'fift' / 'lib'}:{smartcont}",
            "-s",
            str(smartcont / "single-nominator-pool" / "change-validator.fif"),
            validator,
        ],
        cwd=work,
        capture_output=True,
        text=True,
        timeout=60,
    )
    body = work / "change-validator.boc"
    if result.returncode != 0 or not body.is_file():
        raise lib.TestnetError(f"change-validator body: {(result.stdout + result.stderr)[-400:]}")
    return body


def pool_roles_both(operations: ops.Operations, pool: str) -> tuple[str, str]:
    """(owner, validator) of a pool; both validators must agree."""
    return tuple(operations.both(lambda node: Chain(node.url, node.rpc).pool_roles(pool)))


def validator_changed(operations: ops.Operations, rec: dict, delivery, evidence: dict):
    """A change settles when get_roles on both validators shows (owner, new validator)."""
    roles = [Chain(node.url, node.rpc).pool_roles(rec["destination"]) for node in operations.nodes]
    if all(r == (rec["wallet"], rec["validator"]) for r in roles):
        return "settled", dict(evidence, roles=[rec["wallet"], rec["validator"]])
    if any(r[0] != rec["wallet"] for r in roles):
        return "failed", dict(evidence, form="b", reason=f"the pool's owner changed: {roles}")
    return "pending", dict(evidence, reason=f"get_roles does not show the change yet: {roles}")


def change_validator(args: argparse.Namespace, operations: ops.Operations, global_id: int) -> dict:
    """Give a pool a new validator wallet, signed by its offline owner, as operation --id."""
    name = args.name
    ceremony = Path(args.ceremony)
    pool_record = read_pools(ceremony).get(name)
    if not pool_record or "pool" not in pool_record:
        raise lib.TestnetError(f"{ceremony / POOLS_FILE} records no pool for {name}")
    owner = address_from_file(pool_owner_paths(ceremony, name)["addr"])
    if pool_record["owner"] != owner:
        raise lib.TestnetError(f"the pool's recorded owner {pool_record['owner']} is not {owner}")
    pool = pool_record["pool"]
    if not ops.SAFE_ID.match(args.id or ""):
        raise lib.TestnetError(f"not an operation id: {args.id!r}")
    validator = check_raw_address(args.to)
    if not validator.startswith("-1:"):
        raise lib.TestnetError(
            f"{validator} is not a masterchain wallet; the pool stakes only from one"
        )
    if validator in (pool, owner):
        raise lib.TestnetError(f"{validator} is the pool or its owner, not a validator wallet")
    record = operations.journal.record(args.id)
    if args.new and record is not None:
        raise lib.TestnetError(f"operation {args.id} exists; --new needs a new id")
    if not args.new and record is None:
        raise lib.TestnetError(f"no operation {args.id}; create a change with --new")
    if record is not None and record.get("validator") != validator:
        raise lib.TestnetError(
            f"operation {args.id} names {record.get('validator')}, not {validator}"
        )

    def prerequisites() -> None:
        operations.check_network()
        owner_role_check(operations, args.tos_root, pool, owner)
        election = operations.both(lambda node: Chain(node.url, node.rpc).active_election())
        if election:
            raise lib.TestnetError(
                f"election {election} is open: the election task stakes through this pool; "
                "change the validator between elections"
            )
        if pool_roles_both(operations, pool)[1] == validator:
            raise lib.TestnetError(f"{validator} already holds {name}'s validator role")
        if operations.balance(owner) < CHANGE_MESSAGE_NANOTOS + ops.FEE_ALLOWANCE_NANOTOS // 10:
            raise lib.TestnetError("the owner wallet cannot pay for the change message")

    with tempfile.TemporaryDirectory(prefix="change-validator-") as work:
        body = change_validator_body(args, validator, Path(work))
        if args.dry_run:
            print(f"dry run: {args.id}: {pool}'s validator role to {validator}; nothing signed")
            prerequisites()
            return {"dry_run": True}
        previous = record["previous"] if record else pool_roles_both(operations, pool)[1]
        record = owner_transfer(
            args,
            operations,
            global_id,
            name,
            args.id,
            "change-validator",
            pool,
            CHANGE_MESSAGE_NANOTOS,
            body,
            prerequisites,
            {"validator": validator, "previous": previous},
            validator_changed,
        )
    result = {
        "id": args.id,
        "name": name,
        "pool": pool,
        "owner": owner,
        "previous": record["previous"],
        "validator": validator,
        "owner_tx": record["evidence"]["wallet_tx"],
        "pool_tx": record["evidence"]["destination_tx"],
    }
    path = ceremony / VALIDATOR_CHANGES_FILE
    recorded = (
        {json.loads(line).get("id") for line in path.read_text().splitlines() if line}
        if path.is_file()
        else set()
    )
    if args.id not in recorded:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "a") as out:
            out.write(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2))
    return result


# ---------------------------------------------------------------- host-built operator messages


def host_build(
    host, name: str, destination: str, value: int, state_init_b64=None, body_b64=None, bounce=False
) -> bytes:
    """The operator wallet's message, built and signed by tosctl on the host and not
    broadcast there (`wallet send --build-only`). The coordinator decodes and
    checks it before it journals and broadcasts it."""
    command = f"wallet send --from op-{name} --to {destination} --amount-nanotos {value}"
    if state_init_b64:
        command += f" --state-init-boc {shlex.quote(state_init_b64)}"
    if body_b64:
        command += f" --body-boc {shlex.quote(body_b64)}"
    if bounce:
        command += " --bounce"
    output = host.tosctl(command + " --build-only", 90)
    lines = [line for line in output.splitlines() if line.startswith("{")]
    try:
        prepared = json.loads(lines[-1])
        if prepared.get("version") != "tosctl.wallet-prepared-send.v1":
            raise ValueError(prepared.get("version"))
        return base64.b64decode(prepared["message_boc_base64"], validate=True)
    except (IndexError, ValueError, KeyError, TypeError) as exc:
        raise lib.TestnetError(f"no prepared message from the host: {output[-400:]}") from exc


def operator_subwallet(operations: ops.Operations, operator: str) -> int:
    data = operations.wallet_data(operator)
    if data is None:
        raise lib.TestnetError(f"{operator} is not an active wallet; its subwallet is unknown")
    return data[2]


def host_operation_params(
    operations,
    name,
    kind,
    operator,
    destination,
    value,
    state_init_b64=None,
    body_b64=None,
    bounce=False,
    extra=None,
) -> dict:
    state_init_hash = (
        lib.parse_boc(base64.b64decode(state_init_b64)).hash().hex() if state_init_b64 else None
    )
    body_hash = (
        lib.parse_boc(base64.b64decode(body_b64)).hash().hex() if body_b64 else EMPTY_BODY_HASH
    )
    params = {
        "kind": kind,
        "wallet": operator,
        "destination": destination,
        "value": value,
        "bounce": bounce,
        "body_hash": body_hash,
        "state_init_hash": state_init_hash,
        "name": name,
        # The operator wallet's subwallet, as both validators agree it is stored.
        "subwallet": operator_subwallet(operations, operator),
    }
    params.update(extra or {})

    return params


def host_operation(
    operations,
    host,
    name,
    op_id,
    kind,
    operator,
    destination,
    value,
    state_init_b64=None,
    body_b64=None,
    bounce=False,
    expect=None,
    prerequisites=None,
    extra=None,
) -> dict:
    params = host_operation_params(
        operations,
        name,
        kind,
        operator,
        destination,
        value,
        state_init_b64,
        body_b64,
        bounce,
        extra,
    )

    def balance_covers() -> None:
        if operations.balance(operator) < value + ops.FEE_ALLOWANCE_NANOTOS:
            raise lib.TestnetError(f"op-{name} cannot pay {value / NANO:.9f} TOS and its fee")
        if prerequisites:
            prerequisites()

    return operations.run(
        op_id,
        params,
        lambda seqno: host_build(host, name, destination, value, state_init_b64, body_b64, bounce),
        lambda decoded: None,
        balance_covers,
        expect,
    )


def recorded_staking(ceremony: Path, name: str, tos_root) -> tuple[str, str, str]:
    """The pool, owner and operator `pool` recorded for NAME, checked to derive."""
    entry = read_pools(ceremony).get(name)
    if not entry or not all(entry.get(k) for k in ("pool", "owner", "operator")):
        raise lib.TestnetError(
            f"{Path(ceremony) / POOLS_FILE} records no staking pool for {name}; "
            "run `pool` before genesis"
        )
    pool, owner, operator = entry["pool"], entry["owner"], entry["operator"]
    expected = pool_address(single_nominator_code(tos_root), owner, operator)
    if pool != expected:
        raise lib.TestnetError(
            f"{POOLS_FILE} records {name}'s pool as {pool}, but its owner and operator derive {expected}"
        )
    return pool, owner, operator


def genesis_staking_account(ceremony: Path, pool: str) -> None:
    """Refuse a pool that is not a validator id of the genesis records."""
    records = json.loads((Path(ceremony) / "genesis-records.json").read_text())
    if pool.split(":")[1] not in {r.get("validator_id") for r in records}:
        raise lib.TestnetError(f"the pool {pool} is not a validator id in the genesis records")


def stake_pool(args: argparse.Namespace, global_id: int) -> dict:
    """Before genesis: the offline owner and the pool that will be NAME's validator id."""
    name = args.name
    if not SAFE_NAME.match(name):
        raise lib.TestnetError(f"not a node name: {name!r}")
    ceremony = lib.private_dir(Path(args.ceremony))
    operator = (
        check_raw_address(args.operator)
        if ":" in args.operator
        else raw_from_friendly(args.operator)
    )
    if not operator.startswith("-1:"):
        raise lib.TestnetError(f"the operator wallet {operator} is not in the masterchain")
    previous = previous_wallets(args)
    record_fresh_wallets(ceremony, {f"op-{name}": operator}, previous)
    owner = ensure_pool_owner(args, name, global_id, previous)
    pool = pool_address(single_nominator_code(args.tos_root), owner, operator)
    record_pool(ceremony, name, pool, owner, operator)
    result = {
        "name": name,
        "validator_id": pool.split(":")[1],
        "pool": pool,
        "owner": owner,
        "operator": operator,
    }
    print(json.dumps(result, indent=2))
    return result


# What the node logs at start-up for each consensus key it holds (tos
# doc/validator-operator-guide.md, "Bind the node to the staking account").
CUSTODY_LINE = re.compile(r"post-quantum consensus custody: validator_id ([0-9a-f]{64}) ")


def node_staking_account(host) -> str:
    """The validator id the node on the host last reported holding its key for."""
    output = host.run(
        "{ journalctl -u tos-testnet-validator -o cat --no-pager 2>/dev/null; "
        "cat /var/log/tos/validator/node.log* 2>/dev/null; } "
        "| grep -a 'post-quantum consensus custody' | tail -n 1 || true"
    )
    found = CUSTODY_LINE.search(output)
    if not found:
        raise lib.TestnetError(
            "the node reports no post-quantum consensus custody line; check that it is bound "
            "(install-node.sh activate --validator-id) and running"
        )
    return found.group(1)


def staking_readiness(operations, host, pool: str, stake_nanotos: int) -> None:
    """Ready to stand: the pool holds two stakes and the node signs for the pool."""
    available = operations.balance(pool) - POOL_STORAGE_NANOTOS
    if available < 2 * stake_nanotos:
        raise lib.TestnetError(
            f"the pool holds {available / NANO:.9f} TOS above its reserve, less than two stakes "
            f"of {stake_nanotos / NANO:.9f}"
        )
    bound = node_staking_account(host)
    if bound != pool.split(":")[1]:
        raise lib.TestnetError(
            f"the node signs stake authorizations for {bound}, not the pool {pool}; the Elector "
            "refuses a stake signed for another account"
        )


def onboard(
    args: argparse.Namespace, operations: ops.Operations, global_id: int, profile: dict
) -> None:
    name = args.name
    if not SAFE_NAME.match(name):
        raise lib.TestnetError(f"not a node name: {name!r}")
    ceremony = Path(args.ceremony)
    previous = previous_wallets(args)
    elections = profile["elections"]
    pool, owner, operator = recorded_staking(ceremony, name, args.tos_root)
    genesis_staking_account(ceremony, pool)
    host = Host(args.host, args.ssh_key)
    scripts = "/opt/tos-testnet/scripts"

    def step(text: str) -> None:
        print(f"== {name}: {text}", flush=True)

    def settled(step: str) -> bool:
        """Whether a step's newest attempt is settled (a retried step is its successor)."""
        journal = operations.journal
        return ops.state_of(journal.record(journal.newest(step))) == "settled"

    def require(op_id: str) -> None:
        if not settled(op_id):
            raise lib.TestnetError(f"operation {op_id} is not settled")

    step("operator tool")
    last = (
        host.run(f"{scripts}/init-operator.sh --name {shlex.quote(name)}").strip().splitlines()[-1]
    )
    on_host = raw_from_friendly(last.split()[1])
    # The pool, and with it the genesis validator id, derives from the operator
    # wallet recorded before genesis; a host with another wallet cannot stake for it.
    if on_host != operator:
        raise lib.TestnetError(
            f"the host's op-{name} is {on_host}, not the recorded operator wallet {operator} "
            "the pool was derived from"
        )
    step(f"operator wallet {operator}, staking pool {pool}")
    record_fresh_wallets(ceremony, {f"op-{name}": operator}, previous)
    operations.check_network()

    def fund_from_bootstrap(op_id: str, to: str, nanotos: int, label: str) -> None:
        if not settled(op_id):
            step(f"{op_id}: {nanotos / NANO:.9f} TOS from the bootstrap wallet")
        fund(
            argparse.Namespace(
                ceremony=args.ceremony,
                tos_root=args.tos_root,
                fift=args.fift,
                to=to,
                amount=nanotos_text(nanotos),
                label=label,
                op_id=op_id,
                dry_run=False,
            ),
            operations,
            global_id,
        )

    fund_from_bootstrap(
        f"fund-op-{name}", operator, int(elections["operator_funding_tos"]) * NANO, f"op-{name}"
    )
    if operations.state(operator) != "active":
        # No value moves: the wallet deploys itself from its own credit.
        step("activate the operator wallet")
        host.tosctl(f"wallet activate --name op-{name}", 150)
        operations.both(lambda node: Chain(node.url, node.rpc).wait_active(operator))

    # The pool's owner holds the stake principal and is the only role that can
    # take it out. Its key was made here before genesis and never leaves this
    # machine; the operator wallet on the host is only the pool's validator role.
    if ensure_pool_owner(args, name, global_id, previous) != owner:
        raise lib.TestnetError(f"the pool owner key of {name} is not the recorded owner {owner}")
    step(f"pool owner {owner} (key offline in the ceremony's secret/)")
    principal = int(elections["pool_tos"]) * NANO
    fund_from_bootstrap(
        f"fund-owner-{name}",
        owner,
        principal + int(elections["pool_owner_reserve_tos"]) * NANO,
        f"pool-owner-{name}",
    )
    init_boc = pool_owner_paths(ceremony, name)["init"].read_bytes()
    if not settled(f"activate-owner-{name}"):
        step("activate the pool owner wallet")
    operations.run(
        f"activate-owner-{name}",
        owner_op_params(ceremony, name, owner),
        lambda seqno: init_boc,
        lambda decoded: None,
        lambda: require(f"fund-owner-{name}"),
    )

    pool_init_b64 = base64.b64encode(
        lib.serialize_boc(pool_state_init(single_nominator_code(args.tos_root), owner, operator))
    ).decode()

    def pool_deployed(operations_, record, delivery, evidence):
        try:
            verify_pool_both(operations_, args.tos_root, pool, owner, operator)
        except lib.TestnetError as exc:
            return "failed", dict(evidence, form="b", reason=str(exc))
        return "settled", evidence

    if not settled(f"deploy-pool-{name}"):
        step(f"deploy the pool {pool} with {elections['pool_deploy_tos']} TOS")
    host_operation(
        operations,
        host,
        name,
        f"deploy-pool-{name}",
        "deploy-pool",
        operator,
        pool,
        int(elections["pool_deploy_tos"]) * NANO,
        state_init_b64=pool_init_b64,
        expect=pool_deployed,
        extra={"owner": owner},
    )
    configure_pool(host, name, pool, owner, step)

    def principal_prerequisites() -> None:
        require(f"fund-owner-{name}")
        require(f"activate-owner-{name}")
        verify_pool_both(operations, args.tos_root, pool, owner, operator)
        balance = operations.balance(owner)
        if balance < principal + ops.FEE_ALLOWANCE_NANOTOS // 10:
            raise lib.TestnetError(
                f"the pool owner holds {balance / NANO:.9f} TOS, less than the principal and its fee"
            )

    if not settled(f"principal-{name}"):
        step(f"the pool owner sends the principal, {elections['pool_tos']} TOS, to the pool")
    owner_transfer(
        args,
        operations,
        global_id,
        name,
        f"principal-{name}",
        "principal",
        pool,
        principal,
        None,
        principal_prerequisites,
    )
    record_pool(ceremony, name, principal_sent=True)

    step("readiness: two stakes in the pool, the node bound to the pool")
    staking_readiness(operations, host, pool, int(elections["stake_tos"]) * NANO)

    step("election task")
    print(host.run(f"{scripts}/enable-elections.sh --name {shlex.quote(name)}"), end="")
    step("done")


def configure_pool(host, name, pool, owner, step) -> None:
    """The host's tosctl configuration: each step decided by what is there, never nested."""

    def config() -> dict:
        return json.loads(host.run(f"cat {TOSCTL_DIR}/tosctl-config.json"))

    entry = config().get("pools", {}).get(f"pool-{name}")
    if entry is None:
        step(f"config pool add pool-{name}")
        host.tosctl(f"config pool add --name pool-{name} --address {pool} --owner {owner}")
    elif (entry.get("address"), entry.get("owner")) != (pool, owner):
        raise lib.TestnetError(f"pool-{name} is configured on the host as {entry}")
    binding = config().get("bindings", {}).get(name)
    if binding is None or not binding.get("pool"):
        step(f"config bind add {name}")
        host.tosctl(f"config bind add --node {name} --wallet op-{name} --pool pool-{name}")
        binding = config().get("bindings", {}).get(name) or {}
    if (binding.get("wallet"), binding.get("pool")) != (f"op-{name}", f"pool-{name}"):
        raise lib.TestnetError(f"node {name} is bound on the host as {binding}")


# ---------------------------------------------------------------- withdraw

ELECTOR = "-1:" + "3" * 64
SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


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

    def __init__(self, args: argparse.Namespace, chain: Chain, global_id: int, operations=None):
        self.args = args
        self.chain = chain
        self.operations = operations
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
                # A top-up is a new transfer each time it is asked for.
                op_id=f"load-{label}-{time.strftime('%Y%m%dt%H%M%S', time.gmtime())}",
                dry_run=False,
                init=init,
            ),
            self.operations,
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
    common.add_argument(
        "--confirm-rpc",
        help="a second validator's JSON-RPC; value-moving steps read both and need them to agree",
    )
    p_fund = sub.add_parser("fund", parents=[common])
    p_fund.add_argument("--id", dest="op_id", help="operation id (default: the label)")
    p_fund.add_argument("--to", required=True)
    p_fund.add_argument("--amount", required=True)
    p_fund.add_argument("--label", required=True)
    p_fund.add_argument("--dry-run", action="store_true")
    p_pool = sub.add_parser("pool")
    for flag in ("--name", "--operator", "--ceremony", "--tos-root", "--fift"):
        p_pool.add_argument(flag, required=True)
    p_pool.add_argument("--previous-ceremony", action="append", default=[])
    p_onboard = sub.add_parser("onboard", parents=[common])
    for flag in ("--name", "--host", "--ssh-key"):
        p_onboard.add_argument(flag, required=True)
    p_onboard.add_argument("--previous-ceremony", action="append", default=[])
    p_withdraw = sub.add_parser("withdraw", parents=[common])
    p_withdraw.add_argument("--name", required=True)
    p_withdraw.add_argument("--id", required=True, help="the withdrawal's operation id")
    p_withdraw.add_argument("--new", action="store_true", help="create the operation --id")
    how_much = p_withdraw.add_mutually_exclusive_group(required=True)
    how_much.add_argument("--amount")
    how_much.add_argument("--all", action="store_true")
    p_withdraw.add_argument("--dry-run", action="store_true")
    p_change = sub.add_parser("change-validator", parents=[common])
    p_change.add_argument("--name", required=True)
    p_change.add_argument("--id", required=True, help="the change's operation id")
    p_change.add_argument("--new", action="store_true", help="create the operation --id")
    p_change.add_argument("--to", required=True, help="the new validator wallet (masterchain)")
    p_change.add_argument("--dry-run", action="store_true")
    p_reconcile = sub.add_parser("reconcile", parents=[common])
    p_reconcile.add_argument("--wallet", action="append", default=[])
    p_record = sub.add_parser("record", parents=[common])
    p_record.add_argument("--id", required=True)
    outcome = p_record.add_mutually_exclusive_group(required=True)
    outcome.add_argument("--settled", action="store_true")
    outcome.add_argument(
        "--checkpoint", action="store_true", help="Verify the bootstrap closed prefix"
    )
    outcome.add_argument("--failed", choices=("a", "b", "c", "d"))
    outcome.add_argument(
        "--abandoned", action="store_true", help="Close a verified unsigned planned fund"
    )
    p_record.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify abandonment or a bootstrap checkpoint without recording",
    )
    p_record.add_argument("--hint", help="the wallet or destination transaction hash (hex)")
    p_resubmit = sub.add_parser("resubmit", parents=[common])
    p_resubmit.add_argument("--id", required=True)
    p_retry = sub.add_parser("retry", parents=[common])
    p_retry.add_argument("--step", required=True, help="the step id (attempt 1's operation id)")
    p_retry.add_argument("--reason", required=True)
    p_baseline = sub.add_parser("baseline", parents=[common])
    p_baseline.add_argument("--wallet", required=True)
    p_baseline.add_argument("--reason", required=True)
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
        if args.command == "pool":
            stake_pool(args, global_id)
            return 0
        chain = Chain(args.rpc)
        if args.command == "load" and args.dry_run:
            check_load_args(args)
            os.umask(0o077)
            LoadDriver(args, chain, global_id).run()
        else:
            operations = operations_for(args, global_id)
            if args.command == "fund":
                fund(args, operations, global_id)
            elif args.command == "load":
                check_load_args(args)
                os.umask(0o077)
                LoadDriver(args, chain, global_id, operations).run()
            elif args.command == "withdraw":
                withdraw(args, operations, global_id)
            elif args.command == "change-validator":
                change_validator(args, operations, global_id)
            elif args.command in ("reconcile", "record", "resubmit", "baseline", "retry"):
                manual(args, operations)
            else:
                onboard(args, operations, global_id, profile)
    except (lib.TestnetError, OSError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"testnet-elections: {exc}", file=sys.stderr)
        return 1
    return 0


def expect_for(args: argparse.Namespace, record: dict):
    """The kind-specific settlement extra for a record, as onboard would pass it."""
    kind = record["kind"]
    if kind == "deploy-pool":

        def deployed(operations, rec, delivery, evidence):
            try:
                verify_pool_both(
                    operations,
                    args.tos_root,
                    rec["destination"],
                    rec["owner"],
                    rec["wallet"],
                )
            except lib.TestnetError as exc:
                return "failed", dict(evidence, form="b", reason=str(exc))
            return "settled", evidence

        return deployed
    if kind == "change-validator":
        return validator_changed
    return None


def manual(args: argparse.Namespace, operations: ops.Operations) -> None:
    """reconcile (read only), record, resubmit and baseline: a person resolves open operations."""
    journal = operations.journal
    if args.command == "reconcile":
        wallets = args.wallet or sorted(
            {r["wallet"] for r in journal.all() if r} | {BOOTSTRAP_WALLET}
        )
        print(json.dumps(operations.reconcile(wallets), indent=2))
        return
    if args.command == "baseline":
        print(json.dumps(operations.set_baseline(check_raw_address(args.wallet), args.reason)))
        return
    if args.command == "retry":
        successor = operations.retry(args.step, args.reason)
        print(json.dumps({k: successor.get(k) for k in ("id", "state", "predecessor", "reason")}))
        return
    if (
        args.command == "record"
        and getattr(args, "dry_run", False)
        and not getattr(args, "abandoned", False)
        and not getattr(args, "checkpoint", False)
    ):
        raise lib.TestnetError("record --dry-run requires --abandoned or --checkpoint")
    if args.command == "record" and getattr(args, "checkpoint", False):
        print(json.dumps(operations.record_checkpoint(args.id, dry_run=args.dry_run), indent=2))
        return
    if args.command == "record" and getattr(args, "abandoned", False):
        result = operations.record_abandoned(args.id, dry_run=getattr(args, "dry_run", False))
        print(json.dumps(result, indent=2))
        return
    record = journal.record(args.id)
    if record is None:
        raise lib.TestnetError(f"no operation {args.id}")
    expect = expect_for(args, record) if record["kind"] in ops.HOST_KINDS else None
    if args.command == "resubmit":
        prerequisites = None
        if record["kind"] in ("principal", "withdraw"):
            entry = read_pools(Path(args.ceremony)).get(record.get("name"), {})

            def prerequisites():
                if record["kind"] == "principal":
                    verify_pool_both(
                        operations,
                        args.tos_root,
                        record["destination"],
                        entry.get("owner"),
                        entry.get("operator"),
                    )
                    if (
                        operations.balance(record["wallet"])
                        < record["value"] + ops.FEE_ALLOWANCE_NANOTOS // 10
                    ):
                        raise lib.TestnetError("the wallet cannot pay the message any more")
                else:
                    withdrawal_preflight(
                        operations,
                        args.tos_root,
                        record["destination"],
                        record["wallet"],
                        record["requested_nanotos"],
                    )

        result = operations.resubmit(args.id, prerequisites, expect)
    elif args.settled:
        if not args.hint:
            raise lib.TestnetError("--settled needs --hint TXHASH")
        result = operations.record_settled(args.id, args.hint, expect)
    else:
        result = operations.record_failed(args.id, args.failed, args.hint, expect)
    print(json.dumps({k: result.get(k) for k in ("id", "state", "evidence")}, indent=2))


if __name__ == "__main__":
    sys.exit(main())
