#!/usr/bin/env python3
"""Bring the four genesis validators into ordinary elections (coordinator side).

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
          --tos-root DIR --fift PATH --rpc URL
      For one genesis validator, in order, stopping at the first failure:
      init-operator.sh on the host; fund the operator wallet from the
      bootstrap wallet; activate it; deploy the controller (its state init
      from testnet-operator.py controller); deploy the pool with the stake
      money and bind node, wallet and pool; import the controller's birth;
      plan the operating authorization on the host, sign it here with the
      offline root seed, and send it from the operator wallet; then
      enable-elections.sh. Each step checks its result first, so a rerun
      continues where the last one stopped.

URL is a JSON-RPC endpoint of a live node (for example a validator's loopback
listener through an SSH tunnel, http://127.0.0.1:18081/jsonRPC). The amounts
are network/profile.json `elections`. The root seed and the bootstrap key
never leave this machine; the host only ever sees the signed messages.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

BOOTSTRAP_WALLET = "-1:" + "1" * 64
NANO = 10**9
RAW_ADDRESS = re.compile(r"^-?[0-9]+:[0-9a-f]{64}$")


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


def check_raw_address(address: str) -> str:
    address = address.lower()
    if not RAW_ADDRESS.match(address):
        raise lib.TestnetError(f"not a raw workchain:hex address: {address!r}")
    return address


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

    def wait_active(self, address: str, seconds: int = 90) -> int:
        deadline = time.time() + seconds
        while time.time() < deadline:
            state, balance = self.account(address)
            if state == "active":
                return balance
            time.sleep(3)
        raise lib.TestnetError(f"{address} did not become active within {seconds} s")


# ---------------------------------------------------------------- fund


def fund(args: argparse.Namespace, chain: Chain, global_id: int) -> None:
    to = check_raw_address(args.to)
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)?", str(args.amount)) or float(args.amount) <= 0:
        raise lib.TestnetError(f"amount must be a positive number of TOS: {args.amount!r}")
    ceremony = Path(args.ceremony)
    key = ceremony / "secret" / "main-wallet.pk"
    if not key.is_file():
        raise lib.TestnetError(f"{key} is missing; the bootstrap key stays with the coordinator")
    seq = chain.seqno(BOOTSTRAP_WALLET)
    smartcont = Path(args.tos_root) / "crypto" / "smartcont"
    with tempfile.TemporaryDirectory(prefix="fund-") as work:
        work_dir = Path(work)
        (work_dir / "main-wallet.pk").write_bytes(key.read_bytes())
        (work_dir / "main-wallet.addr").write_bytes((ceremony / "main-wallet.addr").read_bytes())
        (work_dir / "gid.fif").write_text(f"{global_id} constant tos-global-id\n")
        argv = [
            args.fift,
            "-I",
            f"{Path(args.tos_root) / 'crypto' / 'fift' / 'lib'}:{smartcont}",
            "-L",
            "gid.fif",
            "-s",
            str(smartcont / "wallet-v3.fif"),
            "main-wallet",
            to,
            "0",
            str(seq),
            str(args.amount),
            "-n",
            "-t",
            "300",
            "query",
        ]
        result = subprocess.run(argv, cwd=work_dir, capture_output=True, text=True)
        if result.returncode != 0 or not (work_dir / "query.boc").is_file():
            raise lib.TestnetError(f"signing failed: {result.stdout[-400:]} {result.stderr[-400:]}")
        boc = (work_dir / "query.boc").read_bytes()
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


class Host:
    def __init__(self, host: str, ssh_key: str, user: str = "root"):
        self.target = f"{user}@{host}"
        self.base = ["ssh", "-i", ssh_key, "-o", "BatchMode=yes", "-p", "22", self.target]
        self.scp = ["scp", "-q", "-P", "22", "-i", ssh_key]

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
        return self.run(
            "set -a; . /etc/tos/tosctl.env; set +a; cd /var/lib/tos-ctl; "
            f"timeout {timeout} tosctl {arguments} 2>&1",
            timeout=timeout + 30,
        )

    def put(self, local: Path, remote: str) -> None:
        subprocess.run(self.scp + [str(local), f"{self.target}:{remote}"], check=True)


def onboard(args: argparse.Namespace, chain: Chain, global_id: int, profile: dict) -> None:
    name = args.name
    elections = profile["elections"]
    controller_doc = json.loads(Path(args.controller).read_text())
    controller_hex = controller_doc["controller_id"]
    records = json.loads((Path(args.ceremony) / "genesis-records.json").read_text())
    if controller_hex not in {r["controller_id"] for r in records}:
        raise lib.TestnetError(f"controller {controller_hex} is not in the genesis records")
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

    state, balance = chain.account(operator)
    funding = int(elections["operator_funding_tos"])
    if state != "active" and balance < (funding - 100) * NANO:
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
        host.put(Path(tx.name), f"/var/lib/tos-ctl/controller-{name}-deploy-tx.boc")

    pools = json.loads(host.run("cat /var/lib/tos-ctl/tosctl-config.json")).get("pools", {})
    if f"pool-{name}" not in pools:
        step(f"deploy the pool with {elections['pool_tos']} TOS")
        pool = parse_pool_deploy(
            host.tosctl(
                f"deploy pool --verbose --node op-{name} --owner {operator} "
                f"--controller {controller} --amount {elections['pool_tos']}",
                240,
            )
        )
        step(f"pool {pool}")
        host.tosctl(
            f"config pool add --name pool-{name} --address {pool} --owner {operator} --controller {controller}"
        )
        host.tosctl(f"config bind add --node {name} --wallet op-{name} --pool pool-{name}")
        # The birth import needs the binding, so it comes after `bind add`.
        host.tosctl(
            f"config bind import-birth --node {name} "
            f"--transaction-boc /var/lib/tos-ctl/controller-{name}-deploy-tx.boc "
            f"--output /var/lib/tos-ctl/controller-birth-{name}.boc",
            90,
        )

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
        signed = subprocess.run(
            [
                args.controller_tool,
                "fund-operations",
                args.root_seed,
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
    args = parser.parse_args(argv)
    try:
        profile = lib.load_profile(args.profile)
        global_id = lib.confirmed_global_id(profile)
        chain = Chain(args.rpc)
        if args.command == "fund":
            fund(args, chain, global_id)
        else:
            onboard(args, chain, global_id, profile)
    except (lib.TestnetError, OSError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"testnet-elections: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
