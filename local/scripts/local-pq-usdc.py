#!/usr/bin/env python3
"""Test USDC on the local PQ network, end to end through the token bridge.

Local development only: a throwaway EVM chain on loopback, a test token of six
decimals, a test bridge on each side, a stand-in oracle set whose keys are
generated here at run time and never leave /data/usdc, and the local faucet.
None of it is a production key, bridge or token.

The steps, in order (`run` does them all and stops at the first refusal):

  keys          generate the stand-in oracle keys (three Ed25519 keys for the TOS
                multisig, three secp256k1 keys for the EVM bridge) and the TOS
                test wallets' keys, once
  evm-deploy    deploy the test token and Bridge.sol on the loopback EVM chain,
                with the stand-in oracles as its oracle set, and open locking by
                an oracle vote
  fund          pay the test wallets from the Genesis wallet (the election service
                owns it: stop tos-pq-elections in a quiet interval first, and start
                it again afterwards)
  tvm-deploy    compile the token bridge for ConfigParam 79's chain, deploy the
                oracle multisig and the bridge, and fix the bridge's life
  config79      build ConfigParam 79 naming the bridge, the multisig and the EVM
                bridge, and adopt it through testnet-governance.py
  generation    vote the EVM generation naming the TOS bridge's life, and activate
                it on the TOS bridge through the multisig
  lock          show a lock of a token without caps refused, vote the token's caps
                (voteForLockCap) and lock test USDC to the buyer
  mint          pay the lock's mint fee from the buyer and vote the v5 swap through
                the multisig; wait for the minted tokens in the buyer's wallet
  config84      build the ConfigParam 84 record with tosctl from the deployed
                bridge's codes and adopt it, as a critical change, through
                testnet-governance.py; verify it with tosctl
  status        print every recorded fact and the live balances

Run as root from the tos-ops root, with the tos checkout's environment:

  sudo env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" local/scripts/local-pq-usdc.py run

Every step records what it did in /data/usdc/state.json and is idempotent: a
step already done is checked against the chain and skipped. A refusal stops the
run; nothing is retried blindly.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTNET_SCRIPTS = HERE.parent.parent / "testnet" / "scripts"
sys.path.insert(0, str(TESTNET_SCRIPTS))
import testnet_lib as lib  # noqa: E402

DATA = Path("/data")
NANO = 10**9

# ConfigParam 79 serves source chain 1 (tos crosschain/token-bridge/tvm/params);
# the loopback EVM chain runs with that chain id, so votes name it.
BRIDGE_PARAM = 79
EVM_CHAIN_ID = 1
TOKEN_DECIMALS = 6
TOKEN_SUPPLY = 1_000_000 * 10**TOKEN_DECIMALS
# Lock caps of the test token, in atomic units: total, per lock, hourly, daily.
LOCK_CAPS = (100_000 * 10**6, 10_000 * 10**6, 20_000 * 10**6, 50_000 * 10**6)
LOCK_AMOUNT = 25 * 10**6
# What the EVM locker holds: more than one lock's cap.
LOCKER_TOKENS = 20_000 * 10**6
# The largest liability one actor may hold in the test asset (ConfigParam 84).
MAX_LIABILITY_PER_ACTOR = 10_000 * 10**6

ORACLES = 3
QUORUM = 2
MULTISIG_WALLET_ID = 0x55534443
PAYER_SUBWALLET = 0x55534443
GENERATION = 1

# ConfigParam 79 prices (TokenBridgePrices), the values the token bridge sandbox uses.
BURN_FEE = 3 * NANO
MINT_FEE = 5 * NANO
WALLET_MIN_STORAGE = NANO // 20
WALLET_GAS = NANO // 50
MINTER_MIN_STORAGE = NANO // 10
DISCOVER_GAS = NANO // 100

VOTE_VALUE = 2 * NANO
OP_EXECUTE_VOTING = 4
OP_PAY_SWAP = 8
VOTE_SWAP = 0
VOTE_ACTIVATE_GENERATION = 8

FUNDING = {  # wallet: (workchain, TOS)
    "deployer": (-1, 120),
    "submitter": (-1, 20),
    "buyer": (0, 30),
}
PAYER_TOS = 150
BRIDGE_TOS = 60
MULTISIG_TOS = 30

# The simple wallet the Genesis wallet runs (tos test/tostester contract/wallet_v1.py).
WALLET_V1_CODE = (
    "b5ee9c7201010101004e000098ff0020dd2082014c97ba9730ed44d0d70b1fe0a4f260810200d71820d70b1f"
    "ed44d0d31fd3ffd15112baf2a122f901541044f910f2a2f80001d31f31d307d4d101fb00a4c8cb1fcbffc9ed54"
)


class Refused(RuntimeError):
    """A step refused; the run stops and nothing is retried."""


def require(condition, message: str) -> None:
    if not condition:
        raise Refused(message)


# ---------------------------------------------------------------- cells


def cell_bits(cell: lib.Cell) -> str:
    if not cell.bits:
        return ""
    return format(int.from_bytes(cell.data, "big"), f"0{8 * len(cell.data)}b")[: cell.bits]


class Builder:
    def __init__(self):
        self.bits, self.refs = "", []

    def uint(self, value: int, width: int) -> Builder:
        require(0 <= value < (1 << width), f"{value} does not fit {width} bits")
        if width:
            self.bits += format(value, f"0{width}b")
        return self

    def int(self, value: int, width: int) -> Builder:
        require(-(1 << (width - 1)) <= value < (1 << (width - 1)), f"{value} is not int{width}")
        return self.uint(value % (1 << width), width)

    def bit(self, value) -> Builder:
        self.bits += "1" if value else "0"
        return self

    def raw(self, data: bytes) -> Builder:
        return self.uint(int.from_bytes(data, "big"), 8 * len(data)) if data else self

    def coins(self, value: int) -> Builder:
        length = (value.bit_length() + 7) // 8
        return self.uint(length, 4).uint(value, 8 * length)

    def addr(self, address: str) -> Builder:
        wc, account = split(address)
        return self.uint(0b100, 3).int(wc, 8).raw(account)

    def ref(self, cell: lib.Cell) -> Builder:
        self.refs.append(cell)
        return self

    def append(self, cell: lib.Cell) -> Builder:
        self.bits += cell_bits(cell)
        self.refs += cell.refs
        return self

    def end(self) -> lib.Cell:
        require(len(self.bits) <= 1023 and len(self.refs) <= 4, "a cell overflowed")
        return lib.cell_from_bits(self.bits, self.refs)


def split(address: str) -> tuple[int, bytes]:
    wc, account = address.split(":")
    raw = bytes.fromhex(account)
    require(len(raw) == 32, f"{address} is not a raw address")
    return int(wc), raw


def boc64(cell: lib.Cell) -> str:
    return base64.b64encode(lib.serialize_boc(cell)).decode()


def from64(text: str) -> lib.Cell:
    return lib.parse_boc(base64.b64decode(text))


def state_init(code: lib.Cell, data: lib.Cell) -> lib.Cell:
    """StateInit: no split depth, not special, code and data, no library."""
    return lib.cell_from_bits("00110", [code, data])


def address_of(init: lib.Cell, wc: int) -> str:
    return f"{wc}:{init.hash().hex()}"


def internal(
    dest: str, value: int, bounce: bool, body: lib.Cell | None = None, init: lib.Cell | None = None
) -> lib.Cell:
    """int_msg_info with ihr disabled, from addr_none (the sender fills it in)."""
    b = Builder().bit(0).bit(1).bit(bounce).bit(0).uint(0, 2).addr(dest).coins(value)
    b.bit(0).coins(0).coins(0).uint(0, 64).uint(0, 32)
    b = b.bit(1).bit(1).ref(init) if init is not None else b.bit(0)
    return (b.bit(1).ref(body) if body is not None else b.bit(0)).end()


def external(dest: str, body: lib.Cell, init: lib.Cell | None = None) -> lib.Cell:
    b = Builder().uint(0b10, 2).uint(0, 2).addr(dest).coins(0)
    b = b.bit(1).bit(1).ref(init) if init is not None else b.bit(0)
    return b.bit(1).ref(body).end()


# ---------------------------------------------------------------- the local chain


class Chain:
    """The local network through the validators' loopback JSON-RPC."""

    def __init__(self, data: Path):
        ports = json.loads((data / "testnet-ports.json").read_text())["nodes"]
        self.urls = [f"http://127.0.0.1:{n['json_rpc_port']}" for n in ports]
        self.validator_urls = [
            f"http://127.0.0.1:{n['json_rpc_port']}"
            for n in ports
            if n["role"] in ("validator", "candidate")
        ]
        self.url = self.urls[0]

    def call(self, rpc_method: str, /, url: str | None = None, **params):
        return lib.rpc(url or self.url, rpc_method, timeout=30, **params)

    def account(self, address: str) -> dict:
        return self.call("getAddressInformation", address=address)

    def balance(self, address: str) -> int:
        return int(self.account(address)["balance"])

    def active(self, address: str) -> bool:
        return self.account(address).get("state") == "active"

    def config(self, param: int, url: str | None = None) -> lib.Cell | None:
        try:
            answer = self.call("getConfigParam", url=url, param=param)
        except lib.RpcError as error:
            if error.reason == "CONFIG_PARAM_ABSENT":
                return None
            raise
        data = (answer or {}).get("config", {}).get("bytes")
        return lib.parse_boc(base64.b64decode(data)) if data else None

    def send(self, message: lib.Cell) -> None:
        self.call("sendBoc", boc=boc64(message))

    def get(self, address: str, method: str, *args) -> list:
        stack = []
        for arg in args:
            if isinstance(arg, int):
                stack.append(["num", str(arg)])
            elif isinstance(arg, tuple) and arg[0] == "slice":
                stack.append(["tvm.Slice", boc64(arg[1])])
            else:
                stack.append(["tvm.Cell", boc64(arg)])
        answer = self.call("runGetMethod", address=address, method=method, stack=stack)
        require(
            answer.get("exit_code") == 0, f"{address} {method} exited {answer.get('exit_code')}"
        )
        # The node lists the result stack top first; return it in the getter's
        # declared order (its first return value first).
        return list(reversed(answer.get("stack") or []))

    def wait(self, what: str, predicate, timeout: float = 120, interval: float = 2) -> object:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = predicate()
            except lib.TestnetError:
                value = None
            if value:
                return value
            time.sleep(interval)
        raise Refused(f"timed out waiting for {what}; nothing was resent")


def num(entry) -> int:
    require(entry[0] == "num", f"expected a number, got {entry[0]}")
    return int(entry[1], 0)


def stack_cell(entry) -> lib.Cell:
    require(entry[0] in ("cell", "slice"), f"expected a cell, got {entry[0]}")
    return from64(entry[1]["bytes"])


def read_address(cell: lib.Cell) -> str:
    s = lib.Slice(cell)
    require(s.bits(3) == 0b100, "not an addr_std")
    wc = s.bits(8)
    wc = wc - 256 if wc >= 128 else wc
    return f"{wc}:{s.bytes(32).hex()}"


def slice_of(address: str) -> tuple[str, lib.Cell]:
    return ("slice", Builder().addr(address).end())


# ---------------------------------------------------------------- simple wallets


class Wallet:
    """A simple wallet (seqno, public key): the Genesis wallet's code."""

    CODE = lib.parse_boc(bytes.fromhex(WALLET_V1_CODE))

    def __init__(self, chain: Chain, seed: bytes, wc: int, address: str | None = None):
        import nacl.signing

        self.chain, self.key = chain, nacl.signing.SigningKey(seed)
        data = Builder().uint(0, 32).raw(bytes(self.key.verify_key)).end()
        self.init = state_init(self.CODE, data)
        self.address = address or address_of(self.init, wc)

    def seqno(self) -> int:
        info = self.chain.account(self.address)
        if info.get("state") != "active":
            return 0
        return lib.Slice(from64(info["data"])).bits(32)

    def send(self, message: lib.Cell, mode: int = 3, deploy: bool = False) -> int:
        """Sign and send one message, then wait for the seqno to move."""
        seqno = self.seqno()
        signed = Builder().uint(seqno, 32).uint(mode, 8).ref(message).end()
        body = Builder().raw(self.key.sign(signed.hash()).signature).append(signed).end()
        self.chain.send(external(self.address, body, self.init if deploy else None))
        self.chain.wait(f"{self.address} seqno {seqno + 1}", lambda: self.seqno() > seqno)
        return seqno

    def transfer(
        self,
        dest: str,
        value: int,
        body: lib.Cell | None = None,
        bounce: bool = True,
        init: lib.Cell | None = None,
    ) -> int:
        require(value > 0, "a transfer must carry a positive value")
        require(
            self.chain.balance(self.address) > value + NANO // 10,
            f"{self.address} cannot pay {value / NANO} TOS",
        )
        return self.send(internal(dest, value, bounce, body, init))


# ---------------------------------------------------------------- state


class State:
    def __init__(self, root: Path):
        self.root = root
        self.path = root / "state.json"
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {}

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value) -> None:
        self.data[key] = value
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True) + "\n")
        os.replace(tmp, self.path)

    def evidence(self, name: str, value) -> Path:
        folder = self.root / "evidence"
        folder.mkdir(mode=0o755, exist_ok=True)
        path = folder / f"{name}.json"
        path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n")
        print(f"evidence: {path}")
        return path


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(
        not path.is_symlink() and path.stat().st_mode & 0o077 == 0, f"{path} must be private (0700)"
    )
    return path


def key_file(path: Path) -> bytes:
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    require(path.stat().st_mode & 0o077 == 0, f"{path} is readable by others")
    return path.read_bytes()


# ---------------------------------------------------------------- tools


class Tools:
    def __init__(self, args):
        self.tos = Path(args.tos_root).resolve()
        self.build = self.tos / "build"
        self.fift = self.build / "crypto" / "fift"
        self.func = self.build / "crypto" / "func"
        self.tosctl = Path(args.tosctl)
        self.cast = args.cast
        self.evm = args.evm_rpc
        self.contracts = self.tos / "crosschain" / "token-bridge" / "tvm" / "contracts"
        self.artifacts = Path(args.evm_artifacts)
        for tool in (self.fift, self.func):
            require(tool.is_file(), f"{tool} is missing; build the tos checkout first")

    def fift_run(self, cwd: Path, script: str, *argv: str, preload: str | None = None) -> str:
        includes = f"{self.tos / 'crypto/fift/lib'}:{self.tos / 'crypto/smartcont'}:{cwd}"
        cmd = [str(self.fift), "-I", includes]
        if preload:
            cmd += ["-L", preload]
        out = subprocess.run(
            cmd + ["-s", script, *argv], cwd=cwd, capture_output=True, text=True, timeout=120
        )
        require(
            out.returncode == 0, f"fift {script} failed: {out.stderr[-2000:]}{out.stdout[-2000:]}"
        )
        return out.stdout

    def cast_run(
        self, *argv: str, env: dict | None = None, check: bool = True
    ) -> subprocess.CompletedProcess:
        out = subprocess.run(
            [self.cast, argv[0], "--rpc-url", self.evm, *argv[1:]]
            if argv[0] in CAST_RPC
            else [self.cast, *argv],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, **(env or {})},
        )
        if check:
            require(out.returncode == 0, f"cast {argv[0]} failed: {out.stderr[-1500:]}")
        return out


CAST_RPC = {"send", "call", "chain-id", "rpc", "receipt", "code", "balance", "block"}
# The cast binary, set from --cast; the oracle helpers sign with it.
CAST = ["cast"]


# ---------------------------------------------------------------- EVM side


def evm_artifact(tools: Tools, name: str) -> dict:
    path = tools.artifacts / f"{name}.sol" / f"{name}.json"
    require(path.is_file(), f"{path} is missing; compile the EVM contracts (CEREMONY.md 8.3)")
    return json.loads(path.read_text())


def bridge_params_source(tools: Tools) -> Path:
    """The network parameters file the bridge is compiled with: the one that selects
    ConfigParam 79 and the EVM chain id the loopback chain runs."""
    found = [
        path
        for path in sorted((tools.contracts.parent / "params").glob("*.fc"))
        if f"CONFIG_PARAM_ID = {BRIDGE_PARAM};" in path.read_text()
        and f"MY_CHAIN_ID = {EVM_CHAIN_ID};" in path.read_text()
    ]
    require(len(found) == 1, f"expected one parameters file for ConfigParam {BRIDGE_PARAM}")
    return found[0]


def evm_accounts(tools: Tools) -> list[str]:
    return json.loads(tools.cast_run("rpc", "eth_accounts").stdout)


def evm_send(
    tools: Tools,
    sender: str,
    to: str,
    signature: str,
    *args: str,
    gas: int | None = None,
    check: bool = True,
) -> dict:
    argv = ["send", "--unlocked", "--from", sender, "--json", to, signature, *args]
    if gas:
        argv[1:1] = ["--gas-limit", str(gas)]
    out = tools.cast_run(*argv, check=check)
    if out.returncode != 0:
        return {"refused": True, "error": out.stderr.strip()[-600:]}
    receipt = json.loads(out.stdout)
    return {
        "tx": receipt["transactionHash"],
        "status": int(receipt["status"], 16),
        "block": int(receipt["blockNumber"], 16),
    }


def evm_call(tools: Tools, to: str, signature: str, *args: str) -> str:
    return tools.cast_run("call", to, signature, *args).stdout.strip()


def evm_values(text: str) -> list[str]:
    """cast's decoded outputs, one per line, without its "[1e6]" annotations."""
    return [line.split(" [")[0].strip() for line in text.splitlines() if line.strip()]


def oracle_keys(keys: Path) -> list[tuple[str, str]]:
    """The stand-in EVM oracles: (address, key file), sorted by address as the
    bridge requires its signatures."""
    out = []
    for i in range(ORACLES):
        path = keys / f"evm-oracle-{i}.key"
        key = key_file(path).hex()
        address = subprocess.run(
            [CAST[0], "wallet", "address", "--private-key", f"0x{key}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        require(address.returncode == 0, "cast wallet address failed")
        out.append((address.stdout.strip(), str(path)))
    return sorted(out, key=lambda pair: int(pair[0], 16))


def oracle_signatures(tools: Tools, keys: Path, digest: str) -> str:
    """A quorum of stand-in oracle signatures over `digest` (EIP-191 prefixed, as
    SignatureChecker recovers them), as the Signature[] argument."""
    rows = []
    for address, path in oracle_keys(keys)[:QUORUM]:
        key = Path(path).read_bytes().hex()
        out = subprocess.run(
            [CAST[0], "wallet", "sign", "--private-key", f"0x{key}", digest],
            capture_output=True,
            text=True,
            timeout=30,
        )
        require(out.returncode == 0, "cast wallet sign failed")
        rows.append(f"({address},{out.stdout.strip()})")
    return "[" + ",".join(rows) + "]"


def evm_vote(
    tools: Tools,
    state: State,
    keys: Path,
    digest_fn: str,
    digest_args: list[str],
    vote_fn: str,
    vote_args: list[str],
) -> dict:
    bridge = state["evm"]["bridge"]
    digest = evm_call(tools, bridge, digest_fn, *digest_args)
    signatures = oracle_signatures(tools, keys, digest)
    # Each signature must verify against the bridge's own checker before any vote is sent.
    for row in signatures[2:-2].split("),("):
        signer, sig = row.split(",")
        evm_call(
            tools, bridge, "checkSignature(bytes32,(address,bytes))", digest, f"({signer},{sig})"
        )
    result = evm_send(tools, state["evm"]["deployer"], bridge, vote_fn, *vote_args, signatures)
    require(result.get("status") == 1, f"{vote_fn} failed: {result}")
    return dict(result, digest=digest)


def evm_create(tools: Tools, deployer: str, name: str, signature: str, *ctor: str) -> str:
    artifact = evm_artifact(tools, name)
    encoded = tools.cast_run("abi-encode", signature, *ctor).stdout.strip()[2:]
    out = tools.cast_run(
        "send",
        "--unlocked",
        "--from",
        deployer,
        "--json",
        "--create",
        artifact["bytecode"] + encoded,
    )
    receipt = json.loads(out.stdout)
    require(int(receipt["status"], 16) == 1, f"{name} deployment failed")
    return receipt["contractAddress"]


def deploy_token(tools: Tools, deployer: str) -> str:
    """A test stand-in for a six-decimal stablecoin (TestFeeToken, its fee left at 0)."""
    token = evm_create(tools, deployer, "TestFeeToken", "constructor(uint256)", str(TOKEN_SUPPLY))
    require(
        evm_call(tools, token, "decimals()(uint8)") == str(TOKEN_DECIMALS),
        "the token is not 6 decimals",
    )
    require(evm_call(tools, token, "feeBasisPoints()(uint256)") == "0", "the token charges a fee")
    return token


def step_evm_deploy(args, state: State, tools: Tools, keys: Path) -> None:
    require(
        tools.cast_run("chain-id").stdout.strip() == str(EVM_CHAIN_ID),
        f"the EVM chain at {tools.evm} must run chain id {EVM_CHAIN_ID}",
    )
    if state.get("evm"):
        code = tools.cast_run("code", state["evm"]["bridge"]).stdout.strip()
        require(code not in ("", "0x"), "the recorded EVM bridge is gone; the EVM chain was reset")
        print(f"EVM bridge {state['evm']['bridge']} already deployed")
        return
    deployer, locker = evm_accounts(tools)[:2]
    oracles = [address for address, _ in oracle_keys(keys)]
    token = deploy_token(tools, deployer)
    bridge = evm_create(
        tools,
        deployer,
        "Bridge",
        "constructor(address[],address[])",
        "[" + ",".join(oracles) + "]",
        "[]",
    )
    funded = evm_send(
        tools, deployer, token, "transfer(address,uint256)", locker, str(LOCKER_TOKENS)
    )
    require(funded["status"] == 1, "funding the locker failed")
    state.set(
        "evm",
        {
            "chain_id": EVM_CHAIN_ID,
            "deployer": deployer,
            "locker": locker,
            "token": token,
            "bridge": bridge,
            "oracles": oracles,
        },
    )
    opened = evm_vote(
        tools,
        state,
        keys,
        "getNewLockStatusId(bool,uint256)(bytes32)",
        ["true", "1"],
        "voteForSwitchLock(bool,uint256,(address,bytes)[])",
        ["true", "1"],
    )
    require(evm_call(tools, bridge, "allowLock()(bool)") == "true", "locking did not open")
    state.evidence(
        "evm-deploy",
        {
            "token": token,
            "bridge": bridge,
            "oracles": oracles,
            "locker": locker,
            "switch_lock_vote": opened,
        },
    )


# ---------------------------------------------------------------- funding


def faucet(chain: Chain, data: Path) -> Wallet:
    network = json.loads((data / "network.json").read_text())
    seed = (data / "testnet" / "state" / "main-wallet.pk").read_bytes()
    return Wallet(chain, seed, -1, network["genesis_wallet_address"])


def wallets(chain: Chain, keys: Path) -> dict[str, Wallet]:
    return {
        name: Wallet(chain, key_file(keys / f"{name}.pk"), wc) for name, (wc, _) in FUNDING.items()
    }


def payer_files(args, state: State, tools: Tools, keys: Path) -> dict:
    """The governance payer: a masterchain wallet v3, as testnet-governance.py signs."""
    if not (keys / "payer.addr").exists():
        gid = keys / "gid.fif"
        gid.write_text(f"{lib.LOCAL_GLOBAL_ID} constant tos-global-id\n")
        tools.fift_run(
            keys,
            str(tools.tos / "crypto/smartcont/new-wallet-v3.fif"),
            "-1",
            str(PAYER_SUBWALLET),
            "payer",
            preload=str(gid),
        )
    address = lib.Slice(lib.Cell((keys / "payer.addr").read_bytes(), 288, []))
    account = address.bytes(32).hex()
    wc = int.from_bytes(address.bytes(4), "big", signed=True)
    return {
        "address": f"{wc}:{account}",
        "key": str(keys / "payer.pk"),
        "addr": str(keys / "payer.addr"),
        "query": str(keys / "payer-query.boc"),
    }


def step_fund(args, state: State, chain: Chain, tools: Tools, keys: Path) -> None:
    payer = payer_files(args, state, tools, keys)
    test_wallets = wallets(chain, keys)
    wanted = [w for w in test_wallets.values() if not chain.active(w.address)]
    payer_missing = not chain.active(payer["address"])
    if not wanted and not payer_missing:
        print("test wallets already funded")
        state.set(
            "wallets", {n: w.address for n, w in test_wallets.items()} | {"payer": payer["address"]}
        )
        return
    active = subprocess.run(
        ["systemctl", "is-active", "tos-pq-elections"], capture_output=True, text=True
    ).stdout.strip()
    require(
        active == "inactive",
        "the election service owns the Genesis wallet: stop tos-pq-elections in a quiet "
        "interval, fund, then start it again",
    )
    require(
        not (args.data / "elections/faucet-journal/pending.json").exists(),
        "the election driver has an unfinished Genesis wallet payment; let it finish first",
    )
    fd = os.open(args.data / ".local-pq-faucet.lock", os.O_RDWR | os.O_CREAT, 0o600)
    receipts = []
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("another driver holds the Genesis wallet (faucet lock)") from None
        genesis = faucet(chain, args.data)
        for name, wallet in test_wallets.items():
            if chain.active(wallet.address):
                continue
            amount = FUNDING[name][1] * NANO
            seqno = genesis.transfer(wallet.address, amount, bounce=False, init=wallet.init)
            chain.wait(f"{name} deployed", lambda w=wallet: chain.active(w.address))
            receipts.append(
                {
                    "wallet": name,
                    "address": wallet.address,
                    "tos": FUNDING[name][1],
                    "genesis_seqno": seqno,
                }
            )
        if payer_missing:
            if chain.balance(payer["address"]) < PAYER_TOS * NANO // 2:
                seqno = genesis.transfer(payer["address"], PAYER_TOS * NANO, bounce=False)
                receipts.append(
                    {
                        "wallet": "payer",
                        "address": payer["address"],
                        "tos": PAYER_TOS,
                        "genesis_seqno": seqno,
                    }
                )
                chain.wait("payer funded", lambda: chain.balance(payer["address"]) > 0)
            chain.call("sendBoc", boc=base64.b64encode(Path(payer["query"]).read_bytes()).decode())
            chain.wait("payer deployed", lambda: chain.active(payer["address"]))
    finally:
        os.close(fd)
    state.set(
        "wallets", {n: w.address for n, w in test_wallets.items()} | {"payer": payer["address"]}
    )
    state.evidence(
        "fund",
        {
            "receipts": receipts,
            "balances": {n: chain.balance(a) for n, a in state["wallets"].items()},
        },
    )


# ---------------------------------------------------------------- TVM side


def friendly_pubkey(public: bytes) -> str:
    """Fift's 48-character public key: tag 3ee6, the key, crc16 (XMODEM)."""
    data = b"\x3e\xe6" + public
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return base64.urlsafe_b64encode(data + crc.to_bytes(2, "big")).decode()


def tvm_oracles(keys: Path) -> list:
    import nacl.signing

    return [nacl.signing.SigningKey(key_file(keys / f"tvm-oracle-{i}.pk")) for i in range(ORACLES)]


def stage_contracts(tools: Tools, stage: Path) -> dict[str, str]:
    """The token bridge compiled for ConfigParam 79's chain, as build-token-bridge.sh
    compiles it, plus the multisig under the name new-multisig.fif includes."""
    for path in tools.contracts.iterdir():
        if path.suffix in (".fc", ".fif"):
            shutil.copy(path, stage / path.name)
    shutil.copy(bridge_params_source(tools), stage / "params.fc")
    hashes = {}
    for contract, output in (
        ("token-bridge", "token-bridge"),
        ("token-minter", "token-minter"),
        ("token-wallet", "token-wallet"),
        ("votes-collector", "votes-collector"),
        ("multisig", "multisig-code"),
    ):
        out = subprocess.run(
            # new-multisig.fif includes its code without Asm.fif, so that one carries it (-A).
            [
                str(tools.func),
                "-SPA" if contract == "multisig" else "-PS",
                "-o",
                f"{output}.fif",
                f"{contract}.fc",
            ],
            cwd=stage,
            capture_output=True,
            text=True,
            timeout=300,
        )
        require(out.returncode == 0, f"func {contract}.fc failed: {out.stderr[-1500:]}")
        wrapper = stage / f"hash-{output}.fif"
        wrapper.write_text(
            f'"Asm.fif" include "{output}.fif" include hashu 256 u>B ." HASH " Bx. cr\n'
        )
        printed = tools.fift_run(stage, wrapper.name)
        hashes[contract] = printed.split("HASH")[-1].strip().lower()
        require(len(hashes[contract]) == 64, f"no code hash for {contract}")
    return hashes


def step_tvm_deploy(args, state: State, chain: Chain, tools: Tools, keys: Path) -> None:
    require(state.get("evm"), "deploy the EVM side first (evm-deploy)")
    require(state.get("wallets"), "fund the test wallets first (fund)")
    tvm = state.get("tvm") or {}
    deployer = wallets(chain, keys)["deployer"]
    if not tvm:
        stage = Path(tempfile.mkdtemp(prefix="usdc-tvm-", dir=state.root))
        hashes = stage_contracts(tools, stage)
        printed = tools.fift_run(
            stage, "new-bridge.fif", str(EVM_CHAIN_ID), state["evm"]["bridge"].lower()
        )
        bridge = next(
            line.split("=")[1].strip().lower()
            for line in printed.splitlines()
            if line.startswith("new bridge address")
        )
        oracles = tvm_oracles(keys)
        (stage / "oracles.pub").write_text(
            " ".join(friendly_pubkey(bytes(k.verify_key)) for k in oracles)
        )
        printed = tools.fift_run(
            stage,
            "new-multisig.fif",
            "-1",
            str(MULTISIG_WALLET_ID),
            "oracles",
            str(QUORUM),
            "oracles.pub",
            bridge,
        )
        multisig = next(
            line.split("=")[1].strip().lower()
            for line in printed.splitlines()
            if line.startswith("new wallet address")
        )
        for name in ("bridge-create.boc", "oracles-create.boc"):
            shutil.copy(stage / name, state.root / name)
        tvm = {
            "bridge": bridge,
            "multisig": multisig,
            "code_hashes": hashes,
            "stage": str(stage),
            "multisig_wallet_id": MULTISIG_WALLET_ID,
            "quorum": QUORUM,
            "oracle_public_keys": [bytes(k.verify_key).hex() for k in oracles],
        }
        state.set("tvm", tvm)
    for name, address, value, boc in (
        ("multisig", tvm["multisig"], MULTISIG_TOS, "oracles-create.boc"),
        ("bridge", tvm["bridge"], BRIDGE_TOS, "bridge-create.boc"),
    ):
        if chain.active(address):
            continue
        if chain.balance(address) < value * NANO // 2:
            deployer.transfer(address, value * NANO, bounce=False)
            chain.wait(f"{name} funded", lambda a=address: chain.balance(a) > 0)
        chain.call("sendBoc", boc=base64.b64encode((state.root / boc).read_bytes()).decode())
        chain.wait(f"{name} active", lambda a=address: chain.active(a))
    life = num(chain.get(tvm["bridge"], "get_bridge_state")[0])
    if life == 0:
        # The bridge's first internal transaction fixes its life; a plain top-up
        # is the only one that needs no ConfigParam 79.
        deployer.transfer(tvm["bridge"], NANO, bounce=False)
        life = chain.wait(
            "the bridge's life", lambda: num(chain.get(tvm["bridge"], "get_bridge_state")[0])
        )
    bridge_data = chain.get(tvm["bridge"], "get_bridge_data")
    minter_code, wallet_code = stack_cell(bridge_data[2]), stack_cell(bridge_data[3])
    bridge_code = from64(chain.account(tvm["bridge"])["code"])
    allowed = stack_cell(chain.get(tvm["multisig"], "get_allowed_bridges")[0])
    require(
        set(lib.hashmap_items(allowed, 256)) == {int(split(tvm["bridge"])[1].hex(), 16)},
        "the multisig's allowlist is not exactly the bridge",
    )
    unsigned = chain.get(tvm["multisig"], "get_messages_unsigned")
    # A null cell renders as an empty list.
    require(
        not unsigned or unsigned[0][0] == "null" or unsigned[0] == ["list", {"elements": []}],
        "the multisig holds pending queries",
    )
    tvm.update(
        life=life,
        minter_code_hash=minter_code.hash().hex(),
        wallet_code_hash=wallet_code.hash().hex(),
        bridge_code_hash=bridge_code.hash().hex(),
    )
    require(
        tvm["minter_code_hash"] == tvm["code_hashes"]["token-minter"],
        "the bridge holds another minter code",
    )
    require(
        tvm["wallet_code_hash"] == tvm["code_hashes"]["token-wallet"],
        "the bridge holds another wallet code",
    )
    state.set("tvm", tvm)
    state.evidence("tvm-deploy", {k: v for k, v in tvm.items() if k != "stage"})


def token_data(state: State) -> lib.Cell:
    token = bytes.fromhex(state["evm"]["token"][2:])
    return Builder().uint(EVM_CHAIN_ID, 32).raw(token).uint(TOKEN_DECIMALS, 8).end()


def step_config79_build(args, state: State, chain: Chain, tools: Tools) -> Path:
    tvm = state["tvm"]
    buyer = state["wallets"]["buyer"]
    floor = num(
        chain.get(tvm["bridge"], "get_mint_fee_floor", token_data(state), slice_of(buyer))[0]
    )
    require(floor < MINT_FEE, f"the mint fee {MINT_FEE} does not cover the bridge's floor {floor}")
    stage = Path(tvm["stage"])
    tools.fift_run(
        stage,
        "build-config79.fif",
        tvm["bridge"],
        tvm["multisig"],
        "0",
        *(
            f"{v / NANO:.9f}"
            for v in (
                BURN_FEE,
                MINT_FEE,
                WALLET_MIN_STORAGE,
                WALLET_GAS,
                MINTER_MIN_STORAGE,
                DISCOVER_GAS,
            )
        ),
        str(int(state["evm"]["bridge"], 16)),
    )
    value = state.root / "config79.boc"
    shutil.copy(stage / "config79.boc", value)
    state.set(
        "config79",
        {
            "value_hash": lib.parse_boc(value.read_bytes()).hash().hex(),
            "mint_fee": MINT_FEE,
            "mint_fee_floor": floor,
        },
    )
    return value


# ---------------------------------------------------------------- governance


def governance(args, *argv: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable,
        str(TESTNET_SCRIPTS / "testnet-governance.py"),
        "--local-network",
        str(args.data / "network.json"),
        *argv,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    print(out.stdout, end="")
    if out.returncode != 0:
        print(out.stderr, end="", file=sys.stderr)
    if check:
        require(out.returncode == 0, f"testnet-governance.py {argv[0]} refused")
    return out


def adopt(
    args, state: State, chain: Chain, tools: Tools, param: int, value: Path, extra: list[str] = ()
) -> dict:
    """Propose, then sign and vote every round under each new validator set, until
    every validator serves the value."""
    urls = chain.validator_urls
    adopted = [
        "adopted",
        "--rpc",
        urls[0],
        "--confirm-rpc",
        urls[1],
        *[a for u in urls[2:] for a in ("--also-rpc", u)],
        "--param",
        str(param),
        "--value-boc",
        str(value),
    ]
    if governance(args, *adopted, check=False).returncode == 0:
        return {"param": param, "already_adopted": True}
    payer = payer_files(args, state, tools, Path(args.keys))
    common = [
        "--ceremony",
        str(args.ceremony),
        "--tos-root",
        str(tools.tos),
        "--fift",
        str(tools.fift),
        "--rpc",
        urls[0],
        "--confirm-rpc",
        urls[1],
        "--payer-key",
        payer["key"],
        "--payer-addr",
        payer["addr"],
        "--payer-subwallet",
        str(PAYER_SUBWALLET),
    ]
    dry = governance(
        args,
        "propose",
        *common,
        "--param",
        str(param),
        "--value-boc",
        str(value),
        *extra,
        "--dry-run",
    )
    plan = json.loads(dry.stdout[: dry.stdout.rindex("}") + 1])
    proposal = plan["proposal"]
    governance(args, "propose", *common, "--param", str(param), "--value-boc", str(value), *extra)
    rounds = []
    deadline = time.monotonic() + args.governance_timeout
    while time.monotonic() < deadline:
        if governance(args, *adopted, check=False).returncode == 0:
            break
        current = governance(args, "status", "--rpc", urls[0], "--proposal", proposal)
        status = json.loads(current.stdout)
        if status is None:
            time.sleep(10)
            continue
        set_hash = chain.config(34).hash().hex()
        if any(r["set"] == set_hash for r in rounds):
            time.sleep(15)
            continue
        signed = governance(
            args,
            "sign",
            "--ceremony",
            str(args.ceremony),
            "--rpc",
            urls[0],
            "--proposal",
            proposal,
            check=False,
        )
        if signed.returncode != 0:
            time.sleep(15)  # the set changed while signing: sign again under the next one
            continue
        governance(args, "vote", *common, "--proposal", proposal)
        after = json.loads(
            governance(args, "status", "--rpc", urls[0], "--proposal", proposal).stdout or "null"
        )
        rounds.append({"set": set_hash, "status_after": after, "at": int(time.time())})
        state.set(f"proposal_{param}", {"proposal": proposal, "rounds": rounds, "plan": plan})
    final = governance(args, *adopted)
    return {
        "param": param,
        "proposal": proposal,
        "plan": plan,
        "rounds": rounds,
        "adopted": final.stdout.strip().splitlines(),
    }


def step_config79(args, state: State, chain: Chain, tools: Tools) -> None:
    value = step_config79_build(args, state, chain, tools)
    result = adopt(args, state, chain, tools, BRIDGE_PARAM, value)
    state.evidence("config79", result)


# ---------------------------------------------------------------- the oracle multisig


def multisig_query(keys: Path, message: lib.Cell, index: int) -> lib.Cell:
    """A query the first QUORUM stand-in oracles sign at once, so it reaches k in
    one message: owner 0 as root, owner 1 as co-signer (bridge_multisig/query.rs)."""
    oracles = tvm_oracles(keys)
    query_id = ((int(time.time()) + 7200) << 32) | index
    rest = (
        Builder()
        .uint(MULTISIG_WALLET_ID, 32)
        .int(lib.LOCAL_GLOBAL_ID, 32)
        .uint(query_id, 64)
        .uint(3, 8)
        .ref(message)
        .end()
    )
    co = oracles[1].sign(rest.hash()).signature
    signatures = Builder().raw(co).uint(1, 8).bit(0).end()
    signed = Builder().uint(0, 8).bit(1).ref(signatures).append(rest).end()
    root = oracles[0].sign(signed.hash()).signature
    return Builder().raw(root).append(signed).end()


def oracle_vote(state: State, chain: Chain, keys: Path, voting: lib.Cell, index: int) -> dict:
    """The stand-in oracle set votes: the multisig sends the vote to the bridge."""
    tvm = state["tvm"]
    body = Builder().uint(OP_EXECUTE_VOTING, 32).uint(index, 64).append(voting).end()
    vote = internal(tvm["bridge"], VOTE_VALUE, True, body)
    query = multisig_query(keys, vote, index)
    submitter = wallets(chain, keys)["submitter"]
    before = chain.account(tvm["bridge"])["last_transaction_id"]["lt"]
    seqno = submitter.transfer(tvm["multisig"], NANO // 2, query)
    chain.wait(
        "the vote at the bridge",
        lambda: chain.account(tvm["bridge"])["last_transaction_id"]["lt"] != before,
        timeout=90,
    )
    return {
        "query_hash": query.hash().hex(),
        "vote_body_hash": body.hash().hex(),
        "submitter_seqno": seqno,
    }


def step_generation(args, state: State, chain: Chain, tools: Tools, keys: Path) -> None:
    tvm = state["tvm"]
    bridge_hash = "0x" + split(tvm["bridge"])[1].hex()
    evm = state["evm"]
    if evm_call(tools, evm["bridge"], "generation()(uint32)") == "0":
        vote = evm_vote(
            tools,
            state,
            keys,
            "getNewGenerationId(uint32,bytes32,uint64,uint256)(bytes32)",
            [str(GENERATION), bridge_hash, str(tvm["life"]), "1"],
            "voteForNewGeneration(uint32,bytes32,uint64,uint256,(address,bytes)[])",
            [str(GENERATION), bridge_hash, str(tvm["life"]), "1"],
        )
        state.evidence("evm-generation", vote)
    named, life, start = evm_values(
        evm_call(
            tools, evm["bridge"], "generations(uint32)(bytes32,uint64,uint64)", str(GENERATION)
        )
    )
    require(
        named == bridge_hash and int(life) == tvm["life"],
        "the EVM generation names another TOS bridge",
    )
    start = int(start)
    bridge_state = chain.get(tvm["bridge"], "get_bridge_state")
    if num(bridge_state[5]) == 0:
        require(chain.config(BRIDGE_PARAM) is not None, "ConfigParam 79 must be adopted first")
        voting = (
            Builder()
            .uint(VOTE_ACTIVATE_GENERATION, 8)
            .raw(split(tvm["bridge"])[1])
            .uint(tvm["life"], 64)
            .uint(GENERATION, 32)
            .uint(start, 64)
            .end()
        )
        receipt = oracle_vote(state, chain, keys, voting, 1)
        bridge_state = chain.wait(
            "the generation active",
            lambda: s if num((s := chain.get(tvm["bridge"], "get_bridge_state"))[5]) != 0 else None,
        )
        state.evidence("tvm-generation", {"vote": receipt, "start": start})
    require(
        num(bridge_state[3]) == GENERATION and num(bridge_state[4]) == start,
        "the TOS bridge's generation differs from the EVM one",
    )
    state.set("generation", {"generation": GENERATION, "start": start})


CAP_STATE = "getLockCapState(address)((uint128,uint128,uint128,uint128),uint256,uint256,uint256)"
LOCK = "lock(address,uint256,bytes32)"


def uncapped_lock_refused(tools: Tools, bridge: str, token: str, locker: str, to: str) -> dict:
    """A lock of a token whose caps were never voted: the bridge refuses it for
    that reason, both simulated and mined, and allocates no lock number."""
    nonce_before = evm_call(tools, bridge, "lockNonce()(uint64)")
    reason = tools.cast_run(
        "call", "--from", locker, bridge, LOCK, token, str(LOCK_AMOUNT), to, check=False
    )
    mined = evm_send(
        tools, locker, bridge, LOCK, token, str(LOCK_AMOUNT), to, gas=300_000, check=False
    )
    require(
        reason.returncode != 0 and "no lock cap" in reason.stderr,
        f"a lock without caps was not refused for that reason: {reason.stderr[-400:]}",
    )
    require(mined.get("status") == 0 or mined.get("refused"), "a lock without caps was mined")
    require(
        evm_call(tools, bridge, "lockNonce()(uint64)") == nonce_before,
        "an uncapped lock took a nonce",
    )
    return {
        "token": token,
        "cap_state": evm_call(tools, bridge, CAP_STATE, token),
        "revert": reason.stderr.strip()[-300:],
        "mined": mined,
        "lock_nonce_unchanged": nonce_before,
    }


def step_lock(args, state: State, chain: Chain, tools: Tools, keys: Path) -> None:
    evm = state["evm"]
    if state.get("lock"):
        print(f"lock n={state['lock']['n']} already made")
        return
    token, bridge, locker = evm["token"], evm["bridge"], evm["locker"]
    buyer_hash = "0x" + split(state["wallets"]["buyer"])[1].hex()
    # The locker must hold more than one lock's cap, so that the over-cap probe
    # below is refused by the cap and not by the token balance.
    held = int(evm_values(evm_call(tools, token, "balanceOf(address)(uint256)", locker))[0])
    if held < LOCKER_TOKENS:
        topped = evm_send(
            tools,
            evm["deployer"],
            token,
            "transfer(address,uint256)",
            locker,
            str(LOCKER_TOKENS - held),
        )
        require(topped["status"] == 1, "funding the locker failed")
    approved = evm_send(tools, locker, token, "approve(address,uint256)", bridge, str(LOCK_CAPS[0]))
    require(approved["status"] == 1, "approve failed")
    caps_now = evm_values(
        evm_call(tools, bridge, "lockCaps(address)(uint128,uint128,uint128,uint128)", token)
    )
    if caps_now[0] == "0":
        # The test token itself, before its first lock: refused, and recorded
        # before the cap vote so the evidence survives a later failure.
        state.set(
            "uncapped_refused", uncapped_lock_refused(tools, bridge, token, locker, buyer_hash)
        )
        nonce = (
            int(evm_values(evm_call(tools, bridge, "lastLockCapNonce(address)(uint256)", token))[0])
            + 1
        )
        caps = [str(c) for c in LOCK_CAPS]
        vote = evm_vote(
            tools,
            state,
            keys,
            "getNewLockCapId(address,uint256,uint256,uint256,uint256,uint256)(bytes32)",
            [token, *caps, str(nonce)],
            "voteForLockCap(address,uint256,uint256,uint256,uint256,uint256,(address,bytes)[])",
            [token, *caps, str(nonce)],
        )
        state.set("lock_cap_vote", vote)
    # A second token that is never capped stays refused after the first is capped.
    probe = evm.get("probe_token")
    if not probe:
        probe = deploy_token(tools, evm["deployer"])
        evm["probe_token"] = probe
        state.set("evm", evm)
    sent = evm_send(
        tools, evm["deployer"], probe, "transfer(address,uint256)", locker, str(LOCK_AMOUNT)
    )
    require(sent["status"] == 1, "funding the locker with the probe token failed")
    approved = evm_send(tools, locker, probe, "approve(address,uint256)", bridge, str(LOCK_AMOUNT))
    require(approved["status"] == 1, "approve of the probe token failed")
    probe_refused = uncapped_lock_refused(tools, bridge, probe, locker, buyer_hash)
    capped = evm_call(tools, bridge, CAP_STATE, token)
    over = tools.cast_run(
        "call",
        "--from",
        locker,
        bridge,
        LOCK,
        token,
        str(LOCK_CAPS[1] + 1),
        buyer_hash,
        check=False,
    )
    require(
        over.returncode != 0 and "per-lock cap" in over.stderr,
        f"a lock above the per-lock cap was not refused: {over.stderr[-300:]}",
    )
    n = int(evm_values(evm_call(tools, bridge, "lockNonce()(uint64)"))[0])
    locked = evm_send(tools, locker, bridge, LOCK, token, str(LOCK_AMOUNT), buyer_hash)
    require(locked["status"] == 1, f"the capped lock failed: {locked}")
    record = evm_values(
        evm_call(tools, bridge, "locks(uint64)(address,address,uint256,uint32,uint8)", str(n))
    )
    amount = int(record[2])
    require(
        int(record[3]) == GENERATION and int(record[4]) == 1,
        f"lock {n} is not open in generation 1",
    )
    lock = {"n": n, "amount": amount, "to_address_hash": buyer_hash, "tx": locked}
    state.set("lock", lock)
    state.evidence(
        "lock",
        {
            "uncapped_refused": state.get("uncapped_refused"),
            "lock_cap_vote": state.get("lock_cap_vote"),
            "probe_token_refused": probe_refused,
            "caps_after_vote": capped,
            "over_per_lock_refused": over.stderr.strip()[-200:],
            "lock": lock,
            "record": record,
        },
    )


def swap_needs_payment(swap_state: int, n: int, watermark: int) -> bool:
    """Only an unseen lock inside the window is paid. get_swap answers -1 both for
    an unseen lock and for one already folded under the watermark (consumed or
    cancelled, record dropped); the second must never be paid again."""
    return swap_state == -1 and n >= watermark


def step_mint(args, state: State, chain: Chain, tools: Tools, keys: Path) -> None:
    tvm, lock = state["tvm"], state["lock"]
    buyer = wallets(chain, keys)["buyer"]
    minter = read_address(
        stack_cell(chain.get(tvm["bridge"], "get_minter_address", token_data(state))[0])
    )
    swap = chain.get(tvm["bridge"], "get_swap", lock["n"])
    receipts = state.get("mint_receipts", {})
    # Below the watermark a lock is already consumed (or cancelled) and its
    # record dropped: an absent record there must never be paid again.
    watermark = num(chain.get(tvm["bridge"], "get_bridge_state")[6])
    if swap_needs_payment(num(swap[0]), lock["n"], watermark):
        pay = (
            Builder()
            .uint(OP_PAY_SWAP, 32)
            .uint(0, 64)
            .uint(GENERATION, 32)
            .uint(lock["n"], 64)
            .end()
        )
        receipts["pay_swap_seqno"] = buyer.transfer(tvm["bridge"], MINT_FEE, pay)
        state.set("mint_receipts", receipts)
        swap = chain.wait(
            "the swap paid",
            lambda: (
                s if num((s := chain.get(tvm["bridge"], "get_swap", lock["n"]))[0]) == 0 else None
            ),
        )
    if num(swap[0]) == 0:
        voting = (
            Builder()
            .uint(VOTE_SWAP, 8)
            .uint(GENERATION, 32)
            .uint(lock["n"], 64)
            .uint(EVM_CHAIN_ID, 32)
            .uint(int(state["evm"]["bridge"], 16), 160)
            .raw(split(buyer.address)[1])
            .coins(lock["amount"])
            .ref(token_data(state))
            .end()
        )
        receipts["swap_vote"] = oracle_vote(state, chain, keys, voting, 100 + lock["n"])
        state.set("mint_receipts", receipts)
    chain.wait("the minter deployed", lambda: chain.active(minter), timeout=120)
    wallet = read_address(
        stack_cell(chain.get(minter, "get_wallet_address", slice_of(buyer.address))[0])
    )

    def balance():
        if not chain.active(wallet):
            return None
        value = num(chain.get(wallet, "get_wallet_data")[0])
        return value if value == lock["amount"] else None

    minted = chain.wait("the minted tokens in the buyer's wallet", balance, timeout=180)
    data = chain.get(wallet, "get_wallet_data")
    wrapped = [num(x) for x in chain.get(minter, "get_wrapped_token_data")]
    supply = [num(x) for x in chain.get(minter, "get_supply_state")]
    swap = [num(x) for x in chain.get(tvm["bridge"], "get_swap", lock["n"])]
    bridge_state = [num(x) for x in chain.get(tvm["bridge"], "get_bridge_state")]
    # A consumed swap is folded under the watermark and its record dropped.
    require(
        swap[0] == 2 or (swap[0] == -1 and bridge_state[6] > lock["n"]),
        f"swap {lock['n']} is not consumed: {swap}, watermark {bridge_state[6]}",
    )
    require(
        read_address(stack_cell(data[1])) == buyer.address, "the wallet belongs to someone else"
    )
    require(read_address(stack_cell(data[2])) == minter, "the wallet names another master")
    result = {
        "minter": minter,
        "buyer": buyer.address,
        "buyer_token_wallet": wallet,
        "balance_atomic": minted,
        "balance_usdc": minted / 10**TOKEN_DECIMALS,
        "wrapped_token_data": wrapped,
        "supply_state": supply,
        "swap": swap,
        "bridge_state": bridge_state,
        "receipts": receipts,
    }
    state.set("mint", result)
    state.evidence("mint", result)


# ---------------------------------------------------------------- ConfigParam 84


def node_release_evidence(state: State) -> Path:
    """Each local validator's running binary and the tos commit it reports (-V)."""
    rows = []
    for unit in [f"tos-pq-validator@{i}" for i in (1, 2, 3, 4, 7)]:
        pid = subprocess.run(
            ["systemctl", "show", unit, "-p", "MainPID", "--value"], capture_output=True, text=True
        ).stdout.strip()
        require(pid not in ("", "0"), f"{unit} is not running")
        exe = os.readlink(f"/proc/{pid}/exe")
        require(
            not exe.endswith("(deleted)"),
            f"{unit} runs a binary that was replaced since it started",
        )
        out = subprocess.run([exe, "-V"], capture_output=True, text=True, timeout=30).stdout
        commit = out.split("Commit:")[1].split(",")[0].strip()
        rows.append({"name": unit, "exe": exe, "commit": commit})
    path = state.root / "node-releases.json"
    path.write_text(json.dumps({"validators": rows}, indent=1) + "\n")
    return path


def step_config84(args, state: State, chain: Chain, tools: Tools) -> None:
    tvm, mint = state["tvm"], state["mint"]
    require(tools.tosctl.is_file(), f"{tools.tosctl} is missing; build tosctl first")
    spec = {
        "assets": [
            {
                "master": split(mint["minter"])[1].hex(),
                "status": "active",
                "decimals": TOKEN_DECIMALS,
                "minter_code_hash": tvm["minter_code_hash"],
                "wallet_code_hash": tvm["wallet_code_hash"],
                "max_liability_per_actor": str(MAX_LIABILITY_PER_ACTOR),
                "origin": {
                    "kind": "token_bridge",
                    "bridge_address": split(tvm["bridge"])[1].hex(),
                    "source_chain_id": EVM_CHAIN_ID,
                    "source_token": state["evm"]["token"][2:].lower(),
                },
            }
        ]
    }
    spec_path = state.root / "config84-spec.json"
    spec_path.write_text(json.dumps(spec, indent=1) + "\n")
    value = state.root / "config84.boc"
    built = subprocess.run(
        [
            str(tools.tosctl),
            "vote",
            "offer",
            "settlement-assets",
            "build",
            "--spec",
            str(spec_path),
            "--out",
            str(value),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    require(
        built.returncode == 0, f"tosctl settlement-assets build refused: {built.stderr[-1500:]}"
    )
    releases = node_release_evidence(state)
    result = adopt(args, state, chain, tools, 84, value, ["--node-release-evidence", str(releases)])
    result["tosctl_build"] = json.loads(built.stdout)
    config = tosctl_config(state, chain, tools)
    verified = subprocess.run(
        [
            str(tools.tosctl),
            "vote",
            "offer",
            "--config",
            str(config),
            "settlement-assets",
            "verify",
            "--pin",
            split(mint["minter"])[1].hex(),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    result["tosctl_verify"] = {
        "exit": verified.returncode,
        "stdout": verified.stdout[-4000:],
        "stderr": verified.stderr[-2000:],
    }
    require(
        verified.returncode == 0,
        f"tosctl settlement-assets verify refused: {verified.stderr[-1500:]}",
    )
    state.evidence("config84", result)


def tosctl_config(state: State, chain: Chain, tools: Tools) -> Path:
    """The tos checkout's tosctl configuration, reading the local network."""
    config = json.loads((tools.tos / "tosctl-config.json").read_text())
    config["chain_rpc"] = {"urls": [chain.url + "/"], "api_key": None}
    path = state.root / "tosctl-config.json"
    path.write_text(json.dumps(config, indent=1) + "\n")
    return path


# ---------------------------------------------------------------- status


def step_status(args, state: State, chain: Chain, tools: Tools) -> None:
    out = dict(state.data)
    if state.get("mint"):
        wallet = state["mint"]["buyer_token_wallet"]
        out["live_buyer_token_balance"] = num(chain.get(wallet, "get_wallet_data")[0])
    for param in (79, 84):
        cells = [chain.config(param, url) for url in chain.validator_urls]
        out[f"config{param}_on_validators"] = [c.hash().hex() if c else None for c in cells]
    print(json.dumps(out, indent=1, sort_keys=True))


STEPS = [
    "keys",
    "evm-deploy",
    "fund",
    "tvm-deploy",
    "config79",
    "generation",
    "lock",
    "mint",
    "config84",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("step", choices=[*STEPS, "run", "status"])
    parser.add_argument("--data", type=Path, default=DATA)
    parser.add_argument("--tos-root", default=os.environ.get("TOS_ROOT", ""))
    parser.add_argument("--tosctl", default="")
    parser.add_argument("--cast", default=shutil.which("cast") or "cast")
    parser.add_argument("--evm-rpc", default="http://127.0.0.1:18545")
    parser.add_argument("--evm-artifacts", default="")
    parser.add_argument("--governance-timeout", type=int, default=3600)
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, "run as root: the Genesis wallet key and the consoles are root's")
    require(args.tos_root, "set TOS_ROOT or --tos-root to the tos checkout the network runs")
    require(args.evm_rpc.startswith("http://127.0.0.1:"), "the EVM chain must be on loopback")
    tos = Path(args.tos_root)
    args.tosctl = args.tosctl or str(tos / "tosctl/src/target/release/tosctl")
    args.evm_artifacts = args.evm_artifacts or str(
        tos / "crosschain/token-bridge/evm/artifacts/contracts"
    )
    network = json.loads((args.data / "network.json").read_text())
    require(
        network.get("global_id") == lib.LOCAL_GLOBAL_ID
        and network.get("scope") == "local-development",
        "this is not the local development network",
    )
    root = private_dir(args.data / "usdc")
    args.keys = str(private_dir(root / "keys"))
    args.ceremony = private_dir(root / "ceremony")
    state = State(root)
    keys = Path(args.keys)
    CAST[0] = args.cast
    tools = Tools(args)
    chain = Chain(args.data)
    steps = STEPS if args.step == "run" else [args.step]
    try:
        for step in steps:
            print(f"== {step}")
            if step == "keys":
                oracle_keys(keys)
                tvm_oracles(keys)
                wallets(chain, keys)
            elif step == "evm-deploy":
                step_evm_deploy(args, state, tools, keys)
            elif step == "fund":
                step_fund(args, state, chain, tools, keys)
            elif step == "tvm-deploy":
                step_tvm_deploy(args, state, chain, tools, keys)
            elif step == "config79":
                step_config79(args, state, chain, tools)
            elif step == "generation":
                step_generation(args, state, chain, tools, keys)
            elif step == "lock":
                step_lock(args, state, chain, tools, keys)
            elif step == "mint":
                step_mint(args, state, chain, tools, keys)
            elif step == "config84":
                step_config84(args, state, chain, tools)
            elif step == "status":
                step_status(args, state, chain, tools)
    except (Refused, lib.TestnetError) as error:
        print(f"local-pq-usdc: {step}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
