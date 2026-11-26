#!/usr/bin/env python3
"""LOCAL ONLY: stage, mint and recognize a separately pinned refusing test asset.

This is synthetic oracle-authorized test supply, not an EVM lock or test USDC.
The normal bridge, minter, ConfigParam 81 and ConfigParam 84 paths are used.
No account state is overwritten. No existing ConfigParam entry is replaced.
"""

import argparse
import fcntl
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "service_token", HERE / "local-pq-service-token.py"
)
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)
u = service.usdc
LABEL = "LOCAL-ONLY-TEST-REFUSAL-v1"
SOURCE_TOKEN = b"LOCAL_ONLY_TEST_REFU".hex()
EXTERNAL_NAMESPACE = int.from_bytes(hashlib.sha256(LABEL.encode()).digest()[:20], "big")


def local_only(args, chain, state):
    service.check_network(args, chain, state)
    # Pin to the exact approved local genesis, not merely a caller-owned file.
    u.require(
        json.loads((args.data / "network.json").read_text())["zerostate_root"]
        == args.approved_genesis,
        "approved local genesis differs",
    )
    u.require(args.approved_genesis != "0" * 64, "empty genesis pin")
    if state.get("network") is None:
        state.set("network", {"global_id": 3, "genesis": args.approved_genesis})


def payer(chain, bridge_state):
    original = json.loads((bridge_state / "state.json").read_text())
    wallet = service.Owner.__new__(service.Owner)
    u.Wallet.__init__(
        wallet,
        chain,
        (bridge_state / "keys/payer.pk").read_bytes(),
        -1,
        original["wallets"]["payer"],
    )
    wallet.subwallet_id = u.PAYER_SUBWALLET
    return wallet


def build(args, state, chain, tools):
    output = state.root / "local-only-test-build"
    if not output.exists():
        service.run(
            [
                "python3",
                str(args.test_source / "test/token-refusal/build-local-only.py"),
                "--source-root",
                str(args.test_source),
                "--output",
                str(output),
                "--global-id",
                "3",
            ]
        )
    marker = json.loads((output / "LOCAL-ONLY-TEST.json").read_text())
    u.require(marker["label"] == LABEL and marker["global_id"] == 3, "wrong test build")
    # Compile the immutable staged source; never write a release artifact.
    wallet_bytes = (output / "token-wallet-local-only-test.fc").read_bytes()
    u.require(
        hashlib.sha256(wallet_bytes).hexdigest() == marker["wallet_source_sha256"],
        "staged wallet source changed",
    )
    u.require(
        (output / "token-wallet.fc").read_bytes() == wallet_bytes,
        "compiled wallet differs from test source",
    )
    aliases = (
        "token-wallet",
        "token-minter",
        "token-bridge",
        "votes-collector",
        "multisig-code",
    )
    for script in ("new-bridge.fif", "new-multisig.fif"):
        text = (tools.contracts / script).read_text()
        for alias in aliases:
            text = text.replace(
                '"' + alias + '.fif"', '"local-only-test-' + alias + '.fif"'
            )
        (output / script).write_text(text)
    hashes = {}
    for contract, target in (
        ("token-wallet", "token-wallet"),
        ("token-minter", "token-minter"),
        ("token-bridge", "token-bridge"),
        ("votes-collector", "votes-collector"),
        ("multisig", "multisig-code"),
    ):
        target = "local-only-test-" + target
        service.run(
            [
                str(tools.func),
                "-SPA" if contract == "multisig" else "-PS",
                "-o",
                target + ".fif",
                contract + ".fc",
            ],
            cwd=output,
        )
        script = output / ("hash-" + target + ".fif")
        script.write_text(
            '"Asm.fif" include "'
            + target
            + '.fif" include hashu 256 u>B ." HASH " Bx. cr\n'
        )
        hashes[contract] = (
            tools.fift_run(output, script.name).split("HASH")[-1].strip().lower()
        )
    prior = state.get("build")
    result = {"label": LABEL, "code_hashes": hashes, "marker": marker}
    u.require(not prior or prior == result, "test build changed since planning")
    state.set("build", result)
    return output, hashes


def require_original_payer_clear(args, state, address):
    if (
        state.intent("namespace-fund") is None
        or state.intent("fund-governance-payer") is None
    ):
        journal = u.governance_module().ops.Journal(args.ceremony)
        u.require(
            not any(
                r.get("state") in ("planned", "signed", "broadcast")
                for r in journal.for_wallet(address)
            ),
            "original payer has an open operation; do not bypass its journal",
        )


def namespace(args, state, chain, tools):
    occupied = chain.config(81)
    if occupied is not None:
        u.require(
            occupied.hash().hex() == (state.get("config79") or {}).get("value_hash"),
            "ConfigParam 81 is occupied by another namespace",
        )
    output, hashes = build(args, state, chain, tools)
    keys = u.private_dir(state.root / "keys")
    # Independent keys and wallet namespace; old payer is used only for fees.
    u.MULTISIG_WALLET_ID = 0x54455354
    u.EVM_CHAIN_ID = 56
    u.BRIDGE_PARAM = 81
    u.BRIDGE_TOS = 6
    u.MULTISIG_TOS = 5
    if not state.get("evm"):
        state.set(
            "evm",
            {
                "chain_id": 56,
                "bridge": "0x" + format(EXTERNAL_NAMESPACE, "040x"),
                "token": "0x" + SOURCE_TOKEN,
                "test_only": True,
            },
        )
    deployer = u.wallets(chain, keys)["deployer"]
    funder = payer(chain, args.bridge_state)
    require_original_payer_clear(args, state, funder.address)
    u.require(
        chain.balance(funder.address) >= 65 * u.NANO or state.intent("namespace-fund"),
        "payer reserve insufficient",
    )
    funder.transfer(
        state,
        "namespace-fund",
        deployer.address,
        45 * u.NANO,
        bounce=False,
        init=deployer.init,
    )
    chain.wait("test deployer active", lambda: chain.active(deployer.address))
    state.set("wallets", {n: w.address for n, w in u.wallets(chain, keys).items()})
    state.set("bridge_param", 81)
    state.set("label", LABEL)
    for name, amount in (("buyer", 7), ("submitter", 3)):
        w = u.wallets(chain, keys)[name]
        deployer.transfer(
            state, "fund-" + name, w.address, amount * u.NANO, bounce=False, init=w.init
        )
        chain.wait(name + " active", lambda w=w: chain.active(w.address))
    if not state.get("tvm"):
        printed = tools.fift_run(output, "new-bridge.fif", "56", state["evm"]["bridge"])
        bridge = next(
            x.split("=")[1].strip().lower()
            for x in printed.splitlines()
            if x.startswith("new bridge address")
        )
        (output / "oracles.pub").write_text(
            " ".join(
                u.friendly_pubkey(bytes(k.verify_key)) for k in u.tvm_oracles(keys)
            )
        )
        printed = tools.fift_run(
            output,
            "new-multisig.fif",
            "-1",
            str(u.MULTISIG_WALLET_ID),
            "oracles",
            str(u.QUORUM),
            "oracles.pub",
            bridge,
        )
        multisig = next(
            x.split("=")[1].strip().lower()
            for x in printed.splitlines()
            if x.startswith("new wallet address")
        )
        for name in ("bridge-create.boc", "oracles-create.boc"):
            shutil.copyfile(output / name, state.root / name)
        state.set(
            "tvm",
            {
                "bridge": bridge,
                "multisig": multisig,
                "code_hashes": hashes,
                "stage": str(output),
            },
        )
    u.step_tvm_deploy(args, state, chain, tools, keys)
    # Governance uses the existing local ceremony payer and the existing signer keys.
    # A fresh payer avoids relying on pruned historical transactions. The old
    # payer's failed read is retained; no baseline or history guard is removed.
    governance_payer = u.payer_files(args, state, tools, keys)
    if not state.intent("fund-governance-payer"):
        u.require(
            chain.balance(funder.address) >= 55 * u.NANO,
            "original payer reserve insufficient",
        )
    funder.transfer(
        state,
        "fund-governance-payer",
        governance_payer["address"],
        35 * u.NANO,
        bounce=False,
    )
    if not chain.active(governance_payer["address"]):
        message = u.lib.parse_boc(Path(governance_payer["query"]).read_bytes())
        prior = state.intent("activate-governance-payer")
        if prior is None:
            prior = {
                "hash": message.hash().hex(),
                "state": "signed",
                "created_at": int(__import__("time").time()),
            }
            state.put_intent("activate-governance-payer", prior)
        u.require(prior["hash"] == message.hash().hex(), "payer activation changed")
        chain.send(message)
        chain.wait(
            "governance payer active", lambda: chain.active(governance_payer["address"])
        )
        tx = chain.executed_external(
            governance_payer["address"], prior["hash"], prior["created_at"] - 60
        )
        u.require(tx and tx["took_effect"], "payer activation unproven")
        prior.update(state="done", tx=tx)
        state.put_intent("activate-governance-payer", prior)
    args.keys = keys
    configured = chain.config(81)
    u.require(
        configured is None
        or configured.hash().hex() == state["config79"]["value_hash"],
        "ConfigParam 81 is occupied by another namespace",
    )
    u.step_config79(args, state, chain, tools)
    st = chain.get(state["tvm"]["bridge"], "get_bridge_state")
    if u.num(st[5]) == 0:
        if not state.get("generation_start"):
            state.set("generation_start", 1)
        vote = (
            u.Builder()
            .uint(u.VOTE_ACTIVATE_GENERATION, 8)
            .raw(u.split(state["tvm"]["bridge"])[1])
            .uint(state["tvm"]["life"], 64)
            .uint(1, 32)
            .uint(state["generation_start"], 64)
            .end()
        )
        u.oracle_vote(state, chain, keys, vote, 1, "test-generation")
        chain.wait(
            "test generation active",
            lambda: (
                u.num(chain.get(state["tvm"]["bridge"], "get_bridge_state")[5]) != 0
            ),
        )
    if not state.get("lock"):
        state.set(
            "lock",
            {
                "n": state["generation_start"],
                "amount": 5000000,
                "synthetic_oracle_authorization": LABEL,
            },
        )
    if not state.get("mint"):
        u.step_mint(args, state, chain, tools, keys)
    # Same on-disk CLI config as the existing test payer; it contains no new signing authority.
    if not (state.root / "tosctl-config.json").exists():
        shutil.copyfile(
            args.bridge_state / "tosctl-config.json", state.root / "tosctl-config.json"
        )
        (state.root / "tosctl-config.json").chmod(0o600)
    state.evidence(
        "namespace", {"label": LABEL, "tvm": state["tvm"], "mint": state["mint"]}
    )


def fund_governance(args, state, chain, tools):
    # The normal faucet lock and inactive-owner check stay mandatory. The
    # operator must restore the local elections service in a shell trap.
    active = service.run(
        ["systemctl", "show", "tos-pq-elections", "-p", "ActiveState", "--value"]
    ).strip()
    u.require(active == "inactive", "local elections service still owns the faucet")
    u.require(
        not (args.data / "elections/faucet-journal/pending.json").exists(),
        "faucet has a pending payment",
    )
    with (args.data / ".local-pq-faucet.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        target = u.payer_files(args, state, tools, state.root / "keys")["address"]
        genesis = u.faucet(chain, args.data)
        u.require(
            chain.balance(genesis.address) > 1000 * u.NANO,
            "faucet reserve insufficient",
        )
        receipt = genesis.transfer(
            state, "critical-recognition-fees", target, 60 * u.NANO, bounce=False
        )
        state.evidence(
            "critical-recognition-fees",
            {
                "label": LABEL,
                "destination": target,
                "nanotos": 60 * u.NANO,
                "receipt": receipt,
            },
        )


def preflight_registration(args, state, chain, value):
    """Quote before creating an operation, so lack of funds leaves no open plan."""
    gov = u.governance_module()
    current = chain.config(84)
    proposal = gov.proposal_cell(84, value, current.hash())
    if gov.status(chain.url, proposal.hash().hex()) is not None:
        return
    setup = gov.parse_vote_setup(chain.config(11), True)
    quoted = (
        gov.proposal_price(value, setup, setup["min_store_sec"]) + gov.REGISTER_HEADROOM
    )
    target = gov.elections.address_from_file(state.root / "keys/payer.addr")
    u.require(
        chain.balance(target) >= quoted + gov.ops.FEE_ALLOWANCE_NANOTOS,
        "critical recognition payer cannot cover its quote; fund before planning",
    )


def recognize(args, state, chain, tools):
    # Preserve the existing entry byte for byte and append exactly our test entry.
    args.keys = state.root / "keys"
    old_spec = json.loads((args.bridge_state / "config84-spec.json").read_text())
    tvm = state["tvm"]
    test = {
        "master": u.split(state["mint"]["minter"])[1].hex(),
        "status": "active",
        "decimals": 6,
        "minter_code_hash": tvm["minter_code_hash"],
        "wallet_code_hash": tvm["wallet_code_hash"],
        "max_liability_per_actor": "10000000",
        "origin": {
            "kind": "token_bridge",
            "bridge_address": u.split(tvm["bridge"])[1].hex(),
            "source_chain_id": 56,
            "source_token": SOURCE_TOKEN,
        },
    }
    u.require(
        all(a["master"] != test["master"] for a in old_spec["assets"]),
        "test master conflicts",
    )
    old_spec["assets"].append(test)
    path = state.root / "config84-local-only-test-spec.json"
    if path.exists():
        u.require(json.loads(path.read_text()) == old_spec, "recognition plan changed")
    else:
        path.write_text(json.dumps(old_spec, indent=2) + "\n")
    boc = state.root / "config84-local-only-test.boc"
    service.run(
        [
            str(args.tosctl),
            "vote",
            "offer",
            "settlement-assets",
            "build",
            "--spec",
            str(path),
            "--out",
            str(boc),
        ]
    )
    current = chain.config(84)
    old = u.lib.parse_boc((args.bridge_state / "config84.boc").read_bytes())
    target = u.lib.parse_boc(boc.read_bytes())
    u.require(
        current and current.hash() in (old.hash(), target.hash()),
        "ConfigParam 84 changed outside the planned extension",
    )
    preflight_registration(args, state, chain, target)
    release = u.node_release_evidence(state, chain, args.data)
    result = u.adopt(
        args, state, chain, tools, 84, boc, ["--node-release-evidence", str(release)]
    )
    state.evidence(
        "recognized-local-only-test",
        {
            "label": LABEL,
            "source_token_ascii": bytes.fromhex(SOURCE_TOKEN).decode(),
            "adoption": result,
            "entry": test,
        },
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("step", choices=("namespace", "recognize", "fund-governance"))
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--test-source", type=Path, required=True)
    p.add_argument("--tools-tos", type=Path, required=True)
    p.add_argument("--running-tos", type=Path, required=True)
    p.add_argument("--tosctl", type=Path, required=True)
    p.add_argument("--approved-genesis", required=True)
    p.add_argument("--data", type=Path, default=Path("/data"))
    p.add_argument("--bridge-state", type=Path, default=Path("/data/usdc"))
    p.add_argument("--ceremony", type=Path, required=True)
    p.add_argument("--governance-timeout", type=int, default=1800)
    a = p.parse_args()
    a.keys = a.bridge_state / "keys"
    root = u.private_dir(a.state)
    chain = u.Chain(a.data)
    with (
        (root / ".lock").open("a") as lock,
        (a.bridge_state / ".lock").open("a") as source_lock,
    ):
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(source_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = u.State(root)
        local_only(a, chain, state)
        tools = u.Tools(
            SimpleNamespace(
                tos_root=a.running_tos,
                tosctl=a.tosctl,
                cast="cast",
                evm_rpc="",
                evm_artifacts=".",
            )
        )
        tools.tos = a.tools_tos
        tools.contracts = a.tools_tos / "crosschain/token-bridge/tvm/contracts"
        tools.fift = a.running_tos / "build/crypto/fift"
        tools.func = a.running_tos / "build/crypto/func"
        {
            "namespace": namespace,
            "recognize": recognize,
            "fund-governance": fund_governance,
        }[a.step](a, state, chain, tools)


if __name__ == "__main__":
    main()
