#!/usr/bin/env python3
"""Change a configuration parameter by a vote of the validators (coordinator side).

  propose  --ceremony DIR --tos-root DIR --fift PATH --rpc URL --confirm-rpc URL
           --payer-key FILE --payer-addr FILE --payer-subwallet N
           --param N --value-boc FILE [--expire-seconds S] [--id ID] [--dry-run]
      Register a proposal with the Config contract (-1:55..55) to set ConfigParam N
      to the cell in FILE. The proposal binds the current value's hash, so it can
      only replace the value it was made against. A parameter that ConfigParam 10
      lists is registered as critical (the contract refuses it otherwise); the
      storage price follows ConfigParam 11 and is paid from the payer, a wallet v3 in
      the masterchain (only masterchain senders reach the Config contract). The
      transfer is an ordinary journaled operation (testnet_ops): one intent, one
      broadcast, settled on both validators; it then counts only if the Config
      contract lists the proposal.

  sign     --ceremony DIR --inventory FILE --rpc URL --proposal HASH [--host NAME]...
      On each validator host, the node's console signs a vote for the proposal
      (`create-proposal-vote`) under the current validator set. Only the vote body
      leaves the host. The votes and the ConfigParam 34 they were signed under are
      written to DIR/governance/<proposal>/round-<set>.json.

  vote     --ceremony DIR --tos-root DIR --fift PATH --rpc URL --confirm-rpc URL
           --payer-key FILE --payer-addr FILE --payer-subwallet N --proposal HASH
      Deliver the current round's votes one at a time, each as its own journaled
      operation with 0.6 TOS attached (the contract pays the verification from it
      and returns the rest). Refused when the validator set changed since the votes
      were signed (a vote is bound to its set), and a validator that already voted
      in this round is skipped. Stops when the round is won.

  status   --rpc URL --proposal HASH
      The proposal as the Config contract stores it: critical flag, parameter,
      remaining weight, rounds left, wins and losses (or "absent").

  adopted  --rpc URL --confirm-rpc URL --param N --value-boc FILE
      Exit 0 only if both validators serve ConfigParam N equal to FILE.

A proposal needs ConfigParam 11's min_wins winning rounds (2 ordinary, 3 critical),
each under a different validator set, and a round is won when votes of more than
3/4 of the set's weight arrive. Votes must be signed again after every rotation.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import testnet_lib as lib  # noqa: E402
import testnet_ops as ops  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "testnet_elections_for_governance", HERE / "testnet-elections.py"
)
elections = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(elections)

CONFIG_ADDRESS = "-1:" + "55" * 32
REGISTER_OP = 0x6E565052
VOTE_OP = 0x5051766F
PROPOSAL_TAG = 0xF3
VOTE_VALUE = 600_000_000
# The contract keeps the price and requires at least 2^30 nanotos beyond it.
REGISTER_HEADROOM = (1 << 30) + 500_000_000
CONSOLE = (
    "validator-engine-console -a 127.0.0.1:30002 "
    "-k /var/lib/tos/validator/console-client/client "
    "-p /var/lib/tos/validator/console-client/server.pub"
)


# ---------------------------------------------------------------- cells


def uint_bits(value: int, width: int) -> str:
    if not 0 <= value < (1 << width):
        raise lib.TestnetError(f"{value} does not fit {width} bits")
    return format(value, f"0{width}b")


def int_bits(value: int, width: int) -> str:
    if not -(1 << (width - 1)) <= value < (1 << (width - 1)):
        raise lib.TestnetError(f"{value} does not fit a signed {width}-bit field")
    return uint_bits(value % (1 << width), width)


def proposal_cell(param: int, value: lib.Cell, current_hash: bytes | None) -> lib.Cell:
    """cfg_proposal#f3 param_id:int32 param_value:(Maybe ^Cell) if_hash_equal:(Maybe uint256)"""
    bits = uint_bits(PROPOSAL_TAG, 8) + int_bits(param, 32) + "1"
    if current_hash is None:
        bits += "0"
    else:
        if len(current_hash) != 32:
            raise lib.TestnetError("the current value hash is 32 bytes")
        bits += "1" + uint_bits(int.from_bytes(current_hash, "big"), 256)
    return lib.cell_from_bits(bits, [value])


def register_body(
    query_id: int, expire_seconds: int, proposal: lib.Cell, critical: bool
) -> lib.Cell:
    """new_voting_proposal: op, query_id, expire_at (relative while < 2^30), ^proposal, critical."""
    if not 0 < expire_seconds < (1 << 30):
        raise lib.TestnetError("expire_seconds is a positive relative time below 2^30")
    bits = (
        uint_bits(REGISTER_OP, 32)
        + uint_bits(query_id, 64)
        + uint_bits(expire_seconds, 32)
        + ("1" if critical else "0")
    )
    return lib.cell_from_bits(bits, [proposal])


def tree_size(root: lib.Cell) -> tuple[int, int]:
    """(bits, refs) over the distinct cells of a tree, as compute_data_size counts them."""
    seen: dict[bytes, lib.Cell] = {}
    stack = [root]
    while stack:
        cell = stack.pop()
        h = cell.hash()
        if h in seen:
            continue
        seen[h] = cell
        stack.extend(cell.refs)
    return sum(c.bits for c in seen.values()), sum(len(c.refs) for c in seen.values())


def parse_vote_setup(cp11: lib.Cell, critical: bool) -> dict[str, int]:
    """cfg_vote_setup#91 normal_params:^ConfigProposalSetup critical_params:^ConfigProposalSetup"""
    s = lib.Slice(cp11)
    if s.bits(8) != 0x91:
        raise lib.TestnetError("ConfigParam 11 is not cfg_vote_setup#91")
    setup = lib.Slice(cp11.refs[1] if critical else cp11.refs[0])
    if setup.bits(8) != 0x36:
        raise lib.TestnetError("ConfigProposalSetup is not cfg_vote_cfg#36")
    names = ("min_tot_rounds", "max_tot_rounds", "min_wins", "max_losses")
    out = {n: setup.bits(8) for n in names}
    for n in ("min_store_sec", "max_store_sec", "bit_price", "cell_price"):
        out[n] = setup.bits(32)
    return out


def proposal_price(value: lib.Cell, setup: dict[str, int], expire_seconds: int) -> int:
    """The price register_voting_proposal keeps (config-code.fc), in nanotos."""
    if expire_seconds < setup["min_store_sec"]:
        raise lib.TestnetError(
            f"the proposal must be kept at least {setup['min_store_sec']} s (ConfigParam 11)"
        )
    kept = min(expire_seconds, setup["max_store_sec"])
    bits, refs = tree_size(value)
    return (setup["bit_price"] * (bits + 1024) + setup["cell_price"] * (refs + 2)) * kept


def signed_keys(cell: lib.Cell | None, width: int = 32) -> set[int]:
    if cell is None:
        return set()
    keys = lib.hashmap_items(cell, width)
    return {k - (1 << width) if k >> (width - 1) else k for k in keys}


def parse_vote(boc: bytes, proposal: str) -> tuple[int, lib.Cell]:
    """The console's vote body: op, query_id, idx:uint16, proposal:uint256, ^signature."""
    cell = lib.parse_boc(boc)
    s = lib.Slice(cell)
    if s.bits(32) != VOTE_OP:
        raise lib.TestnetError("the console's answer is not a configuration vote")
    s.bits(64)
    idx = s.bits(16)
    if f"{s.bits(256):064x}" != proposal:
        raise lib.TestnetError("the vote is for another proposal")
    if len(cell.refs) != 1 or s.remaining() != 0:
        raise lib.TestnetError("the vote body has an unexpected shape")
    return idx, cell


# ---------------------------------------------------------------- reads


def config_cell(url: str, param: int) -> lib.Cell | None:
    answer = lib.rpc(url, "getConfigParam", param=param)
    data = (answer or {}).get("config", {}).get("bytes")
    return lib.parse_boc(base64.b64decode(data)) if data else None


def status(url: str, proposal: str) -> dict | None:
    """get_proposal: [expires, critical?, [param, value, hash], vset_id, voters, weight_remaining,
    rounds_remaining, losses, wins], or null."""
    answer = lib.rpc(
        url,
        "runGetMethod",
        address=CONFIG_ADDRESS,
        method="get_proposal",
        stack=[["num", str(int(proposal, 16))]],
    )
    if answer.get("exit_code") != 0:
        raise lib.TestnetError(f"get_proposal exited {answer.get('exit_code')}")
    stack = answer.get("stack") or []
    if not stack or stack[0][0] != "tuple":
        return None
    e = stack[0][1]["elements"]

    def num(x):
        return int(x[1], 0)

    voters: list[int] = []
    node = e[4]
    while node[0] == "tuple" and node[1]["elements"]:
        head, tail = node[1]["elements"]
        voters.append(num(head))
        node = tail
    if node[0] == "list":
        voters += [num(x) for x in node[1]["elements"]]
    return {
        "expires": num(e[0]),
        "critical": num(e[1]) != 0,
        "param": num(e[2][1]["elements"][0]),
        "vset_id": f"{num(e[3]):064x}",
        "voters": sorted(voters),
        "weight_remaining": num(e[5]),
        "rounds_remaining": num(e[6]),
        "losses": num(e[7]),
        "wins": num(e[8]),
    }


def current_set_hash(url: str) -> str:
    cell = config_cell(url, 34)
    if cell is None:
        raise lib.TestnetError("no ConfigParam 34")
    return cell.hash().hex()


# ---------------------------------------------------------------- operations


def payer_signer(args: argparse.Namespace, global_id: int, value: int, body: lib.Cell):
    key = Path(args.payer_key)
    address_file = Path(args.payer_addr).read_bytes()

    def sign(seqno: int) -> bytes:
        with tempfile.TemporaryDirectory(prefix="governance-") as work:
            path = Path(work) / "body.boc"
            path.write_bytes(lib.serialize_boc(body))
            return elections.sign_wallet_v3(
                args,
                global_id,
                key,
                address_file,
                CONFIG_ADDRESS,
                args.payer_subwallet,
                seqno,
                elections.nanotos_text(value),
                bounce=True,
                body=path,
            )

    return sign


def send(
    args,
    operations,
    global_id: int,
    op_id: str,
    label: str,
    kind: str,
    value: int,
    body: lib.Cell,
    expect,
) -> dict:
    payer = elections.address_from_file(Path(args.payer_addr))
    params = {
        "kind": kind,
        "wallet": payer,
        "destination": CONFIG_ADDRESS,
        "value": value,
        "bounce": True,
        "body_hash": body.hash().hex(),
        "state_init_hash": None,
        "label": label,
        "subwallet": args.payer_subwallet,
    }

    def prerequisites() -> None:
        balance = operations.balance(payer)
        if balance < value + ops.FEE_ALLOWANCE_NANOTOS:
            raise lib.TestnetError(f"the payer holds {balance / 1e9:.9f} TOS")

    return operations.run(
        op_id,
        params,
        payer_signer(args, global_id, value, body),
        lambda decoded: None,
        prerequisites,
        expect,
    )


def cmd_propose(args) -> int:
    value = lib.parse_boc(Path(args.value_boc).read_bytes())
    current = config_cell(args.rpc, args.param)
    if current is not None and current.hash() == value.hash():
        raise lib.TestnetError(f"ConfigParam {args.param} already has this value")
    critical = args.param in signed_keys(config_cell(args.rpc, 10))
    setup = parse_vote_setup(config_cell(args.rpc, 11), critical)
    expire = args.expire_seconds or setup["min_store_sec"]
    price = proposal_price(value, setup, expire)
    proposal = proposal_cell(args.param, value, current.hash() if current is not None else None)
    phash = proposal.hash().hex()
    body = register_body(int(time.time()), expire, proposal, critical)
    plan = {
        "proposal": phash,
        "param": args.param,
        "critical": critical,
        "price_nanotos": price,
        "attached_nanotos": price + REGISTER_HEADROOM,
        "expire_seconds": expire,
        "current_hash": current.hash().hex() if current is not None else None,
        "value_hash": value.hash().hex(),
        "min_wins": setup["min_wins"],
    }
    folder = lib.private_dir(lib.private_dir(Path(args.ceremony) / "governance") / phash)
    (folder / "proposal.json").write_text(json.dumps(plan, indent=1) + "\n")
    (folder / "value.boc").write_bytes(lib.serialize_boc(value))
    print(json.dumps(plan, indent=1))
    if args.dry_run:
        print("dry run: nothing signed or sent")
        return 0
    if status(args.rpc, phash) is not None:
        print(f"proposal {phash} is already registered")
        return 0
    global_id = lib.confirmed_global_id(lib.load_profile(Path(args.profile)))
    operations = elections.operations_for(args, global_id)

    def expect(_ops, record, delivery, evidence):
        if status(args.rpc, phash) is None:
            return "failed", dict(
                evidence, form="b", reason="the Config contract did not register it"
            )
        return "settled", evidence

    send(
        args,
        operations,
        global_id,
        args.id or f"config-propose-{phash[:12]}",
        f"propose-{args.param}",
        "config-propose",
        price + REGISTER_HEADROOM,
        body,
        expect,
    )
    print(json.dumps(status(args.rpc, phash), indent=1))
    return 0


def cmd_sign(args) -> int:
    proposal = args.proposal.lower()
    if status(args.rpc, proposal) is None:
        raise lib.TestnetError(f"proposal {proposal} is not registered")
    set_hash = current_set_hash(args.rpc)
    inventory = {h["name"]: h for h in json.loads(Path(args.inventory).read_text())["hosts"]}
    hosts = args.host or ["node-1", "node-2", "node-3", "node-4"]
    script = (
        "set -eu\numask 077\n"
        "d=$(mktemp -d /var/lib/tos/validator/config-vote.XXXXXX)\n"
        'trap \'rm -rf "$d"\' EXIT\ncd "$d"\n'
        f"{CONSOLE} -c 'create-proposal-vote 0x{proposal} vote.boc' >/dev/null\n"
        "test -s vote.boc\nprintf 'CONFIG_VOTE '\nbase64 -w0 vote.boc\nprintf '\\n'\n"
    )
    votes = {}
    for name in hosts:
        h = inventory[name]
        host = elections.Host(h["address"], str(Path(h["ssh_key"]).expanduser()))
        out = subprocess.run(
            host.base + ["runuser -u tos -- bash -s"],
            input=script,
            text=True,
            capture_output=True,
            timeout=90,
        )
        if out.returncode != 0:
            raise lib.TestnetError(f"{name}: the console refused (exit {out.returncode}); no retry")
        lines = [x for x in out.stdout.splitlines() if x.startswith("CONFIG_VOTE ")]
        if len(lines) != 1:
            raise lib.TestnetError(f"{name}: expected one vote")
        raw = base64.b64decode(lines[0].split()[1], validate=True)
        idx, cell = parse_vote(raw, proposal)
        votes[str(idx)] = {
            "host": name,
            "boc": base64.b64encode(raw).decode(),
            "hash": cell.hash().hex(),
        }
        print(f"{name}: idx {idx}")
    if current_set_hash(args.rpc) != set_hash:
        raise lib.TestnetError("the validator set changed while signing; sign again")
    folder = lib.private_dir(lib.private_dir(Path(args.ceremony) / "governance") / proposal)
    path = folder / f"round-{set_hash[:16]}.json"
    path.write_text(json.dumps({"set": set_hash, "votes": votes}, indent=1) + "\n")
    print(f"{len(votes)} votes signed under ConfigParam 34 {set_hash[:16]}: {path}")
    return 0


def cmd_vote(args) -> int:
    proposal = args.proposal.lower()
    set_hash = current_set_hash(args.rpc)
    path = Path(args.ceremony) / "governance" / proposal / f"round-{set_hash[:16]}.json"
    if not path.is_file():
        raise lib.TestnetError(f"no votes signed under the current set {set_hash[:16]}; run sign")
    round_ = json.loads(path.read_text())
    if round_["set"] != set_hash:
        raise lib.TestnetError("the votes were signed under another validator set")
    global_id = lib.confirmed_global_id(lib.load_profile(Path(args.profile)))
    operations = elections.operations_for(args, global_id)
    before = status(args.rpc, proposal)
    if before is None:
        raise lib.TestnetError(f"proposal {proposal} is not registered (or was already adopted)")
    for idx in sorted(round_["votes"], key=int):
        now = status(args.rpc, proposal)
        if now is None:
            print("the proposal is gone: adopted or removed; check with `adopted`")
            return 0
        if now["wins"] > before["wins"]:
            print(f"round won: wins {now['wins']}")
            return 0
        if int(idx) in now["voters"]:
            print(f"idx {idx} already voted in this round")
            continue
        if current_set_hash(args.rpc) != set_hash:
            raise lib.TestnetError("the validator set changed; these votes no longer count")
        vote = lib.parse_boc(base64.b64decode(round_["votes"][idx]["boc"]))

        def expect(_ops, record, delivery, evidence, _idx=int(idx)):
            after = status(args.rpc, proposal)
            if after is None or _idx in after["voters"] or after["wins"] > before["wins"]:
                return "settled", evidence
            return "failed", dict(
                evidence, form="b", reason="the Config contract did not count the vote"
            )

        send(
            args,
            operations,
            global_id,
            f"config-vote-{proposal[:12]}-{set_hash[:8]}-{idx}",
            f"vote-{proposal[:12]}-{idx}",
            "config-vote",
            VOTE_VALUE,
            vote,
            expect,
        )
        print(f"idx {idx}: {json.dumps(status(args.rpc, proposal))}")
    final = status(args.rpc, proposal)
    print(json.dumps(final, indent=1) if final else "the proposal is gone: adopted or removed")
    return 0


def cmd_status(args) -> int:
    print(json.dumps(status(args.rpc, args.proposal.lower()), indent=1))
    return 0


def cmd_adopted(args) -> int:
    want = lib.parse_boc(Path(args.value_boc).read_bytes()).hash()
    for url in (args.rpc, args.confirm_rpc):
        cell = config_cell(url, args.param)
        if cell is None or cell.hash() != want:
            print(f"{url}: ConfigParam {args.param} is not the proposed value")
            return 1
    print(f"ConfigParam {args.param} = {want.hex()} on both validators")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", default=str(lib.PROFILE_PATH))
    sub = parser.add_subparsers(dest="command", required=True)

    def chain(p, confirm=False):
        p.add_argument("--rpc", required=True)
        if confirm:
            p.add_argument("--confirm-rpc", required=True)

    def payer(p):
        p.add_argument("--ceremony", required=True)
        p.add_argument("--tos-root", required=True)
        p.add_argument("--fift", required=True)
        p.add_argument("--payer-key", required=True)
        p.add_argument("--payer-addr", required=True)
        p.add_argument("--payer-subwallet", type=int, required=True)

    p = sub.add_parser("propose")
    payer(p)
    chain(p, confirm=True)
    p.add_argument("--param", type=int, required=True)
    p.add_argument("--value-boc", required=True)
    p.add_argument("--expire-seconds", type=int)
    p.add_argument("--id")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_propose)

    p = sub.add_parser("sign")
    p.add_argument("--ceremony", required=True)
    p.add_argument("--inventory", required=True)
    chain(p)
    p.add_argument("--proposal", required=True)
    p.add_argument("--host", action="append")
    p.set_defaults(fn=cmd_sign)

    p = sub.add_parser("vote")
    payer(p)
    chain(p, confirm=True)
    p.add_argument("--proposal", required=True)
    p.set_defaults(fn=cmd_vote)

    p = sub.add_parser("status")
    chain(p)
    p.add_argument("--proposal", required=True)
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("adopted")
    chain(p, confirm=True)
    p.add_argument("--param", type=int, required=True)
    p.add_argument("--value-boc", required=True)
    p.set_defaults(fn=cmd_adopted)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except (lib.TestnetError, ops.OperationRefused) as error:
        print(f"testnet-governance: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
