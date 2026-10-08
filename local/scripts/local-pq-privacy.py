#!/usr/bin/env python3
"""Random real shielded-pool operations on the disposable development network.

The local pool uses the development proof key. Private notes and generated
proofs stay under a mode-0700 directory. No production wallet is involved.
"""

import argparse
import asyncio
import base64
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import random
import signal
import time
from contextlib import AsyncExitStack
from pathlib import Path

import local_pq_testnet as local
import nacl.signing
from contract import WalletV1Blueprint
from pytosiq_core import Address, Cell
from toslib import ToslibCDLL, ToslibClient

REPO = local.tos_root()
spec = importlib.util.spec_from_file_location(
    "local_transfers", Path(__file__).with_name("local-pq-transfers.py")
)
transfers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transfers)
require = transfers.require
NANO = 10**9
METHODS = (
    "commitment_root",
    "nullifier_root",
    "commitment_next_index",
    "nullifier_next_index",
    "native_liability",
    "backed",
)


def write_private_json(path, value):
    local.write_json(path, value, 0o600)


def record(directory, row):
    transfers.record(directory, row, status_mode=0o600)


def verify_state(actual, expected):
    require(set(actual) == set(METHODS) and set(expected) == set(METHODS), "incomplete pool state")
    require(
        all(int(actual[k]) == int(expected[k]) for k in METHODS),
        "pool roots, indices, liability or backing differ",
    )


def verify_withdrawal(before, after, amount, fee, sent, received, pool, recipient):
    require(
        amount > 0 and fee >= 0 and after - before == amount - fee,
        "withdrawal balance delta differs",
    )
    require(
        sent.hash == received.hash and sent.value == amount and received.value == amount,
        "withdrawal message differs",
    )
    for msg in (sent, received):
        require(
            Address(msg.source.account_address).to_str(is_user_friendly=False) == pool,
            "withdrawal source differs",
        )
        require(
            Address(msg.destination.account_address).to_str(is_user_friendly=False) == recipient,
            "withdrawal destination differs",
        )


# The pool's deposit and withdrawal denominations. The generator is the
# authority: run() checks at start that it accepts each of these and refuses
# a value outside them.
DENOMINATIONS = (NANO, 10 * NANO, 100 * NANO, 1000 * NANO)
WALLETS = 3


def gas_fee(gas):
    """The value attached for an operation with this gas ceiling, as the generator computes it."""
    return 667 + ((max(gas - 100, 0) * 436907 + 65535) // 65536)


class Costs:
    """What each operation takes from its sending wallet, from the generator's resources."""

    def __init__(self, resources):
        self.withdrawal_fee = int(resources["withdrawal_fee"])
        self.deposit_gas = gas_fee(int(resources["deposit_gas_ceiling"]))
        self.transact_value = gas_fee(int(resources["transact_gas_ceiling"]))
        # A sender keeps this much after paying an operation's attached value.
        self.reserve = NANO + self.transact_value

    def deposit_value(self, amount):
        return amount + self.deposit_gas


def plan_operation(notes, liability, balances, costs, setpoint, rng):
    """The next operation, or {"exhausted": reason} when none is feasible.

    The pool's liability is steered around `setpoint`: above it value is
    withdrawn (or concentrated so it can be), below half of it a deposit is
    made, and in between operations are random among the feasible ones.
    Senders are the richest wallet able to pay; a withdrawal pays the poorest
    other wallet, so the three wallets refill one another and lose only fees.
    """
    order = sorted(range(WALLETS), key=lambda i: (-balances[i], i))
    can_transact = [i for i in order if balances[i] >= costs.transact_value + costs.reserve]
    smallest = DENOMINATIONS[0]
    can_deposit = [i for i in order if balances[i] >= costs.deposit_value(smallest) + costs.reserve]
    positive = sorted((n for n in notes if n["amount"] > 0), key=lambda n: (-n["amount"], n["index"]))

    def poorest_except(sender):
        return min((i for i in range(WALLETS) if i != sender), key=lambda i: (balances[i], i))

    def other_owner(note):
        return rng.choice([i for i in range(WALLETS) if i != note["owner"]])

    withdraw = consolidate = transfer = None
    if len(positive) >= 2 and can_transact:
        best = positive[:2]
        total = best[0]["amount"] + best[1]["amount"]
        payable = [d for d in DENOMINATIONS if d <= total - costs.withdrawal_fee - 2]
        if payable:
            withdraw = {"operation": "withdraw", "amount": payable[-1], "owner": other_owner(best[0]),
                        "inputs": [best[0]["index"], best[1]["index"]]}
        # Value that could still be withdrawn one day: each note keeps 1 nano.
        # Below the smallest withdrawal, private operations can never return
        # value to the wallets, so none is issued and the state is terminal
        # unless a deposit is affordable.
        excess = sum(n["amount"] - 1 for n in positive)
        recoverable = excess >= smallest + costs.withdrawal_fee
        # Concentrating value moves the smaller input into the larger. It is used
        # only above the set-point, where the excess is far above one withdrawal,
        # and only when no withdrawal is payable, which with a dust smaller input
        # cannot happen (the largest note alone then funds one).
        consolidate = {"operation": "transfer", "amount": 1, "owner": other_owner(best[0]),
                       "inputs": [best[0]["index"], best[1]["index"]]}
        pair = rng.sample(positive, 2)
        pair_total = pair[0]["amount"] + pair[1]["amount"]
        if pair_total >= 2 and recoverable:
            transfer = {"operation": "transfer", "amount": rng.randint(1, min(NANO, pair_total - 1)),
                        "owner": other_owner(pair[0]), "inputs": [pair[0]["index"], pair[1]["index"]]}
    deposit = ({"operation": "deposit", "amount": smallest, "owner": rng.randrange(WALLETS)}
               if can_deposit else None)

    if liability > setpoint and (withdraw or consolidate):
        chosen = withdraw or consolidate
    elif liability < setpoint // 2 and deposit:
        chosen = deposit
    else:
        feasible = [op for op in (deposit, transfer, withdraw) if op]
        if not feasible:
            if not can_transact and not can_deposit:
                return {"exhausted": "no-funding"}
            if len(positive) < 2 and not can_deposit:
                return {"exhausted": "no-inputs"}
            return {"exhausted": "no-private-value"}
        chosen = rng.choice(feasible)
    sender = (can_deposit if chosen["operation"] == "deposit" else can_transact)[0]
    return {**chosen, "sender": sender, "recipient": poorest_except(sender)}


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def last_confirmed(output):
    """The newest confirmed record, searching transfers.jsonl and then its rotations."""
    for name in ["transfers.jsonl"] + [f"transfers.jsonl.{i}" for i in range(1, 5)]:
        path = output / name
        if not path.exists(follow_symlinks=False):
            continue
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        confirmed = [r for r in rows if r.get("kind") == "confirmed"]
        if confirmed:
            return confirmed[-1]
    return None


def verify_checkpoint(model, row, network, address, recomputed, onchain, pool_last_tx_hash, pending):
    """Refuse to resume unless the private model, the last confirmed record and the chain agree.

    `recomputed` is the generator's view of the model's state; `pool_last_tx_hash`
    the hash of the pool account's last transaction. A record written before
    state_sha256 existed has no global_id: the pool contract holding exactly its
    expected state, with that record's transaction as its last, identifies the
    chain together with the model's zerostate root.
    """
    require(not pending, "pending private operation requires review before resuming")
    require(
        model["zerostate_root"] == network["zerostate_root"] and model["pool"] == address,
        "model belongs to another chain or pool",
    )
    require(row is not None and row.get("kind") == "confirmed", "no confirmed record to resume from")
    if "state_sha256" in row:
        require(row["state_sha256"] == canonical_sha256(model["state"]),
                "private model differs from the last confirmed record")
        require(row["global_id"] == network["global_id"] and row["pool"] == address,
                "last confirmed record belongs to another network or pool")
    boc = base64.b64decode(row["transaction_bocs"][0])
    require(Cell.one_from_boc(boc).hash == pool_last_tx_hash,
            "the pool's last transaction is not the last confirmed one")
    verify_state(recomputed, row["expected"])
    verify_state(model["expected"], row["expected"])
    verify_state(onchain, row["expected"])


async def pool_state(args, address):
    return {
        k: await asyncio.to_thread(local.get_method, args.lite_client, args.data, address, k)
        for k in METHODS
    }


async def generate(process, request):
    encoded = json.dumps(request).encode() + b"\n"
    require(len(encoded) <= 32 * 1024**2, "private model request exceeds bound")
    process.stdin.write(encoded)
    await process.stdin.drain()
    line = await asyncio.wait_for(process.stdout.readline(), 300)
    require(line and len(line) <= 32 * 1024**2, "generator returned no bounded response")
    response = json.loads(line)
    require(response.get("ok") is True, f"generator refused: {response.get('error')}")
    return response["result"]


async def run(args):
    require(4 <= args.nodes <= 21, "full-node count must be 4..21")
    require(
        math.isfinite(args.min_interval)
        and math.isfinite(args.max_interval)
        and 0 < args.min_interval <= args.max_interval,
        "invalid interval",
    )
    require(args.count >= 0, "invalid count")
    args.lite_client = local.require_installed_executable(args.lite_client)
    local.secure_output_dir(args.output)
    with os.fdopen(local.open_private(args.output / "run.lock", os.O_WRONLY | os.O_CREAT | os.O_APPEND), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        wallets = []
        for i in range(3):
            p = args.output / f"wallet-{i}.seed"
            if not p.exists():
                require(args.bootstrap, "bootstrap private traffic wallets first")
                with os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                    f.write(nacl.signing.SigningKey.generate().encode())
            require(
                not p.is_symlink() and p.stat().st_mode & 0o077 == 0,
                "wallet seed permissions differ",
            )
            wallets.append(WalletV1Blueprint(0, nacl.signing.SigningKey(p.read_bytes())))
        cdll = ToslibCDLL(args.build / "toslib/libtoslibjson.so")
        cdll.client_set_verbosity_level(0)
        async with AsyncExitStack() as stack:
            clients = []
            for i in range(1, args.nodes + 1):
                cfg = local.lite_config(args.data / f"configs/node-{i}-lite.json", 8010 + i)
                clients.append(
                    local.PatientClient(await stack.enter_async_context(ToslibClient(cfg, cdll)))
                )
            if args.bootstrap:
                # Separate wallet keys; the existing regular-transfer config is untouched.
                args.bootstrap_config = "privacy-test.json"
                await transfers.bootstrap(args, clients[0], wallets)
                return
            status = json.loads((args.output / "status.json").read_text())
            resuming = status["kind"] == "failed" and args.resume_after_failure
            require(
                status["kind"] in ("bootstrapped", "confirmed", "resumed") or resuming,
                "previous operation unresolved; inspect private receipts"
                + (" (or resume with --resume-after-failure)" if status["kind"] == "failed" else ""),
            )
            require(
                resuming or not (args.output / "pending.json").exists(),
                "pending private operation requires review before restarting",
            )
            sequence = status.get("sequence", 0)
            counts = status.get("counts", {k: 0 for k in ("deposit", "transfer", "withdraw")})
            pool = json.loads((args.data / "shielded-pool/pool.json").read_text())
            address = pool["address"]
            network = json.loads((args.data / "network.json").read_text())
            stderr = stack.enter_context(
                os.fdopen(
                    local.open_private(
                        args.output / "generator.stderr",
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                    ),
                    "ab",
                )
            )
            generator = await asyncio.create_subprocess_exec(
                str(
                    args.generator
                ),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr,
                limit=32 * 1024**2 + 1,
                start_new_session=True,
                env={**os.environ, "RAYON_NUM_THREADS": "4"},
            )
            try:
                statepath = args.output / "notes.json"
                if statepath.exists():
                    model = json.loads(statepath.read_text())
                    require(
                        model["zerostate_root"] == network["zerostate_root"]
                        and model["pool"] == address,
                        "model belongs to another chain or pool",
                    )
                    state = model["state"]
                    expected = model["expected"]
                else:
                    require(sequence == 0, "confirmed operations but missing private model")
                    initial = await generate(generator, {"operation": "init"})
                    state, expected = initial["state"], initial["expected"]
                costs = Costs(await generate(generator, {"operation": "resources"}))

                def probe(amount):
                    # A deposit plan for this state, used only to check the generator's rules.
                    return generate(generator, {
                        "operation": "deposit", "amount": amount, "owner": 0, "state": state,
                        "global_id": network["global_id"], "pool": address.split(":")[1],
                        "recipient": address.split(":")[1], "valid_until": int(time.time()) + 1800,
                    })

                # The denominations and the attached-value formula this driver plans
                # with must be the generator's own.
                for amount in DENOMINATIONS:
                    require((await probe(amount))["value"] == costs.deposit_value(amount),
                            "generator's attached deposit value differs from this driver's")
                try:
                    await probe(DENOMINATIONS[0] + 1)
                    require(False, "generator accepted a value outside the denominations")
                except ValueError as exc:
                    require("denomination" in str(exc), f"unexpected refusal: {exc}")
                if resuming:
                    row = last_confirmed(args.output)
                    recomputed = (await probe(DENOMINATIONS[0]))["before"]
                    pool_account = await clients[0].raw_get_account_state(Address(address))
                    verify_checkpoint(
                        json.loads(statepath.read_text()), row, network, address, recomputed,
                        await pool_state(args, address), pool_account.last_transaction_id.hash,
                        (args.output / "pending.json").exists(),
                    )
                    kept = args.output / f"status.failed-{int(time.time())}.json"
                    local.write_json(kept, status, 0o600)
                    sequence, counts = row["sequence"], row["counts"]
                    record(args.output, {"kind": "resumed", "sequence": sequence, "counts": counts,
                                         "failure": status.get("error"), "failed_status": kept.name})
                verify_state(await pool_state(args, address), expected)
                rng = random.Random(args.seed)
                done = 0
                while args.count == 0 or done < args.count:
                    await asyncio.sleep(rng.uniform(args.min_interval, args.max_interval))
                    client = clients[sequence % len(clients)]
                    accounts = [w.materialize(client) for w in wallets]
                    balances = [(await client.raw_get_account_state(a.address)).balance for a in accounts]
                    chosen = plan_operation(state["notes"], int(state["liability"]), balances, costs,
                                            args.liability_setpoint, rng)
                    if "exhausted" in chosen:
                        record(args.output, {"kind": "exhausted", "reason": chosen["exhausted"],
                                             "sequence": sequence, "counts": counts, "balances": balances,
                                             "liability": int(state["liability"]),
                                             "notes": len(state["notes"])})
                        return
                    request = {k: chosen[k] for k in ("operation", "amount", "owner", "inputs") if k in chosen}
                    sender = accounts[chosen["sender"]]
                    recipient = accounts[chosen["recipient"]]
                    recipient_raw = recipient.address.to_str(is_user_friendly=False)
                    request.update(
                        state=state,
                        global_id=network["global_id"],
                        pool=address.split(":")[1],
                        recipient=recipient_raw.split(":")[1],
                        valid_until=int(time.time()) + 1800,
                    )
                    started = time.monotonic()
                    plan = await generate(generator, request)
                    verify_state(await pool_state(args, address), plan["before"])
                    before_s, before_r = await asyncio.gather(
                        client.raw_get_account_state(sender.address),
                        client.raw_get_account_state(recipient.address),
                    )
                    require(
                        before_s.balance >= plan["value"] + costs.reserve,
                        "private traffic funding wallet too low",
                    )
                    body = Cell.one_from_boc(bytes.fromhex(plan["body_hex"]))
                    write_private_json(
                        args.output / "pending.json", {"request": request, "plan": plan}
                    )
                    record(
                        args.output,
                        {
                            "kind": "submitting",
                            "sequence": sequence,
                            "operation": request["operation"],
                            "body_hash": body.hash.hex(),
                        },
                    )
                    seqno = await transfers.send(sender, Address(address), plan["value"], body)

                    async def included():
                        account = await client.raw_get_account_state(Address(address))
                        txs = await client.raw_get_transactions(
                            Address(address), account.last_transaction_id
                        )
                        found = [tx for tx in txs.transactions if tx.in_msg.body_hash == body.hash]
                        require(len(found) <= 1, "duplicate pool input")
                        return (account, found[0]) if found else None

                    pool_account, tx = await transfers.wait_for(included, timeout=120)
                    local.write_bytes(args.output / "last-pool-transaction.boc", tx.data, 0o600)
                    transfers.check_transaction(tx)
                    transfers.verify_message(
                        tx.in_msg,
                        sender.address.to_str(is_user_friendly=False),
                        address,
                        plan["value"],
                        body.hash,
                    )
                    verify_state(await pool_state(args, address), plan["expected"])
                    require((await sender.current).seqno == seqno + 1, "sender seqno differs")
                    outgoing = await client.raw_get_transactions(
                        sender.address,
                        (await client.raw_get_account_state(sender.address)).last_transaction_id,
                    )
                    matches = [
                        (t, m)
                        for t in outgoing.transactions
                        for m in t.out_msgs
                        if m.body_hash == body.hash
                    ]
                    require(
                        len(matches) == 1 and matches[0][1].hash == tx.in_msg.hash,
                        "funding send and pool receipt differ",
                    )
                    transfers.check_transaction(matches[0][0])
                    require(
                        before_s.balance
                        - (await client.raw_get_account_state(sender.address)).balance
                        >= plan["value"],
                        "funding debit differs",
                    )
                    payout_boc = None
                    if request["operation"] == "withdraw":
                        require(len(tx.out_msgs) == 1, "withdrawal did not emit exactly one payout")
                        sent = tx.out_msgs[0]

                        async def paid():
                            a = await client.raw_get_account_state(recipient.address)
                            txs = await client.raw_get_transactions(
                                recipient.address, a.last_transaction_id
                            )
                            return next(
                                ((a, t) for t in txs.transactions if t.in_msg.hash == sent.hash),
                                None,
                            )

                        after_r, paid_tx = await transfers.wait_for(paid, timeout=120)
                        transfers.check_transaction(paid_tx)
                        require(not paid_tx.out_msgs, "withdrawal bounced or emitted messages")
                        verify_withdrawal(
                            before_r.balance,
                            after_r.balance,
                            request["amount"],
                            paid_tx.fee,
                            sent,
                            paid_tx.in_msg,
                            address,
                            recipient_raw,
                        )
                        payout_boc = base64.b64encode(paid_tx.data).decode()
                    else:
                        require(not tx.out_msgs, "deposit or private transfer emitted a payout")
                    expected_pool = transfers.snapshot(pool_account)
                    expected_data = Cell.one_from_boc(pool_account.data).hash
                    funding_after = await client.raw_get_account_state(sender.address)
                    recipient_after = await client.raw_get_account_state(recipient.address)
                    wallet_expected = [
                        transfers.snapshot(funding_after),
                        transfers.snapshot(recipient_after),
                    ]

                    async def synchronized():
                        states = await asyncio.gather(
                            *[c.raw_get_account_state(Address(address)) for c in clients]
                        )
                        wallet_states = await asyncio.gather(
                            *[
                                c.raw_get_account_state(addr)
                                for c in clients
                                for addr in (sender.address, recipient.address)
                            ]
                        )
                        return all(
                            transfers.snapshot(a) == wallet_expected[i % 2]
                            for i, a in enumerate(wallet_states)
                        ) and all(
                            transfers.snapshot(a) == expected_pool
                            and Cell.one_from_boc(a.data).hash == expected_data
                            for a in states
                        )

                    await transfers.wait_for(synchronized, timeout=120)
                    state, expected = plan["state"], plan["expected"]
                    write_private_json(
                        statepath,
                        {
                            "zerostate_root": network["zerostate_root"],
                            "pool": address,
                            "state": state,
                            "expected": expected,
                        },
                    )
                    sequence += 1
                    done += 1
                    counts[request["operation"]] += 1
                    record(
                        args.output,
                        {
                            "kind": "confirmed",
                            "sequence": sequence,
                            "operation": request["operation"],
                            "counts": counts,
                            "amount_nanotos": request["amount"],
                            "elapsed_seconds": round(time.monotonic() - started, 3),
                            "nodes_agree": len(clients),
                            "expected": expected,
                            "state_sha256": canonical_sha256(state),
                            "global_id": network["global_id"],
                            "pool": address,
                            "transaction_bocs": [base64.b64encode(tx.data).decode(), payout_boc],
                        },
                    )
                    (args.output / "pending.json").unlink()
            finally:
                if generator.returncode is None:
                    os.killpg(generator.pid, signal.SIGTERM)
                    try:
                        await asyncio.wait_for(generator.wait(), 5)
                    except asyncio.TimeoutError:
                        os.killpg(generator.pid, signal.SIGKILL)
                        await generator.wait()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, default=Path("/data"))
    p.add_argument("--output", type=Path, default=Path("/data/privacy-transfers"))
    p.add_argument("--nodes", type=int, default=7, help="fixed full-node inventory size")
    p.add_argument("--build", type=Path, default=REPO / "build")
    p.add_argument("--lite-client", type=Path, default=local.INSTALLED_LITE_CLIENT)
    p.add_argument(
        "--generator", type=Path,
        default=REPO / "tools/shielded-pool-circuit/crosscheck/target/release/local_pool_traffic",
    )
    p.add_argument("--bootstrap", action="store_true")
    p.add_argument("--count", type=int, default=0)
    p.add_argument("--min-interval", type=float, default=20)
    p.add_argument("--max-interval", type=float, default=60)
    p.add_argument("--seed", type=int)
    p.add_argument("--liability-setpoint", type=int, default=50 * NANO,
                   help="pool liability, in nanotos, the traffic steers towards")
    p.add_argument("--resume-after-failure", action="store_true",
                   help="resume a failed run once the private model, the last record and the chain agree")
    args = p.parse_args()
    os.umask(0o077)
    try:
        asyncio.run(run(args))
    except Exception as exc:
        if args.output.exists():
            record(args.output, {"kind": "failed", "error": f"{type(exc).__name__}: {exc}"})
        raise


if __name__ == "__main__":
    main()
