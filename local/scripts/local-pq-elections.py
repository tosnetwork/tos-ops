#!/usr/bin/env python3
"""Run real development-only PQ elections on the persistent local network.

Each candidate stakes directly from its own disposable masterchain wallet: the
wallet's account id is the validator id its node is bound to, the node signs the
stake authorization for that account, and the wallet sends the elector the
stake with the elector's fees. Recovered stakes come back to the same wallet.
"""

import asyncio
import base64
import json
import os
import re
import time
from pathlib import Path

import local_pq_testnet as local
import nacl.signing
from contract import WalletV1, WalletV1Blueprint
from local_pq_election_evidence import RECOVER_STAKE_OP, election_result, recovery_result
from local_pq_transactions import (
    NANO,
    Faucet,
    atomic_json,
    cursor,
    faucet_lock,
    history_since,
    read_json,
    require_success,
)
from pytosiq_core import (
    Address,
    Builder,
    Cell,
    StateInit,
)
from tosapi import tos_api
from toslib import EngineConsoleClient, ToslibCDLL, ToslibClient, ToslibEventLoop
from tostester.pq_election_fixture import (
    ELECTOR,
    build_production_pool_stake_order,
    elector_body_from_pool_order,
)
from x02_config34_proof import decode_validator_set

DATA = Path("/data")
OUT = DATA / "elections"
REPO = local.tos_root()
CANDIDATES = local.CANDIDATES
STAKE = 11000 * NANO
# What the elector keeps from a stake message for its confirmation, plus compute,
# as tosctl's election runner attaches to a direct stake (runner.rs send_stake).
STAKE_FEE = 1_200_000_000
# Left in a candidate wallet after a stake, for its own storage and gas.
WALLET_RESERVE = NANO
# Attached to a recovery request, as tosctl's election runner does.
RECOVER_FEE = 200_000_000
DEPLOY_VALUE = 10 * NANO
RECOVERY_INTERVAL = 60


def roster(round_index):
    return (1, 2, 3, 7) if round_index % 2 == 0 else (1, 2, 3, 4)


def require_first_hops(sender, actual, current):
    if sender not in current:
        raise ValueError("sender is not a current validator")
    expected = set(current) - {sender}
    if set(actual) != expected:
        raise ValueError(f"first hops differ: actual={sorted(actual)}, expected={sorted(expected)}")


def write(name, obj):
    atomic_json(OUT / name, obj)


def event(kind, **fields):
    row = {"at": time.time(), "kind": kind, **fields}
    local.append_text(OUT / "events.jsonl", json.dumps(row) + "\n")
    print(json.dumps(row), flush=True)
    if kind == "failed":
        write("status.json", {**row, "healthy": False})


async def wait(predicate, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = await predicate()
        if value:
            return value
        await asyncio.sleep(0.5)
    raise TimeoutError("election transaction confirmation timed out")


async def lite_int(method, *args, address=ELECTOR):
    proc = await asyncio.create_subprocess_exec(
        str(local.INSTALLED_LITE_CLIENT),
        "-C",
        str(DATA / "configs/node-1-lite.json"),
        "-v",
        "0",
        "-c",
        f"runmethod {address.to_str(is_user_friendly=False)} {method} " + " ".join(args),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        output, _ = await asyncio.wait_for(proc.communicate(), 20)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    text = output.decode(errors="replace")
    match = re.search(r"result:\s*\[\s*(-?(?:0x[0-9a-fA-F]+|\d+))", text)
    if proc.returncode or not match:
        raise ValueError(f"Elector {method} did not answer: {text[-1000:]}")
    return int(match[1], 0)


def trace_once(offsets):
    import os

    captured = 0
    with os.fdopen(
        local.open_private(OUT / "relay-trace.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND), "a"
    ) as out:
        for node in (1, 2, 3, 4, 7):
            for path in (DATA / f"testnet/node{node}").glob("log*"):
                try:
                    f = path.open("rb")
                except FileNotFoundError:
                    # Rotation can unlink a name after directory enumeration.
                    continue
                with f:
                    stat = os.fstat(f.fileno())
                    inode = (node, stat.st_ino)
                    offset = offsets.get(inode, 0)
                    f.seek(offset if offset <= stat.st_size else 0)
                    while True:
                        position = f.tell()
                        raw = f.readline()
                        if not raw or not raw.endswith(b"\n"):
                            f.seek(position)
                            break
                        if b"twostep " in raw or b"two-step relays:" in raw:
                            out.write(
                                json.dumps(
                                    {"node": node, "line": raw.decode(errors="replace").strip()}
                                )
                                + "\n"
                            )
                            captured += 1
                    offsets[inode] = f.tell()
    write("trace-status.json", {"checked_at": time.time(), "rows_captured": captured})


async def trace_loop():
    offsets = {}
    while True:
        await asyncio.to_thread(trace_once, offsets)
        await asyncio.sleep(1)


async def snapshot(previous):
    infos = await asyncio.gather(
        *[asyncio.to_thread(local.rpc, 8010 + i, "getMasterchainInfo") for i in range(1, 8)]
    )
    height = min(r["last"]["seqno"] for r in infos)
    response = await asyncio.to_thread(local.rpc, 8011, "getConfigParam", param=34, seqno=height)
    cell = Cell.one_from_boc(base64.b64decode(response["config"]["bytes"]))
    decoded = decode_validator_set(cell)
    if decoded["utime_since"] != previous:
        replies = await asyncio.gather(
            *[
                asyncio.to_thread(local.rpc, 8010 + i, "getConfigParam", param=34, seqno=height)
                for i in range(1, 8)
            ]
        )
        if any(r["config"]["bytes"] != response["config"]["bytes"] for r in replies):
            raise ValueError("nodes disagree on elected Config34 bytes")
        write(
            f"activation-{decoded['utime_since']}.json",
            {
                "observed_at": time.time(),
                "height": height,
                "config34": decoded,
                "rpc_responses": replies,
            },
        )
        event(
            "elected_set_observed",
            since=decoded["utime_since"],
            until=decoded["utime_until"],
            # The tos decoder names the validator id field controller_id_hex.
            validators=[v["controller_id_hex"] for v in decoded["validators"]],
        )
    return decoded["utime_since"]


async def verify_local_network(client, network, plan):
    if (
        network.get("scope") != "local-development"
        or network.get("mode") != "pq"
        or network.get("global_id") != 3
        or network.get("election_period_seconds") != 600
        or plan.get("scope") != "local-development-only"
        or plan.get("rosters") != [[1, 2, 3, 7], [1, 2, 3, 4]]
    ):
        raise ValueError("local elections require the explicit disposable --rotate profile")
    info = await client.get_masterchain_info()
    if info.init is None or info.init.root_hash.hex() != network["zerostate_root"]:
        raise ValueError("connected chain is not the provisioned local zero-state")
    config15 = (await client.get_config_param(15)).begin_parse()
    if (
        [config15.load_uint(32) for _ in range(4)] != [600, 300, 60, 180]
        or config15.remaining_bits
        or config15.remaining_refs
    ):
        raise ValueError("connected election schedule differs from the local profile")


def wallet_init(candidate):
    """The candidate's wallet address and StateInit, refused unless they agree."""
    address = Address(candidate["wallet"])
    init = StateInit.deserialize(
        Cell.one_from_boc(
            base64.b64decode(candidate["state_init_b64"], validate=True)
        ).begin_parse()
    )
    if address.wc != -1 or init.serialize().hash != address.hash_part:
        raise ValueError(f"candidate {candidate['node']} wallet is not its masterchain StateInit")
    return address, init


def candidate_wallet(client, candidate, index):
    """The candidate's signing wallet, from its disposable key in OUT/keys."""
    with os.fdopen(local.open_private(OUT / f"keys/wallet-{index}.pk", os.O_RDONLY), "rb") as f:
        seed = f.read()
    if len(seed) != 32:
        raise ValueError(f"candidate {index} wallet key is not a 32-byte seed")
    blueprint = WalletV1Blueprint(workchain=-1, private_key=nacl.signing.SigningKey(seed))
    address, init = wallet_init(candidate)
    if blueprint.address != address or blueprint.state_init.serialize().hash != address.hash_part:
        raise ValueError(f"candidate {index} wallet key does not derive its recorded wallet")
    return WalletV1(client, address, blueprint.private_key)


async def ensure_wallet(client, faucet, candidate, index):
    """Deploy the candidate's wallet from the faucet once; refuse foreign code."""
    address, init = wallet_init(candidate)
    account = await client.raw_get_account_state(address)
    if not account.code:
        require_success(
            await faucet.transfer(f"deploy-wallet-{index}", address, DEPLOY_VALUE, init=init)
        )

        async def deployed():
            raw_account = await client.raw_get_account_state(address)
            return raw_account if raw_account.code else None

        account = await wait(deployed)
    if Cell.one_from_boc(account.code).hash != init.code.hash:
        raise ValueError(f"candidate {index} wallet runs code other than its StateInit's")
    return account


async def reprobe(degraded, candidates, faucet, client, interval=60):
    """Clear a member that was only not ready once its wallet checks out.

    A transient fault (an unresolved read, a wallet not yet visible) must not
    keep the driver unhealthy until that member's next roster turn. A recorded
    stake refusal stays degraded: it is the outcome of that election.
    """
    for i, entry in list(degraded.items()):
        if entry.get("kind") == "refused" or time.time() - entry["at"] < interval:
            continue
        try:
            await ensure_wallet(client, faucet, candidates[i], i)
        except Exception as exc:
            entry.update(at=time.time(), error=f"{type(exc).__name__}: {exc}")
            continue
        degraded.pop(i, None)
        event("candidate_recovered", node=i)


async def run_round(submit, selected, election, degraded):
    """Submit one roster; one member's fault never stops the others.

    Returns the accepted members and whether every member reached a recorded
    outcome. An exception (unresolved or not ready) leaves the persisted intent
    to be retried on the next pass, never paid twice; a recorded refusal is
    final for this election. Both mark the member degraded until it is accepted.
    """
    accepted, settled = [], True
    for i in selected:
        try:
            result = await submit(i)
        except Exception as exc:
            settled = False
            degraded[i] = dict(at=time.time(), kind="failed", error=f"{type(exc).__name__}: {exc}")
            event("candidate_failed", election=election, node=i, error=degraded[i]["error"])
            continue
        if result["kind"] == "accepted":
            degraded.pop(i, None)
            accepted.append(i)
            event("stake_accepted", election=election, node=i, reply=result["reply"])
        elif result.get("reply") == [0xEE6F454C, 0]:
            event("election_closed_skipped", election=election, node=i, result=result)
            break
        else:
            # The persisted refusal cannot be paid again after a restart.
            degraded[i] = dict(at=time.time(), kind="refused", error=f"refused: {result}")
            event("stake_refused", election=election, node=i, result=result)
    return accepted, settled


async def reconcile_candidate(client, intent):
    """Resolve one persisted stake without inventing a second business request."""

    async def observed():
        return election_result(
            await history_since(client, Address(intent["wallet"]), intent["wallet_baseline"]),
            wallet=Address(intent["wallet"]),
            query=intent["query"],
            body_hash=Cell.one_from_boc(base64.b64decode(intent["body"])).hash.hex(),
        )

    result = await wait(observed, 60)
    intent.update(state="done", result=result)
    write(f"candidate-intent-{intent['node']}.json", intent)
    return result


def stake_query(election, index):
    """A query id unique to one candidate's stake in one election."""
    return (election << 8) | index


async def submit_candidate(client, faucet, sender, console, candidate, election, index, network):
    """Stake `candidate` in `election` from its own wallet, at most once.

    `faucet` funds the wallet; `sender` is the candidate wallet's own journaled
    sender. The intent is durable before any value moves.
    """
    name = f"candidate-intent-{index}.json"
    intent = read_json(OUT / name) if (OUT / name).exists() else None
    if intent:
        if (
            intent["network"] != network["zerostate_root"]
            or intent["node"] != index
            or intent["wallet"] != candidate["wallet"]
        ):
            raise ValueError("saved election intent belongs to a different chain/candidate")
        if intent["election"] != election:
            old_label = f"stake-{intent['election']}-{index}"
            if intent["state"] != "done" and sender.record(old_label):
                # A prior round may have changed while this process was down.
                # Finish observing its sent stake before staking again.
                await reconcile_candidate(client, intent)
            write(f"intent-history-{intent['election']}-{index}.json", intent)
            intent = None  # An unsent expired intent is superseded, never broadcast.
        elif intent["state"] == "done":
            return intent["result"]
    if intent is None:
        await ensure_wallet(client, faucet, candidate, index)
        wallet = Address(candidate["wallet"])
        query = stake_query(election, index)
        request = tos_api.Engine_validator_createPqStakeAuthorizationRequest(
            election_date=election,
            max_factor=1 << 16,
            adnl_addr=bytes.fromhex(candidate["adnl_id"]),
            stake_owner=wallet.hash_part,
        )
        response, _, authorization = await console.request_with_raw(request)
        auth = request.parse_result(response)
        if (
            auth.validator_id != wallet.hash_part
            or auth.key_id.hex() != candidate["key_id"]
            or auth.public_key.hex() != candidate["public_key"]
            or auth.algorithm_id != 1
        ):
            raise ValueError("node stake authorization differs from candidate")
        local.write_bytes(OUT / f"authorization-{election}-{index}.json", authorization, 0o600)
        order = await asyncio.to_thread(
            build_production_pool_stake_order,
            local.require_installed_executable(local.INSTALLED_STAKE_ORDER_BUILDER),
            query_id=query,
            stake_amount=STAKE,
            stake_at=election,
            max_factor=1 << 16,
            adnl_addr=bytes.fromhex(candidate["adnl_id"]),
            algorithm_id=1,
            public_key=auth.public_key,
            signature=auth.signature,
        )
        # A wallet that stakes directly sends the elector the order's body
        # without the amount: the stake is the message value.
        body = elector_body_from_pool_order(order)
        account = await client.raw_get_account_state(wallet)
        intent = dict(
            network=network["zerostate_root"],
            election=election,
            node=index,
            wallet=candidate["wallet"],
            query=query,
            body=base64.b64encode(body.to_boc()).decode(),
            wallet_baseline=cursor(account.last_transaction_id),
            capital=max(0, STAKE + STAKE_FEE + WALLET_RESERVE - int(account.balance)),
            state="prepared",
        )
        write(name, intent)  # Before capital or stake is broadcast.
    if intent["capital"]:
        require_success(
            await faucet.transfer(
                f"wallet-capital-{election}-{index}", Address(intent["wallet"]), intent["capital"]
            )
        )
    body = Cell.one_from_boc(base64.b64decode(intent["body"], validate=True))
    receipt = await sender.transfer(
        f"stake-{election}-{index}", ELECTOR, STAKE + STAKE_FEE, body, bounce=True
    )
    if not receipt["ok"]:
        # The elector's own transaction failed; the bounce returns the value.
        result = {k: receipt[k] for k in ("exit_code", "action_code")}
        result["kind"] = "elector_failed"
        intent.update(state="done", result=result)
        write(name, intent)
        return result
    return await reconcile_candidate(client, intent)


async def recover_candidate(client, sender, candidate, index):
    """Ask the elector for this wallet's returned stake once there is one.

    Settles any uncertain earlier send first, so a request that already ran is
    never repeated: after it the elector reports nothing left to return.
    """
    await sender.recover()
    wallet = Address(candidate["wallet"])
    returned = await lite_int(
        "compute_returned_stake", str(int.from_bytes(wallet.hash_part, "big"))
    )
    account = await client.raw_get_account_state(wallet)
    write(
        f"wallet-{index}.json",
        dict(
            node=index,
            wallet=candidate["wallet"],
            deployed=bool(account.code),
            balance=int(account.balance),
            returned_stake=returned,
            checked_at=time.time(),
        ),
    )
    if returned <= 0:
        return None
    baseline = cursor(account.last_transaction_id)
    query = account.last_transaction_id.lt
    if not 0 < query < 1 << 64:
        raise ValueError("candidate wallet has no transaction to key a recovery on")
    body = Builder().store_uint(RECOVER_STAKE_OP, 32).store_uint(query, 64).end_cell()
    receipt = await sender.transfer(
        f"recover-{index}-{query}", ELECTOR, RECOVER_FEE, body, bounce=True
    )
    if not receipt["ok"]:
        result = {k: receipt[k] for k in ("exit_code", "action_code")}
        result["kind"] = "elector_failed"
    else:

        async def observed():
            return recovery_result(
                await history_since(client, wallet, baseline),
                wallet=wallet,
                query=query,
                body_hash=body.hash.hex(),
            )

        result = await wait(observed, 60)
    event("stake_recovery", node=index, expected_nano=returned, result=result)
    return result


async def main():
    local.require_installed_executable(local.INSTALLED_LITE_CLIENT)
    with faucet_lock(DATA):
        await run_driver()


async def run_driver():
    # Runs from a snapshot with no build tree: the lite-client and the stake
    # builder are the installed ones, checked before anything else is touched.
    local.require_installed_executable(local.INSTALLED_LITE_CLIENT)
    local.require_installed_executable(local.INSTALLED_STAKE_ORDER_BUILDER)
    # Runs as root: refuse an output directory another user could redirect.
    local.secure_output_dir(OUT)
    plan = json.loads((OUT / "plan.json").read_text())
    if plan["elected_for"] != 600 or plan["rosters"] != [list(roster(0)), list(roster(1))]:
        raise ValueError("rotation plan differs")
    cdll = ToslibCDLL(REPO / "build/toslib/libtoslibjson.so")
    cdll.client_set_verbosity_level(0)
    config = local.lite_config(DATA / "configs/node-1-lite.json")
    network = json.loads((DATA / "network.json").read_text())
    candidates = {i: json.loads((OUT / f"candidate-{i}.json").read_text()) for i in CANDIDATES}
    tracer = asyncio.create_task(trace_loop())
    try:
        async with ToslibClient(config, cdll) as client:
            client = local.PatientClient(client)
            # The Genesis wallet is the faucet; this service owns it exclusively.
            wallet = WalletV1(
                client,
                Address(network["genesis_wallet_address"]),
                nacl.signing.SigningKey((DATA / "testnet/state/main-wallet.pk").read_bytes()),
            )
            await verify_local_network(client, network, plan)
            faucet = Faucet(client, wallet, OUT / "faucet-journal", network["zerostate_root"])
            await faucet.recover()
            config15 = await client.get_config_param(15)
            fields = config15.begin_parse()
            values = [fields.load_uint(32) for _ in range(4)]
            if values != [600, 300, 60, 180]:
                raise ValueError(f"live election periods differ: {values}")
            write(
                "config15.json",
                {"values": values, "boc_b64": base64.b64encode(config15.to_boc()).decode()},
            )
            degraded = {}
            senders = {
                i: Faucet(
                    client,
                    candidate_wallet(client, c, i),
                    OUT / f"wallet-journal-{i}",
                    network["zerostate_root"],
                )
                for i, c in candidates.items()
            }
            for i, c in candidates.items():
                # One wallet's fault must not stop the others from electing:
                # elections are what let the chain collect garbage.
                try:
                    await ensure_wallet(client, faucet, c, i)
                    await senders[i].recover()
                except Exception as exc:
                    degraded[i] = dict(
                        at=time.time(), kind="not_ready", error=f"{type(exc).__name__}: {exc}"
                    )
                    event("candidate_not_ready", node=i, error=degraded[i]["error"])
                    continue
                event("candidate_ready", node=i, wallet=c["wallet"])
            with ToslibEventLoop(cdll) as loop:
                consoles = {}
                try:
                    for i in candidates:
                        private = json.loads((OUT / f"console-{i}.private.json").read_text())
                        consoles[i] = EngineConsoleClient(
                            cdll, loop, tos_api.EngineConsoleClient_config.from_dict(private)
                        )
                    submitted = (
                        json.loads((OUT / "submitted.json").read_text())
                        if (OUT / "submitted.json").exists()
                        else {}
                    )
                    previous = None
                    recovery_checked = {}
                    while True:
                        if tracer.done():
                            await tracer
                            raise RuntimeError("relay trace task stopped")
                        previous = await snapshot(previous)
                        election = await lite_int("active_election_id")
                        if election and str(election) not in submitted:
                            round_index = len(submitted)
                            selected = roster(round_index)
                            event("election_submitting", election=election, roster=selected)

                            async def submit(i, election=election):
                                write(
                                    "status.json",
                                    dict(
                                        at=time.time(),
                                        kind="submitting",
                                        healthy=True,
                                        election=election,
                                        node=i,
                                        activation_since=previous,
                                    ),
                                )
                                return await submit_candidate(
                                    client,
                                    faucet,
                                    senders[i],
                                    consoles[i],
                                    candidates[i],
                                    election,
                                    i,
                                    network,
                                )

                            accepted_nodes, settled = await run_round(
                                submit, selected, election, degraded
                            )
                            if settled:
                                submitted[str(election)] = list(accepted_nodes)
                                write("submitted.json", submitted)
                        for i, c in candidates.items():
                            if time.time() - recovery_checked.get(i, 0) < RECOVERY_INTERVAL:
                                continue
                            recovery_checked[i] = time.time()
                            try:
                                await recover_candidate(client, senders[i], c, i)
                            except Exception as exc:
                                event(
                                    "stake_recovery_failed",
                                    node=i,
                                    error=f"{type(exc).__name__}: {exc}",
                                )
                        await reprobe(degraded, candidates, faucet, client)
                        write(
                            "status.json",
                            dict(
                                at=time.time(),
                                kind="running",
                                healthy=not degraded,
                                degraded={str(k): v for k, v in degraded.items()},
                                election=election,
                                activation_since=previous,
                            ),
                        )
                        await asyncio.sleep(5)
                finally:
                    for console in consoles.values():
                        console.close()
    finally:
        tracer.cancel()
        await asyncio.gather(tracer, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        event("failed", error=f"{type(exc).__name__}: {exc}")
        raise
