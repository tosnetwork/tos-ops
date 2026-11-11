#!/usr/bin/env python3
"""T1 fund recovery: send each load wallet's whole balance back to the bench wallet, and nowhere else.

  t1-sweep.py --key-file KEY --out NEW_DIR [--go]

Without --go it is a dry run: every check, the plan and its fee bounds, and nothing signed. With --go it sweeps the
load wallets one at a time and stops at the first one that does not settle exactly.

The load wallets are the ones the T4 ramp derived from the bench key (bench/t4/ramp.py load_seed / load_wallet at
the pinned tos revision), and nothing here signs with any other key. Their seeds exist only in memory and on the
signer's stdin, as in the ramp. Each sweep is one external from one load wallet with one send action of mode 130
(128 carry the remaining balance + 2 ignore errors; the wallet requires +2 on every send and refuses 128 alone,
wallet-v5-action-list.fc:60-73).

Safety (codex plan review, AGREE-WITH-CHANGES):
1. The ramp's lock on the bench wallet (shard.journal.WalletState) is taken first and held to the end, and this
   run's journal is registered in the same registry before anything is signed: a ramp or a second sweep cannot
   start in between, and a crash leaves an attempt the next run (or the ramp) reconciles. The registry's
   reconcile must come back clean before the first signature.
2. A sweep counts as settled only by its sender transaction, found by the external's hash in the sender's complete
   history (journal.find_attempt via confirm); a moved nonce or a passed deadline proves nothing. An ambiguous
   send is never resent.
3. The recipient side is proved by transaction, on every RPC (the four validators' tunnels): the destination's
   transaction importing exactly the emitted message, executed, not bounced, crediting its value. The accounting
   equation is checked: balance before = value sent + the sender transaction's total fees + forwarding (at most
   FWD_TOLERANCE), and the wallet's balance after is 0 on every RPC. An RPC behind the one that confirmed the
   sender is given PROOF_WAIT seconds to show both sides before the sweep counts as not exact.
4. The network is pinned: every RPC reports the epoch-6 zerostate and global id 2, the RPCs are the inventory's
   tunnels, the derived addresses are the ramp's, and each wallet's live code hash, authority hash, epoch and
   retirement state are the derived wallet's. The destination is the active bench wallet derived from the key;
   no other destination is accepted.
5. Mode 130 is tested by real execution of the pinned wallet code (tests/test_t1_sweep_emulator.py).

Exit status: 0 done (or dry run passed), 1 stopped on a sweep that did not settle exactly, 2 refused.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

HERE = Path(__file__).resolve().parent
TOS_CHECKOUT = Path("/tos/worktrees/tos/t1-4fb9ee703")
TOS_REV = "4fb9ee70330e6247f2e0bc766a9ac5638b42ce58"
SIGNER = Path("/datax/t1/bin/bench-pq-signer")
SIGNER_SHA256 = "8b5fc20e15e04a25fc7720909a1eb7aa98be3db628da33688973f7e4ed553fb7"
AUTH_TAG = "99d8ae3469661895b820b4c41b6ad21acc448370e814c68d52ee3a12ae2c407a"
GLOBAL_ID = 2
WALLETS = 8
HOSTS = ("node-1", "node-2", "node-3", "node-4")
SEND_ALL = 130  # 128 carry the remaining balance + 2 ignore errors
LIFETIME = 60  # seconds a sweep request is valid
MIN_LEFT_NANO = 50_000_000  # a wallet holding no more than its fee bound + 0.05 TOS is not worth a sweep
FWD_TOLERANCE_NANO = 10_000_000  # balance before - value - total fees: the forwarding fee, at most 0.01 TOS
CONFIRM_TIMEOUT = 300.0
POLL = 2.0
PROOF_WAIT = 300.0  # seconds every RPC has to show a confirmed sweep on both sides (a lagging node is not a failure)


class Refuse(Exception):
    pass


class Stop(Exception):
    """A sweep did not settle exactly: nothing further is signed."""


def sibling(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolve their module by name
    spec.loader.exec_module(mod)
    return mod


def bench_modules(tos: Path):
    """The pinned tos bench modules, imported exactly as the ramp imports them."""
    for p in (str(tos / "bench"), str(tos / "test/tostester/src")):
        if p not in sys.path:
            sys.path.insert(0, p)
    import importlib
    return argparse.Namespace(
        contracts=importlib.import_module("pqbench.contracts"),
        workload=importlib.import_module("pqbench.workload"),
        remote=importlib.import_module("shard.remote"),
        rpc=importlib.import_module("shard.rpc"),
        jr=importlib.import_module("shard.journal"),
        t2check=importlib.import_module("shard.t2check"),
        ramp=importlib.import_module("t4.ramp"),
        core=importlib.import_module("pytosiq_core"),
    )


# ---------------------------------------------------------------- pure checks


def parse_qsp(data_boc_b64: str, Cell) -> dict[str, Any]:
    """A self-pay Quantum wallet's data cell (wallet-quantum-self-pay.fc qsp_store)."""
    cell = Cell.one_from_boc(base64.b64decode(data_boc_b64))
    s = cell.begin_parse()
    out = {"version": s.load_uint(8), "seqno": s.load_uint(32), "wallet_id": s.load_uint(32),
           "retired": s.load_uint(16), "epoch": s.load_uint(64), "primary_nonce": s.load_uint(64),
           "rescue_nonce": s.load_uint(64), "authority": s.load_ref().hash.hex()}
    return out


def check_wallet_state(ans: dict, wallet, code_hash: str, Cell) -> dict[str, Any]:
    """The live account is the derived wallet, active and unretired, with its authority; returns its state."""
    if ans.get("state") != "active":
        raise Refuse(f"wallet is {ans.get('state')!r}, not active")
    live_code = Cell.one_from_boc(base64.b64decode(ans["code"])).hash.hex()
    if live_code != code_hash:
        raise Refuse(f"wallet code hash {live_code} is not the pinned self-pay Quantum code {code_hash}")
    q = parse_qsp(ans["data"], Cell)
    if q["version"] != 1 or q["retired"] != 0 or q["epoch"] != 0:
        raise Refuse(f"wallet state is not version 1, unretired, epoch 0: {q}")
    if q["authority"] != wallet.authority.hash.hex():
        raise Refuse("wallet authority is not the derived wallet's")
    if q["wallet_id"] != wallet.wallet_id:
        raise Refuse(f"wallet id {q['wallet_id']} is not the derived {wallet.wallet_id}")
    balance = int(ans["balance"])
    if balance < 0:
        raise Refuse("negative balance")
    return {"balance": balance, "nonce": q["primary_nonce"]}


def settle_sweep(sender_tx, sender: str, dest: str, balance_before: int, recipient: list[list[Any]],
                 after: list[int]) -> dict[str, Any]:
    """Why a settled sender transaction is or is not an exact sweep (problems empty when it is).

    ``sender_tx`` is the sender's transaction (t2check.Tx), ``recipient`` the destination's transactions
    (journal.AccountTx: the transaction and its utime) read on each RPC since the sweep was signed, ``after`` the
    sender's balance on each RPC after the sweep."""
    problems: list[str] = []
    out = [m for m in sender_tx.out_msgs if m.kind == "internal" and m.source == sender]
    if len(out) != 1 or out[0].destination != dest:
        problems.append(f"expected one internal message to {dest}, found {[(m.destination, m.value) for m in out]}")
        return {"problems": problems}
    msg = out[0]
    if msg.bounced or msg.value is None or msg.value <= 0:
        problems.append(f"the emitted message is bounced or carries no value: {msg}")
    fee = sender_tx.fee
    if fee is None:
        problems.append("the sender transaction reports no total fees")
    else:
        residual = balance_before - (msg.value or 0) - fee
        if not 0 <= residual <= FWD_TOLERANCE_NANO:
            problems.append(f"balance {balance_before} - value {msg.value} - fees {fee} = {residual}, "
                            f"not a forwarding fee in [0, {FWD_TOLERANCE_NANO}]")
    if any(b != 0 for b in after):
        problems.append(f"the wallet still holds {after} after the sweep")
    receipts = []
    for i, txs in enumerate(recipient):
        found = [a for a in txs if a.tx.in_msg is not None and a.tx.in_msg.kind == "internal"
                 and a.tx.in_msg.hash == msg.hash]
        if len(found) != 1:
            problems.append(f"rpc {i}: {len(found)} destination transactions import the swept message")
            continue
        t = found[0].tx
        if t.aborted or t.phase_failure is not None or t.in_msg.bounced or t.in_msg.value != msg.value \
                or t.account != dest:
            problems.append(f"rpc {i}: the destination transaction did not credit the message as sent: "
                            f"aborted={t.aborted} phase={t.phase_failure} value={t.in_msg.value}")
            continue
        receipts.append({"tx": t.hash, "lt": t.lt, "utime": found[0].utime, "block": list(t.block)})
    return {"problems": problems, "value": msg.value, "message": msg.hash, "fee": fee, "receipts": receipts}


# ---------------------------------------------------------------- the chain


class Chain(Protocol):
    async def network(self) -> list[dict[str, Any]]: ...
    async def account(self, address: str) -> list[dict[str, Any]]: ...
    async def now(self) -> int: ...
    async def fee_config(self) -> Any: ...
    async def send(self, external) -> None: ...
    async def confirm(self, record: dict) -> Any: ...
    async def history(self, address: str, since: int) -> list[list[Any]]: ...
    async def pause(self, seconds: float) -> None: ...
    def clock(self) -> float: ...


class LiveChain:
    """Reads on every RPC (they must agree), sends on the first; the pinned bench helpers do the rest."""

    def __init__(self, m, urls: list[str]):
        self.m = m
        self.rpcs = [m.rpc.PacedRpc(u, 0.25) for u in urls]
        self.remote = m.remote.Remote(self.rpcs, POLL)

    async def network(self):
        out = []
        for r in self.rpcs:
            info = await r.call("getMasterchainInfo")
            last = info["last"]
            hdr = await r.call("getBlockHeader", {"workchain": -1, "shard": last["shard"], "seqno": last["seqno"]})
            out.append({"init": info["init"], "global_id": int(hdr["global_id"])})
        return out

    async def account(self, address):
        return [await r.call("getAddressInformation", {"address": address}) for r in self.rpcs]

    async def now(self):
        return await self.remote.now()

    async def pause(self, seconds):
        await asyncio.sleep(seconds)

    def clock(self):
        return time.monotonic()

    async def mc_seqno(self):
        return int((await self.rpcs[0].call("getMasterchainInfo"))["last"]["seqno"])

    async def fee_config(self):
        return await self.remote.fee_config(0)

    async def send(self, external):
        await self.remote.send(external)

    async def confirm(self, record):
        return await self.m.jr.confirm(self.rpcs[0], record, self.remote.now, CONFIRM_TIMEOUT, POLL)

    async def history(self, address, since):
        out = []
        for r in self.rpcs:
            txs, complete = await self.m.jr.account_transactions(r, address, since)
            if not complete:
                raise Stop(f"the destination's history since {since} is not complete on {r}")
            out.append(txs)
        return out


def agreed(answers: list[dict], keys=("state", "balance", "code", "data")) -> dict:
    first = {k: answers[0].get(k) for k in keys}
    for a in answers[1:]:
        if {k: a.get(k) for k in keys} != first:
            seen = [{k: x.get(k) for k in ("state", "balance")} for x in answers]
            raise Refuse(f"the RPCs disagree on an account: {seen}")
    return answers[0]


# ---------------------------------------------------------------- the run


@dataclass
class Sweep:
    index: int
    address: str
    balance: int
    nonce: int
    fee_bound: int
    skip: str | None = None
    result: dict[str, Any] = field(default_factory=dict)


async def plan(m, chain: Chain, wallets, code_hash: str, dest: str, config) -> list[Sweep]:
    Cell = m.core.Cell
    out = []
    for i, w in enumerate(wallets):
        addr = m.remote.raw(w.address)
        st = check_wallet_state(agreed(await chain.account(addr)), w, code_hash, Cell)
        probe = w.external(w.request(st["nonce"], [m.workload.transfer_message(w.address, m.core.Address(dest), 0)],
                                     1, mode=SEND_ALL), bytes(m.workload.SIGNATURE_BYTES))
        bound = m.remote.external_fee_bound(config, f"sweep {i}", probe,
                                            [m.workload.transfer_message(w.address, m.core.Address(dest), 0)]).total
        s = Sweep(i, addr, st["balance"], st["nonce"], bound)
        if st["balance"] <= bound + MIN_LEFT_NANO:
            s.skip = f"balance {st['balance']} not above the fee bound {bound} + {MIN_LEFT_NANO}"
        out.append(s)
    return out


async def sweep_one(m, chain: Chain, journal, signer, w, seed, s: Sweep, dest: str, seqno: int) -> dict:
    """Sign, journal (fsynced), send once, and prove one sweep on both sides on every RPC. Raises Stop when it is
    not exact."""
    now = await chain.now()
    deadline = now + LIFETIME
    action = m.workload.transfer_message(w.address, m.core.Address(dest), 0)
    request = w.request(s.nonce, [action], deadline, mode=SEND_ALL)
    signature = signer.sign([(seed, request.hash)])[0]
    external = w.external(request, signature)
    record = m.jr.attempt_record(role="sweep", sender=s.address, wallet=s.index, seqno=seqno, nonce=s.nonce,
                                 deadline=deadline, cell=external.serialize(), actions=[(dest, 0, SEND_ALL)],
                                 fee_bound=s.fee_bound, what="t1 load-wallet sweep", signed_at=now,
                                 balance_before=s.balance)
    journal.append(record)  # fsynced before the send starts
    try:
        await chain.send(external)
        error = None
    except Exception as caught:  # classified; never resent
        error = caught
    state, reason = m.jr.send_outcome(error)
    journal.event("sent", record["id"], state=state, reason=reason)
    if state == "refused":
        raise Stop(f"wallet {s.index}: the node refused the sweep ({reason}); nothing was executed")
    verdict = await chain.confirm(record)
    sent = m.remote.settle(journal, record, verdict)
    if sent.state != "settled":
        raise Stop(f"wallet {s.index}: sweep {sent.state} ({sent.reason}); see the journal, never resent")
    proof = await prove_sweep(chain, verdict.found.tx, s.address, dest, s.balance, now)
    if proof["problems"]:
        raise Stop(f"wallet {s.index}: the sweep executed but is not exact: {proof['problems']}")
    r = proof["receipts"][0]
    journal.event("delivered", record["id"], **receipt_fields(proof))
    return {"id": record["id"], "tx": verdict.found.tx.hash, **proof}


async def prove_sweep(chain: Chain, sender_tx, sender: str, dest: str, balance: int, since: int) -> dict:
    """settle_sweep on every RPC, read again every POLL seconds until it holds or PROOF_WAIT has passed.

    The sender was confirmed on one RPC; another may not have imported that block yet and shows the old balance
    and no receipt. That is lag, not a failed sweep, so it is read again. A sweep that is really not exact stays
    so on every read, and the last proof, with its problems, is returned.

    PROOF_WAIT bounds the elapsed time on a monotonic clock, reads included: each read gets only what is left,
    so a slow RPC cannot hold the wallet lock past it."""
    deadline = chain.clock() + PROOF_WAIT
    proof: dict[str, Any] = {"problems": [f"no complete read of every RPC within {PROOF_WAIT:.0f} s"]}
    while True:
        try:
            rows = await asyncio.wait_for(chain.account(sender), remaining(chain, deadline))
            history = await asyncio.wait_for(chain.history(dest, since), remaining(chain, deadline))
        except (asyncio.TimeoutError, OutOfTime):
            return proof
        after = [int(x.get("balance", -1)) for x in rows]
        proof = settle_sweep(sender_tx, sender, dest, balance, history, after)
        if not proof["problems"]:
            return proof
        if chain.clock() + POLL >= deadline:
            return proof
        await chain.pause(POLL)


class OutOfTime(Exception):
    pass


def remaining(chain: Chain, deadline: float) -> float:
    left = deadline - chain.clock()
    if left <= 0:
        raise OutOfTime()
    return left


def receipt_fields(proof: dict) -> dict:
    """The delivered record of a proved sweep. The recipient's masterchain block is not read here: it is null,
    never a made-up number; the transaction, its utime and its shard block come from the destination's history."""
    r = proof["receipts"][0]
    return {"action": 0, "recipient_tx": r["tx"], "recipient_lt": r["lt"], "recipient_utime": r["utime"],
            "recipient_block": r["block"], "recipient_mc": None, "receipt_failure": None,
            "value": proof["value"], "message": proof["message"], "fee": proof["fee"],
            "rpcs_proved": len(proof["receipts"])}


def run_record(m, bench, wallets, dest: str, mc_start: int) -> dict:
    """A run record journal.read_journal accepts (version and an integer mc_start), so a registered sweep journal
    never blocks the registry's reconcile."""
    return {"type": "run", "version": m.jr.VERSION, "tool": "t1-sweep", "wallet": m.remote.raw(bench.address),
            "load_wallets": [m.remote.raw(w.address) for w in wallets], "to": dest, "mc_start": mc_start,
            "deadline_grace": m.jr.DEADLINE_GRACE, "time": time.time()}


def observed_tx(m, attempt: dict, observed: dict):
    """The sender transaction as journaled by settle (Verdict.as_dict), as a t2check.Tx for settle_sweep."""
    t2 = m.t2check
    outs = tuple(t2.Msg(hash=o["hash"], kind="internal", source=attempt["sender"], destination=o["destination"],
                        value=o["value"]) for o in observed.get("out_msgs") or [])
    return t2.Tx(hash=observed["tx"], account=attempt["sender"], lt=observed["lt"], block=tuple(observed["block"]),
                 in_msg=None, out_msgs=outs, action_success=True, fee=observed.get("fee"), phase_failure=None)


def sender_execution(read, aid: str, resolution: dict | None):
    """What is proved about one sweep's sender transaction: its observation (dict), None when the chain or the
    RPCs proved it never executed, or a reason (str) why neither is proved."""
    events = read.events.get(aid, [])
    obs = next((e for e in events if e["type"] == "observed"), None)
    if obs is not None:
        return obs
    sent = read.sent(aid)
    if sent is not None and sent.get("state") == "refused":
        return None
    if any(e["type"] == "expired" for e in events):
        return None
    if resolution is None or resolution.get("verdict") == "undetermined":
        return "its execution is not determined: run again once the registry reconcile resolves it"
    if resolution.get("verdict") == "not_executed":
        return None
    if resolution.get("verdict") != "executed" or not isinstance(resolution.get("tx"), str):
        return f"an unexpected registry resolution {resolution.get('verdict')!r}"
    return resolution


async def recover_receipts(m, chain: Chain, state) -> list[str]:
    """Before any new signature: every earlier sweep must have its receipt proved, unless the chain proved it was
    never executed. A journaled `observed` is terminal for the registry's reconcile, and an execution the
    reconcile found itself is recorded only in the registry's resolutions, so this step, not the reconcile,
    keeps a sweep from counting as done while its delivery is unproved. Proved receipts are journaled now;
    returns the sweeps that still cannot be proved (the run refuses while any remain)."""
    pending = []
    resolved = state.resolved()
    for path in state.journals():
        if not path.exists():
            continue
        read = m.jr.read_journal(path)
        if read.run is None or read.run.get("tool") != "t1-sweep":
            continue
        if read.errors:
            pending.append(f"{path}: {read.errors[:3]}")
            continue
        late = None
        for aid, attempt in read.attempts.items():
            events = read.events.get(aid, [])
            kinds = [e["type"] for e in events]
            if attempt.get("role") != "sweep" or "delivered" in kinds:
                continue
            obs = sender_execution(read, aid, resolved.get((str(path), aid)))
            if obs is None:
                continue  # proven never executed: refused by the RPCs, or expired as the chain showed
            if isinstance(obs, str):
                pending.append(f"{aid}: {obs}")
                continue
            # the predicate remote.settle applies: problems or a second execution are never a sweep
            if obs.get("problems") or obs.get("duplicates"):
                pending.append(f"{aid}: executed with problems {obs.get('problems')}, "
                               f"duplicates {obs.get('duplicates', 0)}")
                continue
            dest = attempt["actions"][0]["destination"]
            proof = await prove_sweep(chain, observed_tx(m, attempt, obs), attempt["sender"], dest,
                                      attempt["balance_before"], attempt["signed_at"])
            if proof["problems"]:
                pending.append(f"{aid}: {proof['problems']}")
                continue
            late = late or m.jr.Journal(path, create=False)
            late.event("delivered", aid, **receipt_fields(proof), proved_later=True)
        if late is not None:
            late.close()
    return pending


def check_pins(a, run=subprocess.run) -> None:
    head = run(["git", "-C", str(a.tos), "rev-parse", "HEAD"], capture_output=True, text=True,
               check=False).stdout.strip()
    if head != TOS_REV:
        raise Refuse(f"tos checkout is at {head or 'nothing'}, not {TOS_REV}")
    if hashlib.sha256(a.signer.read_bytes()).hexdigest() != SIGNER_SHA256:
        raise Refuse("signer sha256 is not the pinned build")
    if a.key_file.stat().st_mode & 0o077 or a.key_file.parent.stat().st_mode & 0o077:
        raise Refuse("the bench key file or its directory is readable by others")


def check_network(rows: list[dict], zero: dict) -> None:
    if len(rows) < 2:
        raise Refuse("at least two RPCs are required")
    for r in rows:
        init = r["init"]
        if (init.get("root_hash"), init.get("file_hash"), init.get("seqno")) != \
                (zero["root_hash"], zero["file_hash"], 0) or r["global_id"] != GLOBAL_ID:
            raise Refuse(f"an RPC is not on the epoch-6 network: {init} global_id {r['global_id']}")


async def run(a, m, chain: Chain, state, journal, signer, bench, wallets, seeds, code_hash: str, dest: str,
              zero: dict, log=print) -> int:
    check_network(await chain.network(), zero)
    # Every earlier sweep's receipt is proved (and journaled) before anything new is planned or signed.
    pending = await recover_receipts(m, chain, state)
    if pending:
        raise Refuse(f"earlier sweeps have no proven receipt: {pending}")
    sources = {m.remote.raw(w.address) for w in wallets}
    if dest in sources or dest == "":
        raise Refuse("the destination is one of the swept wallets")
    if dest != m.remote.raw(bench.address):
        raise Refuse(f"the destination {dest} is not the bench wallet {m.remote.raw(bench.address)}")
    if not dest.startswith("0:"):
        raise Refuse("the destination must be a workchain-0 account")
    d = agreed(await chain.account(dest), keys=("state",))
    if d.get("state") != "active":
        raise Refuse(f"the destination {dest} is {d.get('state')!r}, not active")
    config = await chain.fee_config()
    sweeps = await plan(m, chain, wallets, code_hash, dest, config)
    for s in sweeps:
        log(json.dumps({"wallet": s.index, "address": s.address, "balance": s.balance, "nonce": s.nonce,
                        "fee_bound": s.fee_bound, "skip": s.skip}))
    total = sum(s.balance for s in sweeps if s.skip is None)
    log(f"plan: {sum(1 for s in sweeps if s.skip is None)} of {len(sweeps)} wallets, {total / 1e9:.9f} TOS to {dest}")
    if not a.go:
        log("dry run: nothing signed")
        return 0
    results = []
    for seqno, s in enumerate(x for x in sweeps if x.skip is None):
        try:
            res = await sweep_one(m, chain, journal, signer, wallets[s.index], seeds[s.index], s, dest, seqno)
        except Stop as stop:
            log(f"STOP: {stop}")
            results.append({"wallet": s.index, "stop": str(stop)})
            (a.out / "RESULT.json").write_text(json.dumps({"status": "stopped", "results": results}, indent=2))
            return 1
        log(json.dumps({"wallet": s.index, **res}))
        results.append({"wallet": s.index, **res})
    (a.out / "RESULT.json").write_text(json.dumps({"status": "done", "results": results}, indent=2))
    return 0


def main(argv=None) -> int:
    # no abbreviations: a removed option must not silently resolve to a longer one (--to would become --tos)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                 allow_abbrev=False)
    ap.add_argument("--key-file", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True, help="a new directory for the journal and the result")
    ap.add_argument("--inventory", type=Path, default=Path.home() / ".config/tos-alert/hosts.json")
    ap.add_argument("--unit-dir", type=Path, default=Path.home() / ".config/systemd/user")
    ap.add_argument("--tos", type=Path, default=TOS_CHECKOUT)
    ap.add_argument("--signer", type=Path, default=SIGNER)
    ap.add_argument("--go", action="store_true", help="sign and send (default: a dry run)")
    a = ap.parse_args(argv)
    try:
        check_pins(a)
        if subprocess.run(["systemctl", "--user", "is-active", "--quiet", "t1-load"], check=False).returncode == 0:
            raise Refuse("t1-load is active: the ramp is still using these wallets")
        keys = sibling("check-validator-keys")
        urls_by_host = keys.tunnel_inventory(a.unit_dir, json.loads(a.inventory.read_text()))
        urls = [urls_by_host[h] for h in HOSTS]
        if len(set(urls)) != len(HOSTS):
            raise Refuse("the inventory does not give one distinct tunnel per validator")
        m = bench_modules(a.tos)
        with tempfile.TemporaryDirectory() as scratch:
            code = m.contracts.build(a.tos / "build", Path(scratch))["quantum"]
        key = m.remote.load_key(a.key_file)
        auth = bytes.fromhex(AUTH_TAG)
        bench = m.remote.bench_wallet(code, GLOBAL_ID, auth, key, m.remote.Signer(a.signer, key).public_key())
        signer = m.ramp.BatchSigner(a.signer, 2)
        seeds = [m.ramp.load_seed(key.seed, bench.address, i) for i in range(WALLETS)]
        pks = signer.public_keys(seeds)
        wallets = [m.ramp.load_wallet(code, GLOBAL_ID, auth, i, pk, key.rescue_public_key) for i, pk in enumerate(pks)]
        dest = m.remote.raw(bench.address)
        # The ramp's lock first, held to the end; then a clean reconcile of every registered journal.
        state = m.jr.WalletState(m.jr.default_state_dir(a.key_file), m.remote.raw(bench.address))
    except Refuse as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # the lock, the build, the signer
        print(f"refused: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    try:
        chain = LiveChain(m, urls)
        report = asyncio.run(state.reconcile(chain.rpcs[0], chain.remote.now))
        if report.get("attempts") or report.get("errors"):
            print(f"refused: earlier attempts needed reconciling: {json.dumps(report)[:2000]}", file=sys.stderr)
            return 2
        a.out.mkdir(parents=True, exist_ok=False)
        journal = m.jr.Journal(a.out / "journal.jsonl")
        journal.append(run_record(m, bench, wallets, dest, asyncio.run(chain.mc_seqno())))
        if a.go:
            state.register(a.out / "journal.jsonl")
        zero = keys.EPOCH6_ZERO_STATE
        return asyncio.run(run(a, m, chain, state, journal, signer, bench, wallets, seeds, code.hash.hex(), dest,
                               zero))
    except Refuse as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    finally:
        state.release()


if __name__ == "__main__":
    sys.exit(main())
