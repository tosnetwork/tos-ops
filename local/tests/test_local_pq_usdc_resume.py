"""local-pq-usdc.py: every value-moving send is journaled and survives an interruption.

Each test runs a step against a fake chain, interrupts it at a send (before the
broadcast, or after the broadcast and before the result is recorded), runs it
again, and checks that the value moved exactly once.
"""

import importlib.util
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
spec = importlib.util.spec_from_file_location("local_pq_usdc_resume", SCRIPTS / "local-pq-usdc.py")
usdc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(usdc)
lib = usdc.lib

NANO = usdc.NANO
BRIDGE = "-1:" + "73" * 32
MULTISIG = "-1:" + "6a" * 32


class Interrupted(Exception):
    pass


def read_addr(s):
    assert s.bits(3) == 0b100
    wc = s.bits(8)
    return f"{wc - 256 if wc >= 128 else wc}:{s.bytes(32).hex()}"


def parse_internal(cell):
    s = lib.Slice(cell)
    s.bits(4)
    s.bits(2)  # addr_none
    dest = read_addr(s)
    value = lib.read_grams(s)
    s.bits(1)
    lib.read_grams(s)
    lib.read_grams(s)
    s.bits(96)
    if s.bits(1):
        s.bits(1)
        s.take_ref()
    body = s.take_ref() if s.bits(1) else None
    return dest, value, body


class FakeTos:
    """Simple wallets (seqno, balance) and a token bridge's swap records."""

    def __init__(self):
        self.accounts = {}
        self.swaps, self.watermark = {}, 0
        self.executed = []  # (wallet, seqno, dest, value)
        self.externals = []  # (wallet, external message hash) that ran
        self.fail_send = 0  # raise before the next N broadcasts
        self.fail_wait = 0  # raise in the next N waits (after a broadcast ran)

    def fund(self, address, balance, active=True):
        self.accounts[address] = {"seqno": 0, "balance": balance, "active": active}

    def acct(self, address):
        return self.accounts.setdefault(address, {"seqno": 0, "balance": 0, "active": False})

    def account(self, address):
        a = self.acct(address)
        data = usdc.Builder().uint(a["seqno"], 32).raw(b"\0" * 32).end()
        return {
            "state": "active" if a["active"] else "uninitialized",
            "data": usdc.boc64(data),
            "balance": str(a["balance"]),
        }

    def balance(self, address):
        return self.acct(address)["balance"]

    def active(self, address):
        return self.acct(address)["active"]

    def send(self, message):
        if self.fail_send:
            self.fail_send -= 1
            raise Interrupted("before the broadcast")
        s = lib.Slice(message)
        assert s.bits(2) == 0b10 and s.bits(2) == 0
        wallet = read_addr(s)
        lib.read_grams(s)
        if s.bits(1):
            s.bits(1)
            s.take_ref()
        assert s.bits(1) == 1
        body = lib.Slice(s.take_ref())
        body.bytes(64)
        seqno, _mode = body.bits(32), body.bits(8)
        account = self.acct(wallet)
        if seqno != account["seqno"]:
            return  # a replay: the wallet refuses it
        account["seqno"] += 1
        account["active"] = True
        self.externals.append((wallet, message.hash().hex()))
        dest, value, inner = parse_internal(body.take_ref())
        account["balance"] -= value
        target = self.acct(dest)
        target["balance"] += value
        if dest != BRIDGE and dest != MULTISIG:
            target["active"] = True
        self.executed.append((wallet, seqno, dest, value))
        if dest == BRIDGE and inner is not None:
            b = lib.Slice(inner)
            if b.bits(32) == usdc.OP_PAY_SWAP:
                b.bits(64)
                b.bits(32)
                self.swaps[b.bits(64)] = 0
        if dest == MULTISIG:  # the multisig sends the swap vote: the swap is consumed and folded
            for n, st in list(self.swaps.items()):
                if st == 0:
                    del self.swaps[n]
                    self.watermark = n + 1

    def executed_external(self, address, message_hash, since):
        if (address, message_hash) in self.externals:
            return {"hash": message_hash}
        return None

    def wait(self, what, predicate, timeout=0, interval=0):
        if self.fail_wait:
            self.fail_wait -= 1
            raise Interrupted("after the broadcast")
        value = predicate()
        if not value:
            raise usdc.Refused(f"fake: {what}")
        return value

    def get(self, address, method, *args):
        if method == "get_swap":
            return [["num", str(self.swaps.get(args[0], -1))], ["num", "0"], ["num", "0"]]
        if method == "get_bridge_state":
            return [["num", "1"]] * 6 + [["num", str(self.watermark)], ["num", "0"]]
        raise AssertionError(method)


def tos_state(tmp_path):
    return usdc.State(tmp_path)


def test_a_wallet_send_interrupted_before_the_broadcast_runs_once_on_rerun(tmp_path):
    chain, state = FakeTos(), tos_state(tmp_path)
    genesis = usdc.Wallet(chain, b"\1" * 32, -1, "-1:" + "00" * 32)
    chain.fund(genesis.address, 10**6 * NANO)
    target = usdc.Wallet(chain, b"\2" * 32, 0)
    chain.fail_send = 1
    with pytest.raises(Interrupted):
        usdc.fund_wallets(
            state, chain, genesis, [("fund-a", target.address, 30 * NANO, target.init)]
        )
    assert state.intent("fund-a")["state"] == "signed" and not chain.executed
    usdc.fund_wallets(state, chain, genesis, [("fund-a", target.address, 30 * NANO, target.init)])
    assert [e[2] for e in chain.executed] == [target.address]
    assert state.intent("fund-a")["state"] == "done"


def test_a_wallet_send_interrupted_after_the_broadcast_is_not_repeated(tmp_path):
    chain, state = FakeTos(), tos_state(tmp_path)
    genesis = usdc.Wallet(chain, b"\1" * 32, -1, "-1:" + "00" * 32)
    chain.fund(genesis.address, 10**6 * NANO)
    targets = [
        (f"fund-{i}", usdc.Wallet(chain, bytes([i + 2]) * 32, 0).address, NANO, None)
        for i in range(3)
    ]
    chain.fail_wait = 1  # the first payment ran; its confirmation was never seen
    with pytest.raises(Interrupted):
        usdc.fund_wallets(state, chain, genesis, targets)
    usdc.fund_wallets(state, chain, genesis, targets)
    usdc.fund_wallets(state, chain, genesis, targets)  # a third run moves nothing
    assert sorted(e[2] for e in chain.executed) == sorted(t[1] for t in targets)
    assert chain.accounts[genesis.address]["seqno"] == 3


def test_a_new_send_waits_for_the_wallets_unfinished_one(tmp_path):
    chain, state = FakeTos(), tos_state(tmp_path)
    genesis = usdc.Wallet(chain, b"\1" * 32, -1, "-1:" + "00" * 32)
    chain.fund(genesis.address, 10**6 * NANO)
    chain.fail_send = 1
    with pytest.raises(Interrupted):
        genesis.transfer(state, "first", "0:" + "11" * 32, NANO)
    with pytest.raises(usdc.Refused, match="unfinished send"):
        genesis.transfer(state, "second", "0:" + "22" * 32, NANO)


def mint_setup(tmp_path):
    chain, state = FakeTos(), tos_state(tmp_path)
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    buyer = usdc.wallets(chain, keys)["buyer"]
    submitter = usdc.wallets(chain, keys)["submitter"]
    chain.fund(buyer.address, 30 * NANO)
    chain.fund(submitter.address, 20 * NANO)
    state.set("tvm", {"bridge": BRIDGE, "multisig": MULTISIG})
    state.set("evm", {"bridge": "0x" + "e7" * 20, "token": "0x" + "5f" * 20})
    return (
        chain,
        state,
        keys,
        buyer,
        {"bridge": BRIDGE, "multisig": MULTISIG},
        {"n": 0, "amount": 25},
    )


@pytest.mark.parametrize("interrupt", ["fail_send", "fail_wait"])
def test_an_interrupted_mint_payment_is_paid_once(tmp_path, interrupt):
    chain, state, keys, buyer, tvm, lock = mint_setup(tmp_path)
    setattr(chain, interrupt, 1)
    with pytest.raises(Interrupted):
        usdc.pay_and_vote(state, chain, keys, buyer, tvm, lock)
    usdc.pay_and_vote(state, chain, keys, buyer, tvm, lock)
    usdc.pay_and_vote(state, chain, keys, buyer, tvm, lock)
    pays = [e for e in chain.executed if e[2] == BRIDGE]
    votes = [e for e in chain.executed if e[2] == MULTISIG]
    assert len(pays) == 1 and pays[0][3] == usdc.MINT_FEE and len(votes) == 1
    assert chain.watermark == 1


def test_an_interrupted_swap_vote_is_delivered_once(tmp_path):
    chain, state, keys, buyer, tvm, lock = mint_setup(tmp_path)
    # Pay, then interrupt the vote's delivery after it ran.
    original = chain.send

    def send_then_interrupt(message):
        original(message)
        if any(e[2] == MULTISIG for e in chain.executed):
            chain.send = original
            raise Interrupted("after the vote's broadcast")

    chain.send = send_then_interrupt
    with pytest.raises(Interrupted):
        usdc.pay_and_vote(state, chain, keys, buyer, tvm, lock)
    usdc.pay_and_vote(state, chain, keys, buyer, tvm, lock)
    assert len([e for e in chain.executed if e[2] == MULTISIG]) == 1
    assert len([e for e in chain.executed if e[2] == BRIDGE]) == 1


def test_a_consumed_swap_without_a_journal_is_not_paid(tmp_path):
    chain, state, keys, buyer, tvm, lock = mint_setup(tmp_path)
    chain.watermark = 1  # consumed and folded by an earlier run
    usdc.pay_and_vote(state, chain, keys, buyer, tvm, lock)
    assert chain.executed == []


# ---------------------------------------------------------------- EVM


class FakeEvm:
    """A token and a token bridge with lock caps, behind the Evm interface."""

    def __init__(self):
        self.tools = None
        self.nonces, self.blocks = {}, [[]]
        self.tokens = {}
        self.caps, self.cap_nonce, self.locks = {}, {}, {}
        self.lock_nonce = 0
        self.crash = None  # (signature prefix, "before" | "after")

    # reads
    def chain_id(self):
        return 1

    def accounts(self):
        return ["0xd0", "0x10"]

    def code(self, address):
        return "0x60"

    def abi_encode(self, signature, *args):
        return "0x"

    def nonce(self, sender):
        return self.nonces.get(sender, 0)

    def block_number(self):
        return len(self.blocks) - 1

    def call(self, to, signature, *args):
        name = signature.split("(")[0]
        if name == "balanceOf":
            return str(self.tokens[to]["balances"].get(args[0], 0))
        if name == "decimals":
            return "6"
        if name == "feeBasisPoints":
            return "0"
        if name == "lockCaps":
            return "\n".join(str(c) for c in self.caps.get(args[0], (0, 0, 0, 0)))
        if name == "lockNonce":
            return str(self.lock_nonce)
        if name == "lastLockCapNonce":
            return str(self.cap_nonce.get(args[0], 0))
        if name == "getLockCapState":
            return f"{self.caps.get(args[0], (0, 0, 0, 0))}\n0\n0\n0"
        if name.startswith("getNew"):
            return "0x" + "ab" * 32
        if name == "checkSignature":
            return ""
        if name == "locks":
            r = self.locks[int(args[0])]
            return "\n".join([r["locker"], r["token"], str(r["amount"]), "1", "1"])
        raise AssertionError(signature)

    def lock_refusal(self, sender, token, amount):
        caps = self.caps.get(token)
        if not caps or caps[0] == 0:
            return "lock: token has no lock cap"
        if amount > caps[1]:
            return "lock: over the per-lock cap"
        if self.tokens[token]["balances"].get(sender, 0) < amount:
            return "insufficient balance"
        return None

    def simulate(self, sender, to, signature, *args):
        reason = self.lock_refusal(sender, args[0], int(args[1]))
        return reason is None, f"execution reverted: {reason}" if reason else ""

    # sends
    def broadcast(self, sender, nonce, to, signature, args, gas):
        assert nonce == self.nonce(sender), "a send at another nonce"
        if self.crash and signature.startswith(self.crash[0]) and self.crash[1] == "before":
            self.crash = None
            raise Interrupted("before the broadcast")
        status, contract = 1, None
        name = signature.split("(")[0]
        if to is None:
            contract = f"0x{len(self.tokens) + 0xA0:x}"
            self.tokens[contract] = {"balances": {sender: usdc.TOKEN_SUPPLY}}
        elif name == "transfer":
            bal = self.tokens[to]["balances"]
            bal[sender] -= int(args[1])
            bal[args[0]] = bal.get(args[0], 0) + int(args[1])
        elif name == "approve":
            pass
        elif name == "voteForLockCap":
            self.caps[args[0]] = tuple(int(x) for x in args[1:5])
            self.cap_nonce[args[0]] = int(args[5])
        elif name in ("voteForSwitchLock", "voteForNewGeneration"):
            pass
        elif name == "lock":
            if self.lock_refusal(sender, args[0], int(args[1])):
                status = 0
            else:
                self.tokens[args[0]]["balances"][sender] -= int(args[1])
                self.locks[self.lock_nonce] = {
                    "locker": sender,
                    "token": args[0],
                    "amount": int(args[1]),
                }
                self.lock_nonce += 1
        else:
            raise AssertionError(signature)
        self.nonces[sender] = nonce + 1
        tx = f"0x{len(sum(self.blocks, [])) + 1:064x}"
        self.blocks.append(
            [
                {
                    "hash": tx,
                    "from": sender,
                    "nonce": nonce,
                    "status": status,
                    "contract": contract,
                    "signature": signature,
                    "to": to,
                    "input": signature if to is None else self.calldata(signature, *args),
                    "value": 0,
                }
            ]
        )
        if self.crash and signature.startswith(self.crash[0]) and self.crash[1] == "after":
            self.crash = None
            raise Interrupted("after the broadcast")
        return tx

    def find(self, sender, nonce, from_block):
        for block in self.blocks[from_block:]:
            for tx in block:
                if tx["from"] == sender and tx["nonce"] == nonce:
                    return tx["hash"]
        return None

    def calldata(self, signature, *args):
        return "0x" + f"{signature}|{'|'.join(args)}".encode().hex()

    def transaction(self, tx):
        for block in self.blocks:
            for t in block:
                if t["hash"] == tx:
                    return {k: t[k] for k in ("from", "nonce", "to", "input", "value")}
        raise AssertionError(tx)

    def receipt(self, tx):
        for number, block in enumerate(self.blocks):
            for t in block:
                if t["hash"] == tx:
                    return {
                        "tx": tx,
                        "status": t["status"],
                        "block": number,
                        "contract": t["contract"],
                    }
        raise AssertionError(tx)

    def sent(self, prefix):
        return [t for b in self.blocks for t in b if t["signature"].startswith(prefix)]


@pytest.fixture
def evm_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(usdc, "oracle_signatures", lambda keys, digest: "[(0xa1,0x01),(0xb2,0x02)]")
    monkeypatch.setattr(
        usdc, "oracle_keys", lambda keys: [("0xa1", ""), ("0xb2", ""), ("0xc3", "")]
    )
    monkeypatch.setattr(
        usdc, "evm_artifact", lambda tools, name: {"bytecode": "0x60" + name.encode().hex()}
    )
    evm, state = FakeEvm(), usdc.State(tmp_path)
    state.set("wallets", {"buyer": "0:" + "14" * 32})
    return evm, state


@pytest.mark.parametrize("when", ["before", "after"])
def test_an_interrupted_evm_send_is_sent_once(evm_setup, when):
    evm, state = evm_setup
    evm.crash = ("transfer", when)
    token = usdc.deploy_token(evm, state, "deploy", "0xd0")
    with pytest.raises(Interrupted):
        usdc.evm_send_once(
            evm, state, "pay", "0xd0", token, "transfer(address,uint256)", "0x10", "5"
        )
    record = usdc.evm_send_once(
        evm, state, "pay", "0xd0", token, "transfer(address,uint256)", "0x10", "5"
    )
    usdc.evm_send_once(evm, state, "pay", "0xd0", token, "transfer(address,uint256)", "0x10", "5")
    assert record["status"] == 1 and len(evm.sent("transfer")) == 1
    assert evm.tokens[token]["balances"]["0x10"] == 5


def test_the_journaled_arguments_are_resent_not_rebuilt(evm_setup):
    evm, state = evm_setup
    token = usdc.deploy_token(evm, state, "deploy", "0xd0")
    evm.crash = ("transfer", "before")
    made = []

    def build():
        made.append(1)
        return ["0x10", str(len(made))]

    with pytest.raises(Interrupted):
        usdc.evm_send_once(
            evm, state, "t", "0xd0", token, "transfer(address,uint256)", build_args=build
        )
    usdc.evm_send_once(
        evm, state, "t", "0xd0", token, "transfer(address,uint256)", build_args=build
    )
    assert made == [1] and evm.tokens[token]["balances"]["0x10"] == 1


def lock_state(evm, state):
    deployer, locker = evm.accounts()
    token = usdc.deploy_token(evm, state, "evm-deploy-token", deployer)
    state.set("evm", {"token": token, "bridge": "0xb0", "locker": locker, "deployer": deployer})
    return token, locker


@pytest.mark.parametrize(
    "crash",
    [
        ("lock", "after"),  # the lock ran; its receipt was never read
        ("lock", "before"),
        ("voteForLockCap", "after"),
        ("transfer", "after"),  # the locker's top-up
        ("approve", "before"),
    ],
)
def test_an_interrupted_lock_step_locks_once(evm_setup, crash):
    evm, state = evm_setup
    token, locker = lock_state(evm, state)
    evm.crash = crash
    with pytest.raises(Interrupted):
        usdc.step_lock(None, state, None, evm, Path("/nonexistent"))
    usdc.step_lock(None, state, None, evm, Path("/nonexistent"))
    successful = [t for t in evm.sent("lock") if t["status"] == 1]
    assert len(successful) == 1 and evm.lock_nonce == 1
    assert len(evm.sent("voteForLockCap")) == 1
    assert state["lock"]["n"] == 0 and state["lock"]["amount"] == usdc.LOCK_AMOUNT
    # Two refused locks were mined: the test token before its caps, and the probe.
    assert len([t for t in evm.sent("lock") if t["status"] == 0]) == 2
    usdc.step_lock(None, state, None, evm, Path("/nonexistent"))
    assert evm.lock_nonce == 1


def test_an_evm_nonce_used_by_an_unknown_transaction_is_refused(evm_setup):
    evm, state = evm_setup
    token = usdc.deploy_token(evm, state, "deploy", "0xd0")
    evm.crash = ("transfer", "before")
    with pytest.raises(Interrupted):
        usdc.evm_send_once(evm, state, "t", "0xd0", token, "transfer(address,uint256)", "0x10", "5")
    evm.nonces["0xd0"] += 1  # someone else used the nonce, and the chain has no such transaction
    with pytest.raises(usdc.Refused, match="its transaction is not found"):
        usdc.evm_send_once(evm, state, "t", "0xd0", token, "transfer(address,uint256)", "0x10", "5")


def test_another_transaction_at_the_journaled_nonce_is_not_credited(evm_setup):
    # A is journaled and interrupted before its broadcast; B, another transaction,
    # then runs at A's nonce; resuming A must stop, not count B as A.
    evm, state = evm_setup
    token = usdc.deploy_token(evm, state, "deploy", "0xd0")
    evm.crash = ("transfer", "before")
    with pytest.raises(Interrupted):
        usdc.evm_send_once(evm, state, "a", "0xd0", token, "transfer(address,uint256)", "0x10", "5")
    nonce = state.intent("a")["nonce"]
    evm.broadcast("0xd0", nonce, token, "transfer(address,uint256)", ["0x99", "7"], None)
    with pytest.raises(usdc.Refused, match="is not the journaled one"):
        usdc.evm_send_once(evm, state, "a", "0xd0", token, "transfer(address,uint256)", "0x10", "5")
    assert state.intent("a")["state"] != "done"
    assert evm.tokens[token]["balances"].get("0x10", 0) == 0


def test_a_sender_with_an_unresolved_send_cannot_start_another(evm_setup):
    evm, state = evm_setup
    token = usdc.deploy_token(evm, state, "deploy", "0xd0")
    evm.crash = ("transfer", "before")
    with pytest.raises(Interrupted):
        usdc.evm_send_once(evm, state, "a", "0xd0", token, "transfer(address,uint256)", "0x10", "5")
    with pytest.raises(usdc.Refused, match="unresolved EVM send"):
        usdc.evm_send_once(evm, state, "c", "0xd0", token, "transfer(address,uint256)", "0x11", "1")
    # Another sender is not held back, and A itself still resumes.
    usdc.evm_send_once(evm, state, "a", "0xd0", token, "transfer(address,uint256)", "0x10", "5")
    usdc.evm_send_once(evm, state, "c", "0xd0", token, "transfer(address,uint256)", "0x11", "1")
    assert evm.tokens[token]["balances"]["0x10"] == 5 and evm.tokens[token]["balances"]["0x11"] == 1


def test_another_message_at_the_journaled_seqno_is_not_credited(tmp_path):
    chain = FakeTos()
    genesis = usdc.Wallet(chain, b"\1" * 32, -1, "-1:" + "00" * 32)
    chain.fund(genesis.address, 10**6 * NANO)
    journal = usdc.State(tmp_path)
    chain.fail_send = 1
    with pytest.raises(Interrupted):
        genesis.transfer(journal, "a", "0:" + "11" * 32, NANO)
    # Another message signed for the same seqno (by another journal) runs first.
    other = tmp_path / "other"
    other.mkdir()
    genesis.transfer(usdc.State(other), "b", "0:" + "22" * 32, 2 * NANO)
    with pytest.raises(usdc.Refused, match="not by the journaled message"):
        genesis.transfer(journal, "a", "0:" + "11" * 32, NANO)
    assert journal.intent("a")["state"] != "done"
    assert [e[2] for e in chain.executed] == ["0:" + "22" * 32]


def test_the_intent_is_durable_before_the_broadcast(tmp_path, monkeypatch):
    chain = FakeTos()
    genesis = usdc.Wallet(chain, b"\1" * 32, -1, "-1:" + "00" * 32)
    chain.fund(genesis.address, 10**6 * NANO)
    state = usdc.State(tmp_path)
    events = []
    real_fsync, real_replace, real_send = usdc.os.fsync, usdc.os.replace, chain.send

    def fsync(fd):
        events.append("fsync-dir" if usdc.os.path.isdir(f"/proc/self/fd/{fd}") else "fsync-file")
        real_fsync(fd)

    def replace(a, b):
        events.append("rename")
        real_replace(a, b)

    def send(message):
        on_disk = usdc.json.loads((tmp_path / "state.json").read_text())
        events.append(("send", on_disk["intents"]["a"]["state"]))
        real_send(message)

    monkeypatch.setattr(usdc.os, "fsync", fsync)
    monkeypatch.setattr(usdc.os, "replace", replace)
    chain.send = send
    genesis.transfer(state, "a", "0:" + "11" * 32, NANO)
    first_send = events.index(("send", "signed"))
    assert events[:3] == ["fsync-file", "rename", "fsync-dir"]
    assert first_send == 3  # the signed intent was on disk, synced, before the broadcast
