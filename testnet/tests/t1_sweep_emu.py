"""Real execution of the pinned self-pay Quantum wallet code for the sweep tests (no network, nothing sent).

Uses the transaction emulator (libemulator.so of the pinned tos revision), the pinned bench-pq-signer and a
throwaway bench key made in a temporary directory, never the T1 key. The config is the epoch-6 testnet's
(data/t1-sweep/config-epoch6.boc.b64, sha256 pinned below).
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data" / "t1-sweep"
CONFIG_SHA256 = "8fb1e9822300b153a3b7dc2ecdef9f4aea1645a0a4b11f041ea2cce5eae1b056"
LIB = os.environ.get("T1_SWEEP_EMULATOR", "")
SIGNER = Path(os.environ.get("T1_SWEEP_SIGNER", "/datax/t1/bin/bench-pq-signer"))
TOS = Path(os.environ.get("T1_SWEEP_TOS", "/tos/worktrees/tos/t1-4fb9ee703"))


def available() -> str | None:
    """Why the emulator tests cannot run here (None when they can)."""
    if not LIB or not Path(LIB).is_file():
        return "set T1_SWEEP_EMULATOR to the pinned revision's libemulator.so"
    if not SIGNER.is_file():
        return f"no bench signer at {SIGNER}"
    if not (TOS / "build/crypto/func").exists():
        return f"no pinned tos checkout with a FunC build at {TOS}"
    return None


def config_b64() -> str:
    b64 = (DATA / "config-epoch6.boc.b64").read_text().strip()
    if hashlib.sha256(base64.b64decode(b64)).hexdigest() != CONFIG_SHA256:
        raise AssertionError("the pinned config fixture changed")
    return b64


class Emulator:
    def __init__(self, unixtime: int):
        lib = ctypes.CDLL(LIB)
        lib.transaction_emulator_create.restype = ctypes.c_void_p
        lib.transaction_emulator_create.argtypes = [ctypes.c_char_p, ctypes.c_int]
        lib.transaction_emulator_set_unixtime.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        lib.transaction_emulator_set_lt.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        lib.transaction_emulator_emulate_transaction.restype = ctypes.c_char_p
        lib.transaction_emulator_emulate_transaction.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib = lib
        self.em = lib.transaction_emulator_create(config_b64().encode(), 0)
        assert self.em, "transaction_emulator_create failed"
        lib.transaction_emulator_set_unixtime(self.em, unixtime)
        self.lt = 10_000

    def run(self, shard_account_b64: str, message) -> dict:
        self.lt += 1000
        self.lib.transaction_emulator_set_lt(self.em, self.lt)
        msg = base64.b64encode(message.serialize().to_boc()).decode()
        return json.loads(self.lib.transaction_emulator_emulate_transaction(self.em, shard_account_b64.encode(),
                                                                             msg.encode()))


class World:
    """A throwaway bench key, the bench wallet and its load wallets, derived exactly as the ramp derives them."""

    def __init__(self, m, now: int):
        self.m, self.now = m, now
        self._dir = tempfile.TemporaryDirectory()
        key_file = Path(self._dir.name) / "bench-key.json"
        key_file.write_text(json.dumps({"mldsa44_seed": secrets.token_bytes(32).hex(),
                                        "rescue_public_key": secrets.token_bytes(32).hex(), "wallet_id": 0}))
        os.chmod(key_file, 0o600)
        self.key = m.remote.load_key(key_file)
        with tempfile.TemporaryDirectory() as scratch:
            self.code = m.contracts.build(TOS / "build", Path(scratch))["quantum"]
        self.auth = bytes.fromhex("99d8ae3469661895b820b4c41b6ad21acc448370e814c68d52ee3a12ae2c407a")
        self.bench = m.remote.bench_wallet(self.code, 2, self.auth, self.key,
                                           m.remote.Signer(SIGNER, self.key).public_key())
        self.signer = m.ramp.BatchSigner(SIGNER, 2)
        self.seeds = [m.ramp.load_seed(self.key.seed, self.bench.address, i) for i in range(2)]
        pks = self.signer.public_keys(self.seeds)
        self.loads = [m.ramp.load_wallet(self.code, 2, self.auth, i, pk, self.key.rescue_public_key)
                      for i, pk in enumerate(pks)]

    def account(self, wallet, balance: int, cells: int = 0, bits: int = 0, age: int = 10) -> str:
        """The base64 ShardAccount of an active ``wallet`` (its StateInit as derived) holding ``balance``, with
        ``cells``/``bits`` of storage used and storage last paid ``age`` seconds ago."""
        from pytosiq_core.tlb.account import (Account, AccountState, AccountStorage, ShardAccount,
                                              StorageExtraInfo, StorageInfo, StorageUsed)
        from pytosiq_core.tlb.transaction import CurrencyCollection
        acct = Account(wallet.address,
                       StorageInfo(StorageUsed(cells, bits), StorageExtraInfo("storage_extra_none"),
                                   self.now - age, None),
                       AccountStorage(1001, CurrencyCollection(balance),
                                      AccountState("account_active", state_init=wallet.state_init)))
        return base64.b64encode(ShardAccount(acct, bytes(32), 1000).serialize().to_boc()).decode()

    def sweep_external(self, i: int, nonce: int, dest, mode: int, deadline: int | None = None):
        m, w = self.m, self.loads[i]
        action = m.workload.transfer_message(w.address, dest, 0)
        request = w.request(nonce, [action], deadline or self.now + 60, mode=mode)
        return w.external(request, self.signer.sign([(self.seeds[i], request.hash)])[0])


def parse(m, out: dict, account: str) -> dict:
    """The emulated transaction as the bench's transaction summary (t2check.Tx), plus the balance after."""
    from pytosiq_core import Cell, Transaction
    from pytosiq_core.tlb.account import ShardAccount
    t2 = m.t2check
    cell = Cell.one_from_boc(base64.b64decode(out["transaction"]))
    tx = Transaction.deserialize(cell.begin_parse())
    d = tx.description
    raw = m.remote.raw

    def msg(x):
        info = x.info
        internal = type(info).__name__ == "InternalMsgInfo"
        return t2.Msg(hash=x.serialize().hash.hex(), kind="internal" if internal else "external",
                      source=raw(info.src) if internal else None, destination=raw(info.dest),
                      bounced=bool(getattr(info, "bounced", False)), value=info.value_coins if internal else None)

    compute_ok = getattr(d.compute_ph, "success", False) is True
    action_ok = d.action.success if d.action is not None else None
    after = ShardAccount.deserialize(Cell.one_from_boc(base64.b64decode(out["shard_account"])).begin_parse())
    summary = t2.Tx(hash=cell.hash.hex(), account=account,
                    # emulated: no block contains it (seqno 0 marks that; never a chain block)
                    lt=tx.lt, block=(0, -(1 << 63), 0), in_msg=msg(tx.in_msg) if tx.in_msg else None,
                    out_msgs=tuple(msg(x) for x in tx.out_msgs), aborted=bool(d.aborted),
                    action_success=action_ok, fee=tx.total_fees.tomis,
                    phase_failure=None if (compute_ok and not d.aborted) else "compute phase did not succeed")
    balance = after.account.storage.balance.tomis if after.account is not None else None
    return {"tx": summary, "balance_after": balance, "shard_account": out["shard_account"], "raw": tx}
