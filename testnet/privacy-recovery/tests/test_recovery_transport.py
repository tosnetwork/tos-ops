import ast
import asyncio
import copy
import hashlib
import os
import re
import secrets
import tempfile
import types
from pathlib import Path

from pytosiq_core import Cell, StateInit

root = Path(__file__).resolve().parents[1]
tree = ast.parse((root / "pri-driver.py").read_text())
ns = dict(
    Path=Path,
    hashlib=hashlib,
    Cell=Cell,
    StateInit=StateInit,
    re=re,
    secrets=secrets,
    time=__import__("time"),
)
for n in tree.body:
    if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in [
        "Stop",
        "require",
        "recipient_artifact",
        "recovery_post_matches",
        "plan_spend",
    ]:
        exec(compile(ast.Module([n], type_ignores=[]), "actual-driver", "exec"), ns)
artifact = Path(os.environ["PRI_E6_RECIPIENT"])
addr, si, cell = ns["recipient_artifact"](artifact)
with tempfile.TemporaryDirectory() as d:
    p = Path(d) / "state-init.boc"
    raw = (artifact / p.name).read_bytes()
    p.write_bytes(raw + b"\0")
    try:
        ns["recipient_artifact"](d)
    except ns["Stop"]:
        pass
    else:
        raise AssertionError("changed artifact accepted")
planned = dict(
    commitment_next_index="5",
    native_liability="9000",
    reserved_recovery_leaves="1",
    nullifier_root="root",
    nullifier_next_index="3",
)
before = dict(events=[], summary=dict(recoveries=[]))
rec = dict(recipient=addr, consumed=True, minted_amount="800", minted_leaf=5)
after = dict(
    events=[dict(kind="withdraw", hash="tx", applied=True), dict(kind="bounce", applied=True)],
    summary=dict(recoveries=[rec]),
    verified_state={
        **planned,
        "commitment_next_index": "6",
        "native_liability": "9800",
        "reserved_recovery_leaves": "0",
    },
)
f = ns["recovery_post_matches"]
result = dict(pool_tx="tx")
assert f(before, after, planned, result, addr)
for field, bad in [
    ("native_liability", "10000"),
    ("reserved_recovery_leaves", "1"),
    ("nullifier_root", "wrong"),
    ("commitment_next_index", "7"),
]:
    altered = copy.deepcopy(after)
    altered["verified_state"][field] = bad
    assert not f(before, altered, planned, result, addr), field
for mutate in ["wrong_tx", "wrong_sender", "not_consumed", "extra_event"]:
    altered = copy.deepcopy(after)
    if mutate == "wrong_tx":
        altered["events"][0]["hash"] = "different"
    elif mutate == "wrong_sender":
        altered["summary"]["recoveries"][0]["recipient"] = "0:" + "0" * 64
    elif mutate == "not_consumed":
        altered["summary"]["recoveries"][0]["consumed"] = False
    else:
        altered["events"].append(dict(kind="deposit", applied=True))
    assert not f(before, altered, planned, result, addr), mutate


async def route():
    ns["owner_seed"] = lambda *_: "unused-seed-path"
    ns["anchor_arg"] = lambda _: dict(kind="current")

    async def cp(_):
        return "cp21"

    ns["cp21_hex"] = cp
    run = types.SimpleNamespace(reserved=lambda _: [], private_file=lambda *_: "private-out")
    args = types.SimpleNamespace(
        owner="a",
        amount=1,
        validity=1200,
        anchor="current",
        imt="head",
        allow_spent=False,
        inputs=None,
        to_owner=None,
        recipient=addr,
        recipient_wallet=None,
        cmd="withdraw",
    )
    core = types.SimpleNamespace(call=lambda req: req)
    assert (await ns["plan_spend"](args, run, core, []))["withdraw_to"] == addr
    for changes in [
        dict(cmd="transfer"),
        dict(recipient="-1:" + "0" * 64),
        dict(recipient_wallet=2),
    ]:
        bad = copy.copy(args)
        for k, v in changes.items():
            setattr(bad, k, v)
        try:
            await ns["plan_spend"](bad, run, core, [])
        except ns["Stop"]:
            pass
        else:
            raise AssertionError("unsafe route accepted")


asyncio.run(route())
print(
    "PASS frozen-artifact integrity, raw-route validation, exact recovery poststate and 8 negative poststate controls"
)
