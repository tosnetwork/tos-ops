#!/usr/bin/env python3
"""Mutation guards for the operations journal and the election task.

Each mutant replaces one exact snippet of a script, runs the whole suite and
restores the file. Every mutant must make a test fail: only pytest's exit 1
with a failed test counts as killed. The run itself fails when a pattern does
not occur exactly once (a guard that silently stopped running), when two mutants
are identical, when a mutated file does not compile, when the unmutated suite is
not green, when any mutant survives, or when a mutant's run is invalid (pytest
exits 2-5, a collection error, or a timeout).

    TOS_ROOT=<tos checkout> python testnet/tests/mutants.py [LABEL ...]

LABEL is the first word of a mutant's label (O4, N14b, ...); none runs them all.
Not collected by pytest.
"""

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

W = Path(__file__).resolve().parents[1]
FAILED = re.compile(r"\b[1-9]\d* failed\b")
ERRORS = re.compile(r"\b[1-9]\d* errors?\b")
OPS = W / "scripts/testnet_ops.py"
EL = W / "scripts/testnet-elections.py"
CO = W / "scripts/testnet-coordinator.py"

M = [
    (
        "ER9 relay election id does not have to match",
        OPS,
        "            active != stake_at",
        "            False",
    ),
    (
        "ER10 custom profile ignored",
        OPS,
        'limits = lib.load_profile(self.profile_path)["elections"]',
        'limits = lib.load_profile()["elections"]',
    ),
    (
        "ER11 current time substituted for relay time",
        OPS,
        'or not active - start_before <= tx["utime"] < active - end_before',
        "or not active - start_before <= int(self.clock()) < active - end_before",
    ),
    (
        "ER1 election relay classification disabled",
        OPS,
        '        path = self.ceremony / "pools.json"',
        '        return None\n        path = self.ceremony / "pools.json"',
    ),
    (
        "ER2 relay to a different pool accepted",
        OPS,
        'or message["destination"] != matches[0]',
        "or False",
    ),
    (
        "ER3 relay budget ignored",
        OPS,
        'if not 0 < message["value"] <= budget + allowance:',
        "if False:",
    ),
    (
        "ER4 additional outbound message ignored",
        OPS,
        'if len(tx["out"]) != 1:',
        'if not tx["out"]:',
    ),
    (
        "ER5 relay outside election window accepted",
        OPS,
        'or not active - start_before <= tx["utime"] < active - end_before',
        "or False",
    ),
    (
        "ER6 historical window trusts only first validator",
        OPS,
        "block, active, start_before, end_before = self.both(window)",
        "block, active, start_before, end_before = window(self.nodes[0])",
    ),
    (
        "ER7 historical block identity ignored",
        OPS,
        'if election.get("block_id") != block or config.get("block_id") != block:',
        "if False:",
    ),
    (
        "ER8 non-stake body accepted",
        OPS,
        "if init is not None or b.bits(32) != 0x4E73744B:",
        "if init is not None or b.bits(32) < 0:",
    ),
    (
        "W5 owner artifacts published without the shared ceremony lock",
        EL,
        "    with lib.wallet_records_lock(ceremony):\n        paths = pool_owner_paths(ceremony, name)",
        '    with __import__("contextlib").nullcontext():\n        paths = pool_owner_paths(ceremony, name)',
    ),
    (
        "W1 withdrawal resubmit bypasses the shared preflight",
        EL,
        '                    withdrawal_preflight(\n                        operations,\n                        args.tos_root,\n                        record["destination"],\n                        record["wallet"],\n                        record["requested_nanotos"],\n                    )',
        "                    pass",
    ),
    (
        "W2 initial withdrawal bypasses the shared preflight",
        EL,
        "        withdrawal_preflight(operations, args.tos_root, pool, owner, requested_nanotos)",
        "        pass",
    ),
    (
        "W3 short retained payment settles an explicit request",
        OPS,
        'if requested is not None and payment["value"] < requested:',
        "if False:",
    ),
    (
        "W4 all withdrawals incorrectly require the requested sentinel amount",
        OPS,
        '        requested = record["requested_nanotos"]',
        '        requested = record["requested_nanotos"] or 10**30',
    ),
    (
        "Q1 withdrawal trusts the first election view",
        EL,
        "election = operations.both(lambda node: Chain(node.url, node.rpc).active_election())",
        "election = Chain(operations.nodes[0].url, operations.nodes[0].rpc).active_election()",
    ),
    (
        "Q2 network identity cached across decisions",
        OPS,
        "    def check_network(self) -> None:\n        genesis =",
        "    def check_network(self) -> None:\n        if getattr(self, '_network_checked', False):\n            return\n        self._network_checked = True\n        genesis =",
    ),
    (
        "Q3 shared reads omit network revalidation",
        OPS,
        "        self.check_network()\n        return [read(node) for node in self.nodes]",
        "        return [read(node) for node in self.nodes]",
    ),
    (
        "Q4 pool updates omit the shared lock",
        EL,
        "    with lib.wallet_records_lock(ceremony):\n        pools = read_pools(ceremony)",
        "    with __import__('contextlib').nullcontext():\n        pools = read_pools(ceremony)",
    ),
    (
        "O1 gate ignores unexplained activity",
        OPS,
        '            if leaves(tx, wallet) and tx["hash"] not in explained:\n                described',
        "            if False:\n                described",
    ),
    (
        "O2 gate ignores other open operations",
        OPS,
        'if record["id"] != op_id and state_of(record) in ("planned", "signed", "broadcast"):',
        "if False:",
    ),
    (
        "O3 a self-message counts as value leaving",
        OPS,
        'return any(m["destination"] != wallet for m in tx["out"])',
        'return bool(tx["out"])',
    ),
    (
        "O4 validators' histories not compared",
        OPS,
        "        if histories[0] != histories[1]:\n",
        "        if False:\n",
    ),
    ("O5 global id not checked", OPS, 'if decoded["global_id"] != self.global_id:', "if False:"),
    ("O6 seqno not checked", OPS, 'if decoded["seqno"] != seqno:', "if False:"),
    (
        "O7 expiry not checked",
        OPS,
        'if not now < decoded["valid_until"] <= now + ttl + TTL_SKEW:',
        "if False:",
    ),
    (
        "O8 internal message not compared",
        OPS,
        "        if actual != expected:",
        "        if False:",
    ),
    (
        "O9 signing wallet not checked",
        OPS,
        'if decoded["destination"] != params["wallet"]:',
        "if False:",
    ),
    (
        "O10 broadcast before the signed line",
        OPS,
        '            crash_point(op_id, "signed")\n            self.nodes[0].call("sendBoc", boc=base64.b64encode(boc).decode())',
        '            self.nodes[0].call("sendBoc", boc=base64.b64encode(boc).decode())\n            crash_point(op_id, "signed")',
    ),
    (
        "O11 an open operation is sent again",
        OPS,
        '            if state_of(record) in ("signed", "broadcast"):\n                raise OperationRefused(\n                    f"operation {op_id} is open',
        '            if False:\n                raise OperationRefused(\n                    f"operation {op_id} is open',
    ),
    (
        "O12 wallet transaction found without the hash",
        OPS,
        'if tx["in_kind"] == "external" and tx["in_hash"] == record["external_hash"]\n',
        'if tx["in_kind"] == "external"\n',
    ),
    (
        "O13 not exactly the required message accepted",
        OPS,
        'if len(tx["out"]) != 1 or len(wanted) != 1:',
        "if not wanted:",
    ),
    (
        "O14 a bounced credit settles",
        OPS,
        '            if any(m["bounced"] for m in delivery["out"]):\n                return "failed", dict(evidence, form="b", reason="the credit bounced")',
        '            if False:\n                return "failed", dict(evidence, form="b", reason="the credit bounced")',
    ),
    ("O15 destination failure ignored", OPS, "if not took_effect(delivery):", "if False:"),
    ("O16 receipt may bounce", OPS, '            and not receipt["out"]\n', ""),
    (
        "O17 receipt credit not compared",
        OPS,
        '            and receipt["credit"] == payment["value"]\n',
        "",
    ),
    (
        "O18 expiry without margin",
        OPS,
        'if any(t < record["valid_until"] + EXPIRY_MARGIN for t in times):',
        'if any(t < record["valid_until"] for t in times):',
    ),
    (
        "O19 activation may expire",
        OPS,
        'if record["kind"] == "activate-owner" or record["valid_until"] == ACTIVATION_VALID_UNTIL:',
        "if False:",
    ),
    (
        "O20 (d) without identity",
        OPS,
        "if not identity or current is None or list(current) != list(identity):",
        "if False:",
    ),
    (
        "O21 resubmit after the seqno moved",
        OPS,
        '                if self.seqno(wallet) != record["seqno"]:\n                    raise OperationRefused("the wallet\'s seqno moved; the message cannot execute")',
        '                if False:\n                    raise OperationRefused("the wallet\'s seqno moved; the message cannot execute")',
    ),
    (
        "O22 record --settled ignores the hint",
        OPS,
        '            if hint not in (evidence.get("wallet_tx"), evidence.get("destination_tx")):\n                raise OperationRefused(\n',
        "            if False:\n                raise OperationRefused(\n",
    ),
    (
        "O23 record --failed without terminal evidence",
        OPS,
        'if outcome != "failed" or evidence.get("form") != form:',
        "if False:",
    ),
    ("O24 parameters may change", OPS, "        if mismatch:", "        if False:"),
    (
        "O25 a failed id retried",
        OPS,
        '            if state_of(record) == "failed":\n                raise OperationRefused(\n                    f"operation {op_id} failed (',
        '            if False:\n                raise OperationRefused(\n                    f"operation {op_id} failed (',
    ),
    ("O26 torn line accepted", OPS, 'if text and not text.endswith("\\n"):', "if False:"),
    ("O27 no lock", OPS, "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)", "pass"),
    (
        "O28 a directory fsync syncs nothing",
        OPS,
        "    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)\n    try:\n        os.fsync(fd)\n",
        "    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)\n    try:\n        pass\n",
    ),
    (
        "O29 no dedup",
        OPS,
        "                if tx_hash in seen:\n                    continue\n",
        "",
    ),
    (
        "O30 boundary not required",
        OPS,
        '                if boundary:\n                    raise Unknown(f"{self.url}: {address} boundary {boundary} not in its history")\n',
        "",
    ),
    (
        "O31 network not checked",
        OPS,
        '                raise OperationRefused(f"{node.url} serves another network (zero state)")',
        "                pass",
    ),
    (
        "E1 pool owned by the operator",
        EL,
        "    pool = pool_address(code, owner, operator, controller)",
        "    pool = pool_address(code, operator, operator, controller)",
    ),
    (
        "E2 principal one TOS short",
        EL,
        "        principal,\n        None,\n",
        "        principal - NANO,\n        None,\n",
    ),
    (
        "E3 principal without the pool check",
        EL,
        '        require(f"activate-owner-{name}")\n        verify_pool_both(operations, args.tos_root, pool, owner, operator, controller)\n',
        '        require(f"activate-owner-{name}")\n',
    ),
    (
        "E4 principal without the balance check",
        EL,
        "if balance < principal + ops.FEE_ALLOWANCE_NANOTOS // 10:",
        "if False:",
    ),
    (
        "E5 withdraw without the owner-role check",
        EL,
        "    owner_role_check(operations, tos_root, pool, owner)\n",
        "",
    ),
    (
        "E6 withdraw during an election",
        EL,
        "if election:",
        "if False:",
    ),
    ("E7 --new on an existing id", EL, "if args.new and record is not None:", "if False:"),
    (
        "E8 authorization epoch ignored",
        EL,
        "if epoch != planned_epoch or nonce <= planned_nonce:",
        "if nonce <= planned_nonce:",
    ),
    (
        "E9 authorization terms ignored",
        EL,
        "values[1:] != [permission, limit, floor, expires] or sponsor != payer",
        "False",
    ),
    (
        "E10 readiness not checked",
        EL,
        '    # Readiness is tosctl\'s full assessment (capital reserve, a usable grant).\n    status = host.tosctl(f"controller operations status --controller {controller}", 90)\n    if "BLOCKING" in status or "kind 4 never accepted" in status:',
        '    # Readiness is tosctl\'s full assessment (capital reserve, a usable grant).\n    status = host.tosctl(f"controller operations status --controller {controller}", 90)\n    if False:',
    ),
    (
        "E11 a foreign retained birth accepted",
        EL,
        "            return lib.parse_boc(base64.b64decode(content)).hash() == expected\n",
        "            return True\n",
    ),
    (
        "E12 retained birth overwritten",
        EL,
        "    if retained or bound:\n",
        "    if bound:\n",
    ),
    (
        "E13 host pool configuration not compared",
        EL,
        '    elif (entry.get("address"), entry.get("owner"), entry.get("controller")) != (',
        '    elif False and (entry.get("address"), entry.get("owner"), entry.get("controller")) != (',
    ),
]


M += [
    (
        "N1 the record read before the lock (the original race)",
        OPS,
        "        with self.journal.lock(wallet):\n            op_id = self.journal.newest(step)\n            record = self.begin(op_id, params)\n",
        "        op_id = self.journal.newest(step)\n        record = self.journal.record(op_id) or self.begin(op_id, params)\n        with self.journal.lock(wallet):\n",
    ),
    (
        "N2 watch does not re-read a settled record",
        OPS,
        '                record = self.journal.record(op_id)\n                if state_of(record) == "settled":\n                    return record\n',
        "                record = self.journal.record(op_id)\n",
    ),
    (
        "N3 BOC not checked against the transaction id",
        OPS,
        "        if root.hash().hex() != tx_hash:",
        "        if False:",
    ),
    (
        "N4 transaction not bound to account and lt",
        OPS,
        "        if f\"{address.split(':')[0]}:{account}\" != address or lt != tx_lt:",
        "        if False:",
    ),
    (
        "N5 histories compared by length only",
        OPS,
        "        if histories[0] != histories[1]:",
        "        if len(histories[0]) != len(histories[1]):",
    ),
    (
        "N6 an unretained receipt left pending",
        OPS,
        '            failed = dict(evidence, form="b", reason="the owner did not retain the payment")\n            failed["explains"] = evidence["explains"] + [receipt["hash"]]\n            failed["receipt_out"] = [m["hash"] for m in receipt["out"]]\n            return "failed", failed',
        '            return "pending", dict(evidence, reason="payment emitted, not retained")',
    ),
    (
        "N7 resubmit ignores the wallet identity",
        OPS,
        '                    not record.get("identity")\n                    or current is None\n                    or list(current) != record["identity"]\n',
        "                    False\n",
    ),
    (
        "N8 resubmit judges expiry by the earliest validator",
        OPS,
        '                if any(t >= record["valid_until"] for t in times):',
        '                if min(times) >= record["valid_until"]:',
    ),
    (
        "N9 (c) judged by the latest validator",
        OPS,
        'if any(t < record["valid_until"] + EXPIRY_MARGIN for t in times):',
        'if max(times) < record["valid_until"] + EXPIRY_MARGIN:',
    ),
    (
        "N10 resubmit without the balance check",
        OPS,
        'if self.balance(wallet) < record["value"] + FEE_ALLOWANCE_NANOTOS:',
        "if False:",
    ),
    (
        "N11 activation resubmitted over an initialized account",
        OPS,
        '                if state != "uninitialized":',
        "                if False:",
    ),
    (
        "N12 subwallet not checked",
        OPS,
        'if decoded["subwallet"] != params.get("subwallet"):',
        "if False:",
    ),
    (
        "N13 funding credit not compared",
        OPS,
        'if delivery["credit"] != message["value"] or message["value"] != record["value"]:',
        "if False:",
    ),
    (
        "N14 one write call only (new record)",
        OPS,
        '            count = os.write(fd, data[written:])\n            if count <= 0:\n                raise OperationRefused(f"{tmp}: the journal write',
        '            count = os.write(fd, data[written:]) or len(data)\n            written = len(data) - count\n            if count <= 0:\n                raise OperationRefused(f"{tmp}: the journal write',
    ),
    (
        "N15 a write that made no progress ignored",
        OPS,
        '                raise OperationRefused(f"{path}: the journal write made no progress")',
        "                break",
    ),
    (
        "N16 retry of a non-failed attempt",
        OPS,
        '            if state_of(record) != "failed":',
        "            if False:",
    ),
    (
        "E14 a bound birth trusted by its name",
        EL,
        "        if found:\n            return\n",
        "        if bound:\n            return\n",
    ),
    ("E16 operator subwallet guessed", EL, "    return data[2]", "    return 0"),
]


M += [
    (
        "R28 directory not fsynced (append)",
        OPS,
        "    fsync_dir(path.parent)\n\n\ndef publish_new",
        "\n\ndef publish_new",
    ),
    ("R11b a foreign retained birth accepted", EL, "    if retained is False:", "    if False:"),
]


M += [
    (
        "F1 prerequisites read the original attempt",
        EL,
        '        return ops.state_of(journal.record(journal.newest(step))) == "settled"',
        '        return ops.state_of(journal.record(step)) == "settled"',
    ),
    (
        "F2 a new record written in place",
        OPS,
        "        if path.exists():\n            append_line(path, entry)\n        else:\n            publish_new(path, entry)",
        "        append_line(path, entry)",
    ),
    (
        "F3 (d) without the seqno match",
        OPS,
        '            and external_seqno(t) == record["seqno"]\n',
        "",
    ),
    (
        "F4 activation resubmitted without its fee budget",
        OPS,
        "                if self.balance(wallet) < ACTIVATION_FEE_NANOTOS:",
        "                if False:",
    ),
]


M += [
    (
        "N14b one write call only (append)",
        OPS,
        '            count = os.write(fd, data[written:])\n            if count <= 0:\n                raise OperationRefused(f"{path}: the journal write',
        '            count = os.write(fd, data[written:]) or len(data)\n            written = len(data) - count\n            if count <= 0:\n                raise OperationRefused(f"{path}: the journal write',
    ),
    (
        "F2b new record's directory not fsynced",
        OPS,
        "        os.unlink(tmp)\n    fsync_dir(path.parent)\n",
        "        os.unlink(tmp)\n",
    ),
]


M += [
    (
        "F5 (d) matches only single-transfer competitors",
        OPS,
        '        return decode_signed_header(messages.take_ref())["seqno"]',
        '        return decode_external(lib.serialize_boc(messages.take_ref()))["seqno"]',
    ),
]

M += [
    (
        "F6 (d) counts an aborted attempt as the consumer",
        OPS,
        '            and took_effect(t)\n            and external_seqno(t) == record["seqno"]\n',
        '            and t["compute_success"]\n            and external_seqno(t) == record["seqno"]\n',
    ),
    (
        "F7 an aborted run of the message is its wallet transaction",
        OPS,
        "            if took_effect(tx):\n                return tx",
        "            return tx",
    ),
    (
        "F8 compute success alone means the state changed",
        OPS,
        'return bool(tx["compute_success"]) and tx["aborted"] is False',
        'return bool(tx["compute_success"])',
    ),
    (
        "F9 a destination that computed and aborted is accepted",
        OPS,
        "if not took_effect(delivery):",
        'if not delivery["compute_success"]:',
    ),
]

_EXPIRY = (
    "        times = self.utimes()\n"
    '        if any(t < record["valid_until"] + EXPIRY_MARGIN for t in times):\n'
    "            raise OperationRefused(\n"
    "                f\"block times {times} are not all past valid_until {record['valid_until']} + \"\n"
    '                f"{EXPIRY_MARGIN} s; the message can still execute"\n'
    "            )\n"
)
_ABSENCE = (
    "        if self.find_wallet_tx(record) is not None:\n"
    '            raise OperationRefused("the message was accepted; this is not expiry")\n'
    '        if self.seqno(record["wallet"]) != record["seqno"]:\n'
    '            raise OperationRefused("the wallet\'s seqno moved; prove (d) instead")\n'
)

M += [
    ("G1 (c) reads absence before expiry", OPS, _EXPIRY + _ABSENCE, _ABSENCE + _EXPIRY),
    (
        "G2 (d) accepts the message itself from the later scan",
        OPS,
        '            and t["in_hash"] == record["external_hash"]\n'
        "            and took_effect(t)\n"
        "            for t in history\n",
        "            and False\n            for t in history\n",
    ),
    (
        "G3 no last read before a failure record",
        OPS,
        'if form in ("c", "d") and self.find_wallet_tx(record) is not None:',
        "if False:",
    ),
]

M += [
    ("H1 a partly published genesis rerun", CO, "    if leftover:\n", "    if False:\n"),
    (
        "H2 the zero-state AUTH policy checked on the published copy",
        CO,
        "    built = runs[0]\n",
        "    built = ceremony\n    for name in OUTPUTS:\n"
        "        shutil.copyfile(runs[0] / name, ceremony / name)\n",
    ),
    (
        "P1 the plan's payer not compared with the operator",
        EL,
        "    if payer != operator:\n        problems.append(",
        "    if False:\n        problems.append(",
    ),
    (
        "P2 storage floor not compared",
        EL,
        '    if floor != int(authorization["floor_nanotos"]):',
        "    if False:",
    ),
    (
        "P3 allowance not compared",
        EL,
        '    if allowance != target or not context["grant"] <= target < COINS_LIMIT:',
        "    if False:",
    ),
    ("P4 deposit not bounded", EL, "    if deposit != expected_deposit:", "    if False:"),
    (
        "P5 per-request limit not bounded",
        EL,
        "    if limit != expected_limit or limit >= COINS_LIMIT:",
        "    if False:",
    ),
    (
        "P6 message value not bounded",
        EL,
        "    if value != expected_value or not 0 < value < COINS_LIMIT:",
        "    if False:",
    ),
    (
        "P7 validity not bounded",
        EL,
        "    if (\n        not now < valid_until <= now + PLAN_VALID_FOR_SECONDS + PLAN_CLOCK_SKEW_SECONDS\n        or valid_until >= 1 << 32\n    ):",
        "    if False:",
    ),
    (
        "P8 expiry not bounded",
        EL,
        "    if expires != expires_at or not valid_until < expires < 1 << 32:",
        "    if False:",
    ),
    (
        "P9 epoch and nonce not compared with the controller",
        EL,
        '    if (epoch, nonce) != (context["epoch"], context["nonce"]):',
        "    if False:",
    ),
    (
        "P10 onboarding signs an unchecked plan",
        EL,
        "        check_operations_plan(\n            plan,\n",
        "        (lambda *a: None)(\n            plan,\n",
    ),
    (
        "P12 settlement trusts the plan's payer",
        EL,
        "    if payer != operator:\n        raise lib.TestnetError(f\"the plan's payer",
        "    if False:\n        raise lib.TestnetError(f\"the plan's payer",
    ),
]


M += [
    ("P13 trailing payload ignored", EL, "    if not payload.end():", "    if False:"),
    (
        "P14 relay fee calculation changed",
        EL,
        "    grant = 4 * control + callback",
        "    grant = 3 * control + callback",
    ),
    (
        "P15 validators not compared before root signing",
        EL,
        "        context = operations.both(lambda node: controller_plan_context(node, controller))",
        "        context = controller_plan_context(operations.nodes[0], controller)",
    ),
]


M += [
    (
        "U1 renewal disabled again",
        EL,
        '    """A new authorization is its own operation, never a retry of a settled grant."""',
        '    """A new authorization is its own operation, never a retry of a settled grant."""\n    raise lib.TestnetError("refund disabled")',
    ),
    (
        "U2 root signing without the journal lock",
        EL,
        "    with operations.journal.lock(operator):\n        actual_id = operations.journal.newest(op_id)",
        '    with __import__("contextlib").nullcontext():\n        actual_id = operations.journal.newest(op_id)',
    ),
    (
        "U3 other planned operations ignored",
        OPS,
        'if record["id"] != op_id and state_of(record) in ("planned", "signed", "broadcast"):',
        'if record["id"] != op_id and state_of(record) in ("signed", "broadcast"):',
    ),
    (
        "U4 baseline allowed over a planned operation",
        OPS,
        '                if state_of(record) in ("planned", "signed", "broadcast"):',
        '                if state_of(record) in ("signed", "broadcast"):',
    ),
    (
        "U5 window read on only one validator",
        EL,
        "    since, until, election = operations.both(",
        "    since, until, election = (lambda read: read(operations.nodes[0]))(",
    ),
    (
        "U6 window guard removed",
        EL,
        "        reason = window_refusal(since, until, election, lib.validator_schedule(profile), now)",
        "        reason = None",
    ),
    (
        "U7 reserve shortfall ignored",
        EL,
        "    shortfall = reserve_shortfall(balance, value, reserve)",
        "    shortfall = 0",
    ),
    (
        "U8 renewal resubmit bypasses preflight",
        EL,
        '        if record.get("renewal"):\n\n            def prerequisites():\n                authorization_preflight(operations, record, profile)',
        '        if record.get("renewal"):\n            prerequisites = None',
    ),
    (
        "U9 initial authorization bypasses preflight",
        EL,
        "        prerequisites=lambda: authorization_preflight(operations, params, profile),",
        "        prerequisites=lambda: None,",
    ),
    (
        "U10 retry keeps the old expiry",
        OPS,
        '("value", "body_hash", "plan", "body_b64", "expires_at")',
        '("value", "body_hash", "plan", "body_b64")',
    ),
    (
        "U11 election service not restarted",
        EL,
        '            host.run(f"systemctl start {ELECTIONS_SERVICE}")',
        "            pass",
    ),
    (
        "U12 renewal id may change its parameters",
        EL,
        "            if any(record.get(k) != v for k, v in expected.items() if renewal or k in record):",
        "            if False:",
    ),
    (
        "U13 planned expiry trusts either clock",
        EL,
        '                if all(t >= int(plan["valid_until"]) + ops.EXPIRY_MARGIN for t in times):',
        '                if any(t >= int(plan["valid_until"]) + ops.EXPIRY_MARGIN for t in times):',
    ),
    (
        "U14 a settled renewal is not reported",
        EL,
        '            if state == "settled":\n                print(f"{actual_id}: already settled',
        '            if False:\n                print(f"{actual_id}: already settled',
    ),
]


M += [
    (
        "U15 renewal readiness assessment ignored",
        EL,
        '    if "BLOCKING" in status or "kind 4 never accepted" in status:\n        raise lib.TestnetError(\n            f"renewal',
        '    if False:\n        raise lib.TestnetError(\n            f"renewal',
    ),
]


def suite(env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", str(W / "tests")],
        capture_output=True,
        text=True,
        env=env,
        cwd=W.parent,
        timeout=300,
    )


def last_line(result: subprocess.CompletedProcess) -> str:
    out = result.stdout.strip()
    return out.splitlines()[-1] if out else result.stderr[-200:]


def main(only: list[str]) -> int:
    if not os.environ.get("TOS_ROOT"):
        print("TOS_ROOT is not set", file=sys.stderr)
        return 2
    env = dict(os.environ)
    labels = [label.split()[0] for label, *_ in M]
    duplicated = sorted({x for x in labels if labels.count(x) > 1})
    if duplicated:
        print(f"FAIL: duplicate labels {duplicated}")
        return 1
    seen: dict = {}
    for label, path, old, new in M:
        key = (path, old, new)
        if key in seen:
            print(f"FAIL: {label} is identical to {seen[key]}")
            return 1
        seen[key] = label
    unknown = [x for x in only if x not in labels]
    if unknown:
        print(f"FAIL: no mutants {unknown}")
        return 1
    chosen = [m for m in M if not only or m[0].split()[0] in only]
    broken = []
    for label, path, old, _ in chosen:
        count = path.read_text().count(old)
        if count != 1:
            broken.append(f"{label}: pattern occurs {count} times in {path.name}")
    if broken:
        print("FAIL: patterns that do not match exactly once:")
        print("\n".join(f"  {b}" for b in broken))
        return 1
    # A mutant that does not compile only breaks collection: it proves nothing.
    uncompiled = []
    for label, path, old, new in chosen:
        try:
            ast.parse(path.read_text().replace(old, new), filename=str(path))
        except SyntaxError as exc:
            uncompiled.append(f"{label}: {exc.msg} at line {exc.lineno}")
    if uncompiled:
        print("FAIL: mutants that do not compile:")
        print("\n".join(f"  {u}" for u in uncompiled))
        return 1
    baseline = suite(env)
    if baseline.returncode != 0:
        print(f"FAIL: the unmutated suite is not green -- {last_line(baseline)}")
        return 1
    survivors, invalid = [], []
    for label, path, old, new in chosen:
        original = path.read_text()
        try:
            path.write_text(original.replace(old, new))
            try:
                result = suite(env)
                verdict, tail = classify(result), last_line(result)
            except subprocess.TimeoutExpired:
                verdict, tail = "INVALID", "timeout"
        finally:
            path.write_text(original)
        if verdict == "SURVIVED":
            survivors.append(label)
        elif verdict == "INVALID":
            invalid.append(label)
        print(f"{label}: {verdict} -- {tail}", flush=True)
    red = len(chosen) - len(survivors) - len(invalid)
    print(f"{red} of {len(chosen)} red; survivors: {survivors}; invalid: {invalid}")
    return 1 if survivors or invalid else 0


def classify(result: subprocess.CompletedProcess) -> str:
    """RED only for pytest's "tests failed" exit with a failed test reported.
    Exits 2-5 (interrupted, internal error, usage error, nothing collected) and
    collection errors say nothing about the mutant's sensitivity."""
    if result.returncode == 0:
        return "SURVIVED"
    summary = last_line(result)
    if result.returncode == 1 and FAILED.search(summary) and not ERRORS.search(summary):
        return "RED"
    return "INVALID"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
