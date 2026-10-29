#!/usr/bin/env python3
"""Mutation guards for the operations journal, the election task, the handover checker,
the release fetch and the rpc role's installer and unit templates.

Each mutant replaces one exact snippet of a script, runs the whole suite and
restores the file. Every mutant must make a test fail: only pytest's exit 1
with a failed test counts as killed. The run itself fails when a pattern does
not occur exactly once (a guard that silently stopped running), when two mutants
are identical, when a mutated file does not compile (Python by ast, shell by
`bash -n`; unit templates are not compiled), when the unmutated suite is
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
HO = W / "scripts/check-handover.py"
LIB = W / "scripts/testnet_lib.py"
FETCH = W / "scripts/fetch-release.py"
INSTALL = W / "scripts/install-node.sh"
BUILD = W / "scripts/build-node-binaries.sh"
OPERATOR = W / "scripts/testnet-operator.py"
INDEX_UNIT = W / "systemd/tos-testnet-wallet-index.service"
RPC_UNIT = W / "systemd/tos-testnet-rpc.service"

M = [
    # The bootstrap wallet's sweep, its burn and the epoch genesis check.
    (
        "S1 sweep prerequisite ConfigParam 5 not read",
        EL,
        "    burning = operations.both(\n        lambda node: lib.check_burning_config(operations.config_cell(node, 5))\n    )",
        '    burning = {"blackhole": ops.BLACKHOLE, "fee_burn": (0, 1)}',
    ),
    (
        "S2 sweep send mode not checked",
        OPS,
        'mode = SWEEP_MODE if params["kind"] == "sweep" else WALLET_V3_MODE',
        'mode = decoded["mode"]',
    ),
    (
        "S3 sweep shape not checked",
        OPS,
        'if params["kind"] == "sweep" and (\n            params["destination"] != BLACKHOLE',
        'if False and (\n            params["destination"] != BLACKHOLE',
    ),
    (
        "S4 sweep settles without deleting the wallet",
        OPS,
        '        if tx["end_status"] != "nonexist":\n            return "failed", dict(',
        '        if False:\n            return "failed", dict(',
    ),
    (
        "S5 sweep credited at the blackhole settles",
        OPS,
        'if delivery["in_value"] != message["value"] or delivery["credit"] != 0 or delivery["out"]:',
        "if False:",
    ),
    (
        "S6 sweep settles without its burn block",
        OPS,
        '        if expect is None:\n            block = delivery["block"]',
        '        if expect is None:\n            return "settled", evidence\n            block = delivery["block"]',
    ),
    (
        "S7 burn block not authenticated by its file hash",
        OPS,
        'if hashlib.sha256(boc).digest() != b64hash(block_id["file_hash"]):',
        "if False:",
    ),
    ("S8 ValueFlow.burned not reconciled", OPS, 'if flow["burned"] != burned:', "if False:"),
    (
        "S9 gate ignores the retired bootstrap wallet",
        OPS,
        '        retired = self.bootstrap_retired(wallet)\n        if retired:\n            raise OperationRefused(\n                f"the bootstrap wallet has been swept',
        '        retired = None\n        if retired:\n            raise OperationRefused(\n                f"the bootstrap wallet has been swept',
    ),
    (
        "S10 fund signs a dry run after the sweep",
        EL,
        '    retired = operations.bootstrap_retired(BOOTSTRAP_WALLET)\n    if retired:\n        raise lib.TestnetError(\n            f"the bootstrap wallet has been swept ({retired}); it funds nothing',
        '    retired = None\n    if retired:\n        raise lib.TestnetError(\n            f"the bootstrap wallet has been swept ({retired}); it funds nothing',
    ),
    (
        "S11 deleted wallet found on one validator only",
        OPS,
        "return self.both(read)\n\n    def bootstrap_retired",
        "return self.read_both(read)[0]\n\n    def bootstrap_retired",
    ),
    (
        "S12 operator recovery floor ignored",
        EL,
        '        if balance < floor:\n            raise lib.TestnetError(\n                f"op-{name} holds',
        '        if False:\n            raise lib.TestnetError(\n                f"op-{name} holds',
    ),
    (
        "S13 frozen stake not checked",
        EL,
        'if member is None or member["stake"] <= 0 or member["banned"]:',
        "if member is None:",
    ),
    (
        "S14 genesis set taken for an elected one",
        EL,
        "            if len(results) != 1:\n",
        "            if False:\n",
    ),
    (
        "S24 set with two Elector results accepted",
        EL,
        "            if len(results) != 1:\n",
        "            if not results:\n",
    ),
    (
        "S15 onboarding not required before the sweep",
        EL,
        'if ops.state_of(journal.record(op_id)) != "settled":',
        "if False:",
    ),
    (
        "S16 sweep receipt bound to send mode 3",
        OPS,
        '!= (SWEEP_MODE if record["kind"] == "sweep" else WALLET_V3_MODE)',
        "!= WALLET_V3_MODE",
    ),
    (
        "S17 genesis without ConfigParam 5 accepted",
        LIB,
        "    if 5 not in params:\n",
        "    if False:\n",
    ),
    (
        "S18 genesis ConfigParam 5 not critical accepted",
        LIB,
        "if 10 not in params or 5 not in hashmap_items(params[10], 32):",
        "if False:",
    ),
    (
        "S19 genesis bootstrap balance not checked",
        LIB,
        "if held != bootstrap_nanotos:",
        "if False:",
    ),
    (
        "S20 genesis ConfigParam 15 not read back",
        LIB,
        '    if actual != expected:\n        raise TestnetError(f"ConfigParam 15 in the zero state',
        '    if False:\n        raise TestnetError(f"ConfigParam 15 in the zero state',
    ),
    ("S21 unbalanced ValueFlow accepted", LIB, "if credit != debit:", "if False:"),
    (
        "S22 top-up spends the owner's withdrawal money",
        EL,
        "if balance < value + OWNER_MESSAGE_NANOTOS + ops.FEE_ALLOWANCE_NANOTOS // 10:",
        "if False:",
    ),
    (
        "S23 genesis check not called",
        CO,
        '    bootstrap_check = lib.zero_state_bootstrap(\n        (built / "zerostate.boc").read_bytes(), wallet_nanotos, total_nanotos, schedule\n    )',
        "    bootstrap_check = {}",
    ),
    (
        "CH1 handover signature check ignored",
        HO,
        'if not verify_fn(member["pk"], payload, sig):',
        "if False:",
    ),
    (
        "CH2 handover certificate set source ignored",
        HO,
        'if source not in sets or sets[source]["boc"] != sets[k]["boc"]:',
        "if False:",
    ),
    (
        "CH3 handover session commitment ignored",
        HO,
        'if (cert.get("cc_seqno"), cert.get("validator_set_hash")) != (',
        'if False and (cert.get("cc_seqno"), cert.get("validator_set_hash")) != (',
    ),
    ("CH4 handover extended-term binding ignored", HO, "if not bound_ok[s]:", "if False:"),
    (
        "CH5 handover extended term refused (the old window rule)",
        HO,
        '            term = "extended_term"\n',
        '            term = "extended_term"\n            failures.append("outside the term")\n',
    ),
    (
        "CH6 handover block before its term accepted",
        HO,
        "if not isinstance(t, int) or isinstance(t, bool) or t < since:",
        "if not isinstance(t, int) or isinstance(t, bool):",
    ),
    (
        "CH7 handover full-id agreement ignored",
        HO,
        "if len(ids) == 1 and next(iter(ids))[2] == str(s):",
        "if True:",
    ),
    ("CH8 handover header field agreement ignored", HO, "if len(fields) != 1:", "if False:"),
    (
        "CH9 handover shard-top agreement ignored",
        HO,
        "if len(tops) == 1 and next(iter(tops)):",
        "if True:",
    ),
    (
        "CH10 handover set byte agreement ignored",
        HO,
        '        if len(cells) != 1 or None in cells:\n            failures.append(f"ConfigParam 34 at source',
        '        if False:\n            failures.append(f"ConfigParam 34 at source',
    ),
    (
        "CH11 handover set outside both post-handover sets accepted",
        HO,
        'if roles[s] == "other":',
        "if False:",
    ),
    (
        "CH12 handover role contiguity ignored",
        HO,
        'failures.append(\n                "handover roles are not contiguous',
        'print(\n                "handover roles are not contiguous',
    ),
    (
        "CH13 handover installing key block ignored",
        HO,
        'headers[last_out].get("is_key_block") is True and selected.get(first_in) == last_out',
        "True",
    ),
    ("CH14 handover zero state ignored", HO, 'full_id(info.get("init") or {}) != zero', "False"),
    (
        "CH15 handover global id ignored",
        HO,
        'if header.get("global_id") != global_id:',
        "if False:",
    ),
    (
        "CH16 handover wrong-term binding accepted",
        HO,
        'if boc != sets[selected[s]]["boc"]:',
        "if False:",
    ),
    (
        "CH17 handover substitution block unchecked",
        HO,
        "elif substitute_block(collection, k) != read_at:",
        "elif False:",
    ),
    (
        "CH18 handover supplement skipped",
        HO,
        "    supplement(collection, {n.name: n for n in nodes})",
        "    pass",
    ),
    ("CH19 handover pacing removed", HO, "            if gap > 0:", "            if False:"),
    ("CH20 handover allow-list removed", HO, "if method not in READ_ONLY_METHODS:", "if False:"),
    ("CH21 handover journal skipped", HO, "self.journal.write(", "(lambda entry: None)("),
    ("CH22 handover interval floor removed", HO, "if interval < MIN_INTERVAL:", "if False:"),
    (
        "CH23 handover collect boundary disagreement ignored",
        HO,
        "if len(centers) != 1:\n        raise HandoverError",
        "if False:\n        raise HandoverError",
    ),
    ("CH24 handover collect does not wait", HO, "while now() < args.boundary + 1:", "while False:"),
    ("CH25 handover certificate controls unchecked", HO, "if accepted != expect:", "if False:"),
    (
        "CH26 handover accepted control ignored",
        HO,
        'failures.append(f"control accepted: {name}")',
        "pass",
    ),
    (
        "CH27 handover session ids unchecked",
        HO,
        '        if len(ids) != 1:\n            failures.append(f"catchain seqno',
        '        if False:\n            failures.append(f"catchain seqno',
    ),
    ("CH28 handover collect zero state ignored", HO, 'if full_id(r["init"]) != zero:', "if False:"),
    (
        "CH29 handover verify boundary disagreement ignored",
        HO,
        "if len(centers) != 1:\n        failures.append",
        "if False:\n        failures.append",
    ),
    (
        "O56 checkpoint unexecuted receipt accepted",
        OPS,
        "if any(q >= end for q in receipts):",
        "if False:",
    ),
    ("O55 checkpoint head regression ignored", OPS, "if cp and (", "if False and ("),
    (
        "O42 checkpoint gate falls back to baseline",
        OPS,
        "if self.bootstrap_identity(wallet):\n            return self.verify_bootstrap_prefix(wallet)",
        "if False:\n            return self.verify_bootstrap_prefix(wallet)",
    ),
    (
        "O43 checkpoint anchor fetched",
        OPS,
        'if cursor == boundary or cursor is None or int(cursor["lt"]) == 0:',
        'if cursor is None or int(cursor["lt"]) == 0:',
    ),
    (
        "O44 checkpoint counter evidence omitted",
        OPS,
        '        if end - start > len(receipts):\n            raise Unknown("unexplained seqno interval: insufficient verified terminal receipts")\n        for seqno in range(start, end):\n            if seqno not in receipts:\n                raise Unknown(f"unexplained seqno {seqno}: no verified terminal receipt")',
        '        receipts = {q: receipts.get(q, {"id": "unverified", "seqno": q}) for q in range(end)}',
    ),
    ("O45 checkpoint duplicate receipts allowed", OPS, "if seqno in receipts:", "if False:"),
    (
        "O46 checkpoint timeouts treated as retention",
        OPS,
        'isinstance(cause, lib.RpcError)\n                        and cause.code == -32603\n                        and "lt not in db" in cause.message',
        "isinstance(cause, lib.RpcError)",
    ),
    (
        "O47 checkpoint pinned identity ignored",
        OPS,
        "if not data.end() or identity != expected or seqno == 0xFFFFFFFF:",
        "if False:",
    ),
    (
        "O48 checkpoint certificate digest ignored",
        OPS,
        'or cp.get("digest") != certificate_digest(body)',
        "or False",
    ),
    (
        "O49 checkpoint fork silently selected",
        OPS,
        '            if len(children) != 1:\n                raise Unknown("checkpoint certificates fork or have a missing parent")',
        '            if not children:\n                raise Unknown("missing parent")\n            if len(children) > 1:\n                certificates = {children[0]["digest"]: children[0]}',
    ),
    (
        "O50 checkpoint copied to retry",
        OPS,
        '                    "checkpoint",\n                    "gate_witness",\n                    "checkpoint_refusal",',
        "",
    ),
    ("O51 checkpoint dry run writes", OPS, "if not dry_run and cp:", "if cp:"),
    (
        "O52 checkpoint open operations ignored",
        OPS,
        'raise OperationRefused("checkpoint refuses an open bootstrap operation")',
        "pass",
    ),
    ("O53 checkpoint certificate terminal path omitted", OPS, 'entry["checkpoint"] = cp', "pass"),
    (
        "O54 checkpoint verification one node only",
        OPS,
        "return self.both(read)\n\n    def bootstrap_state",
        "return self.read_both(read)[0]\n\n    def bootstrap_state",
    ),
    (
        "O32 gate precedes plan creation",
        OPS,
        'record = self.journal.record(op_id)\n            if state_of(record) in (None, "planned"):',
        'record = self.begin(op_id, params)\n            if state_of(record) in (None, "planned"):',
    ),
    (
        "O33 matching unsigned funding intent ignored",
        OPS,
        '                if any(\n                    message.get("destination")',
        '                if False and any(\n                    message.get("destination")',
    ),
    (
        "O34 signing evidence ignored",
        OPS,
        "or any(line.get(key) is not None for key in signed_fields)",
        "or False",
    ),
    (
        "O35 abandoned history disagreement ignored",
        OPS,
        'if observations[0]["history"] != observations[1]["history"]:',
        "if False:",
    ),
    ("O36 aborted inbound intent ignored", OPS, 'messages.append(decoded["internal"])', "pass"),
    (
        "O37 last absence recheck removed",
        OPS,
        "# Recheck both validators immediately before the terminal append.\n            evidence = self.fund_plan_absence(record, since)",
        "# Recheck both validators immediately before the terminal append.\n            pass",
    ),
    (
        "O38 baseline hides planned transfer",
        OPS,
        'node.history(record["wallet"], None, since)}',
        'node.history(record["wallet"], self.journal.baseline(record["wallet"]), since)}',
    ),
    (
        "O39 nonfund plan abandoned",
        OPS,
        'if state_of(record) != "planned" or record.get("kind") not in ABANDONABLE_KINDS:',
        "if False:",
    ),
    (
        "O39b owner-fund plan cannot be abandoned",
        OPS,
        'ABANDONABLE_KINDS = ("fund", "owner-fund")',
        'ABANDONABLE_KINDS = ("fund",)',
    ),
    (
        "O39c an unexpired signed artifact does not block abandonment",
        OPS,
        '                if not all(now > artifact["valid_until"] for now in times):',
        "                if False:",
    ),
    (
        "O39d the operator copy is exported before the signed journal line",
        EL,
        "        op_id, params, sign, lambda decoded: None, prerequisites, expect, export=export\n",
        "        op_id, params, lambda seqno: (lambda b: (export(b, seqno), b)[1])(sign(seqno)), lambda decoded: None, prerequisites, expect\n",
    ),
    (
        "O40 stale validators accepted for abandonment",
        OPS,
        "if any(now < since for now in chain_times):",
        "if False:",
    ),
    (
        "O41 earlier transfer blocks abandonment",
        OPS,
        'relevant = [tx for tx in history if tx["utime"] >= since]',
        "relevant = history",
    ),
    (
        "DH11 masterchain lookup uses account prefix instead of full shard",
        OPS,
        "if int(wc) == lib.MASTERCHAIN:",
        "if False:",
    ),
    (
        "DH10 block pagination cursor omitted",
        OPS,
        'after = {"after_account": rows[-1]["account"], "after_lt": str(rows[-1]["lt"])}',
        "after = {}",
    ),
    (
        "DH1 busy recipient searched through account history",
        OPS,
        "found = self.read_both(lambda node: node.delivery(destination, message_hash, created_lt))",
        'found = self.read_both(lambda node: next((tx for tx in node.history(destination, None) if tx["in_kind"] == "internal" and tx["in_hash"] == message_hash), None))',
    ),
    (
        "DH2 wrong inbound message accepted",
        OPS,
        'if tx["in_kind"] == "internal" and tx["in_hash"] == message_hash:',
        'if tx["in_kind"] == "internal":',
    ),
    (
        "DH3 transaction page block identity ignored",
        OPS,
        'if page.get("id") != block or type(page.get("incomplete")) is not bool:',
        'if type(page.get("incomplete")) is not bool:',
    ),
    (
        "DH4 header block identity ignored",
        OPS,
        'if header.get("id") != block or int(header["end_lt"]) < cursor:',
        'if int(header["end_lt"]) < cursor:',
    ),
    (
        "DH5 reported transaction hash ignored",
        OPS,
        'b64hash(row["hash"]).hex(),',
        'lib.parse_boc(base64.b64decode(row["data"])).hash().hex(),',
    ),
    (
        "DH6 nonprogressing transaction page accepted",
        OPS,
        "if previous is not None and position <= previous:",
        "if False:",
    ),
    (
        "DH7 inclusive lookup boundary repeated",
        OPS,
        'cursor = int(header["end_lt"]) + 1',
        'cursor = int(header["end_lt"])',
    ),
    (
        "DH8 second validator delivery ignored",
        OPS,
        "if found[0] != found[1]:",
        "if False:",
    ),
    (
        "DH9 delivery block budget bypassed",
        OPS,
        "budget = DELIVERY_BLOCKS if budget is None else budget",
        "budget = DELIVERY_BLOCKS * 10 if budget is None else budget",
    ),
    (
        "ER9 changed current election parameters accepted",
        OPS,
        "if not c.end() or values != expected:",
        "if not c.end():",
    ),
    (
        "ER10 custom profile ignored",
        OPS,
        'ceiling = lib.load_profile(self.profile_path)["elections"].get("stake_order_nanotos")',
        'ceiling = lib.load_profile()["elections"].get("stake_order_nanotos")',
    ),
    (
        "ER11 current time substituted for the message time",
        OPS,
        'or not active - start_before <= tx["utime"] < active - end_before',
        "or not active - start_before <= int(self.clock()) < active - end_before",
    ),
    (
        "ER1 election message classification disabled",
        OPS,
        '        path = self.ceremony / "pools.json"',
        '        return None\n        path = self.ceremony / "pools.json"',
    ),
    (
        "ER2 a message to a different pool accepted",
        OPS,
        'or message["destination"] != matches[0]',
        "or False",
    ),
    (
        "ER3 stake order value ignored",
        OPS,
        '        if not 0 < message["value"] <= ceiling:\n            return None\n\n        genesis',
        "        if False:\n            return None\n\n        genesis",
    ),
    (
        "ER4 additional outbound message ignored",
        OPS,
        'if len(tx["out"]) != 1:',
        'if not tx["out"]:',
    ),
    (
        "ER5 a stake order outside the election window accepted",
        OPS,
        'or not active - start_before <= tx["utime"] < active - end_before',
        "or False",
    ),
    (
        "ER6 current window trusts only first validator",
        OPS,
        "elected_for, start_before, end_before, _held = self.both(window)",
        "elected_for, start_before, end_before, _held = window(self.nodes[0])",
    ),
    (
        "ER7 current profile substituted for genesis",
        OPS,
        'expected = tuple(genesis["election_params"][name] for name in lib.ELECTION_PARAM_NAMES)',
        'expected = tuple(lib.load_profile(self.profile_path)["genesis"]["election_params"][name] for name in lib.ELECTION_PARAM_NAMES)',
    ),
    (
        "ER8 unknown message opcode treated as new stake",
        OPS,
        "if opcode not in kinds:\n                return None",
        "if opcode not in kinds:\n                opcode = 0x4E73744B",
    ),
    (
        "ET1 recover-stake classification removed",
        OPS,
        '                0x47657424: ("recover-stake", 200_000_000),',
        "",
    ),
    (
        "ET2 update-validator-set classification removed",
        OPS,
        '                0x06: ("update-validator-set", 200_000_000),',
        "",
    ),
    (
        "ET3 validator-deposit classification removed",
        OPS,
        '                0x04: ("validator-deposit", 10_000_000_000),',
        "",
    ),
    (
        "ET4 process-withdraw-requests classification removed",
        OPS,
        '                0x02: ("process-withdraw-requests", 200_000_000),',
        "",
    ),
    (
        "ET5 maintenance value ceiling ignored",
        OPS,
        'if not b.end() or not 0 < message["value"] <= ceiling:',
        "if not b.end():",
    ),
    (
        "ET6 maintenance trailing fields ignored",
        OPS,
        'if not b.end() or not 0 < message["value"] <= ceiling:',
        'if not 0 < message["value"] <= ceiling:',
    ),
    (
        "ET7 withdraw queue batch bound ignored",
        OPS,
        'if kind == "process-withdraw-requests" and b.bits(8) != 8:',
        'if kind == "process-withdraw-requests" and b.bits(8) < 0:',
    ),
    (
        "ET8 pool message StateInit allowed",
        OPS,
        "if init is not None:\n                return None\n            opcode = b.bits(32)",
        "if False:\n                return None\n            opcode = b.bits(32)",
    ),
    (
        "ET9 query id not decoded",
        OPS,
        "query_id = b.bits(64)\n            # runner.rs",
        "query_id = 0\n            b.bits(64)\n            # runner.rs",
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
        '            if (\n                leaves(tx, wallet)\n                and tx["hash"] not in explained\n                and self.election_message(wallet, tx) is None\n            ):\n                described',
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
        "    pool = pool_address(single_nominator_code(args.tos_root), owner, operator)",
        "    pool = pool_address(single_nominator_code(args.tos_root), operator, operator)",
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
        '        require(f"activate-owner-{name}")\n        verify_pool_both(operations, args.tos_root, pool, owner, operator)\n',
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
        "E10 readiness not checked",
        EL,
        '    staking_readiness(operations, host, pool, int(elections["stake_tos"]) * NANO)',
        "    pass",
    ),
    (
        "E13 host pool configuration not compared",
        EL,
        '    elif (entry.get("address"), entry.get("owner")) != (pool, owner):',
        "    elif False:",
    ),
    (
        "E15 the node's staking account not compared",
        EL,
        '    if bound != pool.split(":")[1]:',
        "    if False:",
    ),
    (
        "E21 a pool short of two stakes is ready",
        EL,
        "    if available < 2 * stake_nanotos:",
        "    if False:",
    ),
    (
        "E17 the host's operator wallet not compared with the recorded one",
        EL,
        "    if on_host != operator:",
        "    if False:",
    ),
    (
        "E18 a pool genesis does not name is onboarded",
        EL,
        '    if pool.split(":")[1] not in {r.get("validator_id") for r in records}:',
        "    if False:",
    ),
    (
        "E19 a recorded pool that does not derive is trusted",
        EL,
        '    if pool != expected:\n        raise lib.TestnetError(\n            f"{POOLS_FILE} records',
        '    if False:\n        raise lib.TestnetError(\n            f"{POOLS_FILE} records',
    ),
    (
        "E20 a basechain operator wallet accepted for a pool",
        EL,
        '    if not operator.startswith("-1:"):\n        raise lib.TestnetError(f"the operator wallet',
        '    if False:\n        raise lib.TestnetError(f"the operator wallet',
    ),
    (
        "ER12 stake order algorithm not checked",
        OPS,
        "if stake <= 0 or b.bits(16) != MLDSA44_ALGORITHM_ID:",
        "if stake <= 0 or b.bits(16) < 0:",
    ),
    (
        "ER13 stake order trailing data accepted",
        OPS,
        "                b.take_ref()  # signature\n                if not b.end():\n                    return None",
        "                b.take_ref()  # signature",
    ),
]


M += [
    (
        "N1 the record read before the lock (the original race)",
        OPS,
        '        with self.journal.lock(wallet):\n            op_id = self.journal.newest(step)\n            record = self.journal.record(op_id)\n            if state_of(record) in (None, "planned"):\n                self.gate(wallet, op_id)\n            record = self.begin(op_id, params)\n',
        '        op_id = self.journal.newest(step)\n        record = self.journal.record(op_id) or self.begin(op_id, params)\n        with self.journal.lock(wallet):\n            if state_of(record) in (None, "planned"):\n                self.gate(wallet, op_id)\n',
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
    ("E16 operator subwallet guessed", EL, "    return data[2]", "    return 0"),
]


M += [
    (
        "R28 directory not fsynced (append)",
        OPS,
        "    fsync_dir(path.parent)\n\n\ndef publish_new",
        "\n\ndef publish_new",
    ),
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
        "H3 a record naming no recorded pool accepted",
        CO,
        '        if record["validator_id"] not in staking:',
        "        if False:",
    ),
    (
        "H4 a used ceremony directory accepted",
        CO,
        "    if extra:\n        raise",
        "    if False:\n        raise",
    ),
]


M += [
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
]


NETWORK = W.parent / "production/network_check.py"
M += [
    (
        "NC1 foreign zero state accepted",
        NETWORK,
        'if full_id(info["init"]) != expected_zero:',
        "if False:",
    ),
    (
        "NC2 divergent full block ids accepted",
        NETWORK,
        "if len(set(ids.values())) != 1:",
        "if False:",
    ),
    ("NC3 stale heads called healthy", NETWORK, "if newest_age > args.max_age:", "if False:"),
    ("NC4 foreign header global id accepted", NETWORK, "    if foreign:\n", "    if False:\n"),
    (
        "NC5 Elector full-set commitment bypassed",
        NETWORK,
        'matching = [p for p in elector["past"] if p["hash"] == vset["hash"]]',
        'matching = [p for p in elector["past"] if len(p["members"]) == vset["total"]][:1]',
    ),
    (
        "NC6 frozen identities and weights ignored",
        NETWORK,
        'actual == expected, "Config validator members/weights differ from Elector frozen result"',
        'True, "Config validator members/weights differ from Elector frozen result"',
    ),
    (
        "NC7 consensus proof verification bypassed",
        NETWORK,
        "        a, r = json.dumps(anchor).encode(), json.dumps(request).encode()",
        '        return {"status": "verified", "target": request["target"]}\n        a, r = json.dumps(anchor).encode(), json.dumps(request).encode()',
    ),
    (
        "NC8 invalid proof route answer downgraded to equality",
        NETWORK,
        'if exc.code != -32601 or exc.reason != "METHOD_NOT_FOUND":',
        "if False:",
    ),
    (
        "NC9 initial-set commitment ignored",
        NETWORK,
        'require(current["hash"] == initial_hash, "unelected current set differs from initial set")',
        'require(True, "unelected current set differs from initial set")',
    ),
    (
        "NC10 version floor bypassed",
        NETWORK,
        'require(version >= args.min_version, "ConfigParam 8 version below required minimum")',
        'require(True, "ConfigParam 8 version below required minimum")',
    ),
    (
        "NC11 expected AUTH tag bypassed",
        NETWORK,
        'policy["network"] == hash_bytes(args.expected_auth_tag),',
        "True,",
    ),
    (
        "NC12 PQ key id not rederived",
        NETWORK,
        'require(key_id == derived, "validator key id differs from public key")',
        'require(True, "validator key id differs from public key")',
    ),
    (
        "NC13 identical current and previous terms accepted",
        NETWORK,
        'previous["since"] < current["since"] and previous["until"] <= current["since"],',
        "True,",
    ),
    (
        "NC14 authenticated header timestamp ignored",
        NETWORK,
        'require(\n                int(verified["target"]["gen_utime"]) == int(header["gen_utime"]),',
        "require(\n                True,",
    ),
]


M += [
    (
        "NC15 historical lookup uses the wrong time selector",
        NETWORK,
        'unixtime=decode_set(sets[34])["since"] - 1',
        'utime=decode_set(sets[34])["since"] - 1',
    )
]


M += [
    (
        "NC16 mandatory AUTH skipped on an older version",
        NETWORK,
        "or 48 in lib.hashmap_items(sets[9], 32)",
        "or False",
    )
]


M += [
    (
        "NC17 configured Elector locator bypassed",
        NETWORK,
        "elector_addr = elector_address(sets[1])",
        "elector_addr = ELECTOR",
    ),
    (
        "NC18 inconsistent held zero anchors accepted",
        NETWORK,
        'require(anchor["seqno"] != 0 or anchor == zero, "conflicting zero and init anchors")',
        'require(True, "conflicting zero and init anchors")',
    ),
    (
        "NC19 held init block equality ignored",
        NETWORK,
        'full_id(held["id"]) == full_id(identity["anchor"]),',
        "True,",
    ),
    (
        "NC20 retained election accepted instead of active result",
        NETWORK,
        """    matched_ids = [p["election_id"] for p in matching]
    require(
        vset["hash"] == elector["active_hash"],
        f"validator set commitment matches elections {matched_ids}, not Elector active election "
        f"{elector['active_id']} ({elector['active_hash']})",
    )
    matching = [p for p in matching if p["election_id"] == elector["active_id"]]""",
        "",
    ),
    (
        "NC21 active election id ignored",
        NETWORK,
        '    matching = [p for p in matching if p["election_id"] == elector["active_id"]]',
        "",
    ),
    (
        "NC22 retained previous election bypasses historical active binding",
        NETWORK,
        '    raise NetworkError("previous set requires its historical active Elector result")',
        """    record = next(p for p in elector["past"] if p["hash"] == previous["hash"])
    return {"current": compare_elected(current, elector), "previous": compare_elected(
        previous, dict(elector, active_id=record["election_id"], active_hash=record["hash"]))}""",
    ),
    (
        "NC23 initial current set uses only the first proof source",
        NETWORK,
        'verifier, rpc, sources, identity["anchor"], first_id, [34], now(), elector_addr',
        'verifier, rpc, [proof_url], identity["anchor"], first_id, [34], now(), elector_addr',
    ),
    (
        "NC24 historical initial set uses only the first proof source",
        NETWORK,
        '                    sources,\n                    identity["anchor"],',
        '                    [proof_url],\n                    identity["anchor"],',
    ),
    (
        "NC25 proof transport failure prevents source fallback",
        NETWORK,
        '        except OSError as exc:\n            unavailable.append({"url": url, "reason": str(exc)})',
        "        except OSError:\n            raise",
    ),
    (
        "NC26 verification failure retried as a transport failure",
        NETWORK,
        '        except OSError as exc:\n            unavailable.append({"url": url, "reason": str(exc)})',
        '        except (OSError, NetworkError) as exc:\n            unavailable.append({"url": url, "reason": str(exc)})',
    ),
    # Reads at a block a node has not applied yet: bounded retry, narrow classification.
    (
        "NA1 not-applied retry without a bound",
        LIB,
        "                if remaining <= 0:\n                    raise",
        "                if False:\n                    raise",
    ),
    (
        "NA2 not-applied retry bound multiplied",
        LIB,
        "deadline = now() + NOT_APPLIED_RETRY_SECONDS",
        "deadline = now() + 10 * NOT_APPLIED_RETRY_SECONDS",
    ),
    (
        "NA3 not-applied delay never grows",
        LIB,
        "delay = min(delay * 2, NOT_APPLIED_MAX_DELAY)",
        "delay = min(delay, NOT_APPLIED_MAX_DELAY)",
    ),
    (
        "NA4 not-applied read not retried",
        LIB,
        "                if not block_not_applied(exc):\n                    raise",
        "                if True:\n                    raise",
    ),
    (
        "NA5 every node error retried",
        LIB,
        "                if not block_not_applied(exc):\n                    raise",
        "                if False:\n                    raise",
    ),
    (
        "NA6 classification ignores the reason",
        LIB,
        '        and exc.reason == "UPSTREAM_UNAVAILABLE"\n',
        "",
    ),
    ("NA7 classification ignores the retryable flag", LIB, "        and exc.retryable\n", ""),
    (
        "NA8 classification ignores the message",
        LIB,
        "        and NOT_APPLIED_TEXT.search(exc.message) is not None\n",
        "",
    ),
    (
        "NA9 classification ignores error 651",
        LIB,
        r'NOT_APPLIED_TEXT = re.compile(r"\bError : 651 : .*\bis not applied\b", re.DOTALL)',
        r'NOT_APPLIED_TEXT = re.compile(r"\bis not applied\b", re.DOTALL)',
    ),
    (
        "NA10 sendBoc retried",
        LIB,
        "        if method in NEVER_RETRIED_METHODS:\n",
        "        if False:\n",
    ),
    (
        "NA11 a wrapped call wrapped again",
        LIB,
        'if getattr(rpc, "retries_not_applied", False):',
        "if False:",
    ),
    (
        "NA12 operations nodes read without the retry",
        OPS,
        "        self._rpc = lib.retrying_reads(rpc)",
        "        self._rpc = rpc",
    ),
    (
        "NA13 load chain reads without the retry",
        EL,
        "        self._rpc = lib.retrying_reads(rpc)",
        "        self._rpc = rpc",
    ),
    (
        "FR1 provenance tag and commit ignored",
        FETCH,
        '        if record.get(key) != expected:\n            raise Refused(\n                f"release-provenance.json records {key}',
        '        if False:\n            raise Refused(\n                f"release-provenance.json records {key}',
    ),
    (
        "FR2 artifact build commit ignored",
        FETCH,
        'if entry.get("head_sha") != rev:',
        "if False:",
    ),
    (
        "FR3 file absent from SHA256SUMS accepted",
        FETCH,
        "            if name not in sums:\n                raise Refused(",
        "            if name not in sums:\n                continue\n                raise Refused(",
    ),
    (
        "FR4 SHA256SUMS digest ignored",
        FETCH,
        "if sums[name] != actual[name]:",
        "if False:",
    ),
    (
        "FR5 artifact zip digest ignored",
        FETCH,
        "if actual[archive_name] != recorded:",
        "if False:",
    ),
    (
        "FR6 binary not bound to the artifact zip",
        FETCH,
        "if member != actual[asset]:",
        "if False:",
    ),
    (
        "FR7 existing out overwritten",
        FETCH,
        '    if out.exists() or out.is_symlink():\n        raise Refused(f"{out} already exists',
        '    if False:\n        raise Refused(f"{out} already exists',
    ),
    (
        "FR8 missing asset tolerated",
        FETCH,
        "        if error.code == 404:\n            raise Refused(",
        "        if error.code == 404:\n            return\n            raise Refused(",
    ),
    (
        "FR9 check-release result ignored",
        FETCH,
        '        if result.returncode != 0:\n            raise Refused(f"check-release.sh',
        '        if False:\n            raise Refused(f"check-release.sh',
    ),
    (
        "FR10 malformed SHA256SUMS line accepted",
        FETCH,
        '        if not match:\n            raise Refused(f"SHA256SUMS line',
        '        if not match:\n            continue\n            raise Refused(f"SHA256SUMS line',
    ),
    (
        "FR11 plain http off loopback accepted",
        FETCH,
        'if parsed.scheme == "https" or (parsed.scheme == "http" and loopback):',
        'if parsed.scheme in ("https", "http"):',
    ),
    (
        "FR12 node artifact workflow ignored",
        FETCH,
        'if entry.get("workflow") != NODE_WORKFLOW:',
        "if False:",
    ),
    (
        "FR13 build record not bound to the zip",
        FETCH,
        '        members[build_info] = "BUILD-INFO"\n',
        "",
    ),
    (
        "FR14 build record revision ignored",
        FETCH,
        'if fields.get("tos_revision") != rev:',
        "if False:",
    ),
    (
        "FR15 build record binary digests ignored",
        FETCH,
        "if listed.get(name) != digest:",
        "if False:",
    ),
    (
        "FR16 missing library accepted",
        FETCH,
        "    if missing:\n",
        "    if False:\n",
    ),
    ("FR17 old glibc accepted", FETCH, "if glibc < MIN_GLIBC:", "if False:"),
    (
        "FR18 reported commit ignored",
        FETCH,
        'if f"Commit: {rev}" not in ran.stdout:',
        "if False:",
    ),
    (
        "FR19 runtime check skipped",
        FETCH,
        "glibc = check_runnable(stage, binaries, rev)",
        'glibc = "2.39"',
    ),
    (
        "FR20 loader failure ignored",
        FETCH,
        'if loader.returncode != 0 or "not a dynamic executable" in output:',
        "if False:",
    ),
    (
        "FR21 missing package not named",
        FETCH,
        '    "libjemalloc.so.2": "libjemalloc2",\n',
        "",
    ),
    ("FR22 libgsl27 not named", FETCH, '    "libgsl.so.27": "libgsl27",\n', ""),
    ("FR23 libblas3 not named", FETCH, '    "libblas.so.3": "libblas3",\n', ""),
    (
        "FR24 libreadline8t64 not named",
        FETCH,
        '    "libreadline.so.8": "libreadline8t64",\n',
        "",
    ),
    ("FR25 libatomic1 not named", FETCH, '    "libatomic.so.1": "libatomic1",\n', ""),
    (
        "FR26 build record needed lines not compared",
        FETCH,
        "        check_needed(stage, binaries, needed)\n",
        "",
    ),
    ("FR27 needed mismatch accepted", FETCH, "if actual != needed[name]:", "if False:"),
    (
        "FR28 binary without a needed line accepted",
        FETCH,
        "        if name not in needed:\n            raise",
        "        if name not in needed:\n            continue\n            raise",
    ),
    (
        "FR29 a binary's missing libraries dropped",
        FETCH,
        "        if absent:\n",
        "        if False:\n",
    ),
    (
        "FR30 unknown missing library not named",
        FETCH,
        "        if unknown:\n",
        "        if False:\n",
    ),
    ("FR31 missing readelf not named", FETCH, "    if readelf is None:\n", "    if False:\n"),
    (
        "RR1 rpc install role without the services",
        INSTALL,
        "tos-pq-consensus-key \\\n      tos-rpc tos-wallet-index ;;",
        "tos-pq-consensus-key ;;",
    ),
    (
        "RR2 rpc build without tos-wallet-index",
        BUILD,
        "tos-pq-consensus-key tos-rpc tos-wallet-index) ;;",
        "tos-pq-consensus-key tos-rpc) ;;",
    ),
    (
        "RR3 rpc fetch without tos-rpc",
        FETCH,
        '        "tos-pq-consensus-key",\n        "tos-rpc",\n',
        '        "tos-pq-consensus-key",\n',
    ),
    (
        "RR4 preflight ignores running rpc services",
        INSTALL,
        "tos-testnet-dht tos-testnet-wallet-index tos-testnet-rpc)\n",
        "tos-testnet-dht)\n",
    ),
    (
        "RR5 rpc activation skips the binary check",
        INSTALL,
        "  require_role_binaries\n  id tos-rpc >/dev/null 2>&1 || die",
        "  id tos-rpc >/dev/null 2>&1 || die",
    ),
    (
        "RR6 index source database writable",
        INDEX_UNIT,
        "ReadOnlyPaths=/var/lib/tos/fullnode\nReadWritePaths=/var/lib/tos-wallet-index\n",
        "ReadWritePaths=/var/lib/tos-wallet-index /var/lib/tos/fullnode\n",
    ),
    (
        "RR7 index listens on every address",
        INDEX_UNIT,
        "--listen 127.0.0.1:8083",
        "--listen 0.0.0.0:8083",
    ),
    (
        "RR8 index started before the full node",
        INDEX_UNIT,
        "After=network-online.target time-sync.target tos-testnet-fullnode.service\n",
        "After=network-online.target time-sync.target\n",
    ),
    (
        "RR9 public RPC writable by default",
        RPC_UNIT,
        "Environment=TOS_RPC_MODE=--readonly\n",
        "Environment=TOS_RPC_MODE=--submission-address 127.0.0.1:8081\n",
    ),
    (
        "RR10 public RPC listens on every address",
        RPC_UNIT,
        "--listen 127.0.0.1:8080",
        "--listen 0.0.0.0:8080",
    ),
    (
        "RR11 public RPC started before the index",
        RPC_UNIT,
        "tos-testnet-fullnode.service tos-testnet-wallet-index.service\n",
        "tos-testnet-fullnode.service\n",
    ),
    (
        "RR12 public RPC writes the node database",
        RPC_UNIT,
        "InaccessiblePaths=-/var/lib/tos -/var/lib/tos-wallet-index -/var/lib/tos-ctl\n",
        "ReadWritePaths=/var/lib/tos/fullnode\n",
    ),
    # tosctl's master wallet (init-operator.sh, testnet-operator.py master-wallet).
    (
        "MW1 a different master wallet is kept",
        OPERATOR,
        '    if current == MASTER_WALLET:\n        return "keep"',
        '    if True:\n        return "keep"',
    ),
    (
        "MW2 an existing master wallet is set again",
        OPERATOR,
        '    if current is None:\n        return "set"',
        '    if True:\n        return "set"',
    ),
    (
        "MW5 the refusal prints the configured record",
        OPERATOR,
        "f\"a different master wallet is configured (fields that differ: {', '.join(differ)}; \"",
        "f\"a different master wallet is configured ({json.dumps(current)}; fields that differ: {', '.join(differ)}; \"",
    ),
    (
        "MW3 init-operator.sh replaces the master wallet",
        W / "scripts/init-operator.sh",
        "--secret-name master-wallet-secret --version V3R2 >/dev/null",
        "--secret-name master-wallet-secret --version V3R2 --force >/dev/null",
    ),
    (
        "MW4 init-operator.sh skips the required check",
        W / "scripts/init-operator.sh",
        'master-wallet --config "$CONFIG_PATH" --require >/dev/null',
        'master-wallet --config "$CONFIG_PATH" >/dev/null',
    ),
    (
        "RR13 rpc liteserver not on loopback",
        OPERATOR,
        'LOOPBACK = "127.0.0.1"',
        'LOOPBACK = "0.0.0.0"',
    ),
    (
        "RR14 rpc liteserver config from the placeholder",
        OPERATOR,
        "    if lib.is_pregenesis(global_config):\n",
        "    if False:\n",
    ),
    (
        "RR15 rpc liteserver key unchecked",
        OPERATOR,
        "    if len(liteserver_pub) != 36 or not liteserver_pub.startswith(",
        "    if False and not liteserver_pub.startswith(",
    ),
    (
        "RR16 retirement keeps the retired index",
        W / "scripts/retire-host.sh",
        "rm -rf --one-file-system /var/lib/tos-ctl /var/lib/tos-wallet-index\n",
        "rm -rf --one-file-system /var/lib/tos-ctl\n",
    ),
    (
        "RR17 preflight running-service guard removed",
        INSTALL,
        '  for unit in "${NODE_UNITS[@]}"; do\n    if systemctl is-active --quiet "$unit"; then die',
        '  for unit in "${NODE_UNITS[@]}"; do\n    if false; then die',
    ),
    (
        "RR18 prepare writes before its preflight",
        INSTALL,
        "  prepare) preflight; prepare ;;",
        "  prepare) prepare; preflight ;;",
    ),
    (
        "RR19 binaries writes before its preflight",
        INSTALL,
        "  binaries) preflight; binaries ;;",
        "  binaries) binaries; preflight ;;",
    ),
    (
        "RR20 preflight ignores a running DHT node",
        INSTALL,
        "NODE_UNITS=(tos-testnet-validator tos-testnet-fullnode tos-testnet-dht tos-",
        "NODE_UNITS=(tos-testnet-validator tos-testnet-fullnode tos-",
    ),
    (
        "RR21 index not part of the full node",
        INDEX_UNIT,
        "PartOf=tos-testnet-fullnode.service\n",
        "",
    ),
    (
        "RR22 public RPC not part of the index",
        RPC_UNIT,
        "PartOf=tos-testnet-wallet-index.service\n",
        "",
    ),
    (
        "RR23 index not started with the full node",
        INDEX_UNIT,
        "WantedBy=tos-testnet-fullnode.service\n",
        "",
    ),
    (
        "RR24 public RPC not started with the index",
        RPC_UNIT,
        "WantedBy=tos-testnet-wallet-index.service\n",
        "",
    ),
    (
        "RR25 index start condition removed",
        INDEX_UNIT,
        "ExecCondition=/bin/systemctl is-active --quiet tos-testnet-fullnode.service\n",
        "",
    ),
    (
        "RR26 public RPC start condition removed",
        RPC_UNIT,
        "ExecCondition=/bin/systemctl is-active --quiet tos-testnet-wallet-index.service\n",
        "",
    ),
    (
        "RR27 index start condition back to ExecStartPre",
        INDEX_UNIT,
        "ExecCondition=/bin/systemctl is-active --quiet tos-testnet-fullnode.service\n",
        "ExecStartPre=/bin/systemctl is-active --quiet tos-testnet-fullnode.service\n",
    ),
    (
        "RR28 public RPC start condition as ExecStartPre",
        RPC_UNIT,
        "ExecCondition=/bin/systemctl is-active --quiet tos-testnet-wallet-index.service\n",
        "ExecStartPre=/bin/systemctl is-active --quiet tos-testnet-wallet-index.service\n",
    ),
    (
        "RR29 guide prepares the rpc role after activating the full node",
        W / "OPERATOR.md",
        "sudo /opt/tos-testnet/scripts/install-node.sh prepare --role rpc\n"
        "sudo /opt/tos-testnet/scripts/install-node.sh activate --role fullnode \\\n"
        "  --global-config <GLOBAL_CONFIG_JSON> --sha256 <PUBLISHED_SHA256> "
        "--genesis <PUBLISHED_GENESIS_DIRECTORY>\n",
        "sudo /opt/tos-testnet/scripts/install-node.sh activate --role fullnode \\\n"
        "  --global-config <GLOBAL_CONFIG_JSON> --sha256 <PUBLISHED_SHA256> "
        "--genesis <PUBLISHED_GENESIS_DIRECTORY>\n"
        "sudo /opt/tos-testnet/scripts/install-node.sh prepare --role rpc\n",
    ),
    (
        "RR30 test prefix accepted from root",
        INSTALL,
        'if [ -n "$PREFIX" ] && [ "$(/usr/bin/id -u)" = 0 ]; then die',
        "if false; then die",
    ),
    (
        "RR31 test prefix guard reads the injectable EUID",
        INSTALL,
        'if [ -n "$PREFIX" ] && [ "$(/usr/bin/id -u)" = 0 ]; then die',
        'if [ -n "$PREFIX" ] && [ "$EUID" = 0 ]; then die',
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
        mutated = path.read_text().replace(old, new)
        if path.suffix == ".py":
            try:
                ast.parse(mutated, filename=str(path))
            except SyntaxError as exc:
                uncompiled.append(f"{label}: {exc.msg} at line {exc.lineno}")
        elif path.suffix == ".sh":
            check = subprocess.run(["bash", "-n"], input=mutated, capture_output=True, text=True)
            if check.returncode != 0:
                uncompiled.append(f"{label}: bash -n: {check.stderr.strip()}")
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
