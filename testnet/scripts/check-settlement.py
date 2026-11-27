#!/usr/bin/env python3
"""Check complete, checkpoint-bound settlement observations; never sign or broadcast.

Collectors and funded re-report senders are explicit adapters. See settlement-monitor.md.
Exit 0: clear, 1: alarms, 2: incomplete/invalid evidence (also an alarm).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCHEMA = "tos-settlement-observation/1"
MAX_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 20000
HEX = re.compile(r"[0-9a-f]{64}")
EMERGENCIES = {
    "bridge_frozen",
    "token_paused",
    "destroyed_funds",
    "token_deprecated",
    "token_upgrade",
    "unexplained_decrease",
    "backing_shortfall",
}


class Invalid(ValueError):
    pass


def number(value, name, maximum=(1 << 256) - 1):
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,77}", value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= maximum:
        raise Invalid(f"invalid {name}")
    return value


def text(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.:/-]{1,160}", value):
        raise Invalid(f"invalid {name}")
    return value


def flag(obj, key):
    value = obj[key]
    if type(value) is not bool:
        raise Invalid(f"invalid {key}")
    return value


def items(obj, key):
    value = obj[key]
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise Invalid(f"invalid {key}")
    return value


def unique(rows, key):
    values = [text(str(row[key]), key) for row in rows]
    if len(values) != len(set(values)):
        raise Invalid(f"duplicate {key}")
    return set(values)


def digest(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise Invalid("invalid checkpoint hash")
    return value


def checkpoint(obj, now, age):
    digest(obj["hash"])
    height = number(obj["height"], "height", (1 << 64) - 1)
    stamp = number(obj["utime"], "utime", (1 << 64) - 1)
    if stamp > now + 5 or now - stamp > age:
        raise Invalid("stale or future checkpoint")
    return height


def alarm(rows, asset, actor, code, **facts):
    rows.append(dict(asset=asset, actor=actor, code=code, facts=facts))


def evaluate(policy, observation, previous=None, now=None):
    """All amounts are integer atomic units. A malformed asset refuses the entire sample."""
    now = int(time.time()) if now is None else now
    if policy["schema"] != "tos-settlement-policy/1" or observation["schema"] != SCHEMA:
        raise Invalid("unsupported schema")
    network = digest(policy["network"])
    if observation["network"] != network or not flag(observation, "complete"):
        raise Invalid("wrong network or incomplete observation")
    age = number(policy["max_age_seconds"], "max_age_seconds", 3600)
    if age == 0:
        raise Invalid("zero freshness limit")
    height = checkpoint(observation["checkpoint"], now, age)
    checkpoint(observation["source_checkpoint"], now, age)
    limits = dict(policy["thresholds"])
    for key in (
        "payout_blocks",
        "returned_seconds",
        "returned_count",
        "refusals_count",
        "rereport_clear_blocks",
        "rereport_clear_seconds",
    ):
        limits[key] = number(limits[key], key)
        if limits[key] == 0:
            raise Invalid("zero threshold")
    if number(limits["refusals_count"], "refusals_count") > 32:
        raise Invalid("refusal threshold exceeds contract limit")
    configured = items(policy, "assets")
    assets = items(observation, "assets")
    if not configured or unique(configured, "id") != unique(assets, "id"):
        raise Invalid("missing or unconfigured asset")
    pins = {a["id"]: a for a in configured}
    old = {}
    if previous is not None:
        if previous["network"] != network or previous["schema"] != SCHEMA:
            raise Invalid("previous observation identity differs")
        for key in ("checkpoint", "source_checkpoint"):
            p, c = previous[key], observation[key]
            if c["height"] < p["height"] or (c["height"] == p["height"] and c["hash"] != p["hash"]):
                raise Invalid("checkpoint rollback or conflict")
        if observation["checkpoint"]["height"] == previous["checkpoint"]["height"]:
            raise Invalid("checkpoint did not advance")
        old = {a["id"]: a for a in previous["assets"]}
        if set(old) != set(pins):
            raise Invalid("asset inventory changed; review policy separately")
    rows, requests, records = [], [], []
    recognition = items(observation, "recognition")
    unique(recognition, "master")
    if len(recognition) > 16:
        alarm(rows, "network", None, "recognition_size", count=len(recognition), limit=16)
    bridge = text(observation["bridge_address"], "bridge_address")
    for record in recognition:
        text(record["bridge"], "recognition bridge")
        status = number(record["status"], "status", 3)
        if status == 0:
            raise Invalid("unknown recognition status")
        parameter = number(record["bridge_config_param"], "bridge_config_param")
        if parameter == 79 and record["bridge"] != bridge and status == 1:
            alarm(rows, record["master"], None, "active_old_bridge")
    for asset in assets:
        aid = asset["id"]
        pin = pins[aid]
        for key in ("master", "source_token", "implementation"):
            text(pin[key], key)
            text(asset[key], key)
        if number(pin["occupancy_percent"], "occupancy_percent", 100) == 0:
            raise Invalid("zero occupancy threshold")
        if pin["symbol"] not in ("USDC", "USDT") or asset["master"] != pin["master"]:
            raise Invalid("asset pin mismatch")
        if asset["source_token"] != pin["source_token"]:
            raise Invalid("source token pin mismatch")
        actors = items(asset, "actors")
        expected = items(pin, "actors")
        if unique(actors, "id") != unique(expected, "id"):
            raise Invalid("actor inventory incomplete")
        actor_pins = {a["id"]: a for a in expected}
        liability = 0
        for actor in actors:
            actor_id = actor["id"]
            ap = actor_pins[actor_id]
            text(ap["own_wallet"], "own_wallet")
            text(actor["own_wallet"], "own_wallet")
            if number(ap["wallet_tos_floor"], "wallet_tos_floor") == 0:
                raise Invalid("zero wallet floor")
            if actor["own_wallet"] != ap["own_wallet"]:
                raise Invalid("own wallet mismatch")
            payouts = items(actor, "payouts")
            returned = items(actor, "returned")
            unique(payouts, "id")
            unique(returned, "id")
            native = actor["native_ledger"]
            ledger = actor["token_ledger"]
            liability += sum(
                number(ledger[k], k)
                for k in ("pending", "refundable", "returned", "in_flight", "revenue")
            )
            if number(actor["mismatch_events"], "mismatch_events"):
                alarm(rows, aid, actor_id, "outcome_mismatch")
            if sum(number(p["amount"], "amount") for p in payouts) != number(
                ledger["in_flight"], "in_flight"
            ):
                raise Invalid("incomplete payout inventory")
            if len(returned) != number(native["returned_count"], "returned_count"):
                raise Invalid("incomplete returned inventory")
            if sum(
                number(r["amount"], "amount")
                for r in returned
                if number(r["paying"], "paying", (1 << 64) - 1) == 0
            ) != number(ledger["returned"], "returned"):
                raise Invalid("returned liability differs")
            for p in payouts:
                created = number(p["created_height"], "created_height")
                if created > height:
                    raise Invalid("future payout")
                if height - created > limits["payout_blocks"]:
                    alarm(
                        rows, aid, actor_id, "payout_age", payout=p["id"], blocks=height - created
                    )
            if len(returned) >= limits["returned_count"]:
                alarm(rows, aid, actor_id, "returned_count", count=len(returned))
            for r in returned:
                paying = number(r["paying"], "paying", (1 << 64) - 1)
                if paying and not any(
                    number(p["id"], "payout id") == paying
                    and number(p["amount"], "payout amount") == number(r["amount"], "amount")
                    for p in payouts
                ):
                    raise Invalid("returned claim payout missing")
                created = number(r["created_utime"], "created_utime")
                if created > observation["checkpoint"]["utime"]:
                    raise Invalid("future returned entry")
                seconds = observation["checkpoint"]["utime"] - created
                if seconds > limits["returned_seconds"]:
                    alarm(rows, aid, actor_id, "returned_age", entry=r["id"], seconds=seconds)
                kind = number(r["kind"], "kind", 7)
                if kind == 0:
                    raise Invalid("unknown payout kind")
                if kind == 4:
                    alarm(rows, aid, actor_id, "funding_return_refused", entry=r["id"])
            count = number(native["returns_in_flight"], "returns_in_flight")
            if count >= 448:
                alarm(rows, aid, actor_id, "returns_headroom", count=count, limit=512)
            if count >= 512:
                alarm(rows, aid, actor_id, "returns_full", count=count)
            if not flag(actor, "accepting_tokens"):
                alarm(rows, aid, actor_id, "not_accepting_tokens")
            floor = (
                number(native["locked_storage_fees"], "locked_storage_fees")
                + number(native["locked_outcome_fees"], "locked_outcome_fees")
                + max(1_000_000_000, number(ap["tos_floor"], "tos_floor"))
            )
            if number(actor["tos_balance"], "tos_balance") < floor:
                alarm(rows, aid, actor_id, "actor_tos_floor", required=floor)
            if number(actor["wallet_tos_balance"], "wallet_tos_balance") < number(
                ap["wallet_tos_floor"], "wallet_tos_floor"
            ):
                alarm(rows, aid, actor_id, "wallet_tos_floor")
            refusals = items(actor, "refusals")
            unique(refusals, "query_id")
            rc = number(actor["refusals_count"], "refusals_count", 32)
            if rc != len(refusals):
                raise Invalid("incomplete refusal inventory")
            if rc >= limits["refusals_count"]:
                alarm(rows, aid, actor_id, "refusals_headroom", count=rc, limit=32)
            funding = number(actor["rereport_funding"], "rereport_funding")
            if rc and funding == 0:
                raise Invalid("unfunded re-report")
            for refusal in refusals:
                qid = number(refusal["query_id"], "query_id", (1 << 64) - 1)
                total = number(refusal["amount"], "refusal amount")
                records.append(
                    dict(
                        network=network,
                        asset=aid,
                        actor=actor_id,
                        destination=actor["own_wallet"],
                        query_id=qid,
                        amount=total,
                    )
                )
                match = [p for p in payouts if number(p["id"], "payout id") == qid]
                if match and number(match[0]["amount"], "amount") != total:
                    alarm(rows, aid, actor_id, "refusal_mismatch", query_id=qid)
                    continue
                requests.append(
                    dict(
                        network=network,
                        asset=aid,
                        actor=actor_id,
                        destination=actor["own_wallet"],
                        query_id=qid,
                        op="rereport_refusal",
                        opcode="52545131",
                        value_nanotos=funding,
                        checkpoint=observation["checkpoint"],
                    )
                )
        cap = asset["lock_cap"]
        total = number(cap["total"], "total")
        if liability >= total:
            alarm(rows, aid, None, "liability_cap", liability=liability, cap=total)
        supply = number(asset["wrapped_supply"], "wrapped_supply")
        if supply >= total:
            alarm(rows, aid, None, "supply_cap", supply=supply, cap=total)
        balance = number(asset["bridge_balance"], "bridge_balance")
        if supply > balance:
            alarm(rows, aid, None, "backing_shortfall", supply=supply, backing=balance)
        available = number(cap["available"], "available")
        if available <= number(pin["min_lock_headroom"], "min_lock_headroom"):
            alarm(rows, aid, None, "lock_headroom", available=available)
        if balance > total:
            alarm(rows, aid, None, "bridge_over_cap")
        for name, used, limit in (
            ("hourly_headroom", cap["hour_used"], cap["hourly"]),
            ("daily_headroom", cap["day_used"], cap["daily"]),
            ("swap_window", asset["swap_used"], asset["swap_limit"]),
            ("minter_channels", asset["channels_used"], asset["channels_limit"]),
        ):
            used, limit = number(used, name), number(limit, name)
            if limit == 0 or used * 100 >= limit * number(pin["occupancy_percent"], "percent", 100):
                alarm(rows, aid, None, name, used=used, limit=limit)
        prior = old.get(aid)
        if prior:
            if asset["balance_from_hash"] != previous["source_checkpoint"]["hash"]:
                raise Invalid("balance event interval not contiguous")
            expected_delta = 0
            seen = set()
            for e in items(asset, "balance_events"):
                ident = text(e["id"], "event id")
                if ident in seen:
                    raise Invalid("duplicate balance event")
                seen.add(ident)
                amount = number(e["amount"], "event amount")
                if e["kind"] == "Lock":
                    expected_delta += amount
                elif e["kind"] in ("Unlock", "LockRefunded"):
                    expected_delta -= amount
                else:
                    raise Invalid("unknown bridge event")
            actual = balance - number(prior["bridge_balance"], "previous bridge balance")
            if actual != expected_delta:
                code = "unexplained_increase" if actual > expected_delta else "unexplained_decrease"
                alarm(rows, aid, None, code, delta=actual - expected_delta)
        if flag(asset, "bridge_blacklisted"):
            alarm(rows, aid, None, "bridge_frozen")
        if flag(asset, "paused"):
            alarm(rows, aid, None, "token_paused")
        if number(asset["destroy_events"], "destroy_events"):
            alarm(rows, aid, None, "destroyed_funds")
        if number(asset["pause_events"], "pause_events"):
            alarm(rows, aid, None, "token_paused")
        for receiver in items(asset, "redemptions"):
            text(receiver["id"], "redemption id")
            if flag(receiver, "blacklisted") or flag(asset, "paused"):
                alarm(rows, aid, None, "redemption_blocked", redemption=receiver["id"])
        if pin["symbol"] == "USDT":
            if number(asset["fee_basis_points"], "fee_basis_points") or number(
                asset["maximum_fee"], "maximum_fee"
            ):
                alarm(rows, aid, None, "transfer_fee")
            if flag(asset, "deprecated"):
                alarm(rows, aid, None, "token_deprecated")
        if asset["implementation"] != pin["implementation"] or (
            pin["symbol"] == "USDT" and flag(asset, "deprecated")
        ):
            alarm(rows, aid, None, "token_upgrade")
        if not flag(asset, "events_complete"):
            raise Invalid("incomplete source events")
    return dict(
        schema="tos-settlement-report/1",
        checkpoint=observation["checkpoint"],
        alarms=rows,
        rereports=requests,
        refusal_records=records,
        provider_pause_assets=sorted({a["asset"] for a in rows if a["code"] in EMERGENCIES}),
        baseline=previous is None,
    )


def read_json(path):
    with open(path, "rb") as f:
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise Invalid("input exceeds size limit")

    def pairs(values):
        result = {}
        for k, v in values:
            if k in result:
                raise Invalid("duplicate JSON key")
            result[k] = v
        return result

    return json.loads(data, object_pairs_hook=pairs)


def atomic(path, value):
    path = Path(path)
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(encoded) > MAX_BYTES:
        raise Invalid("state exceeds read limit; previous file retained")
    fd, name = tempfile.mkstemp(prefix=".settlement-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


IDENTITY = ("network", "asset", "actor", "destination", "query_id")


def operation_key(record):
    """Stable outbox key of one S-side refusal record."""
    identity = [record[k] for k in IDENTITY]
    return hashlib.sha256(json.dumps(identity).encode()).hexdigest()


def monotonic():
    return time.monotonic()


def reconcile(path, report, policy):
    """Journal eligible requests and revalidate every outbox entry; never sends.

    Prepared entries follow current eligibility only: one that this observation no
    longer makes eligible is withdrawn with its reason, and returns to prepared only
    if a later observation makes it eligible again. A prepared entry still unsent
    past the clearance bounds since it became prepared alarms. Unknown and submitted entries are
    never prepared again; they leave their state only when a later observation shows
    the S-side refusal record gone. Returns (sendable requests, alarms).
    """
    thresholds = policy["thresholds"]
    clear_blocks = number(thresholds["rereport_clear_blocks"], "rereport_clear_blocks")
    clear_seconds = number(thresholds["rereport_clear_seconds"], "rereport_clear_seconds")
    if clear_blocks == 0 or clear_seconds == 0:
        raise Invalid("zero clearance threshold")
    point = report["checkpoint"]
    height = number(point["height"], "height", (1 << 64) - 1)
    utime = number(point["utime"], "utime", (1 << 64) - 1)
    eligible = {operation_key(r): r for r in report["rereports"]}
    observed = {operation_key(r): r for r in report["refusal_records"]}
    outbox = read_json(path) if path.exists() else {}
    for key, request in eligible.items():
        outbox.setdefault(key, dict(state="prepared", request=request, prepared_since=point))
    rows = []
    for key, entry in sorted(outbox.items()):
        state, request = entry["state"], entry["request"]
        record = observed.get(key)
        scope = (request["asset"], request["actor"])
        if state in ("prepared", "withdrawn"):
            if key in eligible:
                # Never sent, so refreshing prices and checkpoint is safe.
                if state == "withdrawn":
                    entry["last_withdrawn"] = entry.pop("withdrawn")
                    entry["prepared_since"] = point
                entry.update(state="prepared", request=eligible[key])
                since = entry.setdefault("prepared_since", point)
                waited = max(0, height - number(since["height"], "height", (1 << 64) - 1))
                idle = max(0, utime - number(since["utime"], "utime", (1 << 64) - 1))
                if waited > clear_blocks or idle > clear_seconds:
                    # Deferred, budget-starved or sender-less: never wait silently.
                    alarm(
                        rows,
                        *scope,
                        "rereport_deferred",
                        operation=key,
                        query_id=request["query_id"],
                        blocks=waited,
                        seconds=idle,
                    )
            else:
                entry.update(
                    state="withdrawn",
                    withdrawn=dict(
                        reason="refusal_absent" if record is None else "ineligible",
                        observed_amount=None if record is None else record["amount"],
                        checkpoint=point,
                    ),
                )
            continue
        sent = request["checkpoint"]
        later = height > number(sent["height"], "height", (1 << 64) - 1)
        if state in ("unknown", "submitted"):
            if record is None and later:
                entry.update(state="cleared", cleared=dict(previous=state, checkpoint=point))
                continue
            if state == "unknown":
                alarm(rows, *scope, "rereport_unknown", operation=key, query_id=request["query_id"])
                continue
            blocks = max(0, height - number(sent["height"], "height", (1 << 64) - 1))
            seconds = max(0, utime - number(sent["utime"], "utime", (1 << 64) - 1))
            if blocks > clear_blocks or seconds > clear_seconds:
                alarm(
                    rows,
                    *scope,
                    "rereport_overdue",
                    operation=key,
                    query_id=request["query_id"],
                    blocks=blocks,
                    seconds=seconds,
                )
            continue
        if state == "cleared":
            if record is not None:
                # Query ids are never reused: a cleared record must not return.
                alarm(rows, *scope, "refusal_reappeared", operation=key)
            continue
        raise Invalid("unknown outbox state")
    atomic(path, outbox)
    sendable = {k: outbox[k]["request"] for k in eligible if outbox[k]["state"] == "prepared"}
    return sendable, rows


def fair_order(outbox, eligible, last=None):
    """Alternate assets over the entries sendable now, starting after `last`.

    History (cleared, submitted, withdrawn) never takes a turn, and `last`, the asset
    served last, carries the turn across batches that the count or time bound cut.
    """
    ranked, seen = [], {}
    candidates = [k for k in outbox if k in eligible]
    for key in sorted(candidates, key=lambda k: (str(outbox[k]["request"]["asset"]), k)):
        asset = str(outbox[key]["request"]["asset"])
        index = seen.get(asset, 0)
        seen[asset] = index + 1
        wrap = last is not None and asset <= last
        ranked.append((index, wrap, asset, key))
    return [key for *_, key in sorted(ranked)]


def dispatch(path, adapter, eligible, *, limit=4, budget=60, timeout=20):
    """An approved adapter owns signing, reserves and transaction-proof reconciliation.

    Sends only prepared entries equal to this observation's eligible requests, at
    most `limit` per call, each with the remaining `budget` seconds as its timeout,
    capped at `timeout`. Unknown is durable BEFORE invoking it. A crash, timeout or
    refusal never retries. Confirmed dispatch is not proof that the actor
    processed/cleared the refusal; reconcile() tracks that.
    """
    outbox = read_json(path)
    started = monotonic()
    cursor_path = path.parent / "dispatch-cursor.json"
    cursor = read_json(cursor_path) if cursor_path.exists() else {}
    # Corrupt state refuses the whole dispatch before any send, like the outbox.
    if not isinstance(cursor, dict) or set(cursor) - {"last_asset"}:
        raise Invalid("malformed dispatch cursor")
    last = cursor.get("last_asset")
    if last is not None:
        text(last, "last_asset")
    attempted, submitted, deferred = [], [], []
    for key in fair_order(outbox, eligible, last):
        entry = outbox[key]
        if entry["state"] != "prepared":
            continue
        if key not in eligible or eligible[key] != entry["request"]:
            continue
        if len(attempted) >= limit:
            deferred.append(key)
            continue
        remaining = budget - (monotonic() - started)
        if remaining < 1:
            deferred.append(key)
            continue
        allowed = min(timeout, int(remaining))
        attempted.append(key)
        entry["state"] = "unknown"
        atomic(path, outbox)
        atomic(cursor_path, dict(last_asset=entry["request"]["asset"]))
        try:
            result = subprocess.run(
                adapter,
                input=json.dumps(dict(operation_id=key, **entry["request"])),
                capture_output=True,
                text=True,
                timeout=allowed,
                check=False,
            )
            if result.returncode or len(result.stdout) > MAX_BYTES:
                continue
            receipt = json.loads(result.stdout)
            if receipt["operation_id"] != key or receipt["status"] != "confirmed":
                continue
            digest(receipt["transaction_hash"])
            if (
                receipt["request_sha256"]
                != hashlib.sha256(
                    json.dumps(dict(operation_id=key, **entry["request"]), sort_keys=True).encode()
                ).hexdigest()
            ):
                continue
            if not flag(receipt, "compute_success") or not flag(receipt, "action_success"):
                continue
            entry.update(state="submitted", transaction_hash=receipt["transaction_hash"])
            atomic(path, outbox)
            submitted.append(key)
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
            continue
    return dict(
        attempted=attempted,
        submitted=submitted,
        unknown=[k for k in attempted if outbox[k]["state"] == "unknown"],
        deferred=deferred,
    )


def bounded(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Invalid(f"invalid {name}")
    return value


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--snapshot", type=Path, required=True)
    ap.add_argument("--state-dir", type=Path, required=True)
    ap.add_argument(
        "--initialize-baseline", action="store_true", help="approve the first balance baseline"
    )
    ap.add_argument("--collect", nargs="+", help="explicit read-only collector argv")
    ap.add_argument("--rereport-adapter", nargs="+", help="explicitly approved funded sender argv")
    ap.add_argument("--rereport-max-per-run", type=int, default=4, help="sends per run (1-32)")
    ap.add_argument(
        "--rereport-budget-seconds",
        type=int,
        default=60,
        help="dispatch time per run (at most 600, at least twice the send timeout)",
    )
    ap.add_argument(
        "--rereport-timeout-seconds", type=int, default=20, help="per-send timeout (1-60)"
    )
    a = ap.parse_args(argv)
    try:
        limit = bounded(a.rereport_max_per_run, "rereport-max-per-run", 1, 32)
        budget = bounded(a.rereport_budget_seconds, "rereport-budget-seconds", 1, 600)
        timeout = bounded(a.rereport_timeout_seconds, "rereport-timeout-seconds", 1, 60)
        if budget < 2 * timeout:
            raise Invalid("dispatch budget must cover at least two send timeouts")
        a.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        state_stat = a.state_dir.lstat()
        if (
            not stat.S_ISDIR(state_stat.st_mode)
            or state_stat.st_uid != os.geteuid()
            or state_stat.st_mode & 0o077
        ):
            raise Invalid("state directory is not private and owned")
        with open(a.state_dir / "monitor.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if a.collect:
                # The adapter writes --snapshot atomically. Never echo its output or secrets.
                result = subprocess.run(
                    a.collect,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=60,
                    check=False,
                )
                if result.returncode:
                    raise Invalid("collector failed")
            policy, snapshot = read_json(a.policy), read_json(a.snapshot)
            prior_path = a.state_dir / "previous.json"
            previous = read_json(prior_path) if prior_path.exists() else None
            if previous is None and not a.initialize_baseline:
                raise Invalid("initial balance baseline needs approval")
            report = evaluate(policy, snapshot, previous)
            # Emergencies latch first: nothing below, dispatch included, may delay them.
            incidents_path = a.state_dir / "incidents.json"
            incidents = read_json(incidents_path) if incidents_path.exists() else {}
            for event in report["alarms"]:
                if event["code"] in EMERGENCIES:
                    key = event["asset"] + ":" + event["code"]
                    incidents.setdefault(key, dict(alarm=event, checkpoint=report["checkpoint"]))
            atomic(incidents_path, incidents)
            report["provider_pause_assets"] = sorted(
                {event["alarm"]["asset"] for event in incidents.values()}
            )
            report["latched_incidents"] = sorted(incidents)
            outbox_path = a.state_dir / "rereports.json"
            sendable, outbox_alarms = reconcile(outbox_path, report, policy)
            report["alarms"].extend(outbox_alarms)
            if sendable and not a.rereport_adapter:
                alarm(report["alarms"], "operator", None, "rereport_sender_missing")
            report["unknown_rereports"] = sorted(
                key for key, entry in read_json(outbox_path).items() if entry["state"] == "unknown"
            )
            report_path = a.state_dir / "report.json"
            atomic(report_path, report)  # published before any dispatch
            if a.rereport_adapter and sendable:
                outcome = dispatch(
                    outbox_path,
                    a.rereport_adapter,
                    sendable,
                    limit=limit,
                    budget=budget,
                    timeout=timeout,
                )
                report["rereport_dispatch"] = outcome
                for key in outcome["unknown"]:
                    request = sendable[key]
                    alarm(
                        report["alarms"],
                        request["asset"],
                        request["actor"],
                        "rereport_unknown",
                        operation=key,
                        query_id=request["query_id"],
                    )
                report["unknown_rereports"] = sorted(
                    set(report["unknown_rereports"]) | set(outcome["unknown"])
                )
                atomic(report_path, report)  # dispatch outcome added
            atomic(prior_path, snapshot)
            print(json.dumps(report, sort_keys=True))
            if report["baseline"]:
                return 2  # No interval was checked on the first observation.
            return 1 if report["alarms"] or report["latched_incidents"] else 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        print(json.dumps(dict(alarms=[dict(code="observation_invalid")], status="INCOMPLETE")))
        return 2


if __name__ == "__main__":
    sys.exit(main())
