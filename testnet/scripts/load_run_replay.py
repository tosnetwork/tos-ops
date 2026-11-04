"""Offline, bounded native/history/digest/clock replay of one closed public run.

Only the explicitly named public captures, events and summary are read. This
never opens wallet keys, private carriers or financial journals. Coverage is not
load acceptance and cannot clear the original qualification spending fence.
"""

import argparse
import base64
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import tempfile
from pathlib import Path

from load_finality import Head, HistoryError, decode_history
from load_finality_collector import capture_size, seal_executable, sync_directory
from load_finality_replay import RetainedPrefix, block_identity
from load_finality_window import BUCKETS, QUERY_LIMIT
from load_proof_archive import PublicProofArchive
from pytosiq_core import Cell, Transaction
from pytosiq_core.tl import TlGenerator

MIB = 1 << 20
MAX_CAPTURE = 64 * MIB


def require(ok, reason):
    if not ok:
        raise HistoryError(reason)


def snapshot(path, limit=8 * MIB):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "public input size/type")
        pieces = []
        total = 0
        while total <= limit:
            chunk = os.read(fd, min(MIB, limit + 1 - total))
            if not chunk:
                break
            pieces.append(chunk)
            total += len(chunk)
        data = b"".join(pieces)
        require(len(data) == info.st_size, "public input changed or oversized")
        after = os.fstat(fd)
        require(
            (after.st_size, after.st_mtime_ns) == (info.st_size, info.st_mtime_ns),
            "public input changed",
        )
        return data
    finally:
        os.close(fd)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pinned(path, expected, limit=8 * MIB):
    raw = snapshot(path, limit)
    require(digest(raw) == expected, "public input pin mismatch")
    return raw


def durable_json(path, value):
    # A failed write/fsync must not leave a partial completion filename that
    # prevents a safe index replay. Link publication is atomic and exclusive.
    require(not path.exists() and not path.is_symlink(), "public result already published")
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False
    ) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temporary, path)
    temporary.unlink()
    sync_directory(path.parent)


def clock(value):
    require(
        type(value) in (int, float) and math.isfinite(value) and value >= 0,
        "invalid monotonic clock",
    )
    return value


def query_id(value):
    require(type(value) is int and 0 <= value < QUERY_LIMIT, "invalid query id")
    return value


class EventIndex:
    """Disk index; event ordering need not equal original window clock ordering."""

    def __init__(self, path, run, *, max_offers=QUERY_LIMIT, max_captures=1_000_000):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE offers(q INTEGER PRIMARY KEY,digest TEXT,clock REAL,boot TEXT,matched INTEGER DEFAULT 0)"
        )
        self.db.execute(
            "CREATE TABLE checkpoints(number INTEGER PRIMARY KEY,event TEXT,matched INTEGER DEFAULT 0)"
        )
        self.run = Path(run)
        self.max_offers, self.max_captures = max_offers, max_captures
        self.offers = self.checkpoints = 0
        self.baseline = None
        self.sealed = self.final_event = self.stage_started = None
        self.last_offered_clock = None
        self.last_observed_clock = None
        self.histogram = [0] * (len(BUCKETS) + 1)

    def add(self, event):
        kind = event.get("event")
        if kind in ("offered", "native_baseline", "native_checkpoint"):
            require(self.final_event is None, "activity after native final evaluation")
        if kind == "offered":
            require(self.sealed is None, "offered after native stage sealed")
            hashes, ids = event["signed_request_hashes"], event["query_ids"]
            require(
                type(hashes) is dict and type(ids) is list and 0 < len(ids) <= 8192,
                "bounded offered batch required",
            )
            require(len(ids) == len(set(query_id(q) for q in ids)), "duplicate offered query")
            require(set(hashes) == {str(q) for q in ids}, "offered digest keys differ")
            offered = clock(event["native_offered_monotonic_seconds"])
            require(
                clock(event["monotonic_seconds"]) >= offered, "offered event precedes window clock"
            )
            require(
                self.last_offered_clock is None or offered >= self.last_offered_clock,
                "serialized offered window clock regressed",
            )
            boot = event["native_boot_id"]
            require(type(boot) is str and 0 < len(boot) <= 128, "invalid boot identity")
            for q in ids:
                Head(0, hashes[str(q)])
                require(self.offers < self.max_offers, "offered count limit")
                self.db.execute(
                    "INSERT INTO offers(q,digest,clock,boot) VALUES(?,?,?,?)",
                    (q, hashes[str(q)], offered, boot),
                )
                self.offers += 1
            self.last_offered_clock = offered
        elif kind in ("native_baseline", "native_checkpoint"):
            path = Path(event["capture"])
            require(
                path.parent == self.run / "native-captures"
                and re.fullmatch(r"capture-[0-9]{6}", path.name),
                "checkpoint belongs to another run",
            )
            number = int(path.name[8:])
            require(
                number < self.max_captures and self.checkpoints < self.max_captures,
                "checkpoint count limit",
            )
            observed = clock(event["verified_observation_monotonic_seconds"])
            require(
                clock(event["monotonic_seconds"]) >= observed,
                "checkpoint record precedes window clock",
            )
            require(
                type(event["boot_id"]) is str and 0 < len(event["boot_id"]) <= 128,
                "invalid boot identity",
            )
            if kind == "native_baseline":
                require(
                    self.baseline is None and number == 1,
                    "one strict baseline at capture1 required",
                )
                self.baseline = event
            self.db.execute(
                "INSERT INTO checkpoints(number,event) VALUES(?,?)",
                (number, json.dumps(event, allow_nan=False)),
            )
            self.checkpoints += 1

        elif kind == "native_stage_started":
            require(
                self.baseline is not None and self.stage_started is None and not self.offers,
                "native stage start must precede offers exactly once",
            )
            stamp = clock(event["started_monotonic_seconds"])
            duration = clock(event["duration_seconds"])
            require(
                duration > 0
                and math.isfinite(stamp + duration)
                and stamp >= self.baseline["verified_observation_monotonic_seconds"]
                and event["boot_id"] == self.baseline["boot_id"]
                and clock(event["monotonic_seconds"]) >= stamp,
                "invalid native stage start context",
            )
            self.stage_started = event
        elif kind == "native_stage_sealed":
            require(
                self.baseline is not None and self.sealed is None,
                "duplicate or premature native stage seal",
            )
            stamp = clock(event["sealed_monotonic_seconds"])
            require(
                event["boot_id"] == self.baseline["boot_id"]
                and stamp >= self.baseline["verified_observation_monotonic_seconds"]
                and (self.last_offered_clock is None or stamp >= self.last_offered_clock)
                and clock(event["monotonic_seconds"]) >= stamp
                and event["offered"] == self.offers,
                "native seal population or clock differs",
            )
            self.sealed = event
        elif kind == "native_stage_finalized":
            require(
                self.sealed is not None and self.final_event is None,
                "missing seal or repeated native final evaluation",
            )
            stamp = clock(event["finalized_monotonic_seconds"])
            require(
                event["boot_id"] == self.baseline["boot_id"]
                and stamp >= self.sealed["sealed_monotonic_seconds"]
                and clock(event["monotonic_seconds"]) >= stamp,
                "native final evaluation clock differs",
            )
            self.final_event = event

    def finish_index(self):
        require(
            self.baseline is not None and self.offers > 0, "baseline and offered queries required"
        )
        baseline = self.baseline
        policy = baseline.get("slo_population", "completion-prefix")
        require(policy in ("completion-prefix", "fixed-stage"), "unknown native SLO policy")
        require(
            (self.sealed is not None and self.final_event is not None)
            if policy == "fixed-stage"
            else self.sealed is None and self.final_event is None,
            "native policy and finalization events differ",
        )
        invalid = self.db.execute(
            "SELECT count(*) FROM offers WHERE boot!=? OR clock<?",
            (baseline["boot_id"], baseline["verified_observation_monotonic_seconds"]),
        ).fetchone()[0]
        require(invalid == 0, "offered boot or baseline clock differs")
        if policy == "fixed-stage":
            require(self.stage_started is not None, "missing native stage start")
            start = self.stage_started["started_monotonic_seconds"]
            end = start + self.stage_started["duration_seconds"]
            outside = self.db.execute(
                "SELECT count(*) FROM offers WHERE clock<? OR clock>=?", (start, end)
            ).fetchone()[0]
            require(outside == 0, "native offers outside declared stage interval")
        else:
            require(self.stage_started is None, "legacy policy has fixed-stage start")
        self.last_observed_clock = baseline["verified_observation_monotonic_seconds"]
        self.db.commit()

    def bind(self, number, seqno, head, receipts):
        row = self.db.execute(
            "SELECT event,matched FROM checkpoints WHERE number=?", (number,)
        ).fetchone()
        if number == 0:
            require(row is None and not receipts, "unscored cold capture contains receipts/event")
            return
        require(row is not None and row[1] == 0, "missing or duplicate checkpoint")
        event = json.loads(row[0])
        require(
            event["checkpoint_seqno"] == seqno and event["boot_id"] == self.baseline["boot_id"],
            "checkpoint identity or boot differs",
        )
        observed = event["verified_observation_monotonic_seconds"]
        require(observed >= self.last_observed_clock, "checkpoint window clock regressed")
        ids = event.get("query_ids", [])
        require(
            type(ids) is list and len(ids) == len(set(query_id(q) for q in ids)),
            "duplicate checkpoint query",
        )
        require(
            set(ids) == {r.query_id for r in receipts} and len(ids) == len(receipts),
            "checkpoint receipts differ",
        )
        if number == 1:
            require(
                event["event"] == "native_baseline"
                and head == Head(event["head_lt"], event["head_hash"]),
                "strict baseline head differs",
            )
        else:
            require(event["event"] == "native_checkpoint", "unexpected baseline")
        for receipt in receipts:
            offer = self.db.execute(
                "SELECT digest,clock,boot,matched FROM offers WHERE q=?", (receipt.query_id,)
            ).fetchone()
            require(
                offer is not None
                and offer[3] == 0
                and offer[0] == receipt.request_hash
                and offer[2] == event["boot_id"],
                "missing/duplicate query or signed digest mismatch",
            )
            delta = event["verified_observation_monotonic_seconds"] - offer[1]
            require(math.isfinite(delta) and delta >= 0, "native observation precedes offer")
            bucket = next((i for i, upper in enumerate(BUCKETS) if delta <= upper), len(BUCKETS))
            self.histogram[bucket] += 1
            self.db.execute("UPDATE offers SET matched=1 WHERE q=?", (receipt.query_id,))
        self.db.execute("UPDATE checkpoints SET matched=1 WHERE number=?", (number,))
        self.db.commit()
        self.last_observed_clock = observed

    def complete(self, qualification):
        native = qualification["native_finality"]
        policy = self.baseline.get("slo_population", "completion-prefix")
        require(
            native.get("slo_population", "completion-prefix") == policy,
            "native summary SLO policy differs",
        )
        if policy == "fixed-stage":
            require(
                self.final_event["summary"] == native
                and native.get("stage_sealed") is True
                and native.get("stage_finalized") is True
                and native.get("stage_duration_seconds") == self.stage_started["duration_seconds"]
                and native.get("stage_start_monotonic_seconds")
                == self.stage_started["started_monotonic_seconds"]
                and native.get("stage_deadline_monotonic_seconds")
                == self.stage_started["started_monotonic_seconds"]
                + self.stage_started["duration_seconds"]
                and (
                    native.get("latency_criteria_pass") is not True
                    or self.sealed["sealed_monotonic_seconds"]
                    >= native["stage_deadline_monotonic_seconds"]
                )
                and self.final_event["finalized_monotonic_seconds"] >= self.last_observed_clock,
                "native final population verdict or clock differs",
            )
        require(
            self.db.execute("SELECT count(*) FROM offers WHERE matched=0").fetchone()[0] == 0,
            "unmatched offered query",
        )
        require(
            self.db.execute("SELECT count(*) FROM checkpoints WHERE matched=0").fetchone()[0] == 0,
            "unmatched checkpoint event",
        )
        require(
            self.offers
            == qualification["offered"]
            == qualification["native_finality"]["native_finalized"],
            "terminal counts differ",
        )
        require(
            self.histogram == qualification["native_finality"]["histogram"],
            "exact-window histogram differs",
        )

        if policy == "fixed-stage" and native.get("latency_criteria_pass") is True:

            def quantile(percent):
                rank = (self.offers * percent + 99) // 100
                count = 0
                for upper, number in zip((*BUCKETS, float("inf")), self.histogram):
                    count += number
                    if count >= rank:
                        return upper
                raise HistoryError("native final histogram inconsistent")

            require(
                native.get("failure") is None
                and native.get("worker_failure") is None
                and native.get("native_pending") == 0
                and quantile(95) <= 5
                and quantile(99) <= 10,
                "native final SLO verdict contradicts replayed population",
            )

    def close(self):
        self.db.close()


def index_events(index, source, target, expected):
    hasher = hashlib.sha256()
    total = count = 0
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream, target.open("xb") as copy:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular event journal required")
        while line := stream.readline(MIB + 1):
            total += len(line)
            count += 1
            require(
                len(line) <= MIB
                and line.endswith(b"\n")
                and total <= 16 << 30
                and count <= 12_000_000,
                "event stream budget or truncated line",
            )
            hasher.update(line)
            copy.write(line)
            index.add(json.loads(line))
        copy.flush()
        os.fsync(copy.fileno())
    require(hasher.hexdigest() == expected, "event journal pin mismatch")
    index.finish_index()


def capture_count(directory, limit):
    count = largest = 0
    for item in directory.iterdir():
        if item.name in ("anchor.json", "liteserver.json"):
            continue
        require(
            re.fullmatch(r"capture-[0-9]{6}", item.name)
            and not item.is_symlink()
            and item.is_dir(),
            "unexpected capture entry",
        )
        number = int(item.name[8:])
        count += 1
        largest = max(largest, number)
        require(count <= limit and number < limit, "capture count budget")
    require(count >= 2 and count == largest + 1, "capture index gap")
    return count


def history(cap, head, previous, wallet, global_id, subwallet_id):
    cursor, encoded, total, artifacts = head, [], 0, []
    artifact_bytes = 0
    for page in range(129):
        if cursor == previous:
            break
        name = f"rpc-{page}.json"
        raw = snapshot(cap / name)
        artifact_bytes += len(raw)
        require(artifact_bytes <= MAX_CAPTURE, "history artifact byte budget")
        artifacts.append((name, raw))
        result = json.loads(raw)
        require(
            "error" not in result
            and type(result.get("result")) is list
            and 0 < len(result["result"]) <= 64,
            "bounded history page required",
        )
        for row in result["result"]:
            if cursor == previous:
                break
            value = row["data"]
            require(
                type(value) is str and len(value) <= 4 * ((MIB + 2) // 3), "transaction size limit"
            )
            total += len(value)
            require(total <= 16 * MIB and len(encoded) < 8192, "history budget")
            cell = Cell.one_from_boc(base64.b64decode(value, validate=True))
            require(cell.hash.hex() == cursor.hash, "history head hash mismatch")
            tx = Transaction.deserialize(cell.begin_parse())
            require(
                tx.lt == cursor.lt and tx.prev_trans_lt < tx.lt, "history logical time mismatch"
            )
            encoded.append(value)
            cursor = Head(tx.prev_trans_lt, tx.prev_trans_hash.hex())
    require(cursor == previous, "history does not reach preceding native head")
    receipts = decode_history(
        encoded,
        verified_head=head,
        previous_head=previous,
        wallet=wallet,
        global_id=global_id,
        subwallet_id=subwallet_id,
        skipped_profile=True,
    )
    return receipts, artifacts


class NativeReplay:
    def __init__(self, verifier, verifier_sha256, anchor, output):
        self.fd = seal_executable(verifier, verifier_sha256)
        self.anchor, self.output = anchor, output

    def __call__(self, request, parts, account, config):
        require(
            sum(map(len, parts)) + len(account) + len(config) <= MAX_CAPTURE,
            "native material budget",
        )
        with tempfile.TemporaryDirectory(dir=self.output, prefix="native-") as temporary:
            root = Path(temporary)
            material = root / "material"
            material.mkdir()
            (root / "request.json").write_bytes(request)
            for i, part in enumerate(parts):
                (material / f"chain-{i:04d}.tl").write_bytes(part)
            (material / "account.tl").write_bytes(account)
            (material / "config.tl").write_bytes(config)
            with (root / "stdout").open("w+b") as out, (root / "stderr").open("w+b") as err:
                done = subprocess.run(
                    [
                        "/usr/bin/prlimit",
                        "--fsize=8388608",
                        "--",
                        f"/proc/self/fd/{self.fd}",
                        "verify",
                        "--anchor",
                        str(self.anchor),
                        "--request",
                        str(root / "request.json"),
                        "--material",
                        str(material),
                    ],
                    pass_fds=(self.fd,),
                    stdout=out,
                    stderr=err,
                    timeout=30,
                )
                require(done.returncode == 0, "offline native verification refused")
                out.seek(0)
                raw = out.read(8 * MIB + 1)
                require(len(raw) <= 8 * MIB, "native output budget")
                return json.loads(raw)

    def close(self):
        os.close(self.fd)


def check_native(proof, live, wallet, code_hash, global_id, global_version):
    require(
        proof.get("status") == "verified" and proof.get("mode") == "historical",
        "native historical verification required",
    )
    account = proof["account"]
    require(
        account["active"] and account["address"] == wallet and account["code_hash"] == code_hash,
        "native account/code identity mismatch",
    )
    for field in ("address", "code_hash", "data_hash", "last_trans_lt", "last_trans_hash"):
        require(account[field] == live["account"][field], "native and retained account differ")
    configs = {
        x["index"]: Cell.one_from_boc(base64.b64decode(x["boc"], validate=True))
        for x in proof["config_params"]
    }
    version = configs[8].begin_parse()
    require(
        version.load_uint(8) == 0xC4 and version.load_uint(32) == global_version,
        "native global version mismatch",
    )
    require(configs[19].begin_parse().load_int(32) == global_id, "native global id mismatch")
    return Head(account["last_trans_lt"], account["last_trans_hash"])


def replay_capture(cap, number, previous, cache, verifier, index, archive, identity):
    capture_size(cap)  # Strict completed public-capture count/byte/symlink guard.
    names = ("proof.json", "result.json", "request.json")
    originals = {name: snapshot(cap / name) for name in names}
    live, result, request = (json.loads(originals[name]) for name in names)
    require(
        live.get("status") == "verified"
        and live.get("mode") == "live"
        and result.get("status") == "VERIFIED_CAPTURE",
        "completed native capture required",
    )
    require(
        set(request) == {"mode", "max_age_seconds", "account", "config_params"}
        and request["mode"] == "live"
        and request["account"] == identity["wallet"]
        and request["config_params"] == [8, 19],
        "capture request context mismatch",
    )
    request.update(
        mode="historical",
        target={
            k: live["target"][k] for k in ("workchain", "shard", "seqno", "root_hash", "file_hash")
        },
    )
    request.pop("max_age_seconds")
    historical_request = json.dumps(request, separators=(",", ":")).encode()
    material = cap / "material"
    require(not material.is_symlink() and material.is_dir(), "public material directory required")
    paths = []
    auxiliary = []
    for item in material.iterdir():
        if item.name in ("account.tl", "config.tl", "masterchain-info.tl"):
            continue
        if re.fullmatch(r"descent-[0-9]{4}\.tl", item.name):
            auxiliary.append(item)
        else:
            require(re.fullmatch(r"chain-[0-9]{4}\.tl", item.name), "unexpected material entry")
            paths.append(item)
        require(len(paths) + len(auxiliary) <= 1024, "material part budget")
    paths.sort()
    require(
        0 < len(paths) <= 1024 and all(p.name == f"chain-{i:04d}.tl" for i, p in enumerate(paths)),
        "chain part gap or budget",
    )
    raw_parts = []
    total_parts = 0
    for path in paths:
        body = snapshot(path)
        total_parts += len(body)
        require(total_parts <= MAX_CAPTURE, "chain byte budget")
        raw_parts.append(body)
    account, config = snapshot(material / "account.tl"), snapshot(material / "config.tl")
    verified = {}
    composed = []

    def verify(parts):
        proof = verifier(historical_request, parts, account, config)
        check_native(
            proof,
            live,
            identity["wallet"],
            identity["wallet_code_hash"],
            identity["global_id"],
            identity["global_version"],
        )
        verified.update(proof)
        composed.extend(parts)
        return proof

    cache.advance(raw_parts, start=live["start"], target=live["target"], verify=verify)
    head = check_native(
        verified,
        live,
        identity["wallet"],
        identity["wallet_code_hash"],
        identity["global_id"],
        identity["global_version"],
    )
    require(
        block_identity(verified["target"]) == block_identity(result["target"]),
        "retained result target differs",
    )
    claimed_previous = Head(**result["previous_head"])
    require(
        head == Head(**result["head"])
        and claimed_previous == (head if previous is None else previous),
        "native history segment continuity mismatch",
    )
    receipts, pages = history(
        cap,
        head,
        claimed_previous,
        identity["wallet"],
        identity["global_id"],
        identity["subwallet_id"],
    )
    require(len(receipts) == result["receipts"], "retained receipt count mismatch")
    index.bind(number, verified["target"]["seqno"], head, receipts)
    parts = (
        [(f"chain-{i:04d}.tl", body) for i, body in enumerate(composed)]
        + [
            ("account.tl", account),
            ("config.tl", config),
            ("historical-request.json", historical_request),
        ]
        + pages
    )
    metadata = {
        "names": [name for name, _ in parts],
        "original_sha256": {name: digest(raw) for name, raw in originals.items()},
        "target": verified["target"],
        "head": {"lt": head.lt, "hash": head.hash},
        "receipts": len(receipts),
    }
    info_path = material / "masterchain-info.tl"
    if info_path.exists() or info_path.is_symlink():
        parts.append(("masterchain-info.tl", snapshot(info_path)))
        metadata["names"].append("masterchain-info.tl")
    for extra in sorted(auxiliary):
        parts.append((extra.name, snapshot(extra)))
        metadata["names"].append(extra.name)
    bodies = [body for _, body in parts]
    if number < archive.next_capture():
        retained_metadata, retained_parts = archive.read(number)
        require(
            retained_metadata == metadata and retained_parts == bodies,
            "resume capture inputs changed",
        )
    else:
        archive.append(number, bodies, metadata=metadata)
    # Original public inputs must not change while this capture is validated.
    require(
        all(snapshot(cap / name) == raw for name, raw in originals.items()),
        "capture input changed during replay",
    )
    return head


def validate_packet(
    packet, run, anchor, args, policy="completion-prefix", *, duration=None, target_gas=None
):
    require(Path(packet["state_directory"]) == run.parent, "producer state/run context differs")
    stages = packet["calibration_commands"]
    require(type(stages) is list and 0 < len(stages) <= 32, "bounded producer stages required")
    expected = {
        "--expected-genesis-root": anchor["root_hash"],
        "--expected-genesis-file": anchor["file_hash"],
        "--native-verifier-sha256": args.verifier_sha256,
        "--native-anchor-sha256": args.anchor_sha256,
        "--native-wallet-code-hash": args.wallet_code_hash,
        "--state": str(run.parent),
    }
    if policy == "fixed-stage":
        require(
            type(duration) in (int, float) and math.isfinite(duration) and duration > 0,
            "invalid native original duration",
        )
        require(
            target_gas is None or type(target_gas) is int and target_gas > 0,
            "invalid native selected gas profile",
        )
    matched_duration = False
    for stage in stages:
        command = stage["command"]
        require("--native-finality" in command, "native producer required")
        key = "--native-slo-population"
        require(command.count(key) <= 1, "duplicate native SLO policy")
        declared = command[command.index(key) + 1] if key in command else "completion-prefix"
        require(declared == policy, "producer native SLO policy differs")
        if policy == "fixed-stage":
            require(command.count("--duration") == 1, "one frozen stage duration required")
            declared_duration = command[command.index("--duration") + 1]
            require(
                re.fullmatch(r"[1-9][0-9]*", declared_duration) is not None,
                "invalid frozen stage duration",
            )
            key = "--target-gas-per-block"
            require(command.count(key) <= 1, "duplicate frozen stage gas profile")
            declared_gas = command[command.index(key) + 1] if key in command else None
            if int(declared_duration) == duration and declared_gas == (
                str(target_gas) if target_gas is not None else None
            ):
                matched_duration = True
        for key, value in expected.items():
            require(
                command.count(key) == 1 and command[command.index(key) + 1] == value,
                "producer identity differs",
            )
    if policy == "fixed-stage":
        require(matched_duration, "native original duration/profile differs from frozen packet")


def run(args):
    source = Path(args.run)
    require(
        source.is_absolute()
        and not source.is_symlink()
        and re.fullmatch(r"qualification-[0-9]+", source.name),
        "explicit absolute qualification run required",
    )
    captures = source / "native-captures"
    require(not captures.is_symlink() and captures.is_dir(), "public captures directory required")
    summary_raw = pinned(args.summary, args.summary_sha256)
    summary = json.loads(summary_raw)
    q = summary["qualification"]
    require(
        q["run_directory"] == source.name
        and summary["wallet"] == args.wallet
        and summary["transfers_mode"] == "skip",
        "summary/run/profile mismatch",
    )
    require(
        q["safe_to_start_new_run"] is True
        and q["pending"] == 0
        and q["funding_unknown"] is False
        and q["native_finality"]["native_pending"] == 0,
        "closed reconciled source required; replay cannot clear its fence",
    )
    require(
        q["native_finality"]["latency_bucket_upper_seconds"] == [*BUCKETS, "infinity"],
        "source histogram bucket definitions differ",
    )
    anchor_raw = pinned(args.anchor, args.anchor_sha256)
    anchor = json.loads(anchor_raw)
    schema_raw = pinned(args.schema, args.schema_sha256, 16 * MIB)
    packet_raw = pinned(args.producer_packet, args.producer_packet_sha256)
    validate_packet(
        json.loads(packet_raw),
        source,
        anchor,
        args,
        q["native_finality"].get("slo_population", "completion-prefix"),
        duration=q["native_finality"].get("stage_duration_seconds"),
        target_gas=summary.get("target_gas_per_block"),
    )
    count = capture_count(captures, args.max_captures)
    identity = {
        "run": str(source),
        "summary_sha256": args.summary_sha256,
        "events_sha256": args.events_sha256,
        "anchor_sha256": args.anchor_sha256,
        "schema_sha256": digest(schema_raw),
        "producer_packet_sha256": args.producer_packet_sha256,
        "verifier_sha256": args.verifier_sha256,
        "wallet": args.wallet,
        "wallet_code_hash": args.wallet_code_hash,
        "global_id": args.global_id,
        "global_version": args.global_version,
        "subwallet_id": args.subwallet_id,
        "captures": count,
        "max_unique_bytes": args.max_unique_bytes,
        "max_captures": args.max_captures,
    }
    output = Path(args.output)
    if not args.resume:
        output.mkdir(mode=0o700)
    require(
        output.is_dir() and not output.is_symlink(), "explicit replay output directory required"
    )
    lock_fd = os.open(output / "replay.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        context = output / "context.json"
        if args.resume:
            require(
                json.loads(snapshot(context)) == identity and not (output / "RESULT.json").exists(),
                "resume context changed or run already complete",
            )
        else:
            durable_json(context, identity)
        public = output / "public"
        require(not public.is_symlink(), "public context symlink refused")
        public.mkdir(mode=0o700, exist_ok=True)
        for name, raw in (
            ("anchor.json", anchor_raw),
            ("schema.tl", schema_raw),
            ("summary.json", summary_raw),
            ("producer-packet.json", packet_raw),
        ):
            path = public / name
            if path.exists() or path.is_symlink():
                require(snapshot(path, 16 * MIB) == raw, "retained public context changed")
            else:
                with path.open("xb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
        sync_directory(public)
        sync_directory(output)
        attempt = 0
        while (output / f"index-{attempt}.sqlite").exists() or (
            output / f"index-{attempt}.sqlite"
        ).is_symlink():
            attempt += 1
            require(attempt < 1000, "resume attempt limit")
        index = EventIndex(
            output / f"index-{attempt}.sqlite", source, max_captures=args.max_captures
        )
        archive = None
        native = None
        try:
            require(not (output / "proofs.sqlite").is_symlink(), "archive symlink refused")
            archive = PublicProofArchive(
                output / "proofs.sqlite",
                identity=identity,
                max_unique_bytes=args.max_unique_bytes,
                max_captures=args.max_captures,
            )
            native = NativeReplay(
                args.verifier, args.verifier_sha256, public / "anchor.json", output
            )
            index_events(
                index,
                source / "events.jsonl",
                output / f"events-{attempt}.jsonl",
                args.events_sha256,
            )
            cache = RetainedPrefix(TlGenerator(str(public / "schema.tl")).generate(), anchor)
            previous = None
            for number in range(count):
                require(
                    shutil.disk_usage(output).free >= (20 << 30) + MAX_CAPTURE,
                    "replay free disk guard",
                )
                previous = replay_capture(
                    captures / f"capture-{number:06d}",
                    number,
                    previous,
                    cache,
                    native,
                    index,
                    archive,
                    identity,
                )
                (output / "PROGRESS.json").write_text(
                    json.dumps(
                        {
                            "attempt": attempt,
                            "captures_verified": number + 1,
                            "captures_required": count,
                        }
                    )
                    + "\n"
                )
            index.complete(q)
            require(
                snapshot(args.summary) == summary_raw
                and snapshot(args.anchor) == anchor_raw
                and snapshot(args.schema, 16 * MIB) == schema_raw
                and snapshot(args.producer_packet) == packet_raw,
                "pinned context changed during replay",
            )
            result = {
                "status": "FULL_CLOSED_RUN_PROOF_HISTORY_DIGEST_CLOCK_COVERAGE_VERIFIED",
                "scope": "Coverage only; no load/72h acceptance, no financial fence clearance",
                "identity": identity,
                "captures": count,
                "offered": index.offers,
                "recomputed_histogram": index.histogram,
                "source_native_latency_criteria_pass": q["native_finality"][
                    "latency_criteria_pass"
                ],
                "archive": archive.stats(),
                "attempt": attempt,
            }
            durable_json(output / "RESULT.json", result)
            return result
        finally:
            if native is not None:
                native.close()
            if archive is not None:
                archive.close()
            index.close()


def install_interrupt_handlers():
    def interrupted(_signum, _frame):
        # subprocess.run kills/reaps its owned child on BaseException; the run
        # finally blocks close the archive/index without publishing completion.
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)


def main():
    install_interrupt_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "run",
        "summary",
        "summary-sha256",
        "events-sha256",
        "anchor",
        "anchor-sha256",
        "schema",
        "schema-sha256",
        "producer-packet",
        "producer-packet-sha256",
        "verifier",
        "verifier-sha256",
        "wallet",
        "wallet-code-hash",
        "output",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--global-id", type=int, default=2)
    parser.add_argument("--global-version", type=int, default=16)
    parser.add_argument("--subwallet-id", type=int, default=4269)
    parser.add_argument("--max-unique-bytes", type=int, default=128 << 30)
    parser.add_argument("--max-captures", type=int, default=1_000_000)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    try:
        result = run(args)
    except (
        HistoryError,
        ValueError,
        OSError,
        KeyError,
        TypeError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ) as error:
        parser.exit(1, f"replay refused: {error}\n")
    print(
        json.dumps(
            {
                "status": result["status"],
                "captures": result["captures"],
                "offered": result["offered"],
            }
        )
    )


if __name__ == "__main__":
    main()
