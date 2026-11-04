"""Bounded, durable evidence for an explicitly qualified load run.

No keys or message bodies enter this journal. Funding reservations never roll back
on an unknown result. An unfinished run refuses a new run rather than replaying it.
"""

import base64
import fcntl
import json
import os
import stat
import threading
import time
from pathlib import Path

import testnet_lib as lib

BUCKETS = (0.1, 0.25, 0.5, 1, 2, 3, 5, 10, 20, 30, 60, 120, 300)
QUERY_LIMIT = 1 << 23


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as out:
        os.chmod(tmp, 0o600)
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)
    sync_directory(path.parent)


def check_genesis(info, root_hex, file_hex):
    """RPC corroboration of the explicit ceremony identity, not a native proof."""
    try:
        initial = info["init"]
        valid = initial["workchain"] == -1 and initial["seqno"] == 0
        valid = valid and base64.b64decode(initial["root_hash"], validate=True).hex() == root_hex
        valid = valid and base64.b64decode(initial["file_hash"], validate=True).hex() == file_hex
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise lib.TestnetError("qualified RPC genesis does not match the explicit ceremony")


class Qualification:
    def __init__(self, directory, funding_cap, fee_stop, max_pending=8192):
        if (
            type(funding_cap) is not int
            or type(fee_stop) is not int
            or funding_cap <= 0
            or fee_stop <= 0
            or not 1 <= max_pending <= 8192
        ):
            raise lib.TestnetError(
                "positive qualification budgets and bounded pending limit required"
            )
        self.directory = lib.private_dir(Path(directory))
        self.lock_fd = os.open(
            self.directory / "qualification.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        info = os.fstat(self.lock_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(self.lock_fd)
            raise lib.TestnetError("unsafe qualification lock")
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.active = self.directory / "qualification-active.json"
            if self.active.exists() and not json.loads(self.active.read_text()).get("closed"):
                raise lib.TestnetError(
                    "previous qualified run unfinished: reconcile original messages"
                )
            self.run = self.directory / f"qualification-{time.time_ns()}"
            self.run.mkdir(mode=0o700)
            (self.run / "private-outbox").mkdir(mode=0o700)
            self.events = (self.run / "events.jsonl").open("x")
            os.chmod(self.run / "events.jsonl", 0o600)
            atomic_json(self.active, {"run": self.run.name, "closed": False})
        except BaseException:
            os.close(self.lock_fd)
            raise
        self.guard = threading.RLock()
        self.funding_cap, self.fee_stop = funding_cap, fee_stop
        self.max_pending = max_pending
        self.live = {}
        self.seen = bytearray(QUERY_LIMIT // 8)
        self.funded = self.funding_operations = self.offered = self.executed = 0
        self.accepted = self.failed = 0
        self.funding_unknown = False
        self.histograms = {name: [0] * (len(BUCKETS) + 1) for name in ("accepted", "executed")}
        self.started = time.monotonic()
        self.closed = False

    def event(self, kind, **fields):
        self.events.write(json.dumps({"event": kind, "time_unix": time.time(), **fields}) + "\n")
        self.events.flush()
        os.fsync(self.events.fileno())

    def reserve_funding(self, amount, label):
        with self.guard:
            if (
                type(amount) is not int
                or amount <= 0
                or self.funded + amount > self.funding_cap
                or self.funding_operations >= 4096
            ):
                raise lib.TestnetError("qualified total funding ceiling reached")
            self.event("funding_reserved", amount_nanotos=amount, label=label)
            self.funded += amount
            self.funding_operations += 1

    def uncertain_funding(self):
        with self.guard:
            self.funding_unknown = True
            self.event("funding_unknown")

    def offer(self, ids, carrier):
        with self.guard:
            if not ids or len(set(ids)) != len(ids) or len(self.live) + len(ids) > self.max_pending:
                raise lib.TestnetError("duplicate query or qualified pending ceiling reached")
            for query in ids:
                if type(query) is not int or not 0 <= query < QUERY_LIMIT or query & 1023 == 1023:
                    raise lib.TestnetError("invalid qualified query id")
                if self.seen[query // 8] & (1 << (query % 8)):
                    raise lib.TestnetError("query reused within qualified run")
            # Keep the original carrier privately for read-only reconciliation; no hash or payload log.
            target = self.run / "private-outbox" / carrier.name
            with carrier.open("rb") as src, target.open("xb") as out:
                os.chmod(target, 0o600)
                while block := src.read(1024 * 1024):
                    out.write(block)
                out.flush()
                os.fsync(out.fileno())
            sync_directory(target.parent)
            stamp = time.monotonic()
            self.event("offered", query_ids=ids, carrier_bytes=target.stat().st_size)
            for query in ids:
                self.seen[query // 8] |= 1 << (query % 8)
                self.live[query] = {"offered": stamp, "accepted": False}
            self.offered += len(ids)

    def _histogram(self, kind, seconds):
        index = next((i for i, upper in enumerate(BUCKETS) if seconds <= upper), len(BUCKETS))
        self.histograms[kind][index] += 1

    def accept(self, ids):
        with self.guard:
            for query in ids:
                row = self.live[query]
                if not row["accepted"]:
                    elapsed = max(0, time.monotonic() - row["offered"])
                    self.event("accepted", query_id=query, offered_latency_seconds=elapsed)
                    row["accepted"] = True
                    self.accepted += 1
                    self._histogram("accepted", elapsed)

    def terminal(self, query, executed):
        with self.guard:
            row = self.live[query]
            elapsed = max(0, time.monotonic() - row["offered"])
            self.event(
                "executed" if executed else "unconfirmed",
                query_id=query,
                offered_latency_seconds=elapsed,
            )
            del self.live[query]
            if executed:
                self.executed += 1
                self._histogram("executed", elapsed)
            else:
                self.failed += 1

    def observe_fees(self, spent):
        with self.guard:
            self.event("fee_observation", spent_nanotos=spent)
            return spent >= self.fee_stop

    def finish(self):
        with self.guard:
            result = {
                "offered": self.offered,
                "accepted": self.accepted,
                "executed": self.executed,
                "unconfirmed": self.failed,
                "pending": len(self.live),
                "funded_nanotos": self.funded,
                "funding_cap_nanotos": self.funding_cap,
                "funding_unknown": self.funding_unknown,
                "observed_fee_stop_nanotos": self.fee_stop,
                "seconds_monotonic": time.monotonic() - self.started,
                "latency_bucket_upper_seconds": [*BUCKETS, "infinity"],
                "histograms": self.histograms,
                "latency_scope": "offered to RPC seqno acceptance / two-RPC per-query processed? observation; not native finality proof",
            }
            result["all_queries_observed_executed"] = (
                self.offered > 0 and self.executed == self.offered
            )
            result["safe_to_start_new_run"] = (
                not self.live and not self.failed and not self.funding_unknown
            )
            atomic_json(self.run / "result.json", result)
            atomic_json(
                self.active, {"run": self.run.name, "closed": result["safe_to_start_new_run"]}
            )
            self.events.close()
            os.close(self.lock_fd)
            self.closed = True
            return result

    def abort(self):
        """Release resources while leaving the unfinished-run fence in place."""
        with self.guard:
            if not self.closed:
                self.events.close()
                os.close(self.lock_fd)
                self.closed = True
